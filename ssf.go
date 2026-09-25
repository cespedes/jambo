package jambo

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Shared Signals Framework (SSF) delivery methods (OpenID SSF 1.0 / RFC 8935 / RFC 8936).
//
// Real receivers disagree on how to spell these: the RISC-era URLs below
// predate the SSF 1.0 spec settling on the RFC-numbered URNs, but at least
// Apple Business Manager still sends the older spelling. Jambo accepts
// either for both push and poll -- see isPushDeliveryMethod /
// isPollDeliveryMethod -- and advertises all four in its own discovery
// document.
const (
	deliveryMethodPush = "urn:ietf:rfc:8935"
	deliveryMethodPoll = "urn:ietf:rfc:8936"

	deliveryMethodPushRISC = "https://schemas.openid.net/secevent/risc/delivery-method/push"
	deliveryMethodPollRISC = "https://schemas.openid.net/secevent/risc/delivery-method/poll"
)

func isPushDeliveryMethod(m string) bool {
	return m == deliveryMethodPush || m == deliveryMethodPushRISC
}

func isPollDeliveryMethod(m string) bool {
	return m == deliveryMethodPoll || m == deliveryMethodPollRISC
}

// CAEP (Continuous Access Evaluation Profile) event type URIs. A Client
// only ever has events delivered on a stream if the event type is both
// requested by the receiver and declared here via
// [Client.AddSSFEventsSupported].
const (
	EventCAEPSessionRevoked    = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
	EventCAEPCredentialChange  = "https://schemas.openid.net/secevent/caep/event-type/credential-change"
	EventCAEPTokenClaimsChange = "https://schemas.openid.net/secevent/caep/event-type/token-claims-change"
)

// SSF lifecycle event types, emitted by the transmitter itself rather
// than requested by the host application.
const (
	eventSSFVerification  = "https://schemas.openid.net/secevent/ssf/event-type/verification"
	eventSSFStreamUpdated = "https://schemas.openid.net/secevent/ssf/event-type/stream-updated"
)

// AddSSFEventsSupported declares the Shared Signals Framework event type
// URIs (see the EventCAEP* constants) that this client's streams may
// receive. A receiver's stream is only ever delivered events that are
// both requested by the receiver when the stream is created and declared
// supported here.
func (c *Client) AddSSFEventsSupported(events ...string) {
	c.configMu.Lock()
	defer c.configMu.Unlock()
	c.ssfEventsSupported = append(c.ssfEventsSupported, events...)
}

// ssfEventsSupportedSnapshot returns a copy of c's supported SSF event
// types, safe to keep and use after this call returns even if c's
// configuration changes later.
func (c *Client) ssfEventsSupportedSnapshot() []string {
	c.configMu.RLock()
	defer c.configMu.RUnlock()
	return slices.Clone(c.ssfEventsSupported)
}

// Subject identifies the principal a Security Event Token is about,
// using one of the formats from RFC 9493. Exactly the fields matching
// Format should be set.
type Subject struct {
	Format string `json:"format"`
	Email  string `json:"email,omitempty"`
	Iss    string `json:"iss,omitempty"`
	Sub    string `json:"sub,omitempty"`
	ID     string `json:"id,omitempty"` // used with Format == "opaque"
}

// Subject identifier formats (RFC 9493) accepted as Subject.Format.
const (
	SubjectFormatEmail  = "email"   // Subject.Email is set
	SubjectFormatIssSub = "iss_sub" // Subject.Iss and Subject.Sub are set
	SubjectFormatOpaque = "opaque"  // Subject.ID is set
)

func (s Subject) equal(o Subject) bool {
	if s.Format != o.Format {
		return false
	}
	switch s.Format {
	case SubjectFormatEmail:
		return s.Email == o.Email
	case SubjectFormatIssSub:
		return s.Iss == o.Iss && s.Sub == o.Sub
	case SubjectFormatOpaque:
		return s.ID == o.ID
	default:
		return false
	}
}

// Delivery describes how Security Event Tokens are transported for a
// stream: either pushed by the transmitter (RFC 8935) to EndpointURL, or
// polled by the receiver (RFC 8936) from EndpointURL.
type Delivery struct {
	Method              string `json:"method"`                         // one of the delivery method URIs isPushDeliveryMethod/isPollDeliveryMethod accept
	EndpointURL         string `json:"endpoint_url,omitempty"`         // where SETs are POSTed to (push) or polled from (poll)
	AuthorizationHeader string `json:"authorization_header,omitempty"` // sent as "Authorization" on each push, if set
}

// Stream is a Shared Signals Framework event stream, as created and
// managed by a receiver (e.g. Apple Business Manager) through the
// /ssf/stream management API.
type Stream struct {
	StreamID                string   `json:"stream_id"`
	Iss                     string   `json:"iss"`
	Aud                     []string `json:"aud"`
	EventsSupported         []string `json:"events_supported,omitempty"`
	EventsRequested         []string `json:"events_requested"`
	EventsDelivered         []string `json:"events_delivered"`
	Delivery                Delivery `json:"delivery"`
	Description             string   `json:"description,omitempty"`
	Format                  string   `json:"format,omitempty"` // default Subject format for this stream (RFC 9493)
	MinVerificationInterval int      `json:"min_verification_interval,omitempty"`

	// Internal bookkeeping: not part of the JSON the receiver sees.
	ClientID string    `json:"-"`
	Status   string    `json:"-"` // "enabled", "paused" or "disabled"
	Subjects []Subject `json:"-"`
}

// audienceList unmarshals a JSON "aud" value that, per RFC 8417, may be
// either a single string or an array of strings; a receiver like Apple
// Business Manager sends it as an array. It's always marshaled back out
// as an array.
type audienceList []string

// UnmarshalJSON implements [json.Unmarshaler], accepting either shape described in audienceList's doc comment.
func (a *audienceList) UnmarshalJSON(data []byte) error {
	var multi []string
	if err := json.Unmarshal(data, &multi); err == nil {
		*a = multi
		return nil
	}
	var single string
	if err := json.Unmarshal(data, &single); err != nil {
		return fmt.Errorf("aud must be a string or an array of strings: %w", err)
	}
	*a = []string{single}
	return nil
}

// Values a Stream's (internal) Status field may hold; also the values
// accepted by the /ssf/status management endpoint.
const (
	StreamStatusEnabled  = "enabled"  // events are delivered normally
	StreamStatusPaused   = "paused"   // no events are delivered, but the stream still exists
	StreamStatusDisabled = "disabled" // no events are delivered
)

// PendingEvent is a signed Security Event Token queued for a poll-delivery stream.
type PendingEvent struct {
	JTI string // the SET's "jti" claim, used to ack/nack it when polling
	SET string // compact JWS serialization
}

// accessTokenClaims are the claims of a Jambo access token relevant to
// authorizing calls to the SSF management API.
type accessTokenClaims struct {
	Audience   string `json:"aud"` // client ID
	Expiration int64  `json:"exp"`
	Scope      string `json:"scope"`
}

// requireSSFScope validates the bearer access token on r and checks that
// it was issued with at least one of the given scopes, returning the
// client ID (the token's audience) it was issued to.
func (s *Server) requireSSFScope(r *http.Request, anyOf ...string) (clientID string, err error) {
	fields := strings.Fields(r.Header.Get("Authorization"))
	if len(fields) != 2 || fields[0] != "Bearer" {
		return "", fmt.Errorf("missing bearer token")
	}
	data, err := s.verifySignedToken(fields[1])
	if err != nil {
		return "", fmt.Errorf("invalid bearer token: %w", err)
	}
	var claims accessTokenClaims
	if err := json.Unmarshal(data, &claims); err != nil {
		return "", fmt.Errorf("malformed token payload")
	}
	if claims.Expiration == 0 {
		return "", fmt.Errorf("token has no expiration")
	}
	if time.Now().Unix() >= claims.Expiration {
		return "", fmt.Errorf("token has expired")
	}
	granted := strings.Fields(claims.Scope)
	for _, want := range anyOf {
		if slices.Contains(granted, want) {
			return claims.Audience, nil
		}
	}
	return "", fmt.Errorf("token lacks required scope (need one of %v)", anyOf)
}

func (s *Server) ssfError(w http.ResponseWriter, status int, err error) {
	if s.debug {
		log.Printf("SSF: status=%d error=%v\n", status, err)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	fmt.Fprintf(w, `{"error":%q}`+"\n", err.Error())
}

// decodeSSFJSON reads r's body -- logging it first when debug logging is
// enabled, so a failed SSF call can be diagnosed from the logs alone --
// and decodes it as JSON into v. An empty body decodes into a zero v
// rather than erroring, since some SSF calls (e.g. a bare poll) are valid
// with no body at all.
func (s *Server) decodeSSFJSON(r *http.Request, v any) error {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return fmt.Errorf("reading request body: %w", err)
	}
	if s.debug {
		log.Printf("%s %s %s: body = %s\n", r.RemoteAddr, r.Method, r.URL, body)
	}
	if len(body) == 0 {
		return nil
	}
	return json.Unmarshal(body, v)
}

// encodeSSFJSON writes v as the response body's JSON encoding, logging
// (in debug mode) if that fails -- which can only happen once the
// response has already started, so there's nothing left to do about it
// besides note it happened.
func (s *Server) encodeSSFJSON(w http.ResponseWriter, v any) {
	if err := json.NewEncoder(w).Encode(v); err != nil && s.debug {
		log.Printf("SSF: encoding JSON response: %v\n", err)
	}
}

// ssfConfiguration is the SSF transmitter metadata document, published at
// /.well-known/ssf-configuration (OpenID SSF 1.0 section 6).
//
// AuthorizationSchemes is deliberately left unset: the spec does not fix a
// registry of spec_urn values for it, and every real transmitter we could
// find treats it as opaque or omits it, so publishing a guessed value
// risks a receiver's validator rejecting the whole document.
type ssfConfiguration struct {
	Issuer                   string   `json:"issuer"`
	JwksURI                  string   `json:"jwks_uri,omitempty"`
	SpecVersion              string   `json:"spec_version,omitempty"`
	DeliveryMethodsSupported []string `json:"delivery_methods_supported,omitempty"`
	ConfigurationEndpoint    string   `json:"configuration_endpoint,omitempty"`
	StatusEndpoint           string   `json:"status_endpoint,omitempty"`
	AddSubjectEndpoint       string   `json:"add_subject_endpoint,omitempty"`
	RemoveSubjectEndpoint    string   `json:"remove_subject_endpoint,omitempty"`
	VerificationEndpoint     string   `json:"verification_endpoint,omitempty"`
}

// ssfConfigurationHandler handles "GET /.well-known/ssf-configuration".
func (s *Server) ssfConfigurationHandler(w http.ResponseWriter, r *http.Request) {
	config := ssfConfiguration{
		Issuer:                   s.issuer,
		JwksURI:                  s.issuer + "/keys",
		SpecVersion:              "1.0",
		DeliveryMethodsSupported: []string{deliveryMethodPush, deliveryMethodPoll, deliveryMethodPushRISC, deliveryMethodPollRISC},
		ConfigurationEndpoint:    s.issuer + "/ssf/stream",
		StatusEndpoint:           s.issuer + "/ssf/status",
		AddSubjectEndpoint:       s.issuer + "/ssf/subjects:add",
		RemoveSubjectEndpoint:    s.issuer + "/ssf/subjects:remove",
		VerificationEndpoint:     s.issuer + "/ssf/verify",
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		http.Error(w, "Internal server error marshaling SSF configuration.", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)+1))
	fmt.Fprintln(w, string(data))
}
