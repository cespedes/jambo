package jambo

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Shared Signals Framework (SSF) delivery methods (OpenID SSF 1.0 / RFC 8935 / RFC 8936).
const (
	deliveryMethodPush = "urn:ietf:rfc:8935"
	deliveryMethodPoll = "urn:ietf:rfc:8936"
)

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
	c.ssfEventsSupported = append(c.ssfEventsSupported, events...)
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

const (
	SubjectFormatEmail  = "email"
	SubjectFormatIssSub = "iss_sub"
	SubjectFormatOpaque = "opaque"
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
	Method              string `json:"method"`
	EndpointURL         string `json:"endpoint_url,omitempty"`
	AuthorizationHeader string `json:"authorization_header,omitempty"`
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
	MinVerificationInterval int      `json:"min_verification_interval,omitempty"`

	// Internal bookkeeping: not part of the JSON the receiver sees.
	ClientID string    `json:"-"`
	Status   string    `json:"-"` // "enabled", "paused" or "disabled"
	Subjects []Subject `json:"-"`
}

const (
	StreamStatusEnabled  = "enabled"
	StreamStatusPaused   = "paused"
	StreamStatusDisabled = "disabled"
)

// PendingEvent is a signed Security Event Token queued for a poll-delivery stream.
type PendingEvent struct {
	JTI string
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
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	fmt.Fprintf(w, `{"error":%q}`+"\n", err.Error())
}

// ssfConfiguration is the SSF transmitter metadata document, published at
// /.well-known/ssf-configuration (OpenID SSF 1.0 section 6).
type ssfConfiguration struct {
	Issuer                   string                   `json:"issuer"`
	JwksURI                  string                   `json:"jwks_uri,omitempty"`
	DeliveryMethodsSupported []string                 `json:"delivery_methods_supported,omitempty"`
	ConfigurationEndpoint    string                   `json:"configuration_endpoint,omitempty"`
	StatusEndpoint           string                   `json:"status_endpoint,omitempty"`
	AddSubjectEndpoint       string                   `json:"add_subject_endpoint,omitempty"`
	RemoveSubjectEndpoint    string                   `json:"remove_subject_endpoint,omitempty"`
	VerificationEndpoint     string                   `json:"verification_endpoint,omitempty"`
	AuthorizationSchemes     []ssfAuthorizationScheme `json:"authorization_schemes,omitempty"`
}

type ssfAuthorizationScheme struct {
	SpecURN string `json:"spec_urn"`
}

func (s *Server) ssfConfigurationHandler(w http.ResponseWriter, r *http.Request) {
	config := ssfConfiguration{
		Issuer:                   s.issuer,
		JwksURI:                  s.issuer + "/keys",
		DeliveryMethodsSupported: []string{deliveryMethodPush, deliveryMethodPoll},
		ConfigurationEndpoint:    s.issuer + "/ssf/stream",
		StatusEndpoint:           s.issuer + "/ssf/status",
		AddSubjectEndpoint:       s.issuer + "/ssf/subjects:add",
		RemoveSubjectEndpoint:    s.issuer + "/ssf/subjects:remove",
		VerificationEndpoint:     s.issuer + "/ssf/verify",
		// RFC 6749 bearer tokens obtained through this same server's /token endpoint.
		AuthorizationSchemes: []ssfAuthorizationScheme{{SpecURN: "urn:ietf:rfc:6749"}},
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
