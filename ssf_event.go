package jambo

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// EmitSecurityEvent notifies every enabled stream belonging to clientID
// that requested eventType (one of the EventCAEP* constants, or a custom
// URI declared via Client.AddSSFEventsSupported) and that has subject
// registered (via the /ssf/subjects:add management call), delivering a
// signed Security Event Token: immediately, for push streams, or queued
// for the receiver to retrieve, for poll streams.
//
// claims is merged into the SET's event-specific claims (e.g.
// {"reason": "password-reset"} for a credential-change event); it may be nil.
func (s *Server) EmitSecurityEvent(clientID, eventType string, subject Subject, claims map[string]any) error {
	streams, err := s.storage.ListStreams(clientID)
	if err != nil {
		return err
	}
	for _, stream := range streams {
		if stream.Status != StreamStatusEnabled {
			continue
		}
		if !slices.Contains(stream.EventsDelivered, eventType) {
			continue
		}
		if !slices.ContainsFunc(stream.Subjects, subject.equal) {
			continue
		}
		if err := s.deliverEvent(stream, eventType, subject, claims); err != nil {
			return fmt.Errorf("stream %s: %w", stream.StreamID, err)
		}
	}
	return nil
}

// deliverEvent signs a SET for (eventType, subject, claims) and hands it
// off for push delivery or queues it for poll delivery, per the stream's
// configured method.
func (s *Server) deliverEvent(stream Stream, eventType string, subject Subject, claims map[string]any) error {
	setJWS, jti, err := s.signSecurityEvent(stream, eventType, subject, claims)
	if err != nil {
		return err
	}
	switch {
	case isPushDeliveryMethod(stream.Delivery.Method):
		s.pushEvent(stream, setJWS)
	case isPollDeliveryMethod(stream.Delivery.Method):
		return s.storage.QueueEvent(stream.StreamID, PendingEvent{JTI: jti, SET: setJWS})
	}
	return nil
}

// securityEventToken is the payload of a Security Event Token (RFC 8417).
// Per RFC 8417 it MUST NOT contain "exp" or "sub" claims.
type securityEventToken struct {
	Issuer   string                    `json:"iss"`
	JTI      string                    `json:"jti"`
	IssuedAt int64                     `json:"iat"`
	Audience []string                  `json:"aud"`
	SubID    Subject                   `json:"sub_id"`
	Events   map[string]map[string]any `json:"events"`
}

// signSecurityEvent builds and signs a securityEventToken for
// (eventType, subject, claims) addressed to stream's audience, returning
// its compact JWS serialization and its "jti".
func (s *Server) signSecurityEvent(stream Stream, eventType string, subject Subject, claims map[string]any) (jws, jti string, err error) {
	signingKey := jose.SigningKey{Key: s.key, Algorithm: jose.RS256}
	signer, err := jose.NewSigner(signingKey, (&jose.SignerOptions{}).WithType("secevent+jwt"))
	if err != nil {
		return "", "", fmt.Errorf("new signer: %w", err)
	}

	b := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", "", err
	}
	jti = hex.EncodeToString(b)

	if claims == nil {
		claims = map[string]any{}
	}

	set := securityEventToken{
		Issuer:   stream.Iss,
		JTI:      jti,
		IssuedAt: time.Now().Unix(),
		Audience: stream.Aud,
		SubID:    subject,
		Events:   map[string]map[string]any{eventType: claims},
	}
	payload, err := json.Marshal(set)
	if err != nil {
		return "", "", err
	}
	signature, err := signer.Sign(payload)
	if err != nil {
		return "", "", fmt.Errorf("signing SET: %w", err)
	}
	jws, err = signature.CompactSerialize()
	return jws, jti, err
}

// pushEvent delivers a signed SET to a push-delivery stream's endpoint,
// retrying with exponential backoff. It runs in its own goroutine so
// EmitSecurityEvent never blocks on a slow or unreachable receiver.
//
// isSafePushURL's SSRF guard runs again before every attempt (not just
// once, when the stream was created/updated): a receiver could otherwise
// register a public endpoint that passes validation and later DNS-rebind
// its hostname to a private address before delivery actually happens, or
// before a later retry. The client also refuses to follow redirects, so
// an endpoint can't pass validation and then 302 the actual push to an
// unvalidated internal URL.
func (s *Server) pushEvent(stream Stream, setJWS string) {
	go func() {
		client := &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		backoff := time.Second
		const maxAttempts = 8
		for attempt := 1; attempt <= maxAttempts; attempt++ {
			if err := isSafePushURL(stream.Delivery.EndpointURL, s.allowInsecureSSFPush); err != nil {
				if s.debug {
					log.Printf("SSF push to stream %s: endpoint_url no longer safe: %v\n", stream.StreamID, err)
				}
				return
			}
			req, err := http.NewRequest(http.MethodPost, stream.Delivery.EndpointURL, strings.NewReader(setJWS))
			if err != nil {
				if s.debug {
					log.Printf("SSF push to stream %s: %v\n", stream.StreamID, err)
				}
				return
			}
			req.Header.Set("Content-Type", "application/secevent+jwt")
			if stream.Delivery.AuthorizationHeader != "" {
				req.Header.Set("Authorization", stream.Delivery.AuthorizationHeader)
			}
			resp, err := client.Do(req)
			if err == nil {
				resp.Body.Close()
				if resp.StatusCode >= 200 && resp.StatusCode < 300 {
					return
				}
				if s.debug {
					log.Printf("SSF push to stream %s: status %d (attempt %d/%d)\n", stream.StreamID, resp.StatusCode, attempt, maxAttempts)
				}
			} else if s.debug {
				log.Printf("SSF push to stream %s: %v (attempt %d/%d)\n", stream.StreamID, err, attempt, maxAttempts)
			}
			if attempt < maxAttempts {
				time.Sleep(backoff)
				backoff *= 2
			}
		}
		if s.debug {
			log.Printf("SSF push to stream %s: giving up after %d attempts\n", stream.StreamID, maxAttempts)
		}
	}()
}

// ssfPoll handles "POST /ssf/poll/{stream_id}" (RFC 8936).
func (s *Server) ssfPoll(w http.ResponseWriter, r *http.Request) {
	clientID, err := s.requireSSFScope(r, "ssf.read", "ssf.manage")
	if err != nil {
		s.ssfError(w, http.StatusUnauthorized, err)
		return
	}
	streamID := r.PathValue("stream_id")
	stream, ok, err := s.storage.GetStream(streamID)
	if err != nil {
		http.Error(w, "Internal server error reading stream.", http.StatusInternalServerError)
		return
	}
	if !ok || stream.ClientID != clientID || !isPollDeliveryMethod(stream.Delivery.Method) {
		s.ssfError(w, http.StatusNotFound, fmt.Errorf("unknown stream_id"))
		return
	}

	var body struct {
		MaxEvents int            `json:"maxEvents"`
		Ack       []string       `json:"ack"`
		SetErrs   map[string]any `json:"setErrs"`
	}
	// An empty body is valid (bare poll for new events).
	_ = s.decodeSSFJSON(r, &body)

	for _, jti := range body.Ack {
		_ = s.storage.AckEvent(streamID, jti)
	}
	for jti := range body.SetErrs {
		// The receiver failed to process this SET; we don't currently retry
		// poll deliveries, so just drop it rather than redeliver forever.
		_ = s.storage.AckEvent(streamID, jti)
	}

	events, err := s.storage.PendingEvents(streamID, body.MaxEvents)
	if err != nil {
		http.Error(w, "Internal server error reading pending events.", http.StatusInternalServerError)
		return
	}
	sets := make(map[string]string, len(events))
	for _, e := range events {
		sets[e.JTI] = e.SET
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"sets": sets,
		// Always false: unlike PendingEvents, we don't currently learn
		// whether MaxEvents truncated the result, so we can't report this
		// accurately when it does.
		"moreAvailable": false,
	})
}
