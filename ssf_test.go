package jambo

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

const ssfClientID = "ssf-client"
const ssfClientSecret = "ssf-secret"

func newSSFTestServer(t *testing.T) *Server {
	t.Helper()
	s := NewServer("http://example.com/oidc", "/oidc")
	if s == nil {
		t.Fatal("NewServer returned nil")
	}
	// Our test "receivers" run on httptest servers (127.0.0.1).
	s.SetSSFAllowPrivatePush(true)

	client := s.NewClient(ssfClientID, ssfClientSecret)
	client.AddAllowedRedirectURIs("http://client.example.com/callback")
	client.AddAllowedScopes("offline_access", "ssf.manage", "ssf.read")
	client.AddSSFEventsSupported(EventCAEPSessionRevoked, EventCAEPCredentialChange)

	s.SetAuthenticator(func(req *Request) Response {
		if req.Params["login"] == "alice" && req.Params["password"] == "secret" {
			return Response{Type: ResponseTypeLoginOK, Login: "alice", Name: "Alice", Mail: "alice@example.com"}
		}
		return Response{Type: ResponseTypeLoginFailed, Login: req.Params["login"]}
	})
	return s
}

// ssfExchangeCode drives a full authorization_code exchange for the ssf-client and returns the token response body.
func ssfExchangeCode(t *testing.T, s *Server, scope string) map[string]any {
	t.Helper()
	session := doAuth(t, s, url.Values{
		"client_id":     {ssfClientID},
		"redirect_uri":  {"http://client.example.com/callback"},
		"response_type": {"code"},
		"scope":         {scope},
		"state":         {"xyz"},
	})
	resp := login(t, s, session, "alice", "secret")
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("POST /auth/login: status = %d", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("invalid redirect Location: %v", err)
	}
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatal("redirect did not contain a code")
	}

	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {"http://client.example.com/callback"},
	}
	req := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(ssfClientID, ssfClientSecret)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("POST /token: invalid JSON response: %v (body=%s)", err, rec.Body.String())
	}
	return body
}

func ssfRefreshToken(t *testing.T, s *Server, refreshToken string) (int, map[string]any) {
	t.Helper()
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	}
	req := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(ssfClientID, ssfClientSecret)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("POST /token (refresh): invalid JSON response: %v (body=%s)", err, rec.Body.String())
	}
	return rec.Code, body
}

// ssfDo makes an authenticated JSON request against the SSF management API.
func ssfDo(t *testing.T, s *Server, method, path, accessToken string, body any) (int, map[string]any) {
	t.Helper()
	var reader *strings.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshaling request body: %v", err)
		}
		reader = strings.NewReader(string(b))
	} else {
		reader = strings.NewReader("")
	}
	req := httptest.NewRequest(method, "/oidc"+path, reader)
	req.Header.Set("Content-Type", "application/json")
	if accessToken != "" {
		req.Header.Set("Authorization", "Bearer "+accessToken)
	}
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)

	var got map[string]any
	if rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("%s %s: invalid JSON response: %v (body=%s)", method, path, err, rec.Body.String())
		}
	}
	return rec.Code, got
}

// verifySET checks the SET's signature against s's signing key and
// returns its decoded claims.
func verifySET(t *testing.T, s *Server, compact string) map[string]any {
	t.Helper()
	parsed, err := jose.ParseSigned(compact, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatalf("parsing SET: %v", err)
	}
	data, err := parsed.Verify(&s.key.Key.(*rsa.PrivateKey).PublicKey)
	if err != nil {
		t.Fatalf("verifying SET signature: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(data, &claims); err != nil {
		t.Fatalf("decoding SET claims: %v", err)
	}
	return claims
}

func TestOfflineAccessIssuesRotatingRefreshToken(t *testing.T) {
	s := newSSFTestServer(t)

	body := ssfExchangeCode(t, s, "openid offline_access")
	refreshToken, _ := body["refresh_token"].(string)
	if refreshToken == "" {
		t.Fatalf("expected a refresh_token, got %v", body)
	}
	if body["access_token"] == "" {
		t.Fatalf("expected an access_token, got %v", body)
	}

	status, refreshed := ssfRefreshToken(t, s, refreshToken)
	if status != http.StatusOK {
		t.Fatalf("refresh_token grant: status = %d, body = %v", status, refreshed)
	}
	newRefreshToken, _ := refreshed["refresh_token"].(string)
	if newRefreshToken == "" || newRefreshToken == refreshToken {
		t.Errorf("expected a new, different refresh_token, got %q", newRefreshToken)
	}

	// The old refresh token must not be usable a second time.
	_, replayed := ssfRefreshToken(t, s, refreshToken)
	if replayed["error"] != "invalid_grant" {
		t.Errorf("replaying refresh token: error = %v, want invalid_grant", replayed["error"])
	}
}

func TestSSFRequiresScope(t *testing.T) {
	s := newSSFTestServer(t)
	body := ssfExchangeCode(t, s, "openid") // no ssf.manage
	accessToken, _ := body["access_token"].(string)

	status, _ := ssfDo(t, s, http.MethodPost, "/ssf/stream", accessToken, streamRequest{
		Delivery:        Delivery{Method: deliveryMethodPoll},
		EventsRequested: []string{EventCAEPSessionRevoked},
	})
	if status != http.StatusUnauthorized {
		t.Errorf("POST /ssf/stream without ssf.manage scope: status = %d, want 401", status)
	}
}

func TestSSFRejectsPrivatePushEndpointByDefault(t *testing.T) {
	s := NewServer("http://example.com/oidc", "/oidc") // no SetSSFAllowPrivatePush
	client := s.NewClient(ssfClientID, ssfClientSecret)
	client.AddAllowedRedirectURIs("http://client.example.com/callback")
	client.AddAllowedScopes("ssf.manage")
	client.AddSSFEventsSupported(EventCAEPSessionRevoked)
	s.SetAuthenticator(func(req *Request) Response {
		return Response{Type: ResponseTypeLoginOK, Login: "alice"}
	})

	body := ssfExchangeCode(t, s, "openid ssf.manage")
	accessToken, _ := body["access_token"].(string)

	status, resp := ssfDo(t, s, http.MethodPost, "/ssf/stream", accessToken, streamRequest{
		Delivery:        Delivery{Method: deliveryMethodPush, EndpointURL: "http://127.0.0.1:9/receiver"},
		EventsRequested: []string{EventCAEPSessionRevoked},
	})
	if status != http.StatusBadRequest {
		t.Fatalf("POST /ssf/stream with private push endpoint: status = %d, body = %v", status, resp)
	}
}

func TestSSFPushDelivery(t *testing.T) {
	s := newSSFTestServer(t)
	body := ssfExchangeCode(t, s, "openid ssf.manage ssf.read")
	accessToken, _ := body["access_token"].(string)

	var mu sync.Mutex
	var received string
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ct := r.Header.Get("Content-Type"); ct != "application/secevent+jwt" {
			t.Errorf("push request Content-Type = %q, want application/secevent+jwt", ct)
		}
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("reading push request body: %v", err)
		}
		mu.Lock()
		received = string(b)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer receiver.Close()

	status, streamResp := ssfDo(t, s, http.MethodPost, "/ssf/stream", accessToken, streamRequest{
		Delivery:        Delivery{Method: deliveryMethodPush, EndpointURL: receiver.URL},
		EventsRequested: []string{EventCAEPSessionRevoked},
	})
	if status != http.StatusCreated {
		t.Fatalf("POST /ssf/stream: status = %d, body = %v", status, streamResp)
	}
	streamID, _ := streamResp["stream_id"].(string)
	if streamID == "" {
		t.Fatalf("POST /ssf/stream: missing stream_id in %v", streamResp)
	}
	delivered, _ := streamResp["events_delivered"].([]any)
	if len(delivered) != 1 || delivered[0] != EventCAEPSessionRevoked {
		t.Errorf("events_delivered = %v, want [%s]", delivered, EventCAEPSessionRevoked)
	}

	subject := Subject{Format: SubjectFormatEmail, Email: "alice@example.com"}
	status, _ = ssfDo(t, s, http.MethodPost, "/ssf/subjects:add", accessToken, subjectRequest{StreamID: streamID, Subject: subject})
	if status != http.StatusNoContent {
		t.Fatalf("POST /ssf/subjects:add: status = %d", status)
	}

	if err := s.EmitSecurityEvent(ssfClientID, EventCAEPSessionRevoked, subject, map[string]any{"reason": "logout"}); err != nil {
		t.Fatalf("EmitSecurityEvent: %v", err)
	}

	waitFor(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return received != ""
	})

	mu.Lock()
	set := received
	mu.Unlock()
	claims := verifySET(t, s, set)
	events, _ := claims["events"].(map[string]any)
	eventClaims, ok := events[EventCAEPSessionRevoked].(map[string]any)
	if !ok {
		t.Fatalf("SET events = %v, missing %s", events, EventCAEPSessionRevoked)
	}
	if eventClaims["reason"] != "logout" {
		t.Errorf("event claims = %v, want reason=logout", eventClaims)
	}
}

// TestSSFPushDoesNotFollowRedirects guards against a push endpoint that
// passes SSRF validation and then redirects the actual delivery to an
// unvalidated (potentially internal) URL.
func TestSSFPushDoesNotFollowRedirects(t *testing.T) {
	s := newSSFTestServer(t)
	body := ssfExchangeCode(t, s, "openid ssf.manage ssf.read")
	accessToken, _ := body["access_token"].(string)

	var mu sync.Mutex
	redirectTargetHit := false
	redirectTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		redirectTargetHit = true
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer redirectTarget.Close()

	receiverHits := 0
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		receiverHits++
		mu.Unlock()
		http.Redirect(w, r, redirectTarget.URL, http.StatusFound)
	}))
	defer receiver.Close()

	status, streamResp := ssfDo(t, s, http.MethodPost, "/ssf/stream", accessToken, streamRequest{
		Delivery:        Delivery{Method: deliveryMethodPush, EndpointURL: receiver.URL},
		EventsRequested: []string{EventCAEPSessionRevoked},
	})
	if status != http.StatusCreated {
		t.Fatalf("POST /ssf/stream: status = %d, body = %v", status, streamResp)
	}
	streamID, _ := streamResp["stream_id"].(string)

	subject := Subject{Format: SubjectFormatEmail, Email: "alice@example.com"}
	if status, _ := ssfDo(t, s, http.MethodPost, "/ssf/subjects:add", accessToken, subjectRequest{StreamID: streamID, Subject: subject}); status != http.StatusNoContent {
		t.Fatalf("POST /ssf/subjects:add: status = %d", status)
	}

	if err := s.EmitSecurityEvent(ssfClientID, EventCAEPSessionRevoked, subject, nil); err != nil {
		t.Fatalf("EmitSecurityEvent: %v", err)
	}

	waitFor(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return receiverHits > 0
	})

	// Give a wrongly-followed redirect plenty of time to have reached
	// redirectTarget (it would happen within the same client.Do call,
	// so this is generous), then confirm it never did.
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if redirectTargetHit {
		t.Error("push delivery followed a redirect to an unvalidated endpoint")
	}
}

// TestSSFPushRevalidatesEndpointBeforeDelivery guards against a push
// endpoint that was safe when the stream was created/updated but has
// since become unsafe (e.g. a DNS rebind to a private address): delivery
// must re-check isSafePushURL before every attempt, not just once at
// stream-creation time.
func TestSSFPushRevalidatesEndpointBeforeDelivery(t *testing.T) {
	s := newSSFTestServer(t) // SetSSFAllowPrivatePush(true), so creating the stream below succeeds
	body := ssfExchangeCode(t, s, "openid ssf.manage ssf.read")
	accessToken, _ := body["access_token"].(string)

	var mu sync.Mutex
	hits := 0
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer receiver.Close()

	status, streamResp := ssfDo(t, s, http.MethodPost, "/ssf/stream", accessToken, streamRequest{
		Delivery:        Delivery{Method: deliveryMethodPush, EndpointURL: receiver.URL},
		EventsRequested: []string{EventCAEPSessionRevoked},
	})
	if status != http.StatusCreated {
		t.Fatalf("POST /ssf/stream: status = %d, body = %v", status, streamResp)
	}
	streamID, _ := streamResp["stream_id"].(string)

	subject := Subject{Format: SubjectFormatEmail, Email: "alice@example.com"}
	if status, _ := ssfDo(t, s, http.MethodPost, "/ssf/subjects:add", accessToken, subjectRequest{StreamID: streamID, Subject: subject}); status != http.StatusNoContent {
		t.Fatalf("POST /ssf/subjects:add: status = %d", status)
	}

	// receiver.URL (plain http, on 127.0.0.1) already passed validation
	// only because SetSSFAllowPrivatePush(true) was in effect when the
	// stream was created. Flip that off now, simulating the endpoint
	// having become unsafe since (e.g. a DNS rebind), without touching
	// the stream itself -- receiver is still listening, so if the guard
	// fails to re-check at delivery time, this push would still succeed.
	s.allowInsecureSSFPush = false

	if err := s.EmitSecurityEvent(ssfClientID, EventCAEPSessionRevoked, subject, nil); err != nil {
		t.Fatalf("EmitSecurityEvent: %v", err)
	}

	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if hits != 0 {
		t.Errorf("push was delivered to an endpoint that should have failed re-validation: %d hits", hits)
	}
}

func TestSSFPollDelivery(t *testing.T) {
	s := newSSFTestServer(t)
	body := ssfExchangeCode(t, s, "openid ssf.manage ssf.read")
	accessToken, _ := body["access_token"].(string)

	status, streamResp := ssfDo(t, s, http.MethodPost, "/ssf/stream", accessToken, streamRequest{
		Delivery:        Delivery{Method: deliveryMethodPoll},
		EventsRequested: []string{EventCAEPCredentialChange},
	})
	if status != http.StatusCreated {
		t.Fatalf("POST /ssf/stream: status = %d, body = %v", status, streamResp)
	}
	streamID, _ := streamResp["stream_id"].(string)
	pollDelivery, _ := streamResp["delivery"].(map[string]any)
	pollURL, _ := pollDelivery["endpoint_url"].(string)
	if !strings.Contains(pollURL, "/ssf/poll/"+streamID) {
		t.Fatalf("poll endpoint_url = %q, want it to contain /ssf/poll/%s", pollURL, streamID)
	}

	subject := Subject{Format: SubjectFormatOpaque, ID: "user-1"}
	if status, _ := ssfDo(t, s, http.MethodPost, "/ssf/subjects:add", accessToken, subjectRequest{StreamID: streamID, Subject: subject}); status != http.StatusNoContent {
		t.Fatalf("POST /ssf/subjects:add: status = %d", status)
	}

	if err := s.EmitSecurityEvent(ssfClientID, EventCAEPCredentialChange, subject, nil); err != nil {
		t.Fatalf("EmitSecurityEvent: %v", err)
	}

	pollPath := fmt.Sprintf("/ssf/poll/%s", streamID)
	status, pollResp := ssfDo(t, s, http.MethodPost, pollPath, accessToken, map[string]any{"maxEvents": 10})
	if status != http.StatusOK {
		t.Fatalf("POST %s: status = %d, body = %v", pollPath, status, pollResp)
	}
	sets, _ := pollResp["sets"].(map[string]any)
	if len(sets) != 1 {
		t.Fatalf("poll sets = %v, want exactly 1 event", sets)
	}
	var jti, set string
	for k, v := range sets {
		jti = k
		set, _ = v.(string)
	}
	claims := verifySET(t, s, set)
	events, _ := claims["events"].(map[string]any)
	if _, ok := events[EventCAEPCredentialChange]; !ok {
		t.Fatalf("SET events = %v, missing %s", events, EventCAEPCredentialChange)
	}

	// Ack it, then polling again should return nothing.
	status, pollResp = ssfDo(t, s, http.MethodPost, pollPath, accessToken, map[string]any{"ack": []string{jti}})
	if status != http.StatusOK {
		t.Fatalf("POST %s (ack): status = %d, body = %v", pollPath, status, pollResp)
	}
	sets, _ = pollResp["sets"].(map[string]any)
	if len(sets) != 0 {
		t.Errorf("poll sets after ack = %v, want none", sets)
	}
}

func TestSSFConfigurationDiscovery(t *testing.T) {
	s := newSSFTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/oidc/.well-known/ssf-configuration", nil)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)

	var config map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &config); err != nil {
		t.Fatalf("invalid JSON: %v (body=%s)", err, rec.Body.String())
	}
	if config["issuer"] != "http://example.com/oidc" {
		t.Errorf("issuer = %v, want http://example.com/oidc", config["issuer"])
	}
	if config["configuration_endpoint"] != "http://example.com/oidc/ssf/stream" {
		t.Errorf("configuration_endpoint = %v", config["configuration_endpoint"])
	}
}

// waitFor polls until cond returns true or fails the test after a timeout.
// Push delivery happens in a background goroutine (see Server.pushEvent),
// so tests observing it can't just check synchronously.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if cond() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for condition")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
