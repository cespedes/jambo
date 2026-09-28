package jambo

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	s := NewServer("http://example.com/oidc", "/oidc")
	if s == nil {
		t.Fatal("NewServer returned nil")
	}
	client := s.NewClient("test-client", "test-secret")
	client.AddAllowedRedirectURIs("http://client.example.com/callback")
	s.SetAuthenticator(func(req *Request) Response {
		if req.Params["login"] == "alice" && req.Params["password"] == "secret" {
			return Response{
				Type:  ResponseTypeLoginOK,
				Login: "alice",
				Name:  "Alice",
				Mail:  "alice@example.com",
			}
		}
		return Response{Type: ResponseTypeLoginFailed, Login: req.Params["login"]}
	})
	return s
}

var sessionRe = regexp.MustCompile(`name="session" value="([^"]+)"`)

// doAuth drives a GET /auth request with the given query parameters and
// returns the session (the authorization code) embedded in the returned
// login form.
func doAuth(t *testing.T, s *Server, q url.Values) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/oidc/auth?"+q.Encode(), nil)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /auth: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	m := sessionRe.FindStringSubmatch(rec.Body.String())
	if m == nil {
		t.Fatalf("GET /auth: could not find session in response body: %s", rec.Body.String())
	}
	return m[1]
}

func startAuth(t *testing.T, s *Server, scope string) string {
	t.Helper()
	return doAuth(t, s, url.Values{
		"client_id":     {"test-client"},
		"redirect_uri":  {"http://client.example.com/callback"},
		"response_type": {"code"},
		"scope":         {scope},
		"state":         {"xyz"},
		"nonce":         {"abc123"},
	})
}

func login(t *testing.T, s *Server, session, login, password string) *http.Response {
	t.Helper()
	form := url.Values{
		"session":  {session},
		"login":    {login},
		"password": {password},
	}
	req := httptest.NewRequest(http.MethodPost, "/oidc/auth/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	return rec.Result()
}

func exchangeCode(t *testing.T, s *Server, code string) (*http.Response, map[string]any) {
	t.Helper()
	return exchangeCodeWithVerifier(t, s, code, "")
}

func exchangeCodeWithVerifier(t *testing.T, s *Server, code, codeVerifier string) (*http.Response, map[string]any) {
	t.Helper()
	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {"http://client.example.com/callback"},
	}
	if codeVerifier != "" {
		form.Set("code_verifier", codeVerifier)
	}
	req := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("test-client", "test-secret")
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("POST /token: invalid JSON response: %v (body=%s)", err, rec.Body.String())
	}
	return rec.Result(), body
}

func TestFullAuthorizationCodeFlow(t *testing.T) {
	s := newTestServer(t)

	session := startAuth(t, s, "openid profile email")

	resp := login(t, s, session, "alice", "secret")
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("POST /auth/login: status = %d", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("invalid redirect Location: %v", err)
	}
	if got := loc.Query().Get("state"); got != "xyz" {
		t.Errorf("state = %q, want %q", got, "xyz")
	}
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatal("redirect did not contain a code")
	}

	tokResp, tokBody := exchangeCode(t, s, code)
	if tokResp.StatusCode != http.StatusOK {
		t.Fatalf("POST /token: status = %d, body = %v", tokResp.StatusCode, tokBody)
	}
	accessToken, _ := tokBody["access_token"].(string)
	if accessToken == "" {
		t.Fatalf("POST /token: missing access_token in %v", tokBody)
	}

	// The same code must not be redeemable twice (RFC 6749 section 4.1.2).
	_, replayBody := exchangeCode(t, s, code)
	if replayBody["error"] != "invalid_grant" {
		t.Errorf("replaying code: error = %v, want invalid_grant", replayBody["error"])
	}

	req := httptest.NewRequest(http.MethodGet, "/oidc/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)

	var claims map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &claims); err != nil {
		t.Fatalf("GET /userinfo: invalid JSON: %v (body=%s)", err, rec.Body.String())
	}
	if claims["sub"] != "alice" {
		t.Errorf("userinfo sub = %v, want %q", claims["sub"], "alice")
	}
	if claims["email"] != "alice@example.com" {
		t.Errorf("userinfo email = %v, want %q", claims["email"], "alice@example.com")
	}
}

// TestCodeCannotBeRedeemedByDifferentClient guards against a code issued
// to one client being redeemed by a different registered client (RFC 6749
// section 4.1.3): even with the correct redirect_uri, valid credentials
// for a *different* client must not be enough to obtain a token for a
// code that was issued to someone else.
func TestCodeCannotBeRedeemedByDifferentClient(t *testing.T) {
	s := newTestServer(t)
	other := s.NewClient("other-client", "other-secret")
	other.AddAllowedRedirectURIs("http://client.example.com/callback")

	session := startAuth(t, s, "openid profile email")
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
	req.SetBasicAuth("other-client", "other-secret")
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("POST /token: invalid JSON response: %v (body=%s)", err, rec.Body.String())
	}
	if body["error"] != "invalid_grant" {
		t.Errorf("redeeming test-client's code as other-client: error = %v, want invalid_grant", body["error"])
	}
	if _, ok := body["access_token"]; ok {
		t.Errorf("redeeming test-client's code as other-client returned an access_token: %v", body)
	}
}

func TestLoginFailedReRendersForm(t *testing.T) {
	s := newTestServer(t)
	session := startAuth(t, s, "openid")

	resp := login(t, s, session, "alice", "wrong-password")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /auth/login with bad credentials: status = %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "Invalid") {
		t.Errorf("expected login error message in response body, got: %s", body)
	}
}

func TestUnknownClientIsRejected(t *testing.T) {
	s := newTestServer(t)
	q := url.Values{
		"client_id":     {"no-such-client"},
		"redirect_uri":  {"http://client.example.com/callback"},
		"response_type": {"code"},
		"scope":         {"openid"},
	}
	req := httptest.NewRequest(http.MethodGet, "/oidc/auth?"+q.Encode(), nil)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)

	if !strings.Contains(rec.Body.String(), "unknown client") {
		t.Errorf("expected 'unknown client' error, got: %s", rec.Body.String())
	}
}

func TestUnregisteredRedirectURIIsRejected(t *testing.T) {
	s := newTestServer(t)
	q := url.Values{
		"client_id":     {"test-client"},
		"redirect_uri":  {"http://evil.example.com/callback"},
		"response_type": {"code"},
		"scope":         {"openid"},
	}
	req := httptest.NewRequest(http.MethodGet, "/oidc/auth?"+q.Encode(), nil)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)

	if !strings.Contains(rec.Body.String(), "Unregistered redirect_uri") {
		t.Errorf("expected 'Unregistered redirect_uri' error, got: %s", rec.Body.String())
	}
}

func TestExpiredConnectionIsRejected(t *testing.T) {
	s := newTestServer(t)
	session := startAuth(t, s, "openid")

	// Force the pending connection into the past so it counts as expired.
	s.Lock()
	conn := s.connections[session]
	conn.created = time.Now().Add(-connectionTTL - time.Minute)
	s.connections[session] = conn
	s.Unlock()

	resp := login(t, s, session, "alice", "secret")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected an error page (status 200), got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "Invalid session") {
		t.Errorf("expected 'Invalid session' error, got: %s", body)
	}

	s.Lock()
	_, stillThere := s.connections[session]
	s.Unlock()
	if stillThere {
		t.Error("expired connection was not purged from s.connections")
	}
}

func TestExpiredConnectionsArePurgedOnNewAuth(t *testing.T) {
	s := newTestServer(t)
	staleSession := startAuth(t, s, "openid")

	s.Lock()
	conn := s.connections[staleSession]
	conn.created = time.Now().Add(-connectionTTL - time.Minute)
	s.connections[staleSession] = conn
	s.Unlock()

	// Starting a new authentication flow should sweep out the stale one.
	startAuth(t, s, "openid")

	s.Lock()
	_, stillThere := s.connections[staleSession]
	s.Unlock()
	if stillThere {
		t.Error("expired connection was not purged when a new one was created")
	}
}

func TestPKCESucceedsWithCorrectVerifier(t *testing.T) {
	s := newTestServer(t)

	codeVerifier := "a-very-random-verifier-that-is-at-least-43-characters-long"
	sum := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(sum[:])

	session := doAuth(t, s, url.Values{
		"client_id":             {"test-client"},
		"redirect_uri":          {"http://client.example.com/callback"},
		"response_type":         {"code"},
		"scope":                 {"openid"},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
	})

	resp := login(t, s, session, "alice", "secret")
	loc, _ := url.Parse(resp.Header.Get("Location"))
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatal("redirect did not contain a code")
	}

	tokResp, tokBody := exchangeCodeWithVerifier(t, s, code, codeVerifier)
	if tokResp.StatusCode != http.StatusOK || tokBody["access_token"] == nil {
		t.Fatalf("POST /token with correct code_verifier: status = %d, body = %v", tokResp.StatusCode, tokBody)
	}
}

func TestPKCERejectsWrongVerifier(t *testing.T) {
	s := newTestServer(t)

	sum := sha256.Sum256([]byte("the-real-verifier"))
	codeChallenge := base64.RawURLEncoding.EncodeToString(sum[:])

	session := doAuth(t, s, url.Values{
		"client_id":             {"test-client"},
		"redirect_uri":          {"http://client.example.com/callback"},
		"response_type":         {"code"},
		"scope":                 {"openid"},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
	})

	resp := login(t, s, session, "alice", "secret")
	loc, _ := url.Parse(resp.Header.Get("Location"))
	code := loc.Query().Get("code")

	_, tokBody := exchangeCodeWithVerifier(t, s, code, "not-the-real-verifier")
	if tokBody["error"] != "invalid_grant" {
		t.Errorf("wrong code_verifier: error = %v, want invalid_grant", tokBody["error"])
	}
}

func TestPKCERejectsMissingVerifier(t *testing.T) {
	s := newTestServer(t)

	sum := sha256.Sum256([]byte("the-real-verifier"))
	codeChallenge := base64.RawURLEncoding.EncodeToString(sum[:])

	session := doAuth(t, s, url.Values{
		"client_id":             {"test-client"},
		"redirect_uri":          {"http://client.example.com/callback"},
		"response_type":         {"code"},
		"scope":                 {"openid"},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
	})

	resp := login(t, s, session, "alice", "secret")
	loc, _ := url.Parse(resp.Header.Get("Location"))
	code := loc.Query().Get("code")

	_, tokBody := exchangeCode(t, s, code) // no code_verifier sent
	if tokBody["error"] != "invalid_grant" {
		t.Errorf("missing code_verifier: error = %v, want invalid_grant", tokBody["error"])
	}
}

func TestAuthWithoutPKCEStillWorks(t *testing.T) {
	// A client that never mentions PKCE gets the pre-existing behavior.
	s := newTestServer(t)
	session := startAuth(t, s, "openid")
	resp := login(t, s, session, "alice", "secret")
	loc, _ := url.Parse(resp.Header.Get("Location"))
	code := loc.Query().Get("code")

	tokResp, tokBody := exchangeCode(t, s, code)
	if tokResp.StatusCode != http.StatusOK || tokBody["access_token"] == nil {
		t.Fatalf("POST /token without PKCE: status = %d, body = %v", tokResp.StatusCode, tokBody)
	}
}

func TestUnsupportedCodeChallengeMethodIsRejected(t *testing.T) {
	s := newTestServer(t)
	q := url.Values{
		"client_id":             {"test-client"},
		"redirect_uri":          {"http://client.example.com/callback"},
		"response_type":         {"code"},
		"scope":                 {"openid"},
		"code_challenge":        {"whatever"},
		"code_challenge_method": {"md5"},
	}
	req := httptest.NewRequest(http.MethodGet, "/oidc/auth?"+q.Encode(), nil)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)

	if !strings.Contains(rec.Body.String(), "Unsupported code_challenge_method") {
		t.Errorf("expected 'Unsupported code_challenge_method' error, got: %s", rec.Body.String())
	}
}

// signTestToken signs a set of claims with the test server's own key,
// bypassing getIDToken, so tests can craft tokens with an arbitrary "exp".
func signTestToken(t *testing.T, s *Server, claims map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Key: s.key, Algorithm: jose.RS256}, &jose.SignerOptions{})
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	b, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	sig, err := signer.Sign(b)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	tok, err := sig.CompactSerialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	return tok
}

func userinfoRequest(s *Server, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/oidc/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	return rec
}

func TestUserinfoRejectsExpiredToken(t *testing.T) {
	s := newTestServer(t)
	token := signTestToken(t, s, map[string]any{
		"sub": "alice",
		"iat": time.Now().Add(-2 * time.Hour).Unix(),
		"exp": time.Now().Add(-time.Hour).Unix(),
	})

	rec := userinfoRequest(s, token)
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid JSON response: %v (body=%s)", err, rec.Body.String())
	}
	if body["error"] != "access_denied" {
		t.Errorf("expired token: error = %v, want access_denied", body["error"])
	}
}

func TestUserinfoRejectsTokenWithoutExpiration(t *testing.T) {
	s := newTestServer(t)
	token := signTestToken(t, s, map[string]any{"sub": "alice"})

	rec := userinfoRequest(s, token)
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid JSON response: %v (body=%s)", err, rec.Body.String())
	}
	if body["error"] != "access_denied" {
		t.Errorf("token without exp: error = %v, want access_denied", body["error"])
	}
}

func TestUserinfoAcceptsUnexpiredToken(t *testing.T) {
	s := newTestServer(t)
	token := signTestToken(t, s, map[string]any{
		"sub": "alice",
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	rec := userinfoRequest(s, token)
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid JSON response: %v (body=%s)", err, rec.Body.String())
	}
	if body["sub"] != "alice" {
		t.Errorf("sub = %v, want %q", body["sub"], "alice")
	}
}

func TestSetDebugTogglesTemplateComment(t *testing.T) {
	s := newTestServer(t)

	authBody := func() string {
		q := url.Values{
			"client_id":     {"test-client"},
			"redirect_uri":  {"http://client.example.com/callback"},
			"response_type": {"code"},
			"scope":         {"openid"},
		}
		req := httptest.NewRequest(http.MethodGet, "/oidc/auth?"+q.Encode(), nil)
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, req)
		return rec.Body.String()
	}

	if strings.Contains(authBody(), "<!--") {
		t.Fatal("debug HTML comment present before SetDebug was ever called")
	}

	s.SetDebug(true)
	if !strings.Contains(authBody(), "<!--") {
		t.Error("expected a debug HTML comment after SetDebug(true)")
	}

	s.SetDebug(false)
	if strings.Contains(authBody(), "<!--") {
		t.Error("expected no debug HTML comment after SetDebug(false)")
	}
}
