package jambo

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

func TestRemoveClientReturnsFalseWhenNotFound(t *testing.T) {
	s := newTestServer(t)
	if s.RemoveClient("no-such-client") {
		t.Error("RemoveClient on an unknown id returned true, want false")
	}
}

func TestRemoveClientRejectsFurtherAuth(t *testing.T) {
	s := newTestServer(t)
	if !s.RemoveClient("test-client") {
		t.Fatal("RemoveClient on a known id returned false, want true")
	}

	q := url.Values{
		"client_id":     {"test-client"},
		"redirect_uri":  {"http://client.example.com/callback"},
		"response_type": {"code"},
		"scope":         {"openid"},
	}
	req := httptest.NewRequest(http.MethodGet, "/oidc/auth?"+q.Encode(), nil)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)

	if !strings.Contains(rec.Body.String(), "unknown client") {
		t.Errorf("expected 'unknown client' error after RemoveClient, got: %s", rec.Body.String())
	}
}

func TestNewClientPreservesSSFStreamsButNotTheOldSecret(t *testing.T) {
	s := newSSFTestServer(t)
	body := ssfExchangeCode(t, s, "openid ssf.manage ssf.read")
	accessToken, _ := body["access_token"].(string)

	status, streamResp := ssfDo(t, s, http.MethodPost, "/ssf/stream", accessToken, streamRequest{
		Delivery:        Delivery{Method: deliveryMethodPoll},
		EventsRequested: []string{EventCAEPSessionRevoked},
	})
	if status != http.StatusCreated {
		t.Fatalf("POST /ssf/stream: status = %d, body = %v", status, streamResp)
	}
	streamID, _ := streamResp["stream_id"].(string)

	// Simulate a config reload that keeps the same client id but changes
	// its secret and re-declares its allowed scopes/events.
	newClient := s.NewClient(ssfClientID, "new-secret")
	newClient.AddAllowedRedirectURIs("http://client.example.com/callback")
	newClient.AddAllowedScopes("offline_access", "ssf.manage", "ssf.read")
	newClient.AddSSFEventsSupported(EventCAEPSessionRevoked)

	// The old access token's bearer auth is unaffected (the signing key
	// didn't change), and the stream -- keyed by client id, not by the
	// *Client value -- is still there under the freshly configured client.
	status, streamResp = ssfDo(t, s, http.MethodGet, "/ssf/stream?stream_id="+streamID, accessToken, nil)
	if status != http.StatusOK {
		t.Fatalf("GET /ssf/stream after re-registering the client: status = %d, body = %v", status, streamResp)
	}
	if streamResp["stream_id"] != streamID {
		t.Errorf("stream_id = %v, want %s", streamResp["stream_id"], streamID)
	}

	// The old secret must no longer authenticate a fresh /token call.
	form := url.Values{"grant_type": {"authorization_code"}, "code": {"whatever"}, "redirect_uri": {"http://client.example.com/callback"}}
	req := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(ssfClientID, ssfClientSecret) // the OLD secret
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	var tokBody map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &tokBody); err != nil {
		t.Fatalf("POST /token: invalid JSON: %v (body=%s)", err, rec.Body.String())
	}
	if tokBody["error"] != "invalid_client" {
		t.Errorf("POST /token with the old secret after re-registering the client: error = %v, want invalid_client", tokBody["error"])
	}
}

func TestSSFRejectsRequestWhenClientRemovedAfterTokenIssuance(t *testing.T) {
	s := newSSFTestServer(t)
	body := ssfExchangeCode(t, s, "openid ssf.manage ssf.read")
	accessToken, _ := body["access_token"].(string)

	if !s.RemoveClient(ssfClientID) {
		t.Fatal("RemoveClient returned false, want true")
	}

	// The bearer token is still validly signed and unexpired; only the
	// client it names no longer exists. This must fail cleanly, not panic.
	status, resp := ssfDo(t, s, http.MethodPost, "/ssf/stream", accessToken, streamRequest{
		Delivery:        Delivery{Method: deliveryMethodPoll},
		EventsRequested: []string{EventCAEPSessionRevoked},
	})
	if status != http.StatusUnauthorized {
		t.Fatalf("POST /ssf/stream with a removed client's token: status = %d, body = %v", status, resp)
	}
}

// TestRemoveClientPurgesRefreshTokensAndSSFStreams guards against a
// removed client id being reused (e.g. for a completely unrelated
// client) and silently inheriting refresh tokens or SSF streams left
// behind by whoever previously had that id.
func TestRemoveClientPurgesRefreshTokensAndSSFStreams(t *testing.T) {
	s := newSSFTestServer(t)
	body := ssfExchangeCode(t, s, "openid offline_access ssf.manage ssf.read")
	accessToken, _ := body["access_token"].(string)
	refreshToken, _ := body["refresh_token"].(string)
	if refreshToken == "" {
		t.Fatal("expected a refresh_token, got none")
	}

	status, streamResp := ssfDo(t, s, http.MethodPost, "/ssf/stream", accessToken, streamRequest{
		Delivery:        Delivery{Method: deliveryMethodPoll},
		EventsRequested: []string{EventCAEPSessionRevoked},
	})
	if status != http.StatusCreated {
		t.Fatalf("POST /ssf/stream: status = %d, body = %v", status, streamResp)
	}
	streamID, _ := streamResp["stream_id"].(string)

	if !s.RemoveClient(ssfClientID) {
		t.Fatal("RemoveClient returned false, want true")
	}

	// A brand new client reusing the same id -- unrelated to the one just
	// removed -- must not inherit anything.
	newClient := s.NewClient(ssfClientID, ssfClientSecret)
	newClient.AddAllowedRedirectURIs("http://client.example.com/callback")
	newClient.AddAllowedScopes("ssf.manage", "ssf.read")

	if _, refreshed := ssfRefreshToken(t, s, refreshToken); refreshed["error"] != "invalid_grant" {
		t.Errorf("refresh_token issued before RemoveClient still works: error = %v, want invalid_grant", refreshed["error"])
	}

	newBody := ssfExchangeCode(t, s, "openid ssf.manage ssf.read")
	newAccessToken, _ := newBody["access_token"].(string)
	status, resp := ssfDo(t, s, http.MethodGet, "/ssf/stream?stream_id="+streamID, newAccessToken, nil)
	if status != http.StatusNotFound {
		t.Errorf("GET /ssf/stream for a stream from before RemoveClient: status = %d, body = %v (want 404, it should have been purged)", status, resp)
	}
}

// TestNewClientConcurrentWithAuth exercises re-registering a client via
// NewClient and a Client's AddAllowed* methods concurrently with /auth
// requests reading that same Client's configuration. It doesn't assert
// much about the outcome of any single request (both "success" and
// "unregistered redirect_uri" are valid depending on timing) -- its
// purpose is to give `go test -race` a real chance to catch a data race
// if one exists.
func TestNewClientConcurrentWithAuth(t *testing.T) {
	s := newTestServer(t)
	done := make(chan struct{})
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for range 200 {
			c := s.NewClient("test-client", "test-secret")
			c.AddAllowedRedirectURIs("http://client.example.com/callback")
			c.AddAllowedScopes("token")
			c.AddAllowedRoles("staff")
		}
		close(done)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		q := url.Values{
			"client_id":     {"test-client"},
			"redirect_uri":  {"http://client.example.com/callback"},
			"response_type": {"code"},
			"scope":         {"openid"},
		}
		for {
			select {
			case <-done:
				return
			default:
			}
			req := httptest.NewRequest(http.MethodGet, "/oidc/auth?"+q.Encode(), nil)
			rec := httptest.NewRecorder()
			s.ServeHTTP(rec, req)
		}
	}()

	wg.Wait()
}
