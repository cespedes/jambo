package jambo

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
)

// getAuthPageBody drives a GET /auth request for "test-client" and
// returns the rendered login page's body.
func getAuthPageBody(t *testing.T, s *Server) string {
	t.Helper()
	q := url.Values{
		"client_id":     {"test-client"},
		"redirect_uri":  {"http://client.example.com/callback"},
		"response_type": {"code"},
		"scope":         {"openid"},
	}
	req := httptest.NewRequest(http.MethodGet, "/oidc/auth?"+q.Encode(), nil)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /auth: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	return rec.Body.String()
}

func TestReplacePresentationOverridesTemplateAndArgs(t *testing.T) {
	s := newTestServer(t)

	before := getAuthPageBody(t, s)
	if strings.Contains(before, "custom-marker") {
		t.Fatal("default login page unexpectedly already contains custom-marker")
	}

	templatesFS := fstest.MapFS{
		"login.html": &fstest.MapFile{Data: []byte(
			`{{ template "header.html" . }}<div id="custom-marker">{{ .banner }}</div>{{ template "footer.html" . }}`,
		)},
	}
	if err := s.ReplacePresentation(nil, templatesFS, map[string]string{"banner": "hello from reload"}); err != nil {
		t.Fatalf("ReplacePresentation: %v", err)
	}

	after := getAuthPageBody(t, s)
	if !strings.Contains(after, `id="custom-marker"`) {
		t.Errorf("login page after ReplacePresentation missing custom-marker, got: %s", after)
	}
	if !strings.Contains(after, "hello from reload") {
		t.Errorf("login page after ReplacePresentation missing template arg value, got: %s", after)
	}
}

func TestReplacePresentationReplacesArgsRatherThanMerging(t *testing.T) {
	s := newTestServer(t)
	templatesFS := fstest.MapFS{
		"login.html": &fstest.MapFile{Data: []byte(
			`{{ template "header.html" . }}<div id="a">{{ .a }}</div><div id="b">{{ .b }}</div>{{ template "footer.html" . }}`,
		)},
	}
	if err := s.ReplacePresentation(nil, templatesFS, map[string]string{"a": "first", "b": "first-b"}); err != nil {
		t.Fatalf("ReplacePresentation (1st): %v", err)
	}
	if err := s.ReplacePresentation(nil, templatesFS, map[string]string{"a": "second"}); err != nil {
		t.Fatalf("ReplacePresentation (2nd): %v", err)
	}

	body := getAuthPageBody(t, s)
	if !strings.Contains(body, `id="a">second<`) {
		t.Errorf("expected the second ReplacePresentation's arg to win, got: %s", body)
	}
	if strings.Contains(body, "first-b") {
		t.Errorf("expected the first ReplacePresentation's args to be gone (replaced, not merged), got: %s", body)
	}
}

func TestReplacePresentationOverridesStaticFiles(t *testing.T) {
	s := newTestServer(t)
	staticFS := fstest.MapFS{
		"custom.txt": &fstest.MapFile{Data: []byte("hello from reload")},
	}
	if err := s.ReplacePresentation(staticFS, nil, nil); err != nil {
		t.Fatalf("ReplacePresentation: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/oidc/custom.txt", nil)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /custom.txt: status = %d", rec.Code)
	}
	if rec.Body.String() != "hello from reload" {
		t.Errorf("GET /custom.txt: body = %q", rec.Body.String())
	}

	// The embedded default static files must still be reachable: staticFS
	// layers on top of them, it doesn't replace them wholesale.
	req = httptest.NewRequest(http.MethodGet, "/oidc/css/jambo.css", nil)
	rec = httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("GET /css/jambo.css after ReplacePresentation: status = %d", rec.Code)
	}
}

func TestReplacePresentationDoesNotAffectClients(t *testing.T) {
	s := newTestServer(t)
	if err := s.ReplacePresentation(nil, nil, map[string]string{"x": "y"}); err != nil {
		t.Fatalf("ReplacePresentation: %v", err)
	}

	body := getAuthPageBody(t, s)
	if strings.Contains(body, "unknown client") {
		t.Errorf("client no longer recognized after ReplacePresentation: %s", body)
	}
}

// TestReplacePresentationConcurrentWithRequests exercises
// ReplacePresentation concurrently with requests that read the static
// files/templates/template args it replaces. It doesn't assert much
// about individual responses -- its purpose is to give `go test -race`
// a real chance to catch a data race if one exists.
func TestReplacePresentationConcurrentWithRequests(t *testing.T) {
	s := newTestServer(t)
	templatesFS := fstest.MapFS{
		"login.html": &fstest.MapFile{Data: []byte(
			`{{ template "header.html" . }}reloaded{{ template "footer.html" . }}`,
		)},
	}
	staticFS := fstest.MapFS{"x.txt": &fstest.MapFile{Data: []byte("x")}}

	done := make(chan struct{})
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for range 100 {
			_ = s.ReplacePresentation(staticFS, templatesFS, map[string]string{"k": "v"})
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
			s.ServeHTTP(httptest.NewRecorder(), req)

			req = httptest.NewRequest(http.MethodGet, "/oidc/css/jambo.css", nil)
			s.ServeHTTP(httptest.NewRecorder(), req)
		}
	}()

	wg.Wait()
}

func TestClientTemplateArgs(t *testing.T) {
	s := newTestServer(t)
	other := s.NewClient("other-client", "other-secret")
	other.AddAllowedRedirectURIs("http://other.example.com/callback")
	other.AddTemplateArgs(map[string]string{"url": "https://other.example.com/"})
	s.clientByID("test-client").AddTemplateArgs(map[string]string{
		"url":    "https://app.example.com/",
		"shared": "from-client",
		"client": "ignored",
	})

	templatesFS := fstest.MapFS{
		"login.html": &fstest.MapFile{Data: []byte(
			`<input name="session" value="{{ .session }}">client={{ .client }} url={{ .url }} shared={{ .shared }}`,
		)},
		"error.html": &fstest.MapFile{Data: []byte(`error client={{ .client }} url={{ .url }}`)},
	}
	if err := s.ReplacePresentation(nil, templatesFS, map[string]string{"shared": "global", "session": "overridden"}); err != nil {
		t.Fatal(err)
	}

	// Each client sees its own values, which win over the Server-wide ones;
	// "client" always is the client's id, and the handler's own values (here,
	// "session") win over both.
	body := getAuthPageBody(t, s)
	for _, want := range []string{"client=test-client", "url=https://app.example.com/", "shared=from-client"} {
		if !strings.Contains(body, want) {
			t.Errorf("login page of test-client missing %q, got: %s", want, body)
		}
	}
	if strings.Contains(body, `value="overridden"`) {
		t.Errorf("a Server-wide arg overrode the handler's own session value, got: %s", body)
	}

	q := url.Values{
		"client_id":     {"other-client"},
		"redirect_uri":  {"http://other.example.com/callback"},
		"response_type": {"code"},
		"scope":         {"openid"},
	}
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/oidc/auth?"+q.Encode(), nil))
	if body := rec.Body.String(); !strings.Contains(body, "client=other-client url=https://other.example.com/ shared=global") {
		t.Errorf("login page of other-client has the wrong values, got: %s", body)
	}

	// The error page of a used session still knows the client's values.
	session := sessionRe.FindStringSubmatch(body)[1]
	resp := login(t, s, session, "alice", "secret")
	loc, _ := url.Parse(resp.Header.Get("Location"))
	exchangeCode(t, s, loc.Query().Get("code"))
	resp = login(t, s, session, "alice", "secret")
	errBody, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(errBody), "error client=test-client url=https://app.example.com/") {
		t.Errorf("error page of a used session lost the client's values, got: %s", errBody)
	}

	// Re-registering the client starts it from scratch: its old args don't carry over.
	s.NewClient("test-client", "test-secret").AddAllowedRedirectURIs("http://client.example.com/callback")
	if body := getAuthPageBody(t, s); strings.Contains(body, "app.example.com") {
		t.Errorf("template args survived NewClient, got: %s", body)
	}
}
