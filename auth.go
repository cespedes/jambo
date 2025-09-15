package jambo

import (
	"crypto/rand"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
)

// openIDAuth is the handler for the Authorization endpoint ("/auth")
func (s *Server) openIDAuth(w http.ResponseWriter, r *http.Request) {
	conn := Connection{
		code:        rand.Text(),
		redirectURI: r.FormValue("redirect_uri"),
		state:       r.FormValue("state"),
		scopes:      strings.Fields(r.FormValue("scope")),
	}
	r = s.SetConnection(r, &conn)

	clientID := r.FormValue("client_id")
	if clientID == "" {
		s.template(w, r, "error.html", map[string]string{
			"errorType": `Bad request`,
			"error":     `Missing required field "client_id"`,
		})
		return
	}

	for _, c := range s.clients {
		if c.id == clientID {
			conn.client = c
			break
		}
	}
	if conn.client == nil {
		s.template(w, r, "error.html", map[string]string{
			"error": fmt.Sprintf(`unknown client "%s"`, clientID),
		})
		return
	}

	// OpenID Connect requests MUST contain the "openid" scope value
	if !slices.Contains(conn.scopes, "openid") {
		s.template(w, r, "error.html", map[string]string{
			"errorType": "Bad request",
			"error":     `Missing required scope: "openid"`,
		})
		return
	}

	// All other scopes are optional.
	// If a client sends an unrecognized scope, we send an error.
	for _, scope := range conn.scopes {
		if !slices.Contains(scopesSupported, scope) && !slices.Contains(conn.client.allowedScopes, scope) {
			s.template(w, r, "error.html", map[string]string{
				"errorType": "Bad request",
				"error":     `Unrecognized scope: "` + scope + `"`,
			})
			return
		}
	}

	// We only support response_type = "code"
	if r.FormValue("response_type") != "code" {
		s.template(w, r, "error.html", map[string]string{
			"error": `Field "response_type" must be "code"`,
		})
		return
	}

	if !slices.Contains(conn.client.allowedRedirectURIs, conn.redirectURI) {
		s.template(w, r, "error.html", map[string]string{
			"error": fmt.Sprintf(`Unregistered redirect_uri ("%s")`, conn.redirectURI),
		})
		return
	}

	s.Lock()
	s.connections[conn.code] = conn
	s.Unlock()

	s.template(w, r, "login.html", map[string]string{
		"postURL": filepath.Join(s.root, "/auth/login"),
		"session": conn.code,
	})
}

// authLogin is the action called from the "form" where user has authenticated.
// It should have the value "session" (and probably a few more) in the query
func (s *Server) authLogin(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		s.template(w, r, "error.html", map[string]string{
			"errorType": "Internal Server Error",
			"error":     fmt.Sprintf(`error parsing form values: %v`, err),
		})
		return
	}
	session := r.FormValue("session")

	s.Lock()
	conn, ok := s.connections[session]
	s.Unlock()

	if !ok {
		s.template(w, r, "error.html", map[string]string{
			"error_type": "Bad request",
			"error":      fmt.Sprintf(`Invalid session %q from request`, session),
		})
		return
	}

	req := Request{
		Session: session,
		Client:  conn.client.id,
		Scopes:  conn.scopes,
	}
	req.Params = make(map[string]string)
	for key := range r.Form {
		req.Params[key] = r.Form.Get(key)
	}

	resp := s.authenticator(&req)

	conn.response = resp

	s.Lock()
	s.connections[session] = conn
	s.Unlock()

	switch resp.Type {
	case ResponseTypeLoginFailed:
		s.template(w, r, "login.html", map[string]string{
			"postURL":     filepath.Join(s.root, "/auth/login"),
			"session":     session,
			"login":       resp.Login,
			"loginFailed": "true",
		})
		return
	case ResponseTypeLoginOK:
		u, err := url.Parse(conn.redirectURI)
		if err != nil {
			http.Error(w, fmt.Sprintf("redirect_uri: %v", err), http.StatusBadRequest)
		}
		q := u.Query()
		q.Set("code", conn.code)
		q.Set("state", conn.state)
		u.RawQuery = q.Encode()
		http.Redirect(w, r, u.String(), http.StatusFound)
		return
	default:
		s.template(w, r, "error.html", map[string]string{
			"errorType": `Bad response from callback`,
			"error":     fmt.Sprintf(`unknown response type %d`, resp.Type),
		})
		return
	}
}

// A Request is a message sent from the OIDC server to the authenticator,
// asking if a given credentials are valid
type Request struct {
	Session string // unique ID for this user.
	Client  string
	Scopes  []string // scopes the user has requested
	Params  map[string]string
}

// A Response is sent from the authenticator to the OIDC server, answering a Request.
type Response struct {
	Type ResponseType // the following fields depend on this type:

	// Standard claims:

	// login for the user. It is usually the same sent in the request.
	// Used in claims "sub" and "preferred_username".
	Login string

	// User name and surname.  Used in claim "name".
	Name string

	// e-mail address.  Used in claim "email".
	Mail string

	// Roles is used as permissions to know what clients this user can use.
	Roles []string

	// Other claims:
	Claims map[string]any
}

type ResponseType int

const (
	ResponseTypeInvalid     ResponseType = iota
	ResponseTypeLoginOK                  // login is successful
	ResponseTypeLoginFailed              // login failed
	ResponseTypeRedirect                 // login is OK so far, but we are not finished yet
)
