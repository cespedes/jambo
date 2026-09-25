package jambo

import (
	"crypto/rand"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// openIDAuth is the handler for the Authorization endpoint ("/auth")
func (s *Server) openIDAuth(w http.ResponseWriter, r *http.Request) {
	conn := Connection{
		code:                rand.Text(),
		created:             time.Now(),
		redirectURI:         r.FormValue("redirect_uri"),
		state:               r.FormValue("state"),
		nonce:               r.FormValue("nonce"),
		scopes:              strings.Fields(r.FormValue("scope")),
		codeChallenge:       r.FormValue("code_challenge"),
		codeChallengeMethod: r.FormValue("code_challenge_method"),
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

	conn.client = s.clientByID(clientID)
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
		if !slices.Contains(scopesSupported, scope) && !conn.client.hasAllowedScope(scope) {
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

	if !conn.client.hasAllowedRedirectURI(conn.redirectURI) {
		s.template(w, r, "error.html", map[string]string{
			"error": fmt.Sprintf(`Unregistered redirect_uri ("%s")`, conn.redirectURI),
		})
		return
	}

	// PKCE (RFC 7636) is optional: a client that does not send a
	// code_challenge gets the flow as before. A client that does send one
	// must use a method we support; the actual verifier is checked later,
	// in openIDToken.
	if conn.codeChallenge != "" {
		if conn.codeChallengeMethod == "" {
			conn.codeChallengeMethod = "plain"
		}
		if conn.codeChallengeMethod != "S256" && conn.codeChallengeMethod != "plain" {
			s.template(w, r, "error.html", map[string]string{
				"errorType": "Bad request",
				"error":     fmt.Sprintf(`Unsupported code_challenge_method: %q`, conn.codeChallengeMethod),
			})
			return
		}
	}

	s.Lock()
	s.purgeExpiredConnections()
	s.connections[conn.code] = conn
	s.Unlock()

	s.template(w, r, "login.html", map[string]string{
		"postURL": filepath.Join(s.root, "/auth/login"),
		"session": conn.code,
	})
}

// authLogin is the handler for "POST /auth/login", the login form's
// submission. It looks up the pending Connection by the "session" form
// value, calls the host's authenticator with every submitted field, and
// dispatches on the resulting Response.Type.
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
	if ok && conn.expired() {
		delete(s.connections, session)
		ok = false
	}
	s.Unlock()

	if !ok {
		s.template(w, r, "error.html", map[string]string{
			"errorType": "Bad request",
			"error":     fmt.Sprintf(`Invalid session %q from request`, session),
		})
		return
	}

	req := Request{
		Session: session,
		Client:  conn.client.id,
		Scopes:  conn.scopes,
		Roles:   conn.client.allowedRolesSnapshot(),
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
	case ResponseTypeLoginOK:
		u, err := url.Parse(conn.redirectURI)
		if err != nil {
			http.Error(w, fmt.Sprintf("redirect_uri: %v", err), http.StatusBadRequest)
			return
		}
		q := u.Query()
		q.Set("code", conn.code)
		q.Set("state", conn.state)
		u.RawQuery = q.Encode()
		http.Redirect(w, r, u.String(), http.StatusFound)
		return
	case ResponseTypeLoginFailed:
		s.template(w, r, "login.html", map[string]string{
			"postURL":     filepath.Join(s.root, "/auth/login"),
			"session":     session,
			"login":       resp.Login,
			"error":       resp.Error,
			"loginFailed": "true",
		})
		return
	case ResponseTypeRedirect:
		m := map[string]string{
			"postURL": filepath.Join(s.root, "/auth/login"),
			"session": session,
		}
		maps.Copy(m, resp.Params)
		s.template(w, r, resp.Redirect, m)
		return
	default:
		s.template(w, r, "error.html", map[string]string{
			"errorType": `Bad response from callback`,
			"error":     fmt.Sprintf(`unknown response type %d`, resp.Type),
		})
		return
	}
}

// Request is a message sent from the OIDC server to the authenticator,
// asking whether the given credentials are valid.
type Request struct {
	Session string            // unique ID for this login attempt.
	Client  string            // id of the OIDC client the user is signing in to.
	Scopes  []string          // scopes the user has requested
	Roles   []string          // roles allowed to sign in through Client; the authenticator should check the user belongs to at least one
	Params  map[string]string // form parameters submitted by the user (e.g. login, password, OTP)
}

// Response is sent from the authenticator to the OIDC server, answering a Request.
type Response struct {
	Type ResponseType

	// If Type == ResponseTypeLoginFailed we can send an error to the user:
	Error string

	// If Type == ResponseTypeRedirect we need the name of the next template
	// and the list of params that will be used to call it:
	Redirect string
	Params   map[string]string

	// Standard claims:

	// Login is the user's login/username, usually the same value sent in
	// the request. Used in claims "sub" and "preferred_username".
	Login string

	// Name is the user's full name (given name and surname). Used in claim "name".
	Name string

	// First and last name.  Used in claims "given_name" and "family_name".
	// Some relying parties (e.g. Apple Business Manager) require these
	// even when "name" is also set.
	GivenName  string
	FamilyName string

	// e-mail address.  Used in claim "email".
	Mail string

	// Other claims:
	Claims map[string]any
}

// ResponseType is the kind of answer a Response carries; see the
// ResponseType* constants.
type ResponseType int

const (
	ResponseTypeInvalid     ResponseType = iota // zero value; an authenticator should never return this
	ResponseTypeLoginOK                         // login is successful
	ResponseTypeLoginFailed                     // login failed
	ResponseTypeRedirect                        // login is OK so far, but we are not finished yet
)
