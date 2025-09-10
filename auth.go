package jambo

import (
	"crypto/rand"
	"fmt"
	"log"
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
			"ErrorType": `Bad request`,
			"Error":     `Missing required field "client_id"`,
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
			"Error": fmt.Sprintf(`unknown client "%s"`, clientID),
		})
		return
	}

	// OpenID Connect requests MUST contain the "openid" scope value
	if !slices.Contains(conn.scopes, "openid") {
		s.template(w, r, "error.html", map[string]string{
			"ErrorType": "Bad request",
			"Error":     `Missing required scope: "openid"`,
		})
		return
	}

	// All other scopes are optional.
	// If a client sends an unrecognized scope, we send an error.
	for _, scope := range conn.scopes {
		if !slices.Contains(scopesSupported, scope) && !slices.Contains(conn.client.allowedScopes, scope) {
			s.template(w, r, "error.html", map[string]string{
				"ErrorType": "Bad request",
				"Error":     `Unrecognized scope: "` + scope + `"`,
			})
			return
		}
	}

	// We only support response_type = "code"
	if r.FormValue("response_type") != "code" {
		s.template(w, r, "error.html", map[string]string{
			"Error": `Field "response_type" must be "code"`,
		})
		return
	}

	if !slices.Contains(conn.client.allowedRedirectURIs, conn.redirectURI) {
		s.template(w, r, "error.html", map[string]string{
			"Error": fmt.Sprintf(`Unregistered redirect_uri ("%s")`, conn.redirectURI),
		})
		return
	}

	s.Lock()
	s.connections[conn.code] = conn
	s.Unlock()

	s.template(w, r, "login.html", map[string]string{
		"PostURL": filepath.Join(s.root, "/auth/login"),
		"code":    conn.code,
		"state":   conn.state,
	})
}

// openIDAuthLogin is the action called from the "form" where user sends login and password
func (s *Server) openIDAuthLogin(w http.ResponseWriter, r *http.Request) {
	login := r.FormValue("login")
	password := r.FormValue("password")
	code := r.FormValue("code")

	s.Lock()
	conn, ok := s.connections[code]
	s.Unlock()

	if !ok {
		s.template(w, r, "error.html", map[string]string{
			"ErrorType": "Bad request",
			"Error":     fmt.Sprintf(`Invalid code %q from request`, code),
		})
		return
	}

	req := Request{
		Type:     RequestTypeUserPassword,
		Client:   conn.client.id,
		User:     login,
		Password: password,
		Scopes:   conn.scopes,
	}
	var resp Response
	for name, auth := range s.authenticators {
		log.Println("jambo: calling auth[%s]", name)
		resp = auth(&req)
		if resp.Type != ResponseTypeInvalid && resp.Type != ResponseTypeLoginFailed {
			break
		}
	}

	conn.response = resp
	s.Lock()
	s.connections[code] = conn
	s.Unlock()

	switch resp.Type {
	case ResponseTypeLoginFailed:
		s.template(w, r, "login.html", map[string]string{
			"PostURL": filepath.Join(s.root, "/auth/login"),
			"code":    code,
			"state":   conn.state,
			"Invalid": "true",
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
	case ResponseType2FANeeded:
		if len(resp.MFAMethods) <= 0 {
			s.template(w, r, "error.html", map[string]string{
				"ErrorType": `Bad response from callback`,
				"Error":     `ResponseType2FANeeded but no MFA methods provided`,
			})
			return
		}

		s.template(w, r, "mfa-select.html", map[string]string{
			"code":    code,
			"state":   conn.state,
			"methods": strings.Join(resp.MFAMethods, ","),
			"name":    resp.Name,
		})
	default:
		s.template(w, r, "error.html", map[string]string{
			"ErrorType": `Bad response from callback`,
			"Error":     fmt.Sprintf(`unknown response type %d`, resp.Type),
		})
		return
	}
}
