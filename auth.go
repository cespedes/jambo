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
	clientID := r.FormValue("client_id")
	if clientID == "" {
		s.template(w, r, "error.html", map[string]string{
			"ErrorType": `Bad request`,
			"Error":     `Missing required field "client_id"`,
		})
		return
	}

	var client *Client
	for _, c := range s.clients {
		if c.ID == clientID {
			client = &c
			break
		}
	}
	if client == nil {
		s.template(w, r, "error.html", map[string]string{
			"Error": fmt.Sprintf(`unknown client "%s"`, clientID),
		})
		return
	}
	r = s.SetClient(r, client)

	// OpenID Connect requests MUST contain the openid scope value
	scopes := strings.Fields(r.FormValue("scope"))
	if !slices.Contains(scopes, "openid") {
		s.template(w, r, "error.html", map[string]string{
			"ErrorType": "Bad request",
			"Error":     `Missing required scope: "openid"`,
		})
		return
	}
	for _, scope := range scopes {
		if !slices.Contains(scopesSupported, scope) {
			s.template(w, r, "error.html", map[string]string{
				"ErrorType": "Bad request",
				"Error":     `Unrecognized scope: "` + scope + `"`,
			})
			return
		}
	}

	// we only support response_type = "code"
	if r.FormValue("response_type") != "code" {
		s.template(w, r, "error.html", map[string]string{
			"Error": `Field "response_type" must be "code"`,
		})
		return
	}

	redirectURI := r.FormValue("redirect_uri")
	if !slices.Contains(client.RedirectURIs, redirectURI) {
		s.template(w, r, "error.html", map[string]string{
			"Error": fmt.Sprintf(`Unregistered redirect_uri ("%s")`, redirectURI),
		})
		return
	}

	state := r.FormValue("state")
	code := rand.Text()

	conn := Connection{
		code:        code,
		client:      client,
		redirectURI: redirectURI,
		state:       state,
		scopes:      scopes,
	}
	s.Lock()
	s.connections[code] = conn
	s.Unlock()

	s.template(w, r, "login.html", map[string]string{
		"PostURL": filepath.Join(s.root, "/auth/login"),
		"code":    code,
		"state":   state,
	})
}

// openIDAuth is the action called from the "form" where user sends login and password
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
		Client:   conn.client.ID,
		User:     login,
		Password: password,
	}
	log.Println("jambo: calling callback")
	resp := s.callback(&req)

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
	default:
		s.template(w, r, "error.html", map[string]string{
			"ErrorType": `Bad response from callback`,
			"Error":     fmt.Sprintf(`unknown response type %d`, resp.Type),
		})
		return
	}
}
