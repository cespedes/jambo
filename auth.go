package jambo

import (
	"crypto/rand"
	"fmt"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
)

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
	}
	s.Lock()
	s.connections = append(s.connections, conn)
	s.Unlock()

	s.template(w, r, "login.html", map[string]string{
		"PostURL": filepath.Join(s.root, "/auth/login"),
		"code":    code,
		"state":   state,
	})
}

func (s *Server) openIDAuthLogin(w http.ResponseWriter, r *http.Request) {
	login := r.FormValue("login")
	password := r.FormValue("password")
	code := r.FormValue("code")

	var conn Connection

	s.Lock()
	for i := range s.connections {
		if code == s.connections[i].code {
			conn = s.connections[i]
		}
	}
	s.Unlock()

	if conn == (Connection{}) {
		s.template(w, r, "error.html", map[string]string{
			"ErrorType": "Bad request",
			"Error":     fmt.Sprintf(`Invalid code %q from request`, code),
		})
		return
	}

	if login == "admin" && password == "secret" {
		fmt.Fprintf(w, "login=%q password=%q conn=%v\n", login, password, conn)
		return
	}

	s.template(w, r, "login.html", map[string]string{
		"PostURL": filepath.Join(s.root, "/auth/login"),
		"code":    code,
		"state":   conn.state,
		"Invalid": "true",
	})
}
