package jambo

import (
	"crypto/rand"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

func (s *Server) openIDAuth(w http.ResponseWriter, r *http.Request) {
	var err error

	// OpenID Connect requests MUST contain the openid scope value
	scopes := strings.Fields(r.FormValue("scope"))
	if !slices.Contains(scopes, "openid") {
		s.template("error", w, map[string]string{"error": "`openid` scope not specidied"})
		return
	}

	// we only support response_type = "code"
	if r.FormValue("response_type") != "code" {
		s.template("error", w, map[string]string{"error": "`response_type` must be `code`"})
		return
	}

	clientID := r.FormValue("client_id")
	redirectURI := r.FormValue("redirect_uri")
	state := r.FormValue("state")

	fmt.Fprintln(w, `<!DOCTYPE html>
<html>
	<head>
		<title>OpenID Authentication</title>
	</head>
	<body>
		<pre>`)
	fmt.Fprintln(w, "<pre>")
	fmt.Fprintf(w, "Client ID: %q\n", clientID)
	fmt.Fprintf(w, "Redirect URI: %q\n", redirectURI)
	fmt.Fprintf(w, "State: %q\n", state)
	code := rand.Text()
	fmt.Fprintf(w, "Random Code: %q\n", code)
	u, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, fmt.Sprintf("redirect_uri: %v", err.Error), http.StatusBadRequest)
		return
	}
	q := u.Query()
	q.Set("code", code)
	q.Set("state", state)
	u.RawQuery = q.Encode()
	fmt.Fprintf(w, "<a href=\"%s\">click me</a>\n", u)
	fmt.Fprintln(w, `</pre>
	</body>
</html>`)
}
