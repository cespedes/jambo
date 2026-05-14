package jambo

import (
	"crypto/rsa"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-jose/go-jose/v4"
)

func (s *Server) userinfo(w http.ResponseWriter, r *http.Request) {
	fields := strings.Fields(r.Header.Get("Authorization"))
	if len(fields) != 2 || fields[0] != "Bearer" {
		fmt.Fprintln(w, `{"error":"access_denied","error_description":"Invalid bearer token."}`)
		return
	}
	token := fields[1]

	parsed, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		fmt.Fprintf(w, `{"error":"access_denied","error_description1":%q}`+"\n", err.Error())
		return
	}

	output, err := parsed.Verify(&s.key.Key.(*rsa.PrivateKey).PublicKey)
	if err != nil {
		fmt.Fprintf(w, `{"error":"access_denied","error_description2":%q}`+"\n", err.Error())
		return
	}

	fmt.Fprintf(w, "%s\n", output)

	return
}
