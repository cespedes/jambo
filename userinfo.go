package jambo

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

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

	data, err := parsed.Verify(&s.key.Key.(*rsa.PrivateKey).PublicKey)
	if err != nil {
		fmt.Fprintf(w, `{"error":"access_denied","error_description2":%q}`+"\n", err.Error())
		return
	}

	var claims struct {
		Expiration int64 `json:"exp"`
	}
	if err := json.Unmarshal(data, &claims); err != nil {
		fmt.Fprintf(w, `{"error":"access_denied","error_description":%q}`+"\n", "malformed token payload")
		return
	}
	if claims.Expiration == 0 || time.Now().Unix() >= claims.Expiration {
		fmt.Fprintln(w, `{"error":"access_denied","error_description":"Token has expired."}`)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)+1))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	fmt.Fprintln(w, string(data))
}
