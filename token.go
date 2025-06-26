package jambo

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/go-jose/go-jose/v4"
)

func (s *Server) openIDToken(w http.ResponseWriter, r *http.Request) {
	grantType := r.PostFormValue("grant_type")
	if grantType != "authorization_code" {
		fmt.Fprintln(w, `{"error":"unsupported_grant_type"}`)
		return
	}
	code := r.PostFormValue("code")
	if code == "" {
		fmt.Fprintln(w, `{"error":"invalid_request","error_description":"Required param: code."}`)
		return
	}
	redirectURI := r.PostFormValue("redirect_uri")
	clientID := r.PostFormValue("client_id")
	clientSecret := r.PostFormValue("client_secret")

	var client *Client
	for _, c := range s.clients {
		if c.ID == clientID && c.Secret == clientSecret {
			client = &c
			break
		}
	}

	if client == nil {
		fmt.Fprintln(w, `{"error":"invalid_client","error_description":"Invalid client credentials."}`)
		return
	}

	s.Lock()
	conn, ok := s.connections[code]
	s.Unlock()

	if !ok {
		log.Printf("invalid code=%q.  Connections: %v\n", code, s.connections)
		fmt.Fprintln(w, `{"error":"invalid_grant","error_description":"Invalid or expired code parameter."}`)
		return
	}

	if redirectURI != conn.redirectURI {
		fmt.Fprintln(w, `{"error":"invalid_request","error_description":"redirect_uri did not match URI from initial request."}`)
		return
	}

	fmt.Printf("code=%q redirect_uri=%q client_id=%q client_secret=%q\n",
		code, redirectURI, clientID, clientSecret)
	fmt.Printf("state=%q nonce=%q\n", conn.state, conn.nonce)

	idToken, err := s.getIDToken(&conn)
	if err != nil {
		http.Error(w, "Internal server error getting ID token.", http.StatusInternalServerError)
		return
	}
	response := map[string]string{
		"access_token": "foo",
		"token_type":   "Bearer",
		"id_token":     idToken,
		// "expires_in": // optional
		// "refresh_token": // optional
		// "scope": // optional
	}

	data, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		http.Error(w, "Internal server error marshaling keys.", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)+1))

	// RFC6749 section 5.1:
	// The authorization server MUST include the HTTP "Cache-Control"
	// response header field [RFC2616] with a value of "no-store" in any
	// response containing tokens, credentials, or other sensitive
	// information, as well as the "Pragma" response header field [RFC2616]
	// with a value of "no-cache"
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	fmt.Fprintln(w, string(data))
	fmt.Println("=======")
	fmt.Println(string(data))
}

// https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.2
// TODO: add support for "nonce"
type IDToken struct {
	Issuer            string `json:"iss"`
	SubjectIdentifier string `json:"sub"`
	Audience          string `json:"aud"`
	Expiration        int64  `json:"exp"`
	IssuedAt          int64  `json:"iat"`
}

func (s *Server) getIDToken(conn *Connection) (jws string, err error) {
	signingKey := jose.SigningKey{Key: s.key, Algorithm: jose.RS256}

	signer, err := jose.NewSigner(signingKey, &jose.SignerOptions{})
	if err != nil {
		return "", fmt.Errorf("new signer: %v", err)
	}

	idToken := IDToken{
		Issuer:            s.issuer,
		SubjectIdentifier: "example-app",
		Audience:          "example-app",
		Expiration:        time.Now().Unix() + 3600, // expires in 1 hour
		IssuedAt:          time.Now().Unix(),
	}
	b, err := json.Marshal(idToken)
	if err != nil {
		return "", err
	}

	signature, err := signer.Sign(b)
	if err != nil {
		return "", fmt.Errorf("signing payload: %v", err)
	}
	return signature.CompactSerialize()
}
