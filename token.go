package jambo

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/go-jose/go-jose/v4"
)

func (s *Server) openIDToken(w http.ResponseWriter, r *http.Request) {
	grantType := r.PostFormValue("grant_type")
	if grantType != "authorization_code" {
		fmt.Printf("error in token endpoint: grant_type=%q\n", grantType)
		return
	}
	code := r.PostFormValue("code")
	redirectURI := r.PostFormValue("redirect_uri")
	clientID := r.PostFormValue("client_id")
	clientSecret := r.PostFormValue("client_secret")

	fmt.Printf("code=%q redirect_uri=%q client_id=%q client_secret=%q\n",
		code, redirectURI, clientID, clientSecret)

	idToken, err := s.getIDToken()
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

func (s *Server) getIDToken() (jws string, err error) {
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
