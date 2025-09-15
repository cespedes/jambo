package jambo

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/iancoleman/orderedmap"
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
		if c.id == clientID && c.secret == clientSecret {
			client = c
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
		"access_token": rand.Text(), // we are not using this; any value should be OK
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
}

// https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.2
type IDToken struct {
	// Standard claims:
	Issuer            string `json:"iss"`
	SubjectIdentifier string `json:"sub"`
	Audience          string `json:"aud"`
	Expiration        int64  `json:"exp"`
	IssuedAt          int64  `json:"iat"`
	Nonce             string `json:"nonce,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
	Name              string `json:"name,omitempty"`
	Email             string `json:"email,omitempty"`
	EmailVerified     bool   `json:"email_verified,omitempty"`

	// Other claims:
	Claims map[string]any
}

func (idt IDToken) MarshalJSON() ([]byte, error) {
	// an Event will be marshaled with all its keys next to those in Extra.
	om := orderedmap.New()
	om.Set("iss", idt.Issuer)
	om.Set("sub", idt.SubjectIdentifier)
	om.Set("aud", idt.Audience)
	om.Set("exp", idt.Expiration)
	if idt.Nonce != "" {
		om.Set("nonce", idt.Nonce)
	}
	if idt.PreferredUsername != "" {
		om.Set("preferred_username", idt.PreferredUsername)
	}
	if idt.Name != "" {
		om.Set("name", idt.Name)
	}
	if idt.Email != "" {
		om.Set("email", idt.Email)
	}
	if idt.EmailVerified {
		om.Set("email_verified", idt.EmailVerified)
	}

	for k, v := range idt.Claims {
		om.Set(k, v)
	}
	return json.Marshal(om)
}

func (s *Server) getIDToken(conn *Connection) (jws string, err error) {
	signingKey := jose.SigningKey{Key: s.key, Algorithm: jose.RS256}

	signer, err := jose.NewSigner(signingKey, &jose.SignerOptions{})
	if err != nil {
		return "", fmt.Errorf("new signer: %v", err)
	}

	idToken := IDToken{
		Issuer:            s.issuer,
		SubjectIdentifier: conn.response.Login,
		Audience:          conn.client.id,
		Expiration:        time.Now().Unix() + 3600, // expires in 1 hour
		IssuedAt:          time.Now().Unix(),
		Nonce:             conn.nonce,
	}
	if slices.Contains(conn.scopes, scopeProfile) {
		idToken.Name = conn.response.Name
		idToken.PreferredUsername = conn.response.Login
	}
	if slices.Contains(conn.scopes, scopeEmail) {
		idToken.Email = conn.response.Mail
		if idToken.Email != "" {
			idToken.EmailVerified = true
		}
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
