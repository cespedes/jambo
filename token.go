package jambo

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/iancoleman/orderedmap"
)

// RefreshToken is the state kept for a refresh token issued when a client
// requests the "offline_access" scope (which it must first be granted via
// Client.AddAllowedScopes). It is persisted through Server's Storage,
// since -- unlike the short-lived authorization code -- it is meant to
// outlive a single login and, often, a process restart.
type RefreshToken struct {
	Token    string   // the opaque bearer value the client presents at /token
	ClientID string   // the client it was issued to
	Scopes   []string // the scopes it was granted, reused for every token it's redeemed for
	Response Response // carries the login/name/mail/claims to reissue tokens from
}

// openIDToken handles "POST /token", dispatching to
// tokenAuthorizationCode or tokenRefreshToken by grant_type.
func (s *Server) openIDToken(w http.ResponseWriter, r *http.Request) {
	switch r.PostFormValue("grant_type") {
	case "authorization_code":
		s.tokenAuthorizationCode(w, r)
	case "refresh_token":
		s.tokenRefreshToken(w, r)
	default:
		if s.debug {
			log.Printf("%s POST /token: unsupported grant_type %q\n", r.RemoteAddr, r.PostFormValue("grant_type"))
		}
		fmt.Fprintln(w, `{"error":"unsupported_grant_type"}`)
	}
}

// authenticateClient authenticates the client making a /token request,
// either via HTTP Basic Authentication (RFC 6749 section 2.3.1) or via
// client_id/client_secret form parameters.
func (s *Server) authenticateClient(r *http.Request) (*Client, error) {
	clientID, clientSecret, ok := r.BasicAuth()
	if ok {
		var err error
		if clientID, err = url.QueryUnescape(clientID); err != nil {
			return nil, fmt.Errorf("client_id improperly encoded")
		}
		if clientSecret, err = url.QueryUnescape(clientSecret); err != nil {
			return nil, fmt.Errorf("client_secret improperly encoded")
		}
	} else {
		clientID = r.PostFormValue("client_id")
		clientSecret = r.PostFormValue("client_secret")
	}

	c := s.clientByID(clientID)
	if c == nil || subtle.ConstantTimeCompare([]byte(c.secret), []byte(clientSecret)) != 1 {
		return nil, fmt.Errorf("invalid client credentials")
	}
	return c, nil
}

// tokenAuthorizationCode handles "grant_type=authorization_code" at
// /token (RFC 6749 section 4.1.3): redeems a code for an ID/access token
// and, if the client requested "offline_access", a refresh token.
func (s *Server) tokenAuthorizationCode(w http.ResponseWriter, r *http.Request) {
	code := r.PostFormValue("code")
	if code == "" {
		if s.debug {
			log.Printf("%s POST /token: empty code\n", r.RemoteAddr)
		}
		fmt.Fprintln(w, `{"error":"invalid_request","error_description":"Required param: code."}`)
		return
	}
	redirectURI := r.PostFormValue("redirect_uri")

	client, err := s.authenticateClient(r)
	if err != nil {
		if s.debug {
			log.Printf("%s POST /token: %v\n", r.RemoteAddr, err)
		}
		fmt.Fprintln(w, `{"error":"invalid_client","error_description":"Invalid client credentials."}`)
		return
	}

	s.Lock()
	conn, ok := s.connections[code]
	if ok {
		// An authorization code MUST NOT be used more than once (RFC 6749, section 4.1.2).
		delete(s.connections, code)
		if conn.expired() {
			ok = false
		}
	}
	s.Unlock()

	if !ok {
		if s.debug {
			log.Printf("%s POST /token: invalid code=%q\n", r.RemoteAddr, code)
		}
		fmt.Fprintln(w, `{"error":"invalid_grant","error_description":"Invalid or expired code parameter."}`)
		return
	}

	// The authorization code MUST have been issued to the client now
	// presenting it (RFC 6749 section 4.1.3) -- otherwise any registered
	// client could redeem a code that leaked from a completely different
	// client's flow (e.g. via a referrer leak) using its own credentials.
	if conn.client.id != client.id {
		if s.debug {
			log.Printf("%s POST /token: code was issued to client %q, not %q\n", r.RemoteAddr, conn.client.id, client.id)
		}
		fmt.Fprintln(w, `{"error":"invalid_grant","error_description":"Authorization code was not issued to this client."}`)
		return
	}

	if redirectURI != conn.redirectURI {
		if s.debug {
			log.Printf("%s POST /token: invalid redirect_uri=%q\n", r.RemoteAddr, redirectURI)
		}
		fmt.Fprintln(w, `{"error":"invalid_request","error_description":"redirect_uri did not match URI from initial request."}`)
		return
	}

	// If the client used PKCE in /auth, it must now prove it holds the
	// code_verifier matching the code_challenge it sent there.
	if conn.codeChallenge != "" {
		codeVerifier := r.PostFormValue("code_verifier")
		if !validPKCEVerifier(conn.codeChallengeMethod, conn.codeChallenge, codeVerifier) {
			if s.debug {
				log.Printf("%s POST /token: invalid code_verifier\n", r.RemoteAddr)
			}
			fmt.Fprintln(w, `{"error":"invalid_grant","error_description":"Invalid or missing code_verifier."}`)
			return
		}
	}

	idToken, err := s.getIDToken(&conn)
	if err != nil {
		http.Error(w, "Internal server error getting ID token.", http.StatusInternalServerError)
		return
	}
	response := map[string]string{
		"access_token": idToken, // this is used by "/userinfo" to return the claims
		"token_type":   "Bearer",
		"id_token":     idToken,
		"scope":        strings.Join(conn.scopes, " "),
		// "expires_in": // optional
	}

	// A client that requested (and is allowed) the "offline_access" scope
	// gets a refresh token it can later redeem via grant_type=refresh_token,
	// without the user being present.
	if slices.Contains(conn.scopes, "offline_access") {
		refreshToken := rand.Text()
		rt := RefreshToken{Token: refreshToken, ClientID: client.id, Scopes: conn.scopes, Response: conn.response}
		if err := s.storage.SaveRefreshToken(rt); err != nil {
			http.Error(w, "Internal server error saving refresh token.", http.StatusInternalServerError)
			return
		}
		response["refresh_token"] = refreshToken
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

// validPKCEVerifier checks a PKCE code_verifier (RFC 7636 section 4.6)
// against the code_challenge stored for the connection.
func validPKCEVerifier(method, challenge, verifier string) bool {
	if verifier == "" {
		return false
	}
	var computed string
	switch method {
	case "S256":
		h := sha256.Sum256([]byte(verifier))
		computed = base64.RawURLEncoding.EncodeToString(h[:])
	default: // "plain"
		computed = verifier
	}
	return subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) == 1
}

// IDToken is the set of claims signed into the JWS jambo issues as both
// "id_token" and "access_token" (see signToken). See
// https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.2.
type IDToken struct {
	// Standard claims:
	Issuer            string `json:"iss"`
	SubjectIdentifier string `json:"sub"`
	Audience          string `json:"aud"`
	Expiration        int64  `json:"exp"`
	IssuedAt          int64  `json:"iat"`
	Scope             string `json:"scope,omitempty"`
	Nonce             string `json:"nonce,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
	Name              string `json:"name,omitempty"`
	GivenName         string `json:"given_name,omitempty"`
	FamilyName        string `json:"family_name,omitempty"`
	Email             string `json:"email,omitempty"`
	EmailVerified     bool   `json:"email_verified,omitempty"`

	// Other claims:
	Claims map[string]any
}

// MarshalJSON implements [json.Marshaler], emitting the standard claims
// in a fixed, spec-friendly order followed by whatever is in idt.Claims.
func (idt IDToken) MarshalJSON() ([]byte, error) {
	om := orderedmap.New()
	om.Set("iss", idt.Issuer)
	om.Set("sub", idt.SubjectIdentifier)
	om.Set("aud", idt.Audience)
	om.Set("exp", idt.Expiration)
	om.Set("iat", idt.IssuedAt)
	if idt.Scope != "" {
		om.Set("scope", idt.Scope)
	}
	if idt.Nonce != "" {
		om.Set("nonce", idt.Nonce)
	}
	if idt.PreferredUsername != "" {
		om.Set("preferred_username", idt.PreferredUsername)
	}
	if idt.Name != "" {
		om.Set("name", idt.Name)
	}
	if idt.GivenName != "" {
		om.Set("given_name", idt.GivenName)
	}
	if idt.FamilyName != "" {
		om.Set("family_name", idt.FamilyName)
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
	return s.signToken(conn.client.id, conn.scopes, conn.nonce, conn.response)
}

// signToken builds and signs an ID/access token (they are the same JWS:
// see the comment on "access_token" in tokenAuthorizationCode) for the
// given client, granted scopes, OIDC nonce (empty outside the initial
// authorization_code exchange) and authenticator response.
func (s *Server) signToken(clientID string, scopes []string, nonce string, resp Response) (jws string, err error) {
	signingKey := jose.SigningKey{Key: s.key, Algorithm: jose.RS256}

	signer, err := jose.NewSigner(signingKey, &jose.SignerOptions{})
	if err != nil {
		return "", fmt.Errorf("new signer: %v", err)
	}

	idToken := IDToken{
		Issuer:            s.issuer,
		SubjectIdentifier: resp.Login,
		Audience:          clientID,
		Expiration:        time.Now().Unix() + 3600, // expires in 1 hour
		IssuedAt:          time.Now().Unix(),
		Scope:             strings.Join(scopes, " "),
		Nonce:             nonce,
	}
	if slices.Contains(scopes, scopeProfile) {
		idToken.Name = resp.Name
		idToken.GivenName = resp.GivenName
		idToken.FamilyName = resp.FamilyName
		idToken.PreferredUsername = resp.Login
	}
	if slices.Contains(scopes, scopeEmail) {
		idToken.Email = resp.Mail
		if idToken.Email != "" {
			idToken.EmailVerified = true
		}
	}

	if len(resp.Claims) > 0 {
		idToken.Claims = resp.Claims
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

// verifySignedToken parses and verifies a compact JWS previously issued by
// this Server (an ID/access token or a Security Event Token), returning
// its raw, still-JSON-encoded claims.
func (s *Server) verifySignedToken(token string) ([]byte, error) {
	parsed, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		return nil, err
	}
	return parsed.Verify(&s.key.Key.(*rsa.PrivateKey).PublicKey)
}

// tokenRefreshToken handles "grant_type=refresh_token" at /token (RFC 6749
// section 6). The refresh token is rotated: redeeming it invalidates it
// and returns a new one.
func (s *Server) tokenRefreshToken(w http.ResponseWriter, r *http.Request) {
	client, err := s.authenticateClient(r)
	if err != nil {
		if s.debug {
			log.Printf("%s POST /token: %v\n", r.RemoteAddr, err)
		}
		fmt.Fprintln(w, `{"error":"invalid_client","error_description":"Invalid client credentials."}`)
		return
	}

	refreshToken := r.PostFormValue("refresh_token")
	if refreshToken == "" {
		fmt.Fprintln(w, `{"error":"invalid_request","error_description":"Required param: refresh_token."}`)
		return
	}

	rt, ok, err := s.storage.GetRefreshToken(refreshToken)
	if err != nil {
		http.Error(w, "Internal server error reading refresh token.", http.StatusInternalServerError)
		return
	}
	if !ok || rt.ClientID != client.id {
		if s.debug {
			log.Printf("%s POST /token: invalid refresh_token\n", r.RemoteAddr)
		}
		fmt.Fprintln(w, `{"error":"invalid_grant","error_description":"Invalid refresh token."}`)
		return
	}
	// A refresh token MUST NOT be usable more than once (RFC 6749 section 10.4).
	if err := s.storage.DeleteRefreshToken(refreshToken); err != nil {
		http.Error(w, "Internal server error invalidating refresh token.", http.StatusInternalServerError)
		return
	}

	scopes := rt.Scopes
	if requested := r.PostFormValue("scope"); requested != "" {
		requestedScopes := strings.Fields(requested)
		for _, sc := range requestedScopes {
			if !slices.Contains(rt.Scopes, sc) {
				fmt.Fprintln(w, `{"error":"invalid_scope","error_description":"Requested scope exceeds the scope granted to the refresh token."}`)
				return
			}
		}
		scopes = requestedScopes
	}

	idToken, err := s.signToken(client.id, scopes, "", rt.Response)
	if err != nil {
		http.Error(w, "Internal server error getting ID token.", http.StatusInternalServerError)
		return
	}

	newRefreshToken := rand.Text()
	if err := s.storage.SaveRefreshToken(RefreshToken{Token: newRefreshToken, ClientID: client.id, Scopes: scopes, Response: rt.Response}); err != nil {
		http.Error(w, "Internal server error saving refresh token.", http.StatusInternalServerError)
		return
	}

	response := map[string]string{
		"access_token":  idToken,
		"token_type":    "Bearer",
		"id_token":      idToken,
		"refresh_token": newRefreshToken,
		"scope":         strings.Join(scopes, " "),
	}
	data, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		http.Error(w, "Internal server error marshaling token response.", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)+1))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	fmt.Fprintln(w, string(data))
}
