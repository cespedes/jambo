package jambo

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)

type openidConfiguration struct {
	Issuer                           string   `json:"issuer"`                                // REQUIRED
	AuthorizationEndpoint            string   `json:"authorization_endpoint"`                // REQUIRED
	TokenEndpoint                    string   `json:"token_endpoint,omitempty"`              // REQUIRED unless only implicit flow
	UserinfoEndpoint                 string   `json:"userinfo_endpoint,omitempty"`           // recommended
	JwksURI                          string   `json:"jwks_uri"`                              // REQUIRED
	RegistrationEndpoint             string   `json:"registration_endpoint,omitempty"`       // recommended
	ScopesSupported                  []string `json:"scopes_supported,omitempty"`            // recommended
	ResponseTypesSupported           []string `json:"response_types_supported"`              // REQUIRED
	ResponseModesSupported           []string `json:"response_modes_supported,omitempty"`    // optional
	GrantTypesSupported              []string `json:"grant_types_supported,omitempty"`       // optional
	ACRValuesSupported               []string `json:"acr_values_supported,omitempty"`        // optional
	SubjectTypesSupported            []string `json:"subject_types_supported"`               // REQUIRED
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"` // REQUIRED
}

func (s *Server) openIDConfiguration(w http.ResponseWriter, r *http.Request) {
	config := openidConfiguration{
		Issuer:                s.issuer,
		AuthorizationEndpoint: s.issuer + "/auth",
	}

	b, err := json.Marshal(config)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Fprintln(w, string(b))
	return

	fmt.Fprintf(w, `{
  "issuer": "%s",
  "authorization_endpoint": "%s/auth",
  "token_endpoint": "%s/token",
  "jwks_uri": "%s/keys",
  "userinfo_endpoint": "%s/userinfo",
  "device_authorization_endpoint": "%s/device/code",
  "end_session_endpoint": "%s",
  "grant_types_supported": [
    "authorization_code",
    "refresh_token",
    "urn:ietf:params:oauth:grant-type:device_code",
    "urn:ietf:params:oauth:grant-type:token-exchange"
  ],
  "response_types_supported": [
    "code"
  ],
  "subject_types_supported": [
    "public"
  ],
  "id_token_signing_alg_values_supported": [
    "RS256"
  ],
  "code_challenge_methods_supported": [
    "S256",
    "plain"
  ],
  "scopes_supported": [
    "openid",
    "email",
    "groups",
    "profile",
    "offline_access"
  ],
  "token_endpoint_auth_methods_supported": [
    "client_secret_basic",
    "client_secret_post"
  ],
  "claims_supported": [
    "iss",
    "sub",
    "aud",
    "iat",
    "exp",
    "email",
    "email_verified",
    "locale",
    "name",
    "preferred_username",
    "at_hash"
  ]
}`, s.issuer, s.issuer, s.issuer, s.issuer, s.issuer, s.issuer, s.issuer)
}
