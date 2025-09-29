package jambo

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
)

const (
	scopeOpenid  = "openid"
	scopeEmail   = "email"
	scopeProfile = "profile"
	scopeGroups  = "groups"
)

var scopesSupported = []string{
	scopeOpenid,
	scopeEmail,
	scopeProfile,
	scopeGroups,
}

type openidConfiguration struct {
	Issuer                            string   `json:"issuer"`                                // REQUIRED
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`                // REQUIRED
	TokenEndpoint                     string   `json:"token_endpoint,omitempty"`              // REQUIRED unless only implicit flow
	UserInfoEndpoint                  string   `json:"userinfo_endpoint,omitempty"`           // recommended
	JwksURI                           string   `json:"jwks_uri"`                              // REQUIRED
	RegistrationEndpoint              string   `json:"registration_endpoint,omitempty"`       // recommended
	ScopesSupported                   []string `json:"scopes_supported,omitempty"`            // recommended
	ResponseTypesSupported            []string `json:"response_types_supported"`              // REQUIRED
	ResponseModesSupported            []string `json:"response_modes_supported,omitempty"`    // optional
	GrantTypesSupported               []string `json:"grant_types_supported,omitempty"`       // optional
	ACRValuesSupported                []string `json:"acr_values_supported,omitempty"`        // optional
	SubjectTypesSupported             []string `json:"subject_types_supported"`               // REQUIRED
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"` // REQUIRED
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"` // optional
	ClaimsSupported                   []string `json:"claims_supported,omitempty"`            // recommended
	// missing a lot of "optional" fields
}

func (s *Server) openIDConfiguration(w http.ResponseWriter, r *http.Request) {
	config := openidConfiguration{
		Issuer:                            s.issuer,
		AuthorizationEndpoint:             s.issuer + "/auth",
		TokenEndpoint:                     s.issuer + "/token",
		JwksURI:                           s.issuer + "/keys",
		ScopesSupported:                   scopesSupported,
		ResponseTypesSupported:            []string{"code"},
		GrantTypesSupported:               []string{"authorization_code"},
		SubjectTypesSupported:             []string{"public"},
		IDTokenSigningAlgValuesSupported:  []string{"RS256"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic", "client_secret_post"},
		// UserInfoEndpoint:                 s.issuer + "/userinfo", // TODO: not implemented
		ClaimsSupported: []string{
			// Required claims:
			"iss", // Issuer.
			"sub", // Subject.
			"aud", // Audience.
			"exp", // Expiration time after which the JWT MUST NOT be accepted for processing.
			"iat", // Time at which the JWT was issued.
			// User profile claims:
			"name",               // Full name
			"email",              // Preferred e-mail address
			"preferred_username", // Shorthand name by which the End-User wishes to be referred to.
			// "jti",                // JWT ID.  A unique identifier for the token.
		},
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)+1))
	fmt.Fprintln(w, string(data))
}
