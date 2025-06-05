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
	UserInfoEndpoint                 string   `json:"userinfo_endpoint,omitempty"`           // recommended
	JwksURI                          string   `json:"jwks_uri"`                              // REQUIRED
	RegistrationEndpoint             string   `json:"registration_endpoint,omitempty"`       // recommended
	ScopesSupported                  []string `json:"scopes_supported,omitempty"`            // recommended
	ResponseTypesSupported           []string `json:"response_types_supported"`              // REQUIRED
	ResponseModesSupported           []string `json:"response_modes_supported,omitempty"`    // optional
	GrantTypesSupported              []string `json:"grant_types_supported,omitempty"`       // optional
	ACRValuesSupported               []string `json:"acr_values_supported,omitempty"`        // optional
	SubjectTypesSupported            []string `json:"subject_types_supported"`               // REQUIRED
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"` // REQUIRED
	ClaimsSupported                  []string `json:"claims_supported,omitempty"`            // recommended
	// missing a lot of "optional" fields
}

func (s *Server) openIDConfiguration(w http.ResponseWriter, r *http.Request) {
	config := openidConfiguration{
		Issuer:                           s.issuer,
		AuthorizationEndpoint:            s.issuer + "/auth",
		TokenEndpoint:                    s.issuer + "/token",
		UserInfoEndpoint:                 s.issuer + "/userinfo",
		JwksURI:                          s.issuer + "/keys",
		ScopesSupported:                  []string{"openid", "email", "profile", "groups"},
		ResponseTypesSupported:           []string{"code"},
		SubjectTypesSupported:            []string{"public"},
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
		ClaimsSupported: []string{
			"iss",                // Issuer.
			"sub",                // Subject.
			"aud",                // Audience.
			"jti",                // JWT ID.  A unique identifier for the token.
			"exp",                // Expiration time after which the JWT MUST NOT be accepted for processing.
			"iat",                // Time at which the JWT was issued.
			"name",               // Full name
			"email",              // Preferred e-mail address
			"preferred_username", // Shorthand name by which the End-User wishes to be referred to.
		},
	}

	b, err := json.Marshal(config)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Fprintln(w, string(b))
	return
}
