package jambo

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
)

func (s *Server) openIDToken(w http.ResponseWriter, r *http.Request) {
	grantType := r.PostFormValue("grant_type")
	if grantType != "authorization_code" {
		fmt.Printf("error in token endpoint: grant_type=%q\n", grantType)
		return
	}
	code := r.PostFormValue("code")
	_ = code
	redirectURI := r.PostFormValue("redirect_uri")
	_ = redirectURI
	clientID := r.PostFormValue("client_id")
	_ = clientID
	clientSecret := r.PostFormValue("client_secret")
	_ = clientSecret

	fmt.Printf("code=%q redirect_uri=%q client_id=%q client_secret=%q\n",
		code, redirectURI, clientID, clientSecret)

	response := map[string]string{
		"access_token": "foobar",
	}

	data, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		http.Error(w, "Internal server error marshaling keys.", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)+1))
	fmt.Fprintln(w, string(data))
}
