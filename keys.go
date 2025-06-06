package jambo

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
)

func (s *Server) openIDKeys(w http.ResponseWriter, r *http.Request) {
	jwks := s.allKeys
	data, err := json.MarshalIndent(jwks, "", "  ")
	if err != nil {
		http.Error(w, "Internal server error marshaling keys.", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)+1))
	fmt.Fprintln(w, string(data))
}
