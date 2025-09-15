package jambo

import (
	"fmt"
	"maps"
	"net/http"
)

func (s *Server) template(w http.ResponseWriter, r *http.Request, name string, data map[string]string) {
	dest := maps.Clone(data)

	dest["root"] = s.root
	dest["issuer"] = s.issuer
	if conn := s.GetConnection(r); conn != nil && conn.client != nil {
		dest["client"] = conn.client.id
	}

	err := s.webTemplates.ExecuteTemplate(w, name, dest)
	fmt.Fprintf(w, "\n<!--\n%v\n-->\n", dest)

	if err != nil {
		http.Error(w, fmt.Sprintf("Error in template(%s): %v", name, err.Error()), http.StatusInternalServerError)
	}
}
