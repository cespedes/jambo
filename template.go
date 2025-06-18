package jambo

import (
	"fmt"
	"maps"
	"net/http"
)

func (s *Server) template(w http.ResponseWriter, r *http.Request, name string, data map[string]string) {
	dest := maps.Clone(data)

	dest["Root"] = s.root
	dest["Issuer"] = s.issuer
	if c := s.GetClient(r); c != nil {
		dest["Client"] = c.ID
	}

	err := s.webTemplates.ExecuteTemplate(w, name, dest)
	fmt.Fprintf(w, "\n<!--\n%v\n-->\n", dest)

	if err != nil {
		http.Error(w, fmt.Sprintf("Error in template(%s): %v", name, err.Error()), http.StatusInternalServerError)
	}
}
