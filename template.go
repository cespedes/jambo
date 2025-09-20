package jambo

import (
	"fmt"
	"maps"
	"net/http"
)

func (s *Server) template(w http.ResponseWriter, r *http.Request, name string, data map[string]string) {
	dest := map[string]string{
		"root":   s.root,
		"issuer": s.issuer,
	}
	maps.Copy(dest, s.templateArgs)
	maps.Copy(dest, data)

	if conn := s.GetConnection(r); conn != nil && conn.client != nil {
		dest["client"] = conn.client.id
	}

	if err := s.webTemplates.ExecuteTemplate(w, name, dest); err != nil {
		http.Error(w, fmt.Sprintf("Error in template(%s): %v", name, err.Error()), http.StatusInternalServerError)
	}

	if _DEBUG {
		fmt.Fprintf(w, "\n<!--\n%v\n-->\n", dest)
	}
}
