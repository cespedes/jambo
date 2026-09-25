package jambo

import (
	"fmt"
	"maps"
	"net/http"
)

func (s *Server) template(w http.ResponseWriter, r *http.Request, name string, data map[string]string) {
	// Snapshot the presentation state under the lock: ReplacePresentation
	// always builds a fresh *template.Template/map rather than mutating
	// these in place, so using these local copies for the rest of the
	// request, unlocked, is safe even if a reload happens concurrently.
	s.Lock()
	tmpl := s.webTemplates
	templateArgs := s.templateArgs
	s.Unlock()

	dest := map[string]string{
		"root":   s.root,
		"issuer": s.issuer,
	}
	maps.Copy(dest, templateArgs)
	maps.Copy(dest, data)

	if conn := s.GetConnection(r); conn != nil && conn.client != nil {
		dest["client"] = conn.client.id
	}

	if err := tmpl.ExecuteTemplate(w, name, dest); err != nil {
		http.Error(w, fmt.Sprintf("Error in template(%s): %v", name, err.Error()), http.StatusInternalServerError)
	}

	if s.debug {
		fmt.Fprintf(w, "\n<!--\n%v\n-->\n", dest)
	}
}
