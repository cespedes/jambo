package jambo

import (
	"fmt"
	"net/http"
)

func (s *Server) openIDToken(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "hi")
}
