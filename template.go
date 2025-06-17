package jambo

import (
	"fmt"
	"net/http"
)

func (s *Server) template(name string, w http.ResponseWriter, m map[string]string) {
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
	<head>
		<title>%s</title>
	</head>
	<body>
		<h1>%s</h1>
		<pre>%s</pre>
	</body>
	</title>
</html>
`, name, name, m)
	return
}
