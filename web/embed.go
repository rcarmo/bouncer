// Package web embeds the static UI files.
package web

import (
	"embed"
	"html"
	"net/http"
	"strings"
)

//go:embed *.html *.png *.js
var Static embed.FS

// ServeScript only exposes the embedded UI scripts, never arbitrary embed files.
func ServeScript(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/static/")
	switch name {
	case "login.js", "landing.js", "onboarding.js", "trust.js":
	default:
		http.NotFound(w, r)
		return
	}
	data, err := Static.ReadFile(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(data) // #nosec G705 -- immutable embedded JavaScript, allowlisted filename, explicit JS MIME and nosniff middleware.
}

// TrustContent escapes the server-generated fingerprint as HTML text, not script.
// HTTP delivery is unauthenticated: independent comparison remains mandatory.
func TrustContent(fingerprint string) string {
	data, _ := Static.ReadFile("trust-content.html")
	return strings.ReplaceAll(string(data), "{{CA_FINGERPRINT}}", html.EscapeString(fingerprint))
}
