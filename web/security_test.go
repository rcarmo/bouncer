package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestExternalScripts(t *testing.T) {
	for _, name := range []string{"landing", "login", "onboarding", "trust"} {
		data, err := Static.ReadFile(name + ".html")
		if err != nil {
			t.Fatal(err)
		}
		page := string(data)
		if strings.Contains(page, "onclick=") || strings.Contains(page, "<script type=\"module\">") {
			t.Fatalf("inline JavaScript in %s", name)
		}
		if !strings.Contains(page, "src=\"/static/"+name+".js\"") {
			t.Fatalf("missing external script in %s", name)
		}
		mux := http.NewServeMux()
		mux.HandleFunc("GET /static/{script}", ServeScript)
		res := httptest.NewRecorder()
		mux.ServeHTTP(res, httptest.NewRequest("GET", "/static/"+name+".js", nil))
		if res.Code != 200 || res.Header().Get("Content-Type") != "text/javascript; charset=utf-8" || res.Body.Len() == 0 {
			t.Fatalf("script route %s: %v", name, res)
		}
	}
	for _, path := range []string{"/static/trust.html", "/static/embed.go", "/static/missing.js", "/static/../trust.js"} {
		res := httptest.NewRecorder()
		ServeScript(res, httptest.NewRequest("GET", path, nil))
		if res.Code != 404 {
			t.Fatalf("exposed %s", path)
		}
	}
}
func TestTrustContentEscapesFingerprint(t *testing.T) {
	page := TrustContent("<script>alert(1)</script>")
	if strings.Contains(page, "<script>") || !strings.Contains(page, "&lt;script&gt;") {
		t.Fatal("unsafe fingerprint injection")
	}
	if !strings.Contains(page, "unauthenticated") || !strings.Contains(page, "unsigned") || !strings.Contains(page, "independent trusted channel") {
		t.Fatal("missing trust warnings")
	}
	if strings.Contains(page, "href=") || !strings.Contains(page, "trust-verified") {
		t.Fatal("downloads available without acknowledgement")
	}
}
