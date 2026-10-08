package main

import (
	"crypto/tls"
	"github.com/rcarmo/bouncer/internal/config"
	"github.com/rcarmo/bouncer/internal/ingress"
	"github.com/rcarmo/bouncer/internal/site"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestTSNetDisablesLANBypassAndProxyTrust(t *testing.T) {
	_, _, _, h := routerFixture(t, "http://127.0.0.1:9000")
	r := httptest.NewRequest(http.MethodGet, "https://bouncer.test/onboarding", nil)
	r.RemoteAddr = "[fd7a:115c:a1e0::1]:1234"
	r.TLS = &tls.ConnectionState{ServerName: "bouncer.test"}
	r.Header.Set("X-Forwarded-For", "127.0.0.1")
	r.Header.Set("X-Forwarded-Host", "evil.test")
	r = r.WithContext(ingress.WithPolicy(r.Context(), &ingress.Policy{ID: "funnel", TSNet: true, Sites: map[string]bool{"default": true}}))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatal(w.Code)
	}
	if contains := strings.Contains(w.Body.String(), `name="bouncer-local-bypass" content="true"`); contains {
		t.Fatal("ULA Funnel peer bypassed enrollment")
	}
	if w.Header().Get("Strict-Transport-Security") == "" {
		t.Fatal("real TLS lost HSTS")
	}
	r.Host = "other.test"
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusNotFound {
		t.Fatal("wrong host accepted")
	}
}

func TestDiscoveryReusesUnchangedLocalRecords(t *testing.T) {
	c := config.Defaults()
	c.Sites = []config.SiteConfig{{ID: "lan", Hostnames: []string{"bouncer.local"}, PublicOrigin: "https://bouncer.local", RPID: "bouncer.local", Backend: "http://127.0.0.1:9000"}}
	c.Ingresses = []config.IngressConfig{{ID: "lan", Type: "local", SiteIDs: []string{"lan"}, Local: &config.LocalIngress{Listen: "127.0.0.1:443", MDNS: config.MDNSConfig{Enabled: true}}}}
	reg, e := site.New(c, nil)
	if e != nil {
		t.Fatal(e)
	}
	a, e := ingress.Validate(c, reg.Sites)
	if e != nil {
		t.Fatal(e)
	}
	c.Sites[0].Backend = "http://127.0.0.1:9001"
	reg, e = site.New(c, nil)
	if e != nil {
		t.Fatal(e)
	}
	b, e := ingress.Validate(c, reg.Sites)
	if e != nil {
		t.Fatal(e)
	}
	if !sameDiscovery(a, b) {
		t.Fatal("backend-only reload restarted discovery")
	}
	c.Ingresses[0].Local.Listen = "127.0.0.1:8443"
	b, e = ingress.Validate(c, reg.Sites)
	if e != nil {
		t.Fatal(e)
	}
	if sameDiscovery(a, b) {
		t.Fatal("changed discovery port reused old records")
	}
}
