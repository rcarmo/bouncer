package ingress

import (
	"context"
	"crypto/tls"
	"github.com/rcarmo/bouncer/internal/config"
	"net"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"tailscale.com/ipn"
	"testing"
)

func TestExactFunnelHostAndSNI(t *testing.T) {
	s := testSites()[0]
	for _, tc := range []struct {
		host, sni string
		allow     bool
	}{{"a.example.ts.net", "a.example.ts.net", true}, {"a.example.ts.net:443", "a.example.ts.net", true}, {"a.example.ts.net:8443", "a.example.ts.net", false}, {"b.example.ts.net", "a.example.ts.net", false}, {"a.example.ts.net", "b.example.ts.net", false}} {
		r := httptest.NewRequest("GET", "https://"+tc.host+"/", nil)
		r.TLS = &tls.ConnectionState{ServerName: tc.sni}
		r = r.WithContext(WithPolicy(r.Context(), &Policy{TSNet: true, Sites: map[string]bool{"a": true}}))
		if Allows(r, s) != tc.allow {
			t.Fatalf("host=%s sni=%s", tc.host, tc.sni)
		}
	}
}
func TestFunnelOriginalClient(t *testing.T) {
	c := &ipn.FunnelConn{Src: netip.MustParseAddrPort("203.0.113.9:4567")}
	r := httptest.NewRequest("GET", "https://a.example.ts.net", nil)
	r.Header.Set("X-Forwarded-For", "127.0.0.1")
	r = r.WithContext(withPeer(context.Background(), c))
	SourceAddress(r)
	if r.RemoteAddr != "203.0.113.9:4567" {
		t.Fatal(r.RemoteAddr)
	}
}
func TestStateDirectoryAliasRejected(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "node")
	if e := os.Mkdir(state, 0700); e != nil {
		t.Fatal(e)
	}
	alias := filepath.Join(dir, "alias")
	if e := os.Symlink(state, alias); e != nil {
		t.Fatal(e)
	}
	c := config.Defaults()
	c.Ingresses = []config.IngressConfig{{ID: "a", Type: "tsnet", SiteIDs: []string{"a"}, TSNet: &config.TSNetIngress{Hostname: "a", StateDir: state}}, {ID: "b", Type: "tsnet", SiteIDs: []string{"b"}, TSNet: &config.TSNetIngress{Hostname: "b", StateDir: alias}}}
	if _, e := Validate(c, testSites()); e == nil {
		t.Fatal("aliased identity accepted")
	}
}
func TestSecretReferenceMissingFailsBeforeEnrollment(t *testing.T) {
	t.Setenv("TS_CLIENT_SECRET", "")
	t.Setenv("TSNET_FORCE_LOGIN", "")
	t.Setenv("MISSING_TEST_NODE_KEY", "")
	s := Spec{Config: config.IngressConfig{TSNet: &config.TSNetIngress{StateDir: filepath.Join(t.TempDir(), "state"), AuthKeyEnv: "MISSING_TEST_NODE_KEY"}}}
	ln, cleanup, e := OpenTSNet(context.Background(), s)
	if e == nil || ln != nil || cleanup != nil {
		t.Fatal("missing bootstrap secret did not fail safely")
	}
}
func TestPolicyUpdatesWithoutSocketReplacement(t *testing.T) {
	a := Spec{Config: config.IngressConfig{Type: "local", Local: &config.LocalIngress{Listen: ":443", TLS: "local-ca"}}}
	b := a
	b.Config.SiteIDs = []string{"b"}
	_, n, _ := net.ParseCIDR("127.0.0.1/32")
	b.Policy = &Policy{Trusted: []*net.IPNet{n}}
	if !reusable(a, b) {
		t.Fatal("routing update should reuse socket")
	}
}

func TestOverlappingLocalSockets(t *testing.T) {
	c := config.Defaults()
	c.Ingresses = []config.IngressConfig{
		{ID: "wild", Type: "local", SiteIDs: []string{"a"}, Local: &config.LocalIngress{Listen: ":443"}},
		{ID: "specific", Type: "local", SiteIDs: []string{"a"}, Local: &config.LocalIngress{Listen: "127.0.0.1:443"}},
	}
	if _, e := Validate(c, testSites()); e == nil {
		t.Fatal("overlapping sockets accepted")
	}
}
func TestBootstrapRequiresTLSOwner(t *testing.T) {
	c := config.Defaults()
	c.Ingresses = []config.IngressConfig{{ID: "trust", Type: "local", SiteIDs: []string{"a"}, Local: &config.LocalIngress{Listen: ":8080", TLS: "off", Bootstrap: true}}}
	if _, e := Validate(c, testSites()); e == nil {
		t.Fatal("bootstrap without local TLS accepted")
	}
}

func TestBootstrapRejectsHTTPOrigin(t *testing.T) {
	c := config.Defaults()
	c.Ingresses = []config.IngressConfig{
		{ID: "tls", Type: "local", SiteIDs: []string{"a"}, Local: &config.LocalIngress{Listen: ":443", TLS: "local-ca"}},
		{ID: "trust", Type: "local", SiteIDs: []string{"a"}, Local: &config.LocalIngress{Listen: ":80", TLS: "off", Bootstrap: true}},
	}
	sites := testSites()
	sites[0].PublicOrigin = "http://app.local"
	if _, err := Validate(c, sites); err == nil {
		t.Fatal("bootstrap redirect to insecure origin accepted")
	}
}
