package site

import (
	"github.com/rcarmo/bouncer/internal/config"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestRegistryInvalidConfiguration(t *testing.T) {
	for _, field := range []string{"backend", "publicOrigin"} {
		for _, value := range []string{"relative", "ftp://example.com", "https://", "https://user@example.com", "https://example.com:70000", "https://example.com:", "https://example.com#x"} {
			t.Run(field+value, func(t *testing.T) {
				cfg := config.Defaults()
				if field == "backend" {
					cfg.Server.Backend = value
				} else {
					cfg.Server.PublicOrigin = value
				}
				if _, err := New(cfg, nil); err == nil {
					t.Fatal("accepted invalid URL")
				}
			})
		}
	}
	for _, value := range []string{"https://example.com/path", "https://example.com?", "https://example.com?q=x"} {
		cfg := config.Defaults()
		cfg.Server.PublicOrigin = value
		if _, err := New(cfg, nil); err == nil {
			t.Fatalf("accepted origin %q", value)
		}
	}
	cfg := config.Defaults()
	cfg.Sites = []config.SiteConfig{{ID: "same", PublicOrigin: "https://a.example", Backend: "http://localhost"}, {ID: "same", PublicOrigin: "https://b.example", Backend: "http://localhost"}}
	if _, err := New(cfg, nil); err == nil {
		t.Fatal("accepted duplicate IDs")
	}
}

func TestOriginPortAndIPv6Aliases(t *testing.T) {
	for _, host := range []string{"192.168.1.50", "[2001:db8::1]"} {
		for _, listen := range []bool{false, true} {
			cfg := config.Defaults()
			cfg.Sites = []config.SiteConfig{{ID: "a", PublicOrigin: "https://" + host + ":8441", Backend: "http://[::1]:3001", Hostnames: []string{host}}, {ID: "b", PublicOrigin: "https://" + host + ":8442", Backend: "http://localhost:3002", Hostnames: []string{host}}}
			if listen {
				cfg.Sites[0].Listen = ":8441"
				cfg.Sites[1].Listen = ":8442"
			}
			reg, err := New(cfg, nil)
			if err != nil {
				t.Fatal(err)
			}
			for i, port := range []string{"8441", "8442"} {
				req := httptest.NewRequest("GET", "https://"+host+":"+port+"/", nil)
				s := reg.Resolve(req)
				if s == nil || s.ID != cfg.Sites[i].ID {
					t.Fatalf("incorrect mapping: %+v", s)
				}
			}
			req := httptest.NewRequest("GET", "https://"+host+":9999/", nil)
			if reg.Resolve(req) != nil {
				t.Fatal("unknown port accepted")
			}
		}
	}
}

func TestSANAggregation(t *testing.T) {
	cfg := config.Defaults()
	cfg.Sites = []config.SiteConfig{{ID: "a", PublicOrigin: "https://[2001:db8::1]:8441", Backend: "http://localhost/base?q=x", Hostnames: []string{"EXAMPLE.COM:8441", "192.168.1.50:8441", "[2001:0db8::1]:8441"}, IPAddresses: []string{"2001:0db8::1", "192.168.1.50"}}}
	reg, err := New(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := reg.AllHostnames(); !reflect.DeepEqual(got, []string{"example.com"}) {
		t.Fatalf("DNS SANs %v", got)
	}
	if got := reg.AllIPs(); !reflect.DeepEqual(got, []string{"192.168.1.50", "2001:db8::1"}) {
		t.Fatalf("IP SANs %v", got)
	}
}

func TestIPv6HostWithoutPort(t *testing.T) {
	cfg := config.Defaults()
	cfg.Server.PublicOrigin = "https://[::1]"
	cfg.Server.RPID = "::1"
	cfg.Server.Hostnames = []string{"::1"}
	reg, err := New(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"[::1]", "[::1]:443"} {
		req := httptest.NewRequest("GET", "https://[::1]/", nil)
		req.Host = host
		if reg.Resolve(req) == nil {
			t.Fatalf("IPv6 host not resolved: %s", host)
		}
	}
}

func TestRPIDRelationship(t *testing.T) {
	for _, tc := range []struct {
		host, rp string
		valid    bool
	}{
		{"app.example.com", "example.com", true}, {"app.example.com", "app.example.com", true}, {"localhost", "localhost", true}, {"bouncer.local", "bouncer.local", true}, {"192.168.1.50", "192.168.1.50", true},
		{"app.example.com", "unrelated.example", false}, {"example.com", "ample.com", false}, {"app.example.com", "com", false}, {"app.co.uk", "co.uk", false}, {"foo.github.io", "github.io", false}, {"localhost", "localhost:8443", false}, {"192.168.1.50", "192.168.1.51", false},
	} {
		if err := validateRPID(tc.host, tc.rp); (err == nil) != tc.valid {
			t.Errorf("%s / %s: %v", tc.host, tc.rp, err)
		}
	}
}

func TestBootstrapSeparatePort(t *testing.T) {
	c := config.Defaults()
	c.Server.PublicOrigin = "https://localhost:8443"
	c.Server.RPID = "localhost"
	c.Server.Hostnames = []string{"localhost"}
	r, err := New(c, nil)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "http://localhost:8080/onboarding", nil)
	if r.ResolveBootstrap(req) == nil {
		t.Fatal("HTTP trust listener failed canonical HTTPS site lookup")
	}
	req.Host = "unknown.test:8080"
	if r.ResolveBootstrap(req) != nil {
		t.Fatal("unknown bootstrap host allowed")
	}
}
