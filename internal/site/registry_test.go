package site

import (
	"net"
	"net/http/httptest"
	"testing"

	"github.com/rcarmo/bouncer/internal/config"
)

func TestRegistrySingleSiteFallback(t *testing.T) {
	cfg := config.Defaults()
	cfg.Server.PublicOrigin = "https://one.example.com"
	cfg.Server.RPID = "one.example.com"
	cfg.Server.Hostnames = []string{"one.example.com"}

	reg, err := New(cfg, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest("GET", "http://unknown.example.com/", nil)
	req.Host = "unknown.example.com"
	s := reg.Resolve(req)
	if s == nil {
		t.Fatal("expected default site")
	}
	if s.ID != "default" {
		t.Fatalf("expected default site, got %s", s.ID)
	}
}

func TestRegistryMultiSiteResolution(t *testing.T) {
	cfg := config.Defaults()
	cfg.Sites = []config.SiteConfig{
		{
			ID:           "site-a",
			PublicOrigin: "https://a.example.com",
			RPID:         "a.example.com",
			Backend:      "http://127.0.0.1:3001",
			Hostnames:    []string{"a.example.com"},
		},
		{
			ID:           "site-b",
			PublicOrigin: "https://b.example.com",
			RPID:         "b.example.com",
			Backend:      "http://127.0.0.1:3002",
			Hostnames:    []string{"b.example.com"},
		},
	}

	reg, err := New(cfg, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	reqA := httptest.NewRequest("GET", "http://a.example.com/", nil)
	reqA.Host = "a.example.com"
	if s := reg.Resolve(reqA); s == nil || s.ID != "site-a" {
		t.Fatalf("expected site-a, got %+v", s)
	}

	reqB := httptest.NewRequest("GET", "http://b.example.com/", nil)
	reqB.Host = "b.example.com"
	if s := reg.Resolve(reqB); s == nil || s.ID != "site-b" {
		t.Fatalf("expected site-b, got %+v", s)
	}

	reqUnknown := httptest.NewRequest("GET", "http://c.example.com/", nil)
	reqUnknown.Host = "c.example.com"
	if s := reg.Resolve(reqUnknown); s != nil {
		t.Fatalf("expected nil for unknown host, got %+v", s)
	}
}

func TestRegistryUsesForwardedHostFromTrustedProxy(t *testing.T) {
	cfg := config.Defaults()
	cfg.Sites = []config.SiteConfig{
		{
			ID:           "site-b",
			PublicOrigin: "https://b.example.com",
			RPID:         "b.example.com",
			Backend:      "http://127.0.0.1:3002",
			Hostnames:    []string{"b.example.com"},
		},
	}

	_, cidr, _ := net.ParseCIDR("10.0.0.0/8")
	reg, err := New(cfg, []*net.IPNet{cidr})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest("GET", "http://internal/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	req.Host = "internal"
	req.Header.Set("X-Forwarded-Host", "b.example.com")
	if s := reg.Resolve(req); s == nil || s.ID != "site-b" {
		t.Fatalf("expected site-b via X-Forwarded-Host, got %+v", s)
	}
}

func TestRegistryPortAliasesAllowSameHostOnDifferentPorts(t *testing.T) {
	cfg := config.Defaults()
	cfg.Sites = []config.SiteConfig{
		{
			ID:           "smith-lan",
			PublicOrigin: "https://192.168.1.50:8441",
			RPID:         "192.168.1.50",
			Backend:      "http://127.0.0.1:8081",
			Hostnames:    []string{"192.168.1.50"},
			Listen:       ":8441",
		},
		{
			ID:           "jones-lan",
			PublicOrigin: "https://192.168.1.50:8442",
			RPID:         "192.168.1.50",
			Backend:      "http://127.0.0.1:8082",
			Hostnames:    []string{"192.168.1.50"},
			Listen:       ":8442",
		},
	}

	reg, err := New(cfg, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	reqSmith := httptest.NewRequest("GET", "https://192.168.1.50:8441/", nil)
	reqSmith.Host = "192.168.1.50:8441"
	if s := reg.Resolve(reqSmith); s == nil || s.ID != "smith-lan" {
		t.Fatalf("expected smith-lan, got %+v", s)
	}

	reqJones := httptest.NewRequest("GET", "https://192.168.1.50:8442/", nil)
	reqJones.Host = "192.168.1.50:8442"
	if s := reg.Resolve(reqJones); s == nil || s.ID != "jones-lan" {
		t.Fatalf("expected jones-lan, got %+v", s)
	}
}
