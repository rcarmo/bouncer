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
