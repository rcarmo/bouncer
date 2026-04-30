// Package mdns publishes local DNS-SD/mDNS service announcements for Bouncer sites.
package mdns

import (
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/grandcat/zeroconf"
	"github.com/rcarmo/bouncer/internal/config"
)

// Announcer owns active mDNS service registrations.
type Announcer struct {
	servers []*zeroconf.Server
}

// Close unregisters all active mDNS announcements.
func (a *Announcer) Close() {
	if a == nil {
		return
	}
	for _, srv := range a.servers {
		if srv != nil {
			srv.Shutdown()
		}
	}
	a.servers = nil
}

// Start publishes one DNS-SD service per configured site.
//
// Note: DNS-SD announcements make services discoverable by Bonjour-capable
// clients. They do not guarantee that every browser can resolve arbitrary
// alias hostnames like smith.local; that requires OS mDNS hostname alias
// support. Bouncer therefore advertises the service instance and URL metadata,
// while host routing still uses the HTTP Host header it receives.
func Start(cfg *config.Config, sites []*config.SiteConfig) (*Announcer, error) {
	if cfg == nil || !cfg.Server.MDNS.Enabled {
		return &Announcer{}, nil
	}
	service := strings.TrimSpace(cfg.Server.MDNS.Service)
	if service == "" {
		service = "_https._tcp"
	}
	domain := strings.TrimSpace(cfg.Server.MDNS.Domain)
	if domain == "" {
		domain = "local."
	}
	prefix := strings.TrimSpace(cfg.Server.MDNS.InstancePrefix)

	ann := &Announcer{}
	for _, s := range sites {
		if s == nil {
			continue
		}
		port := sitePort(cfg, s)
		if port <= 0 {
			slog.Warn("skipping mDNS announcement with no valid port", "site", s.ID)
			continue
		}
		instance := serviceInstance(prefix, s)
		text := []string{
			"id=" + s.ID,
			"origin=" + s.PublicOrigin,
			"backend=" + s.Backend,
		}
		server, err := zeroconf.Register(instance, service, domain, port, text, nil)
		if err != nil {
			ann.Close()
			return nil, fmt.Errorf("register %q: %w", instance, err)
		}
		ann.servers = append(ann.servers, server)
		slog.Info("mDNS service announced", "instance", instance, "service", service, "domain", domain, "port", port, "site", s.ID)
	}
	return ann, nil
}

func serviceInstance(prefix string, s *config.SiteConfig) string {
	name := strings.TrimSpace(s.ID)
	if name == "" {
		name = strings.TrimSpace(s.RPID)
	}
	if name == "" && len(s.Hostnames) > 0 {
		name = strings.TrimSpace(s.Hostnames[0])
	}
	if prefix != "" {
		name = prefix + " " + name
	}
	return sanitizeInstance(name)
}

func sanitizeInstance(value string) string {
	value = strings.TrimSpace(value)
	value = strings.ReplaceAll(value, ".local", "")
	value = strings.ReplaceAll(value, ".", "-")
	value = strings.ReplaceAll(value, "_", "-")
	if value == "" {
		return "bouncer"
	}
	return value
}

func sitePort(cfg *config.Config, s *config.SiteConfig) int {
	if p := portFromListen(s.Listen); p > 0 {
		return p
	}
	if u, err := url.Parse(s.PublicOrigin); err == nil {
		if p := portFromHost(u.Host); p > 0 {
			return p
		}
		if u.Scheme == "https" {
			return 443
		}
		if u.Scheme == "http" {
			return 80
		}
	}
	if cfg.Server.Cloudflare {
		return portFromListen(cfg.Server.Listen)
	}
	return 443
}

func portFromHost(host string) int {
	_, port, err := net.SplitHostPort(host)
	if err != nil || port == "" {
		return 0
	}
	p, _ := strconv.Atoi(port)
	return p
}

func portFromListen(listen string) int {
	listen = strings.TrimSpace(listen)
	if listen == "" {
		return 0
	}
	_, port, err := net.SplitHostPort(listen)
	if err != nil {
		if strings.HasPrefix(listen, ":") {
			port = strings.TrimPrefix(listen, ":")
		}
	}
	p, _ := strconv.Atoi(port)
	return p
}
