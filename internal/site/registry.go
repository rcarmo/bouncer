// Package site provides multi-site configuration and host resolution.
package site

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/rcarmo/bouncer/internal/config"
	"github.com/rcarmo/bouncer/internal/localip"
)

// Registry resolves incoming requests to a site configuration.
type Registry struct {
	Sites   []*config.SiteConfig
	byHost  map[string]*config.SiteConfig
	byID    map[string]*config.SiteConfig
	defaultSite *config.SiteConfig
	trusted []*net.IPNet
}

// New builds a registry from config, supporting single- or multi-site mode.
func New(cfg *config.Config, trusted []*net.IPNet) (*Registry, error) {
	sites := make([]*config.SiteConfig, 0)
	if len(cfg.Sites) == 0 {
		s := &config.SiteConfig{
			ID:          "default",
			PublicOrigin: cfg.Server.PublicOrigin,
			RPID:        cfg.Server.RPID,
			Backend:     cfg.Server.Backend,
			Hostnames:   append([]string(nil), cfg.Server.Hostnames...),
			IPAddresses: append([]string(nil), cfg.Server.IPAddresses...),
		}
		sites = append(sites, s)
	} else {
		for i := range cfg.Sites {
			s := cfg.Sites[i]
			sites = append(sites, &s)
		}
	}

	reg := &Registry{
		Sites:   sites,
		byHost:  make(map[string]*config.SiteConfig),
		byID:    make(map[string]*config.SiteConfig),
		trusted: trusted,
	}

	for _, s := range sites {
		if s.PublicOrigin == "" {
			return nil, fmt.Errorf("site %q missing publicOrigin", s.ID)
		}
		hostFromOrigin := originHost(s.PublicOrigin)
		if s.ID == "" {
			if hostFromOrigin != "" {
				s.ID = hostFromOrigin
			} else if len(s.Hostnames) > 0 {
				s.ID = s.Hostnames[0]
			} else {
				return nil, fmt.Errorf("site missing id and hostnames")
			}
		}
		if s.RPID == "" {
			if hostFromOrigin == "" {
				return nil, fmt.Errorf("site %q missing rpID", s.ID)
			}
			s.RPID = hostFromOrigin
		}
		if s.Backend == "" {
			return nil, fmt.Errorf("site %q missing backend", s.ID)
		}
		if hostFromOrigin != "" {
			s.Hostnames = appendIfMissing(s.Hostnames, hostFromOrigin)
		}

		reg.byID[s.ID] = s
		for _, h := range s.Hostnames {
			nh := normalizeHost(h)
			if nh == "" {
				continue
			}
			if existing, ok := reg.byHost[nh]; ok && existing.ID != s.ID {
				return nil, fmt.Errorf("hostname %q assigned to multiple sites", nh)
			}
			reg.byHost[nh] = s
		}
	}

	if len(sites) > 0 {
		reg.defaultSite = sites[0]
	}
	return reg, nil
}

// Resolve returns the site for a request or nil if not found.
func (r *Registry) Resolve(req *http.Request) *config.SiteConfig {
	if r == nil {
		return nil
	}
	host := r.requestHost(req)
	if host != "" {
		if s, ok := r.byHost[host]; ok {
			return s
		}
	}
	if len(r.Sites) == 1 {
		return r.defaultSite
	}
	return nil
}

// requestHost returns the effective host for a request, honoring X-Forwarded-Host
// only when the source is a trusted proxy.
func (r *Registry) requestHost(req *http.Request) string {
	host := req.Host
	clientIP := localip.ExtractIP(req.RemoteAddr)
	if clientIP != nil && localip.IsTrustedProxy(clientIP, r.trusted) {
		if xfh := req.Header.Get("X-Forwarded-Host"); xfh != "" {
			// Use the first host in the list.
			parts := strings.Split(xfh, ",")
			host = strings.TrimSpace(parts[0])
		}
	}
	return normalizeHost(host)
}

// AllHostnames returns all hostnames for SAN aggregation.
func (r *Registry) AllHostnames() []string {
	set := make(map[string]struct{})
	for _, s := range r.Sites {
		for _, h := range s.Hostnames {
			if h == "" {
				continue
			}
			set[h] = struct{}{}
		}
		hostFromOrigin := originHost(s.PublicOrigin)
		if hostFromOrigin != "" {
			set[hostFromOrigin] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for h := range set {
		out = append(out, h)
	}
	return out
}

// AllIPs returns all IP addresses for SAN aggregation.
func (r *Registry) AllIPs() []string {
	set := make(map[string]struct{})
	for _, s := range r.Sites {
		for _, ip := range s.IPAddresses {
			if ip == "" {
				continue
			}
			set[ip] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for ip := range set {
		out = append(out, ip)
	}
	return out
}

// Helpers

func originHost(origin string) string {
	u, err := url.Parse(origin)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

func normalizeHost(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "" {
		return ""
	}
	if strings.Contains(host, "://") {
		if u, err := url.Parse(host); err == nil {
			host = u.Host
		}
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return host
}

func appendIfMissing(list []string, value string) []string {
	for _, v := range list {
		if strings.EqualFold(v, value) {
			return list
		}
	}
	return append(list, value)
}
