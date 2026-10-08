// Package site provides multi-site configuration and host resolution.
package site

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/rcarmo/bouncer/internal/config"
	"github.com/rcarmo/bouncer/internal/ingress"
	"github.com/rcarmo/bouncer/internal/localip"
	"golang.org/x/net/publicsuffix"
)

// Registry resolves incoming requests to a site configuration.
type Registry struct {
	Sites      []*config.SiteConfig
	byHost     map[string]*config.SiteConfig
	byHostPort map[string]*config.SiteConfig
	byID       map[string]*config.SiteConfig
	trusted    []*net.IPNet
}

// New builds a registry from config, supporting single- or multi-site mode.
func New(cfg *config.Config, trusted []*net.IPNet) (*Registry, error) {
	sites := make([]*config.SiteConfig, 0)
	if len(cfg.Sites) == 0 {
		s := &config.SiteConfig{
			ID:           "default",
			PublicOrigin: cfg.Server.PublicOrigin,
			RPID:         cfg.Server.RPID,
			Backend:      cfg.Server.Backend,
			Hostnames:    append([]string(nil), cfg.Server.Hostnames...),
			IPAddresses:  append([]string(nil), cfg.Server.IPAddresses...),
		}
		sites = append(sites, s)
	} else {
		for i := range cfg.Sites {
			s := cfg.Sites[i]
			s.Hostnames = append([]string(nil), s.Hostnames...)
			s.IPAddresses = append([]string(nil), s.IPAddresses...)
			sites = append(sites, &s)
		}
	}

	reg := &Registry{
		Sites:      sites,
		byHost:     make(map[string]*config.SiteConfig),
		byHostPort: make(map[string]*config.SiteConfig),
		byID:       make(map[string]*config.SiteConfig),
		trusted:    trusted,
	}

	for _, s := range sites {
		if s.PublicOrigin == "" {
			return nil, fmt.Errorf("site %q missing publicOrigin", s.ID)
		}
		origin, err := validateURL(s.PublicOrigin, true)
		if err != nil {
			return nil, fmt.Errorf("site %q invalid publicOrigin: %w", s.ID, err)
		}
		hostFromOrigin := normalizeHost(origin.Host)
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

		if _, exists := reg.byID[s.ID]; exists {
			return nil, fmt.Errorf("duplicate site id %q", s.ID)
		}
		if err := validateRPID(hostFromOrigin, s.RPID); err != nil {
			return nil, fmt.Errorf("site %q invalid rpID: %w", s.ID, err)
		}
		if _, err := validateURL(s.Backend, false); err != nil {
			return nil, fmt.Errorf("site %q invalid backend: %w", s.ID, err)
		}
		reg.byID[s.ID] = s
		listenPort := listenPort(s.Listen)
		originPort := origin.Port()
		if originPort != "" {
			hp := net.JoinHostPort(hostFromOrigin, originPort)
			if existing := reg.byHostPort[hp]; existing != nil && existing != s {
				return nil, fmt.Errorf("hostname/port %q assigned to multiple sites", hp)
			}
			reg.byHostPort[hp] = s
		}
		for _, h := range s.Hostnames {
			nh := normalizeHost(h)
			if nh == "" {
				continue
			}
			if hp := normalizeHostPort(h); hasPort(hp) {
				if existing, ok := reg.byHostPort[hp]; ok && existing.ID != s.ID {
					return nil, fmt.Errorf("hostname/port %q assigned to multiple sites", hp)
				}
				reg.byHostPort[hp] = s
				continue
			}
			if listenPort != "" {
				hp := net.JoinHostPort(nh, listenPort)
				if existing, ok := reg.byHostPort[hp]; ok && existing.ID != s.ID {
					return nil, fmt.Errorf("hostname/port %q assigned to multiple sites", hp)
				}
				reg.byHostPort[hp] = s
				continue
			}
			if originPort != "" && nh == hostFromOrigin {
				continue
			}
			if existing, ok := reg.byHost[nh]; ok && existing.ID != s.ID {
				return nil, fmt.Errorf("hostname %q assigned to multiple sites", nh)
			}
			reg.byHost[nh] = s
		}
	}

	return reg, nil
}

// Resolve returns the site for a request or nil if not found.
func (r *Registry) Resolve(req *http.Request) *config.SiteConfig {
	if r == nil {
		return nil
	}
	hostWithPort, host := r.requestHosts(req)
	if hostWithPort != "" {
		if s, ok := r.byHostPort[hostWithPort]; ok {
			if ingress.Allows(req, s) {
				return s
			}
			return nil
		}
	}
	if host != "" {
		if s, ok := r.byHost[host]; ok {
			if ingress.Allows(req, s) {
				return s
			}
			return nil
		}
	}
	return nil
}

// requestHosts returns the effective host with and without port for a request,
// honoring X-Forwarded-Host only when the source is a trusted proxy.
func (r *Registry) requestHosts(req *http.Request) (string, string) {
	host := req.Host
	trusted := ingress.Trusted(req, r.trusted)
	// Direct listeners cannot honour forwarded hosts; avoid parsing their peer.
	var clientIP net.IP
	if len(trusted) > 0 {
		clientIP = localip.ExtractIP(req.RemoteAddr)
	}
	if clientIP != nil && localip.IsTrustedProxy(clientIP, trusted) {
		if xfh := req.Header.Get("X-Forwarded-Host"); xfh != "" {
			// Use the first host in the list.
			parts := strings.Split(xfh, ",")
			host = strings.TrimSpace(parts[0])
		}
	}
	return normalizeHostPort(host), normalizeHost(host)
}

// AllHostnames returns all hostnames for SAN aggregation.
func (r *Registry) AllHostnames() []string {
	set := make(map[string]struct{})
	for _, s := range r.Sites {
		for _, h := range s.Hostnames {
			h = normalizeHost(h)
			if h == "" || net.ParseIP(h) != nil {
				continue
			}
			set[h] = struct{}{}
		}
		hostFromOrigin := originHost(s.PublicOrigin)
		if hostFromOrigin != "" && net.ParseIP(hostFromOrigin) == nil {
			set[hostFromOrigin] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for h := range set {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

// AllIPs returns all IP addresses for SAN aggregation.
func (r *Registry) AllIPs() []string {
	set := make(map[string]struct{})
	for _, s := range r.Sites {
		values := append([]string(nil), s.IPAddresses...)
		values = append(values, s.Hostnames...)
		values = append(values, originHost(s.PublicOrigin))
		for _, value := range values {
			if ip := net.ParseIP(normalizeHost(value)); ip != nil {
				set[ip.String()] = struct{}{}
			}
		}
	}
	out := make([]string, 0, len(set))
	for ip := range set {
		out = append(out, ip)
	}
	sort.Strings(out)
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
	if strings.Contains(host, ":") {
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
	}
	host = strings.Trim(host, "[]")
	// ParseIP allocates error state for ordinary DNS names. Only numeric dotted
	// hosts or colon-bearing IPv6 candidates need address canonicalisation.
	candidate := strings.Contains(host, ":")
	if !candidate {
		candidate = true
		for i := 0; i < len(host); i++ {
			if (host[i] < '0' || host[i] > '9') && host[i] != '.' {
				candidate = false
				break
			}
		}
	}
	if candidate {
		if ip := net.ParseIP(host); ip != nil {
			return ip.String()
		}
	}
	if strings.ContainsAny(host, " \t\r\n/") || strings.Contains(host, "://") {
		return ""
	}
	return host
}

func normalizeHostPort(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "" {
		return ""
	}
	if strings.Contains(host, "://") {
		if u, err := url.Parse(host); err == nil {
			host = u.Host
		}
	}
	if strings.Contains(host, ":") {
		if h, p, err := net.SplitHostPort(host); err == nil {
			return net.JoinHostPort(normalizeHost(h), p)
		}
	}
	return normalizeHost(host)
}

func listenPort(listen string) string {
	listen = strings.TrimSpace(listen)
	if listen == "" {
		return ""
	}
	_, port, err := net.SplitHostPort(listen)
	if err == nil {
		return port
	}
	if strings.HasPrefix(listen, ":") && len(listen) > 1 {
		return strings.TrimPrefix(listen, ":")
	}
	return ""
}

func appendIfMissing(list []string, value string) []string {
	for _, v := range list {
		if strings.EqualFold(v, value) {
			return list
		}
	}
	return append(list, value)
}

func hasPort(host string) bool { _, _, err := net.SplitHostPort(host); return err == nil }

func validateURL(raw string, origin bool) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.Opaque != "" || strings.ContainsAny(u.Hostname(), " \t\r\n") {
		return nil, fmt.Errorf("expected absolute HTTP(S) URL without userinfo")
	}
	if strings.Contains(u.Hostname(), ":") && net.ParseIP(u.Hostname()) == nil {
		return nil, fmt.Errorf("invalid IP host")
	}
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("invalid port")
		}
	} else if strings.HasSuffix(u.Host, ":") {
		return nil, fmt.Errorf("empty port")
	}
	if u.Fragment != "" || strings.Contains(raw, "#") || (origin && (u.Path != "" || u.RawQuery != "" || u.ForceQuery)) {
		return nil, fmt.Errorf("unexpected path, query or fragment")
	}
	return u, nil
}

func validateRPID(host, rpID string) error {
	rpID = strings.ToLower(rpID)
	if rpID == "" || strings.ContainsAny(rpID, "/?#@ ") {
		return fmt.Errorf("invalid domain")
	}
	if net.ParseIP(host) != nil {
		if net.ParseIP(rpID) == nil || !net.ParseIP(host).Equal(net.ParseIP(rpID)) {
			return fmt.Errorf("IP origin requires matching RP ID")
		}
		return nil
	}
	if host != rpID && !strings.HasSuffix(host, "."+rpID) {
		return fmt.Errorf("RP ID is not an origin domain suffix")
	}
	suffix, icann := publicsuffix.PublicSuffix(rpID)
	if suffix == rpID && (icann || strings.Contains(rpID, ".")) {
		return fmt.Errorf("RP ID is a public suffix")
	}
	return nil
}

// ResolveBootstrap selects the canonical HTTPS site from the separate HTTP
// trust listener. Shared-host port aliases are ambiguous here and fail closed.
func (r *Registry) ResolveBootstrap(req *http.Request) *config.SiteConfig {
	_, host := r.requestHosts(req)
	var found *config.SiteConfig
	for _, s := range r.Sites {
		if originHost(s.PublicOrigin) != host {
			continue
		}
		if found != nil {
			return nil
		}
		found = s
	}
	if !ingress.Allows(req, found) {
		return nil
	}
	return found
}
