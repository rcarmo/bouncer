package ingress

import (
	"encoding/json"
	"fmt"
	"github.com/rcarmo/bouncer/internal/config"
	"github.com/rcarmo/bouncer/internal/localip"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var identifier = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,62}$`)
var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

type Spec struct {
	Config      config.IngressConfig
	Policy      *Policy
	Sites       []*config.SiteConfig
	Fingerprint string
}

// Validate resolves defaults and validates the whole collection before networking.
func Validate(c *config.Config, sites []*config.SiteConfig) ([]Spec, error) {
	if len(c.Ingresses) > 32 {
		return nil, fmt.Errorf("ingresses: at most 32 endpoints allowed")
	}
	if len(c.Ingresses) == 0 {
		return nil, fmt.Errorf("ingresses: configure at least one ingress (legacy listeners are not used)")
	}
	byID := map[string]*config.SiteConfig{}
	for _, s := range sites {
		byID[s.ID] = s
	}
	ids := map[string]bool{}
	states := []string{}
	names := map[string]bool{}
	sockets := map[string]bool{}
	addresses := []string{}
	out := []Spec{}
	for _, raw := range c.Ingresses {
		i := raw
		if !identifier.MatchString(i.ID) || ids[i.ID] {
			return nil, fmt.Errorf("ingress %q: id must be unique and contain letters, digits, underscores or hyphens", i.ID)
		}
		ids[i.ID] = true
		if !i.IsEnabled() {
			continue
		}
		if len(i.SiteIDs) == 0 {
			return nil, fmt.Errorf("ingress %q: siteIds is empty", i.ID)
		}
		p := &Policy{ID: i.ID, Sites: map[string]bool{}}
		selected := []*config.SiteConfig{}
		for _, id := range i.SiteIDs {
			s := byID[id]
			if s == nil || p.Sites[id] {
				return nil, fmt.Errorf("ingress %q: unknown or duplicate site %q", i.ID, id)
			}
			p.Sites[id] = true
			selected = append(selected, s)
		}
		switch i.Type {
		case "local":
			if i.Local == nil || i.TSNet != nil {
				return nil, fmt.Errorf("ingress %q: local settings required; tsnet settings forbidden", i.ID)
			}
			l := *i.Local
			i.Local = &l
			host, port, err := net.SplitHostPort(l.Listen)
			n, e := strconv.Atoi(port)
			if err != nil || e != nil || n < 1 || n > 65535 || (host != "" && net.ParseIP(host) == nil) {
				return nil, fmt.Errorf("ingress %q: local.listen must be an IP:port or :port", i.ID)
			}
			if host != "" {
				host = net.ParseIP(host).String()
			}
			socket := net.JoinHostPort(host, strconv.Itoa(n))
			for _, old := range addresses {
				oh, op, _ := net.SplitHostPort(old)
				if op == strconv.Itoa(n) && (oh == host || oh == "" || host == "" || oh == "0.0.0.0" || host == "0.0.0.0" || oh == "::" || host == "::") {
					return nil, fmt.Errorf("ingress %q: overlapping local socket", i.ID)
				}
			}
			addresses = append(addresses, socket)
			i.Local.Listen = socket
			if sockets[socket] {
				return nil, fmt.Errorf("ingress %q: duplicate local listener", i.ID)
			}
			sockets[socket] = true
			if l.TLS == "" {
				i.Local.TLS = "local-ca"
			}
			if i.Local.TLS != "local-ca" && i.Local.TLS != "off" {
				return nil, fmt.Errorf("ingress %q: local.tls must be local-ca or off", i.ID)
			}
			if l.Bootstrap {
				if i.Local.TLS != "off" || len(l.TrustedProxies) > 0 {
					return nil, fmt.Errorf("ingress %q: bootstrap requires tls off and no trusted proxies", i.ID)
				}
				p.Bootstrap = true
			}
			p.Trusted, err = localip.ParseTrustedProxies(l.TrustedProxies)
			if err != nil {
				return nil, fmt.Errorf("ingress %q: trustedProxies: %w", i.ID, err)
			}
		case "tsnet":
			p.TSNet = true
			if i.TSNet == nil || i.Local != nil || len(selected) != 1 {
				return nil, fmt.Errorf("ingress %q: tsnet settings and exactly one site required", i.ID)
			}
			t := *i.TSNet
			i.TSNet = &t
			if !identifier.MatchString(t.Hostname) || strings.Contains(t.Hostname, "_") || strings.HasSuffix(t.Hostname, "-") || names[strings.ToLower(t.Hostname)] {
				return nil, fmt.Errorf("ingress %q: tsnet.hostname must be a unique DNS node name", i.ID)
			}
			names[strings.ToLower(t.Hostname)] = true
			if t.Port == 0 {
				i.TSNet.Port = 443
			}
			if i.TSNet.Port != 443 && i.TSNet.Port != 8443 && i.TSNet.Port != 10000 {
				return nil, fmt.Errorf("ingress %q: tsnet.port must be 443, 8443 or 10000", i.ID)
			}
			u, err := url.Parse(selected[0].PublicOrigin)
			if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || net.ParseIP(u.Hostname()) != nil || !strings.HasSuffix(u.Hostname(), ".ts.net") || selected[0].RPID != u.Hostname() {
				return nil, fmt.Errorf("ingress %q: site must have an HTTPS ts.net origin and matching rpID", i.ID)
			}
			port := u.Port()
			if port == "" {
				port = "443"
			}
			if port != strconv.Itoa(i.TSNet.Port) {
				return nil, fmt.Errorf("ingress %q: origin port does not match tsnet.port", i.ID)
			}
			if !strings.HasPrefix(u.Hostname(), strings.ToLower(t.Hostname)+".") {
				return nil, fmt.Errorf("ingress %q: origin hostname must match requested node name", i.ID)
			}
			if t.AuthKeyEnv != "" && !envName.MatchString(t.AuthKeyEnv) {
				return nil, fmt.Errorf("ingress %q: invalid authKeyEnv name", i.ID)
			}
			state := t.StateDir
			if state == "" {
				state = filepath.Join("tsnet", i.ID)
			}
			if !filepath.IsAbs(state) {
				state = filepath.Join(filepath.Dir(c.Path()), state)
			}
			state, err = canonical(state)
			if err != nil {
				return nil, fmt.Errorf("ingress %q: stateDir: %w", i.ID, err)
			}
			for _, old := range states {
				if state == old || strings.HasPrefix(state, old+string(filepath.Separator)) || strings.HasPrefix(old, state+string(filepath.Separator)) {
					return nil, fmt.Errorf("ingress %q: overlapping stateDir", i.ID)
				}
			}
			states = append(states, state)
			i.TSNet.StateDir = state
		default:
			return nil, fmt.Errorf("ingress %q: type must be local or tsnet", i.ID)
		}
		// Include identity-bearing site fields; backend changes do not replace listeners.
		identity := []string{}
		for _, s := range selected {
			identity = append(identity, s.ID, s.PublicOrigin, s.RPID)
		}
		data, _ := json.Marshal(struct {
			Ingress  config.IngressConfig
			Identity []string
		}{i, identity})
		out = append(out, Spec{Config: i, Policy: p, Sites: selected, Fingerprint: string(data)})
	}
	tlsSites := map[string]bool{}
	for _, s := range out {
		if s.Config.Type == "local" && s.Config.Local.TLS == "local-ca" {
			for _, id := range s.Config.SiteIDs {
				tlsSites[id] = true
			}
		}
	}
	for _, s := range out {
		if s.Policy.Bootstrap {
			for _, id := range s.Config.SiteIDs {
				origin, _ := url.Parse(byID[id].PublicOrigin)
				if origin == nil || origin.Scheme != "https" {
					return nil, fmt.Errorf("ingress %q: bootstrap site %q requires an HTTPS publicOrigin", s.Config.ID, id)
				}
				if !tlsSites[id] {
					return nil, fmt.Errorf("ingress %q: bootstrap site %q requires a local-ca ingress", s.Config.ID, id)
				}
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("ingresses: at least one enabled ingress required")
	}
	return out, nil
}

func canonical(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err == nil {
		return resolved, nil
	}
	if !os.IsNotExist(err) {
		return "", err
	}
	parent := filepath.Dir(abs)
	if parent == abs {
		return "", err
	}
	base, err := canonical(parent)
	if err != nil {
		return "", err
	}
	return filepath.Join(base, filepath.Base(abs)), nil
}
