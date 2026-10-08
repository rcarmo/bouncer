package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/rcarmo/bouncer/internal/config"
	"github.com/rcarmo/bouncer/internal/ingress"
	"github.com/rcarmo/bouncer/internal/mdns"
	"net"
	"reflect"
)

func localRegistryConfig(c *config.Config, specs []ingress.Spec) *config.Config {
	copy := config.Config{Server: c.Server}
	copy.Server.Hostnames = nil
	copy.Server.IPAddresses = nil
	seen := map[string]bool{}
	for _, s := range specs {
		if s.Config.Type != "local" || s.Config.Local.TLS != "local-ca" {
			continue
		}
		for _, site := range s.Sites {
			if !seen[site.ID] {
				copy.Sites = append(copy.Sites, *site)
				seen[site.ID] = true
			}
		}
	}
	return &copy
}
func hasLocalTLS(specs []ingress.Spec) bool {
	for _, s := range specs {
		if s.Config.Type == "local" && s.Config.Local.TLS == "local-ca" {
			return true
		}
	}
	return false
}
func startDiscovery(c *config.Config, specs []ingress.Spec) ([]*mdns.Announcer, error) {
	out := []*mdns.Announcer{}
	for _, s := range specs {
		if s.Config.Type != "local" || !s.Config.Local.MDNS.Enabled {
			continue
		}
		copy := config.Config{Server: c.Server}
		copy.Server.MDNS = s.Config.Local.MDNS
		sites := []*config.SiteConfig{}
		for _, site := range s.Sites {
			v := *site
			v.Listen = s.Config.Local.Listen
			sites = append(sites, &v)
		}
		ann, e := mdns.Start(&copy, sites)
		if e != nil {
			for _, a := range out {
				a.Close()
			}
			return nil, fmt.Errorf("ingress %q: mDNS: %w", s.Config.ID, e)
		}
		out = append(out, ann)
	}
	return out, nil
}
func sameNodeIdentity(a, b []ingress.Spec) error {
	old := map[string]ingress.Spec{}
	for _, s := range a {
		old[s.Config.ID] = s
	}
	for _, s := range b {
		if o, ok := old[s.Config.ID]; ok && s.Config.Type == "tsnet" && o.Config.Type == "tsnet" && !reflect.DeepEqual(s.Config.TSNet, o.Config.TSNet) {
			return fmt.Errorf("ingress %q: node identity change needs remove then add across two reloads", s.Config.ID)
		}
	}
	return nil
}
func openIngress(tlsConfig *tls.Config) ingress.Open {
	return func(ctx context.Context, s ingress.Spec) (net.Listener, func(), error) {
		if s.Config.Type == "tsnet" {
			return ingress.OpenTSNet(ctx, s)
		}
		ln, e := net.Listen("tcp", s.Config.Local.Listen)
		if e != nil {
			return nil, nil, e
		}
		if s.Config.Local.TLS == "local-ca" {
			ln = tls.NewListener(ln, tlsConfig)
		}
		return ln, func() {}, nil
	}
}

func sameDiscovery(a, b []ingress.Spec) bool {
	records := func(specs []ingress.Spec) map[string]string {
		out := map[string]string{}
		for _, s := range specs {
			if s.Config.Type != "local" || !s.Config.Local.MDNS.Enabled {
				continue
			}
			for _, site := range s.Sites {
				data, _ := json.Marshal(struct {
					MDNS           config.MDNSConfig
					Listen, Origin string
				}{s.Config.Local.MDNS, s.Config.Local.Listen, site.PublicOrigin})
				out[s.Config.ID+"/"+site.ID] = string(data)
			}
		}
		return out
	}
	return reflect.DeepEqual(records(a), records(b))
}
