package ingress

import (
	"github.com/rcarmo/bouncer/internal/config"
	"net/http"
	"net/url"
	"strings"
)

// ExactAuthority forbids cross-node Host/port aliases on tsnet listeners.
func ExactAuthority(r *http.Request, s *config.SiteConfig) bool {
	p := FromRequest(r)
	if p == nil || !p.TSNet {
		return true
	}
	u, e := url.Parse(s.PublicOrigin)
	if e != nil {
		return false
	}
	expected := strings.ToLower(u.Host)
	actual := strings.ToLower(r.Host)
	if u.Port() == "" {
		actual = strings.TrimSuffix(actual, ":443")
	}
	if actual != expected {
		return false
	}
	return r.TLS == nil || r.TLS.ServerName == "" || strings.EqualFold(r.TLS.ServerName, u.Hostname())
}
