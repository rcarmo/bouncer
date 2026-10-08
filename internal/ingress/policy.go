// Package ingress owns listener-scoped routing and trust policy.
package ingress

import (
	"context"
	"github.com/rcarmo/bouncer/internal/config"
	"net"
	"net/http"
)

type key struct{}
type Policy struct {
	ID        string
	TSNet     bool
	Bootstrap bool
	Sites     map[string]bool
	Trusted   []*net.IPNet
}

func WithPolicy(ctx context.Context, p *Policy) context.Context {
	return context.WithValue(ctx, key{}, p)
}
func FromRequest(r *http.Request) *Policy { p, _ := r.Context().Value(key{}).(*Policy); return p }
func Trusted(r *http.Request, fallback []*net.IPNet) []*net.IPNet {
	if p := FromRequest(r); p != nil {
		return p.Trusted
	}
	return fallback
}
func Allows(r *http.Request, s *config.SiteConfig) bool {
	if s == nil {
		return false
	}
	p := FromRequest(r)
	return (p == nil || p.Sites[s.ID]) && ExactAuthority(r, s)
}
func LocalBypass(r *http.Request) bool { p := FromRequest(r); return p == nil || !p.TSNet }
