// Package proxy provides the authenticated reverse proxy.
package proxy

import (
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/rcarmo/bouncer/internal/localip"
)

// New creates a reverse proxy to the backend URL.
// It adds X-Forwarded-* headers and strips them from untrusted sources.
func New(backendURL string, trusted []*net.IPNet) (*httputil.ReverseProxy, error) {
	target, err := url.Parse(backendURL)
	if err != nil {
		return nil, err
	}

	proxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(target)

			clientIP := localip.ExtractIP(r.In.RemoteAddr)

			if clientIP != nil && localip.IsTrustedProxy(clientIP, trusted) {
				// Trusted proxy: preserve existing forwarded headers and append.
				r.SetXForwarded()
				return
			}

			// Direct or untrusted: strip forwarded headers and set clean values.
			r.Out.Header.Del("Forwarded")
			r.Out.Header.Del("X-Forwarded-For")
			r.Out.Header.Del("X-Forwarded-Host")
			r.Out.Header.Del("X-Forwarded-Proto")

			if clientIP != nil {
				r.Out.Header.Set("X-Forwarded-For", clientIP.String())
			}
			r.Out.Header.Set("X-Forwarded-Host", r.In.Host)
			if r.In.TLS != nil {
				r.Out.Header.Set("X-Forwarded-Proto", "https")
			} else {
				r.Out.Header.Set("X-Forwarded-Proto", "http")
			}
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			slog.Error("proxy error", "url", r.URL.String(), "error", err)
			http.Error(w, "bad gateway", http.StatusBadGateway)
		},
	}

	return proxy, nil
}
