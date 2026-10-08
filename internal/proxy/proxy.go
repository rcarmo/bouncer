// Package proxy provides the authenticated reverse proxy.
package proxy

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/rcarmo/bouncer/internal/ingress"
	"github.com/rcarmo/bouncer/internal/localip"
)

// Buffers contain response bytes; the pool never owns request headers or auth
// state. ReverseProxy only forwards the bytes read for the current response.
var responseBuffers = sync.Pool{New: func() any { return new([32 * 1024]byte) }}

type responseBufferPool struct{}

func (responseBufferPool) Get() []byte { return responseBuffers.Get().(*[32 * 1024]byte)[:] }
func (responseBufferPool) Put(buf []byte) {
	if cap(buf) == 32*1024 {
		responseBuffers.Put((*[32 * 1024]byte)(buf[:32*1024]))
	}
}

// New creates a reverse proxy to the backend URL.
// It adds X-Forwarded-* headers and strips them from untrusted sources.
func New(backendURL string, trusted []*net.IPNet) (*httputil.ReverseProxy, error) {
	target, err := url.Parse(backendURL)
	if err != nil {
		return nil, err
	}
	if (target.Scheme != "http" && target.Scheme != "https") || target.Hostname() == "" || target.Fragment != "" {
		return nil, fmt.Errorf("proxy: backend must be an absolute HTTP(S) URL")
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DisableCompression = true
	transport.ForceAttemptHTTP2 = false

	proxy := &httputil.ReverseProxy{
		Transport:  transport,
		BufferPool: responseBufferPool{},
		// Flush frequently so EventSource/SSE streams reach the browser without
		// buffering. WebSocket upgrades are passed through by ReverseProxy.
		FlushInterval: 100 * time.Millisecond,
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(target)

			clientIP := localip.ExtractIP(r.In.RemoteAddr)
			// These non-standard attribution headers may have been supplied by a
			// client even when the immediate peer is a trusted generic proxy.
			for _, header := range []string{"CF-Connecting-IP", "True-Client-IP", "X-Real-IP"} {
				r.Out.Header.Del(header)
			}
			if clientIP != nil && localip.IsTrustedProxy(clientIP, ingress.Trusted(r.In, trusted)) {
				// Rewrite removes forwarded headers before calling us. SetXForwarded
				// alone would discard the original client, public host and HTTPS scheme.
				r.SetXForwarded()
				if original := localip.ClientIPFromRequest(r.In, ingress.Trusted(r.In, trusted)); original != nil {
					r.Out.Header.Set("X-Forwarded-For", original.String()+", "+clientIP.String())
				}
				if host := r.In.Header.Get("X-Forwarded-Host"); host != "" && !strings.Contains(host, ",") {
					r.Out.Header.Set("X-Forwarded-Host", host)
				}
				if proto := strings.ToLower(r.In.Header.Get("X-Forwarded-Proto")); proto == "https" || proto == "http" {
					r.Out.Header.Set("X-Forwarded-Proto", proto)
				}
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
			// #nosec G706 -- structured logging of request URL for diagnostics.
			slog.Error("proxy error", "url", r.URL.String(), "error", err)
			http.Error(w, "bad gateway", http.StatusBadGateway)
		},
	}

	return proxy, nil
}
