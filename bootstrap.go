package main

import (
	"html"
	"net"
	"net/http"
	"strings"

	"github.com/rcarmo/bouncer/internal/ca"
	"github.com/rcarmo/bouncer/internal/config"
	"github.com/rcarmo/bouncer/internal/site"
	"github.com/rcarmo/bouncer/web"
)

// bootstrapHandler offers trust installation only; it never registers passkeys.
func bootstrapHandler(c *config.Config, sites *site.Registry) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /static/{script}", web.ServeScript)
	mux.HandleFunc("GET /certs/rootCA.cer", func(w http.ResponseWriter, r *http.Request) {
		der, e := ca.CACertDER(c)
		if e != nil {
			http.Error(w, "CA unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/x-x509-ca-cert")
		w.Header().Set("Content-Disposition", "attachment; filename=bouncer-ca.cer")
		_, _ = w.Write(der)
	})
	mux.HandleFunc("GET /certs/rootCA.mobileconfig", func(w http.ResponseWriter, r *http.Request) {
		data, e := ca.GenerateMobileconfig(c)
		if e != nil {
			http.Error(w, "CA unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/x-apple-aspen-config")
		w.Header().Set("Content-Disposition", "attachment; filename=bouncer.mobileconfig")
		_, _ = w.Write(data)
	})
	mux.HandleFunc("GET /onboarding", func(w http.ResponseWriter, r *http.Request) {
		s := sites.ResolveBootstrap(r)
		if s == nil {
			http.NotFound(w, r)
			return
		}
		fingerprint, e := ca.FingerprintSHA256(c)
		if e != nil {
			http.Error(w, "CA unavailable", http.StatusServiceUnavailable)
			return
		}
		data, _ := web.Static.ReadFile("trust.html")
		page := strings.ReplaceAll(string(data), "{{TRUST_CONTENT}}", web.TrustContent(fingerprint))
		page = strings.ReplaceAll(page, "{{HTTPS_ORIGIN}}", html.EscapeString(s.PublicOrigin))
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(page))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		s := sites.ResolveBootstrap(r)
		if s == nil {
			http.NotFound(w, r)
			return
		}
		// #nosec G710 -- registry validates HTTPS origin; RequestURI only supplies path/query, never authority.
		http.Redirect(w, r, s.PublicOrigin+r.URL.RequestURI(), http.StatusMovedPermanently)
	})
	guarded := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if sites.ResolveBootstrap(r) == nil {
			http.NotFound(w, r)
			return
		}
		mux.ServeHTTP(w, r)
	})
	return withSecurityHeaders(guarded, func() []*net.IPNet { return nil })
}
