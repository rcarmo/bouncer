package main

import (
	"fmt"
	"github.com/rcarmo/bouncer/internal/authn"
	"github.com/rcarmo/bouncer/internal/ca"
	"github.com/rcarmo/bouncer/internal/config"
	"github.com/rcarmo/bouncer/internal/session"
	"github.com/rcarmo/bouncer/internal/site"
	"github.com/rcarmo/bouncer/web"
	"log/slog"
	"net"
	"net/http"
	"strings"
)

func newRouter(cfg *config.Config, siteRegistry *site.Registry, authnHandler *authn.Handler, proxyBySite map[string]http.Handler, sessStore *session.Store, trusted []*net.IPNet) http.Handler {
	// Router.
	mux := http.NewServeMux()

	// WebAuthn API routes. These dispatch through authnHandler so a SIGHUP
	// config reload can add hostnames/sites without restarting the process.
	mux.HandleFunc("POST /webauthn/register/options", func(w http.ResponseWriter, r *http.Request) { authnHandler.RegisterOptions(w, r) })
	mux.HandleFunc("POST /webauthn/register/verify", func(w http.ResponseWriter, r *http.Request) { authnHandler.RegisterVerify(w, r) })
	mux.HandleFunc("POST /webauthn/login/options", func(w http.ResponseWriter, r *http.Request) { authnHandler.LoginOptions(w, r) })
	mux.HandleFunc("POST /webauthn/login/verify", func(w http.ResponseWriter, r *http.Request) { authnHandler.LoginVerify(w, r) })
	mux.HandleFunc("POST /logout", func(w http.ResponseWriter, r *http.Request) { authnHandler.Logout(w, r) })

	// UI routes.
	mux.HandleFunc("GET /static/{script}", web.ServeScript)
	mux.HandleFunc("GET /static/icon-256.png", func(w http.ResponseWriter, r *http.Request) {
		data, err := web.Static.ReadFile("icon-256.png")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "image/png")
		if _, err := w.Write(data); err != nil {
			slog.Warn("write icon", "error", err)
		}
	})
	mux.HandleFunc("GET /login", func(w http.ResponseWriter, r *http.Request) {
		if siteRegistry.Resolve(r) == nil {
			http.NotFound(w, r)
			return
		}
		data, _ := web.Static.ReadFile("login.html")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if _, err := w.Write(data); err != nil {
			slog.Warn("write login page", "error", err)
		}
	})
	mux.HandleFunc("GET /onboarding", func(w http.ResponseWriter, r *http.Request) {
		curCfg := cfg
		if siteRegistry.Resolve(r) == nil {
			http.NotFound(w, r)
			return
		}
		if !curCfg.Onboarding.Enabled {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		data, _ := web.Static.ReadFile("onboarding.html")
		html := string(data)
		trust := ""
		if !curCfg.Server.Cloudflare {
			fingerprint, err := ca.FingerprintSHA256(curCfg)
			if err != nil {
				http.Error(w, "CA fingerprint unavailable", http.StatusInternalServerError)
				return
			}
			trust = web.TrustContent(fingerprint)
		}
		html = strings.ReplaceAll(html, "{{TRUST_CONTENT}}", trust)
		// Inject local bypass meta tag if applicable.
		if authnHandler.IsLocalBypass(r) {
			{
				html = strings.Replace(html, "<head>",
					"<head>\n<meta name=\"local-bypass\" content=\"true\">", 1)
			}
		}
		if curCfg.Server.Cloudflare {
			html = strings.Replace(html, "<head>",
				"<head>\n<meta name=\"cloudflare\" content=\"true\">", 1)
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if _, err := w.Write([]byte(html)); err != nil {
			slog.Warn("write onboarding page", "error", err)
		}
	})

	// Cert routes (local TLS mode only).
	if !cfg.Server.Cloudflare {
		mux.HandleFunc("GET /certs/rootCA.mobileconfig", func(w http.ResponseWriter, r *http.Request) {
			data, err := ca.GenerateMobileconfig(cfg)
			if err != nil {
				http.Error(w, "failed to generate profile", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/x-apple-aspen-config")
			w.Header().Set("Content-Disposition", "attachment; filename=bouncer.mobileconfig")
			if _, err := w.Write(data); err != nil {
				slog.Warn("write mobileconfig", "error", err)
			}
		})
		mux.HandleFunc("GET /certs/rootCA.cer", func(w http.ResponseWriter, r *http.Request) {
			der, err := ca.CACertDER(cfg)
			if err != nil {
				http.Error(w, "failed to get CA cert", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/x-x509-ca-cert")
			w.Header().Set("Content-Disposition", "attachment; filename=bouncer-ca.cer")
			if _, err := w.Write(der); err != nil {
				slog.Warn("write ca cert", "error", err)
			}
		})
	}

	// All other routes: authenticated proxy.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		curCfg := cfg
		siteCfg := siteRegistry.Resolve(r)
		if siteCfg == nil {
			http.NotFound(w, r)
			return
		}
		// Check session.
		cookie, err := r.Cookie(curCfg.Session.CookieName)
		if err == nil {
			sess := sessStore.Get(cookie.Value)
			if sessionAuthorized(curCfg, sess, siteCfg.ID) {
				if rp := proxyBySite[siteCfg.ID]; rp != nil {
					if strings.EqualFold(strings.TrimSpace(r.Header.Get("Upgrade")), "websocket") && (len(r.Header.Values("Origin")) != 1 || !authn.OriginMatches(r.Header.Get("Origin"), siteCfg.PublicOrigin)) {
						http.Error(w, "invalid websocket origin", http.StatusForbidden)
						return
					}
					// Backend applications own their CSP and permissions policy.
					for _, name := range []string{"Content-Security-Policy", "Permissions-Policy", "X-Frame-Options", "Referrer-Policy", "Cache-Control"} {
						w.Header().Del(name)
					}
					// The backend must not receive Bouncer's bearer credential.
					out := r.Clone(r.Context())
					out.Header.Del("Cookie")
					for _, cookie := range r.Cookies() {
						if cookie.Name != curCfg.Session.CookieName {
							out.AddCookie(cookie)
						}
					}
					rp.ServeHTTP(w, out)
					return
				}
				http.Error(w, "proxy not configured", http.StatusBadGateway)
				return
			}
		}
		// Not authenticated.
		if r.Method == http.MethodGet && r.URL.Path == "/" {
			data, _ := web.Static.ReadFile("landing.html")
			html := string(data)
			html = strings.Replace(html, "<head>", fmt.Sprintf("<head>\n<meta name=\"onboarding\" content=\"%t\">", curCfg.Onboarding.Enabled), 1)
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			if _, err := w.Write([]byte(html)); err != nil {
				slog.Warn("write landing page", "error", err)
			}
			return
		}
		if curCfg.Onboarding.Enabled {
			http.Redirect(w, r, "/onboarding", http.StatusFound)
		} else {
			http.Redirect(w, r, "/login", http.StatusFound)
		}
	})

	return withSecurityHeaders(mux, func() []*net.IPNet { return trusted })
}
func sessionAuthorized(cfg *config.Config, sess *session.Session, siteID string) bool {
	if sess == nil || sess.SiteID != siteID {
		return false
	}
	user := cfg.FindUserByID(siteID, sess.UserID)
	if user == nil || sess.CredentialID == "" {
		return false
	}
	for _, cred := range user.Credentials {
		if cred.ID == sess.CredentialID {
			return true
		}
	}
	return false
}
