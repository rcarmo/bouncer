package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/rcarmo/bouncer/internal/authn"
	"github.com/rcarmo/bouncer/internal/ca"
	"github.com/rcarmo/bouncer/internal/config"
	"github.com/rcarmo/bouncer/internal/localip"
	"github.com/rcarmo/bouncer/internal/proxy"
	"github.com/rcarmo/bouncer/internal/session"
	"github.com/rcarmo/bouncer/internal/site"
	"github.com/rcarmo/bouncer/internal/token"
	"github.com/rcarmo/bouncer/web"
)

var version = "dev"

const (
	readHeaderTimeout = 5 * time.Second
	readTimeout       = 15 * time.Second
	writeTimeout      = 30 * time.Second
	idleTimeout       = 60 * time.Second
	maxHeaderBytes    = 1 << 20
)

type stringSlice []string

func (s *stringSlice) String() string { return strings.Join(*s, ",") }
func (s *stringSlice) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func main() {
	var (
		configPath string
		listen     string
		backend    string
		onboarding bool
		cloudflare bool
		logLevel   string
		hostnames  stringSlice
		ips        stringSlice
	)

	flag.StringVar(&configPath, "config", "bouncer.json", "Path to JSON config")
	flag.StringVar(&listen, "listen", "", "Listen address (overrides config)")
	flag.StringVar(&backend, "backend", "", "Backend URL (overrides config)")
	flag.BoolVar(&onboarding, "onboarding", false, "Enable onboarding mode")
	flag.BoolVar(&cloudflare, "cloudflare", false, "Cloudflare Tunnel mode")
	flag.StringVar(&logLevel, "log-level", "info", "Log level: debug|info|warn|error")
	flag.Var(&hostnames, "hostname", "DNS name for TLS SANs (may be repeated)")
	flag.Var(&ips, "ip", "IP for TLS SANs (may be repeated)")
	flag.Parse()

	// Logging.
	setupLogging(logLevel)
	slog.Info("bouncer starting", "version", version)

	// Load config.
	cfg, err := config.Load(configPath)
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	// Apply CLI overrides.
	if listen != "" {
		cfg.Server.Listen = listen
	}
	if cloudflare {
		cfg.Server.Cloudflare = true
	}
	if len(cfg.Sites) > 0 && (backend != "" || len(hostnames) > 0 || len(ips) > 0) {
		slog.Warn("CLI overrides for backend/hostname/ip are ignored when sites[] is configured")
	} else {
		if backend != "" {
			cfg.Server.Backend = backend
		}
		if len(hostnames) > 0 {
			cfg.Server.Hostnames = hostnames
		}
		if len(ips) > 0 {
			cfg.Server.IPAddresses = ips
		}
	}

	// Onboarding mode.
	cfg.Onboarding.Enabled = onboarding
	if onboarding {
		if cfg.Onboarding.RotateTokenOnStart || cfg.Onboarding.Token == "" {
			t, err := token.Generate()
			if err != nil {
				slog.Error("failed to generate token", "error", err)
				os.Exit(1)
			}
			cfg.Onboarding.Token = t
			_ = cfg.Save()
		}
		slog.Info("=== ONBOARDING MODE ACTIVE ===")
		slog.Info("enrollment token", "token", cfg.Onboarding.Token)
		fmt.Printf("\n  Enrollment Token: %s\n\n", cfg.Onboarding.Token)
	}

	// Parse trusted proxies.
	trustedNets, err := localip.ParseTrustedProxies(cfg.Server.TrustedProxies)
	if err != nil {
		slog.Error("failed to parse trusted proxies", "error", err)
		os.Exit(1)
	}

	// Site registry.
	siteRegistry, err := site.New(cfg, trustedNets)
	if err != nil {
		slog.Error("failed to initialize site registry", "error", err)
		os.Exit(1)
	}

	// Aggregate SANs for all sites (local TLS only).
	if !cfg.Server.Cloudflare {
		cfg.Server.Hostnames = uniqueStrings(append(cfg.Server.Hostnames, siteRegistry.AllHostnames()...))
		cfg.Server.IPAddresses = uniqueStrings(append(cfg.Server.IPAddresses, siteRegistry.AllIPs()...))
	}

	// TLS setup (skip in Cloudflare mode).
	if !cfg.Server.Cloudflare {
		if err := ca.EnsureCA(cfg); err != nil {
			slog.Error("failed to ensure CA", "error", err)
			os.Exit(1)
		}
		if err := ca.EnsureServerCert(cfg); err != nil {
			slog.Error("failed to ensure server cert", "error", err)
			os.Exit(1)
		}
		slog.Info("TLS certificates ready",
			"hostnames", cfg.Server.Hostnames,
			"ips", cfg.Server.IPAddresses,
		)
	}

	// Session store.
	sessStore, err := session.NewStore(cfg.SessionFilePath(), cfg.Session.TTLDays)
	if err != nil {
		slog.Error("failed to init session store", "error", err)
		os.Exit(1)
	}
	defer sessStore.Stop()

	// WebAuthn handler.
	authnHandler, err := authn.New(cfg, sessStore, trustedNets, siteRegistry)
	if err != nil {
		slog.Error("failed to init webauthn", "error", err)
		os.Exit(1)
	}

	// Reverse proxies per site.
	proxyBySite := make(map[string]http.Handler)
	for _, s := range siteRegistry.Sites {
		rp, err := proxy.New(s.Backend, trustedNets)
		if err != nil {
			slog.Error("failed to init proxy", "error", err, "site", s.ID)
			os.Exit(1)
		}
		proxyBySite[s.ID] = rp
	}

	// Router.
	mux := http.NewServeMux()

	// WebAuthn API routes.
	mux.HandleFunc("POST /webauthn/register/options", authnHandler.RegisterOptions)
	mux.HandleFunc("POST /webauthn/register/verify", authnHandler.RegisterVerify)
	mux.HandleFunc("POST /webauthn/login/options", authnHandler.LoginOptions)
	mux.HandleFunc("POST /webauthn/login/verify", authnHandler.LoginVerify)
	mux.HandleFunc("POST /logout", authnHandler.Logout)

	// UI routes.
	mux.HandleFunc("GET /login", func(w http.ResponseWriter, r *http.Request) {
		if siteRegistry.Resolve(r) == nil {
			http.NotFound(w, r)
			return
		}
		data, _ := web.Static.ReadFile("login.html")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(data)
	})
	mux.HandleFunc("GET /onboarding", func(w http.ResponseWriter, r *http.Request) {
		if siteRegistry.Resolve(r) == nil {
			http.NotFound(w, r)
			return
		}
		if !cfg.Onboarding.Enabled {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		data, _ := web.Static.ReadFile("onboarding.html")
		html := string(data)
		// Inject local bypass meta tag if applicable.
		if cfg.Onboarding.LocalBypass {
			clientIP := localip.ExtractIP(r.RemoteAddr)
			if clientIP != nil && localip.IsLocal(clientIP) {
				html = strings.Replace(html, "<head>",
					"<head>\n<meta name=\"local-bypass\" content=\"true\">", 1)
			}
		}
		if cfg.Server.Cloudflare {
			html = strings.Replace(html, "<head>",
				"<head>\n<meta name=\"cloudflare\" content=\"true\">", 1)
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(html))
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
			w.Write(data)
		})
		mux.HandleFunc("GET /certs/rootCA.cer", func(w http.ResponseWriter, r *http.Request) {
			der, err := ca.CACertDER(cfg)
			if err != nil {
				http.Error(w, "failed to get CA cert", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/x-x509-ca-cert")
			w.Header().Set("Content-Disposition", "attachment; filename=bouncer-ca.cer")
			w.Write(der)
		})
	}

	// All other routes: authenticated proxy.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		siteCfg := siteRegistry.Resolve(r)
		if siteCfg == nil {
			http.NotFound(w, r)
			return
		}
		// Check session.
		cookie, err := r.Cookie(cfg.Session.CookieName)
		if err == nil {
			sess := sessStore.Get(cookie.Value)
			if sess != nil && sess.SiteID == siteCfg.ID {
				if rp, ok := proxyBySite[siteCfg.ID]; ok {
					rp.ServeHTTP(w, r)
					return
				}
				http.Error(w, "proxy not configured", http.StatusBadGateway)
				return
			}
		}
		// Not authenticated.
		if cfg.Onboarding.Enabled {
			http.Redirect(w, r, "/onboarding", http.StatusFound)
		} else {
			http.Redirect(w, r, "/login", http.StatusFound)
		}
	})

	// Shutdown context.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	handler := withSecurityHeaders(mux, trustedNets)

	// Start server.
	addr := cfg.Server.Listen
	if cfg.Server.Cloudflare {
		// Cloudflare mode: plain HTTP.
		if addr == ":443" {
			addr = ":8080"
		}
		slog.Info("starting HTTP server (Cloudflare mode)", "addr", addr)
		srv := &http.Server{
			Addr:              addr,
			Handler:           handler,
			ReadHeaderTimeout: readHeaderTimeout,
			ReadTimeout:       readTimeout,
			WriteTimeout:      writeTimeout,
			IdleTimeout:       idleTimeout,
			MaxHeaderBytes:    maxHeaderBytes,
		}
		go func() {
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				slog.Error("server error", "error", err)
				os.Exit(1)
			}
		}()
		<-ctx.Done()
		slog.Info("shutting down...")
		srv.Shutdown(context.Background())
	} else {
		// Local TLS mode.
		certPEM, keyPEM, err := ca.ServerTLSKeyPair(cfg)
		if err != nil {
			slog.Error("failed to get TLS keypair", "error", err)
			os.Exit(1)
		}
		tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			slog.Error("failed to parse TLS cert", "error", err)
			os.Exit(1)
		}

		server := &http.Server{
			Addr:              addr,
			Handler:           handler,
			ReadHeaderTimeout: readHeaderTimeout,
			ReadTimeout:       readTimeout,
			WriteTimeout:      writeTimeout,
			IdleTimeout:       idleTimeout,
			MaxHeaderBytes:    maxHeaderBytes,
			TLSConfig: &tls.Config{
				Certificates: []tls.Certificate{tlsCert},
				MinVersion:   tls.VersionTLS12,
			},
		}

		// Also listen on HTTP for cert/profile downloads.
		var httpSrv *http.Server
		go func() {
			httpAddr := ":80"
			if addr != ":443" {
				_, port, _ := net.SplitHostPort(addr)
				if port == "443" {
					httpAddr = ":80"
				} else {
					httpAddr = ":8080"
				}
			}
			httpMux := http.NewServeMux()
			httpMux.HandleFunc("GET /certs/rootCA.mobileconfig", func(w http.ResponseWriter, r *http.Request) {
				data, err := ca.GenerateMobileconfig(cfg)
				if err != nil {
					http.Error(w, "error", http.StatusInternalServerError)
					return
				}
				w.Header().Set("Content-Type", "application/x-apple-aspen-config")
				w.Header().Set("Content-Disposition", "attachment; filename=bouncer.mobileconfig")
				w.Write(data)
			})
			httpMux.HandleFunc("GET /certs/rootCA.cer", func(w http.ResponseWriter, r *http.Request) {
				der, err := ca.CACertDER(cfg)
				if err != nil {
					http.Error(w, "error", http.StatusInternalServerError)
					return
				}
				w.Header().Set("Content-Type", "application/x-x509-ca-cert")
				w.Header().Set("Content-Disposition", "attachment; filename=bouncer-ca.cer")
				w.Write(der)
			})
			httpMux.HandleFunc("GET /onboarding", func(w http.ResponseWriter, r *http.Request) {
				if siteRegistry.Resolve(r) == nil {
					http.NotFound(w, r)
					return
				}
				data, _ := web.Static.ReadFile("onboarding.html")
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.Write(data)
			})
			httpMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				siteCfg := siteRegistry.Resolve(r)
				if siteCfg == nil || siteCfg.PublicOrigin == "" {
					http.NotFound(w, r)
					return
				}
				target := siteCfg.PublicOrigin + r.URL.RequestURI()
				http.Redirect(w, r, target, http.StatusMovedPermanently)
			})
			httpSrv = &http.Server{
				Addr:              httpAddr,
				Handler:           withSecurityHeaders(httpMux, trustedNets),
				ReadHeaderTimeout: readHeaderTimeout,
				ReadTimeout:       readTimeout,
				WriteTimeout:      writeTimeout,
				IdleTimeout:       idleTimeout,
				MaxHeaderBytes:    maxHeaderBytes,
			}
			slog.Info("starting HTTP server (cert downloads)", "addr", httpAddr)
			if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				slog.Warn("HTTP server error", "error", err)
			}
		}()

		slog.Info("starting HTTPS server", "addr", addr, "origin", cfg.Server.PublicOrigin)
		ln, err := tls.Listen("tcp", addr, server.TLSConfig)
		if err != nil {
			slog.Error("TLS listen error", "error", err)
			os.Exit(1)
		}
		go func() {
			if err := server.Serve(ln); err != nil && err != http.ErrServerClosed {
				slog.Error("server error", "error", err)
				os.Exit(1)
			}
		}()
		<-ctx.Done()
		slog.Info("shutting down...")
		server.Shutdown(context.Background())
		if httpSrv != nil {
			httpSrv.Shutdown(context.Background())
		}
	}
}

func withSecurityHeaders(next http.Handler, trusted []*net.IPNet) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), usb=(), payment=()")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:")
		if isHTTPSRequest(r, trusted) {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

func isHTTPSRequest(r *http.Request, trusted []*net.IPNet) bool {
	if r.TLS != nil {
		return true
	}
	clientIP := localip.ExtractIP(r.RemoteAddr)
	if clientIP != nil && localip.IsTrustedProxy(clientIP, trusted) {
		return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
	}
	return false
}

func setupLogging(level string) {
	var lvl slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl})))
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0, len(values))
	for _, v := range values {
		if v == "" {
			continue
		}
		key := strings.ToLower(v)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, v)
	}
	return out
}
