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

	"github.com/rcarmo/bouncer/internal/authn"
	"github.com/rcarmo/bouncer/internal/ca"
	"github.com/rcarmo/bouncer/internal/config"
	"github.com/rcarmo/bouncer/internal/localip"
	"github.com/rcarmo/bouncer/internal/proxy"
	"github.com/rcarmo/bouncer/internal/session"
	"github.com/rcarmo/bouncer/internal/token"
	"github.com/rcarmo/bouncer/web"
)

var version = "dev"

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
	if backend != "" {
		cfg.Server.Backend = backend
	}
	if cloudflare {
		cfg.Server.Cloudflare = true
	}
	if len(hostnames) > 0 {
		cfg.Server.Hostnames = hostnames
	}
	if len(ips) > 0 {
		cfg.Server.IPAddresses = ips
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

	// Parse trusted proxies.
	trustedNets, err := localip.ParseTrustedProxies(cfg.Server.TrustedProxies)
	if err != nil {
		slog.Error("failed to parse trusted proxies", "error", err)
		os.Exit(1)
	}

	// Session store.
	sessStore, err := session.NewStore(cfg.SessionFilePath(), cfg.Session.TTLDays)
	if err != nil {
		slog.Error("failed to init session store", "error", err)
		os.Exit(1)
	}
	defer sessStore.Stop()

	// WebAuthn handler.
	authnHandler, err := authn.New(cfg, sessStore, trustedNets)
	if err != nil {
		slog.Error("failed to init webauthn", "error", err)
		os.Exit(1)
	}

	// Reverse proxy.
	rp, err := proxy.New(cfg.Server.Backend, trustedNets)
	if err != nil {
		slog.Error("failed to init proxy", "error", err)
		os.Exit(1)
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
		data, _ := web.Static.ReadFile("login.html")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(data)
	})
	mux.HandleFunc("GET /onboarding", func(w http.ResponseWriter, r *http.Request) {
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
		// Check session.
		cookie, err := r.Cookie(cfg.Session.CookieName)
		if err == nil {
			sess := sessStore.Get(cookie.Value)
			if sess != nil {
				rp.ServeHTTP(w, r)
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

	// Start server.
	addr := cfg.Server.Listen
	if cfg.Server.Cloudflare {
		// Cloudflare mode: plain HTTP.
		if addr == ":443" {
			addr = ":8080"
		}
		slog.Info("starting HTTP server (Cloudflare mode)", "addr", addr)
		srv := &http.Server{Addr: addr, Handler: mux}
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
			Addr:    addr,
			Handler: mux,
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
				data, _ := web.Static.ReadFile("onboarding.html")
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.Write(data)
			})
			origin := cfg.Server.PublicOrigin
			if origin == "" {
				origin = "https://localhost"
			}
			httpMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				target := origin + r.URL.RequestURI()
				http.Redirect(w, r, target, http.StatusMovedPermanently)
			})
			httpSrv = &http.Server{Addr: httpAddr, Handler: httpMux}
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
