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
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/rcarmo/bouncer/internal/authn"
	"github.com/rcarmo/bouncer/internal/ca"
	"github.com/rcarmo/bouncer/internal/config"
	"github.com/rcarmo/bouncer/internal/localip"
	"github.com/rcarmo/bouncer/internal/mdns"
	"github.com/rcarmo/bouncer/internal/notify"
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
	// Keep WriteTimeout disabled: proxied Piclaw SSE streams and WebSocket
	// upgrades are intentionally long-lived. Slowloris protection still comes
	// from ReadHeaderTimeout/ReadTimeout and authenticated proxying.
	writeTimeout   = 0 * time.Second
	idleTimeout    = 60 * time.Second
	maxHeaderBytes = 1 << 20
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
		dbipUpdate bool
	)

	flag.StringVar(&configPath, "config", "bouncer.json", "Path to JSON config")
	flag.StringVar(&listen, "listen", "", "Listen address (overrides config)")
	flag.StringVar(&backend, "backend", "", "Backend URL (overrides config)")
	flag.BoolVar(&onboarding, "onboarding", false, "Enable onboarding mode")
	flag.BoolVar(&cloudflare, "cloudflare", false, "Cloudflare Tunnel mode")
	flag.BoolVar(&dbipUpdate, "dbip-update", false, "Download/update DB-IP Lite database and exit")
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

	if dbipUpdate {
		if !cfg.Onboarding.GeoIP.DBIP.Enabled {
			slog.Error("dbip update requested but dbip is disabled")
			os.Exit(1)
		}
		timeout := time.Duration(cfg.Onboarding.GeoIP.DBIP.DownloadTimeoutSeconds) * time.Second
		if timeout <= 0 {
			timeout = 30 * time.Second
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		err := notify.RunDBIPUpdate(ctx, cfg.Onboarding.GeoIP.DBIP, filepath.Dir(cfg.Path()))
		cancel()
		if err != nil {
			slog.Error("dbip update failed", "error", err)
			os.Exit(1)
		}
		slog.Info("dbip update complete")
		os.Exit(0)
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
		if cfg.Onboarding.OneTimeToken {
			slog.Info("=== ONBOARDING MODE ACTIVE ===")
			slog.Info("enrollment tokens are one-time and issued on demand")
		} else {
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
	}

	// Parse trusted proxies.
	if cfg.Server.Cloudflare {
		cfg.Server.TrustedProxies = uniqueStrings(append(cfg.Server.TrustedProxies, "127.0.0.1/32", "::1/128"))
	}
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

	mdnsAnnouncer, err := mdns.Start(cfg, siteRegistry.Sites)
	if err != nil {
		slog.Warn("mDNS announcements disabled", "error", err)
		mdnsAnnouncer = &mdns.Announcer{}
	}
	defer mdnsAnnouncer.Close()

	// Route/auth state is hot-swappable on SIGHUP. Handlers copy the current
	// pointers under the lock and then release it before proxying long-lived
	// responses such as SSE or WebSocket upgrades.
	var stateMu sync.RWMutex
	var currentTLSCert tls.Certificate
	currentConfig := func() *config.Config {
		stateMu.RLock()
		defer stateMu.RUnlock()
		return cfg
	}
	currentSites := func() *site.Registry {
		stateMu.RLock()
		defer stateMu.RUnlock()
		return siteRegistry
	}
	currentAuthn := func() *authn.Handler {
		stateMu.RLock()
		defer stateMu.RUnlock()
		return authnHandler
	}
	currentProxy := func(siteID string) http.Handler {
		stateMu.RLock()
		defer stateMu.RUnlock()
		return proxyBySite[siteID]
	}
	currentTrusted := func() []*net.IPNet {
		stateMu.RLock()
		defer stateMu.RUnlock()
		return trustedNets
	}
	currentSiteListens := func() []string {
		stateMu.RLock()
		defer stateMu.RUnlock()
		listens := make([]string, 0)
		for _, s := range siteRegistry.Sites {
			if strings.TrimSpace(s.Listen) != "" {
				listens = append(listens, s.Listen)
			}
		}
		return listens
	}
	defer func() { currentAuthn().Close() }()

	// Router.
	mux := http.NewServeMux()

	// WebAuthn API routes. These dispatch through currentAuthn() so a SIGHUP
	// config reload can add hostnames/sites without restarting the process.
	mux.HandleFunc("POST /webauthn/register/options", func(w http.ResponseWriter, r *http.Request) { currentAuthn().RegisterOptions(w, r) })
	mux.HandleFunc("POST /webauthn/register/verify", func(w http.ResponseWriter, r *http.Request) { currentAuthn().RegisterVerify(w, r) })
	mux.HandleFunc("POST /webauthn/login/options", func(w http.ResponseWriter, r *http.Request) { currentAuthn().LoginOptions(w, r) })
	mux.HandleFunc("POST /webauthn/login/verify", func(w http.ResponseWriter, r *http.Request) { currentAuthn().LoginVerify(w, r) })
	mux.HandleFunc("POST /logout", func(w http.ResponseWriter, r *http.Request) { currentAuthn().Logout(w, r) })

	// UI routes.
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
		if currentSites().Resolve(r) == nil {
			http.NotFound(w, r)
			return
		}
		data, _ := web.Static.ReadFile("login.html")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if _, err := w.Write(data); err != nil {
			slog.Warn("write login page", "error", err)
		}
	})
	mux.HandleFunc("GET /onboarding", func(w http.ResponseWriter, r *http.Request) {
		curCfg := currentConfig()
		if currentSites().Resolve(r) == nil {
			http.NotFound(w, r)
			return
		}
		if !curCfg.Onboarding.Enabled {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		data, _ := web.Static.ReadFile("onboarding.html")
		html := string(data)
		// Inject local bypass meta tag if applicable.
		if curCfg.Onboarding.LocalBypass {
			clientIP := localip.ExtractIP(r.RemoteAddr)
			if clientIP != nil && localip.IsLocal(clientIP) {
				html = strings.Replace(html, "<head>",
					"<head>\n<meta name=\"local-bypass\" content=\"true\">", 1)
			}
		}
		if curCfg.Server.Cloudflare {
			html = strings.Replace(html, "<head>",
				"<head>\n<meta name=\"cloudflare\" content=\"true\">", 1)
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if _, err := w.Write([]byte(html)); err != nil {
			slog.Warn("write onboarding page", "error", err)
		}
	})

	// Cert routes (local TLS mode only).
	if !cfg.Server.Cloudflare {
		mux.HandleFunc("GET /certs/rootCA.mobileconfig", func(w http.ResponseWriter, r *http.Request) {
			data, err := ca.GenerateMobileconfig(currentConfig())
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
			der, err := ca.CACertDER(currentConfig())
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
		curCfg := currentConfig()
		siteCfg := currentSites().Resolve(r)
		if siteCfg == nil {
			http.NotFound(w, r)
			return
		}
		// Check session.
		cookie, err := r.Cookie(curCfg.Session.CookieName)
		if err == nil {
			sess := sessStore.Get(cookie.Value)
			if sess != nil && sess.SiteID == siteCfg.ID {
				if rp := currentProxy(siteCfg.ID); rp != nil {
					rp.ServeHTTP(w, r)
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

	// Shutdown context.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	handler := withSecurityHeaders(mux, currentTrusted)

	reloadConfig := func() error {
		nextCfg, err := config.Load(configPath)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}

		// Reapply command-line overrides that are process-level policy.
		if listen != "" {
			nextCfg.Server.Listen = listen
		}
		if cloudflare {
			nextCfg.Server.Cloudflare = true
		}
		if len(nextCfg.Sites) > 0 && (backend != "" || len(hostnames) > 0 || len(ips) > 0) {
			slog.Warn("CLI overrides for backend/hostname/ip are ignored when sites[] is configured")
		} else {
			if backend != "" {
				nextCfg.Server.Backend = backend
			}
			if len(hostnames) > 0 {
				nextCfg.Server.Hostnames = hostnames
			}
			if len(ips) > 0 {
				nextCfg.Server.IPAddresses = ips
			}
		}
		nextCfg.Onboarding.Enabled = onboarding

		stateMu.RLock()
		oldListen := cfg.Server.Listen
		oldCloudflare := cfg.Server.Cloudflare
		stateMu.RUnlock()
		if nextCfg.Server.Listen != oldListen {
			slog.Warn("ignoring listen address change during hot reload", "configured", nextCfg.Server.Listen, "active", oldListen)
			nextCfg.Server.Listen = oldListen
		}
		if nextCfg.Server.Cloudflare != oldCloudflare {
			slog.Warn("ignoring cloudflare/local TLS mode change during hot reload", "configured", nextCfg.Server.Cloudflare, "active", oldCloudflare)
			nextCfg.Server.Cloudflare = oldCloudflare
		}

		if nextCfg.Server.Cloudflare {
			nextCfg.Server.TrustedProxies = uniqueStrings(append(nextCfg.Server.TrustedProxies, "127.0.0.1/32", "::1/128"))
		}
		nextTrusted, err := localip.ParseTrustedProxies(nextCfg.Server.TrustedProxies)
		if err != nil {
			return fmt.Errorf("parse trusted proxies: %w", err)
		}
		nextSites, err := site.New(nextCfg, nextTrusted)
		if err != nil {
			return fmt.Errorf("site registry: %w", err)
		}

		if !nextCfg.Server.Cloudflare {
			nextCfg.Server.Hostnames = uniqueStrings(append(nextCfg.Server.Hostnames, nextSites.AllHostnames()...))
			nextCfg.Server.IPAddresses = uniqueStrings(append(nextCfg.Server.IPAddresses, nextSites.AllIPs()...))
			if err := ca.EnsureCA(nextCfg); err != nil {
				return fmt.Errorf("ensure CA: %w", err)
			}
			if err := ca.EnsureServerCert(nextCfg); err != nil {
				return fmt.Errorf("ensure server cert: %w", err)
			}
		}

		nextAuthn, err := authn.New(nextCfg, sessStore, nextTrusted, nextSites)
		if err != nil {
			return fmt.Errorf("webauthn: %w", err)
		}
		nextProxyBySite := make(map[string]http.Handler)
		for _, s := range nextSites.Sites {
			rp, err := proxy.New(s.Backend, nextTrusted)
			if err != nil {
				return fmt.Errorf("proxy for site %q: %w", s.ID, err)
			}
			nextProxyBySite[s.ID] = rp
		}

		nextMDNS, err := mdns.Start(nextCfg, nextSites.Sites)
		if err != nil {
			slog.Warn("mDNS announcements disabled after reload", "error", err)
			nextMDNS = &mdns.Announcer{}
		}

		var nextTLSCert tls.Certificate
		if !nextCfg.Server.Cloudflare {
			certPEM, keyPEM, err := ca.ServerTLSKeyPair(nextCfg)
			if err != nil {
				return fmt.Errorf("get TLS keypair: %w", err)
			}
			nextTLSCert, err = tls.X509KeyPair(certPEM, keyPEM)
			if err != nil {
				return fmt.Errorf("parse TLS cert: %w", err)
			}
		}

		stateMu.Lock()
		oldAuthn := authnHandler
		oldMDNS := mdnsAnnouncer
		cfg = nextCfg
		trustedNets = nextTrusted
		siteRegistry = nextSites
		authnHandler = nextAuthn
		proxyBySite = nextProxyBySite
		if !nextCfg.Server.Cloudflare {
			currentTLSCert = nextTLSCert
		}
		mdnsAnnouncer = nextMDNS
		stateMu.Unlock()
		oldAuthn.Close()
		oldMDNS.Close()
		slog.Info("configuration reloaded", "sites", len(nextSites.Sites), "hostnames", nextSites.AllHostnames())
		return nil
	}

	reloadCh := make(chan os.Signal, 1)
	signal.Notify(reloadCh, syscall.SIGHUP)
	go func() {
		for range reloadCh {
			if err := reloadConfig(); err != nil {
				slog.Error("config reload failed", "error", err)
			}
		}
	}()

	startHTTPServer := func(ctx context.Context, addr string, handler http.Handler) *http.Server {
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
				slog.Error("server error", "addr", addr, "error", err)
				os.Exit(1)
			}
		}()
		go func() {
			<-ctx.Done()
			if err := srv.Shutdown(context.Background()); err != nil {
				slog.Warn("http shutdown", "addr", addr, "error", err)
			}
		}()
		return srv
	}

	startHTTPSServer := func(ctx context.Context, addr string, handler http.Handler, tlsConfig *tls.Config) *http.Server {
		server := &http.Server{
			Addr:              addr,
			Handler:           handler,
			ReadHeaderTimeout: readHeaderTimeout,
			ReadTimeout:       readTimeout,
			WriteTimeout:      writeTimeout,
			IdleTimeout:       idleTimeout,
			MaxHeaderBytes:    maxHeaderBytes,
			TLSConfig:         tlsConfig,
		}
		ln, err := tls.Listen("tcp", addr, tlsConfig)
		if err != nil {
			slog.Error("TLS listen error", "addr", addr, "error", err)
			os.Exit(1)
		}
		go func() {
			if err := server.Serve(ln); err != nil && err != http.ErrServerClosed {
				slog.Error("server error", "addr", addr, "error", err)
				os.Exit(1)
			}
		}()
		go func() {
			<-ctx.Done()
			if err := server.Shutdown(context.Background()); err != nil {
				slog.Warn("https shutdown", "addr", addr, "error", err)
			}
		}()
		return server
	}

	// Start server.
	addr := cfg.Server.Listen
	if cfg.Server.Cloudflare {
		// Cloudflare mode: plain HTTP.
		if addr == ":443" {
			addr = ":8080"
		}
		slog.Info("starting HTTP server (Cloudflare mode)", "addr", addr)
		startHTTPServer(ctx, addr, handler)
		for _, aliasAddr := range uniqueStrings(currentSiteListens()) {
			if aliasAddr == addr {
				continue
			}
			slog.Info("starting HTTP port alias", "addr", aliasAddr)
			startHTTPServer(ctx, aliasAddr, handler)
		}
		<-ctx.Done()
		slog.Info("shutting down...")
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
		currentTLSCert = tlsCert

		tlsConfig := &tls.Config{
			GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
				stateMu.RLock()
				defer stateMu.RUnlock()
				return &currentTLSCert, nil
			},
			MinVersion: tls.VersionTLS12,
		}

		// Also listen on HTTP for cert/profile downloads.
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
				data, err := ca.GenerateMobileconfig(currentConfig())
				if err != nil {
					http.Error(w, "error", http.StatusInternalServerError)
					return
				}
				w.Header().Set("Content-Type", "application/x-apple-aspen-config")
				w.Header().Set("Content-Disposition", "attachment; filename=bouncer.mobileconfig")
				if _, err := w.Write(data); err != nil {
					slog.Warn("write mobileconfig", "error", err)
				}
			})
			httpMux.HandleFunc("GET /certs/rootCA.cer", func(w http.ResponseWriter, r *http.Request) {
				der, err := ca.CACertDER(currentConfig())
				if err != nil {
					http.Error(w, "error", http.StatusInternalServerError)
					return
				}
				w.Header().Set("Content-Type", "application/x-x509-ca-cert")
				w.Header().Set("Content-Disposition", "attachment; filename=bouncer-ca.cer")
				if _, err := w.Write(der); err != nil {
					slog.Warn("write ca cert", "error", err)
				}
			})
			httpMux.HandleFunc("GET /onboarding", func(w http.ResponseWriter, r *http.Request) {
				if currentSites().Resolve(r) == nil {
					http.NotFound(w, r)
					return
				}
				data, _ := web.Static.ReadFile("onboarding.html")
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				if _, err := w.Write(data); err != nil {
					slog.Warn("write onboarding page", "error", err)
				}
			})
			httpMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				siteCfg := currentSites().Resolve(r)
				if siteCfg == nil || siteCfg.PublicOrigin == "" {
					http.NotFound(w, r)
					return
				}
				target := siteCfg.PublicOrigin + r.URL.RequestURI()
				http.Redirect(w, r, target, http.StatusMovedPermanently)
			})
			startHTTPServer(ctx, httpAddr, withSecurityHeaders(httpMux, currentTrusted))
			slog.Info("starting HTTP server (cert downloads)", "addr", httpAddr)
		}()

		slog.Info("starting HTTPS server", "addr", addr, "origin", cfg.Server.PublicOrigin)
		startHTTPSServer(ctx, addr, handler, tlsConfig)
		for _, aliasAddr := range uniqueStrings(currentSiteListens()) {
			if aliasAddr == addr {
				continue
			}
			slog.Info("starting HTTPS port alias", "addr", aliasAddr)
			startHTTPSServer(ctx, aliasAddr, handler, tlsConfig)
		}
		<-ctx.Done()
		slog.Info("shutting down...")
	}
}

func withSecurityHeaders(next http.Handler, trustedFn func() []*net.IPNet) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), usb=(), payment=()")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:")
		if isHTTPSRequest(r, trustedFn()) {
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
