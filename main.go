package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"html"
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

// Test-only builds install a profiler; production leaves this a no-op.
var finishAllocationProfile = func() {}

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
	defer finishAllocationProfile()
	var (
		configPath      string
		listen          string
		backend         string
		onboarding      bool
		cloudflare      bool
		logLevel        string
		hostnames       stringSlice
		ips             stringSlice
		dbipUpdate      bool
		fingerprintCA   bool
		resetEnrollment bool
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
	flag.BoolVar(&fingerprintCA, "fingerprint-CA", false, "Print existing CA certificate SHA256 fingerprint through a trusted console and exit")
	flag.BoolVar(&resetEnrollment, "reset-enrollment", false, "Reset enrollment lockout, print a new code through a trusted console and exit")
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

	if resetEnrollment {
		code, err := token.Generate()
		if err != nil {
			slog.Error("generate enrollment code", "error", err)
			os.Exit(1)
		}
		if err := cfg.SetEnrollmentToken(code); err != nil {
			slog.Error("reset enrollment", "error", err)
			os.Exit(1)
		}
		fmt.Println("Enrollment code:", code)
		return
	}

	// Read-only: this command never generates or replaces a trust root.
	if fingerprintCA {
		fingerprint, err := ca.FingerprintSHA256(cfg)
		if err != nil {
			slog.Error("CA fingerprint unavailable", "error", err)
			os.Exit(1)
		}
		fmt.Println("CA certificate SHA256:", fingerprint)
		return
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

	applyCLIOrigin(cfg, hostnames, ips)
	// Onboarding mode.
	if onboarding {
		cfg.Onboarding.Enabled = true
	}
	if cfg.Onboarding.Enabled {
		if cfg.Onboarding.OneTimeToken {
			slog.Info("=== ONBOARDING MODE ACTIVE ===")
			slog.Info("enrollment tokens are one-time and issued on demand")
		} else {
			if !cfg.Onboarding.TokenLocked && (cfg.Onboarding.RotateTokenOnStart || cfg.Onboarding.Token == "") {
				t, err := token.Generate()
				if err != nil {
					slog.Error("failed to generate token", "error", err)
					os.Exit(1)
				}
				if _, err := cfg.EnsureEnrollmentToken(t); err != nil {
					slog.Error("save enrollment token", "error", err)
					os.Exit(1)
				}
			}
			slog.Info("=== ONBOARDING MODE ACTIVE ===")
			slog.Info("enrollment code configured; retrieve through trusted --reset-enrollment command or Pushover")
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
		fingerprint, err := ca.FingerprintSHA256(cfg)
		if err != nil {
			slog.Error("CA fingerprint unavailable", "error", err)
			os.Exit(1)
		}
		slog.Info("CA certificate SHA256; share through an independent trusted channel before installing trust", "fingerprint", fingerprint)
		fmt.Printf("\n  CA certificate SHA256: %s\n  Compare through an independent trusted channel before installing root trust.\n\n", fingerprint)
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
	defer func() { mdnsAnnouncer.Close() }()

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
	defer func() { authnHandler.Close() }()

	var authGate sync.RWMutex
	activeHandler := newRouter(cfg, siteRegistry, authnHandler, proxyBySite, sessStore, trustedNets)

	// Shutdown context.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/webauthn/") || r.URL.Path == "/logout" {
			authGate.RLock()
			defer authGate.RUnlock()
		}
		stateMu.RLock()
		next := activeHandler
		stateMu.RUnlock()
		next.ServeHTTP(w, r)
	})

	reloadConfig := func() error {
		authGate.Lock()
		defer authGate.Unlock()
		if _, err := os.Stat(configPath); err != nil {
			return fmt.Errorf("reload config: %w", err)
		}
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
		applyCLIOrigin(nextCfg, hostnames, ips)
		if onboarding {
			nextCfg.Onboarding.Enabled = true
		}

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

		if nextCfg.Session != cfg.Session {
			return fmt.Errorf("session settings require restart")
		}
		if nextCfg.Server.HTTPListen != cfg.Server.HTTPListen {
			return fmt.Errorf("HTTP bootstrap listener changes require restart")
		}
		if !sameListeners(cfg, nextCfg) {
			return fmt.Errorf("site listener changes require restart")
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
		committed := false
		defer func() {
			if !committed {
				nextAuthn.Close()
			}
		}()
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

		defer func() {
			if !committed {
				nextMDNS.Close()
			}
		}()
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
		activeHandler = newRouter(nextCfg, nextSites, nextAuthn, nextProxyBySite, sessStore, nextTrusted)
		committed = true
		stateMu.Unlock()
		oldAuthn.Close()
		oldMDNS.Close()
		slog.Info("configuration reloaded", "sites", len(nextSites.Sites), "hostnames", nextSites.AllHostnames())
		return nil
	}

	// Start reload processing only after initial state/certificates/listeners are
	// fully initialized; stop and join it before retiring the active generation.
	startReload := func() func() {
		reloadCh := make(chan os.Signal, 1)
		signal.Notify(reloadCh, syscall.SIGHUP)
		done := make(chan struct{})
		go func() {
			defer close(done)
			for {
				select {
				case <-ctx.Done():
					return
				case <-reloadCh:
					if err := reloadConfig(); err != nil {
						slog.Error("config reload failed", "error", err)
					}
				}
			}
		}()
		return func() { signal.Stop(reloadCh); <-done }
	}

	var servers []*http.Server
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		for _, srv := range servers {
			if err := srv.Shutdown(ctx); err != nil {
				_ = srv.Close()
			}
		}
	}()
	startHTTPServer := func(addr string, handler http.Handler) *http.Server {
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
		servers = append(servers, srv)
		return srv
	}

	startHTTPSServer := func(addr string, handler http.Handler, tlsConfig *tls.Config) *http.Server {
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
		servers = append(servers, server)
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
		startHTTPServer(addr, handler)
		for _, aliasAddr := range uniqueStrings(currentSiteListens()) {
			if aliasAddr == addr {
				continue
			}
			slog.Info("starting HTTP port alias", "addr", aliasAddr)
			startHTTPServer(aliasAddr, handler)
		}
		stopReload := startReload()
		defer stopReload()
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
				cert := currentTLSCert
				return &cert, nil
			},
			MinVersion: tls.VersionTLS12,
		}

		// Also listen on HTTP for cert/profile downloads.
		func() {
			httpAddr := ":80"
			if addr != ":443" {
				_, port, _ := net.SplitHostPort(addr)
				if port == "443" {
					httpAddr = ":80"
				} else {
					httpAddr = ":8080"
				}
			}
			if cfg.Server.HTTPListen != "" {
				httpAddr = cfg.Server.HTTPListen
			}
			httpMux := http.NewServeMux()
			httpMux.HandleFunc("GET /static/{script}", web.ServeScript)
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
				stateMu.RLock()
				sites := siteRegistry
				stateMu.RUnlock()
				if sites.ResolveBootstrap(r) == nil {
					http.NotFound(w, r)
					return
				}
				data, _ := web.Static.ReadFile("trust.html")
				fingerprint, err := ca.FingerprintSHA256(currentConfig())
				if err != nil {
					http.Error(w, "CA fingerprint unavailable", http.StatusInternalServerError)
					return
				}
				page := strings.ReplaceAll(string(data), "{{TRUST_CONTENT}}", web.TrustContent(fingerprint))
				w.Header().Set("Cache-Control", "no-store")
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				if _, err := w.Write([]byte(strings.ReplaceAll(page, "{{HTTPS_ORIGIN}}", html.EscapeString(sites.ResolveBootstrap(r).PublicOrigin)))); err != nil {
					slog.Warn("write onboarding page", "error", err)
				}
			})
			httpMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				stateMu.RLock()
				sites := siteRegistry
				stateMu.RUnlock()
				siteCfg := sites.ResolveBootstrap(r)
				if siteCfg == nil || siteCfg.PublicOrigin == "" {
					http.NotFound(w, r)
					return
				}
				target := siteCfg.PublicOrigin + r.URL.RequestURI()
				http.Redirect(w, r, target, http.StatusMovedPermanently)
			})
			startHTTPServer(httpAddr, withSecurityHeaders(httpMux, currentTrusted))
			slog.Info("starting HTTP server (cert downloads)", "addr", httpAddr)
		}()

		slog.Info("starting HTTPS server", "addr", addr, "origin", cfg.Server.PublicOrigin)
		startHTTPSServer(addr, handler, tlsConfig)
		for _, aliasAddr := range uniqueStrings(currentSiteListens()) {
			if aliasAddr == addr {
				continue
			}
			slog.Info("starting HTTPS port alias", "addr", aliasAddr)
			startHTTPSServer(aliasAddr, handler, tlsConfig)
		}
		stopReload := startReload()
		defer stopReload()
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
		w.Header().Set("Content-Security-Policy", "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:")
		if isHTTPSRequest(r, trustedFn()) {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000")
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

func sameListeners(a, b *config.Config) bool {
	listeners := func(c *config.Config) map[string]struct{} {
		m := map[string]struct{}{}
		for _, s := range c.Sites {
			if s.Listen != "" {
				m[strings.TrimSpace(s.Listen)] = struct{}{}
			}
		}
		return m
	}
	x, y := listeners(a), listeners(b)
	if len(x) != len(y) {
		return false
	}
	for k := range x {
		if _, ok := y[k]; !ok {
			return false
		}
	}
	return true
}

// Host/IP overrides also define WebAuthn's origin, not only TLS SANs.
func applyCLIOrigin(cfg *config.Config, hosts, ips []string) {
	if len(cfg.Sites) != 0 {
		return
	}
	host := ""
	if len(hosts) > 0 {
		host = hosts[0]
	} else if len(ips) > 0 {
		host = ips[0]
	}
	if host == "" {
		return
	}
	cfg.Server.RPID = host
	authority := host
	if strings.Contains(host, ":") {
		authority = "[" + host + "]"
	}
	if !cfg.Server.Cloudflare {
		_, port, err := net.SplitHostPort(cfg.Server.Listen)
		if err == nil && port != "443" {
			authority = net.JoinHostPort(host, port)
		}
	}
	cfg.Server.PublicOrigin = "https://" + authority
}
