package main

import (
	"bytes"
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
	"github.com/rcarmo/bouncer/internal/ingress"
	"github.com/rcarmo/bouncer/internal/localip"
	"github.com/rcarmo/bouncer/internal/notify"
	"github.com/rcarmo/bouncer/internal/proxy"
	"github.com/rcarmo/bouncer/internal/session"
	"github.com/rcarmo/bouncer/internal/site"
	"github.com/rcarmo/bouncer/internal/token"
)

var version = "dev"

// Test-only builds install a profiler; production leaves this a no-op.
var finishAllocationProfile = func() {}

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
		checkConfig     bool
		resetEnrollment bool
	)

	flag.BoolVar(&checkConfig, "check-config", false, "Validate sites and ingresses without starting listeners or reading secrets")
	flag.StringVar(&configPath, "config", "bouncer.yaml", "Path to YAML config")
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

	if checkConfig {
		reg, e := site.New(cfg, nil)
		if e == nil {
			_, e = ingress.Validate(cfg, reg.Sites)
		}
		if e != nil {
			slog.Error("invalid configuration", "error", e)
			os.Exit(1)
		}
		fmt.Printf("Configuration valid: %d ingresses, %d sites\n", len(cfg.Ingresses), len(reg.Sites))
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
	if listen != "" || cloudflare || backend != "" || len(hostnames) > 0 || len(ips) > 0 {
		slog.Error("listener/backend/hostname CLI overrides are removed; edit sites and ingresses then use SIGHUP")
		os.Exit(1)
	}
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

	trustedNets := []*net.IPNet(nil) // Trust is defined by each ingress.

	// Site registry.
	siteRegistry, err := site.New(cfg, trustedNets)
	if err != nil {
		slog.Error("failed to initialize site registry", "error", err)
		os.Exit(1)
	}

	activeSpecs, err := ingress.Validate(cfg, siteRegistry.Sites)
	if err != nil {
		slog.Error("invalid ingress configuration", "error", err)
		os.Exit(1)
	}
	prepareTLS := func(c *config.Config, specs []ingress.Spec) error {
		if !hasLocalTLS(specs) {
			return nil
		}
		local := localRegistryConfig(c, specs)
		reg, err := site.New(local, nil)
		if err != nil {
			return err
		}
		c.Server.Hostnames = reg.AllHostnames()
		c.Server.IPAddresses = reg.AllIPs()
		if err := ca.PrepareCA(c); err != nil {
			return err
		}
		return ca.PrepareServerCert(c)
	}
	if err := prepareTLS(cfg, activeSpecs); err != nil {
		slog.Error("TLS preparation failed", "error", err)
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
	authnHandler, err := authn.Prepare(cfg, sessStore, trustedNets, siteRegistry)
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

	announcements, err := startDiscovery(cfg, activeSpecs)
	if err != nil {
		slog.Error("discovery failed", "error", err)
		return
	}
	defer func() {
		for _, a := range announcements {
			a.Close()
		}
	}()

	// Route/auth state is hot-swappable on SIGHUP. Handlers copy the current
	// pointers under the lock and then release it before proxying long-lived
	// responses such as SSE or WebSocket upgrades.
	var stateMu sync.RWMutex
	var currentTLSCert tls.Certificate
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
		// Select routing and ingress trust from one generation, including requests
		// already accepted by a reused listener when a reload is published.
		if p := ingress.FromRequest(r); p != nil {
			var current *ingress.Policy
			for _, spec := range activeSpecs {
				if spec.Config.ID == p.ID {
					current = spec.Policy
					break
				}
			}
			if current == nil {
				stateMu.RUnlock()
				http.Error(w, "ingress retired", http.StatusServiceUnavailable)
				return
			}
			r = r.WithContext(ingress.WithPolicy(r.Context(), current))
		}
		next := activeHandler
		c := cfg
		sites := siteRegistry
		stateMu.RUnlock()
		if p := ingress.FromRequest(r); p != nil && p.Bootstrap {
			bootstrapHandler(c, sites).ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})

	var manager *ingress.Manager
	reloadConfig := func() error {
		// Snapshot while auth cannot write users/tokens. Staging can be slow;
		// do not block authentication while enrolling nodes or opening sockets.
		authGate.Lock()
		// #nosec G304 -- configPath is the operator-selected configuration file.
		snapshot, readErr := os.ReadFile(configPath)
		if readErr != nil {
			authGate.Unlock()
			return fmt.Errorf("reload config: %w", readErr)
		}
		nextCfg, err := config.Load(configPath)
		authGate.Unlock()
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}

		if onboarding {
			nextCfg.Onboarding.Enabled = true
		}

		if nextCfg.Session != cfg.Session {
			return fmt.Errorf("session settings require restart")
		}
		nextTrusted := []*net.IPNet(nil)
		nextSites, err := site.New(nextCfg, nextTrusted)
		if err != nil {
			return fmt.Errorf("site registry: %w", err)
		}

		nextSpecs, err := ingress.Validate(nextCfg, nextSites.Sites)
		if err != nil {
			return err
		}
		if err := sameNodeIdentity(activeSpecs, nextSpecs); err != nil {
			return err
		}
		if err := prepareTLS(nextCfg, nextSpecs); err != nil {
			return err
		}
		nextAuthn, err := authn.Prepare(nextCfg, sessStore, nextTrusted, nextSites)
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

		nextAnnouncements := announcements
		discoveryChanged := !sameDiscovery(activeSpecs, nextSpecs)
		if discoveryChanged {
			nextAnnouncements, err = startDiscovery(nextCfg, nextSpecs)
			if err != nil {
				return err
			}
		}
		defer func() {
			if !committed && discoveryChanged {
				for _, a := range nextAnnouncements {
					a.Close()
				}
			}
		}()
		var nextTLSCert tls.Certificate
		if hasLocalTLS(nextSpecs) {
			certPEM, keyPEM, err := ca.ServerTLSKeyPair(nextCfg)
			if err != nil {
				return fmt.Errorf("get TLS keypair: %w", err)
			}
			nextTLSCert, err = tls.X509KeyPair(certPEM, keyPEM)
			if err != nil {
				return fmt.Errorf("parse TLS cert: %w", err)
			}
		}

		commitIngress, rollbackIngress, err := manager.Prepare(ctx, nextSpecs)
		if err != nil {
			return err
		}
		defer func() {
			if !committed {
				rollbackIngress()
			}
		}()
		authGate.Lock()
		defer authGate.Unlock()
		// #nosec G304 -- re-read the same operator-selected configuration file.
		latest, err := os.ReadFile(configPath)
		if err != nil {
			return fmt.Errorf("recheck reload config: %w", err)
		}
		if !bytes.Equal(snapshot, latest) {
			return fmt.Errorf("configuration changed during preparation; retry reload")
		}
		if err := nextCfg.Save(); err != nil {
			return fmt.Errorf("persist prepared generation: %w", err)
		}
		stateMu.Lock()
		oldAuthn := authnHandler
		oldAnnouncements := announcements
		cfg = nextCfg
		trustedNets = nextTrusted
		siteRegistry = nextSites
		authnHandler = nextAuthn
		proxyBySite = nextProxyBySite
		if hasLocalTLS(nextSpecs) {
			currentTLSCert = nextTLSCert
		}
		announcements = nextAnnouncements
		activeSpecs = nextSpecs
		activeHandler = newRouter(nextCfg, nextSites, nextAuthn, nextProxyBySite, sessStore, nextTrusted)
		committed = true
		stateMu.Unlock()
		commitIngress()
		oldAuthn.Close()
		if discoveryChanged {
			for _, a := range oldAnnouncements {
				a.Close()
			}
		}
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

	if hasLocalTLS(activeSpecs) {
		certPEM, keyPEM, err := ca.ServerTLSKeyPair(cfg)
		if err != nil {
			slog.Error("TLS keypair unavailable")
			return
		}
		currentTLSCert, err = tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			slog.Error("TLS keypair invalid")
			return
		}
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		stateMu.RLock()
		defer stateMu.RUnlock()
		cert := currentTLSCert
		return &cert, nil
	}}
	manager = ingress.NewManager(handler, openIngress(tlsConfig))
	defer manager.Close()
	commit, rollback, err := manager.Prepare(ctx, activeSpecs)
	if err != nil {
		slog.Error("ingress startup failed", "error", err)
		os.Exit(1)
	}
	if err := cfg.Save(); err != nil {
		rollback()
		slog.Error("persist initial generation", "error", err)
		os.Exit(1)
	}
	commit()
	slog.Info("ingresses ready", "count", len(activeSpecs))
	stopReload := startReload()
	defer stopReload()
	<-ctx.Done()
	slog.Info("shutting down...")

}

func withSecurityHeaders(next http.Handler, trustedFn func() []*net.IPNet) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), usb=(), payment=()")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:")
		if isHTTPSRequest(r, ingress.Trusted(r, trustedFn())) {
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
