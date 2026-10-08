package ingress

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/tsnet"
)

// SourceAddress uses only Funnel metadata provided by tsnet, never HTTP headers.
func SourceAddress(r *http.Request) {
	if c, ok := Peer(r).(*ipn.FunnelConn); ok {
		r.RemoteAddr = c.Src.String()
	}
}

func OpenTSNet(ctx context.Context, s Spec) (net.Listener, func(), error) {
	t := s.Config.TSNet
	if os.Getenv("TS_CLIENT_SECRET") != "" || os.Getenv("TS_CLIENT_ID") != "" || os.Getenv("TS_ID_TOKEN") != "" || os.Getenv("TS_AUDIENCE") != "" || os.Getenv("TSNET_FORCE_LOGIN") != "" {
		return nil, nil, fmt.Errorf("process-wide Tailscale login overrides are forbidden; use per-ingress authKeyEnv")
	}
	if err := os.MkdirAll(t.StateDir, 0700); err != nil {
		return nil, nil, fmt.Errorf("stateDir is not writable")
	}
	// #nosec G302 -- directory requires owner execute; no group/other access.
	if err := os.Chmod(t.StateDir, 0700); err != nil {
		return nil, nil, fmt.Errorf("cannot protect stateDir")
	}
	key := ""
	if t.AuthKeyEnv != "" {
		key = os.Getenv(t.AuthKeyEnv)
	}
	// Prevent implicit process-wide bootstrap credentials from being used for a
	// different ingress. Persisted identity is accepted without a bootstrap key.
	if key == "" {
		if _, err := os.Stat(t.StateDir + "/tailscaled.state"); err != nil {
			return nil, nil, fmt.Errorf("authKeyEnv must provide a key for initial enrollment")
		}
		key = "tskey-auth-unused-persisted-identity"
	}
	node := &tsnet.Server{Dir: t.StateDir, Hostname: t.Hostname, AuthKey: key, Logf: func(string, ...any) {}, UserLogf: func(string, ...any) {}}
	if err := node.Start(); err != nil {
		return nil, nil, fmt.Errorf("node start failed")
	}
	var closeOnce sync.Once
	closeNode := func() { closeOnce.Do(func() { _ = node.Close() }) }
	var once sync.Once
	var undo func()
	cleanup := func() {
		once.Do(func() {
			if undo != nil {
				undo()
			}
			closeNode()
		})
	}
	fail := func(msg string) (net.Listener, func(), error) { cleanup(); return nil, nil, fmt.Errorf("%s", msg) }
	startup, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	done := make(chan struct{})
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		select {
		case <-startup.Done():
			closeNode()
		case <-done:
		}
	}()
	// Stop the close watcher before mutating ServeConfig: cleanup must revoke
	// exposure while the local API is still available.
	st, err := node.Up(startup)
	close(done)
	<-watchDone
	if err != nil || startup.Err() != nil {
		return fail("node enrollment/readiness failed")
	}
	domain := strings.TrimSuffix(strings.TrimPrefix(s.Sites[0].PublicOrigin, "https://"), fmt.Sprintf(":%d", t.Port))
	found := false
	for _, d := range st.CertDomains {
		if d == domain {
			found = true
		}
	}
	if !found {
		return fail("node certificate hostname does not match site publicOrigin")
	}
	if t.Port != 443 && t.Port != 8443 && t.Port != 10000 {
		return fail("unsupported Funnel port")
	}
	// #nosec G115 -- explicit supported-port guard above bounds conversion.
	if err := ipn.CheckFunnelAccess(uint16(t.Port), st.Self); err != nil {
		return fail("Funnel permission is not enabled for this node/port")
	}
	lc, err := node.LocalClient()
	if err != nil {
		return fail("local node API unavailable")
	}
	before, err := lc.GetServeConfig(startup)
	if err != nil {
		return fail("cannot read Funnel configuration")
	}
	if before == nil {
		before = &ipn.ServeConfig{}
	}
	hp := ipn.HostPort(fmt.Sprintf("%s:%d", domain, t.Port))
	was := before.AllowFunnel[hp]
	if !was {
		if before.AllowFunnel == nil {
			before.AllowFunnel = map[ipn.HostPort]bool{}
		}
		before.AllowFunnel[hp] = true
		if err := lc.SetServeConfig(startup, before); err != nil {
			return fail("cannot enable Funnel")
		}
		undo = func() {
			c, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			current, e := lc.GetServeConfig(c)
			if e == nil && current != nil {
				delete(current.AllowFunnel, hp)
				_ = lc.SetServeConfig(c, current)
			}
		}
	}
	// Keep the tls.Conn intact; ConnContext reads its underlying FunnelConn to
	// obtain authenticated source metadata without trusting request headers.
	opts := []tsnet.FunnelOption{tsnet.FunnelTLSConfig(&tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: lc.GetCertificate})}
	if t.FunnelOnly {
		opts = append(opts, tsnet.FunnelOnly())
	}
	ln, err := node.ListenFunnel("tcp", fmt.Sprintf(":%d", t.Port), opts...)
	if err != nil {
		return fail("Funnel listener failed")
	}
	return ln, func() { _ = ln.Close(); cleanup() }, nil
}
