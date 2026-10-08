package ingress

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"reflect"
	"sync"
	"sync/atomic"
	"time"
)

// Open returns a listener and provider cleanup after HTTP connections are closed.
type Open func(context.Context, Spec) (net.Listener, func(), error)
type endpoint struct {
	spec     Spec
	server   *http.Server
	listener net.Listener
	cleanup  func()
	ready    chan struct{}
	stopped  chan struct{}
	policy   atomic.Pointer[Policy]
	connsMu  sync.Mutex
	conns    map[net.Conn]bool
	stopOnce sync.Once
	done     chan struct{}
}

type Manager struct {
	endpoints map[string]*endpoint
	handler   http.Handler
	open      Open
}

func NewManager(handler http.Handler, open Open) *Manager {
	return &Manager{endpoints: map[string]*endpoint{}, handler: handler, open: open}
}

// Prepare starts added resources behind a closed request gate. Active resources
// are never replaced in place: identical sockets/state require remove then add.
func (m *Manager) Prepare(ctx context.Context, specs []Spec) (commit func(), rollback func(), err error) {
	next := map[string]*endpoint{}
	added := []*endpoint{}
	var transaction sync.Once
	updates := map[*endpoint]Spec{}
	rollback = func() {
		transaction.Do(func() {
			for _, e := range added {
				e.stop()
			}
		})
	}
	for _, s := range specs {
		old := m.endpoints[s.Config.ID]
		if old != nil && (old.spec.Fingerprint == s.Fingerprint || reusable(s, old.spec)) {
			next[s.Config.ID] = old
			updates[old] = s
			continue
		}
		for _, e := range m.endpoints {
			if sameResource(s, e.spec) {
				rollback()
				return nil, nil, fmt.Errorf("ingress %q: active socket or node identity change requires removing the ingress in one reload before adding it in another", s.Config.ID)
			}
		}
		ln, cleanup, e := m.open(ctx, s)
		if e != nil {
			rollback()
			return nil, nil, fmt.Errorf("ingress %q: %w", s.Config.ID, e)
		}
		ep := &endpoint{spec: s, listener: ln, cleanup: cleanup, ready: make(chan struct{}), stopped: make(chan struct{}), conns: map[net.Conn]bool{}, done: make(chan struct{})}
		ep.server = &http.Server{ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 1 << 20,
			ConnState: func(c net.Conn, state http.ConnState) {
				ep.connsMu.Lock()
				defer ep.connsMu.Unlock()
				if state == http.StateClosed {
					delete(ep.conns, c)
				} else {
					ep.conns[c] = true
				}
			},
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				select {
				case <-ep.ready:
					r = r.WithContext(WithPolicy(r.Context(), ep.policy.Load()))
					SourceAddress(r)
					m.handler.ServeHTTP(w, r)
				case <-r.Context().Done():
				}
			}),
		}
		// tls.Conn stays intact so net/http populates Request.TLS.
		ep.server.ConnContext = func(ctx context.Context, c net.Conn) context.Context {
			ctx = WithPolicy(ctx, s.Policy)
			if tc, ok := c.(*tls.Conn); ok {
				ctx = withPeer(ctx, tc.NetConn())
			}
			return ctx
		}
		ep.policy.Store(s.Policy)
		added = append(added, ep)
		next[s.Config.ID] = ep
		go func() {
			defer close(ep.done)
			// Do not accept (or perform TLS handshakes) against an unpublished
			// generation. Rollback must also wake this goroutine.
			select {
			case <-ep.ready:
			case <-ep.stopped:
				return
			}
			if e := ep.server.Serve(ln); e != nil && !errors.Is(e, http.ErrServerClosed) && !errors.Is(e, net.ErrClosed) {
				slog.Error("ingress stopped", "ingress", s.Config.ID, "error", e)
			}
		}()
	}
	commit = func() {
		transaction.Do(func() {
			old := m.endpoints
			for ep, s := range updates {
				ep.spec = s
				ep.policy.Store(s.Policy)
			}
			m.endpoints = next
			for _, e := range added {
				close(e.ready)
			}
			for id, e := range old {
				if next[id] != e {
					e.stop()
				}
			}
		})
	}
	return commit, rollback, nil
}

func reusable(a, b Spec) bool {
	if a.Config.Type != b.Config.Type {
		return false
	}
	if a.Config.Type == "local" {
		return a.Config.Local.Listen == b.Config.Local.Listen && a.Config.Local.TLS == b.Config.Local.TLS
	}
	return reflect.DeepEqual(a.Config.TSNet, b.Config.TSNet) && a.Sites[0].ID == b.Sites[0].ID && a.Sites[0].PublicOrigin == b.Sites[0].PublicOrigin && a.Sites[0].RPID == b.Sites[0].RPID
}

func sameResource(a, b Spec) bool {
	if a.Config.Type != b.Config.Type {
		return false
	}
	if a.Config.Type == "local" {
		return a.Config.Local.Listen == b.Config.Local.Listen
	}
	return a.Config.TSNet.StateDir == b.Config.TSNet.StateDir || a.Config.TSNet.Hostname == b.Config.TSNet.Hostname
}
func (e *endpoint) stop() {
	e.stopOnce.Do(func() {
		close(e.stopped)
		_ = e.listener.Close()
		// Explicit removal closes streams on that endpoint only; unchanged endpoints
		// are untouched. net/http Shutdown does not close hijacked WebSockets.
		e.connsMu.Lock()
		for c := range e.conns {
			_ = c.Close()
		}
		e.connsMu.Unlock()
		_ = e.server.Close()
		if e.cleanup != nil {
			e.cleanup()
		}
		<-e.done
	})
}
func (m *Manager) Close() {
	for _, e := range m.endpoints {
		e.stop()
	}
	m.endpoints = map[string]*endpoint{}
}

type peerKey struct{}

func withPeer(ctx context.Context, c net.Conn) context.Context {
	return context.WithValue(ctx, peerKey{}, c)
}
func Peer(r *http.Request) net.Conn { c, _ := r.Context().Value(peerKey{}).(net.Conn); return c }
