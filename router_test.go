package main

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rcarmo/bouncer/internal/authn"
	"github.com/rcarmo/bouncer/internal/config"
	"github.com/rcarmo/bouncer/internal/localip"
	"github.com/rcarmo/bouncer/internal/proxy"
	"github.com/rcarmo/bouncer/internal/session"
	"github.com/rcarmo/bouncer/internal/site"
	"golang.org/x/net/websocket"
)

func streamBackend(marker string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/events":
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Cache-Control", "no-cache")
			ticker := time.NewTicker(100 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-r.Context().Done():
					return
				case <-ticker.C:
					if _, err := io.WriteString(w, "data: "+marker+"\n\n"); err != nil {
						return
					}
					w.(http.Flusher).Flush()
				}
			}
		case "/ws":
			websocket.Handler(func(ws *websocket.Conn) {
				defer func() { _ = ws.Close() }()
				for {
					var text string
					if websocket.Message.Receive(ws, &text) != nil {
						return
					}
					if websocket.Message.Send(ws, marker+":"+text) != nil {
						return
					}
				}
			}).ServeHTTP(w, r)
		default:
			w.Header().Set("X-Backend", marker)
			_, _ = io.WriteString(w, marker+"|"+r.Header.Get("Cookie"))
		}
	})
}

func routerFixture(t *testing.T, backend string) (*config.Config, *session.Store, string, http.Handler) {
	t.Helper()
	c, e := config.Load(filepath.Join(t.TempDir(), "bouncer.json"))
	if e != nil {
		t.Fatal(e)
	}
	c.Server.PublicOrigin = "https://bouncer.test"
	c.Server.RPID = "bouncer.test"
	c.Server.Hostnames = []string{"bouncer.test"}
	c.Server.Backend = backend
	c.Server.Cloudflare = true
	c.Onboarding.Enabled = true
	c.Onboarding.GeoIP.Enabled = false
	c.Users = []config.User{{ID: "user", SiteID: "default", Credentials: []config.Credential{{ID: "credential"}}}}
	if e = c.Save(); e != nil {
		t.Fatal(e)
	}
	store, e := session.NewStore(c.SessionFilePath(), 7)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(store.Stop)
	sess, e := store.Create("default", "user", "credential")
	if e != nil {
		t.Fatal(e)
	}
	trusted, _ := localip.ParseTrustedProxies([]string{"127.0.0.1/32"})
	sites, e := site.New(c, trusted)
	if e != nil {
		t.Fatal(e)
	}
	auth, e := authn.New(c, store, trusted, sites)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(auth.Close)
	rp, e := proxy.New(backend, trusted)
	if e != nil {
		t.Fatal(e)
	}
	return c, store, sess, newRouter(c, sites, auth, map[string]http.Handler{"default": rp}, store, trusted)
}

func TestAuthenticatedProxyStreamsAndRevocation(t *testing.T) {
	backend := httptest.NewServer(streamBackend("one"))
	defer backend.Close()
	cfg, _, cookie, handler := routerFixture(t, backend.URL)
	server := httptest.NewTLSServer(handler)
	defer server.Close()
	client := server.Client()
	client.Timeout = 3 * time.Second
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	get := func(path string, authenticated bool) *http.Response {
		t.Helper()
		req, _ := http.NewRequest("GET", server.URL+path, nil)
		req.Host = "bouncer.test"
		if authenticated {
			req.Header.Set("Cookie", cfg.Session.CookieName+"="+cookie+"; app=kept")
		}
		resp, e := client.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		return resp
	}
	for _, p := range []string{"/events", "/ws"} {
		r := get(p, false)
		_ = r.Body.Close()
		if r.StatusCode != 302 {
			t.Fatalf("unauthenticated %s: %d", p, r.StatusCode)
		}
	}
	r := get("/events", true)
	line, e := bufio.NewReader(r.Body).ReadString('\n')
	_ = r.Body.Close()
	if e != nil || line != "data: one\n" {
		t.Fatalf("unbuffered SSE: %q %v", line, e)
	}
	r = get("/", true)
	body, _ := io.ReadAll(r.Body)
	_ = r.Body.Close()
	if string(body) != "one|app=kept" {
		t.Fatalf("cookies leaked/lost: %s", body)
	}
	if r.Header.Get("Content-Security-Policy") != "" {
		t.Fatal("backend inherited bouncer CSP")
	}
	cfg.Users = nil
	r = get("/events", true)
	_ = r.Body.Close()
	if r.StatusCode != 302 {
		t.Fatal("removed user retained access")
	}
}

func TestOnboardingAttributionAndCache(t *testing.T) {
	_, _, _, handler := routerFixture(t, "http://127.0.0.1:1")
	for _, ip := range []string{"203.0.113.5", "192.168.1.5", ""} {
		req := httptest.NewRequest("GET", "https://bouncer.test/onboarding", nil)
		req.RemoteAddr = "127.0.0.1:5000"
		req.Header.Set("X-Forwarded-For", ip)
		req.Header.Set("CF-Connecting-IP", "192.168.1.10")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		has := strings.Contains(w.Body.String(), `<meta name="local-bypass"`)
		if has != (ip == "192.168.1.5") {
			t.Fatalf("wrong bypass metadata for %q", ip)
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("personalized auth UI cacheable")
		}
	}
}

func TestListenerReloadWithDerivedIDs(t *testing.T) {
	a := config.Defaults()
	b := config.Defaults()
	a.Sites = []config.SiteConfig{{PublicOrigin: "https://a.local", Listen: ":8441"}, {PublicOrigin: "https://b.local", Listen: ":8442"}}
	b.Sites = append([]config.SiteConfig(nil), a.Sites...)
	b.Sites[0].Listen = ":8443"
	if sameListeners(a, b) {
		t.Fatal("listener change with omitted IDs accepted")
	}
	b.Sites[0].Listen = ":8441"
	if !sameListeners(a, b) {
		t.Fatal("unchanged listeners rejected")
	}
}

func TestCLIHostSetsWebAuthnOrigin(t *testing.T) {
	c := config.Defaults()
	c.Server.Listen = "127.0.0.1:8443"
	applyCLIOrigin(c, []string{"myhost.local"}, nil)
	if c.Server.PublicOrigin != "https://myhost.local:8443" || c.Server.RPID != "myhost.local" {
		t.Fatal("CLI hostname did not update WebAuthn origin")
	}
	c.Server.Cloudflare = true
	applyCLIOrigin(c, []string{"public.example"}, nil)
	if c.Server.PublicOrigin != "https://public.example" {
		t.Fatal("tunnel origin contains internal port")
	}
}

func TestCredentialRevocationAndLegacySessions(t *testing.T) {
	backend := httptest.NewServer(streamBackend("test"))
	defer backend.Close()
	cfg, store, id, _ := routerFixture(t, backend.URL)
	sess := store.Get(id)
	if !sessionAuthorized(cfg, sess, "default") {
		t.Fatal("credential-bound session denied")
	}
	cfg.Users[0].Credentials = []config.Credential{{ID: "other"}}
	if sessionAuthorized(cfg, sess, "default") {
		t.Fatal("removed credential still authorised")
	}
	sess.CredentialID = ""
	if sessionAuthorized(cfg, sess, "default") {
		t.Fatal("legacy unbound session authorised")
	}
}
func TestWebsocketOriginRequired(t *testing.T) {
	backend := httptest.NewServer(streamBackend("test"))
	defer backend.Close()
	cfg, _, id, handler := routerFixture(t, backend.URL)
	for _, origin := range []string{"", "https://sibling.bouncer.test", "https://bouncer.test.attacker.example", "https://bouncer.test/path", "null"} {
		req := httptest.NewRequest("GET", "https://bouncer.test/ws", nil)
		req.Header.Set("Upgrade", "websocket")
		req.Header.Set("Connection", "Upgrade")
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		req.AddCookie(&http.Cookie{Name: cfg.Session.CookieName, Value: id})
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Fatalf("origin %q accepted: %d", origin, w.Code)
		}
	}
}
func TestStrictScriptCSP(t *testing.T) {
	h := withSecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }), func() []*net.IPNet { return nil })
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "https://bouncer.test/login", nil))
	csp := w.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "script-src 'self';") || strings.Contains(csp, "script-src 'self' 'unsafe-inline'") {
		t.Fatal(csp)
	}
}
