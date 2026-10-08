package ingress

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/rcarmo/bouncer/internal/config"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func testSites() []*config.SiteConfig {
	return []*config.SiteConfig{{ID: "a", PublicOrigin: "https://a.example.ts.net", RPID: "a.example.ts.net", Backend: "http://localhost:9000"}, {ID: "b", PublicOrigin: "https://b.example.ts.net", RPID: "b.example.ts.net", Backend: "http://localhost:9001"}}
}
func TestValidation(t *testing.T) {
	c := config.Defaults()
	c.Ingresses = []config.IngressConfig{{ID: "a", Type: "tsnet", SiteIDs: []string{"a"}, TSNet: &config.TSNetIngress{Hostname: "a", StateDir: t.TempDir()}}}
	specs, e := Validate(c, testSites())
	if e != nil {
		t.Fatal(e)
	}
	if specs[0].Config.TSNet.Port != 443 {
		t.Fatal("missing port default")
	}
	c.Ingresses = append(c.Ingresses, config.IngressConfig{ID: "b", Type: "tsnet", SiteIDs: []string{"b"}, TSNet: &config.TSNetIngress{Hostname: "b", StateDir: c.Ingresses[0].TSNet.StateDir}})
	if _, e := Validate(c, testSites()); e == nil {
		t.Fatal("shared state accepted")
	}
	c.Ingresses = nil
	if _, e := Validate(c, testSites()); e == nil {
		t.Fatal("empty list accepted")
	}
}
func TestPolicy(t *testing.T) {
	r := httptest.NewRequest("GET", "https://a.example.ts.net/", nil)
	r = r.WithContext(WithPolicy(r.Context(), &Policy{TSNet: true, Sites: map[string]bool{"a": true}}))
	_, n, _ := net.ParseCIDR("0.0.0.0/0")
	if len(Trusted(r, []*net.IPNet{n})) != 0 || LocalBypass(r) || Allows(r, testSites()[1]) {
		t.Fatal("trust escaped transport boundary")
	}
}
func TestManagerReconcile(t *testing.T) {
	opens := 0
	closes := 0
	addresses := map[string]string{}
	m := NewManager(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = fmt.Fprint(w, FromRequest(r).ID) }), func(ctx context.Context, s Spec) (net.Listener, func(), error) {
		if s.Config.ID == "fail" {
			return nil, nil, fmt.Errorf("failed")
		}
		ln, e := net.Listen("tcp", "127.0.0.1:0")
		if e != nil {
			return nil, nil, e
		}
		opens++
		addresses[s.Config.ID] = ln.Addr().String()
		return ln, func() { closes++ }, nil
	})
	defer m.Close()
	spec := func(id, addr string) Spec {
		return Spec{Config: config.IngressConfig{ID: id, Type: "local", Local: &config.LocalIngress{Listen: addr, TLS: "off"}}, Policy: &Policy{ID: id}, Fingerprint: id}
	}
	a := spec("a", ":18080")
	commit, _, e := m.Prepare(context.Background(), []Spec{a})
	if e != nil {
		t.Fatal(e)
	}
	commit()
	get := func(id string) {
		resp, e := http.Get("http://" + addresses[id])
		if e != nil {
			t.Fatal(e)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatal(resp.Status)
		}
	}
	get("a")
	b := spec("b", ":18081")
	commit, _, e = m.Prepare(context.Background(), []Spec{a, b})
	if e != nil {
		t.Fatal(e)
	}
	commit()
	get("a")
	get("b")
	if opens != 2 || closes != 0 {
		t.Fatal("unchanged endpoint restarted")
	}
	if _, _, e = m.Prepare(context.Background(), []Spec{a, b, spec("c", ":18082"), spec("fail", ":18083")}); e == nil {
		t.Fatal("failed prepare committed")
	}
	get("a")
	get("b")
	if closes != 1 {
		t.Fatal("staged endpoint leaked")
	}
	commit, _, e = m.Prepare(context.Background(), []Spec{b})
	if e != nil {
		t.Fatal(e)
	}
	commit()
	get("b")
	if closes != 2 {
		t.Fatal("removed endpoint not closed")
	}
}
func TestTLSContextPreserved(t *testing.T) {
	r := httptest.NewRequest("GET", "https://a.example.ts.net", nil)
	r.TLS = &tls.ConnectionState{}
	r = r.WithContext(WithPolicy(r.Context(), &Policy{TSNet: true}))
	if r.TLS == nil {
		t.Fatal("TLS context lost")
	}
}

func TestManagerTransactionCallbacksAreIdempotent(t *testing.T) {
	for _, commitFirst := range []bool{true, false} {
		t.Run(fmt.Sprint(commitFirst), func(t *testing.T) {
			var cleanups atomic.Int32
			m := NewManager(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }), func(_ context.Context, _ Spec) (net.Listener, func(), error) {
				ln, e := net.Listen("tcp", "127.0.0.1:0")
				return ln, func() { cleanups.Add(1) }, e
			})
			c := config.Defaults()
			c.Ingresses = []config.IngressConfig{{ID: "a", Type: "local", SiteIDs: []string{"a"}, Local: &config.LocalIngress{Listen: "127.0.0.1:12345", TLS: "off"}}}
			specs, e := Validate(c, testSites())
			if e != nil {
				t.Fatal(e)
			}
			commit, rollback, e := m.Prepare(context.Background(), specs)
			if e != nil {
				t.Fatal(e)
			}
			if commitFirst {
				commit()
				commit()
				rollback()
				if cleanups.Load() != 0 {
					t.Fatal("rollback retired committed ingress")
				}
			} else {
				rollback()
				rollback()
				commit()
				if len(m.endpoints) != 0 {
					t.Fatal("commit resurrected rolled-back ingress")
				}
			}
			m.Close()
			m.Close()
			if cleanups.Load() != 1 {
				t.Fatalf("cleanup called %d times", cleanups.Load())
			}
		})
	}
}
