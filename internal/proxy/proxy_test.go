package proxy

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProxyForwardsRequest(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Backend", "ok")
		w.WriteHeader(200)
		if _, err := w.Write([]byte("hello from backend")); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}))
	defer backend.Close()

	rp, err := New(backend.URL, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest("GET", "/test?q=1", nil)
	req.RemoteAddr = "192.168.1.10:12345"
	rr := httptest.NewRecorder()
	rp.ServeHTTP(rr, req)

	if rr.Code != 200 {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	body, _ := io.ReadAll(rr.Body)
	if string(body) != "hello from backend" {
		t.Errorf("got body %q", body)
	}
}

func TestProxyAddsForwardedHeaders(t *testing.T) {
	var gotHeaders http.Header
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeaders = r.Header.Clone()
		w.WriteHeader(200)
	}))
	defer backend.Close()

	rp, _ := New(backend.URL, nil)
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.5:9999"
	req.Host = "myapp.local"
	rr := httptest.NewRecorder()
	rp.ServeHTTP(rr, req)

	if got := gotHeaders.Get("X-Forwarded-For"); got != "10.0.0.5" {
		t.Errorf("X-Forwarded-For = %q, want 10.0.0.5", got)
	}
	if got := gotHeaders.Get("X-Forwarded-Host"); got != "myapp.local" {
		t.Errorf("X-Forwarded-Host = %q, want myapp.local", got)
	}
	if got := gotHeaders.Get("X-Forwarded-Proto"); got != "http" {
		t.Errorf("X-Forwarded-Proto = %q, want http", got)
	}
}

func TestProxyStripsForwardedFromUntrusted(t *testing.T) {
	var gotHeaders http.Header
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeaders = r.Header.Clone()
		w.WriteHeader(200)
	}))
	defer backend.Close()

	// Only trust 10.0.0.0/8.
	_, trustedNet, _ := net.ParseCIDR("10.0.0.0/8")
	rp, _ := New(backend.URL, []*net.IPNet{trustedNet})

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.1.1:1234" // Not trusted.
	req.Header.Set("X-Forwarded-For", "evil-spoof")
	rr := httptest.NewRecorder()
	rp.ServeHTTP(rr, req)

	// Should be overwritten with the actual RemoteAddr.
	if got := gotHeaders.Get("X-Forwarded-For"); got == "evil-spoof" {
		t.Error("spoofed X-Forwarded-For was not stripped")
	}
}

func TestProxyPreservesMethod(t *testing.T) {
	var gotMethod string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		w.WriteHeader(200)
	}))
	defer backend.Close()

	rp, _ := New(backend.URL, nil)

	for _, method := range []string{"GET", "POST", "PUT", "DELETE", "PATCH"} {
		req := httptest.NewRequest(method, "/", nil)
		req.RemoteAddr = "127.0.0.1:1234"
		rr := httptest.NewRecorder()
		rp.ServeHTTP(rr, req)
		if gotMethod != method {
			t.Errorf("expected method %s, got %s", method, gotMethod)
		}
	}
}

func TestProxyBackendDown(t *testing.T) {
	// Point to a backend that doesn't exist.
	rp, err := New("http://127.0.0.1:1", nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	rr := httptest.NewRecorder()
	rp.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadGateway {
		t.Errorf("expected 502, got %d", rr.Code)
	}
}

func TestProxyPreservesQueryString(t *testing.T) {
	var gotQuery string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		w.WriteHeader(200)
	}))
	defer backend.Close()

	rp, _ := New(backend.URL, nil)
	req := httptest.NewRequest("GET", "/search?q=hello&page=2", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	rr := httptest.NewRecorder()
	rp.ServeHTTP(rr, req)

	if gotQuery != "q=hello&page=2" {
		t.Errorf("expected query q=hello&page=2, got %q", gotQuery)
	}
}

func TestTrustedForwardedHeaders(t *testing.T) {
	var got http.Header
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got = r.Header.Clone() }))
	defer backend.Close()
	_, trusted, _ := net.ParseCIDR("127.0.0.1/32")
	rp, _ := New(backend.URL, []*net.IPNet{trusted})
	req := httptest.NewRequest("GET", "http://internal/", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "192.168.1.1, 203.0.113.5")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "public.example")
	req.Header.Set("CF-Connecting-IP", "192.168.1.1")
	rp.ServeHTTP(httptest.NewRecorder(), req)
	for name, want := range map[string]string{"X-Forwarded-For": "203.0.113.5, 127.0.0.1", "X-Forwarded-Proto": "https", "X-Forwarded-Host": "public.example", "CF-Connecting-IP": ""} {
		if got.Get(name) != want {
			t.Errorf("%s=%q want %q", name, got.Get(name), want)
		}
	}
}
func TestInvalidBackend(t *testing.T) {
	for _, target := range []string{"relative", "ftp://example.com", "http://", "http://example.com/#fragment"} {
		if _, err := New(target, nil); err == nil {
			t.Errorf("accepted %q", target)
		}
	}
}

func TestResponseBufferPoolShape(t *testing.T) {
	p := responseBufferPool{}
	b := p.Get()
	if len(b) != 32*1024 || cap(b) != 32*1024 {
		t.Fatalf("unexpected buffer size %d/%d", len(b), cap(b))
	}
	p.Put(b[:1])
	b = p.Get()
	if len(b) != 32*1024 {
		t.Fatal("pool retained shortened slice")
	}
	p.Put(b)
	p.Put(make([]byte, 10)) // Unexpected buffer sizes must never poison the pool.
	b = p.Get()
	if len(b) != 32*1024 {
		t.Fatal("pool retained incompatible buffer")
	}
	p.Put(b)
}
