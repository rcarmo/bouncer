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
		w.Write([]byte("hello from backend"))
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
