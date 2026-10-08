package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Measure response copying without network/client allocations obscuring it.
func BenchmarkProxyResponse(b *testing.B) {
	p, e := New("http://backend.local", nil)
	if e != nil {
		b.Fatal(e)
	}
	p.Transport = benchmarkTransport{}
	req := httptest.NewRequest(http.MethodGet, "http://bouncer.local/app", nil)
	w := &benchmarkWriter{header: make(http.Header)}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		clear(w.header)
		p.ServeHTTP(w, req)
	}
}

type benchmarkTransport struct{}

func (benchmarkTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: 200, Header: make(http.Header), Body: &benchmarkBody{Reader: strings.NewReader("backend response")}, ContentLength: 16}, nil
}

type benchmarkBody struct{ *strings.Reader }

func (*benchmarkBody) Close() error { return nil }

type benchmarkWriter struct{ header http.Header }

func (w *benchmarkWriter) Header() http.Header       { return w.header }
func (*benchmarkWriter) WriteHeader(int)             {}
func (*benchmarkWriter) Write(p []byte) (int, error) { return len(p), nil }
