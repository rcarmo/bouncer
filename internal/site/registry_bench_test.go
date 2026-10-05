package site

import (
	"github.com/rcarmo/bouncer/internal/config"
	"net/http/httptest"
	"testing"
)

func BenchmarkResolve(b *testing.B) {
	registry, err := New(config.Defaults(), nil)
	if err != nil {
		b.Fatal(err)
	}
	request := httptest.NewRequest("GET", "https://bouncer.local/app", nil)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if registry.Resolve(request) == nil {
			b.Fatal("missing site")
		}
	}
}
