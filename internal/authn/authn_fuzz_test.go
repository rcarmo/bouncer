package authn

import (
	"net/url"
	"strings"
	"testing"
)

func FuzzOriginMatches(f *testing.F) {
	seeds := [][2]string{
		{"https://example.com", "https://example.com"},
		{"https://example.com", "https://EXAMPLE.com"},
		{"http://example.com", "https://example.com"},
		{"https://example.com:443", "https://example.com:443"},
		{"not-a-url", "https://example.com"},
		{"https://example.com", "not-a-url"},
	}
	for _, seed := range seeds {
		f.Add(seed[0], seed[1])
	}

	f.Fuzz(func(t *testing.T, origin, siteOrigin string) {
		ok := originMatches(origin, siteOrigin)
		if !ok {
			return
		}
		originURL, err1 := url.Parse(origin)
		siteURL, err2 := url.Parse(siteOrigin)
		if err1 != nil || err2 != nil {
			t.Fatalf("originMatches true for invalid URLs: %q %q", origin, siteOrigin)
		}
		if !strings.EqualFold(originURL.Scheme, siteURL.Scheme) {
			t.Fatalf("scheme mismatch for %q %q", origin, siteOrigin)
		}
		if !strings.EqualFold(originURL.Host, siteURL.Host) {
			t.Fatalf("host mismatch for %q %q", origin, siteOrigin)
		}
	})
}
