package site

import (
	"strings"
	"testing"
)

func FuzzNormalizeHost(f *testing.F) {
	seeds := []string{
		"example.com",
		"EXAMPLE.COM:443",
		"http://Example.com:443",
		" https://Sub.Example.com ",
		"[::1]:8443",
		"localhost",
		"",
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		got := normalizeHost(input)
		if strings.Contains(got, " ") || strings.Contains(got, "\t") || strings.Contains(got, "\n") {
			t.Fatalf("normalizeHost returned whitespace for %q: %q", input, got)
		}
		if strings.Contains(got, "://") {
			t.Fatalf("normalizeHost returned scheme for %q: %q", input, got)
		}
	})
}
