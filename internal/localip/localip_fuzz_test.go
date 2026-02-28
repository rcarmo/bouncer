package localip

import "testing"

func FuzzClientIPNoTrusted(f *testing.F) {
	seeds := []struct {
		remote string
		xff    string
	}{
		{"127.0.0.1:1234", ""},
		{"192.168.1.10:9999", "203.0.113.1"},
		{"10.0.0.5:1111", ""},
		{"[::1]:8080", ""},
		{"bad-addr", "1.1.1.1"},
	}
	for _, seed := range seeds {
		f.Add(seed.remote, seed.xff)
	}

	f.Fuzz(func(t *testing.T, remoteAddr, xff string) {
		got := ClientIP(remoteAddr, xff, nil)
		want := ExtractIP(remoteAddr)
		if want == nil && got != nil {
			t.Fatalf("expected nil for %q, got %v", remoteAddr, got)
		}
		if want != nil && got == nil {
			t.Fatalf("expected %v for %q, got nil", want, remoteAddr)
		}
		if want != nil && got != nil && !got.Equal(want) {
			t.Fatalf("expected %v for %q, got %v", want, remoteAddr, got)
		}
	})
}
