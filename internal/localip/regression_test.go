package localip

import (
	"net/http/httptest"
	"testing"
)

func TestTrustedXFFSpoofResistance(t *testing.T) {
	trusted, err := ParseTrustedProxies([]string{"127.0.0.1/32", "10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, remote, xff, want string }{
		{"untrusted peer", "203.0.113.1:123", "192.168.1.1", "203.0.113.1"},
		{"spoofed prefix", "127.0.0.1:123", "192.168.1.1, 203.0.113.1", "203.0.113.1"},
		{"proxy chain", "127.0.0.1:123", "192.168.1.1, 203.0.113.1, 10.0.0.1", "203.0.113.1"},
		{"malformed suffix", "127.0.0.1:123", "192.168.1.1, invalid", ""},
		{"all trusted", "127.0.0.1:123", "10.0.0.1", ""},
		{"missing", "127.0.0.1:123", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "http://localhost", nil)
			r.RemoteAddr = tc.remote
			r.Header.Set("X-Forwarded-For", tc.xff)
			for _, header := range []string{"CF-Connecting-IP", "True-Client-IP", "X-Real-IP"} {
				r.Header.Set(header, "192.168.1.1")
			}
			r.Header.Set("Forwarded", "for=192.168.1.1")
			ip := ClientIPFromRequest(r, trusted)
			if tc.want == "" {
				if ip != nil {
					t.Fatalf("expected unattributed, got %v", ip)
				}
			} else if ip == nil || ip.String() != tc.want {
				t.Fatalf("got %v, want %s", ip, tc.want)
			}
		})
	}
	r := httptest.NewRequest("GET", "http://localhost", nil)
	r.RemoteAddr = "127.0.0.1:123"
	r.Header.Add("X-Forwarded-For", "192.168.1.1")
	r.Header.Add("X-Forwarded-For", "203.0.113.1")
	if ip := ClientIPFromRequest(r, trusted); ip == nil || ip.String() != "203.0.113.1" {
		t.Fatalf("multiple header spoof: %v", ip)
	}
}
