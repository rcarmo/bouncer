package notify

import (
	"net"
	"strings"
	"testing"
)

func FuzzIPv4ToUint32(f *testing.F) {
	f.Add("1.2.3.4")
	f.Add("255.255.255.255")
	f.Add("0.0.0.0")
	f.Add("not-an-ip")
	f.Add(" 10.0.0.1 ")

	f.Fuzz(func(t *testing.T, input string) {
		got, ok := ipv4ToUint32(input)
		ip := net.ParseIP(strings.TrimSpace(input))
		if ip == nil || ip.To4() == nil {
			if ok {
				t.Fatalf("expected invalid ip for %q", input)
			}
			return
		}
		if !ok {
			t.Fatalf("expected valid ip for %q", input)
		}
		ip4 := ip.To4()
		want := uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3])
		if got != want {
			t.Fatalf("ipv4ToUint32(%q) = %d, want %d", input, got, want)
		}
	})
}
