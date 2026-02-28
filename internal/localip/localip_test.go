package localip

import (
	"net"
	"testing"
)

func TestIsLocal(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"127.0.0.1", true},
		{"10.0.0.1", true},
		{"10.255.255.255", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"172.32.0.1", false},
		{"192.168.0.1", true},
		{"192.168.255.255", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"::1", true},
		{"fc00::1", true},
		{"2001:db8::1", false},
	}
	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		if ip == nil {
			t.Fatalf("invalid IP: %s", tt.ip)
		}
		got := IsLocal(ip)
		if got != tt.want {
			t.Errorf("IsLocal(%s) = %v, want %v", tt.ip, got, tt.want)
		}
	}
}

func TestExtractIP(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"192.168.1.1:8080", "192.168.1.1"},
		{"[::1]:443", "::1"},
		{"10.0.0.1", "10.0.0.1"},
	}
	for _, tt := range tests {
		got := ExtractIP(tt.input)
		if got == nil || got.String() != tt.want {
			t.Errorf("ExtractIP(%q) = %v, want %s", tt.input, got, tt.want)
		}
	}
}

func TestParseTrustedProxies(t *testing.T) {
	nets, err := ParseTrustedProxies([]string{"10.0.0.0/8", "172.16.0.0/12"})
	if err != nil {
		t.Fatalf("ParseTrustedProxies: %v", err)
	}
	if len(nets) != 2 {
		t.Fatalf("expected 2 nets, got %d", len(nets))
	}
}

func TestParseTrustedProxiesInvalid(t *testing.T) {
	_, err := ParseTrustedProxies([]string{"not-a-cidr"})
	if err == nil {
		t.Error("expected error for invalid CIDR")
	}
}

func TestIsTrustedProxy(t *testing.T) {
	nets, _ := ParseTrustedProxies([]string{"10.0.0.0/8"})
	if !IsTrustedProxy(net.ParseIP("10.0.0.1"), nets) {
		t.Error("expected 10.0.0.1 to be trusted")
	}
	if IsTrustedProxy(net.ParseIP("192.168.1.1"), nets) {
		t.Error("expected 192.168.1.1 to NOT be trusted")
	}
}

func TestClientIP(t *testing.T) {
	trusted, _ := ParseTrustedProxies([]string{"10.0.0.0/8"})

	// Direct connection (not trusted proxy).
	ip := ClientIP("192.168.1.1:1234", "1.2.3.4", trusted)
	if ip.String() != "192.168.1.1" {
		t.Errorf("expected 192.168.1.1, got %s", ip)
	}

	// Via trusted proxy.
	ip = ClientIP("10.0.0.1:1234", "1.2.3.4, 10.0.0.2", trusted)
	if ip.String() != "1.2.3.4" {
		t.Errorf("expected 1.2.3.4, got %s", ip)
	}

	// No trusted proxies configured.
	ip = ClientIP("10.0.0.1:1234", "1.2.3.4", nil)
	if ip.String() != "10.0.0.1" {
		t.Errorf("expected 10.0.0.1 (no trusted), got %s", ip)
	}
}
