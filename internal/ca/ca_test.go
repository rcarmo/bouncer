package ca

import (
	"crypto/x509"
	"encoding/pem"
	"path/filepath"
	"testing"

	"github.com/rcarmo/bouncer/internal/config"
)

func loadTestConfig(t *testing.T) *config.Config {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "bouncer.json")
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	cfg.Server.Hostnames = []string{"test.local"}
	cfg.Server.IPAddresses = []string{"127.0.0.1"}
	return cfg
}

func TestEnsureCA(t *testing.T) {
	cfg := loadTestConfig(t)

	if err := EnsureCA(cfg); err != nil {
		t.Fatalf("EnsureCA: %v", err)
	}
	if cfg.Server.TLS.CA == nil || cfg.Server.TLS.CA.CertPem == "" {
		t.Fatal("CA cert not generated")
	}
	if cfg.Server.TLS.CA.KeyPem == "" {
		t.Fatal("CA key not generated")
	}

	// Parse the cert.
	block, _ := pem.Decode([]byte(cfg.Server.TLS.CA.CertPem))
	if block == nil {
		t.Fatal("invalid PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	if !cert.IsCA {
		t.Error("expected IsCA = true")
	}
	if cert.Subject.CommonName != "Bouncer Local CA" {
		t.Errorf("expected CN 'Bouncer Local CA', got %q", cert.Subject.CommonName)
	}
}

func TestEnsureCAIdempotent(t *testing.T) {
	cfg := loadTestConfig(t)
	if err := EnsureCA(cfg); err != nil {
		t.Fatalf("EnsureCA: %v", err)
	}
	origCert := cfg.Server.TLS.CA.CertPem

	// Second call should not regenerate.
	if err := EnsureCA(cfg); err != nil {
		t.Fatalf("EnsureCA: %v", err)
	}
	if cfg.Server.TLS.CA.CertPem != origCert {
		t.Error("CA was regenerated on second call")
	}
}

func TestEnsureServerCert(t *testing.T) {
	cfg := loadTestConfig(t)
	if err := EnsureCA(cfg); err != nil {
		t.Fatalf("EnsureCA: %v", err)
	}

	if err := EnsureServerCert(cfg); err != nil {
		t.Fatalf("EnsureServerCert: %v", err)
	}
	if cfg.Server.TLS.ServerCert == nil || cfg.Server.TLS.ServerCert.CertPem == "" {
		t.Fatal("server cert not generated")
	}

	// Parse and check SANs.
	block, _ := pem.Decode([]byte(cfg.Server.TLS.ServerCert.CertPem))
	cert, _ := x509.ParseCertificate(block.Bytes)

	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "test.local" {
		t.Errorf("expected DNS SAN test.local, got %v", cert.DNSNames)
	}
	if len(cert.IPAddresses) != 1 || cert.IPAddresses[0].String() != "127.0.0.1" {
		t.Errorf("expected IP SAN 127.0.0.1, got %v", cert.IPAddresses)
	}
}

func TestServerCertRegeneratesOnSANChange(t *testing.T) {
	cfg := loadTestConfig(t)
	if err := EnsureCA(cfg); err != nil {
		t.Fatalf("EnsureCA: %v", err)
	}
	if err := EnsureServerCert(cfg); err != nil {
		t.Fatalf("EnsureServerCert: %v", err)
	}
	origCert := cfg.Server.TLS.ServerCert.CertPem

	// Change SANs.
	cfg.Server.Hostnames = []string{"other.local"}
	if err := EnsureServerCert(cfg); err != nil {
		t.Fatalf("EnsureServerCert: %v", err)
	}

	if cfg.Server.TLS.ServerCert.CertPem == origCert {
		t.Error("server cert was not regenerated after SAN change")
	}

	block, _ := pem.Decode([]byte(cfg.Server.TLS.ServerCert.CertPem))
	cert, _ := x509.ParseCertificate(block.Bytes)
	if cert.DNSNames[0] != "other.local" {
		t.Errorf("expected other.local, got %v", cert.DNSNames)
	}
}

func TestCACertDER(t *testing.T) {
	cfg := loadTestConfig(t)
	if err := EnsureCA(cfg); err != nil {
		t.Fatalf("EnsureCA: %v", err)
	}

	der, err := CACertDER(cfg)
	if err != nil {
		t.Fatalf("CACertDER: %v", err)
	}
	if len(der) == 0 {
		t.Fatal("empty DER")
	}
	// Should be parseable.
	_, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate from DER: %v", err)
	}
}

func TestGenerateMobileconfig(t *testing.T) {
	cfg := loadTestConfig(t)
	if err := EnsureCA(cfg); err != nil {
		t.Fatalf("EnsureCA: %v", err)
	}

	mc, err := GenerateMobileconfig(cfg)
	if err != nil {
		t.Fatalf("GenerateMobileconfig: %v", err)
	}
	xml := string(mc)
	if len(xml) < 100 {
		t.Error("mobileconfig too short")
	}
	// Should contain key markers.
	for _, needle := range []string{
		"com.apple.security.root",
		"Bouncer Local CA",
		"PayloadContent",
	} {
		if !contains(xml, needle) {
			t.Errorf("mobileconfig missing %q", needle)
		}
	}
}

func TestServerTLSKeyPair(t *testing.T) {
	cfg := loadTestConfig(t)
	if err := EnsureCA(cfg); err != nil {
		t.Fatalf("EnsureCA: %v", err)
	}
	if err := EnsureServerCert(cfg); err != nil {
		t.Fatalf("EnsureServerCert: %v", err)
	}

	certPEM, keyPEM, err := ServerTLSKeyPair(cfg)
	if err != nil {
		t.Fatalf("ServerTLSKeyPair: %v", err)
	}
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		t.Fatal("empty PEM")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsStr(s, substr))
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
