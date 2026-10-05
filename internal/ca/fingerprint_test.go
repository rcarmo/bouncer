package ca

import (
	"crypto/sha256"
	"encoding/hex"
	"github.com/rcarmo/bouncer/internal/config"
	"strings"
	"testing"
)

func TestFingerprintSHA256(t *testing.T) {
	cfg := loadTestConfig(t)
	if _, err := FingerprintSHA256(cfg); err == nil {
		t.Fatal("accepted missing CA")
	}
	if err := EnsureCA(cfg); err != nil {
		t.Fatal(err)
	}
	der, err := CACertDER(cfg)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	got, err := FingerprintSHA256(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 95 || strings.ReplaceAll(got, ":", "") != strings.ToUpper(hex.EncodeToString(sum[:])) {
		t.Fatalf("wrong DER fingerprint: %s", got)
	}
	cfg.Server.TLS.CA.CertPem = "-----BEGIN CERTIFICATE-----\nYmFk\n-----END CERTIFICATE-----"
	if _, err := FingerprintSHA256(cfg); err == nil {
		t.Fatal("accepted invalid certificate")
	}
	cfg.Server.TLS.CA = &config.KeyPair{CertPem: "invalid"}
	if _, err := FingerprintSHA256(cfg); err == nil {
		t.Fatal("accepted invalid PEM")
	}
}
