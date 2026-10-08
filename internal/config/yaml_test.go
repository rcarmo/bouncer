package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestYAMLRoundTripSecurityState(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bouncer.yaml")
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	c.Onboarding.Token = "000012345678"
	c.Onboarding.TokenExpiresAt = time.Now().UTC().Truncate(time.Second)
	c.Onboarding.TokenFailures = 19
	c.Server.TLS.CA = &KeyPair{CertPem: "-----BEGIN CERTIFICATE-----\nexample\n-----END CERTIFICATE-----\n", KeyPem: "secret\nsecond line\n"}
	c.Users = []User{{ID: "user", SiteID: "default", Credentials: []Credential{{ID: "cred", PublicKey: "key", BackupEligible: true, Transports: []string{"internal"}}}}}
	if err = c.Save(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "certPem: |") || strings.HasPrefix(string(data), "{") {
		t.Fatal("configuration is not human-readable block YAML")
	}
	again, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if again.Onboarding.Token != c.Onboarding.Token || again.Onboarding.TokenFailures != 19 || !again.Onboarding.TokenExpiresAt.Equal(c.Onboarding.TokenExpiresAt) || again.Server.TLS.CA.KeyPem != c.Server.TLS.CA.KeyPem || !again.HasCredential("default", "user", "cred") {
		t.Fatal("security state changed on YAML roundtrip")
	}
	info, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatal("unsafe config permissions")
	}
}
func TestYAMLRejectsAmbiguousConfiguration(t *testing.T) {
	for _, data := range []string{"unknownField: true\n", "server:\n  bakend: wrong\n", "users: []\nusers: []\n", "users: []\n---\nusers: []\n"} {
		p := filepath.Join(t.TempDir(), "bouncer.yaml")
		if err := os.WriteFile(p, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(p); err == nil {
			t.Fatalf("accepted ambiguous YAML: %s", data)
		}
	}
}
