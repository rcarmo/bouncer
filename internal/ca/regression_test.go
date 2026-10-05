package ca

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/rcarmo/bouncer/internal/config"
)

func resign(t *testing.T, pair *config.KeyPair, parent *config.KeyPair, change func(*x509.Certificate)) {
	t.Helper()
	cert, key, err := parseKeyPair(pair)
	if err != nil {
		t.Fatal(err)
	}
	root, signer, err := parseKeyPair(parent)
	if err != nil {
		t.Fatal(err)
	}
	change(cert)
	der, err := x509.CreateCertificate(rand.Reader, cert, root, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	pair.CertPem = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestServerCertificateHealth(t *testing.T) {
	for _, kind := range []string{"expired", "future", "near expiry", "healthy", "key mismatch", "different CA"} {
		t.Run(kind, func(t *testing.T) {
			cfg := loadTestConfig(t)
			if err := EnsureCA(cfg); err != nil {
				t.Fatal(err)
			}
			if err := EnsureServerCert(cfg); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "expired":
				resign(t, cfg.Server.TLS.ServerCert, cfg.Server.TLS.CA, func(c *x509.Certificate) { c.NotAfter = time.Now().Add(-time.Hour) })
			case "future":
				resign(t, cfg.Server.TLS.ServerCert, cfg.Server.TLS.CA, func(c *x509.Certificate) { c.NotBefore = time.Now().Add(time.Hour) })
			case "near expiry":
				resign(t, cfg.Server.TLS.ServerCert, cfg.Server.TLS.CA, func(c *x509.Certificate) { c.NotAfter = time.Now().Add(29 * 24 * time.Hour) })
			case "healthy":
				resign(t, cfg.Server.TLS.ServerCert, cfg.Server.TLS.CA, func(c *x509.Certificate) { c.NotAfter = time.Now().Add(31 * 24 * time.Hour) })
			case "key mismatch":
				cfg.Server.TLS.ServerCert.KeyPem = cfg.Server.TLS.CA.KeyPem
			case "different CA":
				other := loadTestConfig(t)
				if err := EnsureCA(other); err != nil {
					t.Fatal(err)
				}
				cfg.Server.TLS.CA = other.Server.TLS.CA
			}
			before := cfg.Server.TLS.ServerCert.CertPem
			if err := EnsureServerCert(cfg); err != nil {
				t.Fatal(err)
			}
			if (before == cfg.Server.TLS.ServerCert.CertPem) != (kind == "healthy") {
				t.Fatal("incorrect renewal decision")
			}
			cert, _, err := parseKeyPair(cfg.Server.TLS.ServerCert)
			if err != nil {
				t.Fatal(err)
			}
			root, _, err := validatedCA(cfg.Server.TLS.CA)
			if err != nil {
				t.Fatal(err)
			}
			if err := cert.CheckSignatureFrom(root); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestInvalidCANeverReplaced(t *testing.T) {
	for _, kind := range []string{"bad cert", "bad key", "missing cert", "missing key", "mismatch", "expired", "future", "not CA", "no signing usage"} {
		t.Run(kind, func(t *testing.T) {
			cfg := loadTestConfig(t)
			if err := EnsureCA(cfg); err != nil {
				t.Fatal(err)
			}
			kp := cfg.Server.TLS.CA
			switch kind {
			case "bad cert":
				kp.CertPem = "invalid"
			case "bad key":
				kp.KeyPem = "invalid"
			case "missing cert":
				kp.CertPem = ""
			case "missing key":
				kp.KeyPem = ""
			case "mismatch":
				other := loadTestConfig(t)
				if err := EnsureCA(other); err != nil {
					t.Fatal(err)
				}
				kp.KeyPem = other.Server.TLS.CA.KeyPem
			case "expired":
				resign(t, kp, kp, func(c *x509.Certificate) { c.NotAfter = time.Now().Add(-time.Hour) })
			case "future":
				resign(t, kp, kp, func(c *x509.Certificate) { c.NotBefore = time.Now().Add(time.Hour) })
			case "not CA":
				resign(t, kp, kp, func(c *x509.Certificate) { c.IsCA = false; c.MaxPathLen = -1; c.MaxPathLenZero = false })
			case "no signing usage":
				resign(t, kp, kp, func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageDigitalSignature })
			}
			before := *kp
			if err := EnsureCA(cfg); err == nil {
				t.Fatal("accepted invalid CA")
			}
			if err := EnsureServerCert(cfg); err == nil {
				t.Fatal("signed using invalid CA")
			}
			if *kp != before {
				t.Fatal("replaced trusted root")
			}
		})
	}
}

func TestPKCS8CAKeyAndCanonicalIPSAN(t *testing.T) {
	cfg := loadTestConfig(t)
	if err := EnsureCA(cfg); err != nil {
		t.Fatal(err)
	}
	_, key, err := parseKeyPair(cfg.Server.TLS.CA)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Server.TLS.CA.KeyPem = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	if err := EnsureCA(cfg); err != nil {
		t.Fatal(err)
	}
	cfg.Server.IPAddresses = []string{"2001:0db8::1"}
	if err := EnsureServerCert(cfg); err != nil {
		t.Fatal(err)
	}
	before := cfg.Server.TLS.ServerCert.CertPem
	if err := EnsureServerCert(cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Server.TLS.ServerCert.CertPem != before {
		t.Fatal("canonical IPv6 SAN caused renewal")
	}
}
