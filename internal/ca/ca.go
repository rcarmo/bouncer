// Package ca provides built-in CA and server certificate generation using crypto/x509.
package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"

	"github.com/rcarmo/bouncer/internal/config"
)

// EnsureCA generates a root CA if one doesn't exist in the config, and saves it.
func EnsureCA(cfg *config.Config) error {
	if cfg.Server.TLS.CA != nil && cfg.Server.TLS.CA.CertPem != "" {
		return nil // CA already exists.
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("ca: generate key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return err
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "Bouncer Local CA",
			Organization: []string{"Bouncer"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour), // 10 years
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("ca: create cert: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("ca: marshal key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if cfg.Server.TLS.CA == nil {
		cfg.Server.TLS.CA = &config.KeyPair{}
	}
	cfg.Server.TLS.CA.CertPem = string(certPEM)
	cfg.Server.TLS.CA.KeyPem = string(keyPEM)

	return cfg.Save()
}

// EnsureServerCert generates (or regenerates) a server certificate signed by the CA.
func EnsureServerCert(cfg *config.Config) error {
	if cfg.Server.TLS.CA == nil || cfg.Server.TLS.CA.CertPem == "" {
		return fmt.Errorf("ca: no CA available")
	}

	// Parse CA cert + key.
	caCert, caKey, err := parseKeyPair(cfg.Server.TLS.CA)
	if err != nil {
		return fmt.Errorf("ca: parse CA: %w", err)
	}

	// Check if existing server cert matches current SANs.
	if cfg.Server.TLS.ServerCert != nil && cfg.Server.TLS.ServerCert.CertPem != "" {
		if !sansChanged(cfg) {
			return nil // SANs haven't changed, keep existing cert.
		}
	}

	// Generate server key.
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("ca: generate server key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return err
	}

	// Build SANs.
	var dnsNames []string
	var ipAddrs []net.IP
	for _, h := range cfg.Server.Hostnames {
		dnsNames = append(dnsNames, h)
	}
	for _, ipStr := range cfg.Server.IPAddresses {
		if ip := net.ParseIP(ipStr); ip != nil {
			ipAddrs = append(ipAddrs, ip)
		}
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   firstOrDefault(dnsNames, "bouncer"),
			Organization: []string{"Bouncer"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // 1 year
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              dnsNames,
		IPAddresses:           ipAddrs,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("ca: create server cert: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(serverKey)
	if err != nil {
		return fmt.Errorf("ca: marshal server key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if cfg.Server.TLS.ServerCert == nil {
		cfg.Server.TLS.ServerCert = &config.KeyPair{}
	}
	cfg.Server.TLS.ServerCert.CertPem = string(certPEM)
	cfg.Server.TLS.ServerCert.KeyPem = string(keyPEM)

	return cfg.Save()
}

// CACertDER returns the CA certificate in DER format (for .cer download).
func CACertDER(cfg *config.Config) ([]byte, error) {
	if cfg.Server.TLS.CA == nil {
		return nil, fmt.Errorf("ca: no CA")
	}
	block, _ := pem.Decode([]byte(cfg.Server.TLS.CA.CertPem))
	if block == nil {
		return nil, fmt.Errorf("ca: invalid PEM")
	}
	return block.Bytes, nil
}

// ServerTLSCert returns a tls.Certificate for use in tls.Config.
func ServerTLSKeyPair(cfg *config.Config) (certPEM, keyPEM []byte, err error) {
	if cfg.Server.TLS.ServerCert == nil {
		return nil, nil, fmt.Errorf("ca: no server cert")
	}
	return []byte(cfg.Server.TLS.ServerCert.CertPem), []byte(cfg.Server.TLS.ServerCert.KeyPem), nil
}

func parseKeyPair(kp *config.KeyPair) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	certBlock, _ := pem.Decode([]byte(kp.CertPem))
	if certBlock == nil {
		return nil, nil, fmt.Errorf("invalid cert PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}

	keyBlock, _ := pem.Decode([]byte(kp.KeyPem))
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("invalid key PEM")
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

func sansChanged(cfg *config.Config) bool {
	if cfg.Server.TLS.ServerCert == nil {
		return true
	}
	block, _ := pem.Decode([]byte(cfg.Server.TLS.ServerCert.CertPem))
	if block == nil {
		return true
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return true
	}

	// Check DNS names.
	wanted := make(map[string]bool)
	for _, h := range cfg.Server.Hostnames {
		wanted[h] = true
	}
	existing := make(map[string]bool)
	for _, h := range cert.DNSNames {
		existing[h] = true
	}
	if len(wanted) != len(existing) {
		return true
	}
	for k := range wanted {
		if !existing[k] {
			return true
		}
	}

	// Check IPs.
	wantedIPs := make(map[string]bool)
	for _, ip := range cfg.Server.IPAddresses {
		wantedIPs[ip] = true
	}
	existingIPs := make(map[string]bool)
	for _, ip := range cert.IPAddresses {
		existingIPs[ip.String()] = true
	}
	if len(wantedIPs) != len(existingIPs) {
		return true
	}
	for k := range wantedIPs {
		if !existingIPs[k] {
			return true
		}
	}
	return false
}

func randomSerial() (*big.Int, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("ca: random serial: %w", err)
	}
	return serial, nil
}

func firstOrDefault(ss []string, def string) string {
	if len(ss) > 0 {
		return ss[0]
	}
	return def
}
