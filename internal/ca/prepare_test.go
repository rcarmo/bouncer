package ca

import (
	"bytes"
	"github.com/rcarmo/bouncer/internal/config"
	"os"
	"path/filepath"
	"testing"
)

func TestPrepareDoesNotPersistCandidate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	c, e := config.Load(path)
	if e != nil {
		t.Fatal(e)
	}
	before, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	if e := PrepareCA(c); e != nil {
		t.Fatal(e)
	}
	if e := PrepareServerCert(c); e != nil {
		t.Fatal(e)
	}
	after, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("uncommitted TLS candidate changed disk state")
	}
	if c.Server.TLS.CA == nil || c.Server.TLS.ServerCert == nil {
		t.Fatal("candidate missing prepared material")
	}
}

func TestPrepareEnrollmentTokenDoesNotPersist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	c, e := config.Load(path)
	if e != nil {
		t.Fatal(e)
	}
	c.Onboarding.Token = "123456789012"
	if e = c.Save(); e != nil {
		t.Fatal(e)
	}
	before, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	if e = c.PrepareEnrollmentToken(); e != nil {
		t.Fatal(e)
	}
	after, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("candidate enrollment expiry persisted")
	}
	if c.Onboarding.TokenExpiresAt.IsZero() {
		t.Fatal("candidate has no token expiry")
	}
}
