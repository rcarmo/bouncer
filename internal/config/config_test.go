package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaults(t *testing.T) {
	cfg := Defaults()
	if cfg.Server.Listen != ":443" {
		t.Errorf("expected :443, got %s", cfg.Server.Listen)
	}
	if cfg.Session.TTLDays != 7 {
		t.Errorf("expected 7, got %d", cfg.Session.TTLDays)
	}
	if cfg.Session.CookieName != "bouncer_session" {
		t.Errorf("expected bouncer_session, got %s", cfg.Session.CookieName)
	}
	if !cfg.Onboarding.LocalBypass {
		t.Error("expected localBypass true")
	}
	if !cfg.Onboarding.RotateTokenOnStart {
		t.Error("expected rotateTokenOnStart true")
	}
}

func TestLoadCreatesDefault(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bouncer.json")

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.Listen != ":443" {
		t.Errorf("expected :443, got %s", cfg.Server.Listen)
	}

	// File should exist now.
	if _, err := os.Stat(path); err != nil {
		t.Errorf("config file not created: %v", err)
	}
}

func TestLoadExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bouncer.json")

	data := []byte(`{"server":{"listen":":9999","backend":"http://localhost:5000"},"session":{"ttlDays":14}}`)
	os.WriteFile(path, data, 0600)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.Listen != ":9999" {
		t.Errorf("expected :9999, got %s", cfg.Server.Listen)
	}
	if cfg.Server.Backend != "http://localhost:5000" {
		t.Errorf("expected http://localhost:5000, got %s", cfg.Server.Backend)
	}
	if cfg.Session.TTLDays != 14 {
		t.Errorf("expected 14, got %d", cfg.Session.TTLDays)
	}
	// Defaults should fill in missing fields.
	if cfg.Session.CookieName != "bouncer_session" {
		t.Errorf("expected default cookie name, got %s", cfg.Session.CookieName)
	}
}

func TestSaveAndReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bouncer.json")

	cfg, _ := Load(path)
	cfg.Onboarding.Token = "123456"
	if err := cfg.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	cfg2, err := Load(path)
	if err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if cfg2.Onboarding.Token != "123456" {
		t.Errorf("expected 123456, got %s", cfg2.Onboarding.Token)
	}
}

func TestAddUserAndFind(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bouncer.json")

	cfg, _ := Load(path)
	u := User{
		ID:          "u1",
		DisplayName: "Alice",
		Name:        "alice",
		Credentials: []Credential{
			{ID: "cred1", PublicKey: "pk1", SignCount: 0},
		},
	}
	if err := cfg.AddUser(u); err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	if len(cfg.Users) != 1 {
		t.Fatalf("expected 1 user, got %d", len(cfg.Users))
	}

	found := cfg.FindUserByID("u1")
	if found == nil {
		t.Fatal("FindUserByID returned nil")
	}
	if found.DisplayName != "Alice" {
		t.Errorf("expected Alice, got %s", found.DisplayName)
	}

	found2, idx := cfg.FindUserByCredentialID("cred1")
	if found2 == nil || idx != 0 {
		t.Fatalf("FindUserByCredentialID: user=%v, idx=%d", found2, idx)
	}
}

func TestUpdateSignCount(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bouncer.json")

	cfg, _ := Load(path)
	cfg.AddUser(User{
		ID: "u1", DisplayName: "A", Name: "a",
		Credentials: []Credential{{ID: "c1", SignCount: 0}},
	})

	if err := cfg.UpdateSignCount("u1", "c1", 5); err != nil {
		t.Fatalf("UpdateSignCount: %v", err)
	}

	u, _ := cfg.FindUserByCredentialID("c1")
	if u.Credentials[0].SignCount != 5 {
		t.Errorf("expected sign count 5, got %d", u.Credentials[0].SignCount)
	}
}

func TestSessionFilePath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bouncer.json")

	cfg, _ := Load(path)
	got := cfg.SessionFilePath()
	want := filepath.Join(dir, "sessions.json")
	if got != want {
		t.Errorf("expected %s, got %s", want, got)
	}
}
