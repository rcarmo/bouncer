package session

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCreateAndGet(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sessions.json")

	store, err := NewStore(path, 7)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Stop()

	id, err := store.Create("default", "user-1", "credential")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if len(id) != 64 { // 32 bytes hex
		t.Errorf("expected 64 char ID, got %d", len(id))
	}

	sess := store.Get(id)
	if sess == nil {
		t.Fatal("Get returned nil")
	}
	if sess.UserID != "user-1" {
		t.Errorf("expected user-1, got %s", sess.UserID)
	}
	if sess.SiteID != "default" {
		t.Errorf("expected site default, got %s", sess.SiteID)
	}
}

func TestGetNonExistent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sessions.json")

	store, _ := NewStore(path, 7)
	defer store.Stop()

	if store.Get("nonexistent") != nil {
		t.Error("expected nil for nonexistent session")
	}
}

func TestDelete(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sessions.json")

	store, _ := NewStore(path, 7)
	defer store.Stop()

	id, _ := store.Create("default", "user-1", "credential")
	if err := store.Delete(id); err != nil {
		t.Fatal(err)
	}

	if store.Get(id) != nil {
		t.Error("expected nil after delete")
	}
}

func TestTTLExpiry(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sessions.json")

	// TTL of 0 days = immediate expiry.
	store, _ := NewStore(path, 0)
	defer store.Stop()

	id, _ := store.Create("default", "user-1", "credential")
	// Wait a tiny bit so the session is in the past.
	time.Sleep(10 * time.Millisecond)

	if store.Get(id) != nil {
		t.Error("expected nil for expired session")
	}
}

func TestPersistAndReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sessions.json")

	store1, _ := NewStore(path, 7)
	id, _ := store1.Create("default", "user-1", "credential")
	store1.Stop()

	// Reload from disk.
	store2, err := NewStore(path, 7)
	if err != nil {
		t.Fatalf("NewStore reload: %v", err)
	}
	defer store2.Stop()

	sess := store2.Get(id)
	if sess == nil {
		t.Fatal("session not persisted")
	}
	if sess.UserID != "user-1" {
		t.Errorf("expected user-1, got %s", sess.UserID)
	}
	if sess.SiteID != "default" {
		t.Errorf("expected site default, got %s", sess.SiteID)
	}
}

func TestMultipleSessions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sessions.json")

	store, _ := NewStore(path, 7)
	defer store.Stop()

	id1, _ := store.Create("default", "user-1", "credential")
	id2, _ := store.Create("default", "user-2", "credential")
	id3, _ := store.Create("default", "user-3", "credential")

	if id1 == id2 || id2 == id3 || id1 == id3 {
		t.Error("session IDs should be unique")
	}

	if store.Get(id1) == nil || store.Get(id2) == nil || store.Get(id3) == nil {
		t.Error("all sessions should be retrievable")
	}
}

func TestDeleteDoesNotAffectOthers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sessions.json")

	store, _ := NewStore(path, 7)
	defer store.Stop()

	id1, _ := store.Create("default", "user-1", "credential")
	id2, _ := store.Create("default", "user-2", "credential")
	if err := store.Delete(id1); err != nil {
		t.Fatal(err)
	}

	if store.Get(id1) != nil {
		t.Error("deleted session should be nil")
	}
	if store.Get(id2) == nil {
		t.Error("other session should still exist")
	}
}

func TestGetUpdatesLastSeen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sessions.json")

	store, _ := NewStore(path, 7)
	defer store.Stop()

	id, _ := store.Create("default", "user-1", "credential")
	sess1 := store.Get(id)
	firstSeen := sess1.LastSeen

	time.Sleep(1100 * time.Millisecond) // RFC3339 has second precision.
	sess2 := store.Get(id)

	if sess2.LastSeen == firstSeen {
		t.Error("LastSeen should be updated on Get")
	}
}

func TestPersistFilePermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sessions.json")

	store, _ := NewStore(path, 7)
	if _, err := store.Create("default", "user-1", "credential"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	store.Stop()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("expected perm 0600, got %o", info.Mode().Perm())
	}
}

func TestPruneRemovesExpired(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sessions.json")

	// Create a store with very short TTL.
	store, _ := NewStore(path, 0)
	defer store.Stop()

	if _, err := store.Create("default", "user-1", "credential"); err != nil {
		t.Fatalf("Create user-1: %v", err)
	}
	if _, err := store.Create("default", "user-2", "credential"); err != nil {
		t.Fatalf("Create user-2: %v", err)
	}
	time.Sleep(10 * time.Millisecond)

	store.prune()

	store.mu.RLock()
	count := len(store.sessions)
	store.mu.RUnlock()

	if count != 0 {
		t.Errorf("expected 0 sessions after prune, got %d", count)
	}
}

func TestLoadCorruptedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sessions.json")
	if err := os.WriteFile(path, []byte("not json"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err := NewStore(path, 7)
	if err == nil {
		t.Error("expected error for corrupted file")
	}
}

func TestLastSeenSecondPrecision(t *testing.T) {
	store, e := NewStore(filepath.Join(t.TempDir(), "sessions.json"), 7)
	if e != nil {
		t.Fatal(e)
	}
	defer store.Stop()
	sess, e := store.Create("default", "user", "credential")
	if e != nil {
		t.Fatal(e)
	}
	store.mu.Lock()
	store.sessions[sess].LastSeen = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)
	store.mu.Unlock()
	before := time.Now().UTC().Truncate(time.Second)
	got := store.Get(sess)
	if got == nil {
		t.Fatal("missing session")
	}
	seen, e := time.Parse(time.RFC3339, got.LastSeen)
	if e != nil || seen.Before(before) || seen.After(time.Now().UTC()) {
		t.Fatalf("invalid lastSeen %q: %v", got.LastSeen, e)
	}
	// Returned snapshots remain independent from persistent state.
	got.LastSeen = "changed"
	again := store.Get(sess)
	if again == nil || again.LastSeen == "changed" {
		t.Fatal("caller mutated store")
	}
}
