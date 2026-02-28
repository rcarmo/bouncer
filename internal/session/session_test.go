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

	id, err := store.Create("user-1")
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

	id, _ := store.Create("user-1")
	store.Delete(id)

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

	id, _ := store.Create("user-1")
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
	id, _ := store1.Create("user-1")
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
}

func TestMultipleSessions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sessions.json")

	store, _ := NewStore(path, 7)
	defer store.Stop()

	id1, _ := store.Create("user-1")
	id2, _ := store.Create("user-2")
	id3, _ := store.Create("user-3")

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

	id1, _ := store.Create("user-1")
	id2, _ := store.Create("user-2")
	store.Delete(id1)

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

	id, _ := store.Create("user-1")
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
	store.Create("user-1")
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

	store.Create("user-1")
	store.Create("user-2")
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
	os.WriteFile(path, []byte("not json"), 0600)

	_, err := NewStore(path, 7)
	if err == nil {
		t.Error("expected error for corrupted file")
	}
}
