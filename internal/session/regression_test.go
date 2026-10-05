package session

import (
	"path/filepath"
	"sync"
	"testing"
)

func TestSessionCopyIsolationAndConcurrentPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.json")
	s, err := NewStore(path, 7)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Stop()
	id, err := s.Create("default", "original", "credential")
	if err != nil {
		t.Fatal(err)
	}
	copy := s.Get(id)
	copy.UserID = "changed"
	if s.Get(id).UserID != "original" {
		t.Fatal("Get aliases internal session")
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			if err := s.save(); err != nil {
				t.Error(err)
			}
		}()
		go func() {
			defer wg.Done()
			id, err := s.Create("default", "u", "credential")
			if err != nil {
				t.Error(err)
				return
			}
			if err := s.Delete(id); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	disk, err := NewStore(path, 7)
	if err != nil {
		t.Fatal(err)
	}
	defer disk.Stop()
	if len(disk.sessions) != 1 || disk.Get(id) == nil {
		t.Fatal("stale persisted sessions")
	}
	s.Stop()
	s.Stop() // shutdown is idempotent
}

func TestSessionPersistenceFailure(t *testing.T) {
	s, err := NewStore(filepath.Join(t.TempDir(), "sessions.json"), 7)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Stop()
	id, err := s.Create("default", "u", "credential")
	if err != nil {
		t.Fatal(err)
	}
	s.path = t.TempDir()
	if _, err := s.Create("default", "new", "credential"); err == nil {
		t.Fatal("expected create failure")
	}
	if len(s.sessions) != 1 {
		t.Fatal("failed create left active session")
	}
	if err := s.Delete(id); err == nil {
		t.Fatal("delete failure not reported")
	}
	if s.Get(id) != nil {
		t.Fatal("failed disk deletion must revoke in memory")
	}
}

func TestCredentialBindingSurvivesRestartAndLegacyStateIsPreserved(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.json")
	s, err := NewStore(path, 7)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Stop()
	if _, err := s.Create("default", "u", ""); err == nil {
		t.Fatal("unbound session creation allowed")
	}
	id, err := s.Create("default", "u", "credential")
	if err != nil {
		t.Fatal(err)
	}
	disk, err := NewStore(path, 7)
	if err != nil {
		t.Fatal(err)
	}
	defer disk.Stop()
	if sess := disk.Get(id); sess == nil || sess.CredentialID != "credential" {
		t.Fatal("credential binding lost")
	}
	// Old data is loaded intact; admission rejects missing credential bindings.
	s.mu.Lock()
	s.sessions[id].CredentialID = ""
	err = s.saveLocked()
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := NewStore(path, 7)
	if err != nil {
		t.Fatal(err)
	}
	defer legacy.Stop()
	if legacy.Get(id) == nil {
		t.Fatal("legacy state discarded")
	}
}
