// Package session provides file-backed session management with TTL.
package session

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/rcarmo/bouncer/internal/atomicfile"
)

// Session represents a single authenticated session.
type Session struct {
	ID           string `json:"id"`
	SiteID       string `json:"site"`
	UserID       string `json:"userId"`
	CredentialID string `json:"credentialId"`
	CreatedAt    string `json:"createdAt"`
	LastSeen     string `json:"lastSeen"`
}

// Store is an in-memory session store backed by a JSON file.
type Store struct {
	mu       sync.RWMutex
	sessions map[string]*Session
	path     string
	ttl      time.Duration
	stopCh   chan struct{}
	lastSave time.Time
	stopOnce sync.Once
}

// sessionsFile is the JSON structure on disk.
type sessionsFile struct {
	Sessions []*Session `json:"sessions"`
}

// NewStore creates a session store, loading existing sessions from path.
func NewStore(path string, ttlDays int) (*Store, error) {
	ttl := time.Duration(ttlDays) * 24 * time.Hour
	s := &Store{
		sessions: make(map[string]*Session),
		path:     path,
		ttl:      ttl,
		stopCh:   make(chan struct{}),
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	s.prune()
	go s.cleanupLoop()
	return s, nil
}

// Create creates a new session for the given site/user and returns the session ID.
func (s *Store) Create(siteID, userID string, credentialID string) (string, error) {
	if credentialID == "" {
		return "", fmt.Errorf("session: credential ID required")
	}
	id, err := randomSessionID()
	if err != nil {
		return "", err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if siteID == "" {
		siteID = "default"
	}
	sess := &Session{
		ID:        id,
		SiteID:    siteID,
		UserID:    userID,
		CreatedAt: now,
		LastSeen:  now,
	}
	sess.CredentialID = credentialID
	s.mu.Lock()
	s.sessions[id] = sess
	defer s.mu.Unlock()
	if err := s.saveLocked(); err != nil {
		delete(s.sessions, id)
		return "", err
	}
	return id, nil
}

// Get returns a session if it exists and is not expired, updating LastSeen.
func (s *Store) Get(id string) *Session {
	var needSave bool
	s.mu.Lock()
	sess, ok := s.sessions[id]
	if !ok {
		s.mu.Unlock()
		return nil
	}
	created, err := time.Parse(time.RFC3339, sess.CreatedAt)
	if err != nil || time.Since(created) > s.ttl {
		delete(s.sessions, id)
		s.mu.Unlock()
		return nil
	}
	sess.LastSeen = time.Now().UTC().Format(time.RFC3339)
	if time.Since(s.lastSave) > time.Minute {
		needSave = true
	}
	copy := *sess
	if needSave {
		_ = s.saveLocked()
	}
	s.mu.Unlock()
	return &copy
}

// Delete removes a session.
func (s *Store) Delete(id string) error {
	s.mu.Lock()
	delete(s.sessions, id)
	defer s.mu.Unlock()
	return s.saveLocked()
}

// Stop stops the background cleanup goroutine.
func (s *Store) Stop() {
	s.stopOnce.Do(func() { close(s.stopCh) })
}

func (s *Store) load() error {
	data, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("session: read: %w", err)
	}
	var f sessionsFile
	if err := json.Unmarshal(data, &f); err != nil {
		return fmt.Errorf("session: parse: %w", err)
	}
	for _, sess := range f.Sessions {
		if sess == nil || sess.ID == "" {
			continue
		}
		if sess.SiteID == "" {
			sess.SiteID = "default"
		}
		s.sessions[sess.ID] = sess
	}
	return nil
}

func (s *Store) save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveLocked()
}

func (s *Store) saveLocked() error {
	list := make([]*Session, 0, len(s.sessions))
	for _, sess := range s.sessions {
		list = append(list, sess)
	}
	data, err := json.MarshalIndent(sessionsFile{Sessions: list}, "", "  ")
	if err != nil {
		return fmt.Errorf("session: marshal: %w", err)
	}
	if err := atomicfile.Write(s.path, data, 0600); err != nil {
		return err
	}
	s.lastSave = time.Now()
	return nil
}

func (s *Store) prune() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, sess := range s.sessions {
		created, err := time.Parse(time.RFC3339, sess.CreatedAt)
		if err != nil || time.Since(created) > s.ttl {
			delete(s.sessions, id)
		}
	}
}

func (s *Store) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.prune()
			_ = s.save()
		case <-s.stopCh:
			return
		}
	}
}

func randomSessionID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("session: random id: %w", err)
	}
	return hex.EncodeToString(b), nil
}
