// Package config defines the Bouncer configuration types and JSON persistence.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/rcarmo/bouncer/internal/atomicfile"
)

// Config is the top-level bouncer.json structure.
type Config struct {
	Server     ServerConfig     `json:"server"`
	Session    SessionConfig    `json:"session"`
	Onboarding OnboardingConfig `json:"onboarding"`
	Users      []User           `json:"users"`

	mu   sync.RWMutex `json:"-"`
	path string       `json:"-"`
}

type ServerConfig struct {
	Listen         string    `json:"listen"`
	PublicOrigin   string    `json:"publicOrigin"`
	RPID           string    `json:"rpID"`
	Backend        string    `json:"backend"`
	Hostnames      []string  `json:"hostnames"`
	IPAddresses    []string  `json:"ipAddresses"`
	TrustedProxies []string  `json:"trustedProxies"`
	TLS            TLSConfig `json:"tls"`
	Cloudflare     bool      `json:"cloudflare"`
}

type TLSConfig struct {
	CA         *KeyPair `json:"ca,omitempty"`
	ServerCert *KeyPair `json:"serverCert,omitempty"`
}

type KeyPair struct {
	CertPem string `json:"certPem"`
	KeyPem  string `json:"keyPem"`
}

type SessionConfig struct {
	TTLDays    int    `json:"ttlDays"`
	CookieName string `json:"cookieName"`
	File       string `json:"file"`
}

type OnboardingConfig struct {
	Enabled            bool     `json:"enabled"`
	Token              string   `json:"token"`
	RotateTokenOnStart bool     `json:"rotateTokenOnStart"`
	LocalBypass        bool     `json:"localBypass"`
	ProfileURL         string   `json:"profileUrl"`
	MacCertURL         string   `json:"macCertUrl"`
	Instructions       struct {
		IOS []string `json:"ios"`
	} `json:"instructions"`
}

type User struct {
	ID          string       `json:"id"`
	DisplayName string       `json:"displayName"`
	Name        string       `json:"name"`
	Credentials []Credential `json:"credentials"`
}

type Credential struct {
	ID         string   `json:"id"`
	PublicKey  string   `json:"publicKey"`
	SignCount  uint32   `json:"signCount"`
	Transports []string `json:"transports"`
	CreatedAt  string   `json:"createdAt"`
}

// Defaults returns a Config with sensible defaults.
func Defaults() *Config {
	return &Config{
		Server: ServerConfig{
			Listen:       ":443",
			PublicOrigin: "https://bouncer.local",
			RPID:         "bouncer.local",
			Backend:      "http://127.0.0.1:3000",
			Hostnames:    []string{"bouncer.local"},
		},
		Session: SessionConfig{
			TTLDays:    7,
			CookieName: "bouncer_session",
			File:       "sessions.json",
		},
		Onboarding: OnboardingConfig{
			Enabled:            false,
			RotateTokenOnStart: true,
			LocalBypass:        true,
			ProfileURL:         "/certs/rootCA.mobileconfig",
			MacCertURL:         "/certs/rootCA.cer",
		},
	}
}

// Load reads a config from path, creating a default file if it doesn't exist.
func Load(path string) (*Config, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("config: abs path: %w", err)
	}

	data, err := os.ReadFile(absPath)
	if os.IsNotExist(err) {
		cfg := Defaults()
		cfg.path = absPath
		if err := cfg.Save(); err != nil {
			return nil, fmt.Errorf("config: create default: %w", err)
		}
		return cfg, nil
	}
	if err != nil {
		return nil, fmt.Errorf("config: read: %w", err)
	}

	cfg := Defaults() // Start with defaults so missing fields get defaults.
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("config: parse: %w", err)
	}
	cfg.path = absPath
	return cfg, nil
}

// Save persists the config atomically.
func (c *Config) Save() error {
	data, err := c.snapshot()
	if err != nil {
		return err
	}
	return atomicfile.Write(c.path, data, 0600)
}

func (c *Config) snapshot() ([]byte, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("config: marshal: %w", err)
	}
	return data, nil
}

func (c *Config) saveLocked() error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("config: marshal: %w", err)
	}
	return atomicfile.Write(c.path, data, 0600)
}

// Path returns the config file path.
func (c *Config) Path() string {
	return c.path
}

// SessionFilePath returns the absolute path to the sessions file.
func (c *Config) SessionFilePath() string {
	if filepath.IsAbs(c.Session.File) {
		return c.Session.File
	}
	return filepath.Join(filepath.Dir(c.path), c.Session.File)
}

// AddUser adds a user and saves.
func (c *Config) AddUser(u User) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(u.Credentials) > 0 && u.Credentials[0].CreatedAt == "" {
		u.Credentials[0].CreatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	c.Users = append(c.Users, u)
	return c.saveLocked()
}

// FindUserByCredentialID returns a user and credential index, or nil.
func (c *Config) FindUserByCredentialID(credID string) (*User, int) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for i := range c.Users {
		for j := range c.Users[i].Credentials {
			if c.Users[i].Credentials[j].ID == credID {
				return cloneUser(&c.Users[i]), j
			}
		}
	}
	return nil, -1
}

// FindUserByID returns a user by ID.
func (c *Config) FindUserByID(id string) *User {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for i := range c.Users {
		if c.Users[i].ID == id {
			return cloneUser(&c.Users[i])
		}
	}
	return nil
}

func cloneUser(u *User) *User {
	if u == nil {
		return nil
	}
	clone := *u
	clone.Credentials = append([]Credential(nil), u.Credentials...)
	return &clone
}

// UpdateSignCount updates the sign count for a credential and saves.
func (c *Config) UpdateSignCount(userID, credID string, count uint32) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := range c.Users {
		if c.Users[i].ID == userID {
			for j := range c.Users[i].Credentials {
				if c.Users[i].Credentials[j].ID == credID {
					c.Users[i].Credentials[j].SignCount = count
					return c.saveLocked()
				}
			}
		}
	}
	return nil
}
