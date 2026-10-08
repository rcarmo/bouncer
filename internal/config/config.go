// Package config defines the Bouncer configuration types and YAML persistence.
package config

import (
	"bytes"
	"crypto/subtle"
	"errors"
	"fmt"
	"gopkg.in/yaml.v3"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rcarmo/bouncer/internal/atomicfile"
)

// Config is the top-level bouncer.yaml structure.
type Config struct {
	Server     ServerConfig     `json:"server" yaml:"server"`
	Sites      []SiteConfig     `json:"sites,omitempty" yaml:"sites,omitempty"`
	Ingresses  []IngressConfig  `json:"ingresses" yaml:"ingresses"`
	Session    SessionConfig    `json:"session" yaml:"session"`
	Onboarding OnboardingConfig `json:"onboarding" yaml:"onboarding"`
	Users      []User           `json:"users" yaml:"users"`

	mu   sync.RWMutex `json:"-" yaml:"-"`
	path string       `json:"-" yaml:"-"`
}

type ServerConfig struct {
	HTTPListen     string     `json:"httpListen,omitempty" yaml:"httpListen,omitempty"`
	Listen         string     `json:"listen" yaml:"listen"`
	PublicOrigin   string     `json:"publicOrigin" yaml:"publicOrigin"`
	RPID           string     `json:"rpID" yaml:"rpID"`
	Backend        string     `json:"backend" yaml:"backend"`
	Hostnames      []string   `json:"hostnames" yaml:"hostnames"`
	IPAddresses    []string   `json:"ipAddresses" yaml:"ipAddresses"`
	TrustedProxies []string   `json:"trustedProxies" yaml:"trustedProxies"`
	TLS            TLSConfig  `json:"tls" yaml:"tls"`
	Cloudflare     bool       `json:"cloudflare" yaml:"cloudflare"`
	MDNS           MDNSConfig `json:"mdns" yaml:"mdns"`
}

// MDNSConfig controls Bonjour/mDNS service announcements for local discovery.
type MDNSConfig struct {
	Enabled        bool   `json:"enabled" yaml:"enabled"`
	Service        string `json:"service" yaml:"service"`
	Domain         string `json:"domain" yaml:"domain"`
	InstancePrefix string `json:"instancePrefix" yaml:"instancePrefix"`
}

// SiteConfig defines a single public site and its backend.
type SiteConfig struct {
	ID           string   `json:"id" yaml:"id"`
	PublicOrigin string   `json:"publicOrigin" yaml:"publicOrigin"`
	RPID         string   `json:"rpID" yaml:"rpID"`
	Backend      string   `json:"backend" yaml:"backend"`
	Hostnames    []string `json:"hostnames" yaml:"hostnames"`
	IPAddresses  []string `json:"ipAddresses" yaml:"ipAddresses"`
	Listen       string   `json:"listen,omitempty" yaml:"listen,omitempty"`
}

type TLSConfig struct {
	CA         *KeyPair `json:"ca,omitempty" yaml:"ca,omitempty"`
	ServerCert *KeyPair `json:"serverCert,omitempty" yaml:"serverCert,omitempty"`
}

type KeyPair struct {
	CertPem string `json:"certPem" yaml:"certPem"`
	KeyPem  string `json:"keyPem" yaml:"keyPem"`
}

type SessionConfig struct {
	TTLDays    int    `json:"ttlDays" yaml:"ttlDays"`
	CookieName string `json:"cookieName" yaml:"cookieName"`
	File       string `json:"file" yaml:"file"`
}

type OnboardingConfig struct {
	Enabled            bool      `json:"enabled" yaml:"enabled"`
	Token              string    `json:"token" yaml:"token"`
	TokenExpiresAt     time.Time `json:"tokenExpiresAt,omitempty" yaml:"tokenExpiresAt,omitempty"`
	TokenAttempts      int       `json:"tokenAttempts,omitempty" yaml:"tokenAttempts,omitempty"`
	TokenFailures      int       `json:"tokenFailures,omitempty" yaml:"tokenFailures,omitempty"`
	TokenLocked        bool      `json:"tokenLocked,omitempty" yaml:"tokenLocked,omitempty"`
	RotateTokenOnStart bool      `json:"rotateTokenOnStart" yaml:"rotateTokenOnStart"`
	OneTimeToken       bool      `json:"oneTimeToken" yaml:"oneTimeToken"`
	LocalBypass        bool      `json:"localBypass" yaml:"localBypass"`
	ProfileURL         string    `json:"profileUrl" yaml:"profileUrl"`
	MacCertURL         string    `json:"macCertUrl" yaml:"macCertUrl"`
	Instructions       struct {
		IOS []string `json:"ios" yaml:"ios"`
	} `json:"instructions" yaml:"instructions"`
	Pushover PushoverConfig `json:"pushover" yaml:"pushover"`
	GeoIP    GeoIPConfig    `json:"geoip" yaml:"geoip"`
}

type PushoverConfig struct {
	Enabled        bool   `json:"enabled" yaml:"enabled"`
	APIToken       string `json:"apiToken" yaml:"apiToken"`
	UserKey        string `json:"userKey" yaml:"userKey"`
	Device         string `json:"device,omitempty" yaml:"device,omitempty"`
	Sound          string `json:"sound,omitempty" yaml:"sound,omitempty"`
	TimeoutSeconds int    `json:"timeoutSeconds" yaml:"timeoutSeconds"`
}

type GeoIPConfig struct {
	Enabled                 bool       `json:"enabled" yaml:"enabled"`
	URL                     string     `json:"url" yaml:"url"`
	TimeoutSeconds          int        `json:"timeoutSeconds" yaml:"timeoutSeconds"`
	CacheTTLSeconds         int        `json:"cacheTtlSeconds" yaml:"cacheTtlSeconds"`
	PreferCloudflareHeaders bool       `json:"preferCloudflareHeaders" yaml:"preferCloudflareHeaders"`
	DBIP                    DBIPConfig `json:"dbip" yaml:"dbip"`
}

type DBIPConfig struct {
	Enabled                bool   `json:"enabled" yaml:"enabled"`
	DatabasePath           string `json:"databasePath" yaml:"databasePath"`
	AutoUpdate             bool   `json:"autoUpdate" yaml:"autoUpdate"`
	UpdateIntervalHours    int    `json:"updateIntervalHours" yaml:"updateIntervalHours"`
	UpdatePageURL          string `json:"updatePageUrl" yaml:"updatePageUrl"`
	UpdateURL              string `json:"updateUrl" yaml:"updateUrl"`
	DownloadTimeoutSeconds int    `json:"downloadTimeoutSeconds" yaml:"downloadTimeoutSeconds"`
}

type User struct {
	ID          string       `json:"id" yaml:"id"`
	SiteID      string       `json:"site,omitempty" yaml:"site,omitempty"`
	DisplayName string       `json:"displayName" yaml:"displayName"`
	Name        string       `json:"name" yaml:"name"`
	Credentials []Credential `json:"credentials" yaml:"credentials"`
}

type Credential struct {
	ID             string   `json:"id" yaml:"id"`
	PublicKey      string   `json:"publicKey" yaml:"publicKey"`
	SignCount      uint32   `json:"signCount" yaml:"signCount"`
	Transports     []string `json:"transports" yaml:"transports"`
	CreatedAt      string   `json:"createdAt" yaml:"createdAt"`
	BackupEligible bool     `json:"backupEligible" yaml:"backupEligible"`
	BackupState    bool     `json:"backupState" yaml:"backupState"`
}

// Defaults returns a Config with sensible defaults.
func Defaults() *Config {
	return &Config{
		Ingresses: []IngressConfig{
			{ID: "lan", Type: "local", SiteIDs: []string{"default"}, Local: &LocalIngress{Listen: ":443", TLS: "local-ca"}},
			{ID: "trust", Type: "local", SiteIDs: []string{"default"}, Local: &LocalIngress{Listen: ":80", TLS: "off", Bootstrap: true}},
		},
		Server: ServerConfig{
			Listen:       ":443",
			PublicOrigin: "https://bouncer.local",
			RPID:         "bouncer.local",
			Backend:      "http://127.0.0.1:3000",
			Hostnames:    []string{"bouncer.local"},
			MDNS: MDNSConfig{
				Enabled: false,
				Service: "_https._tcp",
				Domain:  "local.",
			},
		},
		Session: SessionConfig{
			TTLDays:    7,
			CookieName: "bouncer_session",
			File:       "sessions.json",
		},
		Onboarding: OnboardingConfig{
			Enabled:            false,
			RotateTokenOnStart: true,
			OneTimeToken:       true,
			LocalBypass:        true,
			ProfileURL:         "/certs/rootCA.mobileconfig",
			MacCertURL:         "/certs/rootCA.cer",
			Pushover: PushoverConfig{
				Enabled:        false,
				TimeoutSeconds: 3,
			},
			GeoIP: GeoIPConfig{
				Enabled:                 true,
				URL:                     "",
				TimeoutSeconds:          2,
				CacheTTLSeconds:         3600,
				PreferCloudflareHeaders: true,
				DBIP: DBIPConfig{
					Enabled:                true,
					DatabasePath:           "dbip-city-lite.sqlite",
					AutoUpdate:             true,
					UpdateIntervalHours:    24,
					UpdatePageURL:          "https://db-ip.com/db/download/ip-to-city-lite",
					UpdateURL:              "",
					DownloadTimeoutSeconds: 30,
				},
			},
		},
	}
}

// Load reads a config from path, creating a default file if it doesn't exist.
func Load(path string) (*Config, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("config: abs path: %w", err)
	}

	// #nosec G304 -- config path is explicitly provided by the user.
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

	cfg := Defaults()   // Non-listener settings retain defaults.
	cfg.Ingresses = nil // Existing files must explicitly declare authoritative ingresses.
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(cfg); err != nil {
		return nil, fmt.Errorf("config: parse YAML: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("config: expected one YAML document")
	}
	cfg.path = absPath
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Save persists the config atomically.
func (c *Config) Save() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.saveLocked()
}

func (c *Config) saveLocked() error {
	var data bytes.Buffer
	encoder := yaml.NewEncoder(&data)
	encoder.SetIndent(2)
	if err := encoder.Encode(c); err != nil {
		return fmt.Errorf("config: encode YAML: %w", err)
	}
	if err := encoder.Close(); err != nil {
		return fmt.Errorf("config: finish YAML: %w", err)
	}
	return atomicfile.Write(c.path, data.Bytes(), 0600)
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
	u = *cloneUser(&u)
	if len(u.Credentials) > 0 && u.Credentials[0].CreatedAt == "" {
		u.Credentials[0].CreatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	old := c.Users
	c.Users = append(c.Users, *cloneUser(&u))
	if err := c.saveLocked(); err != nil {
		c.Users = old
		return err
	}
	return nil
}

// HasCredential checks revocation without copying sensitive credential records.
func (c *Config) HasCredential(siteID, userID, credentialID string) bool {
	if credentialID == "" {
		return false
	}
	siteID = normalizeSiteID(siteID)
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, u := range c.Users {
		if u.ID == userID && normalizeSiteID(u.SiteID) == siteID {
			for _, cred := range u.Credentials {
				if cred.ID == credentialID {
					return true
				}
			}
			return false
		}
	}
	return false
}

// FindUserByCredentialID returns a user and credential index, or nil.
func (c *Config) FindUserByCredentialID(siteID, credID string) (*User, int) {
	siteID = normalizeSiteID(siteID)
	c.mu.RLock()
	defer c.mu.RUnlock()
	for i := range c.Users {
		if normalizeSiteID(c.Users[i].SiteID) != siteID {
			continue
		}
		for j := range c.Users[i].Credentials {
			if c.Users[i].Credentials[j].ID == credID {
				return cloneUser(&c.Users[i]), j
			}
		}
	}
	return nil, -1
}

// FindUserByID returns a user by ID.
func (c *Config) FindUserByID(siteID, id string) *User {
	siteID = normalizeSiteID(siteID)
	c.mu.RLock()
	defer c.mu.RUnlock()
	for i := range c.Users {
		if normalizeSiteID(c.Users[i].SiteID) == siteID && c.Users[i].ID == id {
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
	for i := range clone.Credentials {
		clone.Credentials[i].Transports = append([]string(nil), u.Credentials[i].Transports...)
	}
	return &clone
}

func normalizeSiteID(id string) string {
	if id == "" {
		return "default"
	}
	return id
}

// ErrSignCount marks a replayed, cloned or out-of-order counter-bearing assertion.
var ErrSignCount = errors.New("credential signature counter did not advance")

// UpdateSignCount atomically checks and persists the counter. Zero-only
// authenticators are supported; a nonzero counter must strictly increase.
func (c *Config) UpdateSignCount(siteID, userID, credID string, count uint32) error {
	siteID = normalizeSiteID(siteID)
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := range c.Users {
		if normalizeSiteID(c.Users[i].SiteID) == siteID && c.Users[i].ID == userID {
			for j := range c.Users[i].Credentials {
				if c.Users[i].Credentials[j].ID == credID {
					old := c.Users[i].Credentials[j].SignCount
					if (old != 0 || count != 0) && count <= old {
						return ErrSignCount
					}
					c.Users[i].Credentials[j].SignCount = count
					if err := c.saveLocked(); err != nil {
						c.Users[i].Credentials[j].SignCount = old
						return err
					}
					return nil
				}
			}
		}
	}
	return nil
}

// EnrollmentTokenTTL and EnrollmentTokenMaxAttempts bound one-time enrollment.
const EnrollmentTokenTTL = 10 * time.Minute
const EnrollmentTokenMaxAttempts = 10

// EnrollmentFailureBudget persists across automatic code generations until operator reset.
const EnrollmentFailureBudget = 100

// OnboardingSnapshot returns an independent, locked copy of onboarding settings.
func (c *Config) OnboardingSnapshot() OnboardingConfig {
	c.mu.RLock()
	defer c.mu.RUnlock()
	result := c.Onboarding
	result.Instructions.IOS = append([]string(nil), result.Instructions.IOS...)
	return result
}

// SetEnrollmentToken sets a fresh token and persists its lifetime and guess budget.
// Callers must not mutate Onboarding.Token directly after serving requests.
func (c *Config) SetEnrollmentToken(token string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	old := c.Onboarding
	c.Onboarding.Token = strings.TrimSpace(token)
	c.Onboarding.TokenAttempts = 0
	c.Onboarding.TokenFailures = 0
	c.Onboarding.TokenLocked = false
	c.Onboarding.TokenExpiresAt = time.Time{}
	if c.Onboarding.Token != "" {
		c.Onboarding.TokenExpiresAt = time.Now().Add(EnrollmentTokenTTL).UTC()
	}
	if err := c.saveLocked(); err != nil {
		c.Onboarding = old
		return err
	}
	return nil
}

// InitializeEnrollmentToken upgrades legacy tokens once, persisting the
// deadline so subsequent restarts cannot extend their lifetime.
func (c *Config) InitializeEnrollmentToken() error { return c.initializeEnrollmentToken(true) }

// PrepareEnrollmentToken sets candidate expiry without persisting a reload.
func (c *Config) PrepareEnrollmentToken() error { return c.initializeEnrollmentToken(false) }
func (c *Config) initializeEnrollmentToken(persist bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.Onboarding.Token == "" || !c.Onboarding.TokenExpiresAt.IsZero() {
		return nil
	}
	c.Onboarding.TokenExpiresAt = time.Now().Add(EnrollmentTokenTTL).UTC()
	if !persist {
		return nil
	}
	if err := c.saveLocked(); err != nil {
		c.Onboarding.TokenExpiresAt = time.Time{}
		return err
	}
	return nil
}

// CheckEnrollmentToken checks and (when consume is true) durably consumes a
// one-time token or records a failed guess. Persistence failures never authorize.
func (c *Config) CheckEnrollmentToken(token string, consume bool) (bool, string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	state := c.Onboarding
	current := strings.TrimSpace(state.Token)
	if state.TokenLocked || state.TokenAttempts >= EnrollmentTokenMaxAttempts || state.TokenFailures >= EnrollmentFailureBudget || state.TokenExpiresAt.IsZero() || !time.Now().Before(state.TokenExpiresAt) {
		return false, "", nil
	}
	if current == "" {
		return false, current, nil
	}
	valid := subtle.ConstantTimeCompare([]byte(token), []byte(current)) == 1
	if consume {
		if valid && state.OneTimeToken {
			c.Onboarding.Token = ""
		} else if !valid {
			c.Onboarding.TokenAttempts++
			c.Onboarding.TokenFailures++
			c.Onboarding.TokenLocked = c.Onboarding.TokenAttempts >= EnrollmentTokenMaxAttempts || c.Onboarding.TokenFailures >= EnrollmentFailureBudget
		}
		if err := c.saveLocked(); err != nil {
			c.Onboarding = state
			return false, current, err
		}
	}
	return valid, current, nil
}

// Validate rejects settings that would prevent authentication or overwrite state.
func (c *Config) Validate() error {
	if c.Session.TTLDays <= 0 || c.Session.TTLDays > 3650 {
		return fmt.Errorf("config: session ttlDays must be between 1 and 3650")
	}
	cookie := http.Cookie{Name: c.Session.CookieName, Value: "validation", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode}
	if err := cookie.Valid(); err != nil {
		return fmt.Errorf("config: cookieName: %w", err)
	}
	if c.Session.File == "" || filepath.Clean(c.SessionFilePath()) == filepath.Clean(c.Path()) {
		return fmt.Errorf("config: sessions must use a separate non-empty file")
	}
	return nil
}

// EnsureEnrollmentToken issues on demand without clearing persisted failure state.
// Only the operator's SetEnrollmentToken resets lockout. Reusable codes also expire.
func (c *Config) EnsureEnrollmentToken(token string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	old := c.Onboarding
	if old.TokenLocked || old.TokenAttempts >= EnrollmentTokenMaxAttempts || old.TokenFailures >= EnrollmentFailureBudget {
		return "", nil
	}
	if old.Token != "" && time.Now().Before(old.TokenExpiresAt) {
		return old.Token, nil
	}
	c.Onboarding.Token = token
	c.Onboarding.TokenAttempts = 0
	c.Onboarding.TokenExpiresAt = time.Now().Add(EnrollmentTokenTTL).UTC()
	if err := c.saveLocked(); err != nil {
		c.Onboarding = old
		return "", err
	}
	return token, nil
}
