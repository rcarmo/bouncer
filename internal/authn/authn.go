// Package authn provides WebAuthn registration and login HTTP handlers.
package authn

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/rcarmo/bouncer/internal/config"
	"github.com/rcarmo/bouncer/internal/localip"
	"github.com/rcarmo/bouncer/internal/session"
)

// Handler holds WebAuthn state and HTTP handlers.
type Handler struct {
	wan     *webauthn.WebAuthn
	cfg     *config.Config
	sess    *session.Store
	trusted []*net.IPNet
	secure  bool // whether to set Secure flag on cookies

	// In-flight challenges keyed by a random challenge ID.
	mu         sync.Mutex
	challenges map[string]*challengeEntry
}

// challengeEntry stores a challenge with its expiry time.
type challengeEntry struct {
	data    *webauthn.SessionData
	expires time.Time
}

// New creates a new WebAuthn handler.
func New(cfg *config.Config, sess *session.Store, trusted []*net.IPNet) (*Handler, error) {
	wan, err := webauthn.New(&webauthn.Config{
		RPID:          cfg.Server.RPID,
		RPDisplayName: "Bouncer",
		RPOrigins:     []string{cfg.Server.PublicOrigin},
	})
	if err != nil {
		return nil, fmt.Errorf("authn: init webauthn: %w", err)
	}
	h := &Handler{
		wan:        wan,
		cfg:        cfg,
		sess:       sess,
		trusted:    trusted,
		secure:     !cfg.Server.Cloudflare,
		challenges: make(map[string]*challengeEntry),
	}
	// Start challenge cleanup goroutine.
	go h.cleanupChallenges()
	return h, nil
}

// --- WebAuthn User adapter ---

type webauthnUser struct {
	user *config.User
}

func (u *webauthnUser) WebAuthnID() []byte {
	return []byte(u.user.ID)
}

func (u *webauthnUser) WebAuthnName() string {
	return u.user.Name
}

func (u *webauthnUser) WebAuthnDisplayName() string {
	return u.user.DisplayName
}

func (u *webauthnUser) WebAuthnCredentials() []webauthn.Credential {
	var creds []webauthn.Credential
	for _, c := range u.user.Credentials {
		credID, _ := base64.RawURLEncoding.DecodeString(c.ID)
		pubKey, _ := base64.RawURLEncoding.DecodeString(c.PublicKey)
		cred := webauthn.Credential{
			ID:              credID,
			PublicKey:       pubKey,
			AttestationType: "",
			Authenticator: webauthn.Authenticator{
				SignCount: c.SignCount,
			},
		}
		for _, t := range c.Transports {
			cred.Transport = append(cred.Transport, protocol.AuthenticatorTransport(t))
		}
		creds = append(creds, cred)
	}
	return creds
}

func (u *webauthnUser) WebAuthnIcon() string { return "" }

// --- HTTP Handlers ---

// RegisterOptions handles POST /webauthn/register/options.
func (h *Handler) RegisterOptions(w http.ResponseWriter, r *http.Request) {
	if !h.cfg.Onboarding.Enabled {
		http.Error(w, "registration disabled", http.StatusForbidden)
		return
	}

	// Check token (unless local bypass).
	var req struct {
		Token       string `json:"token"`
		DisplayName string `json:"displayName"`
		Name        string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	if !h.isTokenValid(r, req.Token) {
		http.Error(w, "invalid token", http.StatusForbidden)
		return
	}

	// Create a temporary user for registration.
	userID := randomUserID()
	if req.DisplayName == "" {
		req.DisplayName = "User"
	}
	if req.Name == "" {
		req.Name = fmt.Sprintf("user-%s", userID[:8])
	}
	tmpUser := &webauthnUser{
		user: &config.User{
			ID:          userID,
			DisplayName: req.DisplayName,
			Name:        req.Name,
		},
	}

	options, sessionData, err := h.wan.BeginRegistration(tmpUser)
	if err != nil {
		slog.Error("webauthn: begin registration", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Store challenge.
	challengeID := randomChallengeID()
	h.mu.Lock()
	h.challenges[challengeID] = &challengeEntry{
		data:    sessionData,
		expires: time.Now().Add(5 * time.Minute),
	}
	h.mu.Unlock()

	resp := map[string]any{
		"options":     options,
		"challengeId": challengeID,
		"userId":      userID,
		"displayName": req.DisplayName,
		"name":        req.Name,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// RegisterVerify handles POST /webauthn/register/verify.
func (h *Handler) RegisterVerify(w http.ResponseWriter, r *http.Request) {
	if !h.cfg.Onboarding.Enabled {
		http.Error(w, "registration disabled", http.StatusForbidden)
		return
	}

	var req struct {
		ChallengeID string `json:"challengeId"`
		UserID      string `json:"userId"`
		DisplayName string `json:"displayName"`
		Name        string `json:"name"`
	}
	// Parse challengeId from query or a wrapper; the credential is in the body.
	challengeID := r.URL.Query().Get("challengeId")
	userID := r.URL.Query().Get("userId")
	displayName := r.URL.Query().Get("displayName")
	name := r.URL.Query().Get("name")
	if challengeID == "" {
		// Try parsing a wrapper object.
		// For simplicity, require query params.
		http.Error(w, "missing challengeId", http.StatusBadRequest)
		return
	}
	_ = req // Suppress unused warning.

	h.mu.Lock()
	entry, ok := h.challenges[challengeID]
	if ok {
		delete(h.challenges, challengeID)
	}
	h.mu.Unlock()
	if !ok || time.Now().After(entry.expires) {
		http.Error(w, "challenge expired", http.StatusBadRequest)
		return
	}

	tmpUser := &webauthnUser{
		user: &config.User{
			ID:          userID,
			DisplayName: displayName,
			Name:        name,
		},
	}

	credential, err := h.wan.FinishRegistration(tmpUser, *entry.data, r)
	if err != nil {
		slog.Error("webauthn: finish registration", "error", err)
		http.Error(w, "verification failed", http.StatusBadRequest)
		return
	}

	// Build transports.
	var transports []string
	for _, t := range credential.Transport {
		transports = append(transports, string(t))
	}

	// Save user + credential.
	newUser := config.User{
		ID:          userID,
		DisplayName: displayName,
		Name:        name,
		Credentials: []config.Credential{
			{
				ID:         base64.RawURLEncoding.EncodeToString(credential.ID),
				PublicKey:  base64.RawURLEncoding.EncodeToString(credential.PublicKey),
				SignCount:  credential.Authenticator.SignCount,
				Transports: transports,
				CreatedAt:  time.Now().UTC().Format(time.RFC3339),
			},
		},
	}
	if err := h.cfg.AddUser(newUser); err != nil {
		slog.Error("webauthn: save user", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Create session.
	sessID, err := h.sess.Create(userID)
	if err != nil {
		slog.Error("webauthn: create session", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	setSessionCookie(w, h.cfg.Session.CookieName, sessID, h.cfg.Session.TTLDays, h.secure)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// LoginOptions handles POST /webauthn/login/options.
func (h *Handler) LoginOptions(w http.ResponseWriter, r *http.Request) {
	// Discoverable credential flow: no user specified.
	options, sessionData, err := h.wan.BeginDiscoverableLogin()
	if err != nil {
		slog.Error("webauthn: begin login", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	challengeID := randomChallengeID()
	h.mu.Lock()
	h.challenges[challengeID] = &challengeEntry{
		data:    sessionData,
		expires: time.Now().Add(5 * time.Minute),
	}
	h.mu.Unlock()

	resp := map[string]any{
		"options":     options,
		"challengeId": challengeID,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// LoginVerify handles POST /webauthn/login/verify.
func (h *Handler) LoginVerify(w http.ResponseWriter, r *http.Request) {
	challengeID := r.URL.Query().Get("challengeId")
	if challengeID == "" {
		http.Error(w, "missing challengeId", http.StatusBadRequest)
		return
	}

	h.mu.Lock()
	entry, ok := h.challenges[challengeID]
	if ok {
		delete(h.challenges, challengeID)
	}
	h.mu.Unlock()
	if !ok || time.Now().After(entry.expires) {
		http.Error(w, "challenge expired", http.StatusBadRequest)
		return
	}

	// Discoverable login handler that looks up user by credential ID.
	userHandler := func(rawID, userHandle []byte) (webauthn.User, error) {
		credIDStr := base64.RawURLEncoding.EncodeToString(rawID)
		user, _ := h.cfg.FindUserByCredentialID(credIDStr)
		if user == nil {
			// Try userHandle (which is WebAuthnID = user.ID).
			user = h.cfg.FindUserByID(string(userHandle))
		}
		if user == nil {
			return nil, fmt.Errorf("user not found")
		}
		return &webauthnUser{user: user}, nil
	}

	credential, err := h.wan.FinishDiscoverableLogin(userHandler, *entry.data, r)
	if err != nil {
		slog.Error("webauthn: finish login", "error", err)
		http.Error(w, "authentication failed", http.StatusUnauthorized)
		return
	}

	// Find user by credential to update sign count.
	credIDStr := base64.RawURLEncoding.EncodeToString(credential.ID)
	user, _ := h.cfg.FindUserByCredentialID(credIDStr)
	if user == nil {
		slog.Error("webauthn: user not found after login", "credentialID", credIDStr)
		http.Error(w, `{"error":"user not found"}`, http.StatusInternalServerError)
		return
	}

	_ = h.cfg.UpdateSignCount(user.ID, credIDStr, credential.Authenticator.SignCount)

	sessID, err := h.sess.Create(user.ID)
	if err != nil {
		slog.Error("webauthn: create session", "error", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	setSessionCookie(w, h.cfg.Session.CookieName, sessID, h.cfg.Session.TTLDays, h.secure)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// Logout handles POST /logout.
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(h.cfg.Session.CookieName)
	if err == nil {
		h.sess.Delete(cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     h.cfg.Session.CookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   h.secure,
		SameSite: http.SameSiteLaxMode,
	})
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// --- helpers ---

func (h *Handler) isTokenValid(r *http.Request, token string) bool {
	if h.cfg.Onboarding.LocalBypass {
		clientIP := localip.ExtractIP(r.RemoteAddr)
		if clientIP != nil && localip.IsLocal(clientIP) {
			return true
		}
	}
	return token == h.cfg.Onboarding.Token
}

func setSessionCookie(w http.ResponseWriter, name, value string, ttlDays int, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   ttlDays * 86400,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

func randomUserID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func randomChallengeID() string {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(time.Now().UnixNano()))
	r := make([]byte, 8)
	rand.Read(r)
	return fmt.Sprintf("%x%x", b, r)
}

// cleanupChallenges periodically removes expired challenges.
func (h *Handler) cleanupChallenges() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		h.mu.Lock()
		for id, entry := range h.challenges {
			if now.After(entry.expires) {
				delete(h.challenges, id)
			}
		}
		h.mu.Unlock()
	}
}
