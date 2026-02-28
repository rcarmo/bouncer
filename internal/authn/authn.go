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
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/rcarmo/bouncer/internal/config"
	"github.com/rcarmo/bouncer/internal/localip"
	"github.com/rcarmo/bouncer/internal/session"
	"github.com/rcarmo/bouncer/internal/site"
)

// Handler holds WebAuthn state and HTTP handlers.
type Handler struct {
	wanBySite map[string]*webauthn.WebAuthn
	sites     *site.Registry
	cfg       *config.Config
	sess      *session.Store
	trusted   []*net.IPNet

	// In-flight challenges keyed by a random challenge ID.
	mu         sync.Mutex
	challenges map[string]*challengeEntry

	// Simple per-IP rate limiting.
	rateMu        sync.Mutex
	rate          map[string]*rateEntry
	rateLimit     int
	rateWindow    time.Duration
	blockDuration time.Duration
}

// challengeEntry stores a challenge with its expiry time.
type challengeEntry struct {
	data        *webauthn.SessionData
	expires     time.Time
	siteID      string
	userID      string
	displayName string
	name        string
}

// rateEntry tracks request counts per IP.
type rateEntry struct {
	count        int
	reset        time.Time
	blockedUntil time.Time
	lastSeen     time.Time
}

const (
	maxBodyBytes = 1 << 20 // 1 MiB
	maxNameLen   = 128
)

// New creates a new WebAuthn handler.
func New(cfg *config.Config, sess *session.Store, trusted []*net.IPNet, sites *site.Registry) (*Handler, error) {
	if sites == nil {
		return nil, fmt.Errorf("authn: sites registry is nil")
	}
	wanBySite := make(map[string]*webauthn.WebAuthn)
	for _, s := range sites.Sites {
		wan, err := webauthn.New(&webauthn.Config{
			RPID:          s.RPID,
			RPDisplayName: "Bouncer",
			RPOrigins:     []string{s.PublicOrigin},
		})
		if err != nil {
			return nil, fmt.Errorf("authn: init webauthn for site %q: %w", s.ID, err)
		}
		wanBySite[s.ID] = wan
	}
	h := &Handler{
		wanBySite:     wanBySite,
		sites:         sites,
		cfg:           cfg,
		sess:          sess,
		trusted:       trusted,
		challenges:    make(map[string]*challengeEntry),
		rate:          make(map[string]*rateEntry),
		rateLimit:     20,
		rateWindow:    time.Minute,
		blockDuration: 5 * time.Minute,
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
	setNoStore(w)
	if !h.cfg.Onboarding.Enabled {
		writeJSONError(w, http.StatusForbidden, "registration disabled")
		return
	}
	if !h.allowRequest(r) {
		writeJSONError(w, http.StatusTooManyRequests, "rate limited")
		return
	}

	// Check token (unless local bypass).
	var req struct {
		Token       string `json:"token"`
		DisplayName string `json:"displayName"`
		Name        string `json:"name"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "bad request")
		return
	}
	if len(req.DisplayName) > maxNameLen || len(req.Name) > maxNameLen {
		writeJSONError(w, http.StatusBadRequest, "input too long")
		return
	}

	if !h.isTokenValid(r, req.Token) {
		writeJSONError(w, http.StatusForbidden, "invalid token")
		return
	}

	// Resolve site.
	siteCfg, wan, err := h.siteForRequest(r)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "unknown site")
		return
	}
	if !h.validOrigin(r, siteCfg) {
		writeJSONError(w, http.StatusForbidden, "invalid origin")
		return
	}

	// Create a temporary user for registration.
	userID, err := randomUserID()
	if err != nil {
		slog.Error("webauthn: random user id", "error", err)
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if req.DisplayName == "" {
		req.DisplayName = "User"
	}
	if req.Name == "" {
		req.Name = fmt.Sprintf("user-%s", userID[:8])
	}
	tmpUser := &webauthnUser{
		user: &config.User{
			ID:          userID,
			SiteID:      siteCfg.ID,
			DisplayName: req.DisplayName,
			Name:        req.Name,
		},
	}

	options, sessionData, err := wan.BeginRegistration(tmpUser)
	if err != nil {
		slog.Error("webauthn: begin registration", "error", err)
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}

	// Store challenge.
	challengeID, err := randomChallengeID()
	if err != nil {
		slog.Error("webauthn: random challenge", "error", err)
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}
	h.mu.Lock()
	h.challenges[challengeID] = &challengeEntry{
		data:        sessionData,
		expires:     time.Now().Add(5 * time.Minute),
		siteID:      siteCfg.ID,
		userID:      userID,
		displayName: req.DisplayName,
		name:        req.Name,
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
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		slog.Warn("webauthn: write response", "error", err)
	}
}

// RegisterVerify handles POST /webauthn/register/verify.
func (h *Handler) RegisterVerify(w http.ResponseWriter, r *http.Request) {
	setNoStore(w)
	if !h.cfg.Onboarding.Enabled {
		writeJSONError(w, http.StatusForbidden, "registration disabled")
		return
	}
	if !h.allowRequest(r) {
		writeJSONError(w, http.StatusTooManyRequests, "rate limited")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)

	var req struct {
		ChallengeID string `json:"challengeId"`
		UserID      string `json:"userId"`
		DisplayName string `json:"displayName"`
		Name        string `json:"name"`
	}
	// Parse challengeId from query or a wrapper; the credential is in the body.
	challengeID := r.URL.Query().Get("challengeId")
	userID := r.URL.Query().Get("userId")
	if challengeID == "" {
		// Try parsing a wrapper object.
		// For simplicity, require query params.
		writeJSONError(w, http.StatusBadRequest, "missing challengeId")
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
		writeJSONError(w, http.StatusBadRequest, "challenge expired")
		return
	}

	siteCfg := h.sites.Resolve(r)
	if siteCfg == nil || siteCfg.ID != entry.siteID {
		writeJSONError(w, http.StatusNotFound, "unknown site")
		return
	}
	if !h.validOrigin(r, siteCfg) {
		writeJSONError(w, http.StatusForbidden, "invalid origin")
		return
	}
	if entry.userID == "" || string(entry.data.UserID) != entry.userID {
		writeJSONError(w, http.StatusBadRequest, "invalid challenge")
		return
	}
	if userID != "" && userID != entry.userID {
		writeJSONError(w, http.StatusBadRequest, "invalid user")
		return
	}

	wan, ok := h.wanBySite[entry.siteID]
	if !ok {
		writeJSONError(w, http.StatusInternalServerError, "invalid site")
		return
	}

	tmpUser := &webauthnUser{
		user: &config.User{
			ID:          entry.userID,
			SiteID:      entry.siteID,
			DisplayName: entry.displayName,
			Name:        entry.name,
		},
	}

	credential, err := wan.FinishRegistration(tmpUser, *entry.data, r)
	if err != nil {
		slog.Error("webauthn: finish registration", "error", err)
		writeJSONError(w, http.StatusBadRequest, "verification failed")
		return
	}

	// Build transports.
	var transports []string
	for _, t := range credential.Transport {
		transports = append(transports, string(t))
	}

	// Save user + credential.
	newUser := config.User{
		ID:          entry.userID,
		SiteID:      entry.siteID,
		DisplayName: entry.displayName,
		Name:        entry.name,
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
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}

	// Create session.
	sessID, err := h.sess.Create(entry.siteID, entry.userID)
	if err != nil {
		slog.Error("webauthn: create session", "error", err)
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}

	setSessionCookie(w, h.cfg.Session.CookieName, sessID, h.cfg.Session.TTLDays, h.cookieSecure(r))
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{"status": "ok"}); err != nil {
		slog.Warn("webauthn: write response", "error", err)
	}
}

// LoginOptions handles POST /webauthn/login/options.
func (h *Handler) LoginOptions(w http.ResponseWriter, r *http.Request) {
	setNoStore(w)
	if !h.allowRequest(r) {
		writeJSONError(w, http.StatusTooManyRequests, "rate limited")
		return
	}
	// Resolve site.
	siteCfg, wan, err := h.siteForRequest(r)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "unknown site")
		return
	}
	if !h.validOrigin(r, siteCfg) {
		writeJSONError(w, http.StatusForbidden, "invalid origin")
		return
	}

	// Discoverable credential flow: no user specified.
	options, sessionData, err := wan.BeginDiscoverableLogin()
	if err != nil {
		slog.Error("webauthn: begin login", "error", err)
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}

	challengeID, err := randomChallengeID()
	if err != nil {
		slog.Error("webauthn: random challenge", "error", err)
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}
	h.mu.Lock()
	h.challenges[challengeID] = &challengeEntry{
		data:    sessionData,
		expires: time.Now().Add(5 * time.Minute),
		siteID:  siteCfg.ID,
	}
	h.mu.Unlock()

	resp := map[string]any{
		"options":     options,
		"challengeId": challengeID,
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		slog.Warn("webauthn: write response", "error", err)
	}
}

// LoginVerify handles POST /webauthn/login/verify.
func (h *Handler) LoginVerify(w http.ResponseWriter, r *http.Request) {
	setNoStore(w)
	if !h.allowRequest(r) {
		writeJSONError(w, http.StatusTooManyRequests, "rate limited")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	challengeID := r.URL.Query().Get("challengeId")
	if challengeID == "" {
		writeJSONError(w, http.StatusBadRequest, "missing challengeId")
		return
	}

	h.mu.Lock()
	entry, ok := h.challenges[challengeID]
	if ok {
		delete(h.challenges, challengeID)
	}
	h.mu.Unlock()
	if !ok || time.Now().After(entry.expires) {
		writeJSONError(w, http.StatusBadRequest, "challenge expired")
		return
	}

	siteCfg := h.sites.Resolve(r)
	if siteCfg == nil || siteCfg.ID != entry.siteID {
		writeJSONError(w, http.StatusNotFound, "unknown site")
		return
	}
	if !h.validOrigin(r, siteCfg) {
		writeJSONError(w, http.StatusForbidden, "invalid origin")
		return
	}

	wan, ok := h.wanBySite[entry.siteID]
	if !ok {
		writeJSONError(w, http.StatusInternalServerError, "invalid site")
		return
	}

	// Discoverable login handler that looks up user by credential ID.
	userHandler := func(rawID, userHandle []byte) (webauthn.User, error) {
		credIDStr := base64.RawURLEncoding.EncodeToString(rawID)
		user, _ := h.cfg.FindUserByCredentialID(entry.siteID, credIDStr)
		if user == nil {
			// Try userHandle (which is WebAuthnID = user.ID).
			user = h.cfg.FindUserByID(entry.siteID, string(userHandle))
		}
		if user == nil {
			return nil, fmt.Errorf("user not found")
		}
		return &webauthnUser{user: user}, nil
	}

	credential, err := wan.FinishDiscoverableLogin(userHandler, *entry.data, r)
	if err != nil {
		slog.Error("webauthn: finish login", "error", err)
		writeJSONError(w, http.StatusUnauthorized, "authentication failed")
		return
	}

	// Find user by credential to update sign count.
	credIDStr := base64.RawURLEncoding.EncodeToString(credential.ID)
	user, _ := h.cfg.FindUserByCredentialID(entry.siteID, credIDStr)
	if user == nil {
		// #nosec G706 -- structured logging of credential ID for diagnostics.
		slog.Error("webauthn: user not found after login", "credentialID", credIDStr)
		writeJSONError(w, http.StatusInternalServerError, "user not found")
		return
	}

	_ = h.cfg.UpdateSignCount(entry.siteID, user.ID, credIDStr, credential.Authenticator.SignCount)

	sessID, err := h.sess.Create(entry.siteID, user.ID)
	if err != nil {
		slog.Error("webauthn: create session", "error", err)
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}
	setSessionCookie(w, h.cfg.Session.CookieName, sessID, h.cfg.Session.TTLDays, h.cookieSecure(r))

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{"status": "ok"}); err != nil {
		slog.Warn("webauthn: write response", "error", err)
	}
}

// Logout handles POST /logout.
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	setNoStore(w)
	siteCfg := h.sites.Resolve(r)
	if siteCfg == nil {
		writeJSONError(w, http.StatusNotFound, "unknown site")
		return
	}
	if !h.validOrigin(r, siteCfg) {
		writeJSONError(w, http.StatusForbidden, "invalid origin")
		return
	}
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
		Secure:   h.cookieSecure(r),
		SameSite: http.SameSiteLaxMode,
	})
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{"status": "ok"}); err != nil {
		slog.Warn("webauthn: write response", "error", err)
	}
}

// --- helpers ---

func (h *Handler) isTokenValid(r *http.Request, token string) bool {
	if h.cfg.Onboarding.LocalBypass {
		clientIP := localip.ClientIP(r.RemoteAddr, r.Header.Get("X-Forwarded-For"), h.trusted)
		if clientIP != nil && localip.IsLocal(clientIP) {
			return true
		}
	}
	return token == h.cfg.Onboarding.Token
}

func (h *Handler) clientIP(r *http.Request) string {
	ip := localip.ClientIP(r.RemoteAddr, r.Header.Get("X-Forwarded-For"), h.trusted)
	if ip == nil {
		return ""
	}
	return ip.String()
}

func (h *Handler) siteForRequest(r *http.Request) (*config.SiteConfig, *webauthn.WebAuthn, error) {
	s := h.sites.Resolve(r)
	if s == nil {
		return nil, nil, fmt.Errorf("unknown site")
	}
	wan, ok := h.wanBySite[s.ID]
	if !ok {
		return nil, nil, fmt.Errorf("no webauthn config")
	}
	return s, wan, nil
}

func (h *Handler) validOrigin(r *http.Request, siteCfg *config.SiteConfig) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return false
	}
	return originMatches(origin, siteCfg.PublicOrigin)
}

func (h *Handler) cookieSecure(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	clientIP := localip.ExtractIP(r.RemoteAddr)
	if clientIP != nil && localip.IsTrustedProxy(clientIP, h.trusted) {
		return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
	}
	return false
}

func originMatches(origin string, siteOrigin string) bool {
	if origin == "" || siteOrigin == "" {
		return false
	}
	originURL, err := url.Parse(origin)
	if err != nil {
		return false
	}
	siteURL, err := url.Parse(siteOrigin)
	if err != nil {
		return false
	}
	if !strings.EqualFold(originURL.Scheme, siteURL.Scheme) {
		return false
	}
	return strings.EqualFold(originURL.Host, siteURL.Host)
}

func (h *Handler) allowRequest(r *http.Request) bool {
	ip := h.clientIP(r)
	if ip == "" {
		return true
	}
	now := time.Now()
	h.rateMu.Lock()
	defer h.rateMu.Unlock()
	entry := h.rate[ip]
	if entry == nil {
		entry = &rateEntry{reset: now.Add(h.rateWindow)}
		h.rate[ip] = entry
	}
	entry.lastSeen = now
	if now.Before(entry.blockedUntil) {
		return false
	}
	if now.After(entry.reset) {
		entry.count = 0
		entry.reset = now.Add(h.rateWindow)
	}
	entry.count++
	if entry.count > h.rateLimit {
		entry.blockedUntil = now.Add(h.blockDuration)
		return false
	}
	return true
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	setNoStore(w)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func setNoStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
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

func randomUserID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", b), nil
}

func randomChallengeID() (string, error) {
	var b [8]byte
	now := time.Now().UnixNano()
	if now < 0 {
		now = 0
	}
	// #nosec G115 -- time.Now().UnixNano is non-negative for real system time.
	binary.BigEndian.PutUint64(b[:], uint64(now))
	r := make([]byte, 8)
	if _, err := rand.Read(r); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x%x", b, r), nil
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

		h.rateMu.Lock()
		for ip, entry := range h.rate {
			if entry == nil {
				delete(h.rate, ip)
				continue
			}
			if !entry.lastSeen.IsZero() && now.Sub(entry.lastSeen) > h.rateWindow && now.After(entry.blockedUntil) {
				delete(h.rate, ip)
			}
		}
		h.rateMu.Unlock()
	}
}
