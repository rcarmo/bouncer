package authn

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rcarmo/bouncer/internal/config"
	"github.com/rcarmo/bouncer/internal/session"
	"github.com/rcarmo/bouncer/internal/site"
)

func setupTestHandler(t *testing.T) (*Handler, *config.Config, *session.Store) {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "bouncer.json")
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	cfg.Server.RPID = "localhost"
	cfg.Server.PublicOrigin = "https://localhost"
	cfg.Onboarding.Enabled = true
	cfg.Onboarding.Token = "123456"
	cfg.Onboarding.LocalBypass = true

	sessPath := filepath.Join(dir, "sessions.json")
	sess, err := session.NewStore(sessPath, 7)
	if err != nil {
		t.Fatalf("session.NewStore: %v", err)
	}
	t.Cleanup(sess.Stop)

	sites, err := site.New(cfg, nil)
	if err != nil {
		t.Fatalf("site.New: %v", err)
	}

	h, err := New(cfg, sess, nil, sites)
	if err != nil {
		t.Fatalf("authn.New: %v", err)
	}
	return h, cfg, sess
}

func TestRegisterOptionsDisabledWhenNotOnboarding(t *testing.T) {
	h, cfg, _ := setupTestHandler(t)
	cfg.Onboarding.Enabled = false

	body := `{"token":"123456","displayName":"Test","name":"test"}`
	req := httptest.NewRequest("POST", "/webauthn/register/options", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.RegisterOptions(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rr.Code)
	}
}

func TestRegisterOptionsInvalidToken(t *testing.T) {
	h, _, _ := setupTestHandler(t)

	body := `{"token":"000000","displayName":"Test","name":"test"}`
	req := httptest.NewRequest("POST", "/webauthn/register/options", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "8.8.8.8:1234" // Not local, so bypass doesn't apply.
	rr := httptest.NewRecorder()
	h.RegisterOptions(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rr.Code)
	}
}

func TestRegisterOptionsRateLimit(t *testing.T) {
	h, _, _ := setupTestHandler(t)
	h.rateLimit = 2
	h.rateWindow = time.Minute
	h.blockDuration = time.Minute

	body := `{"token":"000000","displayName":"Test","name":"test"}`
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest("POST", "/webauthn/register/options", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "8.8.8.8:1234"
		rr := httptest.NewRecorder()
		h.RegisterOptions(rr, req)
		if i < 2 && rr.Code != http.StatusForbidden {
			t.Fatalf("expected 403 before rate limit, got %d", rr.Code)
		}
		if i == 2 && rr.Code != http.StatusTooManyRequests {
			t.Fatalf("expected 429 after rate limit, got %d", rr.Code)
		}
	}
}

func TestRegisterOptionsValidToken(t *testing.T) {
	h, _, _ := setupTestHandler(t)

	body := `{"token":"123456","displayName":"Test","name":"test"}`
	req := httptest.NewRequest("POST", "https://localhost/webauthn/register/options", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://localhost")
	req.RemoteAddr = "8.8.8.8:1234"
	rr := httptest.NewRecorder()
	h.RegisterOptions(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if resp["challengeId"] == nil {
		t.Error("missing challengeId in response")
	}
	if resp["options"] == nil {
		t.Error("missing options in response")
	}
}

func TestRegisterOptionsLocalBypass(t *testing.T) {
	h, _, _ := setupTestHandler(t)

	// Empty token but from local IP.
	body := `{"token":"","displayName":"Test","name":"test"}`
	req := httptest.NewRequest("POST", "https://localhost/webauthn/register/options", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://localhost")
	req.RemoteAddr = "192.168.1.1:1234" // Local IP.
	rr := httptest.NewRecorder()
	h.RegisterOptions(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 (local bypass), got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestRegisterOptionsLocalBypassDisabled(t *testing.T) {
	h, cfg, _ := setupTestHandler(t)
	cfg.Onboarding.LocalBypass = false

	body := `{"token":"","displayName":"Test","name":"test"}`
	req := httptest.NewRequest("POST", "/webauthn/register/options", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "192.168.1.1:1234"
	rr := httptest.NewRecorder()
	h.RegisterOptions(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 (bypass disabled), got %d", rr.Code)
	}
}

func TestRegisterOptionsBadBody(t *testing.T) {
	h, _, _ := setupTestHandler(t)

	req := httptest.NewRequest("POST", "/webauthn/register/options", strings.NewReader("not json"))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.RegisterOptions(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestRegisterVerifyDisabledWhenNotOnboarding(t *testing.T) {
	h, cfg, _ := setupTestHandler(t)
	cfg.Onboarding.Enabled = false

	req := httptest.NewRequest("POST", "/webauthn/register/verify?challengeId=x&userId=x", nil)
	rr := httptest.NewRecorder()
	h.RegisterVerify(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rr.Code)
	}
}

func TestRegisterVerifyMissingChallengeId(t *testing.T) {
	h, _, _ := setupTestHandler(t)

	req := httptest.NewRequest("POST", "/webauthn/register/verify", nil)
	rr := httptest.NewRecorder()
	h.RegisterVerify(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestRegisterVerifyExpiredChallenge(t *testing.T) {
	h, _, _ := setupTestHandler(t)

	req := httptest.NewRequest("POST", "/webauthn/register/verify?challengeId=nonexistent&userId=x&displayName=x&name=x", nil)
	rr := httptest.NewRecorder()
	h.RegisterVerify(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 (expired), got %d", rr.Code)
	}
}

func TestLoginOptions(t *testing.T) {
	h, _, _ := setupTestHandler(t)

	req := httptest.NewRequest("POST", "https://localhost/webauthn/login/options", nil)
	req.Header.Set("Origin", "https://localhost")
	rr := httptest.NewRecorder()
	h.LoginOptions(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if resp["challengeId"] == nil {
		t.Error("missing challengeId")
	}
	if resp["options"] == nil {
		t.Error("missing options")
	}
}

func TestLoginVerifyMissingChallengeId(t *testing.T) {
	h, _, _ := setupTestHandler(t)

	req := httptest.NewRequest("POST", "/webauthn/login/verify", nil)
	rr := httptest.NewRecorder()
	h.LoginVerify(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestLoginVerifyExpiredChallenge(t *testing.T) {
	h, _, _ := setupTestHandler(t)

	req := httptest.NewRequest("POST", "/webauthn/login/verify?challengeId=bogus", nil)
	rr := httptest.NewRecorder()
	h.LoginVerify(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestLogoutClearsCookie(t *testing.T) {
	h, _, sess := setupTestHandler(t)

	sessID, _ := sess.Create("default", "user-1")

	req := httptest.NewRequest("POST", "https://localhost/logout", nil)
	req.Header.Set("Origin", "https://localhost")
	req.AddCookie(&http.Cookie{Name: "bouncer_session", Value: sessID})
	rr := httptest.NewRecorder()
	h.Logout(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}

	// Session should be deleted.
	if sess.Get(sessID) != nil {
		t.Error("session should be deleted after logout")
	}

	// Cookie should be expired.
	cookies := rr.Result().Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == "bouncer_session" {
			found = true
			if c.MaxAge != -1 {
				t.Errorf("expected MaxAge -1, got %d", c.MaxAge)
			}
		}
	}
	if !found {
		t.Error("expected bouncer_session cookie in response")
	}
}

func TestLogoutWithoutCookie(t *testing.T) {
	h, _, _ := setupTestHandler(t)

	req := httptest.NewRequest("POST", "https://localhost/logout", nil)
	req.Header.Set("Origin", "https://localhost")
	rr := httptest.NewRecorder()
	h.Logout(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 even without cookie, got %d", rr.Code)
	}
}

func TestIsTokenValidLocalBypass(t *testing.T) {
	h, _, _ := setupTestHandler(t)

	tests := []struct {
		name       string
		remoteAddr string
		token      string
		want       bool
	}{
		{"valid token", "8.8.8.8:1234", "123456", true},
		{"invalid token remote", "8.8.8.8:1234", "000000", false},
		{"local bypass", "192.168.1.1:1234", "", true},
		{"local bypass 10.x", "10.0.0.1:1234", "", true},
		{"local bypass loopback", "127.0.0.1:1234", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/", nil)
			req.RemoteAddr = tt.remoteAddr
			got := h.isTokenValid(req, tt.token)
			if got != tt.want {
				t.Errorf("isTokenValid(%s, %q) = %v, want %v", tt.remoteAddr, tt.token, got, tt.want)
			}
		})
	}
}
