package authn

import (
	"bytes"
	"fmt"
	"github.com/rcarmo/bouncer/internal/localip"
	"log/slog"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRateLimiterFallbackAndGlobalBounds(t *testing.T) {
	h := &Handler{rate: make(map[string]*rateEntry), rateLimit: 20, rateWindow: time.Minute, blockDuration: time.Minute}
	req := httptest.NewRequest("POST", "https://bouncer.test/webauthn/login/options", nil)
	req.RemoteAddr = "broken"
	if h.allowRequest(req) {
		t.Fatal("unknown peer not denied")
	}
	for i := 0; i < maxGlobalRequests+10; i++ {
		req.RemoteAddr = fmt.Sprintf("192.0.%d.%d:1234", i/255, i%255)
		ok := h.allowRequest(req)
		if ok != (i < maxGlobalRequests) {
			t.Fatalf("global limiter at %d: %v", i, ok)
		}
	}
	if len(h.rate) > maxGlobalRequests {
		t.Fatal("unbounded limiter")
	}
}
func TestNotificationConcurrencyBound(t *testing.T) {
	h := &Handler{notifications: make(chan struct{}, 2)}
	release := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		h.runNotification(func() { defer wg.Done(); <-release })
	}
	if len(h.notifications) != 2 {
		t.Fatal("not running")
	}
	h.runNotification(func() { t.Error("over-capacity notification executed") })
	close(release)
	wg.Wait()
}
func TestEnrollmentLogsDoNotContainCode(t *testing.T) {
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	defer slog.SetDefault(old)
	h := &Handler{}
	h.announceEnrollmentToken(httptest.NewRequest("GET", "https://bouncer.test", nil), "123456789012")
	if strings.Contains(buf.String(), "123456789012") {
		t.Fatal("enrollment code leaked")
	}
}

func TestTrustedProxyRateLimitWithoutXFF(t *testing.T) {
	trusted, _ := localip.ParseTrustedProxies([]string{"127.0.0.1/32"})
	h := &Handler{trusted: trusted, rate: make(map[string]*rateEntry), rateLimit: 2, rateWindow: time.Minute, blockDuration: time.Minute}
	req := httptest.NewRequest("POST", "https://bouncer.test", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	for i := 0; i < 3; i++ {
		if ok := h.allowRequest(req); ok != (i < 2) {
			t.Fatalf("fallback limiter %d: %v", i, ok)
		}
	}
	if _, ok := h.rate["127.0.0.1"]; !ok {
		t.Fatal("no safe peer fallback")
	}
}
func TestChallengeMapCapacity(t *testing.T) {
	h, _, _ := setupTestHandler(t)
	h.mu.Lock()
	for i := 0; i < maxChallenges; i++ {
		h.challenges[fmt.Sprint(i)] = &challengeEntry{expires: time.Now().Add(time.Minute)}
	}
	h.mu.Unlock()
	req := httptest.NewRequest("POST", "https://localhost/webauthn/login/options", nil)
	req.RemoteAddr = "192.168.1.100:1234"
	req.Header.Set("Origin", "https://localhost")
	w := httptest.NewRecorder()
	h.LoginOptions(w, req)
	if w.Code != 503 || len(h.challenges) != maxChallenges {
		t.Fatalf("capacity not enforced: %d / %d", w.Code, len(h.challenges))
	}
}
