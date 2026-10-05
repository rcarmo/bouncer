package authn

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rcarmo/bouncer/internal/localip"
)

func TestRegistrationOriginDoesNotMutateEnrollment(t *testing.T) {
	for _, token := range []string{"123456", "wrong"} {
		t.Run(token, func(t *testing.T) {
			h, c, _ := setupTestHandler(t)
			before := c.OnboardingSnapshot()
			r := httptest.NewRequest("POST", "https://localhost/webauthn/register/options", strings.NewReader(`{"token":"`+token+`"}`))
			r.RemoteAddr = "203.0.113.1:123"
			r.Header.Set("Origin", "https://evil.example")
			w := httptest.NewRecorder()
			h.RegisterOptions(w, r)
			if w.Code != http.StatusForbidden {
				t.Fatalf("got %d", w.Code)
			}
			after := c.OnboardingSnapshot()
			if after.Token != before.Token || after.TokenAttempts != before.TokenAttempts || !after.TokenExpiresAt.Equal(before.TokenExpiresAt) || h.tokenAnnounced || len(h.challenges) != 0 {
				t.Fatal("invalid origin mutated enrollment state")
			}
		})
	}
}

func TestResidentCredentialAndInvalidOriginPreservesChallenges(t *testing.T) {
	h, _, _ := setupTestHandler(t)
	for _, registration := range []bool{true, false} {
		endpoint := "login"
		body := ""
		if registration {
			endpoint = "register"
			body = `{"token":"123456"}`
		}
		r := httptest.NewRequest("POST", "https://localhost/webauthn/"+endpoint+"/options", strings.NewReader(body))
		r.RemoteAddr = "203.0.113.1:123"
		r.Header.Set("Origin", "https://localhost")
		w := httptest.NewRecorder()
		if registration {
			h.RegisterOptions(w, r)
		} else {
			h.LoginOptions(w, r)
		}
		if w.Code != http.StatusOK {
			t.Fatalf("%s options: %d %s", endpoint, w.Code, w.Body.String())
		}
		var response struct {
			ChallengeID string `json:"challengeId"`
			Options     struct {
				PublicKey struct {
					AuthenticatorSelection struct {
						ResidentKey        string `json:"residentKey"`
						RequireResidentKey bool   `json:"requireResidentKey"`
					} `json:"authenticatorSelection"`
				} `json:"publicKey"`
			} `json:"options"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		if registration && (response.Options.PublicKey.AuthenticatorSelection.ResidentKey != "required" || !response.Options.PublicKey.AuthenticatorSelection.RequireResidentKey) {
			t.Fatalf("resident credential not required: %s", w.Body.String())
		}
		entry := h.challenges[response.ChallengeID]
		if entry == nil {
			t.Fatal("missing challenge")
		}
		r = httptest.NewRequest("POST", "https://localhost/webauthn/"+endpoint+"/verify?challengeId="+response.ChallengeID, nil)
		r.Header.Set("Origin", "https://evil.example")
		w = httptest.NewRecorder()
		if registration {
			h.RegisterVerify(w, r)
		} else {
			h.LoginVerify(w, r)
		}
		if w.Code != http.StatusForbidden || h.challenges[response.ChallengeID] != entry {
			t.Fatalf("invalid origin consumed %s challenge (status %d)", endpoint, w.Code)
		}
	}
}

func TestLocalBypassUsesTrustedXFFPolicy(t *testing.T) {
	h, _, _ := setupTestHandler(t)
	h.trusted, _ = localip.ParseTrustedProxies([]string{"127.0.0.1/32"})
	r := httptest.NewRequest("GET", "https://localhost", nil)
	r.RemoteAddr = "127.0.0.1:123"
	r.Header.Set("CF-Connecting-IP", "192.168.1.1")
	if h.IsLocalBypass(r) {
		t.Fatal("trusted proxy without XFF bypassed")
	}
	r.Header.Set("X-Forwarded-For", "192.168.1.1, 203.0.113.1")
	if h.IsLocalBypass(r) {
		t.Fatal("spoofed XFF prefix bypassed")
	}
	r.Header.Set("X-Forwarded-For", "192.168.1.1")
	if !h.IsLocalBypass(r) {
		t.Fatal("observed local client did not bypass")
	}
}

func TestOriginRejectsNonOriginURLs(t *testing.T) {
	for _, origin := range []string{"https://user@localhost", "https://localhost/", "https://localhost?", "https://localhost?q=x", "https://localhost#x"} {
		if originMatches(origin, "https://localhost") {
			t.Errorf("accepted %q", origin)
		}
	}
}
