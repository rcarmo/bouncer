package config

import (
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func regressionConfig(t *testing.T) *Config {
	t.Helper()
	c, err := Load(filepath.Join(t.TempDir(), "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestUserCopyIsolation(t *testing.T) {
	c := regressionConfig(t)
	u := User{ID: "u", SiteID: "default", Credentials: []Credential{{ID: "c", Transports: []string{"usb"}}}}
	if err := c.AddUser(u); err != nil {
		t.Fatal(err)
	}
	if u.Credentials[0].CreatedAt != "" {
		t.Fatal("AddUser mutated input")
	}
	u.Credentials[0].Transports[0] = "changed"
	found := c.FindUserByID("default", "u")
	if found.Credentials[0].Transports[0] != "usb" {
		t.Fatal("input aliases stored user")
	}
	found.Credentials[0].Transports[0] = "changed"
	found, _ = c.FindUserByCredentialID("default", "c")
	if found.Credentials[0].Transports[0] != "usb" {
		t.Fatal("returned user aliases stored user")
	}
	c.Onboarding.Instructions.IOS = []string{"original"}
	snapshot := c.OnboardingSnapshot()
	snapshot.Instructions.IOS[0] = "changed"
	if c.OnboardingSnapshot().Instructions.IOS[0] != "original" {
		t.Fatal("onboarding snapshot aliases config")
	}
}

func TestConcurrentConfigPersistence(t *testing.T) {
	c := regressionConfig(t)
	if err := c.AddUser(User{ID: "u", Credentials: []Credential{{ID: "c"}}}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			if err := c.Save(); err != nil {
				t.Error(err)
			}
		}()
		go func(n uint32) {
			defer wg.Done()
			if err := c.UpdateSignCount("default", "u", "c", n); err != nil && !errors.Is(err, ErrSignCount) {
				t.Error(err)
			}
		}(uint32(i))
	}
	wg.Wait()
	disk, err := Load(c.Path())
	if err != nil {
		t.Fatal(err)
	}
	if disk.FindUserByID("default", "u").Credentials[0].SignCount != c.FindUserByID("default", "u").Credentials[0].SignCount {
		t.Fatal("disk has stale snapshot")
	}
}

func TestEnrollmentTokenLifetimeAndGuessCap(t *testing.T) {
	c := regressionConfig(t)
	if err := c.SetEnrollmentToken("123456"); err != nil {
		t.Fatal(err)
	}
	deadline := c.OnboardingSnapshot().TokenExpiresAt
	if deadline.IsZero() || time.Until(deadline) > EnrollmentTokenTTL {
		t.Fatal("missing bounded lifetime")
	}
	disk, err := Load(c.Path())
	if err != nil {
		t.Fatal(err)
	}
	if err := disk.InitializeEnrollmentToken(); err != nil {
		t.Fatal(err)
	}
	if !disk.OnboardingSnapshot().TokenExpiresAt.Equal(deadline) {
		t.Fatal("restart extended token")
	}
	for i := 0; i < EnrollmentTokenMaxAttempts; i++ {
		valid, _, err := c.CheckEnrollmentToken("wrong", true)
		if valid || err != nil {
			t.Fatalf("guess %d: valid=%v err=%v", i, valid, err)
		}
	}
	disk, err = Load(c.Path())
	if err != nil {
		t.Fatal(err)
	}
	if valid, current, err := disk.CheckEnrollmentToken("123456", true); valid || current != "" || err != nil {
		t.Fatal("guess cap did not survive restart")
	}
	if err := c.SetEnrollmentToken("fresh"); err != nil {
		t.Fatal(err)
	}
	c.Onboarding.TokenExpiresAt = time.Now().Add(-time.Second)
	if valid, current, _ := c.CheckEnrollmentToken("fresh", true); valid || current != "" {
		t.Fatal("expired token accepted")
	}
	if err := c.SetEnrollmentToken("fresh"); err != nil {
		t.Fatal(err)
	}
	if valid, _, err := c.CheckEnrollmentToken("fresh", false); !valid || err != nil {
		t.Fatal("status check failed")
	}
	if valid, _, err := c.CheckEnrollmentToken("fresh", true); !valid || err != nil {
		t.Fatal("consume failed")
	}
	if valid, _, _ := c.CheckEnrollmentToken("fresh", true); valid {
		t.Fatal("token reused")
	}
}

func TestConfigPersistenceFailureRollsBack(t *testing.T) {
	c := regressionConfig(t)
	if err := c.SetEnrollmentToken("token"); err != nil {
		t.Fatal(err)
	}
	c.path = t.TempDir() // atomic rename onto directory must fail
	if valid, _, err := c.CheckEnrollmentToken("token", true); valid || err == nil {
		t.Fatal("authorized despite persistence failure")
	}
	if c.OnboardingSnapshot().Token != "token" {
		t.Fatal("failed consume changed memory")
	}
	if err := c.AddUser(User{ID: "u"}); err == nil {
		t.Fatal("expected save failure")
	}
	if c.FindUserByID("default", "u") != nil {
		t.Fatal("failed AddUser changed memory")
	}
}

func TestEnrollmentTokenConcurrentConsumption(t *testing.T) {
	c := regressionConfig(t)
	if err := c.SetEnrollmentToken("token"); err != nil {
		t.Fatal(err)
	}
	results := make(chan bool, 20)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			valid, _, err := c.CheckEnrollmentToken("token", true)
			if err != nil {
				t.Error(err)
			}
			results <- valid
		}()
	}
	wg.Wait()
	close(results)
	successes := 0
	for valid := range results {
		if valid {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("token consumed %d times", successes)
	}
	disk, err := Load(c.Path())
	if err != nil {
		t.Fatal(err)
	}
	if valid, _, _ := disk.CheckEnrollmentToken("token", true); valid {
		t.Fatal("consumed token survived reload")
	}
}

func TestRejectUnsafeSessionSettings(t *testing.T) {
	for _, mutate := range []func(*Config){func(c *Config) { c.Session.File = c.Path() }, func(c *Config) { c.Session.File = "" }, func(c *Config) { c.Session.CookieName = "bad cookie" }, func(c *Config) { c.Session.TTLDays = 0 }} {
		c, err := Load(filepath.Join(t.TempDir(), "bouncer.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		mutate(c)
		if err := c.Validate(); err == nil {
			t.Fatal("unsafe config accepted")
		}
	}
}

func TestSignCounterNeverRegresses(t *testing.T) {
	c := regressionConfig(t)
	if err := c.AddUser(User{ID: "u", Credentials: []Credential{{ID: "c"}}}); err != nil {
		t.Fatal(err)
	}
	for _, counter := range []uint32{0, 0, 12} {
		if err := c.UpdateSignCount("default", "u", "c", counter); err != nil {
			t.Fatal(err)
		}
	}
	for _, counter := range []uint32{11, 12, 0} {
		if err := c.UpdateSignCount("default", "u", "c", counter); !errors.Is(err, ErrSignCount) {
			t.Fatalf("counter %d accepted: %v", counter, err)
		}
	}
	disk, err := Load(c.Path())
	if err != nil {
		t.Fatal(err)
	}
	if disk.FindUserByID("default", "u").Credentials[0].SignCount != 12 {
		t.Fatal("persisted counter regressed")
	}
}

func TestEnrollmentLockoutCannotAutoReset(t *testing.T) {
	for _, oneTime := range []bool{true, false} {
		t.Run(fmt.Sprint(oneTime), func(t *testing.T) {
			c := regressionConfig(t)
			c.Onboarding.OneTimeToken = oneTime
			if err := c.SetEnrollmentToken("123456789012"); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < EnrollmentTokenMaxAttempts; i++ {
				if ok, _, err := c.CheckEnrollmentToken("wrong", true); ok || err != nil {
					t.Fatal(ok, err)
				}
			}
			disk, err := Load(c.Path())
			if err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 20; i++ {
				if code, err := disk.EnsureEnrollmentToken("999999999999"); code != "" || err != nil {
					t.Fatal("automatic lockout reset", code, err)
				}
			}
			if ok, _, _ := disk.CheckEnrollmentToken("123456789012", true); ok {
				t.Fatal("locked code accepted")
			}
			if err := disk.SetEnrollmentToken("999999999999"); err != nil {
				t.Fatal(err)
			}
			if ok, _, err := disk.CheckEnrollmentToken("999999999999", true); !ok || err != nil {
				t.Fatal("operator reset failed", err)
			}
		})
	}
}
func TestEnrollmentBudgetAcrossExpiredGenerations(t *testing.T) {
	c := regressionConfig(t)
	if err := c.SetEnrollmentToken("123456789012"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		if ok, _, err := c.CheckEnrollmentToken("wrong", true); ok || err != nil {
			t.Fatal(ok, err)
		}
		c.Onboarding.TokenExpiresAt = time.Now().Add(-time.Minute)
		code, err := c.EnsureEnrollmentToken("123456789012")
		if err != nil {
			t.Fatal(err)
		}
		if i < 99 && code == "" {
			t.Fatalf("premature lock at %d", i)
		}
	}
	if code, _ := c.EnsureEnrollmentToken("999999999999"); code != "" {
		t.Fatal("global budget reset")
	}
	disk, err := Load(c.Path())
	if err != nil {
		t.Fatal(err)
	}
	if !disk.Onboarding.TokenLocked || disk.Onboarding.TokenFailures != 100 {
		t.Fatal("global lock not persisted")
	}
}
func TestReusableEnrollmentCodeExpires(t *testing.T) {
	c := regressionConfig(t)
	c.Onboarding.OneTimeToken = false
	if err := c.SetEnrollmentToken("123456789012"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if ok, _, _ := c.CheckEnrollmentToken("123456789012", true); !ok {
			t.Fatal("reuse rejected")
		}
	}
	c.Onboarding.TokenExpiresAt = time.Now().Add(-time.Second)
	if ok, _, _ := c.CheckEnrollmentToken("123456789012", true); ok {
		t.Fatal("expired reusable code accepted")
	}
}
