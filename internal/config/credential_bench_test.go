package config

import "testing"

func BenchmarkCredentialAuthorization(b *testing.B) {
	c := Defaults()
	c.Users = []User{{ID: "user", SiteID: "default", Credentials: []Credential{{ID: "credential", PublicKey: "public-key", Transports: []string{"internal", "hybrid"}}}}}
	b.Run("Snapshot", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			u := c.FindUserByID("default", "user")
			if u == nil || u.Credentials[0].ID != "credential" {
				b.Fatal("missing credential")
			}
		}
	})
	b.Run("Membership", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if !c.HasCredential("default", "user", "credential") {
				b.Fatal("missing credential")
			}
		}
	})
}
func TestHasCredentialScope(t *testing.T) {
	c := Defaults()
	c.Users = []User{{ID: "user", SiteID: "a", Credentials: []Credential{{ID: "credential"}}}}
	for _, v := range []struct {
		site, user, credential string
		want                   bool
	}{{"a", "user", "credential", true}, {"b", "user", "credential", false}, {"a", "other", "credential", false}, {"a", "user", "other", false}, {"a", "user", "", false}} {
		if got := c.HasCredential(v.site, v.user, v.credential); got != v.want {
			t.Fatalf("%+v: %t", v, got)
		}
	}
	c.Users[0].Credentials = nil
	if c.HasCredential("a", "user", "credential") {
		t.Fatal("removed credential accepted")
	}
}
