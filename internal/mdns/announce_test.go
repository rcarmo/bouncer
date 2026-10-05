package mdns

import (
	"reflect"
	"strings"
	"testing"

	"github.com/rcarmo/bouncer/internal/config"
)

func TestServiceTXTExcludesBackend(t *testing.T) {
	site := &config.SiteConfig{
		ID:           "public-site",
		PublicOrigin: "https://public.local",
		Backend:      "http://private-user:private-password@internal-backend:8080/private-path",
	}
	got := serviceTXT(site)
	want := []string{"id=public-site", "origin=https://public.local"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("TXT records = %q, want only public metadata %q", got, want)
	}
	for _, record := range got {
		for _, secret := range []string{"backend=", site.Backend, "private-user", "private-password", "internal-backend", "private-path"} {
			if strings.Contains(record, secret) {
				t.Errorf("TXT record leaks backend information: %q", record)
			}
		}
	}
}
