package notify

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rcarmo/bouncer/internal/config"
)

func TestDBIPBuildAndLookup(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "dbip.sqlite")
	provider := &DBIPProvider{
		cfg: config.DBIPConfig{
			Enabled:    true,
			AutoUpdate: false,
		},
		dbPath: dbPath,
	}

	csvData := strings.Join([]string{
		"1.0.0.0,1.0.0.255,OC,AU,Queensland,\"South Brisbane\",-27.4767,153.017",
		"2.0.0.0,2.0.0.255,EU,FR,Ile-de-France,Paris,48.8566,2.3522",
	}, "\n")

	if err := provider.buildDB(dbPath, strings.NewReader(csvData), "test"); err != nil {
		t.Fatalf("buildDB: %v", err)
	}
	if err := provider.openExistingDB(); err != nil {
		t.Fatalf("openExistingDB: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	info, err := provider.Lookup(ctx, "1.0.0.8", nil)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if info == nil || info.Country != "AU" || info.Region != "Queensland" || info.City != "South Brisbane" {
		t.Fatalf("unexpected info: %+v", info)
	}

	info2, err := provider.Lookup(ctx, "5.0.0.1", nil)
	if err != nil {
		t.Fatalf("Lookup miss: %v", err)
	}
	if info2 != nil {
		t.Fatalf("expected nil info, got %+v", info2)
	}

	info3, err := provider.Lookup(ctx, "2001:db8::1", nil)
	if err != nil {
		t.Fatalf("Lookup ipv6: %v", err)
	}
	if info3 != nil {
		t.Fatalf("expected nil info for ipv6, got %+v", info3)
	}

	provider.dbMu.Lock()
	if provider.db != nil {
		_ = provider.db.Close()
		provider.db = nil
	}
	provider.dbMu.Unlock()
}
