package notify

import (
	"compress/gzip"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
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

func TestExplicitDBIPUpdateRefreshesRecentDatabase(t *testing.T) {
	var downloads atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := downloads.Add(1)
		gz := gzip.NewWriter(w)
		_, _ = fmt.Fprintf(gz, "1.0.0.0,1.0.0.255,OC,AU,Queensland,City%d,-27,153\n", n)
		_ = gz.Close()
	}))
	defer server.Close()
	cfg := config.DBIPConfig{
		Enabled: true, DatabasePath: "dbip.sqlite", UpdateURL: server.URL,
		AutoUpdate: false, UpdateIntervalHours: 24,
	}
	dir := t.TempDir()
	for want := int32(1); want <= 2; want++ {
		if err := RunDBIPUpdate(context.Background(), cfg, dir); err != nil {
			t.Fatal(err)
		}
		if got := downloads.Load(); got != want {
			t.Fatalf("explicit update made %d downloads, want %d", got, want)
		}
		p := NewDBIPProvider(cfg, dir).(*DBIPProvider)
		info, err := p.Lookup(context.Background(), "1.0.0.8", nil)
		_ = p.Close()
		if err != nil || info == nil || info.City != fmt.Sprintf("City%d", want) {
			t.Fatalf("updated lookup: %+v, %v", info, err)
		}
		if downloads.Load() != want {
			t.Fatal("ordinary lookup bypassed the update schedule")
		}
	}
}

func TestAutomaticDBIPUpdateKeepsRecentDatabase(t *testing.T) {
	var downloads atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		downloads.Add(1)
		http.Error(w, "unexpected refresh", http.StatusInternalServerError)
	}))
	defer server.Close()
	p := &DBIPProvider{
		cfg:    config.DBIPConfig{Enabled: true, AutoUpdate: true, UpdateURL: server.URL, UpdateIntervalHours: 24},
		dbPath: filepath.Join(t.TempDir(), "dbip.sqlite"),
	}
	defer func() {
		if err := p.Close(); err != nil {
			t.Error(err)
		}
	}()
	if err := p.buildDB(p.dbPath, strings.NewReader("1.0.0.0,1.0.0.255,OC,AU,Queensland,Brisbane,-27,153\n"), server.URL); err != nil {
		t.Fatal(err)
	}
	p.updateOnce()
	if got := downloads.Load(); got != 0 {
		t.Fatalf("automatic update downloaded recent database %d times", got)
	}
}
