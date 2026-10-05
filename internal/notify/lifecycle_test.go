package notify

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rcarmo/bouncer/internal/config"
)

const lifecycleCSV = "1.0.0.0,1.0.0.255,OC,AU,Queensland,Brisbane,-27,153\n"

func lifecycleProvider(t *testing.T) *DBIPProvider {
	t.Helper()
	p := &DBIPProvider{cfg: config.DBIPConfig{Enabled: true}, dbPath: filepath.Join(t.TempDir(), "geo.sqlite")}
	if err := p.buildDB(p.dbPath, strings.NewReader(lifecycleCSV), "test"); err != nil {
		t.Fatal(err)
	}
	if err := p.openExistingDB(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := p.Close(); err != nil {
			t.Error(err)
		}
	})
	return p
}

func TestDBIPCloseRetiresPool(t *testing.T) {
	p := lifecycleProvider(t)
	db := p.getDB()
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := p.Close(); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if err := db.Ping(); err == nil {
		t.Fatal("retired pool still open")
	}
	if _, err := p.Lookup(context.Background(), "1.0.0.1", nil); err == nil {
		t.Fatal("closed provider reopened")
	}
}

func TestDBIPCloseCancelsAndJoinsWorkers(t *testing.T) {
	started := make(chan struct{})
	cancelled := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
		close(cancelled)
	}))
	defer server.Close()
	p := NewDBIPProvider(config.DBIPConfig{Enabled: true, AutoUpdate: true, DatabasePath: "geo.sqlite", UpdateURL: server.URL, DownloadTimeoutSeconds: 60}, t.TempDir()).(*DBIPProvider)
	defer func() { _ = p.Close() }()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("worker did not start")
	}
	done := make(chan struct{})
	go func() { _ = p.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Close did not join cancelled workers")
	}
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("download was not cancelled")
	}
	if p.getDB() != nil {
		t.Fatal("pool survived retirement")
	}
}

func TestDBIPMissingDatabaseAlwaysErrors(t *testing.T) {
	p := &DBIPProvider{cfg: config.DBIPConfig{Enabled: true}, dbPath: filepath.Join(t.TempDir(), "missing.sqlite")}
	defer func() { _ = p.Close() }()
	for range 3 {
		if _, err := p.Lookup(context.Background(), "1.0.0.1", nil); err == nil {
			t.Fatal("missing DB error suppressed")
		}
	}
}

func TestDBIPLookupLeaseDuringReplacement(t *testing.T) {
	p := lifecycleProvider(t)
	old := p.getDB()
	// Occupy the only connection so Lookup must keep its lease while Scan waits.
	conn, err := old.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	lookup := make(chan error, 1)
	go func() {
		info, err := p.Lookup(context.Background(), "1.0.0.1", nil)
		if err == nil && (info == nil || info.Country != "AU") {
			err = errors.New("bad lookup")
		}
		lookup <- err
	}()
	deadline := time.Now().Add(time.Second)
	for p.dbMu.TryLock() {
		p.dbMu.Unlock()
		if time.Now().After(deadline) {
			t.Fatal("lookup did not acquire lease")
		}
		time.Sleep(time.Millisecond)
	}
	var payload bytes.Buffer
	gz := gzip.NewWriter(&payload)
	_, _ = io.WriteString(gz, lifecycleCSV)
	_ = gz.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(payload.Bytes()) }))
	defer server.Close()
	replaced := make(chan error, 1)
	go func() {
		p.updateMu.Lock()
		defer p.updateMu.Unlock()
		replaced <- p.downloadAndBuild(context.Background(), server.URL)
	}()
	select {
	case err := <-replaced:
		t.Fatalf("replacement bypassed lookup lease: %v", err)
	case <-time.After(40 * time.Millisecond):
	}
	_ = conn.Close()
	select {
	case err := <-lookup:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("lookup deadlock")
	}
	select {
	case err := <-replaced:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("replacement deadlock")
	}
	if old == p.getDB() {
		t.Fatal("pool not replaced")
	}
	if err := old.Ping(); err == nil {
		t.Fatal("old pool leaked")
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 20 {
				if _, err := p.Lookup(context.Background(), "1.0.0.1", nil); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	for range 3 {
		p.updateMu.Lock()
		err := p.downloadAndBuild(context.Background(), server.URL)
		p.updateMu.Unlock()
		if err != nil {
			t.Error(err)
		}
	}
	wg.Wait()
}

type lifecycleCloser struct{ calls atomic.Int32 }

func (p *lifecycleCloser) Lookup(context.Context, string, http.Header) (*GeoInfo, error) {
	return nil, nil
}
func (p *lifecycleCloser) Close() error { p.calls.Add(1); return errors.New("close failure") }

func TestFallbackClosePropagatesOnce(t *testing.T) {
	child := &lifecycleCloser{}
	dbip := lifecycleProvider(t)
	pool := dbip.getDB()
	nested := &FallbackGeoProvider{providers: []GeoProvider{CloudflareGeoProvider{}, child, dbip}}
	p := &FallbackGeoProvider{providers: []GeoProvider{nested}}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := p.Close(); err == nil {
				t.Error("close error lost")
			}
		}()
	}
	wg.Wait()
	if child.calls.Load() != 1 {
		t.Fatal("child closed repeatedly")
	}
	if err := pool.Ping(); err == nil {
		t.Fatal("fallback leaked pool")
	}
}
