package notify

import (
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"github.com/rcarmo/bouncer/internal/config"
)

type DBIPProvider struct {
	cfg           config.DBIPConfig
	dbPath        string
	dbMu          sync.RWMutex
	db            *sql.DB
	lastUpdate    time.Time
	lastSourceURL string
	lastChecked   time.Time
	updateMu      sync.Mutex
	initOnce      sync.Once
	ctx           context.Context
	cancel        context.CancelFunc
	workers       sync.WaitGroup
	closeOnce     sync.Once
	closeErr      error
	closed        bool // protected by dbMu
}

func NewDBIPProvider(cfg config.DBIPConfig, baseDir string) GeoProvider {
	if !cfg.Enabled {
		return nil
	}
	dbPath := resolveDBPath(cfg.DatabasePath, baseDir)
	if dbPath == "" {
		return nil
	}
	provider := &DBIPProvider{
		cfg:    cfg,
		dbPath: dbPath,
	}

	if err := provider.openExistingDB(); err != nil && !errors.Is(err, os.ErrNotExist) {
		slog.Warn("dbip open failed", "error", err)
	}

	provider.initLifecycle()
	if cfg.AutoUpdate {
		provider.workers.Add(2)
		go func() { defer provider.workers.Done(); provider.updateOnce() }()
		go func() { defer provider.workers.Done(); provider.autoUpdateLoop() }()
	}

	return provider
}

func (p *DBIPProvider) Lookup(ctx context.Context, ip string, _ http.Header) (*GeoInfo, error) {
	if ip == "" {
		return nil, nil
	}
	ipValue, ok := ipv4ToUint32(ip)
	if !ok {
		return nil, nil
	}

	if err := p.ensureDB(ctx, false); err != nil {
		return nil, err
	}
	p.dbMu.RLock()
	defer p.dbMu.RUnlock()
	if p.closed {
		return nil, fmt.Errorf("dbip: provider closed")
	}
	db := p.db
	if db == nil {
		return nil, fmt.Errorf("dbip: database missing")
	}

	row := db.QueryRowContext(ctx, `
		SELECT country_code, region, city, latitude, longitude
		FROM geoip
		WHERE ip_from <= ? AND ip_to >= ?
		ORDER BY ip_from DESC
		LIMIT 1`, ipValue, ipValue)

	var country, region, city sql.NullString
	var lat, lon sql.NullFloat64
	if err := row.Scan(&country, &region, &city, &lat, &lon); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	info := &GeoInfo{IP: ip}
	if country.Valid {
		info.Country = country.String
	}
	if region.Valid {
		info.Region = region.String
	}
	if city.Valid {
		info.City = city.String
	}
	if lat.Valid {
		info.Latitude = lat.Float64
	}
	if lon.Valid {
		info.Longitude = lon.Float64
	}
	if info.Country == "" && info.Region == "" && info.City == "" && info.Latitude == 0 && info.Longitude == 0 {
		return nil, nil
	}
	return info, nil
}

func (p *DBIPProvider) ensureDB(ctx context.Context, force bool) error {
	if !p.cfg.Enabled {
		return nil
	}
	p.initLifecycle()
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(p.ctx, cancel)
	defer func() { stop(); cancel() }()
	p.updateMu.Lock()
	defer p.updateMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if p.ctx.Err() != nil {
		return fmt.Errorf("dbip: provider closed")
	}

	if p.getDB() == nil {
		if err := p.openExistingDB(); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}

	if p.getDB() == nil && !p.cfg.AutoUpdate && !force {
		return fmt.Errorf("dbip: database missing and autoUpdate disabled")
	}
	if !force && p.getDB() != nil && !p.shouldCheck() {
		return nil
	}

	if p.getDB() != nil && !p.updateDue() {
		return nil
	}

	if !p.cfg.AutoUpdate && p.getDB() != nil && !force {
		return nil
	}

	updateURL, err := p.resolveUpdateURL(ctx)
	if err != nil {
		return err
	}
	if updateURL == "" {
		return fmt.Errorf("dbip: update URL not resolved")
	}
	if p.getDB() != nil && p.lastSourceURL == updateURL && !p.updateDue() {
		return nil
	}

	if err := p.downloadAndBuild(ctx, updateURL); err != nil {
		return err
	}
	return p.openExistingDB()
}

func (p *DBIPProvider) updateOnce() {
	ctx, cancel := context.WithTimeout(p.lifecycleContext(), p.downloadTimeout())
	defer cancel()
	if err := p.ensureDB(ctx, true); err != nil {
		slog.Warn("dbip update failed", "error", err)
	}
}

func (p *DBIPProvider) autoUpdateLoop() {
	interval := p.updateInterval()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-p.lifecycleContext().Done():
			return
		case <-ticker.C:
		}
		ctx, cancel := context.WithTimeout(p.lifecycleContext(), p.downloadTimeout())
		if err := p.ensureDB(ctx, false); err != nil {
			slog.Warn("dbip auto update failed", "error", err)
		}
		cancel()
	}
}

func (p *DBIPProvider) updateInterval() time.Duration {
	interval := time.Duration(p.cfg.UpdateIntervalHours) * time.Hour
	if interval <= 0 {
		return 24 * time.Hour
	}
	return interval
}

func (p *DBIPProvider) downloadTimeout() time.Duration {
	if p.cfg.DownloadTimeoutSeconds <= 0 {
		return 30 * time.Second
	}
	return time.Duration(p.cfg.DownloadTimeoutSeconds) * time.Second
}

func (p *DBIPProvider) shouldCheck() bool {
	interval := p.updateInterval()
	if time.Since(p.lastChecked) < interval {
		return false
	}
	p.lastChecked = time.Now()
	return true
}

func (p *DBIPProvider) updateDue() bool {
	if p.lastUpdate.IsZero() {
		return true
	}
	return time.Since(p.lastUpdate) >= p.updateInterval()
}

func (p *DBIPProvider) getDB() *sql.DB {
	p.dbMu.RLock()
	defer p.dbMu.RUnlock()
	return p.db
}

func (p *DBIPProvider) openExistingDB() error {
	p.dbMu.Lock()
	defer p.dbMu.Unlock()
	return p.openExistingDBLocked()
}

func (p *DBIPProvider) openExistingDBLocked() error {
	if p.closed {
		return fmt.Errorf("dbip: provider closed")
	}
	if p.db != nil {
		return nil
	}
	if _, err := os.Stat(p.dbPath); err != nil {
		return err
	}
	db, err := sql.Open("sqlite", p.dbPath)
	if err != nil {
		return err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	url, updatedAt := readDBIPMeta(db)
	p.db = db
	p.lastSourceURL = url
	p.lastUpdate = updatedAt
	return nil
}

func (p *DBIPProvider) resolveUpdateURL(ctx context.Context) (string, error) {
	if p.cfg.UpdateURL != "" {
		return p.cfg.UpdateURL, nil
	}
	pageURL := strings.TrimSpace(p.cfg.UpdatePageURL)
	if pageURL == "" {
		pageURL = "https://db-ip.com/db/download/ip-to-city-lite"
	}
	client := &http.Client{Timeout: p.downloadTimeout()}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("dbip: update page status %d", resp.StatusCode)
	}
	body, err := readBounded(resp.Body, maxUpdatePageBytes)
	if err != nil {
		return "", err
	}

	re := regexp.MustCompile(`https://download\.db-ip\.com/free/dbip-city-lite-\d{4}-\d{2}\.csv\.gz`)
	matches := re.FindAllString(string(body), -1)
	if len(matches) == 0 {
		return "", fmt.Errorf("dbip: update URL not found")
	}
	sort.Strings(matches)
	return matches[len(matches)-1], nil
}

func (p *DBIPProvider) downloadAndBuild(ctx context.Context, url string) error {
	slog.Info("dbip update started", "url", url)
	client := &http.Client{Timeout: p.downloadTimeout()}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("dbip: download status %d", resp.StatusCode)
	}

	gz, err := gzip.NewReader(&byteBudget{reader: resp.Body, remaining: maxDBIPCompressedBytes})
	if err != nil {
		return err
	}
	defer func() { _ = gz.Close() }()

	if err := os.MkdirAll(filepath.Dir(p.dbPath), 0700); err != nil {
		return err
	}

	tmpPath := fmt.Sprintf("%s.%d.tmp", p.dbPath, time.Now().UnixNano())
	if err := p.buildDBContext(ctx, tmpPath, gz, url); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}

	p.dbMu.Lock()
	defer p.dbMu.Unlock()
	if err := ctx.Err(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if p.closed {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("dbip: provider closed")
	}
	if p.db != nil {
		_ = p.db.Close()
		p.db = nil
	}

	if err := os.Rename(tmpPath, p.dbPath); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	p.lastSourceURL = url
	p.lastUpdate = time.Now().UTC()
	return p.openExistingDBLocked()
}

func (p *DBIPProvider) buildDB(path string, reader io.Reader, sourceURL string) error {
	return p.buildDBContext(context.Background(), path, reader, sourceURL)
}

func (p *DBIPProvider) buildDBContext(ctx context.Context, path string, reader io.Reader, sourceURL string) error {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	if _, err := db.ExecContext(ctx, "PRAGMA journal_mode=OFF"); err != nil {
		return err
	}
	if _, err := db.ExecContext(ctx, "PRAGMA synchronous=OFF"); err != nil {
		return err
	}
	if _, err := db.ExecContext(ctx, "PRAGMA temp_store=MEMORY"); err != nil {
		return err
	}

	if _, err := db.ExecContext(ctx, `
		CREATE TABLE geoip (
			ip_from INTEGER NOT NULL,
			ip_to INTEGER NOT NULL,
			country_code TEXT,
			region TEXT,
			city TEXT,
			latitude REAL,
			longitude REAL
		);
	`); err != nil {
		return err
	}
	if _, err := db.ExecContext(ctx, `CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);`); err != nil {
		return err
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO geoip (ip_from, ip_to, country_code, region, city, latitude, longitude) VALUES (?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	defer func() { _ = stmt.Close() }()

	csvReader := csv.NewReader(newCSVBudget(&byteBudget{reader: reader, remaining: maxDBIPExpandedBytes}, maxDBIPRecordBytes, maxDBIPRows))
	csvReader.ReuseRecord = true
	csvReader.FieldsPerRecord = -1

	var count int
	for {
		if err := ctx.Err(); err != nil {
			_ = tx.Rollback()
			return err
		}
		record, err := csvReader.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			_ = tx.Rollback()
			return err
		}
		if len(record) < 8 {
			continue
		}
		ipFrom, ok := ipv4ToUint32(record[0])
		if !ok {
			continue
		}
		ipTo, ok := ipv4ToUint32(record[1])
		if !ok {
			continue
		}
		countryCode := strings.TrimSpace(record[3])
		region := strings.TrimSpace(record[4])
		city := strings.Trim(strings.TrimSpace(record[5]), "\"")
		lat := parseFloat(record[6])
		lon := parseFloat(record[7])

		if _, err := stmt.ExecContext(ctx, int64(ipFrom), int64(ipTo), countryCode, region, city, lat, lon); err != nil {
			_ = tx.Rollback()
			return err
		}
		count++
	}
	if err := tx.Commit(); err != nil {
		return err
	}

	if _, err := db.ExecContext(ctx, `CREATE INDEX idx_geoip_from ON geoip (ip_from);`); err != nil {
		return err
	}
	if _, err := db.ExecContext(ctx, `CREATE INDEX idx_geoip_to ON geoip (ip_to);`); err != nil {
		return err
	}

	updatedAt := time.Now().UTC().Format(time.RFC3339)
	if _, err := db.ExecContext(ctx, `INSERT INTO meta (key, value) VALUES (?, ?), (?, ?), (?, ?)`, "source_url", sourceURL, "updated_at", updatedAt, "record_count", strconv.Itoa(count)); err != nil {
		return err
	}

	slog.Info("dbip update complete", "records", count)
	return nil
}

func readDBIPMeta(db *sql.DB) (string, time.Time) {
	rows, err := db.Query(`SELECT key, value FROM meta`)
	if err != nil {
		return "", time.Time{}
	}
	defer func() { _ = rows.Close() }()

	var url string
	var updatedAt time.Time
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			continue
		}
		switch key {
		case "source_url":
			url = value
		case "updated_at":
			if parsed, err := time.Parse(time.RFC3339, value); err == nil {
				updatedAt = parsed
			}
		}
	}
	return url, updatedAt
}

func ipv4ToUint32(value string) (uint32, bool) {
	ip := net.ParseIP(strings.TrimSpace(value))
	if ip == nil {
		return 0, false
	}
	ip = ip.To4()
	if ip == nil {
		return 0, false
	}
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3]), true
}

func parseFloat(value string) float64 {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return 0
	}
	return parsed
}

func RunDBIPUpdate(ctx context.Context, cfg config.DBIPConfig, baseDir string) error {
	if !cfg.Enabled {
		return fmt.Errorf("dbip: disabled")
	}
	path := resolveDBPath(cfg.DatabasePath, baseDir)
	if path == "" {
		return fmt.Errorf("dbip: databasePath missing")
	}
	provider := &DBIPProvider{
		cfg:    cfg,
		dbPath: path,
	}
	defer func() { _ = provider.Close() }()
	return provider.ensureDB(ctx, true)
}

func resolveDBPath(path string, baseDir string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	if filepath.IsAbs(path) {
		return path
	}
	if baseDir == "" {
		return path
	}
	return filepath.Join(baseDir, path)
}

// initLifecycle also supports providers constructed directly by callers/tests.
func (p *DBIPProvider) initLifecycle() {
	// #nosec G118 -- lifecycle cancellation is retained on the provider and invoked by Close.
	p.initOnce.Do(func() { p.ctx, p.cancel = context.WithCancel(context.Background()) })
}

func (p *DBIPProvider) lifecycleContext() context.Context {
	p.initLifecycle()
	return p.ctx
}

// Close cancels downloads, joins workers, then retires the pool. Never wait
// for workers while holding updateMu or dbMu: workers need both to exit.
func (p *DBIPProvider) Close() error {
	p.initLifecycle()
	p.closeOnce.Do(func() {
		p.cancel()
		p.workers.Wait()
		p.updateMu.Lock()
		defer p.updateMu.Unlock()
		p.dbMu.Lock()
		defer p.dbMu.Unlock()
		p.closed = true
		if p.db != nil {
			p.closeErr = p.db.Close()
			p.db = nil
		}
	})
	return p.closeErr
}
