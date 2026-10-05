package notify

import (
	"container/list"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rcarmo/bouncer/internal/config"
)

// GeoInfo captures basic IP geolocation fields.
type GeoInfo struct {
	IP        string
	City      string
	Region    string
	Country   string
	Latitude  float64
	Longitude float64
	Org       string
	ISP       string
}

type GeoProvider interface {
	Lookup(ctx context.Context, ip string, headers http.Header) (*GeoInfo, error)
}

type CloudflareGeoProvider struct{}

type ExternalGeoProvider struct {
	cfg config.GeoIPConfig
}

type FallbackGeoProvider struct {
	providers []GeoProvider
	closeOnce sync.Once
	closeErr  error
}

// External lookups retain at most 4096 entries, including across providers.
const geoCacheCapacity = 4096

// Cap retained field bytes as well as entry count (under 8 MiB of text at capacity).
const maxGeoFieldBytes = 256

type geoCacheEntry struct {
	key     string
	info    *GeoInfo
	expires time.Time
}
type externalGeoCache struct {
	mu      sync.Mutex
	entries map[string]*list.Element
	order   list.List // insertion order (FIFO)
}

var geoCache = externalGeoCache{entries: make(map[string]*list.Element)}

func (c *externalGeoCache) evictExpired(now time.Time) {
	for e := c.order.Front(); e != nil; {
		next := e.Next()
		entry := e.Value.(geoCacheEntry)
		if !now.Before(entry.expires) {
			delete(c.entries, entry.key)
			c.order.Remove(e)
		}
		e = next
	}
}
func (c *externalGeoCache) get(key string, now time.Time) *GeoInfo {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.evictExpired(now)
	if e := c.entries[key]; e != nil {
		return e.Value.(geoCacheEntry).info
	}
	return nil
}
func (c *externalGeoCache) put(key string, info *GeoInfo, expires, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.evictExpired(now)
	if e := c.entries[key]; e != nil {
		c.order.Remove(e)
		delete(c.entries, key)
	}
	if len(c.entries) >= geoCacheCapacity {
		e := c.order.Front()
		delete(c.entries, e.Value.(geoCacheEntry).key)
		c.order.Remove(e)
	}
	c.entries[key] = c.order.PushBack(geoCacheEntry{key: key, info: info, expires: expires})
}

// LookupGeoIP performs a basic geolocation lookup for an IP.
func LookupGeoIP(ctx context.Context, cfg config.GeoIPConfig, ip string) (*GeoInfo, error) {
	if !cfg.Enabled || cfg.URL == "" || ip == "" {
		return nil, nil
	}

	ttl := time.Duration(cfg.CacheTTLSeconds) * time.Second
	key := cfg.URL + "\x00" + ip
	if ttl > 0 {
		if info := geoCache.get(key, time.Now()); info != nil {
			return info, nil
		}
	}

	url := fmt.Sprintf(cfg.URL, ip)
	timeout := cfg.TimeoutSeconds
	if timeout <= 0 {
		timeout = 2
	}
	client := &http.Client{Timeout: time.Duration(timeout) * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("geoip: status %d", resp.StatusCode)
	}

	body, err := readBounded(resp.Body, maxExternalJSONBytes)
	if err != nil {
		return nil, err
	}
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}

	// Handle ip-api.com style.
	if status, ok := payload["status"].(string); ok && strings.EqualFold(status, "fail") {
		return nil, fmt.Errorf("geoip: lookup failed")
	}

	info := &GeoInfo{}
	info.IP = stringField(payload, "ip", "query")
	info.City = stringField(payload, "city")
	info.Region = stringField(payload, "region", "regionName")
	info.Country = stringField(payload, "country_name", "country")
	info.Latitude = floatField(payload, "latitude", "lat")
	info.Longitude = floatField(payload, "longitude", "lon")
	info.Org = stringField(payload, "org")
	info.ISP = stringField(payload, "isp")
	if info.IP == "" {
		info.IP = ip
	}
	if ttl > 0 {
		now := time.Now()
		geoCache.put(key, info, now.Add(ttl), now)
	}
	return info, nil
}

// CloudflareGeoFromHeaders extracts geolocation info from Cloudflare headers.
// Returns nil if no meaningful data is present.
func CloudflareGeoFromHeaders(headers http.Header) *GeoInfo {
	if headers == nil {
		return nil
	}
	info := &GeoInfo{}
	info.IP = strings.TrimSpace(headers.Get("CF-Connecting-IP"))
	info.Country = strings.TrimSpace(headers.Get("CF-IPCountry"))
	info.Region = strings.TrimSpace(headers.Get("CF-Region"))
	info.City = strings.TrimSpace(headers.Get("CF-IPCity"))

	lat := strings.TrimSpace(headers.Get("CF-Latitude"))
	lon := strings.TrimSpace(headers.Get("CF-Longitude"))
	if lat != "" {
		if parsed, err := strconv.ParseFloat(lat, 64); err == nil {
			info.Latitude = parsed
		}
	}
	if lon != "" {
		if parsed, err := strconv.ParseFloat(lon, 64); err == nil {
			info.Longitude = parsed
		}
	}

	hasLocation := info.Country != "" || info.Region != "" || info.City != "" || info.Latitude != 0 || info.Longitude != 0
	if !hasLocation {
		return nil
	}
	return info
}

func (CloudflareGeoProvider) Lookup(_ context.Context, ip string, headers http.Header) (*GeoInfo, error) {
	info := CloudflareGeoFromHeaders(headers)
	if info == nil {
		return nil, nil
	}
	if info.IP == "" {
		info.IP = ip
	}
	return info, nil
}

func (p ExternalGeoProvider) Lookup(ctx context.Context, ip string, _ http.Header) (*GeoInfo, error) {
	return LookupGeoIP(ctx, p.cfg, ip)
}

func (p *FallbackGeoProvider) Lookup(ctx context.Context, ip string, headers http.Header) (*GeoInfo, error) {
	var lastErr error
	for _, provider := range p.providers {
		if provider == nil {
			continue
		}
		info, err := provider.Lookup(ctx, ip, headers)
		if err != nil {
			lastErr = err
			continue
		}
		if info != nil {
			return info, nil
		}
	}
	return nil, lastErr
}

func NewGeoProvider(cfg config.GeoIPConfig, baseDir string) GeoProvider {
	if !cfg.Enabled {
		return nil
	}
	providers := []GeoProvider{}
	if cfg.PreferCloudflareHeaders {
		providers = append(providers, CloudflareGeoProvider{})
	}
	if cfg.DBIP.Enabled {
		providers = append(providers, NewDBIPProvider(cfg.DBIP, baseDir))
	}
	if cfg.URL != "" {
		providers = append(providers, ExternalGeoProvider{cfg: cfg})
	}
	if len(providers) == 0 {
		return nil
	}
	if len(providers) == 1 {
		return providers[0]
	}
	return &FallbackGeoProvider{providers: providers}
}

func stringField(payload map[string]any, keys ...string) string {
	for _, key := range keys {
		if v, ok := payload[key].(string); ok {
			if len(v) > maxGeoFieldBytes {
				return v[:maxGeoFieldBytes]
			}
			return v
		}
	}
	return ""
}

func floatField(payload map[string]any, keys ...string) float64 {
	for _, key := range keys {
		if v, ok := payload[key].(float64); ok {
			return v
		}
	}
	return 0
}

// Close propagates lifecycle cleanup only to providers that own resources.
func (p *FallbackGeoProvider) Close() error {
	p.closeOnce.Do(func() {
		for _, provider := range p.providers {
			if closer, ok := provider.(io.Closer); ok {
				p.closeErr = errors.Join(p.closeErr, closer.Close())
			}
		}
	})
	return p.closeErr
}
