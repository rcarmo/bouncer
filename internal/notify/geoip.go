package notify

import (
	"context"
	"encoding/json"
	"fmt"
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
}

type geoCacheEntry struct {
	info    *GeoInfo
	expires time.Time
}

var geoCache = struct {
	mu      sync.Mutex
	entries map[string]geoCacheEntry
}{entries: make(map[string]geoCacheEntry)}

// LookupGeoIP performs a basic geolocation lookup for an IP.
func LookupGeoIP(ctx context.Context, cfg config.GeoIPConfig, ip string) (*GeoInfo, error) {
	if !cfg.Enabled || cfg.URL == "" || ip == "" {
		return nil, nil
	}

	ttl := time.Duration(cfg.CacheTTLSeconds) * time.Second
	if ttl > 0 {
		geoCache.mu.Lock()
		if entry, ok := geoCache.entries[ip]; ok {
			if time.Now().Before(entry.expires) {
				geoCache.mu.Unlock()
				return entry.info, nil
			}
			delete(geoCache.entries, ip)
		}
		geoCache.mu.Unlock()
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
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("geoip: status %d", resp.StatusCode)
	}

	var payload map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
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
		geoCache.mu.Lock()
		geoCache.entries[ip] = geoCacheEntry{info: info, expires: time.Now().Add(ttl)}
		geoCache.mu.Unlock()
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

func (p FallbackGeoProvider) Lookup(ctx context.Context, ip string, headers http.Header) (*GeoInfo, error) {
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
	return FallbackGeoProvider{providers: providers}
}

func stringField(payload map[string]any, keys ...string) string {
	for _, key := range keys {
		if v, ok := payload[key].(string); ok {
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
