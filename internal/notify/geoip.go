package notify

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
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

// LookupGeoIP performs a basic geolocation lookup for an IP.
func LookupGeoIP(ctx context.Context, cfg config.GeoIPConfig, ip string) (*GeoInfo, error) {
	if !cfg.Enabled || cfg.URL == "" || ip == "" {
		return nil, nil
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
	return info, nil
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
