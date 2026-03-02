package notify

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/rcarmo/bouncer/internal/config"
)

const pushoverEndpoint = "https://api.pushover.net/1/messages.json"

// SendPushover posts a message to the Pushover API. It is a no-op if disabled.
func SendPushover(ctx context.Context, cfg config.PushoverConfig, title, message, link string) error {
	if !cfg.Enabled || cfg.APIToken == "" || cfg.UserKey == "" {
		return nil
	}

	values := url.Values{}
	values.Set("token", cfg.APIToken)
	values.Set("user", cfg.UserKey)
	if title != "" {
		values.Set("title", title)
	}
	values.Set("message", message)
	if cfg.Device != "" {
		values.Set("device", cfg.Device)
	}
	if cfg.Sound != "" {
		values.Set("sound", cfg.Sound)
	}
	if link != "" {
		values.Set("url", link)
		values.Set("url_title", "Open Bouncer")
	}

	timeout := cfg.TimeoutSeconds
	if timeout <= 0 {
		timeout = 3
	}
	client := &http.Client{Timeout: time.Duration(timeout) * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, pushoverEndpoint, strings.NewReader(values.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("pushover: status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}
