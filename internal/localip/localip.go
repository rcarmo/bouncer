// Package localip detects whether an IP address is in RFC1918 or loopback ranges.
package localip

import (
	"net"
	"net/http"
	"strings"
)

var privateRanges []*net.IPNet

func init() {
	cidrs := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"::1/128",
		"fc00::/7",
	}
	for _, cidr := range cidrs {
		_, ipnet, _ := net.ParseCIDR(cidr)
		if ipnet != nil {
			privateRanges = append(privateRanges, ipnet)
		}
	}
}

// IsLocal returns true if the IP is RFC1918, loopback, or ULA.
func IsLocal(ip net.IP) bool {
	for _, r := range privateRanges {
		if r.Contains(ip) {
			return true
		}
	}
	return false
}

// ParseTrustedProxies parses a list of CIDR strings into IPNets.
func ParseTrustedProxies(cidrs []string) ([]*net.IPNet, error) {
	var nets []*net.IPNet
	for _, cidr := range cidrs {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, err
		}
		nets = append(nets, ipnet)
	}
	return nets, nil
}

// IsTrustedProxy checks if ip is within any of the trusted proxy CIDRs.
func IsTrustedProxy(ip net.IP, trusted []*net.IPNet) bool {
	for _, n := range trusted {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// ExtractIP parses an IP from a host:port or bare IP string.
func ExtractIP(remoteAddr string) net.IP {
	// Try host:port first.
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	return net.ParseIP(strings.TrimSpace(host))
}

// ClientIP returns the real client IP, considering trusted proxies.
// If remoteAddr is a trusted proxy, use X-Forwarded-For; otherwise use remoteAddr.
func ClientIP(remoteAddr, xForwardedFor string, trusted []*net.IPNet) net.IP {
	remote := ExtractIP(remoteAddr)
	if remote == nil {
		return nil
	}
	if len(trusted) == 0 || !IsTrustedProxy(remote, trusted) {
		return remote
	}
	// Use the last non-trusted IP from X-Forwarded-For.
	parts := strings.Split(xForwardedFor, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		ip := net.ParseIP(strings.TrimSpace(parts[i]))
		if ip != nil && !IsTrustedProxy(ip, trusted) {
			return ip
		}
	}
	return remote
}

// ClientIPFromRequest returns the real client IP from a request, honoring trusted proxies
// and common reverse proxy headers (including Cloudflare Tunnel headers).
func ClientIPFromRequest(r *http.Request, trusted []*net.IPNet) net.IP {
	if r == nil {
		return nil
	}
	remote := ExtractIP(r.RemoteAddr)
	if remote == nil {
		return nil
	}
	if len(trusted) == 0 || !IsTrustedProxy(remote, trusted) {
		return remote
	}
	if ip := headerIP(r.Header.Get("CF-Connecting-IP")); ip != nil {
		return ip
	}
	if ip := headerIP(r.Header.Get("True-Client-IP")); ip != nil {
		return ip
	}
	if ip := headerIP(r.Header.Get("X-Real-IP")); ip != nil {
		return ip
	}
	if ip := forwardedClientIP(r.Header.Get("Forwarded"), trusted); ip != nil {
		return ip
	}
	return ClientIP(r.RemoteAddr, r.Header.Get("X-Forwarded-For"), trusted)
}

func headerIP(value string) net.IP {
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	candidate := strings.TrimSpace(parts[0])
	candidate = strings.Trim(candidate, "\"")
	if strings.EqualFold(candidate, "unknown") {
		return nil
	}
	if strings.HasPrefix(candidate, "[") && strings.Contains(candidate, "]") {
		candidate = strings.TrimPrefix(candidate, "[")
		candidate = strings.TrimSuffix(candidate, "]")
	}
	return ExtractIP(candidate)
}

func forwardedClientIP(value string, trusted []*net.IPNet) net.IP {
	if value == "" {
		return nil
	}
	entries := strings.Split(value, ",")
	for i := len(entries) - 1; i >= 0; i-- {
		entry := strings.TrimSpace(entries[i])
		params := strings.Split(entry, ";")
		for _, param := range params {
			param = strings.TrimSpace(param)
			lower := strings.ToLower(param)
			if !strings.HasPrefix(lower, "for=") {
				continue
			}
			forValue := strings.TrimSpace(param[4:])
			forValue = strings.Trim(forValue, "\"")
			if strings.EqualFold(forValue, "unknown") {
				continue
			}
			if strings.HasPrefix(forValue, "[") && strings.Contains(forValue, "]") {
				forValue = strings.TrimPrefix(forValue, "[")
				forValue = strings.TrimSuffix(forValue, "]")
			}
			ip := ExtractIP(forValue)
			if ip != nil && !IsTrustedProxy(ip, trusted) {
				return ip
			}
		}
	}
	return nil
}
