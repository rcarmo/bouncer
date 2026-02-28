// Package localip detects whether an IP address is in RFC1918 or loopback ranges.
package localip

import (
	"net"
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
