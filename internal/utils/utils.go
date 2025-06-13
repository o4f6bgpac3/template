package utils

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"

	"github.com/o4f6bgpac3/template/cfg"
)

// GetClientIp securely determines the client IP address with trusted proxy validation.
//
// Security Behavior:
// - If TrustProxyHeaders is false: Always returns RemoteAddr (secure default)
// - If TrustProxyHeaders is true: Only trusts headers from IPs in TrustedProxies list
// - Validates proxy source before trusting X-Forwarded-For, X-Real-IP headers
// - Falls back to RemoteAddr if headers are invalid or proxy is untrusted
//
// This prevents IP spoofing attacks that could bypass rate limiting and audit logging.
func GetClientIp(r *http.Request) netip.Addr {
	// If proxy headers are not trusted, always use RemoteAddr
	if !cfg.Config.Security.TrustProxyHeaders {
		return parseRemoteAddr(r.RemoteAddr)
	}

	// Get the immediate client IP (the proxy)
	proxyIP := parseRemoteAddr(r.RemoteAddr)
	
	// Validate that the request comes from a trusted proxy
	if !isTrustedProxy(proxyIP) {
		// Request doesn't come from trusted proxy, don't trust headers
		return proxyIP
	}

	// Extract client IP from trusted proxy headers
	clientIP := extractClientIPFromHeaders(r)
	if !clientIP.IsValid() {
		// Fallback to proxy IP if headers are invalid
		return proxyIP
	}

	return clientIP
}

// parseRemoteAddr extracts IP from RemoteAddr (which includes port)
func parseRemoteAddr(remoteAddr string) netip.Addr {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		// If no port, try parsing as-is
		host = remoteAddr
	}
	
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return addr
}

// isTrustedProxy checks if the given IP is in the trusted proxies list
func isTrustedProxy(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}

	trustedProxies := cfg.Config.Security.TrustedProxies
	if len(trustedProxies) == 0 {
		return false
	}

	for _, trustedProxy := range trustedProxies {
		// Parse as prefix (CIDR) first
		if prefix, err := netip.ParsePrefix(trustedProxy); err == nil {
			if prefix.Contains(ip) {
				return true
			}
		} else {
			// Parse as single IP
			if trustedIP, err := netip.ParseAddr(trustedProxy); err == nil {
				if trustedIP == ip {
					return true
				}
			}
		}
	}

	return false
}

// extractClientIPFromHeaders extracts the real client IP from proxy headers
func extractClientIPFromHeaders(r *http.Request) netip.Addr {
	// Try X-Forwarded-For first (most common)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// X-Forwarded-For can contain multiple IPs: "client, proxy1, proxy2"
		// We want the leftmost (original client) IP
		ips := strings.Split(xff, ",")
		for _, ipStr := range ips {
			ipStr = strings.TrimSpace(ipStr)
			if ip, err := netip.ParseAddr(ipStr); err == nil && ip.IsValid() {
				// Skip private/loopback IPs in the chain (these are likely proxies)
				if !isPrivateOrLoopback(ip) {
					return ip
				}
			}
		}
	}

	// Try X-Real-IP as fallback
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		if ip, err := netip.ParseAddr(xri); err == nil && ip.IsValid() {
			return ip
		}
	}

	// Try X-Forwarded header (less common)
	if xf := r.Header.Get("X-Forwarded"); xf != "" {
		// X-Forwarded: for=192.168.1.1
		if strings.HasPrefix(xf, "for=") {
			ipStr := strings.TrimPrefix(xf, "for=")
			if ip, err := netip.ParseAddr(ipStr); err == nil && ip.IsValid() {
				return ip
			}
		}
	}

	return netip.Addr{}
}

// isPrivateOrLoopback checks if an IP is in private or loopback ranges
func isPrivateOrLoopback(ip netip.Addr) bool {
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
}

// ValidateTrustedProxies validates the trusted proxy configuration
func ValidateTrustedProxies(proxies []string) error {
	for i, proxy := range proxies {
		// Try parsing as CIDR first
		if _, err := netip.ParsePrefix(proxy); err != nil {
			// Try parsing as single IP
			if _, err := netip.ParseAddr(proxy); err != nil {
				return fmt.Errorf("invalid trusted proxy at index %d: %s is not a valid IP address or CIDR", i, proxy)
			}
		}
	}
	return nil
}

// GetCommonProxyConfigurations returns common trusted proxy configurations
func GetCommonProxyConfigurations() map[string][]string {
	return map[string][]string{
		"cloudflare": {
			"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
			"141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
			"197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
			"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
		},
		"aws_elb": {
			"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", // Private ranges commonly used by AWS
		},
		"localhost": {
			"127.0.0.1", "::1",
		},
		"private_networks": {
			"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		},
	}
}

// LogProxySecurityWarnings logs warnings about potentially insecure proxy configurations
func LogProxySecurityWarnings() []string {
	var warnings []string

	if cfg.Config.Security.TrustProxyHeaders {
		if len(cfg.Config.Security.TrustedProxies) == 0 {
			warnings = append(warnings, "TrustProxyHeaders is enabled but no trusted proxies configured - proxy headers will be ignored")
		}

		// Check for overly broad configurations
		for _, proxy := range cfg.Config.Security.TrustedProxies {
			if proxy == "0.0.0.0/0" || proxy == "::/0" {
				warnings = append(warnings, fmt.Sprintf("Trusted proxy '%s' is too broad - allows any IP to spoof headers", proxy))
			}
		}
	}

	return warnings
}
