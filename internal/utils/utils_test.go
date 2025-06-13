package utils

import (
	"net/http"
	"net/netip"
	"testing"

	"github.com/o4f6bgpac3/template/cfg"
)

func TestGetClientIp_NoProxyHeaders(t *testing.T) {
	// Setup: Disable proxy header trust
	originalConfig := cfg.Config.Security.TrustProxyHeaders
	cfg.Config.Security.TrustProxyHeaders = false
	defer func() { cfg.Config.Security.TrustProxyHeaders = originalConfig }()

	req := &http.Request{
		RemoteAddr: "192.168.1.100:12345",
		Header: http.Header{
			"X-Forwarded-For": []string{"10.0.0.1"},
			"X-Real-IP":       []string{"10.0.0.2"},
		},
	}

	ip := GetClientIp(req)
	expected := netip.MustParseAddr("192.168.1.100")

	if ip != expected {
		t.Errorf("Expected %v, got %v", expected, ip)
	}
}

func TestGetClientIp_TrustedProxy(t *testing.T) {
	// Setup: Enable proxy headers and configure trusted proxy
	originalTrust := cfg.Config.Security.TrustProxyHeaders
	originalProxies := cfg.Config.Security.TrustedProxies
	cfg.Config.Security.TrustProxyHeaders = true
	cfg.Config.Security.TrustedProxies = []string{"192.168.1.0/24"}
	defer func() {
		cfg.Config.Security.TrustProxyHeaders = originalTrust
		cfg.Config.Security.TrustedProxies = originalProxies
	}()

	req := &http.Request{
		RemoteAddr: "192.168.1.100:12345",
		Header: http.Header{
			"X-Forwarded-For": []string{"203.0.113.1"},
		},
	}

	ip := GetClientIp(req)
	expected := netip.MustParseAddr("203.0.113.1")

	if ip != expected {
		t.Errorf("Expected %v, got %v", expected, ip)
	}
}

func TestGetClientIp_UntrustedProxy(t *testing.T) {
	// Setup: Enable proxy headers but request comes from untrusted proxy
	originalTrust := cfg.Config.Security.TrustProxyHeaders
	originalProxies := cfg.Config.Security.TrustedProxies
	cfg.Config.Security.TrustProxyHeaders = true
	cfg.Config.Security.TrustedProxies = []string{"10.0.0.0/8"}
	defer func() {
		cfg.Config.Security.TrustProxyHeaders = originalTrust
		cfg.Config.Security.TrustedProxies = originalProxies
	}()

	req := &http.Request{
		RemoteAddr: "192.168.1.100:12345", // Not in trusted 10.0.0.0/8
		Header: http.Header{
			"X-Forwarded-For": []string{"203.0.113.1"}, // Should be ignored
		},
	}

	ip := GetClientIp(req)
	expected := netip.MustParseAddr("192.168.1.100") // Should use RemoteAddr

	if ip != expected {
		t.Errorf("Expected %v, got %v", expected, ip)
	}
}

func TestValidateTrustedProxies(t *testing.T) {
	validProxies := []string{
		"192.168.1.1",
		"10.0.0.0/8",
		"2001:db8::1",
		"2001:db8::/32",
	}

	if err := ValidateTrustedProxies(validProxies); err != nil {
		t.Errorf("Valid proxies should not return error: %v", err)
	}

	invalidProxies := []string{
		"invalid-ip",
		"999.999.999.999",
		"192.168.1.1/99",
	}

	if err := ValidateTrustedProxies(invalidProxies); err == nil {
		t.Error("Invalid proxies should return error")
	}
}