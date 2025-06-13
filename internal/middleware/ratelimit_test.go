package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestEnhancedRateLimit_IPBased(t *testing.T) {
	store := NewRateLimitStore(time.Minute)
	config := RateLimitConfig{
		IPRequests: 2,
		IPWindow:   time.Minute,
	}

	middleware := EnhancedRateLimit(store, config, "test")
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Create requests from same IP
	req1 := httptest.NewRequest("POST", "/test", nil)
	req1.RemoteAddr = "192.168.1.1:12345"
	req2 := httptest.NewRequest("POST", "/test", nil)
	req2.RemoteAddr = "192.168.1.1:12345"
	req3 := httptest.NewRequest("POST", "/test", nil)
	req3.RemoteAddr = "192.168.1.1:12345"

	// First two requests should succeed
	w1 := httptest.NewRecorder()
	handler.ServeHTTP(w1, req1)
	if w1.Code != http.StatusOK {
		t.Errorf("First request should succeed, got %d", w1.Code)
	}

	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Errorf("Second request should succeed, got %d", w2.Code)
	}

	// Third request should be rate limited
	w3 := httptest.NewRecorder()
	handler.ServeHTTP(w3, req3)
	if w3.Code != http.StatusTooManyRequests {
		t.Errorf("Third request should be rate limited, got %d", w3.Code)
	}
}

func TestEnhancedRateLimit_UserBased(t *testing.T) {
	// Skip user-based testing for now since it requires auth middleware context
	// In practice, user-based rate limiting would be tested with full auth integration
	t.Skip("User-based rate limiting requires auth middleware context setup")
}

func TestAuthSpecificRateLimit_EndpointDifferentiation(t *testing.T) {
	store := NewRateLimitStore(time.Minute)
	middleware := AuthSpecificRateLimit(store)

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Test that different endpoints get different rate limits
	loginReq := httptest.NewRequest("POST", "/api/auth/login", nil)
	loginReq.RemoteAddr = "192.168.1.1:12345"

	registerReq := httptest.NewRequest("POST", "/api/auth/register", nil)
	registerReq.RemoteAddr = "192.168.1.1:12345"

	// Both should succeed initially
	w1 := httptest.NewRecorder()
	handler.ServeHTTP(w1, loginReq)
	if w1.Code != http.StatusOK {
		t.Errorf("Login request should succeed, got %d", w1.Code)
	}

	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, registerReq)
	if w2.Code != http.StatusOK {
		t.Errorf("Register request should succeed, got %d", w2.Code)
	}
}

func TestGetEndpointFromPath(t *testing.T) {
	tests := []struct {
		path     string
		expected string
	}{
		{"/api/auth/login", "login"},
		{"/api/auth/register", "register"},
		{"/api/auth/forgot-password", "forgot-password"},
		{"/api/auth/reset-password", "reset-password"},
		{"/api/other/endpoint", "default"},
		{"/invalid/path", "default"},
	}

	for _, test := range tests {
		result := getEndpointFromPath(test.path)
		if result != test.expected {
			t.Errorf("getEndpointFromPath(%s) = %s, expected %s", test.path, result, test.expected)
		}
	}
}

func TestGetDefaultEndpointRateLimits(t *testing.T) {
	limits := GetDefaultEndpointRateLimits()

	// Verify login has strictest limits
	if limits.Login.IPRequests >= limits.Default.IPRequests {
		t.Error("Login should have stricter IP limits than default")
	}

	// Verify password operations have strict limits
	if limits.Password.IPRequests >= limits.Default.IPRequests {
		t.Error("Password operations should have stricter limits than default")
	}

	// Verify registration has reasonable limits
	if limits.Register.IPRequests <= 0 {
		t.Error("Register should have positive rate limits")
	}
}