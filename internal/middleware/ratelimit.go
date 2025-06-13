package middleware

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/o4f6bgpac3/template/internal/utils"
	"golang.org/x/time/rate"
)

type rateLimiter struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

type RateLimitStore struct {
	mu       sync.RWMutex
	limiters map[string]*rateLimiter
	cleanup  time.Duration
}

func NewRateLimitStore(cleanup time.Duration) *RateLimitStore {
	store := &RateLimitStore{
		limiters: make(map[string]*rateLimiter),
		cleanup:  cleanup,
	}

	go store.cleanupRoutine()
	return store
}

func (s *RateLimitStore) cleanupRoutine() {
	ticker := time.NewTicker(s.cleanup)
	defer ticker.Stop()

	for range ticker.C {
		s.mu.Lock()
		for key, limiter := range s.limiters {
			if time.Since(limiter.lastSeen) > s.cleanup {
				delete(s.limiters, key)
			}
		}
		s.mu.Unlock()
	}
}

func (s *RateLimitStore) getLimiter(key string, requests int, window time.Duration) *rate.Limiter {
	s.mu.Lock()
	defer s.mu.Unlock()

	limiter, exists := s.limiters[key]
	if !exists {
		limiter = &rateLimiter{
			limiter: rate.NewLimiter(rate.Every(window/time.Duration(requests)), requests),
		}
		s.limiters[key] = limiter
	}

	limiter.lastSeen = time.Now()
	return limiter.limiter
}

func RateLimit(store *RateLimitStore, requests int, window time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := utils.GetClientIp(r).String()
			limiter := store.getLimiter(key, requests, window)

			if !limiter.Allow() {
				w.Header().Set("Retry-After", window.String())
				writeJSONRateLimitError(w, "Rate limit exceeded", http.StatusTooManyRequests)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func RateLimitByKey(store *RateLimitStore, keyFunc func(*http.Request) string, requests int, window time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := keyFunc(r)
			limiter := store.getLimiter(key, requests, window)

			if !limiter.Allow() {
				w.Header().Set("Retry-After", window.String())
				writeJSONRateLimitError(w, "Rate limit exceeded", http.StatusTooManyRequests)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RateLimitConfig defines rate limiting configuration for different scenarios
type RateLimitConfig struct {
	IPRequests   int           `json:"ip_requests"`
	IPWindow     time.Duration `json:"ip_window"`
	UserRequests int           `json:"user_requests"`
	UserWindow   time.Duration `json:"user_window"`
}

// EndpointRateLimitConfig defines specific rate limits for different endpoints
type EndpointRateLimitConfig struct {
	Login    RateLimitConfig
	Register RateLimitConfig
	Password RateLimitConfig
	Default  RateLimitConfig
}

// GetDefaultEndpointRateLimits returns secure default rate limits for different endpoints
func GetDefaultEndpointRateLimits() EndpointRateLimitConfig {
	return EndpointRateLimitConfig{
		// Login endpoint - most sensitive, strictest limits
		Login: RateLimitConfig{
			IPRequests:   5,                // 5 attempts per IP
			IPWindow:     5 * time.Minute,  // in 5 minutes
			UserRequests: 3,                // 3 attempts per user (if known)
			UserWindow:   10 * time.Minute, // in 10 minutes
		},
		// Registration endpoint - moderate limits
		Register: RateLimitConfig{
			IPRequests:   3,                // 3 registrations per IP
			IPWindow:     10 * time.Minute, // in 10 minutes
			UserRequests: 1,                // 1 registration per user (edge case)
			UserWindow:   time.Hour,        // in 1 hour
		},
		// Password-related endpoints - strict limits
		Password: RateLimitConfig{
			IPRequests:   3,                // 3 password operations per IP
			IPWindow:     15 * time.Minute, // in 15 minutes
			UserRequests: 2,                // 2 password operations per user
			UserWindow:   30 * time.Minute, // in 30 minutes
		},
		// Default for other endpoints - moderate limits
		Default: RateLimitConfig{
			IPRequests:   20,               // 20 requests per IP
			IPWindow:     time.Minute,      // per minute
			UserRequests: 30,               // 30 requests per user
			UserWindow:   time.Minute,      // per minute
		},
	}
}

// EnhancedRateLimit provides multi-layered rate limiting with IP and user-based limits
func EnhancedRateLimit(store *RateLimitStore, config RateLimitConfig, endpoint string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			clientIP := utils.GetClientIp(r).String()
			
			// Layer 1: IP-based rate limiting (always applied)
			ipKey := fmt.Sprintf("ip:%s:%s", endpoint, clientIP)
			ipLimiter := store.getLimiter(ipKey, config.IPRequests, config.IPWindow)
			
			if !ipLimiter.Allow() {
				w.Header().Set("Retry-After", config.IPWindow.String())
				writeJSONRateLimitError(w, "IP rate limit exceeded", http.StatusTooManyRequests)
				return
			}
			
			// Layer 2: User-based rate limiting (applied if user is authenticated)
			userID := getUserIDFromRequest(r)
			if userID != "" {
				userKey := fmt.Sprintf("user:%s:%s", endpoint, userID)
				userLimiter := store.getLimiter(userKey, config.UserRequests, config.UserWindow)
				
				if !userLimiter.Allow() {
					w.Header().Set("Retry-After", config.UserWindow.String())
					writeJSONRateLimitError(w, "User rate limit exceeded", http.StatusTooManyRequests)
					return
				}
			}
			
			next.ServeHTTP(w, r)
		})
	}
}

// AuthSpecificRateLimit applies different rate limits based on authentication endpoints
func AuthSpecificRateLimit(store *RateLimitStore) func(http.Handler) http.Handler {
	endpointLimits := GetDefaultEndpointRateLimits()
	
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			endpoint := getEndpointFromPath(r.URL.Path)
			
			var config RateLimitConfig
			switch endpoint {
			case "login":
				config = endpointLimits.Login
			case "register":
				config = endpointLimits.Register
			case "forgot-password", "reset-password", "change-password":
				config = endpointLimits.Password
			default:
				config = endpointLimits.Default
			}
			
			// Apply enhanced rate limiting
			EnhancedRateLimit(store, config, endpoint)(next).ServeHTTP(w, r)
		})
	}
}

// Helper functions

// getUserIDFromRequest extracts user ID from authenticated request context
func getUserIDFromRequest(r *http.Request) string {
	if userID, ok := GetUserID(r.Context()); ok {
		return userID.String()
	}
	return ""
}

// getEndpointFromPath extracts the endpoint name from URL path
func getEndpointFromPath(path string) string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) >= 2 && parts[0] == "api" && parts[1] == "auth" && len(parts) >= 3 {
		return parts[2] // e.g., "login", "register", etc.
	}
	return "default"
}

// writeJSONRateLimitError writes a JSON error response for rate limit violations
func writeJSONRateLimitError(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	response := map[string]string{
		"error": message,
		"type":  "rate_limit_exceeded",
	}
	_ = json.NewEncoder(w).Encode(response) // Ignore encoding errors at this point
}