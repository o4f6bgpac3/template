package middleware

import (
	"github.com/o4f6bgpac3/template/internal/utils"
	"net/http"
	"sync"
	"time"

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
				http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
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
				http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
