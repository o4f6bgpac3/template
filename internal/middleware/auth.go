package middleware

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/o4f6bgpac3/template/cfg"
	"github.com/o4f6bgpac3/template/internal/audit"
	"github.com/o4f6bgpac3/template/internal/auth"
)

type contextKey string

const (
	UserContextKey contextKey = "user"
)

func RequireAuth(authService *auth.Service, auditService *audit.Service) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := extractToken(r)
			if token == "" {
				auditService.LogEventFromRequest(r.Context(), r, audit.EventPermissionDenied, nil, false, nil)
				writeJSONError(w, "Missing authorization token", http.StatusUnauthorized)
				return
			}

			claims, err := authService.ValidateAccessToken(token)
			if err != nil {
				auditService.LogEventFromRequest(r.Context(), r, audit.EventPermissionDenied, nil, false, err)
				writeJSONError(w, "Invalid token", http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), UserContextKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func RequireRole(auditService *audit.Service, roles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := r.Context().Value(UserContextKey).(*auth.Claims)
			if !ok {
				auditService.LogEventFromRequest(r.Context(), r, audit.EventPermissionDenied, nil, false, nil)
				writeJSONError(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			for _, requiredRole := range roles {
				for _, userRole := range claims.Roles {
					if userRole == requiredRole {
						next.ServeHTTP(w, r)
						return
					}
				}
			}

			auditService.LogPermissionDenied(r.Context(), r, claims.UserID, "role", strings.Join(roles, ","))
			writeJSONError(w, "Forbidden", http.StatusForbidden)
		})
	}
}

func RequirePermission(authService *auth.Service, auditService *audit.Service, resource, action string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := r.Context().Value(UserContextKey).(*auth.Claims)
			if !ok {
				auditService.LogEventFromRequest(r.Context(), r, audit.EventPermissionDenied, nil, false, nil)
				writeJSONError(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			hasPermission, err := authService.CheckPermission(r.Context(), claims.UserID, resource, action)
			if err != nil {
				writeJSONError(w, "Internal server error", http.StatusInternalServerError)
				return
			}

			if !hasPermission {
				auditService.LogPermissionDenied(r.Context(), r, claims.UserID, resource, action)
				writeJSONError(w, "Forbidden", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func RequireAuthWithAudit(authService *auth.Service, auditService *audit.Service) func(http.Handler) http.Handler {
	return RequireAuth(authService, auditService)
}

func RequireAuthWithRateLimit(authService *auth.Service, auditService *audit.Service, rateLimitStore *RateLimitStore, requests int, window int) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		rateLimited := RateLimit(rateLimitStore, requests, time.Duration(window)*time.Second)
		authenticated := RequireAuth(authService, auditService)

		return rateLimited(authenticated(next))
	}
}

func GetUserFromContext(ctx context.Context) (*auth.Claims, bool) {
	claims, ok := ctx.Value(UserContextKey).(*auth.Claims)
	return claims, ok
}

func GetUserID(ctx context.Context) (uuid.UUID, bool) {
	claims, ok := GetUserFromContext(ctx)
	if !ok {
		return uuid.UUID{}, false
	}
	return claims.UserID, true
}

func extractToken(r *http.Request) string {
	bearerToken := r.Header.Get("Authorization")
	if len(bearerToken) > 7 && strings.ToUpper(bearerToken[0:7]) == "BEARER " {
		return bearerToken[7:]
	}

	// Use configured cookie name with secure prefix when in secure context
	cookieName := cfg.Config.Security.SessionCookieName
	if cfg.Config.Security.SessionCookieSecure && isSecureContext() {
		cookieName = "__Secure-" + cookieName
	}

	cookie, err := r.Cookie(cookieName)
	if err == nil {
		return cookie.Value
	}

	return ""
}

// isSecureContext checks if we're in a secure context (HTTPS or production)
// __Secure- prefix should only be used over HTTPS
func isSecureContext() bool {
	// In development mode (ENV=0), assume non-secure context for localhost HTTP testing
	// This allows __Secure- prefix to be skipped for localhost HTTP
	return cfg.Config.HTTP.BaseURL != "" && 
		   len(cfg.Config.HTTP.BaseURL) >= 8 &&
		   (cfg.Config.HTTP.BaseURL[:8] == "https://" || cfg.Config.Env > 0)
}

