package middleware

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
)

const (
	csrfTokenHeader = "X-CSRF-Token"
	csrfTokenForm   = "csrf_token"
	csrfCookieName  = "csrf_token"
	csrfTokenLength = 32
)

// CSRFToken represents a CSRF token with its creation time
type CSRFToken struct {
	Token     string
	CreatedAt time.Time
}

// CSRFConfig holds CSRF middleware configuration
type CSRFConfig struct {
	TokenLength     int
	CookieName      string
	HeaderName      string
	FormFieldName   string
	CookieSecure    bool
	CookieHTTPOnly  bool
	CookieSameSite  http.SameSite
	TokenExpiration time.Duration
}

// DefaultCSRFConfig returns default CSRF configuration
func DefaultCSRFConfig() CSRFConfig {
	return CSRFConfig{
		TokenLength:     csrfTokenLength,
		CookieName:      csrfCookieName,
		HeaderName:      csrfTokenHeader,
		FormFieldName:   csrfTokenForm,
		CookieSecure:    true,
		CookieHTTPOnly:  true,
		CookieSameSite:  http.SameSiteLaxMode,
		TokenExpiration: 24 * time.Hour,
	}
}

// CSRFProtect returns a CSRF protection middleware
func CSRFProtect(config CSRFConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip CSRF protection for safe methods
			if r.Method == "GET" || r.Method == "HEAD" || r.Method == "OPTIONS" {
				// Only generate and set CSRF token if one doesn't exist or is empty
				existingToken := getCSRFTokenFromCookie(r, config.CookieName)
				if existingToken == "" {
					token, err := generateCSRFToken()
					if err != nil {
						writeJSONError(w, "Failed to generate CSRF token", http.StatusInternalServerError)
						return
					}
					setCSRFCookie(w, token, config)
				}
				next.ServeHTTP(w, r)
				return
			}

			// For unsafe methods, validate CSRF token
			cookieToken := getCSRFTokenFromCookie(r, config.CookieName)
			if cookieToken == "" {
				writeJSONError(w, "CSRF token missing from cookie", http.StatusForbidden)
				return
			}

			// Get token from header or form
			requestToken := getCSRFTokenFromRequest(r, config)
			if requestToken == "" {
				writeJSONError(w, "CSRF token missing from request", http.StatusForbidden)
				return
			}

			// Validate tokens match using constant-time comparison
			if !validateCSRFToken(cookieToken, requestToken) {
				writeJSONError(w, "CSRF token mismatch", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// generateCSRFToken generates a cryptographically secure random token
func generateCSRFToken() (string, error) {
	bytes := make([]byte, csrfTokenLength)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// setCSRFCookie sets the CSRF token in a cookie
func setCSRFCookie(w http.ResponseWriter, token string, config CSRFConfig) {
	cookie := &http.Cookie{
		Name:     config.CookieName,
		Value:    token,
		Path:     "/",
		Secure:   config.CookieSecure,
		HttpOnly: config.CookieHTTPOnly,
		SameSite: config.CookieSameSite,
		Expires:  time.Now().Add(config.TokenExpiration),
	}
	http.SetCookie(w, cookie)
}

// getCSRFTokenFromCookie extracts CSRF token from cookie
func getCSRFTokenFromCookie(r *http.Request, cookieName string) string {
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return ""
	}
	return cookie.Value
}

// getCSRFTokenFromRequest extracts CSRF token from request header or form
func getCSRFTokenFromRequest(r *http.Request, config CSRFConfig) string {
	// First try header
	token := r.Header.Get(config.HeaderName)
	if token != "" {
		return token
	}

	// Then try form field
	if err := r.ParseForm(); err != nil {
		return ""
	}
	return r.FormValue(config.FormFieldName)
}

// validateCSRFToken validates CSRF tokens using constant-time comparison
func validateCSRFToken(cookieToken, requestToken string) bool {
	return subtle.ConstantTimeCompare([]byte(cookieToken), []byte(requestToken)) == 1
}

// GetCSRFToken is a helper function to get CSRF token for templates/API responses
func GetCSRFToken(r *http.Request) string {
	return getCSRFTokenFromCookie(r, csrfCookieName)
}

// CSRFTokenFromContext extracts CSRF token from request context (for use in handlers)
func CSRFTokenFromContext(r *http.Request) string {
	return GetCSRFToken(r)
}

// SetupCSRFRoutes adds routes for CSRF token retrieval
func SetupCSRFRoutes(r chi.Router) {
	r.Get("/csrf-token", func(w http.ResponseWriter, r *http.Request) {
		token := GetCSRFToken(r)
		if token == "" {
			writeJSONError(w, "CSRF token not found", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		response := map[string]string{"csrf_token": token}
		if err := json.NewEncoder(w).Encode(response); err != nil {
			writeJSONError(w, "Failed to encode response", http.StatusInternalServerError)
			return
		}
	})
}

// writeJSONError writes a JSON error response
func writeJSONError(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	response := map[string]string{"error": message}
	_ = json.NewEncoder(w).Encode(response) // Ignore encoding errors at this point
}
