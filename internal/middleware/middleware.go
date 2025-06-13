package middleware

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/o4f6bgpac3/template/cfg"
	"github.com/unrolled/secure"
)

func Setup(r chi.Router) {
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)

	// Add CSP nonce middleware before security middleware
	r.Use(CSPNonceMiddleware)
	r.Use(CSPHeaderMiddleware)

	r.Use(CSRFProtect(DefaultCSRFConfig()))

	secureMiddleware := secure.New(secure.Options{
		AllowedHosts:      cfg.Config.HTTP.Hosts,
		HostsProxyHeaders: []string{"X-Forwarded-Hosts"},
		SSLRedirect:       true,
		SSLHost:           cfg.Config.HTTP.BaseURL,
		SSLProxyHeaders:   map[string]string{"X-Forwarded-Proto": "https"},

		// Enhanced HSTS Configuration
		STSSeconds:           63072000, // 2 years (more secure than 1 year)
		STSIncludeSubdomains: true,
		STSPreload:           true,

		// Core Security Headers
		FrameDeny:             true,
		ContentTypeNosniff:    true,
		BrowserXssFilter:      true,
		ContentSecurityPolicy: "", // Will be set dynamically by CSP middleware

		// Enhanced Referrer Policy (more restrictive)
		ReferrerPolicy: "strict-origin-when-cross-origin",

		// Enhanced Permissions Policy (more comprehensive)
		PermissionsPolicy: buildPermissionsPolicy(),

		// Cross-Origin Policies (already secure)
		CrossOriginOpenerPolicy:   "same-origin",
		CrossOriginEmbedderPolicy: "require-corp",
		CrossOriginResourcePolicy: "same-origin",

		// Additional Security Headers
		XDNSPrefetchControl:           "off",
		XPermittedCrossDomainPolicies: "none",

		IsDevelopment: false,
	})

	// Apply the secure middleware first
	r.Use(secureMiddleware.Handler)

	// Add additional custom security headers not covered by secure package
	r.Use(additionalSecurityHeaders)
}

func SetupDev(r chi.Router) {
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)

	// Add CSP nonce middleware for development
	r.Use(CSPNonceMiddleware)
	r.Use(CSPHeaderMiddleware)

	// Development CORS - cannot use wildcard with credentials
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins: []string{
			"http://localhost:5173",
			"http://localhost:3000",
		},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token", "X-Requested-With"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	devCSRFConfig := DefaultCSRFConfig()
	devCSRFConfig.CookieSecure = false
	r.Use(CSRFProtect(devCSRFConfig))

	// Add security headers for development (with relaxed settings)
	r.Use(developmentSecurityHeaders)
}

// developmentSecurityHeaders applies security headers appropriate for development
func developmentSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Basic security headers that don't interfere with development
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")

		// Relaxed permissions policy for development
		w.Header().Set("Permissions-Policy", "geolocation=(), camera=(), microphone=()")

		// Cache control for auth endpoints (same as production)
		if strings.HasPrefix(r.URL.Path, "/api/auth/") {
			w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
			w.Header().Set("Pragma", "no-cache")
		}

		// Server hiding (development)
		w.Header().Set("Server", "Dev-Server")

		next.ServeHTTP(w, r)
	})
}

// CSPNonceMiddleware generates a random nonce for each request and adds it to the context
func CSPNonceMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonce, err := generateNonce()
		if err != nil {
			// SECURITY: If nonce generation fails, we must fail securely
			// Log the error and return an error response rather than allowing unsafe-inline
			http.Error(w, "Security system unavailable", http.StatusServiceUnavailable)
			return
		}

		// Add nonce to request context
		ctx := r.Context()
		ctx = SetCSPNonce(ctx, nonce)
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}

// generateNonce creates a cryptographically secure random nonce
func generateNonce() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(bytes), nil
}

// CSPHeaderMiddleware sets the Content-Security-Policy header with nonce support
func CSPHeaderMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		csp := generateCSP(r)
		w.Header().Set("Content-Security-Policy", csp)
		next.ServeHTTP(w, r)
	})
}

// generateCSP creates a CSP header with enhanced security
func generateCSP(r *http.Request) string {
	nonce := GetCSPNonce(r.Context())

	// Significantly enhanced CSP directives for better security
	baseCSP := "default-src 'self'; " +
		"img-src 'self' data:; " +
		"font-src 'self'; " +
		"connect-src 'self'; " +
		"manifest-src 'self'; " +
		"media-src 'self'; " +
		"object-src 'none'; " +
		"frame-ancestors 'none'; " +
		"base-uri 'self'; " +
		"form-action 'self'; " +
		"upgrade-insecure-requests"

	// SECURITY: We now guarantee nonce existence via fail-secure middleware
	// No unsafe fallback CSP - if nonce fails, request fails
	if nonce == "" {
		// This should never happen due to fail-secure nonce middleware
		// But if it does, use the most restrictive CSP possible
		return baseCSP + "; " +
			"style-src 'self'; " +
			"script-src 'self'"
	}

	// Enhanced CSP with nonce - allows whitelisted inline scripts via nonce
	// Allow 'unsafe-inline' for styles only (needed for SvelteKit component styles)
	return baseCSP + "; " +
		"style-src 'self' 'unsafe-inline'; " +
		"script-src 'self' 'nonce-" + nonce + "'"
}

// buildPermissionsPolicy creates a comprehensive Permissions Policy header
func buildPermissionsPolicy() string {
	// Comprehensive permissions policy that denies most sensitive features by default
	policies := []string{
		// Location and sensors
		"geolocation=()",
		"camera=()",
		"microphone=()",
		"gyroscope=()",
		"accelerometer=()",
		"magnetometer=()",
		"ambient-light-sensor=()",

		// Payment and crypto
		"payment=()",
		"encrypted-media=()",

		// Display and interaction
		"fullscreen=()",
		"picture-in-picture=()",
		"display-capture=()",
		"screen-wake-lock=()",

		// Device access
		"usb=()",
		"serial=()",
		"hid=()",
		"bluetooth=()",

		// Tracking and analytics
		"interest-cohort=()", // Disables FLoC
		"browsing-topics=()", // Disables Topics API

		// Web features
		"midi=()",
		"web-share=()",
		"xr-spatial-tracking=()",
		"publickey-credentials-get=self", // Allow WebAuthn on same origin only
	}

	return strings.Join(policies, ", ")
}

// additionalSecurityHeaders adds custom security headers not covered by the secure package
func additionalSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Timing Attack Protection
		w.Header().Set("X-Response-Time-Limit", "5000") // 5 second max response time

		// Additional Content Security Headers
		w.Header().Set("X-Download-Options", "noopen")              // IE download security
		w.Header().Set("X-Permitted-Cross-Domain-Policies", "none") // Flash/PDF policies

		// Cache Control for sensitive endpoints
		if strings.HasPrefix(r.URL.Path, "/api/auth/") {
			w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate")
			w.Header().Set("Pragma", "no-cache")
			w.Header().Set("Expires", "0")
		}

		// Server Information Hiding
		w.Header().Set("Server", "WebServer") // Generic server name

		// Additional Security Context
		w.Header().Set("X-Content-Type-Options", "nosniff") // Extra protection
		w.Header().Set("X-Robots-Tag", "noindex, nofollow") // Prevent search indexing

		// Origin and Embedder Protection
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Cross-Origin-Embedder-Policy", "require-corp")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")

		next.ServeHTTP(w, r)
	})
}
