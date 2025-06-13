package routes

import (
	"encoding/json"
	"github.com/go-chi/chi/v5"
	"github.com/o4f6bgpac3/template/internal/middleware"
	"github.com/o4f6bgpac3/template/internal/services"
	"io/fs"
	"mime"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"regexp"
	"strings"
)

func Setup(r chi.Router, fSys fs.FS, svc *services.Services) {
	api(r, svc)

	if fSys == nil {
		// Development mode
		frontendURL := os.Getenv("FRONTEND_URL")
		if frontendURL == "" {
			frontendURL = "http://localhost:5173"
		}

		r.NotFound(func(w http.ResponseWriter, r *http.Request) {
			target, _ := url.Parse(frontendURL)
			proxy := httputil.NewSingleHostReverseProxy(target)
			proxy.ServeHTTP(w, r)
		})
	} else {
		r.NotFound(func(w http.ResponseWriter, r *http.Request) {
			// Clean the path and remove the leading slash
			filePath := strings.TrimPrefix(path.Clean(r.URL.Path), "/")

			// Try to serve the file from the embedded filesystem
			content, err := fs.ReadFile(fSys, filePath)
			if err == nil {
				// File exists, serve it with the appropriate MIME type
				ext := path.Ext(filePath)
				mimeType := mime.TypeByExtension(ext)
				if mimeType != "" {
					w.Header().Set("Content-Type", mimeType)
				} else {
					w.Header().Set("Content-Type", "application/octet-stream")
				}

				// Set cache headers based on a file type
				if strings.HasPrefix(filePath, "_app/") || strings.HasPrefix(filePath, "assets/") {
					// Cache immutable assets for a long time
					w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
				} else if ext == ".html" {
					// Don't cache HTML files
					w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
				} else {
					// Cache other files for a shorter time
					w.Header().Set("Cache-Control", "public, max-age=3600")
				}

				if _, err := w.Write(content); err != nil {
					// Log error but continue - content is already set
					return
				}
				return
			}

			// File not found, serve index.html (SPA fallback)
			serveIndexHTML(w, r, fSys, svc)
		})
	}
}

func api(r chi.Router, svc *services.Services) {
	r.Route("/api", func(r chi.Router) {
		r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("OK"))
		})

		// Setup CSRF token endpoint
		middleware.SetupCSRFRoutes(r)

		// Setup auth routes
		setupAuthRoutes(r, svc)

		// Example protected route
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireAuth(svc.Auth, svc.Audit))
			r.Get("/protected", func(w http.ResponseWriter, r *http.Request) {
				claims, _ := middleware.GetUserFromContext(r.Context())
				w.Header().Set("Content-Type", "application/json")
				if err := json.NewEncoder(w).Encode(map[string]interface{}{
					"message": "This is a protected route",
					"user":    claims,
				}); err != nil {
					http.Error(w, "Failed to encode response", http.StatusInternalServerError)
					return
				}
			})
		})

		// Example admin-only route
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireAuth(svc.Auth, svc.Audit))
			r.Use(middleware.RequireRole(svc.Audit, "admin"))
			r.Get("/admin", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if err := json.NewEncoder(w).Encode(map[string]interface{}{
					"message": "Admin access granted",
				}); err != nil {
					http.Error(w, "Failed to encode response", http.StatusInternalServerError)
					return
				}
			})
		})
	})
}

func serveIndexHTML(w http.ResponseWriter, r *http.Request, fSys fs.FS, svc *services.Services) {
	indexHTML, err := fs.ReadFile(fSys, "index.html")
	if err != nil {
		svc.Log.Error().Err(err).Msg("Failed to read index.html")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Inject CSP nonce into inline scripts
	htmlWithNonce := injectNonceIntoHTML(string(indexHTML), r)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	if _, err := w.Write([]byte(htmlWithNonce)); err != nil {
		svc.Log.Error().Err(err).Msg("Failed to write index.html")
		return
	}
}

// injectNonceIntoHTML adds nonce attributes to inline script tags for CSP compliance
func injectNonceIntoHTML(html string, r *http.Request) string {
	nonce := middleware.GetCSPNonceFromRequest(r)
	if nonce == "" {
		// Should not happen due to fail-secure middleware, but be defensive
		return html
	}

	// Regex to find inline script tags that don't already have a nonce
	scriptRegex := regexp.MustCompile(`<script(?:\s+[^>]*?)?\s*>`)
	
	// Replace script tags with nonce-enabled versions
	return scriptRegex.ReplaceAllStringFunc(html, func(match string) string {
		// Check if nonce is already present
		if strings.Contains(match, "nonce=") {
			return match
		}
		
		// Insert nonce attribute before the closing >
		if strings.HasSuffix(match, ">") {
			return strings.TrimSuffix(match, ">") + ` nonce="` + nonce + `">`
		}
		return match
	})
}
