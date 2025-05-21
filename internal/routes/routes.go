package routes

import (
	"github.com/go-chi/chi/v5"
	"github.com/o4f6bgpac3/template/internal/services"
	"io/fs"
	"mime"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"strings"
)

func Setup(r chi.Router, fSys fs.FS, svc *services.Services) {
	api(r)

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

				w.Write(content)
				return
			}

			// File not found, serve index.html (SPA fallback)
			serveIndexHTML(w, fSys, svc)
		})
	}
}

func api(r chi.Router) {
	r.Route("/api", func(r chi.Router) {
		r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("OK"))
		})
	})
}

func serveIndexHTML(w http.ResponseWriter, fSys fs.FS, svc *services.Services) {
	indexHTML, err := fs.ReadFile(fSys, "index.html")
	if err != nil {
		svc.Log.Error().Err(err).Msg("Failed to read index.html")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Write(indexHTML)
}
