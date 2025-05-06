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
		// Production mode
		assets(r, fSys, svc)

		r.NotFound(func(w http.ResponseWriter, r *http.Request) {
			serveIndexHTML(w, fSys, svc)
		})
	}
}

func api(r chi.Router) {
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
}

func assets(r chi.Router, fSys fs.FS, svc *services.Services) {
	r.Handle("/assets/*", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		filePath := strings.TrimPrefix(r.URL.Path, "/assets/")
		assetPath := path.Join("assets", filePath)

		content, err := fs.ReadFile(fSys, assetPath)
		if err != nil {
			svc.Log.Error().Err(err).Str("path", assetPath).Msg("Failed to read asset file")
			http.NotFound(w, r)
			return
		}

		ext := path.Ext(filePath)
		mimeType := mime.TypeByExtension(ext)
		if mimeType != "" {
			w.Header().Set("Content-Type", mimeType)
		} else {
			w.Header().Set("Content-Type", "application/octet-stream")
		}

		w.Header().Set("Cache-Control", "public, max-age=31536000")
		w.Write(content)
	}))
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
