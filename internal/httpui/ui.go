package httpui

import (
	"embed"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"path/filepath"
	"strings"
	"time"
)

// Put your Vite build output in: web/dist
//
//go:embed dist/**
var embedded embed.FS

// Handler serves the embedded Vite dist folder.
// - Serves real files (works with hashed assets).
// - Falls back to index.html for client-side routes (SPA).
func Handler() (http.Handler, error) {
	sub, err := fs.Sub(embedded, "dist")
	if err != nil {
		return nil, err
	}

	// Ensure common types are known (some systems miss .js/.mjs/etc)
	_ = mime.AddExtensionType(".js", "application/javascript; charset=utf-8")
	_ = mime.AddExtensionType(".mjs", "application/javascript; charset=utf-8")
	_ = mime.AddExtensionType(".css", "text/css; charset=utf-8")
	_ = mime.AddExtensionType(".svg", "image/svg+xml")

	fileServer := http.FileServer(http.FS(sub))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only serve GET/HEAD
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		p := r.URL.Path
		if p == "" {
			p = "/"
		}

		// Normalize path
		p = path.Clean(p)
		if p == "." {
			p = "/"
		}

		// If it's clearly an API route, don't let UI handler catch it
		// Adjust these prefixes to match your API.
		if strings.HasPrefix(p, "/api/") ||
			strings.HasPrefix(p, "/quantum-auth/") ||
			strings.HasPrefix(p, "/status") ||
			strings.HasPrefix(p, "/healthz") {
			http.NotFound(w, r)
			return
		}

		// Map "/" to "index.html"
		try := strings.TrimPrefix(p, "/")
		if try == "" {
			try = "index.html"
		}

		// If requested file exists, serve it (static assets)
		if exists(sub, try) {
			setCacheHeaders(w, try)
			fileServer.ServeHTTP(w, r)
			return
		}

		// SPA fallback -> index.html
		r2 := r.Clone(r.Context())
		r2.URL.Path = "/index.html"
		setCacheHeaders(w, "index.html")
		fileServer.ServeHTTP(w, r2)
	}), nil
}

func exists(fsys fs.FS, name string) bool {
	f, err := fsys.Open(name)
	if err != nil {
		return false
	}
	_ = f.Close()
	return true
}

func setCacheHeaders(w http.ResponseWriter, name string) {
	ext := strings.ToLower(filepath.Ext(name))

	// Vite assets are fingerprinted (e.g. assets/index-ABC123.js) => safe to cache long
	// index.html should be short cached.
	switch ext {
	case ".js", ".mjs", ".css", ".png", ".jpg", ".jpeg", ".webp", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".map":
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	default:
		// index.html + anything else
		w.Header().Set("Cache-Control", "no-cache")
	}
	w.Header().Set("X-Content-Type-Options", "nosniff")

	// Optional: you can uncomment if you want basic hardening (test with your app)
	// w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'")
}

// Helper if you want a simple "ready" wait in other parts later
var _ = time.Second
