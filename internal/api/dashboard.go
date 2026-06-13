package api

import (
	"embed"
	"net/http"
)

//go:embed static/dashboard.html
var dashboardFS embed.FS

// serveDashboard serves the built-in admin dashboard UI.
func (h *handlers) serveDashboard(w http.ResponseWriter, r *http.Request) {
	data, err := dashboardFS.ReadFile("static/dashboard.html")
	if err != nil {
		http.Error(w, "Dashboard not found", 500)
		return
	}

	hdr := w.Header()
	hdr.Set("Content-Type", "text/html; charset=utf-8")
	hdr.Set("Cache-Control", "no-store")
	// Prevent the dashboard from being embedded in iframes (clickjacking).
	hdr.Set("X-Frame-Options", "DENY")
	hdr.Set("X-Content-Type-Options", "nosniff")
	// CSP: only allow scripts/styles/fonts from self and Google Fonts CDN.
	// 'unsafe-inline' is required for the inline <script> and <style> blocks.
	// script-src 'self' 'unsafe-inline' is acceptable here because the HTML is
	// served from a non-public admin port (8081) behind authentication.
	hdr.Set("Content-Security-Policy",
		"default-src 'self'; "+
			"script-src 'self' 'unsafe-inline'; "+
			"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "+
			"font-src https://fonts.gstatic.com; "+
			"connect-src 'self'; "+
			"img-src 'self' data:; "+
			"frame-ancestors 'none'")

	w.Write(data) //nolint:errcheck
}
