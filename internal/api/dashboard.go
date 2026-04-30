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
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Write(data) //nolint:errcheck
}
