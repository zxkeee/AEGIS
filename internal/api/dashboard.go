package api

import (
	"crypto/rand"
	"embed"
	"encoding/base64"
	"net/http"
	"strings"
)

//go:embed static/dashboard.html
var dashboardFS embed.FS

// serveDashboard serves the built-in admin dashboard UI. CSP is nonce-based:
// every response gets a freshly generated nonce, the same nonce is injected
// into every inline <script> and <style> tag, and the CSP allows only that
// nonce — `unsafe-inline` is gone. An attacker who lands stored content in
// the page cannot execute it without knowing the per-request nonce.
func (h *handlers) serveDashboard(w http.ResponseWriter, r *http.Request) {
	data, err := dashboardFS.ReadFile("static/dashboard.html")
	if err != nil {
		http.Error(w, "Dashboard not found", 500)
		return
	}

	// 16 bytes → 22-char base64 nonce; new value per response.
	var nb [16]byte
	if _, err := rand.Read(nb[:]); err != nil {
		http.Error(w, "csp nonce", http.StatusInternalServerError)
		return
	}
	nonce := base64.RawStdEncoding.EncodeToString(nb[:])

	// Inject `nonce="..."` into every inline tag. Templates would be cleaner
	// but the dashboard is a single embedded blob; a literal replace keeps the
	// file content unmodified at build time.
	html := strings.ReplaceAll(string(data), "<script>", `<script nonce="`+nonce+`">`)
	html = strings.ReplaceAll(html, "<style>", `<style nonce="`+nonce+`">`)

	hdr := w.Header()
	hdr.Set("Content-Type", "text/html; charset=utf-8")
	hdr.Set("Cache-Control", "no-store")
	// Prevent the dashboard from being embedded in iframes (clickjacking).
	hdr.Set("X-Frame-Options", "DENY")
	hdr.Set("X-Content-Type-Options", "nosniff")
	// Nonce-based CSP — no `unsafe-inline`. Google Fonts stays whitelisted for
	// the font-face requests the inline @import triggers.
	hdr.Set("Content-Security-Policy",
		"default-src 'self'; "+
			"script-src 'self' 'nonce-"+nonce+"'; "+
			"style-src 'self' 'nonce-"+nonce+"' https://fonts.googleapis.com; "+
			"font-src https://fonts.gstatic.com; "+
			"connect-src 'self'; "+
			"img-src 'self' data:; "+
			"base-uri 'self'; "+
			"form-action 'self'; "+
			"frame-ancestors 'none'")

	_, _ = w.Write([]byte(html))
}
