package api

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed all:console_dist
var consoleFS embed.FS

// consoleAssets is the built React console (Vite output) rooted at console_dist.
var consoleAssets, _ = fs.Sub(consoleFS, "console_dist")

// consoleCSP is the Content-Security-Policy for the single-page console.
//
// script-src stays strict 'self': the Vite production bundle is a self-hosted
// module with no inline scripts and no eval, so XSS cannot execute injected
// script. style-src allows 'unsafe-inline' because the animation layer
// (Framer Motion) and React set inline styles at runtime; style injection cannot
// execute code, so this is a deliberate, bounded relaxation — the important
// anti-XSS control (script-src) remains locked down.
const consoleCSP = "default-src 'self'; " +
	"script-src 'self'; " +
	"style-src 'self' 'unsafe-inline'; " +
	"img-src 'self' data:; " +
	"font-src 'self'; " +
	"connect-src 'self'; " +
	"base-uri 'self'; " +
	"form-action 'self'; " +
	"frame-ancestors 'none'"

// serveDashboard serves the console's index.html shell. Any non-asset path
// resolves here (SPA fallback), so client-side navigation works on reload.
func (h *handlers) serveDashboard(w http.ResponseWriter, r *http.Request) {
	data, err := consoleAssets.(fs.ReadFileFS).ReadFile("index.html")
	if err != nil {
		http.Error(w, "console not built", http.StatusInternalServerError)
		return
	}
	hdr := w.Header()
	hdr.Set("Content-Type", "text/html; charset=utf-8")
	hdr.Set("Cache-Control", "no-store")
	hdr.Set("Content-Security-Policy", consoleCSP)
	hdr.Set("X-Frame-Options", "DENY")
	hdr.Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(data)
}

// assetETag is the strong validator for an embedded console asset: the SHA-256
// of the bytes compiled into this binary, so it changes exactly when the asset
// does and is identical across replicas.
func assetETag(data []byte) string {
	sum := sha256.Sum256(data)
	return `"` + hex.EncodeToString(sum[:16]) + `"`
}

// serveConsoleAsset serves the bundle assets (JS/CSS/svg), revalidated by ETag.
//
// This previously sent `max-age=31536000, immutable`, justified by a comment
// claiming Vite fingerprints the filenames. It does not: vite.config.ts pins
// `entryFileNames: "assets/console.js"` so the bundle is served under one
// constant URL — deliberately, because the built bundle is committed and a
// hashed name would churn the diff on every build.
//
// A constant URL and an immutable year-long cache together mean an upgraded
// gateway keeps serving the old console out of the browser cache, with no
// request that could ever discover the new one. That is not a caching nuisance:
// it is how a fixed console never reaches the operator who needs it. The ETag
// keeps the cheap 304 without pinning a stale bundle.
func (h *handlers) serveConsoleAsset(w http.ResponseWriter, r *http.Request) {
	// Path is "/assets/console.js" etc.; strip the leading slash for the sub-FS.
	name := strings.TrimPrefix(r.URL.Path, "/")
	data, err := consoleAssets.(fs.ReadFileFS).ReadFile(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	etag := assetETag(data)
	hdr := w.Header()
	hdr.Set("ETag", etag)
	hdr.Set("Cache-Control", "no-cache")
	if match := r.Header.Get("If-None-Match"); match != "" && strings.Contains(match, etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	hdr.Set("Content-Type", contentType(name))
	hdr.Set("X-Content-Type-Options", "nosniff")
	// #nosec G705 -- data is a compiled-in embedded asset (our own build output),
	// not user input; the URL only selects which embedded file. Served with an
	// explicit non-HTML Content-Type plus nosniff, and embed.FS rejects traversal.
	_, _ = w.Write(data)
}

// consoleEnv is a public bootstrap endpoint: it exposes only whether admin
// authentication and OIDC SSO are enabled, so the login screen can render the
// right controls. No secrets.
func (h *handlers) consoleEnv(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"admin_auth": h.cfg.AdminAuth,
		"sso":        h.oidcEnabled(),
	})
}

func contentType(name string) string {
	switch {
	case strings.HasSuffix(name, ".js"):
		return "text/javascript; charset=utf-8"
	case strings.HasSuffix(name, ".css"):
		return "text/css; charset=utf-8"
	case strings.HasSuffix(name, ".svg"):
		return "image/svg+xml"
	case strings.HasSuffix(name, ".woff2"):
		return "font/woff2"
	default:
		return "application/octet-stream"
	}
}
