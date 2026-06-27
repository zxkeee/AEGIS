package api

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"api-gateway/internal/logger"
)

func TestDashboard_CSPIsNonceBasedNoUnsafeInline(t *testing.T) {
	h := &handlers{log: logger.New("error")}
	rec := httptest.NewRecorder()
	h.serveDashboard(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("dashboard status = %d, want 200", rec.Code)
	}
	csp := rec.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("CSP header is missing")
	}
	if strings.Contains(csp, "'unsafe-inline'") {
		t.Fatalf("CSP still allows unsafe-inline: %q", csp)
	}
	// A base64 nonce must appear in both script-src and style-src.
	nonceRE := regexp.MustCompile(`'nonce-[A-Za-z0-9+/]{20,}'`)
	if !nonceRE.MatchString(csp) {
		t.Fatalf("CSP missing nonce-XXX: %q", csp)
	}

	body := rec.Body.String()
	// Every inline script/style in the served page must carry the same nonce.
	for _, tag := range []string{"<script", "<style"} {
		// Count: every opening tag should have a `nonce="..."` attribute.
		open := strings.Count(body, tag)
		withNonce := strings.Count(body, tag+` nonce="`)
		if open == 0 || open != withNonce {
			t.Errorf("%s tags without nonce: total=%d, with-nonce=%d", tag, open, withNonce)
		}
	}
	// Sanity: the harden-only directives are present.
	for _, want := range []string{"frame-ancestors 'none'", "base-uri 'self'", "form-action 'self'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP missing %q", want)
		}
	}
}

func TestDashboard_NonceChangesEachResponse(t *testing.T) {
	h := &handlers{log: logger.New("error")}
	get := func() string {
		rec := httptest.NewRecorder()
		h.serveDashboard(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		return rec.Header().Get("Content-Security-Policy")
	}
	if a, b := get(), get(); a == b {
		t.Fatal("CSP nonce must rotate per response")
	}
}
