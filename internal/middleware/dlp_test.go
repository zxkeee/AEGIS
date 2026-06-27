package middleware

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"api-gateway/internal/config"
)

func TestDLP_RedactsDefaultPatterns(t *testing.T) {
	_ = InitTrustedProxies(nil)
	cfg := config.DLPConfig{Enabled: true}
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"card":"4111 1111 1111 1111","email":"a@b.com"}`)
	})
	h := DLP(cfg, fakeLogger{}, &fakeStore{})(next)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	body := rec.Body.String()
	if strings.Contains(body, "4111 1111 1111 1111") {
		t.Fatal("credit card was not redacted")
	}
	if strings.Contains(body, "a@b.com") {
		t.Fatal("email was not redacted")
	}
	if !strings.Contains(body, "REDACTED") {
		t.Fatalf("expected redaction marker, got %q", body)
	}
}

func TestDLP_StreamingPassthrough(t *testing.T) {
	// Server-sent events must not be buffered/redacted; they stream through.
	_ = InitTrustedProxies(nil)
	cfg := config.DLPConfig{Enabled: true}
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "data: hello\n\n")
	})
	h := DLP(cfg, fakeLogger{}, &fakeStore{})(next)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "data: hello") {
		t.Fatalf("SSE body not passed through: %q", rec.Body.String())
	}
}

func TestDLP_DisabledIsPassthrough(t *testing.T) {
	_ = InitTrustedProxies(nil)
	cfg := config.DLPConfig{Enabled: false}
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "a@b.com")
	})
	h := DLP(cfg, fakeLogger{}, &fakeStore{})(next)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Body.String() != "a@b.com" {
		t.Fatalf("disabled DLP must not alter body, got %q", rec.Body.String())
	}
}

// TestDLP_StripsAcceptEncoding verifies DLP removes the client's Accept-Encoding
// before proxying, so the backend returns an uncompressed body the scanner can
// actually read (the http.Transport otherwise re-adds gzip and decompresses).
func TestDLP_StripsAcceptEncoding(t *testing.T) {
	_ = InitTrustedProxies(nil)
	cfg := config.DLPConfig{Enabled: true}
	var seen string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("Accept-Encoding")
		w.WriteHeader(http.StatusOK)
	})
	h := DLP(cfg, fakeLogger{}, &fakeStore{})(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept-Encoding", "gzip, br")
	h.ServeHTTP(httptest.NewRecorder(), req)

	if seen != "" {
		t.Fatalf("Accept-Encoding must be stripped before proxy, backend saw %q", seen)
	}
}

// TestDLP_CompressedResponsePassthrough verifies the defence-in-depth branch: a
// backend that still returns a compressed body (ignoring the stripped header) is
// passed through untouched rather than scanned as gibberish and falsely reported
// clean. The raw bytes must reach the client unmodified.
func TestDLP_CompressedResponsePassthrough(t *testing.T) {
	_ = InitTrustedProxies(nil)
	cfg := config.DLPConfig{Enabled: true}
	raw := "\x1f\x8b\x08compressed-pii-a@b.com"
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, raw)
	})
	h := DLP(cfg, fakeLogger{}, &fakeStore{})(next)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Body.String() != raw {
		t.Fatalf("compressed body must pass through unmodified, got %q", rec.Body.String())
	}
}
