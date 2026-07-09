package middleware

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
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

// TestDLP_ChunkedResponseIsRedacted guards the DLP bypass on chunked responses.
// A backend that does not set Content-Length makes the reverse proxy flush the
// body mid-flight (Go sets FlushInterval to immediate when ContentLength == -1).
// If DLP honoured that flush it would emit the body before inspection — the
// flagship control failing silently. Here we drive a next handler that writes,
// Flushes, then writes more; every sensitive token must still be redacted.
func TestDLP_ChunkedResponseIsRedacted(t *testing.T) {
	_ = InitTrustedProxies(nil)
	cfg := config.DLPConfig{Enabled: true}
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"card":"4111 1111 1111 1111",`)
		// The reverse proxy flushes here for a Content-Length: -1 response.
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		_, _ = io.WriteString(w, `"email":"a@b.com"}`)
	})
	h := DLP(cfg, fakeLogger{}, &fakeStore{})(next)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	body := rec.Body.String()
	if strings.Contains(body, "4111 1111 1111 1111") {
		t.Fatalf("credit card leaked through a flushed (chunked) response: %q", body)
	}
	if strings.Contains(body, "a@b.com") {
		t.Fatalf("email leaked through a flushed (chunked) response: %q", body)
	}
	if !strings.Contains(body, "REDACTED") {
		t.Fatalf("expected redaction marker, got %q", body)
	}
}

// TestDLP_ResponseFormMatrix pins DLP behaviour across the response shapes a
// backend can emit. The chunked bypass (P0) slipped through because the tests
// only covered the fixed-Content-Length happy path; this matrix makes every
// inspectable form prove it redacts and every genuinely-uninspectable form
// prove it passes through intact.
func TestDLP_ResponseFormMatrix(t *testing.T) {
	_ = InitTrustedProxies(nil)
	const card = "4111 1111 1111 1111"

	cases := []struct {
		name       string
		write      func(w http.ResponseWriter)
		wantRedact bool // true: card must be gone; false: body must survive verbatim
	}{
		{
			name: "fixed_content_length",
			write: func(w http.ResponseWriter) {
				body := `{"card":"` + card + `"}`
				w.Header().Set("Content-Length", itoa(len(body)))
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, body)
			},
			wantRedact: true,
		},
		{
			name: "chunked_flushed_midflight",
			write: func(w http.ResponseWriter) {
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, `{"card":"`+card)
				if f, ok := w.(http.Flusher); ok {
					f.Flush() // Content-Length: -1 makes the proxy flush here
				}
				_, _ = io.WriteString(w, `"}`)
			},
			wantRedact: true,
		},
		{
			name: "no_content_length_no_flush",
			write: func(w http.ResponseWriter) {
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, `{"card":"`+card+`"}`)
			},
			wantRedact: true,
		},
		{
			name: "sse_streams_through",
			write: func(w http.ResponseWriter) {
				w.Header().Set("Content-Type", "text/event-stream")
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, "data: "+card+"\n\n")
			},
			wantRedact: false, // SSE is not buffered/inspected by design
		},
		{
			name: "precompressed_passes_through",
			write: func(w http.ResponseWriter) {
				w.Header().Set("Content-Encoding", "gzip")
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, "\x1f\x8b\x08"+card) // undecodable: passed through
			},
			wantRedact: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.DLPConfig{Enabled: true}
			h := DLP(cfg, fakeLogger{}, &fakeStore{})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				tc.write(w)
			}))
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

			body := rec.Body.String()
			if tc.wantRedact && strings.Contains(body, card) {
				t.Fatalf("%s: card leaked (DLP bypassed): %q", tc.name, body)
			}
			if !tc.wantRedact && !strings.Contains(body, card) {
				t.Fatalf("%s: uninspectable body was altered, want verbatim: %q", tc.name, body)
			}
		})
	}
}

func itoa(n int) string { return strconv.Itoa(n) }

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
