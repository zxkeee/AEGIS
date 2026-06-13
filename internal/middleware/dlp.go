package middleware

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"

	"api-gateway/internal/config"
)

// dlpMaxBuffer caps how much of a response body DLP will hold in memory for
// inspection. Beyond this the response streams through unmodified — a bounded
// inspection gap is preferable to unbounded memory growth (OOM/DoS).
const dlpMaxBuffer = 4 << 20 // 4 MB

// DLP provides Data Loss Prevention by masking sensitive data in responses.
func DLP(cfg config.DLPConfig, log Logger, st Store) Middleware {
	if !cfg.Enabled {
		return passthrough
	}

	// Compile PII patterns
	defaults := []string{
		`\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b`,             // Credit cards
		`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`, // Emails
		`\b\d{3}-\d{2}-\d{4}\b`,                               // SSN
	}

	allPatterns := cfg.Patterns
	if len(allPatterns) == 0 {
		allPatterns = defaults
	}

	patterns := make([]*regexp.Regexp, 0, len(allPatterns))
	for _, p := range allPatterns {
		if re, err := regexp.Compile(p); err == nil {
			patterns = append(patterns, re)
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// FIX BUG-3 & BUG-4: Capture status code, headers, AND body
			dw := &dlpWriter{
				ResponseWriter: w,
				buf:            &bytes.Buffer{},
				status:         http.StatusOK,
			}

			next.ServeHTTP(dw, r)

			// Streaming, protocol upgrades, or oversized responses were passed
			// through directly — nothing left to inspect or write.
			if dw.passthrough {
				return
			}

			body := dw.buf.Bytes()
			redacted := false
			for _, re := range patterns {
				newBody := re.ReplaceAll(body, []byte("***REDACTED***"))
				if len(newBody) != len(body) {
					redacted = true
				}
				body = newBody
			}

			if redacted {
				st.IncrMetric(r.Context(), "dlp_redacted")
				// Flag the discovery observation so the catalog can mark this
				// endpoint as exposing sensitive data (drives risk scoring).
				if obs := observationFrom(r.Context()); obs != nil {
					obs.PII = true
				}
				log.Info("dlp: PII redacted from response", map[string]any{
					"path": r.URL.Path,
					"ip":   RealIP(r),
				})
			}

			// Write actual status code and corrected Content-Length
			w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
			w.WriteHeader(dw.status)
			w.Write(body) //nolint:errcheck
		})
	}
}

// dlpWriter buffers the response body so PII patterns can be redacted before the
// bytes reach the client. To avoid breaking streaming responses (SSE), protocol
// upgrades (WebSocket), or exhausting memory on large bodies, it falls back to a
// transparent passthrough mode in those cases.
type dlpWriter struct {
	http.ResponseWriter
	buf         *bytes.Buffer
	status      int
	passthrough bool // once true, all writes go straight to the client
	wroteHeader bool
}

func (d *dlpWriter) Write(b []byte) (int, error) {
	if d.passthrough {
		return d.ResponseWriter.Write(b)
	}
	// Switch to passthrough if buffering this chunk would exceed the cap.
	if d.buf.Len()+len(b) > dlpMaxBuffer {
		d.flushPassthrough()
		return d.ResponseWriter.Write(b)
	}
	return d.buf.Write(b)
}

func (d *dlpWriter) WriteHeader(code int) {
	if d.wroteHeader {
		return
	}
	d.status = code
	// Non-inspectable responses (protocol upgrades, server-sent events) must not
	// be buffered — switch to passthrough and emit the header immediately.
	if code == http.StatusSwitchingProtocols ||
		strings.HasPrefix(d.Header().Get("Content-Type"), "text/event-stream") {
		d.passthrough = true
		d.wroteHeader = true
		d.ResponseWriter.WriteHeader(code)
		return
	}
	d.wroteHeader = true
	// Otherwise delay: the body is modified before the header is sent.
}

// flushPassthrough emits the captured status and already-buffered bytes, then
// switches the writer into transparent mode for the remainder of the response.
func (d *dlpWriter) flushPassthrough() {
	d.passthrough = true
	d.ResponseWriter.WriteHeader(d.status)
	if d.buf.Len() > 0 {
		d.ResponseWriter.Write(d.buf.Bytes()) //nolint:errcheck
		d.buf.Reset()
	}
}

// Flush implements http.Flusher. In buffering mode flushing is a no-op (we must
// hold the body for inspection); in passthrough mode it delegates downstream.
func (d *dlpWriter) Flush() {
	if !d.passthrough {
		d.flushPassthrough()
	}
	if f, ok := d.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack implements http.Hijacker so WebSocket and other connection upgrades
// proxied through the gateway continue to work.
func (d *dlpWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := d.ResponseWriter.(http.Hijacker); ok {
		d.passthrough = true
		return hj.Hijack()
	}
	return nil, nil, fmt.Errorf("dlp: underlying ResponseWriter does not support hijacking")
}
