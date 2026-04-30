package middleware

import (
	"bytes"
	"fmt"
	"net/http"
	"regexp"

	"api-gateway/internal/config"
)

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

type dlpWriter struct {
	http.ResponseWriter
	buf    *bytes.Buffer
	status int
}

func (d *dlpWriter) Write(b []byte) (int, error) {
	return d.buf.Write(b)
}

func (d *dlpWriter) WriteHeader(code int) {
	d.status = code
	// Don't call ResponseWriter.WriteHeader yet — we need to modify the body first
}
