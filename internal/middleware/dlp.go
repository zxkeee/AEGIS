package middleware

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"

	"api-gateway/internal/classify"
	"api-gateway/internal/config"
)

// dlpMaxBuffer is the default cap on how much of a response body DLP holds in
// memory for inspection; dlp.max_buffer_bytes overrides it. The cap itself is
// not optional — buffering without one is an OOM vector — but what happens at
// the cap is: see dlp.fail_closed.
const dlpMaxBuffer = 4 << 20 // 4 MB

// DLP provides Data Loss Prevention by masking sensitive data in responses.
func DLP(cfg config.DLPConfig, log Logger, st MetricsSink) Middleware {
	if !cfg.Enabled {
		return passthrough
	}

	// Typed redaction + classification is handled by internal/classify (Luhn-
	// validated cards, SSN range checks, etc.). Any additional operator-supplied
	// regexes are applied on top; their matches redact but carry no data type.
	customPatterns := make([]*regexp.Regexp, 0, len(cfg.Patterns))
	for _, p := range cfg.Patterns {
		if re, err := regexp.Compile(p); err == nil {
			customPatterns = append(customPatterns, re)
		}
	}

	maxBuffer := cfg.MaxBufferBytes
	if maxBuffer <= 0 {
		maxBuffer = dlpMaxBuffer
	}
	// Observe mode must never turn a response into an error the caller sees;
	// config.ApplyObserveMode already clears this, and this is the belt to its
	// braces so a DLP built directly (tests, future callers) cannot block either.
	failClosed := cfg.FailClosed && !cfg.Observe

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Strip the client's Accept-Encoding before the request is proxied.
			// Otherwise the backend may return a gzip/br-compressed body, and DLP
			// would scan the compressed bytes — finding nothing and leaking PII
			// silently. With the header removed, http.Transport transparently adds
			// gzip and DECOMPRESSES the response, so DLP inspects plaintext. (This
			// runs only when DLP is active for the path, since the middleware is
			// gated per-route.)
			r.Header.Del("Accept-Encoding")

			// FIX BUG-3 & BUG-4: Capture status code, headers, AND body
			dw := &dlpWriter{
				ResponseWriter: w,
				buf:            &bytes.Buffer{},
				status:         http.StatusOK,
				log:            log,
				path:           r.URL.Path,
				ip:             RealIP(r),
				ctx:            r.Context(),
				metrics:        st,
				maxBuffer:      maxBuffer,
				failClosed:     failClosed,
			}

			next.ServeHTTP(dw, r)

			// Streaming, protocol upgrades, or oversized responses were passed
			// through directly — nothing left to inspect or write. A refused
			// oversized response has already had its status written.
			if dw.passthrough || dw.refused {
				return
			}

			orig := dw.buf.Bytes()
			mask := []byte("***REDACTED***")

			// Typed pass: classify WHICH data classes are present. Redact returns a
			// new slice, so `orig` is untouched — in observe mode we keep it for the
			// wire and use the classification for reporting only.
			redactedBody, types := classify.Redact(orig, mask)
			found := len(types) > 0

			body := redactedBody
			if cfg.Observe {
				body = orig
			}

			// Custom operator regexes (untyped). Always DETECT; only rewrite when
			// enforcing (observe mode must not modify the response body).
			for _, re := range customPatterns {
				if cfg.Observe {
					if re.Match(body) {
						found = true
					}
					continue
				}
				newBody := re.ReplaceAll(body, mask)
				if len(newBody) != len(body) {
					found = true
				}
				body = newBody
			}

			if found {
				metric, msg := "dlp_redacted", "dlp: sensitive data redacted from response"
				if cfg.Observe {
					metric, msg = "dlp_observed", "dlp: sensitive data detected (observe mode — not redacted)"
				}
				st.IncrMetric(r.Context(), metric)
				// Flag the discovery observation so the catalog can mark this
				// endpoint as exposing sensitive data (drives risk + findings) —
				// this is the pilot's value and runs in both modes.
				if obs := observationFrom(r.Context()); obs != nil {
					obs.PII = true
					obs.PIITypes = types
				}
				log.Info(msg, map[string]any{
					"path":  r.URL.Path,
					"ip":    RealIP(r),
					"types": types,
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
	log         Logger
	path        string
	ip          string
	ctx         context.Context
	metrics     MetricsSink
	maxBuffer   int64
	// failClosed refuses a response too large to inspect rather than streaming
	// it through unscanned; refused records that this has happened, so the outer
	// handler does not then write a body of its own.
	failClosed bool
	refused    bool
}

func (d *dlpWriter) Write(b []byte) (int, error) {
	if d.passthrough {
		return d.ResponseWriter.Write(b)
	}
	// Switch to passthrough if buffering this chunk would exceed the cap. This
	// is a silent inspection gap unless surfaced: a response that would have
	// contained redactable PII sails through unmodified, and nothing else
	// distinguishes "over the cap, not scanned" from "scanned and clean" —
	// record it so operators can see the coverage gap (e.g. tune pagination
	// limits on endpoints that trip this).
	if d.refused {
		return len(b), nil // status already sent; the body is deliberately dropped
	}
	if int64(d.buf.Len()+len(b)) > d.maxBuffer {
		// This response cannot be scanned. Which way that fails is the
		// operator's call, because both directions have a real cost: streaming
		// it through means PII may leave unredacted, and the size of a response
		// is often within the caller's control (a pagination limit, an export
		// range), so passing is a control the caller can switch off. Refusing
		// means a legitimate large response becomes an error.
		if d.failClosed {
			if d.log != nil {
				d.log.Warn("dlp: response exceeds inspection buffer; refusing it (fail_closed)", map[string]any{
					"path": d.path, "ip": d.ip, "max_buffer_bytes": d.maxBuffer,
				})
			}
			if d.metrics != nil {
				d.metrics.IncrMetric(d.ctx, "dlp_blocked_oversized")
			}
			d.refused = true
			d.buf.Reset() // nothing buffered may reach the client
			http.Error(d.ResponseWriter, "Response too large to inspect", http.StatusBadGateway)
			return len(b), nil
		}
		if d.log != nil {
			d.log.Warn("dlp: response exceeds inspection buffer; skipping DLP for this response", map[string]any{
				"path": d.path, "ip": d.ip, "max_buffer_bytes": d.maxBuffer,
			})
		}
		if d.metrics != nil {
			d.metrics.IncrMetric(d.ctx, "dlp_skipped_oversized")
		}
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
	// Non-inspectable responses must not be buffered — switch to passthrough and
	// emit the header immediately. This covers protocol upgrades, server-sent
	// events, and bodies still carrying a content encoding we cannot decode
	// (defence in depth: Accept-Encoding is stripped upstream, so a compressed
	// body here means the backend ignored that and produced bytes DLP cannot
	// scan — we pass them through rather than falsely report a clean scan).
	if enc := d.Header().Get("Content-Encoding"); enc != "" && !strings.EqualFold(enc, "identity") {
		// This is the second of the two ways a response can go uninspected, and
		// it used to behave differently from the first. Oversized bodies honour
		// fail_closed and increment a metric; an undecodable encoding did
		// neither — it logged and passed the body through, whatever the operator
		// had configured.
		//
		// Stripping Accept-Encoding upstream is a request to the backend, not a
		// constraint on it: an nginx in front of the app, a CDN, or a
		// compression middleware that ignores the header all produce a
		// compressed body anyway. When one does, fail_closed silently stopped
		// meaning what it says — an uninspected response reached the client.
		//
		// Both paths now answer to the same switch, and both are counted, so
		// the coverage gap is visible rather than inferred from its absence.
		if d.failClosed {
			if d.log != nil {
				d.log.Warn("dlp: response carries an undecodable content-encoding; refusing it (fail_closed)",
					map[string]any{"path": d.path, "ip": d.ip, "content_encoding": enc})
			}
			if d.metrics != nil {
				d.metrics.IncrMetric(d.ctx, "dlp_blocked_encoding")
			}
			d.refused = true
			d.buf.Reset()
			d.wroteHeader = true
			http.Error(d.ResponseWriter, "Response encoding cannot be inspected", http.StatusBadGateway)
			return
		}
		if d.log != nil {
			d.log.Warn("dlp: response carries an undecodable content-encoding; skipping inspection", map[string]any{
				"path":             d.path,
				"content_encoding": enc,
			})
		}
		if d.metrics != nil {
			d.metrics.IncrMetric(d.ctx, "dlp_skipped_encoding")
		}
		d.passthrough = true
		d.wroteHeader = true
		d.ResponseWriter.WriteHeader(code)
		return
	}
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

// Flush implements http.Flusher. In buffering mode it is deliberately a NO-OP:
// we must hold the body for inspection. The reverse proxy calls Flush eagerly
// for any response with Content-Length: -1 (chunked / unknown length — the norm
// for a JSON API that does not set Content-Length). Honouring that flush here
// would emit the body BEFORE classify.Redact runs, silently bypassing DLP on
// every chunked response — the scanner would never see the bytes and no
// redaction would be logged. Genuine streams that must not be stalled (SSE,
// protocol upgrades) already flipped to passthrough in WriteHeader/Hijack, so a
// Flush reached in buffering mode is never such a stream. Memory stays bounded:
// once the buffer cap is hit, Write() switches to passthrough on its own.
func (d *dlpWriter) Flush() {
	if !d.passthrough {
		return
	}
	// ResponseController, not a direct d.ResponseWriter.(http.Flusher): the
	// writer directly beneath DLP is AbuseDetection's captureWriter, which
	// exposes the real connection via Unwrap and has no Flush method of its
	// own, so the assertion silently failed and the flush went nowhere.
	//nolint:errcheck // best-effort: a writer that cannot flush simply buffers
	http.NewResponseController(d.ResponseWriter).Flush()
}

// Hijack implements http.Hijacker so WebSocket and other connection upgrades
// proxied through the gateway continue to work.
func (d *dlpWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	// Same reason as Flush above: the writer beneath is Unwrap-only, so a direct
	// http.Hijacker assertion failed and every WebSocket upgrade through the
	// gateway answered 502 with "dlp: underlying ResponseWriter does not support
	// hijacking" — despite this method existing precisely to make them work.
	conn, rw, err := http.NewResponseController(d.ResponseWriter).Hijack()
	if err != nil {
		return nil, nil, fmt.Errorf("dlp: hijack: %w", err)
	}
	d.passthrough = true
	return conn, rw, nil
}
