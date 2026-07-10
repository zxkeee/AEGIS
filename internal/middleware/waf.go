package middleware

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"api-gateway/internal/config"
	"api-gateway/internal/secevent"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
	txhttp "github.com/corazawaf/coraza/v3/http"
	"github.com/jcchavezs/mergefs"
	mergefsio "github.com/jcchavezs/mergefs/io"
)

// jsonBodyDirectives make Coraza inspect JSON / typed / untyped request bodies.
// Coraza only auto-selects the urlencoded and multipart processors, so without
// these an application/json body (the API norm) is never flattened into ARGS and
// every body-borne payload bypasses the rules simply by picking a Content-Type.
// Applied in both the built-in and OWASP-CRS modes.
const jsonBodyDirectives = `
	SecRule REQUEST_HEADERS:Content-Type "@rx ^application/(?:[a-z0-9.+-]+\+)?json" \
		"id:10000,phase:1,pass,nolog,ctl:requestBodyProcessor=JSON"
	SecRule REQUEST_HEADERS:Content-Type "!@rx (?i)^(?:application/(?:[a-z0-9.+-]+\+)?json|application/x-www-form-urlencoded|multipart/form-data)" \
		"id:10013,phase:1,pass,nolog,ctl:forceRequestBodyVariable=On"
	SecRule &REQUEST_HEADERS:Content-Type "@eq 0" \
		"id:10014,phase:1,pass,nolog,ctl:forceRequestBodyVariable=On"
`

// xxeScanLimit bounds how much of an XML body the XXE pre-filter reads. A DTD
// (DOCTYPE/ENTITY) is always in the prologue at the very top of the document, so
// the first few KB are sufficient; the rest streams to Coraza and the backend
// untouched.
const xxeScanLimit = 8 << 10 // 8 KB

// xxeMarkerRE matches the structural signature of an XML external-entity attack:
// a DOCTYPE or ENTITY declaration that references an external SYSTEM/PUBLIC id.
// Mirrors the built-in ruleset's id:10008. It is deliberately specific so it
// does NOT fire on an ordinary "<?xml …?>" declaration or benign markup.
var xxeMarkerRE = regexp.MustCompile(`(?i)<!(?:DOCTYPE|ENTITY)\s[^>]*(?:SYSTEM|PUBLIC)\s`)

// isXMLContentType reports whether a Content-Type denotes XML (application/xml,
// text/xml, or any structured +xml suffix such as application/soap+xml).
func isXMLContentType(ct string) bool {
	ct = strings.ToLower(ct)
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	ct = strings.TrimSpace(ct)
	return ct == "application/xml" || ct == "text/xml" || strings.HasSuffix(ct, "+xml")
}

// screenXXE checks an XML request body for the XXE structural marker WITHOUT
// consuming it: it reads the bounded head, tests the marker, and rewinds the
// body (head + untouched remainder) so Coraza and the backend still see the full
// stream. Returns true when an XXE payload is present.
//
// This exists because OWASP CRS v4 does not reliably catch XXE — its XML body
// processor consumes the DTD prologue, so REQUEST_BODY never contains it, and
// forcing raw inspection instead false-positives on the "<?xml" declaration via
// the PHP-open-tag rules. Screening in Go, before Coraza, closes that gap with
// no false positives and works regardless of paranoia level. Without it,
// enabling use_crs would SILENTLY DROP the XXE protection the built-in ruleset
// provides via id:10008 — a regression exactly when an operator "upgrades" to
// CRS for production.
func screenXXE(r *http.Request) bool {
	if r.Body == nil || !isXMLContentType(r.Header.Get("Content-Type")) {
		return false
	}
	head := make([]byte, xxeScanLimit)
	n, _ := io.ReadFull(r.Body, head)
	head = head[:n]
	// Rewind: the backend/Coraza must still read the complete body.
	r.Body = struct {
		io.Reader
		io.Closer
	}{io.MultiReader(bytes.NewReader(head), r.Body), r.Body}
	return xxeMarkerRE.Match(head)
}

// WAF provides Web Application Firewall protection using Coraza (OWASP CRS).
// Protects against: SQL Injection, XSS, RCE, LFI, SSRF, XXE, Log4Shell, and more.
func WAF(cfg config.WAFConfig, log Logger, st wafStore) Middleware {
	if !cfg.Enabled {
		return passthrough
	}

	// Built-in starter rules covering the OWASP Top 10 (used unless use_crs).
	directives := `
		SecRuleEngine On
		SecRequestBodyAccess On
		SecResponseBodyAccess Off
		SecRequestBodyLimit 13107200
		SecRequestBodyNoFilesLimit 131072
		# Reject (don't silently scan-partial) a body over the limit, so an
		# attacker cannot hide a payload past the 13 MB mark in an unscanned tail.
		# Operators with legitimately larger uploads should raise SecRequestBodyLimit.
		SecRequestBodyLimitAction Reject

		# Enable JSON request-body parsing. Coraza only auto-selects the urlencoded
		# and multipart body processors; without this an application/json body (the
		# API norm) is never flattened into ARGS, so every body-borne SQLi/XSS/RCE
		# payload bypasses the rules below simply by setting Content-Type: json.
		# Runs in phase 1 (before the body is read) and matches json and +json
		# media types (e.g. application/vnd.api+json).
		SecRule REQUEST_HEADERS:Content-Type "@rx ^application/(?:[a-z0-9.+-]+\+)?json" \
			"id:10000,phase:1,pass,nolog,ctl:requestBodyProcessor=JSON"

		# Force raw-body inspection for content types Coraza has no structured
		# processor for (text/plain, text/xml, application/octet-stream, unknown).
		# Without this REQUEST_BODY is never populated for them, so a body-borne
		# payload bypasses every rule below simply by picking such a Content-Type
		# (this also makes the XXE rule effective on text/xml). JSON, urlencoded and
		# multipart keep their own parsers and are excluded.
		SecRule REQUEST_HEADERS:Content-Type "!@rx (?i)^(?:application/(?:[a-z0-9.+-]+\+)?json|application/x-www-form-urlencoded|multipart/form-data)" \
			"id:10013,phase:1,pass,nolog,ctl:forceRequestBodyVariable=On"

		# Same, for requests that send a body with NO Content-Type header at all
		# (Coraza selects no processor, so REQUEST_BODY would otherwise stay empty).
		SecRule &REQUEST_HEADERS:Content-Type "@eq 0" \
			"id:10014,phase:1,pass,nolog,ctl:forceRequestBodyVariable=On"

		# SQL Injection. REQUEST_HEADERS is inspected too (minus Authorization, a
		# base64 JWT, and Cookie, already covered by REQUEST_COOKIES) so a payload
		# in an arbitrary header like X-Search cannot reach a header-trusting backend.
		SecRule ARGS|ARGS_NAMES|REQUEST_COOKIES|REQUEST_BODY|REQUEST_HEADERS|!REQUEST_HEADERS:Authorization|!REQUEST_HEADERS:Cookie "@rx (?i)(?:union\s+select|select\s+(?:@@|from|count)|(?:insert|update|delete)\s+(?:into|from|set)|drop\s+(?:table|database)|alter\s+table|exec\s*\()" \
			"id:10001,phase:2,deny,status:403,log,msg:'SQL Injection',tag:'sqli',severity:CRITICAL"

		SecRule ARGS|REQUEST_BODY "@rx (?i)(?:'\s*(?:or|and|union|select|insert|delete|drop)\s|--\s*$|/\*.*?\*/)" \
			"id:10002,phase:2,deny,status:403,log,msg:'SQL Injection (Boolean)',tag:'sqli',severity:CRITICAL"

		# XSS
		SecRule ARGS|ARGS_NAMES|REQUEST_COOKIES|REQUEST_BODY|REQUEST_HEADERS|!REQUEST_HEADERS:Authorization|!REQUEST_HEADERS:Cookie "@rx (?i)(?:<script|javascript:|on(?:error|load|click|mouseover)\s*=)" \
			"id:10003,phase:2,deny,status:403,log,msg:'XSS Attack',tag:'xss',severity:CRITICAL"

		SecRule ARGS|REQUEST_BODY "@rx (?i)(?:eval\s*\(|document\.(?:cookie|write|location)|\.innerHTML\s*=|alert\s*\()" \
			"id:10004,phase:2,deny,status:403,log,msg:'XSS (DOM)',tag:'xss',severity:CRITICAL"

		# Command Injection
		SecRule ARGS|REQUEST_BODY|REQUEST_HEADERS|!REQUEST_HEADERS:Authorization|!REQUEST_HEADERS:Cookie "@rx (?i)(?:;\s*(?:ls|cat|id|whoami|wget|curl|bash|sh|python|perl|php)\b)" \
			"id:10005,phase:2,deny,status:403,log,msg:'Command Injection',tag:'rce',severity:CRITICAL"

		# Path Traversal / LFI
		SecRule ARGS|REQUEST_URI|REQUEST_BODY "@rx (?:(?:\.\./){2,}|/etc/(?:passwd|shadow)|/proc/self)" \
			"id:10006,phase:2,deny,status:403,log,msg:'Path Traversal',tag:'lfi',severity:CRITICAL"

		# SSRF
		SecRule ARGS|REQUEST_BODY "@rx (?i)(?:(?:https?|ftp|file)://(?:127\.|10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|localhost|\[::1\]|169\.254\.))" \
			"id:10007,phase:2,deny,status:403,log,msg:'SSRF Attempt',tag:'ssrf',severity:CRITICAL"

		# XXE
		SecRule REQUEST_BODY "@rx (?i)(?:<!(?:DOCTYPE|ENTITY)\s.*(?:SYSTEM|PUBLIC)\s)" \
			"id:10008,phase:2,deny,status:403,log,msg:'XXE Attack',tag:'xxe',severity:CRITICAL"

		# Invalid HTTP Method
		SecRule REQUEST_METHOD "!@rx ^(?:GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)$" \
			"id:10009,phase:1,deny,status:405,log,msg:'Invalid HTTP Method',tag:'protocol',severity:WARNING"

		# Scanner Detection
		SecRule REQUEST_HEADERS:User-Agent "@rx (?i)(?:nikto|sqlmap|nmap|dirbuster|gobuster|wpscan|hydra|burpsuite|zaproxy|acunetix|nessus)" \
			"id:10010,phase:1,deny,status:403,log,msg:'Scanner Detected',tag:'scanner',severity:WARNING"

		# Log4Shell / JNDI
		SecRule ARGS|ARGS_NAMES|REQUEST_COOKIES|REQUEST_HEADERS|REQUEST_BODY "@rx (?i)(?:\$\{(?:jndi|lower|upper|env|sys|java):)" \
			"id:10011,phase:2,deny,status:403,log,msg:'Log4Shell/JNDI',tag:'rce',severity:CRITICAL"

		# Request Smuggling
		SecRule REQUEST_HEADERS:Transfer-Encoding "@rx (?i)(?:chunked.*,.*chunked)" \
			"id:10012,phase:1,deny,status:400,log,msg:'Request Smuggling',tag:'protocol',severity:CRITICAL"
	`

	waf, err := buildCorazaWAF(cfg, directives)
	if err != nil {
		log.Error("waf: failed to initialize", map[string]any{"error": err.Error()})
		return passthrough
	}

	if cfg.UseCRS {
		log.Info("waf: OWASP CRS v4 engine ready", map[string]any{
			"paranoia_level":    firstPositive(cfg.ParanoiaLevel, 1),
			"anomaly_threshold": firstPositive(cfg.AnomalyThreshold, 5),
			"block_mode":        cfg.BlockMode,
		})
	} else {
		log.Info("waf: Coraza engine ready (built-in rules)", map[string]any{
			"rules":      12,
			"block_mode": cfg.BlockMode,
		})
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// XXE pre-filter (CRS mode only — the built-in ruleset already blocks
			// XXE via id:10008). CRS v4 does not reliably detect XXE, so screen the
			// XML body here before Coraza. Enforce only in block mode, matching CRS's
			// detection-vs-blocking semantics; in detection mode we log and continue.
			if cfg.UseCRS && screenXXE(r) {
				ip := RealIP(r)
				if cfg.BlockMode {
					st.IncrMetric(r.Context(), "waf_blocked")
					st.IncrBehaviorScore(r.Context(), ip, 15)
					log.BlockEvent("waf_xxe_blocked", ip, r.URL.Path, r.Method, map[string]any{"status": http.StatusForbidden})
					st.PushForensic(r.Context(), secevent.Entry{
						Timestamp: time.Now().UTC(), IP: ip, Path: r.URL.Path,
						Method: r.Method, Reason: "waf_xxe_blocked", Code: http.StatusForbidden,
					})
					http.Error(w, "Forbidden", http.StatusForbidden)
					return
				}
				log.Warn("waf: XXE payload detected (detection mode, not blocked)", map[string]any{
					"ip": ip, "path": r.URL.Path,
				})
			}

			// Distinguish a real WAF interruption from a downstream response. Coraza
			// calls next ONLY when it does NOT block, so a closure-captured flag set
			// by this sentinel tells us the request reached the backend. Without it,
			// an upstream 403/400/405 was indistinguishable from a Coraza block and
			// was mis-counted as waf_blocked (inflating metrics/forensics AND adding a
			// behaviour penalty toward auto-ban for clients hitting endpoints that
			// legitimately return those statuses).
			reached := false
			sentinel := http.HandlerFunc(func(sw http.ResponseWriter, sr *http.Request) {
				reached = true
				next.ServeHTTP(sw, sr)
			})

			sw := &wafStatusWriter{ResponseWriter: w, status: 200}
			txhttp.WrapHandler(waf, sentinel).ServeHTTP(sw, r)

			// A WAF block: the request never reached the backend and Coraza wrote a
			// block status. If it reached the backend, the status is the upstream's.
			if !reached && (sw.status == 403 || sw.status == 400 || sw.status == 405) {
				ip := RealIP(r)
				st.IncrMetric(r.Context(), "waf_blocked")
				st.IncrBehaviorScore(r.Context(), ip, 15)
				log.BlockEvent("waf_rule_triggered", ip, r.URL.Path, r.Method, map[string]any{
					"status": sw.status,
				})
				st.PushForensic(r.Context(), secevent.Entry{
					Timestamp: time.Now().UTC(),
					IP:        ip,
					Path:      r.URL.Path,
					Method:    r.Method,
					Reason:    "waf_blocked",
					Code:      sw.status,
				})
			} else if reached {
				st.IncrMetric(r.Context(), "requests_passed_waf")
			}
		})
	}
}

// buildCorazaWAF assembles the Coraza engine. In CRS mode it loads the full
// OWASP Core Rule Set v4 (embedded via coraza-coreruleset) with anomaly scoring
// at the configured paranoia level and threshold; otherwise it uses the built-in
// starter directives. A RulesetPath is included last as operator overrides
// (e.g. SecRuleRemoveById for a tuned-out false positive).
func buildCorazaWAF(cfg config.WAFConfig, builtin string) (coraza.WAF, error) {
	if cfg.UseCRS {
		pl := firstPositive(cfg.ParanoiaLevel, 1)
		at := firstPositive(cfg.AnomalyThreshold, 5)
		// @coraza.conf-recommended ships SecRuleEngine DetectionOnly. Enforce only
		// in block mode; otherwise stay DetectionOnly (monitor: score + log, no
		// block) so operators can tune out false positives before enforcing.
		engine := "DetectionOnly"
		if cfg.BlockMode {
			engine = "On"
		}
		directives := fmt.Sprintf(`
Include @coraza.conf-recommended
SecRuleEngine %s
Include @crs-setup.conf.example
SecAction "id:9005000,phase:1,nolog,pass,t:none,setvar:tx.blocking_paranoia_level=%d,setvar:tx.detection_paranoia_level=%d,setvar:tx.inbound_anomaly_score_threshold=%d,setvar:tx.outbound_anomaly_score_threshold=%d"
%s
Include @owasp_crs/*.conf
`, engine, pl, pl, at, at, jsonBodyDirectives)

		wafCfg := coraza.NewWAFConfig().
			WithRootFS(mergefs.Merge(coreruleset.FS, mergefsio.OSFS)).
			WithDirectives(directives)
		if cfg.RulesetPath != "" {
			wafCfg = wafCfg.WithDirectivesFromFile(cfg.RulesetPath)
		}
		return coraza.NewWAF(wafCfg)
	}

	wafCfg := coraza.NewWAFConfig()
	if cfg.RulesetPath != "" {
		wafCfg = wafCfg.WithDirectivesFromFile(cfg.RulesetPath)
	}
	return coraza.NewWAF(wafCfg.WithDirectives(builtin))
}

// firstPositive returns v when it is > 0, else the fallback default.
func firstPositive(v, def int) int {
	if v > 0 {
		return v
	}
	return def
}

type wafStatusWriter struct {
	http.ResponseWriter
	status int
}

func (w *wafStatusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

// Unwrap exposes the underlying writer to http.ResponseController (Flush/Hijack
// pass-through for SSE and WebSocket).
func (w *wafStatusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
