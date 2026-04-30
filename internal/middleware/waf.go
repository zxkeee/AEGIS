package middleware

import (
	"net/http"
	"time"

	"api-gateway/internal/config"
	"api-gateway/internal/store"

	"github.com/corazawaf/coraza/v3"
	txhttp "github.com/corazawaf/coraza/v3/http"
)

// WAF provides Web Application Firewall protection using Coraza (OWASP CRS).
// Protects against: SQL Injection, XSS, RCE, LFI, SSRF, XXE, Log4Shell, and more.
func WAF(cfg config.WAFConfig, log Logger, st Store) Middleware {
	if !cfg.Enabled {
		return passthrough
	}

	wafCfg := coraza.NewWAFConfig()

	// Built-in rules covering OWASP Top 10
	directives := `
		SecRuleEngine On
		SecRequestBodyAccess On
		SecResponseBodyAccess Off
		SecRequestBodyLimit 13107200
		SecRequestBodyNoFilesLimit 131072

		# SQL Injection
		SecRule ARGS|ARGS_NAMES|REQUEST_COOKIES|REQUEST_BODY "@rx (?i)(?:union\s+select|select\s+(?:@@|from|count)|(?:insert|update|delete)\s+(?:into|from|set)|drop\s+(?:table|database)|alter\s+table|exec\s*\()" \
			"id:10001,phase:2,deny,status:403,log,msg:'SQL Injection',tag:'sqli',severity:CRITICAL"

		SecRule ARGS|REQUEST_BODY "@rx (?i)(?:'\s*(?:or|and|union|select|insert|delete|drop)\s|--\s*$|/\*.*?\*/)" \
			"id:10002,phase:2,deny,status:403,log,msg:'SQL Injection (Boolean)',tag:'sqli',severity:CRITICAL"

		# XSS
		SecRule ARGS|ARGS_NAMES|REQUEST_COOKIES|REQUEST_BODY "@rx (?i)(?:<script|javascript:|on(?:error|load|click|mouseover)\s*=)" \
			"id:10003,phase:2,deny,status:403,log,msg:'XSS Attack',tag:'xss',severity:CRITICAL"

		SecRule ARGS|REQUEST_BODY "@rx (?i)(?:eval\s*\(|document\.(?:cookie|write|location)|\.innerHTML\s*=|alert\s*\()" \
			"id:10004,phase:2,deny,status:403,log,msg:'XSS (DOM)',tag:'xss',severity:CRITICAL"

		# Command Injection
		SecRule ARGS|REQUEST_BODY "@rx (?i)(?:;\s*(?:ls|cat|id|whoami|wget|curl|bash|sh|python|perl|php)\b)" \
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

	if cfg.RulesetPath != "" {
		wafCfg = wafCfg.WithDirectivesFromFile(cfg.RulesetPath)
	}
	wafCfg = wafCfg.WithDirectives(directives)

	waf, err := coraza.NewWAF(wafCfg)
	if err != nil {
		log.Error("waf: failed to initialize", map[string]any{"error": err.Error()})
		return passthrough
	}

	log.Info("waf: Coraza engine ready", map[string]any{
		"rules":      12,
		"block_mode": cfg.BlockMode,
	})

	return func(next http.Handler) http.Handler {
		wrapped := txhttp.WrapHandler(waf, next)

		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sw := &wafStatusWriter{ResponseWriter: w, status: 200}
			wrapped.ServeHTTP(sw, r)

			if sw.status == 403 || sw.status == 400 || sw.status == 405 {
				ip := RealIP(r)
				st.IncrMetric(r.Context(), "waf_blocked")
				st.IncrBehaviorScore(r.Context(), ip, 15)
				log.BlockEvent("waf_rule_triggered", ip, r.URL.Path, r.Method, map[string]any{
					"status": sw.status,
				})
				st.PushForensic(r.Context(), store.ForensicEntry{
					Timestamp: time.Now().UTC(),
					IP:        ip,
					Path:      r.URL.Path,
					Method:    r.Method,
					Reason:    "waf_blocked",
					Code:      sw.status,
				})
			} else {
				st.IncrMetric(r.Context(), "requests_passed_waf")
			}
		})
	}
}

type wafStatusWriter struct {
	http.ResponseWriter
	status int
}

func (w *wafStatusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}
