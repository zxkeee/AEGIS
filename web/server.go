// Command aegis-site serves the AEGIS visiting-card static site and captures
// pilot-request form submissions to a JSONL file. Standard library only, so it
// builds to a single static binary and runs anywhere.
//
//	go run . -addr :8090
//	# then open http://localhost:8090
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/smtp"
	"os"
	"strings"
	"sync"
	"time"
)

func main() {
	addr := flag.String("addr", ":8090", "listen address")
	dir := flag.String("dir", ".", "directory of static site files")
	out := flag.String("out", "pilot-requests.jsonl", "file to append pilot requests to")
	flag.Parse()

	srv := &site{
		dir:  *dir,
		out:  *out,
		seen: map[string][]time.Time{},
		// TRUST_PROXY_HEADERS opts into reading CF-Connecting-IP/X-Forwarded-For
		// as the client IP. Off by default: this binary has no notion of "trusted
		// proxies" like the gateway does (internal/middleware.RealIP), so trusting
		// a client-settable header unconditionally would let a direct request (or
		// one from anywhere the origin isn't fully hidden behind the proxy that's
		// assumed to set these) forge a fresh IP per request — bypassing allow()'s
		// rate limit entirely and growing `seen` without bound. Set it only when
		// this binary is deployed so the origin is truly unreachable except
		// through the header-setting proxy (e.g. Cloudflare with no direct-origin
		// DNS record).
		trustProxyHeaders: os.Getenv("TRUST_PROXY_HEADERS") != "",
		sendSem:           make(chan struct{}, smtpConcurrency),
	}
	if mc, ok := mailFromEnv(); ok {
		srv.mail = &mc
		log.Printf("email delivery enabled: %s -> %s via %s", mc.from, mc.to, mc.host)
	} else {
		log.Printf("email delivery disabled (set SMTP_USER, SMTP_PASS, MAIL_TO to enable); submissions saved to file only")
	}
	if !srv.trustProxyHeaders {
		log.Printf("proxy headers (CF-Connecting-IP/X-Forwarded-For) not trusted — using the raw connection IP; set TRUST_PROXY_HEADERS=1 only if this binary sits unreachably behind a proxy that sets them")
	}

	// Periodically sweep `seen` so its memory is bounded by recently-active
	// IPs, not by every distinct value ever seen. allow() also filters its own
	// per-key window, but that only shrinks a key already looked up — an IP
	// that submits once and never returns would otherwise sit in the map
	// forever. Independent of whether proxy headers are trusted: even the raw
	// connection IP accumulates one entry per distinct visitor over the life
	// of a long-running process.
	go srv.sweepLoop()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/pilot", srv.pilot)
	mux.Handle("/", srv.static())

	s := &http.Server{
		Addr:              *addr,
		Handler:           securityHeaders(mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
	}
	log.Printf("aegis-site listening on %s (serving %q, capturing to %q)", *addr, *dir, *out)
	log.Fatal(s.ListenAndServe())
}

// smtpConcurrency bounds concurrent outbound SMTP sends. Each /api/pilot
// success previously spawned an unbounded goroutine, so a burst of
// submissions could open arbitrarily many simultaneous SMTP connections; a
// send that hangs (a slow/unresponsive mail server) held its goroutine open
// indefinitely with nothing capping how many accumulated.
const smtpConcurrency = 8

// seenMaxIPs is a hard ceiling on distinct IPs tracked between sweeps — a
// circuit breaker of last resort. sweepLoop keeps steady-state memory bounded
// by recent activity, but a sudden burst between sweep ticks could otherwise
// still grow the map arbitrarily large before the next sweep runs.
const seenMaxIPs = 50_000

// seenSweepInterval is how often sweep() runs. Independent of the 10-minute
// rate-limit window itself so a low-traffic period doesn't leave stale entries
// resident for hours.
const seenSweepInterval = 5 * time.Minute

type site struct {
	dir               string
	out               string
	mail              *mailCfg
	trustProxyHeaders bool
	sendSem           chan struct{} // semaphore bounding concurrent SMTP sends
	mu                sync.Mutex
	seen              map[string][]time.Time // per-IP submit timestamps (rate limit)
}

// mailCfg holds SMTP delivery settings, all sourced from the environment so no
// secret ever lives in code or the image.
type mailCfg struct {
	host, port, user, pass, from, to string
}

func mailFromEnv() (mailCfg, bool) {
	c := mailCfg{
		host: envOr("SMTP_HOST", "smtp.gmail.com"),
		port: envOr("SMTP_PORT", "587"),
		user: os.Getenv("SMTP_USER"),
		pass: os.Getenv("SMTP_PASS"),
		to:   os.Getenv("MAIL_TO"),
	}
	c.from = envOr("MAIL_FROM", c.user)
	if c.user == "" || c.pass == "" || c.to == "" {
		return c, false
	}
	return c, true
}

// send delivers one submission as a plain-text email. Header fields are stripped
// of CR/LF to prevent SMTP header injection via the user-supplied email address.
func (c *mailCfg) send(rec pilotRecord) error {
	subject := hdr("New AEGIS pilot request — " + firstNonEmpty(rec.Company, rec.Name))
	body := fmt.Sprintf(
		"Name:    %s\r\nEmail:   %s\r\nCompany: %s\r\nTraffic: %s\r\n\r\n%s\r\n\r\n—\r\nreceived %s · ip %s\r\nua %s\r\n",
		rec.Name, rec.Email, rec.Company, rec.Scale, rec.Message, rec.At, rec.IP, rec.UA)
	msg := "From: AEGIS site <" + hdr(c.from) + ">\r\n" +
		"To: " + hdr(c.to) + "\r\n" +
		"Reply-To: " + hdr(rec.Email) + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"MIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n" + body
	auth := smtp.PlainAuth("", c.user, c.pass, c.host)
	return smtp.SendMail(c.host+":"+c.port, auth, c.from, []string{c.to}, []byte(msg))
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

// hdr strips characters that could break out of an email header / log line.
func hdr(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r < 0x20 {
			return -1
		}
		return r
	}, s)
}

// static serves the site files but never lists directories.
func (s *site) static() http.Handler {
	fs := http.FileServer(http.Dir(s.dir))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/") && r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		fs.ServeHTTP(w, r)
	})
}

type pilotReq struct {
	Name    string `json:"name"`
	Email   string `json:"email"`
	Company string `json:"company"`
	Scale   string `json:"scale"`
	Message string `json:"message"`
}

type pilotRecord struct {
	pilotReq
	At string `json:"at"`
	IP string `json:"ip"`
	UA string `json:"ua"`
}

func (s *site) pilot(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ip := s.clientIP(r)
	if !s.allow(ip) {
		writeJSON(w, http.StatusTooManyRequests, map[string]any{"ok": false, "error": "rate limited"})
		return
	}

	var req pilotReq
	if err := json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid body"})
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	req.Email = strings.TrimSpace(req.Email)
	if req.Name == "" || !strings.Contains(req.Email, "@") {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "name and a valid email are required"})
		return
	}
	// Cap field sizes so a bad actor can't bloat the capture file.
	req.Name = clip(req.Name, 200)
	req.Email = clip(req.Email, 200)
	req.Company = clip(strings.TrimSpace(req.Company), 200)
	req.Scale = clip(strings.TrimSpace(req.Scale), 60)
	req.Message = clip(strings.TrimSpace(req.Message), 4000)

	rec := pilotRecord{pilotReq: req, At: time.Now().UTC().Format(time.RFC3339), IP: ip, UA: clip(r.UserAgent(), 300)}
	if err := s.append(rec); err != nil {
		log.Printf("pilot: append failed: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "could not save"})
		return
	}
	// Email delivery is best-effort and async: the file save already succeeded,
	// so a slow/failed SMTP never blocks or fails the visitor's request. The
	// semaphore bounds how many sends run concurrently (smtpConcurrency); a
	// non-blocking acquire means a saturated semaphore drops the send (logged)
	// rather than piling up an unbounded goroutine queue behind it — the
	// submission is never lost, since it's already durably on disk.
	if s.mail != nil {
		select {
		case s.sendSem <- struct{}{}:
			go func(m *mailCfg, rec pilotRecord) {
				defer func() { <-s.sendSem }()
				if err := m.send(rec); err != nil {
					log.Printf("pilot: email send failed (saved to file): %v", err)
				}
			}(s.mail, rec)
		default:
			log.Printf("pilot: email send skipped (already %d in flight, saved to file)", smtpConcurrency)
		}
	}
	// #nosec G706 -- every field is passed through hdr() (strips CR/LF/control
	// chars), gosec's taint tracker just doesn't recognise a local sanitizer.
	log.Printf("pilot request: %s <%s> company=%q ip=%s", hdr(rec.Name), hdr(rec.Email), hdr(rec.Company), hdr(ip))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *site) append(rec pilotRecord) error {
	line, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := os.OpenFile(s.out, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	_, err = f.Write(append(line, '\n'))
	return err
}

// allow permits at most 5 submissions per IP per 10 minutes.
func (s *site) allow(ip string) bool {
	const limit, window = 5, 10 * time.Minute
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	var kept []time.Time
	for _, t := range s.seen[ip] {
		if now.Sub(t) < window {
			kept = append(kept, t)
		}
	}
	if len(kept) >= limit {
		s.seen[ip] = kept
		return false
	}
	// Hard ceiling on distinct IPs (seenMaxIPs): refuse a BRAND NEW key once
	// hit, rather than growing the map further — a burst spanning many fake
	// IPs between sweepLoop ticks would otherwise still be unbounded. An IP
	// already tracked (kept non-empty, i.e. seen before, or just evaluated
	// above) is unaffected; this only turns away first-time keys.
	if _, tracked := s.seen[ip]; !tracked && len(s.seen) >= seenMaxIPs {
		return false
	}
	s.seen[ip] = append(kept, now)
	return true
}

// sweepLoop periodically calls sweep until the process exits.
func (s *site) sweepLoop() {
	t := time.NewTicker(seenSweepInterval)
	defer t.Stop()
	for range t.C {
		s.sweep()
	}
}

// sweep drops every tracked IP with no submission inside the rate-limit
// window, bounding steady-state memory to recently-active visitors instead of
// every distinct IP ever seen over the life of the process.
func (s *site) sweep() {
	const window = 10 * time.Minute
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for ip, times := range s.seen {
		var kept []time.Time
		for _, t := range times {
			if now.Sub(t) < window {
				kept = append(kept, t)
			}
		}
		if len(kept) == 0 {
			delete(s.seen, ip)
		} else {
			s.seen[ip] = kept
		}
	}
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
}

// clientIP returns the address allow() and the pilot-request log rate-limit
// on. Proxy-supplied headers (CF-Connecting-IP, X-Forwarded-For) are trusted
// ONLY when trustProxyHeaders is set (TRUST_PROXY_HEADERS env var) — both are
// plain client-settable request headers a direct request can set to any
// value, so trusting them unconditionally would let a single attacker forge a
// fresh claimed IP on every request: allow()'s per-IP limit would never
// engage for them, and (before sweep()/seenMaxIPs) `seen` would grow one
// entry per forged value forever. See main()'s comment on trustProxyHeaders
// for when it's actually safe to opt in.
func (s *site) clientIP(r *http.Request) string {
	if s.trustProxyHeaders {
		if cf := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); cf != "" {
			return cf
		}
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			if i := strings.IndexByte(xff, ','); i >= 0 {
				return strings.TrimSpace(xff[:i])
			}
			return strings.TrimSpace(xff)
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
