package middleware

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"api-gateway/internal/config"
)

// challengeStore is ChallengeStore plus the metric sink needed to make a
// store-outage fail-open visible to operators.
type challengeStore interface {
	ChallengeStore
	MetricsSink
}

// Challenge presents a JavaScript challenge to suspicious clients.
func Challenge(cfg config.ChallengeConfig, log Logger, st challengeStore) Middleware {
	if !cfg.Enabled {
		return passthrough
	}

	ttl := cfg.TTL
	if ttl == 0 {
		ttl = 5 * time.Minute
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := RealIP(r)

			// Check if already solved. A store error here has no safe
			// fail-closed option (audit finding, 2026-08-22): the discarded
			// error used to make `solved` default to false, falling through
			// to IssueChallenge below — which ALSO hits the same down store,
			// so the client can never solve its way out. Every request on
			// every Challenge-enabled route would 403 forever until the
			// store recovers. Challenge is a soft anti-bot friction control,
			// not a hard block (its own doc comment: "not bot-proof by
			// design"), so fail open here — matching Behavior/Bot/ThreatFeed's
			// stance elsewhere in this codebase — and make the gap visible
			// via a log line and metric rather than leaving it silent.
			solved, err := st.IsChallengeSolved(r.Context(), ip)
			if err != nil {
				log.Warn("challenge: store unavailable, failing open", map[string]any{"error": err.Error(), "ip": ip})
				st.IncrMetric(r.Context(), "challenge_store_unavailable")
				next.ServeHTTP(w, r)
				return
			}
			if solved {
				next.ServeHTTP(w, r)
				return
			}

			// Check for challenge response
			token := r.Header.Get("X-Challenge-Token")
			if token != "" {
				valid, _ := st.IsValidChallengeToken(r.Context(), ip, token)
				if valid {
					st.MarkChallengeSolved(r.Context(), ip, ttl) //nolint:errcheck
					next.ServeHTTP(w, r)
					return
				}
			}

			// Issue a new challenge. The page embeds a random seed; the client
			// must send back challengeAnswer(seed), which the embedded JS
			// computes. Only the ANSWER is stored server-side, so a client that
			// merely scrapes the seed out of the HTML and echoes it back does
			// not pass — it has to execute (or reimplement) the transform. This
			// raises the bar for trivial scripted clients; it is not bot-proof
			// (a headless browser or a client implementing FNV-1a passes by
			// design).
			seed := generateToken()
			st.IssueChallenge(r.Context(), ip, challengeAnswer(seed), ttl) //nolint:errcheck

			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusForbidden)
			_, _ = fmt.Fprintf(w, challengeHTML, seed)
		})
	}
}

func generateToken() string {
	b := make([]byte, 16)
	rand.Read(b) //nolint:errcheck
	return hex.EncodeToString(b)
}

// challengeAnswer derives the expected X-Challenge-Token from the page seed:
// 32-bit FNV-1a over the seed string, hex-encoded (8 chars, zero-padded). The
// JS in challengeHTML computes the identical value — Math.imul gives the same
// exact 32-bit multiplication semantics as Go's uint32 arithmetic.
func challengeAnswer(seed string) string {
	h := uint32(2166136261) // FNV-1a offset basis
	for i := 0; i < len(seed); i++ {
		h ^= uint32(seed[i])
		h *= 16777619 // FNV-1a prime
	}
	return fmt.Sprintf("%08x", h)
}

const challengeHTML = `<!DOCTYPE html>
<html>
<head><title>Security Check</title></head>
<body style="background:#000;color:#fff;font-family:monospace;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;">
<div style="text-align:center;">
<h2>⚡ Verifying your connection...</h2>
<p>This is an automated security check. Please wait.</p>
<script>
(function(){
  var seed = "%s";
  // FNV-1a 32-bit over the seed — must match challengeAnswer() on the server.
  var h = 0x811c9dc5;
  for (var i = 0; i < seed.length; i++) {
    h ^= seed.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  var answer = ("00000000" + h.toString(16)).slice(-8);
  var x = new XMLHttpRequest();
  x.open("GET", window.location.href, true);
  x.setRequestHeader("X-Challenge-Token", answer);
  x.onload = function(){ window.location.reload(); };
  setTimeout(function(){ x.send(); }, 1500);
})();
</script>
</div>
</body>
</html>`
