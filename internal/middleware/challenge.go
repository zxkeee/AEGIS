package middleware

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"api-gateway/internal/config"
)

// Challenge presents a JavaScript challenge to suspicious clients.
func Challenge(cfg config.ChallengeConfig, log Logger, st Store) Middleware {
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

			// Check if already solved
			solved, _ := st.IsChallengeSolved(r.Context(), ip)
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

			// Issue a new challenge
			challengeToken := generateToken()
			st.IssueChallenge(r.Context(), ip, challengeToken, ttl) //nolint:errcheck

			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusForbidden)
			_, _ = fmt.Fprintf(w, challengeHTML, challengeToken)
		})
	}
}

func generateToken() string {
	b := make([]byte, 16)
	rand.Read(b) //nolint:errcheck
	return hex.EncodeToString(b)
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
  var t = "%s";
  var x = new XMLHttpRequest();
  x.open("GET", window.location.href, true);
  x.setRequestHeader("X-Challenge-Token", t);
  x.onload = function(){ window.location.reload(); };
  setTimeout(function(){ x.send(); }, 1500);
})();
</script>
</div>
</body>
</html>`
