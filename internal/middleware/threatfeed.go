package middleware

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"api-gateway/internal/config"
)

const (
	// threatFeedMaxBytes caps the response body to prevent OOM via a malicious feed.
	threatFeedMaxBytes = 10 * 1024 * 1024 // 10 MB
	// threatFeedMaxIPs caps the in-memory blocklist to prevent memory exhaustion.
	threatFeedMaxIPs = 500_000
)

// ThreatFeed blocks IPs from known threat intelligence feeds.
func ThreatFeed(cfg config.ThreatFeedConfig, log Logger, st DenySink) Middleware {
	if !cfg.Enabled || cfg.URL == "" {
		return passthrough
	}

	tf := &threatFeed{
		url:      cfg.URL,
		interval: cfg.Interval,
		log:      log,
		threats:  make(map[string]bool),
	}

	if tf.interval == 0 {
		tf.interval = 1 * time.Hour
	}

	// Initial load
	go tf.refresh()

	// Periodic refresh
	go func() {
		ticker := time.NewTicker(tf.interval)
		defer ticker.Stop()
		for range ticker.C {
			tf.refresh()
		}
	}()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := RealIP(r)

			tf.mu.RLock()
			isThreat := tf.threats[ip]
			tf.mu.RUnlock()

			if isThreat {
				SecurityDeny(w, r, log, st, "threat_feed_blocked", ip, http.StatusForbidden,
					map[string]any{"source": "threat_feed"})
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// checkFeedRedirect is the redirect policy for feed fetches. See safeRedirect.
func checkFeedRedirect(req *http.Request, via []*http.Request) error {
	return safeRedirect("threat_feed", req, via)
}

// safeRedirect is the redirect policy for EVERY outbound fetch whose
// destination is operator-configured and required to be HTTPS: follow only
// HTTPS redirects to non-private hosts, and cap the hop count.
//
// Config validation pins the URL an operator wrote; without this, a redirect
// from that host silently unpins it — to http://, or to an internal address
// such as 169.254.169.254. Enforcing the scheme at config time and then letting
// the client follow anything is a guarantee that only holds until the first
// 302.
//
// Shared rather than duplicated because the gateway has several such fetches
// (the threat feed, the JWKS document) and the one that was missing this
// policy was the one authenticating production traffic.
func safeRedirect(what string, req *http.Request, via []*http.Request) error {
	if len(via) >= 5 {
		return fmt.Errorf("%s: too many redirects", what)
	}
	if req.URL.Scheme != "https" {
		return fmt.Errorf("%s: refusing non-https redirect to %q", what, req.URL.Redacted())
	}
	if host := req.URL.Hostname(); isPrivateOrLocalHost(host) {
		return fmt.Errorf("%s: refusing redirect to private/loopback host %q", what, host)
	}
	return nil
}

// isPrivateOrLocalHost reports whether a redirect target host is an internal
// address a public threat feed must never point us at. It blocks the literal
// "localhost" and any IP literal that is loopback, private, link-local (covers
// 169.254.169.254 cloud metadata) or unspecified. A bare DNS name that resolves
// to a private IP is not caught here (no lookup on the hot path); the scheme +
// IP-literal checks cover the realistic MITM/SSRF vectors.
func isPrivateOrLocalHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false // a domain name; allowed (HTTPS + public-name redirect)
	}
	return ip.IsLoopback() || ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified()
}

type threatFeed struct {
	url      string
	interval time.Duration
	log      Logger
	mu       sync.RWMutex
	threats  map[string]bool
}

func (tf *threatFeed) refresh() {
	// The feed URL is validated HTTPS at config load to prevent MITM, but the
	// default client would follow a redirect to http:// or an internal address
	// (e.g. cloud metadata at 169.254.169.254), undermining that guarantee and
	// enabling a blind SSRF. Only follow HTTPS redirects to non-private hosts,
	// and cap the hop count.
	client := &http.Client{Timeout: 30 * time.Second, CheckRedirect: checkFeedRedirect}
	resp, err := client.Get(tf.url)
	if err != nil {
		tf.log.Error("threat_feed: fetch error", map[string]any{"error": err.Error()})
		return
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		tf.log.Error("threat_feed: unexpected status", map[string]any{
			"status": resp.StatusCode,
			"url":    tf.url,
		})
		return
	}

	// Cap body size to prevent OOM from a malicious or misconfigured feed.
	limited := io.LimitReader(resp.Body, threatFeedMaxBytes)

	newThreats := make(map[string]bool, 1024)
	scanner := bufio.NewScanner(limited)
	for scanner.Scan() {
		if len(newThreats) >= threatFeedMaxIPs {
			tf.log.Error("threat_feed: IP limit reached, truncating", map[string]any{
				"limit": threatFeedMaxIPs,
				"url":   tf.url,
			})
			break
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		ip := strings.SplitN(line, " ", 2)[0]
		if net.ParseIP(ip) != nil {
			newThreats[ip] = true
		}
	}
	if err := scanner.Err(); err != nil {
		tf.log.Error("threat_feed: scan error", map[string]any{"error": err.Error(), "url": tf.url})
		// Keep the previous blocklist rather than replacing with partial data.
		return
	}

	tf.mu.Lock()
	tf.threats = newThreats
	tf.mu.Unlock()

	tf.log.Info("threat_feed: refreshed", map[string]any{"count": len(newThreats)})
}
