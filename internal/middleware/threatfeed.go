package middleware

import (
	"bufio"
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
func ThreatFeed(cfg config.ThreatFeedConfig, log Logger, st Store) Middleware {
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

type threatFeed struct {
	url      string
	interval time.Duration
	log      Logger
	mu       sync.RWMutex
	threats  map[string]bool
}

func (tf *threatFeed) refresh() {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(tf.url)
	if err != nil {
		tf.log.Error("threat_feed: fetch error", map[string]any{"error": err.Error()})
		return
	}
	defer resp.Body.Close()

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
