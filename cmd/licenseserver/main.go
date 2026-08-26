// Command licenseserver is the SELF-SERVICE reissuance endpoint: it lets a
// customer whose gateway's hardware fingerprint changed get a replacement
// license automatically, without a human round-trip through cmd/licensegen.
//
// This is a deliberate, real change in risk posture from the rest of the
// licensing system: every other tool in this repo (cmd/licensegen) keeps the
// private key OFFLINE. This one needs it ONLINE and reachable to do its job.
// Read docs/licensing.md's "self-service reissuance" section before running
// this anywhere reachable from the internet — in short: run it on a host you
// control tightly (not co-located with a customer's infrastructure), behind
// TLS, and treat it with the same operational care as a CA's signing
// service, because that is functionally what it is.
//
// Usage:
//
//	go run ./cmd/licenseserver -key aegis-license.key -listen :8443
//
// Protocol: POST /reissue, JSON body:
//
//	{"license": "<contents of the customer's current .lic file>", "hardware_id": "<new fingerprint>"}
//
// Response: {"license": "<new .lic contents>"} on success, or
// {"error": "..."} with a 4xx/5xx status otherwise.
package main

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"api-gateway/internal/license"
)

// maxRequestBody bounds the JSON body accepted per request. A real license
// file is a few hundred bytes; this is generous headroom, not an invitation
// to accept arbitrary-sized input from an unauthenticated caller in front of
// a service holding the signing key.
const maxRequestBody = 16 * 1024

// perIPLimiter is a minimal fixed-window rate limiter: this endpoint holds
// the private signing key in memory, so it is worth bounding how fast an
// unauthenticated caller can hammer it, independent of any reverse proxy the
// operator puts in front. Not a substitute for one — a dedicated proxy/WAF in
// front of this service (e.g. AEGIS itself) is still recommended, see
// docs/licensing.md.
type perIPLimiter struct {
	mu       sync.Mutex
	window   time.Duration
	limit    int
	counts   map[string]int
	resetsAt time.Time
}

func newPerIPLimiter(limit int, window time.Duration) *perIPLimiter {
	return &perIPLimiter{limit: limit, window: window, counts: make(map[string]int), resetsAt: time.Now().Add(window)}
}

func (l *perIPLimiter) Allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if time.Now().After(l.resetsAt) {
		l.counts = make(map[string]int)
		l.resetsAt = time.Now().Add(l.window)
	}
	l.counts[ip]++
	return l.counts[ip] <= l.limit
}

type reissueRequest struct {
	License    string `json:"license"`
	HardwareID string `json:"hardware_id"`
}

type reissueResponse struct {
	License string `json:"license,omitempty"`
	Error   string `json:"error,omitempty"`
}

func main() {
	keyPath := flag.String("key", "", "path to the Ed25519 private key file (from cmd/licensegen -genkey)")
	listen := flag.String("listen", ":8443", "listen address")
	rateLimit := flag.Int("rate-limit", 10, "max reissue requests per IP per rate-limit-window")
	rateWindow := flag.Duration("rate-limit-window", time.Hour, "rate-limit window")
	flag.Parse()

	if *keyPath == "" {
		fmt.Fprintln(os.Stderr, "usage: licenseserver -key <priv.key> [-listen :8443] [-rate-limit N] [-rate-limit-window 1h]")
		os.Exit(2)
	}
	raw, err := os.ReadFile(*keyPath) // #nosec G304 -- operator-supplied path
	if err != nil {
		log.Fatalf("licenseserver: read key: %v", err)
	}
	if len(raw) != ed25519.PrivateKeySize {
		log.Fatalf("licenseserver: %s does not look like an Ed25519 private key (got %d bytes, want %d)",
			*keyPath, len(raw), ed25519.PrivateKeySize)
	}
	priv := ed25519.PrivateKey(raw)
	limiter := newPerIPLimiter(*rateLimit, *rateWindow)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /reissue", func(w http.ResponseWriter, r *http.Request) {
		handleReissue(w, r, priv, limiter)
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	log.Printf("licenseserver: listening on %s (rate limit %d/%s per IP) — this process holds the "+
		"private signing key in memory; see docs/licensing.md before exposing it publicly", *listen, *rateLimit, *rateWindow)
	srv := &http.Server{
		Addr:              *listen,
		Handler:           mux,
		ReadTimeout:       5 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 * 1024,
	}
	log.Fatal(srv.ListenAndServe())
}

func handleReissue(w http.ResponseWriter, r *http.Request, priv ed25519.PrivateKey, limiter *perIPLimiter) {
	ip := clientIP(r)
	if !limiter.Allow(ip) {
		writeJSON(w, http.StatusTooManyRequests, reissueResponse{Error: "rate limit exceeded, try again later"})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	var req reissueRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, reissueResponse{Error: "malformed request body"})
		return
	}
	if req.License == "" || req.HardwareID == "" {
		writeJSON(w, http.StatusBadRequest, reissueResponse{Error: "\"license\" and \"hardware_id\" are both required"})
		return
	}

	newLicense, err := license.Reissue(priv, []byte(req.License), req.HardwareID)
	if err != nil {
		status := http.StatusForbidden // most failures here are "this isn't a license we can reissue"
		if errors.Is(err, license.ErrLicenseTermExpired) {
			status = http.StatusPaymentRequired // distinguishable from a bogus/forged submission
		}
		log.Printf("licenseserver: reissue denied for %s: %v", ip, err)
		writeJSON(w, status, reissueResponse{Error: err.Error()})
		return
	}

	log.Printf("licenseserver: reissued a license for %s (new hardware_id=%s)", ip, req.HardwareID)
	writeJSON(w, http.StatusOK, reissueResponse{License: newLicense})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// clientIP is deliberately simple (RemoteAddr only, no X-Forwarded-For
// trust): this service is expected to sit behind an operator-controlled
// reverse proxy (recommended: AEGIS itself, or any proxy that sets
// RemoteAddr correctly), not to be exposed raw to the internet — see the
// docs/licensing.md deployment guidance. Blindly trusting a client-supplied
// forwarding header here would let a caller evade its own rate limit.
func clientIP(r *http.Request) string {
	return r.RemoteAddr
}
