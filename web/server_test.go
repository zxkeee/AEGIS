package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestHdr_StripsCRLFAndControlChars(t *testing.T) {
	in := "alice\r\nX-Injected: evil\x00\x07"
	got := hdr(in)
	if got != "aliceX-Injected: evil" {
		t.Fatalf("hdr(%q) = %q, want CR/LF/control chars stripped", in, got)
	}
}

// Regression test for the log-injection fix: clientIP() itself doesn't
// sanitize (it trusts CF-Connecting-IP / the X-Forwarded-For a proxy sets,
// when trustProxyHeaders is on), so a forged X-Forwarded-For carrying a
// newline must not survive hdr() — what the pilot handler now wraps it in —
// into a log line.
func TestClientIP_ForgedXFF_StrippedByHdr(t *testing.T) {
	s := &site{trustProxyHeaders: true}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Forwarded-For", "1.2.3.4\r\nERROR: forged log line")
	ip := s.clientIP(r)
	if !bytes.ContainsAny([]byte(ip), "\r\n") {
		t.Fatal("test setup: expected clientIP to still carry the raw CRLF before hdr()")
	}
	if bytes.ContainsAny([]byte(hdr(ip)), "\r\n") {
		t.Fatalf("hdr(clientIP(r)) = %q still contains CR/LF", hdr(ip))
	}
}

// TestClientIP_UntrustedByDefault is a regression test for the IP-spoofing /
// rate-limit-bypass / unbounded-`seen`-growth finding (2026-08-23 audit):
// clientIP used to trust CF-Connecting-IP/X-Forwarded-For unconditionally, so
// any direct request — not just one actually behind Cloudflare — could forge
// a fresh IP on every submission and both dodge allow()'s per-IP limit and
// grow `seen` by one entry per forged value. A zero-value site (the default,
// trustProxyHeaders unset) must ignore both headers and fall back to the
// connection's own RemoteAddr.
func TestClientIP_UntrustedByDefault(t *testing.T) {
	s := &site{} // trustProxyHeaders defaults to false
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "203.0.113.9:54321"
	r.Header.Set("CF-Connecting-IP", "1.2.3.4")
	r.Header.Set("X-Forwarded-For", "5.6.7.8")
	if ip := s.clientIP(r); ip != "203.0.113.9" {
		t.Fatalf("clientIP() = %q, want the RemoteAddr host (203.0.113.9) — proxy headers must not be trusted by default", ip)
	}
}

// With trustProxyHeaders explicitly on, CF-Connecting-IP still wins over
// X-Forwarded-For (Cloudflare's own header is harder to forge end-to-end).
func TestClientIP_TrustedOptIn_PrefersCFHeader(t *testing.T) {
	s := &site{trustProxyHeaders: true}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "203.0.113.9:54321"
	r.Header.Set("CF-Connecting-IP", "1.2.3.4")
	r.Header.Set("X-Forwarded-For", "5.6.7.8")
	if ip := s.clientIP(r); ip != "1.2.3.4" {
		t.Fatalf("clientIP() = %q, want CF-Connecting-IP (1.2.3.4) when trusted", ip)
	}
}

func TestSite_Allow_RateLimitsPerIP(t *testing.T) {
	s := &site{seen: map[string][]time.Time{}}
	ip := "9.9.9.9"
	for i := 0; i < 5; i++ {
		if !s.allow(ip) {
			t.Fatalf("request %d: expected allowed within limit", i+1)
		}
	}
	if s.allow(ip) {
		t.Fatal("6th request within the window should be rate limited")
	}
	// A different IP is unaffected.
	if !s.allow("1.1.1.1") {
		t.Fatal("a different IP must not be limited by another IP's history")
	}
}

// TestSite_Sweep_DropsStaleIPs is a regression test for the unbounded-memory
// finding: without a periodic sweep, an IP that submits once and never
// returns sat in `seen` forever for the life of the process.
func TestSite_Sweep_DropsStaleIPs(t *testing.T) {
	s := &site{seen: map[string][]time.Time{
		"1.1.1.1": {time.Now().Add(-1 * time.Hour)}, // stale, outside the 10min window
		"2.2.2.2": {time.Now()},                     // fresh
	}}
	s.sweep()
	if _, ok := s.seen["1.1.1.1"]; ok {
		t.Error("sweep() left a stale IP in the map")
	}
	if _, ok := s.seen["2.2.2.2"]; !ok {
		t.Error("sweep() dropped a fresh IP it should have kept")
	}
}

// TestSite_Allow_HardCeiling is a regression test for the finding: without a
// ceiling, an attacker rotating a spoofed identity per request could grow
// `seen` without bound between sweep() ticks. A brand-new IP is refused once
// the map already holds seenMaxIPs distinct entries; an already-tracked IP is
// unaffected by the ceiling.
func TestSite_Allow_HardCeiling(t *testing.T) {
	s := &site{seen: make(map[string][]time.Time, seenMaxIPs)}
	for i := 0; i < seenMaxIPs; i++ {
		s.seen[fmt.Sprintf("10.0.%d.%d", i/256, i%256)] = []time.Time{time.Now()}
	}
	if s.allow("192.0.2.1") {
		t.Fatal("a brand-new IP once the map is at seenMaxIPs must be refused")
	}
	// An IP already tracked keeps working (only new keys are turned away).
	existing := "10.0.0.0"
	if !s.allow(existing) {
		t.Fatal("an already-tracked IP must still be allowed under its own limit")
	}
}

func TestSite_Pilot_RejectsMissingFields(t *testing.T) {
	dir := t.TempDir()
	s := &site{out: filepath.Join(dir, "out.jsonl"), seen: map[string][]time.Time{}}

	body, _ := json.Marshal(pilotReq{Name: "", Email: "not-an-email"})
	r := httptest.NewRequest(http.MethodPost, "/api/pilot", bytes.NewReader(body))
	r.RemoteAddr = "1.2.3.4:1"
	rec := httptest.NewRecorder()
	s.pilot(rec, r)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing name / invalid email = %d, want 400", rec.Code)
	}
}

func TestSite_Pilot_SavesValidSubmission(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "out.jsonl")
	s := &site{out: out, seen: map[string][]time.Time{}}

	body, _ := json.Marshal(pilotReq{Name: "Alice", Email: "alice@corp.com", Company: "Acme"})
	r := httptest.NewRequest(http.MethodPost, "/api/pilot", bytes.NewReader(body))
	r.RemoteAddr = "1.2.3.4:1"
	rec := httptest.NewRecorder()
	s.pilot(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("valid submission = %d, want 200", rec.Code)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read capture file: %v", err)
	}
	var rec2 pilotRecord
	if err := json.Unmarshal(bytes.TrimSpace(data), &rec2); err != nil {
		t.Fatalf("unmarshal captured record: %v", err)
	}
	if rec2.Name != "Alice" || rec2.Email != "alice@corp.com" {
		t.Fatalf("captured record = %+v, want name/email preserved", rec2)
	}
}

func TestSite_Pilot_ClipsOversizedFields(t *testing.T) {
	dir := t.TempDir()
	s := &site{out: filepath.Join(dir, "out.jsonl"), seen: map[string][]time.Time{}}

	long := make([]byte, 10_000)
	for i := range long {
		long[i] = 'a'
	}
	body, _ := json.Marshal(pilotReq{Name: "Bob", Email: "bob@corp.com", Message: string(long)})
	r := httptest.NewRequest(http.MethodPost, "/api/pilot", bytes.NewReader(body))
	r.RemoteAddr = "5.5.5.5:1"
	rec := httptest.NewRecorder()
	s.pilot(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("submission = %d, want 200", rec.Code)
	}
	data, _ := os.ReadFile(s.out)
	var rec2 pilotRecord
	_ = json.Unmarshal(bytes.TrimSpace(data), &rec2)
	if len(rec2.Message) != 4000 {
		t.Fatalf("message len = %d, want clipped to 4000", len(rec2.Message))
	}
}

func TestMailCfg_Send_HeaderFieldsStripCRLF(t *testing.T) {
	// mailCfg.send builds raw SMTP header text by hand; confirm hdr() keeps a
	// CRLF-laced email/name from forging extra headers (e.g. Bcc, another
	// Subject) into the message.
	c := mailCfg{host: "localhost", port: "1", user: "u", pass: "p", from: "from@x.com", to: "to@x.com"}
	rec := pilotRecord{
		pilotReq: pilotReq{
			Name:  "Eve",
			Email: "eve@x.com\r\nBcc: attacker@evil.com",
		},
		At: "now", IP: "1.2.3.4", UA: "ua",
	}
	subject := hdr("New AEGIS pilot request — " + firstNonEmpty(rec.Company, rec.Name))
	from := hdr(c.from)
	to := hdr(c.to)
	replyTo := hdr(rec.Email)
	if bytes.ContainsAny([]byte(subject+from+to+replyTo), "\r\n") {
		t.Fatal("a header field still contains CR/LF after hdr()")
	}
}
