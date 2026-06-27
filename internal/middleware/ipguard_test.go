package middleware

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"api-gateway/internal/config"
)

func runIPGuard(cfg config.IPGuardConfig, st Store, ip string) *httptest.ResponseRecorder {
	_ = InitTrustedProxies(nil)
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	h := IPGuard(cfg, fakeLogger{}, st)(next)
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = ip + ":1111"
	h.ServeHTTP(rec, r)
	return rec
}

func TestIPGuard_BlocklistDenies(t *testing.T) {
	cfg := config.IPGuardConfig{Enabled: true, Blacklist: []string{"9.9.9.9"}}
	if rec := runIPGuard(cfg, &fakeStore{}, "9.9.9.9"); rec.Code != http.StatusForbidden {
		t.Fatalf("blacklisted IP: got %d, want 403", rec.Code)
	}
}

func TestIPGuard_FailOpen_OnRedisError(t *testing.T) {
	cfg := config.IPGuardConfig{Enabled: true, FailClosed: false}
	st := &fakeStore{ipBlockErr: errors.New("redis down")}
	if rec := runIPGuard(cfg, st, "1.2.3.4"); rec.Code != http.StatusOK {
		t.Fatalf("fail-open: got %d, want 200 when Redis errors", rec.Code)
	}
}

func TestIPGuard_FailClosed_OnRedisError(t *testing.T) {
	cfg := config.IPGuardConfig{Enabled: true, FailClosed: true}
	st := &fakeStore{ipBlockErr: errors.New("redis down")}
	if rec := runIPGuard(cfg, st, "1.2.3.4"); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("fail-closed: got %d, want 503 when Redis errors", rec.Code)
	}
}

func TestIPGuard_WhitelistBypassesError(t *testing.T) {
	// A whitelisted IP is allowed before the dynamic lookup, so a Redis outage
	// must not block it even in fail-closed mode.
	cfg := config.IPGuardConfig{Enabled: true, FailClosed: true, Whitelist: []string{"5.5.5.5"}}
	st := &fakeStore{ipBlockErr: errors.New("redis down")}
	if rec := runIPGuard(cfg, st, "5.5.5.5"); rec.Code != http.StatusOK {
		t.Fatalf("whitelisted IP: got %d, want 200", rec.Code)
	}
}
