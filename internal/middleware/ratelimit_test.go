package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"api-gateway/internal/config"
)

func runRateLimit(cfg config.RateLimitConfig, st Store) *httptest.ResponseRecorder {
	_ = InitTrustedProxies(nil)
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := RateLimit(cfg, fakeLogger{}, st)(next)
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "1.2.3.4:1111"
	h.ServeHTTP(rec, r)
	return rec
}

func TestRateLimit_BlocksOverLimit(t *testing.T) {
	cfg := config.RateLimitConfig{Enabled: true, Requests: 10, Window: time.Minute}
	st := &fakeStore{incrRate: func(context.Context, string, time.Duration) (int64, error) {
		return 11, nil // over the limit
	}}
	if rec := runRateLimit(cfg, st); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("over-limit request: got %d, want 429", rec.Code)
	}
}

func TestRateLimit_FailOpen_OnRedisError(t *testing.T) {
	cfg := config.RateLimitConfig{Enabled: true, Requests: 10, Window: time.Minute, FailClosed: false}
	st := &fakeStore{incrRate: func(context.Context, string, time.Duration) (int64, error) {
		return 0, errors.New("redis down")
	}}
	if rec := runRateLimit(cfg, st); rec.Code != http.StatusOK {
		t.Fatalf("fail-open: got %d, want 200 (request should pass when Redis errors)", rec.Code)
	}
}

func TestRateLimit_FailClosed_OnRedisError(t *testing.T) {
	cfg := config.RateLimitConfig{Enabled: true, Requests: 10, Window: time.Minute, FailClosed: true}
	st := &fakeStore{incrRate: func(context.Context, string, time.Duration) (int64, error) {
		return 0, errors.New("redis down")
	}}
	if rec := runRateLimit(cfg, st); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("fail-closed: got %d, want 503 (request must be denied when Redis errors)", rec.Code)
	}
}
