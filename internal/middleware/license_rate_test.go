package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func runLicenseRateLimit(maxRPS int, st *fakeStore) *httptest.ResponseRecorder {
	_ = InitTrustedProxies(nil)
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	h := LicenseRateLimit(maxRPS, fakeLogger{}, st)(next)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "1.2.3.4:1"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func TestLicenseRateLimit_ZeroMeansUnlimited(t *testing.T) {
	st := &fakeStore{incrRate: func(context.Context, string, time.Duration) (int64, error) { return 999999, nil }}
	rec := runLicenseRateLimit(0, st)
	if rec.Code != http.StatusOK {
		t.Fatalf("maxRPS=0 must be a passthrough regardless of count, got %d", rec.Code)
	}
}

func TestLicenseRateLimit_UnderCapPasses(t *testing.T) {
	st := &fakeStore{incrRate: func(context.Context, string, time.Duration) (int64, error) { return 5, nil }}
	rec := runLicenseRateLimit(10, st)
	if rec.Code != http.StatusOK {
		t.Fatalf("under cap: status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("X-License-RPS-Limit"); got != "10" {
		t.Errorf("X-License-RPS-Limit = %q, want 10", got)
	}
}

func TestLicenseRateLimit_OverCapDenies(t *testing.T) {
	st := &fakeStore{incrRate: func(context.Context, string, time.Duration) (int64, error) { return 11, nil }}
	rec := runLicenseRateLimit(10, st)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("over cap: status = %d, want 429", rec.Code)
	}
}

func TestLicenseRateLimit_AtCapPasses(t *testing.T) {
	// count == maxRPS is still within budget; only count > maxRPS denies.
	st := &fakeStore{incrRate: func(context.Context, string, time.Duration) (int64, error) { return 10, nil }}
	rec := runLicenseRateLimit(10, st)
	if rec.Code != http.StatusOK {
		t.Fatalf("at cap: status = %d, want 200", rec.Code)
	}
}

func TestLicenseRateLimit_StoreErrorFailsOpen(t *testing.T) {
	st := &fakeStore{incrRate: func(context.Context, string, time.Duration) (int64, error) {
		return 0, errors.New("redis down")
	}}
	rec := runLicenseRateLimit(10, st)
	if rec.Code != http.StatusOK {
		t.Fatalf("a store error must fail OPEN (commercial cap, not a security control), got %d", rec.Code)
	}
}

func TestLicenseRateLimit_UsesOneGlobalKeyNotPerIP(t *testing.T) {
	var gotKeys []string
	st := &fakeStore{incrRate: func(_ context.Context, key string, _ time.Duration) (int64, error) {
		gotKeys = append(gotKeys, key)
		return 1, nil
	}}
	_ = InitTrustedProxies(nil)
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	h := LicenseRateLimit(10, fakeLogger{}, st)(next)

	for _, ip := range []string{"1.1.1.1:1", "2.2.2.2:1"} {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = ip
		h.ServeHTTP(httptest.NewRecorder(), r)
	}
	if len(gotKeys) != 2 || gotKeys[0] != gotKeys[1] {
		t.Fatalf("expected both requests to share one global key, got %v", gotKeys)
	}
}
