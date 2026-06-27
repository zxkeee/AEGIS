package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"api-gateway/internal/config"
)

func runBot(cfg config.BotConfig, st Store, setup func(*http.Request)) *httptest.ResponseRecorder {
	_ = InitTrustedProxies(nil)
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	h := BotProtection(cfg, fakeLogger{}, st)(next)
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "1.2.3.4:1111"
	r.Header.Set("User-Agent", "test-agent")
	if setup != nil {
		setup(r)
	}
	h.ServeHTTP(rec, r)
	return rec
}

func TestBot_Disabled_Passthrough(t *testing.T) {
	if rec := runBot(config.BotConfig{Enabled: false}, &fakeStore{}, nil); rec.Code != http.StatusOK {
		t.Fatalf("disabled bot protection should pass, got %d", rec.Code)
	}
}

func TestBot_BlockedJA3_Denied(t *testing.T) {
	cfg := config.BotConfig{Enabled: true, BlockedJA3: []string{"badfingerprint"}}
	rec := runBot(cfg, &fakeStore{}, func(r *http.Request) {
		r.Header.Set("X-JA3-Fingerprint", "badfingerprint")
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("blocked JA3: got %d, want 403", rec.Code)
	}
}

func TestBot_AllowedJA3_Passes(t *testing.T) {
	cfg := config.BotConfig{Enabled: true, BlockedJA3: []string{"badfingerprint"}}
	rec := runBot(cfg, &fakeStore{}, func(r *http.Request) {
		r.Header.Set("X-JA3-Fingerprint", "goodfingerprint")
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("allowed JA3: got %d, want 200", rec.Code)
	}
}

func TestBot_EmptyUA_StillPasses(t *testing.T) {
	// Empty UA raises the behaviour score but does not block on its own.
	cfg := config.BotConfig{Enabled: true}
	rec := runBot(cfg, &fakeStore{}, func(r *http.Request) { r.Header.Del("User-Agent") })
	if rec.Code != http.StatusOK {
		t.Fatalf("empty UA should pass (score only), got %d", rec.Code)
	}
}
