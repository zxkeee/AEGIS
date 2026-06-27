package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"api-gateway/internal/config"
	"api-gateway/internal/discovery"
)

// — Chain —

func TestChain_AppliesOutermostFirst(t *testing.T) {
	var order []string
	mark := func(label string) Middleware {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				order = append(order, label+":enter")
				next.ServeHTTP(w, r)
				order = append(order, label+":exit")
			})
		}
	}
	target := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		order = append(order, "target")
		w.WriteHeader(http.StatusTeapot)
	})
	h := Chain(target, mark("A"), mark("B"))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusTeapot {
		t.Fatalf("status = %d, want 418 (handler reached)", rec.Code)
	}
	got := strings.Join(order, ",")
	want := "A:enter,B:enter,target,B:exit,A:exit"
	if got != want {
		t.Fatalf("execution order = %q, want %q", got, want)
	}
}

func TestChain_NoMiddlewares(t *testing.T) {
	target := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	rec := httptest.NewRecorder()
	Chain(target).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK {
		t.Fatal("empty Chain must call the handler unchanged")
	}
}

// — RequestID —

func TestRequestID_GeneratesWhenAbsent(t *testing.T) {
	var seen string
	h := RequestID()(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("X-Request-ID")
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if seen == "" || len(seen) != 16 { // 8 random bytes hex-encoded
		t.Fatalf("generated id = %q, want 16-char hex", seen)
	}
	if rec.Header().Get("X-Request-ID") != seen {
		t.Fatal("X-Request-ID must be echoed on the response")
	}
}

func TestRequestID_PreservesClientSupplied(t *testing.T) {
	var seen string
	h := RequestID()(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("X-Request-ID")
	}))
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Request-ID", "from-client")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	if seen != "from-client" || rec.Header().Get("X-Request-ID") != "from-client" {
		t.Fatalf("client-supplied id lost: req=%q resp=%q", seen, rec.Header().Get("X-Request-ID"))
	}
}

// — BehaviorAnalysis —

func runBehavior(cfg config.BehaviorConfig, st Store, statusFromNext int) *httptest.ResponseRecorder {
	_ = InitTrustedProxies(nil)
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(statusFromNext)
	})
	h := BehaviorAnalysis(cfg, fakeLogger{}, st)(next)
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.RemoteAddr = "1.2.3.4:5555"
	h.ServeHTTP(rec, r)
	return rec
}

func TestBehavior_DisabledPassthrough(t *testing.T) {
	cfg := config.BehaviorConfig{Enabled: false, ScoreThreshold: 50}
	if rec := runBehavior(cfg, &fakeStore{behavior: 999}, http.StatusOK); rec.Code != http.StatusOK {
		t.Fatalf("disabled middleware should pass, got %d", rec.Code)
	}
}

func TestBehavior_BelowThresholdServesRequest(t *testing.T) {
	cfg := config.BehaviorConfig{Enabled: true, ScoreThreshold: 70}
	if rec := runBehavior(cfg, &fakeStore{behavior: 10}, http.StatusOK); rec.Code != http.StatusOK {
		t.Fatalf("low-risk: got %d, want 200", rec.Code)
	}
}

func TestBehavior_AboveThresholdBlocks(t *testing.T) {
	cfg := config.BehaviorConfig{Enabled: true, ScoreThreshold: 70}
	if rec := runBehavior(cfg, &fakeStore{behavior: 90}, http.StatusOK); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("high-risk: got %d, want 429", rec.Code)
	}
}

func TestBehavior_AutoBanAfterThirdStrike(t *testing.T) {
	// autoban counter ≥3 triggers BlockIP; we verify by reading the fake's set.
	cfg := config.BehaviorConfig{Enabled: true, ScoreThreshold: 70}
	st := &fakeStore{behavior: 90, autoban: 3}
	_ = runBehavior(cfg, st, http.StatusOK)
	if !st.blockedIPs["1.2.3.4"] {
		t.Fatal("third-strike high-risk IP must be auto-banned")
	}
}

// — Challenge —

func runChallenge(cfg config.ChallengeConfig, st Store, setup func(*http.Request)) *httptest.ResponseRecorder {
	_ = InitTrustedProxies(nil)
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	h := Challenge(cfg, fakeLogger{}, st)(next)
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "1.2.3.4:5555"
	if setup != nil {
		setup(r)
	}
	h.ServeHTTP(rec, r)
	return rec
}

func TestChallenge_DisabledPassthrough(t *testing.T) {
	if rec := runChallenge(config.ChallengeConfig{Enabled: false}, &fakeStore{}, nil); rec.Code != http.StatusOK {
		t.Fatalf("disabled: got %d, want 200", rec.Code)
	}
}

func TestChallenge_AlreadySolved_Passthrough(t *testing.T) {
	st := &fakeStore{challengeSolved: map[string]bool{"1.2.3.4": true}}
	if rec := runChallenge(config.ChallengeConfig{Enabled: true}, st, nil); rec.Code != http.StatusOK {
		t.Fatalf("solved IP must pass, got %d", rec.Code)
	}
}

func TestChallenge_ValidTokenMarksSolvedThenPasses(t *testing.T) {
	st := &fakeStore{challengeValid: map[string]string{"1.2.3.4": "tok-ok"}}
	rec := runChallenge(config.ChallengeConfig{Enabled: true}, st, func(r *http.Request) {
		r.Header.Set("X-Challenge-Token", "tok-ok")
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("valid token: got %d, want 200", rec.Code)
	}
	if !st.challengeSolved["1.2.3.4"] {
		t.Fatal("valid token must mark the IP as solved for next time")
	}
}

func TestChallenge_NoTokenIssuesChallenge(t *testing.T) {
	rec := runChallenge(config.ChallengeConfig{Enabled: true}, &fakeStore{}, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("unchallenged client: got %d, want 403", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "X-Challenge-Token") {
		t.Fatalf("challenge HTML missing the JS that posts X-Challenge-Token; body=%q", rec.Body.String())
	}
}

func TestGenerateToken(t *testing.T) {
	a, b := generateToken(), generateToken()
	if len(a) != 32 || a == b {
		t.Fatalf("tokens must be 32-char hex and unique; got %q/%q", a, b)
	}
}

// — Discovery middleware + consumerLabel —

// fakeCatalog records observations so the test can assert what Discovery
// captured. Implements middleware.Catalog (single Record method).
type fakeCatalog struct{ obs []discovery.Observation }

func (f *fakeCatalog) Record(o discovery.Observation) { f.obs = append(f.obs, o) }

func runDiscovery(cfg config.APIInventoryConfig, cat Catalog, nextStatus int) (*httptest.ResponseRecorder, *http.Request) {
	_ = InitTrustedProxies(nil)
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(nextStatus) })
	h := Discovery(cfg, cat, fakeLogger{})(next)
	r := httptest.NewRequest(http.MethodGet, "/api/v1/users/42", nil)
	r.RemoteAddr = "1.2.3.4:5555"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec, r
}

func TestDiscovery_DisabledIsPassthrough(t *testing.T) {
	cat := &fakeCatalog{}
	rec, _ := runDiscovery(config.APIInventoryConfig{Enabled: false}, cat, http.StatusOK)
	if rec.Code != http.StatusOK {
		t.Fatalf("disabled: %d", rec.Code)
	}
	if len(cat.obs) != 0 {
		t.Fatal("disabled discovery must not record observations")
	}
}

func TestDiscovery_NilCatalogIsPassthrough(t *testing.T) {
	rec, _ := runDiscovery(config.APIInventoryConfig{Enabled: true}, nil, http.StatusOK)
	if rec.Code != http.StatusOK {
		t.Fatalf("nil catalog: %d", rec.Code)
	}
}

func TestDiscovery_RecordsSuccessfulRequest(t *testing.T) {
	cat := &fakeCatalog{}
	_, r := runDiscovery(config.APIInventoryConfig{Enabled: true}, cat, http.StatusOK)
	if len(cat.obs) != 1 {
		t.Fatalf("observations = %d, want 1", len(cat.obs))
	}
	obs := cat.obs[0]
	if obs.Method != http.MethodGet || obs.Path != r.URL.Path || obs.Status != 200 {
		t.Fatalf("observation wrong: %+v", obs)
	}
}

func TestDiscovery_Skips404(t *testing.T) {
	// 404s never reach the catalog — they would be polluted by probing.
	cat := &fakeCatalog{}
	runDiscovery(config.APIInventoryConfig{Enabled: true}, cat, http.StatusNotFound)
	if len(cat.obs) != 0 {
		t.Fatalf("404 must not be recorded; got %d observations", len(cat.obs))
	}
}

func TestConsumerLabel_PrefersStrongestIdentity(t *testing.T) {
	cases := []struct {
		obs  discovery.Observation
		want string
	}{
		{discovery.Observation{ConsumerSubject: "u-7"}, "jwt:u-7"},
		{discovery.Observation{ConsumerKey: "k1", ConsumerIP: "1.1.1.1"}, "key:k1"},
		{discovery.Observation{ConsumerIP: "1.1.1.1"}, "ip:1.1.1.1"},
	}
	for _, c := range cases {
		if got := consumerLabel(&c.obs); got != c.want {
			t.Errorf("consumerLabel(%+v) = %q, want %q", c.obs, got, c.want)
		}
	}
}

// — observationFrom (helper used by inner middleware to enrich the obs) —

func TestObservationFrom_NilWhenAbsent(t *testing.T) {
	if observationFrom(context.Background()) != nil {
		t.Fatal("no obs in ctx must yield nil")
	}
}
