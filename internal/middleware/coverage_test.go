package middleware

import (
	"context"
	"io"
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

// runDiscoveryRequest is runDiscovery's more general form: lets a test drive
// an arbitrary method/path/body through Discovery, for the GraphQL-path tests
// below (runDiscovery itself is fixed to a plain GET with no body).
func runDiscoveryRequest(cfg config.APIInventoryConfig, cat Catalog, method, path, body string) *httptest.ResponseRecorder {
	_ = InitTrustedProxies(nil)
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	h := Discovery(cfg, cat, fakeLogger{})(next)
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	r.RemoteAddr = "1.2.3.4:5555"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func TestDiscovery_GraphQLNamedOperationGetsOwnCatalogEntry(t *testing.T) {
	cat := &fakeCatalog{}
	cfg := config.APIInventoryConfig{Enabled: true, GraphQLPath: "/graphql"}
	body := `{"query":"query GetUser { user(id: 42) { id name } }"}`
	runDiscoveryRequest(cfg, cat, http.MethodPost, "/graphql", body)

	if len(cat.obs) != 1 {
		t.Fatalf("observations = %d, want 1", len(cat.obs))
	}
	want := "/graphql/query/GetUser"
	if cat.obs[0].Path != want {
		t.Fatalf("Path = %q, want %q", cat.obs[0].Path, want)
	}
}

func TestDiscovery_GraphQLDifferentOperationsGetDifferentEntries(t *testing.T) {
	cat := &fakeCatalog{}
	cfg := config.APIInventoryConfig{Enabled: true, GraphQLPath: "/graphql"}
	runDiscoveryRequest(cfg, cat, http.MethodPost, "/graphql", `{"query":"query GetUser { user(id: 1) { id } }"}`)
	runDiscoveryRequest(cfg, cat, http.MethodPost, "/graphql", `{"query":"mutation CreateOrder { createOrder(item: \"x\") { id } }"}`)

	if len(cat.obs) != 2 {
		t.Fatalf("observations = %d, want 2", len(cat.obs))
	}
	if cat.obs[0].Path == cat.obs[1].Path {
		t.Fatalf("two different GraphQL operations must not collapse to the same catalog path, both got %q", cat.obs[0].Path)
	}
}

func TestDiscovery_GraphQLAnonymousOperation(t *testing.T) {
	cat := &fakeCatalog{}
	cfg := config.APIInventoryConfig{Enabled: true, GraphQLPath: "/graphql"}
	runDiscoveryRequest(cfg, cat, http.MethodPost, "/graphql", `{"query":"{ me { id } }"}`)

	want := "/graphql/query/anonymous"
	if cat.obs[0].Path != want {
		t.Fatalf("Path = %q, want %q", cat.obs[0].Path, want)
	}
}

func TestDiscovery_GraphQLMalformedBodyFallsBackToPlainPath(t *testing.T) {
	cat := &fakeCatalog{}
	cfg := config.APIInventoryConfig{Enabled: true, GraphQLPath: "/graphql"}
	// Not valid GraphQL at all (e.g. a REST-style JSON payload posted to the
	// same path) — must not break the request or the catalog entry.
	runDiscoveryRequest(cfg, cat, http.MethodPost, "/graphql", `{"foo":"bar"}`)

	if len(cat.obs) != 1 {
		t.Fatalf("observations = %d, want 1", len(cat.obs))
	}
	if cat.obs[0].Path != "/graphql" {
		t.Fatalf("Path = %q, want plain /graphql fallback", cat.obs[0].Path)
	}
}

func TestDiscovery_GraphQLPathUnsetDoesNotParseBody(t *testing.T) {
	// GraphQLPath empty (default) — behavior must be byte-for-byte identical
	// to before this feature existed, even for a request that happens to look
	// like GraphQL.
	cat := &fakeCatalog{}
	cfg := config.APIInventoryConfig{Enabled: true} // GraphQLPath: ""
	runDiscoveryRequest(cfg, cat, http.MethodPost, "/graphql", `{"query":"query GetUser { user(id: 1) { id } }"}`)

	if cat.obs[0].Path != "/graphql" {
		t.Fatalf("Path = %q, want raw /graphql (GraphQL parsing must be opt-in)", cat.obs[0].Path)
	}
}

func TestDiscovery_GraphQLBodyStillReachesUpstream(t *testing.T) {
	// Regression guard: peeking the body for GraphQL parsing must not consume
	// it — the proxied backend still needs the exact original bytes.
	_ = InitTrustedProxies(nil)
	cfg := config.APIInventoryConfig{Enabled: true, GraphQLPath: "/graphql"}
	body := `{"query":"query GetUser { user(id: 1) { id } }"}`
	var gotBody string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusOK)
	})
	h := Discovery(cfg, &fakeCatalog{}, fakeLogger{})(next)
	r := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(body))
	r.RemoteAddr = "1.2.3.4:5555"
	h.ServeHTTP(httptest.NewRecorder(), r)

	if gotBody != body {
		t.Fatalf("upstream body = %q, want %q (body must survive the GraphQL peek)", gotBody, body)
	}
}

// TestDiscovery_GraphQLOperationGetsPIIAttribution proves the ROADMAP.md B5
// "DLP is not GraphQL-field-aware" gap is narrower than documented: DLP
// enriches the SAME *discovery.Observation Discovery seeds into the request
// context (observationFrom), and Discovery already resolves a per-operation
// path for GraphQL before DLP ever runs (Discovery wraps DLP in the real
// chain — see chain.go's ordering comment). So a PII finding on a GraphQL
// response lands on the correct per-operation catalog entry today, with no
// GraphQL-specific code in DLP at all.
func TestDiscovery_GraphQLOperationGetsPIIAttribution(t *testing.T) {
	cat := &fakeCatalog{}
	discCfg := config.APIInventoryConfig{Enabled: true, GraphQLPath: "/graphql"}
	dlpCfg := config.DLPConfig{Enabled: true}

	_ = InitTrustedProxies(nil)
	backend := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// A credit-card-shaped value in the body — DLP's default classifiers
		// detect this by content, independent of GraphQL/REST.
		_, _ = w.Write([]byte(`{"data":{"user":{"card":"4111111111111111"}}}`))
	})
	// Discovery wraps DLP, matching the real chain's ordering.
	h := Discovery(discCfg, cat, fakeLogger{})(DLP(dlpCfg, fakeLogger{}, &fakeStore{})(backend))

	r := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(`{"query":"query GetUser { user(id: 1) { card } }"}`))
	r.RemoteAddr = "1.2.3.4:1"
	h.ServeHTTP(httptest.NewRecorder(), r)

	if len(cat.obs) != 1 {
		t.Fatalf("observations = %d, want 1", len(cat.obs))
	}
	obs := cat.obs[0]
	if obs.Path != "/graphql/query/GetUser" {
		t.Fatalf("Path = %q, want the per-operation path", obs.Path)
	}
	if !obs.PII {
		t.Fatal("expected the PII finding to be attached to this GraphQL operation's observation")
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

func TestRequestID_RejectsMalformedClientID(t *testing.T) {
	for _, bad := range []string{
		"has spaces",
		"inject\r\nX-Evil: 1",
		strings.Repeat("a", 65), // over the 64-char cap
		"кириллица",
	} {
		var seen string
		h := RequestID()(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			seen = r.Header.Get("X-Request-ID")
		}))
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header["X-Request-Id"] = []string{bad} // bypass Set's canonicalisation guards
		h.ServeHTTP(httptest.NewRecorder(), r)
		if seen == bad {
			t.Fatalf("malformed client id %q propagated verbatim", bad)
		}
		if len(seen) != 16 {
			t.Fatalf("malformed id must be replaced with a generated one, got %q", seen)
		}
	}
}

func TestSecurityHeaders_NoDeprecatedXSSHeader(t *testing.T) {
	h := SecurityHeaders()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if _, present := rec.Header()["X-Xss-Protection"]; present {
		t.Fatal("deprecated X-XSS-Protection must not be emitted")
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("core security headers must still be present")
	}
}
