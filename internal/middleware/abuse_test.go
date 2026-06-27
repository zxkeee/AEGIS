package middleware

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"api-gateway/internal/config"
)

func runAbuse(cfg config.AbuseConfig, st Store, method, path, subject, roles string) *httptest.ResponseRecorder {
	_ = InitTrustedProxies(nil)
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	h := AbuseDetection(cfg, fakeLogger{}, st)(next)
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(method, path, nil)
	r.RemoteAddr = "1.2.3.4:1"
	if subject != "" {
		r.Header.Set("X-Gateway-Subject", subject)
	}
	if roles != "" {
		r.Header.Set("X-Gateway-Roles", roles)
	}
	h.ServeHTTP(rec, r)
	return rec
}

func TestExtractObjectIDs(t *testing.T) {
	got := extractObjectIDs("/api/v1/users/42/orders/100", "/api/v1/users/{id}/orders/{id}")
	want := []string{"42", "100"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("extractObjectIDs = %v, want %v", got, want)
	}
	if ids := extractObjectIDs("/api/v1/users", "/api/v1/users"); ids != nil {
		t.Fatalf("no dynamic segments expected, got %v", ids)
	}
}

func TestBFLA_BlocksUnprivilegedConsumer(t *testing.T) {
	cfg := config.AbuseConfig{
		Enabled:   true,
		BlockMode: true,
		Privileged: []config.PrivilegedRule{
			{Path: "/admin/", RequiredRoles: []string{"admin"}},
		},
	}
	rec := runAbuse(cfg, &fakeStore{}, http.MethodGet, "/admin/users", "alice", "user")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("unprivileged access to /admin: got %d, want 403", rec.Code)
	}
}

func TestBFLA_AllowsPrivilegedConsumer(t *testing.T) {
	cfg := config.AbuseConfig{
		Enabled:   true,
		BlockMode: true,
		Privileged: []config.PrivilegedRule{
			{Path: "/admin/", RequiredRoles: []string{"admin"}},
		},
	}
	rec := runAbuse(cfg, &fakeStore{}, http.MethodGet, "/admin/users", "boss", "user,admin")
	if rec.Code != http.StatusOK {
		t.Fatalf("admin access to /admin: got %d, want 200", rec.Code)
	}
}

func TestBFLA_DetectOnly_DoesNotBlock(t *testing.T) {
	cfg := config.AbuseConfig{
		Enabled:   true,
		BlockMode: false, // detect only
		Privileged: []config.PrivilegedRule{
			{Path: "/admin/", RequiredRoles: []string{"admin"}},
		},
	}
	rec := runAbuse(cfg, &fakeStore{}, http.MethodGet, "/admin/users", "alice", "user")
	if rec.Code != http.StatusOK {
		t.Fatalf("detect-only must not block: got %d, want 200", rec.Code)
	}
}

func TestBOLA_BlocksEnumeration(t *testing.T) {
	cfg := config.AbuseConfig{Enabled: true, BlockMode: true, EnumThreshold: 50, Window: time.Minute}
	// Simulate the consumer having already swept 51 distinct object IDs.
	st := &fakeStore{trackObject: func() (int64, error) { return 51, nil }}
	rec := runAbuse(cfg, st, http.MethodGet, "/api/v1/users/777", "scraper", "user")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("enumeration over threshold: got %d, want 429", rec.Code)
	}
}

func TestBOLA_AllowsUnderThreshold(t *testing.T) {
	cfg := config.AbuseConfig{Enabled: true, BlockMode: true, EnumThreshold: 50, Window: time.Minute}
	st := &fakeStore{trackObject: func() (int64, error) { return 5, nil }}
	rec := runAbuse(cfg, st, http.MethodGet, "/api/v1/users/777", "alice", "user")
	if rec.Code != http.StatusOK {
		t.Fatalf("under threshold: got %d, want 200", rec.Code)
	}
}

func TestAbuse_DisabledIsPassthrough(t *testing.T) {
	rec := runAbuse(config.AbuseConfig{Enabled: false}, &fakeStore{}, http.MethodGet, "/admin/x", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("disabled abuse detection must pass through: got %d", rec.Code)
	}
}

// Allowlisted consumers are exempt from detection — the FP control. A known
// batch job sweeping many IDs must NOT be flagged, and a BFLA-shaped request
// from an allowlisted subject must NOT be blocked.
func TestAbuse_AllowlistExemptsConsumer(t *testing.T) {
	cfg := config.AbuseConfig{
		Enabled: true, BlockMode: true, EnumThreshold: 50, Window: time.Minute,
		Allowlist: []string{"svc-indexer"},
		Privileged: []config.PrivilegedRule{
			{Path: "/admin/", RequiredRoles: []string{"admin"}},
		},
	}
	// Would be BOLA (51 distinct) AND BFLA (no admin role) — but allowlisted.
	st := &fakeStore{trackObject: func() (int64, error) { return 51, nil }}
	rec := runAbuse(cfg, st, http.MethodGet, "/admin/users/777", "svc-indexer", "user")
	if rec.Code != http.StatusOK {
		t.Fatalf("allowlisted consumer must pass: got %d, want 200", rec.Code)
	}
	if len(st.forensic) != 0 {
		t.Fatalf("allowlisted consumer must not record events, got %d", len(st.forensic))
	}
}

// A2: a consumer whose normal is low (baseline 2) but suddenly sweeps 30
// distinct IDs is flagged — even though 30 is under the fixed hard ceiling of 50.
// A fixed threshold would miss this.
func TestBOLA_Adaptive_FlagsSpikeBelowCeiling(t *testing.T) {
	cfg := config.AbuseConfig{
		Enabled: true, BlockMode: true, EnumThreshold: 50, Window: time.Minute,
		Adaptive: true, Sensitivity: 3, AdaptiveMinObjects: 8,
	}
	st := &fakeStore{trackObject: func() (int64, error) { return 30, nil }, baseline: 2}
	rec := runAbuse(cfg, st, http.MethodGet, "/api/v1/users/9", "alice", "user")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("spike vs low baseline: got %d, want 429", rec.Code)
	}
}

// A2: a consumer whose normal IS high (baseline 60) is NOT flagged at 65 — under
// the hard ceiling and well within its own norm. A fixed threshold of 50 would
// false-positive here every window.
func TestBOLA_Adaptive_AllowsHighButNormalConsumer(t *testing.T) {
	cfg := config.AbuseConfig{
		Enabled: true, BlockMode: true, EnumThreshold: 100, Window: time.Minute,
		Adaptive: true, Sensitivity: 3, AdaptiveMinObjects: 8,
	}
	st := &fakeStore{trackObject: func() (int64, error) { return 65, nil }, baseline: 60}
	rec := runAbuse(cfg, st, http.MethodGet, "/api/v1/users/9", "dashboard", "user")
	if rec.Code != http.StatusOK {
		t.Fatalf("high-but-normal consumer: got %d, want 200", rec.Code)
	}
}

// A2: the absolute floor stops a tiny baseline from flagging a benign handful.
// baseline 0.5 × sensitivity 3 = 1.5, but 6 < AdaptiveMinObjects(8) ⇒ no flag.
func TestBOLA_Adaptive_RespectsMinFloor(t *testing.T) {
	cfg := config.AbuseConfig{
		Enabled: true, BlockMode: true, EnumThreshold: 50, Window: time.Minute,
		Adaptive: true, Sensitivity: 3, AdaptiveMinObjects: 8,
	}
	st := &fakeStore{trackObject: func() (int64, error) { return 6, nil }, baseline: 0.5}
	rec := runAbuse(cfg, st, http.MethodGet, "/api/v1/users/9", "newuser", "user")
	if rec.Code != http.StatusOK {
		t.Fatalf("below min floor: got %d, want 200", rec.Code)
	}
}

// Detected events carry an explainable severity + "why" (A6 explainability).
func TestAbuse_EventsCarrySeverityAndWhy(t *testing.T) {
	// BFLA, detect-only so we can inspect the recorded event.
	bflaCfg := config.AbuseConfig{
		Enabled: true, BlockMode: false,
		Privileged: []config.PrivilegedRule{{Path: "/admin/", RequiredRoles: []string{"admin"}}},
	}
	st := &fakeStore{}
	runAbuse(bflaCfg, st, http.MethodGet, "/admin/users", "mallory", "user")
	if len(st.forensic) != 1 {
		t.Fatalf("expected 1 BFLA event, got %d", len(st.forensic))
	}
	if st.forensic[0].Extra["severity"] != "critical" {
		t.Fatalf("BFLA severity = %v, want critical", st.forensic[0].Extra["severity"])
	}
	if why, _ := st.forensic[0].Extra["why"].(string); why == "" {
		t.Fatal("BFLA event missing 'why' explanation")
	}

	// BOLA, detect-only.
	bolaCfg := config.AbuseConfig{Enabled: true, BlockMode: false, EnumThreshold: 50, Window: time.Minute}
	st2 := &fakeStore{trackObject: func() (int64, error) { return 60, nil }}
	runAbuse(bolaCfg, st2, http.MethodGet, "/api/v1/users/9", "scraper", "user")
	if len(st2.forensic) != 1 {
		t.Fatalf("expected 1 BOLA event, got %d", len(st2.forensic))
	}
	if st2.forensic[0].Extra["severity"] != "warning" {
		t.Fatalf("BOLA severity = %v, want warning", st2.forensic[0].Extra["severity"])
	}
	if why, _ := st2.forensic[0].Extra["why"].(string); why == "" {
		t.Fatal("BOLA event missing 'why' explanation")
	}
}
