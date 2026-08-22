package middleware

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
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

// runAbuseStatus is runAbuse with a controllable backend response status, so the
// object-ownership check (which keys off 2xx-vs-4xx) can be exercised both ways.
func runAbuseStatus(cfg config.AbuseConfig, st Store, method, path, subject, roles string, status int) *httptest.ResponseRecorder {
	_ = InitTrustedProxies(nil)
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(status) })
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

// ── Object-ownership BOLA / IDOR (single-object) ─────────────────────────────

func ownershipCfg() config.AbuseConfig {
	return config.AbuseConfig{Enabled: true, ObjectOwnership: true, SharedObjectThreshold: 2, Window: time.Minute}
}

// runAbuseBody is runAbuseStatus with a controllable JSON response body, so the
// confirmed-ownership path (owner extracted from the body) can be exercised.
func runAbuseBody(cfg config.AbuseConfig, st Store, path, subject, roles string, status int, body string) *httptest.ResponseRecorder {
	_ = InitTrustedProxies(nil)
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	})
	h := AbuseDetection(cfg, fakeLogger{}, st)(next)
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, path, nil)
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

// Heuristic (first-accessor) path: a consumer reading an object owned by another
// small set — and never accessed by it — is a warning (no body confirmation).
func TestBOLAOwnership_CrossOwnerHeuristicFlagged(t *testing.T) {
	st := &fakeStore{trackOwner: func() (int64, bool, error) { return 1, false, nil }}
	rec := runAbuseStatus(ownershipCfg(), st, http.MethodGet, "/api/orders/12345", "bob", "user", http.StatusOK)
	if rec.Code != http.StatusOK {
		t.Fatalf("ownership is detect-only, must not alter status: got %d", rec.Code)
	}
	if len(st.forensic) != 1 || st.forensic[0].Reason != "bola_object_ownership" {
		t.Fatalf("expected 1 bola_object_ownership event, got %+v", st.forensic)
	}
	if st.forensic[0].Extra["severity"] != "warning" {
		t.Fatalf("heuristic severity = %v, want warning", st.forensic[0].Extra["severity"])
	}
}

// Confirmed path: the response body names an owner different from the caller —
// a real data leak, flagged critical, and the owner binding is recorded.
func TestBOLAOwnership_ConfirmedFromBodyFlagged(t *testing.T) {
	cfg := ownershipCfg()
	cfg.OwnerFields = []string{"user_id"}
	st := &fakeStore{}
	_ = runAbuseBody(cfg, st, "/api/orders/12345", "bob", "user", http.StatusOK, `{"user_id":"alice","amount":10}`)
	if len(st.forensic) != 1 || st.forensic[0].Reason != "bola_object_ownership" {
		t.Fatalf("expected 1 confirmed IDOR event, got %+v", st.forensic)
	}
	if st.forensic[0].Extra["severity"] != "critical" || st.forensic[0].Extra["confirmed"] != true {
		t.Fatalf("confirmed event = %+v, want critical/confirmed", st.forensic[0].Extra)
	}
	if len(st.setOwners) != 1 || st.setOwners[0] != "alice" {
		t.Fatalf("owner binding = %v, want [alice]", st.setOwners)
	}
}

// Confirmed path, owner matches caller: bind the owner, do not flag.
func TestBOLAOwnership_ConfirmedOwnerMatchesNotFlagged(t *testing.T) {
	cfg := ownershipCfg()
	cfg.OwnerFields = []string{"user_id"}
	st := &fakeStore{}
	_ = runAbuseBody(cfg, st, "/api/orders/12345", "alice", "user", http.StatusOK, `{"user_id":"alice"}`)
	if len(st.forensic) != 0 {
		t.Fatalf("owner reading own object must not flag, got %+v", st.forensic)
	}
	if len(st.setOwners) != 1 || st.setOwners[0] != "alice" {
		t.Fatalf("owner binding = %v, want [alice]", st.setOwners)
	}
}

// Proactive block: a known confirmed owner different from the caller is denied
// BEFORE forwarding (prevents the leak, not just records it).
func TestBOLAOwnership_BlockKnownCrossOwner(t *testing.T) {
	cfg := ownershipCfg()
	cfg.ObjectOwnershipBlock = true
	st := &fakeStore{getOwner: func() (string, bool, error) { return "alice", true, nil }}
	rec := runAbuseStatus(cfg, st, http.MethodGet, "/api/orders/12345", "bob", "user", http.StatusOK)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("known cross-owner access: got %d, want 403", rec.Code)
	}
}

// The confirmed owner reaching their own object is not blocked.
func TestBOLAOwnership_BlockAllowsRealOwner(t *testing.T) {
	cfg := ownershipCfg()
	cfg.ObjectOwnershipBlock = true
	cfg.OwnerFields = []string{"user_id"}
	st := &fakeStore{getOwner: func() (string, bool, error) { return "alice", true, nil }}
	rec := runAbuseBody(cfg, st, "/api/orders/12345", "alice", "user", http.StatusOK, `{"user_id":"alice"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("real owner must not be blocked: got %d", rec.Code)
	}
}

// TestBOLAOwnership_StoreErrorFailOpenByDefault is a regression test:
// ObjectOwnershipBlock is a proactive HARD DENY (blocks before forwarding),
// unlike the rest of BOLA detection (detect-and-record). A GetObjectOwner
// error (e.g. Redis outage) must not silently disable that guarantee without
// a way to opt out — default is fail-open (request proceeds, matching
// RateLimitConfig/IPGuardConfig's own fail-open default).
func TestBOLAOwnership_StoreErrorFailOpenByDefault(t *testing.T) {
	cfg := ownershipCfg()
	cfg.ObjectOwnershipBlock = true
	st := &fakeStore{getOwner: func() (string, bool, error) { return "", false, errors.New("redis: connection refused") }}
	rec := runAbuseStatus(cfg, st, http.MethodGet, "/api/orders/12345", "bob", "user", http.StatusOK)
	if rec.Code != http.StatusOK {
		t.Fatalf("store error, OwnershipFailClosed=false: got %d, want 200 (fail-open — candidate skipped, request proceeds)", rec.Code)
	}
}

// TestBOLAOwnership_StoreErrorFailClosedWhenConfigured is the counterpart:
// with OwnershipFailClosed set, the same store error must deny instead of
// silently degrading the hard-block guarantee to record-only.
func TestBOLAOwnership_StoreErrorFailClosedWhenConfigured(t *testing.T) {
	cfg := ownershipCfg()
	cfg.ObjectOwnershipBlock = true
	cfg.OwnershipFailClosed = true
	st := &fakeStore{getOwner: func() (string, bool, error) { return "", false, errors.New("redis: connection refused") }}
	rec := runAbuseStatus(cfg, st, http.MethodGet, "/api/orders/12345", "bob", "user", http.StatusOK)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("store error, OwnershipFailClosed=true: got %d, want 503 (deny — cross-owner status cannot be confirmed)", rec.Code)
	}
}

// TestIsJSONContentType_AcceptsPlusJSONVariants is a regression test: a
// sibling instance of waf.go's own JSON-body detection gap. Coraza (and this
// package's own jsonBodyDirectives) treats any "application/...+json" suffix
// as JSON, not just the bare media type — bodyObjectIDs and
// captureWriter.decide must agree, or a body sent as e.g.
// application/vnd.api+json is fully JSON-parsed by the WAF but invisible to
// BOLA body-ID extraction and confirmed-owner binding.
func TestIsJSONContentType_AcceptsPlusJSONVariants(t *testing.T) {
	accept := []string{
		"application/json",
		"application/json; charset=utf-8",
		"application/vnd.api+json",
		"application/merge-patch+json",
		"application/hal+json",
		"APPLICATION/JSON",
	}
	for _, ct := range accept {
		if !isJSONContentType(ct) {
			t.Errorf("isJSONContentType(%q) = false, want true", ct)
		}
	}
	reject := []string{"", "text/plain", "application/xml", "application/x-www-form-urlencoded", "multipart/form-data"}
	for _, ct := range reject {
		if isJSONContentType(ct) {
			t.Errorf("isJSONContentType(%q) = true, want false", ct)
		}
	}
}

// TestBodyObjectIDs_AcceptsPlusJSONContentType end-to-end: a body sent with a
// +json media type must still have its object IDs extracted.
func TestBodyObjectIDs_AcceptsPlusJSONContentType(t *testing.T) {
	r := httptest.NewRequest(http.MethodPatch, "/api/v1/orders", strings.NewReader(`{"order_id":1002}`))
	r.Header.Set("Content-Type", "application/vnd.api+json")
	got := bodyObjectIDs(r)
	if len(got["order_id"]) != 1 || got["order_id"][0] != "1002" {
		t.Fatalf("bodyObjectIDs with +json content-type: got %v, want order_id=[1002]", got)
	}
}

// runAbuseBodyID adds a propagated X-Gateway-Identity (the ownership claim), so
// ownership comparison against a non-subject identity can be exercised.
func runAbuseBodyID(cfg config.AbuseConfig, st Store, path, subject, identity, roles string, status int, body string) *httptest.ResponseRecorder {
	_ = InitTrustedProxies(nil)
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	})
	h := AbuseDetection(cfg, fakeLogger{}, st)(next)
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, path, nil)
	r.RemoteAddr = "1.2.3.4:1"
	if subject != "" {
		r.Header.Set("X-Gateway-Subject", subject)
	}
	if identity != "" {
		r.Header.Set("X-Gateway-Identity", identity)
	}
	if roles != "" {
		r.Header.Set("X-Gateway-Roles", roles)
	}
	h.ServeHTTP(rec, r)
	return rec
}

// Ownership compares against the propagated identity claim, NOT the subject: the
// caller's sub is an email but its id (identity) is 42, and it reads its own
// object (user_id=42) — must not flag even though sub != user_id.
func TestBOLAOwnership_IdentityClaimOwnerMatch(t *testing.T) {
	cfg := ownershipCfg()
	cfg.OwnerFields = []string{"user_id"}
	st := &fakeStore{}
	_ = runAbuseBodyID(cfg, st, "/api/orders/1", "bob@example.com", "42", "user", http.StatusOK, `{"user_id":"42"}`)
	if len(st.forensic) != 0 {
		t.Fatalf("owner-by-identity must not flag, got %+v", st.forensic)
	}
	if len(st.setOwners) != 1 || st.setOwners[0] != "42" {
		t.Fatalf("owner binding = %v, want [42]", st.setOwners)
	}
}

// Same setup, but the object belongs to 42 while the caller's identity is 43 — a
// confirmed IDOR, decided against the identity claim (not the email subject).
func TestBOLAOwnership_IdentityClaimCrossOwner(t *testing.T) {
	cfg := ownershipCfg()
	cfg.OwnerFields = []string{"user_id"}
	st := &fakeStore{}
	_ = runAbuseBodyID(cfg, st, "/api/orders/1", "carol@example.com", "43", "user", http.StatusOK, `{"user_id":"42"}`)
	if len(st.forensic) != 1 || st.forensic[0].Extra["severity"] != "critical" {
		t.Fatalf("cross-owner by identity must flag critical, got %+v", st.forensic)
	}
}

// Ownership is method-independent: an owner learned from a GET read must protect
// the same object against a cross-owner WRITE (PUT/DELETE), which is more
// dangerous (tampering/deletion) than a read.
func TestBOLAOwnership_ReadLearnedOwnerBlocksWrite(t *testing.T) {
	cfg := ownershipCfg()
	cfg.OwnerFields = []string{"user_id"}
	cfg.ObjectOwnershipBlock = true
	st := &fakeStore{}

	// 1. alice reads her own order via GET → owner bound from the body under the
	//    method-independent scope "/api/orders/{id}".
	if rec := runAbuseBody(cfg, st, "/api/orders/1001", "alice", "user", http.StatusOK, `{"user_id":"alice"}`); rec.Code != http.StatusOK {
		t.Fatalf("owner GET should pass: got %d", rec.Code)
	}

	// 2. bob tries to modify the same object via PUT — never PUT before — and is
	//    blocked by the ownership learned from the read.
	rec := runAbuseStatus(cfg, st, http.MethodPut, "/api/orders/1001", "bob", "user", http.StatusOK)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("cross-owner PUT: got %d, want 403 (read-learned ownership must cover writes)", rec.Code)
	}

	// 3. the real owner may still modify it via PUT.
	rec = runAbuseStatus(cfg, st, http.MethodPut, "/api/orders/1001", "alice", "user", http.StatusOK)
	if rec.Code != http.StatusOK {
		t.Fatalf("owner PUT: got %d, want 200", rec.Code)
	}
}

// A bypass role (support/admin) is allowed to see others' objects.
func TestBOLAOwnership_BypassRoleSkips(t *testing.T) {
	cfg := ownershipCfg()
	cfg.OwnerFields = []string{"user_id"}
	cfg.OwnershipBypassRoles = []string{"admin"}
	st := &fakeStore{}
	_ = runAbuseBody(cfg, st, "/api/orders/12345", "bob", "admin", http.StatusOK, `{"user_id":"alice"}`)
	if len(st.forensic) != 0 {
		t.Fatalf("bypass role must not flag, got %+v", st.forensic)
	}
}

// The legitimate owner re-reading its own object must never flag.
func TestBOLAOwnership_OwnAccessNotFlagged(t *testing.T) {
	st := &fakeStore{trackOwner: func() (int64, bool, error) { return 1, true, nil }} // alreadyOwned
	_ = runAbuseStatus(ownershipCfg(), st, http.MethodGet, "/api/orders/12345", "alice", "user", http.StatusOK)
	if len(st.forensic) != 0 {
		t.Fatalf("owner re-access must not flag, got %+v", st.forensic)
	}
}

// A broadly shared/public object (many prior owners) is not an ownership signal.
func TestBOLAOwnership_SharedObjectNotFlagged(t *testing.T) {
	st := &fakeStore{trackOwner: func() (int64, bool, error) { return 10, false, nil }} // > SharedObjectThreshold
	_ = runAbuseStatus(ownershipCfg(), st, http.MethodGet, "/api/orders/12345", "bob", "user", http.StatusOK)
	if len(st.forensic) != 0 {
		t.Fatalf("shared object must not flag, got %+v", st.forensic)
	}
}

// The killer discriminator: a cross-owner access the BACKEND denied (4xx) means
// authorization was enforced — not a leak — so it must NOT flag.
func TestBOLAOwnership_BackendDeniedNotFlagged(t *testing.T) {
	st := &fakeStore{trackOwner: func() (int64, bool, error) { return 1, false, nil }}
	_ = runAbuseStatus(ownershipCfg(), st, http.MethodGet, "/api/orders/12345", "bob", "user", http.StatusForbidden)
	if len(st.forensic) != 0 {
		t.Fatalf("backend-denied (403) cross access must not flag, got %+v", st.forensic)
	}
}

// Anonymous callers (no verified subject) are too noisy to attribute ownership.
func TestBOLAOwnership_AnonymousSkipped(t *testing.T) {
	st := &fakeStore{trackOwner: func() (int64, bool, error) { return 1, false, nil }}
	_ = runAbuseStatus(ownershipCfg(), st, http.MethodGet, "/api/orders/12345", "", "", http.StatusOK)
	if len(st.forensic) != 0 {
		t.Fatalf("anonymous access must not flag ownership, got %+v", st.forensic)
	}
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

// Regression: a backend may route case-insensitively, so "/ADMIN" must not slip
// past a "/admin" privileged rule.
func TestBFLA_CaseInsensitiveMatch(t *testing.T) {
	cfg := config.AbuseConfig{
		Enabled:   true,
		BlockMode: true,
		Privileged: []config.PrivilegedRule{
			{Path: "/admin", RequiredRoles: []string{"admin"}},
		},
	}
	for _, p := range []string{"/ADMIN/users", "/Admin/users", "/admin/users"} {
		rec := runAbuse(cfg, &fakeStore{}, http.MethodGet, p, "mallory", "user")
		if rec.Code != http.StatusForbidden {
			t.Errorf("BFLA case-bypass via %q: got %d, want 403", p, rec.Code)
		}
	}
}

// A path that merely shares a prefix but not a segment boundary must not be
// falsely flagged as privileged.
func TestBFLA_BoundaryNoFalsePositive(t *testing.T) {
	cfg := config.AbuseConfig{
		Enabled:   true,
		BlockMode: true,
		Privileged: []config.PrivilegedRule{
			{Path: "/admin", RequiredRoles: []string{"admin"}},
		},
	}
	rec := runAbuse(cfg, &fakeStore{}, http.MethodGet, "/administrators/list", "alice", "user")
	if rec.Code != http.StatusOK {
		t.Fatalf("/administrators wrongly flagged as /admin: got %d, want 200", rec.Code)
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

// Regression: enumerating string identifiers (slugs/usernames) that do not
// normalize to "{id}" must still be tracked via the terminal-segment fallback.
func TestBOLA_BlocksStringIDEnumeration(t *testing.T) {
	cfg := config.AbuseConfig{Enabled: true, BlockMode: true, EnumThreshold: 50, Window: time.Minute}
	st := &fakeStore{trackObject: func() (int64, error) { return 51, nil }}
	rec := runAbuse(cfg, st, http.MethodGet, "/api/members/alice", "scraper", "user")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("string-ID enumeration: got %d, want 429", rec.Code)
	}
}

// A single-segment path has no collection/object shape and must not be tracked.
func TestBOLA_SingleSegment_NotTracked(t *testing.T) {
	cfg := config.AbuseConfig{Enabled: true, BlockMode: true, EnumThreshold: 50, Window: time.Minute}
	st := &fakeStore{trackObject: func() (int64, error) { return 999, nil }}
	rec := runAbuse(cfg, st, http.MethodGet, "/health", "x", "user")
	if rec.Code != http.StatusOK {
		t.Fatalf("single-segment path should not be BOLA-tracked: got %d, want 200", rec.Code)
	}
}

// TestBOLA_BlocksQueryParamEnumeration is a regression test for VULN-M02: the
// BOLA/BFLA detector used to derive object IDs exclusively from URL-path
// segments, so a backend that keys object access off a query parameter
// (?order_id=1002) rather than a path segment was invisible to enumeration
// detection no matter how many distinct IDs one consumer swept. Uses a
// single-segment path so the path-fallback candidate (which would also fire
// on any query, since fakeStore.trackObject ignores its arguments) can't mask
// whether the query-side detection is actually what's firing.
func TestBOLA_BlocksQueryParamEnumeration(t *testing.T) {
	cfg := config.AbuseConfig{Enabled: true, BlockMode: true, EnumThreshold: 50, Window: time.Minute}
	st := &fakeStore{trackObject: func() (int64, error) { return 51, nil }}
	rec := runAbuse(cfg, st, http.MethodGet, "/orders?order_id=1002", "scraper", "user")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("query-param enumeration: got %d, want 429", rec.Code)
	}
}

// A UUID-shaped query value must be tracked the same way as a numeric one.
func TestBOLA_BlocksQueryParamEnumeration_UUID(t *testing.T) {
	cfg := config.AbuseConfig{Enabled: true, BlockMode: true, EnumThreshold: 50, Window: time.Minute}
	st := &fakeStore{trackObject: func() (int64, error) { return 51, nil }}
	rec := runAbuse(cfg, st, http.MethodGet, "/orders?id=550e8400-e29b-41d4-a716-446655440000", "scraper", "user")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("UUID query-param enumeration: got %d, want 429", rec.Code)
	}
}

// A free-text query parameter (not numeric/UUID-shaped) must NOT be treated as
// an object ID — otherwise a search/filter param would false-positive. Uses a
// single-segment path (like TestBOLA_SingleSegment_NotTracked) so the
// path-fallback candidate doesn't also fire and mask the query-side check.
func TestBOLA_QueryParam_FreeTextNotTracked(t *testing.T) {
	cfg := config.AbuseConfig{Enabled: true, BlockMode: true, EnumThreshold: 50, Window: time.Minute}
	st := &fakeStore{trackObject: func() (int64, error) { return 999, nil }}
	rec := runAbuse(cfg, st, http.MethodGet, "/search?q=laptop", "scraper", "user")
	if rec.Code != http.StatusOK {
		t.Fatalf("free-text query param should not be BOLA-tracked: got %d, want 200", rec.Code)
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

// ── BOLA blind-spot regressions: query batching + request body ──────────────

// TestBolaTargets_QueryBatchDefeatsThreshold is a regression test: the query-
// string BOLA fix originally required len(vals)==1, so an attacker batching
// an entire enumeration sweep into one request (?id=1&id=2&...&id=1000, or
// the comma-joined ?ids=1,2,...,1000 form) was silently dropped — zero IDs
// counted — while the identical sweep split across N single-id requests
// would have been caught. bolaTargets must track every qualifying value.
func TestBolaTargets_QueryBatchDefeatsThreshold(t *testing.T) {
	q := url.Values{"id": {"1", "2", "3"}}
	ids := idsFor(t, bolaTargets(http.MethodGet, "/api/v1/orders", q, nil), "?id=")
	if len(ids) != 3 {
		t.Fatalf("repeated ?id=1&id=2&id=3: got %d ids %v, want 3", len(ids), ids)
	}

	q2 := url.Values{"ids": {"10,20,30"}}
	ids2 := idsFor(t, bolaTargets(http.MethodGet, "/api/v1/orders", q2, nil), "?ids=")
	if len(ids2) != 3 {
		t.Fatalf("comma-joined ?ids=10,20,30: got %d ids %v, want 3", len(ids2), ids2)
	}

	// Free-text params must still be ignored (no false positives from a
	// multi-valued non-ID param).
	q3 := url.Values{"tag": {"red", "blue"}}
	cands3 := bolaTargets(http.MethodGet, "/api/v1/orders", q3, nil)
	for _, c := range cands3 {
		if strings.Contains(c.scope, "?tag=") {
			t.Fatalf("free-text ?tag=red&tag=blue must not be treated as an ID candidate, got %+v", c)
		}
	}
}

// TestBodyObjectIDs_ExtractsAndBatches is a regression test for the BOLA
// body blind spot: an object reference carried in a JSON request body
// (PATCH /orders {"order_id":1002}) or a batch body ({"ids":[1,2,3]}) used to
// be invisible to BOLA detection entirely, since only the path and query
// string were inspected.
func TestBodyObjectIDs_ExtractsAndBatches(t *testing.T) {
	r := httptest.NewRequest(http.MethodPatch, "/api/v1/orders", strings.NewReader(`{"order_id":1002,"note":"hi"}`))
	r.Header.Set("Content-Type", "application/json")
	got := bodyObjectIDs(r)
	if len(got["order_id"]) != 1 || got["order_id"][0] != "1002" {
		t.Fatalf("bodyObjectIDs single field: got %v, want order_id=[1002]", got)
	}
	// Body must be rewound so a downstream reader (proxy/DLP) still sees it.
	rest, _ := io.ReadAll(r.Body)
	if !strings.Contains(string(rest), "order_id") {
		t.Fatalf("body was not rewound after extraction: got %q", rest)
	}

	r2 := httptest.NewRequest(http.MethodPost, "/api/v1/orders/batch", strings.NewReader(`{"ids":[1,2,3],"valid":true}`))
	r2.Header.Set("Content-Type", "application/json")
	got2 := bodyObjectIDs(r2)
	if len(got2["ids"]) != 3 {
		t.Fatalf("bodyObjectIDs batch array: got %v, want 3 ids", got2["ids"])
	}
	// "valid" ends in "id" as a bare substring but is not an id-shaped field
	// name (looksLikeIDField requires "id"/"_id"/"Id" boundary) — must not
	// appear even though its value wouldn't pass looksLikeObjectID anyway.
	if _, present := got2["valid"]; present {
		t.Fatalf("bodyObjectIDs false-positived on field 'valid': got %v", got2)
	}

	// Non-JSON body: no extraction, no panic.
	r3 := httptest.NewRequest(http.MethodPost, "/api/v1/orders", strings.NewReader("order_id=1002"))
	r3.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if got3 := bodyObjectIDs(r3); got3 != nil {
		t.Fatalf("bodyObjectIDs on non-JSON content-type: got %v, want nil", got3)
	}
}

// TestAbuseDetection_BodyIDEnumeration is an end-to-end regression test: a
// consumer sweeping object IDs via a JSON body field (rather than the path or
// query string) must still trip BOLA enumeration.
func TestAbuseDetection_BodyIDEnumeration(t *testing.T) {
	cfg := config.AbuseConfig{Enabled: true, BlockMode: false, EnumThreshold: 50, Window: time.Minute}
	st := &fakeStore{trackObject: func() (int64, error) { return 60, nil }}
	_ = InitTrustedProxies(nil)
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	h := AbuseDetection(cfg, fakeLogger{}, st)(next)
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/orders/action", strings.NewReader(`{"order_id":9001}`))
	r.Header.Set("Content-Type", "application/json")
	r.RemoteAddr = "1.2.3.4:1"
	r.Header.Set("X-Gateway-Subject", "scraper")
	h.ServeHTTP(rec, r)
	found := false
	for _, ev := range st.forensic {
		if ev.Reason != "bola_enumeration" {
			continue
		}
		if ep, _ := ev.Extra["endpoint"].(string); strings.Contains(ep, "body.order_id") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a bola_enumeration event for body field order_id, got %+v", st.forensic)
	}
}

// idsFor collects the ids of every candidate whose scope mentions want.
func idsFor(t *testing.T, cands []bolaCandidate, want string) []string {
	t.Helper()
	for _, c := range cands {
		if strings.Contains(c.scope, want) {
			return c.ids
		}
	}
	return nil
}
