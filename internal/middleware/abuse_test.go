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
	"api-gateway/internal/gql"
)

func runAbuse(cfg config.AbuseConfig, st Store, method, path, subject, roles string) *httptest.ResponseRecorder {
	_ = InitTrustedProxies(nil)
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	h := AbuseDetection(cfg, "", fakeLogger{}, st, nil)(next)
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
	h := AbuseDetection(cfg, "", fakeLogger{}, st, nil)(next)
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
	h := AbuseDetection(cfg, "", fakeLogger{}, st, nil)(next)
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
	h := AbuseDetection(cfg, "", fakeLogger{}, st, nil)(next)
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
	ids := idsFor(t, bolaTargets(http.MethodGet, "/api/v1/orders", q, nil, nil), "?id=")
	if len(ids) != 3 {
		t.Fatalf("repeated ?id=1&id=2&id=3: got %d ids %v, want 3", len(ids), ids)
	}

	q2 := url.Values{"ids": {"10,20,30"}}
	ids2 := idsFor(t, bolaTargets(http.MethodGet, "/api/v1/orders", q2, nil, nil), "?ids=")
	if len(ids2) != 3 {
		t.Fatalf("comma-joined ?ids=10,20,30: got %d ids %v, want 3", len(ids2), ids2)
	}

	// Free-text params must still be ignored (no false positives from a
	// multi-valued non-ID param).
	q3 := url.Values{"tag": {"red", "blue"}}
	cands3 := bolaTargets(http.MethodGet, "/api/v1/orders", q3, nil, nil)
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
	h := AbuseDetection(cfg, "", fakeLogger{}, st, nil)(next)
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

// ── GraphQL BOLA (ROADMAP.md B5) ────────────────────────────────────────────

func TestBolaTargets_GraphQLArgumentBecomesCandidate(t *testing.T) {
	op, err := gql.Parse([]byte(`{"query":"query GetUser { user(id: 42) { id name } }"}`))
	if err != nil {
		t.Fatalf("gql.Parse: %v", err)
	}
	cands := bolaTargets(http.MethodPost, "/graphql", nil, nil, op)
	ids := idsFor(t, cands, "gql.query.GetUser.user")
	if len(ids) != 1 || ids[0] != "42" {
		t.Fatalf("ids = %v, want [\"42\"]", ids)
	}
}

func TestBolaTargets_GraphQLDifferentOperationsDoNotShareScope(t *testing.T) {
	op1, err := gql.Parse([]byte(`{"query":"query GetUser { user(id: 1) { id } }"}`))
	if err != nil {
		t.Fatalf("gql.Parse: %v", err)
	}
	op2, err := gql.Parse([]byte(`{"query":"query GetOrder { user(id: 2) { id } }"}`)) // same field name "user", different op
	if err != nil {
		t.Fatalf("gql.Parse: %v", err)
	}
	c1 := bolaTargets(http.MethodPost, "/graphql", nil, nil, op1)
	c2 := bolaTargets(http.MethodPost, "/graphql", nil, nil, op2)
	if c1[0].scope == c2[0].scope {
		t.Fatalf("two different operations sharing a field name must not share a BOLA scope, both got %q", c1[0].scope)
	}
}

func TestBolaTargets_GraphQLNonIDArgumentIgnored(t *testing.T) {
	op, err := gql.Parse([]byte(`{"query":"query Search { products(category: \"shoes\") { id } }"}`))
	if err != nil {
		t.Fatalf("gql.Parse: %v", err)
	}
	cands := bolaTargets(http.MethodPost, "/graphql", nil, nil, op)
	if len(cands) != 0 {
		t.Fatalf("a non-id-shaped argument name must not produce a BOLA candidate, got %+v", cands)
	}
}

func TestBolaTargets_NilGraphQLOperationProducesNoGraphQLCandidates(t *testing.T) {
	cands := bolaTargets(http.MethodGet, "/graphql", nil, nil, nil)
	if len(cands) != 0 {
		t.Fatalf("nil gqlOp must add nothing, got %+v", cands)
	}
}

func TestAbuseDetection_GraphQLEnumeration(t *testing.T) {
	cfg := config.AbuseConfig{Enabled: true, BlockMode: false, EnumThreshold: 50, Window: time.Minute}
	st := &fakeStore{trackObject: func() (int64, error) { return 60, nil }}
	_ = InitTrustedProxies(nil)
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	h := AbuseDetection(cfg, "/graphql", fakeLogger{}, st, nil)(next)
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(`{"query":"query GetUser { user(id: 42) { id } }"}`))
	r.Header.Set("Content-Type", "application/json")
	r.RemoteAddr = "1.2.3.4:1"
	r.Header.Set("X-Gateway-Subject", "scraper")
	h.ServeHTTP(rec, r)

	found := false
	for _, ev := range st.forensic {
		if ev.Reason != "bola_enumeration" {
			continue
		}
		if ep, _ := ev.Extra["endpoint"].(string); strings.Contains(ep, "gql.query.GetUser.user") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a bola_enumeration event scoped to the GraphQL operation, got %+v", st.forensic)
	}
}

func TestAbuseDetection_GraphQLPathUnsetIgnoresGraphQLBody(t *testing.T) {
	// graphQLPath empty (default): a request that would otherwise look like
	// GraphQL must not be parsed as such — zero behavior change when the
	// feature isn't opted into.
	cfg := config.AbuseConfig{Enabled: true, BlockMode: false, EnumThreshold: 50, Window: time.Minute}
	st := &fakeStore{trackObject: func() (int64, error) { return 60, nil }}
	_ = InitTrustedProxies(nil)
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	h := AbuseDetection(cfg, "", fakeLogger{}, st, nil)(next) // graphQLPath: ""
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(`{"query":"query GetUser { user(id: 42) { id } }"}`))
	r.Header.Set("Content-Type", "application/json")
	r.RemoteAddr = "1.2.3.4:1"
	r.Header.Set("X-Gateway-Subject", "scraper")
	h.ServeHTTP(rec, r)

	for _, ev := range st.forensic {
		if strings.Contains(fmtExtra(ev.Extra["endpoint"]), "gql.") {
			t.Fatalf("GraphQL parsing must be opt-in; got a gql-scoped event with graphQLPath unset: %+v", ev)
		}
	}
}

func TestPeekGraphQLOperation_BodyReachesDownstream(t *testing.T) {
	body := `{"query":"query GetUser { user(id: 1) { id } }"}`
	r := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(body))
	op := peekGraphQLOperation(r, "/graphql")
	if op == nil || op.Name != "GetUser" {
		t.Fatalf("op = %+v, want a parsed GetUser operation", op)
	}
	got, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("read restored body: %v", err)
	}
	if string(got) != body {
		t.Fatalf("body after peek = %q, want %q (must be restored byte-for-byte)", got, body)
	}
}

func TestPeekGraphQLOperation_WrongPathReturnsNil(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/other", strings.NewReader(`{"query":"{ me { id } }"}`))
	if op := peekGraphQLOperation(r, "/graphql"); op != nil {
		t.Fatalf("expected nil for a request not targeting graphQLPath, got %+v", op)
	}
}

func fmtExtra(v any) string {
	s, _ := v.(string)
	return s
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

// ── Nested owner fields ──────────────────────────────────────────────────────
//
// Real APIs return the owner as an object, not a flat id. Against a live
// Forgejo every response looked like {"user":{"id":70422,…}} and a flat-key
// lookup found nothing on every request, so confirmed-IDOR never fired
// (assessment, 2026-08-31). These pin the dotted-path form that fixes it.

// The exact shape a Forgejo/Gitea issue comes back in, trimmed to the parts
// that matter — the owner is two levels down and is a number, not a string.
const forgejoIssueBody = `{
  "id": 6978952,
  "number": 14195,
  "title": "fix: notification link",
  "user": {"id": 70422, "login": "forgejo", "email": "x@example.com"},
  "repository": {"id": 73144, "owner": "forgejo", "name": "forgejo"}
}`

func TestBOLAOwnership_ConfirmedFromNestedField(t *testing.T) {
	cfg := ownershipCfg()
	cfg.OwnerFields = []string{"user.id"}
	st := &fakeStore{}
	// Caller is 99999; the object belongs to 70422 — a real cross-owner read.
	_ = runAbuseBody(cfg, st, "/api/v1/repos/forgejo/forgejo/issues/14195",
		"99999", "user", http.StatusOK, forgejoIssueBody)

	if len(st.forensic) != 1 || st.forensic[0].Reason != "bola_object_ownership" {
		t.Fatalf("expected 1 confirmed IDOR event, got %+v", st.forensic)
	}
	if st.forensic[0].Extra["confirmed"] != true {
		t.Fatalf("event = %+v, want confirmed from the response body", st.forensic[0].Extra)
	}
	if len(st.setOwners) != 1 || st.setOwners[0] != "70422" {
		t.Fatalf("owner binding = %v, want [70422] (numeric id, exact precision)", st.setOwners)
	}
}

func TestBOLAOwnership_NestedOwnerMatchesNotFlagged(t *testing.T) {
	cfg := ownershipCfg()
	cfg.OwnerFields = []string{"user.id"}
	st := &fakeStore{}
	_ = runAbuseBody(cfg, st, "/api/v1/repos/forgejo/forgejo/issues/14195",
		"70422", "user", http.StatusOK, forgejoIssueBody)
	if len(st.forensic) != 0 {
		t.Fatalf("owner reading its own object must not flag, got %+v", st.forensic)
	}
}

func TestExtractOwner_PathForms(t *testing.T) {
	tests := []struct {
		name   string
		body   string
		fields []string
		want   string
	}{
		{"flat key still works", `{"user_id":"alice"}`, []string{"user_id"}, "alice"},
		{"nested one level", `{"user":{"id":70422}}`, []string{"user.id"}, "70422"},
		{"nested two levels", `{"data":{"attributes":{"owner_id":7}}}`,
			[]string{"data.attributes.owner_id"}, "7"},
		{"data envelope plus nested path", `{"data":{"owner":{"id":"o-1"}}}`,
			[]string{"owner.id"}, "o-1"},
		{"first matching field wins", `{"owner":{"id":1},"user":{"id":2}}`,
			[]string{"owner.id", "user.id"}, "1"},
		{"falls through to the next field when absent", `{"user":{"id":2}}`,
			[]string{"owner.id", "user.id"}, "2"},
		// An object is not an id. Stringifying one would bind a nonsense owner
		// and produce a permanent false IDOR on every later read of that object.
		{"object value is not an owner", `{"user":{"id":{"nested":1}}}`,
			[]string{"user.id"}, ""},
		{"array value is not an owner", `{"owners":[1,2]}`, []string{"owners"}, ""},
		{"path through a non-object misses", `{"user":"alice"}`, []string{"user.id"}, ""},
		{"missing path misses", `{"a":{"b":1}}`, []string{"x.y"}, ""},
		{"empty body", ``, []string{"user.id"}, ""},
		{"not json", `<html>`, []string{"user.id"}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractOwner([]byte(tt.body), tt.fields); got != tt.want {
				t.Errorf("extractOwner(%s, %v) = %q, want %q", tt.body, tt.fields, got, tt.want)
			}
		})
	}
}

// TestBOLAOwnership_AnonymousCallerNotFlagged pins the guard that makes the
// dotted-path owner lookup safe to ship.
//
// Confirmed-ownership compares the body's owner against the caller's identity,
// and an anonymous caller has none — so the comparison "owner != identity" is
// trivially true for every object in existence. The single `subject != ""`
// condition in AbuseDetection is the only thing standing between that and a
// critical IDOR finding on every read.
//
// It mattered little while owner extraction rarely succeeded (flat keys missed
// on most real APIs). Now that a dotted path finds the owner in a Forgejo,
// GitHub or Stripe response almost every time, this configuration —
// owner_fields set, auth disabled, which is exactly what
// config/gateway.pilot.yaml ships — would otherwise turn an ordinary pilot into
// a wall of false criticals on day one.
func TestBOLAOwnership_AnonymousCallerNotFlagged(t *testing.T) {
	cfg := ownershipCfg()
	cfg.OwnerFields = []string{"user.id"}
	const path = "/api/v1/repos/forgejo/forgejo/issues/14195"
	const body = `{"user":{"id":70422}}`

	// Control: an identified caller reading someone else's object IS flagged,
	// so the code path under test is genuinely reachable and this test would
	// notice if the guard were removed.
	identified := &fakeStore{}
	_ = runAbuseBody(cfg, identified, path, "99999", "user", http.StatusOK, body)
	if len(identified.forensic) != 1 {
		t.Fatalf("control: identified cross-owner read produced %d events, want 1 — "+
			"the anonymous case below would then prove nothing", len(identified.forensic))
	}

	anon := &fakeStore{}
	_ = runAbuseBody(cfg, anon, path, "", "", http.StatusOK, body)
	for _, e := range anon.forensic {
		t.Errorf("anonymous caller flagged: %s — %v", e.Reason, e.Extra["why"])
	}
}

// ── Pseudonymous consumers (opaque credentials, no JWT) ──────────────────────

// runAbusePseudonym drives AbuseDetection for a caller identified only by the
// pseudonym middleware.ConsumerID derives from an opaque credential.
func runAbusePseudonym(cfg config.AbuseConfig, st Store, path, consumerKey string, status int, body string) {
	_ = InitTrustedProxies(nil)
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	})
	h := AbuseDetection(cfg, "", fakeLogger{}, st, nil)(next)
	r := httptest.NewRequest(http.MethodGet, path, nil)
	r.RemoteAddr = "1.2.3.4:1"
	if consumerKey != "" {
		r.Header.Set("X-Gateway-Consumer-Key", consumerKey)
	}
	h.ServeHTTP(httptest.NewRecorder(), r)
}

// The point of the whole feature: two callers holding different opaque tokens
// must be two consumers. Attributed to a shared "ip:" identity, one caller
// sweeping objects and a hundred ordinary callers are indistinguishable, and
// every per-consumer control is measuring noise.
func TestBOLA_PseudonymSeparatesConsumers(t *testing.T) {
	cfg := ownershipCfg()
	cfg.OwnerFields = nil // heuristic path: it is what works without a JWT
	st := &fakeStore{}

	// Two different callers reading the SAME object. Under the old behaviour
	// both were "ip:1.2.3.4" and the second read looked like the first caller
	// re-reading its own object.
	runAbusePseudonym(cfg, st, "/api/orders/12345", "token:aaaa", http.StatusOK, `{"x":1}`)
	runAbusePseudonym(cfg, st, "/api/orders/12345", "token:bbbb", http.StatusOK, `{"x":1}`)

	if len(st.trackedOwners) < 2 {
		t.Fatalf("expected both callers to be tracked separately, got %v", st.trackedOwners)
	}
	if st.trackedOwners[0] == st.trackedOwners[1] {
		t.Errorf("both callers recorded as the same consumer %q", st.trackedOwners[0])
	}
}

// The trap this must not fall into. A pseudonym is a hash of a credential, so it
// can never equal an owner id read out of a response body — comparing them would
// make "owner != caller" true for every object in existence and turn an ordinary
// pilot into a wall of critical findings on day one. It is the same failure the
// anonymous caller is guarded against, and the guard has to cover this case too.
func TestBOLAOwnership_PseudonymDoesNotConfirmIDOR(t *testing.T) {
	cfg := ownershipCfg()
	cfg.OwnerFields = []string{"user.id"}
	st := &fakeStore{}

	runAbusePseudonym(cfg, st, "/api/v1/repos/forgejo/forgejo/issues/14195",
		"token:aaaa", http.StatusOK, `{"user":{"id":70422}}`)

	for _, e := range st.forensic {
		if e.Extra["confirmed"] == true {
			t.Errorf("pseudonymous caller produced a confirmed IDOR: %v", e.Extra["why"])
		}
	}
}

// Enumeration is pure consumer-equality counting, so it is the detection that
// benefits most: a sweep by one token-authenticated caller is now visible as one
// caller rather than smeared across a shared address.
func TestBOLA_PseudonymEnumerationIsAttributed(t *testing.T) {
	cfg := ownershipCfg()
	cfg.OwnerFields = nil
	cfg.EnumThreshold = 3
	st := &fakeStore{trackObject: func() (int64, error) { return 4, nil }} // over the ceiling

	runAbusePseudonym(cfg, st, "/api/orders/99", "token:sweeper", http.StatusOK, `{}`)

	if len(st.forensic) != 1 {
		t.Fatalf("expected an enumeration event, got %+v", st.forensic)
	}
	if got := st.forensic[0].Extra["consumer"]; got != "token:sweeper" {
		t.Errorf("consumer = %v, want token:sweeper (not the source address)", got)
	}
}

// When a caller presents neither a verified JWT subject nor an opaque
// credential, BOLA can only name it by address — and behind a proxy that address
// comes from a header the caller controls, so varying it makes every request a
// fresh consumer and enumeration never accumulates. That is not fixable inside
// the detector, but it must be visible: an operator reading a BOLA report needs
// to know what share of traffic the verdict rested on such an identity, rather
// than assuming it was zero.
func TestAbuse_CountsIdentityDerivedFromAddressAlone(t *testing.T) {
	if err := InitTrustedProxies([]string{"203.0.113.7"}); err != nil {
		t.Fatalf("InitTrustedProxies: %v", err)
	}
	defer func() { _ = InitTrustedProxies(nil) }()

	st := &fakeStore{}
	h := AbuseDetection(config.AbuseConfig{Enabled: true}, "", fakeLogger{}, st, nil)(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))

	// Behind the trusted proxy, with no credential of any kind: the identity is
	// whatever X-Forwarded-For says.
	r := httptest.NewRequest(http.MethodGet, "/orders/42", nil)
	r.RemoteAddr = "203.0.113.7:5555"
	r.Header.Set("X-Forwarded-For", "198.51.100.9")
	h.ServeHTTP(httptest.NewRecorder(), r)

	if st.metrics["abuse_consumer_ip_only"] == 0 {
		t.Error("an address-only consumer was not counted: the weakness is invisible on /api/metrics")
	}
	if st.metrics["abuse_consumer_ip_from_header"] == 0 {
		t.Error("a header-derived address was not distinguished from a real peer address")
	}

	// A verified subject is a real identity and must not be counted as one.
	st2 := &fakeStore{}
	h2 := AbuseDetection(config.AbuseConfig{Enabled: true}, "", fakeLogger{}, st2, nil)(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	r2 := httptest.NewRequest(http.MethodGet, "/orders/42", nil)
	r2.Header.Set("X-Gateway-Subject", "alice")
	h2.ServeHTTP(httptest.NewRecorder(), r2)
	if st2.metrics["abuse_consumer_ip_only"] != 0 {
		t.Error("a JWT-identified caller was counted as address-only")
	}
}
