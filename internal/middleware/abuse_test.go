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
