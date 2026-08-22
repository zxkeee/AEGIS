package api

import (
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"api-gateway/internal/iam"
	"api-gateway/internal/license"
)

func withLicenseStatus(h *handlers, st license.Status) {
	v := &atomic.Value{}
	v.Store(st)
	h.licenseStatus = v
}

func TestGetLicense_ValidLicense(t *testing.T) {
	h, _ := redisHandlers(t)
	expires := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	withLicenseStatus(h, license.Status{
		Valid: true, DaysLeft: 42,
		Claims: license.Claims{Licensee: "Acme Corp", Tier: "pilot", ExpiresAt: expires},
	})

	rec, body := doReq(h.getLicense, http.MethodGet, "/api/license", ctxAs("acme", iam.RoleViewer, false), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("getLicense = %d, want 200", rec.Code)
	}
	if body["valid"] != true || body["licensee"] != "Acme Corp" || body["tier"] != "pilot" {
		t.Fatalf("getLicense body = %v", body)
	}
	if body["expires_at"] != "2026-12-01" {
		t.Fatalf("expires_at = %v, want 2026-12-01", body["expires_at"])
	}
	if body["grace"] != false {
		t.Fatalf("grace = %v, want false for a plain valid license", body["grace"])
	}
}

func TestGetLicense_GraceStillReportsLicenseeAndTier(t *testing.T) {
	h, _ := redisHandlers(t)
	until := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	withLicenseStatus(h, license.Status{
		Valid: true, Grace: true, GraceUntil: until,
		Claims: license.Claims{Licensee: "Acme Corp", Tier: "pilot"},
	})

	rec, body := doReq(h.getLicense, http.MethodGet, "/api/license", ctxAs("acme", iam.RoleViewer, false), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("getLicense = %d, want 200", rec.Code)
	}
	if body["grace"] != true {
		t.Fatalf("grace = %v, want true", body["grace"])
	}
	if body["licensee"] != "Acme Corp" {
		t.Fatalf("licensee = %v, want Acme Corp even in grace", body["licensee"])
	}
	if body["grace_until"] == nil || body["grace_until"] == "" {
		t.Fatal("expected grace_until to be set during a grace period")
	}
}

func TestGetLicense_InvalidHidesLicenseeDetail(t *testing.T) {
	h, _ := redisHandlers(t)
	withLicenseStatus(h, license.Status{
		Valid: false, Reason: "license expired",
		Claims: license.Claims{Licensee: "Acme Corp", Tier: "pilot"},
	})

	rec, body := doReq(h.getLicense, http.MethodGet, "/api/license", ctxAs("acme", iam.RoleViewer, false), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("getLicense = %d, want 200", rec.Code)
	}
	if body["valid"] != false {
		t.Fatalf("valid = %v, want false", body["valid"])
	}
	if body["reason"] != "license expired" {
		t.Fatalf("reason = %v, want %q", body["reason"], "license expired")
	}
	if _, ok := body["licensee"]; ok {
		t.Fatal("licensee should be omitted (omitempty) for a fully invalid status")
	}
}

func TestGetLicense_NoStatusRecordedYet(t *testing.T) {
	h, _ := redisHandlers(t) // h.licenseStatus is nil — nothing recorded

	rec, body := doReq(h.getLicense, http.MethodGet, "/api/license", ctxAs("acme", iam.RoleViewer, false), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("getLicense = %d, want 200", rec.Code)
	}
	if body["valid"] != false {
		t.Fatalf("valid = %v, want false when no status has been recorded", body["valid"])
	}
}
