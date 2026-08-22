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

// TestGetLicense_LastDayStillReportsDaysLeft is a regression test: DaysLeft
// used to be a plain `int` with `json:",omitempty"` — a license on its FINAL
// day legitimately computes DaysLeft == 0, and omitempty silently drops a
// zero value from the JSON response entirely, hiding the single most urgent
// renewal-warning state from the console banner (every other day, 14 down to
// 1, rendered correctly; day 0 vanished). DaysLeft is now a *int so the field
// is present (0) here and only absent for a genuinely never-expiring license.
func TestGetLicense_LastDayStillReportsDaysLeft(t *testing.T) {
	h, _ := redisHandlers(t)
	expires := time.Now().Add(2 * time.Hour) // < 24h left -> DaysLeft computes to 0
	withLicenseStatus(h, license.Status{
		Valid: true, DaysLeft: 0,
		Claims: license.Claims{Licensee: "Acme Corp", Tier: "trial", ExpiresAt: expires},
	})

	rec, body := doReq(h.getLicense, http.MethodGet, "/api/license", ctxAs("acme", iam.RoleViewer, false), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("getLicense = %d, want 200", rec.Code)
	}
	got, ok := body["days_left"]
	if !ok {
		t.Fatal("days_left must be present (0) on the license's final day, not omitted")
	}
	if got != float64(0) {
		t.Fatalf("days_left = %v, want 0", got)
	}
}

// TestGetLicense_NeverExpiresOmitsDaysLeft is the counterpart: a license with
// no ExpiresAt (internal/demo use) has no meaningful DaysLeft at all — this
// must stay absent from the response (nil *int), not render as a false "0
// days left" expiry warning.
func TestGetLicense_NeverExpiresOmitsDaysLeft(t *testing.T) {
	h, _ := redisHandlers(t)
	withLicenseStatus(h, license.Status{
		Valid:  true,
		Claims: license.Claims{Licensee: "Internal", Tier: "internal"}, // ExpiresAt zero value
	})

	rec, body := doReq(h.getLicense, http.MethodGet, "/api/license", ctxAs("acme", iam.RoleViewer, false), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("getLicense = %d, want 200", rec.Code)
	}
	if _, ok := body["days_left"]; ok {
		t.Fatalf("days_left should be omitted for a never-expiring license, got %v", body["days_left"])
	}
	if _, ok := body["expires_at"]; ok {
		t.Fatalf("expires_at should also be omitted for a never-expiring license, got %v", body["expires_at"])
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
