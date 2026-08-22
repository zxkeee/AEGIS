package api

import (
	"net/http"

	"api-gateway/internal/license"
)

// licenseResp is the wire shape for GET /api/license — deliberately never
// includes the raw HardwareID/CurrentFingerprint strings from license.Status;
// those aren't secret, but they're also not anything the console UI needs,
// and keeping the response minimal avoids having to reason about which
// fields are safe to hand to a "viewer"-role session later if that ever
// changes.
type licenseResp struct {
	Valid      bool   `json:"valid"`
	Grace      bool   `json:"grace"`
	Licensee   string `json:"licensee,omitempty"`
	Tier       string `json:"tier,omitempty"`
	ExpiresAt  string `json:"expires_at,omitempty"`
	DaysLeft   int    `json:"days_left,omitempty"`
	GraceUntil string `json:"grace_until,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

// GET /api/license reports the gateway's current license status (set on boot
// and on every hot-reload — see cmd/gateway/main.go's loadValidatedConfig and
// Server.SetLicenseStatus) so the console can show a banner instead of an
// operator needing to read gateway logs. Any authenticated session (viewer or
// admin) can read this — it's not sensitive, and a viewer is exactly the role
// most likely to just be watching for "is this thing licensed."
//
// loadValidatedConfig treats an invalid license as a hard boot/reload
// rejection, so in practice this endpoint reports either a fully valid
// license or a Grace-period hardware mismatch — never a "hard invalid"
// status, because the gateway serving this request could not have booted
// with one. The Reason/false-Valid shape is still exposed for completeness
// and so handlers_test can exercise it without depending on that invariant.
func (h *handlers) getLicense(w http.ResponseWriter, r *http.Request) {
	var st license.Status
	if h.licenseStatus != nil {
		st, _ = h.licenseStatus.Load().(license.Status)
	}

	resp := licenseResp{Valid: st.Valid, Grace: st.Grace, Reason: st.Reason}
	if st.Valid || st.Grace {
		resp.Licensee = st.Claims.Licensee
		resp.Tier = st.Claims.Tier
		if !st.Claims.ExpiresAt.IsZero() {
			resp.ExpiresAt = st.Claims.ExpiresAt.Format("2006-01-02")
			resp.DaysLeft = st.DaysLeft
		}
	}
	if st.Grace {
		resp.GraceUntil = st.GraceUntil.Format("2006-01-02T15:04:05Z07:00")
	}
	writeJSON(w, http.StatusOK, resp)
}
