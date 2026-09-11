package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"api-gateway/internal/iam"
	"api-gateway/internal/logger"
)

// The range check ran on the input and the cap on the resulting time.Duration,
// so a value large enough to overflow int64 nanoseconds landed between them:
// positive, non-zero, and under the cap. The endpoint answered "JWT revoked"
// and the revocation evaporated a fraction of a second later — the worst
// failure this handler has, because it reports success.
func TestRevokeJWT_TTLCannotOverflowPastTheCap(t *testing.T) {
	h := &handlers{log: logger.New("error")}

	// 18446744074s ≈ 2^64 ns, the classic overflow. Also the plain int64 max
	// and a value just past the cap.
	for _, ttl := range []int64{18446744074, 1 << 62, 9223372036854775807, maxRevocationTTLSeconds + 1} {
		body := `{"jti":"x","ttl_seconds":` + strconv.FormatInt(ttl, 10) + `}`
		r := httptest.NewRequest(http.MethodPost, "/api/jwt/revoke", strings.NewReader(body))
		r = r.WithContext(iam.WithRole(r.Context(), iam.RoleAdmin))
		rec := httptest.NewRecorder()
		h.revokeJWT(rec, r)

		if rec.Code != http.StatusBadRequest {
			var out map[string]any
			_ = json.Unmarshal(rec.Body.Bytes(), &out)
			t.Errorf("ttl_seconds=%d: status = %d, want 400 (got %v) — a revocation must never "+
				"report success with a TTL the caller did not ask for", ttl, rec.Code, out)
		}
	}

	// Negative is still refused, and the boundary value is still accepted as
	// far as validation goes (it fails later on the absent store, not here).
	r := httptest.NewRequest(http.MethodPost, "/api/jwt/revoke", strings.NewReader(`{"jti":"x","ttl_seconds":-1}`))
	r = r.WithContext(iam.WithRole(r.Context(), iam.RoleAdmin))
	rec := httptest.NewRecorder()
	h.revokeJWT(rec, r)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("negative ttl: status = %d, want 400", rec.Code)
	}
}

// The cap is 30 days expressed in the caller's units, so it can be applied to
// the input before any conversion can overflow.
func TestMaxRevocationTTL(t *testing.T) {
	if got := time.Duration(maxRevocationTTLSeconds) * time.Second; got != 30*24*time.Hour {
		t.Errorf("cap = %s, want 30 days", got)
	}
}
