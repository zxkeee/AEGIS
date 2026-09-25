package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"api-gateway/internal/config"
	"api-gateway/internal/logger"
)

// The console showed "Security Overview" with active controls while the gateway
// was configured to block nothing. An operator running a pilot in observe or
// mirror mode had no way to learn that from the screen — the information
// existed only in a log line at startup.
func TestGetSession_ReportsWhatTheGatewayActuallyDoesToTraffic(t *testing.T) {
	cases := []struct {
		name      string
		cfg       config.GatewayConfig
		wantMode  string
		enforcing bool
	}{
		{"a plain config enforces", config.GatewayConfig{}, "enforce", true},
		{"observe blocks nothing", config.GatewayConfig{Observe: true}, "observe", false},
		{"mirror is not even in the path", config.GatewayConfig{MirrorSink: true}, "mirror", false},
		{"mirror wins over observe", config.GatewayConfig{Observe: true, MirrorSink: true}, "mirror", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &Server{}
			s.SetEnforcementMode(tc.cfg)
			h := &handlers{log: logger.New("error"), enforcement: &s.enforcement}

			rec := httptest.NewRecorder()
			h.getSession(rec, httptest.NewRequest(http.MethodGet, "/api/session", nil))

			var got struct {
				Enforcement EnforcementMode `json:"enforcement"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatalf("decode: %v (body %s)", err, rec.Body.String())
			}
			if got.Enforcement.Mode != tc.wantMode {
				t.Errorf("mode = %q, want %q", got.Enforcement.Mode, tc.wantMode)
			}
			if got.Enforcement.Enforcing != tc.enforcing {
				t.Errorf("enforcing = %v, want %v", got.Enforcement.Enforcing, tc.enforcing)
			}
			if !tc.enforcing && got.Enforcement.Reason == "" {
				t.Error("a passive mode with no reason gives the operator a warning they cannot act on")
			}
		})
	}
}

// An absent value must read as enforcing. The failure this whole feature
// prevents is an operator trusting protection that is not running; inventing a
// warning when we simply do not know would train them to dismiss the real one.
func TestGetSession_UnsetEnforcementDoesNotInventAWarning(t *testing.T) {
	for _, h := range []*handlers{
		{log: logger.New("error")},
		{log: logger.New("error"), enforcement: new(atomic.Value)},
	} {
		rec := httptest.NewRecorder()
		h.getSession(rec, httptest.NewRequest(http.MethodGet, "/api/session", nil))
		var got struct {
			Enforcement EnforcementMode `json:"enforcement"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if !got.Enforcement.Enforcing || got.Enforcement.Mode != "enforce" {
			t.Errorf("unset enforcement reported %+v, want the enforcing default", got.Enforcement)
		}
	}
}
