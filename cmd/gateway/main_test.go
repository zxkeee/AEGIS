package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"api-gateway/internal/config"
	"api-gateway/internal/discovery"
	"api-gateway/internal/logger"
	"api-gateway/internal/middleware"
	"api-gateway/internal/store"

	"github.com/alicebob/miniredis/v2"
)

// TestChain_PostureMatchesEnforcement is the guard against the headline bug class:
// the posture engine must never report protection the data plane does not deliver.
// It builds the real handler chain and asserts, for representative routes, that the
// posture label and the chain's actual behaviour agree.
func TestChain_PostureMatchesEnforcement(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	defer mr.Close()
	st, err := store.New(mr.Addr(), "", 0)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	defer func() { _ = st.Close() }()
	if err := middleware.InitTrustedProxies(nil); err != nil {
		t.Fatalf("InitTrustedProxies: %v", err)
	}

	// A backend that records whether it was actually reached.
	var reached bool
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()
	bu, _ := url.Parse(backend.URL)

	requireAuth := true
	cfg := config.GatewayConfig{
		Security: config.SecurityConfig{
			Auth: config.AuthConfig{Enabled: false}, // auth globally OFF
		},
		Routes: []config.RouteConfig{
			// Protected purely via per-route override (the exact scenario that
			// previously reported "protected" while reaching the backend open).
			{Path: "/secure", Upstreams: []string{bu.String()}, RequireAuth: &requireAuth},
			// No override: inherits the (off) global posture.
			{Path: "/open", Upstreams: []string{bu.String()}},
		},
	}

	log := logger.New("error")
	postureEng := discovery.NewPostureEngine(cfg)
	handler, _, err := buildHandlerChain(cfg, log, st, nil, nil, postureEng)
	if err != nil {
		t.Fatalf("buildHandlerChain: %v", err)
	}

	// /secure: posture reports auth as required (here "partial" — only auth is on)
	// -> the chain MUST reject an unauthenticated request before the backend.
	if c, _ := postureEng.ControlsFor("/secure"); !c.AuthRequired {
		t.Fatal("/secure posture: AuthRequired should be true via per-route override")
	}
	if label := postureEng.Classify("/secure"); label == discovery.PostureUnprotected || label == discovery.PostureShadow {
		t.Fatalf("/secure posture: got %q, want a protected/partial label", label)
	}
	reached = false
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/secure", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("/secure: posture is protected but chain returned %d (want 401)", rec.Code)
	}
	if reached {
		t.Fatal("/secure: backend reached without auth — posture lied about protection")
	}

	// /open: no auth control -> request passes through to the backend.
	reached = false
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/open", nil))
	if !reached {
		t.Fatalf("/open: expected passthrough to backend, got status %d", rec.Code)
	}
}
