package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"api-gateway/internal/license"
)

func genKeys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return pub, priv
}

func doReissue(t *testing.T, priv ed25519.PrivateKey, limiter *perIPLimiter, body reissueRequest, remoteAddr string) (*httptest.ResponseRecorder, reissueResponse) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	r := httptest.NewRequest(http.MethodPost, "/reissue", bytes.NewReader(raw))
	r.RemoteAddr = remoteAddr
	rec := httptest.NewRecorder()
	handleReissue(rec, r, priv, limiter)

	var resp reissueResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response %q: %v", rec.Body.String(), err)
	}
	return rec, resp
}

func TestHandleReissue_ValidRequestSucceeds(t *testing.T) {
	_, priv := genKeys(t)
	c := license.Claims{Licensee: "Acme Corp", Tier: "pilot", HardwareID: "old", ExpiresAt: time.Now().Add(time.Hour)}
	signed, err := license.Sign(priv, c)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	rec, resp := doReissue(t, priv, newPerIPLimiter(10, time.Hour),
		reissueRequest{License: signed, HardwareID: "new"}, "1.2.3.4:1")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%+v", rec.Code, resp)
	}
	if resp.License == "" {
		t.Fatal("expected a non-empty reissued license")
	}
}

func TestHandleReissue_ExpiredLicenseReturns402(t *testing.T) {
	_, priv := genKeys(t)
	c := license.Claims{Licensee: "Acme Corp", Tier: "trial", HardwareID: "old", ExpiresAt: time.Now().Add(-time.Hour)}
	signed, err := license.Sign(priv, c)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	rec, resp := doReissue(t, priv, newPerIPLimiter(10, time.Hour),
		reissueRequest{License: signed, HardwareID: "new"}, "1.2.3.4:1")
	if rec.Code != http.StatusPaymentRequired {
		t.Fatalf("status = %d, want 402, body=%+v", rec.Code, resp)
	}
}

func TestHandleReissue_ForgedLicenseReturns403(t *testing.T) {
	_, priv := genKeys(t)
	_, otherPriv := genKeys(t)
	c := license.Claims{Licensee: "Acme Corp", Tier: "pilot", HardwareID: "old", ExpiresAt: time.Now().Add(time.Hour)}
	signed, err := license.Sign(otherPriv, c) // signed by a DIFFERENT key than this server holds
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	rec, _ := doReissue(t, priv, newPerIPLimiter(10, time.Hour),
		reissueRequest{License: signed, HardwareID: "new"}, "1.2.3.4:1")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

func TestHandleReissue_MissingFieldsReturns400(t *testing.T) {
	_, priv := genKeys(t)
	rec, _ := doReissue(t, priv, newPerIPLimiter(10, time.Hour), reissueRequest{}, "1.2.3.4:1")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestHandleReissue_RateLimitEnforced(t *testing.T) {
	_, priv := genKeys(t)
	c := license.Claims{Licensee: "Acme Corp", Tier: "pilot", HardwareID: "old", ExpiresAt: time.Now().Add(time.Hour)}
	signed, err := license.Sign(priv, c)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	limiter := newPerIPLimiter(2, time.Hour)

	for i := 0; i < 2; i++ {
		rec, _ := doReissue(t, priv, limiter, reissueRequest{License: signed, HardwareID: "new"}, "9.9.9.9:1")
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d, want 200", i, rec.Code)
		}
	}
	rec, _ := doReissue(t, priv, limiter, reissueRequest{License: signed, HardwareID: "new"}, "9.9.9.9:1")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("3rd request: status = %d, want 429", rec.Code)
	}
}

func TestHandleReissue_RateLimitIsPerIP(t *testing.T) {
	_, priv := genKeys(t)
	c := license.Claims{Licensee: "Acme Corp", Tier: "pilot", HardwareID: "old", ExpiresAt: time.Now().Add(time.Hour)}
	signed, err := license.Sign(priv, c)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	limiter := newPerIPLimiter(1, time.Hour)

	rec1, _ := doReissue(t, priv, limiter, reissueRequest{License: signed, HardwareID: "new"}, "1.1.1.1:1")
	if rec1.Code != http.StatusOK {
		t.Fatalf("IP1: status = %d, want 200", rec1.Code)
	}
	rec2, _ := doReissue(t, priv, limiter, reissueRequest{License: signed, HardwareID: "new"}, "2.2.2.2:1")
	if rec2.Code != http.StatusOK {
		t.Fatalf("IP2 must have its own budget: status = %d, want 200", rec2.Code)
	}
}
