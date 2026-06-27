package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"api-gateway/internal/discovery"
)

func TestRandToken_UniqueHex(t *testing.T) {
	a, err := randToken()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := randToken()
	if a == b {
		t.Fatal("tokens must be unique")
	}
	if len(a) != 64 { // 32 bytes hex-encoded
		t.Fatalf("token length = %d, want 64", len(a))
	}
	for _, c := range a {
		if !strings.ContainsRune("0123456789abcdef", c) {
			t.Fatalf("non-hex char %q in token", c)
		}
	}
}

func TestWriteJSONAndError(t *testing.T) {
	rec := httptest.NewRecorder()
	writeJSON(rec, http.StatusCreated, map[string]string{"a": "b"})
	if rec.Code != http.StatusCreated || rec.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("writeJSON headers wrong: %d %q", rec.Code, rec.Header().Get("Content-Type"))
	}

	rec = httptest.NewRecorder()
	writeError(rec, http.StatusForbidden, "nope")
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusForbidden || body["error"] != "nope" {
		t.Fatalf("writeError wrong: %d %v", rec.Code, body)
	}
}

func TestDecodeJSON(t *testing.T) {
	type payload struct {
		Name string `json:"name"`
	}

	t.Run("valid", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"x"}`))
		var p payload
		if err := decodeJSON(r, &p); err != nil || p.Name != "x" {
			t.Fatalf("valid decode failed: %v p=%+v", err, p)
		}
	})

	t.Run("unknown field rejected", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"x","evil":1}`))
		var p payload
		if err := decodeJSON(r, &p); err == nil {
			t.Fatal("unknown field must be rejected (DisallowUnknownFields)")
		}
	})

	t.Run("oversized body rejected", func(t *testing.T) {
		big := `{"name":"` + strings.Repeat("a", 2<<20) + `"}` // > 1MB
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(big))
		var p payload
		if err := decodeJSON(r, &p); err == nil {
			t.Fatal("oversized body must be rejected (MaxBytesReader)")
		}
	})
}

func TestHealth_OK(t *testing.T) {
	h := &handlers{}
	rec := httptest.NewRecorder()
	h.health(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("health status = %d", rec.Code)
	}
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["status"] != "healthy" {
		t.Fatalf("health body = %v", body)
	}
}

func TestCatalogReady_NilCatalog(t *testing.T) {
	h := &handlers{} // catalog is nil
	rec := httptest.NewRecorder()
	if h.catalogReady(rec) {
		t.Fatal("catalogReady should be false when catalog is nil")
	}
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rec.Code)
	}
}

func TestWriteCatalogCSV_HeaderAndInjectionSafe(t *testing.T) {
	rec := httptest.NewRecorder()
	eps := []discovery.Endpoint{{
		Method:       "GET",
		PathTemplate: "=cmd|'/c calc'!A1", // formula-injection attempt
		Posture:      "unprotected",
		RiskScore:    90,
		RequestCount: 3,
		LastSeen:     time.Unix(0, 0).UTC(),
	}}
	writeCatalogCSV(rec, eps)

	if ct := rec.Header().Get("Content-Type"); ct != "text/csv" {
		t.Fatalf("content-type = %q", ct)
	}
	out := rec.Body.String()
	if !strings.Contains(out, "method,path_template,posture") {
		t.Fatalf("missing CSV header: %q", out)
	}
	// The injecting cell must be neutralised with a leading quote.
	if !strings.Contains(out, "'=cmd") {
		t.Fatalf("formula injection not neutralised: %q", out)
	}
}
