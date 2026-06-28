package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"api-gateway/internal/discovery"
	"api-gateway/internal/logger"
)

// fakeSpecOps is an in-memory specOps for testing the spec handlers without a
// live PostgreSQL catalog.
type fakeSpecOps struct {
	setErr    error
	meta      discovery.SpecInfo
	metaFound bool
	metaErr   error
	delOK     bool
	delErr    error
	drift     discovery.DriftReport
	driftErr  error

	lastRaw []byte
}

func (f *fakeSpecOps) SetSpec(_ context.Context, raw []byte) (discovery.SpecInfo, error) {
	f.lastRaw = raw
	if f.setErr != nil {
		return discovery.SpecInfo{}, f.setErr
	}
	return f.meta, nil
}
func (f *fakeSpecOps) SpecMeta(context.Context) (discovery.SpecInfo, bool, error) {
	return f.meta, f.metaFound, f.metaErr
}
func (f *fakeSpecOps) DeleteSpec(context.Context) (bool, error) { return f.delOK, f.delErr }
func (f *fakeSpecOps) Drift(context.Context) (discovery.DriftReport, error) {
	return f.drift, f.driftErr
}

func specHandlers(t *testing.T, fake *fakeSpecOps) *handlers {
	t.Helper()
	return &handlers{log: logger.New("error"), specCat: fake}
}

func decode(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode body: %v", err)
		}
	}
	return body
}

func TestPutSpec_Success(t *testing.T) {
	fake := &fakeSpecOps{meta: discovery.SpecInfo{Version: "openapi:3", OpCount: 7}}
	h := specHandlers(t, fake)

	r := httptest.NewRequest(http.MethodPut, "/api/discovery/spec",
		strings.NewReader("openapi: 3.0.0\npaths: {/x: {get: {}}}"))
	rec := httptest.NewRecorder()
	h.putSpec(rec, r)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := decode(t, rec)
	if body["version"] != "openapi:3" || body["operations"].(float64) != 7 {
		t.Fatalf("body = %v", body)
	}
	if len(fake.lastRaw) == 0 {
		t.Fatal("raw body not forwarded to SetSpec")
	}
}

func TestPutSpec_InvalidSpec(t *testing.T) {
	fake := &fakeSpecOps{setErr: errors.New("spec: empty document")}
	h := specHandlers(t, fake)

	r := httptest.NewRequest(http.MethodPut, "/api/discovery/spec", strings.NewReader("garbage"))
	rec := httptest.NewRecorder()
	h.putSpec(rec, r)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if msg, _ := decode(t, rec)["error"].(string); !strings.Contains(msg, "invalid spec") {
		t.Fatalf("error message = %q", msg)
	}
}

func TestGetSpec_FoundAndNotFound(t *testing.T) {
	// Found.
	h := specHandlers(t, &fakeSpecOps{meta: discovery.SpecInfo{Version: "swagger:2", OpCount: 3}, metaFound: true})
	rec := httptest.NewRecorder()
	h.getSpec(rec, httptest.NewRequest(http.MethodGet, "/api/discovery/spec", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("found: status = %d, want 200", rec.Code)
	}
	if decode(t, rec)["version"] != "swagger:2" {
		t.Fatal("found: version missing")
	}

	// Not found.
	h = specHandlers(t, &fakeSpecOps{metaFound: false})
	rec = httptest.NewRecorder()
	h.getSpec(rec, httptest.NewRequest(http.MethodGet, "/api/discovery/spec", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("not-found: status = %d, want 404", rec.Code)
	}
}

func TestDeleteSpec(t *testing.T) {
	// Deleted.
	h := specHandlers(t, &fakeSpecOps{delOK: true})
	rec := httptest.NewRecorder()
	h.deleteSpec(rec, httptest.NewRequest(http.MethodDelete, "/api/discovery/spec", nil))
	if rec.Code != http.StatusOK || decode(t, rec)["deleted"] != true {
		t.Fatalf("delete: status=%d body=%v", rec.Code, decode(t, rec))
	}

	// Nothing to delete.
	h = specHandlers(t, &fakeSpecOps{delOK: false})
	rec = httptest.NewRecorder()
	h.deleteSpec(rec, httptest.NewRequest(http.MethodDelete, "/api/discovery/spec", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("delete-missing: status = %d, want 404", rec.Code)
	}
}

func TestGetDrift_Success(t *testing.T) {
	fake := &fakeSpecOps{drift: discovery.DriftReport{
		SpecPresent: true, UndocumentedCount: 2, ZombieCount: 1,
		Undocumented: []discovery.DriftItem{{Method: "GET", Path: "/x"}},
		Zombie:       []discovery.DriftItem{},
	}}
	h := specHandlers(t, fake)
	rec := httptest.NewRecorder()
	h.getDrift(rec, httptest.NewRequest(http.MethodGet, "/api/discovery/drift", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := decode(t, rec)
	if body["spec_present"] != true || body["undocumented_count"].(float64) != 2 {
		t.Fatalf("drift body = %v", body)
	}
}

func TestGetDrift_Error(t *testing.T) {
	h := specHandlers(t, &fakeSpecOps{driftErr: errors.New("db down")})
	rec := httptest.NewRecorder()
	h.getDrift(rec, httptest.NewRequest(http.MethodGet, "/api/discovery/drift", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}
