package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// callGet drives a GET handler with an optional path value, returning the
// recorder and decoded JSON body.
func callGet(h func(http.ResponseWriter, *http.Request), path string, pathVals map[string]string) (*httptest.ResponseRecorder, map[string]any) {
	r := httptest.NewRequest(http.MethodGet, path, nil)
	for k, v := range pathVals {
		r.SetPathValue(k, v)
	}
	rec := httptest.NewRecorder()
	h(rec, r)
	var body map[string]any
	if rec.Body.Len() > 0 {
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
	}
	return rec, body
}

// When forensic_dsn is unset the catalog is nil; every catalog-backed endpoint
// must degrade to 503 (not panic / 500).
func TestCatalog_NilDegradesTo503(t *testing.T) {
	h, _ := redisHandlers(t) // catalog == nil
	cases := []struct {
		name string
		h    func(http.ResponseWriter, *http.Request)
		path string
		pv   map[string]string
	}{
		{"catalog", h.getCatalog, "/api/catalog", nil},
		{"catalog-endpoint", h.getCatalogEndpoint, "/api/catalog/abc", map[string]string{"id": "abc"}},
		{"consumers", h.getConsumers, "/api/consumers", nil},
		{"posture", h.getPostureSummary, "/api/posture/summary", nil},
		{"findings", h.getFindings, "/api/findings", nil},
		{"report", h.getReport, "/api/report", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec, body := callGet(c.h, c.path, c.pv)
			if rec.Code != http.StatusServiceUnavailable {
				t.Fatalf("%s = %d, want 503", c.name, rec.Code)
			}
			if body["error"] == nil {
				t.Fatalf("%s: missing error message", c.name)
			}
		})
	}
}

// getEffectiveness works WITHOUT a catalog: it still rolls up the per-control
// block counters from Redis and just omits coverage_pct.
func TestEffectiveness_NilCatalogRollsUpMetrics(t *testing.T) {
	h, _ := redisHandlers(t)
	ctx := context.Background()
	h.store.IncrMetric(ctx, "waf_blocked")
	h.store.IncrMetric(ctx, "waf_blocked")
	h.store.IncrMetric(ctx, "blocked_ip_blacklisted")

	rec, body := callGet(h.getEffectiveness, "/api/effectiveness", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("effectiveness = %d", rec.Code)
	}
	if _, ok := body["coverage_pct"]; ok {
		t.Fatal("coverage_pct must be absent without a catalog")
	}
	if got, _ := body["total_blocks"].(float64); got != 3 {
		t.Fatalf("total_blocks = %v, want 3", body["total_blocks"])
	}
	blocks, _ := body["blocks_by_control"].(map[string]any)
	if blocks == nil || blocks["waf"].(float64) != 2 || blocks["ip_guard"].(float64) != 1 {
		t.Fatalf("blocks_by_control = %v", body["blocks_by_control"])
	}
}

// CSV report path is reachable only with a catalog, but the formatter itself is
// independent — assert the header row and Content-Type for an empty endpoint set.
func TestReportCSV_HeaderShape(t *testing.T) {
	rec := httptest.NewRecorder()
	writeCatalogCSV(rec, nil)
	if ct := rec.Header().Get("Content-Type"); ct != "text/csv" {
		t.Fatalf("content-type = %q", ct)
	}
	if !strings.Contains(rec.Body.String(), "method,path_template,posture") {
		t.Fatalf("missing CSV header: %q", rec.Body.String())
	}
}
