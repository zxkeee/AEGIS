package api

import (
	"encoding/csv"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"api-gateway/internal/discovery"
)

// catalogReady guards catalog endpoints when discovery is disabled (no DSN).
func (h *handlers) catalogReady(w http.ResponseWriter) bool {
	if h.catalog == nil {
		writeError(w, http.StatusServiceUnavailable,
			"API discovery is disabled; set forensic_dsn (PostgreSQL) to enable the catalog")
		return false
	}
	return true
}

// GET /api/catalog?posture=&q=&risk=&limit=
func (h *handlers) getCatalog(w http.ResponseWriter, r *http.Request) {
	if !h.catalogReady(w) {
		return
	}
	f := discovery.EndpointFilter{
		Posture: r.URL.Query().Get("posture"),
		Search:  r.URL.Query().Get("q"),
	}
	f.MinRisk, _ = strconv.Atoi(r.URL.Query().Get("risk"))
	f.Limit, _ = strconv.Atoi(r.URL.Query().Get("limit"))

	eps, err := h.catalog.ListEndpoints(r.Context(), f)
	if err != nil {
		h.log.Error("admin: catalog list failed", map[string]any{"error": err.Error()})
		writeError(w, http.StatusInternalServerError, "failed to fetch catalog")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"endpoints": eps, "count": len(eps)})
}

// GET /api/catalog/{id}
func (h *handlers) getCatalogEndpoint(w http.ResponseWriter, r *http.Request) {
	if !h.catalogReady(w) {
		return
	}
	id := r.PathValue("id")
	ep, consumers, err := h.catalog.GetEndpoint(r.Context(), id)
	if err != nil {
		h.log.Error("admin: catalog endpoint failed", map[string]any{"error": err.Error()})
		writeError(w, http.StatusInternalServerError, "failed to fetch endpoint")
		return
	}
	if ep == nil {
		writeError(w, http.StatusNotFound, "endpoint not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"endpoint": ep, "consumers": consumers})
}

// GET /api/consumers?limit=
func (h *handlers) getConsumers(w http.ResponseWriter, r *http.Request) {
	if !h.catalogReady(w) {
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	consumers, err := h.catalog.ListConsumers(r.Context(), limit)
	if err != nil {
		h.log.Error("admin: consumers list failed", map[string]any{"error": err.Error()})
		writeError(w, http.StatusInternalServerError, "failed to fetch consumers")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"consumers": consumers, "count": len(consumers)})
}

// GET /api/posture/summary
func (h *handlers) getPostureSummary(w http.ResponseWriter, r *http.Request) {
	if !h.catalogReady(w) {
		return
	}
	sum, err := h.catalog.PostureSummary(r.Context())
	if err != nil {
		h.log.Error("admin: posture summary failed", map[string]any{"error": err.Error()})
		writeError(w, http.StatusInternalServerError, "failed to fetch posture summary")
		return
	}
	writeJSON(w, http.StatusOK, sum)
}

// GET /api/effectiveness
// Combines coverage (from the catalog posture) with the live block counters
// already maintained per control, to answer "is the protection effective?".
func (h *handlers) getEffectiveness(w http.ResponseWriter, r *http.Request) {
	metrics, err := h.store.GetMetrics(r.Context())
	if err != nil {
		h.log.Error("admin: effectiveness metrics failed", map[string]any{"error": err.Error()})
		writeError(w, http.StatusInternalServerError, "failed to fetch metrics")
		return
	}

	// Roll up block counters by control.
	blocks := map[string]int64{
		"waf":        metrics["waf_blocked"],
		"rate_limit": metrics["blocked_rate_limit_exceeded"],
		"ip_guard":   metrics["blocked_ip_blocked_dynamic"] + metrics["blocked_ip_blacklisted"],
		"behavior":   metrics["blocked_behavior_high_risk"],
		"threatfeed": metrics["blocked_threat_feed_blocked"],
		"bot":        metrics["bot_ja3_blocked"],
		"dlp":        metrics["dlp_redacted"],
	}
	var totalBlocks int64
	for _, v := range blocks {
		totalBlocks += v
	}

	resp := map[string]any{
		"blocks_by_control": blocks,
		"total_blocks":      totalBlocks,
		"passed_waf":        metrics["requests_passed_waf"],
	}

	if h.catalog != nil {
		if sum, err := h.catalog.PostureSummary(r.Context()); err == nil {
			resp["coverage_pct"] = sum.CoveragePct
			resp["posture"] = sum
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

// GET /api/report?format=json|csv
// Full posture report. CSV returns the endpoint catalog for spreadsheets.
func (h *handlers) getReport(w http.ResponseWriter, r *http.Request) {
	if !h.catalogReady(w) {
		return
	}
	eps, err := h.catalog.ListEndpoints(r.Context(), discovery.EndpointFilter{Limit: 1000})
	if err != nil {
		h.log.Error("admin: report failed", map[string]any{"error": err.Error()})
		writeError(w, http.StatusInternalServerError, "failed to build report")
		return
	}

	if strings.EqualFold(r.URL.Query().Get("format"), "csv") {
		writeCatalogCSV(w, eps)
		return
	}

	sum, _ := h.catalog.PostureSummary(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{
		"posture":   sum,
		"endpoints": eps,
		"count":     len(eps),
	})
}

// GET /api/findings — the security-issues view. Flattens every endpoint's
// derived findings (e.g. "PII exposed to unauthenticated callers") into one
// list, critical first, so an operator sees actionable exposures rather than a
// raw catalog. This is the data-centric, buyer-facing money view.
func (h *handlers) getFindings(w http.ResponseWriter, r *http.Request) {
	if !h.catalogReady(w) {
		return
	}
	eps, err := h.catalog.ListEndpoints(r.Context(), discovery.EndpointFilter{Limit: 1000})
	if err != nil {
		h.log.Error("admin: findings list failed", map[string]any{"error": err.Error()})
		writeError(w, http.StatusInternalServerError, "failed to build findings")
		return
	}

	rows, counts := flattenFindings(eps)
	writeJSON(w, http.StatusOK, map[string]any{
		"findings": rows,
		"count":    len(rows),
		"by_severity": map[string]int{
			"critical": counts["critical"], "warning": counts["warning"], "info": counts["info"],
		},
	})
}

// findingRow is one endpoint↔finding pair in the findings view.
type findingRow struct {
	Method       string            `json:"method"`
	PathTemplate string            `json:"path_template"`
	RiskScore    int               `json:"risk_score"`
	Finding      discovery.Finding `json:"finding"`
}

// flattenFindings explodes endpoints into a severity-sorted (critical first)
// list of findings plus per-severity counts. Pure, so it is unit-tested without
// a catalog/database.
func flattenFindings(eps []discovery.Endpoint) ([]findingRow, map[string]int) {
	rows := []findingRow{}
	counts := map[string]int{"critical": 0, "warning": 0, "info": 0}
	for _, e := range eps {
		for _, f := range e.Findings {
			rows = append(rows, findingRow{Method: e.Method, PathTemplate: e.PathTemplate, RiskScore: e.RiskScore, Finding: f})
			counts[f.Severity]++
		}
	}
	rank := func(s string) int {
		switch s {
		case "critical":
			return 0
		case "warning":
			return 1
		default:
			return 2
		}
	}
	sort.SliceStable(rows, func(i, j int) bool {
		return rank(rows[i].Finding.Severity) < rank(rows[j].Finding.Severity)
	})
	return rows, counts
}

func writeCatalogCSV(w http.ResponseWriter, eps []discovery.Endpoint) {
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", `attachment; filename="aegis-api-report.csv"`)
	cw := csv.NewWriter(w)
	defer cw.Flush()
	_ = cw.Write([]string{"method", "path_template", "posture", "risk_score",
		"requests", "errors", "auth_present", "anonymous", "pii", "avg_latency_ms", "last_seen"})
	for _, e := range eps {
		_ = cw.Write([]string{
			csvSafe(e.Method), csvSafe(e.PathTemplate), csvSafe(e.Posture), strconv.Itoa(e.RiskScore),
			strconv.FormatInt(e.RequestCount, 10), strconv.FormatInt(e.ErrorCount, 10),
			strconv.FormatInt(e.AuthPresentCount, 10), strconv.FormatInt(e.AnonCount, 10),
			strconv.FormatInt(e.PIICount, 10), strconv.FormatInt(e.AvgLatencyMs, 10),
			e.LastSeen.Format("2006-01-02T15:04:05Z07:00"),
		})
	}
}

// csvSafe neutralises CSV/formula injection. A spreadsheet treats a cell
// beginning with =, +, -, @ (or certain control characters) as a formula; since
// path templates are derived from untrusted request paths, such values are
// prefixed with a single quote so they are rendered as literal text.
func csvSafe(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	}
	return s
}
