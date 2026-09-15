package api

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"api-gateway/internal/discovery"
	"api-gateway/internal/forensic"
	"api-gateway/internal/store"
	"api-gateway/internal/tenant"
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
		h.writeStoreError(w, "admin: catalog list failed", "failed to fetch catalog", err)
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
		h.writeStoreError(w, "admin: catalog endpoint failed", "failed to fetch endpoint", err)
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
		h.writeStoreError(w, "admin: consumers list failed", "failed to fetch consumers", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"consumers": consumers, "count": len(consumers)})
}

// GET /api/graph?limit= — the consumer→endpoint access map for the dashboard
// visualisation (who calls what, where risk/PII concentrates).
func (h *handlers) getGraph(w http.ResponseWriter, r *http.Request) {
	if !h.catalogReady(w) {
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	g, err := h.catalog.Graph(r.Context(), limit)
	if err != nil {
		h.writeStoreError(w, "admin: graph failed", "failed to build graph", err)
		return
	}
	// Enrich with authorization-abuse signal: flag nodes that appear in recent
	// BOLA/BFLA/IDOR events so the map shows who/what is under active abuse. The
	// forensic feed is best-effort — a failure to read it must not fail the graph.
	if entries, ferr := h.store.GetForensicLog(r.Context(), 300); ferr == nil {
		flagAbuseNodes(&g, entries)
	}
	writeJSON(w, http.StatusOK, g)
}

// flagAbuseNodes marks graph nodes that appear in recent abuse events. Endpoints
// match by "METHOD /normalized-path" (deterministic, shared with the catalog);
// consumers match the event's `consumer` field against the node's id/label
// (exact for ip:, suffix for jwt:<sub>).
func flagAbuseNodes(g *discovery.Graph, entries []store.ForensicEntry) {
	epHits := map[string]int{}  // endpoint label -> count
	conHits := map[string]int{} // consumer identity -> count
	for _, e := range entries {
		if !isAbuseReason(e.Reason) {
			continue
		}
		epHits[e.Method+" "+discovery.NormalizePath(e.Path)]++
		if c, ok := e.Extra["consumer"].(string); ok && c != "" {
			conHits[c]++
		}
	}
	if len(epHits) == 0 && len(conHits) == 0 {
		return
	}
	for i := range g.Nodes {
		n := &g.Nodes[i]
		if n.Type == "endpoint" {
			if c := epHits[n.Label]; c > 0 {
				n.Flagged, n.AbuseCount = true, c
			}
			continue
		}
		id := strings.TrimPrefix(n.ID, "consumer:")
		for c, cnt := range conHits {
			if c == id || c == n.Label || strings.HasSuffix(id, ":"+c) {
				n.Flagged = true
				n.AbuseCount += cnt
			}
		}
	}
}

func isAbuseReason(reason string) bool {
	return strings.HasPrefix(reason, "bola") || strings.HasPrefix(reason, "bfla")
}

// GET /api/posture/summary
func (h *handlers) getPostureSummary(w http.ResponseWriter, r *http.Request) {
	if !h.catalogReady(w) {
		return
	}
	sum, err := h.catalog.PostureSummary(r.Context())
	if err != nil {
		h.writeStoreError(w, "admin: posture summary failed", "failed to fetch posture summary", err)
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
		h.writeStoreError(w, "admin: effectiveness metrics failed", "failed to fetch metrics", err)
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
	from, to, perr := parseTimeWindow(r)
	if perr != nil {
		writeError(w, http.StatusBadRequest, perr.Error())
		return
	}

	eps, err := h.catalog.ListEndpoints(r.Context(), discovery.EndpointFilter{
		Limit: reportEndpointLimit, SeenFrom: from, SeenTo: to,
	})
	if err != nil {
		h.writeStoreError(w, "admin: report failed", "failed to build report", err)
		return
	}

	if strings.EqualFold(r.URL.Query().Get("format"), "csv") {
		// CSV has nowhere to carry an attestation, and answering an unsigned CSV
		// to a request that asked for a signature is the silent-downgrade this
		// whole path refuses. Say so instead.
		if sign, _ := wantsSignature(r); sign {
			writeError(w, http.StatusBadRequest,
				"format=csv cannot carry a signature; request the JSON report to have it attested")
			return
		}
		writeCatalogCSV(w, eps)
		return
	}

	sum, _ := h.catalog.PostureSummary(r.Context())
	h.writeSignable(w, r, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"window":       map[string]any{"from": rfc3339OrNil(from), "to": rfc3339OrNil(to)},
		"coverage":     h.reportCoverage(r.Context(), len(eps), eps),
		"posture":      sum,
		"endpoints":    eps,
		"count":        len(eps),
		// An inventory built from observed traffic cannot say what was never
		// called, and that is the reading a reader most wants from it.
		"limits": catalogReportLimits(),
	})
}

// reportEndpointLimit caps a single report. Reaching it is itself a coverage
// fact, so the limit is stated in the coverage section rather than silently
// truncating.
const reportEndpointLimit = 1000

// reportCoverage states what this report could NOT see.
//
// A report that lists only what it found reads as complete, and this one is not:
// it sees the traffic that passed through the gateway, findings whose individual
// occurrences were never retained, and — under load — a record with gaps in it.
// An auditor who discovers any of that unaided stops trusting the whole
// document, so the document says it first.
func (h *handlers) reportCoverage(ctx context.Context, shown int, eps []discovery.Endpoint) map[string]any {
	var limits []string

	limits = append(limits, "covers API traffic routed through this gateway; endpoints reached by another path are not visible here")

	if shown >= reportEndpointLimit {
		limits = append(limits, fmt.Sprintf("endpoint list truncated at %d; narrow the period or filter to see the rest", reportEndpointLimit))
	}

	// How much of the finding set can be evidenced request by request.
	var withEvents, counterOnly int
	for _, e := range eps {
		for _, f := range e.Findings {
			if f.Evidence.Kind == discovery.EvidenceEvents {
				withEvents++
			} else {
				counterOnly++
			}
		}
	}
	if counterOnly > 0 {
		limits = append(limits, fmt.Sprintf(
			"%d of %d findings are derived from counters; the individual requests behind them are not retained and cannot be produced on request",
			counterOnly, counterOnly+withEvents))
	}

	cov := map[string]any{
		"findings_with_event_evidence": withEvents,
		"findings_from_counters_only":  counterOnly,
	}

	if h.forensic == nil {
		limits = append(limits, "no durable event store configured (forensic_dsn): security events survive only in a capped in-memory ring")
		cov["evidence_store"] = sourceRing
	} else {
		cov["evidence_store"] = sourcePostgres
		if n := h.forensic.Dropped(); n > 0 {
			limits = append(limits, fmt.Sprintf("%d security events were dropped under load and are absent from the record", n))
			cov["events_dropped"] = n
		}
	}
	if h.audit != nil {
		if n := h.audit.Dropped(); n > 0 {
			limits = append(limits, fmt.Sprintf("%d admin actions were dropped under load and are absent from the audit trail", n))
			cov["audit_entries_dropped"] = n
		}
	}

	// Responses too large for the data-classification buffer were passed through
	// unscanned, so "no sensitive data found" does not cover them.
	// Guarded: a coverage section that panics costs the whole report, which is a
	// worse outcome than a missing caveat.
	if m, err := h.metricsOrNil(ctx); err == nil {
		if n := m["dlp_skipped_oversized"]; n > 0 {
			limits = append(limits, fmt.Sprintf("%d responses exceeded the inspection buffer and were not scanned for sensitive data", n))
			cov["responses_not_scanned"] = n
		}
		if n := m["abuse_consumer_ip_only"]; n > 0 {
			limits = append(limits, fmt.Sprintf("%d requests could only be attributed by network address; authorization abuse by such callers is under-counted", n))
			cov["requests_identified_by_address_only"] = n
		}
	}

	cov["limits"] = limits
	return cov
}

// metricsOrNil reads the metric counters, tolerating an unwired store.
func (h *handlers) metricsOrNil(ctx context.Context) (map[string]int64, error) {
	if h.store == nil {
		return nil, errNoStore
	}
	return h.store.GetMetrics(ctx)
}

var errNoStore = errors.New("no metrics store configured")

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
		h.writeStoreError(w, "admin: findings list failed", "failed to build findings", err)
		return
	}

	rows, counts := flattenFindings(eps)

	if strings.EqualFold(r.URL.Query().Get("format"), "csv") {
		writeFindingsCSV(w, rows)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"findings": rows,
		"count":    len(rows),
		"by_severity": map[string]int{
			"critical": counts["critical"], "warning": counts["warning"], "info": counts["info"],
		},
	})
}

// GET /api/compliance — the findings and runtime abuse detections mapped onto
// NIS2 / ISO 27001 / OWASP controls, for the compliance/audit view.
func (h *handlers) getCompliance(w http.ResponseWriter, r *http.Request) {
	if !h.catalogReady(w) {
		return
	}
	eps, err := h.catalog.ListEndpoints(r.Context(), discovery.EndpointFilter{Limit: 1000})
	if err != nil {
		h.writeStoreError(w, "admin: compliance findings failed", "failed to build compliance report", err)
		return
	}
	rows, _ := flattenFindings(eps)

	from, to, perr := parseTimeWindow(r)
	if perr != nil {
		writeError(w, http.StatusBadRequest, perr.Error())
		return
	}

	abuse, source, err := h.abuseCounts(r.Context(), from, to)
	if err != nil {
		h.writeStoreError(w, "admin: compliance abuse counts failed", "failed to build compliance report", err)
		return
	}

	rep := buildCompliance(rows, abuse, h.incidentEvidence(r.Context()))
	rep.GeneratedAt = time.Now().UTC().Format(time.RFC3339)
	rep.Tenant = tenant.From(r.Context())
	// State where the runtime numbers came from and what they cover. A report
	// that omits this reads as complete whatever its source, and the ring source
	// is neither complete nor period-scoped.
	rep.Evidence = evidenceProvenance{
		Source:   source,
		Complete: source == sourcePostgres,
		From:     rfc3339OrNil(from),
		To:       rfc3339OrNil(to),
	}
	if source == sourceRing {
		rep.Evidence.Note = "runtime counts come from the in-memory ring: recent entries only, " +
			"not period-scoped, and lost on restart. Set forensic_dsn for the durable record."
	}
	h.writeSignable(w, r, rep)
}

// Sources a compliance report's runtime numbers can come from.
const (
	sourcePostgres = "postgresql"
	sourceRing     = "redis-ring"
)

// abuseCounts totals access-control abuse events per reason. It reads the
// durable record when one is configured — the only source that can answer for a
// period — and otherwise falls back to the capped in-memory ring, reporting
// which it used so the caller never has to assume.
func (h *handlers) abuseCounts(ctx context.Context, from, to time.Time) (map[string]int, string, error) {
	abuse := map[string]int{}

	if h.forensic != nil {
		byReason, err := h.forensic.CountByReason(ctx, forensic.LogFilter{
			TenantID: tenant.From(ctx), From: from, To: to,
		})
		if err != nil {
			return nil, "", err
		}
		for reason, n := range byReason {
			if abuseOWASP(reason) != "" {
				abuse[reason] = n
			}
		}
		return abuse, sourcePostgres, nil
	}

	// No durable record. The ring holds only recent entries, so this is a
	// lower bound on what happened, not a count of it.
	entries, ferr := h.store.GetForensicLog(ctx, ringComplianceScan)
	if ferr != nil {
		return abuse, sourceRing, nil // best-effort, as before
	}
	for _, e := range entries {
		if abuseOWASP(e.Reason) != "" {
			abuse[e.Reason]++
		}
	}
	return abuse, sourceRing, nil
}

// ringComplianceScan bounds the fallback scan of the in-memory ring.
const ringComplianceScan = 300

func rfc3339OrNil(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC().Format(time.RFC3339)
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

// writeFindingsCSV renders the findings view as a downloadable report — the
// artifact handed to a pilot partner after the observe-mode run, so it needs
// no admin-console access to read.
func writeFindingsCSV(w http.ResponseWriter, rows []findingRow) {
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", `attachment; filename="aegis-findings-report.csv"`)
	cw := csv.NewWriter(w)
	defer cw.Flush()
	_ = cw.Write([]string{"severity", "owasp", "method", "path_template", "risk_score", "title", "why"})
	for _, row := range rows {
		_ = cw.Write([]string{
			csvSafe(row.Finding.Severity), csvSafe(row.Finding.OWASP), csvSafe(row.Method), csvSafe(row.PathTemplate),
			strconv.Itoa(row.RiskScore), csvSafe(row.Finding.Title), csvSafe(row.Finding.Why),
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
