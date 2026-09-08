package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"api-gateway/internal/discovery"
	"api-gateway/internal/incident"
	"api-gateway/internal/tenant"
)

// incidentOps is the slice of the incident store the handlers use, behind an
// interface so they are testable without PostgreSQL.
type incidentOps interface {
	List(ctx context.Context, tenant string, f incident.Filter, s incident.Schedule, now time.Time) ([]incident.Incident, error)
	Get(ctx context.Context, tenant, id string) (*incident.Incident, error)
	Apply(ctx context.Context, tenant, id string, u incident.Update) error
	RecordNotification(ctx context.Context, tenant, id string, n incident.Notification) error
}

// incidentsReady guards the routes when there is no store — which is the same
// condition as having no forensic DSN.
func (h *handlers) incidentsReady(w http.ResponseWriter) bool {
	if h.incidents == nil {
		writeError(w, http.StatusServiceUnavailable,
			"incident tracking is disabled; set forensic_dsn (PostgreSQL) to enable it")
		return false
	}
	return true
}

// incidentView is an incident plus what a reader needs to act on it: the
// deadlines it is under, and the classification criteria still missing.
//
// Both are computed, never stored. A deadline depends on the notification
// history and on the schedule in force; persisting it would produce a row that
// silently disagrees with the regulation the day either changes.
type incidentView struct {
	incident.Incident
	Deadlines []incident.Deadline `json:"deadlines"`
	Overdue   bool                `json:"overdue"`
	// AwaitingOperator lists the DORA Art. 18 criteria only a human can supply.
	// Its presence is the difference between "no economic impact" and "nobody
	// has assessed the economic impact".
	AwaitingOperator []string `json:"awaiting_operator,omitempty"`
	// ProposedSeverity is what the observed signals suggest, shown whenever a
	// human has not yet confirmed one.
	ProposedSeverity incident.Severity `json:"proposed_severity,omitempty"`
}

// view enriches one incident for the API.
//
// The catalog supplies the two Art. 18 criteria that depend on knowing what an
// endpoint is rather than what happened to it: whether any affected endpoint is
// critical, and what classes of data it returns. Absent a catalog they stay
// empty rather than false-by-default, because "not critical" and "we could not
// check" are different statements.
func (h *handlers) view(ctx context.Context, inc incident.Incident, now time.Time) incidentView {
	h.enrichFromCatalog(ctx, &inc)
	v := incidentView{
		Incident:         inc,
		Deadlines:        inc.Deadlines(incident.DefaultSchedule, now),
		AwaitingOperator: inc.Classification.Missing(),
	}
	for _, d := range v.Deadlines {
		if d.Overdue {
			v.Overdue = true
		}
	}
	if !inc.SeverityConfirmed {
		v.ProposedSeverity = incident.ProposeSeverity(inc.Classification, inc.EventCount)
	}
	return v
}

// enrichFromCatalog fills the endpoint-derived half of the classification.
func (h *handlers) enrichFromCatalog(ctx context.Context, inc *incident.Incident) {
	if h.catalog == nil || len(inc.Endpoints) == 0 {
		return
	}
	eps, err := h.catalog.ListEndpoints(ctx, discovery.EndpointFilter{Limit: reportEndpointLimit})
	if err != nil {
		// A classification missing its catalog half is worse than useless only
		// if it pretends to be complete; it does not, so degrade quietly rather
		// than fail the whole read.
		return
	}
	affected := map[string]bool{}
	for _, e := range inc.Endpoints {
		affected[e] = true
	}
	seen := map[string]bool{}
	var types []string
	for _, e := range eps {
		if !affected[e.Method+" "+e.PathTemplate] {
			continue
		}
		if e.RiskScore >= criticalRiskScore || e.Posture == "unprotected" {
			inc.Classification.CriticalService = true
		}
		for _, tpe := range e.PIITypes {
			if !seen[tpe] {
				seen[tpe] = true
				types = append(types, tpe)
			}
		}
	}
	inc.Classification.DataAtRisk = types
}

// criticalRiskScore is the catalog risk score at or above which an endpoint
// counts as a critical service for DORA Art. 18(1)(e).
const criticalRiskScore = 70

// GET /api/incidents?status=&severity=&class=&from=&to=&overdue=&limit=
func (h *handlers) getIncidents(w http.ResponseWriter, r *http.Request) {
	if !h.incidentsReady(w) {
		return
	}
	from, to, perr := parseTimeWindow(r)
	if perr != nil {
		writeError(w, http.StatusBadRequest, perr.Error())
		return
	}
	q := r.URL.Query()
	f := incident.Filter{
		Status: q.Get("status"), Severity: q.Get("severity"), Class: q.Get("class"),
		From: from, To: to,
	}
	f.Limit, _ = strconv.Atoi(q.Get("limit"))
	if v := q.Get("overdue"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			writeError(w, http.StatusBadRequest, "overdue must be true or false, got "+strconv.Quote(v))
			return
		}
		f.OverdueOnly = b
	}
	if f.Status != "" && !incident.Status(f.Status).Valid() {
		writeError(w, http.StatusBadRequest, "unknown status "+strconv.Quote(f.Status))
		return
	}
	if f.Severity != "" && !incident.Severity(f.Severity).Valid() {
		writeError(w, http.StatusBadRequest, "unknown severity "+strconv.Quote(f.Severity))
		return
	}

	ctx := r.Context()
	now := time.Now().UTC()
	list, err := h.incidents.List(ctx, tenant.From(ctx), f, incident.DefaultSchedule, now)
	if err != nil {
		h.writeStoreError(w, "admin: incident list failed", "failed to fetch incidents", err)
		return
	}

	views := make([]incidentView, 0, len(list))
	var overdue int
	for _, inc := range list {
		v := h.view(ctx, inc, now)
		if v.Overdue {
			overdue++
		}
		views = append(views, v)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"incidents": views,
		"count":     len(views),
		// Surfaced at the top level because it is the one number an operator
		// needs before any other: an unmet reporting deadline is a breach of
		// the obligation regardless of how the incident itself is going.
		"overdue": overdue,
	})
}

// GET /api/incidents/{id}
func (h *handlers) getIncident(w http.ResponseWriter, r *http.Request) {
	if !h.incidentsReady(w) {
		return
	}
	ctx := r.Context()
	inc, err := h.incidents.Get(ctx, tenant.From(ctx), r.PathValue("id"))
	if err != nil {
		h.writeStoreError(w, "admin: incident fetch failed", "failed to fetch incident", err)
		return
	}
	if inc == nil {
		writeError(w, http.StatusNotFound, "incident not found")
		return
	}
	writeJSON(w, http.StatusOK, h.view(ctx, *inc, time.Now().UTC()))
}

// incidentPatch is the operator-owned half of an incident.
//
// Every field is a pointer so "not mentioned" and "set to zero" are different
// requests. Clients affected genuinely can be zero, and an economic impact of
// zero is an assessment someone made — neither may be mistaken for silence.
type incidentPatch struct {
	Status            *string  `json:"status"`
	Severity          *string  `json:"severity"`
	ClientsAffected   *int     `json:"clients_affected"`
	GeographicSpread  *string  `json:"geographic_spread"`
	EconomicImpactEUR *float64 `json:"economic_impact_eur"`
	Notes             *string  `json:"notes"`
}

// PATCH /api/incidents/{id}
func (h *handlers) patchIncident(w http.ResponseWriter, r *http.Request) {
	if !h.requireMutator(w, r) || !h.incidentsReady(w) {
		return
	}
	var p incidentPatch
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&p); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	u := incident.Update{
		ClientsAffected:   p.ClientsAffected,
		GeographicSpread:  p.GeographicSpread,
		EconomicImpactEUR: p.EconomicImpactEUR,
		Notes:             p.Notes,
	}
	if p.Status != nil {
		s := incident.Status(*p.Status)
		if !s.Valid() {
			writeError(w, http.StatusBadRequest, "unknown status "+strconv.Quote(*p.Status))
			return
		}
		u.Status = &s
	}
	if p.Severity != nil {
		s := incident.Severity(*p.Severity)
		if !s.Valid() {
			writeError(w, http.StatusBadRequest, "unknown severity "+strconv.Quote(*p.Severity))
			return
		}
		u.Severity = &s
	}

	ctx := r.Context()
	tid := tenant.From(ctx)
	id := r.PathValue("id")
	if err := h.incidents.Apply(ctx, tid, id, u); err != nil {
		if errors.Is(err, incident.ErrNotFound) {
			writeError(w, http.StatusNotFound, "incident not found")
			return
		}
		h.writeStoreError(w, "admin: incident update failed", "failed to update incident", err)
		return
	}
	inc, err := h.incidents.Get(ctx, tid, id)
	if err != nil || inc == nil {
		h.writeStoreError(w, "admin: incident reload failed", "failed to update incident", err)
		return
	}
	writeJSON(w, http.StatusOK, h.view(ctx, *inc, time.Now().UTC()))
}

// notificationBody records a report submitted to a competent authority.
type notificationBody struct {
	Kind      string `json:"kind"`
	SentAt    string `json:"sent_at"`
	Authority string `json:"authority"`
	Reference string `json:"reference"`
}

// POST /api/incidents/{id}/notifications
//
// Append-only, and deliberately so: this is the record that an obligation was
// met. If a submission time could be edited, a missed deadline could be made to
// look met — and the audit that catches that is the one you least want to fail.
func (h *handlers) postIncidentNotification(w http.ResponseWriter, r *http.Request) {
	if !h.requireMutator(w, r) || !h.incidentsReady(w) {
		return
	}
	var b notificationBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&b); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	n := incident.Notification{
		Kind:      incident.DeadlineKind(b.Kind),
		Authority: b.Authority,
		Reference: b.Reference,
	}
	if b.SentAt != "" {
		t, err := time.Parse(time.RFC3339, b.SentAt)
		if err != nil {
			writeError(w, http.StatusBadRequest, "sent_at must be RFC 3339")
			return
		}
		n.SentAt = t.UTC()
	}

	ctx := r.Context()
	tid := tenant.From(ctx)
	id := r.PathValue("id")
	if err := h.incidents.RecordNotification(ctx, tid, id, n); err != nil {
		switch {
		case errors.Is(err, incident.ErrNotFound):
			writeError(w, http.StatusNotFound, "incident not found")
		case errors.Is(err, incident.ErrInvalid):
			// Only a caller mistake gets 400 with its reason. This used to be
			// the default for every non-ErrNotFound error, so a connection
			// failure or an RLS violation was reported to the client as a bad
			// request with the raw PostgreSQL text attached — wrong status, and
			// internal detail leaked from a handler whose own writeError says
			// "internal error details never leak to clients".
			writeError(w, http.StatusBadRequest, err.Error())
		default:
			h.writeStoreError(w, "admin: record notification failed", "failed to record notification", err)
		}
		return
	}
	inc, err := h.incidents.Get(ctx, tid, id)
	if err != nil || inc == nil {
		h.writeStoreError(w, "admin: incident reload failed", "failed to record notification", err)
		return
	}
	writeJSON(w, http.StatusOK, h.view(ctx, *inc, time.Now().UTC()))
}

// incidentEvidence summarises the incident record for the compliance mapping.
//
// A store that errors yields a zero value, which reports the incident articles
// as unevidenced. That is the right way round: a compliance report that cannot
// read the incident record must claim less, not more.
func (h *handlers) incidentEvidence(ctx context.Context) incidentEvidence {
	if h.incidents == nil {
		return incidentEvidence{}
	}
	now := time.Now().UTC()
	list, err := h.incidents.List(ctx, tenant.From(ctx), incident.Filter{Limit: complianceIncidentLimit},
		incident.DefaultSchedule, now)
	if err != nil {
		h.log.Error("admin: incident evidence unavailable", map[string]any{"error": err.Error()})
		return incidentEvidence{}
	}
	st := incident.Summarise(list, incident.DefaultSchedule, now)
	return incidentEvidence{
		Total: st.Total, Open: st.Open, Contained: st.Contained, Closed: st.Closed,
		Classified: st.Classified, Notified: st.Notified, Overdue: st.Overdue,
	}
}

// complianceIncidentLimit caps how many incidents the compliance summary reads.
const complianceIncidentLimit = 1000
