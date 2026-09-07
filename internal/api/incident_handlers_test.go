package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"api-gateway/internal/iam"
	"api-gateway/internal/incident"
	"api-gateway/internal/logger"
)

var incT0 = time.Date(2026, 9, 7, 8, 0, 0, 0, time.UTC)

// fakeIncidents is an in-memory incidentOps.
type fakeIncidents struct {
	items     []incident.Incident
	lastFiler incident.Filter
	err       error
	applied   incident.Update
	recorded  incident.Notification
}

func (f *fakeIncidents) List(_ context.Context, _ string, fl incident.Filter, s incident.Schedule, now time.Time) ([]incident.Incident, error) {
	f.lastFiler = fl
	if f.err != nil {
		return nil, f.err
	}
	if !fl.OverdueOnly {
		return f.items, nil
	}
	var out []incident.Incident
	for i := range f.items {
		if f.items[i].Overdue(s, now) {
			out = append(out, f.items[i])
		}
	}
	return out, nil
}

func (f *fakeIncidents) Get(_ context.Context, _, id string) (*incident.Incident, error) {
	if f.err != nil {
		return nil, f.err
	}
	for i := range f.items {
		if f.items[i].ID == id {
			return &f.items[i], nil
		}
	}
	return nil, nil
}

func (f *fakeIncidents) Apply(_ context.Context, _, id string, u incident.Update) error {
	f.applied = u
	for i := range f.items {
		if f.items[i].ID != id {
			continue
		}
		if u.Status != nil {
			f.items[i].Status = *u.Status
		}
		if u.Severity != nil {
			f.items[i].Severity = *u.Severity
			f.items[i].SeverityConfirmed = true
		}
		if u.ClientsAffected != nil {
			f.items[i].Classification.ClientsAffected = u.ClientsAffected
		}
		if u.GeographicSpread != nil {
			f.items[i].Classification.GeographicSpread = u.GeographicSpread
		}
		if u.EconomicImpactEUR != nil {
			f.items[i].Classification.EconomicImpactEUR = u.EconomicImpactEUR
		}
		return nil
	}
	return incident.ErrNotFound
}

func (f *fakeIncidents) RecordNotification(_ context.Context, _, id string, n incident.Notification) error {
	f.recorded = n
	switch n.Kind {
	case incident.KindEarlyWarning, incident.KindNotification, incident.KindFinalReport:
	default:
		return incident.ErrNotFound
	}
	for i := range f.items {
		if f.items[i].ID == id {
			f.items[i].Notifications = append(f.items[i].Notifications, n)
			return nil
		}
	}
	return incident.ErrNotFound
}

func incidentHandlers(items ...incident.Incident) (*handlers, *fakeIncidents) {
	f := &fakeIncidents{items: items}
	return &handlers{log: logger.New("error"), incidents: f}, f
}

// call runs a handler as an authenticated ADMIN. The mutating handlers go
// through requireMutator, and a context with no role resolves to viewer — so
// without this every PATCH/POST test would assert a 403 and prove nothing about
// the handler under it.
func call(t *testing.T, fn http.HandlerFunc, method, target, body string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, target, nil)
	} else {
		r = httptest.NewRequest(method, target, strings.NewReader(body))
	}
	r = r.WithContext(iam.WithRole(r.Context(), iam.RoleAdmin))
	// httptest.NewRequest does not populate path values — only ServeMux pattern
	// matching does — so a handler reading r.PathValue("id") would see "" and
	// answer 404 for every test.
	if rest, ok := strings.CutPrefix(r.URL.Path, "/api/incidents/"); ok {
		r.SetPathValue("id", strings.SplitN(rest, "/", 2)[0])
	}
	rec := httptest.NewRecorder()
	fn(rec, r)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec, out
}

// Without a store the routes must say the feature is switched off, not that it
// does not exist — a 404 would send an operator looking for a newer version.
func TestIncidents_DisabledWithoutAStore(t *testing.T) {
	h := &handlers{log: logger.New("error")}
	for _, fn := range []http.HandlerFunc{h.getIncidents, h.getIncident} {
		rec, body := call(t, fn, http.MethodGet, "/api/incidents", "")
		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("status = %d, want 503", rec.Code)
		}
		if !strings.Contains(body["error"].(string), "forensic_dsn") {
			t.Errorf("the error should name what to configure: %v", body["error"])
		}
	}
}

// The deadlines and the missing criteria are the whole operational value: the
// list has to answer "what must I do, and by when" without a second request.
func TestGetIncidents_CarriesDeadlinesAndWhatIsMissing(t *testing.T) {
	h, _ := incidentHandlers(incident.Incident{
		ID: "i1", Class: "bola", Subject: "jwt:alice", Status: incident.StatusOpen,
		DetectedAt: incT0, LastEventAt: incT0.Add(time.Minute), EventCount: 40,
	})

	rec, body := call(t, h.getIncidents, http.MethodGet, "/api/incidents", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	list, _ := body["incidents"].([]any)
	if len(list) != 1 {
		t.Fatalf("%d incidents, want 1", len(list))
	}
	first, _ := list[0].(map[string]any)
	ds, _ := first["deadlines"].([]any)
	if len(ds) != 3 {
		t.Fatalf("%d deadlines, want the three NIS2 Art. 23 obligations", len(ds))
	}
	missing, _ := first["awaiting_operator"].([]any)
	if len(missing) != 3 {
		t.Errorf("awaiting_operator = %v, want the three criteria only a human can supply", missing)
	}
	// Nobody has assessed it yet, so the report must show a proposal, clearly
	// labelled as one, rather than presenting a guess as an assessment.
	if first["proposed_severity"] == nil {
		t.Error("no proposed_severity on an unconfirmed incident")
	}
	if first["severity_confirmed"] != false {
		t.Error("severity_confirmed should be false before a human sets one")
	}
}

// An unmet deadline is the one number an operator needs before any other.
func TestGetIncidents_SurfacesOverdueAtTheTopLevel(t *testing.T) {
	old := time.Now().UTC().Add(-100 * time.Hour)
	h, _ := incidentHandlers(
		incident.Incident{ID: "old", DetectedAt: old, LastEventAt: old, Status: incident.StatusOpen},
		incident.Incident{ID: "new", DetectedAt: time.Now().UTC(), Status: incident.StatusOpen},
	)
	rec, body := call(t, h.getIncidents, http.MethodGet, "/api/incidents", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if n, _ := body["overdue"].(float64); n != 1 {
		t.Errorf("overdue = %v, want 1", body["overdue"])
	}
}

func TestGetIncidents_RejectsUnknownFilterValues(t *testing.T) {
	h, _ := incidentHandlers()
	for _, q := range []string{"status=resolved", "severity=catastrophic", "overdue=maybe"} {
		rec, _ := call(t, h.getIncidents, http.MethodGet, "/api/incidents?"+q, "")
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", q, rec.Code)
		}
	}
	// And a valid one reaches the store.
	h2, f := incidentHandlers()
	if rec, _ := call(t, h2.getIncidents, http.MethodGet, "/api/incidents?status=open&overdue=true&class=bola", ""); rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if f.lastFiler.Status != "open" || !f.lastFiler.OverdueOnly || f.lastFiler.Class != "bola" {
		t.Errorf("filter = %+v, want the query values passed through", f.lastFiler)
	}
}

func TestGetIncident_NotFound(t *testing.T) {
	h, _ := incidentHandlers()
	rec, _ := call(t, h.getIncident, http.MethodGet, "/api/incidents/nope", "")
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

// Zero is a real assessment. If the handler could not tell "0" from "not
// mentioned", an operator recording that no clients were affected would be
// indistinguishable from one who never looked.
func TestPatchIncident_ZeroIsAnAnswerNotSilence(t *testing.T) {
	h, f := incidentHandlers(incident.Incident{ID: "i1", DetectedAt: incT0, Status: incident.StatusOpen})

	rec, body := call(t, h.patchIncident, http.MethodPatch, "/api/incidents/i1",
		`{"clients_affected":0,"economic_impact_eur":0,"geographic_spread":"DE"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	if f.applied.ClientsAffected == nil || *f.applied.ClientsAffected != 0 {
		t.Errorf("clients_affected = %v, want a pointer to 0", f.applied.ClientsAffected)
	}
	if f.applied.EconomicImpactEUR == nil || *f.applied.EconomicImpactEUR != 0 {
		t.Errorf("economic_impact_eur = %v, want a pointer to 0", f.applied.EconomicImpactEUR)
	}
	// With all three supplied the incident is classified and nothing is awaited.
	if aw, _ := body["awaiting_operator"].([]any); len(aw) != 0 {
		t.Errorf("awaiting_operator = %v, want empty once every criterion is answered", aw)
	}
}

// Fields nobody mentioned must not be touched.
func TestPatchIncident_UnmentionedFieldsAreLeftAlone(t *testing.T) {
	h, f := incidentHandlers(incident.Incident{ID: "i1", DetectedAt: incT0, Status: incident.StatusOpen})

	if rec, _ := call(t, h.patchIncident, http.MethodPatch, "/api/incidents/i1", `{"notes":"triaged"}`); rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if f.applied.Status != nil || f.applied.Severity != nil || f.applied.ClientsAffected != nil {
		t.Errorf("update = %+v, want only notes set", f.applied)
	}
}

func TestPatchIncident_RejectsUnknownValues(t *testing.T) {
	h, _ := incidentHandlers(incident.Incident{ID: "i1", DetectedAt: incT0})
	for _, body := range []string{`{"status":"resolved"}`, `{"severity":"catastrophic"}`, `not json`} {
		rec, _ := call(t, h.patchIncident, http.MethodPatch, "/api/incidents/i1", body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", body, rec.Code)
		}
	}
	rec, _ := call(t, h.patchIncident, http.MethodPatch, "/api/incidents/i1", `{"status":"closed"}`)
	if rec.Code != http.StatusOK {
		t.Errorf("a valid status was rejected: %d", rec.Code)
	}
}

// Recording a submission must clear the matching deadline, which is the point
// of recording it.
func TestPostIncidentNotification_ClearsTheDeadline(t *testing.T) {
	old := time.Now().UTC().Add(-30 * time.Hour)
	h, f := incidentHandlers(incident.Incident{ID: "i1", DetectedAt: old, LastEventAt: old, Status: incident.StatusOpen})

	// Overdue before.
	_, before := call(t, h.getIncident, http.MethodGet, "/api/incidents/i1", "")
	if before["overdue"] != true {
		t.Fatalf("expected the 24h early warning to be overdue, got %v", before["overdue"])
	}

	rec, body := call(t, h.postIncidentNotification, http.MethodPost, "/api/incidents/i1/notifications",
		`{"kind":"early_warning","sent_at":"`+old.Add(time.Hour).Format(time.RFC3339)+`","authority":"NCSC","reference":"EW-9"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	if f.recorded.Authority != "NCSC" || f.recorded.Reference != "EW-9" {
		t.Errorf("recorded = %+v, want the authority and reference kept", f.recorded)
	}
	ds, _ := body["deadlines"].([]any)
	for _, d := range ds {
		m, _ := d.(map[string]any)
		if m["kind"] == "early_warning" {
			if m["overdue"] == true {
				t.Error("the early warning is still overdue after a submission was recorded")
			}
			if m["sent_at"] == nil {
				t.Error("the deadline does not carry the submission time")
			}
		}
	}
}

func TestPostIncidentNotification_RejectsBadInput(t *testing.T) {
	h, _ := incidentHandlers(incident.Incident{ID: "i1", DetectedAt: incT0})
	for _, body := range []string{
		`{"kind":"early_warning","sent_at":"yesterday"}`,
		`not json`,
	} {
		rec, _ := call(t, h.postIncidentNotification, http.MethodPost, "/api/incidents/i1/notifications", body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", body, rec.Code)
		}
	}
	rec, _ := call(t, h.postIncidentNotification, http.MethodPost, "/api/incidents/nope/notifications",
		`{"kind":"early_warning"}`)
	if rec.Code != http.StatusNotFound {
		t.Errorf("unknown incident: status = %d, want 404", rec.Code)
	}
}

// A compliance report that cannot read the incident record must claim LESS, not
// more. A store error yielding "everything is evidenced" would be the worst
// possible failure mode for this feature.
func TestIncidentEvidence_FailsTowardClaimingNothing(t *testing.T) {
	h, f := incidentHandlers(incident.Incident{
		ID: "i1", DetectedAt: incT0, Status: incident.StatusClosed,
		Notifications: []incident.Notification{{Kind: incident.KindEarlyWarning, SentAt: incT0}},
	})
	if ev := h.incidentEvidence(context.Background()); ev.Total != 1 || ev.Notified != 1 {
		t.Fatalf("evidence = %+v, want the record summarised", ev)
	}

	f.err = context.DeadlineExceeded
	if ev := h.incidentEvidence(context.Background()); ev != (incidentEvidence{}) {
		t.Errorf("evidence = %+v on a store error, want the zero value", ev)
	}

	none := &handlers{log: logger.New("error")}
	if ev := none.incidentEvidence(context.Background()); ev != (incidentEvidence{}) {
		t.Errorf("evidence = %+v with no store, want the zero value", ev)
	}
}

// A viewer may read the incident record but must never edit an assessment or
// claim a report was filed. The helper above authenticates as admin, so this is
// the one test that must build its own request.
func TestIncidents_ViewerCannotMutate(t *testing.T) {
	h, f := incidentHandlers(incident.Incident{ID: "i1", DetectedAt: incT0, Status: incident.StatusOpen})

	as := func(fn http.HandlerFunc, method, target, body string) int {
		r := httptest.NewRequest(method, target, strings.NewReader(body))
		r = r.WithContext(iam.WithRole(r.Context(), iam.RoleViewer))
		r.SetPathValue("id", "i1")
		rec := httptest.NewRecorder()
		fn(rec, r)
		return rec.Code
	}

	if code := as(h.patchIncident, http.MethodPatch, "/api/incidents/i1", `{"status":"closed"}`); code != http.StatusForbidden {
		t.Errorf("viewer PATCH = %d, want 403", code)
	}
	if code := as(h.postIncidentNotification, http.MethodPost, "/api/incidents/i1/notifications",
		`{"kind":"early_warning"}`); code != http.StatusForbidden {
		t.Errorf("viewer POST notification = %d, want 403", code)
	}
	if f.applied.Status != nil || f.recorded.Kind != "" {
		t.Errorf("a viewer's rejected request still reached the store: %+v / %+v", f.applied, f.recorded)
	}

	// Reading is fine.
	r := httptest.NewRequest(http.MethodGet, "/api/incidents", nil)
	r = r.WithContext(iam.WithRole(r.Context(), iam.RoleViewer))
	rec := httptest.NewRecorder()
	h.getIncidents(rec, r)
	if rec.Code != http.StatusOK {
		t.Errorf("viewer GET = %d, want 200", rec.Code)
	}
}
