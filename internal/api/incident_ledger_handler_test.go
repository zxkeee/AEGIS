package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"api-gateway/internal/incident"
	"api-gateway/internal/logger"
	"api-gateway/internal/tenant"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func ledgerReq(t *testing.T, tid string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/api/incidents/ledger", nil)
	return r.WithContext(tenant.With(context.Background(), tid))
}

func decodeLedgerDoc(t *testing.T, body []byte) ledgerReportDoc {
	t.Helper()
	var doc ledgerReportDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("decode ledger document: %v\n%s", err, body)
	}
	return doc
}

// ledgerHandlers wires the real PostgreSQL incident store, because the point of
// this route is what the store can prove; a fake would test the JSON only.
func ledgerHandlers(t *testing.T) (*handlers, *incident.PGStore) {
	t.Helper()
	db, err := sql.Open("pgx", pgDSN(t))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	st, err := incident.NewPGStore(db, logger.New("error"))
	if err != nil {
		t.Fatalf("NewPGStore: %v", err)
	}
	return &handlers{log: logger.New("error"), incidents: st}, st
}

func TestIncidentLedger_DisabledWithoutAStore(t *testing.T) {
	h := &handlers{log: logger.New("error")}
	rec := httptest.NewRecorder()
	h.getIncidentLedgerReport(rec, ledgerReq(t, "acme"))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503: %s", rec.Code, rec.Body.String())
	}
}

// A store that satisfies incidentOps but keeps no ledger must not be reported
// as an intact register. Answering "intact" for a store that records nothing is
// the worst possible failure of this route: it produces a signable document
// asserting an integrity property that was never checked.
type ledgerlessStore struct{}

func (ledgerlessStore) List(context.Context, string, incident.Filter, incident.Schedule, time.Time) ([]incident.Incident, error) {
	return nil, nil
}
func (ledgerlessStore) Get(context.Context, string, string) (*incident.Incident, error) {
	return nil, nil
}
func (ledgerlessStore) Apply(context.Context, string, string, incident.Update) error { return nil }
func (ledgerlessStore) RecordNotification(context.Context, string, string, incident.Notification) error {
	return nil
}

func TestIncidentLedger_RefusesAStoreThatKeepsNoLedger(t *testing.T) {
	h := &handlers{log: logger.New("error"), incidents: ledgerlessStore{}}
	rec := httptest.NewRecorder()
	h.getIncidentLedgerReport(rec, ledgerReq(t, "acme"))
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501 — a store with no ledger must not answer "+
			"'intact': %s", rec.Code, rec.Body.String())
	}
}

func TestIncidentLedger_ReportsAnIntactRegister(t *testing.T) {
	h, st := ledgerHandlers(t)
	const tid = "ledger-api-clean"
	if err := st.Merge(context.Background(), incident.Delta{
		Tenant: tid, Class: "bola", Subject: "jwt:alice",
		First: time.Now().UTC().Add(-time.Hour), Last: time.Now().UTC().Add(-time.Hour),
		Count: 3, Endpoints: []string{"GET /orders/{id}"},
		Sources: []string{"1.1.1.1"}, Reasons: []string{"bola_object_ownership"},
	}, incident.DefaultWindow); err != nil {
		t.Fatalf("Merge: %v", err)
	}

	rec := httptest.NewRecorder()
	h.getIncidentLedgerReport(rec, ledgerReq(t, tid))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}

	doc := decodeLedgerDoc(t, rec.Body.Bytes())
	if !doc.Intact {
		t.Fatalf("an untouched register did not verify: %+v", doc)
	}
	if doc.Entries == 0 {
		t.Error("intact over zero entries is not evidence of anything; the count " +
			"is what tells those two answers apart")
	}
	if doc.Tenant != tid {
		t.Errorf("tenant = %q, want %q — a shared-key deployment cannot tell two "+
			"tenants' signed answers apart without it", doc.Tenant, tid)
	}
	if len(doc.Limits) == 0 {
		t.Error("the document states no limits; a green verification result is " +
			"exactly the artifact a reader over-interprets")
	}
}

// The lists must be [] and never null in a body that can be signed: to a
// careless reader a JSON null and an empty list say the same thing, and here
// one of those readings is "no incident is missing" while the other is "the
// question was not answered".
func TestIncidentLedger_EmptyListsAreNotNull(t *testing.T) {
	h, _ := ledgerHandlers(t)
	rec := httptest.NewRecorder()
	h.getIncidentLedgerReport(rec, ledgerReq(t, "ledger-api-empty"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, field := range []string{"missing", "altered", "unledgered", "chain_broken"} {
		if string(raw[field]) != "[]" {
			t.Errorf("%s = %s, want []", field, raw[field])
		}
	}
}
