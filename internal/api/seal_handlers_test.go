package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"api-gateway/internal/attest"
	"api-gateway/internal/forensic"
	"api-gateway/internal/logger"
	"api-gateway/internal/store"
	"api-gateway/internal/tenant"
)

// sealReq builds a request pinned to a tenant, the way AdminAuth pins one.
func sealReq(t *testing.T, target, tid string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, target, nil)
	return r.WithContext(tenant.With(context.Background(), tid))
}

// seedAndSeal writes n entries into one period for a tenant and seals it.
func seedAndSeal(t *testing.T, sink *forensic.PGSink, tid string, at time.Time, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		sink.Push(store.ForensicEntry{
			Tenant: tid, Timestamp: at.Add(time.Duration(i) * time.Second),
			IP: "9.9.9.9", Path: "/orders/42", Method: "GET",
			Reason: "bola_enumeration", Code: 200,
		})
	}
	sink.Flush()
	if _, err := sink.SealPeriod(context.Background(), tid, at, at.Add(time.Hour), nil); err != nil {
		t.Fatalf("SealPeriod: %v", err)
	}
}

func decodeSealDoc(t *testing.T, body []byte) sealReportDoc {
	t.Helper()
	var doc sealReportDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("decode seal document: %v\n%s", err, body)
	}
	return doc
}

// The reason this endpoint exists: the seals were written by a worker and read
// by nothing reachable. VerifySeals had no production caller, so an operator
// could not ask "has my log been tampered with" without writing Go.
func TestSealReport_ReportsAnIntactChain(t *testing.T) {
	h, sink := durableHandlers(t)
	const tid = "seal-api-clean"
	start := time.Now().UTC().Add(-4 * time.Hour).Truncate(time.Hour)
	seedAndSeal(t, sink, tid, start, 4)

	rec := httptest.NewRecorder()
	h.getSealReport(rec, sealReq(t, "/api/forensic/seals", tid))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}

	doc := decodeSealDoc(t, rec.Body.Bytes())
	if !doc.Intact || !doc.Chain.Complete {
		t.Fatalf("an untouched log did not verify: %+v", doc)
	}
	if doc.Tenant != tid {
		t.Errorf("tenant = %q, want %q — a shared-key deployment cannot tell two "+
			"tenants' signed reports apart without it", doc.Tenant, tid)
	}
	if doc.Sealed.Periods != 1 || doc.Sealed.Intact != 1 || doc.Sealed.Altered != 0 {
		t.Errorf("summary = %+v, want 1 period, 1 intact, 0 altered", doc.Sealed)
	}
	if len(doc.Limits) == 0 {
		t.Error("the document states no limits; a green verification result is exactly " +
			"the artifact a reader over-interprets, so the limits travel inside it")
	}
}

// A green result must never be able to say more than the mechanism supports.
// The wording is the deliverable here, so it is pinned.
func TestSealReport_CarriesItsOwnLimits(t *testing.T) {
	h, sink := durableHandlers(t)
	const tid = "seal-api-limits"
	start := time.Now().UTC().Add(-5 * time.Hour).Truncate(time.Hour)
	seedAndSeal(t, sink, tid, start, 2)

	rec := httptest.NewRecorder()
	h.getSealReport(rec, sealReq(t, "/api/forensic/seals", tid))
	doc := decodeSealDoc(t, rec.Body.Bytes())

	joined := strings.ToLower(strings.Join(doc.Limits, "\n"))
	for _, must := range []string{
		"detectable, not impossible", // deletion is caught, not prevented
		"period, not a row",          // granularity
		"party being audited",        // the key is the operator's own
		"no external anchor",         // the missing independent witness
		"tamper-evident",             // the only accurate word
	} {
		if !strings.Contains(joined, must) {
			t.Errorf("the limits omit %q; that omission is how a verification result "+
				"gets quoted as proof:\n%s", must, joined)
		}
	}
	if strings.Contains(joined, "tamper-proof") && !strings.Contains(joined, "never tamper-proof") {
		t.Error("the limits use 'tamper-proof' as a claim rather than as the word to avoid")
	}
}

// Truncation is the case the chain head was added for, and the endpoint has to
// surface it — otherwise the fix is unreachable in exactly the way the endpoint
// exists to correct.
func TestSealReport_SurfacesATruncatedChain(t *testing.T) {
	dsn := pgDSN(t)
	h, sink := durableHandlersAt(t, dsn)
	const tid = "seal-api-truncated"
	start := time.Now().UTC().Add(-6 * time.Hour).Truncate(time.Hour)
	for i := 0; i < 3; i++ {
		seedAndSeal(t, sink, tid, start.Add(time.Duration(i)*time.Hour), 2)
	}

	rec := httptest.NewRecorder()
	h.getSealReport(rec, sealReq(t, "/api/forensic/seals", tid))
	if doc := decodeSealDoc(t, rec.Body.Bytes()); !doc.Intact {
		t.Fatalf("the chain did not verify before tampering: %+v", doc)
	}

	// The operator deletes the last period's entries and its seal together —
	// the cheap attack the per-seal check structurally cannot see.
	last := start.Add(2 * time.Hour)
	sealTamper(t, dsn, tid, `DELETE FROM forensic_logs WHERE tenant_id = $1 AND ts >= $2`, tid, last)
	sealTamper(t, dsn, tid, `DELETE FROM forensic_seals WHERE tenant_id = $1 AND period_start = $2`, tid, last)

	rec = httptest.NewRecorder()
	h.getSealReport(rec, sealReq(t, "/api/forensic/seals", tid))
	doc := decodeSealDoc(t, rec.Body.Bytes())

	// Every surviving seal still recomputes — that is the whole difficulty.
	if doc.Sealed.Altered != 0 {
		t.Fatalf("a surviving seal stopped recomputing; truncation leaves them "+
			"untouched, and reporting otherwise hides what actually happened: %+v", doc.Sealed)
	}
	if doc.Intact || doc.Chain.Complete {
		t.Fatalf("a truncated chain was reported intact through the API: %+v", doc)
	}
	if !strings.Contains(doc.Chain.Detail, "missing from the end") {
		t.Errorf("the detail does not tell an operator what happened: %q", doc.Chain.Detail)
	}
}

// The document is evidence, so it has to be verifiable away from the system
// that produced it. Without this the endpoint would only serve a dashboard.
func TestSealReport_SignedDocumentVerifiesStandalone(t *testing.T) {
	h, sink := durableHandlers(t)
	const tid = "seal-api-signed"
	start := time.Now().UTC().Add(-7 * time.Hour).Truncate(time.Hour)
	seedAndSeal(t, sink, tid, start, 3)

	signer := signerFixture(t)
	pub := signPubKey(t, signer)
	h.reportSigner = signer

	rec := httptest.NewRecorder()
	h.getSealReport(rec, sealReq(t, "/api/forensic/seals?sign=1", tid))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}

	var env attest.Envelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	if err := attest.Verify(env, pub); err != nil {
		t.Fatalf("a freshly signed seal report did not verify: %v", err)
	}

	// And an edit to the body must break it, or the signature is decoration.
	tampered := env
	tampered.Document = strings.Replace(env.Document, `"intact":true`, `"intact":false`, 1)
	if tampered.Document == env.Document {
		t.Fatal("fixture did not contain the field it meant to edit; the tamper case never ran")
	}
	if err := attest.Verify(tampered, pub); err == nil {
		t.Fatal("an edited seal report still verified")
	}
}

// Without a durable store there are no seals, and the honest answer is that the
// feature is off — not an empty report that reads like a clean one.
func TestSealReport_SaysSoWhenSealsAreDisabled(t *testing.T) {
	h := &handlers{log: logger.New("error")}
	rec := httptest.NewRecorder()
	h.getSealReport(rec, sealReq(t, "/api/forensic/seals", "default"))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 — an empty report would read as a clean one", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "forensic_dsn") {
		t.Errorf("the error does not say how to enable it: %s", rec.Body.String())
	}
}

// sealTamper performs the edits an operator would make to cover something up,
// with app.tenant_id pinned for the duration.
//
// One transaction with is_local=true, not set_config(..., false) on a pool
// followed by a separate Exec: the session form applies to whichever pooled
// connection served it, and the next statement may land on another, where RLS
// matches zero rows and the tampering silently does not happen. The test would
// then assert against a log nobody touched. Invariant 9 in
// scripts/lint-invariants.sh rejects the other shape.
// dsn must be the one the sink is already using. Calling pgDSN again would not
// do: pgtest.DSN DROPs and recreates the schema on every call, so a second
// invocation mid-test deletes the tables the test is about to inspect.
func sealTamper(t *testing.T, dsn, tid, q string, args ...any) {
	t.Helper()
	ctx := context.Background()

	conn, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("tamper: open: %v", err)
	}
	defer func() { _ = conn.Close() }()

	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("tamper: begin: %v", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `SELECT set_config('app.tenant_id', $1, true)`, tid); err != nil {
		t.Fatalf("tamper: set_config: %v", err)
	}
	res, err := tx.ExecContext(ctx, q, args...)
	if err != nil {
		t.Fatalf("tamper: %v", err)
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		t.Fatalf("tamper statement changed no rows; the edit this test depends on did "+
			"not happen: %s", q)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("tamper: commit: %v", err)
	}
}
