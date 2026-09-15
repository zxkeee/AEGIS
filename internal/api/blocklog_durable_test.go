package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"api-gateway/internal/forensic"
	"api-gateway/internal/logger"
	"api-gateway/internal/store"
)

// durableHandlers wires a real PostgreSQL forensic sink into *handlers, which is
// how the gateway runs whenever forensic_dsn is set.
func durableHandlers(t *testing.T) (*handlers, *forensic.PGSink) {
	t.Helper()
	return durableHandlersAt(t, pgDSN(t))
}

// durableHandlersAt is durableHandlers for a DSN the caller already holds.
//
// pgtest.DSN DROPs and recreates the schema on every call, so a test that needs
// a second connection of its own must reuse the string rather than ask for
// another one — asking again deletes the tables it is about to inspect.
func durableHandlersAt(t *testing.T, dsn string) (*handlers, *forensic.PGSink) {
	t.Helper()
	sink, err := forensic.NewPGSink(dsn, logger.New("error"))
	if err != nil {
		t.Fatalf("NewPGSink: %v", err)
	}
	t.Cleanup(sink.Close)
	return &handlers{log: logger.New("error"), forensic: sink}, sink
}

// The durable record was written and never read: events went to forensic_logs
// while /api/block-log served the Redis ring instead, so the evidence trail
// existed and was unreachable. This asserts the handler now answers from
// PostgreSQL, and says so.
func TestBlockLog_ReadsTheDurableRecord(t *testing.T) {
	h, sink := durableHandlers(t)
	sink.Push(store.ForensicEntry{
		Tenant: "default", Timestamp: time.Now().UTC().Add(-time.Hour),
		IP: "9.9.9.9", Path: "/orders/42", Method: "GET", Reason: "bola_enumeration", Code: 200,
	})
	sink.Flush() // persist now; Close would also shut the connection the read needs

	rec := httptest.NewRecorder()
	h.getBlockLog(rec, httptest.NewRequest(http.MethodGet, "/api/block-log", nil).WithContext(context.Background()))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("X-Evidence-Source"); got != "postgresql" {
		t.Fatalf("source = %q, want postgresql — the handler is still answering from the ring", got)
	}
	if got := rec.Header().Get("X-Evidence-Complete"); got != "true" {
		t.Errorf("complete = %q, want true", got)
	}
	var got []store.ForensicEntry
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 1 || got[0].Reason != "bola_enumeration" {
		t.Fatalf("entries = %+v, want the one persisted event", got)
	}
}

// The window has to reach the query, not merely be parsed. A period that
// excludes an event must exclude it — the failure mode where a narrow question
// silently returns a broad answer is the one that ruins an audit.
func TestBlockLog_WindowReachesTheQuery(t *testing.T) {
	h, sink := durableHandlers(t)
	old := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	recent := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	for _, ts := range []time.Time{old, recent} {
		sink.Push(store.ForensicEntry{
			Tenant: "default", Timestamp: ts, IP: "9.9.9.9",
			Path: "/orders/42", Method: "GET", Reason: "bola_enumeration", Code: 200,
		})
	}
	sink.Flush()

	query := func(q string) []store.ForensicEntry {
		t.Helper()
		rec := httptest.NewRecorder()
		h.getBlockLog(rec, httptest.NewRequest(http.MethodGet, "/api/block-log"+q, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status = %d, want 200 (%s)", q, rec.Code, rec.Body.String())
		}
		var got []store.ForensicEntry
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("%s: decode: %v", q, err)
		}
		return got
	}

	if got := query(""); len(got) != 2 {
		t.Fatalf("unbounded = %d, want 2", len(got))
	}
	if got := query("?from=2026-07-01T00:00:00Z"); len(got) != 1 {
		t.Fatalf("from July = %d, want 1 — the window did not reach the query", len(got))
	}
	if got := query("?to=2026-07-01T00:00:00Z"); len(got) != 1 {
		t.Fatalf("to July = %d, want 1", len(got))
	}
	if got := query("?from=2027-01-01T00:00:00Z"); len(got) != 0 {
		t.Fatalf("future window = %d, want 0 — a narrow question returned a broad answer", len(got))
	}
	// The window is echoed so a report built on this can state what it covered.
	rec := httptest.NewRecorder()
	h.getBlockLog(rec, httptest.NewRequest(http.MethodGet, "/api/block-log?from=2026-07-01T00:00:00Z", nil))
	if got := rec.Header().Get("X-Evidence-From"); got != "2026-07-01T00:00:00Z" {
		t.Errorf("X-Evidence-From = %q, want the requested bound echoed", got)
	}
}

// The compliance report's runtime numbers used to be tallied from the last 300
// entries of the in-memory ring — a capped, restart-losing buffer — and
// presented without saying so. That is a count of whatever happened to fit,
// offered as evidence of what happened.
func TestCompliance_CountsFromTheDurableRecord(t *testing.T) {
	h, sink := durableHandlers(t)
	h.catalog = nil // no catalog: this test is about the runtime half

	old := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	recent := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	for _, ts := range []time.Time{old, recent, recent} {
		sink.Push(store.ForensicEntry{
			Tenant: "default", Timestamp: ts, IP: "9.9.9.9",
			Path: "/orders/42", Method: "GET", Reason: "bola_enumeration", Code: 200,
		})
	}
	// An unrelated reason must not be counted as access-control abuse.
	sink.Push(store.ForensicEntry{
		Tenant: "default", Timestamp: recent, IP: "9.9.9.9",
		Path: "/x", Method: "GET", Reason: "waf_blocked", Code: 403,
	})
	sink.Flush()

	counts, source, err := h.abuseCounts(context.Background(), time.Time{}, time.Time{})
	if err != nil {
		t.Fatalf("abuseCounts: %v", err)
	}
	if source != sourcePostgres {
		t.Fatalf("source = %q, want %q — the report is still tallying the ring", source, sourcePostgres)
	}
	if counts["bola_enumeration"] != 3 {
		t.Errorf("bola_enumeration = %d, want 3", counts["bola_enumeration"])
	}
	if _, unrelated := counts["waf_blocked"]; unrelated {
		t.Error("a non-access-control reason was counted as abuse")
	}

	// The window must narrow the count, or "for the period under review" is a
	// phrase the report cannot honour.
	counts, _, err = h.abuseCounts(context.Background(), time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC), time.Time{})
	if err != nil {
		t.Fatalf("windowed abuseCounts: %v", err)
	}
	if counts["bola_enumeration"] != 2 {
		t.Errorf("windowed bola_enumeration = %d, want 2 — the period did not reach the query", counts["bola_enumeration"])
	}
}
