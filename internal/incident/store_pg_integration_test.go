package incident

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"api-gateway/internal/pgtest"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// newTestStore opens a schema-isolated store. Skips without POSTGRES_DSN.
func newTestStore(t *testing.T) *PGStore {
	t.Helper()
	db, err := sql.Open("pgx", pgtest.DSN(t, "test_incident"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s, err := NewPGStore(db, nopLog{})
	if err != nil {
		t.Fatalf("NewPGStore: %v", err)
	}
	return s
}

func mergeN(t *testing.T, s *PGStore, d Delta, window time.Duration) {
	t.Helper()
	if err := s.Merge(context.Background(), d, window); err != nil {
		t.Fatalf("Merge: %v", err)
	}
}

func listAll(t *testing.T, s *PGStore, tenant string) []Incident {
	t.Helper()
	got, err := s.List(context.Background(), tenant, Filter{}, DefaultSchedule, t0)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	return got
}

func TestPG_MergeOpensThenAccumulates(t *testing.T) {
	s := newTestStore(t)
	base := Delta{
		Tenant: "acme", Class: "bola", Subject: "jwt:alice",
		First: t0, Last: t0, Count: 5,
		Endpoints: []string{"GET /orders/{id}"}, Sources: []string{"1.1.1.1"},
		Reasons: []string{"bola_object_ownership"},
	}
	mergeN(t, s, base, DefaultWindow)

	second := base
	second.First, second.Last, second.Count = t0.Add(time.Minute), t0.Add(2*time.Minute), 3
	second.Endpoints = []string{"GET /invoices/{id}"}
	second.Sources = []string{"2.2.2.2"}
	mergeN(t, s, second, DefaultWindow)

	got := listAll(t, s, "acme")
	if len(got) != 1 {
		t.Fatalf("%d incidents, want 1 — the second delta opened a duplicate", len(got))
	}
	inc := got[0]
	if inc.EventCount != 8 {
		t.Errorf("event_count = %d, want 8", inc.EventCount)
	}
	if !inc.DetectedAt.Equal(t0) {
		t.Errorf("detected_at = %s, want the earliest event %s", inc.DetectedAt, t0)
	}
	if !inc.LastEventAt.Equal(t0.Add(2 * time.Minute)) {
		t.Errorf("last_event_at = %s, want the latest event", inc.LastEventAt)
	}
	if len(inc.Endpoints) != 2 || len(inc.Sources) != 2 {
		t.Errorf("endpoints=%v sources=%v — the arrays should be unioned", inc.Endpoints, inc.Sources)
	}
	if inc.Status != StatusOpen || inc.SeverityConfirmed {
		t.Errorf("a fresh incident is %s / confirmed=%v", inc.Status, inc.SeverityConfirmed)
	}
	// Derived on read, never stored.
	if inc.Classification.DurationMinutes != 2 || inc.Classification.EndpointsAffected != 2 {
		t.Errorf("classification = %+v, want duration 2 and 2 endpoints", inc.Classification)
	}
}

// Beyond the window the activity is a new incident. A report covering a
// fortnight of unrelated attempts describes nothing.
func TestPG_MergeOpensANewIncidentBeyondTheWindow(t *testing.T) {
	s := newTestStore(t)
	d := Delta{Tenant: "acme", Class: "bola", Subject: "u1", First: t0, Last: t0, Count: 1}
	mergeN(t, s, d, time.Hour)

	later := d
	later.First, later.Last = t0.Add(5*time.Hour), t0.Add(5*time.Hour)
	mergeN(t, s, later, time.Hour)

	if got := listAll(t, s, "acme"); len(got) != 2 {
		t.Fatalf("%d incidents, want 2 — five hours apart with a one-hour window is not one incident", len(got))
	}
}

// A closed incident may already have been reported. Appending new activity to a
// filed report is the one thing this record must never do.
func TestPG_MergeNeverReopensAClosedIncident(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	d := Delta{Tenant: "acme", Class: "bola", Subject: "u1", First: t0, Last: t0, Count: 1}
	mergeN(t, s, d, DefaultWindow)

	id := listAll(t, s, "acme")[0].ID
	closed := StatusClosed
	if err := s.Apply(ctx, "acme", id, Update{Status: &closed}); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	next := d
	next.First, next.Last, next.Count = t0.Add(time.Minute), t0.Add(time.Minute), 7
	mergeN(t, s, next, DefaultWindow)

	got := listAll(t, s, "acme")
	if len(got) != 2 {
		t.Fatalf("%d incidents, want 2 — new activity was appended to a closed one", len(got))
	}
	for _, i := range got {
		if i.ID == id && i.EventCount != 1 {
			t.Errorf("the closed incident's event_count moved to %d", i.EventCount)
		}
	}
}

func TestPG_ApplyRecordsAnOperatorsAssessment(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	mergeN(t, s, Delta{Tenant: "acme", Class: "waf", Subject: "9.9.9.9", First: t0, Last: t0, Count: 2}, DefaultWindow)
	id := listAll(t, s, "acme")[0].ID

	clients, geo, eur := 42, "DE, FR", 15000.0
	notes := "customer-facing outage on the payments path"
	sev := SeverityMajor
	st := StatusContained
	if err := s.Apply(ctx, "acme", id, Update{
		Status: &st, Severity: &sev, ClientsAffected: &clients,
		GeographicSpread: &geo, EconomicImpactEUR: &eur, Notes: &notes,
	}); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	got, err := s.Get(ctx, "acme", id)
	if err != nil || got == nil {
		t.Fatalf("Get: %v (%v)", err, got)
	}
	if got.Status != StatusContained || got.Severity != SeverityMajor {
		t.Errorf("status=%s severity=%s", got.Status, got.Severity)
	}
	// Setting a severity by hand is what lets a report say a human assessed it.
	if !got.SeverityConfirmed {
		t.Error("severity_confirmed is false after an operator set the severity")
	}
	if !got.Classification.Complete() {
		t.Errorf("still missing: %v", got.Classification.Missing())
	}
	if *got.Classification.ClientsAffected != 42 || *got.Classification.EconomicImpactEUR != 15000 {
		t.Errorf("classification = %+v", got.Classification)
	}
	if got.Classification.Notes != notes {
		t.Errorf("notes = %q", got.Classification.Notes)
	}
}

func TestPG_ApplyRejectsUnknownValuesAndMissingRows(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	bad := Status("deleted")
	if err := s.Apply(ctx, "acme", "x", Update{Status: &bad}); err == nil {
		t.Error("an unknown status was accepted")
	}
	badSev := Severity("catastrophic")
	if err := s.Apply(ctx, "acme", "x", Update{Severity: &badSev}); err == nil {
		t.Error("an unknown severity was accepted")
	}
	st := StatusClosed
	if err := s.Apply(ctx, "acme", "no-such-incident", Update{Status: &st}); err != ErrNotFound {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
	// An empty update is a no-op, not an error and not a wipe.
	if err := s.Apply(ctx, "acme", "no-such-incident", Update{}); err != nil {
		t.Errorf("empty update: %v", err)
	}
}

// Closing twice must not move closed_at: the first close is when it happened.
func TestPG_ClosedAtIsStampedOnce(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	mergeN(t, s, Delta{Tenant: "acme", Class: "bola", Subject: "u1", First: t0, Last: t0, Count: 1}, DefaultWindow)
	id := listAll(t, s, "acme")[0].ID

	closed := StatusClosed
	if err := s.Apply(ctx, "acme", id, Update{Status: &closed}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	first, _ := s.Get(ctx, "acme", id)
	if first.ClosedAt == nil {
		t.Fatal("closed_at was not stamped")
	}
	time.Sleep(10 * time.Millisecond)
	if err := s.Apply(ctx, "acme", id, Update{Status: &closed}); err != nil {
		t.Fatalf("Apply again: %v", err)
	}
	second, _ := s.Get(ctx, "acme", id)
	if !second.ClosedAt.Equal(*first.ClosedAt) {
		t.Errorf("closed_at moved from %s to %s on a second close", first.ClosedAt, second.ClosedAt)
	}
}

// The notification history is the record that a deadline was met. It is
// append-only so a missed deadline cannot be made to look met.
func TestPG_NotificationsAreAppendOnly(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	// Anchored to real time, not the package's fixed t0: sent_at is now bounded
	// against the database clock, so a submission dated from a hardcoded future
	// day is correctly refused. Everything here must sit in the past.
	base := time.Now().UTC().Add(-200 * time.Hour)
	mergeN(t, s, Delta{Tenant: "acme", Class: "bola", Subject: "u1", First: base, Last: base, Count: 1}, DefaultWindow)
	id := listAll(t, s, "acme")[0].ID

	first := Notification{Kind: KindEarlyWarning, SentAt: base.Add(time.Hour), Authority: "NCSC", Reference: "EW-1"}
	if err := s.RecordNotification(ctx, "acme", id, first); err != nil {
		t.Fatalf("RecordNotification: %v", err)
	}
	second := Notification{Kind: KindNotification, SentAt: base.Add(50 * time.Hour), Reference: "N-1"}
	if err := s.RecordNotification(ctx, "acme", id, second); err != nil {
		t.Fatalf("RecordNotification 2: %v", err)
	}

	got, _ := s.Get(ctx, "acme", id)
	if len(got.Notifications) != 2 {
		t.Fatalf("%d notifications, want 2 — the second replaced the first", len(got.Notifications))
	}
	if got.Notifications[0].Reference != "EW-1" || got.Notifications[0].Authority != "NCSC" {
		t.Errorf("first notification lost its detail: %+v", got.Notifications[0])
	}
	// The witness is stamped server-side and is not the operator's claim.
	for i, n := range got.Notifications {
		if n.RecordedAt.IsZero() {
			t.Errorf("notification %d has no recorded_at; the claim has no witness", i)
		}
		if !n.RecordedAt.After(n.SentAt) {
			t.Errorf("notification %d: recorded_at %s is not after the claimed sent_at %s",
				i, n.RecordedAt, n.SentAt)
		}
	}

	// And the deadlines reflect it.
	ds := got.Deadlines(DefaultSchedule, time.Now().UTC())
	if d := deadline(t, ds, KindEarlyWarning); d.Overdue || d.SentAt == nil {
		t.Errorf("early warning still overdue after an on-time submission: %+v", d)
	}
	if d := deadline(t, ds, KindFinalReport); !d.Due.Equal(base.Add(50 * time.Hour).Add(30 * 24 * time.Hour)) {
		t.Errorf("final report due %s, want one month after the notification was submitted", d.Due)
	}

	if err := s.RecordNotification(ctx, "acme", id, Notification{Kind: "made_up"}); err == nil {
		t.Error("an unknown notification kind was accepted")
	}
	if err := s.RecordNotification(ctx, "acme", "nope", first); err != ErrNotFound {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

// sent_at is a claim AEGIS cannot witness, so the bounds it CAN check are
// checked: a filing cannot predate the incident it reports, and cannot be in
// the future — the latter would let a deadline be met in advance.
func TestPG_RecordNotification_BoundsTheClaimedTime(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	base := time.Now().UTC().Add(-10 * time.Hour)
	mergeN(t, s, Delta{Tenant: "acme", Class: "bola", Subject: "u1", First: base, Last: base, Count: 1}, DefaultWindow)
	id := listAll(t, s, "acme")[0].ID

	cases := map[string]time.Time{
		"before the incident existed": base.Add(-time.Hour),
		"in the future":               time.Now().UTC().Add(48 * time.Hour),
	}
	for name, when := range cases {
		err := s.RecordNotification(ctx, "acme", id, Notification{Kind: KindEarlyWarning, SentAt: when})
		if err == nil {
			t.Errorf("%s: sent_at %s was accepted", name, when.Format(time.RFC3339))
			continue
		}
		if !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrInvalid so the API can answer 400 rather than 500", name, err)
		}
	}

	// A plausible time is accepted, and an omitted one defaults to now.
	if err := s.RecordNotification(ctx, "acme", id,
		Notification{Kind: KindEarlyWarning, SentAt: base.Add(time.Hour)}); err != nil {
		t.Errorf("a plausible sent_at was refused: %v", err)
	}
	if err := s.RecordNotification(ctx, "acme", id, Notification{Kind: KindNotification}); err != nil {
		t.Errorf("an omitted sent_at was refused: %v", err)
	}
}

// The forgery the append-only comment claimed to prevent and did not: file
// nothing until after the deadline, then append an entry BACKDATED to before
// it. Editing was blocked; appending achieved the same outcome, and the
// earliest-CLAIM reduction made the new entry authoritative.
func TestPG_BackdatedNotificationCannotRewriteHistory(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	base := time.Now().UTC().Add(-200 * time.Hour)
	mergeN(t, s, Delta{Tenant: "acme", Class: "bola", Subject: "u1", First: base, Last: base, Count: 1}, DefaultWindow)
	id := listAll(t, s, "acme")[0].ID

	// Filed 100 hours after detection, against a 24-hour obligation.
	if err := s.RecordNotification(ctx, "acme", id,
		Notification{Kind: KindEarlyWarning, SentAt: base.Add(100 * time.Hour), Reference: "honest"}); err != nil {
		t.Fatalf("RecordNotification: %v", err)
	}
	got, _ := s.Get(ctx, "acme", id)
	d := deadline(t, got.Deadlines(DefaultSchedule, time.Now().UTC()), KindEarlyWarning)
	if !d.Overdue || !d.Late {
		t.Fatalf("a submission 76 hours past the deadline reports overdue=%v late=%v", d.Overdue, d.Late)
	}

	// Now append a backdated one claiming it was filed within the window.
	if err := s.RecordNotification(ctx, "acme", id,
		Notification{Kind: KindEarlyWarning, SentAt: base.Add(2 * time.Hour), Reference: "backdated"}); err != nil {
		t.Fatalf("RecordNotification (backdated): %v", err)
	}
	got, _ = s.Get(ctx, "acme", id)
	d = deadline(t, got.Deadlines(DefaultSchedule, time.Now().UTC()), KindEarlyWarning)
	if !d.Overdue {
		t.Fatal("a backdated entry cleared a missed deadline — the record was rewritten after the fact")
	}
	if d.SentAt == nil || !d.SentAt.Equal(base.Add(100*time.Hour)) {
		t.Errorf("sent_at = %v, want the FIRST submission the gateway witnessed", d.SentAt)
	}
	// Both entries survive: the attempt itself is part of the record.
	if len(got.Notifications) != 2 {
		t.Errorf("%d notifications, want both retained", len(got.Notifications))
	}
}

// An incident names who attacked which endpoints. A leak across tenants would
// be worse here than almost anywhere else in the system.
//
// The ids collide on purpose: they are derived from class, subject and start,
// so two tenants attacked by the same subject at the same moment produce the
// SAME id. That is the sharpest possible test of isolation — every read and
// write below is addressed by an id that exists in both tenants.
func TestPG_TenantIsolation(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	d := Delta{Class: "bola", Subject: "u1", First: t0, Last: t0, Count: 1}
	acmeD, globexD := d, d
	acmeD.Tenant, globexD.Tenant = "acme", "globex"
	mergeN(t, s, acmeD, DefaultWindow)
	mergeN(t, s, globexD, DefaultWindow)

	acme, globex := listAll(t, s, "acme"), listAll(t, s, "globex")
	if len(acme) != 1 || len(globex) != 1 {
		t.Fatalf("acme sees %d, globex sees %d; each must see exactly its own", len(acme), len(globex))
	}
	id := acme[0].ID
	if globex[0].ID != id {
		t.Fatalf("ids differ (%s vs %s); this test is only meaningful when they collide", id, globex[0].ID)
	}

	// Closing in one tenant must not touch the other's identically-named row.
	closed := StatusClosed
	if err := s.Apply(ctx, "acme", id, Update{Status: &closed}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	other, err := s.Get(ctx, "globex", id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if other == nil {
		t.Fatal("globex lost its own incident when acme closed one with the same id")
	}
	if other.Status != StatusOpen {
		t.Fatalf("globex's incident is %s — acme's write crossed the tenant boundary", other.Status)
	}

	// Same for the notification history, which is the record of meeting a
	// deadline and so the most damaging thing to write into the wrong tenant.
	if err := s.RecordNotification(ctx, "acme", id,
		Notification{Kind: KindEarlyWarning, SentAt: t0.Add(time.Hour)}); err != nil {
		t.Fatalf("RecordNotification: %v", err)
	}
	other, _ = s.Get(ctx, "globex", id)
	if len(other.Notifications) != 0 {
		t.Fatalf("globex's incident acquired %d notifications it never filed", len(other.Notifications))
	}
}

func TestPG_ListFilters(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	mergeN(t, s, Delta{Tenant: "acme", Class: "bola", Subject: "u1", First: t0, Last: t0, Count: 1}, DefaultWindow)
	mergeN(t, s, Delta{Tenant: "acme", Class: "waf", Subject: "u2", First: t0.Add(time.Hour), Last: t0.Add(time.Hour), Count: 1}, DefaultWindow)

	byClass, err := s.List(ctx, "acme", Filter{Class: "waf"}, DefaultSchedule, t0)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(byClass) != 1 || byClass[0].Class != "waf" {
		t.Errorf("class filter returned %+v", byClass)
	}

	id := listAll(t, s, "acme")[0].ID
	closed := StatusClosed
	if err := s.Apply(ctx, "acme", id, Update{Status: &closed}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	open, _ := s.List(ctx, "acme", Filter{Status: "open"}, DefaultSchedule, t0)
	for _, i := range open {
		if i.Status != StatusOpen {
			t.Errorf("status filter returned a %s incident", i.Status)
		}
	}

	// Overdue is computed from the notification history, not a column.
	late := t0.Add(200 * time.Hour)
	overdue, err := s.List(ctx, "acme", Filter{OverdueOnly: true}, DefaultSchedule, late)
	if err != nil {
		t.Fatalf("List overdue: %v", err)
	}
	if len(overdue) == 0 {
		t.Error("nothing reported overdue 200 hours after detection with no submissions")
	}
	none, _ := s.List(ctx, "acme", Filter{OverdueOnly: true}, DefaultSchedule, t0)
	if len(none) != 0 {
		t.Errorf("%d incidents overdue at the moment of detection", len(none))
	}
}
