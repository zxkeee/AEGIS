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

func ticketTestStore(t *testing.T) *PGStore {
	t.Helper()
	db, err := sql.Open("pgx", pgtest.DSN(t, "test_incident_ticket"))
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

func seedSeverity(t *testing.T, s *PGStore, tenant, subject string, sev Severity) string {
	t.Helper()
	ctx := context.Background()
	d := Delta{
		Tenant: tenant, Class: "bola", Subject: subject,
		First: t0, Last: t0, Count: 1,
		Endpoints: []string{"GET /orders/{id}"}, Sources: []string{"1.1.1.1"},
		Reasons: []string{"bola_object_ownership"},
	}
	if err := s.Merge(ctx, d, DefaultWindow); err != nil {
		t.Fatalf("Merge: %v", err)
	}
	list, err := s.List(ctx, tenant, Filter{}, DefaultSchedule, t0)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	var id string
	for _, inc := range list {
		if inc.Subject == subject {
			id = inc.ID
		}
	}
	if id == "" {
		t.Fatalf("seeded incident for %q not found", subject)
	}
	if sev != SeverityMinor {
		if err := s.Apply(ctx, tenant, id, Update{Severity: &sev}); err != nil {
			t.Fatalf("Apply severity: %v", err)
		}
	}
	return id
}

// The severity filter must order by urgency, not alphabetically. "major" sorts
// before "minor" in ASCII, so a string comparison would file exactly the wrong
// half of the register — the low-severity incidents — and quietly skip the ones
// that matter.
func TestPG_Unticketed_OrdersSeverityByUrgencyNotAlphabet(t *testing.T) {
	s := ticketTestStore(t)
	ctx := context.Background()

	minor := seedSeverity(t, s, "acme", "jwt:low", SeverityMinor)
	major := seedSeverity(t, s, "acme", "jwt:high", SeverityMajor)

	got, err := s.Unticketed(ctx, "acme", SeverityMajor, 10)
	if err != nil {
		t.Fatalf("Unticketed: %v", err)
	}
	if len(got) != 1 || got[0].ID != major {
		ids := make([]string, len(got))
		for i, f := range got {
			ids[i] = f.ID + "/" + string(f.Severity)
		}
		t.Fatalf("want only the major incident %s, got %v (minor was %s)", major, ids, minor)
	}
}

func TestPG_RecordTicket_IsIdempotentAndSaysWhoLost(t *testing.T) {
	s := ticketTestStore(t)
	ctx := context.Background()
	id := seedSeverity(t, s, "acme", "jwt:alice", SeverityMajor)

	if err := s.RecordTicket(ctx, "acme", id, "jira", "SEC-1", "https://j/browse/SEC-1"); err != nil {
		t.Fatalf("first RecordTicket: %v", err)
	}
	err := s.RecordTicket(ctx, "acme", id, "jira", "SEC-2", "")
	if !errors.Is(err, ErrTicketExists) {
		// Silently overwriting would lose SEC-1 and leave SEC-2 as the only
		// reference, with nobody aware a duplicate exists in the tracker.
		t.Fatalf("second RecordTicket returned %v, want ErrTicketExists", err)
	}

	got, err := s.TicketFor(ctx, "acme", id)
	if err != nil {
		t.Fatalf("TicketFor: %v", err)
	}
	if got == nil || got.Ref != "SEC-1" {
		t.Fatalf("ticket = %+v, want the first reference kept", got)
	}
}

// An incident with a ticket must drop out of the queue, or every sweep files it
// again for as long as it exists.
func TestPG_Unticketed_ExcludesWhatIsAlreadyFiled(t *testing.T) {
	s := ticketTestStore(t)
	ctx := context.Background()
	id := seedSeverity(t, s, "acme", "jwt:alice", SeverityMajor)

	before, err := s.Unticketed(ctx, "acme", SeverityMinor, 10)
	if err != nil || len(before) == 0 {
		t.Fatalf("Unticketed before = %v, %v; want at least one", before, err)
	}
	if err := s.RecordTicket(ctx, "acme", id, "jira", "SEC-1", ""); err != nil {
		t.Fatalf("RecordTicket: %v", err)
	}

	after, err := s.Unticketed(ctx, "acme", SeverityMinor, 10)
	if err != nil {
		t.Fatalf("Unticketed after: %v", err)
	}
	for _, f := range after {
		if f.ID == id {
			t.Fatal("a filed incident is still queued; every sweep would file it again")
		}
	}
}

// Ticket bookkeeping is tenant-scoped like everything else here: one tenant's
// ticket must not satisfy another tenant's incident.
func TestPG_Tickets_AreTenantScoped(t *testing.T) {
	s := ticketTestStore(t)
	ctx := context.Background()
	acme := seedSeverity(t, s, "acme", "jwt:alice", SeverityMajor)
	_ = seedSeverity(t, s, "globex", "jwt:alice", SeverityMajor)

	if err := s.RecordTicket(ctx, "acme", acme, "jira", "SEC-1", ""); err != nil {
		t.Fatalf("RecordTicket: %v", err)
	}
	got, err := s.TicketFor(ctx, "globex", acme)
	if err != nil {
		t.Fatalf("TicketFor: %v", err)
	}
	if got != nil {
		t.Fatalf("globex can read acme's ticket: %+v", got)
	}

	tenants, err := s.TenantsWithIncidents(ctx)
	if err != nil {
		t.Fatalf("TenantsWithIncidents: %v", err)
	}
	if len(tenants) < 2 {
		t.Errorf("tenants = %v; the sweep would never discover a tenant it was not told about", tenants)
	}
}

// The ledger must not see ticket bookkeeping as a change to the evidence: the
// reference lives in its own table precisely so recording it cannot make a
// routine upgrade look like tampering.
func TestPG_RecordingATicketDoesNotDisturbTheLedger(t *testing.T) {
	s := ticketTestStore(t)
	ctx := context.Background()
	id := seedSeverity(t, s, "acme", "jwt:alice", SeverityMajor)

	before, err := s.VerifyLedger(ctx, "acme")
	if err != nil || !before.Intact {
		t.Fatalf("ledger before = %+v, %v", before, err)
	}
	if err := s.RecordTicket(ctx, "acme", id, "jira", "SEC-1", ""); err != nil {
		t.Fatalf("RecordTicket: %v", err)
	}
	after, err := s.VerifyLedger(ctx, "acme")
	if err != nil {
		t.Fatalf("VerifyLedger: %v", err)
	}
	if !after.Intact {
		t.Fatalf("recording a ticket reported the register as tampered: %+v", after)
	}
	if after.Entries != before.Entries {
		t.Errorf("entries went %d -> %d; ticket bookkeeping is not a state change of the incident",
			before.Entries, after.Entries)
	}
}

var _ = time.Second
