package incident

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"api-gateway/internal/pgtest"
	"api-gateway/internal/tenant"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// The incident register decides what a SIGNED compliance document says about
// DORA Art. 17-19 and NIS2 Art. 23: which incidents existed, how they were
// classified, when they were notified. The signature covers the document, so it
// proves the document was not altered after it was produced — and says nothing
// about whether the register it was computed from had a row removed first.
//
// forensic_logs got that protection (hourly Merkle roots, a chain, a signed
// head). incidents did not, and it is the more direct target: one DELETE
// changes what the signed report claims about a regulator's deadline.
//
// These tests are written before the mechanism, and they are written to FAIL.
// Each one performs the tampering an operator would perform and then asks the
// register whether anything is wrong. Until VerifyLedger exists and answers
// yes, there is nothing to fix and nothing to claim.

func ledgerTestStore(t *testing.T) *PGStore {
	t.Helper()
	db, err := sql.Open("pgx", pgtest.DSN(t, "test_incident_ledger"))
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

// tamper runs a statement the way an operator with database access would, and
// insists it actually changed something.
//
// One transaction with app.tenant_id set is_local, because that setting is
// transaction-scoped: a set_config on a pooled handle followed by a separate
// Exec can land on a different connection, and the statement then runs with no
// tenant pinned — under a role that cannot bypass RLS it matches zero rows and
// reports success. A tamper that changed nothing would leave every assertion
// below testing an untouched database. (handoff.md §0j; the same trap already
// cost this repository sixteen misleading test sites.)
func tamper(t *testing.T, s *PGStore, tenantID, query string, args ...any) {
	t.Helper()
	ctx := tenant.With(context.Background(), tenantID)
	err := s.withTenantTx(ctx, tenantID, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, query, args...)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n == 0 {
			t.Fatalf("tamper changed no rows; the assertions after it would prove nothing: %s", query)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("tamper: %v", err)
	}
}

func seedIncidents(t *testing.T, s *PGStore, tenantID string, n int) []Incident {
	t.Helper()
	for i := 0; i < n; i++ {
		d := Delta{
			Tenant:    tenantID,
			Class:     "bola",
			Subject:   "jwt:user" + string(rune('a'+i)),
			First:     t0.Add(time.Duration(i) * time.Minute),
			Last:      t0.Add(time.Duration(i) * time.Minute),
			Count:     i + 1,
			Endpoints: []string{"GET /orders/{id}"},
			Sources:   []string{"1.1.1.1"},
			Reasons:   []string{"bola_object_ownership"},
		}
		mergeN(t, s, d, DefaultWindow)
	}
	got := listAll(t, s, tenantID)
	if len(got) != n {
		t.Fatalf("seed: want %d incidents, got %d", n, len(got))
	}
	return got
}

// A deleted incident is the cheapest possible tampering: it costs one DELETE,
// no key, and it changes what the signed document says happened.
func TestPG_Ledger_DetectsDeletedIncident(t *testing.T) {
	s := ledgerTestStore(t)
	ctx := context.Background()
	seeded := seedIncidents(t, s, "acme", 3)

	if rep, err := s.VerifyLedger(ctx, "acme"); err != nil {
		t.Fatalf("VerifyLedger on an untouched register: %v", err)
	} else if !rep.Intact {
		t.Fatalf("untouched register reported as tampered: %+v", rep)
	}

	tamper(t, s, "acme", "DELETE FROM incidents WHERE tenant_id = $1 AND id = $2",
		"acme", seeded[1].ID)

	rep, err := s.VerifyLedger(ctx, "acme")
	if err != nil {
		t.Fatalf("VerifyLedger: %v", err)
	}
	if rep.Intact {
		t.Fatalf("a deleted incident went undetected: %+v", rep)
	}
	if len(rep.Missing) != 1 || rep.Missing[0] != seeded[1].ID {
		t.Fatalf("want the deleted incident named, got missing=%v altered=%v",
			rep.Missing, rep.Altered)
	}
}

// Editing is the subtler half and the one a signature cannot see at all: the
// register still has the same number of rows, and the report still signs
// cleanly — it just says something different about severity or a deadline.
func TestPG_Ledger_DetectsEditedIncident(t *testing.T) {
	s := ledgerTestStore(t)
	ctx := context.Background()
	seeded := seedIncidents(t, s, "acme", 2)

	tamper(t, s, "acme",
		"UPDATE incidents SET severity = 'minor', severity_confirmed = TRUE "+
			"WHERE tenant_id = $1 AND id = $2", "acme", seeded[0].ID)

	rep, err := s.VerifyLedger(ctx, "acme")
	if err != nil {
		t.Fatalf("VerifyLedger: %v", err)
	}
	if rep.Intact {
		t.Fatalf("an edited incident went undetected: %+v", rep)
	}
	if len(rep.Altered) != 1 || rep.Altered[0] != seeded[0].ID {
		t.Fatalf("want the edited incident named, got altered=%v missing=%v",
			rep.Altered, rep.Missing)
	}
}

// An operator who understands the mechanism deletes the evidence of the
// deletion too, and the cheapest version of that is removing an incident's only
// ledger row from the END of the chain — where no later row commits to it, so
// the chain still recomputes perfectly. The incident is then present with
// nothing recorded about it, and only the "no ledger entry at all" check can
// see that.
//
// Which incident this targets is load-bearing, and the first version of this
// test got it wrong: List orders by detected_at DESC, so seeded[0] is the
// NEWEST incident and owns the last ledger row, while seeded[2] is the oldest
// and owns the first. Deleting the latter is an interior deletion, caught by
// the chain — the test passed while the branch it claimed to cover never ran.
// Proved by mutation: removing the Unledgered branch left the whole suite
// green. That is the §0c shape, found here by the method rather than by luck.
func TestPG_Ledger_DetectsIncidentWithNoLedgerEntry(t *testing.T) {
	s := ledgerTestStore(t)
	ctx := context.Background()
	seeded := seedIncidents(t, s, "acme", 3)
	newest := seeded[0].ID // owns the LAST ledger row; deleting it breaks no link

	tamper(t, s, "acme",
		"DELETE FROM incident_ledger WHERE tenant_id = $1 AND incident_id = $2",
		"acme", newest)

	rep, err := s.VerifyLedger(ctx, "acme")
	if err != nil {
		t.Fatalf("VerifyLedger: %v", err)
	}
	if rep.Intact {
		t.Fatalf("an incident with no ledger entry went undetected: %+v", rep)
	}
	if len(rep.Unledgered) != 1 || rep.Unledgered[0] != newest {
		t.Fatalf("want %s named as unledgered, got %+v", newest, rep)
	}
	if len(rep.ChainBroken) != 0 {
		t.Fatalf("deleting the tail breaks no link; the chain must stay quiet: %+v", rep)
	}
}

// Legitimate change must NOT read as tampering. A register that cries wolf on
// every status transition is worse than none: it trains its reader to ignore
// it, and the one real alert arrives to an audience that has stopped looking.
func TestPG_Ledger_LegitimateUpdatesStayIntact(t *testing.T) {
	s := ledgerTestStore(t)
	ctx := context.Background()
	seeded := seedIncidents(t, s, "acme", 2)

	contained := StatusContained
	if err := s.Apply(ctx, "acme", seeded[0].ID, Update{Status: &contained}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if err := s.RecordNotification(ctx, "acme", seeded[0].ID, Notification{
		Kind: KindEarlyWarning, Authority: "CSIRT", SentAt: t0.Add(time.Hour),
	}); err != nil {
		t.Fatalf("RecordNotification: %v", err)
	}

	rep, err := s.VerifyLedger(ctx, "acme")
	if err != nil {
		t.Fatalf("VerifyLedger: %v", err)
	}
	if !rep.Intact {
		t.Fatalf("legitimate lifecycle changes reported as tampering: %+v", rep)
	}
}

// The interior case, which the four tests above do not reach: a ledger row
// removed from the MIDDLE of an incident's history. The incident still exists,
// its latest entry still matches its current state, and nothing about the
// register looks wrong — only the chain fails to recompute. Without this test
// the chain column could be dropped entirely and the suite would stay green.
func TestPG_Ledger_DetectsInteriorLedgerDeletion(t *testing.T) {
	s := ledgerTestStore(t)
	ctx := context.Background()
	seeded := seedIncidents(t, s, "acme", 1)
	id := seeded[0].ID

	contained := StatusContained
	if err := s.Apply(ctx, "acme", id, Update{Status: &contained}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	note := "operator assessed"
	if err := s.Apply(ctx, "acme", id, Update{Notes: &note}); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	before, err := s.VerifyLedger(ctx, "acme")
	if err != nil {
		t.Fatalf("VerifyLedger: %v", err)
	}
	if !before.Intact || before.Entries != 3 {
		t.Fatalf("want an intact 3-entry ledger before tampering, got %+v", before)
	}

	// The middle entry: not the one the current state is compared against, so
	// only the chain can notice.
	tamper(t, s, "acme", `
DELETE FROM incident_ledger WHERE tenant_id = $1 AND seq = (
	SELECT seq FROM incident_ledger WHERE tenant_id = $1 ORDER BY seq OFFSET 1 LIMIT 1)`,
		"acme")

	rep, err := s.VerifyLedger(ctx, "acme")
	if err != nil {
		t.Fatalf("VerifyLedger: %v", err)
	}
	if rep.Intact {
		t.Fatalf("an interior ledger deletion went undetected: %+v", rep)
	}
	if len(rep.ChainBroken) == 0 {
		t.Fatalf("want the broken chain named, got %+v", rep)
	}
	if len(rep.Missing) != 0 || len(rep.Altered) != 0 || len(rep.Unledgered) != 0 {
		t.Fatalf("the register itself is untouched; only the chain should complain: %+v", rep)
	}
	// The head must also notice, by a different route: an interior deletion
	// leaves the highest sequence number untouched and lowers the COUNT. The
	// count comparison is the only thing that sees it, and without this
	// assertion that branch was never exercised — removing it left the whole
	// suite green, found by mutation.
	if rep.Head.FoundEntries >= rep.Head.HeadEntries {
		t.Errorf("head = %+v, want fewer entries found than the head records", rep.Head)
	}
	if rep.Head.Complete {
		t.Errorf("the head reported complete while an entry is missing: %+v", rep.Head)
	}
}

// The limits travel with the answer. A report that says "intact" and nothing
// else invites being read as proof, and the most important thing this mechanism
// does not do — detect an incident deleted together with all of its ledger rows
// — is exactly what a reader would otherwise assume it covers.
func TestPG_Ledger_ReportStatesItsLimits(t *testing.T) {
	s := ledgerTestStore(t)
	rep, err := s.VerifyLedger(context.Background(), "acme")
	if err != nil {
		t.Fatalf("VerifyLedger: %v", err)
	}
	if len(rep.Limits) == 0 {
		t.Fatal("a verification result with no stated limits reads as proof")
	}
	// The gap a reader would otherwise assume closed. It used to be the missing
	// head; the head now exists, so the remaining one is that the ledger and
	// its head share a database with the register they attest — an operator who
	// can rewrite all three can make them agree, and only an external anchor
	// defeats that.
	var mentionsAnchor bool
	for _, l := range rep.Limits {
		if strings.Contains(l, "external anchor") {
			mentionsAnchor = true
		}
	}
	if !mentionsAnchor {
		t.Fatalf("the limits do not name the remaining gap; limits=%v", rep.Limits)
	}
}

// --- the head ---

// The case the head exists for, and the only one a back-reference chain
// structurally cannot see: delete the incident AND every ledger row that
// mentions it. Nothing surviving refers to what is gone, so every remaining
// link recomputes perfectly and every remaining incident matches its digest.
// Only a commitment to the COUNT notices.
func TestPG_LedgerHead_DetectsIncidentDeletedWithItsLedgerRows(t *testing.T) {
	s := ledgerTestStore(t)
	ctx := context.Background()
	seeded := seedIncidents(t, s, "acme", 3)
	victim := seeded[0].ID // the newest: its ledger row is the tail

	before, err := s.VerifyLedger(ctx, "acme")
	if err != nil || !before.Intact {
		t.Fatalf("ledger before = %+v, %v", before, err)
	}
	if !before.Head.Present || before.Head.HeadEntries != 3 {
		t.Fatalf("head before = %+v, want 3 entries recorded", before.Head)
	}

	// Two statements, no key, exactly what the cheap attack looks like.
	tamper(t, s, "acme", "DELETE FROM incident_ledger WHERE tenant_id = $1 AND incident_id = $2",
		"acme", victim)
	tamper(t, s, "acme", "DELETE FROM incidents WHERE tenant_id = $1 AND id = $2",
		"acme", victim)

	rep, err := s.VerifyLedger(ctx, "acme")
	if err != nil {
		t.Fatalf("VerifyLedger: %v", err)
	}
	if rep.Intact {
		t.Fatalf("an incident deleted together with its ledger rows went undetected: %+v", rep)
	}
	// The per-incident checks see nothing, which is the point of the test.
	if len(rep.Missing) != 0 || len(rep.Altered) != 0 || len(rep.Unledgered) != 0 || len(rep.ChainBroken) != 0 {
		t.Errorf("the per-incident checks should be silent here; only the head knows: %+v", rep)
	}
	if rep.Head.Complete {
		t.Fatalf("the head reported complete after a truncation: %+v", rep.Head)
	}
	if rep.Head.HeadEntries != 3 || rep.Head.FoundEntries != 2 {
		t.Errorf("head = %+v, want it to claim 3 entries against 2 found", rep.Head)
	}
}

// Deleting the head itself is the other half: it leaves the ledger internally
// perfect and removes the record of how far it should reach.
func TestPG_LedgerHead_DetectsADeletedHead(t *testing.T) {
	s := ledgerTestStore(t)
	ctx := context.Background()
	seedIncidents(t, s, "acme", 2)

	tamper(t, s, "acme", "DELETE FROM incident_ledger_head WHERE tenant_id = $1", "acme")

	rep, err := s.VerifyLedger(ctx, "acme")
	if err != nil {
		t.Fatalf("VerifyLedger: %v", err)
	}
	if rep.Intact || rep.Head.Present {
		t.Fatalf("a deleted head went undetected: %+v", rep.Head)
	}
	if !strings.Contains(rep.Head.Detail, "missing") {
		t.Errorf("detail = %q, want it to say the head is missing", rep.Head.Detail)
	}
}

// The head must never move backwards: lowering last_seq is what a truncation
// looks like, and letting a late write do it would erase the evidence that
// later entries existed.
//
// THIS TEST ONLY MEANS ANYTHING UNDER A ROLE THAT CANNOT BYPASS RLS. Under a
// superuser the policy is skipped and the guard is never exercised — handoff
// §0h records two mutations that survived exactly that way.
func TestPG_LedgerHead_NeverMovesBackwards(t *testing.T) {
	s := ledgerTestStore(t)
	ctx := context.Background()
	seedIncidents(t, s, "acme", 3)

	before, err := s.VerifyLedger(ctx, "acme")
	if err != nil {
		t.Fatalf("VerifyLedger: %v", err)
	}
	highest := before.Head.HeadSeq

	// A write that tries to lower the head, through the same path the store
	// uses. The guard must refuse it.
	err = s.withTenantTx(ctx, "acme", func(tx *sql.Tx) error {
		return advanceHead(ctx, tx, "acme", highest-2, "rolled-back-chain", nil)
	})
	if err != nil {
		t.Fatalf("advanceHead: %v", err)
	}

	after, err := s.VerifyLedger(ctx, "acme")
	if err != nil {
		t.Fatalf("VerifyLedger: %v", err)
	}
	if after.Head.HeadSeq != highest {
		t.Fatalf("the head moved backwards: %d -> %d", highest, after.Head.HeadSeq)
	}
	if !after.Intact {
		t.Errorf("a refused rollback left the ledger reported as tampered: %+v", after)
	}
}

// An unsigned head still commits to the count, and the report must say plainly
// that it proves nothing to a third party. A reader who is not told will assume
// the opposite, because every other verification artifact here is signed.
func TestPG_LedgerHead_SaysWhenItIsNotSigned(t *testing.T) {
	s := ledgerTestStore(t)
	rep, err := s.VerifyLedger(context.Background(), "acme")
	if err != nil {
		t.Fatalf("VerifyLedger: %v", err)
	}
	var said bool
	for _, l := range rep.Limits {
		if strings.Contains(l, "NOT signed") {
			said = true
		}
	}
	if !said {
		t.Errorf("an unsigned head did not say so; limits = %v", rep.Limits)
	}
}

// With a signer attached the head carries a signature and a key id, so an
// auditor can pin the key out of band and check the claim away from this
// system — which is the only thing that makes the head evidence rather than
// bookkeeping.
func TestPG_LedgerHead_IsSignedWhenAKeyIsConfigured(t *testing.T) {
	s := ledgerTestStore(t).WithSigner(fakeSigner{})
	ctx := context.Background()
	seedIncidents(t, s, "acme", 2)

	rep, err := s.VerifyLedger(ctx, "acme")
	if err != nil {
		t.Fatalf("VerifyLedger: %v", err)
	}
	if rep.Head.Signature == "" || rep.Head.KeyID == "" {
		t.Fatalf("head = %+v, want a signature and a key id", rep.Head)
	}
	for _, l := range rep.Limits {
		if strings.Contains(l, "NOT signed") {
			t.Errorf("a signed head still claims to be unsigned: %q", l)
		}
	}
}

// fakeSigner stands in for internal/attest. The signature's cryptography is
// that package's business and is tested there; what matters here is that the
// head carries one and that it covers the head's own claim.
type fakeSigner struct{}

func (fakeSigner) SignBytes(payload []byte) (string, string) {
	return "sig:" + string(payload[:min(len(payload), 24)]), "test-key"
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
