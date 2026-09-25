package audit

import (
	"context"
	"database/sql"
	"strings"
	"sync"
	"testing"
	"time"

	"api-gateway/internal/pgtest"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// The admin trail is what docs/ARCHITECTURE.md offers as the mitigation for the
// insider threat. Until now that claim had nothing behind it: no RLS, no
// integrity, and a retention sweep deleting from the table on a schedule. These
// tests are the evidence for the claim, and each one performs the edit an
// insider would actually make.

func integrityStore(t *testing.T) *Store {
	t.Helper()
	s, err := New(pgtest.DSN(t, "test_audit_integrity"), nopLogger{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// record writes one entry and waits for the async writer to persist it.
func record(t *testing.T, s *Store, tenant, action string, at time.Time) {
	t.Helper()
	s.Record(Entry{
		Time: at, TenantID: tenant, ActorID: "u1", ActorEmail: "root@acme.example",
		Role: "admin", Action: action, Method: "POST", Path: "/api/users",
		Status: 200, IP: "10.0.0.9",
	})
}

// drain waits until the tenant's trail holds n entries, so a test never races
// the async writer. Fails rather than hanging: a writer that stopped is a
// result, not a reason to wait forever.
func drain(t *testing.T, s *Store, tenant string, n int64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		chk, err := s.Verify(context.Background(), tenant)
		if err == nil && chk.Entries >= n {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("the audit writer never persisted %d entries for %q", n, tenant)
}

// tamper runs a statement the way an insider with database access would, in one
// transaction with the tenant pinned, and insists it changed something. A
// tamper that changed nothing would leave every assertion after it testing an
// untouched table (handoff §0j).
func tamper(t *testing.T, s *Store, tenant, query string, args ...any) {
	t.Helper()
	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT set_config('app.tenant_id', $1, true)`, tenant); err != nil {
		t.Fatalf("set_config: %v", err)
	}
	res, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		t.Fatalf("tamper: %v", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		t.Fatalf("rows affected: %v", err)
	}
	if n == 0 {
		t.Fatalf("tamper changed no rows; the assertions after it would prove nothing: %s", query)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
}

func TestAudit_IntactTrailVerifies(t *testing.T) {
	s := integrityStore(t)
	for i := 0; i < 4; i++ {
		record(t, s, "acme", "login", time.Now().UTC())
	}
	drain(t, s, "acme", 4)

	chk, err := s.Verify(context.Background(), "acme")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !chk.Intact {
		t.Fatalf("an untouched trail did not verify: %+v", chk)
	}
	if !chk.HeadPresent || chk.HeadEntries != 4 {
		t.Errorf("head = present:%v entries:%d, want 4 recorded", chk.HeadPresent, chk.HeadEntries)
	}
	if len(chk.Limits) == 0 {
		t.Error("a green verification result with no stated limits reads as proof")
	}
}

// The edit an insider makes: change the record of what they did. The trail
// keeps the same number of rows and says something different.
func TestAudit_DetectsAnEditedEntry(t *testing.T) {
	s := integrityStore(t)
	for i := 0; i < 3; i++ {
		record(t, s, "acme", "delete_user", time.Now().UTC())
	}
	drain(t, s, "acme", 3)

	tamper(t, s, "acme",
		`UPDATE admin_audit_log SET action = 'login', detail = 'routine'
		 WHERE tenant_id = $1 AND id = (SELECT min(id) FROM admin_audit_log WHERE tenant_id = $1)`,
		"acme")

	chk, err := s.Verify(context.Background(), "acme")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if chk.Intact {
		t.Fatalf("an edited audit entry went undetected: %+v", chk)
	}
	if len(chk.Broken) == 0 {
		t.Errorf("the edit did not break a link: %+v", chk)
	}
}

// Deleting the record of an action is the other half, and the cheaper one.
func TestAudit_DetectsADeletedEntry(t *testing.T) {
	s := integrityStore(t)
	for i := 0; i < 3; i++ {
		record(t, s, "acme", "delete_user", time.Now().UTC())
	}
	drain(t, s, "acme", 3)

	tamper(t, s, "acme",
		`DELETE FROM admin_audit_log WHERE tenant_id = $1
		 AND id = (SELECT max(id) FROM admin_audit_log WHERE tenant_id = $1)`, "acme")

	chk, err := s.Verify(context.Background(), "acme")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if chk.Intact {
		t.Fatalf("a deleted audit entry went undetected: %+v", chk)
	}
	if !strings.Contains(chk.Detail, "missing") && !strings.Contains(chk.Detail, "short of its head") {
		t.Errorf("detail = %q, want it to name the missing entries", chk.Detail)
	}
}

// THE CASE RETENTION CREATES. Deleting old rows is lawful and scheduled, and a
// naive chain would report every sweep as tampering — which would train an
// operator to ignore the one alert that matters. Recorded pruning must verify
// clean.
func TestAudit_RetentionPruningIsNotTampering(t *testing.T) {
	s := integrityStore(t)
	old := time.Now().UTC().Add(-90 * 24 * time.Hour)
	for i := 0; i < 3; i++ {
		record(t, s, "acme", "login", old)
	}
	for i := 0; i < 2; i++ {
		record(t, s, "acme", "login", time.Now().UTC())
	}
	drain(t, s, "acme", 5)

	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if _, err := tx.ExecContext(ctx, `SELECT set_config('app.tenant_id', '*', true)`); err != nil {
		t.Fatalf("set_config: %v", err)
	}
	cutoff := time.Now().UTC().Add(-24 * time.Hour)
	var highest int64
	var count int64
	if err := tx.QueryRowContext(ctx,
		`SELECT COALESCE(max(id),0), count(*) FROM admin_audit_log WHERE tenant_id = $1 AND ts < $2`,
		"acme", cutoff).Scan(&highest, &count); err != nil {
		t.Fatalf("scan victims: %v", err)
	}
	if count != 3 {
		t.Fatalf("expected 3 expired rows, found %d", count)
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM admin_audit_log WHERE tenant_id = $1 AND ts < $2`, "acme", cutoff); err != nil {
		t.Fatalf("prune: %v", err)
	}
	if err := RecordPruning(ctx, tx, "acme", highest, count, nil); err != nil {
		t.Fatalf("RecordPruning: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}

	chk, err := s.Verify(ctx, "acme")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !chk.Intact {
		t.Fatalf("a recorded retention pruning read as tampering: %+v", chk)
	}
	if chk.PrunedCount != 3 {
		t.Errorf("pruned_count = %d, want 3", chk.PrunedCount)
	}
}

// And the other side of that coin: a deletion NOT recorded must still fail, or
// the pruning mechanism would be a way to delete anything.
func TestAudit_UnrecordedDeletionStillFails(t *testing.T) {
	s := integrityStore(t)
	old := time.Now().UTC().Add(-90 * 24 * time.Hour)
	for i := 0; i < 3; i++ {
		record(t, s, "acme", "login", old)
	}
	drain(t, s, "acme", 3)

	tamper(t, s, "acme", `DELETE FROM admin_audit_log WHERE tenant_id = $1 AND ts < $2`,
		"acme", time.Now().UTC().Add(-24*time.Hour))

	chk, err := s.Verify(context.Background(), "acme")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if chk.Intact {
		t.Fatalf("an unrecorded deletion verified clean; pruning would be a way to delete anything: %+v", chk)
	}
}

// Deleting the head removes the record of how far the trail should reach.
func TestAudit_DetectsADeletedHead(t *testing.T) {
	s := integrityStore(t)
	record(t, s, "acme", "login", time.Now().UTC())
	drain(t, s, "acme", 1)

	tamper(t, s, "acme", `DELETE FROM admin_audit_head WHERE tenant_id = $1`, "acme")

	chk, err := s.Verify(context.Background(), "acme")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if chk.Intact || chk.HeadPresent {
		t.Fatalf("a deleted head went undetected: %+v", chk)
	}
}

// RLS, which this table never had. One tenant's trail must not be visible to
// another — and the listing must not silently come back empty for the right
// tenant either, which is what a pooled read under RLS would do.
func TestAudit_TenantIsolation(t *testing.T) {
	s := integrityStore(t)
	record(t, s, "acme", "login", time.Now().UTC())
	record(t, s, "globex", "login", time.Now().UTC())
	drain(t, s, "acme", 1)
	drain(t, s, "globex", 1)

	ctx := context.Background()
	acme, err := s.List(ctx, Filter{TenantID: "acme"})
	if err != nil {
		t.Fatalf("List(acme): %v", err)
	}
	if len(acme) == 0 {
		t.Fatal("the tenant's own listing came back empty; a pooled read under RLS does exactly this")
	}
	for _, e := range acme {
		if e.TenantID != "acme" {
			t.Fatalf("acme can read %q's audit trail", e.TenantID)
		}
	}

	all, err := s.List(ctx, Filter{TenantID: "*"})
	if err != nil {
		t.Fatalf("List(*): %v", err)
	}
	var sawOther bool
	for _, e := range all {
		if e.TenantID == "globex" {
			sawOther = true
		}
	}
	if !sawOther {
		t.Error("the super-admin listing does not span tenants; the '*' escape hatch is not working")
	}
}

var _ = sql.ErrNoRows

// A COMPETENT insider does not just delete a row — they recompute the links
// after it, so the chain reads perfectly. Every per-row check then passes and
// the only thing left standing is the head's commitment to the count.
//
// This is the attack the head exists for, and without this test the count
// comparison was dead code: deleting a row naively is caught by the broken
// links, deleting the last row by the highest-id check. Found by mutation —
// removing the count branch left the suite green.
func TestAudit_DetectsADeletionWithTheChainRepaired(t *testing.T) {
	s := integrityStore(t)
	for i := 0; i < 4; i++ {
		record(t, s, "acme", "delete_user", time.Now().UTC())
	}
	drain(t, s, "acme", 4)

	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT set_config('app.tenant_id', 'acme', true)`); err != nil {
		t.Fatalf("set_config: %v", err)
	}

	// Remove the second entry.
	var victim int64
	if err := tx.QueryRowContext(ctx,
		`SELECT id FROM admin_audit_log WHERE tenant_id = 'acme' ORDER BY id OFFSET 1 LIMIT 1`).
		Scan(&victim); err != nil {
		t.Fatalf("pick victim: %v", err)
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM admin_audit_log WHERE tenant_id = 'acme' AND id = $1`, victim); err != nil {
		t.Fatalf("delete: %v", err)
	}

	// Repair every link after it, exactly as the writer would have.
	rows, err := tx.QueryContext(ctx, `
SELECT id, ts, tenant_id, actor_id, actor_email, role, super_admin,
       action, method, path, status, ip, detail, chain
FROM admin_audit_log WHERE tenant_id = 'acme' ORDER BY id`)
	if err != nil {
		t.Fatalf("read trail: %v", err)
	}
	type row struct {
		id    int64
		e     Entry
		chain string
	}
	var all []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.e.Time, &r.e.TenantID, &r.e.ActorID, &r.e.ActorEmail,
			&r.e.Role, &r.e.SuperAdmin, &r.e.Action, &r.e.Method, &r.e.Path,
			&r.e.Status, &r.e.IP, &r.e.Detail, &r.chain); err != nil {
			_ = rows.Close()
			t.Fatalf("scan: %v", err)
		}
		all = append(all, r)
	}
	_ = rows.Close()

	prev := all[0].chain
	for _, r := range all[1:] {
		d := entryDigest(r.id, r.e)
		c := chainValue(prev, d, r.id)
		if _, err := tx.ExecContext(ctx,
			`UPDATE admin_audit_log SET digest = $2, chain = $3 WHERE id = $1`, r.id, d, c); err != nil {
			t.Fatalf("repair: %v", err)
		}
		prev = c
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}

	chk, err := s.Verify(ctx, "acme")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(chk.Broken) != 0 {
		t.Fatalf("the repair was incomplete, so this test is not exercising what it claims: %+v", chk)
	}
	if chk.Intact {
		t.Fatalf("a deletion with the chain repaired went undetected — the head's count is the "+
			"only thing that can see this: %+v", chk)
	}
	if chk.Entries >= chk.HeadEntries {
		t.Errorf("entries=%d head=%d, want fewer present than recorded", chk.Entries, chk.HeadEntries)
	}
}

// The head must never move backwards: lowering last_id is the shape of a
// truncation. Only meaningful under a role that cannot bypass RLS.
func TestAudit_HeadNeverMovesBackwards(t *testing.T) {
	s := integrityStore(t)
	for i := 0; i < 3; i++ {
		record(t, s, "acme", "login", time.Now().UTC())
	}
	drain(t, s, "acme", 3)

	ctx := context.Background()
	// Read inside a scoped transaction: the head table carries RLS now, and a
	// pooled read with no app.tenant_id set matches zero rows while reporting
	// success. That is the policy working, and it is also the trap this
	// repository has fallen into before (handoff §0j).
	before := headLastID(t, s, "acme")

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if _, err := tx.ExecContext(ctx, `SELECT set_config('app.tenant_id', 'acme', true)`); err != nil {
		t.Fatalf("set_config: %v", err)
	}
	if err := advanceHead(ctx, tx, "acme", before-2, "rolled-back", nil); err != nil {
		t.Fatalf("advanceHead: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}

	after := headLastID(t, s, "acme")
	if after != before {
		t.Fatalf("the head moved backwards: %d -> %d", before, after)
	}
}

// headLastID reads a tenant's head inside a scoped transaction.
func headLastID(t *testing.T, s *Store, tenant string) int64 {
	t.Helper()
	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT set_config('app.tenant_id', $1, true)`, tenant); err != nil {
		t.Fatalf("set_config: %v", err)
	}
	var id int64
	if err := tx.QueryRowContext(ctx,
		`SELECT last_id FROM admin_audit_head WHERE tenant_id = $1`, tenant).Scan(&id); err != nil {
		t.Fatalf("read head: %v", err)
	}
	return id
}

// THE SAME RACE THE INCIDENT LEDGER HAD, in the trail that records what
// administrators did.
//
// Within one process this is invisible: Store.worker() is a single goroutine
// draining one channel, so its own writes are already serial. The exposure is
// the deployment this project documents as supported — more than one admin-plane
// replica sharing one PostgreSQL. Each replica has its own worker, the two
// workers do not know about each other, and `insert` reads the previous chain
// link with a bare SELECT under READ COMMITTED.
//
// Two replicas, both writing for one tenant: B inserts, then looks for "the row
// before mine" and cannot see A's uncommitted row, so it chains to A's
// predecessor instead of to A. Verification walks by id and reports Broken —
// an accusation of tampering against an operator who did nothing.
//
// Two Store instances on one DSN is exactly two replicas, which is why this
// test builds them that way rather than reaching inside one.
func TestAudit_ConcurrentReplicasKeepTheChainIntact(t *testing.T) {
	dsn := pgtest.DSN(t, "test_audit_race")

	newReplica := func() *Store {
		s, err := New(dsn, nopLogger{})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		t.Cleanup(func() { _ = s.Close() })
		return s
	}
	a, b := newReplica(), newReplica()

	const perReplica = 12
	start := make(chan struct{})
	var wg sync.WaitGroup
	for _, s := range []*Store{a, b} {
		wg.Add(1)
		go func(s *Store) {
			defer wg.Done()
			<-start
			for i := 0; i < perReplica; i++ {
				s.Record(Entry{
					Time: time.Now().UTC(), TenantID: "acme", ActorID: "u1",
					ActorEmail: "root@acme.example", Role: "admin",
					Action: "delete_user", Method: "POST", Path: "/api/users",
					Status: 200, IP: "10.0.0.9",
				})
			}
		}(s)
	}
	close(start)
	wg.Wait()

	// Both replicas' workers are asynchronous; wait for the trail to settle.
	drain(t, a, "acme", perReplica*2)

	chk, err := a.Verify(context.Background(), "acme")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(chk.Broken) != 0 {
		t.Fatalf("%d positions report a broken chain after %d ordinary writes from "+
			"two replicas and zero tampering: %v\n"+
			"The admin action trail is accusing an operator who did nothing.",
			len(chk.Broken), perReplica*2, chk.Broken)
	}
	if !chk.Intact {
		t.Fatalf("trail not intact after ordinary concurrent writes: %+v", chk)
	}
}

// The coverage section of a signed compliance report asks "how many security
// events were lost", and Dropped() is documented as cumulative since start. A
// background ticker used to answer that question by calling Swap(0) on the same
// counter every three seconds — so the report read a non-zero figure only
// inside the brief window after a drop, and zero the rest of the time. The
// gateway's own error log said events were lost; the signed document said none
// were. This test holds the two readers of that counter to one story.
func TestAudit_DropCounterSurvivesThePeriodicLogLine(t *testing.T) {
	s := integrityStore(t) // its worker(), and therefore its ticker, is running

	const dropped = 7
	for i := 0; i < dropped; i++ {
		s.dropped.Add(1)
	}
	if got := s.Dropped(); got != dropped {
		t.Fatalf("Dropped() = %d immediately after the drops, want %d", got, dropped)
	}

	// Outlast the reporting tick. The log line is allowed to fire; what it is
	// not allowed to do is erase the figure the compliance report reads.
	time.Sleep(dropReportInterval + 500*time.Millisecond)

	if got := s.Dropped(); got != dropped {
		t.Fatalf("Dropped() = %d after the periodic log line ran, want %d — "+
			"the compliance report would state that no events were lost while "+
			"the error log says %d were", got, dropped, dropped)
	}
}

// A retention sweep prunes the audit trail with no signing key (the worker that
// prunes deliberately does not hold one), which blanks the head's signature.
// That is acceptable — an unsigned head still commits to the trail for a reader.
// What is not acceptable is the report continuing to omit the "unsigned" caveat
// because it decided from process configuration ("is a key configured?") rather
// than from the row it just read ("is THIS head signed?").
func TestAudit_PrunedHeadIsReportedAsUnsigned(t *testing.T) {
	s := integrityStore(t).WithSigner(fakeAuditSigner{})
	ctx := context.Background()

	old := time.Now().UTC().Add(-90 * 24 * time.Hour)
	for i := 0; i < 3; i++ {
		record(t, s, "acme", "login", old)
	}
	record(t, s, "acme", "login", time.Now().UTC())
	drain(t, s, "acme", 4)

	before, err := s.Verify(ctx, "acme")
	if err != nil {
		t.Fatalf("Verify before: %v", err)
	}
	if before.Signature == "" {
		t.Fatal("head is unsigned before pruning; this test cannot show what it claims")
	}
	for _, l := range before.Limits {
		if strings.Contains(l, "NO signature") {
			t.Fatalf("a signed head was reported as unsigned: %q", l)
		}
	}

	// Prune the way retention does: in a transaction, with no signer.
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if _, err := tx.ExecContext(ctx, `SELECT set_config('app.tenant_id', '*', true)`); err != nil {
		t.Fatalf("set_config: %v", err)
	}
	cutoff := time.Now().UTC().Add(-24 * time.Hour)
	var highest, n int64
	if err := tx.QueryRowContext(ctx,
		`SELECT COALESCE(max(id),0), count(*) FROM admin_audit_log WHERE tenant_id=$1 AND ts < $2`,
		"acme", cutoff).Scan(&highest, &n); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM admin_audit_log WHERE tenant_id=$1 AND ts < $2`, "acme", cutoff); err != nil {
		t.Fatalf("prune: %v", err)
	}
	if err := RecordPruning(ctx, tx, "acme", highest, n, nil); err != nil {
		t.Fatalf("RecordPruning: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}

	after, err := s.Verify(ctx, "acme")
	if err != nil {
		t.Fatalf("Verify after: %v", err)
	}
	if after.Signature != "" {
		t.Fatalf("pruning was expected to leave the head unsigned, got %q", after.Signature)
	}
	var warned bool
	for _, l := range after.Limits {
		if strings.Contains(l, "NO signature") {
			warned = true
		}
	}
	if !warned {
		t.Fatalf("the head lost its signature and the report does not say so; limits=%v\n"+
			"A reader trusting the prose over the raw field believes this trail is "+
			"attested when it is not.", after.Limits)
	}
}

// fakeAuditSigner stands in for internal/attest; the cryptography is that
// package's business and is tested there.
type fakeAuditSigner struct{}

func (fakeAuditSigner) SignBytes(p []byte) (string, string) {
	return "sig:" + string(p[:minInt(len(p), 16)]), "test-key"
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
