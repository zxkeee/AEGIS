package forensic

import (
	"context"
	"errors"
	"testing"
	"time"

	"api-gateway/internal/pgtest"
	"api-gateway/internal/store"
)

func sealSink(t *testing.T) *PGSink {
	t.Helper()
	s, err := NewPGSink(pgtest.DSN(t, "test_forensic_seal"), nopLogger{})
	if err != nil {
		t.Fatalf("NewPGSink: %v", err)
	}
	t.Cleanup(s.Close)
	return s
}

// seedEntries writes n entries into one period and waits for them to land.
func seedEntries(t *testing.T, s *PGSink, tenant string, at time.Time, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		s.Push(store.ForensicEntry{
			Tenant: tenant, Timestamp: at.Add(time.Duration(i) * time.Second),
			IP: "1.2.3.4", Path: "/api/orders", Method: "GET",
			Reason: "waf_blocked", Code: 403,
		})
	}
	s.Flush()
}

// The question the whole mechanism answers: an operator deletes an
// inconvenient row after the fact, and the seal says so.
func TestSeal_DetectsADeletedEntry(t *testing.T) {
	s := sealSink(t)
	ctx := context.Background()
	start := time.Date(2026, 9, 13, 10, 0, 0, 0, time.UTC)

	seedEntries(t, s, "acme", start, 8)
	seal, err := s.SealPeriod(ctx, "acme", start, start.Add(time.Hour), nil)
	if err != nil {
		t.Fatalf("SealPeriod: %v", err)
	}
	if seal.EntryCount != 8 {
		t.Fatalf("sealed %d entries, want 8", seal.EntryCount)
	}

	// Clean before tampering: the check must not be reporting pre-existing noise.
	checks, err := s.VerifySeals(ctx, "acme")
	if err != nil {
		t.Fatalf("VerifySeals: %v", err)
	}
	if len(checks) != 1 || !checks[0].Intact {
		t.Fatalf("an untouched log did not verify: %+v", checks)
	}

	// The deletion an operator would actually perform.
	if _, err := s.db.ExecContext(ctx, `
		SELECT set_config('app.tenant_id', 'acme', false)`); err != nil {
		t.Fatalf("set_config: %v", err)
	}
	if _, err := s.db.ExecContext(ctx,
		`DELETE FROM forensic_logs WHERE tenant_id = 'acme' AND id = (
			SELECT id FROM forensic_logs WHERE tenant_id = 'acme' ORDER BY id OFFSET 3 LIMIT 1)`,
	); err != nil {
		t.Fatalf("delete: %v", err)
	}

	checks, err = s.VerifySeals(ctx, "acme")
	if err != nil {
		t.Fatalf("VerifySeals after delete: %v", err)
	}
	if len(checks) != 1 {
		t.Fatalf("checks = %d, want 1", len(checks))
	}
	if checks[0].Intact {
		t.Fatal("a deleted entry left the seal intact — the mechanism does nothing")
	}
	if checks[0].ActualCount != 7 {
		t.Errorf("actual count = %d, want 7", checks[0].ActualCount)
	}
	if checks[0].Detail == "" {
		t.Error("no detail: an operator is told something is wrong but not what")
	}
	t.Logf("detected: %s", checks[0].Detail)
}

// An entry ADDED to a sealed period must also fail: backdating an event into a
// closed window is forgery in the other direction.
func TestSeal_DetectsAnAddedEntry(t *testing.T) {
	s := sealSink(t)
	ctx := context.Background()
	start := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)

	seedEntries(t, s, "acme", start, 4)
	if _, err := s.SealPeriod(ctx, "acme", start, start.Add(time.Hour), nil); err != nil {
		t.Fatalf("SealPeriod: %v", err)
	}

	seedEntries(t, s, "acme", start.Add(30*time.Minute), 1)

	checks, err := s.VerifySeals(ctx, "acme")
	if err != nil {
		t.Fatalf("VerifySeals: %v", err)
	}
	if checks[0].Intact {
		t.Fatal("an entry backdated into a sealed period left the seal intact")
	}
	if checks[0].ActualCount != 5 {
		t.Errorf("actual count = %d, want 5", checks[0].ActualCount)
	}
	t.Logf("detected: %s", checks[0].Detail)
}

// The chain: re-sealing one period in isolation must not produce a consistent
// history, because every later seal commits to its predecessor's root.
func TestSeal_ChainDetectsARewrittenSeal(t *testing.T) {
	s := sealSink(t)
	ctx := context.Background()
	h1 := time.Date(2026, 9, 13, 14, 0, 0, 0, time.UTC)
	h2 := h1.Add(time.Hour)

	seedEntries(t, s, "acme", h1, 3)
	seedEntries(t, s, "acme", h2, 3)
	if _, err := s.SealPeriod(ctx, "acme", h1, h2, nil); err != nil {
		t.Fatalf("seal h1: %v", err)
	}
	if _, err := s.SealPeriod(ctx, "acme", h2, h2.Add(time.Hour), nil); err != nil {
		t.Fatalf("seal h2: %v", err)
	}

	checks, _ := s.VerifySeals(ctx, "acme")
	if len(checks) != 2 || !checks[0].Intact || !checks[1].Intact {
		t.Fatalf("a clean two-period chain did not verify: %+v", checks)
	}

	// An operator deletes an entry from the FIRST period and rewrites that
	// seal's root to match — the obvious cover-up.
	if _, err := s.db.ExecContext(ctx, `SELECT set_config('app.tenant_id', 'acme', false)`); err != nil {
		t.Fatalf("set_config: %v", err)
	}
	if _, err := s.db.ExecContext(ctx,
		`DELETE FROM forensic_logs WHERE tenant_id='acme' AND id = (
			SELECT id FROM forensic_logs WHERE tenant_id='acme' ORDER BY id LIMIT 1)`); err != nil {
		t.Fatalf("delete: %v", err)
	}
	recomputed, err := s.VerifySeals(ctx, "acme")
	if err != nil {
		t.Fatalf("VerifySeals: %v", err)
	}
	if _, err := s.db.ExecContext(ctx,
		`UPDATE forensic_seals SET merkle_root = $1, entry_count = $2
		 WHERE tenant_id='acme' AND period_start = $3`,
		recomputed[0].ActualRoot, recomputed[0].ActualCount, h1); err != nil {
		t.Fatalf("rewrite seal: %v", err)
	}

	checks, err = s.VerifySeals(ctx, "acme")
	if err != nil {
		t.Fatalf("VerifySeals after rewrite: %v", err)
	}
	if !checks[0].Intact {
		t.Error("the rewritten seal should now match its own period — that is the " +
			"point of the cover-up, and what the chain is for")
	}
	if checks[1].Intact {
		t.Fatal("the SECOND seal still verified: its prev_root should no longer " +
			"match the rewritten first root, which is the only thing that makes " +
			"rewriting one seal insufficient")
	}
	t.Logf("chain break reported as: %s", checks[1].Detail)
}

// Sealing the same period twice is refused. A second seal for one window is how
// an operator would keep the convenient one and discard the other.
func TestSeal_RefusesToSealAPeriodTwice(t *testing.T) {
	s := sealSink(t)
	ctx := context.Background()
	start := time.Date(2026, 9, 13, 16, 0, 0, 0, time.UTC)
	seedEntries(t, s, "acme", start, 2)

	if _, err := s.SealPeriod(ctx, "acme", start, start.Add(time.Hour), nil); err != nil {
		t.Fatalf("first seal: %v", err)
	}
	// errors.Is, not "any error": the UNIQUE constraint on
	// (tenant_id, period_start) would also reject the second insert, so a test
	// that accepts any failure passes with the explicit check removed and tells
	// us nothing about which barrier held. Both are wanted — the check gives a
	// usable error, the constraint holds when two replicas race — but only one
	// of them is this function's contract.
	_, err := s.SealPeriod(ctx, "acme", start, start.Add(time.Hour), nil)
	if !errors.Is(err, ErrPeriodAlreadySealed) {
		t.Fatalf("second seal returned %v, want ErrPeriodAlreadySealed", err)
	}
}

// A tenant's seals must not be visible to another tenant, and a seal must not
// cover another tenant's entries.
func TestSeal_IsTenantScoped(t *testing.T) {
	s := sealSink(t)
	ctx := context.Background()
	start := time.Date(2026, 9, 13, 18, 0, 0, 0, time.UTC)

	seedEntries(t, s, "acme", start, 3)
	seedEntries(t, s, "globex", start, 5)

	acme, err := s.SealPeriod(ctx, "acme", start, start.Add(time.Hour), nil)
	if err != nil {
		t.Fatalf("seal acme: %v", err)
	}
	if acme.EntryCount != 3 {
		t.Fatalf("acme's seal covers %d entries, want 3 — it is counting another "+
			"tenant's log", acme.EntryCount)
	}

	globex, err := s.SealPeriod(ctx, "globex", start, start.Add(time.Hour), nil)
	if err != nil {
		t.Fatalf("seal globex: %v", err)
	}
	if globex.MerkleRoot == acme.MerkleRoot {
		t.Fatal("two tenants with different logs produced the same root")
	}

	checks, err := s.VerifySeals(ctx, "acme")
	if err != nil {
		t.Fatalf("VerifySeals: %v", err)
	}
	if len(checks) != 1 {
		t.Fatalf("acme sees %d seals, want only its own", len(checks))
	}

	// Note on what this test can and cannot pin. Tenant scoping here has TWO
	// barriers: the WHERE tenant_id clause, and the RLS policy keyed on the
	// app.tenant_id GUC that SealPeriod sets. Against a role that enforces RLS
	// (a production role, and the local one) removing the WHERE clause changes
	// nothing — RLS still cuts the rows. Against a role that bypasses it (a
	// superuser, which is what the CI container runs as) the WHERE clause is
	// the only thing left.
	//
	// So this assertion is checking RLS here and the WHERE clause in CI, and
	// neither environment checks both. That is worth knowing rather than
	// papering over: it is the same asymmetry that let a discovery test assert
	// on rows it had never written (#52).
}

// The worker seals closed periods and leaves the open one alone.
//
// The open period is still being written to — sealing it would commit to a
// window that has not finished, and every entry arriving afterwards would read
// as "added after sealing" for the life of the log.
func TestSealWorker_SealsClosedPeriodsAndSkipsTheOpenOne(t *testing.T) {
	s := sealSink(t)
	ctx := context.Background()
	h0 := time.Date(2026, 9, 13, 8, 0, 0, 0, time.UTC)

	// Three hours of entries: two closed, one still open at `now`.
	seedEntries(t, s, "acme", h0, 2)
	seedEntries(t, s, "acme", h0.Add(time.Hour), 3)
	seedEntries(t, s, "acme", h0.Add(2*time.Hour), 4)

	w := NewSealWorker(s, SealSchedule{Period: time.Hour, Lag: 5 * time.Minute},
		nil, s.TenantsWithEntries, nopLogger{})
	// now is inside the third hour, so only the first two have closed.
	w.sealDue(ctx, h0.Add(2*time.Hour+30*time.Minute))

	checks, err := s.VerifySeals(ctx, "acme")
	if err != nil {
		t.Fatalf("VerifySeals: %v", err)
	}
	if len(checks) != 2 {
		t.Fatalf("sealed %d periods, want 2 — the open period must be left alone", len(checks))
	}
	for i, c := range checks {
		if !c.Intact {
			t.Errorf("seal %d is not intact straight after sealing: %s", i, c.Detail)
		}
	}
	if checks[0].Seal.EntryCount != 2 || checks[1].Seal.EntryCount != 3 {
		t.Errorf("entry counts = %d, %d; want 2, 3",
			checks[0].Seal.EntryCount, checks[1].Seal.EntryCount)
	}
	// The chain starts empty and then links.
	if checks[0].Seal.PrevRoot != "" {
		t.Errorf("the first seal has prev_root %q, want empty", checks[0].Seal.PrevRoot)
	}
	if checks[1].Seal.PrevRoot != checks[0].Seal.MerkleRoot {
		t.Error("the second seal does not link to the first")
	}
}

// A gateway that was down must catch up rather than leave a hole. An unsealed
// window is one an operator can edit freely, and a missing seal is
// indistinguishable from a deleted one unless the chain is contiguous.
func TestSealWorker_CatchesUpWithoutLeavingAHole(t *testing.T) {
	s := sealSink(t)
	ctx := context.Background()
	h0 := time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC)

	for i := 0; i < 5; i++ {
		seedEntries(t, s, "acme", h0.Add(time.Duration(i)*time.Hour), i+1)
	}

	w := NewSealWorker(s, SealSchedule{Period: time.Hour, Lag: time.Minute},
		nil, s.TenantsWithEntries, nopLogger{})
	// One tick, five hours after the first entry: all five periods have closed.
	w.sealDue(ctx, h0.Add(5*time.Hour+10*time.Minute))

	checks, err := s.VerifySeals(ctx, "acme")
	if err != nil {
		t.Fatalf("VerifySeals: %v", err)
	}
	if len(checks) != 5 {
		t.Fatalf("sealed %d periods, want 5: a gap in the chain is a window that "+
			"can be edited without detection", len(checks))
	}
	for i, c := range checks {
		if !c.Intact {
			t.Errorf("period %d not intact: %s", i, c.Detail)
		}
		want := int64(i + 1)
		if c.Seal.EntryCount != want {
			t.Errorf("period %d sealed %d entries, want %d", i, c.Seal.EntryCount, want)
		}
	}
	// Contiguous: each period_end is the next period_start.
	for i := 1; i < len(checks); i++ {
		if !checks[i].Seal.PeriodStart.Equal(checks[i-1].Seal.PeriodEnd) {
			t.Errorf("gap between period %d and %d: %s .. %s",
				i-1, i, checks[i-1].Seal.PeriodEnd, checks[i].Seal.PeriodStart)
		}
	}
}

// Running the worker twice must not double-seal or break the chain — under HA
// two replicas tick at the same time, and that has to be ordinary.
func TestSealWorker_IsIdempotent(t *testing.T) {
	s := sealSink(t)
	ctx := context.Background()
	h0 := time.Date(2026, 9, 13, 20, 0, 0, 0, time.UTC)
	seedEntries(t, s, "acme", h0, 3)

	w := NewSealWorker(s, SealSchedule{Period: time.Hour, Lag: time.Minute},
		nil, s.TenantsWithEntries, nopLogger{})
	at := h0.Add(time.Hour + 10*time.Minute)
	w.sealDue(ctx, at)
	w.sealDue(ctx, at)

	checks, err := s.VerifySeals(ctx, "acme")
	if err != nil {
		t.Fatalf("VerifySeals: %v", err)
	}
	if len(checks) != 1 {
		t.Fatalf("sealed %d periods, want 1: a second seal for one window lets an "+
			"operator keep the convenient one", len(checks))
	}
	if !checks[0].Intact {
		t.Errorf("not intact after a repeated run: %s", checks[0].Detail)
	}
}

// Run ticks and Stop ends it. Covered because the worker's lifecycle is how
// seals actually get written in production — sealDue being correct is no use if
// nothing calls it, and a Stop that does not stop leaks a goroutine per reload.
func TestSealWorker_RunAndStop(t *testing.T) {
	s := sealSink(t)
	ctx := context.Background()
	h0 := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Hour)
	seedEntries(t, s, "acme", h0, 2)

	// A short period so the first immediate pass has something closed to seal.
	w := NewSealWorker(s, SealSchedule{Period: time.Hour, Lag: time.Minute},
		nil, s.TenantsWithEntries, nopLogger{})

	done := make(chan struct{})
	go func() { w.Run(ctx); close(done) }()

	// Run seals once immediately, before the first tick.
	deadline := time.After(5 * time.Second)
	for {
		checks, err := s.VerifySeals(ctx, "acme")
		if err != nil {
			t.Fatalf("VerifySeals: %v", err)
		}
		if len(checks) > 0 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("Run did not seal the closed period within 5s")
		case <-time.After(20 * time.Millisecond):
		}
	}

	w.Stop()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop did not end Run: a goroutine leaks on every config reload")
	}
}

// Run must also end when its context is cancelled — shutdown path.
func TestSealWorker_RunStopsOnContextCancel(t *testing.T) {
	s := sealSink(t)
	ctx, cancel := context.WithCancel(context.Background())

	w := NewSealWorker(s, SealSchedule{Period: time.Hour, Lag: time.Minute},
		nil, s.TenantsWithEntries, nopLogger{})
	done := make(chan struct{})
	go func() { w.Run(ctx); close(done) }()

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run ignored context cancellation")
	}
}

// Defaults: a zero Period or Lag must not produce a worker that ticks
// constantly or seals a window still being written to.
func TestNewSealWorker_Defaults(t *testing.T) {
	w := NewSealWorker(nil, SealSchedule{}, nil, nil, nopLogger{})
	if w.cfg.Period != time.Hour {
		t.Errorf("period = %v, want 1h", w.cfg.Period)
	}
	if w.cfg.Lag != 5*time.Minute {
		t.Errorf("lag = %v, want 5m", w.cfg.Lag)
	}
}

// A tenant listing that fails must not take the worker down, and must not seal
// a partial set of tenants as though the rest had nothing to seal.
func TestSealWorker_SurvivesATenantListingFailure(t *testing.T) {
	s := sealSink(t)
	w := NewSealWorker(s, SealSchedule{Period: time.Hour, Lag: time.Minute}, nil,
		func(context.Context) ([]string, error) { return nil, errors.New("db down") },
		nopLogger{})
	// Must return rather than panic or block.
	w.sealDue(context.Background(), time.Now())
}

// A tenant with no entries has nothing to commit to, and must not get a seal
// over an empty window that would then conflict with its first real period.
func TestSealWorker_SkipsATenantWithNoEntries(t *testing.T) {
	s := sealSink(t)
	ctx := context.Background()
	w := NewSealWorker(s, SealSchedule{Period: time.Hour, Lag: time.Minute}, nil,
		func(context.Context) ([]string, error) { return []string{"empty-tenant"}, nil },
		nopLogger{})
	w.sealDue(ctx, time.Now())

	checks, err := s.VerifySeals(ctx, "empty-tenant")
	if err != nil {
		t.Fatalf("VerifySeals: %v", err)
	}
	if len(checks) != 0 {
		t.Fatalf("sealed %d periods for a tenant with no entries", len(checks))
	}
}

// SealPeriod refuses a period that is not a period.
func TestSealPeriod_RefusesAnEmptyWindow(t *testing.T) {
	s := sealSink(t)
	at := time.Date(2026, 9, 13, 6, 0, 0, 0, time.UTC)
	if _, err := s.SealPeriod(context.Background(), "acme", at, at, nil); err == nil {
		t.Fatal("a zero-length period was sealed")
	}
	if _, err := s.SealPeriod(context.Background(), "acme", at, at.Add(-time.Hour), nil); err == nil {
		t.Fatal("a backwards period was sealed")
	}
}

// A signed seal carries the signature and the key id that produced it.
func TestSealPeriod_SignsWhenASignerIsGiven(t *testing.T) {
	s := sealSink(t)
	ctx := context.Background()
	start := time.Date(2026, 9, 13, 4, 0, 0, 0, time.UTC)
	seedEntries(t, s, "acme", start, 2)

	seal, err := s.SealPeriod(ctx, "acme", start, start.Add(time.Hour), stubSigner{})
	if err != nil {
		t.Fatalf("SealPeriod: %v", err)
	}
	if seal.Signature == "" || seal.KeyID == "" {
		t.Fatalf("seal is unsigned: sig=%q keyID=%q", seal.Signature, seal.KeyID)
	}
	// And it survives the round trip through the database.
	checks, err := s.VerifySeals(ctx, "acme")
	if err != nil {
		t.Fatalf("VerifySeals: %v", err)
	}
	if checks[0].Seal.Signature != seal.Signature {
		t.Error("the signature did not round-trip")
	}
}

type stubSigner struct{}

func (stubSigner) SignBytes(payload []byte) (string, string) {
	return "sig-" + string(payload[:8]), "key-1"
}
