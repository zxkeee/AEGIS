package forensic

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Seal is one period's commitment to the contents of the log.
type Seal struct {
	TenantID string `json:"tenant_id"`
	// Seq is this seal's position in the tenant's chain, from 1. The chain head
	// commits to the highest one, which is what makes a missing tail countable
	// rather than invisible.
	Seq         int64     `json:"seq"`
	PeriodStart time.Time `json:"period_start"`
	PeriodEnd   time.Time `json:"period_end"`
	EntryCount  int64     `json:"entry_count"`
	MerkleRoot  string    `json:"merkle_root"`
	PrevRoot    string    `json:"prev_root"`
	Signature   string    `json:"signature,omitempty"`
	KeyID       string    `json:"key_id,omitempty"`
	SealedAt    time.Time `json:"sealed_at"`
}

// Signer signs a seal payload. Satisfied by *attest.Signer; an interface here
// so this package does not depend on the attestation package and the seal can
// be written unsigned when no key is configured.
type Signer interface {
	SignBytes(payload []byte) (signature string, keyID string)
}

// ErrPeriodAlreadySealed is returned when a period already has a seal. Sealing
// it again is refused rather than overwritten: a second seal for one window is
// how an operator would keep the convenient one.
var ErrPeriodAlreadySealed = errors.New("forensic: this period is already sealed")

// SealPeriod commits to every log entry in [from, to) for one tenant.
//
// Called by the scheduler after a period closes. It reads the entries in id
// order, folds them into a Merkle root, links to the previous seal, and writes
// the result — signed, when a signer is configured.
//
// The whole thing runs in ONE transaction, and that is load-bearing rather than
// tidiness: reading the entries and writing the seal must see the same snapshot,
// or a row arriving between the two would be excluded from a root that claims
// to cover the window it landed in.
func (s *PGSink) SealPeriod(ctx context.Context, tenant string, from, to time.Time, signer Signer) (Seal, error) {
	if !to.After(from) {
		return Seal{}, fmt.Errorf("forensic: seal period must be non-empty (%s .. %s)", from, to)
	}

	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return Seal{}, fmt.Errorf("forensic: seal begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `SELECT set_config('app.tenant_id', $1, true)`, tenant); err != nil {
		return Seal{}, fmt.Errorf("forensic: seal set_config: %w", err)
	}

	var exists bool
	if err := tx.QueryRowContext(ctx,
		`SELECT EXISTS (SELECT 1 FROM forensic_seals WHERE tenant_id = $1 AND period_start = $2)`,
		tenant, from.UTC()).Scan(&exists); err != nil {
		return Seal{}, fmt.Errorf("forensic: seal exists check: %w", err)
	}
	if exists {
		return Seal{}, ErrPeriodAlreadySealed
	}

	digests, err := readPeriodDigests(ctx, tx, tenant, from, to)
	if err != nil {
		return Seal{}, err
	}

	prevRoot, maxSeq, err := chainPosition(ctx, tx, tenant, from)
	if err != nil {
		return Seal{}, err
	}

	seal := Seal{
		TenantID:    tenant,
		Seq:         maxSeq + 1,
		PeriodStart: from.UTC(),
		PeriodEnd:   to.UTC(),
		EntryCount:  int64(len(digests)),
		MerkleRoot:  merkleRoot(digests),
		PrevRoot:    prevRoot,
	}
	if signer != nil {
		seal.Signature, seal.KeyID = signer.SignBytes(
			sealPayload(seal.TenantID, seal.PeriodStart, seal.PeriodEnd,
				seal.EntryCount, seal.MerkleRoot, seal.PrevRoot))
	}

	if err := tx.QueryRowContext(ctx, `
		INSERT INTO forensic_seals
			(tenant_id, seq, period_start, period_end, entry_count, merkle_root, prev_root, signature, key_id)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		RETURNING sealed_at`,
		seal.TenantID, seal.Seq, seal.PeriodStart, seal.PeriodEnd, seal.EntryCount,
		seal.MerkleRoot, seal.PrevRoot, seal.Signature, seal.KeyID,
	).Scan(&seal.SealedAt); err != nil {
		return Seal{}, fmt.Errorf("forensic: seal insert: %w", err)
	}

	if err := advanceChainHead(ctx, tx, seal, signer); err != nil {
		return Seal{}, err
	}

	if err := tx.Commit(); err != nil {
		return Seal{}, fmt.Errorf("forensic: seal commit: %w", err)
	}
	return seal, nil
}

// chainHead is the stored claim about how far a tenant's chain reaches.
type chainHead struct {
	TenantID      string
	LastSeq       int64
	LastRoot      string
	LastPeriodEnd time.Time
	Signature     string
	KeyID         string
}

// advanceChainHead moves a tenant's head to the seal just written.
//
// Takes the caller's transaction rather than opening its own, and that is the
// point: a head written in a separate transaction could be lost to a crash
// between the two, leaving a seal the head does not count — which verification
// would then report as a truncation by an operator who did nothing.
func advanceChainHead(ctx context.Context, tx *sql.Tx, seal Seal, signer Signer) error {
	head := chainHead{
		TenantID:      seal.TenantID,
		LastSeq:       seal.Seq,
		LastRoot:      seal.MerkleRoot,
		LastPeriodEnd: seal.PeriodEnd,
	}
	if signer != nil {
		head.Signature, head.KeyID = signer.SignBytes(
			headPayload(head.TenantID, head.LastSeq, head.LastRoot, head.LastPeriodEnd))
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO forensic_chain_head
			(tenant_id, last_seq, last_root, last_period_end, signature, key_id, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,NOW())
		ON CONFLICT (tenant_id) DO UPDATE SET
			last_seq        = EXCLUDED.last_seq,
			last_root       = EXCLUDED.last_root,
			last_period_end = EXCLUDED.last_period_end,
			signature       = EXCLUDED.signature,
			key_id          = EXCLUDED.key_id,
			updated_at      = NOW()
		-- Never let the head move backwards. A seal written for an earlier
		-- period after a later one exists would otherwise lower last_seq and
		-- erase the evidence that the later seals are gone.
		WHERE forensic_chain_head.last_seq < EXCLUDED.last_seq`,
		head.TenantID, head.LastSeq, head.LastRoot, head.LastPeriodEnd,
		head.Signature, head.KeyID,
	); err != nil {
		return fmt.Errorf("forensic: chain head update: %w", err)
	}
	return nil
}

// SealCheck is the result of recomputing one seal against the log as it stands.
type SealCheck struct {
	Seal        Seal   `json:"seal"`
	ActualCount int64  `json:"actual_count"`
	ActualRoot  string `json:"actual_root"`
	Intact      bool   `json:"intact"`
	// Detail says what differs, in the words an operator has to act on.
	Detail string `json:"detail,omitempty"`
}

// ChainCheck answers the question a per-seal check structurally cannot: is any
// seal MISSING.
//
// Recomputing a seal compares it against the log, so it can only speak about
// seals that are still there. Deleting the last three seals together with the
// entries they covered leaves nothing behind that refers to them, and every
// surviving seal still verifies. The head is the only record of how far the
// chain is supposed to reach.
type ChainCheck struct {
	Complete    bool   `json:"complete"`
	HeadPresent bool   `json:"head_present"`
	HeadSeq     int64  `json:"head_seq"`
	SealsFound  int64  `json:"seals_found"`
	HighestSeq  int64  `json:"highest_seq"`
	HeadKeyID   string `json:"head_key_id,omitempty"`
	Detail      string `json:"detail,omitempty"`
}

// SealReport is the whole answer for one tenant: every seal recomputed, plus
// whether the set of seals is complete.
//
// One call returns both, deliberately. A separate VerifyChain method would be a
// thing a caller can forget, and "the check everybody runs does not cover this
// case" is precisely the defect this type exists to close.
type SealReport struct {
	Checks []SealCheck `json:"checks"`
	Chain  ChainCheck  `json:"chain"`
	// Intact is true only when every seal recomputes AND no seal is missing.
	Intact bool `json:"intact"`
}

// VerifySeals recomputes every seal for a tenant and reports which no longer
// match the log, together with whether any seal has been removed outright.
//
// This is the question the mechanism exists to answer: has anything been
// removed from, added to, or altered in a period that was already sealed. It
// answers per period — the seal commits to a window, so a mismatch names the
// window, not the row. Recovering the row is not possible and is not claimed:
// a root is a commitment, not a backup.
//
// WHAT IT STILL DOES NOT CATCH: an operator holding the signing key can lower
// the head and re-sign it, and an operator who deletes the head along with
// every seal leaves a state indistinguishable from "seals were never enabled".
// Both need a witness outside this database — see the anchoring note in
// seal.go. What changed is the price: truncation used to cost one DELETE.
func (s *PGSink) VerifySeals(ctx context.Context, tenant string) (SealReport, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return SealReport{}, fmt.Errorf("forensic: verify begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT set_config('app.tenant_id', $1, true)`, tenant); err != nil {
		return SealReport{}, fmt.Errorf("forensic: verify set_config: %w", err)
	}

	seals, err := readSeals(ctx, tx, tenant)
	if err != nil {
		return SealReport{}, err
	}

	out := make([]SealCheck, 0, len(seals))
	var expectedPrev string
	for _, sl := range seals {
		chk := SealCheck{Seal: sl}

		digests, err := readPeriodDigests(ctx, tx, tenant, sl.PeriodStart, sl.PeriodEnd)
		if err != nil {
			return SealReport{}, err
		}

		chk.ActualCount = int64(len(digests))
		chk.ActualRoot = merkleRoot(digests)

		switch {
		case chk.ActualRoot == sl.MerkleRoot && sl.PrevRoot == expectedPrev:
			chk.Intact = true
		case chk.ActualRoot != sl.MerkleRoot && chk.ActualCount < sl.EntryCount:
			chk.Detail = fmt.Sprintf("%d entries are missing: sealed %d, found %d",
				sl.EntryCount-chk.ActualCount, sl.EntryCount, chk.ActualCount)
		case chk.ActualRoot != sl.MerkleRoot && chk.ActualCount > sl.EntryCount:
			chk.Detail = fmt.Sprintf("%d entries were added after sealing: sealed %d, found %d",
				chk.ActualCount-sl.EntryCount, sl.EntryCount, chk.ActualCount)
		case chk.ActualRoot != sl.MerkleRoot:
			chk.Detail = fmt.Sprintf("the entry count matches (%d) but the contents changed: "+
				"an entry was altered or replaced", sl.EntryCount)
		default:
			// Root matches but the chain does not: this seal's prev_root is not
			// the previous seal's root, so a seal was inserted, removed or
			// rewritten even though this period's entries are untouched.
			chk.Detail = fmt.Sprintf("the chain is broken: prev_root is %q, expected %q",
				short(sl.PrevRoot), short(expectedPrev))
		}
		out = append(out, chk)
		expectedPrev = sl.MerkleRoot
	}

	chain, err := checkChain(ctx, tx, tenant, seals)
	if err != nil {
		return SealReport{}, err
	}
	report := SealReport{Checks: out, Chain: chain, Intact: chain.Complete}
	for _, c := range out {
		if !c.Intact {
			report.Intact = false
		}
	}
	return report, nil
}

// readSeals loads a tenant's seals in chain order.
func readSeals(ctx context.Context, tx *sql.Tx, tenant string) ([]Seal, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT tenant_id, COALESCE(seq, 0), period_start, period_end, entry_count,
		       merkle_root, prev_root, signature, key_id, sealed_at
		FROM forensic_seals WHERE tenant_id = $1 ORDER BY period_start`, tenant)
	if err != nil {
		return nil, fmt.Errorf("forensic: verify read seals: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var seals []Seal
	for rows.Next() {
		var sl Seal
		if err := rows.Scan(&sl.TenantID, &sl.Seq, &sl.PeriodStart, &sl.PeriodEnd, &sl.EntryCount,
			&sl.MerkleRoot, &sl.PrevRoot, &sl.Signature, &sl.KeyID, &sl.SealedAt); err != nil {
			return nil, fmt.Errorf("forensic: verify scan seal: %w", err)
		}
		seals = append(seals, sl)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("forensic: verify seal rows: %w", err)
	}
	return seals, nil
}

// checkChain compares the stored head against the seals that are actually
// present, and names what is missing.
//
// Every branch below is a state an operator has to act on, so each says what it
// found rather than returning a bare false. The one branch that reports nothing
// wrong for an absent head is the tenant with no seals at all: there is no
// claim to contradict, and calling that tampering would cry wolf on every
// install that has not sealed its first period yet.
func checkChain(ctx context.Context, tx *sql.Tx, tenant string, seals []Seal) (ChainCheck, error) {
	chk := ChainCheck{SealsFound: int64(len(seals))}
	for _, sl := range seals {
		if sl.Seq > chk.HighestSeq {
			chk.HighestSeq = sl.Seq
		}
	}

	var head chainHead
	err := tx.QueryRowContext(ctx, `
		SELECT last_seq, last_root, last_period_end, signature, key_id
		FROM forensic_chain_head WHERE tenant_id = $1`, tenant).
		Scan(&head.LastSeq, &head.LastRoot, &head.LastPeriodEnd, &head.Signature, &head.KeyID)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if len(seals) == 0 {
			chk.Complete = true // nothing sealed yet, nothing claimed
			return chk, nil
		}
		chk.Detail = fmt.Sprintf("the chain head is missing while %d seals exist: "+
			"the record of how far the chain should reach was deleted", len(seals))
		return chk, nil
	case err != nil:
		return ChainCheck{}, fmt.Errorf("forensic: verify read chain head: %w", err)
	}

	chk.HeadPresent = true
	chk.HeadSeq = head.LastSeq
	chk.HeadKeyID = head.KeyID

	switch {
	case chk.HighestSeq < head.LastSeq:
		chk.Detail = fmt.Sprintf("%d seals are missing from the end of the chain: "+
			"the head records seal %d, the highest one present is %d",
			head.LastSeq-chk.HighestSeq, head.LastSeq, chk.HighestSeq)
	case chk.SealsFound != chk.HighestSeq:
		chk.Detail = fmt.Sprintf("the chain has gaps: seals are numbered up to %d "+
			"but only %d are present", chk.HighestSeq, chk.SealsFound)
	case chk.HighestSeq > head.LastSeq:
		chk.Detail = fmt.Sprintf("the head is behind the chain: it records seal %d "+
			"but seal %d exists, so the head was rolled back or a seal was inserted",
			head.LastSeq, chk.HighestSeq)
	case len(seals) > 0 && seals[len(seals)-1].MerkleRoot != head.LastRoot:
		chk.Detail = fmt.Sprintf("the head does not match the last seal: head root %q, "+
			"last seal root %q", short(head.LastRoot), short(seals[len(seals)-1].MerkleRoot))
	default:
		chk.Complete = true
	}
	return chk, nil
}

func short(s string) string {
	if len(s) <= 12 {
		return s
	}
	return s[:12] + "…"
}

// nextUnsealedPeriod returns the start of the first period that still needs a
// seal for this tenant, or the zero time when the tenant has no entries.
//
// It is the last sealed period's end, or — for a tenant sealed for the first
// time — the period containing its oldest entry. Starting from the oldest entry
// rather than from now matters: it means enabling seals on an existing
// deployment commits to the history that is already there, instead of leaving
// everything before today permanently unsealed and therefore freely editable.
func (s *PGSink) nextUnsealedPeriod(ctx context.Context, tenant string, period time.Duration) (time.Time, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return time.Time{}, fmt.Errorf("forensic: next period begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT set_config('app.tenant_id', $1, true)`, tenant); err != nil {
		return time.Time{}, fmt.Errorf("forensic: next period set_config: %w", err)
	}

	var last sql.NullTime
	if err := tx.QueryRowContext(ctx,
		`SELECT MAX(period_end) FROM forensic_seals WHERE tenant_id = $1`, tenant).Scan(&last); err != nil {
		return time.Time{}, fmt.Errorf("forensic: next period last seal: %w", err)
	}
	if last.Valid {
		return last.Time.UTC(), nil
	}

	var oldest sql.NullTime
	if err := tx.QueryRowContext(ctx,
		`SELECT MIN(ts) FROM forensic_logs WHERE tenant_id = $1`, tenant).Scan(&oldest); err != nil {
		return time.Time{}, fmt.Errorf("forensic: next period oldest entry: %w", err)
	}
	if !oldest.Valid {
		return time.Time{}, nil // no entries
	}
	return oldest.Time.UTC().Truncate(period), nil
}

// TenantsWithEntries lists every tenant that has forensic entries or seals.
//
// Driven from the data rather than from the configured tenant list: a tenant
// removed from the config still has a log somebody may audit, and its periods
// still have to be sealed contiguously or its chain acquires a permanent hole.
func (s *PGSink) TenantsWithEntries(ctx context.Context) ([]string, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, fmt.Errorf("forensic: tenants begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT set_config('app.tenant_id', '*', true)`); err != nil {
		return nil, fmt.Errorf("forensic: tenants set_config: %w", err)
	}
	rows, err := tx.QueryContext(ctx, `
		SELECT tenant_id FROM forensic_logs
		UNION
		SELECT tenant_id FROM forensic_seals
		ORDER BY 1`)
	if err != nil {
		return nil, fmt.Errorf("forensic: tenants query: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return nil, fmt.Errorf("forensic: tenants scan: %w", err)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// backfillSeqAndHeads brings an install sealed before the sequence existed up to
// the shape the chain check needs: every seal numbered, every tenant with a head.
//
// It runs once per process start, after the schema. Both statements read and
// write forensic_seals, which has FORCE ROW LEVEL SECURITY, so both need
// app.tenant_id — '*' here because the migration is deliberately cross-tenant
// and there is no request context to take a tenant from. Issuing them from the
// schema block instead would have matched zero rows and migrated nothing, which
// is the failure this function exists to avoid rather than a hypothetical.
//
// Idempotent: the UPDATE only touches unnumbered seals, and the INSERT only
// creates heads for tenants that have none.
func backfillSeqAndHeads(ctx context.Context, db *sql.DB) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT set_config('app.tenant_id', '*', true)`); err != nil {
		return fmt.Errorf("set_config: %w", err)
	}

	// Numbered by period order, which is the order the chain itself is in —
	// sealed_at would put a seal written late in the wrong place.
	if _, err := tx.ExecContext(ctx, `
		UPDATE forensic_seals s
		   SET seq = n.rn
		  FROM (SELECT id, ROW_NUMBER() OVER (PARTITION BY tenant_id ORDER BY period_start) AS rn
		          FROM forensic_seals WHERE seq IS NULL) n
		 WHERE s.id = n.id AND s.seq IS NULL`); err != nil {
		return fmt.Errorf("number existing seals: %w", err)
	}

	// A head for every tenant that has seals but no head. Unsigned: there is no
	// signer here, and inventing one would be worse than an honest gap. It
	// attests to the state at upgrade time, not to the history before it.
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO forensic_chain_head (tenant_id, last_seq, last_root, last_period_end)
		SELECT DISTINCT ON (tenant_id) tenant_id, seq, merkle_root, period_end
		  FROM forensic_seals
		 ORDER BY tenant_id, seq DESC
		    ON CONFLICT (tenant_id) DO NOTHING`); err != nil {
		return fmt.Errorf("backfill chain heads: %w", err)
	}
	return tx.Commit()
}

// readPeriodDigests hashes every entry in [from, to) for one tenant, in id
// order.
//
// Shared by sealing and verification on purpose: the root a seal commits to and
// the root a check recomputes have to come from the same bytes in the same
// order, and two copies of this loop are two chances for them to drift. id
// order rather than ts order because two entries can share a timestamp, and the
// root commits to an order the database must reproduce exactly.
func readPeriodDigests(ctx context.Context, tx *sql.Tx, tenant string, from, to time.Time) ([][]byte, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT id, ts, tenant_id, ip, path, method, reason, code
		FROM forensic_logs
		WHERE tenant_id = $1 AND ts >= $2 AND ts < $3
		ORDER BY id`, tenant, from.UTC(), to.UTC())
	if err != nil {
		return nil, fmt.Errorf("forensic: read period: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var digests [][]byte
	for rows.Next() {
		var (
			id                            int64
			ts                            time.Time
			tid, ip, path, method, reason string
			code                          int
		)
		if err := rows.Scan(&id, &ts, &tid, &ip, &path, &method, &reason, &code); err != nil {
			return nil, fmt.Errorf("forensic: scan entry: %w", err)
		}
		digests = append(digests, entryDigest(id, ts, tid, ip, path, method, reason, code))
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("forensic: entry rows: %w", err)
	}
	return digests, nil
}

// chainPosition returns what a new seal for a period starting at `from` must
// link to: the preceding seal's root, and the highest seq the tenant has.
//
// prevRoot is ordered by period_start and not by sealed_at, because a seal
// written late still belongs where its period puts it. maxSeq comes from MAX
// rather than COUNT: after a deletion a count would re-issue a number that was
// already used, which hands the truncation back the invisibility this whole
// mechanism is meant to remove.
func chainPosition(ctx context.Context, tx *sql.Tx, tenant string, from time.Time) (prevRoot string, maxSeq int64, err error) {
	err = tx.QueryRowContext(ctx, `
		SELECT merkle_root FROM forensic_seals
		WHERE tenant_id = $1 AND period_start < $2
		ORDER BY period_start DESC LIMIT 1`, tenant, from.UTC()).Scan(&prevRoot)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", 0, fmt.Errorf("forensic: seal prev: %w", err)
	}
	if err := tx.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(seq), 0) FROM forensic_seals WHERE tenant_id = $1`,
		tenant).Scan(&maxSeq); err != nil {
		return "", 0, fmt.Errorf("forensic: seal seq: %w", err)
	}
	return prevRoot, maxSeq, nil
}
