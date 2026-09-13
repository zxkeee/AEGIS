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
	TenantID    string    `json:"tenant_id"`
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

	// id order, not ts order: two entries can share a timestamp, and the root
	// commits to an order, so it has to be one the database can reproduce
	// exactly on recomputation.
	rows, err := tx.QueryContext(ctx, `
		SELECT id, ts, tenant_id, ip, path, method, reason, code
		FROM forensic_logs
		WHERE tenant_id = $1 AND ts >= $2 AND ts < $3
		ORDER BY id`, tenant, from.UTC(), to.UTC())
	if err != nil {
		return Seal{}, fmt.Errorf("forensic: seal read: %w", err)
	}
	var digests [][]byte
	for rows.Next() {
		var (
			id                            int64
			ts                            time.Time
			tid, ip, path, method, reason string
			code                          int
		)
		if err := rows.Scan(&id, &ts, &tid, &ip, &path, &method, &reason, &code); err != nil {
			_ = rows.Close()
			return Seal{}, fmt.Errorf("forensic: seal scan: %w", err)
		}
		digests = append(digests, entryDigest(id, ts, tid, ip, path, method, reason, code))
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return Seal{}, fmt.Errorf("forensic: seal rows: %w", err)
	}
	_ = rows.Close()

	// The previous seal's root, or the empty string for the first one. A gap
	// here would break the chain silently, so the ordering is by period_start
	// and not by sealed_at: a seal written late still belongs where its period
	// puts it.
	var prevRoot string
	err = tx.QueryRowContext(ctx, `
		SELECT merkle_root FROM forensic_seals
		WHERE tenant_id = $1 AND period_start < $2
		ORDER BY period_start DESC LIMIT 1`, tenant, from.UTC()).Scan(&prevRoot)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return Seal{}, fmt.Errorf("forensic: seal prev: %w", err)
	}

	seal := Seal{
		TenantID:    tenant,
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
			(tenant_id, period_start, period_end, entry_count, merkle_root, prev_root, signature, key_id)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		RETURNING sealed_at`,
		seal.TenantID, seal.PeriodStart, seal.PeriodEnd, seal.EntryCount,
		seal.MerkleRoot, seal.PrevRoot, seal.Signature, seal.KeyID,
	).Scan(&seal.SealedAt); err != nil {
		return Seal{}, fmt.Errorf("forensic: seal insert: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Seal{}, fmt.Errorf("forensic: seal commit: %w", err)
	}
	return seal, nil
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

// VerifySeals recomputes every seal for a tenant and reports which no longer
// match the log.
//
// This is the question the mechanism exists to answer: has anything been
// removed from, added to, or altered in a period that was already sealed. It
// answers per period — the seal commits to a window, so a mismatch names the
// window, not the row. Recovering the row is not possible and is not claimed:
// a root is a commitment, not a backup.
func (s *PGSink) VerifySeals(ctx context.Context, tenant string) ([]SealCheck, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return nil, fmt.Errorf("forensic: verify begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT set_config('app.tenant_id', $1, true)`, tenant); err != nil {
		return nil, fmt.Errorf("forensic: verify set_config: %w", err)
	}

	sealRows, err := tx.QueryContext(ctx, `
		SELECT tenant_id, period_start, period_end, entry_count, merkle_root, prev_root,
		       signature, key_id, sealed_at
		FROM forensic_seals WHERE tenant_id = $1 ORDER BY period_start`, tenant)
	if err != nil {
		return nil, fmt.Errorf("forensic: verify read seals: %w", err)
	}
	var seals []Seal
	for sealRows.Next() {
		var sl Seal
		if err := sealRows.Scan(&sl.TenantID, &sl.PeriodStart, &sl.PeriodEnd, &sl.EntryCount,
			&sl.MerkleRoot, &sl.PrevRoot, &sl.Signature, &sl.KeyID, &sl.SealedAt); err != nil {
			_ = sealRows.Close()
			return nil, fmt.Errorf("forensic: verify scan seal: %w", err)
		}
		seals = append(seals, sl)
	}
	if err := sealRows.Err(); err != nil {
		_ = sealRows.Close()
		return nil, fmt.Errorf("forensic: verify seal rows: %w", err)
	}
	_ = sealRows.Close()

	out := make([]SealCheck, 0, len(seals))
	var expectedPrev string
	for _, sl := range seals {
		chk := SealCheck{Seal: sl}

		rows, err := tx.QueryContext(ctx, `
			SELECT id, ts, tenant_id, ip, path, method, reason, code
			FROM forensic_logs
			WHERE tenant_id = $1 AND ts >= $2 AND ts < $3
			ORDER BY id`, tenant, sl.PeriodStart, sl.PeriodEnd)
		if err != nil {
			return nil, fmt.Errorf("forensic: verify read entries: %w", err)
		}
		var digests [][]byte
		for rows.Next() {
			var (
				id                            int64
				ts                            time.Time
				tid, ip, path, method, reason string
				code                          int
			)
			if err := rows.Scan(&id, &ts, &tid, &ip, &path, &method, &reason, &code); err != nil {
				_ = rows.Close()
				return nil, fmt.Errorf("forensic: verify scan entry: %w", err)
			}
			digests = append(digests, entryDigest(id, ts, tid, ip, path, method, reason, code))
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("forensic: verify entry rows: %w", err)
		}
		_ = rows.Close()

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
	return out, nil
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
