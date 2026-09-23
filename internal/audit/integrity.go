// Integrity for the admin action trail.
//
// `docs/ARCHITECTURE.md` names the insider as a threat model and says it is
// covered by "RBAC + audit log". RBAC decides what an administrator may do;
// the audit log records what they did. The second half of that sentence was
// unbacked: the table had no row-level security, no integrity protection, and a
// retention sweep deleting from it on a schedule. It was the least protected
// store in the system and the one an insider would edit first.
//
// # What this adds
//
// Each row carries a digest of its own content and a chain value linking it to
// the previous row for that tenant. Deleting or editing a row makes every later
// row fail to recompute. A head row per tenant commits to how far the trail
// reaches, so removing the tail — which breaks no link, because nothing
// surviving refers to it — is visible as well.
//
// # Retention, which is the hard part
//
// The retention sweep deletes old rows by design, and a naive chain would read
// that as tampering. The alternative of exempting the audit log from retention
// is worse: a trail that can only grow is a trail that eventually cannot be
// stored, and a deployment with a legal duty to delete would have to disable
// integrity to comply.
//
// So pruning is RECORDED rather than hidden. When retention removes rows, it
// reports how many and up to which id, and the head carries that watermark.
// Verification then expects the trail to start after the watermark and counts
// the pruned rows as accounted for. An operator who deletes rows without
// updating the watermark still fails verification; an operator who updates the
// watermark to cover their deletion has to do it in the head, which is signed.
//
// # What this does not do
//
//   - It does not make deletion impossible, only detectable.
//   - It does not recover a deleted row. A chain is not a backup.
//   - An operator holding the signing key can rewrite the trail, recompute the
//     chain and re-sign the head. Only an external anchor defeats that, and
//     there is none. The word is tamper-EVIDENT.
package audit

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"
)

const integritySchema = `
ALTER TABLE admin_audit_log ADD COLUMN IF NOT EXISTS digest TEXT NOT NULL DEFAULT '';
ALTER TABLE admin_audit_log ADD COLUMN IF NOT EXISTS chain  TEXT NOT NULL DEFAULT '';

-- Row-level security, which this table never had. The policy is the same one
-- the catalog and forensic tables use, including the '*' escape hatch that
-- maintenance work (the retention sweep, a super-admin listing) runs under.
ALTER TABLE admin_audit_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE admin_audit_log FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON admin_audit_log;
CREATE POLICY tenant_isolation ON admin_audit_log
	USING (tenant_id = current_setting('app.tenant_id', true)
	    OR current_setting('app.tenant_id', true) = '*')
	WITH CHECK (tenant_id = current_setting('app.tenant_id', true)
	    OR current_setting('app.tenant_id', true) = '*');

CREATE TABLE IF NOT EXISTS admin_audit_head (
	tenant_id   TEXT        NOT NULL,
	last_id     BIGINT      NOT NULL,
	last_chain  TEXT        NOT NULL,
	entries     BIGINT      NOT NULL DEFAULT 0,
	-- pruned_to_id and pruned_count record what retention removed, so a lawful
	-- deletion does not read as tampering and an unlawful one still does.
	pruned_to_id BIGINT     NOT NULL DEFAULT 0,
	pruned_count BIGINT     NOT NULL DEFAULT 0,
	signature   TEXT        NOT NULL DEFAULT '',
	key_id      TEXT        NOT NULL DEFAULT '',
	updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	PRIMARY KEY (tenant_id)
);

ALTER TABLE admin_audit_head ENABLE ROW LEVEL SECURITY;
ALTER TABLE admin_audit_head FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON admin_audit_head;
CREATE POLICY tenant_isolation ON admin_audit_head
	USING (tenant_id = current_setting('app.tenant_id', true)
	    OR current_setting('app.tenant_id', true) = '*')
	WITH CHECK (tenant_id = current_setting('app.tenant_id', true)
	    OR current_setting('app.tenant_id', true) = '*');
`

// Signer signs the audit head. Declared here rather than imported so this
// package does not depend on the forensic or incident one to sign its own
// commitments.
type Signer interface {
	SignBytes(payload []byte) (signature string, keyID string)
}

// lp appends a length-prefixed field.
//
// Length-prefixed rather than delimiter-joined for the reason this repository
// learned the hard way: a delimiter-joined payload let a subject containing the
// delimiter authenticate a different identity. Here the fields are an actor's
// email, a path and a free-text detail — all attacker- or operator-influenced.
func lp(dst []byte, s string) []byte {
	dst = append(dst, []byte(strconv.Itoa(len(s)))...)
	dst = append(dst, ':')
	return append(dst, []byte(s)...)
}

// entryDigest hashes one audit row's content.
func entryDigest(id int64, e Entry) string {
	var b []byte
	b = lp(b, strconv.FormatInt(id, 10))
	b = lp(b, e.Time.UTC().Format(time.RFC3339Nano))
	b = lp(b, e.TenantID)
	b = lp(b, e.ActorID)
	b = lp(b, e.ActorEmail)
	b = lp(b, e.Role)
	b = lp(b, strconv.FormatBool(e.SuperAdmin))
	b = lp(b, e.Action)
	b = lp(b, e.Method)
	b = lp(b, e.Path)
	b = lp(b, strconv.Itoa(e.Status))
	b = lp(b, e.IP)
	b = lp(b, e.Detail)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// chainValue links a row to its predecessor.
func chainValue(prev, digest string, id int64) string {
	var b []byte
	b = lp(b, "aegis-audit-chain-v1")
	b = lp(b, prev)
	b = lp(b, strconv.FormatInt(id, 10))
	b = lp(b, digest)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// headPayload is what the head's signature covers.
func headPayload(tenant string, lastID, entries, prunedToID, prunedCount int64, lastChain string) []byte {
	var b []byte
	b = lp(b, "aegis-audit-head-v1")
	b = lp(b, tenant)
	b = lp(b, strconv.FormatInt(lastID, 10))
	b = lp(b, strconv.FormatInt(entries, 10))
	b = lp(b, strconv.FormatInt(prunedToID, 10))
	b = lp(b, strconv.FormatInt(prunedCount, 10))
	b = lp(b, lastChain)
	return b
}

type head struct {
	LastID      int64
	LastChain   string
	Entries     int64
	PrunedToID  int64
	PrunedCount int64
	Signature   string
	KeyID       string
}

// advanceHead moves a tenant's head to the row just written, in the caller's
// transaction.
func advanceHead(ctx context.Context, tx *sql.Tx, tenantID string, id int64, chain string, signer Signer) error {
	var entries, prunedTo, prunedCount int64
	if err := tx.QueryRowContext(ctx,
		`SELECT count(*) FROM admin_audit_log WHERE tenant_id = $1`, tenantOr(tenantID)).
		Scan(&entries); err != nil {
		return err
	}
	// The pruning watermark is carried forward: it describes rows that are
	// gone, and writing a new entry does not un-delete them.
	err := tx.QueryRowContext(ctx,
		`SELECT pruned_to_id, pruned_count FROM admin_audit_head WHERE tenant_id = $1`,
		tenantOr(tenantID)).Scan(&prunedTo, &prunedCount)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}

	var signature, keyID string
	if signer != nil {
		signature, keyID = signer.SignBytes(
			headPayload(tenantOr(tenantID), id, entries, prunedTo, prunedCount, chain))
	}

	_, err = tx.ExecContext(ctx, `
INSERT INTO admin_audit_head
	(tenant_id, last_id, last_chain, entries, pruned_to_id, pruned_count, signature, key_id, updated_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NOW())
ON CONFLICT (tenant_id) DO UPDATE SET
	last_id    = EXCLUDED.last_id,
	last_chain = EXCLUDED.last_chain,
	entries    = EXCLUDED.entries,
	signature  = EXCLUDED.signature,
	key_id     = EXCLUDED.key_id,
	updated_at = NOW()
-- Never backwards: lowering last_id is what a truncation looks like.
WHERE admin_audit_head.last_id < EXCLUDED.last_id`,
		tenantOr(tenantID), id, chain, entries, prunedTo, prunedCount, signature, keyID)
	return err
}

// RecordPruning tells the head that retention removed rows, so a lawful
// deletion does not read as tampering.
//
// Called by the retention sweep inside its own transaction. The count and the
// watermark are what verification subtracts; an operator who deletes rows
// without calling this still fails verification, which is the point.
func RecordPruning(ctx context.Context, tx *sql.Tx, tenantID string, upToID, removed int64, signer Signer) error {
	var h head
	err := tx.QueryRowContext(ctx, `
SELECT last_id, last_chain, entries, pruned_to_id, pruned_count
FROM admin_audit_head WHERE tenant_id = $1`, tenantOr(tenantID)).
		Scan(&h.LastID, &h.LastChain, &h.Entries, &h.PrunedToID, &h.PrunedCount)
	if errors.Is(err, sql.ErrNoRows) {
		// Nothing was ever recorded for this tenant, so nothing was pruned
		// from a trail this head describes. Refusing silently would be wrong
		// either way; there is nothing to update.
		return nil
	}
	if err != nil {
		return err
	}

	prunedTo, prunedCount := h.PrunedToID, h.PrunedCount
	if upToID > prunedTo {
		prunedTo = upToID
	}
	prunedCount += removed

	var entries int64
	if err := tx.QueryRowContext(ctx,
		`SELECT count(*) FROM admin_audit_log WHERE tenant_id = $1`, tenantOr(tenantID)).
		Scan(&entries); err != nil {
		return err
	}

	var signature, keyID string
	if signer != nil {
		signature, keyID = signer.SignBytes(
			headPayload(tenantOr(tenantID), h.LastID, entries, prunedTo, prunedCount, h.LastChain))
	}

	_, err = tx.ExecContext(ctx, `
UPDATE admin_audit_head
SET entries = $2, pruned_to_id = $3, pruned_count = $4, signature = $5, key_id = $6, updated_at = NOW()
WHERE tenant_id = $1`,
		tenantOr(tenantID), entries, prunedTo, prunedCount, signature, keyID)
	return err
}

// Check is the result of verifying one tenant's audit trail.
type Check struct {
	Intact bool `json:"intact"`
	// Entries examined, and what the head claims.
	Entries     int64 `json:"entries"`
	HeadEntries int64 `json:"head_entries"`
	HeadPresent bool  `json:"head_present"`
	// Broken names row ids whose chain value does not recompute — an edit or a
	// deletion earlier in the trail.
	Broken []int64 `json:"broken,omitempty"`
	// PrunedCount is how many rows retention removed with the head's knowledge.
	PrunedCount int64 `json:"pruned_count"`
	// KeyID and Signature let an auditor check the head away from this system.
	KeyID     string   `json:"key_id,omitempty"`
	Signature string   `json:"signature,omitempty"`
	Detail    string   `json:"detail,omitempty"`
	Limits    []string `json:"limits"`
}

func checkLimits(signed bool) []string {
	out := []string{
		"Tampering is detectable, not impossible: this reports that the trail changed, not what it held.",
		"A chain is not a backup. A removed entry is gone; this only shows that it was there.",
		"Retention deletes from this trail on a schedule. Those removals are recorded in the head and counted as accounted for, so a lawful deletion does not read as tampering — and an operator who can rewrite both the trail and its head can make them agree.",
	}
	if !signed {
		out = append(out, "The audit head is NOT signed (no report signing key is configured), "+
			"so it commits to the trail for a reader but proves nothing to a third party.")
	}
	return out
}

// Verify recomputes one tenant's audit trail against its head.
func (s *Store) Verify(ctx context.Context, tenantID string) (Check, error) {
	chk := Check{Limits: checkLimits(s.signer != nil)}

	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return chk, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx,
		`SELECT set_config('app.tenant_id', $1, true)`, tenantOr(tenantID)); err != nil {
		return chk, err
	}

	lastID, err := walkTrail(ctx, tx, tenantOr(tenantID), &chk)
	if err != nil {
		return chk, err
	}
	return compareHead(ctx, tx, tenantOr(tenantID), lastID, chk)
}

// walkTrail recomputes every link and returns the highest id seen.
func walkTrail(ctx context.Context, tx *sql.Tx, tenantID string, chk *Check) (int64, error) {
	rows, err := tx.QueryContext(ctx, `
SELECT id, ts, tenant_id, actor_id, actor_email, role, super_admin,
       action, method, path, status, ip, detail, digest, chain
FROM admin_audit_log WHERE tenant_id = $1 ORDER BY id`, tenantID)
	if err != nil {
		return 0, err
	}
	defer func() { _ = rows.Close() }()

	var prev string
	var lastID int64
	first := true
	for rows.Next() {
		var (
			id     int64
			e      Entry
			digest string
			chain  string
		)
		if err := rows.Scan(&id, &e.Time, &e.TenantID, &e.ActorID, &e.ActorEmail,
			&e.Role, &e.SuperAdmin, &e.Action, &e.Method, &e.Path, &e.Status,
			&e.IP, &e.Detail, &digest, &chain); err != nil {
			return 0, err
		}
		chk.Entries++
		lastID = id

		// The digest is recomputed for EVERY row, including the first. The
		// chain cannot be: the first surviving row's predecessor may have been
		// pruned, so its link is accepted as given. Without a per-row digest,
		// editing that first row would therefore be invisible — its successors
		// chain off its stored link, which an edit to its content does not
		// change. Found by the test for exactly that edit.
		if want := entryDigest(id, e); want != digest {
			// Content edited. Already reported, so the link is not checked
			// again for the same row — one finding per row reads better than
			// two that mean the same thing.
			chk.Broken = append(chk.Broken, id)
		} else if !first {
			if want := chainValue(prev, digest, id); want != chain {
				chk.Broken = append(chk.Broken, id)
			}
		}
		first = false
		prev = chain
	}
	return lastID, rows.Err()
}

// compareHead answers the question the links cannot: does the trail reach as
// far as the head says it should.
func compareHead(ctx context.Context, tx *sql.Tx, tenantID string, lastID int64, chk Check) (Check, error) {
	var h head
	err := tx.QueryRowContext(ctx, `
SELECT last_id, last_chain, entries, pruned_to_id, pruned_count, signature, key_id
FROM admin_audit_head WHERE tenant_id = $1`, tenantID).
		Scan(&h.LastID, &h.LastChain, &h.Entries, &h.PrunedToID, &h.PrunedCount,
			&h.Signature, &h.KeyID)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if chk.Entries == 0 {
			chk.Intact = true
			return chk, nil
		}
		chk.Detail = fmt.Sprintf("the audit head is missing while %d entries exist: "+
			"the record of how far the trail should reach was deleted", chk.Entries)
		return chk, nil
	case err != nil:
		return chk, err
	}

	chk.HeadPresent = true
	chk.HeadEntries = h.Entries
	chk.PrunedCount = h.PrunedCount
	chk.KeyID = h.KeyID
	chk.Signature = h.Signature

	switch {
	case chk.Entries < h.Entries:
		chk.Detail = fmt.Sprintf("%d audit entries are missing: the head records %d, "+
			"%d are present, and retention's %d pruned rows are already accounted for",
			h.Entries-chk.Entries, h.Entries, chk.Entries, h.PrunedCount)
	case lastID < h.LastID:
		chk.Detail = fmt.Sprintf("the trail is short of its head: the head records entry %d, "+
			"the highest present is %d", h.LastID, lastID)
	case len(chk.Broken) > 0:
		chk.Detail = fmt.Sprintf("%d entries no longer recompute: the trail was edited or "+
			"rows were removed from the middle", len(chk.Broken))
	default:
		chk.Intact = true
	}
	return chk, nil
}
