package incident

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"time"
)

// The ledger head: a commitment to how far the ledger reaches.
//
// Without it, the ledger detects an incident deleted from the register and an
// entry deleted from the middle of the chain — and misses the case an operator
// who understands the mechanism would actually use: delete the incident AND
// every ledger row that mentions it. Nothing that survives refers to what is
// gone, so everything recomputes perfectly, and the state is indistinguishable
// from "that incident never happened".
//
// A back-reference chain can say "the entry before this one changed". It cannot
// say "there should be four more after this one". That has to be a separate
// commitment to the COUNT, and it is the same shape the forensic chain uses
// (internal/forensic: forensic_chain_head), for the same reason.
//
// Two properties are load-bearing and neither is decorative:
//
//   - The head is written in the SAME transaction as the ledger entry. A head
//     written separately could be lost to a crash between the two, leaving an
//     entry the head does not count — which verification would then report as
//     tampering by an operator who did nothing.
//   - The head never moves backwards. Lowering last_seq is exactly what
//     truncation looks like, so the UPDATE carries a guard, and the guard only
//     runs under a role that cannot bypass RLS. Under a superuser the policy is
//     skipped and this protection is never exercised — which is why the tests
//     for it demand POSTGRES_APP_DSN (handoff §0h).
//
// WHAT IT STILL DOES NOT DO. An operator holding the signing key can lower the
// head and re-sign it. An operator who deletes the head along with every ledger
// row leaves a state indistinguishable from "the ledger was never enabled".
// Neither is closable inside one database; both need an external anchor, and
// there is none. What this buys is that tampering costs a key and a rewrite of
// the whole chain instead of two DELETE statements.

const ledgerHeadSchema = `
CREATE TABLE IF NOT EXISTS incident_ledger_head (
	tenant_id  TEXT        NOT NULL,
	last_seq   BIGINT      NOT NULL,
	last_chain TEXT        NOT NULL,
	entries    BIGINT      NOT NULL DEFAULT 0,
	signature  TEXT        NOT NULL DEFAULT '',
	key_id     TEXT        NOT NULL DEFAULT '',
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	PRIMARY KEY (tenant_id)
);

ALTER TABLE incident_ledger_head ENABLE ROW LEVEL SECURITY;
ALTER TABLE incident_ledger_head FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON incident_ledger_head;
CREATE POLICY tenant_isolation ON incident_ledger_head
	USING (tenant_id = current_setting('app.tenant_id', true)
	    OR current_setting('app.tenant_id', true) = '*')
	WITH CHECK (tenant_id = current_setting('app.tenant_id', true)
	    OR current_setting('app.tenant_id', true) = '*');
`

// Signer signs a head payload. Same shape as forensic.Signer, and deliberately
// a separate declaration: this package must not import the forensic one to sign
// its own commitments.
type Signer interface {
	SignBytes(payload []byte) (signature string, keyID string)
}

// headPayload is the exact byte string a head's signature covers.
//
// Length-prefixed, like every other signed payload here: the fields are
// operator-influenced text, and a delimiter-joined payload let a subject
// containing the delimiter authenticate a different identity once already.
func headPayload(tenant string, lastSeq, entries int64, lastChain string) []byte {
	var out []byte
	write := func(s string) {
		out = append(out, []byte(strconv.Itoa(len(s)))...)
		out = append(out, ':')
		out = append(out, []byte(s)...)
	}
	write("aegis-incident-head-v1")
	write(tenant)
	write(strconv.FormatInt(lastSeq, 10))
	write(strconv.FormatInt(entries, 10))
	write(lastChain)
	return out
}

type ledgerHead struct {
	LastSeq   int64
	LastChain string
	Entries   int64
	Signature string
	KeyID     string
	UpdatedAt time.Time
}

// advanceHead moves a tenant's head to the ledger entry just written.
func advanceHead(ctx context.Context, tx *sql.Tx, tenantID string, seq int64, chain string, signer Signer) error {
	// The count is read inside the same transaction as the insert, so it counts
	// the entry that was just written and nothing that arrives after.
	var entries int64
	if err := tx.QueryRowContext(ctx,
		`SELECT count(*) FROM incident_ledger WHERE tenant_id = $1`, tenantOr(tenantID)).
		Scan(&entries); err != nil {
		return err
	}

	var signature, keyID string
	if signer != nil {
		signature, keyID = signer.SignBytes(headPayload(tenantOr(tenantID), seq, entries, chain))
	}

	_, err := tx.ExecContext(ctx, `
INSERT INTO incident_ledger_head (tenant_id, last_seq, last_chain, entries, signature, key_id, updated_at)
VALUES ($1,$2,$3,$4,$5,$6,NOW())
ON CONFLICT (tenant_id) DO UPDATE SET
	last_seq   = EXCLUDED.last_seq,
	last_chain = EXCLUDED.last_chain,
	entries    = EXCLUDED.entries,
	signature  = EXCLUDED.signature,
	key_id     = EXCLUDED.key_id,
	updated_at = NOW()
-- Never backwards. Lowering last_seq is the shape of a truncation, so an entry
-- written out of order can only ever be refused here, not allowed to erase the
-- evidence that later entries existed.
WHERE incident_ledger_head.last_seq < EXCLUDED.last_seq`,
		tenantOr(tenantID), seq, chain, entries, signature, keyID)
	return err
}

// HeadCheck is the chain-level half of a ledger verification.
type HeadCheck struct {
	// Present reports whether a head exists at all. Absent with entries in the
	// ledger means the record of how far the chain reaches was deleted.
	Present bool `json:"present"`
	// Complete is true when the head and the ledger agree.
	Complete bool `json:"complete"`
	// HeadSeq and HeadEntries are what the head claims.
	HeadSeq     int64 `json:"head_seq"`
	HeadEntries int64 `json:"head_entries"`
	// FoundSeq and FoundEntries are what the ledger actually holds.
	FoundSeq     int64 `json:"found_seq"`
	FoundEntries int64 `json:"found_entries"`
	// KeyID names the key the head was signed with, so a verifier can pin it
	// out of band. Empty when no signer is configured.
	KeyID string `json:"key_id,omitempty"`
	// Signature is the head's signature over its own claim, carried so an
	// auditor can check it away from this system.
	Signature string `json:"signature,omitempty"`
	// Detail says what is wrong, in a sentence an operator can act on.
	Detail string `json:"detail,omitempty"`
}

// checkHead compares the head's claim against the ledger as it stands.
func checkHead(ctx context.Context, tx *sql.Tx, tenantID string, foundSeq, foundEntries int64) (HeadCheck, error) {
	chk := HeadCheck{FoundSeq: foundSeq, FoundEntries: foundEntries}

	var head ledgerHead
	err := tx.QueryRowContext(ctx, `
SELECT last_seq, last_chain, entries, signature, key_id, updated_at
FROM incident_ledger_head WHERE tenant_id = $1`, tenantOr(tenantID)).
		Scan(&head.LastSeq, &head.LastChain, &head.Entries, &head.Signature, &head.KeyID, &head.UpdatedAt)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if foundEntries == 0 {
			// Nothing recorded yet and nothing claimed. Consistent.
			chk.Complete = true
			return chk, nil
		}
		chk.Detail = fmt.Sprintf("the ledger head is missing while %d entries exist: "+
			"the record of how far the ledger should reach was deleted", foundEntries)
		return chk, nil
	case err != nil:
		return HeadCheck{}, err
	}

	chk.Present = true
	chk.HeadSeq = head.LastSeq
	chk.HeadEntries = head.Entries
	chk.KeyID = head.KeyID
	chk.Signature = head.Signature

	switch {
	case foundEntries < head.Entries:
		chk.Detail = fmt.Sprintf("%d ledger entries are missing: the head records %d, "+
			"%d are present", head.Entries-foundEntries, head.Entries, foundEntries)
	case foundSeq < head.LastSeq:
		chk.Detail = fmt.Sprintf("the ledger is short of its head: the head records entry %d, "+
			"the highest present is %d", head.LastSeq, foundSeq)
	case foundEntries > head.Entries || foundSeq > head.LastSeq:
		chk.Detail = fmt.Sprintf("the head is behind the ledger: it records entry %d and %d entries, "+
			"but entry %d and %d entries exist — the head was rolled back or rows were inserted",
			head.LastSeq, head.Entries, foundSeq, foundEntries)
	default:
		chk.Complete = true
	}
	return chk, nil
}
