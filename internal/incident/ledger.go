// Integrity for the incident register.
//
// The signed compliance document is computed from `incidents`: which incidents
// existed, how they were classified, when they were notified. The signature
// covers the document, so it proves the document was not altered after it was
// produced — and proves nothing about whether a row was removed from the
// register first. An auditor's question is the same one the forensic seals
// answer for the log, and here the answer mattered more: `incidents` decides
// directly what the report claims about DORA Art. 17-19 and NIS2 Art. 23, and
// removing a row cost one DELETE.
//
// WHY NOT THE SEAL MECHANISM AS IT STANDS. A seal commits to a Merkle root over
// the rows of a period. That works for `forensic_logs` because a forensic row
// is written once and never touched again. An incident is the opposite: its
// whole point is a lifecycle — open becomes contained becomes closed, notes are
// written, notifications are appended. A root over a period of incidents would
// fail on the first legitimate status change, and a check that fires on normal
// operation gets switched off within a week.
//
// WHAT IS DONE INSTEAD. Every write to `incidents` appends one row to
// `incident_ledger`, in the SAME transaction, recording the digest of the
// incident's full state after that write. The ledger is append-only and each
// row is chained to the one before it. Verification then asks three questions
// no signature can:
//
//   - Does every incident the ledger knows about still exist? (deletion)
//   - Does every existing incident hash to what the ledger last recorded?
//     (edit — the case a signature is completely blind to, because the document
//     still signs cleanly, it just says something different)
//   - Does every existing incident have a ledger entry at all, and does the
//     chain of entries recompute? (removal of the evidence of removal)
//
// WHAT THIS DOES NOT DO, stated here rather than discovered later:
//
//   - It does not make tampering impossible, only detectable. Same word as the
//     seals: tamper-EVIDENT.
//   - The ledger is not a backup. It records that an incident had a different
//     state, not what that state was.
//   - The ledger head (ledger_head.go) commits to how far the ledger reaches,
//     so deleting an incident together with every ledger row that mentions it
//     is now visible. What remains is what remains for the forensic chain too:
//     an operator holding the signing key can lower the head and re-sign it,
//     and an operator who deletes the head along with everything else leaves a
//     state indistinguishable from "the ledger was never enabled".
//   - An operator with the database can still rewrite ledger rows wholesale and
//     recompute the chain, exactly as with the seals. Only an external anchor
//     defeats that, and there is none.
package incident

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"time"
)

// Ledger operations. Recorded for the reader of an audit, not used in any
// decision: the digest is what verification compares.
const (
	opOpen   = "open"
	opMerge  = "merge"
	opApply  = "apply"
	opNotify = "notify"
)

// incidentDigest hashes the state of one incident.
//
// Length-prefixed for the same reason the forensic entry digest and the
// identity payload are: these fields carry attacker-influenced text (subject
// comes from a JWT, endpoints from request paths), and joining them with a
// delimiter lets two different incidents produce one digest. A subject
// containing the delimiter would otherwise let one row impersonate another.
//
// Every field that a signed document can depend on is covered. Anything added
// to the report later must be added here too, or the report will be able to
// state something the ledger does not commit to.
func incidentDigest(inc Incident) string {
	h := sha256.New()
	write := func(s string) {
		_, _ = h.Write([]byte(strconv.Itoa(len(s))))
		_, _ = h.Write([]byte(":"))
		_, _ = h.Write([]byte(s))
	}
	writeTime := func(t time.Time) {
		// UTC and RFC3339Nano so a digest recomputed by a process in another
		// timezone, or after a driver round-trip, produces the same bytes.
		write(t.UTC().Format(time.RFC3339Nano))
	}
	writeList := func(v []string) {
		write(strconv.Itoa(len(v)))
		for _, s := range v {
			write(s)
		}
	}

	write(inc.ID)
	write(inc.Title)
	write(inc.Class)
	write(inc.Subject)
	write(string(inc.Status))
	write(string(inc.Severity))
	write(strconv.FormatBool(inc.SeverityConfirmed))
	writeTime(inc.DetectedAt)
	writeTime(inc.LastEventAt)
	if inc.ClosedAt == nil {
		write("")
	} else {
		writeTime(*inc.ClosedAt)
	}
	write(strconv.FormatInt(int64(inc.EventCount), 10))
	writeList(inc.Endpoints)
	writeList(inc.Sources)
	writeList(inc.Reasons)
	write(strconv.FormatBool(inc.EvidenceTruncated))

	// Classification: what the operator filled in, and what the report repeats
	// back to a regulator.
	if inc.Classification.ClientsAffected == nil {
		write("")
	} else {
		write(strconv.Itoa(*inc.Classification.ClientsAffected))
	}
	if inc.Classification.GeographicSpread == nil {
		write("")
	} else {
		write(*inc.Classification.GeographicSpread)
	}
	if inc.Classification.EconomicImpactEUR == nil {
		write("")
	} else {
		write(strconv.FormatFloat(*inc.Classification.EconomicImpactEUR, 'g', 17, 64))
	}
	write(inc.Classification.Notes)

	// Notifications are append-only and their order is meaningful: the earliest
	// filing is what resolves a deadline.
	write(strconv.Itoa(len(inc.Notifications)))
	for _, n := range inc.Notifications {
		write(string(n.Kind))
		writeTime(n.SentAt)
		writeTime(n.RecordedAt)
		write(n.Authority)
		write(n.Reference)
	}

	return hex.EncodeToString(h.Sum(nil))
}

// chainDigest links one ledger row to its predecessor.
//
// Deleting an interior row makes every row after it recompute to something
// else, the same property the seal chain has. Unlike the seals there is no
// Merkle root here, because there is no period to summarise: the ledger is read
// in full by a verification that has to look at every incident anyway.
func chainDigest(prev, state, incidentID, op string, seq int64) string {
	h := sha256.New()
	write := func(s string) {
		_, _ = h.Write([]byte(strconv.Itoa(len(s))))
		_, _ = h.Write([]byte(":"))
		_, _ = h.Write([]byte(s))
	}
	write("aegis-incident-ledger-v1")
	write(prev)
	write(strconv.FormatInt(seq, 10))
	write(incidentID)
	write(op)
	write(state)
	return hex.EncodeToString(h.Sum(nil))
}

// appendLedger records the state of one incident after a write, inside the
// caller's transaction.
//
// Being in the same transaction is the whole guarantee: an incident whose
// ledger entry could fail separately would produce exactly the state this
// mechanism is meant to detect, and it would produce it by accident, which is
// worse than an attack because nobody is looking.
func appendLedger(ctx context.Context, tx *sql.Tx, tenantID, incidentID, op string, signer Signer) error {
	row := tx.QueryRowContext(ctx, `
SELECT id, title, class, subject, status, severity, severity_confirmed,
       detected_at, last_event_at, closed_at, event_count, endpoints, sources,
       reasons, clients_affected, geographic_spread, economic_impact_eur, notes,
       notifications, evidence_truncated
FROM incidents WHERE tenant_id = $1 AND id = $2`, tenantOr(tenantID), incidentID)
	inc, err := scanIncident(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// The write this is recording did not leave a row behind. That is
			// not a state any caller here produces, and treating it as
			// ordinary would silently skip the ledger entry.
			return fmt.Errorf("incident ledger: %s/%s vanished inside its own transaction", tenantID, incidentID)
		}
		return err
	}

	var prev string
	err = tx.QueryRowContext(ctx, `
SELECT chain FROM incident_ledger
WHERE tenant_id = $1 ORDER BY seq DESC LIMIT 1`, tenantOr(tenantID)).Scan(&prev)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}

	var seq int64
	if err := tx.QueryRowContext(ctx, `
INSERT INTO incident_ledger (tenant_id, incident_id, op, state_digest, chain)
VALUES ($1, $2, $3, $4, '')
RETURNING seq`, tenantOr(tenantID), incidentID, op, incidentDigest(inc)).Scan(&seq); err != nil {
		return err
	}
	// The chain covers seq, which the database assigns, so it is written in a
	// second statement rather than guessed in the first.
	chain := chainDigest(prev, incidentDigest(inc), incidentID, op, seq)
	if _, err = tx.ExecContext(ctx, `
UPDATE incident_ledger SET chain = $3 WHERE tenant_id = $1 AND seq = $2`,
		tenantOr(tenantID), seq, chain); err != nil {
		return err
	}
	// Same transaction as the entry, deliberately: a head written separately
	// could be lost to a crash between the two, leaving an entry the head does
	// not count — reported later as tampering by an operator who did nothing.
	return advanceHead(ctx, tx, tenantID, seq, chain, signer)
}

// LedgerReport is the answer to "has this register been tampered with".
//
// Deliberately one structure with every question answered, rather than several
// methods a caller has to remember to call. A check that has to be assembled by
// its caller is the shape that already produced one defect here: VerifySeals
// existed for two sessions with no way to invoke it.
type LedgerReport struct {
	Intact bool `json:"intact"`
	// Missing names incidents the ledger recorded that are no longer in the
	// register: the plain deletion case.
	Missing []string `json:"missing,omitempty"`
	// Altered names incidents whose current state does not hash to what the
	// ledger last recorded: the edit case, invisible to any signature.
	Altered []string `json:"altered,omitempty"`
	// Unledgered names incidents present in the register with no ledger entry
	// at all — either the entry was deleted, or the row was inserted around
	// the store's own write paths.
	Unledgered []string `json:"unledgered,omitempty"`
	// ChainBroken names the ledger sequence numbers whose chain value does not
	// recompute, which is what an interior deletion or an edit of the ledger
	// itself looks like.
	ChainBroken []int64 `json:"chain_broken,omitempty"`
	// Entries is how many ledger rows were examined, so a reader can tell
	// "verified, nothing wrong" from "there was nothing to verify".
	Entries int `json:"entries"`
	// Head is the chain-level answer: does the ledger reach as far as the head
	// says it should. It travels with the per-incident findings in ONE result
	// rather than behind a second method somebody has to remember to call —
	// which is the defect this project has already paid for once, when
	// VerifySeals existed with no production caller at all.
	Head HeadCheck `json:"head"`
	// Limits is what this check does not establish. It travels with the result
	// for the same reason every signed document here carries one: the answer
	// looks authoritative, and a reader will not qualify it unaided.
	Limits []string `json:"limits"`
}

// ledgerLimits are properties of the mechanism, not of any particular run.
func ledgerLimits(signed bool) []string {
	out := []string{
		"Tampering is detectable, not impossible: this reports that the register changed, not what it held.",
		"The ledger lives in the same database as the register, so an operator who can rewrite the ledger, its head and the register together can make them agree. Only an external anchor defeats that, and there is none.",
	}
	if !signed {
		// An unsigned head still records the count, so truncation is visible to
		// anyone reading the database. What it is not is evidence against the
		// operator who holds that database, and a reader must not take it for
		// more than it is.
		out = append(out, "The ledger head is NOT signed (no report signing key is configured), "+
			"so it commits to the count for a reader but proves nothing to a third party.")
	}
	return out
}

// VerifyLedger recomputes the register against its ledger.
func (s *PGStore) VerifyLedger(ctx context.Context, tenantID string) (LedgerReport, error) {
	rep := LedgerReport{Limits: ledgerLimits(s.signer != nil)}

	err := s.withTenantTx(ctx, tenantID, func(tx *sql.Tx) error {
		// The ledger, in order. Read first so the chain is checked against the
		// same snapshot the state comparison uses.
		rows, err := tx.QueryContext(ctx, `
SELECT seq, incident_id, op, state_digest, chain
FROM incident_ledger WHERE tenant_id = $1 ORDER BY seq`, tenantOr(tenantID))
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()

		latest := map[string]string{} // incident id -> last recorded digest
		var prev string
		var highestSeq int64
		for rows.Next() {
			var (
				seq         int64
				incidentID  string
				op          string
				stateDigest string
				chain       string
			)
			if err := rows.Scan(&seq, &incidentID, &op, &stateDigest, &chain); err != nil {
				return err
			}
			rep.Entries++
			if seq > highestSeq {
				highestSeq = seq
			}
			if want := chainDigest(prev, stateDigest, incidentID, op, seq); want != chain {
				rep.ChainBroken = append(rep.ChainBroken, seq)
			}
			prev = chain
			latest[incidentID] = stateDigest
		}
		if err := rows.Err(); err != nil {
			return err
		}

		// The register, as it stands now.
		incRows, err := tx.QueryContext(ctx, `
SELECT id, title, class, subject, status, severity, severity_confirmed,
       detected_at, last_event_at, closed_at, event_count, endpoints, sources,
       reasons, clients_affected, geographic_spread, economic_impact_eur, notes,
       notifications, evidence_truncated
FROM incidents WHERE tenant_id = $1`, tenantOr(tenantID))
		if err != nil {
			return err
		}
		defer func() { _ = incRows.Close() }()

		present := map[string]bool{}
		for incRows.Next() {
			inc, err := scanIncident(incRows)
			if err != nil {
				return err
			}
			present[inc.ID] = true
			recorded, ok := latest[inc.ID]
			switch {
			case !ok:
				rep.Unledgered = append(rep.Unledgered, inc.ID)
			case recorded != incidentDigest(inc):
				rep.Altered = append(rep.Altered, inc.ID)
			}
		}
		if err := incRows.Err(); err != nil {
			return err
		}

		for id := range latest {
			if !present[id] {
				rep.Missing = append(rep.Missing, id)
			}
		}

		// The chain-level question the per-entry checks structurally cannot
		// answer: is anything missing from the END. Nothing surviving refers to
		// a deleted tail, so only a commitment to the count can see it.
		head, err := checkHead(ctx, tx, tenantID, highestSeq, int64(rep.Entries))
		if err != nil {
			return err
		}
		rep.Head = head
		return nil
	})
	if err != nil {
		return LedgerReport{Limits: ledgerLimits(s.signer != nil)}, err
	}

	// Stable order: a report that reshuffles between runs cannot be diffed, and
	// this one is a candidate for signing, where two orderings of the same
	// finding would be two different documents.
	sort.Strings(rep.Missing)
	sort.Strings(rep.Altered)
	sort.Strings(rep.Unledgered)
	sort.Slice(rep.ChainBroken, func(i, j int) bool { return rep.ChainBroken[i] < rep.ChainBroken[j] })

	rep.Intact = len(rep.Missing) == 0 && len(rep.Altered) == 0 &&
		len(rep.Unledgered) == 0 && len(rep.ChainBroken) == 0 &&
		rep.Head.Complete
	return rep, nil
}
