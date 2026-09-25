// Package pglock serialises the append of a hash-chain link within one tenant.
//
// # The bug this exists to prevent
//
// A chain-of-custody append is a read-then-write: read the previous link, then
// insert a row whose hash commits to it. Under PostgreSQL's default READ
// COMMITTED isolation, two transactions can read the SAME previous link before
// either commits. Nothing aborts — the sequence number comes from BIGSERIAL,
// which never collides — so both commit, and the later row now carries a hash
// computed against a link that is not its actual predecessor. Verification,
// which walks by sequence and recomputes against the stored previous value,
// then reports tampering.
//
// Measured, not theorised: eight concurrent writers over four rounds produced
// 23 false "chain broken" positions out of 32 writes
// (TestPG_Ledger_ConcurrentWritersKeepTheChainIntact, before this package
// existed). For a product whose claim is that tampering is detectable, a
// mechanism that cries tampering at ordinary concurrency is worse than none: it
// teaches its reader to dismiss the alarm, and the real deletion then arrives to
// an audience that has stopped believing it.
//
// # Why an advisory lock and not a higher isolation level
//
// The obvious fix — copy internal/forensic's RepeatableRead — does not work.
// PostgreSQL's REPEATABLE READ is snapshot isolation, and snapshot isolation
// does not prevent write skew: two transactions each reading a snapshot that
// excludes the other's not-yet-committed insert is exactly the anomaly here,
// and both still commit. Only SERIALIZABLE detects it, and only if every caller
// retries on a 40001 serialization failure — a retry loop threaded through four
// call sites, each of which would have to be correct.
//
// (internal/forensic survives on RepeatableRead alone for a different reason:
// its sequence number is computed by the application as max+1 and constrained
// UNIQUE, so a collision aborts one writer. It is the UNIQUE constraint doing
// the work there, not the isolation level.)
//
// A transaction-scoped advisory lock is smaller and exact: it serialises the
// critical section for one tenant, releases automatically at commit or
// rollback — so it cannot be leaked by an early return or a panic — and needs
// no retry logic anywhere. Because a transaction takes at most one of these
// locks, there is no lock-ordering deadlock to reason about.
//
// The cost is that chain appends for one tenant are serial. That is the correct
// trade: these are incident records and administrator actions, which arrive at
// human and flush-interval rates, not at request rates.
package pglock

import (
	"context"
	"database/sql"
	"fmt"
	"hash/fnv"
)

// ChainAppend takes the per-tenant chain-append lock inside the caller's
// transaction.
//
// It must be called BEFORE the previous link is read. Taking it afterwards
// would serialise the write while leaving the read unprotected, which is the
// bug wearing a lock.
//
// The lock is released by the transaction ending; there is deliberately no
// Unlock to forget.
func ChainAppend(ctx context.Context, tx *sql.Tx, tenantID string) error {
	// The key is derived in Go rather than with PostgreSQL's hashtext(), which
	// is an internal function with no compatibility promise across versions.
	// FNV-1a is not cryptographic and does not need to be: a collision between
	// two tenants costs some parallelism and nothing else, because the lock
	// only ever serialises — it never decides correctness for a tenant.
	h := fnv.New64a()
	_, _ = h.Write([]byte(tenantID))
	// Mask the sign bit rather than converting the full uint64 and letting it
	// wrap. pg_advisory_xact_lock takes the whole int64 range, so a negative key
	// would work — but a silent sign flip is the kind of thing that reads as a
	// bug to the next person and to gosec (G115), and one bit of key space costs
	// nothing here: a collision only ever costs parallelism between two tenants.
	key := int64(h.Sum64() & 0x7FFFFFFFFFFFFFFF)

	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, key); err != nil {
		return fmt.Errorf("pglock: chain-append lock for tenant %q: %w", tenantID, err)
	}
	return nil
}
