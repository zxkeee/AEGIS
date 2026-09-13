# Forensic integrity seals

## The question this answers

An auditor looks at a signed AEGIS report and asks:

> What stops you deleting the inconvenient rows before you generate it?

Until this existed, the honest answer was **nothing**. `forensic_logs` is an
ordinary table with a `BIGSERIAL` primary key, and the retention sweep runs
`DELETE FROM forensic_logs WHERE ts < $1` on a schedule. The report's signature
covers the *document*; it has never said anything about the log the document was
computed from.

## How a seal works

Every period — an hour by default — the gateway reads that period's entries in
`id` order, hashes each one, folds them into a Merkle root, and writes a row:

| tenant | period_start | period_end | entry_count | merkle_root | prev_root | signature |
|---|---|---|---|---|---|---|

`prev_root` is the previous seal's root, and it is inside the signed payload.
That is what makes the seals a chain rather than a list of independent claims.

Delete an entry afterwards and the root recomputed from the surviving rows no
longer matches what was sealed. Rewrite that seal to match, and the *next*
seal's `prev_root` no longer matches — so covering up one period means
rewriting every seal after it, and re-signing each one.

Seals are never deleted by retention. A seal is about 200 bytes, and outliving
the entries it describes is the entire point: the question is asked *after* the
data is gone.

## What this does NOT prove

Read this part before quoting the feature to anyone.

**It makes deletion detectable, not impossible.** Nothing here stops an operator
with database access from running a `DELETE`. The verification tells you it
happened.

**A seal covers a period, not a row.** A mismatch says "this hour was altered",
with the entry count as the only hint about direction. It cannot say which entry
is missing, and it cannot recover it — a Merkle root is a commitment, not a
backup.

**An operator holding the signing key can forge a consistent chain.** The seals
are signed with the same key that signs reports, which lives on the gateway the
operator runs. Rewriting the chain and re-signing it produces something that
verifies. What this buys is cost: tampering goes from one `DELETE` to rewriting
and re-signing every subsequent seal. That is a real increase and it is not the
same as proof.

**The gap that closes it is an external anchor**, and AEGIS does not ship one.
Publishing a root where the operator cannot alter it — an RFC 3161 timestamp
authority, a transparency log, an email to the auditor at period end — is what
turns "expensive to forge" into "cannot forge without the third party
noticing". Until then, do not describe seals as tamper-*proof*. Tamper-*evident*
is the accurate word and it is still worth having.

## Configuration

```yaml
forensic_seal:
  enabled: true
  period: 1h      # window each seal covers
  lag: 5m         # wait after a period closes before sealing it
forensic_dsn: "postgres://..."   # required
```

`lag` is not padding. The forensic sink batches writes, so an entry timestamped
10:59 can land in the table after 11:00. Sealing 10:00–11:00 immediately would
commit to a window still being written to, and the late entry would read as
"added after sealing" forever.

`period` trades legibility against precision. A day-long period tells an auditor
"something on Tuesday changed"; an hour narrows it to the hour. Shorter costs one
small row per tenant per period.

## Catching up

The worker walks forward from the last sealed period, so a gateway that was down
does not leave a hole. Holes matter: an unsealed window is one an operator can
edit freely, and "there is no seal for Tuesday" is indistinguishable from "the
seal for Tuesday was deleted" unless the chain is contiguous.

Enabling seals on an existing deployment starts from the **oldest entry**, not
from today — otherwise everything already in the table would stay permanently
unsealed and therefore freely editable.

Catch-up is capped at 24 periods per tick so a long outage does not hold a
transaction per period while the request path waits on the same connection pool.

## Verifying

`VerifySeals` recomputes every seal for a tenant against the log as it stands
and reports, per period, one of:

- intact;
- `N entries are missing: sealed X, found Y`;
- `N entries were added after sealing`;
- `the entry count matches but the contents changed` — an entry was edited in
  place;
- `the chain is broken: prev_root is …, expected …` — this period's entries are
  untouched, but a seal before it was rewritten, inserted or removed.

## What to tell a customer

Say it plainly, because the precise version is more persuasive than the vague
one:

> Every hour, we commit to what the log contained. If anything is removed or
> changed afterwards, the commitment stops matching and we can show you exactly
> which hour. We cannot stop someone with database access from deleting a row,
> and we cannot get it back — what we can do is make it impossible to do
> quietly.
