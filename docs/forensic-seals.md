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

| tenant | seq | period_start | period_end | entry_count | merkle_root | prev_root | signature |
|---|---|---|---|---|---|---|---|

`prev_root` is the previous seal's root, and it is inside the signed payload.
That is what makes the seals a chain rather than a list of independent claims.

Delete an entry afterwards and the root recomputed from the surviving rows no
longer matches what was sealed. Rewrite that seal to match, and the *next*
seal's `prev_root` no longer matches — so covering up one period means
rewriting every seal after it, and re-signing each one.

### Why there is also a chain head

A chain of back-references catches a seal that was *changed*. It cannot catch
one that is simply *gone from the end*, because nothing that remains refers to
it: delete the last three seals together with the entries they covered, and
every surviving seal still recomputes perfectly. The worker then seals the
emptied periods again, and the result is a shorter chain that verifies. That was
cheaper than the attack seals exist to stop — no key, no rewriting, two
`DELETE`s.

So each tenant also has one row in `forensic_chain_head`: the highest seal
number, the last root, and a signature over those. Seals carry a gapless `seq`,
and the head is written in the same transaction as the seal it describes, so a
seal can never exist that the head does not count. The head never moves
backwards — re-sealing an emptied period leaves the head still pointing at the
root the period used to have, which is what gives the rewrite away.

Verification compares the two and reports any of: seals missing from the end,
gaps in the middle, a head behind the chain, or a head whose root does not match
the last seal. A head that is missing entirely while seals exist is reported
too — "the anchor is gone" is what a cover-up looks like, and it must not read
the same as "nothing is wrong".

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
and the chain head are signed with the same key that signs reports, which lives
on the gateway the operator runs. Rewriting the chain, moving the head back and
re-signing both produces something that verifies. What this buys is cost:
tampering goes from one `DELETE` to rewriting and re-signing every subsequent
seal *and* the head. That is a real increase and it is not the same as proof.

**An operator who deletes the head along with every seal** leaves a state that
cannot be told apart from "seals were never switched on". The head makes
truncation visible for as long as it is there; nothing held in the same database
can make its own absence suspicious. Only a record kept elsewhere does that,
which is the next point.

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

It returns the per-period results together with one chain-level answer, in a
single call. Completeness deliberately is not a second method somebody has to
remember to call: "the check everyone runs does not cover this case" is how the
truncation gap survived in the first place. The chain-level result is one of:

- complete;
- `N seals are missing from the end of the chain: the head records seal X, the
  highest one present is Y`;
- `the chain has gaps: seals are numbered up to X but only Y are present`;
- `the head is behind the chain` — the head was rolled back, or a seal inserted;
- `the head does not match the last seal` — the tail was removed and re-sealed;
- `the chain head is missing while N seals exist`.

Upgrading from a version without the head: existing seals are numbered by period
order and a head is created for each tenant on first start. That head is
unsigned and attests to the state at upgrade time, not to the history before it.

## What to tell a customer

Say it plainly, because the precise version is more persuasive than the vague
one:

> Every hour, we commit to what the log contained. If anything is removed or
> changed afterwards, the commitment stops matching and we can show you exactly
> which hour — including whole hours deleted off the end, which is the easy way
> to try it. We cannot stop someone with database access from deleting a row,
> and we cannot get it back — what we can do is make it impossible to do
> quietly.

If they ask what would make it stronger, the honest answer is an external
anchor, and we do not have one yet. Say that; it is a better answer than a
confident one, and the question is a buying signal worth hearing accurately.
