<!--
Short PRs do not need every heading. Delete what does not apply; do not delete a
heading to avoid answering it.
-->

## What changed, and why

<!-- The defect or the need, then the change. If it is a fix, say what the old
     behaviour did wrong rather than what the new code does right — the second is
     visible in the diff, the first is not. -->

## How it was verified

<!-- What you ran, and what you broke on purpose to check the tests notice.
     A test that has never been seen to fail has not been shown to test anything.
     Mutations must COMPILE: a red from the compiler says nothing about the test. -->

## What this does not do

<!-- Limits, known gaps, and anything a reader might assume is covered and is
     not. This section is the one that makes the rest trustworthy. -->

---

### Checklist

- [ ] `make preflight` passes. If it printed `INCOMPLETE`, Redis and PostgreSQL
      were not up — that is not a pass.
- [ ] PostgreSQL tests were run under an unprivileged role (`POSTGRES_APP_DSN`).
      A superuser bypasses row-level security, and two real protections have
      already survived mutation testing because of it.
- [ ] **Did this add a capability a buyer or an operator is told about?** Then it
      belongs in `docs/capabilities.json`, or `make doc-drift` will keep passing
      while the documents quietly stop describing the product. The check only
      knows what is listed there.
- [ ] Docs that would now be wrong are updated: positioning in
      `docs/PRODUCT.md`, status in `ROADMAP.md`, the release gate in
      `RELEASE-CHECKLIST.md`. They drifted apart four times in one session.
- [ ] If it produces a document that can be signed, it states what it does **not**
      establish. `writeSignable` refuses to sign one that does not.
