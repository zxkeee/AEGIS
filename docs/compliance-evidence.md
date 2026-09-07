# Signed compliance evidence

A posture report that anyone can edit in a text editor is not evidence. This
document describes how AEGIS signs the reports it produces, and how the person
receiving one checks it.

Both `GET /api/report` and `GET /api/compliance` can be signed. Signing is
opt-in per request (`?sign=1`); without it, both endpoints behave exactly as
before.

## The trust model, in one paragraph

The gateway signs a report with an Ed25519 key that only the operator holds.
The signed file carries the public key, so anyone can check that the file is
internally consistent — but that check proves nothing on its own, because a
forger who edits the numbers can re-sign with a key they generated and produce a
file that is just as consistent. **Trust comes from the key id.** The operator
publishes the key id once, through a channel that is not the report; the
recipient pins it and rejects any report signed by anything else.

## Setting it up

Generate a key. It is a secret and it must not be the license key or any other
secret the gateway already holds — a shared key means whoever can issue licences
can also forge an audit report. `config.Validate` refuses that reuse at startup.

```bash
go build -o bin/reportverify ./cmd/reportverify
bin/reportverify -genkey
```

That prints three things: the environment variable to set on the gateway, and
the `key_id` / `public_key` to publish.

```bash
export AEGIS_REPORT_SIGNING_KEY='…'   # secret; environment only, never YAML
```

The variable is environment-only by construction: the field carries `yaml:"-"`,
so a signing key cannot be committed to a config file even by mistake. An
unusable key is rejected at boot rather than at the moment an auditor asks for a
signed report.

The gateway republishes the key's identity at `GET /api/report/signing-key`
(admin-authenticated). That endpoint returns the key id and the public key and
never the private key.

## Producing a report

```bash
curl -H "Authorization: Bearer $AEGIS_ADMIN_SECRET" \
     'http://gateway:8081/api/report?sign=1' > report.json
```

The response is an envelope:

```json
{
  "document": "{\"count\":42,\"coverage\":{…},\"posture\":{…},…}",
  "attestation": {
    "algorithm": "ed25519",
    "key_id": "821e82c8add428bb",
    "public_key": "2sfMPMTyy7Bktg0V9YtG7h7eCHUJYny7fNToi0L3uIY=",
    "digest": "sha256:f3f7dc…",
    "signed_at": "2026-09-06T11:10:43Z",
    "signature": "e074e337…"
  }
}
```

The report is carried as a **string** of its JSON, not as a nested object. That
is deliberate: it removes any question about which bytes were signed. A verifier
hashes the `document` string exactly as it arrives. Re-serialising a nested
object — different key order, different number formatting — would break valid
reports and, worse, make two different documents indistinguishable.

`digest` is a convenience, not a control: it lets a reader identify the document
with `sha256sum` and no crypto tooling. The signature is what protects it.

`format=csv` cannot carry an attestation, so `?format=csv&sign=1` is refused
rather than answered with an unsigned spreadsheet. Likewise, a request for a
signature on a gateway with no key configured is a `400`, never a quietly
unsigned document — a script that asked for a signature will not notice it did
not get one.

## Verifying a report

```bash
reportverify -in report.json -key-id 821e82c8add428bb
```

Exit status `0` means the report was signed by that key and has not been
modified. Anything else is `1`. The tool needs no gateway, no database and no
network.

The `-key-id` (or `-pubkey`) argument is mandatory. Running it without one is
refused, because checking a report only against the key it carries is a check
that always passes.

What each failure looks like:

| what was done to the report | what the verifier says |
| --- | --- |
| one character changed | `digest is …, document hashes to …` |
| changed, digest recomputed | `signature does not verify under the given key` |
| changed, re-signed with another key | `signed by key 04d5…, not the 821e… you pinned` |
| fetched without `?sign=1` | `carries no attestation` |

## What the signature does and does not say

It says: this file is exactly what the gateway produced at `signed_at`, and it
was produced by the holder of that key.

It does not say the report is complete. The report's own `coverage` section
states what it could not see — traffic that never passed through the gateway,
findings derived from counters with no retained per-request evidence, a
truncated endpoint list. Signing an incomplete document does not make it
complete; read both.

## Regulatory context

NIS2 (Art. 21, Art. 23) and DORA (Art. 8–10, Art. 17–19) both require evidence
that can be produced to a supervisory authority. Integrity of that evidence is
the part a spreadsheet export cannot provide: a report is only useful to a
regulator if the operator cannot silently revise it after the fact. That is what
this signature is for.

`GET /api/compliance` maps findings and detected abuse onto specific articles:

| DORA article | evidenced by |
| --- | --- |
| Art. 8(1) — identification and documentation of ICT assets | the passive API catalog, including shadow endpoints |
| Art. 9(3) — confidentiality and integrity of data | PII exposure findings |
| Art. 9(4)(c) — logical access limited to what is required | BOLA / BFLA findings and events |
| Art. 9(4)(d) — strong authentication mechanisms | broken-authentication findings |
| Art. 10(1) — prompt detection of anomalous activities | **detected events only** |

Art. 10 is deliberately different. It is about detection mechanisms actually
working, so only an observed event evidences it — a catalog finding says an
endpoint *could* be abused, which is not the same claim and would be false if
counted. The distinction is enforced in the mapping, not left to the reader.

## Incidents (NIS2 Art. 23, DORA Art. 17–19)

A log line is not an incident. These articles are about an object with a
lifecycle, a classification and deadlines, so AEGIS keeps one.

Security events are correlated into incidents by `(tenant, class, subject)`
within a six-hour window — the caller's verified identity where there is one,
otherwise the source address, because correlating on an address splits a single
campaign into hundreds of incidents the moment the attacker rotates it. Only
activity a regulator would recognise as an attack opens an incident: BOLA,
BFLA, WAF, hostile behaviour scores, known-bad sources. A rate-limit rejection
or a redacted response is a control working as designed, thousands of times a
day, and an incident list full of those is worse than no list at all.

```
GET   /api/incidents?status=&severity=&class=&overdue=&from=&to=
GET   /api/incidents/{id}
PATCH /api/incidents/{id}                 # the operator's assessment
POST  /api/incidents/{id}/notifications   # record a submitted report
```

### Deadlines

Every incident carries the NIS2 Art. 23(4) timetable, computed and never
stored:

| obligation | due |
| --- | --- |
| early warning — Art. 23(4)(a) | detection + 24h |
| incident notification — Art. 23(4)(b) | detection + 72h |
| final report — Art. 23(4)(d) | **submission of the notification** + 1 month |

The last row is the one that is easy to get wrong. Art. 23(4)(d) runs from when
the notification was *submitted*, not from detection — anchoring it to
detection hands an operator up to three days they do not have. Submitting early
moves the final report forward with it.

Only the NIS2 timings are hard-coded, because the directive states them. DORA
Art. 19 requires an initial notification, an intermediate report and a final
report too, but its time limits are set by the regulatory technical standards
under Art. 20, not by the regulation — so that schedule is configuration.
Confirm the limits that apply to you; do not assume the NIS2 defaults do.

Closing an incident does not clear a deadline that passed unmet. An obligation
that was missed stays missed, and a report that hid that would be the most
dangerous kind of wrong this system could produce. `?overdue=true` lists them,
and the count is on every listing.

### Classification, and who supplies what

DORA Art. 18 lists six criteria. A gateway can observe three:

| criterion | source |
| --- | --- |
| Art. 18(1)(b) duration | first to last correlated event |
| Art. 18(1)(d) data at risk | the classes of data the affected endpoints return |
| Art. 18(1)(e) criticality of services | the catalog's risk score for those endpoints |
| Art. 18(1)(a) clients affected | **you** — an API caller is not a client |
| Art. 18(1)(c) geographic spread | **you** — attacker-controlled source addresses are poor evidence of geography |
| Art. 18(1)(f) economic impact | **you** — not observable from traffic |

`awaiting_operator` lists what is still missing, per incident. That field is the
difference between "no economic impact" and "nobody has assessed the economic
impact", which are materially different statements to put in front of a
regulator. Zero is a real answer and counts as supplied.

Severity works the same way: `proposed_severity` is what the observed signals
suggest, shown only until a human sets one, and `severity_confirmed` tells a
reader which of the two they are looking at.

### What this changes in the compliance report

The incident articles are evidenced by the incident record, never by a finding.
A list of vulnerable endpoints, however long, says nothing about whether an
entity has an incident process — so each article has its own bar:

| article | evidenced when |
| --- | --- |
| DORA Art. 17 | any incident is tracked through a lifecycle |
| DORA Art. 18 | at least one incident carries a complete Art. 18 classification |
| DORA Art. 19 | at least one submission is recorded |
| NIS2 Art. 23 | at least one submission is recorded |

Recording incidents is not classifying them, and classifying them is not
reporting them. Until each bar is met the article stays in `not_evidenced` with
the reason. An incident with an unmet deadline makes its article **critical**:
a missed 24-hour early warning is a breach of the obligation itself, whatever
the incident turned out to be.

Filing the report remains a human act. AEGIS tracks the deadline, holds the
evidence and records that you filed — it does not submit anything to anyone.

**Still not covered.** The notification history is what AEGIS knows; it cannot
verify that a submission actually reached a competent authority. And without
`forensic_dsn` there is nowhere to keep an incident, so the routes report 503
and the articles stay unevidenced.
