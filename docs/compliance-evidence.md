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

**What is not covered.** DORA Art. 17–19 and NIS2 Art. 23 are incident
lifecycle: grouping events into an incident, classifying it against a
regulator's criteria, and driving it to a notification deadline. AEGIS has no
incident entity, so it evidences none of them. The report says so itself, in a
`not_evidenced` list on each framework, and the console and the sample report
both show it beside the mapped controls. A document that lists only what it
mapped reads as covering the framework.
