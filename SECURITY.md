# Security Policy

## Reporting a vulnerability

**Do not open a public issue.**

Use a [GitHub Security Advisory](https://github.com/zxkeee/AEGIS/security/advisories)
— "Report a vulnerability". It notifies the maintainer privately and gives us a
place to work on a fix without disclosing it first.

There is no security email address. One will be listed here when it exists;
until then the advisory form is the only reporting channel, and claiming a
second one would be claiming a process that does not run.

### What to expect

AEGIS is maintained by a single engineer, so these are honest commitments
rather than an enterprise SLA:

| | |
|---|---|
| Acknowledgement | Within a few working days |
| Assessment | We will tell you whether we consider it a vulnerability, and why |
| Fix | Prioritised by severity; no fixed calendar promise |
| Disclosure | Coordinated with you, default 90 days after a fix ships |
| Credit | In the CHANGELOG, if you want it |

If a report is not a vulnerability we will say so plainly and explain the
reasoning, rather than leaving it open.

## What is actually run against this codebase

CI gates every push. This is the whole of the automated security process —
there is no Snyk and no nancy in this repository, and previous versions of this
file described both.

| Check | Where | What it does |
|---|---|---|
| `gosec` | `.github/workflows/security.yml` | Static analysis for insecure Go constructs |
| `govulncheck` | `.github/workflows/security.yml` | Known CVEs in dependencies, reachability-aware |
| `trivy image` | `.github/workflows/security.yml` | CVEs in the **shipped image** — base OS packages and the compiled binary's module graph. Blocking for HIGH/CRITICAL with a fix available; unfixed ones are listed, not enforced |
| `trivy fs --scanners secret` | `.github/workflows/security.yml` | Credentials committed to the repository |
| Dependabot | `.github/dependabot.yml` | Weekly updates for both Go modules, both npm lockfiles, GitHub Actions and the Dockerfile |
| `golangci-lint` | `.github/workflows/lint.yml` | Both Go modules (root and `web/`) |
| `go test -race` | `.github/workflows/test.yml` | Full suite under the race detector |
| Coverage gate | `.github/workflows/test.yml` | Per-package floors that only ratchet up |
| `npm audit` | preflight | Both lockfiles (`web/console`, `web/v3`) |
| Repo invariants | `scripts/lint-invariants.sh` | Secrets that must never render into a ConfigMap, pinned image digests, no committed binaries |

`govulncheck` and `trivy` answer different questions and both are needed:
govulncheck is reachability-aware, so it stays silent about a vulnerable
function nothing calls, while trivy reports on the version present. The image
that shipped before this was written carried five HIGH/CRITICAL CVEs with fixes
available, every one of them invisible to govulncheck.

Run all of it locally before pushing:

```bash
make preflight
```

It installs the versions CI pins and runs the same checks in the same way. A
preflight that has drifted from CI is worse than none, so when a workflow
changes, `scripts/preflight.sh` changes with it.

### What has NOT been done

- **No independent third-party penetration test.** The scope is written up in
  `docs/security/external-pentest-scope.md`; the engagement has not been
  commissioned. We do not self-certify.
- **The internal adversarial audit is incomplete.** 6 of 13 review categories
  returned; the other 7 are unexamined, not clean.

## Deploying AEGIS securely

### Secrets come from the environment, never from config files

`config.Validate` rejects placeholder values, short admin secrets and any reuse
of the report signing key as another secret. Set these in the environment:

| Variable | What it protects |
|---|---|
| `AEGIS_ADMIN_SECRET` | Admin API / console bearer authentication |
| `AEGIS_JWT_SECRET` | HMAC JWT verification (unset when using `jwks_url`) |
| `AEGIS_REDIS_PASSWORD` | Redis, plus `AEGIS_REDIS_SENTINEL_PASSWORD` for Sentinel |
| `AEGIS_CONSUMER_SALT` | Makes the consumer catalog irreversible |
| `AEGIS_PROPAGATION_SECRET` | Signs the identity forwarded to your backends |
| `AEGIS_REPORT_SIGNING_KEY` | **Signs compliance evidence.** Separate key, never reused |
| `AEGIS_FORENSIC_DSN` | Forensic log and catalog database |
| `AEGIS_OIDC_CLIENT_ID` / `AEGIS_OIDC_CLIENT_SECRET` | Console SSO |
| `AEGIS_ALERT_WEBHOOK_URL` | Alert delivery (https only) |

Generate the report signing key with `reportverify -genkey`. It prints the
secret to set, and the `key_id` plus public key to publish — an auditor pins the
key id and verifies reports against it.

### Network placement

- `listen` (default `:8080`) — the data plane. This is the only port that
  should face untrusted traffic.
- `admin_listen` (default `:8081`) — the control plane: console, metrics,
  catalog, incident and report APIs. **Never expose it publicly.** Bind it to a
  private interface or put it behind a VPN.
- Redis and PostgreSQL belong on a private network reachable only by the
  gateway. Use `sslmode=require` (or stronger) in the DSN.

### `trusted_proxies` is load-bearing

`X-Forwarded-For` is honoured only from peers listed in `trusted_proxies`,
walked right to left. Get this wrong and every per-IP control — rate limiting,
the IP guard, behavioural scoring, the threat feed — is either bypassable by a
spoofed header or applied to your own load balancer's address. The same list
gates `bot.trust_upstream_ja3`.

### TLS

The gateway terminates TLS itself when configured to, which is also what makes
JA3 fingerprinting real: the fingerprint is computed from the ClientHello and
bound to the connection. Behind a TLS-terminating upstream there is no
handshake to fingerprint, and the inbound `X-JA3-Fingerprint` header is always
stripped — an upstream-supplied one is trusted only from a `trusted_proxies`
peer with `bot.trust_upstream_ja3` explicitly enabled.

### Fail-closed

`fail_closed` is opt-in per control (rate limit, IP guard): on a Redis outage,
deny rather than allow. Behavioural scoring stays fail-open deliberately — a
scoring gap is safer than blocking all traffic on a cache failure. Decide which
you want per control; the default is not "secure by default" in both
directions, and pretending otherwise would hide a real trade-off.

## Verifying the identity AEGIS forwards

After JWT authentication the gateway signs the identity it passes to your
backend. Verify it with the reference SDK — `sdk/gatewayverify` — rather than
reimplementing it:

```go
import "api-gateway/sdk/gatewayverify"

v := gatewayverify.New(os.Getenv("AEGIS_PROPAGATION_SECRET"), 60*time.Second, nil)

func handler(w http.ResponseWriter, r *http.Request) {
    id, err := v.Verify(r) // authenticity + freshness + replay, in that order
    if err != nil {
        http.Error(w, "forbidden", http.StatusForbidden)
        return
    }
    // id.Subject, id.Roles, id.Scopes, id.Identity
}
```

The signature is `HMAC-SHA256` over the canonical payload
`subject:roles:scopes:identity:timestamp:nonce`, hex-encoded, in
`X-Gateway-Signature`. It is **not** a signature over the request body — an
earlier version of this document showed exactly that, and code copied from it
would have verified nothing.

`CleanHeaders` strips every inbound `X-Gateway-*` before anything downstream
sees it, so a client cannot forge these headers through the gateway. That
guarantee ends at your backend's door: if your backend is reachable without
going through AEGIS, it must still verify.

### What your backend should still do

- **Verify the signature, the timestamp and the nonce.** All three; the SDK
  does it in the right order.
- **Enforce its own authorization.** The gateway tells you *who* the caller is.
  Whether that caller may touch *this object* is a decision only your
  application can make. AEGIS detects and can block object-level abuse
  (BOLA/BFLA) from traffic patterns; that is a safety net, not your access
  control layer.
- **Do not rely on client IP for authorization** — requests arrive through the
  gateway and any load balancer in front of it.

## What AEGIS does and does not stop

Coverage is honest rather than uniformly ticked. `ROADMAP.md` and
`docs/PRODUCT.md` are the source of truth; this is the summary.

| Class | Control | Status |
|---|---|---|
| SQLi, XSS, RCE, traversal, XXE, SSRF payloads | WAF (Coraza, OWASP CRS v4) | Detected and blocked by signature; CRS is not a proof of absence, and paranoia level trades detection against false positives |
| Object-level abuse (BOLA / BFLA) | Behavioural detection on verified JWT roles | Detected; blocking is opt-in per route |
| Credential brute force, flooding | Rate limiting, behavioural scoring | Enforced; `fail_closed` opt-in |
| Bot traffic | JA3 fingerprint + behavioural scoring | Enforced when the gateway terminates TLS |
| PII / card data in responses | DLP masking | Masked for the classes in `internal/classify` (`credit_card`, `ssn`, `email`, `phone`, `npi`) — not a general PII engine |
| Shadow and undocumented endpoints | Passive discovery | Surfaced in the catalog with a posture score |
| Account takeover, credential stuffing | — | **Not implemented** |
| L7 DDoS, client-side (Magecart) attacks | — | **Not implemented** |
| Mass assignment (API6), schema enforcement | — | **Not implemented** (drift reporting only) |
| Request smuggling | Header validation + WAF | Partial; not independently tested |

## Compliance

AEGIS maps findings and runtime abuse onto NIS2 Article 21(2), DORA Articles
8–10 and 17–19, and ISO/IEC 27001 Annex A, and signs the resulting report so an
auditor can verify it with `reportverify` without trusting the operator or us.

That is evidence, not certification:

- **AEGIS is not certified against PCI-DSS, and running it does not make you
  compliant.** It can produce evidence relevant to some requirements — masking
  card data in responses (3.4), the WAF (6.5.x), an audit trail in PostgreSQL
  (10.x) — but only a QSA assessment of *your* environment decides compliance.
  A previous version of this file presented a requirement-by-requirement table
  of green ticks. It should not have.
- Every report carries a `not_evidenced` list naming the controls it does not
  cover. Keeping an incident register is not classifying incidents, and
  classifying is not filing; each is evidenced at its own threshold or not at
  all.
- Controls marked `runtimeOnly` are evidenced only by observed events. A static
  finding says an endpoint *can* be abused, not that detection fired, and
  counting the first as the second would be a lie told to an assessor.

## Resources

- OWASP API Security Top 10 — https://owasp.org/API-Security/
- OWASP Top 10 — https://owasp.org/www-project-top-ten/
- Coraza — https://coraza.io/docs/
- NIS2 — Directive (EU) 2022/2555
- DORA — Regulation (EU) 2022/2554
