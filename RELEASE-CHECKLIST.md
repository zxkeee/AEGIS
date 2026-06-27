# AEGIS — Release Readiness Checklist (v1.0 Gate)

This document defines the gate that must be cleared before AEGIS is released as a
commercial product. The goal is a release that is (1) free of known security
holes, (2) competitive in the API-security market, and (3) demonstrably reliable.

Do not ship v1.0 until every **P0** item is checked. **P1** items are required to
be competitive; **P2** items are post-launch improvements.

Legend: `[ ]` open · `[x]` done · `[~]` partially done

---

## Pillar 1 — No security holes

### Already addressed
- [x] Constant-time challenge-token compare in `store.IsValidChallengeToken`
      (was `stored == token` — replaced with `subtle.ConstantTimeCompare`).
- [x] Backend identity propagation works in JWKS mode: separate
      `auth.propagation_secret` (env `AEGIS_PROPAGATION_SECRET`) signs the
      `X-Gateway-Signature` header even when JWT verification is JWKS-based;
      startup-warning fires when JWKS is on without a propagation secret so the
      operator knows the gatewayverify SDK will reject every request.
- [x] `gosec_results.json` removed from repo + `.gitignore` (build artifact).
- [x] Stored XSS in the admin console (output escaping across all tables;
      data-attribute event delegation instead of inline JS)
- [x] CSV/formula injection in the report export (`csvSafe`)
- [x] JWT algorithm-confusion and fail-closed when JWKS is unavailable
- [x] Rate-limiter window-reset defect; opt-in `fail_closed`
- [x] DLP streaming / WebSocket safety (Flusher/Hijacker, bounded buffer)
- [x] Proxy retry only for idempotent requests; buffered attempt
- [x] Signed identity propagation with timestamp + nonce
- [x] `gosec` and `golangci-lint` run in CI on every commit

### P0 — release blockers
- [x] **Real console authentication.** Static bearer in `sessionStorage` replaced
      with server-side sessions in Redis: HttpOnly session cookie (unreadable by
      JS/XSS) + CSRF double-submit token on mutations, with TTL. Bearer kept for
      API/CLI. (Full OIDC/SAML SSO + `admin`/`viewer` roles + MFA remain P1.)
- [x] **Dependency CVE scanning.** `govulncheck` runs in CI; x/net bumped and
      toolchain pinned (go1.26.4) so the module and stdlib are CVE-clean.
- [ ] **Independent security testing.** Manual pentest plus an automated dynamic
      scan (OWASP ZAP / nuclei) against a running instance; triage and fix.
      (External step — cannot be self-certified.)
- [x] **TLS mandatory in production.** `require_tls` makes startup fail without
      gateway TLS; the gateway now actually terminates TLS
      (`ListenAndServeTLS`) when `tls.enabled`, not just plaintext; a loud
      startup warning fires when TLS is off; documented that production must
      terminate TLS at the gateway or a trusted upstream.
- [x] **Backend signature verification reference.** `sdk/gatewayverify` Go
      package + README verifies `X-Gateway-Signature`, timestamp freshness and
      nonce uniqueness (HMAC over `sub:roles:scopes:ts:nonce`), with an
      `http.Handler` wrapper, a pluggable `NonceStore`, and a non-Go recipe.
- [x] **Secret rotation procedure** documented (`docs/runbooks/secret-rotation.md`)
      with rolling/dual-accept steps and verification for admin, JWT, Redis and
      forensic-DSN secrets.

### P1 — strongly recommended before launch
- [x] Real TLS JA3/JA4 fingerprinting. Spoofable `X-JA3-Fingerprint` header is
      now stripped; a real fingerprint is computed from the TLS ClientHello at
      the gateway (`internal/tlsfp`, JA3-style over stdlib-exposed fields, GREASE
      filtered). Canonical JA3 extension-list parsing remains a future refinement.
- [~] Extend `fail_closed` semantics to IP guard and behavioural scoring.
      IP-guard `fail_closed` done (denies on Redis outage); behavioural scoring
      intentionally stays fail-open (a scoring gap is safer than blocking all
      traffic) — documented in `store`.
- [x] Security headers / CSP tightened: nonce-based `script-src`/`style-src`,
      no more `unsafe-inline`; nonce rotates per response; added `base-uri`,
      `form-action`, kept `frame-ancestors 'none'`. Validated live on stand.
- [x] Per-IP brute-force rate limit on `/api/login`: 8 failures / 5 min →
      `429 Retry-After`. Counter only consumes budget on failure (successful
      operators never throttle). Validated live: 8× 401 → 9th request 429.

---

## Pillar 2 — Competitive

### Differentiators already in place
- [x] Passive API discovery with path normalization
- [x] Posture classification (protected / partial / unprotected / shadow)
- [x] Risk scoring
- [x] Consumer graph (who calls what)
- [x] Coverage, effectiveness and reporting (JSON/CSV)

### P1 — table stakes / flagship
- [ ] **OWASP API Top-10 detection**, starting with **BOLA/BFLA** built on the
      existing consumer graph. This is the primary reason customers buy API
      security; without it the product reads as "another WAF".
- [~] **SIEM integration** (Splunk / Elastic) and **alerting** (Slack / PagerDuty)
      with configurable webhooks. Done: `alerting` config block (webhook URL,
      `generic`/`slack` payload format, `min_severity` gate); `AEGIS_ALERT_WEBHOOK_URL`
      env override. Remaining: per-rule routing, ticketing (Jira/ServiceNow).
- [x] **Native Prometheus exposition** of the AEGIS counters (`GET /metrics`,
      text format 0.0.4, behind the admin bearer; scrape config in `prometheus.yml`).
- [ ] **OpenAPI / spec drift**: import a spec, compare documented vs observed.

### P2
- [ ] Multi-tenancy (organisations, per-tenant data isolation).
- [ ] Anomaly detection / behavioural baselines per consumer.
- [ ] Out-of-band deployment (traffic mirroring) in addition to inline.
- [ ] Compliance report templates (PCI-DSS, HIPAA, GDPR).
- [ ] Licensing / metering.

---

## Pillar 3 — Works excellently

### P0 — release blockers
- [~] **Test coverage.** Regression tests added for every recent security fix
      (JA3 spoof, IP-guard/rate-limit fail-closed, identity signature/replay).
      A CI coverage gate (`scripts/coverage-gate.sh`, wired into `test.yml`)
      enforces per-package floors that ratchet toward the >= 70% target.
      Current: tenant 100%, tlsfp 100%, gatewayverify 93.4%, proxy 89%,
      config 85.4%, alert 75.6%, middleware ~65%; with real Redis/PG
      discovery is ~86% and store ~28% (the cross-tenant deny tests pass against
      live databases — validated on the home-server containers, not just CI).
      api 18.4% (pure helpers; handler integration tests still to add).
      proxy/discovery/api were 26/23/11% before this pass.
- [~] **Load and latency benchmarks.** k6 scripts + guide under `tests/load/`
      (single-tenant + multi-tenant + attack-mix scenarios, CI-able
      thresholds). First on-hardware run in `tests/load/results-2026-06-21.md`:
      single-tenant 373.6 RPS / p50 33.5 ms, multi-tenant 375.7 RPS / p50
      34 ms (MT overhead in the noise), attack-mix p50 7.9 ms (WAF rejects
      early). Still to do: wired-LAN run, VU sweep, WAF on/off split for
      published capacity numbers.
- [~] **Graceful failure under load.** Redis-outage behaviour verified two ways:
      (1) end-to-end unit matrix in `internal/middleware/degradation_test.go`
      (fail_closed → 503, default → 200, static blacklist still enforced, no
      panics) against a killed Redis; (2) **on-hardware sustained-traffic run**
      with Redis killed mid-test (`tests/load/redis-outage-results-2026-06-26.md`):
      at 50 rps, during a full Redis outage the gateway kept **100% success**
      (fail-open) with **p99 864 ms / max 1.30 s** — bounded by the fail-fast
      Redis timeouts (dial 1s / read-write 500ms / 1 retry), vs the 3–9 s hangs
      the go-redis defaults would cause; latency snapped back to p99 42 ms on
      recovery. PostgreSQL-unavailable is partially covered (catalog → 503,
      `catalog_nil_test.go`; forensic falls back to the Redis ring buffer).
      Still to do: capacity sweep for published max-RPS, PG-outage-under-load,
      and a rolling-update drain (zero-5xx during `Shutdown`).

### P1
- [x] High-availability guide (`docs/runbooks/ha.md`): topology (Sentinel + PG
      streaming replication), per-failure-mode matrix (fail-open vs
      fail-closed per control), RLS rolling-deploy notes, bring-up checklist.
      Sentinel client implemented: `redis.UniversalOptions{MasterName, Addrs}`
      via `store.NewWithConfig` + `config.RedisConfig.Sentinel`; AEGIS code
      is mode-agnostic (the client handles failover).
- [~] Capacity-planning guidance with **rule-of-thumb** sizing (in `ha.md`);
      concrete numbers pending the benchmark run on reference hardware.
- [ ] End-to-end smoke test in CI (start gateway + Redis + PG, drive traffic,
      assert catalog and posture populate).

---

## Suggested sequence

1. **Tests (P3-P0)** — establish reliability and lock in the security fixes with
   regression tests. *In progress.*
2. **Console authentication (P1-P0)** — close the last release-blocking hole.
3. **BOLA/BFLA detection (P2-P1)** — the competitive flagship.
4. **SIEM/alerting + Prometheus (P2-P1)** — fit into customer stacks.
5. **Benchmarks + HA hardening (P3-P0/P1)** — prove "works excellently".

Realistic effort: roughly 2–4 focused iterations. The foundation is solid; this
checklist is the disciplined path from a strong implementation to a shippable
product.
