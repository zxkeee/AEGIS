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
- [ ] **Real console authentication.** Replace the static bearer token in
      `sessionStorage` with proper sessions (expiry + rotation), and ideally
      OIDC/SAML SSO with `admin`/`viewer` roles and MFA.
- [ ] **Dependency CVE scanning.** Add `govulncheck` to CI and resolve findings.
- [ ] **Independent security testing.** Manual pentest plus an automated dynamic
      scan (OWASP ZAP / nuclei) against a running instance; triage and fix.
- [ ] **TLS mandatory in production.** Enforce or strongly document TLS
      termination; refuse insecure production configurations.
- [ ] **Backend signature verification reference.** Provide a reference
      implementation/SDK so backends correctly verify `X-Gateway-Signature`,
      timestamp freshness and nonce uniqueness.
- [ ] **Secret rotation procedure** documented and tested (admin, JWT, Redis).

### P1 — strongly recommended before launch
- [ ] Real TLS JA3/JA4 fingerprinting (currently header-based, spoofable) or
      remove the claim from marketing.
- [ ] Extend `fail_closed` semantics to IP guard and behavioural scoring.
- [ ] Security headers / CSP review for the console (tighten `script-src`).
- [ ] Rate limiting on authentication failures beyond the admin plane.

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
- [ ] **SIEM integration** (Splunk / Elastic) and **alerting** (Slack / PagerDuty)
      with configurable webhooks.
- [ ] **Native Prometheus exposition** of the AEGIS counters.
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
- [ ] **Test coverage.** Unit tests for all middleware, config validation, proxy
      and store; integration tests against Redis and PostgreSQL; regression tests
      for every fixed vulnerability. Target >= 70% on critical packages, enforced
      in CI.
- [ ] **Load and latency benchmarks.** Published latency overhead and max RPS per
      core (k6 / vegeta), with the WAF on and off.
- [ ] **Graceful failure under load.** Verify behaviour when Redis or PostgreSQL
      is unavailable, and during rolling updates, under sustained traffic.

### P1
- [ ] High-availability guide (Redis Sentinel/Cluster, replicated PostgreSQL).
- [ ] Capacity-planning guidance with concrete numbers.
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
