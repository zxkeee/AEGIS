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
- [x] Hot-reload runs the full startup safety gate: `config.Validate` +
      `InitTrustedProxies` now apply on every reload (previously an unsafe edit
      went live unvalidated, and `trusted_proxies` changes were silently
      ignored — breaking every per-IP control). Trusted-proxy set is swapped
      atomically (race-free with in-flight requests).
- [x] Proxy no longer wraps upstreams in `http.TimeoutHandler` (which buffered
      whole responses in memory — an OOM vector — and broke SSE/WebSocket).
      The per-route timeout is now a response-header bound on the transport;
      SSE flushes and WebSocket upgrades pass through end-to-end (covered by
      `TestProxy_SSEStreamsThroughRetryPath` / `TestProxy_WebSocketUpgradePassesThrough`).
- [x] JWKS initial fetch retries forever with capped backoff (a transient IdP
      outage at boot used to leave the gateway permanently fail-closed after
      5 attempts, 401-ing all traffic until restart).
- [x] Challenge no longer embeds the expected token in the page: the server
      stores an FNV-1a transform of the embedded seed, so scraping the HTML and
      echoing the seed back does not pass (documented honestly as a
      trivial-bot filter, not bot-proof).
- [x] Unknown `load_balance` strategies and malformed route timeouts are
      rejected by `config.Validate` instead of silently degrading to defaults.
- [x] Optional `admin_cors` block: the admin plane no longer has to share the
      data-plane CORS origin list; wildcard rejected when `admin_auth` is on.
- [x] Client-supplied `X-Request-ID` is sanitised (charset + 64-char cap)
      before being logged/echoed/forwarded; deprecated `X-XSS-Protection`
      header dropped (CSP is the control).
- [x] **No false-positive auto-bans on normal traffic.** The behavioural error
      signal now counts only genuinely abusive statuses (`400`/`429`), not the
      normal `401`/`403`/`404` or backend `5xx`, so an active client behind a
      shared IP/NAT is not banned for hitting missing/protected endpoints. The
      WAF no longer mis-attributes an upstream `403`/`400`/`405` as its own block
      (a "reached backend" sentinel distinguishes a Coraza interruption from a
      passed-through downstream status), so those responses no longer inflate
      `waf_blocked` or add a behaviour penalty.
- [x] **Catalog cardinality cap.** The PostgreSQL catalog bounds the total number
      of distinct endpoints (mirroring the Redis inventory cap), so a path-flood
      through a catch-all route cannot grow `api_endpoints` without limit.
- [x] **Threat-feed redirect safety.** Feed fetches follow only HTTPS redirects to
      non-private hosts, closing a blind-SSRF path (redirect to `http://` or an
      internal address such as cloud metadata).
- [x] **CIDR-aware IPGuard.** Whitelist/blacklist used to match only exact IP
      strings, so a configured subnet (`10.0.0.0/8`) silently matched nothing;
      now parses IPs/CIDRs and matches by containment, and `config.Validate`
      rejects malformed entries at startup instead of failing silently at
      request time.
- [x] **Per-account brute-force gate.** Login throttling was keyed only by
      source IP, so a distributed attacker (fresh IP per attempt) could grind
      one known account forever without tripping it. An independent
      per-(tenant,email) gate now runs alongside the per-IP one (same
      atomic-reserve-then-refund pattern).
- [x] **Admin bootstrap-secret can be permanently disabled.**
      `admin_bootstrap_secret_disabled` closes the always-super-admin,
      per-operator-unauditable `AEGIS_ADMIN_SECRET` bearer path once real IAM
      users are provisioned; every successful bearer use (not just failures)
      now logs unconditionally so its usage is visible to log-based alerting
      even before it's disabled.
- [~] **Cross-IP bootstrap-secret brute-force is now both visible and slowed
      (VULN-802/901/902/904, security audit 2026-08-22).** The bootstrap path
      has no per-account key to gate on (`AEGIS_ADMIN_SECRET` is one secret for
      the whole deployment), so a blocking gate on a shared/global key was
      rejected — it would let any unauthenticated caller lock every admin out
      with a handful of requests, trading the brute-force gap for a trivial
      unauthenticated DoS. Instead: a cross-IP failure counter fires one alert
      per window past a threshold sized for a global/shared key (not copied
      from the per-account budget, which false-positived on ordinary
      multi-source legitimate traffic), correctly refunded on a successful
      login (an earlier version of this fix double-counted successes as
      failures — caught by 3 independent reviewer passes before it shipped),
      *plus* a ramping response delay (0 / 200ms / 1s / capped 3s) ahead of
      that same threshold that multiplies a sustained/distributed guesser's
      wall-clock cost by orders of magnitude without ever refusing a correct
      secret or becoming a timing side-channel on correctness. Operators who
      want the gap fully closed rather than slowed should still disable the
      bootstrap path (`admin_bootstrap_secret_disabled`, above) once real IAM
      users exist — recommended default posture, not just a fallback.

      **Update (same-day follow-up audit):** the first version of the delay
      only taxed each request's own latency — by Little's Law
      (throughput ≈ concurrency / latency), an attacker who simply opens more
      concurrent connections routes around a fixed per-request delay for
      free; a botnet at high concurrency saw effectively the same
      guesses/sec through the ladder as with no delay at all. A bounded
      semaphore (capacity 64) now gates entry to the delay itself, and a
      caller that can't get a slot immediately **waits** for one rather than
      skipping through untouched (an even earlier draft of this exact fix
      made that skip-on-saturation mistake — caught before shipping). This
      makes capacity/holdTime (~64/3s ≈ 21 req/s) an actual ceiling on
      aggregate throughput through the bootstrap-secret path, independent of
      attacker concurrency — not just a per-request latency tax. Still fails
      open on a Redis outage (consistent with every other gate in this
      handler); the secret's entropy, separately enforced by
      `config.Validate`, remains the real backstop against a guesser this
      throttle can't outright stop, only slow to a bounded rate.

      **Second follow-up audit (still same day):** the blocking semaphore
      above traded the concurrency-bypass gap for a new one — a legitimate
      operator's CORRECT secret shares the same queue as attacker traffic,
      with no priority or fairness, so a sustained flood could queue a real
      login behind however many attacker slots preceded it, bounded in
      practice only by the admin server's own 30s connection timeout. That is
      a denial, not a delay, aimed at exactly the moment (active
      incident/attack) this bootstrap credential exists for — this is why the
      item above is marked partial rather than done. Two bounds now cap that:
      `bootstrapSecretMaxQueueWait` (3s) — a caller that can't get a slot in
      time gives up and proceeds unthrottled rather than queuing further —
      and `bootstrapSecretQueueAdmission` (512) — bounds how many callers may
      be waiting at all, independent of how many are holding a slot, so
      concurrency can't pile up an unbounded number of goroutines/sockets in
      front of the gate either. (A related robustness gap was fixed
      alongside these: the semaphore slot is now released via `defer`, so a
      panic mid-hold can no longer leak a slot permanently.) Net effect: this
      throttle no longer has an unbounded-wait failure mode, but it is still
      an inherently shared, unprioritized resource between attacker and
      operator traffic by design (the same reasoning that ruled out a hard
      per-secret block applies here too) — a legitimate operator can still
      see up to ~3s of added latency during an active flood, just never an
      unbounded hang or a silent connection-timeout failure. Whether that
      residual latency is acceptable for incident-response access, versus
      e.g. an allowlisted bypass for known operator source ranges, is a
      product decision this fix intentionally leaves open rather than
      deciding unilaterally.
- [x] **Cross-tenant super-admin reads are now audited.** Tenant list, cross-
      tenant/`?all=true` user and audit-log reads were unrecorded (`serveAndAudit`
      only covered mutations); `auditCrossTenantRead` closes that blind spot.
- [x] **Dead/unwired config now rejected instead of silently doing nothing.**
      `registry.enabled: true` (ServiceAuth is not wired into the request
      chain; no real `RegistryProvider` exists) is rejected by
      `config.Validate` rather than giving an operator false confidence.
      `RateLimitConfig.BurstLimit` (declared everywhere, never read by the
      fixed-window limiter) removed rather than left as a misleading knob.
- [x] **Helm ConfigMap secret leak.** `gateway.forensic_dsn` /
      `gateway.redis.password` could leak into the plaintext ConfigMap if an
      operator filled them directly instead of `secrets.forensicDsn` /
      `secrets.redisPassword`. The template now force-blanks both regardless
      of `.Values.gateway`; `forensic_dsn` gets a proper Secret-backed env var
      (`AEGIS_FORENSIC_DSN`), matching the existing admin-secret/redis-password
      pattern.
- [x] **docker-compose resource limits + supply-chain CI gates.** Per-container
      CPU/memory limits (gateway/redis/postgres/grafana), mirroring the Helm
      chart. Two new CI-wired checks: `check-image-pins.sh` (fails on a
      tag-only-pinned image without a tracked exception) and
      `check-weak-secrets.sh` (rejects weak/default `AEGIS_REDIS_PASSWORD` /
      `POSTGRES_PASSWORD` / `GRAFANA_ADMIN_PASSWORD` — these feed
      docker-compose directly and never pass through `config.Validate`).
      `helm lint` also wired into `lint.yml`.

### P0 — release blockers
- [x] **Real console authentication.** Static bearer in `sessionStorage` replaced
      with server-side sessions in Redis: HttpOnly session cookie (unreadable by
      JS/XSS) + CSRF double-submit token on mutations, with TTL. Bearer kept for
      API/CLI. `admin`/`viewer` roles enforced. **OIDC single sign-on** now
      implemented (`internal/sso`): Authorization Code flow with PKCE against the
      provider discovery document, ID-token verification (signature via the
      provider JWKS, issuer/audience/expiry, nonce), claim→tenant/role mapping,
      and just-in-time user provisioning. `GET /api/auth/oidc/login` +
      `/callback`; validated end-to-end against a local IdP with real RS256
      crypto (`internal/sso` integration tests) and a live-PG callback test.
      (SAML + SCIM + MFA remain P1 — most enterprises front OIDC with their own
      MFA, so this unblocks the majority of SSO deals.)
- [x] **Dependency CVE scanning.** `govulncheck` runs in CI; x/net bumped and
      toolchain pinned (go1.26.4) so the module and stdlib are CVE-clean.
- [~] **Independent security testing.** Automated dynamic scan in place
      (`.github/workflows/security-scan.yml`): boots a self-contained instance and
      runs `tests/pentest.sh` (WAF efficacy + admin-auth) plus **nuclei** against
      the admin plane (high/critical gate, allowlist in `tests/dynamic/`).
      Validated end-to-end on a Linux Docker host: pentest 18/18, nuclei admin
      plane 0 high/critical. This scan also surfaced and fixed a real WAF gap
      (JSON request bodies were not inspected — see `waf.go` JSON body processor).
      Note: nuclei against the data plane false-positives on the reflecting test
      backend, so the gate scans the admin plane and pentest.sh covers the WAF.
      Second automated pass added: **OWASP ZAP baseline scan** against the same
      admin plane (`tests/dynamic/zap-baseline-2026-07-31.md`) — 0 high/critical,
      4 warnings, all pre-existing and already-documented tradeoffs (CSP
      style-src, COEP). Not wired into CI (one-off run, see the report for why).
      Still open (external, cannot be self-certified): an **independent manual
      pentest** by a third party. Scope and rules of engagement are now
      written up (`docs/security/external-pentest-scope.md`) so an external
      team can start from the frontier of internal testing rather than from
      zero — the doc itself is not a substitute for the engagement.
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
- [ ] **Known trade-off, deliberately not changed (CHAIN-801, security audit
      2026-08-22):** the admin-plane rate limit, the per-IP `/api/login` gate,
      and the per-account `/api/login` gate all default `fail_closed: false`
      independently. Each is individually documented and correct on its own,
      but a single Redis outage drops all three at once, leaving only
      `subtle.ConstantTimeCompare` on the credential — an unthrottled login
      window during any Redis disruption, not just a targeted attack. Decision
      (2026-08-22): keep the fail-open default — this is a self-hosted product
      and an operator locked out of their own admin console by a Redis blip is
      worse than the narrow brute-force window, given `AEGIS_ADMIN_SECRET`
      strength is already enforced by `config.Validate`. Deployments that want
      the stricter behaviour can set `admin_login_fail_closed: true` (and the
      matching `rate_limit`/`ip_guard` flags) today — no code change needed.
      Revisit if a managed/hosted offering ships, where an SRE on-call can
      absorb a fail-closed lockout that a self-hosted operator cannot.
- [x] Security headers / CSP tightened: nonce-based `script-src`/`style-src`,
      no more `unsafe-inline`; nonce rotates per response; added `base-uri`,
      `form-action`, kept `frame-ancestors 'none'`. Validated live on stand.
- [x] Per-IP brute-force rate limit on `/api/login`: 8 failures / 5 min →
      `429 Retry-After`. Counter only consumes budget on failure (successful
      operators never throttle). Validated live: 8× 401 → 9th request 429.
- [x] Migrate `github.com/lib/pq` → `github.com/jackc/pgx/v5`. All 6 call sites
      (audit, discovery catalog, forensic sink, iam, retention, pgtest) now open
      via `sql.Open("pgx", dsn)` through `github.com/jackc/pgx/v5/stdlib`.
      `pq.Array()` binding was dropped — pgx's `database/sql` compat layer binds
      plain Go slices (`[]string`, `[]int`) against `text[]`/`ANY($n)` natively;
      scanning an array column back still needs an adapter, done via
      `pgtype.NewMap().SQLScanner(&dest)` (verified empirically against a live
      DB: plain-slice scan target errors, the adapter round-trips correctly).
      `pq.QuoteIdentifier` → `pgx.Identifier{...}.Sanitize()` in `pgtest`. Bumped
      `golang.org/x/text` v0.38.0→v0.39.0 along the way — pulled in transitively
      by pgx, and govulncheck flagged a real, reachable CVE (GO-2026-5970) in the
      old version via `audit.New`. Verified: full test suite incl. PG/Redis
      integration tests + `-race`, coverage-gate (no package regressed),
      govulncheck/gosec/golangci-lint clean, static (`CGO_ENABLED=0`) build.

---

## Pillar 2 — Competitive

### Differentiators already in place
- [x] Passive API discovery with path normalization
- [x] Posture classification (protected / partial / unprotected / shadow)
- [x] Risk scoring
- [x] Consumer graph (who calls what)
- [x] Coverage, effectiveness and reporting (JSON/CSV)

### P1 — table stakes / flagship
- [x] **OWASP API Top-10 detection**, starting with **BOLA/BFLA** built on the
      existing consumer graph. This is the primary reason customers buy API
      security; without it the product reads as "another WAF". Implemented in
      `middleware.AbuseDetection` (wired after JWT so it sees verified roles):
      **BFLA** flags a consumer hitting a privileged path prefix without any
      required role; **BOLA/IDOR** is caught two ways: (1) **enumeration** via
      per-consumer/endpoint distinct-ID counts (`store.TrackObjectAccess`) against
      both a hard `enum_threshold` ceiling and an adaptive per-consumer EWMA
      baseline (`store.TrackBaseline`, A2); (2) **single-object IDOR**
      (`object_ownership`) — learns which consumers own which objects
      (`store.TrackObjectOwner`) and flags a consumer that **successfully (2xx)**
      reads an object owned by a different, small set of consumers and never
      accessed by it. Evaluated after the response so a backend 4xx (authorization
      enforced) is correctly NOT flagged — the one-object leak that enumeration and
      signature WAFs miss. **Confirmed ownership**: with `owner_fields` set, the
      object's true owner is read from the response body and compared to the
      authenticated subject (heuristic warning → confirmed critical), and that
      binding (`store.SetObjectOwner`/`GetObjectOwner`) lets `object_ownership_block`
      **deny a known cross-owner access before forwarding** — preventing the leak,
      not just recording it; `ownership_bypass_roles` exempt support/admin. With an
      allowlist for known high-cardinality callers and explainable `why` on every event.
- [~] **SIEM integration** (Splunk / Elastic) and **alerting** (Slack / PagerDuty)
      with configurable webhooks. Done: `alerting` config block (webhook URL,
      `generic`/`slack` payload format, `min_severity` gate); `AEGIS_ALERT_WEBHOOK_URL`
      env override. Remaining: per-rule routing, ticketing (Jira/ServiceNow).
- [x] **Native Prometheus exposition** of the AEGIS counters (`GET /metrics`,
      text format 0.0.4, behind the admin bearer; scrape config in `prometheus.yml`).
- [x] **OpenAPI / spec drift**: import an OpenAPI 3.x / Swagger 2.0 spec (config
      `discovery.spec_path` fallback or per-tenant `PUT /api/discovery/spec`) and
      compare documented vs observed. `GET /api/discovery/drift` reports
      **undocumented** endpoints (observed, not in spec — OWASP API9) and
      **zombie** operations (documented, never observed); undocumented endpoints
      also surface as `undocumented_endpoint`/`undocumented_method` findings on
      the catalog. Spec paths are canonicalised to the catalog's `{id}` template
      so documented and observed surfaces compare exactly. Parser is dependency
      -free (yaml.v3, which also reads JSON). Per-tenant spec stored in PG with
      RLS; validated on the home-server containers.
- [~] **Schema enforcement (positive security)**: beyond reporting drift, actively
      validate requests against the documented contract (`security.schema`,
      `middleware.SchemaValidation`). The parser captures each operation's request
      schema (params + JSON body, `$ref`-resolved); the validator flags missing/
      mistyped/out-of-enum query params and JSON body fields, and — the
      anti mass-assignment lever — rejects undocumented body fields when the schema
      sets `additionalProperties:false` (OWASP API6). Monitor mode records, block
      mode returns a machine-readable 422. Contract source in v1 is the config-level
      spec (`discovery.spec_path`); remaining: enforce per-tenant uploaded specs,
      path/header params, formats/bounds.

### P2
- [~] **Admin audit log** (enterprise/compliance table-stake). Done: `internal/audit`
      persists every control-plane action (login/login_failed/logout/mutation/
      `denied:<reason>`) to PostgreSQL via an async best-effort writer that never
      blocks the admin request path; entries carry actor/role/super-admin/tenant/
      method/path/status/ip. `AdminAuth` records; `GET /api/audit` reads,
      tenant-scoped (super-admin spans all with `?all=true`). Remaining:
      retention/rollup, data-residency, export, and an RLS policy on
      `admin_audit_log` (today it is application-scoped only).
- [x] **Multi-tenancy** (organisations, per-tenant data isolation). Closed
      end-to-end across all 6 phases of ADR-001 (`docs/design/multitenancy.md`):
      `TenantResolve` ingress (route+host, strips `X-Tenant-*`); PostgreSQL
      isolation (`tenant_id` + composite PKs on all catalog/forensic tables,
      `WHERE tenant_id` everywhere, RLS `FORCE`+policy via `set_config` GUC as a
      fail-closed backstop); Redis isolation (`tkey(ctx)` → `gw:t:<tenant>:*` on
      every key family); console sessions pinned to a tenant + RBAC (admin/viewer)
      in `internal/iam`; tenant + user CRUD (`/api/tenants`, `/api/users`) with
      super-admin scoping; cross-tenant deny tests against live PG/Redis, plus a
      multi-tenant k6 load run (overhead in the noise) and `docs/runbooks/ha.md`.
- [~] Anomaly detection / behavioural baselines per consumer. Done: per-consumer
      EWMA baseline for BOLA enumeration (`store.TrackBaseline`, A2). Remaining:
      volume/time/geo/error-rate profiles, sequence anomaly, peer-group.
- [~] **Data retention.** Background sweep (`internal/retention`) deletes rows
      older than a configured per-table window from the tables that grow
      unbounded with traffic — `forensic_logs`, `admin_audit_log`, and the
      consumer graph (`api_consumers` / `api_endpoint_consumers` + orphan
      cleanup). The endpoint catalog is left intact (bounded by normalisation).
      One maintenance transaction spans all tenants via the RLS `app.tenant_id='*'`
      escape hatch. Config: `retention` (interval + `forensic_days` / `audit_days`
      / `consumer_idle_days`; 0 keeps a table forever). Remaining: rollup of aged
      rows into summaries, backups/PITR (ops), batching for very large deletes.
- [ ] Out-of-band deployment (traffic mirroring) in addition to inline.
- [ ] Compliance report templates (PCI-DSS, HIPAA, GDPR).
- [~] **Licensing / metering.** Done: repo relicensed MIT → **BUSL 1.1**
      (`LICENSE`) — production use now requires a commercial license or
      written agreement, converting to Apache 2.0 four years after each
      release. `internal/license` + offline `cmd/licensegen` issue signed
      Ed25519 license files (licensee/tier/expiry/features/max_rps/hardware_id);
      the gateway verifies on boot and every hot-reload as a **hard gate** —
      missing/expired/tampered/wrong-hardware license gets the same treatment
      as any other `config.Validate` rejection (boot refuses to start; a
      hot-reload is rejected and the previous config keeps serving). No free
      degraded mode: an unlicensed copy does not run at all, so it can't give
      away discovery/posture/findings for free. **Node-locking**: `gateway
      -print-fingerprint` derives a deterministic fingerprint from the
      machine's network hardware (SHA-256 of non-loopback MAC addresses); the
      customer reports it before issuance, `licensegen -hardware-id` binds the
      license to it. A hardware change doesn't hard-fail immediately: the
      first time a mismatch is seen it grants a persisted 72h grace window
      (`license.LoadWithGrace`/`DefaultHardwareGrace`) — fully functional,
      loud `WARN` in logs and in the console banner — then hard-fails once the
      window elapses if not re-issued. See `docs/licensing.md` for the
      workflow and the Docker/k8s container-MAC caveat. **`GET /api/license`
      + console banner**: `Server.SetLicenseStatus` records the outcome from
      every boot/hot-reload; the console (`LicenseBanner.tsx`) polls it and
      shows nothing when healthy, a warning ~14 days before expiry, and a hard
      warning during a hardware-grace window or an invalid status — so an
      operator doesn't have to read gateway logs to know. **Self-service
      reissuance** (`cmd/licenseserver`): a standalone HTTP service with the
      private key held in memory (a deliberate, documented change in exposure
      from the fully-offline `licensegen` flow — see `docs/licensing.md`'s
      explicit deployment guidance) automates the "hardware changed, same
      term" case via `POST /reissue`: verifies the old license's signature,
      rejects an already-expired term (`402`, no free extension), carries
      every other claim over unchanged, re-signs for the new fingerprint.
      Per-IP rate-limited. **Tier/feature/RPS entitlement now enforced**:
      `trial`/`pilot` tiers force `Observe` regardless of the operator's own
      config (`Claims.RequiresObserve`); `Claims.Features` gates
      `multitenancy`/`oidc` — enabling either without the matching feature is
      a hard boot/reload rejection (`license.CheckFeatureGates`), empty
      `Features` stays fully permissive for backward compatibility;
      `Claims.MaxRPS` is a real global throughput ceiling
      (`middleware.LicenseRateLimit`, fails open on a store error — a
      commercial constraint, not a security control). Remaining: real usage
      metering (billing-grade consumption tracking), revocation (for both the
      offline and the `licenseserver` key).

---

## Pillar 3 — Works excellently

### P0 — release blockers
- [x] **Test coverage.** Regression tests for every recent security fix
      (JA3 spoof, IP-guard/rate-limit fail-closed, identity signature/replay).
      A CI coverage gate (`scripts/coverage-gate.sh`, wired into `test.yml`)
      enforces per-package floors that ratchet toward the >= 70% target — now met
      on **every critical package**. Current (against the live Redis+PostgreSQL
      stand): tenant/tlsfp 100%, classify 93%, gatewayverify 93%, proxy 92%,
      config 90%, gateway 87%, sso 88%, store 85%, discovery 84%, iam 82%,
      middleware 82%, retention 81%, audit 80%, **api 76%** (the catalog/posture
      handlers are now exercised through a seeded live catalog, plus requireAuth
      and the store error paths). The `api` floor was ratcheted 60→70.
      **Gap found in this audit pass, not previously flagged:** `internal/forensic`
      (the PostgreSQL forensic-log sink, 279 lines, wired from `cmd/gateway/main.go`)
      has **zero test files** and no entry in `scripts/coverage-gate.sh` — it sits
      outside the "every critical package" claim above rather than meeting it.
      Needs an integration test against `pgtest` before this bullet can honestly
      say "every critical package."
- [~] **Load and latency benchmarks.** k6 scripts + guide under `tests/load/`
      (single-tenant + multi-tenant + attack-mix scenarios, CI-able
      thresholds). First on-hardware run in `tests/load/results-2026-06-21.md`:
      single-tenant 373.6 RPS / p50 33.5 ms, multi-tenant 375.7 RPS / p50
      34 ms (MT overhead in the noise), attack-mix p50 7.9 ms (WAF rejects
      early). **VU sweep (10/50/100/200) + WAF on/off split** run on the NUC
      (`tests/load/capacity-sweep-2026-07-31.md`): WAF overhead is small and
      flat at moderate load (~5–7% throughput, few ms latency). Honest finding,
      not hidden: the first sweep hit the shared demo backend's ceiling
      (~400–450 req/s, flat across VU counts) before AEGIS's own — at 200 VUs
      with WAF off the backend saturated and the circuit breaker opened (no
      second upstream configured), correct behaviour but not an AEGIS number.
      Re-run same day against a purpose-built no-op Go backend: throughput rose
      to 630–890 req/s, confirming the earlier ceiling was the backend — but
      the NUC's `load average` hit 16.9 on 4 cores (shared with ~30 other
      always-on services), which shows up as non-monotonic, sometimes-inverted
      results (WAF-off slower than WAF-on at 200 VUs). Re-ran a third time with
      the NUC's other ~30 containers stopped for the run (`load average` ~1
      before starting, all restarted + verified healthy after): throughput
      landed in the same 600–1000 req/s band, confirming that band is AEGIS's
      own signal, not third-party noise; errors first appear at 100+ VUs on
      both WAF-on/off — the honest onset of this box's ceiling. **Still open:
      no *production-grade* max-RPS number exists** — this is a 2015
      ultra-low-voltage 4-core laptop chip; read 600–900 req/s as "AEGIS's
      floor on weak hardware," not its ceiling. Needs dedicated/cloud
      server-grade hardware with a wired client for a number worth publishing
      to a prospective partner.
- [~] **Graceful failure under load.** Redis-outage behaviour verified two ways:
      (1) end-to-end unit matrix in `internal/middleware/degradation_test.go`
      (fail_closed → 503, default → 200, static blacklist still enforced, no
      panics) against a killed Redis; (2) **on-hardware sustained-traffic run**
      with Redis killed mid-test (`tests/load/redis-outage-results-2026-06-26.md`):
      at 50 rps, during a full Redis outage the gateway kept **100% success**
      (fail-open) with **p99 864 ms / max 1.30 s** — bounded by the fail-fast
      Redis timeouts (dial 1s / read-write 500ms / 1 retry), vs the 3–9 s hangs
      the go-redis defaults would cause; latency snapped back to p99 42 ms on
      recovery. **PostgreSQL-outage under load** now covered on a live stand
      (`tests/load/reliability-results-2026-07-08.md`): at 100 rps with PG killed
      mid-run the data plane held **100% success with flat latency** (p99 11 ms
      through the outage) — the async catalog/forensic path is decoupled from
      proxied traffic; the admin catalog read degrades and self-recovers. **Rolling
      -update drain** covered in the same run: **zero 5xx** during `Shutdown`, and
      a new lame-duck grace (`shutdown_drain`: `/readyz` → 503 → serve → drain →
      stop) turns a post-SIGTERM burst of connection errors into zero-downtime
      rollouts behind a readiness-gated LB (601/1200 drain-window requests now
      succeed vs 0 before). Regression: `internal/api` readyz-draining tests.
      Admin read handlers now return **503** (not 500) when the backing store is
      unreachable, so clients/LBs back off correctly (`storeUnavailable`
      classifier, `TestStoreUnavailable_Classifies`). Still to do: capacity sweep
      for published max-RPS (needs dedicated hardware, not Docker Desktop).

### P1
- [x] High-availability guide (`docs/runbooks/ha.md`): topology (Sentinel + PG
      streaming replication), per-failure-mode matrix (fail-open vs
      fail-closed per control), RLS rolling-deploy notes, bring-up checklist.
      Sentinel client implemented: `redis.UniversalOptions{MasterName, Addrs}`
      via `store.NewWithConfig` + `config.RedisConfig.Sentinel`; AEGIS code
      is mode-agnostic (the client handles failover).
- [~] Capacity-planning guidance with **rule-of-thumb** sizing (in `ha.md`);
      concrete numbers pending the benchmark run on reference hardware.
- [x] End-to-end smoke test in CI (start gateway + Redis + PG, drive traffic,
      assert catalog and posture populate). `.github/workflows/e2e-smoke.yml`
      boots the gateway against real Redis + PostgreSQL + an echo upstream, drives
      traffic, and asserts the discovery catalog (`/api/catalog`) and posture
      summary (`/api/posture/summary`) populate with normalised `{id}` templates.
      Validated end-to-end on a Linux Docker host.

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
