# AEGIS — Release Readiness Checklist (v1.0 Gate)

This document defines the gate that must be cleared before AEGIS is released as a
commercial product. The goal is a release that is (1) free of known security
holes, (2) competitive in the API-security market, and (3) demonstrably reliable.

Do not ship v1.0 until every **P0** item is checked. **P1** items are required to
be competitive; **P2** items are post-launch improvements.

Legend: `[ ]` open · `[x]` done · `[~]` partially done

Positioning belongs to [`docs/PRODUCT.md`](./docs/PRODUCT.md) and implementation
status to [`ROADMAP.md`](./ROADMAP.md); this file answers only "may we ship
v1.0". Reviewed 2026-09-15 against the code — it had drifted four PRs behind,
and the drift was in the direction that flatters: work that had shipped was
still listed as open, and a whole third of the product (Prove) was not gated on
at all.

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
- [x] **Outbound fetch safety (`internal/safefetch`).** Supersedes the earlier
      redirect-only fix, which checked the host STRING in the URL. That could not
      be the control: `https://127.1/`, `https://2130706433/`,
      `https://0x7f.0.0.1/` and `https://localhost./` all passed it and then
      connected to loopback anyway, because the resolver accepts forms
      `net.ParseIP` rejects and the resolver decides where the connection goes —
      as does any DNS name with a private A record, for which anyone can obtain a
      genuine certificate. The decision now happens in `net.Dialer.Control`,
      after resolution, against the address actually dialled: that closes the
      numeric forms, the trailing dot, DNS names and DNS rebinding in one place,
      and covers the FIRST request as well as redirects — the URL an operator
      configured had never been checked at all. `safefetch.Client` is the only
      way to build one of these clients and has no opt-out. Guards the JWKS
      document (the trust root for every RSA/ECDSA token), the threat feed and
      the alert webhook.
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
      nonce uniqueness (HMAC over `gatewayverify.CanonicalPayload`), with an
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
- [~] **SIEM integration** (Splunk / Elastic) — **done**, `docs/siem.md`:
      Splunk HEC with its own envelope (numeric epoch `time`, which is what HEC
      requires) and Elasticsearch in ECS field names, so events land in
      dashboards that already exist. Each sink carries its own severity
      threshold, because a SIEM wants everything while on-call wants criticals
      and one shared threshold is wrong for one of them in every deployment.
      Collector tokens come from the environment and are refused at startup when
      missing for Splunk — the collector rejects untokenised events at the far
      end, so the gateway would log deliveries while the SIEM held nothing.
      Delivery is concurrent and off the request path; there is no retry queue,
      so a collector outage is a gap in the SIEM's copy and not in the forensic
      log. `allow_private` per sink reaches a collector on the internal network
      while loopback, link-local (cloud metadata) and multicast stay refused.
      **Ticketing is done too** (`docs/ticketing.md`): one ticket per
      INCIDENT rather than per event, which is the difference between an
      integration that survives its first week and one that files a thousand
      tickets for one campaign. Jira and ServiceNow, filed by a sweep rather
      than a callback so a slow tracker never becomes a slow gateway and an
      outage delays filing instead of dropping it. Duplicates are handled by
      searching the tracker for a deterministic correlation key before
      creating, so a ticket left by a crashed run is adopted; the honest
      guarantee is at-least-once deduplicated on the tracker side, and the
      remaining window is documented rather than glossed. The reference lives
      in its own table, because adding a column to `incidents` would either
      leave a field of the evidence table uncommitted to or make every existing
      incident read as altered after an upgrade.
      Remaining under this heading: SOAR, per-rule routing. Original entry follows —
      **alerting** (Slack / PagerDuty)
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
- [x] **Out-of-band deployment (traffic mirroring) in addition to inline.**
      `mirror_sink: true` turns the gateway into a terminal sink: the customer's
      load balancer sends a copy of each request, AEGIS drains the body, builds
      its catalog and answers 204, forwarding nothing. Their traffic never passes
      through this process, so it can be stopped mid-pilot with nothing changing
      — which is the objection that ends most first deployments. Refused without
      `observe: true` (a control that "blocks" a copy stops nothing and would
      record a denial that never happened) and refused with `tls.enabled` (the
      mirroring proxy already terminated TLS, so the JA3 would describe this
      process, not the caller). Honest by construction: a copy carries no
      response, so observations are marked `RequestOnly` and the catalog counts
      `responsesSeen` separately — a zero `pii_count` reads as "responses were
      never examined", not "nothing was found". `docs/mirror-mode.md`.
- [ ] Compliance report templates (PCI-DSS, HIPAA, GDPR).

#### Prove — the evidence layer

This block did not exist until 2026-09-15, which was itself the problem:
`docs/PRODUCT.md` names Prove as one of the three stages of the product, several
sessions of work went into it, and the release gate did not mention it at all.
A gate that ignores a third of the product cannot say whether that third is
shippable.

- [~] **Regulatory mapping.** Findings and runtime abuse map onto NIS2
      Art. 21(2), DORA Art. 8/9/10 and 17–19, and ISO/IEC 27001:2022 Annex A via
      the OWASP API Top-10; `GET /api/compliance` + console tab. The report names
      what it does NOT evidence (`not_evidenced`), and DORA Art. 10(1) counts
      only observed events — a static finding says an endpoint *can* be abused,
      not that detection fired. Remaining: PCI-DSS/HIPAA/GDPR templates (above),
      PDF/CSV export.
- [~] **Incident register.** `internal/incident` correlates events into
      incidents by verified caller identity (not address — a changing address
      would shatter one campaign into hundreds of incidents), tracks
      open→contained→closed, NIS2 Art. 23(4) deadlines measured from submission
      rather than detection, DORA Art. 18 classification, and an append-only
      notification history. Closing an incident does not clear a missed deadline.
      Remaining: console page, export.
- [~] **Signed reports.** `GET /api/report?sign=1` and `/api/compliance?sign=1`
      return `{document, attestation}` with an Ed25519 signature over
      `aegis-attest-v1\n<signed_at>\n<document>` on a dedicated key
      (`AEGIS_REPORT_SIGNING_KEY`; reusing another secret is refused in
      `config.Validate`). `cmd/reportverify` is standalone and refuses to run
      against a key taken from the document it is checking. `format=csv&sign=1`
      and a missing key return 400 rather than a silently unsigned document.
- [~] **Log integrity (tamper-evidence).** Hourly Merkle root per period, each
      seal committing to its predecessor, plus a gapless `seq` and a signed
      per-tenant chain head — so deleting entries inside a sealed period and
      removing whole seals from the end of the chain are both detectable.
      `docs/forensic-seals.md`.
- [x] **Seal verification has an entry point.** Was a release blocker:
      `VerifySeals` had no production caller at all — no admin endpoint, no
      `reportverify` command — so the only way to ask whether the log had been
      tampered with was to write Go against the database, and a detection nobody
      can invoke detects nothing. `GET /api/forensic/seals` now recomputes every
      seal for the caller's tenant and returns the per-period results with the
      chain-level answer; `?sign=1` returns a signed envelope `cmd/reportverify`
      verifies against an out-of-band key, which is what makes it an artifact to
      hand over rather than a page to look at. The document carries its own
      `limits` field **inside the signed body** — a verification result is
      exactly the artifact a reader over-interprets, so the limits travel with
      it. Remaining (not blocking): a console page.
- [~] **The data feeding a signed document has no integrity protection.**
      Half done, and the half that is done is the one that fed the signed report.
      `incidents` now keeps an append-only ledger (`incident_ledger`): every
      write records the digest of the incident's state in the same transaction,
      each row is chained to the one before it, and
      `GET /api/incidents/ledger?sign=1` recomputes the register against it —
      naming deleted incidents, edited ones, incidents with no ledger entry, and
      broken chain positions. The seal mechanism could not be reused unchanged:
      a Merkle root over a period assumes rows never change, and an incident's
      whole point is a lifecycle, so a period root would fail on the first
      legitimate status transition.
      Remaining, and neither is closed by the above: **the ledger has no signed
      head**, so deleting an incident together with every ledger row that
      mentions it is still undetected (the forensic chain solved the same
      problem with a signed head; the shape transfers). And **`admin_audit_log`
      still has neither integrity protection nor RLS** — the insider trail
      `docs/ARCHITECTURE.md` names as the mitigation for the operator threat.
- [ ] **No independent witness, and this must never be overstated.** The signing
      key is held by the party being audited, so a signature proves "this
      document was not altered after it was produced" and not "it was not
      assembled from tidied-up data". An external anchor (RFC 3161, a
      transparency log) is not shipped. Ship only the word tamper-**evident**;
      never tamper-proof. Not a release blocker — an honesty blocker, and the
      wording is the deliverable.
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
- [x] **The test suite exercises row-level security.** CI connected to
      PostgreSQL as the service container's superuser, which ignores RLS
      entirely — so every tenant-isolation policy was dead code for the whole
      run, and a query that forgot its tenant filter passed exactly like one
      that did not. Measured, not assumed: two mutations that removed real
      protections in the seal chain stayed GREEN under a superuser and went red
      immediately under an ordinary role. The mirror image was as bad — the five
      tests that build their own restricted role were the only RLS assertions
      running, and pointing `POSTGRES_DSN` at an unprivileged role made all five
      SKIP, so the stronger environment proved strictly less than the weaker one.
      `POSTGRES_APP_DSN` now names an unprivileged role that ordinary tests
      connect as; the few that must `CREATE ROLE` ask for `pgtest.AdminDSN`
      explicitly; those five run in both modes and their skips are fatals. Both
      `pgtest` and the CI step refuse a role that can bypass RLS, because a
      silently privileged "unprivileged" role is how this returns.
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
- [~] **Load and latency benchmarks.** **The per-request cost is now measured**
      (`tests/load/overhead-results-2026-09-23.md`): observe mode adds
      +1.1…+1.6 ms at p50, full enforcement +1.8…+2.7 ms, three runs each,
      reported as a range because two identical runs differed by 0.9 ms. That
      question was unanswerable before: every earlier run went over Wi-Fi, whose
      jitter is an order of magnitude larger than the thing being measured. The
      new harness (`tests/load/overhead.sh`) puts client, gateway and upstream
      on loopback and runs a direct control scenario that cancels everything
      but the gateway. It is explicitly not a capacity benchmark and not what a
      remote client sees. Below, the throughput work, which answers a different
      question:
      k6 scripts + guide under `tests/load/`
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

Revised 2026-09-15. The first three steps of the previous version were done and
still written as upcoming, which is how a checklist stops being read.

1. ~~Tests~~ ✅ — coverage gate in CI with per-package floors, and the suite now
   runs under a role that cannot bypass RLS (Pillar 3 P0).
2. ~~Console authentication~~ ✅ — sessions, RBAC, OIDC SSO.
3. ~~BOLA/BFLA detection~~ ✅ — confirmed object ownership from the response
   body, proactive block before forward.
4. **Seal verification entry point** — half a day, and it is a release blocker:
   the integrity claim currently cannot be exercised by anyone who is not
   writing Go.
5. **Benchmarks (P3)** — the one open item a *sales conversation* needs rather
   than a customer. "Plus N ms" answers half the objections on a call; the
   present numbers are noise off a Wi-Fi link.
6. **SIEM/alerting** — the webhook exists and is validated; Splunk/Elastic
   export and routing do not.
7. **HA hardening** — Redis Sentinel/Cluster and PostgreSQL failover.

Ordering note: steps 4–7 are listed by what unblocks a deal, not by what is
technically interesting — the same rule `ROADMAP.md` now uses. And the honest
caveat that belongs on any release gate: nothing here is validated by a customer,
because there has not been one. A checklist proves the product is shippable, not
that it should be shipped.
