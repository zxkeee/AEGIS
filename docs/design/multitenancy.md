# ADR-001 — Multi-tenancy (tenant resolution & data isolation)

| | |
|---|---|
| **Status** | Accepted |
| **Date** | 2026-06-15 |
| **Roadmap item** | P0-3 (release blocker) · Phase E1 |
| **Deciders** | AEGIS Team |
| **Supersedes** | — |

## Context

AEGIS is currently **single-tenant**. Every piece of state is global:

- **PostgreSQL** — five tables with no tenant column: `api_endpoints`,
  `api_endpoint_status`, `api_consumers`, `api_endpoint_consumers`
  (`internal/discovery/store_pg.go`) and `forensic_logs`
  (`internal/forensic/pg_sink.go`).
- **Redis** — a flat `gw:*` key namespace (`internal/store/redis.go`): rate-limit
  windows, blocklists, behaviour scores, JA3 sets, BOLA counters, challenges,
  JTI revocations, console **sessions**, metrics.
- **Admin console** — sessions carry no organisation; every admin endpoint
  (`/api/catalog`, `/api/consumers`, `/api/posture/summary`, `/api/report`,
  `/api/block-log`, `/api/blocked-ips`, `/api/metrics`) returns **all** data
  globally.

To sell into enterprise (and to host more than one customer on one deployment)
we need organisations with hard data isolation: tenant A must never be able to
observe or affect tenant B's catalog, consumers, forensic logs, blocklists or
metrics.

The pivotal decision is **how an incoming request maps to a tenant**, because
that choice propagates into every storage signature and middleware.

## Decision

Adopt a **two-source tenant resolution model, "B + A"**, resolved once at
ingress and threaded through `context.Context`:

- **B — route-scoped (primary, authoritative).** Each `RouteConfig` carries a
  `tenant_id`. The tenant is a property of the matched route. This reuses the
  existing routing layer and is known *before* auth, so it is available to the
  earliest controls (IP-guard, rate-limit).
- **A — host/SNI (secondary, convenience).** A `tenants[].hosts` map lets a
  request resolve by `Host`/SNI when that is operationally cleaner (one vhost
  per tenant). Host resolution must agree with the route's `tenant_id`; on
  conflict the request is **rejected**, never silently coerced.

Resolution order: match host → if it yields a tenant, use it; then match the
route → its `tenant_id` must equal the host-derived tenant (if any). If neither
yields a tenant, **reject** (`404`) — there is no implicit "default" tenant in
production (a `default` tenant exists only for migration backfill and
single-tenant local dev, gated by `multitenancy.enabled`).

Rejected alternatives:

- **C — tenant from API key / JWT issuer.** Tenant would be unknown until after
  authentication, too late for IP-guard and rate-limiting, which must be
  tenant-scoped to prevent one tenant exhausting another's limits. Kept as a
  *future* enrichment, not the resolver.
- **D — one process per tenant.** Zero cross-tenant code risk, but it is not
  real multi-tenancy: no shared control plane, N× operational cost, and it does
  not satisfy "organisations on one deployment". Still supported as a deployment
  *option* for the highest-isolation customers.

## Architecture

### Tenant resolution (ingress)

A new **outermost** middleware `TenantResolve()` runs before everything
(including `CleanHeaders`):

```
TenantResolve → CleanHeaders → TLSFingerprint → SecurityHeaders → … → proxy
```

- Strips any client-supplied `X-Tenant-*` header (spoof defence, same pattern as
  `X-Gateway-*` / `X-JA3-Fingerprint`).
- Resolves tenant via host map, then validates against the matched route's
  `tenant_id`.
- Stores the tenant on the request context; exposes `middleware.TenantID(ctx)`.
- Unknown/ambiguous tenant ⇒ `404` (no information leak about which tenants
  exist) and a `tenant_unresolved` metric.

Config shape:

```yaml
multitenancy:
  enabled: true            # false → legacy single-tenant ("default")
  tenants:
    - id: acme
      name: "ACME Corp"
      hosts: ["acme.api.example", "acme.internal"]
    - id: globex
      name: "Globex"
      hosts: ["globex.api.example"]
routes:
  - path: /orders
    tenant_id: acme         # NEW: route belongs to a tenant
    upstreams: ["http://orders.acme:8080"]
```

`config.Validate` enforces: every route's `tenant_id` exists in `tenants`; no
host appears under two tenants; `tenant_id` non-empty when `multitenancy.enabled`.

### PostgreSQL isolation

Add `tenant_id TEXT NOT NULL` to all five tables and make it part of every
primary/foreign key:

| Table | New primary key |
|---|---|
| `api_endpoints` | `(tenant_id, id)` |
| `api_endpoint_status` | `(tenant_id, endpoint_id, status)` |
| `api_consumers` | `(tenant_id, id)` |
| `api_endpoint_consumers` | `(tenant_id, endpoint_id, consumer_id)` |
| `forensic_logs` | `tenant_id` column + index |

- Indexes become tenant-leading: `(tenant_id, last_seen DESC)`,
  `(tenant_id, risk_score DESC)`.
- **Every** query in `store_pg.go` and `pg_sink.go` gains `tenant_id` in its
  `INSERT` column list / `WHERE` clause / `ON CONFLICT` target (~10 statements).
- **Defence in depth — PostgreSQL Row-Level Security.** Enable RLS on each table
  with a policy `USING (tenant_id = current_setting('app.tenant_id'))`. The
  store sets `SET LOCAL app.tenant_id = $tenant` at the start of each
  transaction. This makes a forgotten `WHERE` clause fail closed rather than
  leak — the single most important guarantee in this ADR.

### Redis isolation

All keys gain a tenant segment immediately after the `gw:` root:

```
gw:rate:<ip>              →  gw:t:<tenant>:rate:<ip>
gw:blocked_ips            →  gw:t:<tenant>:blocked_ips
gw:behavior:<ip>:*        →  gw:t:<tenant>:behavior:<ip>:*
gw:session:<token>        →  gw:t:<tenant>:session:<token>
gw:bola:<consumer>:<ep>   →  gw:t:<tenant>:bola:<consumer>:<ep>
gw:metrics:<name>         →  gw:t:<tenant>:metrics:<name>
…all ~15 key families
```

Implementation: a thin `scopedStore` wrapper that takes a tenant and prefixes
keys, so callers pass the tenant from context rather than threading it through
every method signature. `GetMetrics` switches its `KEYS gw:metrics:*` scan to
`KEYS gw:t:<tenant>:metrics:*`; `/metrics` exposition gains a `tenant` label.

### Admin console & RBAC

- New tables: `tenants(id, name, created_at)` and
  `admin_users(id, tenant_id, email, role, password_hash, created_at)` with
  `role ∈ {admin, viewer}`. A separate `super_admin` flag (or a reserved
  `system` tenant) owns tenant lifecycle.
- Console sessions store `tenant_id` + `role`. `AdminAuth` resolves them and
  injects both into context.
- Every admin handler filters by the session's `tenant_id`. `viewer` is denied
  on mutating routes (block IP, revoke JWT) in addition to the existing CSRF
  check.
- Tenant lifecycle API (super-admin only): `POST/GET/DELETE /api/admin/tenants`,
  user-to-tenant assignment.

### Migration & backfill

- Schema changes are idempotent: `ALTER TABLE … ADD COLUMN IF NOT EXISTS
  tenant_id TEXT NOT NULL DEFAULT 'default'`, then backfill existing rows to
  `'default'`, then drop the default. Existing single-tenant deployments keep
  working as the `default` tenant until `multitenancy.enabled: true`.
- Redis has no migration: legacy `gw:*` keys are read under the `default` tenant
  prefix going forward; old keys expire naturally (rate/behaviour/challenge all
  have TTLs; blocklists can be re-imported).

## Consequences

**Positive**

- Hard isolation enforced at two layers (explicit `WHERE` + RLS fail-closed).
- Earliest controls (IP-guard, rate-limit) are tenant-scoped — no cross-tenant
  resource exhaustion.
- Reuses existing routing and the `X-*`-stripping pattern; no new infra.
- Backwards compatible via the `default` tenant; single-tenant users unaffected.

**Negative / costs**

- Touches every storage call site (~10 SQL statements, ~15 Redis key families)
  and every admin handler — broad but mechanical.
- RLS + `SET LOCAL` requires all catalog/forensic DB access to run inside a
  transaction that sets the tenant GUC.
- Per-tenant Redis key explosion is fine, but `KEYS` scans must always be
  tenant-scoped (never a global `gw:*` scan) to avoid cross-tenant reads.

**Risks & mitigations**

- *Cross-tenant leak via a forgotten filter* → RLS makes it fail closed;
  mandatory **cross-tenant deny tests** (tenant A cannot read B's endpoints,
  consumers, forensic rows, blocklists, metrics) are the gate's acceptance
  criterion.
- *Host/route disagreement* → reject, never coerce.
- *Index regressions from tenant-leading keys* → re-run `tests/load/` after the
  change and confirm plans use the new composite indexes.

## Implementation plan (sequenced)

1. ✅ **Done.** `TenantResolve` middleware + `TenantID(ctx)`/`WithTenant` +
   config (`multitenancy`, route `tenant_id`) + validation
   (`validateMultitenancy`) + `X-Tenant-*` stripping; wired as the outermost
   gateway middleware. Tested (resolve by route/host, mismatch→404,
   unresolved→404, spoof-strip, longest-prefix). — ~3–4 d
2. ✅ **Done.** PostgreSQL: `tenant_id` on all 5 tables (catalog + forensic),
   composite primary keys, tenant-leading indexes, idempotent migration +
   `default` backfill, every query scoped with `WHERE tenant_id`; tenant
   threaded via the leaf `internal/tenant` package (Observation → aggregation
   → flush; reads from request context). Cross-tenant deny test covers
   endpoints/consumers/posture.

   **2b — RLS backstop**: every catalog/forensic table now has
   `ENABLE ROW LEVEL SECURITY` + `FORCE ROW LEVEL SECURITY` + policy
   `USING/WITH CHECK (tenant_id = current_setting('app.tenant_id', true)
   OR current_setting('app.tenant_id', true) = '*')`. The `FORCE` clause makes
   the policy apply even to the table owner, so a connection that forgets
   `SET LOCAL` sees zero rows instead of all of them — true fail-closed.
   All `pgStore` methods are wrapped in `withTenantTx` which opens a
   transaction and pins `app.tenant_id` via `set_config(..., is_local=true)`
   for the duration. Forensic flush elevates to `'*'` (gateway is the trusted
   source); reads pin to the caller's tenant. Acceptance tests:
   `TestPG_RLS_FailsClosedWithoutGUC` (unscoped SELECT → 0 rows) and
   `TestPG_RLS_RejectsCrossTenantWrite` (INSERT for another tenant rejected
   by `WITH CHECK`). — ~1 wk
3. ✅ **Done.** Redis: every key family is tenant-scoped via `tkey(ctx, …)` →
   `gw:t:<tenant>:<suffix>` (rate, blocked_ips, behavior, ja3, autoban,
   challenge, inventory, params, sessions, bola, jti, metrics, forensic_log);
   `GetMetrics` scans and strips the per-tenant prefix. Cross-tenant Redis deny
   tests (blocklist, metrics, rate-limit, session, forensic) run in CI. — ~3–4 d
4. ✅ **Done.** Console: new `internal/iam` package owns the `tenants` /
   `admin_users` tables + bcrypt password verification + first-boot
   `BootstrapRoot` (env `AEGIS_ROOT_EMAIL`/`AEGIS_ROOT_PASSWORD`). Sessions
   now carry `tenant_id` + role (`admin`/`viewer`) as a JSON payload under a
   flat `gw:session:<token>` key; `AdminAuth` reads the session, pins the
   request to its tenant via `tenant.With(ctx, sess.TenantID)`, and 403s
   mutating requests from viewers (`iam.RoleViewer.CanMutate() == false`).
   Bearer secret is preserved as the bootstrap super-admin (pinned to
   `default`, role admin). Per-tenant handler filtering is automatic because
   the storage layers already key by `tenant.From(ctx)` (phases 2–3).
   Login endpoint accepts `{secret}` (legacy) or `{email,password,tenant}`.
   Cross-tenant deny tests cover both VerifyPassword (wrong tenant ⇒
   `ErrUserNotFound`, no enumeration leak) and AdminAuth (viewer ⇒ 403 on
   mutation, ctx threading verified). — ~1 wk
5. ✅ **Done.** Tenant + user lifecycle API:
   `GET/POST /api/tenants`, `DELETE /api/tenants/{id}` (super-admin only;
   refuses to delete `default`), `GET/POST /api/users`, `DELETE /api/users/{id}`
   (admin in own tenant or any super-admin). `iam.Session.SuperAdmin` is
   threaded into request context (`iam.WithSuperAdmin`/`IsSuperAdmin`);
   `requireSuperAdmin` and `canManageTenant` gates protect the endpoints.
   Ordinary admins are silently coerced to their own tenant on list queries
   (no info leak about other organisations). Bearer secret is implicitly
   super-admin so first-day operations are possible without a UI. 12 RBAC +
   cross-tenant deny tests against live PG. — ~3–4 d
6. 🟡 **Mostly done.** Cross-tenant deny tests are in place across every layer
   (config validation, Redis isolation, PG composite-key isolation, IAM
   password lookup, API tenant/user CRUD, RLS fail-closed). Load
   re-validation: `tests/load/multitenant_load.js` drives mixed-tenant
   traffic with optional attack channel and reports per-tenant p50/p95/p99
   alongside the aggregate; HA topology, failure-mode matrix and capacity
   guidance are documented in `docs/runbooks/ha.md`. **Remaining:** actually
   run the benchmark on reference hardware and publish the numbers
   (gateway-vs-backend overhead, single-tenant vs multi-tenant overhead,
   WAF-on vs WAF-off). — ~3–4 d

**Total ≈ 4–6 weeks** (matches roadmap E1).

## Acceptance criteria (release gate)

- [ ] Catalog, consumers, posture, forensic logs, blocklists and metrics are
      scoped by `tenant_id` end to end.
- [ ] Automated tests prove tenant A cannot read or mutate tenant B's data
      through the gateway **or** the admin API.
- [ ] RLS denies a deliberately tenant-unfiltered query in a test.
- [ ] Unknown/ambiguous tenant is rejected (`404`), with no enumeration of
      existing tenants.
- [ ] Single-tenant deployments keep working as the `default` tenant with
      `multitenancy.enabled: false`.
