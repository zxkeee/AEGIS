# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

AEGIS is an API Security Gateway written in Go: a reverse proxy that runs every
request through a chain of security middleware (WAF, rate limiting, JWT auth,
IP/bot/behaviour controls, DLP, BOLA/BFLA abuse detection) and passively builds
an API catalog with posture scoring. It targets the API-security product space
(Salt / Noname / Akamai). See `ROADMAP.md` and `RELEASE-CHECKLIST.md` for the
path to 1.0 — both are kept current and are the source of truth for what is done
vs. open.

## Commands

```bash
make build           # build ./cmd/gateway -> bin/gateway
make run             # build + run with config/gateway.yaml
make test            # go test ./... -v -race
make lint            # golangci-lint run ./...
make fmt             # go fmt + goimports

go test ./internal/middleware/ -run TestRateLimit_FailClosed -v   # single test
go test ./... -cover                                              # coverage
./scripts/coverage-gate.sh                                        # enforce per-package coverage floors
```

Go toolchain is pinned in `go.mod` (CI installs gosec/golangci-lint/govulncheck
from source against it). CI runs three workflows: `test.yml` (race + coverage +
the coverage gate), `lint.yml` (golangci-lint), `security.yml` (gosec +
govulncheck).

### Integration tests

Tests that need real backing stores **skip unless env vars are set** (so the
default `go test ./...` runs everywhere). In CI the `test.yml` job provides them
via service containers:

```bash
REDIS_ADDR=host:6379 \
POSTGRES_DSN='postgres://aegis:aegis@host:5432/aegis?sslmode=disable' \
go test ./internal/store/ ./internal/discovery/ -v
```

`internal/store` (Redis) and `internal/discovery` (PostgreSQL catalog) have such
tests; the discovery PG tests `TRUNCATE` the catalog tables for determinism.

**PostgreSQL test isolation.** `go test ./...` runs packages in parallel against
the one shared database, so a package that `TRUNCATE`s a table would wipe
another package's rows mid-test. Every PG integration test gets its DSN from
`pgtest.DSN(t, "<schema>")` (`internal/pgtest`), which routes that package into
its own schema via `search_path` and drops/recreates it per run. New PG tests
MUST use it (never read `POSTGRES_DSN` directly) and pick a unique schema name.

## Architecture

### Two servers, one process (`cmd/gateway/main.go`)

- **Gateway server** (`listen`, default `:8080`) — the data plane: the security
  middleware chain wrapping the reverse proxy.
- **Admin API server** (`admin_listen`, default `:8081`) — control plane:
  dashboard (`/`), health/readiness, metrics, the discovery catalog/consumers/
  posture/report endpoints, IP and JWT management. Wrapped by `AdminAuth`
  (bearer token for API/CLI, HttpOnly session cookie + CSRF for the console).

Config is **hot-reloaded**: `watchConfigFile` rebuilds the handler chain on file
change and swaps it atomically via `atomic.Value`; in-flight requests keep the
old chain.

### Middleware chain — order is load-bearing

`BuildHandlerChain` (via `chainSteps`) in `internal/gateway/chain.go` assembles
the chain; the **first listed is outermost**. The ordering is deliberate (e.g.
`TenantResolve` must run first; `CleanHeaders` strips spoofed identity before
anything trusts it; `Discovery` sits inside auth/DLP so it can enrich the
observation with identity and PII signals, and outside the proxy so it captures
the final status). Read
that function before reordering anything. Each middleware lives in
`internal/middleware/` and is a `func(http.Handler) http.Handler`; disabled
features return `passthrough`.

### State backends

- **Redis** (`internal/store`) — rate-limit windows, IP blocklists, behaviour
  scores, JA3 sets, BOLA counters, challenges, JTI revocations, admin sessions,
  metrics, and a recent forensic ring buffer. Most keys carry TTLs.
- **PostgreSQL** (`internal/forensic` = forensic logs; `internal/discovery` =
  the API catalog) — enabled only when `forensic_dsn` is set; the catalog and
  forensic sink share that one database. Without a DSN the catalog is nil and
  the Discovery middleware degrades to passthrough.

### Passive discovery (`internal/discovery`)

The `Discovery` middleware emits an `Observation` per request; the `Catalog`
worker aggregates observations in-memory per 5s window and flushes rolled-up
deltas to PostgreSQL (`upsert*` with `ON CONFLICT` accumulation). Paths are
normalised (`/users/42` -> `/users/{id}`) by `normalize.go`; `posture.go`
classifies each endpoint (protected/partial/unprotected/shadow) and scores risk.
Reads for the admin API are served from PostgreSQL.

### Multi-tenancy (ADR-001 — `docs/design/multitenancy.md`)

Hard data isolation between organisations, resolved at ingress and threaded
through `context.Context`:

- `internal/tenant` is a **leaf package** (`tenant.With` / `tenant.From`,
  default `"default"`) imported by every layer to avoid import cycles. Read the
  tenant from `ctx`, never thread it through signatures by hand.
- `middleware.TenantResolve` (outermost) maps a request to a tenant by route
  `tenant_id` (authoritative) and/or Host, rejects mismatch/unresolved with 404,
  and strips client-supplied `X-Tenant-*`.
- **Redis** keys are scoped by `tkey(ctx, suffix)` -> `gw:t:<tenant>:<suffix>`.
- **PostgreSQL** tables carry `tenant_id` (composite primary keys); every query
  filters by it. Schema migrations are idempotent with a `default` backfill.
- When `multitenancy.enabled: false`, everything runs as the `default` tenant
  (legacy single-tenant behaviour). Phases 4–6 (admin/session scoping, tenant
  CRUD, RLS) are still open — see the ADR's implementation plan.

### Identity propagation (`sdk/gatewayverify`)

After JWT auth, the gateway signs the forwarded identity:
`HMAC-SHA256(secret, "sub:roles:scopes:ts:nonce")` in `X-Gateway-Signature`
(set in `middleware/jwt.go`). Backends verify authenticity + timestamp freshness
+ nonce replay using the reference SDK in `sdk/gatewayverify`. `CleanHeaders`
strips inbound `X-Gateway-*` so clients can never forge it.

### TLS fingerprinting (`internal/tlsfp`)

When the gateway terminates TLS, a JA3-style fingerprint is computed from the
ClientHello and bound to the connection (via `Server.ConnContext`/`ConnState`),
then injected as the internal `X-JA3-Fingerprint` (the spoofable inbound header
is always stripped). Behind a TLS-terminating upstream (e.g. Cloudflare) the
gateway sees no handshake; `bot.trust_upstream_ja3` opts into trusting an
upstream-supplied JA3 header, but **only from a `trusted_proxies` peer**.

## Conventions

- **Secrets come from the environment**, never config files: `AEGIS_ADMIN_SECRET`,
  `AEGIS_REDIS_PASSWORD`, `AEGIS_REDIS_SENTINEL_PASSWORD`, `AEGIS_JWT_SECRET`,
  `AEGIS_PROPAGATION_SECRET`, `AEGIS_FORENSIC_DSN`, `AEGIS_OIDC_CLIENT_ID`,
  `AEGIS_OIDC_CLIENT_SECRET`, `AEGIS_ALERT_WEBHOOK_URL` (`applyEnvOverrides` in
  `internal/config`). `config.Validate` rejects insecure placeholder secrets,
  short admin secrets, and inconsistent TLS/CORS/tenant settings — run it
  mentally when adding config. (`web/server.go` — a separate `aegis-site`
  marketing binary, not the gateway — has its own unrelated `SMTP_USER`/
  `SMTP_PASS`/`MAIL_TO` env vars; out of scope for this list.)
- **`fail_closed`** is an opt-in per control (rate limit, IP guard): on a Redis
  outage, deny instead of failing open. Behavioural scoring intentionally stays
  fail-open (a scoring gap beats blocking all traffic).
- **Coverage gate** (`scripts/coverage-gate.sh`, wired into CI) enforces
  per-package floors that ratchet toward 70%. When you raise real coverage, raise
  the floor; never lower it.
- The middleware `Store`/`Logger`/`Catalog`/`RegistryProvider` interfaces live in
  `internal/middleware/ports.go`; tests use the fakes in `fakes_test.go`.
- RealIP trusts `X-Forwarded-For` only from `trusted_proxies` (right-to-left
  walk). Misconfiguring `trusted_proxies` breaks every per-IP control.



Оспаривай мои решения. Если подход плохой - скажи прямо. Не соглашайся просто потому что я попросил.
Каждый ответ структурируй: что сделано, что нужно от меня и какой следующий шаг.
После каждой задачи предлагай что улучшить и автоматизировать.
Все что можешь делать ты - делай ты, твоя главная задача качественно выполнять работу и освободить мое время.