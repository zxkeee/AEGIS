# Runbook — High Availability & Scale

AEGIS is a stateless reverse proxy: the gateway process holds no durable state
of its own. Every per-request decision (rate limit, IP block, behaviour score,
session, BOLA counter, forensic event) lives in **Redis** or **PostgreSQL**. The
HA story is therefore "scale the gateway horizontally; make the backing stores
highly available".

This runbook describes the production topology, the failure modes the gateway
already handles, and the configuration knobs that control degradation when a
backing store is unavailable.

---

## Reference topology

```
                  ┌─────────────┐
                  │   Clients   │
                  └──────┬──────┘
                         │ TLS
                  ┌──────▼──────┐
                  │ Cloudflare  │ (or any L7 LB)
                  └──────┬──────┘
                         │ XFF + CF-Connecting-IP
        ┌────────────────┼────────────────┐
        │                │                │
   ┌────▼────┐      ┌────▼────┐      ┌────▼────┐
   │ AEGIS-1 │      │ AEGIS-2 │      │ AEGIS-N │   (N stateless replicas;
   └────┬────┘      └────┬────┘      └────┬────┘    scale by VU traffic)
        │                │                │
        └────────┬───────┴────────┬───────┘
                 │                │
        ┌────────▼───────┐  ┌─────▼─────────────┐
        │ Redis Sentinel │  │  PostgreSQL HA    │
        │ (3 sentinels,  │  │  (1 primary +     │
        │  1 primary +   │  │   ≥ 1 replica,    │
        │  ≥ 1 replica)  │  │   sync repl prefd)│
        └────────────────┘  └───────────────────┘
```

Each AEGIS replica must point at the **Sentinel set** for Redis and the
**primary** (writeable) PostgreSQL endpoint. Use a connection-aware load
balancer (HAProxy/PgBouncer) or DNS+keepalive to expose a stable primary
endpoint that follows failover.

---

## What the gateway already handles

The middleware chain was designed for partial failure of the backing stores.
The relevant defences are summarised here so an operator can reason about what
will happen on the next outage without re-reading the code.

| Failure | Default behaviour | High-assurance flag |
|---|---|---|
| Redis unreachable | rate-limit & ip-guard **fail open** (preserve availability); behaviour score gap; metrics dropped | `security.rate_limit.fail_closed: true`, `security.ip_guard.fail_closed: true` → deny instead |
| PostgreSQL unreachable | catalog `Record()` drops on a full in-memory channel; forensic events stay in the Redis ring buffer (`gw:t:<tenant>:forensic_log`) until PG is back | none (forensic is best-effort; Redis already retains the last 1k events per tenant) |
| Upstream backend down | circuit-breaker opens after 5 failures, half-opens after 30s; idempotent retries fall through to the next upstream | `routes[].retry_attempts` per route |
| Session-cookie validation under Redis outage | response is `503 Service Unavailable` (we cannot positively authenticate) | none — `fail_closed` is intentional for auth |
| TLS terminator dies (upstream of gateway) | `require_tls: true` causes startup failure (operator catches it); plaintext fallback only when `require_tls: false` is explicitly configured | `require_tls: true` for production |

The asymmetry — rate-limit fails *open* by default, sessions fail *closed* — is
deliberate: a Redis blip should not blackhole all traffic, but it must blackhole
authentication. Override per deployment.

**Bounded outage latency.** The Redis client uses fail-fast timeouts (dial 1s,
read/write 500ms, 1 retry — `store.defaultDialTimeout` et al.). This is what makes
fail-open meaningful under load: without it, the go-redis defaults (5s dial / 3s
read / 3 retries) would hang each request for seconds during an outage, piling up
goroutines and exploding tail latency *before* the fail-open/closed logic runs.
The matrix above is verified end-to-end against a killed Redis in
`internal/middleware/degradation_test.go` (`TestDegrade_*`): fail_closed controls
return 503, default controls keep serving 200, the static IP blacklist still
enforces, and nothing panics.

---

## Redis HA — Sentinel

Redis Sentinel is the supported HA option; it gives automatic primary failover
without operator intervention. A 3-node sentinel quorum is the minimum (so a
single sentinel loss does not split the quorum).

**Minimum production layout**
- 1 Redis primary, 1 replica (more replicas if read traffic warrants).
- 3 sentinels on independent nodes (anti-collocation: never run all sentinels
  on the same hypervisor or in the same rack).
- All sentinels share the same `myid` and watch the same primary.

**AEGIS wiring**: set `redis.sentinel.master_name` and `redis.sentinel.addrs`
in `gateway.yaml` (the single `redis.addr` is ignored when Sentinel is on).
The gateway uses `redis.NewUniversalClient` so failover is handled by the
go-redis client itself; AEGIS code does not need to know which mode is active.

```yaml
redis:
  password: "${AEGIS_REDIS_PASSWORD}"
  sentinel:
    master_name: "mymaster"
    addrs: ["sentinel-1:26379", "sentinel-2:26379", "sentinel-3:26379"]
    sentinel_password: ""  # only if sentinels themselves require auth
```

**Failover behaviour seen by AEGIS**: during the ~5–15s sentinel reconfigure
window, in-flight requests will see Redis errors. Rate-limit and IP-guard
degrade per their `fail_closed` setting; sessions return 503; forensic writes
are buffered locally. Once Sentinel promotes the new primary, traffic resumes
without operator action.

**Memory**: scale Redis memory per tenant + traffic. The dominant keyspaces are
`gw:t:<tenant>:rate:*` (1 key per active IP, TTL = `rate_limit.window`),
`gw:t:<tenant>:behavior:<ip>:*` (5 keys per IP, 60s TTL), and `gw:t:<tenant>:forensic_log`
(capped at 1000 events). All other keyspaces are bounded or TTL'd; see
[secret-rotation.md](secret-rotation.md) for the operational view.

---

## PostgreSQL HA — replication

The catalog, forensic log, tenants and admin users share one database. RLS
(phase 2b) means every read goes through a transaction with `set_config(app.tenant_id,...)`,
so streaming replicas are fine: the GUC is per-connection, and replicas observe
the same RLS policies after the schema is replicated.

**Recommended layout**
- 1 primary (writeable), ≥ 1 streaming replica.
- Synchronous replication for the primary→first-replica pair if your latency
  budget allows (`synchronous_commit = on`, `synchronous_standby_names = '...'`);
  asynchronous to additional replicas.
- Connection pooler (PgBouncer) in front so AEGIS gateway replicas do not
  saturate `max_connections`.
- A managed VIP or DNS that follows the primary (Patroni / pg_auto_failover /
  AWS RDS-style endpoint).

**AEGIS only writes from the primary.** Catalog upserts, forensic inserts, and
IAM CRUD all go through `pgStore.withTenantTx` and `PGSink`, both of which
issue `BEGIN; SELECT set_config(...); INSERT/UPDATE; COMMIT`. Reads from the
admin API can be routed to a replica (with read-after-write delay caveats) but
this is not done today — `AEGIS_FORENSIC_DSN` is a single endpoint.

**Schema migrations** are idempotent (`CREATE … IF NOT EXISTS`, `ALTER TABLE …
ADD COLUMN IF NOT EXISTS`, `DROP POLICY IF EXISTS … / CREATE POLICY`), so a
rolling deploy across replicas is safe. The migration runs on every gateway
boot and is a no-op when the schema is current.

> **RLS gotcha — required role hardening.** PostgreSQL superusers and roles
> with `BYPASSRLS` automatically skip every Row-Level Security policy. If the
> AEGIS database role is a superuser (the default when you run a `postgres`
> container with `POSTGRES_USER=aegis`), the phase-2b fail-closed backstop is
> silently disabled — every tenant sees every row. Always run:
> ```sql
> ALTER ROLE aegis NOSUPERUSER NOBYPASSRLS;
> ```
> before pointing AEGIS at the database, or create a dedicated app role with
> `CREATE ROLE aegis_app LOGIN PASSWORD '...' NOSUPERUSER NOBYPASSRLS;` and
> grant it the minimum required privileges on the catalog/forensic/IAM tables.
> AEGIS logs `RLS DEGRADED: …` at startup when it detects that its current
> role bypasses RLS, so this is an observable misconfiguration — but it is
> not a fatal one, by design (operator may have a reason).

**RLS migration note**: when upgrading from a pre-2b release, the
`ENABLE ROW LEVEL SECURITY` + `FORCE ROW LEVEL SECURITY` statements take an
exclusive lock per table for a moment. Schedule the deploy at low traffic, or
disable `FORCE` in advance and re-enable after rollout if you are worried about
the lock window.

---

## Capacity guidance

These are first-order estimates pending the published benchmark numbers from
`tests/load/`. Treat them as planning starting points, not warranty.

| Resource | Sizing rule of thumb | Why |
|---|---|---|
| AEGIS replicas (CPU) | 1 vCPU per ~3–5k RPS legit traffic (WAF on) | The Coraza WAF is the dominant CPU cost; WAF-off can roughly double per-core throughput |
| AEGIS replicas (RAM) | 256 MB base + bounded in-flight buffers; scales with `routes` and JWKS cache | Process is stateless |
| Redis (RAM) | 200 MB + ~1 MB per 10k active IPs per tenant per minute | Rate-limit windows + behaviour TTLs dominate |
| Redis (connections) | One pool per gateway replica; default pool size is fine up to ~10k RPS | go-redis pools amortise |
| PostgreSQL (RAM) | 4 GB + 1 GB per 1M catalog rows | Indexes on `(tenant_id, last_seen)` and `(tenant_id, risk_score)` |
| PostgreSQL (storage) | Forensic logs grow linearly with blocked events; budget retention per tenant | No retention/rollup yet — see `RELEASE-CHECKLIST` P1 |
| PostgreSQL (connections) | ≤ 5 per gateway replica (configured in code); use PgBouncer in front | `db.SetMaxOpenConns(5)` in both `pgStore` and `PGSink` |

Run `tests/load/gateway_load.js` (single tenant) and `tests/load/multitenant_load.js`
(mixed tenants) on the target hardware and replace these estimates with measured
numbers before publishing a capacity sheet.

---

## Verification — bring-up checklist

After deploying or failing over either backing store, verify:

- [ ] `/health` returns 200 from every gateway replica.
- [ ] `/readyz` returns 200 (Redis ping succeeded).
- [ ] `aegis_blocked_*` metrics still increment when you drive a known-blocked
      pattern through `/api/v1/...`.
- [ ] A test login (super-admin via bearer, then per-tenant via email/password)
      succeeds and the session survives across replicas (because sessions live
      in Redis, not in-process).
- [ ] A deliberate Redis kill on the active primary causes Sentinel to promote
      a replica within ~15s; gateway traffic resumes without restart.
- [ ] A deliberate PostgreSQL failover keeps the gateway running; catalog
      writes resume once the primary endpoint follows the promotion.

Tie these checks to a synthetic monitor so the next failover is observed by a
robot, not by a customer.
