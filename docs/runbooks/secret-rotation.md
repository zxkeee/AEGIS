# Runbook — Secret Rotation

AEGIS holds four classes of secret. This runbook describes how to rotate each
without dropping traffic, and how to verify the rotation. Rotate on a fixed
cadence (recommended: 90 days) and immediately on suspected compromise or
operator off-boarding.

| Secret | Source of truth | Env var | Blast radius if leaked |
|--------|-----------------|---------|------------------------|
| Admin secret | `admin_secret` / env | `AEGIS_ADMIN_SECRET` | Full admin-API + console takeover |
| JWT / identity-signing secret | `security.auth.secret` / env | `AEGIS_JWT_SECRET` | Forge downstream identity (`X-Gateway-*`) |
| Redis password | `redis.password` / env | `AEGIS_REDIS_PASSWORD` | Read/poison sessions, rate-limit, blocklists |
| Forensic / catalog DSN password | `forensic_dsn` / env | `AEGIS_FORENSIC_DSN` | Read forensic logs + API catalog |

Secrets are read from the environment first (`applyEnvOverrides`), so production
should inject them via the orchestrator's secret store (Kubernetes Secret,
Vault, SSM) — never commit them. Generate with `openssl rand -hex 32`.

---

## General principles

- **Two running replicas minimum** so rotation is a rolling restart with no
  downtime. AEGIS has no in-memory secret cache beyond process start, so a fresh
  process picks up the new value immediately.
- **Order matters for shared secrets** (JWT, Redis): update the *consumers* that
  must agree before flipping the gateway, or use a dual-accept window.
- **Verify after every rotation** using the checks below; a silent failure here
  is a security incident.

---

## 1. Admin secret (`AEGIS_ADMIN_SECRET`)

The admin secret authenticates the admin API (bearer) and backs console login.
There are no other parties, so rotation is a simple replace.

1. Generate: `openssl rand -hex 32`.
2. Update the secret in your secret store.
3. Rolling-restart the gateway replicas.
4. Existing console sessions (Redis-backed) survive until their TTL; bearer
   clients (CI, scripts) must be updated to the new value.

**Verify:**
```bash
# Old secret must now be rejected.
curl -sk -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $OLD" https://admin/api/metrics   # expect 403
# New secret must work.
curl -sk -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $NEW" https://admin/api/metrics   # expect 200
```
To force-invalidate all console sessions immediately, flush the session keys:
`redis-cli --scan --pattern 'gw:session:*' | xargs redis-cli del`.

---

## 2. JWT / identity-signing secret (`AEGIS_JWT_SECRET`)

This secret signs the `X-Gateway-*` identity headers verified by backends (see
`sdk/gatewayverify`). Backends and the gateway **must agree**, so rotate with a
dual-accept window to avoid rejecting in-flight requests.

> If you authenticate end-users via **JWKS** (RSA/ECDSA) rather than this shared
> HMAC secret, rotate at the IdP and AEGIS picks up the new keys from the JWKS
> endpoint automatically — only the identity-propagation secret below needs this
> procedure.

1. Generate the new secret.
2. **Backends first:** deploy backends that accept *either* the old or new
   secret (verify against both; accept if either matches). `gatewayverify`
   makes this a two-instance check or a small wrapper around `Verify`.
3. **Gateway next:** update `AEGIS_JWT_SECRET` and rolling-restart. The gateway
   now signs with the new secret; backends still accept both.
4. **Retire the old secret** from backends once all gateway replicas have
   restarted and the freshness window (default 60s) has elapsed.

**Verify:**
```bash
# A request through the gateway must be accepted by the backend (200), and a
# request carrying a hand-forged signature with the OLD secret must be rejected
# once step 4 is complete.
```

---

## 3. Redis password (`AEGIS_REDIS_PASSWORD`)

Redis backs sessions, rate-limit windows, behavioural scores and IP blocklists.

1. Set the new password on Redis. With Redis ACLs you can add the new
   credential alongside the old for a dual-accept window; with a single
   `requirepass` you must flip it atomically and restart consumers promptly.
2. Update `AEGIS_REDIS_PASSWORD` in the secret store.
3. Rolling-restart the gateway. On a single-`requirepass` setup, expect a brief
   reconnect; with `fail_closed` enabled (rate-limit / IP-guard), requests are
   denied (503) rather than passed during the gap — plan a short maintenance
   window or use ACL dual-accept.

**Verify:**
```bash
redis-cli -a "$NEW" ping        # PONG
redis-cli -a "$OLD" ping        # (error) NOAUTH / WRONGPASS once old is retired
```
Confirm the gateway reports healthy and rate-limit/session operations work
(`/readyz` green, a login succeeds).

---

## 4. Forensic / catalog DSN (`AEGIS_FORENSIC_DSN`)

The DSN embeds the PostgreSQL password used for forensic logs and the API
catalog.

1. Create a new DB password (or a new role) in PostgreSQL.
2. Update `AEGIS_FORENSIC_DSN` with the new credential.
3. Rolling-restart the gateway. The forensic sink and catalog reconnect on
   start; if the DSN is wrong, the gateway logs a sink-init error and degrades
   to Redis-only forensic logging (it does **not** crash) — so verify.
4. Revoke the old DB password/role.

**Verify:**
```bash
# After restart, drive one request and confirm a forensic row appears.
psql "$NEW_DSN" -c "select count(*) from forensic_logs where ts > now() - interval '1 minute';"
```

---

## Post-rotation checklist

- [ ] Old secret demonstrably rejected (per the verify step).
- [ ] New secret demonstrably accepted.
- [ ] `/health` and `/readyz` green on every replica.
- [ ] No spike in `aegis_*` error counters on `/metrics` (e.g.
      `behavior_record_redis_error`, `rate_limit_store_unavailable`).
- [ ] Rotation recorded in the change log with date and operator.
- [ ] Old credential destroyed in the secret store.
