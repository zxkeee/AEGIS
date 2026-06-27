# Redis-outage under load — graceful-degradation run (2026-06-26)

Validates the RELEASE-CHECKLIST "graceful failure under load" item for the
**Redis-unavailable** case, on real hardware, under steady traffic with the
backing store killed mid-run.

## Setup

- **Host:** home-server NUC (Debian, 4 vCPU, 15 GiB). Shared box — traffic kept
  deliberately gentle (50 rps) so co-tenant services (Nextcloud/Immich/…) were
  unaffected. Box load average during the run stayed ~2.
- **Gateway:** current `cmd/gateway` build (with the fail-fast Redis timeouts:
  dial 1s / read-write 500ms / 1 retry), isolated on host ports 18080/18081,
  `config` = `tests/load/loadtest.yaml`-equivalent: `rate_limit` (fail-open) and
  `ip_guard` (fail-open) enabled — the two Redis-dependent controls in the hot
  path. No PG (forensic/catalog disabled) to isolate the Redis variable.
- **Backend:** throwaway httpbin container. **Store:** throwaway Redis container
  (own password), `docker stop` at t=45s, `docker start` at t=65s.
- **Driver:** `redis_outage_loadgen.go` run on-host against `127.0.0.1:18080`
  (the firewall only exposes the demo port externally; on-host avoids touching
  it). Constant 50 rps for 90s; latency bucketed into pre / outage / recovery.

## Result

| Phase | Requests | Success | p50 | p95 | p99 | max |
|---|---|---|---|---|---|---|
| PRE (0–45s, Redis up) | 2249 | 100.0% | 4 ms | 8 ms | 11 ms | 31 ms |
| **OUTAGE (45–65s, Redis DOWN)** | 1000 | **100.0%** | 38 ms | 62 ms | **864 ms** | **1.297 s** |
| RECOVERY (65–90s, Redis up) | 1250 | 100.0% | 5 ms | 12 ms | 42 ms | 58 ms |

## Reading

1. **Fail-open held:** 100% of requests succeeded with Redis completely dead —
   the gateway did not blackhole traffic when it could not consult the rate-limit
   / IP-block state. (This is the documented default; `fail_closed: true` would
   instead return 503 — see `internal/middleware/degradation_test.go`.)
2. **Latency stayed bounded:** during the outage p99 = 864 ms and the worst
   single request was 1.30 s — consistent with the fail-fast timeouts (≈ read
   500 ms × 1 retry + dial). Without the fix, the go-redis defaults (5s dial /
   3s read / 3 retries) would have hung each request for **3–9 s**, piling up
   goroutines and collapsing throughput.
3. **Clean recovery:** the moment Redis returned, latency snapped back to
   baseline (p99 42 ms) with no operator action.

## Still open (needs a quieter/dedicated box)

- Capacity sweep (VU ramp, WAF on/off) for published max-RPS numbers.
- PostgreSQL-outage under load (catalog/forensic) — unit-level covered
  (`catalog_nil_test.go`), not yet load-tested.
- Rolling-update drain: zero-5xx during `Shutdown(ctx)` under sustained traffic.

## Reproduce

```bash
# 1. cross-compile gateway + driver for the target, copy over
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o gateway ./cmd/gateway
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o loadgen tests/load/redis_outage_loadgen.go
# 2. throwaway backing services (own ports/passwords), start the gateway
# 3. on the host:
./loadgen -rate 50 -dur 90 -outage_start 45 -outage_end 65 -redis <redis-container>
```
