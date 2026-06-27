# Load & latency benchmarks

[k6](https://k6.io) scripts to measure AEGIS throughput and the latency overhead
it adds in front of a backend. This satisfies the "Load and latency benchmarks"
release-gate item: publish latency overhead and max RPS, with the WAF on and off.

## Prerequisites

- `k6` installed (`brew install k6` / see k6 docs).
- A running gateway (`:8080`) in front of the mock backend (`:3000`):
  ```bash
  go run ./tests/mock_backend.go &        # backend on :3000
  go run ./cmd/gateway -config config/gateway.yaml &
  ```

## Measuring gateway overhead

Run the same script against the gateway and against the backend directly; the
difference is AEGIS's added latency.

```bash
# 1. Backend baseline (no gateway in the path)
k6 run -e TARGET=http://localhost:3000 -e PATH=/ tests/load/gateway_load.js

# 2. Through the gateway
k6 run -e TARGET=http://localhost:8080 -e PATH=/api/v1/ping tests/load/gateway_load.js
```

## WAF on vs off

Run #2 twice, flipping `security.waf.enabled` in `config/gateway.yaml` between
runs (hot-reload picks it up), to publish both numbers.

## Tunables

| Env | Default | Meaning |
|-----|---------|---------|
| `TARGET` | `http://localhost:8080` | base URL |
| `PATH` | `/api/v1/ping` | request path |
| `VUS` | `50` | peak virtual users |
| `DURATION` | `30s` | steady-state duration |
| `TOKEN` | _(empty)_ | Bearer token if auth is enabled |

## Thresholds (CI-able)

The script fails (non-zero exit) if error rate ≥ 1% or p95 ≥ 50ms / p99 ≥ 150ms,
so it can gate a performance-regression job. A machine-readable `summary.json` is
written next to the script for trend tracking.

## Multi-tenant scenario (ADR-001 phase 6)

`multitenant_load.js` drives mixed-tenant traffic to measure the cost of
isolation added in phases 2–3 (per-tenant Redis prefixes + PG RLS + explicit
`WHERE tenant_id`) against the single-tenant baseline.

```bash
# Mixed-tenant traffic, 50 VUs over 3 tenants, no attack channel.
k6 run -e TARGET=http://localhost:8080 tests/load/multitenant_load.js

# Same load but 10% of requests carry a SQLi payload that the WAF must block —
# exercises the deny path so the latency curve includes blocked-vs-passed mix.
k6 run -e ATTACK=0.10 tests/load/multitenant_load.js
```

The script reports **per-tenant p50/p95/p99** so you can spot a tenant whose
workload pattern (lots of unique IPs, lots of new endpoints) costs more than
the others. Compare the aggregate numbers to `gateway_load.js` at the same VUs
to publish the MT overhead.

Extra env: `TENANTS=acme,globex` (per-VU tenant assignment), `HOSTS=...`
(override `<id>.api.example`), `ATTACK=0.10` (10% SQLi requests).
