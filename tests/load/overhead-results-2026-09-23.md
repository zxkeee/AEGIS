# What AEGIS adds to a request — 2026-09-23

The number a sales conversation asks for first, and the one no previous run in
this directory could answer: **how many milliseconds does putting AEGIS in front
of an API cost.**

## Answer

| Mode | p50 added | p95 added | runs |
|---|---:|---:|---|
| **Observe** (what a pilot runs) | **+1.1 … +1.6 ms** | +1.5 … +3.0 ms | 3 |
| **Full enforcement** | **+1.8 … +2.7 ms** | +1.7 … +3.1 ms | 3 |

Median of three runs: observe **+1.5 ms**, enforce **+1.8 ms** at p50.

Say it as "under three milliseconds at the median, with the whole security
chain on". Do not say "1.8 ms" as if it were a constant: the spread across
identical runs is larger than the difference between the two modes, and the
first run after a build was consistently the slowest (+2.7 ms enforce), which
is cold caches rather than a property of the product.

## Why the earlier numbers could not answer this

Every measurement in this directory before today ran k6 over **Wi-Fi** to the
NUC. Wi-Fi jitter is tens of milliseconds; the gateway's own cost is a single
digit. The noise was an order of magnitude larger than the signal, so no delta
could be read off `results-2026-06-21.md`, `observe-mode-results-2026-07-31.md`
or `capacity-sweep-2026-07-31.md` — all three measured other things well and
this one not at all.

This run removes the network rather than averaging it out: client, gateway and
upstream all on loopback of one machine.

## What this run is not

- **Not a capacity benchmark.** 200 requests/second, far below saturation. For
  throughput see `capacity-sweep-2026-07-31.md`.
- **Not what a real client sees.** A user in another datacentre pays network
  latency that dwarfs this. The number is the gateway's own cost, isolated
  deliberately, and it is honest only as that term.
- **Not a measurement of an idle machine.** k6, both processes, Redis and
  PostgreSQL share one laptop's cores. Co-residency inflates both sides, and
  the control cancels most but not all of it.
- **Not a single-number guarantee.** Three runs per mode, reported as a range,
  because two runs of the same configuration differed by 0.9 ms.

## Method

`tests/load/overhead.sh` + `tests/load/overhead.js`, repeatable:

```bash
make stand                        # upstream, Redis, PostgreSQL
./tests/load/overhead.sh          # full enforcement
MODE=observe ./tests/load/overhead.sh
```

Two k6 scenarios, same arrival rate and payload, **sequential rather than
parallel** — run side by side they would compete for cores and each would
measure the other's scheduling. The direct scenario is the control: it already
carries k6, loopback and the upstream itself, and those terms cancel in the
delta.

The measured gateway runs its own config on a separate port, with the whole
chain enabled (WAF in block mode, DLP, discovery, abuse detection, bot, IP
guard, behaviour scoring, consumer identification) and only the rate-limit and
enumeration thresholds lifted out of the way. Lifted, not disabled: the
middleware stays in the chain, so its per-request cost is still counted. A
gateway with the limiter removed is not one anybody runs.

Environment: macOS on Apple silicon, Go toolchain from `go.mod`, Redis and
PostgreSQL from `make stand`, upstream `aegis-demo-backend` on loopback,
200 req/s for 30 s per scenario, no errors in any run.

## Raw

| Run | Mode | direct p50 | gateway p50 | delta p50 | delta p95 |
|---|---|---:|---:|---:|---:|
| 1 | enforce | 0.48 ms | 3.16 ms | +2.68 ms | +3.06 ms |
| 2 | enforce | 0.38 ms | 2.16 ms | +1.78 ms | +1.67 ms |
| 3 | enforce | 0.37 ms | 2.15 ms | +1.78 ms | +1.76 ms |
| 1 | observe | 0.51 ms | 2.01 ms | +1.50 ms | +1.95 ms |
| 2 | observe | 0.38 ms | 1.46 ms | +1.08 ms | +1.53 ms |
| 3 | observe | 0.38 ms | 1.95 ms | +1.57 ms | +3.01 ms |

## Still open

- **No run on dedicated hardware over a real network.** That measurement
  answers a different question — what a client experiences — and it needs the
  NUC free and a wired client. The two numbers should be published together:
  this one says what the product costs, that one says what the deployment costs.
- **No profile of where the 1.8 ms goes.** Per-middleware cost would say
  whether the WAF, the catalog write or Redis dominates, and therefore what is
  worth optimising. Nothing here is slow enough to demand it yet.
