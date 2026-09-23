# AEGIS capacity sweep (VU 10/50/100/200) — WAF on vs off — 2026-07-31

Closes the last open item under Pillar 3 ("Load and latency benchmarks") in
`RELEASE-CHECKLIST.md`: a VU sweep and a WAF on/off split, on dedicated
hardware (the NUC, not Docker Desktop).

## Environment

Same setup as `tests/load/results-2026-06-21.md` and
`tests/load/observe-mode-results-2026-07-31.md`: gateway built from current
`main`, `aegis-demo-backend` (httpbin) over the `aegis-demo-net` bridge, a
fresh isolated Redis, LAN gigabit NUC host, k6 client over Wi-Fi from macOS.
Two configs identical except `security.waf.enabled` / `block_mode` and ports;
`rate_limit.requests` lifted to 10,000,000 so it's out of the picture; DLP,
bot, behavior, ip_guard, abuse all disabled in both (isolating WAF cost
specifically, not the whole chain — see `observe-mode-results-2026-07-31.md`
for the whole-chain enforce-vs-observe comparison).

## Results

| Config | VUs | Throughput | p50 | p95 | Errors |
|---|---:|---:|---:|---:|---:|
| WAF on | 10 | 399.6 req/s | 17.55 ms | 32.98 ms | 0.00 % |
| WAF on | 50 | 436.0 req/s | 85.93 ms | 163.85 ms | 0.00 % |
| WAF on | 100 | 429.9 req/s | 175.86 ms | 341.19 ms | 0.00 % |
| WAF on | 200 | 431.5 req/s | 361.89 ms | 702.05 ms | 0.00 % |
| WAF off | 10 | 429.0 req/s | 15.74 ms | 31.61 ms | 0.00 % |
| WAF off | 50 | 451.5 req/s | 80.89 ms | 156.78 ms | 0.00 % |
| WAF off | 100 | 451.2 req/s | 166.96 ms | 318.05 ms | 0.00 % |
| WAF off | 200 | ~~4413.9 req/s~~ | ~~18.70 ms~~ | ~~62.09 ms~~ | **96.36 %** |

> **The last row is not a result — struck through 2026-09-23.** At 96% errors
> it measured how fast the gateway can refuse, not how fast it can serve:
> 4413 req/s at 18 ms next to 451 req/s at 167 ms is the signature of requests
> being rejected, not of a configuration that got ten times faster.
>
> The cause is known and was never hidden — the shared demo backend saturated
> and the circuit breaker opened with no second upstream configured, which is
> correct behaviour and not an AEGIS number. It is written out in
> `RELEASE-CHECKLIST.md` under "Load and latency benchmarks", together with the
> two re-runs that followed. What was missing is the one place it mattered: the
> table itself, where a reader who never opens the checklist sees a row that
> flatters. Every other row here stands.

## Reading

**This sweep did not find AEGIS's own throughput ceiling — it found the
shared demo backend's.** From 10 to 100 VUs, throughput is flat at ~400–450
req/s regardless of VU count while p50/p95 scale up roughly linearly with VUs
— the textbook signature of a fixed-capacity server (here, the single
`kennethreitz/httpbin` container `aegis-demo-backend`, not built for this) with
requests queueing behind it, not of AEGIS adding per-request cost that grows
with concurrency.

**WAF cost is small and consistent at moderate load**: 400→436 req/s (WAF on)
vs 429→452 req/s (WAF off) at 10–100 VUs — roughly a 5–7% throughput cost and
a few ms of added latency for Coraza's rule evaluation. Consistent with the
"WAF blocks are cheap" finding in `results-2026-06-21.md`.

**The 200-VU WAF-off row is not a real throughput number — it's a saturation
failure.** `docker logs` for that run show the proxy's circuit breaker
repeatedly opening against `aegis-demo-backend` (`"circuit_breaker: open,
trying next upstream"`) because the single-threaded-ish demo backend couldn't
keep up once WAF-off let requests reach it faster; with only one upstream
configured there is nowhere to fail over to, so those attempts surface as
errors instead of degrading gracefully. The reported "4413.9 req/s" is mostly
k6 counting failed/short-circuited requests, not successful ones (96.36%
`http_req_failed`). WAF-on's extra per-request latency at the same VU count
incidentally throttled the effective request rate reaching the backend enough
to avoid tripping the same collapse (0% errors) — a side effect of the WAF's
cost, not a designed backpressure mechanism; do not read this as "the WAF
protects the backend from overload" without a dedicated test for that claim.

## What this does and doesn't tell you

- **Does**: WAF overhead at realistic concurrency (10–100 VUs, where this demo
  backend holds up) is small and doesn't grow disproportionately with load.
- **Does**: confirms the proxy's circuit breaker does engage under backend
  saturation (working as designed) rather than queueing forever.
- **Doesn't**: give AEGIS's own max-RPS ceiling — that number is currently the
  demo backend's ceiling, not the gateway's. A real capacity number needs a
  backend that can absorb far more load than AEGIS itself can push (e.g. a
  Go `net/http` no-op handler, not a single Python/Flask-style httpbin
  container), so the gateway's own per-request cost becomes the bottleneck
  being measured instead of the backend's.

## Next iteration

- Swap `aegis-demo-backend` for a purpose-built high-throughput no-op backend
  (a trivial Go handler) to actually find AEGIS's own ceiling, not the demo
  backend's.
- Add a second upstream (or lower `retry_attempts` deliberately) to see
  graceful-degradation behavior under backend saturation instead of the
  circuit breaker's fail path with nowhere to go.
- A raw-backend-only k6 run (bypassing AEGIS entirely) would separate "backend
  ceiling" from "AEGIS overhead" cleanly — still on the existing TODO list in
  `tests/load/README.md`/`results-2026-06-21.md`.

## Follow-up (same day): backend swap confirms the diagnosis, hardware caveat found instead

Re-ran the identical sweep against a trivial Go no-op handler (`{"ok":true}`,
no logging, no work) instead of `aegis-demo-backend`, same NUC, same isolated
Redis, same two WAF configs:

| Config | VUs | Throughput | p50 | p95 | Errors |
|---|---:|---:|---:|---:|---:|
| WAF on | 10 | 716.6 req/s | 6.54 ms | 16.94 ms | 0.00 % |
| WAF on | 50 | 671.5 req/s | 24.11 ms | 233.92 ms | 0.00 % |
| WAF on | 100 | 729.1 req/s | 49.86 ms | 370.20 ms | 0.00 % |
| WAF on | 200 | 769.9 req/s | 92.25 ms | 632.68 ms | 0.00 % |
| WAF off | 10 | 892.8 req/s | 5.68 ms | 12.40 ms | 0.00 % |
| WAF off | 50 | 631.0 req/s | 24.28 ms | 260.85 ms | 0.00 % |
| WAF off | 100 | 775.4 req/s | 32.46 ms | 448.55 ms | 0.06 % |
| WAF off | 200 | 674.8 req/s | 76.63 ms | 972.14 ms | 0.00 % |

**Confirms the diagnosis**: throughput jumped from a flat ~400–450 req/s to a
630–890 req/s range the moment the weak backend was replaced — the earlier
ceiling really was `aegis-demo-backend`, not AEGIS.

**But this run is not clean enough to publish as "AEGIS's max RPS" either.**
`uptime` on the NUC read **load average 16.9 on 4 cores** near the end of this
run — the box was ~4x oversubscribed from its other ~30 always-on services
(Immich, Nextcloud, Paperless, etc.), not from this test alone. That noise
shows in the numbers: WAF-off at 200 VUs (674.8 req/s, p95 972 ms) is *slower*
than WAF-on at 200 VUs (769.9 req/s, p95 633 ms) — the opposite of what WAF
overhead should ever produce, and throughput is non-monotonic across VU counts
in both rows (e.g. WAF-off 50 VUs < WAF-off 10 VUs). This is CPU contention
from concurrent unrelated load, not a signal about AEGIS or the WAF.

**Honest conclusion**: this NUC — a 2015 ultra-low-voltage laptop chip (Intel
i5-5250U, 4 cores/1.6 GHz), shared with ~30 unrelated always-on services — is
not a clean enough environment to publish a trustworthy absolute capacity
number, independent of which backend sits behind AEGIS. It's good enough for
*relative* comparisons run back-to-back under the same ambient load (enforce
vs observe, WAF on vs off at moderate VUs — see
`observe-mode-results-2026-07-31.md` and the first table above), where both
sides absorb the same noise. It is not good enough for "AEGIS handles N req/s"
as a number to hand a prospective pilot partner on its own — see the
noise-controlled re-run below.

## Second follow-up (same day): re-run with the other ~30 services stopped

With explicit authorization, stopped the 18 heaviest non-essential containers
on the NUC for the duration of the run (Immich's 5 containers, Paperless's 3,
Nextcloud's 3, Gitea, netdata, kiwix, tor-proxy, the nutrition-bot's 2,
bmx-sender, watchtower) — left VPN (`wireguard`), the reverse proxy fronting
`aegis.34host.org` (`npm-app-1`), `vaultwarden`, `portainer`, `homepage`,
`nuc-dashboard`, `uptime-kuma`, and every `aegis-*` container running, since
none of those were the CPU cost and some are load-bearing for remote access or
the live demo site. Confirmed `load average` down to ~1 (from 16.9) before
starting, then re-ran the identical lean-backend sweep:

| Config | VUs | Throughput | p50 | p95 | Errors |
|---|---:|---:|---:|---:|---:|
| WAF on | 10 | 807.4 req/s | 5.78 ms | 10.66 ms | 0.00 % |
| WAF on | 50 | 897.6 req/s | 22.33 ms | 139.84 ms | 0.00 % |
| WAF on | 100 | 628.0 req/s | 24.68 ms | 629.45 ms | 1.19 % |
| WAF on | 200 | 844.4 req/s | 115.80 ms | 534.12 ms | 0.00 % |
| WAF off | 10 | 1005.8 req/s | 4.91 ms | 8.63 ms | 0.00 % |
| WAF off | 50 | 750.6 req/s | 23.41 ms | 222.20 ms | 0.00 % |
| WAF off | 100 | 703.4 req/s | 20.55 ms | 658.59 ms | 0.77 % |
| WAF off | 200 | 720.0 req/s | 92.39 ms | 805.74 ms | 0.00 % |

All 18 stopped containers were restarted immediately after the run and
verified healthy (`docker ps`, no `starting`/`unhealthy`/`restarting` states);
`aegis.34host.org` re-checked at 200 through the reverse proxy.

**Reading**: throughput lands in the same 600–1000 req/s band as the noisy
run, ruling out unrelated background load as the explanation for that range —
this is AEGIS's own signal on this hardware. It is still not perfectly
monotonic (WAF-on dips to 628 req/s at 100 VUs, with the first non-zero error
rate of the whole sweep, 1.19%), but that's now plausibly *real* saturation
onset — Coraza's rule evaluation is CPU-bound, and on a 4-core box, k6's own
client-side load plus the gateway plus Redis are now the only three things
competing for cores, which is a fundamentally different (and legitimate)
source of variance than 30 unrelated containers. Errors start appearing at
100+ VUs in both WAF-on and WAF-off — this is the honest onset of this
specific box's ceiling, somewhere in the 600–900 req/s / ~100 concurrent
requests range.

**Still not a production capacity number.** This is a 2015 ultra-low-voltage
4-core laptop chip — a real production host (server-grade, more cores, no
Wi-Fi-hop client) will sit meaningfully higher. Read this as "AEGIS's floor on
weak hardware," not "AEGIS's ceiling" — useful for sizing a worst case, not for
a headline number to a prospective partner. That still needs dedicated/cloud
hardware with a wired client, not done here.
