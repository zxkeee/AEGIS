# Deploying AEGIS behind Cloudflare (home server)

This guide covers running AEGIS on a self-hosted origin (e.g. a home server)
with Cloudflare in front. Cloudflare terminates TLS and proxies requests to your
origin, so a few settings must be tuned for AEGIS to see the real client IP,
enforce TLS correctly, and (optionally) consume Cloudflare's JA3 fingerprint.

There are two supported topologies. **Cloudflare Tunnel is strongly recommended
for a home server** because it needs no open inbound ports and never exposes
your home IP.

---

## Topology A — Cloudflare Tunnel (recommended for home servers)

```
client ──TLS──> Cloudflare edge ──(cloudflared tunnel)──> AEGIS :8080 ──> backends
```

`cloudflared` makes an outbound connection to Cloudflare, so your router needs
**no port-forwarding** and your home IP stays private.

1. Install and authenticate `cloudflared`, create a tunnel, and route your
   hostname to the local AEGIS port:
   ```
   cloudflared tunnel create aegis
   cloudflared tunnel route dns aegis api.example.com
   ```
2. `~/.cloudflared/config.yml`:
   ```yaml
   tunnel: aegis
   credentials-file: /home/you/.cloudflared/aegis.json
   ingress:
     - hostname: api.example.com
       service: http://localhost:8080   # AEGIS gateway (plaintext on loopback)
     - service: http_status:404
   ```
3. Because the tunnel connects from loopback, trust the loopback peer in AEGIS:
   ```yaml
   trusted_proxies: ["127.0.0.1/32", "::1/128"]
   ```
   The real client IP arrives in `X-Forwarded-For` (Cloudflare → cloudflared →
   AEGIS); AEGIS's right-to-left XFF walk returns it once loopback is trusted.

TLS is terminated at Cloudflare and the hop to AEGIS is loopback, so running the
gateway as plaintext is fine here (see TLS section below).

---

## Topology B — Cloudflare proxy (orange cloud) to a public origin

```
client ──TLS──> Cloudflare edge ──TLS──> your origin:443 (AEGIS or a TLS front) ──> backends
```

Use this when the origin has a routable address and you port-forward 443. You
must restrict the origin so only Cloudflare can reach it (firewall to
Cloudflare's IP ranges, or use Cloudflare's Authenticated Origin Pulls).

`trusted_proxies` must list **Cloudflare's IP ranges** so AEGIS extracts the
real client IP from `X-Forwarded-For` instead of trusting Cloudflare's edge IP:

```yaml
trusted_proxies:
  # Fetch the current lists — they change. https://www.cloudflare.com/ips/
  #   curl https://www.cloudflare.com/ips-v4
  #   curl https://www.cloudflare.com/ips-v6
  - 173.245.48.0/20
  - 103.21.244.0/22
  - 103.22.200.0/22
  - 103.31.4.0/22
  - 141.101.64.0/18
  - 108.162.192.0/18
  - 190.93.240.0/20
  - 188.114.96.0/20
  - 197.234.240.0/22
  - 198.41.128.0/17
  - 162.158.0.0/15
  - 104.16.0.0/13
  - 104.24.0.0/14
  - 172.64.0.0/13
  - 131.0.72.0/22
  - 2400:cb00::/32
  - 2606:4700::/32
  - 2803:f800::/32
  - 2405:b500::/32
  - 2405:8100::/32
  - 2a06:98c0::/29
  - 2c0f:f248::/32
```

> Keep this list current. A stale list means either a real client IP is mistaken
> for a proxy (if a range was removed) or Cloudflare's edge IP is reported as the
> client (if a range was added). Automate the refresh from the URLs above.

---

## TLS

Cloudflare terminates client TLS. What AEGIS should do depends on the hop from
Cloudflare to your origin:

| Hop CF → origin | AEGIS setting |
|---|---|
| Loopback (Tunnel) | `tls.enabled: false`, `require_tls: false` — plaintext on localhost is fine |
| LAN to another box | terminate TLS at AEGIS (`tls.enabled: true` + cert/key) **or** at a trusted TLS front; keep that front in `trusted_proxies` |
| Public origin | use Cloudflare **Full (strict)** SSL and terminate TLS at the origin (AEGIS `tls.enabled: true` with a real/Origin cert), or behind a TLS-terminating reverse proxy you trust |

- `require_tls: true` makes startup fail unless AEGIS itself terminates TLS. With
  Tunnel/loopback you intentionally leave it `false`; the startup warning is
  expected and benign in that topology.
- AEGIS already sends HSTS (`Strict-Transport-Security`). Cloudflare can also add
  HSTS; don't enable it in both or you'll send duplicate headers — pick one
  (Cloudflare's dashboard is the usual choice).
- The admin console session cookie is `Secure` by default. Access the console
  over HTTPS (through Cloudflare); leave `admin_cookie_insecure: false`. Only set
  it true for plain-HTTP local dev.

---

## Real client IP

AEGIS derives the client IP from `X-Forwarded-For`, skipping any hop in
`trusted_proxies` (right-to-left). With the correct `trusted_proxies` (CF ranges
for Topology B, loopback for Tunnel) this yields the true client IP, which feeds
rate-limiting, IP-guard, behavioural scoring and forensic logs.

Cloudflare also sends `CF-Connecting-IP` (the authoritative client IP). If you
prefer it, you can strip/rewrite `X-Forwarded-For` at Cloudflare via a Transform
Rule so the chain is unambiguous. The XFF approach above works without that.

---

## JA3 fingerprinting behind Cloudflare

AEGIS computes a real JA3-style fingerprint from the TLS ClientHello **only when
it terminates TLS itself**. Behind Cloudflare it does not see the handshake, so
that path produces nothing, and the spoofable inbound `X-JA3-Fingerprint` header
is always stripped (P0-4).

To still get a fingerprint, have **Cloudflare supply its JA3 hash** and let AEGIS
trust it — but only from the trusted Cloudflare/origin peer:

1. Cloudflare (Enterprise Bot Management exposes `cf.bot_management.ja3_hash`).
   Add a **Transform Rule → Modify Request Header** that sets a header, e.g.
   `Cf-Ja3-Hash`, to `cf.bot_management.ja3_hash`.
2. AEGIS config:
   ```yaml
   security:
     bot:
       enabled: true
       trust_upstream_ja3: true
       upstream_ja3_header: "Cf-Ja3-Hash"   # must NOT be X-JA3-Fingerprint
   ```
AEGIS believes this header only when the immediate peer is in `trusted_proxies`
(so a direct client cannot spoof it), copies it into the internal fingerprint
used by bot detection / behavioural scoring, and never forwards it to backends.
If you are not on an Enterprise plan that exposes JA3, leave `trust_upstream_ja3`
off — bot detection still works on other signals.

---

## Minimal config (Cloudflare Tunnel)

```yaml
listen: ":8080"
admin_listen: "127.0.0.1:8081"   # keep the admin plane off the tunnel
require_tls: false               # TLS terminated at Cloudflare; loopback hop
admin_cookie_insecure: false     # console reached over HTTPS via Cloudflare

trusted_proxies: ["127.0.0.1/32", "::1/128"]

redis:
  addr: "127.0.0.1:6379"
forensic_dsn: "postgres://aegis:***@127.0.0.1:5432/aegis?sslmode=disable"

security:
  rate_limit: { enabled: true, requests: 100, window: 1m, fail_closed: false }
  ip_guard:   { enabled: true, fail_closed: false }
  bot:
    enabled: true
    trust_upstream_ja3: false    # set true + upstream_ja3_header if on CF Enterprise
```

Do **not** expose `admin_listen` through the tunnel — bind it to loopback and
reach the console via SSH port-forward, or put it behind Cloudflare Access on a
separate hostname.

---

## Checklist

- [ ] `trusted_proxies` matches the topology (loopback for Tunnel; CF ranges for
      orange-cloud) and is kept current.
- [ ] TLS model chosen; `require_tls` consistent with it; HSTS set in exactly one
      place.
- [ ] Admin plane bound to loopback / behind Cloudflare Access, not the public
      tunnel ingress.
- [ ] Origin reachable only via Cloudflare (firewall to CF ranges, or Tunnel).
- [ ] Real client IP verified (block an IP, confirm it's the client and not a CF
      edge IP) — check a forensic log entry.
- [ ] JA3: either gateway-terminated TLS, or `trust_upstream_ja3` with a CF
      Transform Rule, or accept that JA3 is unavailable.
