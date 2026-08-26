# AEGIS — Licensing & Trial Enforcement

How AEGIS is licensed, and how the trial/pilot license mechanism actually
works end to end. Read this before issuing a license to anyone, and before
telling a customer or partner "it's under a trial."

## 1. The legal boundary (`LICENSE`)

The repository is under the **Business Source License 1.1** (BUSL), not MIT.
In plain terms:

- Anyone can read the source, run it locally, modify it, and use it for
  internal evaluation/testing/research — free, no license file needed.
- **Production use** (protecting real traffic — yours or a customer's)
  requires either a signed license file (below) or a separate written
  agreement.
- Four years after each release, that release's code converts to Apache 2.0.
  You are not giving the product away forever, but you are not locking it up
  forever either — this is a normal, deliberate open-core-adjacent posture
  (same model Sentry, CockroachDB, MariaDB itself use), not a compromise.
- Redistribution or offering AEGIS as a hosted/managed service to third
  parties is **not** covered by the free-use grant, full stop.

The `LICENSE` file is the actual legal instrument. This document is
operational guidance, not a legal opinion — if a real dispute ever comes up,
talk to a lawyer, not this file.

## 2. The technical enforcement (`internal/license`, `cmd/licensegen`)

This is a **deterrent and a trust boundary**, not DRM. It cannot stop someone
determined to patch a Go binary. What it does do:

- A trial/pilot clock that is real, not "honor system."
- A copied/unlicensed deployment does not run at all — no free degraded mode
  to give away discovery/posture/findings for nothing (see below).
- **Node-locking**: a license can be tied to the specific machine it was
  issued for (`Claims.HardwareID`), so a `.lic` file copied to different
  hardware fails to verify there.
- A paper trail: every gateway logs its license status (valid/invalid,
  licensee, tier, expiry) on every boot and hot-reload.

### One-time setup (do this once, then never again casually)

```bash
go run ./cmd/licensegen -genkey -out aegis-license
```

This prints an Ed25519 keypair.

- `aegis-license.key` (the **private** key) — move it off this machine into a
  password manager / secrets vault immediately. **Never commit it, never
  send it over Slack/email.** Anyone who has it can mint valid licenses for
  your product forever, with no revocation mechanism.
- The printed **public** key — safe to keep in a build script or CI secret.
  It only lets a binary *verify* licenses, not issue them.

### Building a licensed release

```bash
go build -ldflags "-X api-gateway/internal/license.publicKeyB64=<public-key>" ./cmd/gateway
```

A plain `go build` from this repo with no `-ldflags` produces a binary with no
embedded public key — it will refuse every license file and always run in
Observe mode. That is intentional: a stray internal build is never
accidentally "fully licensed."

### Issuing a trial/pilot license for a specific customer

**Step 1 — have the customer report their machine's fingerprint.** Node-locking
means the license only works on the box it was issued for. On the machine that
will actually run the gateway (not your laptop), the customer runs the
release binary itself:

```bash
./gateway -print-fingerprint
# or, from source: go run ./cmd/gateway -print-fingerprint
```

This prints a single deterministic string derived from that machine's network
hardware (SHA-256 of its non-loopback interface MAC addresses — see
`license.Fingerprint`) and exits immediately; it needs no config, no Redis, no
license file. The customer sends you that string.

**Step 2 — issue the license bound to that fingerprint:**

```bash
go run ./cmd/licensegen -issue \
  -key aegis-license.key \
  -licensee "Acme Corp" \
  -tier pilot \
  -days 30 \
  -hardware-id <fingerprint the customer sent you> \
  -out acme-pilot.lic
```

Omitting `-hardware-id` issues a floating license that runs on any machine —
`licensegen` prints a loud warning if you do this, since it's the exception,
not the default. Reserve floating licenses for your own internal/demo use.

Send `acme-pilot.lic` to the customer. They point their config at it:

```yaml
license_path: /etc/aegis/acme-pilot.lic
# or: export AEGIS_LICENSE_PATH=/etc/aegis/acme-pilot.lic
```

**If the customer changes hardware** (new server, re-provisioned VM, swapped
NIC, migrated to a different host), the gateway does not immediately hard-fail
— it grants a **72-hour grace window** (`license.DefaultHardwareGrace`) the
first time it sees a given mismatch: it boots normally, fully functional, but
logs a loud `WARN` every time ("HARDWARE MISMATCH — running on a temporary
grace period... Contact the vendor for a free re-issue now") so it's
impossible to miss in the logs. The grace deadline is persisted next to the
license file (`<license_path>.hwgrace`) so it survives restarts — it does not
reset every reboot, and it does not re-grant a fresh 72h on every mismatch of
the *same* new hardware. Once the window elapses, the next boot hard-fails
exactly like an expired license.

Practically: as soon as you see (or the customer reports) that warning, have
them re-run `-print-fingerprint` on the new machine and send you the new
value; **re-issue a replacement license free of charge** for the remainder of
the original term (adjust `-days` to the time actually remaining, don't just
reset the clock to 30 — a hardware swap isn't a free term extension). This is
a manual, human step today; there is no self-service re-issuance flow. The
grace window buys you time to do this without a same-minute outage — it does
not remove the need to do it.

**Caveat for containerized deployments:** in Docker/Kubernetes without a
pinned MAC address, the virtual NIC is often reassigned on container
recreation — meaning a routine redeploy can look identical to "the customer
swapped hardware" and break the license. Before node-locking a containerized
deployment, either pin the container's MAC address in its network config, or
bind the license to the underlying host (run `-print-fingerprint` on the host,
not inside the container) instead. Mention this explicitly to any customer
running in k8s before handing them a hardware-locked license — it is the most
likely source of "why did my license just stop working" support tickets.

### What happens on expiry / tamper / missing file

`main.go` checks the license once at boot and again on every config
hot-reload (`loadValidatedConfig`), as a **hard gate — the same treatment as
any other `config.Validate` rejection**, not a soft degrade. If the license is
missing, unreadable, signed by the wrong key, tampered with, or past
`ExpiresAt`:

- **On boot:** the gateway does not come up. `main()` panics with the
  license's `Reason` in the message, exactly like a placeholder admin secret
  or an invalid `trusted_proxies` entry would.
- **On hot-reload:** the reload is rejected and logged
  (`hot-reload: rejected, previous config stays active`); the previously
  running config keeps serving. An already-running gateway does not go down
  the instant a license quietly expires mid-shift — but it will refuse to
  come back up on the next restart until the license is renewed, so don't
  treat that grace as a schedule; renew before `ExpiresAt`, not after.
- A valid license logs its licensee/tier/expiry/`days_left` on every boot and
  reload (`logLicenseStatus` in `cmd/gateway/main.go`) so it's never silent.

This is deliberately stricter than the observe-mode pilot posture
(`docs/pilot-mode.md`): a copy running without a license does not get a
watered-down "detect only" mode for free — it does not run at all. Letting an
unlicensed copy still produce discovery/posture/findings for nothing would
have defeated the point.

**Operational implication:** monitor `days_left` (log field on every valid
boot/reload) and renew ahead of expiry. Losing the license file, or an
IdP/ops mistake that lets it expire un-renewed, is now a full outage on the
next restart, not a graceful degrade — that trade-off is intentional (see
above) but it does mean license expiry needs the same on-call attention as a
TLS cert or a Redis password rotation.

### The mid-run expiry design note

A long-lived gateway whose `gateway.yaml` is never edited again — the
steady-state case for a production proxy — would otherwise only ever re-check
its license as a side effect of a config hot-reload, i.e. never. So
`licenseRecheckLoop` (`cmd/gateway/main.go`) re-runs `LoadWithGrace` on a
timer and pushes the fresh result to `GET /api/license` and the console
banner.

**What it deliberately does not do is stop traffic.** When a license goes
invalid mid-run, the gateway keeps serving and logs a loud, explicit
licensing-breach error instead of tearing down the chain. Same reasoning as
the hardware-change grace period: a same-minute production outage over a
licensing technicality is a worse outcome than a bounded, noisy window of
non-compliance. The re-check makes the status *current and loud*, not
*enforcing*.

**Known limitation, stated plainly:** the tier and feature entitlements above
are applied by `loadValidatedConfig` — that is, at boot and on config
hot-reload, the two moments where coercing the config is meaningful. The
periodic re-check does not re-apply them. So if someone swaps a
`production` `.lic` for a `trial` one *without* touching `gateway.yaml`, the
re-check will report the new trial license (loudly, and in the console), but
the running process keeps enforcing until the next reload or restart. That is
consistent with the "never change traffic behaviour mid-run" rule above —
silently switching a running gateway into detect-only would be its own
outage-shaped surprise — but it does mean tier is a boot-time decision, not a
continuously-enforced one. Don't describe it to a customer as the latter.

### Extending a pilot, or converting to production

Re-run `licensegen -issue` with a longer `-days` (or `-days 0` for
never-expires — internal/demo use only, never hand a customer a
never-expiring file unless that is the actual deal) and `-tier production`,
and send the new file. There is no in-place renewal; the customer replaces
the file and the gateway picks it up on the next hot-reload or restart.

### `Tier`, `Features`, and `MaxRPS` are real, enforced entitlements

Issuing a `-tier trial` or `-tier pilot` license is not just a label: those
tiers **cannot enforce**, ever, regardless of the customer's own config.
`license.Claims.RequiresObserve()` forces `Observe: true` the same way an
invalid-hardware grace period or an explicit pilot opt-in does — a trial
customer literally cannot turn on blocking by editing their YAML. Only
`-tier production` (or an unset/internal tier, for your own use) enforces
what the operator configures.

`-features` gates specific config surfaces the same way: today,
`multitenancy.enabled: true` and `oidc.enabled: true` each require the
matching feature (`multitenancy`, `sso`) to be present in the license's
`Features` list, or **the gateway refuses to boot** — same hard-gate
treatment as an invalid license, not a silent downgrade. A license issued
with `-features` omitted (empty list) is **unrestricted** — this is
deliberate backward compatibility: every license issued before this existed
keeps working exactly as before, nothing retroactively breaks.

```bash
go run ./cmd/licensegen -issue -key aegis-license.key -licensee "Acme Corp" \
  -tier production -days 365 -features multitenancy,sso -hardware-id <fp> -out acme.lic
```

`-max-rps` becomes a real ceiling on the gateway's total throughput
(`middleware.LicenseRateLimit`, wired near-outermost in the chain): once
active requests-per-second across ALL routes/tenants exceeds it, further
requests get `429` until the 1-second window rolls over. This is a
**commercial constraint, not a security control** — it has no `fail_closed`
option and always fails open on a Redis outage, same reasoning as
behavioral scoring staying fail-open elsewhere in this codebase: a licensing
technicality must never turn into a customer-facing outage. `-max-rps 0`
(the default) means unlimited.

## 3. What this does NOT do

- It does not stop someone from disassembling the binary and patching out the
  check. Nothing short of a hardware dongle does, and that is not worth the
  cost for this product's scale. The legal + visible-degradation combination
  is the actual deterrent.
- `Tier`, `Features`, and `MaxRPS` ARE now enforced (see §2a below) — this
  bullet used to say they weren't; that's stale as of the entitlement work.
- Node-locking only checks the *primary* machine's network hardware; it does
  not detect running the same license inside multiple VMs cloned from one
  image with a preserved MAC, or other virtualization tricks. It raises the
  bar for casual reuse, it does not eliminate it — same "deterrent, not DRM"
  framing as the rest of this mechanism.
- It is not a substitute for the contract. The license file is a technical
  nudge; the MSA/pilot agreement with the customer is what actually protects
  you if someone violates the terms.

## 4. Self-service reissuance on hardware change (`cmd/licenseserver`)

The manual flow above (customer emails a fingerprint, you run `licensegen` by
hand) doesn't scale past a handful of customers. `cmd/licenseserver` is a
small standalone HTTP service that automates exactly the "hardware changed,
same commercial term" case:

```bash
go run ./cmd/licenseserver -key aegis-license.key -listen :8443
```

The customer's gateway (or a small script they run) POSTs to `/reissue`:

```bash
curl -X POST https://license.yourdomain.example/reissue \
  -H 'Content-Type: application/json' \
  -d '{"license": "<contents of their current .lic file>", "hardware_id": "<new fingerprint>"}'
```

and gets back `{"license": "<new .lic contents>"}` with no human involved.

**What it checks** (`license.Reissue`): the presented license's signature
must verify against this server's own key (proof the caller already holds a
genuine license — not just anyone can request one for any licensee), and its
`ExpiresAt` must not already be in the past. Everything else (Licensee, Tier,
Features, MaxRPS, **ExpiresAt**) carries over unchanged — this fixes a
hardware swap, it does not grant a free extension. An already-expired license
gets `402 Payment Required` with a message pointing at a real renewal instead
of a silent reissue.

**The real tradeoff — read before deploying this anywhere:** every other tool
in this repo (`cmd/licensegen`) keeps the private key fully offline. This
service needs the key loaded in memory and reachable over the network to do
its job. That is a genuine, deliberate increase in exposure, not a detail:

- Run it on infrastructure you control tightly, not co-located with a
  customer's environment, not on a shared/general-purpose box.
- Put it behind TLS and, ideally, behind AEGIS itself (or another
  reverse proxy/WAF) rather than exposed raw — the built-in per-IP rate
  limiter (`-rate-limit`, default 10/hour) is a floor, not a substitute for
  one.
- Treat this process with the same operational care as a CA's signing
  service, because that is functionally what it is: whoever compromises
  this host's memory can mint licenses, same as whoever steals the offline
  key file.
- If you don't want that exposure at all, don't run this — the manual
  `licensegen` flow (fully offline key) remains the safer default and is
  still perfectly fine at low customer volume.

## 5. Other open follow-ups (tracked here, not yet built)

- Per-tier feature gating (e.g. `sso`/`multitenancy` behind `Claims.Features`)
  — `Claims` carries this data but nothing enforces it yet.
- A revocation list, if a private key is ever suspected compromised or a
  customer's license needs to be pulled mid-term (today: only expiry ends a
  license; nothing revokes one early — this applies to `licenseserver`'s key
  too, and matters more there given the higher exposure).
- Per-customer accountability on `licenseserver` (today: any caller holding a
  valid old license can reissue for any new hardware id — there's no
  additional shared secret/API key per customer, to keep the flow genuinely
  self-service; consider adding one if abuse becomes a real concern).
