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

### Extending a pilot, or converting to production

Re-run `licensegen -issue` with a longer `-days` (or `-days 0` for
never-expires — internal/demo use only, never hand a customer a
never-expiring file unless that is the actual deal) and `-tier production`,
and send the new file. There is no in-place renewal; the customer replaces
the file and the gateway picks it up on the next hot-reload or restart.

## 3. What this does NOT do

- It does not stop someone from disassembling the binary and patching out the
  check. Nothing short of a hardware dongle does, and that is not worth the
  cost for this product's scale. The legal + visible-degradation combination
  is the actual deterrent.
- It does not enforce `Tier` or `Features` or `MaxRPS` anywhere yet —
  `Claims` carries them so the caller *can* gate on them later, but today
  only validity, expiry, and hardware-lock actually decide whether the
  gateway starts. Don't advertise per-feature license gating to a customer
  until that's actually wired.
- Node-locking only checks the *primary* machine's network hardware; it does
  not detect running the same license inside multiple VMs cloned from one
  image with a preserved MAC, or other virtualization tricks. It raises the
  bar for casual reuse, it does not eliminate it — same "deterrent, not DRM"
  framing as the rest of this mechanism.
- It is not a substitute for the contract. The license file is a technical
  nudge; the MSA/pilot agreement with the customer is what actually protects
  you if someone violates the terms.

## 4. Open follow-ups (tracked here, not yet built)

- Admin API endpoint (`GET /api/license`) + a console banner so an operator
  sees license status without reading gateway logs.
- Per-tier feature gating (e.g. `sso`/`multitenancy` behind `Claims.Features`).
- A revocation list, if a private key is ever suspected compromised or a
  customer's license needs to be pulled mid-term (today: only expiry ends a
  license; nothing revokes one early).
- Self-service re-issuance on hardware change (today: customer emails a new
  fingerprint, you run `licensegen` by hand — fine at pilot volume, will not
  scale past a handful of customers).
