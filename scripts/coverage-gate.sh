#!/usr/bin/env bash
# coverage-gate.sh — fail CI if a critical package regresses below its floor.
#
# The release goal is >=70% on critical packages (RELEASE-CHECKLIST, Pillar 3).
# We are not there on every package yet, so this gate enforces a per-package
# FLOOR set to the current level: it locks in regression-test coverage of the
# security fixes and prevents back-sliding. Raise a floor whenever you raise the
# real coverage — the floors should ratchet up toward 70.
#
# Usage: scripts/coverage-gate.sh
set -euo pipefail

# "package floor" — minimum percent (integer) per critical package. Ratchet
# these up as real coverage rises; never down. Portable (no assoc arrays, so it
# runs on macOS bash 3.2 as well as CI).
#
# SET A FLOOR FROM CI'S NUMBER, NOT FROM A LOCAL RUN. Local coverage reads
# consistently HIGHER than CI — on 2026-09-06 internal/config measured 94.7%
# locally and 93.0% in CI, and internal/api 88.2% against 81.6%. A floor
# ratcheted to a local figure fails on push, which is how this comment got
# written. Read the number off a CI run of this script and leave a point or two
# of headroom.
FLOORS="
api-gateway/internal/middleware 80
api-gateway/internal/config 92
api-gateway/internal/alert 75
api-gateway/internal/tlsfp 95
api-gateway/internal/tenant 100
api-gateway/internal/iam 75
api-gateway/internal/proxy 92
api-gateway/internal/discovery 80
api-gateway/internal/classify 90
api-gateway/internal/api 70
api-gateway/internal/store 80
api-gateway/internal/audit 75
api-gateway/internal/gateway 82
api-gateway/internal/sso 85
api-gateway/internal/retention 80
api-gateway/internal/license 90
api-gateway/internal/attest 100
api-gateway/internal/gql 90
api-gateway/internal/forensic 80
api-gateway/sdk/gatewayverify 90
"

TARGET=70 # the goal; printed for visibility, not yet enforced everywhere.
fail=0

while read -r pkg floor; do
  [[ -z "$pkg" ]] && continue
  # -covermode=atomic so the gate is consistent under -race in CI.
  cov=$(go test -covermode=atomic -coverprofile=/dev/null "$pkg" 2>/dev/null \
        | sed -n 's/.*coverage: \([0-9.]*\)%.*/\1/p')
  if [[ -z "$cov" ]]; then
    echo "ERROR: no coverage reported for $pkg"
    fail=1
    continue
  fi
  # integer compare on the truncated percentage
  cov_int=${cov%.*}
  flag="ok"
  if (( cov_int < floor )); then
    flag="BELOW FLOOR ($floor%)"
    fail=1
  elif (( cov_int < TARGET )); then
    flag="below target ($TARGET%)"
  fi
  printf '  %-40s %6s%%  [%s]\n' "$pkg" "$cov" "$flag"
done <<< "$FLOORS"

if (( fail )); then
  echo "coverage gate: FAILED — a critical package dropped below its floor"
  exit 1
fi
echo "coverage gate: passed"
