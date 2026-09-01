#!/usr/bin/env bash
# Run locally everything CI will run, in the same way CI runs it.
#
# This exists because "green locally, red on push" happened three times in a row
# and each time the cause was the local run being a DIFFERENT run, not a flake:
#
#   - golangci-lint was v1.64.8 locally against CI's v2.12.2. The module path
#     gained a /v2 at the major bump, so `go install …/golangci-lint@latest`
#     silently keeps installing the old major forever. Different major, different
#     default linter set, and four errcheck findings invisible locally.
#   - Only the root Go module was linted. CI lints web/ as a second module.
#   - npm audit was never run at all. CI audits two separate lockfiles, and a
#     fix applied to one of them left the other failing.
#
# Mirrors .github/workflows/{lint,test,security}.yml. When those change, change
# this — a preflight that has drifted from CI is worse than none, because it
# buys confidence it cannot back.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Pinned to match .github/workflows/lint.yml exactly.
GOLANGCI_VERSION=v2.12.2

fail=0
step() { printf '\n\033[1m── %s\033[0m\n' "$*"; }
ok()   { printf '   \033[32mok\033[0m %s\n' "$*"; }
bad()  { printf '   \033[31mFAIL\033[0m %s\n' "$*"; fail=1; }

# ── Integration environment ───────────────────────────────────────────────────
# Without these the suite still passes, but six packages skip their integration
# tests and the coverage gate then measures something CI does not.
if [ -z "${REDIS_ADDR:-}" ] || [ -z "${POSTGRES_DSN:-}" ]; then
  printf '\033[33mwarning:\033[0m REDIS_ADDR / POSTGRES_DSN are unset — integration\n'
  printf '         tests will skip and the coverage gate will not match CI.\n'
fi

step "golangci-lint $GOLANGCI_VERSION"
have=$(golangci-lint version 2>&1 | grep -oE 'version v?[0-9]+\.[0-9]+\.[0-9]+' | head -1 | tr -d 'version ')
if [ "v${have#v}" != "$GOLANGCI_VERSION" ]; then
  printf '   installing (found "%s", need %s)\n' "${have:-none}" "$GOLANGCI_VERSION"
  go install "github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$GOLANGCI_VERSION" || bad "install"
fi
golangci-lint run --timeout 5m ./... && ok "root module" || bad "root module"
(cd web && golangci-lint run --timeout 5m ./...) && ok "web module" || bad "web module"

step "go test -race"
go test ./... -race -timeout 180s > /tmp/preflight-test.log 2>&1 \
  && ok "root module" || { bad "root module"; grep -E '^(--- FAIL|FAIL)' /tmp/preflight-test.log | head -20; }
(cd web && go test ./... -race -timeout 180s >/dev/null 2>&1) && ok "web module" || bad "web module"

step "coverage gate"
./scripts/coverage-gate.sh > /tmp/preflight-cov.log 2>&1 \
  && ok "floors held" || { bad "a package dropped below its floor"; grep BELOW /tmp/preflight-cov.log; }

step "npm audit (both lockfiles)"
for dir in web/console web/v3; do
  (cd "$dir" && npm audit --audit-level=high >/dev/null 2>&1) \
    && ok "$dir" || { bad "$dir"; (cd "$dir" && npm audit --audit-level=high 2>&1 | tail -12); }
done

step "repo invariants"
./scripts/lint-invariants.sh >/dev/null 2>&1 && ok "security invariants" || bad "security invariants"
./scripts/check-no-binaries.sh >/dev/null 2>&1 && ok "no tracked binaries" || bad "no tracked binaries"
./scripts/check-weak-secrets.sh >/dev/null 2>&1 && ok "no weak secrets" || bad "no weak secrets"
./scripts/check-image-pins.sh  >/dev/null 2>&1 && ok "images pinned" || bad "images pinned"

echo
if [ "$fail" -ne 0 ]; then
  printf '\033[31mpreflight: FAILED\033[0m — CI would reject this push.\n'
  exit 1
fi
printf '\033[32mpreflight: OK\033[0m\n'
