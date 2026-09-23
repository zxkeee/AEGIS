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
#   - security.yml was never run at all, while the header below claimed this
#     script mirrored it. gosec and govulncheck are that workflow's entire
#     content, so "preflight: OK" was asserting something it had not checked.
#
# Mirrors .github/workflows/{lint,test,security}.yml. When those change, change
# this — a preflight that has drifted from CI is worse than none, because it
# buys confidence it cannot back.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# `go install` puts the pinned tools in GOPATH/bin, which is not on PATH in a
# default shell. Without this the script installed golangci-lint, gosec and
# govulncheck and then reported all three as "command not found" — three FAILs
# that said nothing about the code. Prepend it so the tools this script just
# installed are the ones it runs.
PATH="$(go env GOPATH)/bin:$PATH"
export PATH

# Pinned to match .github/workflows/lint.yml exactly.
GOLANGCI_VERSION=v2.12.2
GOSEC_VERSION=v2.28.0
GOVULNCHECK_VERSION=v1.6.0

fail=0
step() { printf '\n\033[1m── %s\033[0m\n' "$*"; }
ok()   { printf '   \033[32mok\033[0m %s\n' "$*"; }
bad()  { printf '   \033[31mFAIL\033[0m %s\n' "$*"; fail=1; }

# ── Integration environment ───────────────────────────────────────────────────
# Without reachable stores the suite still passes, but the packages backed by
# Redis/PostgreSQL skip their integration tests and the coverage gate then
# measures something CI does not.
#
# This used to be a warning, after which the gate ran anyway and the script
# ended with "CI would reject this push" — on a commit CI had already accepted
# with every check green. Reporting "I could not check" as "this is broken" is
# the same class of defect as reporting a failure as a pass: both teach the
# reader to stop believing the output. The stores are now PROBED, not merely
# assumed from the environment, because a DSN pointing at a stopped container
# fails in exactly the same way as an unset one.
stores=ok
store_why=""
note() { printf '   \033[33m--\033[0m %s\n' "$*"; }

if [ -z "${REDIS_ADDR:-}" ] || [ -z "${POSTGRES_DSN:-}" ]; then
  stores=missing
  store_why="REDIS_ADDR / POSTGRES_DSN are unset"
else
  if command -v redis-cli >/dev/null 2>&1; then
    redis-cli -u "redis://${REDIS_ADDR}" ping >/dev/null 2>&1 \
      || { stores=missing; store_why="Redis at ${REDIS_ADDR} did not answer"; }
  fi
  if command -v pg_isready >/dev/null 2>&1; then
    pg_isready -d "$POSTGRES_DSN" -q >/dev/null 2>&1 \
      || { stores=missing; store_why="PostgreSQL in POSTGRES_DSN did not answer"; }
  fi
fi

if [ "$stores" = missing ]; then
  step "integration stores"
  note "$store_why"
  note "integration tests will skip; coverage cannot be compared with CI"
  note "start them, e.g.: make stand-test"
else
  # Which role the tests run as decides whether RLS is exercised at all. A
  # superuser (or any BYPASSRLS role) silently skips every tenant-isolation
  # guarantee, so a green run under one proves strictly less than under an
  # ordinary role — and that difference has already hidden a defect once.
  #
  # POSTGRES_APP_DSN is what CI sets: tests connect as that unprivileged role,
  # while POSTGRES_DSN stays superuser for the few that must CREATE ROLE.
  if command -v psql >/dev/null 2>&1; then
    probe_dsn="${POSTGRES_APP_DSN:-$POSTGRES_DSN}"
    rls=$(psql "$probe_dsn" -tAc \
      "SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user" 2>/dev/null || true)
    if [ "$rls" = "t" ]; then
      step "integration stores"
      note "the PostgreSQL role the tests connect as bypasses row-level security"
      note "RLS-dependent checks are NOT exercised in this run"
      note "set POSTGRES_APP_DSN to an unprivileged role, as CI does"
    fi
  fi
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
if [ "$stores" = missing ]; then
  # Running it here would measure a suite with its integration tests skipped and
  # report the shortfall as a regression. Not checked is not the same as failed.
  note "not checked — needs the integration stores"
  cov_unchecked=1
else
  ./scripts/coverage-gate.sh > /tmp/preflight-cov.log 2>&1 \
    && ok "floors held" || { bad "a package dropped below its floor"; grep BELOW /tmp/preflight-cov.log; }
fi

# ── gosec / govulncheck ───────────────────────────────────────────────────────
# These are the whole of security.yml, and this script claimed to mirror it
# while running neither. A preflight that silently omits a CI job is the exact
# failure this file was written to prevent, so it now runs both — and installs
# them with the CURRENT toolchain rather than trusting whatever is on PATH.
#
# A govulncheck binary built by an older Go cannot parse a module whose sources
# use newer language features; it fails with "file requires newer Go version"
# and an exit code that is easy to read as "no vulnerabilities". Reinstalling
# pins the build to the toolchain in go.mod, the same thing CI does and for the
# same reason.
step "gosec $GOSEC_VERSION"
go install "github.com/securego/gosec/v2/cmd/gosec@$GOSEC_VERSION" >/dev/null 2>&1 || bad "gosec install"
gosec -quiet -severity medium ./... >/tmp/preflight-gosec.log 2>&1 \
  && ok "root module" || { bad "root module"; grep -E '^\[|Severity' /tmp/preflight-gosec.log | head -12; }
(cd web && gosec -quiet -severity medium ./... >/tmp/preflight-gosec-web.log 2>&1) \
  && ok "web module" || { bad "web module"; tail -12 /tmp/preflight-gosec-web.log; }

step "govulncheck $GOVULNCHECK_VERSION"
go install "golang.org/x/vuln/cmd/govulncheck@$GOVULNCHECK_VERSION" >/dev/null 2>&1 || bad "govulncheck install"
for mod in . web; do
  out=$( (cd "$mod" && govulncheck ./... 2>&1) )
  rc=$?
  name=$([ "$mod" = "." ] && echo "root module" || echo "web module")
  # "requires newer Go version" means the scanner could not read the sources at
  # all. That is not a clean result and must never be reported as one.
  if printf '%s' "$out" | grep -q 'requires newer Go version'; then
    bad "$name — govulncheck could not parse the sources (toolchain mismatch); it scanned nothing"
    printf '%s\n' "$out" | grep 'requires newer Go version' | head -3
  elif [ "$rc" -ne 0 ]; then
    bad "$name"
    printf '%s\n' "$out" | tail -15
  else
    ok "$name"
  fi
done

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
./scripts/check-support-bundle.sh >/tmp/preflight-bundle.log 2>&1 \
  && ok "support bundle leaks no secrets" \
  || { bad "the support bundle carries secrets"; cat /tmp/preflight-bundle.log; }
python3 ./scripts/check-doc-drift.py >/tmp/preflight-drift.log 2>&1 \
  && ok "docs match the code" || { bad "docs and code disagree about what exists"; cat /tmp/preflight-drift.log; }
python3 ./scripts/check-plan-tables.py >/tmp/preflight-plan.log 2>&1 \
  && ok "no duplicated rows in the planning tables" \
  || { bad "a planning document lists the same thing twice"; cat /tmp/preflight-plan.log; }
# Exit 2 from this check means "could not answer" (a shallow clone), which is
# neither a pass nor a contradiction — reporting it as FAILED would put a lie in
# the output of the tool whose whole job is not to lie about verdicts.
python3 ./scripts/check-handoff.py >/tmp/preflight-handoff.log 2>&1
case $? in
  0) ok "handoff matches the merge history" ;;
  2) note "handoff check could not run"; cat /tmp/preflight-handoff.log ;;
  *) bad "handoff contradicts the repository"; cat /tmp/preflight-handoff.log ;;
esac

# Not a gate: a forge being down does not make the code wrong, so this never
# sets `fail`. It exists because the primary forge was unreachable for five days
# and nobody noticed — the work sat on one laptop while both copies of the
# history were assumed to be fine. A push that cannot land is worth one line of
# output before the run that produces it.
step "where this push can land"
for remote in $(git remote 2>/dev/null); do
  url=$(git remote get-url "$remote" 2>/dev/null)
  if GIT_TERMINAL_PROMPT=0 git ls-remote --exit-code "$remote" HEAD >/dev/null 2>&1; then
    ahead=$(git rev-list --count "$remote/$(git rev-parse --abbrev-ref HEAD)"..HEAD 2>/dev/null || echo "?")
    if [ "$ahead" = "0" ]; then ok "$remote up to date"; else note "$remote reachable, $ahead commit(s) not pushed"; fi
  else
    note "$remote UNREACHABLE ($url) — history is not backed up there"
  fi
done

echo
if [ "$fail" -ne 0 ]; then
  printf '\033[31mpreflight: FAILED\033[0m — CI would reject this push.\n'
  exit 1
fi
if [ "${cov_unchecked:-0}" -ne 0 ]; then
  # Exit 2, not 0 and not 1: everything that could be checked passed, and one
  # thing could not be. A caller that treats this as success is making the same
  # mistake this script just stopped making.
  printf '\033[33mpreflight: INCOMPLETE\033[0m — everything checked passed, but the\n'
  printf '            coverage gate needs Redis and PostgreSQL (%s).\n' "$store_why"
  exit 2
fi
printf '\033[32mpreflight: OK\033[0m\n'
