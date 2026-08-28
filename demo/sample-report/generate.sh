#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
# AEGIS — generate the sample findings report from a REAL run.
#
# Stands up a throwaway AEGIS in front of a deliberately flawed fictional API,
# drives realistic traffic through it, and exports what the gateway actually
# observed. Nothing in the resulting report is written by hand — the point of
# the artifact is that a prospect is looking at genuine output.
#
#   ./demo/sample-report/generate.sh
#
# Requires: go, curl, redis-server, and a reachable PostgreSQL (the catalog and
# findings live in PG; without it there is no report to export). Override the
# database with POSTGRES_DSN. Everything else is built to a temp dir and torn
# down on exit.
#
# Raw exports land in demo/sample-report/out/ ; the presentable document is
# rendered separately from those files.
# ══════════════════════════════════════════════════════════════════════════════
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HERE="$ROOT/demo/sample-report"
OUT="$HERE/out"
BIN="$(mktemp -d)"

GW=http://127.0.0.1:19080
ADMIN=http://127.0.0.1:19081
REDIS_PORT=16399

: "${POSTGRES_DSN:=postgres://aegis:aegis@127.0.0.1:5432/aegis?sslmode=disable}"

export AEGIS_ADMIN_SECRET="$(openssl rand -hex 32)"
export AEGIS_JWT_SECRET="$(openssl rand -hex 32)"
export AEGIS_REDIS_PASSWORD="samplereport"
export AEGIS_FORENSIC_DSN="$POSTGRES_DSN"

cleanup() {
  [ -n "${GW_PID:-}" ] && kill "$GW_PID" 2>/dev/null || true
  [ -n "${BE_PID:-}" ] && kill "$BE_PID" 2>/dev/null || true
  redis-cli -p "$REDIS_PORT" -a "$AEGIS_REDIS_PASSWORD" --no-auth-warning shutdown nosave 2>/dev/null || true
  rm -rf "$BIN"
}
trap cleanup EXIT

say() { printf '\n\033[1m%s\033[0m\n' "$*"; }

# ── 0. Clean slate ────────────────────────────────────────────────────────────
# The catalog accumulates across runs; a stale row would misreport the estate.
say "0/5  Resetting the sample schema in PostgreSQL"
psql "$POSTGRES_DSN" -q -c "DROP SCHEMA IF EXISTS sample_report CASCADE; CREATE SCHEMA sample_report;" >/dev/null
SAMPLE_DSN="${POSTGRES_DSN}&search_path=sample_report"
export AEGIS_FORENSIC_DSN="$SAMPLE_DSN"

# ── 1. Build ──────────────────────────────────────────────────────────────────
say "1/5  Building gateway, backend and JWT minter"
# The gateway hard-gates on a valid licence, so the stand mints its own throwaway
# keypair and bakes the public half in — exactly the release build path, just
# with a key that lives for the duration of this script.
go run "$ROOT/cmd/licensegen" -genkey -out "$BIN/sample" >"$BIN/genkey.txt" 2>&1
PUBKEY="$(grep -oE '^  [A-Za-z0-9+/=]{40,}$' "$BIN/genkey.txt" | tr -d ' ')"
go build -ldflags "-X api-gateway/internal/license.publicKeyB64=$PUBKEY" -o "$BIN/gateway" "$ROOT/cmd/gateway"
go run "$ROOT/cmd/licensegen" -issue -key "$BIN/sample.key" \
  -licensee "Sample Report Stand" -tier trial -days 1 -out "$BIN/sample.lic" >/dev/null
export AEGIS_LICENSE_PATH="$BIN/sample.lic"

go build -o "$BIN/backend" "$HERE/backend"
go build -o "$BIN/mint" "$ROOT/demo/mint-jwt"
go build -o "$BIN/traffic" "$HERE/traffic"

# ── 2. Boot ───────────────────────────────────────────────────────────────────
say "2/5  Starting Redis, the fictional backend and AEGIS"
redis-server --port "$REDIS_PORT" --requirepass "$AEGIS_REDIS_PASSWORD" \
  --daemonize yes --save '' --appendonly no
"$BIN/backend" >"$BIN/backend.log" 2>&1 & BE_PID=$!
"$BIN/gateway" -config "$HERE/gateway.yaml" >"$BIN/gateway.log" 2>&1 & GW_PID=$!

for _ in $(seq 1 40); do
  curl -fsS "$ADMIN/health" >/dev/null 2>&1 && break
  sleep 0.25
done
curl -fsS "$ADMIN/health" >/dev/null || { echo "gateway failed to start:"; tail -20 "$BIN/gateway.log"; exit 1; }

# A dozen consumers with distinct identities, because "who calls what" is only
# worth a page in the report if there is actually a graph to show. uid is the
# ownership claim; sub is an unrelated email, which is the realistic case.
mint() { "$BIN/mint" -secret "$AEGIS_JWT_SECRET" -sub "$1" -uid "$2" -roles "$3" -ttl 2h; }
T_WEB=$(mint web-checkout@northwind.example 7 user)
T_MOBILE=$(mint mobile-app@northwind.example 9 user)
T_SUPPORT=$(mint support-tools@northwind.example 11 user)
T_PARTNER=$(mint partner-integration@acme-partner.example 12 partner)
T_ANALYTICS=$(mint analytics-batch@northwind.example 13 user)
T_BILLING=$(mint billing-worker@northwind.example 14 service)
T_RECON=$(mint reconciliation@northwind.example 15 service)
T_OPS=$(mint ops-console@northwind.example 16 admin)
T_MARKET=$(mint marketing-sync@northwind.example 17 user)
T_LEGACY=$(mint legacy-importer@northwind.example 18 service)

say "3/5  Driving traffic (ordinary business use, plus the real problems)"
"$BIN/traffic" -gw "$GW" -n 2400 \
  -tokens "web-checkout=7:$T_WEB,mobile-app=9:$T_MOBILE,support-tools=11:$T_SUPPORT,\
partner-integration=12:$T_PARTNER,analytics-batch=13:$T_ANALYTICS,billing-worker=14:$T_BILLING,\
reconciliation=15:$T_RECON,ops-console=16:$T_OPS,marketing-sync=17:$T_MARKET,legacy-importer=18:$T_LEGACY,\
anonymous-partner,uptime-robot"

# ── 3b. Prove the traffic actually landed ─────────────────────────────────────
# Without this the script is happy to "succeed" while every request 404s (a
# route declared without a trailing slash matches only the exact path in
# net/http's ServeMux, so /api/v1/customers never covers /api/v1/customers/7).
# That produced an empty, entirely misleading report the first time this ran —
# fail loudly instead.
say "3b/5 Verifying the traffic reached the backend"
probe() { # path, expected-status, [auth header value]
  local code
  if [ -n "${3:-}" ]; then
    code=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $3" "$GW$1")
  else
    code=$(curl -s -o /dev/null -w '%{http_code}' "$GW$1")
  fi
  if [ "$code" != "$2" ]; then
    echo "  FAIL $1 -> $code (expected $2)"; return 1
  fi
  echo "  ok   $1 -> $code"
}
ok=1
probe /health 200                      || ok=0
probe /api/v1/customers/7 200          || ok=0
probe /internal/reports/export 200     || ok=0
probe /api/v1/orders/1002 200 "$T_WEB"   || ok=0
probe /api/v1/invoices/501 200 "$T_WEB" || ok=0
[ "$ok" = "1" ] || { echo; echo "Traffic is not reaching the backend — the report would be empty/misleading. Aborting."; exit 1; }

# ── 4. Let the catalog flush ──────────────────────────────────────────────────
say "4/5  Waiting for the catalog to flush (5s aggregation window)"
sleep 8

# ── 5. Export ─────────────────────────────────────────────────────────────────
say "5/5  Exporting what the gateway actually observed"
mkdir -p "$OUT"

# The admin plane rate-limits itself (5 req/s, brute-force protection), so a
# tight export loop gets "Access Denied" on the later calls and silently writes
# that string into the artifact. Pace the calls and verify each one.
fetch() { # url, outfile, [expect-json]
  local url="$1" dest="$2" expect="${3:-json}" attempt
  for attempt in 1 2 3 4 5; do
    curl -s -H "Authorization: Bearer $AEGIS_ADMIN_SECRET" "$url" >"$dest"
    if [ "$expect" != "json" ]; then
      [ -s "$dest" ] && return 0
    elif python3 -c "import json,sys; json.load(open(sys.argv[1]))" "$dest" 2>/dev/null; then
      return 0
    fi
    sleep 1
  done
  echo "  FAILED to export $url — got: $(head -c 80 "$dest")"
  return 1
}

fail=0
fetch "$ADMIN/api/findings"          "$OUT/findings.json"   || fail=1
fetch "$ADMIN/api/posture/summary"   "$OUT/posture.json"    || fail=1
fetch "$ADMIN/api/catalog?limit=100" "$OUT/catalog.json"    || fail=1
fetch "$ADMIN/api/consumers"         "$OUT/consumers.json"  || fail=1
fetch "$ADMIN/api/compliance"        "$OUT/compliance.json" || fail=1
fetch "$ADMIN/api/block-log" "$OUT/block-log.json" || fail=1
fetch "$ADMIN/api/report?format=csv"   "$OUT/catalog.csv"  csv || fail=1
fetch "$ADMIN/api/findings?format=csv" "$OUT/findings.csv" csv || fail=1
[ "$fail" = "0" ] || { echo; echo "One or more exports failed — the report would be incomplete. Aborting."; exit 1; }

echo
echo "Raw exports written to demo/sample-report/out/:"
ls -1 "$OUT" | sed 's/^/  /'
echo
echo "Headline numbers:"
python3 - "$OUT" <<'PY'
import json, sys, pathlib
out = pathlib.Path(sys.argv[1])
f = json.loads((out/"findings.json").read_text())
p = json.loads((out/"posture.json").read_text())
print(f"  endpoints discovered : {p.get('total')}")
print(f"  coverage             : {p.get('coverage_pct')}%")
print(f"  findings             : {f.get('count')}  {f.get('by_severity')}")
PY
