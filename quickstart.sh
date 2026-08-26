#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
# AEGIS — see it work, from a clean checkout, in about two minutes.
#
#   ./quickstart.sh
#
# Stands AEGIS up in front of a deliberately flawed API, sends ordinary traffic
# through it, and prints what the gateway found. Then leaves everything running
# so you can poke at the admin API yourself. Ctrl-C tears it all down.
#
# Needs: go, curl, redis-server (brew install redis / apt install redis-server),
# and PostgreSQL. The catalog and findings live in Postgres — without it the
# gateway still runs, but there is nothing interesting to show, so this script
# asks for it up front rather than showing you an empty result.
#
#   POSTGRES_DSN=postgres://user:pass@host:5432/db?sslmode=disable ./quickstart.sh
# ══════════════════════════════════════════════════════════════════════════════
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$(mktemp -d)"
GW=http://127.0.0.1:19080
ADMIN=http://127.0.0.1:19081
REDIS_PORT=16399

: "${POSTGRES_DSN:=postgres://aegis:aegis@127.0.0.1:5432/aegis?sslmode=disable}"

bold()  { printf '\033[1m%s\033[0m\n' "$*"; }
dim()   { printf '\033[2m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
red()   { printf '\033[31m%s\033[0m\n' "$*"; }

# ── Preflight ─────────────────────────────────────────────────────────────────
missing=0
for cmd in go curl redis-server psql python3; do
  command -v "$cmd" >/dev/null 2>&1 || { red "missing: $cmd"; missing=1; }
done
[ "$missing" = "0" ] || { echo; echo "Install the tools above and re-run."; exit 1; }

# A gateway left over from a previous run keeps these ports and answers every
# request with the *old* admin secret — which looks exactly like a broken build
# until you think to check. Refuse to start on top of one.
for port in 19080 19081; do
  if lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then
    red "Port $port is already in use — most likely a gateway left running by an earlier run."
    echo
    echo "  lsof -nP -iTCP:$port -sTCP:LISTEN     # see what it is"
    echo "  pkill -f 'gateway -config'            # stop it"
    exit 1
  fi
done

if ! psql "$POSTGRES_DSN" -q -c 'SELECT 1' >/dev/null 2>&1; then
  red "Cannot reach PostgreSQL at: $POSTGRES_DSN"
  echo
  echo "AEGIS keeps its API catalog and findings there. Start one, or point this"
  echo "script at an existing database:"
  echo
  echo "  POSTGRES_DSN='postgres://user:pass@host:5432/db?sslmode=disable' ./quickstart.sh"
  exit 1
fi

cleanup() {
  echo
  dim "shutting down…"
  [ -n "${GW_PID:-}" ] && kill "$GW_PID" 2>/dev/null || true
  [ -n "${BE_PID:-}" ] && kill "$BE_PID" 2>/dev/null || true
  redis-cli -p "$REDIS_PORT" -a quickstart --no-auth-warning shutdown nosave 2>/dev/null || true
  rm -rf "$BIN"
}
trap cleanup EXIT INT TERM

export AEGIS_ADMIN_SECRET="$(openssl rand -hex 32)"
export AEGIS_JWT_SECRET="$(openssl rand -hex 32)"
export AEGIS_REDIS_PASSWORD="quickstart"

# ── 1. Build ──────────────────────────────────────────────────────────────────
bold "① Building"
# AEGIS will not start without a signed licence (docs/licensing.md). For local
# evaluation you mint your own: a throwaway keypair, its public half baked into
# the binary, and a short-lived *trial* licence — which the tier gate then runs
# in observe-only mode. Exactly what the BUSL grant allows for free.
go run ./cmd/licensegen -genkey -out "$BIN/eval" >"$BIN/genkey.txt" 2>&1
PUBKEY="$(grep -oE '^  [A-Za-z0-9+/=]{40,}$' "$BIN/genkey.txt" | tr -d ' ')"
go build -ldflags "-X api-gateway/internal/license.publicKeyB64=$PUBKEY" -o "$BIN/gateway" ./cmd/gateway
go run ./cmd/licensegen -issue -key "$BIN/eval.key" \
  -licensee "Local evaluation" -tier trial -days 1 -out "$BIN/eval.lic" >/dev/null 2>&1
export AEGIS_LICENSE_PATH="$BIN/eval.lic"
go build -o "$BIN/backend" ./demo/sample-report/backend
go build -o "$BIN/mint" ./demo/mint-jwt
dim "   gateway, sample backend and a throwaway evaluation licence"

# ── 2. Start ──────────────────────────────────────────────────────────────────
bold "② Starting Redis, a deliberately flawed API, and AEGIS in front of it"
psql "$POSTGRES_DSN" -q -c "DROP SCHEMA IF EXISTS quickstart CASCADE; CREATE SCHEMA quickstart;" >/dev/null
export AEGIS_FORENSIC_DSN="${POSTGRES_DSN}&search_path=quickstart"
redis-server --port "$REDIS_PORT" --requirepass "$AEGIS_REDIS_PASSWORD" \
  --daemonize yes --save '' --appendonly no
"$BIN/backend" >"$BIN/backend.log" 2>&1 & BE_PID=$!
"$BIN/gateway" -config ./demo/sample-report/gateway.yaml >"$BIN/gateway.log" 2>&1 & GW_PID=$!

for _ in $(seq 1 40); do curl -fsS "$ADMIN/health" >/dev/null 2>&1 && break; sleep 0.25; done
curl -fsS "$ADMIN/health" >/dev/null || { red "gateway did not start:"; tail -20 "$BIN/gateway.log"; exit 1; }
dim "   data plane $GW · admin plane $ADMIN"

# ── 3. Traffic ────────────────────────────────────────────────────────────────
bold "③ Sending ordinary traffic through it"
ALICE="$("$BIN/mint" -secret "$AEGIS_JWT_SECRET" -sub alice.renner@example.com -uid 7)"
BOB="$("$BIN/mint" -secret "$AEGIS_JWT_SECRET" -sub bob.kessler@example.com -uid 9)"

for i in 1001 1003; do curl -s -o /dev/null -H "Authorization: Bearer $ALICE" "$GW/api/v1/orders/$i"; done
for i in 501 502; do curl -s -o /dev/null -H "Authorization: Bearer $ALICE" "$GW/api/v1/invoices/$i"; done
curl -s -o /dev/null -X POST -H "Authorization: Bearer $ALICE" -H 'Content-Type: application/json' \
  -d '{"amount":"25.00"}' "$GW/api/v1/payments"
# Nobody authenticates to read customer records — including their card numbers.
for id in 7 9 11 12 13; do curl -s -o /dev/null "$GW/api/v1/customers/$id"; done
# One authenticated user reads orders that are not theirs.
for i in 1001 1003 1004 1005; do curl -s -o /dev/null -H "Authorization: Bearer $BOB" "$GW/api/v1/orders/$i"; done
curl -s -o /dev/null "$GW/internal/reports/export"
dim "   28 requests: normal business use, plus the two things that are actually wrong"

bold "④ Waiting for the catalog to flush"
sleep 8

# ── 5. Show ───────────────────────────────────────────────────────────────────
bold "⑤ What AEGIS found — none of this was configured in advance"
echo
curl -s -H "Authorization: Bearer $AEGIS_ADMIN_SECRET" "$ADMIN/api/findings" >"$BIN/f.json"
sleep 1
curl -s -H "Authorization: Bearer $AEGIS_ADMIN_SECRET" "$ADMIN/api/catalog?limit=50" >"$BIN/c.json"
sleep 1
curl -s -H "Authorization: Bearer $AEGIS_ADMIN_SECRET" "$ADMIN/api/block-log?limit=50" >"$BIN/b.json"

python3 - "$BIN" <<'PY'
import json, pathlib, sys
b = pathlib.Path(sys.argv[1])
def load(n):
    try: return json.loads((b/n).read_text())
    except Exception: return {}
f, c, bl = load("f.json"), load("c.json"), load("b.json")

R, D, B = "\033[31m", "\033[2m", "\033[1m"; X = "\033[0m"
for row in f.get("findings", []):
    fi = row["finding"]
    print(f"  {R}{fi['severity'].upper()}{X}  {B}{fi['title']}{X}")
    print(f"         {row['method']} {row['path_template']}   {D}{fi['owasp']}{X}")
    print(f"         {fi['why']}\n")

ev = bl if isinstance(bl, list) else bl.get("entries", bl.get("events", []))
idor = {}
for e in ev:
    x = e.get("extra") or {}
    if e.get("reason") == "bola_object_ownership":
        idor[x.get("object_id")] = x.get("why")
if idor:
    print(f"  {R}CRITICAL{X}  {B}Confirmed IDOR — a user reading other users' records{X}")
    print(f"         {len(idor)} objects; the owner was read from each response body")
    print(f"         {D}{list(idor.values())[0]}{X}\n")

eps = c if isinstance(c, list) else c.get("endpoints", [])
if eps:
    print(f"  {B}API inventory discovered from traffic{X}")
    for e in sorted(eps, key=lambda x: -x.get("risk_score", 0)):
        p = e.get("posture", "")
        col = R if p == "unprotected" else ""
        print(f"         {col}{p:<12}{X} {e['method']:<5} {e['path_template']:<30}"
              f" {D}req={e.get('request_count',0)} anon={e.get('anon_count',0)} pii={e.get('pii_count',0)}{X}")
PY

echo
green "Still running — explore it yourself:"
echo
echo "  export TOKEN=$AEGIS_ADMIN_SECRET"
echo "  curl -s -H \"Authorization: Bearer \$TOKEN\" $ADMIN/api/findings | python3 -m json.tool"
echo "  curl -s -H \"Authorization: Bearer \$TOKEN\" $ADMIN/api/consumers | python3 -m json.tool"
echo "  curl -s -H \"Authorization: Bearer \$TOKEN\" $ADMIN/api/compliance | python3 -m json.tool"
echo
dim "  The web console is at $ADMIN (same token). Ctrl-C to stop everything."
echo
# wait, not a sleep loop: this stays interruptible, so Ctrl-C reaches the trap
# and actually tears the gateway down instead of orphaning it on these ports.
wait "$GW_PID"
