#!/usr/bin/env bash
# Stand AEGIS in front of Codeberg (a public Forgejo) and drive genuine
# read-only browsing through it, to measure how many findings a real,
# third-party API produces — and how many of them are true.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
BIN="$(mktemp -d)"
GW=http://127.0.0.1:19080
ADMIN=http://127.0.0.1:19081
REDIS_PORT=16399

: "${POSTGRES_DSN:=postgres://aegis:aegis@127.0.0.1:5432/aegis?sslmode=disable}"
export AEGIS_ADMIN_SECRET="$(openssl rand -hex 32)"
export AEGIS_REDIS_PASSWORD="fpassess"

cleanup() {
  [ -n "${GW_PID:-}" ] && kill "$GW_PID" 2>/dev/null || true
  redis-cli -p "$REDIS_PORT" -a "$AEGIS_REDIS_PASSWORD" --no-auth-warning shutdown nosave 2>/dev/null || true
  rm -rf "$BIN"
}
trap cleanup EXIT
say() { printf '\n\033[1m%s\033[0m\n' "$*"; }

for p in 19080 19081; do
  if lsof -nP -iTCP:$p -sTCP:LISTEN >/dev/null 2>&1; then echo "порт $p занят"; exit 1; fi
done

say "0/4  Чистая схема в PostgreSQL"
psql "$POSTGRES_DSN" -q -c "DROP SCHEMA IF EXISTS fp_assess CASCADE; CREATE SCHEMA fp_assess;" >/dev/null
export AEGIS_FORENSIC_DSN="${POSTGRES_DSN}&search_path=fp_assess"

say "1/4  Сборка (лицензия одноразовая, как в релизной сборке)"
go run "$ROOT/cmd/licensegen" -genkey -out "$BIN/k" >"$BIN/genkey.txt" 2>&1
PUBKEY="$(grep -oE '^  [A-Za-z0-9+/=]{40,}$' "$BIN/genkey.txt" | tr -d ' ')"
go build -ldflags "-X api-gateway/internal/license.publicKeyB64=$PUBKEY" -o "$BIN/gateway" "$ROOT/cmd/gateway"
go run "$ROOT/cmd/licensegen" -issue -key "$BIN/k.key" -licensee "FP assessment" \
  -tier trial -days 1 -out "$BIN/k.lic" >/dev/null
export AEGIS_LICENSE_PATH="$BIN/k.lic"

say "2/4  Старт Redis и AEGIS"
redis-server --port "$REDIS_PORT" --requirepass "$AEGIS_REDIS_PASSWORD" \
  --daemonize yes --save '' --appendonly no
"$BIN/gateway" -config "$HERE/gateway.yaml" >"$BIN/gateway.log" 2>&1 & GW_PID=$!
for _ in $(seq 1 60); do curl -fsS "$ADMIN/health" >/dev/null 2>&1 && break; sleep 0.25; done
curl -fsS "$ADMIN/health" >/dev/null || { echo "шлюз не поднялся:"; tail -20 "$BIN/gateway.log"; exit 1; }
code=$(curl -s -o /dev/null -w '%{http_code}' -m 25 "$GW/api/v1/version")
[ "$code" = "200" ] || { echo "сквозной проход не работает: $code"; tail -20 "$BIN/gateway.log"; exit 1; }
echo "  сквозной проход ок"

say "3/4  Настоящий трафик через шлюз"
python3 "$HERE/traffic.py" "$GW"

say "4/4  Экспорт наблюдений"
sleep 8
mkdir -p "$HERE/out"
LOGIN=$(curl -s -c "$BIN/c" -X POST "$ADMIN/api/login" -H 'Content-Type: application/json' \
        -d "{\"secret\":\"$AEGIS_ADMIN_SECRET\"}")
CSRF=$(printf '%s' "$LOGIN" | python3 -c "import json,sys;print(json.load(sys.stdin).get('csrf_token',''))")
fetch() {
  for _ in 1 2 3 4 5; do
    if curl -fsS -b "$BIN/c" -H "X-CSRF-Token: $CSRF" -m 30 "$ADMIN$1" -o "$2" 2>/dev/null; then
      head -c1 "$2" | grep -qE '[[{]' && return 0
    fi
    sleep 2
  done
  echo "  не удалось выгрузить $1"; return 1
}
fetch /api/findings   "$HERE/out/findings.json"
fetch /api/catalog    "$HERE/out/catalog.json"
fetch /api/consumers  "$HERE/out/consumers.json"
fetch /api/posture    "$HERE/out/posture.json"
fetch "/api/block-log?limit=1000" "$HERE/out/block-log.json"
cp "$BIN/gateway.log" "$HERE/out/gateway.log" 2>/dev/null || true
echo "  экспорт в $HERE/out/"
