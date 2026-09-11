#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
# AEGIS — live evidence demo
#
# The one thing no competitor ships: the auditor verifies the report themselves,
# on their own machine, without trusting the operator or us.
#
# Every other API-security product hands you a dashboard. This hands the auditor
# a document and a static binary, and the binary refuses to say OK unless the
# document is exactly what was signed — and unless the key came from somewhere
# other than the document.
#
# Usage:  ./demo/evidence-demo.sh        # interactive: press Enter between steps
#         ./demo/evidence-demo.sh -y     # run straight through
#
# Requires: go, curl, and whatever scripts/pentest-stand.sh needs (redis-server,
# postgres, openssl). jq is used if present.
# ══════════════════════════════════════════════════════════════════════════════
set -uo pipefail

AUTO=0
[ "${1:-}" = "-y" ] && AUTO=1

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
WORK="$(mktemp -d)"

C_HDR=$'\033[1;36m'; C_OK=$'\033[0;32m'; C_BAD=$'\033[0;31m'
C_DIM=$'\033[0;90m'; C_Y=$'\033[1;33m'; C_B=$'\033[1m'; NC=$'\033[0m'

STAND_STARTED=0
cleanup() {
  echo
  echo "${C_DIM}— tearing down —${NC}"
  [ "$STAND_STARTED" = "1" ] && ./scripts/pentest-stand.sh down >/dev/null 2>&1
  rm -rf "$WORK"
}
trap cleanup EXIT

pause()  { [ "$AUTO" = "1" ] && return 0; echo -n "${C_DIM}   (press Enter)${NC}"; read -r _ || true; }
hdr()    { echo; echo "${C_HDR}$1${NC}"; }
note()   { echo "${C_DIM}   $1${NC}"; }
good()   { echo "   ${C_OK}$1${NC}"; }
bad()    { echo "   ${C_BAD}$1${NC}"; }
die()    { echo "   ${C_BAD}FAILED: $1${NC}"; exit 1; }
pretty() { if command -v jq >/dev/null 2>&1; then jq -C .; else cat; fi; }

# run_verify prints the command as an auditor would type it, then runs it, and
# reports the exit status — which is the whole interface of the tool.
run_verify() {
  local label=$1; shift
  echo "${C_B}   \$ reportverify $*${NC}"
  local out rc
  out=$("$VERIFY" "$@" 2>&1); rc=$?
  echo "$out" | sed 's/^/   /'
  echo "${C_DIM}   exit status $rc${NC}"
  return $rc
}

echo "${C_HDR}AEGIS — how an auditor checks the report${NC}"
echo "${C_DIM}A signed compliance report, and the tool that refuses to lie about it.${NC}"

# ── Stand ─────────────────────────────────────────────────────────────────────
hdr "Bringing up a complete AEGIS (gateway, catalog, PostgreSQL, Redis)"
./scripts/pentest-stand.sh up >"$WORK/stand.log" 2>&1 || {
  tail -20 "$WORK/stand.log"; die "the stand did not come up"
}
STAND_STARTED=1
eval "$(./scripts/pentest-stand.sh env)"
good "gateway $AEGIS_GW · admin $AEGIS_ADMIN"

VERIFY="$WORK/reportverify"
go build -o "$VERIFY" ./cmd/reportverify || die "could not build reportverify"
note "reportverify built — a static binary, no gateway, no database, no network"
pause

# ── 1. Traffic ────────────────────────────────────────────────────────────────
# The stand keeps its PostgreSQL between runs, so without this the counts in the
# report accumulate across demos — 18 requests reported as 84 events. A number
# in the report has to describe the run the audience just watched.
psql "$POSTGRES_DSN" -q -c \
  "TRUNCATE api_endpoints, api_endpoint_status, api_endpoint_consumers,
            api_consumers, api_specs, incidents, forensic_logs;" >/dev/null 2>&1 \
  || note "could not reset the catalog; counts may include earlier runs"

hdr "① Ordinary traffic goes through the gateway"
note "Nothing here is staged: the report below is computed from these requests."
for i in $(seq 1 12); do
  curl -s -o /dev/null "$AEGIS_GW/public/orders/$i" -H "X-API-Key: partner-key-a"
done
# An endpoint reached with no credentials at all — the shape that becomes an
# API3 finding once the catalog has seen it.
for i in $(seq 1 6); do
  curl -s -o /dev/null "$AEGIS_GW/public/customers/$i"
done
# A payload the WAF stops. It never reaches the catalog, which is the point:
# attack noise does not pollute the map of the real API.
curl -s -o /dev/null "$AEGIS_GW/public/orders?id=1%20OR%201=1--"
good "18 requests through the data plane, 1 blocked by the WAF"
note "The catalog aggregates in 5-second windows; waiting for the flush."
sleep 7
pause

# ── 2. What the gateway observed ──────────────────────────────────────────────
hdr "② The catalog — built from traffic, not from a spreadsheet"
curl -s -H "Authorization: Bearer $AEGIS_ADMIN_SECRET" \
  "$AEGIS_ADMIN/api/catalog?limit=10" > "$WORK/catalog.json"
python3 - "$WORK/catalog.json" <<'PY' 2>/dev/null || pretty < "$WORK/catalog.json" | head -20
import json, sys
cat = json.load(open(sys.argv[1]))
eps = cat.get("endpoints") or []
print(f"   {'endpoint':<34} {'reqs':>5} {'anon':>5} {'posture':<12} {'risk':>4}  data")
print(f"   {'-'*34} {'-'*5} {'-'*5} {'-'*12} {'-'*4}  {'-'*24}")
for e in eps:
    data = ", ".join(e.get("pii_types") or []) or "-"
    print(f"   {e.get('id','?'):<34} {e.get('request_count',0):>5} "
          f"{e.get('anon_count',0):>5} {e.get('posture','?'):<12} "
          f"{e.get('risk_score',0):>4}  {data}")
print()
print(f"   {len(eps)} endpoint(s) discovered from traffic alone — no spec was imported.")
PY
note "Paths are normalised: /public/orders/7 and /public/orders/8 are one endpoint."
note "The SQL injection never appears: the WAF stopped it before the catalog saw it."
pause

# ── 3. The key the auditor pins ───────────────────────────────────────────────
hdr "③ The auditor pins the signing key — out of band, before any report"
KEYJSON=$(curl -s -H "Authorization: Bearer $AEGIS_ADMIN_SECRET" \
  "$AEGIS_ADMIN/api/report/signing-key")
echo "$KEYJSON" | pretty | sed 's/^/   /'
KEY_ID=$(echo "$KEYJSON" | sed -n 's/.*"key_id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
[ -n "$KEY_ID" ] || die "the gateway has no signing key configured"
note "This is the one fact the auditor must get from somewhere other than the report."
pause

# ── 4. The signed report ──────────────────────────────────────────────────────
hdr "④ The operator exports the signed compliance report"
curl -s -H "Authorization: Bearer $AEGIS_ADMIN_SECRET" \
  "$AEGIS_ADMIN/api/compliance?sign=1" > "$WORK/report.json"
python3 - "$WORK/report.json" <<'PY' 2>/dev/null || head -c 400 "$WORK/report.json"
import json, sys
env = json.load(open(sys.argv[1]))
att = env.get("attestation", {})
print(f"   algorithm  {att.get('algorithm')}")
print(f"   key_id     {att.get('key_id')}")
print(f"   signed_at  {att.get('signed_at')}   (inside the signature)")
print(f"   digest     {att.get('digest')}")
doc = json.loads(env["document"])
frameworks = doc.get("frameworks") or []
mapped = sum(len(f.get("controls") or []) for f in frameworks)
unevidenced = sum(len(f.get("not_evidenced") or []) for f in frameworks)
summary = doc.get("summary") or {}
print()
print(f"   tenant     {doc.get('tenant')}")
print(f"   frameworks {', '.join(f.get('framework', '?') for f in frameworks) or 'none'}")
print(f"   evidenced  {mapped} controls · {summary.get('critical', 0)} critical")
print()
# Two real rows, so the audience sees a regulation article tied to an
# observation rather than a number.
shown = 0
for f in frameworks:
    if f.get("framework") == "OWASP API Top 10":
        continue  # the regulator-facing frameworks are the point
    for c in (f.get("controls") or []):
        issues = c.get("issues") or []
        print(f"   {f['framework']} {c.get('control')} — {c.get('title')}")
        print(f"      {c.get('severity')}, {c.get('count')} issue(s): {issues[0] if issues else '-'}")
        shown += 1
        if shown == 2:
            break
    if shown == 2:
        break
print()
if unevidenced:
    print(f"   And {unevidenced} control(s) the report names as NOT evidenced:")
    for f in frameworks:
        for u in (f.get("not_evidenced") or [])[:2]:
            print(f"      {f['framework']} {u.get('control')} — {u.get('reason')}")
else:
    print("   not_evidenced is empty in THIS run: the traffic above opened incidents,")
    print("   so the incident-lifecycle controls are genuinely covered. On a gateway")
    print("   that has never seen one, they are listed here as not evidenced rather")
    print("   than quietly counted as passing.")
PY
note "The document travels as a string of its own JSON, so a byte cannot shift."
pause

# ── 5. It verifies ────────────────────────────────────────────────────────────
hdr "⑤ The auditor verifies it against the key they pinned"
if run_verify "ok" -in "$WORK/report.json" -key-id "$KEY_ID"; then
  good "The document is exactly what was signed."
else
  die "a genuine report failed to verify"
fi
pause

# ── 6. One digit changed ──────────────────────────────────────────────────────
hdr "⑥ Now someone edits one number — the signature is left untouched"
python3 - "$WORK/report.json" "$WORK/tampered.json" <<'PY'
import json, re, sys
env = json.load(open(sys.argv[1]))
doc = env["document"]
# Change exactly one digit somewhere in the document text. Nothing else is
# touched — not the signature, not the key, not the timestamp.
m = re.search(r'(: *)(\d+)', doc)
if not m:
    doc = doc.replace("}", ', "injected": 1}', 1)
else:
    start, end = m.span(2)
    doc = doc[:start] + str(int(m.group(2)) + 1) + doc[end:]
env["document"] = doc
json.dump(env, open(sys.argv[2], "w"))
print("   one integer in the document incremented by 1; attestation untouched")
PY
if run_verify "tampered" -in "$WORK/tampered.json" -key-id "$KEY_ID"; then
  die "the tampered report verified — that must never happen"
else
  good "Refused. The digest no longer matches the bytes."
fi
pause

# ── 7. The wrong pinned key ───────────────────────────────────────────────────
hdr "⑦ And a genuine report checked against a different pinned key"
OTHER_KEY=$("$VERIFY" -genkey | sed -n 's/^key_id: *//p' | tr -d ' ')
note "A second key, generated here: $OTHER_KEY"
if run_verify "wrong key" -in "$WORK/report.json" -key-id "$OTHER_KEY"; then
  die "a report verified against a key that did not sign it"
else
  good "Refused. The report names which key actually signed it."
fi
pause

# ── 8. The point ──────────────────────────────────────────────────────────────
hdr "⑧ The check that makes the rest mean anything"
note "A signed report carries the public key that signed it. So it is always"
note "possible to check a report against ITSELF — and that proves nothing:"
note "a forger edits the numbers, signs with a key they invented, and ships both."
if run_verify "unpinned" -in "$WORK/report.json"; then
  die "the verifier ran without a pinned key"
else
  good "The tool refuses to run at all."
fi

echo
echo "${C_Y}${C_B}   That refusal is the product.${NC}"
echo "${C_DIM}   Everything else in this category ends at a dashboard: a claim you${NC}"
echo "${C_DIM}   are asked to believe. This ends at a document an assessor checks${NC}"
echo "${C_DIM}   without trusting the operator, the vendor, or the gateway.${NC}"
echo
