#!/usr/bin/env bash
# support-bundle.sh — collect what a support conversation needs, and nothing else.
#
# The first exchange of every support thread is "which version, what config,
# what did the logs say", and it takes a day when it happens by email. This
# collects it in one step.
#
# WHAT IT REFUSES TO COLLECT is the more important half. No request bodies, no
# forensic log contents, no secret values. The configuration is emitted with
# every secret-bearing field replaced, and the redaction works on the KEY name
# rather than on a list of known paths, because a list only ever covers the
# fields somebody remembered — and this repository has already shipped one
# ConfigMap leak that a per-field allowlist was supposed to prevent.
#
#   ./scripts/support-bundle.sh [-c config.yaml] [-a http://127.0.0.1:8081]
#
# Read the bundle before sending it. It is your data and it leaves your
# infrastructure.
set -uo pipefail

# Captured BEFORE the cd below: the bundle belongs where the operator ran the
# command, not in the repository root, and BUNDLE_DIR lets a caller say so
# explicitly. The cd exists so the log and binary paths below stay relative to
# the checkout.
BUNDLE_DIR="${BUNDLE_DIR:-$PWD}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

CONFIG="config/gateway.yaml"
ADMIN=""
while getopts "c:a:h" opt; do
  case $opt in
    c) CONFIG="$OPTARG" ;;
    a) ADMIN="$OPTARG" ;;
    h) sed -n '2,20p' "$0"; exit 0 ;;
    *) exit 2 ;;
  esac
done

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="support-bundle-$STAMP"
mkdir -p "$OUT" || { echo "cannot create $OUT"; exit 1; }

say() { printf '   %s\n' "$*"; }

# ── version ─────────────────────────────────────────────────────────────────
{
  if [ -x bin/gateway ]; then
    ./bin/gateway -version 2>&1
  else
    echo "bin/gateway not built; run 'make build' on the affected host"
  fi
  echo
  echo "go:  $(go version 2>/dev/null || echo 'not installed')"
  echo "os:  $(uname -a)"
} > "$OUT/version.txt" 2>&1
say "version.txt"

# ── configuration, redacted ─────────────────────────────────────────────────
#
# Key-based redaction: any key whose name contains secret, password, token,
# key, dsn, url, salt, credential, passphrase or private keeps its shape and
# loses its value. Over-redacting a URL is a nuisance; under-redacting a DSN
# posts a database password into a support thread, and the two mistakes are not
# comparable.
#
# `salt` is in that list because the canary check put it there, not because it
# was foreseen: the first version of this word list omitted it, and
# consumer_id.salt is what makes the catalog irreversible — without it the
# consumer graph turns back into live API keys. A word list only ever covers
# what somebody remembered, which is why scripts/check-support-bundle.sh exists
# and why it plants a canary in every secret-bearing field rather than trusting
# this regex.
if [ -f "$CONFIG" ]; then
  python3 - "$CONFIG" > "$OUT/config-redacted.yaml" <<'PY'
import re, sys

SECRET = re.compile(
    r'^(\s*(?:-\s*)?[\w.\-]*(?:secret|password|passwd|token|api_key|apikey|key|dsn|url|uri|salt|credential|passphrase|private)[\w.\-]*\s*:\s*)(.+)$',
    re.IGNORECASE)

# Credentials embedded in a URL, whatever the key is called. An upstream is not
# a secret field and "http://user:pass@backend" in one is still a password in a
# support thread. Key-based redaction cannot see this, which is why it is a
# second pass rather than another word in the list above.
URLCREDS = re.compile(r'(\w+://)[^/\s"\']+:[^/\s"\']+@')

for line in open(sys.argv[1], encoding="utf-8"):
    line = line.rstrip("\n")
    m = SECRET.match(line)
    if m and m.group(2).strip() not in ("", "{}", "[]", "|", ">"):
        print(m.group(1) + "<redacted>")
    else:
        print(URLCREDS.sub(r'\1<redacted>@', line))
PY
  say "config-redacted.yaml"
else
  echo "config not found at $CONFIG" > "$OUT/config-redacted.yaml"
  say "config not found at $CONFIG — pass -c"
fi

# ── environment: names only, never values ───────────────────────────────────
env | grep -oE '^AEGIS_[A-Z_]+' | sort > "$OUT/env-names.txt" 2>/dev/null
say "env-names.txt (names only — no values are read)"

# ── live state, when an admin endpoint was given ────────────────────────────
if [ -n "$ADMIN" ]; then
  # The admin plane needs a bearer token. It is deliberately NOT read from the
  # environment here: a token pasted into a support bundle is a token to
  # rotate, and the two endpoints below are the only ones worth the risk.
  for path in health readyz; do
    curl -s --max-time 5 "$ADMIN/$path" > "$OUT/$path.json" 2>&1
  done
  say "health.json, readyz.json"
else
  echo "no admin endpoint given (-a); pass one for health and readiness" > "$OUT/health.json"
  say "no -a given, skipping live state"
fi

# ── recent log lines ────────────────────────────────────────────────────────
#
# Bounded: the tail is what a support thread reads, and a whole log is both
# unusable and far more likely to contain something the sender did not intend
# to share.
for candidate in .stand/gateway.log /var/log/aegis/gateway.log gateway.log; do
  if [ -f "$candidate" ]; then
    tail -n 500 "$candidate" > "$OUT/gateway-tail.log"
    say "gateway-tail.log (last 500 lines of $candidate)"
    break
  fi
done
[ -f "$OUT/gateway-tail.log" ] || {
  echo "no gateway log found; attach the last few hundred lines by hand" > "$OUT/gateway-tail.log"
  say "no log file found — attach one by hand"
}

cat > "$OUT/README.txt" <<TXT
AEGIS support bundle — $STAMP

What is here:
  version.txt           build, Go version, host OS
  config-redacted.yaml  configuration with every secret-bearing value replaced
  env-names.txt         names of AEGIS_* variables that are set (no values)
  health.json/readyz.json  live state, if an admin endpoint was given
  gateway-tail.log      last 500 log lines

What is deliberately NOT here: request bodies, forensic log contents, the
contents of any secret, and anything from your database.

Read this before sending it. It is your data.
TXT

tar -czf "$BUNDLE_DIR/$OUT.tar.gz" "$OUT" && rm -rf "$OUT"
echo
echo "wrote $BUNDLE_DIR/$OUT.tar.gz"
echo "Read it before sending — it is your data and it leaves your infrastructure."
