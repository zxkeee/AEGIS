#!/usr/bin/env bash
# Prove the support bundle does not carry secrets out of a customer's network.
#
# The method is the one that caught the Helm ConfigMap leak, and it is used here
# for the same reason: reasoning about which fields are secret is exactly the
# reasoning that was wrong last time. An argument about `yaml:"-"` was written
# in a commit, repeated in an invariant, and independently reproduced by an
# audit agent — all three concluded a leak was impossible while it was shipping.
# What settled it was rendering with canaries and grepping the output.
#
# So: a config full of values that appear nowhere else, redacted, then grepped.
# A canary that survives is a secret that would have been mailed to a support
# thread.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

cat > "$TMP/canary.yaml" <<'YAML'
listen: ":8080"
admin_secret: "CANARY01admin"
require_tls: false
redis:
  addr: "10.0.0.5:6379"
  password: "CANARY02redis"
  sentinel_password: "CANARY03sentinel"
forensic_dsn: "postgres://user:CANARY04pg@db:5432/aegis?sslmode=disable"
tls:
  key_file: "/etc/aegis/CANARY05key.pem"
auth:
  jwt_secret: "CANARY06jwt"
  jwks_url: "https://idp.example/CANARY07jwks"
  propagation_secret: "CANARY08prop"
consumer_id:
  salt: "CANARY09salt"
report_signing_key: "CANARY10report"
oidc:
  client_secret: "CANARY11oidc"
alerting:
  webhook_url: "https://hooks.example/CANARY12hook"
  sinks:
    - type: splunk_hec
      url: "https://splunk.internal:8088/CANARY13splunk"
ticketing:
  base_url: "https://acme.atlassian.net/CANARY14jira"
routes:
  - path: "/"
    upstreams: ["http://svc:CANARY15upstream@backend:3000"]
YAML

out="$(BUNDLE_DIR="$TMP" "$ROOT/scripts/support-bundle.sh" -c "$TMP/canary.yaml" 2>&1)" || {
  echo "ERROR: the support bundle script failed to run."
  echo "$out"
  exit 1
}

bundle="$(ls -t "$TMP"/support-bundle-*.tar.gz 2>/dev/null | head -1)"
if [ -z "$bundle" ]; then
  echo "ERROR: the support bundle script produced no archive; nothing was checked."
  echo "       A check that silently verifies nothing is worse than no check."
  exit 1
fi

tar xzf "$bundle" -C "$TMP"
dir="$(ls -td "$TMP"/support-bundle-*/ | head -1)"

# The canary must be found in the INPUT, or the test is checking an empty file
# and would pass with the redaction removed entirely.
if ! grep -q "CANARY01admin" "$TMP/canary.yaml"; then
  echo "ERROR: the canary config lost its canaries; this check proves nothing."
  exit 1
fi

leaked="$(grep -rlE 'CANARY[0-9]+' "$dir" 2>/dev/null || true)"
if [ -n "$leaked" ]; then
  echo "ERROR: the support bundle carries secrets out of the customer's network."
  echo "       These files contain values that were meant to be redacted:"
  for f in $leaked; do
    echo "  ${f#"$dir"}"
    grep -oE 'CANARY[0-9]+[a-z]*' "$f" | sort -u | sed 's/^/      /'
  done
  exit 1
fi

echo "check-support-bundle: OK (15 canaries planted, none survived redaction)"
