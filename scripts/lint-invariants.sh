#!/usr/bin/env bash
# Project-specific security invariants that a general-purpose linter cannot
# express. Each one encodes a bug we actually shipped and fixed, so the class
# cannot silently return. Run locally with `make lint-invariants`; CI runs it in
# the lint workflow.
set -euo pipefail

fail=0

# ── Invariant 1: no raw prefix match on request paths ────────────────────────
#
# strings.HasPrefix(r.URL.Path, ...) matches on a byte boundary, so a rule for
# "/orders" also captures "/ordersXYZ". That mis-attributed requests to the
# wrong tenant (isolation bug). Path prefixing MUST go through
# config.PathHasPrefix, which matches on a path-segment boundary.
echo "invariant: no raw strings.HasPrefix on r.URL.Path"
if hits=$(grep -rn --include='*.go' 'strings\.HasPrefix(r\.URL\.Path' internal cmd sdk 2>/dev/null); then
  echo "ERROR: raw strings.HasPrefix on a request path — use config.PathHasPrefix (segment boundary):"
  echo "$hits"
  fail=1
fi

# ── Invariant 2: every forwarded X-Gateway-* identity header is signed ────────
#
# The gateway signs an HMAC over a canonical payload so backends can trust the
# identity headers. A header the gateway *sets* but forgets to fold into that
# payload is unauthenticated — a backend reachable directly can be fed a forged
# value. This checks that each identity header set in jwt.go appears in the
# canonical payload string. Timestamp/Nonce/Signature are the envelope, not
# identity, so they are exempt.
echo "invariant: every X-Gateway-* identity header is in the signature payload"
JWT=internal/middleware/jwt.go
# The line that builds the signed payload (strings.Join of the canonical fields).
payload_line=$(grep -n 'payload := strings.Join' "$JWT" | head -1 | cut -d: -f1 || true)
if [ -z "${payload_line:-}" ]; then
  echo "ERROR: could not locate the canonical payload line in $JWT"
  fail=1
else
  # Envelope headers that are intentionally NOT identity fields.
  exempt='X-Gateway-Timestamp|X-Gateway-Nonce|X-Gateway-Signature'
  # Every identity header the gateway sets, mapped to the payload variable it
  # must contribute. We assert the header is set AND its value feeds the payload.
  for pair in \
    'X-Gateway-Subject:sub' \
    'X-Gateway-Roles:roleStr' \
    'X-Gateway-Scopes:scopeStr' \
    'X-Gateway-Identity:identityStr'; do
    hdr=${pair%%:*}
    var=${pair##*:}
    if grep -q "r.Header.Set(\"$hdr\"" "$JWT"; then
      if ! grep 'payload := strings.Join' "$JWT" | grep -q "$var"; then
        echo "ERROR: $hdr is set in $JWT but its value ($var) is not in the signed payload"
        fail=1
      fi
    fi
  done
  # Belt-and-braces: no identity header set outside the exempt envelope that we
  # forgot to enumerate above.
  while IFS= read -r h; do
    case "$h" in
      X-Gateway-Subject|X-Gateway-Roles|X-Gateway-Scopes|X-Gateway-Identity) : ;;
      *)
        if ! printf '%s' "$h" | grep -Eq "$exempt"; then
          echo "ERROR: unrecognised identity header $h set in $JWT — add it to the signature payload and to this check"
          fail=1
        fi
        ;;
    esac
  done < <(grep -oE 'X-Gateway-[A-Za-z-]+' "$JWT" | sort -u)
fi

if [ "$fail" -ne 0 ]; then
  echo
  echo "lint-invariants: FAILED — a security invariant regressed (see above)."
  exit 1
fi

echo "lint-invariants: OK"
