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
# "/orders" also captures "/ordersXYZ". That has shipped as two DIFFERENT bugs
# so far: a tenant-isolation mis-attribution (fixed in tenant.go) and a
# route-posture confusion in discovery/posture.go that let a permissive route
# like "/api/public" silently strip auth/WAF/DLP/rate-limit off an unrelated,
# longer path such as "/api/publicdata/42" (2026-08-21 audit, CRITICAL). Both
# instances used a local variable holding a path (`path`, `lpath`, `rawPath`,
# ...), not the literal `r.URL.Path` expression the original version of this
# check looked for — which is exactly why the second bug slipped past it.
# Path prefixing MUST go through config.PathHasPrefix, which matches on a
# path-segment boundary.
#
# Matches any strings.HasPrefix call whose first argument is an identifier
# (optionally dotted, e.g. r.URL.Path) ending in "path"/"Path" — not just the
# literal r.URL.Path spelling. internal/config/config.go is excluded: it is
# PathHasPrefix's own implementation, the one place a raw strings.HasPrefix on
# a path variable is correct.
echo "invariant: no raw strings.HasPrefix on a path variable"
if hits=$(grep -rn --include='*.go' -E 'strings\.HasPrefix\([A-Za-z0-9_.]*[Pp]ath\b' internal cmd sdk 2>/dev/null | grep -v '^internal/config/config\.go:'); then
  echo "ERROR: raw strings.HasPrefix on a path variable — use config.PathHasPrefix (segment boundary):"
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

# ── Invariant 3: every AEGIS_*-sourced secret field is force-blanked in the
#    Helm ConfigMap ───────────────────────────────────────────────────────────
#
# charts/aegis/templates/configmap.yaml renders .Values.gateway verbatim into
# a plaintext, RBAC-only-protected ConfigMap. Any field also reachable via an
# AEGIS_* env var (internal/config's applyEnvOverrides — Secret-backed,
# authoritative at runtime) must be force-blanked there: an operator who sets
# the real value directly in values.yaml (the natural shape) instead of via
# secrets.* would otherwise get it persisted in cleartext, readable by anyone
# with ConfigMap RBAC. This shipped as exactly this bug twice: first for
# forensic_dsn/redis.password, then admin_secret/security.auth.secret were
# found missed on the identical fix (2026-08-22 audit) — plus four more of
# the same env-override family (propagation_secret, redis.sentinel_password,
# oidc.client_secret, alerting.webhook_url) that had never been covered at
# all. This check derives the full list from applyEnvOverrides itself (rather
# than a hand-maintained copy) so a NEW AEGIS_* field added later is caught
# automatically if the matching blank isn't added to configmap.yaml in the
# same change.
echo "invariant: every AEGIS_*-sourced secret field is force-blanked in the Helm ConfigMap"
CFG=internal/config/config.go
CM=charts/aegis/templates/configmap.yaml
# Map each AEGIS_* env var's assigned Go field to the YAML key it ultimately
# serializes to (the field's own `yaml:"..."` tag) — e.g. cfg.OIDC.ClientSecret
# assigns to a field named ClientSecret; find ClientSecret's yaml tag.
while IFS= read -r goField; do
  # `|| true`: with `set -e` and `pipefail`, a field whose tag does not match
  # killed this script outright — it exited before printing the very error it
  # was written to print, so the check reported "failed" with no reason at all.
  yamlKey=$(grep -oE "\\b${goField}\\b +\\S+ +\`yaml:\"[a-z0-9_-]+\"" "$CFG" | grep -oE '"[a-z0-9_-]+"' | tr -d '"' | head -1 || true)
  # A field tagged `yaml:"-"` must be checked HARDER, not skipped.
  #
  # This block used to `continue` here, on the reasoning that `yaml:"-"` means
  # the field "cannot reach the ConfigMap at all — a stronger guarantee than
  # being force-blanked". That reasoning is a category error and it let two
  # secrets leak (2026-09-07 audit): `yaml:"-"` governs how GO marshals the
  # config struct. The ConfigMap does not marshal the Go struct — Helm marshals
  # `.Values.gateway`, an operator-authored YAML map, through `toYaml`. Helm has
  # no knowledge of Go struct tags and never will.
  #
  # The tag therefore makes a field MORE likely to leak, not less: it is the
  # marker of "environment-only secret", precisely the class this invariant
  # exists for. Such a field still needs blanking, under the snake_case key an
  # operator would naturally write in values.yaml.
  if [ "$yamlKey" = "-" ]; then
    yamlKey=$(printf '%s' "$goField" \
      | sed -E 's/([a-z0-9])([A-Z])/\1_\2/g' | tr '[:upper:]' '[:lower:]')
  fi
  if [ -z "$yamlKey" ]; then
    echo "ERROR: could not resolve the yaml tag for field $goField (assigned from an AEGIS_* env var in $CFG) — add it manually to this invariant"
    fail=1
    continue
  fi
  # configmap.yaml must contain a `set ... "<yamlKey>" ""` blank for it.
  if ! grep -q "\"$yamlKey\" \"\"" "$CM"; then
    echo "ERROR: $CM does not force-blank \"$yamlKey\" (Go field $goField, sourced from an AEGIS_* env var) — an operator setting it directly in values.yaml would leak it into the plaintext ConfigMap"
    fail=1
  fi
done < <(grep -oE 'cfg\.[A-Za-z.]+ = v$' "$CFG" | sed -E 's/ = v$//; s/^.*\.//')

# The static check above reads templates; this one reads the OUTPUT. A grep over
# a template can be satisfied by a commented-out line, cannot see whether a
# `set` targets the right nesting level, and — as the block above proves — can
# be defeated entirely by reasoning about the wrong marshaller. Rendering the
# chart with canary values and grepping the result cannot be fooled by any of
# that: if a secret appears in the rendered ConfigMap, it appears.
echo "invariant: no AEGIS_*-sourced secret survives into the rendered ConfigMap"
if ! command -v helm >/dev/null 2>&1; then
  # NOT a silent skip. A guard that quietly does nothing where it matters is the
  # failure mode this whole block was rewritten to fix.
  echo "WARNING: helm is not installed — the canary render check did NOT run."
  echo "         Install helm, or this invariant is only as strong as the static grep above."
else
  canaryOut=$(helm template charts/aegis \
    --set secrets.adminSecret=x --set secrets.redisPassword=y \
    --set gateway.report_signing_key=AEGIS_CANARY_A \
    --set gateway.security.consumer_id.salt=AEGIS_CANARY_B \
    --set gateway.forensic_dsn=AEGIS_CANARY_C \
    --set gateway.admin_secret=AEGIS_CANARY_D \
    --set gateway.security.auth.secret=AEGIS_CANARY_E \
    --set gateway.security.auth.propagation_secret=AEGIS_CANARY_F \
    --set gateway.redis.password=AEGIS_CANARY_G \
    --set gateway.alerting.webhook_url=AEGIS_CANARY_H \
    2>/dev/null | grep -n 'AEGIS_CANARY' || true)
  if [ -n "$canaryOut" ]; then
    echo "ERROR: the rendered chart contains operator-supplied secret values in cleartext:"
    echo "$canaryOut"
    echo "       Force-blank each of these keys in $CM."
    fail=1
  fi
fi

# ── Invariant 4: every payload-inspection WAF rule covers REQUEST_URI (no
#    path blindness) ──────────────────────────────────────────────────────────
#
# ARGS only covers query-string/body parameters — a REST path segment
# (/api/orders/{payload}) is invisible to a rule that omits REQUEST_URI, so a
# payload placed in the path bypasses detection entirely despite matching the
# pattern everywhere else. This shipped as exactly this bug twice on the same
# ruleset: once across SQLi/XSS/RCE/Log4Shell (fixed together), then again on
# the SSRF rule (id:10007), which was missed in that same fix (2026-08-22
# audit). Every built-in rule whose targets include ARGS or REQUEST_BODY —
# i.e. it inspects request *content* for an injected payload, not a protocol/
# header property — must also inspect REQUEST_URI. Exempt: XXE (id:10008, a
# DTD only ever appears in the body, never the path), invalid-method/scanner
# detection (id:10009/10010, protocol and User-Agent checks, not payload
# targets), and request-smuggling (id:10012/10015, header-only by definition).
echo "invariant: every ARGS/REQUEST_BODY WAF rule also covers REQUEST_URI"
WAF=internal/middleware/waf.go
exempt_ids='10008|10009|10010|10012|10015'
hits=$(perl -0777 -ne '
  my $exempt = qr/^(?:'"$exempt_ids"')$/;
  while (/SecRule\s+(\S+)\s+"\@rx[^"]*"\s*\\\s*\n\s*"id:(\d+)/gs) {
    my ($targets, $id) = ($1, $2);
    next if $id =~ $exempt;
    next unless $targets =~ /\bARGS\b|\bREQUEST_BODY\b/;
    print "id:$id targets=$targets\n" unless $targets =~ /\bREQUEST_URI\b/;
  }
' "$WAF")
if [ -n "$hits" ]; then
  echo "ERROR: WAF rule inspects ARGS/REQUEST_BODY but not REQUEST_URI — a path-embedded payload silently bypasses it:"
  echo "$hits"
  fail=1
fi

# ── Invariant 5: every evidence document can be signed ───────────────────────
#
# A posture or compliance report is handed to an auditor and treated as
# evidence, which is only true if the recipient can prove it was not edited
# afterwards (internal/attest, docs/compliance-evidence.md). Signing is opt-in
# per request and lives in ONE place — handlers.writeSignable — which also
# holds every refusal that keeps a request for a signature from being answered
# with an unsigned document.
#
# The failure this prevents is silent: someone adds /api/dora-report next
# quarter, ends it with writeJSON like every other handler in the file, and
# nothing anywhere says the new report is the one document that cannot be
# attested. Nobody notices until an auditor asks.
#
# So: any handler whose name says it serves a report or a compliance document
# must route its response through writeSignable. A handler that genuinely is
# not evidence opts out explicitly with a `// not-evidence:` comment and a
# reason, which makes that a decision someone made rather than one nobody saw.
echo "invariant: every report/compliance handler can be signed"
while IFS= read -r hit; do
  echo "ERROR: $hit"
  fail=1
done < <(
  awk '
    # Start of a handler method on *handlers taking (w, r).
    /^func \(h \*handlers\) [A-Za-z0-9_]+\(w http\.ResponseWriter, r \*http\.Request\)/ {
      name = $0
      sub(/^func \(h \*handlers\) /, "", name)
      sub(/\(.*$/, "", name)
      lower = tolower(name)
      if (lower ~ /report|compliance/) {
        inFn = 1; fn = name; line = FNR; signable = 0; optout = 0
      }
      next
    }
    inFn && /writeSignable/      { signable = 1 }
    inFn && /\/\/ not-evidence:/ { optout = 1 }
    # A closing brace in column 0 ends the function body.
    inFn && /^}/ {
      if (!signable && !optout)
        printf "%s:%d: handler %s serves an evidence document but never calls writeSignable — an auditor cannot verify it. Route the response through writeSignable, or state why not with a \"// not-evidence:\" comment.\n", FILENAME, line, fn
      inFn = 0
    }
  ' $(ls internal/api/*.go | grep -v '_test\.go$')
)

# The signing path itself must stay the only one, or the refusals in
# writeSignable (no key configured, unparseable ?sign, CSV) can be bypassed by
# a handler that reaches for attest directly.
echo "invariant: reports are attested only through writeSignable"
if hits=$(grep -rn --include='*.go' 'reportSigner\.Attest(' internal/api \
          | grep -v '_test\.go:' | grep -v '^internal/api/sign\.go:'); then
  echo "ERROR: a handler signs a document outside writeSignable, bypassing its refusals:"
  echo "$hits"
  fail=1
fi

if [ "$fail" -ne 0 ]; then
  echo
  echo "lint-invariants: FAILED — a security invariant regressed (see above)."
  exit 1
fi

echo "lint-invariants: OK"
