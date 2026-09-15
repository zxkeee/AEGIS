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
# The line that builds the signed payload. It used to be a strings.Join here;
# the canonical form now lives in sdk/gatewayverify so the signer and the
# verifier cannot describe it differently, and this matches the call site.
payload_line=$(grep -n 'gatewayverify.CanonicalPayload(' "$JWT" | head -1 | cut -d: -f1 || true)
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
      if ! grep 'gatewayverify.CanonicalPayload(' "$JWT" | grep -q "$var"; then
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

# ── Invariant 3b: every AEGIS_* env var the gateway reads is reachable from the
#    Helm chart ────────────────────────────────────────────────────────────────
#
# Invariant 3 checks that a secret set the WRONG way cannot leak. This checks
# the other half: that it can be set the RIGHT way at all.
#
# AEGIS_CONSUMER_SALT had no plumbing in this chart. The ConfigMap force-blanks
# security.consumer_id.salt (invariant 3 requires exactly that), and no
# environment variable carried it — so every Kubernetes deployment silently fell
# back to deriving the salt from the admin secret. The salt is what makes the
# consumer catalog irreversible: whoever held the admin secret could search the
# catalog back to live API keys, and rotating that secret renamed every
# consumer. Nothing failed, nothing warned; the value was simply unreachable.
#
# AEGIS_ROOT_EMAIL and AEGIS_ROOT_PASSWORD had the same gap, which left a
# Kubernetes operator with no way to create a real account — only the bearer
# secret the bootstrap exists to avoid.
#
# The list is derived from the source, not maintained by hand, so a new
# AEGIS_* variable added to the gateway is caught here if the chart is not
# updated in the same change.
echo "invariant: every AEGIS_* env var the gateway reads is reachable from the Helm chart"
DEPLOY=charts/aegis/templates/deployment.yaml
# Deliberate exemptions, each with a reason. Not a way to silence the check:
# adding a name here is a claim that the chart must NOT plumb it.
#   AEGIS_LICENSE_PATH — a filesystem path, not a secret; the chart exposes it
#                        as gateway.license_path in the ConfigMap instead.
chartExempt="AEGIS_LICENSE_PATH"
for envVar in $(grep -ohE 'AEGIS_[A-Z_]+' internal/config/config.go cmd/gateway/main.go | sort -u); do
  case " $chartExempt " in *" $envVar "*) continue ;; esac
  if ! grep -q "name: $envVar\b" "$DEPLOY"; then
    echo "ERROR: $DEPLOY never sets $envVar — the gateway reads it, so a Kubernetes"
    echo "       operator has no way to supply it and silently gets the fallback."
    fail=1
  fi
done

# ── Invariant 2b: nothing describes the identity payload as delimiter-joined ──
#
# The signed identity payload was `sub:roles:scopes:identity:ts:nonce` — six
# fields joined with ":", none of them constrained to exclude it. `sub` comes
# straight from a JWT claim, so a subject containing a colon produced a
# signature that was equally valid for a DIFFERENT split of the same bytes,
# naming a different user. It is length-prefixed now
# (gatewayverify.CanonicalPayload).
#
# Six places described that format in prose, and three of them were already
# wrong in another way — they listed five fields, from before the identity claim
# was added. A format documented in seven places is a format that will be
# described incorrectly somewhere, and someone reimplementing a backend verifier
# from the docs would reintroduce exactly this bug.
#
# So: no file may spell the payload as a delimiter-joined field list.
echo "invariant: the identity payload is not described as a delimiter-joined string"
# This script is excluded: the comment above has to name the format it forbids.
joined=$(grep -rIn --exclude-dir=.git --exclude-dir=node_modules --exclude-dir=.stand \
  --exclude=lint-invariants.sh -E '(sub|subject):roles:scopes' . 2>/dev/null || true)
if [ -n "$joined" ]; then
  echo "ERROR: the identity payload is described as a delimiter-joined string here:"
  echo "$joined" | sed 's/^/       /'
  echo "       It is length-prefixed (gatewayverify.CanonicalPayload). A delimiter-joined"
  echo "       payload is not injective and let one signature authenticate two identities."
  fail=1
fi

# ── Invariant 6: the admin RBAC gate sees every mutating route ────────────────
#
# AdminAuth refuses a viewer's request inside `if isMutating(r.Method)`. That
# makes isMutating the definition of "mutation" for the whole admin plane: a
# route registered with a method it does not list is reachable by a viewer, and
# by anyone holding a session, with no RBAC check and no CSRF check either —
# both live in the same branch.
#
# Today every route in server.go names a method and every mutating one is in
# that set. This keeps it that way: a route registered with no method at all
# (http.ServeMux then matches ALL methods, including POST) or with a verb the
# gate does not recognise would otherwise pass review as ordinary plumbing.
echo "invariant: every admin route's method is one the RBAC gate understands"
SRV=internal/api/server.go
ADM=internal/middleware/admin.go
# Methods isMutating() treats as a mutation, read from the source rather than
# copied here — a copy is what drifts.
mutating=$(sed -n '/func isMutating/,/^}/p' "$ADM" \
  | grep -oE 'http\.Method[A-Za-z]+' | sed 's/http.Method//' | tr '[:lower:]' '[:upper:]' | sort -u)
# Safe verbs need no RBAC check: they change nothing.
safe="GET HEAD OPTIONS"
allowed=$(printf '%s\n%s\n' "$mutating" "$(printf '%s\n' $safe)" | sort -u)
while IFS= read -r line; do
  pattern=$(printf '%s' "$line" | sed -n 's/.*mux.HandleFunc("\([^"]*\)".*/\1/p')
  [ -z "$pattern" ] && continue
  verb=$(printf '%s' "$pattern" | awk '{print $1}')
  # A pattern with no space is a bare path: ServeMux matches every method on it.
  case "$pattern" in
    *" "*) : ;;
    *)
      echo "ERROR: $SRV registers \"$pattern\" with no method — ServeMux will match POST"
      echo "       on it too, and AdminAuth's RBAC and CSRF checks both sit inside"
      echo "       isMutating(r.Method). Name the method."
      fail=1
      continue
      ;;
  esac
  if ! printf '%s\n' "$allowed" | grep -qx "$verb"; then
    echo "ERROR: $SRV registers \"$pattern\" with method $verb, which isMutating() in"
    echo "       $ADM does not recognise — a viewer could call it, and no CSRF token"
    echo "       would be required. Add it to isMutating or use a listed verb."
    fail=1
  fi
done < <(grep 'mux.HandleFunc("' "$SRV")

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

# ── Invariant 9: writes to RLS tables go through a transaction ───────────────
#
# Every catalog/forensic table has FORCE ROW LEVEL SECURITY, and the policy
# reads app.tenant_id, which is set with set_config(..., is_local => true) — a
# TRANSACTION-local setting. A write issued on a pooled *sql.DB handle therefore
# has no tenant pinned: under an unprivileged role the policy matches zero rows,
# the statement reports success, and nothing happened.
#
# This has shipped twice. Once in discovery, where a test UPDATE ran outside
# withTenantTx and the test then asserted on data it had never written — green,
# for years, because the connected role was a superuser and RLS never engaged.
# Once nearly again in the seal migration, where the same shape would have left
# every existing seal unnumbered on upgrade and migrated nothing, silently.
#
# The sibling trap is set_config(..., false) on a *sql.DB followed by a separate
# Exec: session scope applies to whichever pooled connection served it, and the
# next statement may land on another. Both shapes are caught by requiring the
# executing receiver to be a transaction.
#
# Test files are included deliberately — the first instance was in one, and a
# test that fails to write what it is about to assert on is worse than
# production code that fails loudly.
echo "invariant: writes to RLS-protected tables run inside a transaction"
if hits=$(python3 - <<'PYEOF'
import pathlib, re, sys

RLS = ["forensic_logs", "forensic_seals", "forensic_chain_head", "incidents",
       "api_endpoints", "api_endpoint_status", "api_consumers",
       "api_endpoint_consumers", "api_specs"]
write = re.compile(r"\b(UPDATE|INSERT\s+INTO|DELETE\s+FROM)\s+\"?(" + "|".join(RLS) + r")\b", re.I)
# Two spellings of the same mistake: a field (s.db.Exec) and a bare handle
# (db.Exec on a *sql.DB opened locally, which a test naturally writes). The
# first version of this check matched only the field form, so the second would
# have walked straight past it.
call = re.compile(r"(?:\.|(?:^|[^A-Za-z0-9_.]))(?:db|sqlDB|conn|pool)\.(Exec|Query|QueryRow)(Context)?\(")

out = []
for f in sorted(pathlib.Path("internal").rglob("*.go")):
    lines = f.read_text().splitlines()
    for i, line in enumerate(lines):
        if not call.search(line):
            continue
        m = write.search("\n".join(lines[i:i + 12]))
        if m:
            out.append("%s:%d: %s %s issued on a pooled DB handle, not a transaction"
                       % (f, i + 1, m.group(1).upper(), m.group(2)))
for o in out:
    print(o)
sys.exit(0)
PYEOF
) && [ -n "$hits" ]; then
  echo "ERROR: a write to an RLS-protected table runs outside a transaction."
  echo "       app.tenant_id is transaction-local, so this statement has no tenant"
  echo "       pinned: under a non-superuser role it matches zero rows and succeeds."
  echo "$hits"
  fail=1
fi

if [ "$fail" -ne 0 ]; then
  echo
  echo "lint-invariants: FAILED — a security invariant regressed (see above)."
  exit 1
fi

echo "lint-invariants: OK"
