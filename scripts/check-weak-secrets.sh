#!/usr/bin/env bash
# Reject known-weak literal values for the secrets docker-compose feeds
# directly to Redis/Postgres/Grafana. config.Validate (internal/config)
# already rejects insecure placeholders for AEGIS_ADMIN_SECRET,
# AEGIS_JWT_SECRET, and AEGIS_PROPAGATION_SECRET — but AEGIS_REDIS_PASSWORD,
# POSTGRES_PASSWORD, and GRAFANA_ADMIN_PASSWORD are consumed straight from the
# environment by docker-compose.yml and never pass through internal/config, so
# that gate structurally cannot cover them. This script is the equivalent
# check for those three, run before `docker compose up` (see `make docker`).
#
# Run locally with `make check-secrets`; also invoked by `make docker`.
set -euo pipefail

ENV_FILE="${1:-.env}"

if [ ! -f "$ENV_FILE" ]; then
  echo "check-weak-secrets: no $ENV_FILE found — nothing to check (docker compose will fail on its own required vars)"
  exit 0
fi

# Same spirit as internal/config's insecurePlaceholders list: common
# words/defaults that indicate "never changed the placeholder," not real
# secret strength.
WEAK_VALUES=(
  "changeme" "change-me" "password" "secret" "admin" "aegis" "devpass"
  "postgres" "redis" "default" "123456" "test" "root" ""
)

is_weak() {
  local v_lower
  v_lower=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')
  for w in "${WEAK_VALUES[@]}"; do
    [ "$v_lower" = "$w" ] && return 0
  done
  # Also reject anything under 12 characters — too short to be a generated secret.
  [ "${#1}" -lt 12 ] && return 0
  # Reject low-diversity values that pass both checks above but still aren't
  # random — e.g. "111111111111" or "abababababab" (12 chars, absent from the
  # literal list). A real generated secret (openssl rand -hex, base64, etc.)
  # over 12 characters draws from a wide alphabet; fewer than 6 distinct
  # characters is a strong repetition signal on its own. Mirrors
  # internal/config's looksLowEntropy check for AEGIS_ADMIN_SECRET/JWT_SECRET/
  # PROPAGATION_SECRET, which these infra passwords bypass entirely.
  local distinct
  distinct=$(printf '%s' "$1" | fold -w1 | sort -u | wc -l | tr -d ' ')
  [ "$distinct" -lt 6 ] && return 0
  return 1
}

fail=0
for var in AEGIS_REDIS_PASSWORD POSTGRES_PASSWORD GRAFANA_ADMIN_PASSWORD; do
  # Read the value as docker-compose/`env` would: last assignment wins, no
  # shell expansion beyond simple VAR=value lines.
  val=$(grep -E "^${var}=" "$ENV_FILE" | tail -n1 | cut -d'=' -f2- || true)
  if is_weak "$val"; then
    echo "ERROR: $var in $ENV_FILE is missing or looks like a weak/default value"
    fail=1
  fi
done

if [ "$fail" -ne 0 ]; then
  echo
  echo "Generate strong values, e.g.: openssl rand -hex 32"
  echo "This check exists because these three secrets are consumed directly by"
  echo "docker-compose (Redis/Postgres/Grafana), so config.Validate's placeholder"
  echo "rejection for the AEGIS_* app secrets never sees them."
  exit 1
fi

echo "check-weak-secrets: OK"
