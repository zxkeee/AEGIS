#!/usr/bin/env bash
# Flag container images referenced by a YAML `image:` key with a tag only
# (not a @sha256: digest) in docker-compose.yml. A tag is mutable at the
# registry — a repointed tag changes what gets pulled with no diff in this
# repo, unlike a digest pin.
#
# Existing exceptions are tracked explicitly with a
# "TODO(security-audit): pin by digest" comment somewhere in the (possibly
# multi-line) comment block immediately above the `image:` line (see
# docker-compose.yml's prometheus/grafana services) rather than silently
# allowed — this script's job is to make sure that list doesn't grow without
# notice, not to resolve the digests itself (no registry access from this
# script).
#
# Scope: only YAML `image:` keys in docker-compose.yml are checked. Images
# referenced inside a multi-line shell `docker run ...` block (e.g. nuclei in
# .github/workflows/security-scan.yml) are NOT parsed here — that pattern is
# too varied to regex reliably. Those are tracked by their own inline TODO
# comment and rely on manual review, not this script.
#
# Run locally with `make check-image-pins`; wired into the lint CI workflow.
set -euo pipefail

cd "$(dirname "$0")/.."

f="docker-compose.yml"
fail=0
todo_pending=0

while IFS= read -r line; do
  trimmed="$(echo "$line" | sed -e 's/^[[:space:]]*//')"

  if echo "$trimmed" | grep -q "TODO(security-audit): pin by digest"; then
    todo_pending=1
    continue
  fi

  if echo "$line" | grep -qE '^\s*image:\s*"?[a-zA-Z0-9./_-]+:[a-zA-Z0-9._-]+"?\s*(#.*)?$'; then
    if ! echo "$line" | grep -q '@sha256:' && [ "$todo_pending" -ne 1 ]; then
      echo "ERROR: $f: tag-only image reference with no tracked exception: $(echo "$line" | xargs)"
      fail=1
    fi
    todo_pending=0
    continue
  fi

  # A comment line (part of the TODO block or otherwise) doesn't reset the
  # pending flag; anything else (blank line, a new YAML key, etc.) does —
  # the exception only covers the image: line immediately following its
  # comment block, not the rest of the file.
  case "$trimmed" in
  '#'*) : ;;
  *) todo_pending=0 ;;
  esac
done <"$f"

if [ "$fail" -ne 0 ]; then
  echo
  echo "Pin the image by digest (docker pull <image> && docker inspect --format='{{index .RepoDigests 0}}' <image>)"
  echo "or, if resolving the digest isn't possible right now, add a"
  echo '"# TODO(security-audit): pin by digest" comment in the block above it to track the exception explicitly.'
  exit 1
fi

echo "check-image-pins: OK"
