#!/usr/bin/env bash
# Fail closed if the AC image's Traefik source rebuild can be weakened below
# either reviewed Go dependency security floor.

set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
DOCKERFILE=${1:-"$REPO_ROOT/docker/Dockerfile.ac.aws"}

if [ ! -f "$DOCKERFILE" ]; then
  echo "ERROR: Traefik Dockerfile not found: $DOCKERFILE" >&2
  exit 1
fi

# Strip whole-line comments so prose cannot satisfy either required literal.
active=$(grep -vE '^[[:space:]]*#' "$DOCKERFILE" || true)

# The rebuild is defined entirely by hardcoded literals, so no part of it may
# be caller-overridable. Reject any ARG outright rather than enumerating the
# security-sensitive names per floor: a blanket ban is self-maintaining (new
# floors need no regex edit) and closes the gap where a differently-named ARG
# (e.g. TEXT_VER) would have slipped past a name-fragment allowlist.
if grep -Eq '^[[:space:]]*ARG[[:space:]]+' <<<"$active"; then
  echo "ERROR: Traefik source identity and dependency security floors must not be caller-overridable" >&2
  exit 1
fi

require_once() {
  local literal=$1 description=$2 count
  count=$(grep -Fc -- "$literal" <<<"$active" || true)
  if [ "$count" -ne 1 ]; then
    echo "ERROR: Dockerfile.ac.aws must contain $description exactly once" >&2
    exit 1
  fi
}

require_once 'https://github.com/traefik/traefik/releases/download/v3.6.25/traefik-v3.6.25.src.tar.gz' \
  'the pinned Traefik v3.6.25 source URL'
require_once 'bc72a87f59e9d81f62cf3a44ef34df4fe99aebdc1549e69f864087aff07983b7  /tmp/traefik-src.tar.gz' \
  'the pinned Traefik source SHA256 check'
require_once 'sha256sum -c -' \
  'the Traefik source checksum verifier'
require_once 'git fetch --depth=1 origin 4b18b24b0b002dcc80e0640c6088a87d813de29a' \
  'the pinned upstream Traefik commit fetch'
require_once "test \"\$(git rev-parse HEAD)\" = 4b18b24b0b002dcc80e0640c6088a87d813de29a" \
  'the pinned upstream Traefik HEAD assertion'
# No `go get` override is required any more: v3.6.25 ships grpc v1.82.1 and
# x/text v0.40.0 in its own go.mod, and re-pinning x/text to v0.39.0 against it
# would DOWNGRADE the dependency. The embedded assertions below carry the floor
# guarantee instead — they now verify upstream rather than verifying our own
# override, which is the stronger check.
require_once '-buildvcs=true' \
  'the VCS-enabled Traefik build'
require_once 'awk -v want=v1.82.1' \
  'the embedded grpc-go v1.82.1 assertion'
require_once 'awk -v want=v0.40.0' \
  'the embedded x/text v0.40.0 assertion'
require_once "\$3 == \"v3.6.25+dirty\"" \
  'the versioned Traefik main-module assertion'
require_once "\$2 == \"vcs.revision=4b18b24b0b002dcc80e0640c6088a87d813de29a\"" \
  'the Traefik VCS revision assertion'
require_once "\$2 == \"vcs.modified=true\"" \
  'the expected patched-source VCS state assertion'

echo "OK: AC Traefik rebuild pins source identity and verifies versioned Traefik + Go dependency security metadata"
