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

require_once 'https://github.com/traefik/traefik/releases/download/v3.6.24/traefik-v3.6.24.src.tar.gz' \
  'the pinned Traefik v3.6.24 source URL'
require_once 'bdd5ac1d6d8a046a518d7f4493f15d0b4a919fab51654852c9e75c54720edbcf  /tmp/traefik-src.tar.gz' \
  'the pinned Traefik source SHA256 check'
require_once 'sha256sum -c -' \
  'the Traefik source checksum verifier'
require_once 'git fetch --depth=1 origin cc336581846996ffbd01b1290fd5b44787bad324' \
  'the pinned upstream Traefik commit fetch'
require_once "test \"\$(git rev-parse HEAD)\" = cc336581846996ffbd01b1290fd5b44787bad324" \
  'the pinned upstream Traefik HEAD assertion'
require_once 'go get google.golang.org/grpc@v1.82.1' \
  'the grpc-go v1.82.1 selection'
require_once 'golang.org/x/text@v0.39.0' \
  'the x/text v0.39.0 selection'
require_once '-buildvcs=true' \
  'the VCS-enabled Traefik build'
require_once 'awk -v want=v1.82.1' \
  'the embedded grpc-go v1.82.1 assertion'
require_once 'awk -v want=v0.39.0' \
  'the embedded x/text v0.39.0 assertion'
require_once "\$3 == \"v3.6.24+dirty\"" \
  'the versioned Traefik main-module assertion'
require_once "\$2 == \"vcs.revision=cc336581846996ffbd01b1290fd5b44787bad324\"" \
  'the Traefik VCS revision assertion'
require_once "\$2 == \"vcs.modified=true\"" \
  'the expected patched-source VCS state assertion'

echo "OK: AC Traefik rebuild pins source identity and verifies versioned Traefik + Go dependency security metadata"
