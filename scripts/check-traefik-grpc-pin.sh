#!/usr/bin/env bash
# Fail closed if the AC image's temporary Traefik source rebuild can be
# weakened back below the grpc-go release that fixes GHSA-hrxh-6v49-42gf.

set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
DOCKERFILE=${1:-"$REPO_ROOT/docker/Dockerfile.ac.aws"}

if [ ! -f "$DOCKERFILE" ]; then
  echo "ERROR: Traefik Dockerfile not found: $DOCKERFILE" >&2
  exit 1
fi

# Strip whole-line comments so prose cannot satisfy either required literal.
active=$(grep -vE '^[[:space:]]*#' "$DOCKERFILE" || true)

if grep -Eq '^[[:space:]]*ARG[[:space:]]+[^=[:space:]]*(GRPC|TRAEFIK_(VERSION|SOURCE|COMMIT))[^=[:space:]]*=' <<<"$active"; then
  echo "ERROR: Traefik source identity and grpc-go security floor must not be caller-overridable" >&2
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

require_once 'https://github.com/traefik/traefik/releases/download/v3.6.23/traefik-v3.6.23.src.tar.gz' \
  'the pinned Traefik v3.6.23 source URL'
require_once 'c8a0fcd1916ad69d8c38707975bc4ab0ed3ffc0abfbaee0a8fdb41cb6289bad2  /tmp/traefik-src.tar.gz' \
  'the pinned Traefik source SHA256 check'
require_once 'sha256sum -c -' \
  'the Traefik source checksum verifier'
require_once 'git fetch --depth=1 origin 84d4e8b139d1ac5e5b2d250fff95baed5ba0584f' \
  'the pinned upstream Traefik commit fetch'
require_once "test \"\$(git rev-parse HEAD)\" = 84d4e8b139d1ac5e5b2d250fff95baed5ba0584f" \
  'the pinned upstream Traefik HEAD assertion'
require_once 'go get google.golang.org/grpc@v1.82.1' \
  'the grpc-go v1.82.1 selection'
require_once '-buildvcs=true' \
  'the VCS-enabled Traefik build'
require_once 'awk -v want=v1.82.1' \
  'the embedded grpc-go v1.82.1 assertion'
require_once "\$3 == \"v3.6.23+dirty\"" \
  'the versioned Traefik main-module assertion'
require_once "\$2 == \"vcs.revision=84d4e8b139d1ac5e5b2d250fff95baed5ba0584f\"" \
  'the Traefik VCS revision assertion'
require_once "\$2 == \"vcs.modified=true\"" \
  'the expected patched-source VCS state assertion'

echo "OK: AC Traefik rebuild pins source identity and verifies versioned Traefik + grpc-go v1.82.1 metadata"
