#!/usr/bin/env bash
# Fail closed if the AC image's Traefik source rebuild can be weakened below
# the reviewed Go dependency security floors.

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

require_count() {
  local literal=$1 description=$2 expected=$3 count
  count=$(grep -Fc -- "$literal" <<<"$active" || true)
  if [ "$count" -ne "$expected" ]; then
    echo "ERROR: Dockerfile.ac.aws must contain $description exactly $expected time(s)" >&2
    exit 1
  fi
}

require_once() {
  require_count "$1" "$2" 1
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
require_once 'go get golang.org/x/mod@v0.40.0' \
  'the exact x/mod v0.40.0 security override'
require_once "test \"\$(go list -m -f '{{.Version}}' golang.org/x/crypto)\" = v0.55.0" \
  'the selected x/crypto v0.55.0 assertion'
require_once "test \"\$(go list -m -f '{{.Version}}' golang.org/x/mod)\" = v0.40.0" \
  'the selected x/mod v0.40.0 assertion'
require_once "test \"\$(go list -m -f '{{.Version}}' golang.org/x/net)\" = v0.58.0" \
  'the selected x/net v0.58.0 assertion'
require_once "test \"\$(go list -m -f '{{.Version}}' golang.org/x/text)\" = v0.41.0" \
  'the selected x/text v0.41.0 assertion'
require_once "test \"\$(go list -m -f '{{.Version}}' golang.org/x/tools)\" = v0.49.0" \
  'the selected x/tools v0.49.0 assertion'
# One verify authenticates the checksum-pinned upstream graph before mutation;
# the second authenticates every module selected by the x/mod override.
require_count 'go mod verify' 'the before-and-after Go module checksum verifiers' 2
require_once 'CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build' \
  'the Linux amd64 Traefik build command'
require_once '-buildvcs=true' \
  'the VCS-enabled Traefik build'
require_once 'awk -v want=v1.82.1' \
  'the embedded grpc-go v1.82.1 assertion'
require_once 'awk -v want=v0.55.0' \
  'the embedded x/crypto v0.55.0 assertion'
require_once "\$2 == \"golang.org/x/crypto\"" \
  'the embedded x/crypto module-name assertion'
require_once 'awk -v want=v0.40.0' \
  'the embedded x/mod v0.40.0 assertion'
require_once "\$2 == \"golang.org/x/mod\"" \
  'the embedded x/mod module-name assertion'
require_once 'awk -v want=v0.58.0' \
  'the embedded x/net v0.58.0 assertion'
require_once "\$2 == \"golang.org/x/net\"" \
  'the embedded x/net module-name assertion'
require_once 'awk -v want=v0.41.0' \
  'the embedded x/text v0.41.0 assertion'
require_once "\$2 == \"golang.org/x/text\"" \
  'the embedded x/text module-name assertion'
require_once "\$3 == \"v3.6.25+dirty\"" \
  'the versioned Traefik main-module assertion'
require_once "\$2 == \"vcs.revision=4b18b24b0b002dcc80e0640c6088a87d813de29a\"" \
  'the Traefik VCS revision assertion'
require_once "\$2 == \"vcs.modified=true\"" \
  'the expected patched-source VCS state assertion'

line_of() {
  grep -Fn -- "$1" <<<"$active" | cut -d: -f1
}

mapfile -t verify_lines < <(grep -Fn -- 'go mod verify' <<<"$active" | cut -d: -f1)
ordered_lines=(
  "$(line_of "test \"\$(git rev-parse HEAD)\" = 4b18b24b0b002dcc80e0640c6088a87d813de29a")"
  "${verify_lines[0]}"
  "$(line_of 'go get golang.org/x/mod@v0.40.0')"
  "$(line_of "test \"\$(go list -m -f '{{.Version}}' golang.org/x/crypto)\" = v0.55.0")"
  "$(line_of "test \"\$(go list -m -f '{{.Version}}' golang.org/x/mod)\" = v0.40.0")"
  "$(line_of "test \"\$(go list -m -f '{{.Version}}' golang.org/x/net)\" = v0.58.0")"
  "$(line_of "test \"\$(go list -m -f '{{.Version}}' golang.org/x/text)\" = v0.41.0")"
  "$(line_of "test \"\$(go list -m -f '{{.Version}}' golang.org/x/tools)\" = v0.49.0")"
  "${verify_lines[1]}"
  "$(line_of 'CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build')"
  "$(line_of 'go version -m /usr/local/bin/traefik')"
  "$(line_of 'awk -v want=v1.82.1')"
  "$(line_of 'awk -v want=v0.55.0')"
  "$(line_of 'awk -v want=v0.40.0')"
  "$(line_of 'awk -v want=v0.58.0')"
  "$(line_of 'awk -v want=v0.41.0')"
  "$(line_of "\$3 == \"v3.6.25+dirty\"")"
  "$(line_of "\$2 == \"vcs.revision=4b18b24b0b002dcc80e0640c6088a87d813de29a\"")"
  "$(line_of "\$2 == \"vcs.modified=true\"")"
)

previous=0
for current in "${ordered_lines[@]}"; do
  if (( current <= previous )); then
    echo 'ERROR: Dockerfile.ac.aws must verify source, override, selected graph, build, and embedded metadata in fail-closed order' >&2
    exit 1
  fi
  previous=$current
done

echo "OK: AC Traefik rebuild pins source identity and verifies versioned Traefik + Go dependency security metadata"
