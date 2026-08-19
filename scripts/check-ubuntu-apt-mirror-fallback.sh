#!/usr/bin/env bash
# Keep every Ubuntu runtime image in build-and-push.yml's application-image
# matrix on the same bounded mirror-fallback contract. The helper owns both
# apt-get update and package installation so either network phase can recover.

set -euo pipefail

REPO_ROOT=${1:-"$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"}
HELPER_REL=docker/ubuntu-apt-install-with-fallback.sh
HELPER="$REPO_ROOT/$HELPER_REL"
RUNTIME_HELPER=/usr/local/sbin/ubuntu-apt-install-with-fallback
MOUNT="RUN --mount=type=bind,source=$HELPER_REL,target=$RUNTIME_HELPER,ro"

fail() {
  echo "ERROR: ubuntu apt mirror fallback contract: $*" >&2
  exit 1
}

[[ -f "$HELPER" && ! -L "$HELPER" && -x "$HELPER" ]] ||
  fail "$HELPER_REL must be a regular executable, non-symlink file"

dockerfiles=(
  docker/Dockerfile.server
  docker/Dockerfile.ac.aws
  docker/Dockerfile.hub
  docker/Dockerfile.relay
)

workflow="$REPO_ROOT/.github/workflows/build-and-push.yml"
[[ -f "$workflow" ]] || fail ".github/workflows/build-and-push.yml is missing"
expected_matrix=$(printf '%s\n' "${dockerfiles[@]}" | sort)
actual_matrix=$(sed -nE 's/^[[:space:]]+dockerfile:[[:space:]]+(docker\/Dockerfile[^[:space:]]+)[[:space:]]*$/\1/p' "$workflow" | sort)
[[ "$actual_matrix" == "$expected_matrix" ]] ||
  fail "application-image matrix Dockerfiles drifted from the shared-helper set"

for relative in "${dockerfiles[@]}"; do
  file="$REPO_ROOT/$relative"
  [[ -f "$file" ]] || fail "$relative is missing"

  runtime_line=$(grep -nE '^FROM ubuntu:[^[:space:]]+ AS runtime$' "$file" | tail -1 | cut -d: -f1 || true)
  [[ -n "$runtime_line" ]] || fail "$relative has no canonical Ubuntu runtime stage"

  mount_count=$(grep -Fxc "$MOUNT \\" "$file" || true)
  [[ "$mount_count" == 1 ]] ||
    fail "$relative must bind-mount the shared helper exactly once (found $mount_count)"

  mount_line=$(grep -nFx "$MOUNT \\" "$file" | cut -d: -f1)
  invocation_count=$(grep -Ec "^[[:space:]]+$RUNTIME_HELPER \\\\$" "$file" || true)
  [[ "$invocation_count" == 1 ]] ||
    fail "$relative must invoke the mounted helper exactly once (found $invocation_count)"
  invocation_line=$(grep -nE "^[[:space:]]+$RUNTIME_HELPER \\\\$" "$file" | cut -d: -f1)

  first_package_line=$((invocation_line + 1))
  if (( mount_line <= runtime_line || invocation_line != mount_line + 1 )) ||
     ! sed -n "${first_package_line}p" "$file" | grep -Eq '^[[:space:]]+[A-Za-z0-9][A-Za-z0-9.+:~=_-]*[[:space:]]+\\$'; then
    fail "$relative must order runtime stage -> bind mount -> helper invocation -> package arguments"
  fi

  if tail -n "+$((runtime_line + 1))" "$file" |
     sed -E 's/[[:space:]]+#.*$//; /^[[:space:]]*#/d' |
     grep -Eq '(^|[^[:alnum:]_.-])([^[:space:]]*/)?apt-get([[:space:]]|$)'; then
    fail "$relative must not bypass the shared helper with runtime apt-get"
  fi
  if grep -Eq "^[[:space:]]*COPY .*${HELPER_REL##*/}" "$file"; then
    fail "$relative must bind-mount the build helper, not ship it in the runtime image"
  fi
done

echo "Ubuntu apt mirror fallback contract is present in all ${#dockerfiles[@]} application-image matrix runtimes."
