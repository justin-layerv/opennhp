#!/bin/bash
# Decide whether the current deploy must build and deploy a fresh app image.
#
# Inputs:
#   resolve-app-image-required.sh <head-sha> <component=active-image-tag>...
#
# The deploy path has two change notions:
#   1. "Did this single commit touch app paths?" from dorny/paths-filter.
#   2. "Do the live image tags already contain the app tree at HEAD?"
#
# The second question is the safety property. A failed app rollout followed by
# an infra-only commit must not re-roll the old image and then stamp
# deployed-commit as if the app bytes were live.

set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <head-sha> <component=active-image-tag>..." >&2
  exit 1
fi

HEAD_SHA="$1"
shift

REPO_ROOT=$(git rev-parse --show-toplevel)
cd "$REPO_ROOT"

# Must mirror build-and-push.yml's paths-filter `app` group after stripping
# trailing /** globs. resolve-app-image-required_test.sh asserts this lockstep.
SERVER_AC_IMAGE_PATHS=(
  nhp
  internalauth
  endpoints
  docker
  tests/scripts/check-hub-image-contract.sh
  Makefile
  .trivyignore
)

# Relay has a narrower app surface than server/AC because endpoint server/AC
# sources do not enter Dockerfile.relay's `make relayd` build. Keep this list
# in lockstep with Dockerfile.relay plus the packages imported by `make relayd`.
RELAY_IMAGE_PATHS=(
  nhp
  internalauth
  endpoints/go.mod
  endpoints/go.sum
  endpoints/internal
  endpoints/metrics
  endpoints/relay
  docker/Dockerfile.relay
  docker/ubuntu-apt-install-with-fallback.sh
  Makefile
  .trivyignore
)

app_image_required=false
reasons=()

# Coarse by design: one lagging component requires one fresh app image build for
# the workflow SHA. That can re-roll already-current components, but it keeps the
# deploy-tracking contract simple: every live app image tag must prove HEAD
# before deployed-commit is stamped.

emit_output() {
  echo "app_image_required=$app_image_required"
  if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    echo "app_image_required=$app_image_required" >> "$GITHUB_OUTPUT"
  fi
}

fetch_commit() {
  local ref="$1"
  git fetch --no-tags --depth=1 origin "$ref" >/dev/null 2>&1
}

ensure_head_available() {
  if git cat-file -e "$HEAD_SHA^{commit}" 2>/dev/null; then
    return 0
  fi
  if fetch_commit "$HEAD_SHA" && git cat-file -e "$HEAD_SHA^{commit}" 2>/dev/null; then
    return 0
  fi
  echo "::error::HEAD_SHA $HEAD_SHA is not available as a git commit; cannot evaluate app image drift." >&2
  exit 1
}

ensure_head_available

for pair in "$@"; do
  component="${pair%%=*}"
  tag="${pair#*=}"
  paths=()

  if [[ "$component" == "$pair" || -z "$component" ]]; then
    echo "::error::active image tag arguments must be component=tag pairs (got '$pair')." >&2
    exit 1
  fi

  case "$component" in
    server | ac)
      paths=("${SERVER_AC_IMAGE_PATHS[@]}")
      ;;
    relay)
      paths=("${RELAY_IMAGE_PATHS[@]}")
      ;;
    *)
      echo "::error::unknown app image component '$component' (expected server, ac, or relay)." >&2
      exit 1
      ;;
  esac

  if [[ -z "$tag" || "$tag" == "unknown" || "$tag" == "None" ]]; then
    app_image_required=true
    reasons+=("$component active image tag is empty/unknown")
    continue
  fi

  # Active image tags are written as full commit IDs. Accept today's SHA-1 width
  # and SHA-256 width only; short or ambiguous IDs fail closed as malformed.
  if [[ ! "$tag" =~ ^([0-9a-f]{40}|[0-9a-f]{64})$ ]]; then
    app_image_required=true
    reasons+=("$component active image tag '$tag' is not a git SHA")
    continue
  fi

  if ! git cat-file -e "$tag^{commit}" 2>/dev/null; then
    if ! fetch_commit "$tag" || ! git cat-file -e "$tag^{commit}" 2>/dev/null; then
      app_image_required=true
      reasons+=("$component active image tag '$tag' is not available as a git commit")
      continue
    fi
  fi

  # The deploy target SHA is the desired app tree, not only a lower bound. If a
  # manual redeploy/rollback targets an older SHA while the active image is ahead
  # with different app paths, require a rebuild so live bytes converge to the
  # target before deployed-commit is stamped.
  diff_err=""
  # In an `if` condition, `set -e` does not exit on git's 1/128 statuses;
  # diff_rc in the else branch is git diff's exit code.
  if diff_err=$(git diff --quiet "$tag" "$HEAD_SHA" -- "${paths[@]}" 2>&1); then
    continue
  else
    diff_rc=$?
  fi

  if [[ "$diff_rc" -eq 1 ]]; then
    app_image_required=true
    reasons+=("$component active image tag '$tag' has app paths that differ from target $HEAD_SHA")
    continue
  fi

  echo "::error::git diff failed for $component active image tag '$tag' against $HEAD_SHA; cannot evaluate app image drift." >&2
  if [[ -n "$diff_err" ]]; then
    echo "$diff_err" >&2
  fi
  exit 1
done

if [[ "$app_image_required" == "true" ]]; then
  echo "::notice::Fresh app image required:"
  for reason in "${reasons[@]}"; do
    echo "::notice::  - $reason"
  done
else
  echo "::notice::Live app image tags already contain app paths at $HEAD_SHA."
fi

emit_output
