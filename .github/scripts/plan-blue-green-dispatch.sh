#!/bin/bash
# Emit the minimal set of blue-green-deploy dispatches needed to refresh the
# NHP server and AC at the given image tags.
#
# blue-green-deploy.yml accepts a single image_tag per dispatch, so:
#   - when both components share a tag we refresh them together in one
#     `component=both` dispatch;
#   - when they have drifted to different tags we dispatch each component
#     separately at its own tag.
#
# Drift is a reachable state even though app-changing CI commits build and
# deploy both components at one github.sha: a per-component manual dispatch,
# or a `both` deploy where only one colour's SSM tag advanced before the
# other failed/rolled back, leaves the two components on different active
# tags. Before this script, build-and-push.yml's infra-only deploy path
# hard-failed in that state ("blue-green-deploy.yml only accepts a single
# image_tag input today"); splitting into two dispatches lets the refresh
# proceed at each component's own tag instead.
#
# Centralising the decision keeps the dispatch step in build-and-push.yml
# thin and gives the contract a fixture test
# (tests/scripts/plan-blue-green-dispatch_test.sh) — in particular it pins
# that a drifted pair NEVER deploys one component at the other's tag.
#
# Usage: plan-blue-green-dispatch.sh <server_tag> <ac_tag>
#
# Stdout: one "<component> <tag>" line per required dispatch, in the order
#         build-and-push.yml should dispatch them:
#   - tags equal:  "both <tag>"
#   - tags differ: "server <server_tag>" then "ac <ac_tag>"
# Stderr: ::error:: annotation on invalid input.
#
# Exit codes:
#   0 — printed a dispatch plan
#   1 — input validation failure

set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "Usage: $0 <server_tag> <ac_tag>" >&2
  exit 1
fi

SERVER_TAG="$1"
AC_TAG="$2"

# Fail closed on a blank or whitespace-bearing tag rather than dispatching
# blue-green-deploy.yml with a bad image_tag (which its "Validate Inputs" step
# would reject deep in a dispatched run, long after this step "succeeded"). A
# real tag is a SHA / clean ref with no whitespace, so any whitespace — empty,
# all-spaces (e.g. a corrupted SSM value), or embedded — is invalid.
if [[ -z "$SERVER_TAG" || -z "$AC_TAG" || "$SERVER_TAG" == *[[:space:]]* || "$AC_TAG" == *[[:space:]]* ]]; then
  echo "::error::plan-blue-green-dispatch.sh requires non-empty, whitespace-free server and ac tags (got server='$SERVER_TAG', ac='$AC_TAG')." >&2
  exit 1
fi

if [[ "$SERVER_TAG" == "$AC_TAG" ]]; then
  printf 'both %s\n' "$SERVER_TAG"
else
  # Drift is tolerated (we still refresh each component at its own tag rather
  # than failing the deploy), but it is notable: surface it as a CI annotation
  # so an operator notices if it persists run-after-run, which can mean a
  # colour stuck or rolled back and never reconverged. Stderr keeps stdout the
  # clean machine-readable plan; this mirrors the ::error:: path above.
  echo "::warning::server and AC active image tags differ (server=$SERVER_TAG, ac=$AC_TAG); dispatching each component at its own tag. Persistent drift across runs may indicate a colour that stuck or rolled back." >&2
  printf 'server %s\n' "$SERVER_TAG"
  printf 'ac %s\n' "$AC_TAG"
fi
