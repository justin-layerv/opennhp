#!/usr/bin/env bash
# check-image-tag-writer-allowlist.sh
# ---------------------------------------------------------------------
# Fail if anything outside the deployer family writes
#   /<env>/nhp/<component>/image-tag
#   /<env>/nhp/<component>/green-image-tag
# where <component> ∈ {server, ac, reverse-tunnel-server}.
#
# Background: until 2026-05-19 the build matrix in build-and-push.yml
# also wrote /<env>/nhp/<component>/image-tag at the end of each
# matrix entry. Two parallel matrix entries (server, ac) racing the
# same SSM slot — without ordering guarantees with respect to a
# concurrent infra-only run reading the same slot — produced a torn
# read that hard-failed dispatcher run 26130904414. The fix removed
# the builder's write entirely, leaving exactly three writers:
#
#   - blue-green-deploy.yml   (sandbox; writes the STANDBY slot only,
#                              picked by active-color indirection)
#   - canary-deploy.yml       (prod; writes /image-tag — prod has no
#                              green-image-tag sibling)
#   - update-ssm-image-tag.sh (helper called by promote-to-prod.yml
#                              for prod canary (server/ac) and the
#                              prod reverse-tunnel-server deploy-qrts
#                              job; same single-slot contract)
#
# Anything else that writes these slots can recreate the original
# race or another flavour of it. This script keeps that contract
# enforceable at PR time rather than at incident time.
#
# Scope: bash `aws ssm put-parameter` invocations only. boto3
# (`ssm.put_parameter(...)`) is NOT detected — see #2028. If you're
# adding a Python/Lambda writer of these slots, route it through the
# bash deployer family (or extend `PUT_RE` in
# check-image-tag-writer-allowlist.py rather than just allowlisting
# your new file).
#
# Usage:
#   ./scripts/check-image-tag-writer-allowlist.sh   # exit 0 clean, 1 on violation
#
# This wrapper delegates the actual scan to a small Python script so
# the multi-line, variable-indirected SSM-write detection is precise
# (a pure-bash version produced false positives on files that mix
# get-parameter reads of slot paths with unrelated put-parameter
# writes to other params).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

python3 "$REPO_ROOT/scripts/check-image-tag-writer-allowlist.py" "$@"
