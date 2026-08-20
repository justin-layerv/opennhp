#!/usr/bin/env bash
# run-smoke.sh
# ----------------------------------------------------------------------------
# Single entrypoint for the NHP smoke suite (tests/smoke, build tag `smoke`).
# Runs the SAME harness in every context:
#
#   - local pre-PR:   TARGET=local    (brings up a self-contained stack)
#   - PR CI:          TARGET=local    (tests the PR's freshly-built binaries)
#   - post-deploy CI: TARGET=sandbox|prod   (against the deployed env)
#   - manual debug:   any of the above
#
# This script is the SOURCE OF TRUTH for two things that used to be
# duplicated between the Makefile and .github/workflows/nhp-smoke-tests.yml:
#
#   1. The tier -> RUN_FILTER mapping (the `case "$TIER"` block below).
#      Fenced by scripts/check-smoke-tier-filter-coverage.sh, which parses
#      THIS file: each `Foo` token must match a real `TestFoo_<...>`
#      declaration in tests/smoke/0X_*_test.go and conversely. Keep the
#      single-line single-quoted `RUN_FILTER='^Test(...)_'` shape — the awk
#      parser in that checker depends on it.
#   2. The env-derived NHP_SMOKE_QURL_INTERNAL_ALB_ENABLED flag (keyed on
#      the target name, so a future regional env added without the internal
#      ALB wired skips the 07_/08_/09_ fences cleanly). nhp#1640 will move
#      this to an SSM-sourced read and collapse the remaining duplication.
#
# Credentials are the CALLER's responsibility:
#   - local:  AWS_PROFILE (sandbox/prod targets) — or nothing for `local`.
#   - CI:     an OIDC role is assumed before this script is invoked.
# (No Auth0 is fetched or passed: the qURL/Auth0-dependent smoke tests were
# moved to qurl-service, so nothing in this suite needs it anymore.)
#
# Usage:
#   TARGET=sandbox TIER=all scripts/run-smoke.sh
#   TARGET=local scripts/run-smoke.sh                # TIER defaults to `local`
#
# Inputs (environment variables):
#   TARGET                       local | sandbox | prod              (required)
#   TIER                         tier1 | tier1+tier2 | tier3-no-ssm | all | local
#                                (default: `local` for TARGET=local, else `tier1`)
#   NHP_SMOKE_ALLOW_SSM_PROBES   true|false (default false; forced false for local)
#   AWS_REGION                   default us-east-2 (sandbox/prod only)
#   QURL_LINK_ORIGIN             optional origin override (sandbox/prod)
#   GO_TEST_TIMEOUT              default 15m
#   NHP_SMOKE_KEEP_STACK         local only: 1 leaves the stack up after the run
#                                (skip teardown) for debugging (default 0)
# ----------------------------------------------------------------------------

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SMOKE_DIR="${REPO_ROOT}/tests/smoke"

TARGET="${TARGET:-}"
if [ -z "$TARGET" ]; then
  echo "ERROR: TARGET must be set (local | sandbox | prod)" >&2
  exit 2
fi

AWS_REGION="${AWS_REGION:-us-east-2}"
GO_TEST_TIMEOUT="${GO_TEST_TIMEOUT:-15m}"

# Default tier depends on target: `local` runs the curated local-safe subset.
if [ "$TARGET" = "local" ]; then
  TIER="${TIER:-local}"
else
  TIER="${TIER:-tier1}"
fi

# ----------------------------------------------------------------------------
# Per-target environment derivation.
# ----------------------------------------------------------------------------
case "$TARGET" in
  local)
    # No AWS, no Auth0, no SSM probes against a local stack.
    # scripts/smoke-local-stack.sh (invoked below) brings up nhp-server +
    # nhp-ac + dynamodb-local via docker compose; the suite points at
    # http://localhost:8888 (see tests/smoke/dns.go's local case).
    export NHP_ENVIRONMENT="local"
    export NHP_SMOKE_ALLOW_SSM_PROBES="false"
    export NHP_SMOKE_QURL_INTERNAL_ALB_ENABLED="false"
    if ! command -v docker >/dev/null 2>&1; then
      echo "ERROR: TARGET=local needs Docker (the local stack runs via docker compose); 'docker' not found on PATH" >&2
      exit 2
    fi
    ;;
  sandbox)
    export NHP_ENVIRONMENT="sandbox"
    export AWS_REGION
    export NHP_SMOKE_ALLOW_SSM_PROBES="${NHP_SMOKE_ALLOW_SSM_PROBES:-false}"
    # sandbox has the qurl-service internal ALB wired (qurl-service #335).
    export NHP_SMOKE_QURL_INTERNAL_ALB_ENABLED="true"
    [ -n "${QURL_LINK_ORIGIN:-}" ] && export QURL_LINK_ORIGIN
    ;;
  prod)
    export NHP_ENVIRONMENT="prod"
    export AWS_REGION
    export NHP_SMOKE_ALLOW_SSM_PROBES="${NHP_SMOKE_ALLOW_SSM_PROBES:-false}"
    # prod has the qurl-service internal ALB wired.
    export NHP_SMOKE_QURL_INTERNAL_ALB_ENABLED="true"
    [ -n "${QURL_LINK_ORIGIN:-}" ] && export QURL_LINK_ORIGIN
    ;;
  *)
    echo "ERROR: unknown TARGET: $TARGET (expected local | sandbox | prod)" >&2
    exit 2
    ;;
esac

# ----------------------------------------------------------------------------
# Tier -> RUN_FILTER mapping. SOURCE OF TRUTH (moved here from
# nhp-smoke-tests.yml). See the header note and
# scripts/check-smoke-tier-filter-coverage.sh.
# ----------------------------------------------------------------------------
case "$TIER" in
  tier1)
    RUN_FILTER='^Test(HealthKnockReady|HealthLive|HealthReady|HealthStartup|DockerImage|ACEBPFObjects|SSMRunbook|BlueGreen|Canary|ACAlarms|AuthorityAlarms|ACEIPPool|ACLogs|ServerDeployStability|QurlInternalALB|QurlConfig|QurlDeviceCredentialAuthorityIAM|PublicALB|ResolveOrigin)_'
    ;;
  tier1+tier2)
    RUN_FILTER='^Test(HealthKnockReady|HealthLive|HealthReady|HealthStartup|DockerImage|ACEBPFObjects|SSMRunbook|BlueGreen|Canary|ACAlarms|AuthorityAlarms|ACEIPPool|ACLogs|ServerDeployStability|QurlInternalALB|QurlConfig|QurlDeviceCredentialAuthorityIAM|QurlBrowserTimings|QurlLinkFrontend|PublicALB|Resolve|ResolveV2|ResolveOrigin|Knock|Plugins|InternalAPI|CustomDomainCleanup|CustomDomainCertDNSOwnership)_'
    ;;
  tier3-no-ssm)
    RUN_FILTER='^Test(HealthKnockReady|HealthLive|HealthReady|HealthStartup|BlueGreen|Canary|ACAlarms|AuthorityAlarms|ACEIPPool|ACLogs|QurlInternalALB|QurlConfig|QurlDeviceCredentialAuthorityIAM|QurlBrowserTimings|QurlLinkFrontend|PublicALB|Resolve|ResolveV2|ResolveOrigin|Knock|Plugins|InternalAPI|Protocol|ServerLogs|Timing|CustomDomainCleanup|CustomDomainCertDNSOwnership)_'
    ;;
  local)
    # Curated local-safe subset: pure NHP wire/HTTP contract that runs against
    # the self-contained local stack (nhp-server + nhp-ac + dynamodb-local; no
    # AWS control-plane, no qURL minting — qURL smoke belongs in the
    # qurl-service repo). The AC registers via a seeded license so
    # HealthKnockReady reflects a live AC peer. qURL/Auth0-dependent sub-tests
    # under these prefixes skip via requireRemote. Like `all`, this is an
    # allow-list: the coverage checker validates these tokens are real but does
    # NOT require every test to appear here.
    #
    # ResolveV2 (the offline qurl-go rejection tripwire) and
    # QurlLinkFrontend (whose remote checks skip while its committed-template
    # qv2t1 render fences execute) do NOT touch the local stack. They ride this
    # tier so PR pre-flight executes both reader boundaries before deployment.
    RUN_FILTER='^Test(HealthLive|HealthReady|HealthStartup|HealthKnockReady|Plugins|Timing|ResolveV2|QurlLinkFrontend)_'
    ;;
  all)
    RUN_FILTER=''
    ;;
  *)
    echo "ERROR: unknown TIER: $TIER (expected tier1 | tier1+tier2 | tier3-no-ssm | all | local)" >&2
    exit 2
    ;;
esac

# The resolved internal-ALB flag is surfaced in the line below (every
# non-local target sets it true today; an unrecognized target errors out in
# the case above rather than silently skipping the 07_/08_/09_ fences).
echo "smoke: target=${TARGET} env=${NHP_ENVIRONMENT} tier=${TIER} region=${AWS_REGION} ssm_probes=${NHP_SMOKE_ALLOW_SSM_PROBES} internal_alb=${NHP_SMOKE_QURL_INTERNAL_ALB_ENABLED}" >&2

# For the local target, bring up the self-contained stack (dynamodb-local +
# nhp-server) and tear it down on exit. Set NHP_SMOKE_KEEP_STACK=1 to leave it
# running for debugging.
if [ "$TARGET" = "local" ]; then
  if [ "${NHP_SMOKE_KEEP_STACK:-0}" != "1" ]; then
    trap '"${REPO_ROOT}/scripts/smoke-local-stack.sh" down' EXIT
  fi
  "${REPO_ROOT}/scripts/smoke-local-stack.sh" up
fi

cd "$SMOKE_DIR"

# Run the suite, teeing to test-output.txt (consumed by downstream CI steps:
# the summary, the CloudWatch metric, and the artifact
# upload). Capture the test's own exit code via PIPESTATUS so the tee does
# not mask a failure.
set +e
if [ -n "$RUN_FILTER" ]; then
  go test -tags=smoke -v -count=1 -timeout "$GO_TEST_TIMEOUT" -run "$RUN_FILTER" ./... 2>&1 | tee test-output.txt
else
  go test -tags=smoke -v -count=1 -timeout "$GO_TEST_TIMEOUT" ./... 2>&1 | tee test-output.txt
fi
TEST_EXIT=${PIPESTATUS[0]}
set -e

exit "$TEST_EXIT"
