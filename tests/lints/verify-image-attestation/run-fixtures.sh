#!/usr/bin/env bash
# Behaviour fixture for .github/actions/verify-image-attestation/action.yml.
#
# The composite action's bash logic is the safety-critical core of the #1334
# Phase 1 deploy-time attestation gate, and it cannot be exercised pre-merge
# (the `uses:` wiring only runs in the deploy workflows). This fixture stubs
# aws/gh/docker/sleep on PATH and asserts the exit-code + ATTEST_RESULT contract
# per mode, so a future edit can't silently turn the audit-mode gate into a
# deploy blocker — or weaken enforce. Wired into `make lint-workflows` and
# .github/workflows/validate-workflows.yml.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
ACTION="$ROOT/.github/actions/verify-image-attestation/action.yml"
[[ -f "$ACTION" ]] || { echo "missing action: $ACTION"; exit 1; }

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
BIN="$TMP/bin"; mkdir -p "$BIN"

# Extract the composite action's run: script.
python3 - "$ACTION" > "$TMP/script.sh" <<'PY'
import sys, yaml
print(yaml.safe_load(open(sys.argv[1]))["runs"]["steps"][0]["run"])
PY

# Also lint the extracted action script. make lint-workflows and CI only run a
# linter over workflow files + this wrapper, not the composite action's
# embedded run: block — so without this a lint regression inside action.yml's
# safety-critical script would ship uncaught. The linter is a lint-workflows /
# CI prerequisite; skip with a note only when run standalone without it.
if command -v shellcheck >/dev/null 2>&1; then
  shellcheck -s bash "$TMP/script.sh" || { echo "FAIL  extracted action script failed shellcheck"; exit 1; }
  echo "PASS  extracted action script shellcheck"
else
  echo "NOTE  shellcheck not on PATH; skipping extracted-action-script lint (CI/make lint-workflows provide it)"
fi

# Stubs — behaviour controlled via STUB_* env.
cat > "$BIN/aws" <<'STUB'
#!/usr/bin/env bash
case "$*" in
  *"sts get-caller-identity"*) echo "767397897469" ;;
  *"ecr describe-images"*)
    # Emit a specific error to stderr so the action's failure-path re-read can
    # classify it (INFRA_RE -> infra/fail-open; genuine-absent -> verdict).
    if [[ -n "${STUB_DESCRIBE_ERR:-}" ]]; then echo "$STUB_DESCRIBE_ERR" >&2; exit 254; fi
    [[ "${STUB_DESCRIBE_FAIL:-0}" == 1 ]] && exit 254
    # Fail the first STUB_FAIL_FILE-count attempts (decrementing a counter file),
    # then succeed — exercises the retry-then-succeed path.
    if [[ -n "${STUB_FAIL_FILE:-}" && -s "${STUB_FAIL_FILE:-}" ]]; then
      left="$(cat "$STUB_FAIL_FILE")"
      if [[ "$left" -gt 0 ]]; then echo "$((left - 1))" > "$STUB_FAIL_FILE"; exit 254; fi
    fi
    echo "sha256:abc123" ;;
  *"ecr get-login-password"*) echo "stub-pw" ;;
  *) exit 0 ;;
esac
STUB
cat > "$BIN/gh" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "${STUB_GH_OUT:-}" >&2
exit "${STUB_GH_RC:-0}"
STUB
cat > "$BIN/docker" <<'STUB'
#!/usr/bin/env bash
# Drain stdin before exiting: the action pipes `aws get-login-password` into
# `docker login --password-stdin`, which a real docker consumes. Exiting without
# reading would SIGPIPE the upstream aws under pipefail (flaky exit 141).
cat >/dev/null 2>&1 || true
[[ "${1:-}" == "login" ]] && exit "${STUB_DOCKER_RC:-0}"
exit 0
STUB
printf '#!/usr/bin/env bash\nexit 0\n' > "$BIN/sleep"
chmod +x "$BIN"/*

PASS=0; FAIL=0
# run_case <name> <expect_exit> <expect_result> <mode> [STUB_x=y ...]
run_case() {
  local name="$1" exp_rc="$2" exp_res="$3" mode="$4"; shift 4
  local out rc res
  out="$(env -i PATH="$BIN:/usr/bin:/bin" HOME="$TMP" \
      REPOSITORY=layerv/nhp-server IMAGE_TAG=deadbeef REGION=us-east-2 \
      REGISTRY_ID=767397897469 GH_REPO=layervai/nhp \
      SIGNER_WORKFLOW=.github/workflows/build-and-push.yml GH_TOKEN=x \
      MODE="$mode" "$@" \
      bash -eo pipefail "$TMP/script.sh" 2>&1)"; rc=$?
  res="$(printf '%s\n' "$out" | grep -oE 'ATTEST_RESULT=[a-z]+' | head -1 | cut -d= -f2)"
  if [[ "$rc" == "$exp_rc" && "$res" == "$exp_res" ]]; then
    printf 'PASS  %-38s exit=%s result=%s\n' "$name" "$rc" "$res"; PASS=$((PASS+1))
  else
    printf 'FAIL  %-38s exit=%s(want %s) result=%s(want %s)\n' "$name" "$rc" "$exp_rc" "${res:-none}" "$exp_res"
    printf '%s\n' "$out" | sed 's/^/        /'; FAIL=$((FAIL+1))
  fi
}

# trap_case <name> <expect_exit> <mode>: inject an UNHANDLED error (REPOSITORY
# unset -> set -u) to exercise the EXIT-trap backstop itself — audit must
# convert it to exit 0, enforce must propagate. No ATTEST_RESULT is emitted
# (the script dies before any fail_* path), so only the exit code is asserted.
trap_case() {
  local name="$1" exp_rc="$2" mode="$3" rc
  env -i PATH="$BIN:/usr/bin:/bin" HOME="$TMP" \
    IMAGE_TAG=deadbeef REGION=us-east-2 REGISTRY_ID=767397897469 GH_REPO=layervai/nhp \
    SIGNER_WORKFLOW=.github/workflows/build-and-push.yml GH_TOKEN=x MODE="$mode" \
    bash -eo pipefail "$TMP/script.sh" >/dev/null 2>&1
  rc=$?
  if [[ "$rc" == "$exp_rc" ]]; then
    printf 'PASS  %-38s exit=%s\n' "$name" "$rc"; PASS=$((PASS+1))
  else
    printf 'FAIL  %-38s exit=%s(want %s)\n' "$name" "$rc" "$exp_rc"; FAIL=$((FAIL+1))
  fi
}

# Real gh/aws wording captured against a live post-#2339 sandbox image
# (acct 767397897469, layerv/nhp-server) on 2026-06-13 with gh 2.92.0 — see PR
# description. Using OBSERVED strings (not guessed) makes the verdict-vs-infra
# fixtures NON-tautological. These are the COMPLETE gh failure outputs, not
# excerpts: gh 2.92.0 emits a single `Error: <...>` line per failure (preceded by
# a cosmetic blank line) and does NOT echo the candidate attestation's identity.
G404='Error: HTTP 404: Not Found (https://api.github.com/repos/layervai/nhp/attestations/sha256:abc?per_page=30&predicate_type=https://slsa.dev/provenance/v1)'
G403='Error: HTTP 403: Forbidden (https://api.github.com/repos/layervai/nhp/attestations/sha256:abc)'
# Attestation EXISTS but fails the identity/ref/workflow pin — the terse line gh
# prints, and the case the pre-#1334 classifier mis-classified as infra/fail-open.
G_IDMISMATCH='Error: verifying with issuer "GitHub, Inc."'
# Image manifest gone from the registry (deleted under us mid-deploy).
G_MANIFEST='Error: failed to fetch remote image: GET https://767397897469.dkr.ecr.us-east-2.amazonaws.com/v2/layerv/nhp-server/manifests/sha256:abc: MANIFEST_UNKNOWN: Requested image not found'
G_5XX='Error: HTTP 503: Service Unavailable (https://api.github.com/repos/layervai/nhp/attestations/sha256:abc)'
G_429='Error: HTTP 429: Too Many Requests (https://api.github.com/repos/layervai/nhp/attestations/sha256:abc)'
# Real captured DNS/network failure (bogus registry host) — gh wraps it in its
# own `Error: failed to fetch remote image: Get "...": dial tcp ... no such host`.
G_NETWORK='Error: failed to fetch remote image: Get "https://nonexistent-registry-zzz.invalid/v2/": dial tcp: lookup nonexistent-registry-zzz.invalid: no such host'
# HYPOTHETICAL future-gh verbosity: a multi-line failure whose INFORMATIONAL lines
# echo the candidate attestation's identity — here an attacker-influenceable
# branch ref 'fix-503-timeout' that contains INFRA_RE tokens ('timeout', and a
# bare '503'). The terminal `Error:` line is a clean verdict. The classifier scopes
# the infra match to the `Error:` line, so this stays a VERDICT (fail-closed). A
# whole-blob grep would match 'timeout' on the info line and fail OPEN — the hole.
G_VERBOSE_MISMATCH='Loaded digest sha256:abc for oci://example/img
✗ The attestation identity https://github.com/layervai/nhp/.github/workflows/build-and-push.yml@refs/heads/fix-503-timeout did not match the expected SAN
Error: verifying with issuer "GitHub, Inc."'
# x509 / cert-chain-authority wording is AMBIGUOUS — it can be a transport TLS
# error OR an attestation whose signing cert doesn't chain to a trusted root (a
# verdict). A fail-closed gate must NOT fail open on it, so it is excluded from
# INFRA_RE and classifies as a verdict. Locks that decision against regression
# (re-adding 'x509' to INFRA_RE would flip this case to error and fail this test).
G_X509='Error: failed to verify certificate: x509: certificate signed by unknown authority'
# `aws ecr describe-images` errors (captured form), classified on the failure-path
# re-read: ImageNotFound is genuinely-absent (verdict); Throttling is transient.
E_IMAGEABSENT="An error occurred (ImageNotFoundException) when calling the DescribeImages operation: The image with imageId {imageDigest:'null', imageTag:'deadbeef'} does not exist within the repository with name 'layerv/nhp-server'"
# Genuinely-absent image whose OPERATOR/dispatch-settable tag carries an INFRA_RE
# token ('rate-limit-fix' -> rate.?limit), which aws echoes back in the error. The
# absent-image verdict MUST be checked before the INFRA_RE grep, else the echoed
# tag flips it to fail-OPEN. Caught by the ABSENT_RE-first check.
E_IMAGEABSENT_INFRATAG="An error occurred (ImageNotFoundException) when calling the DescribeImages operation: The image with imageId {imageDigest:'null', imageTag:'rate-limit-fix'} does not exist within the repository with name 'layerv/nhp-server'"
# An UNRECOGNIZED (non-absent, non-infra) describe error that still echoes the
# operator tag ('timeout-debug' -> timeout). Not caught by ABSENT_RE, so the tag
# scrub is what prevents the echoed token from matching INFRA_RE and failing OPEN;
# it must fall through to the fail-closed default. Envelope is illustrative — the
# load-bearing part is the operator-settable tag carrying an infra token.
E_UNREC_INFRATAG="An error occurred (InvalidParameterException) when calling the DescribeImages operation: invalid request for imageTag:'timeout-debug'"
E_THROTTLE='An error occurred (ThrottlingException) when calling the DescribeImages operation: Rate exceeded'

# CONTRACT (post-#1334 finalization): fail-CLOSED by default. audit NEVER blocks.
# Under enforce a verify failure BLOCKS unless it matches the recognized-infra
# allowlist (INFRA_RE), which fails OPEN. Verdicts (fail-closed): unattested,
# identity/ref mismatch, manifest gone, genuinely-absent image, unrecognized
# failure. Infra (fail-open): 401/403/408/429/5xx, throttle, timeout, network,
# TLS, credential/permission, docker-login blip.
run_case "audit + verify-pass"               0 pass  audit   STUB_GH_RC=0
# REGISTRY_ID unset -> account resolved via `aws sts get-caller-identity` (the
# same-account path used by blue-green/promote, vs the cross-account registry-id
# path used by canary). The later REGISTRY_ID= wins under env, overriding the
# default. Locks both account-resolution branches.
run_case "audit + same-account (sts path)"   0 pass  audit   STUB_GH_RC=0 REGISTRY_ID=
run_case "audit + no-attestation"            0 fail  audit   STUB_GH_RC=1 STUB_GH_OUT="$G404"
run_case "enforce + verify-pass"             0 pass  enforce STUB_GH_RC=0
run_case "enforce + no-attestation (404)"    1 fail  enforce STUB_GH_RC=1 STUB_GH_OUT="$G404"

# THE #1334 fix, keyed on real wording: an attestation that EXISTS but fails the
# identity/ref pin is a verdict, so it fails CLOSED under enforce. Pre-fix it fell
# through to infra/fail-OPEN — the documented gap. This is the load-bearing,
# non-tautological assertion of this PR.
run_case "audit + identity-mismatch"         0 fail  audit   STUB_GH_RC=1 STUB_GH_OUT="$G_IDMISMATCH"
run_case "enforce + identity-mismatch"       1 fail  enforce STUB_GH_RC=1 STUB_GH_OUT="$G_IDMISMATCH"
run_case "enforce + manifest-unknown"        1 fail  enforce STUB_GH_RC=1 STUB_GH_OUT="$G_MANIFEST"
run_case "enforce + cert-untrusted (x509)"   1 fail  enforce STUB_GH_RC=1 STUB_GH_OUT="$G_X509"
# Multi-line failure whose info line echoes an attacker-influenceable identity
# ('fix-503-timeout') containing INFRA_RE tokens; terminal Error: line is a clean
# verdict. MUST stay fail-closed — proves the infra match is scoped to gh's Error:
# line, not the whole blob (a whole-blob grep would match 'timeout' -> fail-OPEN).
run_case "enforce + verbose-mismatch(scoped)" 1 fail  enforce STUB_GH_RC=1 STUB_GH_OUT="$G_VERBOSE_MISMATCH"

# Recognized-infra signals fail OPEN even under enforce (transient/permission).
run_case "enforce + docker-login-fail"       0 error enforce STUB_DOCKER_RC=1
run_case "enforce + gh-permission(403)"      0 error enforce STUB_GH_RC=1 STUB_GH_OUT="$G403"
run_case "enforce + gh-5xx"                  0 error enforce STUB_GH_RC=1 STUB_GH_OUT="$G_5XX"
run_case "enforce + gh-429-throttle"         0 error enforce STUB_GH_RC=1 STUB_GH_OUT="$G_429"
run_case "enforce + gh-network(no-host)"     0 error enforce STUB_GH_RC=1 STUB_GH_OUT="$G_NETWORK"

# gh fails with empty/unrecognized output: NOT a recognized-infra signal, so it
# fails CLOSED under enforce (the post-#1334 default). Pre-fix this was infra/
# fail-OPEN; the inversion is the point — an unrecognized failure must not let an
# unverified image ship.
run_case "enforce + gh-empty-output"         1 fail  enforce STUB_GH_RC=1

# describe-images failure classification (failure-path re-read): genuinely-absent
# tag/repo is a verdict; transient throttle is infra; a bare failure with no error
# text fails CLOSED (real aws always emits stderr, so this is a defensive default).
run_case "enforce + describe-image-absent"   1 fail  enforce STUB_DESCRIBE_ERR="$E_IMAGEABSENT"
# Absent image whose tag carries an infra token — fail-closed via ABSENT_RE-first
# (IMAGE_TAG matches the tag aws echoes, the realistic deploy scenario).
run_case "enforce + absent w/ infra-tok tag"  1 fail  enforce IMAGE_TAG=rate-limit-fix STUB_DESCRIBE_ERR="$E_IMAGEABSENT_INFRATAG"
# Unrecognized describe error whose tag carries an infra token — fail-closed via
# the tag scrub (would fail-OPEN on the echoed 'timeout' without it).
run_case "enforce + unrec err, infra-tok tag" 1 fail  enforce IMAGE_TAG=timeout-debug STUB_DESCRIBE_ERR="$E_UNREC_INFRATAG"
run_case "enforce + describe-throttle"       0 error enforce STUB_DESCRIBE_ERR="$E_THROTTLE"
run_case "enforce + describe-fail (bare)"    1 fail  enforce STUB_DESCRIBE_FAIL=1
# Retry-then-succeed: describe fails once, then resolves. Locks that the retry
# ::notice:: goes to stderr and doesn't pollute the captured digest (otherwise the
# captured value gains a "::notice::..." line, fails the sha256: check, and the
# failure path fires on a digest that WAS resolvable).
echo 1 > "$TMP/describe_fail_count"
run_case "enforce + describe-fail-then-pass" 0 pass  enforce STUB_GH_RC=0 STUB_FAIL_FILE="$TMP/describe_fail_count"

# Mode normalization (trim + lowercase); an unrecognized mode -> audit.
run_case "mode 'Enforce' normalized"         1 fail  Enforce STUB_GH_RC=1 STUB_GH_OUT="$G404"
run_case "mode ' ENFORCE ' normalized"       1 fail  " ENFORCE " STUB_GH_RC=1 STUB_GH_OUT="$G404"
run_case "mode 'bogus' -> audit default"     0 fail  bogus   STUB_GH_RC=1 STUB_GH_OUT="$G404"

# EXIT-trap backstop (the audit safety net itself): an unhandled error must
# convert to exit 0 under audit and propagate under enforce.
trap_case "EXIT-trap audit (unbound var)"   0 audit
trap_case "EXIT-trap enforce (unbound var)" 1 enforce

# Static guard: gh's flag is --cert-identity-regex (one 'p'), not cosign's
# --cert-identity-regexp. A wrong spelling makes real gh exit on an unknown flag
# before checking attestations, so every image would classify as an infra error
# and the gate would silently never verify — a failure the arg-ignoring stubs
# above cannot catch. Lock the spelling here.
if grep -q -- '--cert-identity-regexp' "$TMP/script.sh"; then
  printf 'FAIL  %-38s (cosign spelling; gh wants --cert-identity-regex)\n' "gh flag spelling"; FAIL=$((FAIL+1))
elif grep -q -- '--cert-identity-regex' "$TMP/script.sh"; then
  printf 'PASS  %-38s\n' "gh flag spelling (--cert-identity-regex)"; PASS=$((PASS+1))
else
  printf 'FAIL  %-38s (no --cert-identity-regex identity pin found)\n' "gh flag spelling"; FAIL=$((FAIL+1))
fi

# Lock the sed-built --cert-identity-regex string for the default inputs. The gh
# stub ignores the flag, so the behavioural cases above don't exercise the
# regex-escaping — yet that string is what pins signer + @refs/heads/main on the
# enforce path. The expected value was validated against real gh; assert the
# action's actual escaping reproduces it end-to-end.
EXPECTED_ID='^https://github\.com/layervai/nhp/\.github/workflows/build-and-push\.yml@refs/heads/main$'
id_out="$(env -i PATH="$BIN:/usr/bin:/bin" HOME="$TMP" \
  REPOSITORY=layerv/nhp-server IMAGE_TAG=x REGION=us-east-2 REGISTRY_ID=767397897469 \
  GH_REPO=layervai/nhp SIGNER_WORKFLOW=.github/workflows/build-and-push.yml GH_TOKEN=x \
  MODE=audit STUB_GH_RC=0 bash -eo pipefail "$TMP/script.sh" 2>&1)"
if printf '%s\n' "$id_out" | grep -qF -- "identity-regex  : $EXPECTED_ID"; then
  printf 'PASS  %-38s\n' "cert-identity-regex escaping"; PASS=$((PASS+1))
else
  printf 'FAIL  %-38s\n' "cert-identity-regex escaping"
  printf '%s\n' "$id_out" | grep -F "identity-regex" | sed 's/^/        got: /'; FAIL=$((FAIL+1))
fi

echo "---"
if [[ "$FAIL" -gt 0 ]]; then echo "verify-image-attestation fixtures: $FAIL FAILED, $PASS passed"; exit 1; fi
echo "verify-image-attestation fixtures: all $PASS passed"
