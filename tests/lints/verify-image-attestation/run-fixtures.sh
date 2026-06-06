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

G404='Error: HTTP 404: Not Found'
G403='Error: HTTP 403: Forbidden'

# audit never blocks; enforce blocks only on a real "no attestation" verdict;
# infra/tooling errors (login/describe/permission) fail OPEN even under enforce.
run_case "audit + verify-pass"            0 pass  audit   STUB_GH_RC=0
# REGISTRY_ID unset -> account resolved via `aws sts get-caller-identity` (the
# same-account path used by blue-green/promote, vs the cross-account registry-id
# path used by canary). The later REGISTRY_ID= wins under env, overriding the
# default. Locks both account-resolution branches.
run_case "audit + same-account (sts path)" 0 pass  audit   STUB_GH_RC=0 REGISTRY_ID=
run_case "audit + no-attestation"         0 fail  audit   STUB_GH_RC=1 STUB_GH_OUT="$G404"
run_case "enforce + verify-pass"          0 pass  enforce STUB_GH_RC=0
run_case "enforce + no-attestation"       1 fail  enforce STUB_GH_RC=1 STUB_GH_OUT="$G404"
run_case "enforce + docker-login-fail"    0 error enforce STUB_DOCKER_RC=1
run_case "enforce + gh-permission(403)"   0 error enforce STUB_GH_RC=1 STUB_GH_OUT="$G403"
# gh fails with empty/unrecognized output (not matching the verdict grep) -> infra
# (fail-open), so a future grep-pattern edit can't silently reclassify an
# unmatched failure as a blocking verdict.
run_case "enforce + gh-empty-output"      0 error enforce STUB_GH_RC=1
run_case "enforce + describe-fail"        0 error enforce STUB_DESCRIBE_FAIL=1
# Retry-then-succeed: describe fails once, then resolves. Locks that retry()'s
# progress goes to stderr and doesn't pollute the captured digest (otherwise the
# captured value gains a "::notice::..." line, fails the sha256: check, and
# fail_infra fires on a digest that WAS resolvable).
echo 1 > "$TMP/describe_fail_count"
run_case "enforce + describe-fail-then-pass" 0 pass enforce STUB_GH_RC=0 STUB_FAIL_FILE="$TMP/describe_fail_count"
run_case "mode 'Enforce' normalized"      1 fail  Enforce STUB_GH_RC=1 STUB_GH_OUT="$G404"
run_case "mode ' ENFORCE ' normalized"    1 fail  " ENFORCE " STUB_GH_RC=1 STUB_GH_OUT="$G404"
run_case "mode 'bogus' -> audit default"  0 fail  bogus   STUB_GH_RC=1 STUB_GH_OUT="$G404"

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
