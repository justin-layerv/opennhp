#!/usr/bin/env bash
# Fixture tests for scripts/check-lambda-boto-pin-lockstep.sh.
#
# The script derives REPO_ROOT from its own location and discovers the lambda
# requirement files by the glob terraform/modules/*/lambda/requirements*.txt, so
# each fixture is a fake repo: a symlink to the real script at <tmp>/scripts/
# plus a <tmp>/terraform/modules/<mod>/lambda/ tree of requirements files. That
# exercises the real discovery + `==` pin extraction + within-file (a) and
# cross-file (b) comparison against known-good and known-bad inputs, so a
# regression in the pin regex, the multiplicity guard, or either comparison is
# caught here before the real tree runs in CI.

set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$HERE/../.." && pwd)
SCRIPT="$REPO_ROOT/scripts/check-lambda-boto-pin-lockstep.sh"

# Two matched-pair versions (boto3/botocore ship at identical numbers) and a
# lower one used to force drift.
A="1.43.51"
B="1.43.46"

pass=0
fail=0

report_pass() {
  pass=$((pass + 1))
  printf '  [PASS] %s\n' "$1"
}

report_fail() {
  fail=$((fail + 1))
  printf '  [FAIL] %s\n      %s\n' "$1" "$2"
}

# Stage a fake repo root with the script symlinked in.
new_fixture() {
  local dir="$1"
  mkdir -p "$dir/scripts"
  ln -sf "$SCRIPT" "$dir/scripts/check-lambda-boto-pin-lockstep.sh"
}

# Create <dir>/terraform/modules/<module>/lambda/<file> with the given content
# ($4). Content is passed verbatim so each case controls the exact pin lines.
write_req() {
  local dir="$1" module="$2" file="$3" content="$4"
  local d="$dir/terraform/modules/$module/lambda"
  mkdir -p "$d"
  printf '%s\n' "$content" > "$d/$file"
}

assert_pass() {
  local name="$1" dir="$2" out
  if out=$("$dir/scripts/check-lambda-boto-pin-lockstep.sh" 2>&1); then
    report_pass "$name"
  else
    report_fail "$name" "expected exit 0, got non-zero; output: $out"
  fi
}

assert_fail() {
  local name="$1" dir="$2" want="$3" out
  if out=$("$dir/scripts/check-lambda-boto-pin-lockstep.sh" 2>&1); then
    report_fail "$name" "expected non-zero exit, got 0"
    return
  fi
  if [ -n "$want" ] && ! printf '%s' "$out" | grep -qF "$want"; then
    report_fail "$name" "stderr missing '$want'; got: $out"
    return
  fi
  report_pass "$name"
}

# Like assert_fail, but also asserts $unwanted is ABSENT from the output — for
# checking a specific message is NOT emitted (e.g. the cross-file (b) text on a
# single-file split).
assert_fail_lacks() {
  local name="$1" dir="$2" want="$3" unwanted="$4" out
  if out=$("$dir/scripts/check-lambda-boto-pin-lockstep.sh" 2>&1); then
    report_fail "$name" "expected non-zero exit, got 0"
    return
  fi
  if [ -n "$want" ] && ! printf '%s' "$out" | grep -qF "$want"; then
    report_fail "$name" "stderr missing '$want'; got: $out"
    return
  fi
  if [ -n "$unwanted" ] && printf '%s' "$out" | grep -qF "$unwanted"; then
    report_fail "$name" "stderr unexpectedly contains '$unwanted'; got: $out"
    return
  fi
  report_pass "$name"
}

ROOT=$(mktemp -d)
trap 'rm -rf "$ROOT"' EXIT

# 1. Two files, each pinning boto3==botocore at the SAME version -> pass.
d="$ROOT/all-good"; new_fixture "$d"
write_req "$d" acme-cert requirements-dev.txt "pytest==9.1.1
boto3==$A
botocore==$A
-r requirements.txt"
write_req "$d" status-page requirements-dev.txt "pytest==9.0.3
boto3==$A
botocore==$A"
assert_pass "matched pair, identical across files" "$d"

# 2. A single file whose boto3 and botocore differ -> fail (a), naming the file.
d="$ROOT/within-file-split"; new_fixture "$d"
write_req "$d" acme-cert requirements-dev.txt "boto3==$A
botocore==$A"
write_req "$d" status-page requirements-dev.txt "boto3==$B
botocore==$A"
assert_fail "within-file boto3 != botocore fails" "$d" "status-page/lambda/requirements-dev.txt: boto3==$B does not match botocore==$A"

# 3. Two files each internally matched but disagreeing across files -> fail (b).
d="$ROOT/cross-file-split"; new_fixture "$d"
write_req "$d" acme-cert requirements-dev.txt "boto3==$A
botocore==$A"
write_req "$d" status-page requirements-dev.txt "boto3==$B
botocore==$B"
assert_fail "cross-file version disagreement fails" "$d" "not identical across"

# 4. A runtime requirements.txt with NO boto pins alongside good test files ->
#    pass (the no-pin file is skipped).
d="$ROOT/runtime-skipped"; new_fixture "$d"
write_req "$d" acme-cert requirements.txt "cryptography==49.0.0
urllib3==2.7.0
requests==2.34.2"
write_req "$d" acme-cert requirements-dev.txt "boto3==$A
botocore==$A
-r requirements.txt"
assert_pass "runtime requirements.txt with no boto pins is skipped" "$d"

# 5. A pytest-only dev file (the developer-portal shape) alongside a good file ->
#    pass (skipped, contributes no pins).
d="$ROOT/pytest-only-skipped"; new_fixture "$d"
write_req "$d" developer-portal requirements-dev.txt "pytest"
write_req "$d" acme-cert requirements-dev.txt "boto3==$A
botocore==$A"
assert_pass "pytest-only dev file is skipped" "$d"

# 6. No boto3/botocore pin anywhere -> hard error (fail-closed checked==0 guard).
d="$ROOT/no-pins"; new_fixture "$d"
write_req "$d" developer-portal requirements-dev.txt "pytest"
write_req "$d" acme-cert requirements.txt "cryptography==49.0.0"
assert_fail "no boto pins anywhere is a hard error" "$d" "no boto3/botocore == pins found"

# 7. Cross-package cross-file agreement: one file pins only boto3, another only
#    botocore, SAME version -> pass (the shared env resolves to one version).
d="$ROOT/split-package-agree"; new_fixture "$d"
write_req "$d" acme-cert requirements-dev.txt "boto3==$A"
write_req "$d" status-page requirements-dev.txt "botocore==$A"
assert_pass "boto3-only + botocore-only at same version passes" "$d"

# 8. The same split-package shape but at DIFFERENT versions -> fail (b). Neither
#    file pins both packages, so the within-file (a) check can't see it, and the
#    separate `pip install -r` runs don't hard-fail either (the later install just
#    conflict-warns and exits 0) — only the cross-file (b) collapse catches it.
d="$ROOT/split-package-disagree"; new_fixture "$d"
write_req "$d" acme-cert requirements-dev.txt "boto3==$A"
write_req "$d" status-page requirements-dev.txt "botocore==$B"
assert_fail "boto3-only + botocore-only at different versions fails" "$d" "not identical across"

# 9. Inline comments and an environment marker on the pin lines are parsed to the
#    bare version and compared -> pass when equal.
d="$ROOT/comment-and-marker"; new_fixture "$d"
write_req "$d" acme-cert requirements-dev.txt "boto3==$A  # AWS SDK, pinned for reproducible installs
botocore==$A ; python_version >= \"3.8\""
write_req "$d" status-page requirements-dev.txt "boto3==$A
botocore==$A"
assert_pass "inline comment + env marker on pin lines are parsed" "$d"

# 10. `boto3-stubs==` / `botocore-stubs==` and a commented-out `# boto3==` are NOT
#     read as the real pins; the file's real matched pins still win -> pass.
d="$ROOT/stubs-and-comments"; new_fixture "$d"
write_req "$d" acme-cert requirements-dev.txt "# boto3==9.9.9  (historical note, not a pin)
boto3-stubs==1.40.0
botocore-stubs==1.40.0
boto3==$A
botocore==$A"
write_req "$d" status-page requirements-dev.txt "boto3==$A
botocore==$A"
assert_pass "stubs packages and commented pins are not mistaken for the real pins" "$d"

# 11. Whitespace around `==` is tolerated (PEP 508 allows it) -> pass when equal.
d="$ROOT/spaced-operator"; new_fixture "$d"
write_req "$d" acme-cert requirements-dev.txt "boto3 == $A
botocore == $A"
assert_pass "spaces around == are tolerated" "$d"

# 12. Two differing boto3 `==` lines in ONE file -> fail (self-contradictory pin).
d="$ROOT/duplicate-boto3"; new_fixture "$d"
write_req "$d" acme-cert requirements-dev.txt "boto3==$A
boto3==$B
botocore==$A"
assert_fail "duplicate conflicting boto3 pins in one file fail" "$d" "multiple differing boto3 pins"

# 13. botocore pinned AHEAD of boto3 in one file (installs fine, but not the
#     matched pair) -> fail (a). The lint enforces strict equality so the next
#     lone-boto3 bump can't silently outrun botocore.
d="$ROOT/botocore-ahead"; new_fixture "$d"
write_req "$d" acme-cert requirements-dev.txt "boto3==$B
botocore==$A"
assert_fail "botocore ahead of boto3 still fails the equality check" "$d" "boto3==$B does not match botocore==$A"

# 14. Degenerate: the ONLY boto content in the whole tree is a self-contradictory
#     pair of boto3 pins (no botocore, no other file). checked stays 0, but the
#     failure must report the specific "multiple differing boto3 pins" error, NOT
#     the generic "no pins found" fail-closed message — i.e. the failures block is
#     evaluated before the checked==0 guard.
d="$ROOT/only-conflicting-dup"; new_fixture "$d"
write_req "$d" acme-cert requirements-dev.txt "boto3==$A
boto3==$B"
assert_fail "a lone conflicting-dup file reports the dup error, not 'no pins found'" "$d" "multiple differing boto3 pins"

# 15. Documented fail-OPEN boundary: an extras-annotated `boto3[crt]==` pin is not
#     parsed (the `[` breaks the name anchor), so even a MISMATCHED extras boto3
#     pin slips through undetected. This locks in that current, intentional
#     behavior (per the script header) — if extras are ever adopted, the regex AND
#     this case must change together. Here boto3[crt]==9.9.9 is invisible, so the
#     only versions the lint sees (botocore==$A here, boto3==botocore==$A in the
#     sibling) agree and it passes despite the stray 9.9.9.
d="$ROOT/extras-fail-open"; new_fixture "$d"
write_req "$d" acme-cert requirements-dev.txt "boto3[crt]==9.9.9
botocore==$A"
write_req "$d" status-page requirements-dev.txt "boto3==$A
botocore==$A"
assert_pass "extras-annotated boto3[crt]== is not parsed (documented fail-open)" "$d"

# 16. CRLF line endings parse identically to LF: a trailing CR is whitespace
#     (POSIX [:space:] includes \r) so the capture excludes it. A CRLF file and an
#     LF file at the same version must NOT report a phantom invisible-CR drift.
#     (write_req emits LF; the CRLF file is written directly with \r\n.)
d="$ROOT/crlf-endings"; new_fixture "$d"
mkdir -p "$d/terraform/modules/acme-cert/lambda"
printf 'boto3==%s\r\nbotocore==%s\r\n' "$A" "$A" \
  > "$d/terraform/modules/acme-cert/lambda/requirements-dev.txt"
write_req "$d" status-page requirements-dev.txt "boto3==$A
botocore==$A"
assert_pass "CRLF file parses identically to LF (no phantom CR drift)" "$d"

# 17. A compound `==X,<Y` specifier is read as its exact pin X — the capture stops
#     at the comma — so `boto3==$A,<2` and a bare `boto3==$A` elsewhere agree and do
#     NOT phantom-drift on the literal `$A,<2`. Real requirements use a bare `==X`;
#     this guards the capture boundary (the fail-CLOSED counterpart to the non-`==`
#     fail-open cases).
d="$ROOT/compound-specifier"; new_fixture "$d"
write_req "$d" acme-cert requirements-dev.txt "boto3==$A,<2
botocore==$A"
write_req "$d" status-page requirements-dev.txt "boto3==$A
botocore==$A"
assert_pass "compound ==X,<Y reads as X (no phantom comma drift)" "$d"

# 18. A LONE pinning file with a within-file split is reported ONLY by the (a)
#     check; the cross-file (b) "not identical across the … files" message is gated
#     on file_count>1 (it reads oddly for a single file), so it must be absent.
d="$ROOT/single-file-split-only-a"; new_fixture "$d"
write_req "$d" acme-cert requirements-dev.txt "boto3==$B
botocore==$A"
assert_fail_lacks "single-file split reports (a) only, not the cross-file (b)" "$d" \
  "boto3==$B does not match botocore==$A" "not identical across"

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
