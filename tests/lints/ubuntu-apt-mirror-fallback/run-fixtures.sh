#!/usr/bin/env bash
# Behavioral fixtures for the mirror selector plus negative contract fixtures
# for all shipped Ubuntu runtime Dockerfiles.

set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
HELPER="$REPO_ROOT/docker/ubuntu-apt-install-with-fallback.sh"
CHECKER="$REPO_ROOT/scripts/check-ubuntu-apt-mirror-fallback.sh"
FIXTURE_ROOT=$(mktemp -d)
trap 'rm -rf "$FIXTURE_ROOT"' EXIT

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

write_official_sources() {
  local path=$1
  mkdir -p "$(dirname "$path")"
  cat >"$path" <<'EOF'
Types: deb
URIs: http://archive.ubuntu.com/ubuntu
Suites: resolute resolute-updates resolute-backports
Components: main universe restricted multiverse

Types: deb
URIs: http://security.ubuntu.com/ubuntu
Suites: resolute-security
Components: main universe restricted multiverse
EOF
}

write_fake_apt_get() {
  local path=$1
  cat >"$path" <<'EOF'
#!/bin/sh
set -eu

count=0
if [ -f "$APT_TEST_COUNTER_FILE" ]; then
  count=$(cat "$APT_TEST_COUNTER_FILE")
fi
count=$((count + 1))
printf '%s' "$count" >"$APT_TEST_COUNTER_FILE"
printf '%s\n' "$*" >>"$APT_TEST_LOG"

args=" $* "
case "$args" in
  *' clean '*) exit 0 ;;
  *' update '*) operation=update ;;
  *' install '*) operation=install ;;
  *) echo "fake apt-get: unexpected operation" >&2; exit 98 ;;
esac

for required in \
  ' -o Acquire::Retries=3 ' \
  ' -o Acquire::http::Timeout=30 ' \
  ' -o Acquire::https::Timeout=30 '
do
  case "$args" in
    *"$required"*) ;;
    *) echo "fake apt-get: network safety options drifted" >&2; exit 97 ;;
  esac
done
if [ "$operation" = update ]; then
  case "$args" in
    *' -o APT::Update::Error-Mode=any '*) ;;
    *) echo "fake apt-get: update Error-Mode drifted" >&2; exit 89 ;;
  esac
else
  for required in ' -y ' ' ca-certificates ' ' curl '; do
    case "$args" in
      *"$required"*) ;;
      *) echo "fake apt-get: requested package set or -y drifted" >&2; exit 88 ;;
    esac
  done
fi

if grep -Fq 'http://ports.ubuntu.com/ubuntu-ports/' "$NHP_UBUNTU_SOURCES_FILE"; then
  source=ports
elif grep -Fq 'azure.archive.ubuntu.com' "$NHP_UBUNTU_SOURCES_FILE"; then
  source=azure
else
  source=official
fi

if [ "$source" = official ]; then
  grep -Fq 'http://archive.ubuntu.com/ubuntu' "$NHP_UBUNTU_SOURCES_FILE" || exit 95
  grep -Fq 'http://security.ubuntu.com/ubuntu' "$NHP_UBUNTU_SOURCES_FILE" || exit 94
  if [ "$operation" = update ]; then
    result=$APT_TEST_OFFICIAL_UPDATE
  else
    result=$APT_TEST_OFFICIAL_INSTALL
  fi
elif [ "$source" = azure ]; then
  grep -Fq 'azure.archive.ubuntu.com' "$NHP_UBUNTU_SOURCES_FILE" || exit 96
  if grep -Eq '//(archive|security)\.ubuntu\.com' "$NHP_UBUNTU_SOURCES_FILE"; then exit 91; fi
  if [ "$operation" = update ] && [ "${APT_TEST_REQUIRE_CLEAN:-0}" = 1 ] &&
     find "$NHP_APT_LISTS_DIR" -mindepth 1 -print -quit | grep -q .; then
    echo "fake apt-get: stale indexes survived fallback" >&2
    exit 92
  fi
  if [ "$operation" = update ]; then
    result=$APT_TEST_AZURE_UPDATE
  else
    result=$APT_TEST_AZURE_INSTALL
  fi
else
  [ "${APT_TEST_PRIMARY_SOURCE:-official}" = ports ] || exit 87
  if [ "$operation" = update ]; then
    result=$APT_TEST_OFFICIAL_UPDATE
  else
    result=$APT_TEST_OFFICIAL_INSTALL
  fi
fi

if [ "$operation" = install ] && [ "$source" = official ] && [ "$result" != success ] &&
   [ "${APT_TEST_SIMULATE_PARTIAL:-0}" = 1 ]; then
  printf '%s\n' 'package curl is unpacked but not configured' >"$APT_TEST_DPKG_AUDIT_FILE"
  printf '%s\n' 'interrupted dpkg journal' >"$APT_TEST_DPKG_JOURNAL_FILE"
fi
if [ "$result" = timeout ]; then
  trap '' TERM
  printf '%s' "$$" >"$APT_TEST_TIMEOUT_APT_FILE"
  sleep 30 &
  child=$!
  printf '%s' "$child" >"$APT_TEST_TIMEOUT_CHILD_FILE"
  wait "$child"
fi
if [ "$operation" = install ] && [ "$source" = azure ] &&
   [ -s "$APT_TEST_DPKG_AUDIT_FILE" ]; then
  [ ! -e "$APT_TEST_DPKG_JOURNAL_FILE" ] || {
    echo "fake apt-get: interrupted dpkg journal was not recovered" >&2
    exit 85
  }
  case "$args" in
    *' --fix-broken '*) ;;
    *) echo "fake apt-get: partial dpkg recovery omitted --fix-broken" >&2; exit 90 ;;
  esac
  [ "$result" = success ] && rm -f "$APT_TEST_DPKG_AUDIT_FILE"
fi

[ "$result" = success ] && exit 0
exit 42
EOF
  chmod 0755 "$path"
}

write_fake_setsid() {
  local path=$1
  cat >"$path" <<'EOF'
#!/usr/bin/env perl
use strict;
use warnings;
use POSIX qw(setsid);
setsid() >= 0 or die "setsid failed: $!";
exec @ARGV or die "exec failed: $!";
EOF
  chmod 0755 "$path"
}

write_fake_dpkg() {
  local path=$1
  cat >"$path" <<'EOF'
#!/bin/sh
set -eu
if [ "$#" -eq 1 ] && [ "$1" = --audit ]; then
  [ ! -f "$APT_TEST_DPKG_AUDIT_FILE" ] || cat "$APT_TEST_DPKG_AUDIT_FILE"
  exit 0
fi
if [ "$#" -eq 2 ] && [ "$1" = --configure ] && [ "$2" = -a ]; then
  printf '%s\n' 'dpkg --configure -a' >>"$APT_TEST_DPKG_LOG"
  rm -f "$APT_TEST_DPKG_JOURNAL_FILE"
  # Simulate a dependency that the subsequent apt --fix-broken pass must
  # resolve. The helper intentionally proceeds, then enforces a clean audit.
  [ ! -s "$APT_TEST_DPKG_AUDIT_FILE" ] && exit 0
  exit 42
fi
exit 86
EOF
  chmod 0755 "$path"
}

new_behavior_case() {
  local name=$1
  CASE_DIR="$FIXTURE_ROOT/behavior-$name"
  mkdir -p "$CASE_DIR/bin" "$CASE_DIR/lists" "$CASE_DIR/tmp"
  SOURCES="$CASE_DIR/ubuntu.sources"
  COUNTER="$CASE_DIR/counter"
  LOG="$CASE_DIR/apt.log"
  DPKG_AUDIT="$CASE_DIR/dpkg-audit"
  DPKG_JOURNAL="$CASE_DIR/dpkg-journal"
  DPKG_LOG="$CASE_DIR/dpkg.log"
  TIMEOUT_CHILD="$CASE_DIR/timeout-child"
  TIMEOUT_APT="$CASE_DIR/timeout-apt"
  write_official_sources "$SOURCES"
  write_fake_apt_get "$CASE_DIR/bin/apt-get"
  write_fake_dpkg "$CASE_DIR/bin/dpkg"
  write_fake_setsid "$CASE_DIR/bin/setsid"
}

run_helper() {
  local official_update=${1:-success}
  local official_install=${2:-success}
  local azure_update=${3:-success}
  local azure_install=${4:-success}
  local simulate_partial=${5:-0}
  local require_clean=${6:-0}
  local primary_source=${7:-official}
  set +e
  OUTPUT=$(
    PATH="$CASE_DIR/bin:$PATH" \
    TMPDIR="$CASE_DIR/tmp" \
    NHP_UBUNTU_SOURCES_FILE="$SOURCES" \
    NHP_APT_LISTS_DIR="$CASE_DIR/lists" \
    APT_TEST_COUNTER_FILE="$COUNTER" \
    APT_TEST_LOG="$LOG" \
    APT_TEST_OFFICIAL_UPDATE="$official_update" \
    APT_TEST_OFFICIAL_INSTALL="$official_install" \
    APT_TEST_AZURE_UPDATE="$azure_update" \
    APT_TEST_AZURE_INSTALL="$azure_install" \
    APT_TEST_SIMULATE_PARTIAL="$simulate_partial" \
    APT_TEST_DPKG_AUDIT_FILE="$DPKG_AUDIT" \
    APT_TEST_DPKG_JOURNAL_FILE="$DPKG_JOURNAL" \
    APT_TEST_DPKG_LOG="$DPKG_LOG" \
    APT_TEST_TIMEOUT_CHILD_FILE="$TIMEOUT_CHILD" \
    APT_TEST_TIMEOUT_APT_FILE="$TIMEOUT_APT" \
    APT_TEST_REQUIRE_CLEAN="$require_clean" \
    APT_TEST_PRIMARY_SOURCE="$primary_source" \
    NHP_APT_ATTEMPT_TIMEOUT_SECONDS="${APT_TEST_ATTEMPT_TIMEOUT_SECONDS:-180}" \
    NHP_APT_KILL_AFTER_SECONDS="${APT_TEST_KILL_AFTER_SECONDS:-5}" \
      "$HELPER" ca-certificates curl 2>&1
  )
  STATUS=$?
  set -e
}

new_behavior_case primary-success
ORIGINAL=$(cat "$SOURCES")
run_helper success success fail fail
[[ "$STATUS" == 0 ]] || fail "primary success returned $STATUS: $OUTPUT"
[[ $(cat "$COUNTER") == 2 ]] || fail "primary success did not stop after update + install"
[[ $(cat "$SOURCES") == "$ORIGINAL" ]] || fail "primary success changed the pinned official sources"
grep -Fq 'APT::Update::Error-Mode=any' "$LOG" || fail "primary update omitted Error-Mode=any"
echo "PASS: pinned official-source primary success"

new_behavior_case azure-fallback
touch "$CASE_DIR/lists/stale-primary-index"
run_helper fail fail success success 0 1
[[ "$STATUS" == 0 ]] || fail "Azure fallback returned $STATUS: $OUTPUT"
[[ $(cat "$COUNTER") == 4 ]] || fail "update-failure fallback did not make the expected bounded calls"
grep -Fq 'azure.archive.ubuntu.com' "$SOURCES" || fail "Azure fallback did not select the Azure-local source"
if grep -Eq '//(archive|security)\.ubuntu\.com' "$SOURCES"; then
  fail "Azure fallback left an official-source entry behind"
fi
grep -Fq 'retrying once' <<<"$OUTPUT" || fail "fallback diagnostic omitted the bounded retry"
echo "PASS: failed official update clears indexes and completes on Azure"

new_behavior_case install-fetch-fallback
touch "$CASE_DIR/lists/stale-primary-index"
run_helper success fail success success 1 1
[[ "$STATUS" == 0 ]] || fail "install-fetch fallback returned $STATUS: $OUTPUT"
[[ $(cat "$COUNTER") == 5 ]] || fail "install-fetch fallback did not make the expected bounded calls"
[[ ! -e "$DPKG_AUDIT" ]] || fail "fallback left simulated partial dpkg state behind"
[[ ! -e "$DPKG_JOURNAL" ]] || fail "fallback left the interrupted dpkg journal behind"
grep -Fqx 'dpkg --configure -a' "$DPKG_LOG" ||
  fail "fallback did not attempt dpkg journal recovery"
grep -Fq -- '--fix-broken install -y ca-certificates curl' "$LOG" ||
  fail "fallback install did not use fix-broken with the complete package set"
echo "PASS: primary update success + install failure recovers package set and partial dpkg state"

new_behavior_case whole-attempt-timeout
touch "$CASE_DIR/lists/stale-primary-index"
APT_TEST_ATTEMPT_TIMEOUT_SECONDS=1 APT_TEST_KILL_AFTER_SECONDS=1 \
  run_helper success timeout success success 1 1
[[ "$STATUS" == 0 ]] || fail "whole-attempt timeout fallback returned $STATUS: $OUTPUT"
grep -Fq 'timed out after 1s' <<<"$OUTPUT" || fail "whole-attempt timeout omitted its diagnostic"
[[ -s "$TIMEOUT_CHILD" ]] || fail "timeout fixture did not record its slow child"
[[ -s "$TIMEOUT_APT" ]] || fail "timeout fixture did not record its TERM-ignoring apt process"
if kill -0 "$(cat "$TIMEOUT_APT")" 2>/dev/null; then
  fail "whole-attempt timeout left its TERM-ignoring apt process running"
fi
if kill -0 "$(cat "$TIMEOUT_CHILD")" 2>/dev/null; then
  fail "whole-attempt timeout left apt's TERM-ignoring child running"
fi
[[ ! -e "$DPKG_AUDIT" ]] || fail "timeout fallback left simulated partial dpkg state behind"
[[ ! -e "$DPKG_JOURNAL" ]] || fail "timeout fallback left the interrupted dpkg journal behind"
grep -Fqx 'dpkg --configure -a' "$DPKG_LOG" ||
  fail "timeout fallback did not attempt dpkg journal recovery"
echo "PASS: whole-attempt timeout terminates the slow attempt and repairs through fallback"

new_behavior_case outer-cancel-cleanup
ORIGINAL=$(cat "$SOURCES")
PATH="$CASE_DIR/bin:$PATH" \
TMPDIR="$CASE_DIR/tmp" \
NHP_UBUNTU_SOURCES_FILE="$SOURCES" \
NHP_APT_LISTS_DIR="$CASE_DIR/lists" \
APT_TEST_COUNTER_FILE="$COUNTER" \
APT_TEST_LOG="$LOG" \
APT_TEST_OFFICIAL_UPDATE=success \
APT_TEST_OFFICIAL_INSTALL=timeout \
APT_TEST_AZURE_UPDATE=success \
APT_TEST_AZURE_INSTALL=success \
APT_TEST_SIMULATE_PARTIAL=1 \
APT_TEST_DPKG_AUDIT_FILE="$DPKG_AUDIT" \
APT_TEST_DPKG_JOURNAL_FILE="$DPKG_JOURNAL" \
APT_TEST_DPKG_LOG="$DPKG_LOG" \
APT_TEST_TIMEOUT_CHILD_FILE="$TIMEOUT_CHILD" \
APT_TEST_TIMEOUT_APT_FILE="$TIMEOUT_APT" \
APT_TEST_REQUIRE_CLEAN=1 \
APT_TEST_PRIMARY_SOURCE=official \
NHP_APT_ATTEMPT_TIMEOUT_SECONDS=180 \
NHP_APT_KILL_AFTER_SECONDS=1 \
  "$HELPER" ca-certificates curl >"$CASE_DIR/output" 2>&1 &
HELPER_PID=$!
for _ in {1..200}; do
  [[ -s "$TIMEOUT_APT" && -s "$TIMEOUT_CHILD" ]] && break
  sleep 0.01
done
[[ -s "$TIMEOUT_APT" && -s "$TIMEOUT_CHILD" ]] ||
  fail "outer-cancel fixture did not reach the TERM-ignoring apt attempt"
kill -TERM "$HELPER_PID"
set +e
wait "$HELPER_PID"
STATUS=$?
set -e
[[ "$STATUS" == 143 ]] || fail "outer cancellation returned $STATUS instead of 143"
if kill -0 "$(cat "$TIMEOUT_APT")" 2>/dev/null; then
  fail "outer cancellation left its TERM-ignoring apt process running"
fi
if kill -0 "$(cat "$TIMEOUT_CHILD")" 2>/dev/null; then
  fail "outer cancellation left apt's TERM-ignoring child running"
fi
[[ $(cat "$SOURCES") == "$ORIGINAL" ]] || fail "outer cancellation incorrectly entered fallback"
echo "PASS: outer TERM cleanup kills the active apt process group without entering fallback"

new_behavior_case both-fail
run_helper fail fail fail fail 0 1
[[ "$STATUS" != 0 ]] || fail "two failed mirrors returned success"
[[ $(cat "$COUNTER") == 3 ]] || fail "dual update failure did not stop at the bounded fallback update"
grep -Fq 'both official and Azure Ubuntu package attempts failed' <<<"$OUTPUT" ||
  fail "dual failure omitted the fail-closed diagnostic"
echo "PASS: dual mirror failure is bounded and fail-closed"

new_behavior_case fallback-install-fail
run_helper success fail success fail 1 1
[[ "$STATUS" != 0 ]] || fail "failed fallback install returned success"
[[ -s "$DPKG_AUDIT" ]] || fail "failed fallback unexpectedly hid the partial dpkg state"
grep -Fq 'both official and Azure Ubuntu package attempts failed' <<<"$OUTPUT" ||
  fail "fallback install failure omitted its fail-closed diagnostic"
echo "PASS: failed fallback install leaves the image build red with partial state visible"

new_behavior_case malformed-sources
sed -i.bak '/security\.ubuntu\.com/d' "$SOURCES"
run_helper success success
[[ "$STATUS" != 0 ]] || fail "malformed official source set was accepted"
[[ ! -e "$COUNTER" ]] || fail "malformed source set reached apt-get"
echo "PASS: unfamiliar official source shape fails before network access"

new_behavior_case third-party-source
printf '\nTypes: deb\nURIs: https://packages.example.invalid/ubuntu\nSuites: resolute\nComponents: main\n' >>"$SOURCES"
run_helper success success
[[ "$STATUS" != 0 ]] || fail "third-party source mixed with official sources was accepted"
[[ ! -e "$COUNTER" ]] || fail "third-party source set reached apt-get"
grep -Fq 'non-official or unfamiliar Ubuntu URI' <<<"$OUTPUT" ||
  fail "third-party source rejection omitted its diagnostic"
echo "PASS: third-party source fails before network access"

new_behavior_case duplicate-official-source
printf '\nTypes: deb\nURIs: http://archive.ubuntu.com/ubuntu/\nSuites: resolute\nComponents: main\n' >>"$SOURCES"
run_helper success success
[[ "$STATUS" != 0 ]] || fail "duplicate official archive source was accepted"
[[ ! -e "$COUNTER" ]] || fail "duplicate official source set reached apt-get"
echo "PASS: duplicate official source fails before network access"

new_behavior_case symlink-sources
mv "$SOURCES" "$SOURCES.real"
ln -s "$SOURCES.real" "$SOURCES"
run_helper success success
[[ "$STATUS" != 0 ]] || fail "symlink sources file was accepted"
[[ ! -e "$COUNTER" ]] || fail "symlink sources file reached apt-get"
echo "PASS: symlink sources file is rejected"

new_behavior_case symlink-lists
mv "$CASE_DIR/lists" "$CASE_DIR/lists.real"
ln -s "$CASE_DIR/lists.real" "$CASE_DIR/lists"
run_helper fail success
[[ "$STATUS" != 0 ]] || fail "symlink apt lists directory was accepted"
[[ ! -e "$COUNTER" ]] || fail "symlink apt lists directory reached apt-get"
echo "PASS: symlink apt lists directory is rejected before cleanup"

new_behavior_case official-ports
cat >"$SOURCES" <<'EOF'
Types: deb
URIs: http://ports.ubuntu.com/ubuntu-ports/
Suites: resolute resolute-updates resolute-backports
Components: main universe restricted multiverse

Types: deb
URIs: http://ports.ubuntu.com/ubuntu-ports/
Suites: resolute-security
Components: main universe restricted multiverse
EOF
run_helper success success fail fail 0 0 ports
[[ "$STATUS" == 0 ]] || fail "official ports source returned $STATUS: $OUTPUT"
[[ $(cat "$COUNTER") == 2 ]] || fail "official ports source did not make one update + install attempt"
grep -Fq 'ports.ubuntu.com' <<<"$OUTPUT" || fail "official ports diagnostic is missing"
echo "PASS: non-amd64 pinned base uses one bounded official ports source"

new_contract_root() {
  local name=$1
  CONTRACT_ROOT="$FIXTURE_ROOT/contract-$name"
  mkdir -p "$CONTRACT_ROOT/docker"
  mkdir -p "$CONTRACT_ROOT/.github/workflows"
  cp "$HELPER" "$CONTRACT_ROOT/docker/ubuntu-apt-install-with-fallback.sh"
  chmod 0755 "$CONTRACT_ROOT/docker/ubuntu-apt-install-with-fallback.sh"
  cp "$REPO_ROOT/docker/Dockerfile.server" "$CONTRACT_ROOT/docker/"
  cp "$REPO_ROOT/docker/Dockerfile.ac.aws" "$CONTRACT_ROOT/docker/"
  cp "$REPO_ROOT/docker/Dockerfile.hub" "$CONTRACT_ROOT/docker/"
  cp "$REPO_ROOT/docker/Dockerfile.relay" "$CONTRACT_ROOT/docker/"
  cp "$REPO_ROOT/.github/workflows/build-and-push.yml" "$CONTRACT_ROOT/.github/workflows/"
}

expect_contract_failure() {
  local name=$1
  if "$CHECKER" "$CONTRACT_ROOT" >"$CONTRACT_ROOT/output" 2>&1; then
    fail "$name: checker accepted invalid contract"
  fi
  echo "PASS: $name"
}

"$CHECKER" "$REPO_ROOT" >/dev/null
echo "PASS: live Dockerfiles satisfy the shared-helper contract"

new_contract_root missing-helper-use
sed -i.bak '/ubuntu-apt-install-with-fallback \\/d' "$CONTRACT_ROOT/docker/Dockerfile.server"
expect_contract_failure "missing helper invocation is rejected"

new_contract_root direct-runtime-update
printf '\nRUN apt-get update\n' >>"$CONTRACT_ROOT/docker/Dockerfile.relay"
expect_contract_failure "direct runtime apt update bypass is rejected"

new_contract_root direct-runtime-install
printf '\nRUN apt-get install -y jq\n' >>"$CONTRACT_ROOT/docker/Dockerfile.server"
expect_contract_failure "direct runtime apt install bypass is rejected"

new_contract_root env-prefixed-runtime-install
printf '\nRUN env DEBIAN_FRONTEND=noninteractive apt-get install -y jq\n' >>"$CONTRACT_ROOT/docker/Dockerfile.server"
expect_contract_failure "environment-prefixed runtime apt bypass is rejected"

new_contract_root path-qualified-runtime-update
printf '\nRUN /usr/bin/apt-get update\n' >>"$CONTRACT_ROOT/docker/Dockerfile.ac.aws"
expect_contract_failure "path-qualified runtime apt bypass is rejected"

new_contract_root shell-wrapped-runtime-update
printf '\nRUN sh -c "apt-get update"\n' >>"$CONTRACT_ROOT/docker/Dockerfile.hub"
expect_contract_failure "shell-wrapped runtime apt bypass is rejected"

new_contract_root copied-helper
printf '\nCOPY docker/ubuntu-apt-install-with-fallback.sh /tmp/\n' >>"$CONTRACT_ROOT/docker/Dockerfile.hub"
expect_contract_failure "shipping the build-only helper is rejected"

new_contract_root non-executable-helper
chmod 0644 "$CONTRACT_ROOT/docker/ubuntu-apt-install-with-fallback.sh"
expect_contract_failure "non-executable helper is rejected"

new_contract_root matrix-drift
sed -i.bak 's|dockerfile: docker/Dockerfile.relay|dockerfile: docker/Dockerfile.unfenced|' \
  "$CONTRACT_ROOT/.github/workflows/build-and-push.yml"
expect_contract_failure "application-image matrix drift is rejected"

echo "All Ubuntu apt mirror fallback fixtures passed."
