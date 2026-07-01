#!/usr/bin/env bash
# check-ebpf-load-path-lockstep_test.sh
# ----------------------------------------------------------------------------
# Fixture tests for scripts/check-ebpf-load-path-lockstep.sh.
#
# Copies the real source/probe files into a tempdir that mimics the
# repo layout, points the script at it via $EBPF_LOCKSTEP_ROOT, and asserts:
#   - the unmutated copy passes (exit 0),
#   - each independent single-site mutation (Go xdp name, Go tc name, Go dir,
#     Makefile xdp path, Makefile tc path, prod Dockerfile guard path, local
#     Dockerfile guard path, local Dockerfile WORKDIR, local compose broad-shadow
#     mount, local compose missing config-file bind, local compose writable
#     config-file bind, local Dockerfile start script copy, local compose missing
#     BPF cap, local compose missing seccomp opt, local compose missing memlock,
#     local compose memlock values only present under a sibling ulimit, local
#     start script missing bpffs mount, validate-workflows missing start-ac
#     trigger, future non-toml local config file, smoke xdp path, smoke tc path,
#     AC FilterMode enum value, smoke FilterMode value) is
#     DETECTED (exit non-zero) — this proves the lint is non-vacuous: it
#     actually fails when a site drifts, not just when nothing changed,
#   - an AC FilterMode const block with simple explicit numeric values still
#     passes, so the extractor is not coupled only to implicit iota shape,
#   - shape-breaking edits fail loud rather than silently passing: deleting
#     the Go const (extractor returns empty) and changing the Makefile object
#     layout out from under the ./release/nhp-ac/ capture (path-shape check).
#
# Usage: bash tests/scripts/check-ebpf-load-path-lockstep_test.sh
# ============================================================================

set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$HERE/../.." && pwd)
SCRIPT="$REPO_ROOT/scripts/check-ebpf-load-path-lockstep.sh"

REAL_GO="$REPO_ROOT/endpoints/ac/ebpf/ebpfegine.go"
REAL_AC_CONFIG="$REPO_ROOT/endpoints/ac/config.go"
REAL_MK="$REPO_ROOT/Makefile"
REAL_DK_AWS="$REPO_ROOT/docker/Dockerfile.ac.aws"
REAL_DK_LOCAL="$REPO_ROOT/docker/Dockerfile.ac"
REAL_SMOKE="$REPO_ROOT/tests/smoke/ssm_probe.go"
REAL_COMPOSE="$REPO_ROOT/docker/docker-compose.yaml"
REAL_AC_START="$REPO_ROOT/docker/start-ac.sh"
REAL_VALIDATE_WORKFLOW="$REPO_ROOT/.github/workflows/validate-workflows.yml"

pass=0
fail=0

# Track every tempdir we create and remove them all on EXIT. (A per-function
# RETURN trap leaks into the caller's return under `set -u` and trips on the
# now-out-of-scope $tmp — so we use one EXIT trap instead.)
TMPDIRS=()
cleanup() { local d; for d in "${TMPDIRS[@]:-}"; do [ -n "$d" ] && rm -rf "$d"; done; }
trap cleanup EXIT
_mktemp() { local d; d=$(mktemp -d); TMPDIRS+=("$d"); printf '%s' "$d"; }

report_pass() { pass=$((pass + 1)); printf '  \033[32m✓\033[0m %s\n' "$1"; }
report_fail() { fail=$((fail + 1)); printf '  \033[31m✗\033[0m %s\n      %s\n' "$1" "$2"; }

# Build a fixture repo: copy the real files into the same relative paths under
# a tempdir. The script reads only these files, so nothing else is needed.
_make_fixture() {
  local dir="$1"
  mkdir -p "$dir/.github/workflows" "$dir/endpoints/ac/ebpf" "$dir/docker/nhp-ac/etc" "$dir/tests/smoke"
  cp "$REAL_GO" "$dir/endpoints/ac/ebpf/ebpfegine.go"
  cp "$REAL_AC_CONFIG" "$dir/endpoints/ac/config.go"
  cp "$REAL_MK" "$dir/Makefile"
  cp "$REAL_DK_AWS" "$dir/docker/Dockerfile.ac.aws"
  cp "$REAL_DK_LOCAL" "$dir/docker/Dockerfile.ac"
  cp "$REAL_SMOKE" "$dir/tests/smoke/ssm_probe.go"
  cp "$REAL_COMPOSE" "$dir/docker/docker-compose.yaml"
  cp "$REAL_AC_START" "$dir/docker/start-ac.sh"
  cp "$REAL_VALIDATE_WORKFLOW" "$dir/.github/workflows/validate-workflows.yml"
  cp "$REPO_ROOT"/docker/nhp-ac/etc/*.toml "$dir/docker/nhp-ac/etc/"
}

# Run the script against a fixture root; echo its exit code.
_run() {
  EBPF_LOCKSTEP_ROOT="$1" bash "$SCRIPT" >/dev/null 2>&1
  echo $?
}

# ---- test: in-sync copy passes ---------------------------------------------
test_in_sync() {
  local name="unmutated copy passes (exit 0)"
  local tmp; tmp=$(_mktemp)
  _make_fixture "$tmp"
  local rc; rc=$(_run "$tmp")
  if [ "$rc" = "0" ]; then report_pass "$name"; else report_fail "$name" "expected exit 0, got $rc"; fi
}

# Generic: apply a sed mutation to one fixture file, expect a NON-zero exit.
_expect_drift_detected() {
  local name="$1" file="$2" sed_expr="$3"
  local tmp; tmp=$(_mktemp)
  _make_fixture "$tmp"
  # Snapshot the pristine fixture file so we can detect a no-op sed (a mutation
  # that matched nothing would make the test vacuously "pass").
  cp "$tmp/$file" "$tmp/$file.pristine"
  sed -i.bak -E "$sed_expr" "$tmp/$file" && rm -f "$tmp/$file.bak"
  if diff -q "$tmp/$file" "$tmp/$file.pristine" >/dev/null 2>&1; then
    report_fail "$name" "mutation was a no-op (sed matched nothing) — test would be vacuous"
    return
  fi
  rm -f "$tmp/$file.pristine"
  local rc; rc=$(_run "$tmp")
  if [ "$rc" != "0" ]; then report_pass "$name"; else report_fail "$name" "drift NOT detected (exit 0) — lint is vacuous for this site"; fi
}

# ---- mutation tests: each site, independently ------------------------------
test_go_xdp_rename() {
  _expect_drift_detected "Go xdp object rename is detected" \
    "endpoints/ac/ebpf/ebpfegine.go" \
    's/ebpfenginename string = "nhp_ebpf_xdp\.o"/ebpfenginename string = "nhp_ebpf_xdp_RENAMED.o"/'
}
test_go_tc_rename() {
  _expect_drift_detected "Go tc object rename is detected" \
    "endpoints/ac/ebpf/ebpfegine.go" \
    's/tcObjName string = "tc_egress\.o"/tcObjName string = "tc_egress_RENAMED.o"/'
}
test_go_dir_rename() {
  _expect_drift_detected "Go bpfDir rename is detected" \
    "endpoints/ac/ebpf/ebpfegine.go" \
    's/bpfDir := "etc"/bpfDir := "bpf"/'
}
test_mk_xdp_drift() {
  _expect_drift_detected "Makefile EBPF_OBJ_XDP drift is detected" \
    "Makefile" \
    's#EBPF_OBJ_XDP = \./release/nhp-ac/etc/nhp_ebpf_xdp\.o#EBPF_OBJ_XDP = ./release/nhp-ac/etc/nhp_ebpf_xdp_DRIFT.o#'
}
test_mk_tc_drift() {
  _expect_drift_detected "Makefile EBPF_OBJ_TC_EGRESS drift is detected" \
    "Makefile" \
    's#EBPF_OBJ_TC_EGRESS = \./release/nhp-ac/etc/tc_egress\.o#EBPF_OBJ_TC_EGRESS = ./release/nhp-ac/etc/tc_egress_DRIFT.o#'
}
test_dk_aws_guard_drift() {
  _expect_drift_detected "Dockerfile.ac.aws guard path drift is detected" \
    "docker/Dockerfile.ac.aws" \
    's#/nhp-ac/etc/nhp_ebpf_xdp\.o#/nhp-ac/etc/nhp_ebpf_xdp_DRIFT.o#g'
}
test_dk_local_guard_drift() {
  _expect_drift_detected "Dockerfile.ac guard path drift is detected" \
    "docker/Dockerfile.ac" \
    's#/nhp-ac/etc/nhp_ebpf_xdp\.o#/nhp-ac/etc/nhp_ebpf_xdp_DRIFT.o#g'
}
test_dk_local_workdir_drift() {
  _expect_drift_detected "Dockerfile.ac missing WORKDIR /nhp-ac is detected" \
    "docker/Dockerfile.ac" \
    's#WORKDIR /nhp-ac#WORKDIR /#'
}
test_compose_broad_mount_drift() {
  _expect_drift_detected "docker-compose AC etc broad mount is detected" \
    "docker/docker-compose.yaml" \
    's#\./nhp-ac/etc/config\.toml:/nhp-ac/etc/config\.toml:ro#./nhp-ac/etc/:/nhp-ac/etc/#'
}
test_compose_missing_config_bind_drift() {
  _expect_drift_detected "docker-compose missing AC config file bind is detected" \
    "docker/docker-compose.yaml" \
    '/resource\.toml:/d'
}
test_compose_writable_config_bind_drift() {
  _expect_drift_detected "docker-compose writable AC config file bind is detected" \
    "docker/docker-compose.yaml" \
    's#\./nhp-ac/etc/config\.toml:/nhp-ac/etc/config\.toml:ro#./nhp-ac/etc/config.toml:/nhp-ac/etc/config.toml:rw#'
}
test_dk_local_start_script_copy_drift() {
  _expect_drift_detected "Dockerfile.ac missing start-ac.sh copy is detected" \
    "docker/Dockerfile.ac" \
    '/start-ac\.sh/d'
}
test_compose_missing_bpf_cap_drift() {
  _expect_drift_detected "docker-compose missing BPF cap is detected" \
    "docker/docker-compose.yaml" \
    '/^[[:space:]]*- BPF$/d'
}
test_compose_missing_seccomp_drift() {
  _expect_drift_detected "docker-compose missing seccomp opt is detected" \
    "docker/docker-compose.yaml" \
    '/seccomp=unconfined/d'
}
test_compose_missing_memlock_drift() {
  _expect_drift_detected "docker-compose missing memlock ulimit is detected" \
    "docker/docker-compose.yaml" \
    '/memlock:/,/hard: -1/d'
}
test_compose_memlock_values_scoped_drift() {
  local name="docker-compose memlock values must be scoped to memlock block"
  local tmp; tmp=$(_mktemp)
  _make_fixture "$tmp"
  local compose="$tmp/docker/docker-compose.yaml"
  awk '
    /^[[:space:]]*ulimits:[[:space:]]*$/ {
      print
      print "      nofile:"
      print "        soft: -1"
      print "        hard: -1"
      next
    }
    /^[[:space:]]*memlock:[[:space:]]*$/ { in_memlock = 1; print; next }
    in_memlock && /^[[:space:]]*soft:[[:space:]]*-1[[:space:]]*$/ { sub(/-1/, "65536") }
    in_memlock && /^[[:space:]]*hard:[[:space:]]*-1[[:space:]]*$/ { sub(/-1/, "65536"); in_memlock = 0 }
    { print }
  ' "$compose" >"$compose.tmp"
  mv "$compose.tmp" "$compose"
  local rc; rc=$(_run "$tmp")
  if [ "$rc" != "0" ]; then report_pass "$name"; else report_fail "$name" "memlock soft/hard drift passed because sibling ulimit values were -1"; fi
}
test_start_ac_bpffs_mount_drift() {
  _expect_drift_detected "start-ac.sh missing bpffs mount is detected" \
    "docker/start-ac.sh" \
    's#mount -t bpf bpf /sys/fs/bpf#echo "skip bpffs mount"#'
}
test_validate_workflows_missing_start_ac_trigger_drift() {
  _expect_drift_detected "validate-workflows missing start-ac trigger is detected" \
    ".github/workflows/validate-workflows.yml" \
    '/docker\/start-ac\.sh/d'
}
test_compose_future_non_toml_config_bind_drift() {
  local name="docker-compose missing future non-toml AC config bind is detected"
  local tmp; tmp=$(_mktemp)
  _make_fixture "$tmp"
  printf '%s\n' '{"example":true}' >"$tmp/docker/nhp-ac/etc/example.json"
  local rc; rc=$(_run "$tmp")
  if [ "$rc" != "0" ]; then report_pass "$name"; else report_fail "$name" "new non-object config file without a per-file bind did not fail the lint (exit 0)"; fi
}
test_smoke_xdp_drift() {
  _expect_drift_detected "smoke xdp object path drift is detected" \
    "tests/smoke/ssm_probe.go" \
    's#/opt/layerv/nhp-ac/etc/nhp_ebpf_xdp\.o#/opt/layerv/nhp-ac/etc/nhp_ebpf_xdp_DRIFT.o#g'
}
test_smoke_tc_drift() {
  _expect_drift_detected "smoke tc object path drift is detected" \
    "tests/smoke/ssm_probe.go" \
    's#/opt/layerv/nhp-ac/etc/tc_egress\.o#/opt/layerv/nhp-ac/etc/tc_egress_DRIFT.o#g'
}
test_ac_filtermode_enum_drift() {
  _expect_drift_detected "AC FilterMode enum insertion is detected" \
    "endpoints/ac/config.go" \
    's/FilterMode_EBPFXDP/FilterMode_NFTABLES\n\tFilterMode_EBPFXDP/'
}
test_smoke_filtermode_drift() {
  _expect_drift_detected "smoke FilterMode value drift is detected" \
    "tests/smoke/ssm_probe.go" \
    's/acFilterModeEBPFXDP  = 1/acFilterModeEBPFXDP  = 2/'
}

test_ac_filtermode_explicit_values_pass() {
  local name="AC FilterMode explicit numeric values pass"
  local tmp; tmp=$(_mktemp)
  _make_fixture "$tmp"
  cp "$tmp/endpoints/ac/config.go" "$tmp/endpoints/ac/config.go.pristine"
  sed -i.bak -E \
    -e 's/FilterMode_IPTABLES = iota/FilterMode_IPTABLES = 0/' \
    -e 's/FilterMode_EBPFXDP[[:space:]]*\/\/ 1/FilterMode_EBPFXDP  = 1 \/\/ 1/' \
    "$tmp/endpoints/ac/config.go" && rm -f "$tmp/endpoints/ac/config.go.bak"
  if diff -q "$tmp/endpoints/ac/config.go" "$tmp/endpoints/ac/config.go.pristine" >/dev/null 2>&1; then
    report_fail "$name" "mutation was a no-op (sed matched nothing) — test would be vacuous"
    return
  fi
  rm -f "$tmp/endpoints/ac/config.go.pristine"
  local rc; rc=$(_run "$tmp")
  if [ "$rc" = "0" ]; then report_pass "$name"; else report_fail "$name" "expected explicit numeric values to pass, got exit $rc"; fi
}

# ---- test: shape-breaking edit fails loud (extractor empty) ----------------
test_shape_break_go_fails_loud() {
  local name="deleting the Go xdp const fails loud (not silent pass)"
  local tmp; tmp=$(_mktemp)
  _make_fixture "$tmp"
  # Remove the ebpfenginename const line entirely -> extractor returns empty.
  sed -i.bak -E '/ebpfenginename string = "[^"]+"/d' "$tmp/endpoints/ac/ebpf/ebpfegine.go" \
    && rm -f "$tmp/endpoints/ac/ebpf/ebpfegine.go.bak"
  local rc; rc=$(_run "$tmp")
  if [ "$rc" != "0" ]; then report_pass "$name"; else report_fail "$name" "missing const did not fail the lint (exit 0)"; fi
}

# A Makefile shape change that defeats the ./release/nhp-ac/ capture must fail
# loud via the path-shape check (not silently extract a garbage value).
test_shape_break_makefile_fails_loud() {
  local name="Makefile EBPF_OBJ_XDP layout change fails loud (path-shape check)"
  local tmp; tmp=$(_mktemp)
  _make_fixture "$tmp"
  # Move the object out of ./release/nhp-ac/ so the sed capture no longer fires;
  # the extracted value then keeps the raw line and must fail the path-shape re.
  sed -i.bak -E 's#EBPF_OBJ_XDP = \./release/nhp-ac/etc/nhp_ebpf_xdp\.o#EBPF_OBJ_XDP = ./some/other/layout/nhp_ebpf_xdp.o#' \
    "$tmp/Makefile" && rm -f "$tmp/Makefile.bak"
  local rc; rc=$(_run "$tmp")
  if [ "$rc" != "0" ]; then report_pass "$name"; else report_fail "$name" "Makefile layout change did not fail the lint (exit 0)"; fi
}

echo "check-ebpf-load-path-lockstep.sh fixture tests"
test_in_sync
test_go_xdp_rename
test_go_tc_rename
test_go_dir_rename
test_mk_xdp_drift
test_mk_tc_drift
test_dk_aws_guard_drift
test_dk_local_guard_drift
test_dk_local_workdir_drift
test_compose_broad_mount_drift
test_compose_missing_config_bind_drift
test_compose_writable_config_bind_drift
test_dk_local_start_script_copy_drift
test_compose_missing_bpf_cap_drift
test_compose_missing_seccomp_drift
test_compose_missing_memlock_drift
test_compose_memlock_values_scoped_drift
test_start_ac_bpffs_mount_drift
test_validate_workflows_missing_start_ac_trigger_drift
test_compose_future_non_toml_config_bind_drift
test_smoke_xdp_drift
test_smoke_tc_drift
test_ac_filtermode_enum_drift
test_smoke_filtermode_drift
test_ac_filtermode_explicit_values_pass
test_shape_break_go_fails_loud
test_shape_break_makefile_fails_loud

echo ""
if [ "$fail" -gt 0 ]; then
  printf '\033[31mFAILED\033[0m: %d passed, %d failed\n' "$pass" "$fail"
  exit 1
fi
printf '\033[32mPASSED\033[0m: %d checks\n' "$pass"
