#!/usr/bin/env bash
# Fixture tests for scripts/check-go-version-drift.sh.

set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$HERE/../.." && pwd)
SCRIPT="$REPO_ROOT/scripts/check-go-version-drift.sh"
GO_LINUX_AMD64_SHA256=708effb774be8237570d0add163225abbdfaf4fca28b2611df167beba4feef89
GO_LINUX_ARM64_SHA256=d0507e9e9d7fe012aae570108cbd76c15de879e17130ab8cb90d4d7445cb1f2e
GO_LINUX_ARMV6L_SHA256=e1379a2fe77bd30fa29833074388247e7c65416e09279f746f20de2d5cf4dfea

pass=0
fail=0
failures=""

report_pass() {
  pass=$((pass + 1))
  printf '  [PASS] %s\n' "$1"
}

report_fail() {
  fail=$((fail + 1))
  failures+="  [FAIL] $1: $2\n"
  printf '  [FAIL] %s\n      %s\n' "$1" "$2"
}

write_good_fixture() {
  local dir="$1"
  local version=1.26.6
  mkdir -p \
    "$dir/scripts" \
    "$dir/.github/workflows" \
    "$dir/docker" \
    "$dir/nhp" \
    "$dir/internalauth" \
    "$dir/endpoints" \
    "$dir/examples/server_plugin" \
    "$dir/tests/e2e" \
    "$dir/tests/local" \
    "$dir/tests/smoke" \
    "$dir/tests/smoke/local-stack"
  ln -sf "$SCRIPT" "$dir/scripts/check-go-version-drift.sh"

  for mod in nhp internalauth endpoints examples/server_plugin tests/e2e tests/local tests/smoke; do
    cat > "$dir/$mod/go.mod" <<EOF
module example.com/$mod

go $version
EOF
  done

  for wf in build-and-push ubuntu-build codeql build-binaries; do
    cat > "$dir/.github/workflows/$wf.yml" <<EOF
name: $wf
env:
  GO_VERSION: '$version'
EOF
  done

  cat >> "$dir/.github/workflows/build-and-push.yml" <<EOF
  GO_TEST_IMAGE: 'golang:${version}-bookworm@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
EOF

  for dockerfile in Dockerfile.server Dockerfile.ac Dockerfile.ac.aws Dockerfile.relay Dockerfile.hub; do
    cat > "$dir/docker/$dockerfile" <<EOF
FROM golang:${version}-bookworm@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa AS builder
EOF
  done

  # The smoke local-stack builder is the one golang FROM outside docker/ that
  # check-go-version-drift.sh fences (added to golang_from_files + the widened
  # discovery root). Keep it in the in-sync fixture so that fence stays tested.
  cat > "$dir/tests/smoke/local-stack/Dockerfile" <<EOF
FROM golang:${version}-bookworm@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa AS builder
EOF

  for dockerfile in Dockerfile.app Dockerfile.base; do
    cat > "$dir/docker/$dockerfile" <<EOF
FROM ubuntu:26.04@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc AS builder
ARG GO_VERSION=$version
ARG GO_LINUX_AMD64_SHA256=$GO_LINUX_AMD64_SHA256
ARG GO_LINUX_ARM64_SHA256=$GO_LINUX_ARM64_SHA256
ARG GO_LINUX_ARMV6L_SHA256=$GO_LINUX_ARMV6L_SHA256
EOF
  done
}

run_check() {
  local dir="$1" out_var="$2" rc_var="$3"
  local run_out run_rc=0
  run_out=$(cd "$dir" && bash scripts/check-go-version-drift.sh 2>&1) || run_rc=$?
  printf -v "$out_var" '%s' "$run_out"
  printf -v "$rc_var" '%s' "$run_rc"
}

assert_failure() {
  local name="$1" tmp="$2" expected="$3" unexpected="${4:-}"
  local out rc
  run_check "$tmp" out rc
  if [ "$rc" -eq 0 ]; then
    report_fail "$name" "expected non-zero exit. Output: $out"
    return
  fi
  if ! grep -Fq "$expected" <<<"$out"; then
    report_fail "$name" "expected '$expected' in output, got: $out"
    return
  fi
  if [ -n "$unexpected" ] && grep -Fq "$unexpected" <<<"$out"; then
    report_fail "$name" "did not expect '$unexpected' in output, got: $out"
    return
  fi
  report_pass "$name"
}

assert_success() {
  local name="$1" tmp="$2"
  local out rc
  run_check "$tmp" out rc
  if [ "$rc" -ne 0 ]; then
    report_fail "$name" "expected exit 0, got $rc. Output: $out"
    return
  fi
  if ! grep -Fq "OK: Go toolchain lockstep clean" <<<"$out"; then
    report_fail "$name" "expected OK marker in output, got: $out"
    return
  fi
  report_pass "$name"
}

test_in_sync() {
  local name="in-sync surfaces pass"
  local tmp
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' RETURN
  write_good_fixture "$tmp"
  assert_success "$name" "$tmp"
}

test_workflow_drift_fails() {
  local name="workflow GO_VERSION drift fails"
  local tmp
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' RETURN
  write_good_fixture "$tmp"
  sed -i.bak "s/GO_VERSION: '1.26.6'/GO_VERSION: '1.26.7'/" "$tmp/.github/workflows/codeql.yml"
  assert_failure "$name" "$tmp" ".github/workflows/codeql.yml env.GO_VERSION"
}

test_unlisted_workflow_go_version_fails() {
  local name="unlisted workflow GO_VERSION fails"
  local tmp
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' RETURN
  write_good_fixture "$tmp"
  cat > "$tmp/.github/workflows/new-go-workflow.yml" <<EOF
name: new-go-workflow
env:
  GO_VERSION: '1.26.6'
EOF
  assert_failure "$name" "$tmp" ".github/workflows/new-go-workflow.yml: contains GO_VERSION but is not listed in workflow_files"
}

test_literal_setup_go_version_fails() {
  local name="literal setup-go version fails"
  local tmp
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' RETURN
  write_good_fixture "$tmp"
  cat >> "$tmp/.github/workflows/codeql.yml" <<EOF
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-go@v6
        with:
          go-version: '1.26.6'
EOF
  assert_failure "$name" "$tmp" ".github/workflows/codeql.yml: setup-go go-version must reference env.GO_VERSION or go-version-file, not a numeric literal"
}

test_unlisted_setup_go_version_file_fails() {
  local name="unlisted setup-go go-version-file fails"
  local tmp
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' RETURN
  write_good_fixture "$tmp"
  cat >> "$tmp/.github/workflows/codeql.yml" <<EOF
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-go@v6
        with:
          go-version-file: examples/random/go.mod
EOF
  assert_failure "$name" "$tmp" ".github/workflows/codeql.yml go-version-file: examples/random/go.mod is not listed in go_mod_files"
}

test_dot_slash_setup_go_version_file_passes() {
  local name="dot-slash setup-go go-version-file passes"
  local tmp
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' RETURN
  write_good_fixture "$tmp"
  cat >> "$tmp/.github/workflows/codeql.yml" <<EOF
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-go@v6
        with:
          go-version-file: ./nhp/go.mod
EOF
  assert_success "$name" "$tmp"
}

test_composite_action_literal_setup_go_version_fails() {
  local name="composite action literal setup-go version fails"
  local tmp
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' RETURN
  write_good_fixture "$tmp"
  mkdir -p "$tmp/.github/actions/go-action"
  cat > "$tmp/.github/actions/go-action/action.yml" <<EOF
name: go-action
runs:
  using: composite
  steps:
    - uses: actions/setup-go@v6
      with:
        go-version: '1.26.6'
EOF
  assert_failure "$name" "$tmp" ".github/actions/go-action/action.yml: setup-go go-version must reference env.GO_VERSION or go-version-file, not a numeric literal"
}

test_step_scoped_go_version_is_ignored() {
  local name="step-scoped GO_VERSION is ignored"
  local tmp
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' RETURN
  write_good_fixture "$tmp"
  cat > "$tmp/.github/workflows/step-env-only.yml" <<EOF
name: step-env-only
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: local env
        env:
          GO_VERSION: '1.26.6'
        run: go version
EOF
  assert_success "$name" "$tmp"
}

test_job_scoped_go_version_fails() {
  local name="job-scoped GO_VERSION fails"
  local tmp
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' RETURN
  write_good_fixture "$tmp"
  cat > "$tmp/.github/workflows/job-env.yml" <<EOF
name: job-env
jobs:
  test:
    runs-on: ubuntu-latest
    env:
      GO_VERSION: '1.26.6'
    steps:
      - run: go version
EOF
  assert_failure "$name" "$tmp" ".github/workflows/job-env.yml: job-level GO_VERSION must move to top-level env.GO_VERSION or use setup-go go-version-file"
}

test_missing_go_directive_fails() {
  local name="missing go directive fails"
  local tmp
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' RETURN
  write_good_fixture "$tmp"
  sed -i.bak '/^go /d' "$tmp/internalauth/go.mod"
  assert_failure "$name" "$tmp" "internalauth/go.mod: expected exactly one go directive, found 0"
}

test_duplicate_go_directive_fails() {
  local name="duplicate go directive fails"
  local tmp
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' RETURN
  write_good_fixture "$tmp"
  printf '\ngo 1.26.6\n' >> "$tmp/tests/local/go.mod"
  assert_failure "$name" "$tmp" "tests/local/go.mod: expected exactly one go directive, found 2"
}

test_two_part_go_directive_drift_fails() {
  local name="two-part go directive drift fails"
  local tmp
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' RETURN
  write_good_fixture "$tmp"
  sed -i.bak 's/go 1.26.6/go 1.27/' "$tmp/endpoints/go.mod"
  assert_failure "$name" "$tmp" "endpoints/go.mod: expected Go 1.26.6, got 1.27"
}

test_source_go_directive_requires_patch() {
  local name="source go directive requires patch"
  local tmp
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' RETURN
  write_good_fixture "$tmp"
  sed -i.bak 's/go 1.26.6/go 1.26/' "$tmp/nhp/go.mod"
  assert_failure "$name" "$tmp" "source Go version must include a patch release"
}

test_go_directive_comments_and_whitespace_pass() {
  local name="go directive comments and whitespace pass"
  local tmp
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' RETURN
  write_good_fixture "$tmp"
  sed -i.bak 's/go 1.26.6/go 1.26.6   \/\/ CI lockstep/' "$tmp/endpoints/go.mod"
  printf '\ntoolchain go1.26.6   // CI lockstep\n' >> "$tmp/tests/local/go.mod"
  assert_success "$name" "$tmp"
}

test_toolchain_directive_drift_fails() {
  local name="toolchain directive drift fails"
  local tmp
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' RETURN
  write_good_fixture "$tmp"
  printf '\ntoolchain go1.26.7\n' >> "$tmp/nhp/go.mod"
  assert_failure "$name" "$tmp" "nhp/go.mod toolchain directive: expected Go 1.26.6, got 1.26.7"
}

test_unpinned_test_image_fails() {
  local name="tag-only GO_TEST_IMAGE fails"
  local tmp
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' RETURN
  write_good_fixture "$tmp"
  sed -i.bak "s|GO_TEST_IMAGE: 'golang:1.26.6-bookworm@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'|GO_TEST_IMAGE: 'golang:1.26.6-bookworm'|" "$tmp/.github/workflows/build-and-push.yml"
  assert_failure "$name" "$tmp" "GO_TEST_IMAGE: must be tag+digest pinned" "expected exactly one digest-pinned GO_TEST_IMAGE"
}

test_docker_from_drift_fails() {
  local name="Dockerfile golang FROM drift fails"
  local tmp
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' RETURN
  write_good_fixture "$tmp"
  sed -i.bak "s/golang:1.26.6-bookworm/golang:1.26.7-bookworm/" "$tmp/docker/Dockerfile.server"
  assert_failure "$name" "$tmp" "docker/Dockerfile.server golang FROM"
}

test_docker_digest_drift_fails() {
  local name="Dockerfile golang digest drift fails"
  local tmp
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' RETURN
  write_good_fixture "$tmp"
  sed -i.bak "s/sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/sha256:9999999999999999999999999999999999999999999999999999999999999999/" "$tmp/docker/Dockerfile.ac"
  assert_failure "$name" "$tmp" "docker/Dockerfile.ac golang FROM: expected Go image"
}

test_hub_docker_digest_drift_fails() {
  local name="Hub Dockerfile golang digest drift fails"
  local tmp
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' RETURN
  write_good_fixture "$tmp"
  sed -i.bak 's/sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/sha256:9999999999999999999999999999999999999999999999999999999999999999/' "$tmp/docker/Dockerfile.hub"
  assert_failure "$name" "$tmp" "docker/Dockerfile.hub golang FROM: expected Go image"
}

test_docker_from_variant_fails_with_variant_error() {
  local name="Dockerfile golang variant fails with variant error"
  local tmp
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' RETURN
  write_good_fixture "$tmp"
  sed -i.bak "s/golang:1.26.6-bookworm/golang:1.26.6-alpine/" "$tmp/docker/Dockerfile.ac"
  assert_failure "$name" "$tmp" "docker/Dockerfile.ac golang FROM: must use repo-standard golang:<version>-bookworm@sha256:<64-hex>"
}

test_duplicate_dockerfile_golang_from_passes() {
  local name="duplicate Dockerfile golang FROM passes when pinned identically"
  local tmp
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' RETURN
  write_good_fixture "$tmp"
  cat >> "$tmp/docker/Dockerfile.server" <<EOF
FROM golang:1.26.6-bookworm@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa AS second-builder
EOF
  assert_success "$name" "$tmp"
}

test_second_dockerfile_golang_from_digest_drift_fails() {
  local name="second Dockerfile golang FROM digest drift fails"
  local tmp
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' RETURN
  write_good_fixture "$tmp"
  cat >> "$tmp/docker/Dockerfile.server" <<EOF
FROM golang:1.26.6-bookworm@sha256:9999999999999999999999999999999999999999999999999999999999999999 AS second-builder
EOF
  assert_failure "$name" "$tmp" "docker/Dockerfile.server golang FROM stage 2: expected Go image"
}

test_dockerfile_backup_is_ignored() {
  local name="Dockerfile backup is ignored"
  local tmp
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' RETURN
  write_good_fixture "$tmp"
  cat > "$tmp/docker/Dockerfile.server.bak" <<EOF
FROM golang:1.99.0-bookworm@sha256:9999999999999999999999999999999999999999999999999999999999999999 AS backup-builder
EOF
  assert_success "$name" "$tmp"
}

test_nested_dockerfile_golang_from_fails() {
  local name="nested Dockerfile golang FROM fails"
  local tmp
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' RETURN
  write_good_fixture "$tmp"
  mkdir -p "$tmp/docker/nested"
  cat > "$tmp/docker/nested/Dockerfile" <<EOF
FROM golang:1.26.6-bookworm@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa AS builder
EOF
  assert_failure "$name" "$tmp" "docker/nested/Dockerfile: contains a golang FROM but is not listed in golang_from_files"
}

test_unlisted_dockerfile_golang_from_fails() {
  local name="unlisted Dockerfile golang FROM fails"
  local tmp
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' RETURN
  write_good_fixture "$tmp"
  cat > "$tmp/docker/Dockerfile.extra" <<EOF
FROM golang:1.26.6-bookworm@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa AS builder
EOF
  assert_failure "$name" "$tmp" "docker/Dockerfile.extra: contains a golang FROM but is not listed in golang_from_files"
}

# Fences the discovery widening: a golang FROM Dockerfile under
# tests/smoke/local-stack that isn't in golang_from_files must be caught the
# same way as an unlisted docker/ one, so a future local-stack Dockerfile can't
# silently escape the GO_VERSION lockstep.
test_unlisted_smoke_dockerfile_golang_from_fails() {
  local name="unlisted smoke local-stack Dockerfile golang FROM fails"
  local tmp
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' RETURN
  write_good_fixture "$tmp"
  cat > "$tmp/tests/smoke/local-stack/Dockerfile.extra" <<EOF
FROM golang:1.26.6-bookworm@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa AS builder
EOF
  assert_failure "$name" "$tmp" "tests/smoke/local-stack/Dockerfile.extra: contains a golang FROM but is not listed in golang_from_files"
}

test_dev_dockerfile_checksum_fails() {
  local name="dev Dockerfile missing checksum fails"
  local tmp
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' RETURN
  write_good_fixture "$tmp"
  sed -i.bak '/GO_LINUX_ARM64_SHA256/d' "$tmp/docker/Dockerfile.app"
  assert_failure "$name" "$tmp" "docker/Dockerfile.app: expected exactly one 64-hex GO_LINUX_ARM64_SHA256 checksum, found 0"
}

test_dev_dockerfile_quoted_args_pass() {
  local name="dev Dockerfile quoted ARGs pass"
  local tmp
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' RETURN
  write_good_fixture "$tmp"
  sed -i.bak "s/ARG GO_VERSION=1.26.6/ARG GO_VERSION='1.26.6'/" "$tmp/docker/Dockerfile.app"
  sed -i.bak "s/ARG GO_LINUX_ARM64_SHA256=$GO_LINUX_ARM64_SHA256/ARG GO_LINUX_ARM64_SHA256=\"$GO_LINUX_ARM64_SHA256\"/" "$tmp/docker/Dockerfile.app"
  assert_success "$name" "$tmp"
}

test_dev_dockerfile_checksum_drift_fails() {
  local name="dev Dockerfile checksum drift fails"
  local tmp
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' RETURN
  write_good_fixture "$tmp"
  sed -i.bak "s/ARG GO_LINUX_ARM64_SHA256=$GO_LINUX_ARM64_SHA256/ARG GO_LINUX_ARM64_SHA256=9999999999999999999999999999999999999999999999999999999999999999/" "$tmp/docker/Dockerfile.base"
  assert_failure "$name" "$tmp" "docker/Dockerfile.base: expected GO_LINUX_ARM64_SHA256 checksum"
}

test_dev_dockerfile_stale_matching_checksums_fail() {
  local name="dev Dockerfile stale matching checksums fail"
  local tmp
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' RETURN
  write_good_fixture "$tmp"
  for dockerfile in Dockerfile.app Dockerfile.base; do
    sed -i.bak "s/ARG GO_LINUX_ARM64_SHA256=$GO_LINUX_ARM64_SHA256/ARG GO_LINUX_ARM64_SHA256=9999999999999999999999999999999999999999999999999999999999999999/" "$tmp/docker/$dockerfile"
  done
  assert_failure "$name" "$tmp" "expected GO_LINUX_ARM64_SHA256 checksum $GO_LINUX_ARM64_SHA256 for Go 1.26.6"
}

test_checksum_table_version_drift_fails() {
  local name="checksum table version drift fails"
  local tmp
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' RETURN
  write_good_fixture "$tmp"
  sed -i.bak 's/go 1.26.6/go 1.26.7/' "$tmp/nhp/go.mod"
  assert_failure "$name" "$tmp" "Go tarball checksum table: expected checksums for Go 1.26.7, table is for Go 1.26.6"
}

echo "Running check-go-version-drift_test.sh"
test_in_sync
test_workflow_drift_fails
test_unlisted_workflow_go_version_fails
test_literal_setup_go_version_fails
test_unlisted_setup_go_version_file_fails
test_dot_slash_setup_go_version_file_passes
test_composite_action_literal_setup_go_version_fails
test_step_scoped_go_version_is_ignored
test_job_scoped_go_version_fails
test_missing_go_directive_fails
test_duplicate_go_directive_fails
test_two_part_go_directive_drift_fails
test_source_go_directive_requires_patch
test_go_directive_comments_and_whitespace_pass
test_toolchain_directive_drift_fails
test_unpinned_test_image_fails
test_docker_from_drift_fails
test_docker_digest_drift_fails
test_hub_docker_digest_drift_fails
test_docker_from_variant_fails_with_variant_error
test_duplicate_dockerfile_golang_from_passes
test_second_dockerfile_golang_from_digest_drift_fails
test_dockerfile_backup_is_ignored
test_nested_dockerfile_golang_from_fails
test_unlisted_dockerfile_golang_from_fails
test_unlisted_smoke_dockerfile_golang_from_fails
test_dev_dockerfile_checksum_fails
test_dev_dockerfile_quoted_args_pass
test_dev_dockerfile_checksum_drift_fails
test_dev_dockerfile_stale_matching_checksums_fail
test_checksum_table_version_drift_fails

printf '\n[check-go-version-drift_test.sh] %d passed, %d failed\n' "$pass" "$fail"
if [ "$fail" -ne 0 ]; then
  printf '%b' "$failures"
  exit 1
fi
