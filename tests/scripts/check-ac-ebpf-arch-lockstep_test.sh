#!/usr/bin/env bash
# Fixture tests for scripts/check-ac-ebpf-arch-lockstep.sh.
#
# The real lint compares build-and-push.yml's AC image platform with the AC
# launch-template instance families in terraform/modules/ac/main.tf. These
# fixtures keep tiny synthetic copies of those two files and prove that each
# relevant single-site drift fails non-zero instead of passing vacuously.

set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$HERE/../.." && pwd)
SCRIPT="$REPO_ROOT/scripts/check-ac-ebpf-arch-lockstep.sh"

pass=0
fail=0

TMPDIRS=()
cleanup() {
  local d
  for d in "${TMPDIRS[@]:-}"; do
    [ -n "$d" ] && rm -rf "$d"
  done
}
trap cleanup EXIT

_mktemp() {
  local d
  d=$(mktemp -d)
  TMPDIRS+=("$d")
  printf '%s' "$d"
}

report_pass() {
  pass=$((pass + 1))
  printf '  PASS %s\n' "$1"
}

report_fail() {
  fail=$((fail + 1))
  printf '  FAIL %s\n      %s\n' "$1" "$2"
}

_make_fixture() {
  local dir="$1"
  mkdir -p "$dir/.github/workflows" "$dir/terraform/modules/ac"

  cat >"$dir/.github/workflows/build-and-push.yml" <<'YAML'
name: Build and Deploy NHP

jobs:
  build:
    strategy:
      matrix:
        include:
          - image: server
            dockerfile: docker/Dockerfile.server
            repo: layerv/nhp-server
            platform: linux/amd64
          - image: ac
            dockerfile: docker/Dockerfile.ac.aws
            repo: layerv/nhp-ac
            platform: linux/amd64
          - image: relay
            dockerfile: docker/Dockerfile.relay
            repo: layerv/nhp-relay
            platform: linux/amd64
    steps:
      - name: Build image
        uses: docker/build-push-action@f9f3042f7e2789586610d6e8b85c8f03e5195baf
        with:
          context: .
          file: ${{ matrix.dockerfile }}
          platforms: ${{ matrix.platform }}
          push: false
          load: true
YAML

  cat >"$dir/terraform/modules/ac/main.tf" <<'TF'
resource "aws_launch_template" "ac" {
  name_prefix   = "${var.name_prefix}-ac-"
  image_id      = local.ac_ami_id
  instance_type = local.is_prod ? "c6i.xlarge" : "t3.medium"
}

resource "aws_autoscaling_group" "ac" {
  name = "ac"

  launch_template {
    id      = aws_launch_template.ac.id
    version = aws_launch_template.ac.latest_version
  }
}
TF
}

_write_tf_mixed_instances_policy() {
  local dir="$1"
  cat >"$dir/terraform/modules/ac/main.tf" <<'TF'
resource "aws_launch_template" "ac" {
  name_prefix   = "${var.name_prefix}-ac-"
  image_id      = local.ac_ami_id
  instance_type = local.is_prod ? "c6i.xlarge" : "t3.medium"
}

resource "aws_autoscaling_group" "ac" {
  name = "ac"

  mixed_instances_policy {
    launch_template {
      launch_template_specification {
        launch_template_id = aws_launch_template.ac.id
        version            = aws_launch_template.ac.latest_version
      }

      override {
        instance_type = "c7g.xlarge"
      }
    }
  }
}
TF
}

_write_workflow_ac_last() {
  local dir="$1"
  cat >"$dir/.github/workflows/build-and-push.yml" <<'YAML'
name: Build and Deploy NHP

jobs:
  build:
    strategy:
      matrix:
        include:
          - image: server
            dockerfile: docker/Dockerfile.server
            repo: layerv/nhp-server
            platform: linux/amd64
          - image: relay
            dockerfile: docker/Dockerfile.relay
            repo: layerv/nhp-relay
            platform: linux/amd64
          - image: ac
            dockerfile: docker/Dockerfile.ac.aws
            repo: layerv/nhp-ac
            platform: linux/amd64
    steps:
      - name: Build image
        uses: docker/build-push-action@f9f3042f7e2789586610d6e8b85c8f03e5195baf
        with:
          context: .
          file: ${{ matrix.dockerfile }}
          platforms: ${{ matrix.platform }}
          push: false
          load: true
YAML
}

_write_workflow_comment_decoy() {
  local dir="$1"
  cat >"$dir/.github/workflows/build-and-push.yml" <<'YAML'
name: Build and Deploy NHP

jobs:
  build:
    strategy:
      matrix:
        include:
          - image: server
            dockerfile: docker/Dockerfile.server
            repo: layerv/nhp-server
            platform: linux/amd64
          - image: ac
            dockerfile: docker/Dockerfile.ac.aws
            repo: layerv/nhp-ac
            # platform: linux/arm64
            platform: linux/amd64
          - image: relay
            dockerfile: docker/Dockerfile.relay
            repo: layerv/nhp-relay
            platform: linux/amd64
    steps:
      - name: Build image
        uses: docker/build-push-action@f9f3042f7e2789586610d6e8b85c8f03e5195baf
        with:
          context: .
          file: ${{ matrix.dockerfile }}
          platforms: ${{ matrix.platform }}
          push: false
          load: true
YAML
}

_write_workflow_second_build_action() {
  local dir="$1"
  cat >"$dir/.github/workflows/build-and-push.yml" <<'YAML'
name: Build and Deploy NHP

jobs:
  build:
    strategy:
      matrix:
        include:
          - image: server
            dockerfile: docker/Dockerfile.server
            repo: layerv/nhp-server
            platform: linux/amd64
          - image: ac
            dockerfile: docker/Dockerfile.ac.aws
            repo: layerv/nhp-ac
            platform: linux/amd64
          - image: relay
            dockerfile: docker/Dockerfile.relay
            repo: layerv/nhp-relay
            platform: linux/amd64
    steps:
      - name: Build image
        uses: docker/build-push-action@f9f3042f7e2789586610d6e8b85c8f03e5195baf
        with:
          context: .
          file: ${{ matrix.dockerfile }}
          platforms: ${{ matrix.platform }}
          push: false
          load: true
      - name: Build sidecar image
        uses: docker/build-push-action@f9f3042f7e2789586610d6e8b85c8f03e5195baf
        with:
          context: .
          file: docker/Dockerfile.sidecar
          push: false
          load: true
YAML
}

_write_workflow_unrelated_include_before_build() {
  local dir="$1"
  cat >"$dir/.github/workflows/build-and-push.yml" <<'YAML'
name: Build and Deploy NHP

jobs:
  unrelated-scan:
    strategy:
      matrix:
        include:
          - image: scanner
    steps:
      - run: echo scan
  build:
    strategy:
      matrix:
        include:
          - image: server
            dockerfile: docker/Dockerfile.server
            repo: layerv/nhp-server
            platform: linux/amd64
          - image: ac
            dockerfile: docker/Dockerfile.ac.aws
            repo: layerv/nhp-ac
            platform: linux/amd64
          - image: relay
            dockerfile: docker/Dockerfile.relay
            repo: layerv/nhp-relay
            platform: linux/amd64
    steps:
      - name: Build image
        uses: docker/build-push-action@f9f3042f7e2789586610d6e8b85c8f03e5195baf
        with:
          context: .
          file: ${{ matrix.dockerfile }}
          platforms: ${{ matrix.platform }}
          push: false
          load: true
YAML
}

_write_workflow_unrelated_image_matrix() {
  local dir="$1"
  cat >>"$dir/.github/workflows/build-and-push.yml" <<'YAML'
  unrelated-scan:
    strategy:
      matrix:
        include:
          - image: scanner
    steps:
      - run: echo scan
YAML
}

_run() {
  AC_EBPF_ARCH_LOCKSTEP_ROOT="$1" bash "$SCRIPT" >/dev/null 2>&1
  echo $?
}

test_in_sync() {
  local name="unmutated fixture passes"
  local tmp
  tmp=$(_mktemp)
  _make_fixture "$tmp"

  local rc
  rc=$(_run "$tmp")
  if [ "$rc" = "0" ]; then
    report_pass "$name"
  else
    report_fail "$name" "expected exit 0, got $rc"
  fi
}

test_ac_last_matrix_entry_passes() {
  local name="AC as final matrix entry passes"
  local tmp
  tmp=$(_mktemp)
  _make_fixture "$tmp"
  _write_workflow_ac_last "$tmp"

  local rc
  rc=$(_run "$tmp")
  if [ "$rc" = "0" ]; then
    report_pass "$name"
  else
    report_fail "$name" "expected exit 0, got $rc"
  fi
}

test_platform_comment_decoy_ignored() {
  local name="AC platform comment decoy is ignored"
  local tmp
  tmp=$(_mktemp)
  _make_fixture "$tmp"
  _write_workflow_comment_decoy "$tmp"

  local rc
  rc=$(_run "$tmp")
  if [ "$rc" = "0" ]; then
    report_pass "$name"
  else
    report_fail "$name" "expected exit 0, got $rc"
  fi
}

test_second_build_action_fails() {
  local name="second docker/build-push-action step fails loud"
  local tmp
  tmp=$(_mktemp)
  _make_fixture "$tmp"
  _write_workflow_second_build_action "$tmp"

  local rc
  rc=$(_run "$tmp")
  if [ "$rc" != "0" ]; then
    report_pass "$name"
  else
    report_fail "$name" "second build action did not fail the lint"
  fi
}

test_missing_build_action_fails() {
  _expect_failure "missing docker/build-push-action step fails loud" \
    ".github/workflows/build-and-push.yml" \
    '/uses:[[:space:]]*docker\/build-push-action@/d'
}

test_unrelated_include_before_build_is_ignored() {
  local name="unrelated include before build job is ignored"
  local tmp
  tmp=$(_mktemp)
  _make_fixture "$tmp"
  _write_workflow_unrelated_include_before_build "$tmp"

  local rc
  rc=$(_run "$tmp")
  if [ "$rc" = "0" ]; then
    report_pass "$name"
  else
    report_fail "$name" "expected exit 0, got $rc"
  fi
}

test_unrelated_image_matrix_is_ignored() {
  local name="unrelated image-shaped matrix is ignored"
  local tmp
  tmp=$(_mktemp)
  _make_fixture "$tmp"
  _write_workflow_unrelated_image_matrix "$tmp"

  local rc
  rc=$(_run "$tmp")
  if [ "$rc" = "0" ]; then
    report_pass "$name"
  else
    report_fail "$name" "expected exit 0, got $rc"
  fi
}

test_asg_mixed_instances_policy_fails() {
  local name="AC ASG MixedInstancesPolicy fails loud"
  local tmp
  tmp=$(_mktemp)
  _make_fixture "$tmp"
  _write_tf_mixed_instances_policy "$tmp"

  local rc
  rc=$(_run "$tmp")
  if [ "$rc" != "0" ]; then
    report_pass "$name"
  else
    report_fail "$name" "MixedInstancesPolicy bypassed the launch-template arch gate"
  fi
}

_expect_failure() {
  local name="$1" file="$2" sed_expr="$3"
  local tmp
  tmp=$(_mktemp)
  _make_fixture "$tmp"

  cp "$tmp/$file" "$tmp/$file.pristine"
  sed -i.bak -E "$sed_expr" "$tmp/$file" && rm -f "$tmp/$file.bak"
  if diff -q "$tmp/$file" "$tmp/$file.pristine" >/dev/null 2>&1; then
    report_fail "$name" "mutation was a no-op, so the fixture would be vacuous"
    return
  fi
  rm -f "$tmp/$file.pristine"

  local rc
  rc=$(_run "$tmp")
  if [ "$rc" != "0" ]; then
    report_pass "$name"
  else
    report_fail "$name" "drift was not detected"
  fi
}

test_ac_platform_arm64_fails() {
  _expect_failure "AC linux/arm64 build platform is rejected without load test" \
    ".github/workflows/build-and-push.yml" \
    '/image:[[:space:]]*ac/,/image:[[:space:]]*relay/s/platform: linux\/amd64/platform: linux\/arm64/'
}

test_ac_platform_missing_fails() {
  _expect_failure "missing AC platform fails loud" \
    ".github/workflows/build-and-push.yml" \
    '/image:[[:space:]]*ac/,/image:[[:space:]]*relay/{/platform: linux\/amd64/d;}'
}

test_non_ac_platform_missing_fails() {
  _expect_failure "missing non-AC matrix platform fails loud" \
    ".github/workflows/build-and-push.yml" \
    '/image:[[:space:]]*server/,/image:[[:space:]]*ac/{/platform: linux\/amd64/d;}'
}

test_build_action_platforms_missing_fails() {
  _expect_failure "build action must consume matrix.platform" \
    ".github/workflows/build-and-push.yml" \
    '/platforms:[[:space:]]*\$\{\{ matrix\.platform \}\}/d'
}

test_multi_platform_fails() {
  _expect_failure "AC multi-platform build is rejected without per-arch load test" \
    ".github/workflows/build-and-push.yml" \
    '/image:[[:space:]]*ac/,/image:[[:space:]]*relay/s/platform: linux\/amd64/platform: linux\/amd64,linux\/arm64/'
}

test_prod_graviton_fails() {
  _expect_failure "prod Graviton instance mismatch is detected" \
    "terraform/modules/ac/main.tf" \
    's/local\.is_prod \? "c6i\.xlarge" : "t3\.medium"/local.is_prod ? "c7g.xlarge" : "t3.medium"/'
}

test_nonprod_graviton_fails() {
  _expect_failure "non-prod Graviton instance mismatch is detected" \
    "terraform/modules/ac/main.tf" \
    's/local\.is_prod \? "c6i\.xlarge" : "t3\.medium"/local.is_prod ? "c6i.xlarge" : "t4g.medium"/'
}

test_unknown_instance_family_fails() {
  _expect_failure "unknown AC instance family fails loud" \
    "terraform/modules/ac/main.tf" \
    's/local\.is_prod \? "c6i\.xlarge" : "t3\.medium"/local.is_prod ? "z9.nano" : "t3.medium"/'
}

test_instance_type_refactor_fails_loud() {
  _expect_failure "refactored AC instance_type expression fails loud" \
    "terraform/modules/ac/main.tf" \
    's/instance_type = local\.is_prod \? "c6i\.xlarge" : "t3\.medium"/instance_type = local.ac_instance_type/'
}

echo "check-ac-ebpf-arch-lockstep.sh fixture tests"
test_in_sync
test_ac_last_matrix_entry_passes
test_platform_comment_decoy_ignored
test_second_build_action_fails
test_missing_build_action_fails
test_unrelated_include_before_build_is_ignored
test_unrelated_image_matrix_is_ignored
test_ac_platform_arm64_fails
test_ac_platform_missing_fails
test_non_ac_platform_missing_fails
test_build_action_platforms_missing_fails
test_multi_platform_fails
test_prod_graviton_fails
test_nonprod_graviton_fails
test_unknown_instance_family_fails
test_instance_type_refactor_fails_loud
test_asg_mixed_instances_policy_fails

echo ""
if [ "$fail" -gt 0 ]; then
  printf 'FAILED: %d passed, %d failed\n' "$pass" "$fail"
  exit 1
fi
printf 'PASSED: %d checks\n' "$pass"
