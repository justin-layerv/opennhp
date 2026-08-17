#!/usr/bin/env bash
# check-go-version-drift.sh
# ----------------------------------------------------------------------------
# Fail if repo surfaces that must use the same Go toolchain drift apart.
# nhp/go.mod is the source of truth; workflows, Docker builders, privileged
# test containers, and checksum-verified dev Dockerfiles must follow it. Its
# go directive must stay patch-specific (X.Y.Z) because those images and
# tarball checksums are patch-specific too.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

failures=""
checked=0
go_image_ref=""
go_image_ref_label=""

fail() {
  failures="${failures}ERROR: $1"$'\n'
}

die_if_failed() {
  if [ -n "$failures" ]; then
    printf '%s' "$failures" >&2
    exit 1
  fi
}

require_file() {
  local path="$1"
  if [ ! -f "$REPO_ROOT/$path" ]; then
    fail "missing $path"
    return 1
  fi
}

single_match() {
  local out_var="$1" label="$2" matches="$3" desc="$4" mode="${5:-fail_zero}"
  local non_empty count
  non_empty=$(printf '%s\n' "$matches" | sed '/^$/d')
  if [ -z "$non_empty" ]; then
    count=0
  else
    count=$(printf '%s\n' "$non_empty" | wc -l | tr -d ' ')
  fi
  if [ "$count" -eq 1 ]; then
    printf -v "$out_var" '%s' "${non_empty%$'\n'}"
    return 0
  fi
  if [ "$count" -eq 0 ] && [ "$mode" = "quiet_zero" ]; then
    return 2
  fi
  fail "$label: expected exactly one $desc, found $count"
  return 1
}

extract_go_mod_version() {
  sed -nE 's/^go[[:space:]]+([0-9]+\.[0-9]+(\.[0-9]+)?)([[:space:]]+\/\/.*)?[[:space:]]*$/\1/p' "$1"
}

extract_go_mod_toolchain_version() {
  sed -nE 's/^toolchain[[:space:]]+go([0-9]+\.[0-9]+(\.[0-9]+)?)([[:space:]]+\/\/.*)?[[:space:]]*$/\1/p' "$1"
}

extract_workflow_go_version() {
  sed -nE "s/^  GO_VERSION:[[:space:]]*['\"]?([0-9]+\.[0-9]+\.[0-9]+)['\"]?.*$/\1/p" "$1"
}

extract_setup_go_version_file() {
  sed -nE "s|^[[:space:]]*go-version-file:[[:space:]]*['\"]?([^'\"[:space:]]+)['\"]?[[:space:]]*$|\1|p" "$1"
}

extract_go_test_image_ref() {
  sed -nE "s|^[[:space:]]*GO_TEST_IMAGE:[[:space:]]*['\"]?(golang:[0-9]+\.[0-9]+\.[0-9]+-bookworm@sha256:[0-9a-f]{64})['\"]?[[:space:]]*$|\1|p" "$1"
}

extract_golang_from_ref() {
  sed -nE 's|^FROM[[:space:]]+(--platform=[^[:space:]]+[[:space:]]+)?(golang:[0-9]+\.[0-9]+\.[0-9]+-bookworm@sha256:[0-9a-f]{64})([[:space:]].*)?$|\2|p' "$1"
}

extract_arg_value() {
  local file="$1" arg="$2" value_re="$3"
  sed -nE "s/^ARG[[:space:]]+$arg=($value_re)$/\\1/p; s/^ARG[[:space:]]+$arg=['\"]($value_re)['\"]$/\\1/p" "$file"
}

check_equals() {
  local label="$1" version="$2" expected="$3"
  if [ -z "$version" ]; then
    return
  fi
  checked=$((checked + 1))
  if [ "$version" != "$expected" ]; then
    fail "$label: expected Go $expected, got $version"
  fi
}

check_go_image_ref() {
  local label="$1" ref="$2"
  if [ -z "$ref" ]; then
    return
  fi
  checked=$((checked + 1))
  if [ -z "$go_image_ref" ]; then
    go_image_ref="$ref"
    go_image_ref_label="$label"
    return
  fi
  if [ "$ref" != "$go_image_ref" ]; then
    fail "$label: expected Go image $go_image_ref (from $go_image_ref_label), got $ref"
  fi
}

check_pinned_go_image() {
  local label="$1" path="$2" matches="$3" pin_grep="$4" desc="$5"
  local refs count ref version index ref_label
  refs=$(printf '%s\n' "$matches" | sed '/^$/d')
  if [ -z "$refs" ]; then
    if grep -Eq "$pin_grep" "$REPO_ROOT/$path"; then
      if grep -Eq 'golang:[^[:space:]'"'"'"]+@sha256:[0-9a-f]{64}' "$REPO_ROOT/$path"; then
        fail "$label: must use repo-standard golang:<version>-bookworm@sha256:<64-hex>"
      else
        fail "$label: must be tag+digest pinned as golang:<version>-bookworm@sha256:<64-hex>"
      fi
    else
      fail "$label: expected at least one $desc, found 0"
    fi
    return
  fi
  count=$(printf '%s\n' "$refs" | wc -l | tr -d ' ')
  index=0
  while IFS= read -r ref; do
    [ -n "$ref" ] || continue
    index=$((index + 1))
    ref_label="$label"
    if [ "$count" -gt 1 ]; then
      ref_label="$label stage $index"
    fi
    version=${ref#golang:}
    version=${version%%-*}
    check_go_image_ref "$ref_label" "$ref"
    check_equals "$ref_label" "$version" "$canonical"
  done <<<"$refs"
}

is_listed() {
  local candidate="$1" item
  shift
  for item in "$@"; do
    if [ "$candidate" = "$item" ]; then
      return 0
    fi
  done
  return 1
}

require_file "nhp/go.mod" || die_if_failed

canonical=""
single_match canonical "nhp/go.mod" "$(extract_go_mod_version "$REPO_ROOT/nhp/go.mod")" "go directive" || true
[ -n "$canonical" ] || die_if_failed
case "$canonical" in
  [0-9]*.[0-9]*.[0-9]*) ;;
  *)
    fail "nhp/go.mod: source Go version must include a patch release (X.Y.Z) because workflows, Docker images, and tarball checksums pin full Go releases"
    die_if_failed
    ;;
esac

# CI-touched modules only. Excluded modules intentionally follow their own
# lifecycle today: tests/integration and docker/web-app. tests/smoke and
# tests/e2e are included here because CI runs them with the shared Go version,
# even though their dependency tidy lifecycles are separate.
go_mod_files=(
  "nhp/go.mod"
  "internalauth/go.mod"
  "endpoints/go.mod"
  "examples/server_plugin/go.mod"
  "tests/e2e/go.mod"
  "tests/local/go.mod"
  "tests/smoke/go.mod"
)

workflow_files=(
  ".github/workflows/build-and-push.yml"
  ".github/workflows/ubuntu-build.yml"
  ".github/workflows/codeql.yml"
  ".github/workflows/build-binaries.yml"
)

golang_from_files=(
  "docker/Dockerfile.server"
  "docker/Dockerfile.ac"
  "docker/Dockerfile.ac.aws"
  "docker/Dockerfile.relay"
  "docker/Dockerfile.hub"
  # Local smoke-stack builder — lives under tests/, not docker/, so the
  # discovery below is widened to that root too (otherwise its golang FROM
  # would silently escape the GO_VERSION lockstep on the next bump).
  "tests/smoke/local-stack/Dockerfile"
)

dev_go_dockerfiles=(
  "docker/Dockerfile.app"
  "docker/Dockerfile.base"
)

# Discovery intentionally covers the CI/toolchain roots in this repo:
# workflow YAML, composite action YAML, and docker/** + tests/smoke/local-stack
# Dockerfiles.
while IFS= read -r workflow_file; do
  path=${workflow_file#"$REPO_ROOT"/}
  # Workflow indentation is part of the convention: top-level env.GO_VERSION is
  # two spaces, while job-level env.GO_VERSION is six spaces in this repo.
  if grep -Eq '^  GO_VERSION:' "$workflow_file" && ! is_listed "$path" "${workflow_files[@]}"; then
    fail "$path: contains GO_VERSION but is not listed in workflow_files"
  fi
  if grep -Eq '^      GO_VERSION:' "$workflow_file"; then
    fail "$path: job-level GO_VERSION must move to top-level env.GO_VERSION or use setup-go go-version-file"
  fi
  if grep -Eq '^[[:space:]]*go-version:[[:space:]]*['"'"'"]?[0-9]+\.[0-9]+(\.[0-9]+)?['"'"'"]?[[:space:]]*$' "$workflow_file"; then
    fail "$path: setup-go go-version must reference env.GO_VERSION or go-version-file, not a numeric literal"
  fi
  while IFS= read -r version_file; do
    normalized_version_file=${version_file#./}
    checked=$((checked + 1))
    if ! is_listed "$normalized_version_file" "${go_mod_files[@]}"; then
      fail "$path go-version-file: $version_file is not listed in go_mod_files"
    fi
  done < <(extract_setup_go_version_file "$workflow_file")
done < <(
  find "$REPO_ROOT/.github/workflows" -type f \( -name '*.yml' -o -name '*.yaml' \) -print
  if [ -d "$REPO_ROOT/.github/actions" ]; then
    find "$REPO_ROOT/.github/actions" -type f \( -name '*.yml' -o -name '*.yaml' \) -print
  fi
)

while IFS= read -r dockerfile; do
  path=${dockerfile#"$REPO_ROOT"/}
  if grep -Eq '^FROM[[:space:]].*golang:' "$dockerfile" && ! is_listed "$path" "${golang_from_files[@]}"; then
    fail "$path: contains a golang FROM but is not listed in golang_from_files"
  fi
done < <(find "$REPO_ROOT/docker" "$REPO_ROOT/tests/smoke/local-stack" -type f \( -name 'Dockerfile' -o -name 'Dockerfile.*' \) ! -name '*.bak' -print)

# `make lint-workflows` runs on macOS too, where /usr/bin/env bash may still be
# 3.2. Use indexed arrays instead of Bash 4 associative arrays.
checksum_args=(GO_LINUX_AMD64_SHA256 GO_LINUX_ARM64_SHA256 GO_LINUX_ARMV6L_SHA256)
# Human-verified go.dev/dl SHA256s for checksum_version. This lint enforces
# repo lockstep, while Docker builds verify the bytes with sha256sum -c.
# Keep this table, GO_VERSION, and the dev Dockerfile ARGs together on each
# Go bump. The armv6l checksum stays here because Dockerfile.app/base still
# accept TARGETARCH=arm.
checksum_version="1.26.6"
expected_checksums=(
  708effb774be8237570d0add163225abbdfaf4fca28b2611df167beba4feef89
  d0507e9e9d7fe012aae570108cbd76c15de879e17130ab8cb90d4d7445cb1f2e
  e1379a2fe77bd30fa29833074388247e7c65416e09279f746f20de2d5cf4dfea
)

checked=$((checked + 1))
if [ "$checksum_version" != "$canonical" ]; then
  fail "Go tarball checksum table: expected checksums for Go $canonical, table is for Go $checksum_version"
fi

for path in "${go_mod_files[@]}"; do
  require_file "$path" || continue
  version=""
  single_match version "$path" "$(extract_go_mod_version "$REPO_ROOT/$path")" "go directive" || true
  check_equals "$path" "$version" "$canonical"
  toolchain_version=""
  single_match toolchain_version "$path" "$(extract_go_mod_toolchain_version "$REPO_ROOT/$path")" "toolchain directive" quiet_zero || true
  # If a module opts into toolchain, keep it at the same patch as repo CI,
  # Docker images, and tarball checksums instead of silently selecting ahead.
  check_equals "$path toolchain directive" "$toolchain_version" "$canonical"
done

for path in "${workflow_files[@]}"; do
  require_file "$path" || continue
  version=""
  single_match version "$path" "$(extract_workflow_go_version "$REPO_ROOT/$path")" "env.GO_VERSION" || true
  check_equals "$path env.GO_VERSION" "$version" "$canonical"
done

build_workflow=".github/workflows/build-and-push.yml"
if require_file "$build_workflow"; then
  check_pinned_go_image \
    "$build_workflow GO_TEST_IMAGE" \
    "$build_workflow" \
    "$(extract_go_test_image_ref "$REPO_ROOT/$build_workflow")" \
    '^[[:space:]]*GO_TEST_IMAGE:.*golang:' \
    "digest-pinned GO_TEST_IMAGE"
fi

for path in "${golang_from_files[@]}"; do
  require_file "$path" || continue
  check_pinned_go_image \
    "$path golang FROM" \
    "$path" \
    "$(extract_golang_from_ref "$REPO_ROOT/$path")" \
    '^FROM[[:space:]].*golang:' \
    "digest-pinned golang FROM"
done

for path in "${dev_go_dockerfiles[@]}"; do
  require_file "$path" || continue
  version=""
  single_match version "$path" "$(extract_arg_value "$REPO_ROOT/$path" GO_VERSION '[0-9]+\.[0-9]+\.[0-9]+')" "ARG GO_VERSION" || true
  check_equals "$path ARG GO_VERSION" "$version" "$canonical"
  for i in "${!checksum_args[@]}"; do
    arg="${checksum_args[$i]}"
    checksum=""
    single_match checksum "$path" "$(extract_arg_value "$REPO_ROOT/$path" "$arg" '[0-9a-f]{64}')" "64-hex $arg checksum" || true
    if [ -z "$checksum" ]; then
      continue
    fi
    checked=$((checked + 1))
    expected="${expected_checksums[$i]}"
    if [ "$checksum" != "$expected" ]; then
      fail "$path: expected $arg checksum $expected for Go $canonical, got $checksum"
    fi
  done
done

if [ -n "$failures" ]; then
  echo "DRIFT: Go version lockstep check failed." >&2
  echo "Source of truth: nhp/go.mod declares Go $canonical." >&2
  echo "" >&2
  printf '%s' "$failures" >&2
  echo "" >&2
  echo "Bump the go.mod directive, workflow GO_VERSION values, GO_TEST_IMAGE tag+digest, Dockerfile golang FROM tags, dev Dockerfile tarball checksums, and this script's human-verified checksum_version/expected_checksums together." >&2
  exit 1
fi

echo "OK: Go toolchain lockstep clean ($checked assertions at Go $canonical)"
