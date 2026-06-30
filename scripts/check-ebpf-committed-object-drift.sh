#!/usr/bin/env bash
# Rebuilds the XDP eBPF object from source and verifies the committed native AC
# object is load-relevant fresh. This closes the gap where make test-ebpf
# proves a newly compiled release/ object while endpoints/ac/main/etc/
# nhp_ebpf_xdp.o could still lag the source and fail the native AC load path.
#
# Scope: this gate is intentionally scoped to the committed native-AC object
# built with the Ubuntu CI eBPF toolchain. It is not asserting byte identity with
# the Docker AC image object, which is compiled independently in
# docker/Dockerfile.ac.aws. It also does not compare tc_egress.o because there
# is no committed native-AC TC object under endpoints/ac/main/etc/.
#
# Canonical eBPF object toolchain:
#   Ubuntu 24.04
#   apt snapshot 20260628T000000Z
#   clang-18=1:18.1.3-1ubuntu1
#   llvm-18=1:18.1.3-1ubuntu1
#   libbpf-dev=1:1.3.0-2build2
# Keep this comment and the defaults below in sync with
# .github/workflows/ebpf-datapath-test.yml; guarded by
# scripts/check-ebpf-toolchain-pin-lockstep.sh.
# The workflow exports EBPF_*_PACKAGE values; this script derives its local
# warning expectations from those same package specs when they are present. If
# any pin moves, regenerate and commit the native AC object with the same
# toolchain so a red drift gate points at source/artifact drift instead of
# package drift. EBPF_LLVM_PACKAGE is installed in CI for toolchain parity and
# the derived llvm-strip binary, which removes DWARF/debug sections before the
# required compare; the workflow prints "$LLVM_STRIP --version" before use so
# packaging changes fail before the freshness check.
#
# The committed native AC object is intentionally DWARF-stripped while retaining
# load-relevant sections such as .BTF/.BTF.ext. This script strips a fresh
# compile the same way before cmp, so branch protection is sensitive to loadable
# bytes and not non-loadable debug metadata. Rebaseline with --update whenever
# eBPF source, object bytes, or canonical toolchain pins intentionally change.

set -euo pipefail

package_name_from_spec() {
  printf '%s' "${1%%=*}"
}

package_version_from_spec() {
  case "$1" in
    *=*) printf '%s' "${1#*=}" ;;
    # Bare package specs intentionally emit no version; callers treat empty
    # stdout as "no exact package version to check."
    *) return 0 ;;
  esac
}

clang_semver_from_package_spec() {
  local version
  version=$(package_version_from_spec "$1")
  if [ -z "$version" ]; then
    return 0
  fi
  version="${version#*:}"
  printf '%s' "${version%%-*}"
}

canonical_apt_snapshot="20260628T000000Z"
actual_apt_snapshot="${EBPF_APT_SNAPSHOT:-$canonical_apt_snapshot}"
expected_apt_snapshot="${EBPF_EXPECTED_APT_SNAPSHOT:-$canonical_apt_snapshot}"
# This script never installs from the snapshot itself; install-ebpf-toolchain.sh
# enforces CI install pins, while these values warn on noncanonical local runs.
expected_clang_package="${EBPF_EXPECTED_CLANG_PACKAGE:-${EBPF_CLANG_PACKAGE:-clang-18=1:18.1.3-1ubuntu1}}"
expected_llvm_package="${EBPF_EXPECTED_LLVM_PACKAGE:-${EBPF_LLVM_PACKAGE:-llvm-18=1:18.1.3-1ubuntu1}}"
expected_libbpf_dev_package_spec="${EBPF_EXPECTED_LIBBPF_DEV_PACKAGE:-${EBPF_LIBBPF_DEV_PACKAGE:-libbpf-dev=1:1.3.0-2build2}}"
expected_clang_bin="${EBPF_EXPECTED_CLANG_BIN:-$(package_name_from_spec "$expected_clang_package")}"
expected_clang_version="${EBPF_EXPECTED_CLANG_VERSION:-$(clang_semver_from_package_spec "$expected_clang_package")}"
expected_llvm_package_name="$(package_name_from_spec "$expected_llvm_package")"
expected_llvm_package_version="${EBPF_EXPECTED_LLVM_VERSION:-$(package_version_from_spec "$expected_llvm_package")}"
expected_libbpf_dev_package="$(package_name_from_spec "$expected_libbpf_dev_package_spec")"
expected_libbpf_dev_version="${EBPF_EXPECTED_LIBBPF_DEV_VERSION:-$(package_version_from_spec "$expected_libbpf_dev_package_spec")}"

llvm_strip_bin_from_package() {
  # Intentional mirror of the workflow's "Resolve eBPF tool names" step; kept
  # local so --check/--update do not depend on Actions env.
  case "$expected_llvm_package_name" in
    llvm-*) printf 'llvm-strip%s' "${expected_llvm_package_name#llvm}" ;;
    # Bare `llvm` (and any other spelling) maps to the unsuffixed binary.
    *) printf 'llvm-strip' ;;
  esac
}

expected_llvm_strip_bin="$(llvm_strip_bin_from_package)"
strip_bin="${LLVM_STRIP:-$expected_llvm_strip_bin}"

fail() {
  echo "ERROR: $1" >&2
  exit 1
}

usage() {
  cat <<EOF
Usage:
  bash scripts/check-ebpf-committed-object-drift.sh [--check|--update]

Modes:
  --check   Recompile release/nhp-ac/etc/nhp_ebpf_xdp.o and compare it with
            endpoints/ac/main/etc/nhp_ebpf_xdp.o. This is the default and the
            CI mode.
  --update  Recompile and replace endpoints/ac/main/etc/nhp_ebpf_xdp.o with a
            DWARF-stripped, BTF-retaining fresh object. Run from Ubuntu 24.04 snapshot
            $expected_apt_snapshot with $expected_clang_package and
            $expected_libbpf_dev_package_spec, matching the CI package pins.
            Set EBPF_ALLOW_NONCANONICAL_UPDATE=1 only when deliberately
            rebaselining with a noncanonical local toolchain.

Runs that pass preflight force a fresh make ebpf-objects and remove local
release eBPF objects first, so preserve any local release artifacts before
running this script if you need them.
EOF
}

if [ "$#" -gt 1 ]; then
  usage >&2
  exit 2
fi

mode="check"
case "${1:-}" in
  ""|"--check")
    : # Keep the default check mode.
    ;;
  "--update")
    mode="update"
    ;;
  "-h"|"--help")
    usage
    exit 0
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac

if [ -n "${EBPF_COMMITTED_OBJECT_ROOT:-}" ]; then
  repo_root="$EBPF_COMMITTED_OBJECT_ROOT"
elif ! repo_root="$(git rev-parse --show-toplevel 2>/dev/null)"; then
  echo "ERROR: run from a git checkout or set EBPF_COMMITTED_OBJECT_ROOT." >&2
  exit 1
fi
make_bin="${EBPF_COMMITTED_OBJECT_MAKE:-make}"
if [ -n "${CLANG:-}" ]; then
  clang_bin="$CLANG"
  command -v "$clang_bin" >/dev/null 2>&1 ||
    fail "CLANG=$clang_bin was not found; pass CLANG=<clang binary> or install the canonical $expected_clang_bin."
else
  clang_bin="$(command -v "$expected_clang_bin" 2>/dev/null || command -v clang 2>/dev/null || true)"
  [ -n "$clang_bin" ] ||
    fail "no clang binary was found; pass CLANG=<clang binary> or install the canonical $expected_clang_bin."
  export CLANG="$clang_bin"
fi

compiled_xdp="${repo_root}/release/nhp-ac/etc/nhp_ebpf_xdp.o"
compiled_tc="${repo_root}/release/nhp-ac/etc/tc_egress.o"
committed_xdp="${repo_root}/endpoints/ac/main/etc/nhp_ebpf_xdp.o"
source_xdp="${repo_root}/nhp/ebpf/xdp/nhp_ebpf_xdp.c"

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

clang_version() {
  local version
  version=$("$clang_bin" --version 2>/dev/null || true)
  if [ -n "$version" ]; then
    printf '%s' "${version%%$'\n'*}"
  else
    printf 'unavailable'
  fi
}

package_version() {
  if command -v dpkg-query >/dev/null 2>&1; then
    dpkg-query -W -f='${Version}' "$1" 2>/dev/null || printf 'unavailable'
  else
    # Non-Debian local runs can only warn; canonical --update runs use Ubuntu.
    printf 'unavailable'
  fi
}

toolchain_summary() {
  printf '%s; %s=%s; %s=%s' \
    "$(clang_version)" \
    "$expected_llvm_package_name" "$(package_version "$expected_llvm_package_name")" \
    "$expected_libbpf_dev_package" "$(package_version "$expected_libbpf_dev_package")"
}

strip_debug_object() {
  local input="$1" output="$2"
  command -v "$strip_bin" >/dev/null 2>&1 ||
    fail "LLVM_STRIP=$strip_bin was not found; install $expected_llvm_package_name or pass LLVM_STRIP=<llvm-strip binary> to strip the fresh XDP object before the load-relevant comparison."
  cp "$input" "$output"
  "$strip_bin" --strip-debug "$output"
}

warn_if_toolchain_noncanonical() {
  local mode_label="$1"
  local actual_clang_semver actual_clang_version actual_libbpf_version actual_llvm_version clang_name strip_name warning
  local warnings=()
  clang_name=$(basename "$clang_bin")
  strip_name=$(basename "$strip_bin")
  actual_clang_version=$(clang_version)
  actual_clang_semver=$(printf '%s\n' "$actual_clang_version" | sed -n 's/.*version \([0-9][0-9.]*\).*/\1/p')
  actual_llvm_version=$(package_version "$expected_llvm_package_name")
  actual_libbpf_version=$(package_version "$expected_libbpf_dev_package")

  if [ "$actual_apt_snapshot" != "$expected_apt_snapshot" ]; then
    warnings+=("expected EBPF_APT_SNAPSHOT=$expected_apt_snapshot; got EBPF_APT_SNAPSHOT=$actual_apt_snapshot.")
  fi
  if [ "$clang_name" != "$expected_clang_bin" ]; then
    warnings+=("expected CLANG=$expected_clang_bin; got CLANG=$clang_bin.")
  fi
  if [ -n "$expected_clang_version" ] && [ "$actual_clang_semver" != "$expected_clang_version" ]; then
    warnings+=("expected $expected_clang_bin version $expected_clang_version; got: $actual_clang_version.")
  fi
  if [ "$strip_name" != "$expected_llvm_strip_bin" ]; then
    warnings+=("expected LLVM_STRIP=$expected_llvm_strip_bin; got LLVM_STRIP=$strip_bin.")
  fi
  if [ -n "$expected_llvm_package_version" ] && [ "$actual_llvm_version" != "$expected_llvm_package_version" ]; then
    warnings+=("expected $expected_llvm_package_name=$expected_llvm_package_version; got $expected_llvm_package_name=$actual_llvm_version.")
  fi
  if [ -n "$expected_libbpf_dev_version" ] && [ "$actual_libbpf_version" != "$expected_libbpf_dev_version" ]; then
    warnings+=("expected $expected_libbpf_dev_package=$expected_libbpf_dev_version; got $expected_libbpf_dev_package=$actual_libbpf_version.")
  fi
  if [ "${#warnings[@]}" -eq 0 ]; then
    return 0
  fi
  for warning in "${warnings[@]}"; do
    echo "WARNING: $mode_label $warning" >&2
  done
  return 1
}

[ -f "$source_xdp" ] || fail "missing XDP source at $source_xdp"
[ -f "$committed_xdp" ] || fail "missing committed XDP object at $committed_xdp"

if [ "$mode" = "update" ] && ! warn_if_toolchain_noncanonical "--update"; then
  if [ "${EBPF_ALLOW_NONCANONICAL_UPDATE:-}" = "1" ]; then
    echo "WARNING: --update proceeding with noncanonical toolchain because EBPF_ALLOW_NONCANONICAL_UPDATE=1." >&2
  else
    fail "--update detected a noncanonical eBPF toolchain; rerun in the pinned Ubuntu 24.04 snapshot toolchain or set EBPF_ALLOW_NONCANONICAL_UPDATE=1 to force an intentional local rebaseline."
  fi
fi

# Force a fresh compile. An old release/ object may already be newer than the C
# file in a local workspace, but this check is about source -> committed object
# freshness, not Make's incremental cache. Remove TC too because `ebpf-objects`
# builds both files; stale release artifacts should never influence this check.
# TC is not compared because no TC object is committed in endpoints/ac/main/etc/.
# Keep these paths in lockstep with the Makefile's `ebpf-objects` outputs.
rm -f "$compiled_xdp" "$compiled_tc"
"$make_bin" -C "$repo_root" ebpf-objects

[ -s "$compiled_xdp" ] || fail "fresh compile did not produce $compiled_xdp"

check_mode_noncanonical=0
if [ "$mode" != "update" ] && ! warn_if_toolchain_noncanonical "--check"; then
  check_mode_noncanonical=1
fi

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT
compiled_stripped="${tmpdir}/fresh-load-relevant.o"
strip_debug_object "$compiled_xdp" "$compiled_stripped"

if [ "$mode" = "update" ]; then
  mv "$compiled_stripped" "$committed_xdp"
  echo "Updated endpoints/ac/main/etc/nhp_ebpf_xdp.o from a DWARF-stripped fresh eBPF compile."
  echo "sha256: $(sha256_file "$committed_xdp")"
  echo "toolchain: $(toolchain_summary)"
  exit 0
fi

if cmp -s "$compiled_stripped" "$committed_xdp"; then
  echo "OK: committed XDP load-relevant object matches fresh compile ($(sha256_file "$committed_xdp"); $(toolchain_summary))."
  exit 0
fi

if [ "$check_mode_noncanonical" -eq 1 ]; then
  echo "WARNING: --check used a noncanonical eBPF toolchain; verify the pinned toolchain before treating this as source/object drift." >&2
  echo "" >&2
fi

cat <<EOF >&2
ERROR: committed XDP load-relevant object drifted from ${source_xdp#"$repo_root"/}.

Fresh compile:    ${compiled_xdp#"$repo_root"/}
  full sha256:          $(sha256_file "$compiled_xdp")
  load-relevant sha256: $(sha256_file "$compiled_stripped")
Committed object: ${committed_xdp#"$repo_root"/}
  load-relevant sha256: $(sha256_file "$committed_xdp")
Toolchain:
  $(toolchain_summary)

Regenerate with the canonical Linux eBPF toolchain, then commit the object:
  EBPF_APT_SNAPSHOT='$expected_apt_snapshot' \\
    EBPF_CLANG_PACKAGE='$expected_clang_package' \\
    EBPF_LLVM_PACKAGE='$expected_llvm_package' \\
    EBPF_LIBBPF_DEV_PACKAGE='$expected_libbpf_dev_package_spec' \\
    CLANG=$expected_clang_bin \\
    LLVM_STRIP=$expected_llvm_strip_bin \\
    bash scripts/check-ebpf-committed-object-drift.sh --update

For local failures, verify CLANG=$expected_clang_bin and the pinned Ubuntu
$expected_libbpf_dev_package package before treating the source or committed
object as stale.

If no eBPF source, committed object, or workflow toolchain pin changed, suspect
an unpinned transitive header or runner-image refresh and follow the eBPF
committed-object triage notes in CLAUDE.md before rebaselining. This required
gate stores DWARF-stripped, BTF-retaining committed bytes so non-loadable debug
metadata cannot churn git history or block branch protection.

This matters because make test-ebpf and the in-kernel datapath proof load the
fresh release/ object, while the native AC load path can read the committed
endpoints/ac/main/etc/nhp_ebpf_xdp.o. A stale committed object can pass source
tests and still fail under FilterMode=EBPFXDP. CI pins clang-18/llvm-18 because
the load-relevant object comparison is compiler-version-sensitive, and pins
libbpf-dev because its headers also feed the object bytes.
EOF
exit 1
