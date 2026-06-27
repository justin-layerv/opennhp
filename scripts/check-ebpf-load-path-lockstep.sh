#!/usr/bin/env bash
# Asserts the eBPF object load path is in lockstep across the three sites that
# independently hardcode the object directory + filenames (eBPF-mode-adoption
# E1, PR #2810).
#
# Sites compared:
#   1. endpoints/ac/ebpf/ebpfegine.go  (the runtime SOURCE OF TRUTH — the AC
#        loads the objects from here)
#        - const ebpfenginename = "nhp_ebpf_xdp.o"
#        - const tcObjName      = "tc_egress.o"
#        - bpfDir := "etc"
#   2. Makefile
#        - EBPF_OBJ_XDP       = ./release/nhp-ac/<dir>/<xdp>.o
#        - EBPF_OBJ_TC_EGRESS = ./release/nhp-ac/<dir>/<tc>.o
#   3. docker/Dockerfile.ac.aws
#        - the runtime regression guard: test -s /nhp-ac/<dir>/<xdp>.o
#                                        test -s /nhp-ac/<dir>/<tc>.o
#          (the extractor accepts -f/-s/-e; the flag is the guard's choice,
#          the path is what must stay in lockstep — see Site 3 below.)
#
# Why this lint exists: the build guard in Dockerfile.ac.aws only asserts the
# Makefile-vs-Dockerfile path agreement (the .o lands where the COPY puts it).
# It does NOT compare against the Go consts. So a Go-only rename — e.g. changing
# `bpfDir` or an object name in ebpfegine.go — would still pass the build guard
# but boot-fail the AC under FilterMode=EBPFXDP, because the AC would look for an
# object the image doesn't ship under that name. That is exactly the gap the
# inline back-pointer comment on the Go consts warns about; this lint closes it
# permanently by surfacing the drift at PR time.
#
# The Makefile and Dockerfile use a fixed mount layout (./release/nhp-ac/ and
# /nhp-ac/ respectively); only the trailing <dir>/<file> segment is governed by
# the Go consts, so that's what we compare. The dir + both filenames must agree
# across all three sites.
#
# A refactor that changes the *shape* of any of these sites (so an extractor
# returns empty) fails loud here with a clear pointer rather than silently
# accepting a stale value — update the matching extractor in the same change.
#
# Wired into `make lint-workflows`.
#
# Testability: REPO_ROOT may be overridden via $EBPF_LOCKSTEP_ROOT so the paired
# fixture test (tests/scripts/check-ebpf-load-path-lockstep_test.sh) can point
# the extractors at mutated copies in a tempdir. Defaults to the git toplevel.

set -euo pipefail

REPO_ROOT="${EBPF_LOCKSTEP_ROOT:-$(git rev-parse --show-toplevel)}"
GO_SRC="${REPO_ROOT}/endpoints/ac/ebpf/ebpfegine.go"
MK_SRC="${REPO_ROOT}/Makefile"
DK_SRC="${REPO_ROOT}/docker/Dockerfile.ac.aws"

for f in "$GO_SRC" "$MK_SRC" "$DK_SRC"; do
  if [ ! -f "$f" ]; then
    echo "ERROR: $f not found" >&2
    exit 1
  fi
done

fail() {
  echo "ERROR: $1" >&2
  exit 1
}

# --- Site 1: Go consts (the source of truth) --------------------------------
# const ebpfenginename string = "nhp_ebpf_xdp.o"
go_xdp=$(grep -E 'ebpfenginename[[:space:]]+string[[:space:]]*=[[:space:]]*"[^"]+"' "$GO_SRC" \
  | head -n1 | sed -E 's/^.*=[[:space:]]*"([^"]+)".*$/\1/')
# const tcObjName string = "tc_egress.o"
go_tc=$(grep -E 'tcObjName[[:space:]]+string[[:space:]]*=[[:space:]]*"[^"]+"' "$GO_SRC" \
  | head -n1 | sed -E 's/^.*=[[:space:]]*"([^"]+)".*$/\1/')
# bpfDir := "etc"  (tolerate `:=` or `=`)
go_dir=$(grep -E 'bpfDir[[:space:]]*:?=[[:space:]]*"[^"]+"' "$GO_SRC" \
  | head -n1 | sed -E 's/^.*:?=[[:space:]]*"([^"]+)".*$/\1/')

[ -n "$go_xdp" ] || fail "could not extract ebpfenginename (xdp object) from $GO_SRC (expected: const ebpfenginename string = \"...\")"
[ -n "$go_tc" ]  || fail "could not extract tcObjName from $GO_SRC (expected: const tcObjName string = \"...\")"
[ -n "$go_dir" ] || fail "could not extract bpfDir from $GO_SRC (expected: bpfDir := \"...\")"

# --- Site 2: Makefile EBPF_OBJ_* paths --------------------------------------
# EBPF_OBJ_XDP = ./release/nhp-ac/etc/nhp_ebpf_xdp.o  -> capture etc/nhp_ebpf_xdp.o
mk_xdp=$(grep -E '^[[:space:]]*EBPF_OBJ_XDP[[:space:]]*=' "$MK_SRC" \
  | head -n1 | sed -E 's#^.*=[[:space:]]*\./release/nhp-ac/(.+\.o).*$#\1#')
mk_tc=$(grep -E '^[[:space:]]*EBPF_OBJ_TC_EGRESS[[:space:]]*=' "$MK_SRC" \
  | head -n1 | sed -E 's#^.*=[[:space:]]*\./release/nhp-ac/(.+\.o).*$#\1#')

# If the sed didn't substitute (no `./release/nhp-ac/<...>.o` to capture), the
# value still holds the whole raw line and won't look like a bare relative path
# — so a single path-shape check both confirms a non-empty match and catches a
# no-op sed, without re-reading the Makefile.
mk_path_re='^[A-Za-z0-9._/-]+\.o$'
[[ "$mk_xdp" =~ $mk_path_re ]] || fail "could not extract EBPF_OBJ_XDP path under ./release/nhp-ac/ from $MK_SRC"
[[ "$mk_tc"  =~ $mk_path_re ]] || fail "could not extract EBPF_OBJ_TC_EGRESS path under ./release/nhp-ac/ from $MK_SRC"

# --- Site 3: Dockerfile.ac.aws runtime guard paths --------------------------
# RUN test -s /nhp-ac/etc/nhp_ebpf_xdp.o && test -s /nhp-ac/etc/tc_egress.o ...
# Grab every /nhp-ac/<...>.o token on the `test -<f|s|e>` guard line(s). The
# guard's test flag (-f exists / -s non-empty / -e exists) is an
# implementation detail of the guard, not of the load path, so accept any of
# them — the path is what must stay in lockstep.
dk_paths=$(grep -E 'test -[fse][[:space:]]+/nhp-ac/' "$DK_SRC" \
  | grep -oE '/nhp-ac/[A-Za-z0-9._/-]+\.o' | sed -E 's#^/nhp-ac/##' | sort -u)

[ -n "$dk_paths" ] || fail "could not extract any /nhp-ac/<...>.o guard path from the 'test -<f|s|e>' line in $DK_SRC"

# --- Compose the expected trailing dir/file segment from the Go consts -------
want_xdp="${go_dir}/${go_xdp}"
want_tc="${go_dir}/${go_tc}"

# --- Compare -----------------------------------------------------------------
mismatch=""
[ "$mk_xdp" = "$want_xdp" ] || mismatch+=$'\n'"  Makefile EBPF_OBJ_XDP       = ./release/nhp-ac/${mk_xdp}   (want .../${want_xdp})"
[ "$mk_tc" = "$want_tc" ]   || mismatch+=$'\n'"  Makefile EBPF_OBJ_TC_EGRESS = ./release/nhp-ac/${mk_tc}   (want .../${want_tc})"

# Dockerfile: both wanted paths must appear in the guard's path set.
printf '%s\n' "$dk_paths" | grep -qxF "$want_xdp" \
  || mismatch+=$'\n'"  Dockerfile.ac.aws guard is missing  /nhp-ac/${want_xdp}  (xdp object)"
printf '%s\n' "$dk_paths" | grep -qxF "$want_tc" \
  || mismatch+=$'\n'"  Dockerfile.ac.aws guard is missing  /nhp-ac/${want_tc}  (tc object)"

if [ -n "$mismatch" ]; then
  cat <<EOF >&2
ERROR: eBPF object load-path drift across the three source-of-truth sites.

       Source of truth — $GO_SRC:
         bpfDir         = "${go_dir}"
         ebpfenginename = "${go_xdp}"
         tcObjName      = "${go_tc}"
       => expected trailing path: ${want_xdp} , ${want_tc}

       Drift:${mismatch}

       Fix: update the Makefile EBPF_OBJ_* paths and/or the Dockerfile.ac.aws
       runtime guard so all three sites agree with the Go consts. A rename in
       ebpfegine.go without matching the build side ships an image whose objects
       the AC cannot find — boot-fail under FilterMode=EBPFXDP. (PR #2810)
EOF
  exit 1
fi

echo "OK: eBPF object load path is lockstep across ebpfegine.go + Makefile + Dockerfile.ac.aws (etc=${go_dir}: ${go_xdp}, ${go_tc})"
