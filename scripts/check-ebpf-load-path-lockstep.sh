#!/usr/bin/env bash
# Asserts the eBPF object load path and the AC FilterMode stay in lockstep
# across five files. Four of them (sites 1-4 below) independently hardcode the
# object directory + filenames (eBPF-mode-adoption E1, PR #2810, PR #2859); the
# smoke probe (site 4) also carries the FilterMode numeric constants, which must
# match the AC source-of-truth enum in endpoints/ac/config.go (site 5).
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
#   4. tests/smoke/ssm_probe.go
#        - the deployed host-layout smoke: test -s /opt/layerv/nhp-ac/<dir>/<xdp>.o
#                                           test -s /opt/layerv/nhp-ac/<dir>/<tc>.o
#        - smoke gate constants:
#             acFilterModeIPTables
#             acFilterModeEBPFXDP
#   5. endpoints/ac/config.go
#        - FilterMode_IPTABLES / FilterMode_EBPFXDP are the source of truth for
#          the numeric values rendered into config.toml and read by the smoke.
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
# across all four sites.
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
AC_CONFIG_SRC="${REPO_ROOT}/endpoints/ac/config.go"
MK_SRC="${REPO_ROOT}/Makefile"
DK_SRC="${REPO_ROOT}/docker/Dockerfile.ac.aws"
SMOKE_SRC="${REPO_ROOT}/tests/smoke/ssm_probe.go"

for f in "$GO_SRC" "$AC_CONFIG_SRC" "$MK_SRC" "$DK_SRC" "$SMOKE_SRC"; do
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

# --- Site 4: smoke deployed host-layout paths --------------------------------
# acEBPFXDPObjectPath = "/opt/layerv/nhp-ac/etc/nhp_ebpf_xdp.o" -> capture etc/nhp_ebpf_xdp.o
smoke_xdp=$(grep -E 'acEBPFXDPObjectPath[[:space:]]*=[[:space:]]*"[^"]+"' "$SMOKE_SRC" \
  | head -n1 | sed -E 's#^.*=[[:space:]]*"/opt/layerv/nhp-ac/(.+\.o)".*$#\1#')
smoke_tc=$(grep -E 'acTCEgressObjectPath[[:space:]]*=[[:space:]]*"[^"]+"' "$SMOKE_SRC" \
  | head -n1 | sed -E 's#^.*=[[:space:]]*"/opt/layerv/nhp-ac/(.+\.o)".*$#\1#')

[[ "$smoke_xdp" =~ $mk_path_re ]] || fail "could not extract acEBPFXDPObjectPath path under /opt/layerv/nhp-ac/ from $SMOKE_SRC"
[[ "$smoke_tc"  =~ $mk_path_re ]] || fail "could not extract acTCEgressObjectPath path under /opt/layerv/nhp-ac/ from $SMOKE_SRC"

# --- FilterMode numeric constants -------------------------------------------
# endpoints/ac/config.go is the runtime source of truth; tests/smoke cannot
# import endpoints/ac without turning a smoke package into an application
# dependency, so the constants are duplicated and linted here. The extractor
# follows the current iota block and also honors simple explicit numeric RHS
# values if this enum ever stops using positional iota values.
go_filter_modes=$(awk '
  BEGIN {
    in_const = 0
    iota_value = -1
    iptables = ""
    ebpfxdp = ""
  }
  /^[[:space:]]*const[[:space:]]*\([[:space:]]*$/ {
    in_const = 1
    iota_value = -1
    next
  }
  in_const && /^[[:space:]]*\)[[:space:]]*$/ {
    in_const = 0
    next
  }
  in_const {
    line = $0
    sub(/\/\/.*/, "", line)
    if (line !~ /^[[:space:]]*[A-Za-z_][A-Za-z0-9_]*/) {
      next
    }
    iota_value++
    value = iota_value
    if (line ~ /=[[:space:]]*[0-9]+/) {
      explicit_value = line
      sub(/^.*=[[:space:]]*/, "", explicit_value)
      sub(/[^0-9].*$/, "", explicit_value)
      value = explicit_value
    }
    if (line ~ /^[[:space:]]*FilterMode_IPTABLES([[:space:]]|=|$)/) {
      iptables = value
    }
    if (line ~ /^[[:space:]]*FilterMode_EBPFXDP([[:space:]]|=|$)/) {
      ebpfxdp = value
    }
  }
  END {
    if (iptables != "" && ebpfxdp != "") {
      printf "%s %s\n", iptables, ebpfxdp
    }
  }
' "$AC_CONFIG_SRC")
read -r go_mode_iptables go_mode_ebpfxdp <<<"$go_filter_modes"

[ -n "$go_mode_iptables" ] || fail "could not extract FilterMode_IPTABLES iota value from $AC_CONFIG_SRC"
[ -n "$go_mode_ebpfxdp" ]  || fail "could not extract FilterMode_EBPFXDP iota value from $AC_CONFIG_SRC"

smoke_mode_iptables=$(grep -E 'acFilterModeIPTables[[:space:]]*=[[:space:]]*[0-9]+' "$SMOKE_SRC" \
  | head -n1 | sed -E 's/^.*=[[:space:]]*([0-9]+).*$/\1/')
smoke_mode_ebpfxdp=$(grep -E 'acFilterModeEBPFXDP[[:space:]]*=[[:space:]]*[0-9]+' "$SMOKE_SRC" \
  | head -n1 | sed -E 's/^.*=[[:space:]]*([0-9]+).*$/\1/')

[ -n "$smoke_mode_iptables" ] || fail "could not extract acFilterModeIPTables from $SMOKE_SRC"
[ -n "$smoke_mode_ebpfxdp" ]  || fail "could not extract acFilterModeEBPFXDP from $SMOKE_SRC"

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

[ "$smoke_xdp" = "$want_xdp" ] || mismatch+=$'\n'"  smoke acEBPFXDPObjectPath  = /opt/layerv/nhp-ac/${smoke_xdp}   (want .../${want_xdp})"
[ "$smoke_tc" = "$want_tc" ]   || mismatch+=$'\n'"  smoke acTCEgressObjectPath = /opt/layerv/nhp-ac/${smoke_tc}   (want .../${want_tc})"
[ "$smoke_mode_iptables" = "$go_mode_iptables" ] || mismatch+=$'\n'"  smoke acFilterModeIPTables = ${smoke_mode_iptables}   (want endpoints/ac FilterMode_IPTABLES=${go_mode_iptables})"
[ "$smoke_mode_ebpfxdp" = "$go_mode_ebpfxdp" ]   || mismatch+=$'\n'"  smoke acFilterModeEBPFXDP  = ${smoke_mode_ebpfxdp}   (want endpoints/ac FilterMode_EBPFXDP=${go_mode_ebpfxdp})"

if [ -n "$mismatch" ]; then
  cat <<EOF >&2
ERROR: eBPF object load-path or FilterMode drift across the source-of-truth/probe sites.

       Source of truth — $GO_SRC:
         bpfDir         = "${go_dir}"
         ebpfenginename = "${go_xdp}"
         tcObjName      = "${go_tc}"
       => expected trailing path: ${want_xdp} , ${want_tc}

       Source of truth — $AC_CONFIG_SRC:
         FilterMode_IPTABLES = ${go_mode_iptables}
         FilterMode_EBPFXDP  = ${go_mode_ebpfxdp}

       Drift:${mismatch}

       Fix: update the Makefile EBPF_OBJ_* paths and/or the Dockerfile.ac.aws
       runtime guard and tests/smoke/ssm_probe.go object paths/mode constants
       so every site agrees with the Go consts. A rename in ebpfegine.go
       without matching the build side ships an image whose objects the AC
       cannot find — boot-fail under FilterMode=EBPFXDP. A stale smoke path or
       mode constant misses the deployed host-layout fence added for #2812.
EOF
  exit 1
fi

echo "OK: eBPF object load path and FilterMode constants are lockstep across ebpfegine.go + endpoints/ac/config.go + Makefile + Dockerfile.ac.aws + smoke deployed-layout probe (etc=${go_dir}: ${go_xdp}, ${go_tc}; modes iptables=${go_mode_iptables}, ebpfxdp=${go_mode_ebpfxdp})"
