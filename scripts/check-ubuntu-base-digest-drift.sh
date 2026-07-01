#!/usr/bin/env bash
# check-ubuntu-base-digest-drift.sh
# ----------------------------------------------------------------------------
# Fail if the ubuntu base image digest drifts apart across the repo's
# Dockerfiles. Every ubuntu-based `FROM` — the trivy-gated trio
# (Dockerfile.{server,ac.aws,relay}), the un-gated Dockerfile.{ac,app,base},
# and the local/CI smoke image tests/smoke/local-stack/Dockerfile — must pin the
# SAME ubuntu:<tag>@sha256:<digest> as docker/Dockerfile.server, the source of
# truth. images built FROM opennhp-base (Dockerfile.agent/db) inherit the digest
# Dockerfile.base pins, so they carry no ubuntu FROM of their own to check.
#
# Why this lint exists (#2800): the ubuntu base is where #2800's CVE-bearing
# /usr/bin/pebble shipped. When a base bump lands, a Dockerfile left on the old
# digest keeps pulling the OLD, more-vulnerable base — exactly the silent
# base-image drift #2800 was about. #2755 (dependabot "bump ubuntu … in /docker")
# moved every docker/** Dockerfile from f3d2860 to 53958ec but left
# tests/smoke/local-stack/Dockerfile on the pre-bump f3d2860 — despite that
# file's own comment promising it "pins to match docker/Dockerfile.server …
# Bump together." Nothing enforced that promise. check-go-version-drift.sh
# already fences the golang builder FROM + GO_VERSION; this is its ubuntu-base
# counterpart. A dependabot bump is scoped to one ecosystem/dir, so the smoke
# Dockerfile (under tests/) is the one it structurally cannot reach — this lint
# fails that PR at CI time until smoke is bumped in lockstep.
#
# Discovery mirrors check-base-image-pebble-purge.sh EXACTLY (same two roots,
# same Dockerfile* glob, same ubuntu FROM regex) so the two base-image guards
# scan an identical file set — a new ubuntu Dockerfile is caught by both or
# neither, never one. Those two roots (docker/ + tests/smoke/local-stack/) ARE
# the discovery scope: a smoke Dockerfile relocated OUT of that path would escape
# silently — docker/** keeps `checked` > 0, so the checked==0 guard wouldn't fire
# — the same discovery-scope residual as the pebble/go-version siblings. Widen
# the roots here (and in those siblings) if the smoke image ever moves. Each
# ubuntu FROM must be digest-pinned; an un-pinned `FROM ubuntu:26.04` fails (it is
# non-reproducible and cannot be lockstep-checked) with the same safe bias as the
# golang FROM pin check.
#
# Scope: it compares DIGESTS (the content-addressable pin), not the whole ref,
# so a digest-only `FROM ubuntu@sha256:…` and a `FROM ubuntu:26.04@sha256:…`
# carrying the same digest are correctly the same base (the tag is advisory once
# a digest is present — docker pulls by digest). A `FROM $BASE` that indirects
# through an ARG can't be matched textually (the same residual as the pebble
# lint). The golang builder FROM is check-go-version-drift.sh's job, not this
# one, so a golang-only Dockerfile carries nothing this lint requires.
#
# Wired into `make lint-workflows` and .github/workflows/validate-workflows.yml.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DOCKER_DIR="$REPO_ROOT/docker"
# The local/CI smoke image lives under tests/, not docker/ — the same second
# root check-go-version-drift.sh / check-base-image-pebble-purge.sh widen to.
SMOKE_DIR="$REPO_ROOT/tests/smoke/local-stack"
# Source of truth: docker/Dockerfile.server's ubuntu runtime FROM. Every other
# ubuntu FROM in the repo must carry this same digest. If this file is renamed
# or loses its ubuntu stage, update this constant (as you would
# check-go-version-drift.sh's nhp/go.mod source of truth).
CANONICAL_FILE="docker/Dockerfile.server"

failures=""
checked=0
canonical=""

fail() {
  failures="${failures}ERROR: $1"$'\n'
}

if [ ! -d "$DOCKER_DIR" ]; then
  echo "ERROR: $DOCKER_DIR not found" >&2
  exit 1
fi

# Same ubuntu FROM matcher as check-base-image-pebble-purge.sh — see that
# script's header for the anatomy (optional --platform, optional registry
# prefix, :tag / @digest / bare, case-insensitive, leading whitespace). Keeping
# them identical means both base-image guards agree on what "an ubuntu
# Dockerfile" is.
ubuntu_from_re='^[[:space:]]*FROM[[:space:]]+(--platform=[^[:space:]]+[[:space:]]+)?([^[:space:]]*/)?ubuntu([:@]|[[:space:]]|$)'
# Digest extractor: anchored at ^FROM, through the image ref, to its
# @sha256:<64hex> pin (capture group 3). It mirrors ubuntu_from_re's shape
# (optional --platform, optional registry prefix), so it reads exactly the ref
# discovery matched. Anchoring at ^FROM — rather than a floating `.*ubuntu@` —
# means a later `ubuntu:<tag>@sha256:...` inside a trailing inline comment can't
# be read as the pin (the tail `.*` swallows it); the ref's own digest wins.
# `[Ff]...` gives the same case-insensitivity as the grep -i discovery without a
# non-portable sed `I` flag; the image name `ubuntu` is always lowercase in a
# valid ref, so it needn't be case-folded.
ubuntu_digest_re='^[[:space:]]*[Ff][Rr][Oo][Mm][[:space:]]+(--platform=[^[:space:]]+[[:space:]]+)?([^[:space:]]*/)?ubuntu[^[:space:]]*@(sha256:[0-9a-f]{64}).*'

# Print the pinned digest (sha256:<64hex>) of every ubuntu FROM line in a
# Dockerfile, one per line, in file order. An ubuntu FROM with no digest prints
# the sentinel UNPINNED, preserving one line per ubuntu FROM so the caller can
# flag it and label the right stage. Discovery matches the raw file with the
# same ubuntu_from_re as check-base-image-pebble-purge.sh — no whole-line comment
# strip, because the ^FROM anchor already excludes comment lines and stripping
# them would only make the two guards' matchers textually diverge. The `|| true`
# swallows grep's no-match exit so pipefail can't abort on a non-ubuntu file.
ubuntu_digests() {
  local file="$1" ubuntu_lines line d
  ubuntu_lines=$(grep -iE "$ubuntu_from_re" "$file" || true)
  [ -n "$ubuntu_lines" ] || return 0
  while IFS= read -r line; do
    d=$(printf '%s\n' "$line" | sed -nE "s|$ubuntu_digest_re|\\3|p")
    printf '%s\n' "${d:-UNPINNED}"
  done <<<"$ubuntu_lines"
}

process_file() {
  local file="$1" path digests total idx d stage_label
  path=${file#"$REPO_ROOT"/}
  digests=$(ubuntu_digests "$file")
  # No ubuntu FROM (golang-only builder, opennhp-base child) — nothing to check.
  [ -n "$digests" ] || return 0
  total=$(printf '%s\n' "$digests" | wc -l | tr -d ' ')
  idx=0
  while IFS= read -r d; do
    [ -n "$d" ] || continue
    idx=$((idx + 1))
    # `checked` counts per ubuntu FROM (a 2-stage file adds 2), not per file like
    # the pebble sibling — both only feed the identical checked==0 "discovery
    # matched nothing" guard below, so the different granularity is benign.
    checked=$((checked + 1))
    # Only disambiguate the stage when a file has more than one ubuntu FROM
    # (Dockerfile.app's builder+runtime, the smoke image's two runtimes).
    stage_label="$path"
    if [ "$total" -gt 1 ]; then
      stage_label="$path stage $idx"
    fi
    if [ "$d" = "UNPINNED" ]; then
      fail "$stage_label: ubuntu FROM is not digest-pinned — pin it as ubuntu:<tag>@sha256:<64-hex> (matching $CANONICAL_FILE)."
    elif [ "$d" != "$canonical" ]; then
      fail "$stage_label: ubuntu base digest $d != $canonical (canonical, from $CANONICAL_FILE)."
    fi
  done <<<"$digests"
}

if [ ! -f "$REPO_ROOT/$CANONICAL_FILE" ]; then
  echo "ERROR: source-of-truth $CANONICAL_FILE not found — it defines the canonical ubuntu digest. If it was renamed, update CANONICAL_FILE in this script (as with check-go-version-drift.sh's nhp/go.mod source of truth)." >&2
  exit 1
fi

# The canonical digest is the first digest-pinned ubuntu FROM in the SoT file.
canonical=$(ubuntu_digests "$REPO_ROOT/$CANONICAL_FILE" | { grep -vx UNPINNED || true; })
canonical=${canonical%%$'\n'*}
if [ -z "$canonical" ]; then
  echo "ERROR: $CANONICAL_FILE has no digest-pinned ubuntu FROM to serve as the canonical digest (expected ubuntu:<tag>@sha256:<64-hex>)." >&2
  exit 1
fi

find_roots=("$DOCKER_DIR")
[ -d "$SMOKE_DIR" ] && find_roots+=("$SMOKE_DIR")

while IFS= read -r dockerfile; do
  process_file "$dockerfile"
done < <(find "${find_roots[@]}" -type f -name 'Dockerfile*' ! -name '*.bak' -print | sort)

if [ "$checked" -eq 0 ]; then
  echo "ERROR: no ubuntu-based Dockerfile FROM found under docker/ or tests/smoke/local-stack/ — the discovery glob or the ubuntu FROM pattern has drifted; this lint would silently pass on nothing." >&2
  exit 1
fi

if [ -n "$failures" ]; then
  echo "DRIFT: ubuntu base image digest lockstep check failed." >&2
  echo "Source of truth: $CANONICAL_FILE pins ubuntu@$canonical." >&2
  echo "" >&2
  printf '%s' "$failures" >&2
  echo "" >&2
  echo "Every ubuntu FROM across docker/** and tests/smoke/local-stack/ must pin the SAME ubuntu:<tag>@sha256:<digest>. A dependabot 'bump ubuntu' PR is scoped to docker/, so update tests/smoke/local-stack/Dockerfile in the same PR (see the base-digest note in that file)." >&2
  exit 1
fi

echo "OK: $checked ubuntu FROM(s) pinned to $canonical"
