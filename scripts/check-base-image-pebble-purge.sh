#!/usr/bin/env bash
# check-base-image-pebble-purge.sh
# ----------------------------------------------------------------------------
# Fail if any Dockerfile that builds on the ubuntu base ships Canonical's
# /usr/bin/pebble. That base (ubuntu:26.04) bakes in `pebble`, an unused Go
# service-manager binary that vendors an old golang.org/x/net + Go stdlib, so
# Trivy's gobinary scanner flags a cluster of HIGH CVEs against it. We never
# invoke pebble (every image execs its own entrypoint), so each ubuntu-based
# runtime stage deletes it — see the Pebble note in .trivyignore.
#
# Why this lint exists (#2800 / #2804): the purge is an `rm` line that must be
# repeated in every ubuntu-based Dockerfile. #2800 was a base-image binary that
# silently shipped CVEs until Trivy's DB happened to flag it; #2804 then found
# two more Dockerfiles (ac, app) pinning the same base outside the trivy-gated
# build matrix, carrying pebble with nothing to catch them. A new or refactored
# ubuntu-based Dockerfile that forgets the purge would re-open exactly that gap.
# Trivy only covers the three gated images and only once its DB lists the CVEs;
# this lint covers EVERY ubuntu Dockerfile deterministically, at PR time.
#
# Discovery is intentional: it globs Dockerfiles across the same two roots as
# check-go-version-drift.sh — docker/ and tests/smoke/local-stack/ — rather than
# reading an enumerated list, which is exactly what a new Dockerfile escapes.
# Only Dockerfiles with a direct `FROM ubuntu` are checked; images built FROM
# opennhp-base (Dockerfile.agent/db) inherit the purge done once in
# Dockerfile.base, so they need no separate `rm`. A future age-compliant base
# digest whose pebble is patched (or that drops pebble) makes the `rm` a harmless
# no-op; revisit the removals together then (#2785) rather than weakening this lint.
#
# Scope: it asserts at least one purge is PRESENT per ubuntu Dockerfile — not
# that it runs in the surviving runtime stage (a file-wide grep can't tell a
# runtime stage from a discarded builder) and not once-per-stage (a file with two
# ubuntu runtime stages, like the smoke image, passes on a single rm); a FROM that
# indirects through an ARG (`FROM $BASE`) likewise can't be matched textually.
# Requiring the `rm` (erring toward one harmless extra removal) is the safe bias;
# these residuals are documented rather than papered over. The match also expects
# the canonical single-target `rm -f /usr/bin/pebble`: a multi-target
# (`rm -f /a /usr/bin/pebble`), split-flag (`rm -r -f …`), quoted-path, or
# `--`-terminated form fails closed — the error points at the canonical form —
# which is the safe direction. A purge string buried in an *inline* trailing
# comment (`RUN x  # rm -f /usr/bin/pebble`) can also satisfy the check:
# whole-line `#` comments are stripped, but telling an inline comment from a
# real command needs shell parsing (a `#` can sit inside a quoted string), so
# this lint matches text and leaves that to trivy on the trio.
#
# Wired into `make lint-workflows` and .github/workflows/validate-workflows.yml.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DOCKER_DIR="$REPO_ROOT/docker"
# The local/CI smoke image lives under tests/, not docker/ — check-go-version-drift.sh
# discovers it too. Included only if present so the lint stays portable.
SMOKE_DIR="$REPO_ROOT/tests/smoke/local-stack"

failures=""
checked=0

fail() {
  failures="${failures}ERROR: $1"$'\n'
}

if [ ! -d "$DOCKER_DIR" ]; then
  echo "ERROR: $DOCKER_DIR not found" >&2
  exit 1
fi

# A FROM on the Canonical ubuntu base, with an optional `--platform=...` flag and
# an optional registry/namespace prefix in between (Dockerfile.app/base use
# `FROM --platform=$BUILDPLATFORM ubuntu:`; a refactor to a fully-qualified
# `FROM docker.io/library/ubuntu:` is caught by the `([^[:space:]]*/)?` prefix).
# Matched case-insensitively (grep -i) and with leading whitespace allowed because
# the Dockerfile parser accepts `from ubuntu:` and indented `FROM`. The trailing
# `([:@]|[[:space:]]|$)` accepts a `:tag`, a digest-only `ubuntu@sha256:...` pin,
# and a bare `FROM ubuntu`, while still rejecting a different image like
# `ubuntu-minimal` or `my/ubuntu-fork`. A FROM that indirects through an ARG
# (`FROM $BASE`) can't be matched textually — see the Scope note in the header.
ubuntu_from_re='^[[:space:]]*FROM[[:space:]]+(--platform=[^[:space:]]+[[:space:]]+)?([^[:space:]]*/)?ubuntu([:@]|[[:space:]]|$)'
# The load-bearing removal: the gobinary itself (not the `/var/lib/pebble` dir
# the Dockerfiles also clear — that carries no CVE; the binary is trivy's scan
# target). Accept any force-flag form — `-f`, `-rf`, `--force` — so a valid
# removal isn't rejected over a stylistic flag choice. The force flag is required
# on purpose: it keeps the `rm` a safe no-op once a future base drops pebble. The
# trailing `([[:space:]]|$)` pins the path end so a different file like
# `/usr/bin/pebble-old` can't satisfy the check.
purge_re='rm[[:space:]]+(-[[:alpha:]]*f[[:alpha:]]*|--force)[[:space:]]+/usr/bin/pebble([[:space:]]|$)'

# Discover Dockerfile* recursively under each root — the same two roots (docker/
# + tests/smoke/local-stack/) and recursive model as check-go-version-drift.sh, so
# a Dockerfile in a subdir (e.g. a future docker/web-app/Dockerfile) can't escape.
# The `Dockerfile*` name pattern matches the docker/Dockerfile* CI trigger glob
# (slightly broader than that script's `Dockerfile`/`Dockerfile.*`), which keeps
# what fires the job and what the lint scans aligned; tests/smoke/** recurses too.
find_roots=("$DOCKER_DIR")
[ -d "$SMOKE_DIR" ] && find_roots+=("$SMOKE_DIR")

while IFS= read -r dockerfile; do
  path=${dockerfile#"$REPO_ROOT"/}
  if ! grep -iEq "$ubuntu_from_re" "$dockerfile"; then
    continue
  fi
  checked=$((checked + 1))
  # Strip whole-line comments first, then look for the purge, so a Dockerfile that
  # only *mentions* the command in a `#`-led prose line can't satisfy the check.
  # (An inline trailing comment is a documented residual — see the Scope note;
  # closing it cleanly needs shell parsing, which this lint deliberately avoids.)
  # Capturing the result (rather than `grep … | grep -q`) avoids a pipefail SIGPIPE
  # when a file holds both a prose mention and the real rm — `grep -q` would close
  # the pipe early and the upstream grep's SIGPIPE would surface as a false failure.
  purge_hit=$(grep -vE '^[[:space:]]*#' "$dockerfile" | grep -E "$purge_re" || true)
  if [ -z "$purge_hit" ]; then
    fail "$path: derives FROM the ubuntu base (ships Canonical /usr/bin/pebble) but never force-removes it (e.g. 'rm -f /usr/bin/pebble'). Fold the purge into the runtime apt RUN, matching docker/Dockerfile.server. See .trivyignore."
  fi
done < <(find "${find_roots[@]}" -type f -name 'Dockerfile*' ! -name '*.bak' -print | sort)

if [ "$checked" -eq 0 ]; then
  echo "ERROR: no ubuntu-based Dockerfile found under docker/ or tests/smoke/local-stack/ — the discovery glob or the FROM pattern has drifted; this lint would silently pass on nothing." >&2
  exit 1
fi

if [ -n "$failures" ]; then
  printf '%s' "$failures" >&2
  exit 1
fi

echo "OK: all $checked ubuntu-based Dockerfile(s) purge /usr/bin/pebble"
