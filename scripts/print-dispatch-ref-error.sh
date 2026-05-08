#!/usr/bin/env bash
# Print the structured error for build-and-push.yml's dispatch-ref guard.
# Called only after the workflow's `if:` has determined the dispatch is
# invalid; this script renders the message and exits 1.
#
# Lifted out of the YAML so the message body is fixture-testable without
# an Actions runner — see tests/lints/dispatch-ref-error/run-fixtures.sh.
#
# Annotation goes to stdout to match the repo convention; every other
# `::error::` in build-and-push.yml uses `echo "::error::..."` (stdout).
# GitHub Actions parses workflow commands from stdout reliably.
#
# Safety: the heredoc is unquoted so `${ref}` interpolates, but bash
# variable expansion is single-pass — a `GITHUB_REF` containing
# `$(...)` would be printed literally, not executed. `git
# check-ref-format` also rejects `::` in refs, so a forged ref can't
# inject a fake `::error::` annotation either.

set -euo pipefail

ref="${GITHUB_REF:-<unknown>}"

cat <<EOF
::error title=Invalid dispatch ref::workflow_dispatch is only valid from refs/heads/main (got ${ref})

The OIDC trust policy on this workflow's AWS roles only accepts
the following sub claims:
  repo:layervai/nhp:ref:refs/heads/main
  repo:layervai/nhp:environment:sandbox
  repo:layervai/nhp:environment:production

A dispatch from a feature branch produces
  repo:layervai/nhp:ref:refs/heads/<branch>
which is rejected with sts:AssumeRoleWithWebIdentity denial.
This is intentional security per #1121.

This is for manual recovery — typical sandbox deploys fire
automatically on push to main. Re-dispatch with:
  gh workflow run build-and-push.yml --ref main \\
    -f environment=sandbox -f force_build=true -f deploy=true
EOF
exit 1
