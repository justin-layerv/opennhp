#!/usr/bin/env bash
# Scan deploy-path run logs for the image-attestation verify gate's ATTEST_RESULT
# marker and decide, per deploy lane, whether the gate needs human attention.
#
# Context: the #1334 Phase 1 gate (.github/actions/verify-image-attestation)
# emits exactly one greppable marker per run it verifies:
#   ::notice::ATTEST_RESULT=<pass|fail|error> repo=<ecr-repo> tag=<t> digest=<d> mode=<audit|enforce>
# `gh run view <id> --log` renders that as `##[notice]ATTEST_RESULT=...`. Today
# soak-readiness — and, once enforce is live, "is the gate actually verifying" —
# is a MANUAL grep of those logs (docs/SECURITY.md). Under enforce a persistent
# `error` (the gate could not complete verification, so it fails OPEN) provides
# zero protection until a human notices. This script is the parser half of the
# Attestation Verify Watchdog (attestation-verify-watchdog.yml), which automates
# that grep into a paging tracker issue — the pre-enforce-flip item on #1334.
#
# It is deliberately pure/offline (no gh/aws/network) so the load-bearing
# classification can be unit-tested against the REAL captured marker wording by
# tests/lints/attestation-verify-watchdog/run-fixtures.sh. The workflow keeps the
# un-testable `gh run list`/`gh run view --log` I/O thin around it.
#
# Input : a directory ($1) of per-run log files, one per `gh run view <id> --log`,
#         named  <workflow>__<created_at_epoch>__<run_id>.log
#         The marker line itself carries only repo+mode, so the workflow encodes
#         the workflow name / run timestamp / run id (needed to pick the LATEST
#         run per lane and to link it from the issue) in the filename.
# Output: one TSV line per deploy lane (the latest run per (workflow,repo) wins),
#         sorted stably by workflow then repo:
#           result <TAB> workflow <TAB> repo <TAB> mode <TAB> run_id <TAB> created_at_epoch <TAB> fire
#         fire=1 means the gate needs attention:
#           - result=error (ANY mode): verification could not complete and FAILED
#             OPEN — under enforce the gate is silently not protecting. This is
#             the case the watchdog exists to page on.
#           - result=fail AND mode=enforce: a verdict blocked a deploy — a real
#             miss (unattested / wrong signer-ref / absent image) OR an
#             under-matched INFRA_RE spuriously blocking a known-attested image.
#             Either way a human must look.
#         fire=0 otherwise. In particular result=fail under mode=audit is the
#         EXPECTED state for legacy / pre-#2339 images during the audit soak and
#         must NOT page; the workflow surfaces such lanes for context only when
#         the issue is already open for a firing lane.
#
# Exit: 0 on success (the report itself carries the verdict, like the gate it
#       watches); non-zero only on a usage/operational error (missing LOG_DIR).
set -euo pipefail

LOG_DIR="${1:-}"
if [[ -z "$LOG_DIR" ]]; then
  echo "usage: $0 <log-dir>" >&2
  exit 2
fi
if [[ ! -d "$LOG_DIR" ]]; then
  echo "scan-attestation-soak: not a directory: $LOG_DIR" >&2
  exit 2
fi

# Emit one marker record per (run-log-file × marker line) and stream it straight
# into the latest-per-lane reducer below — no intermediate temp file. The
# filename supplies workflow / epoch / run-id (the marker line does not); awk
# pulls result / repo / mode out of the marker.
#
# Anchoring on the notice prefix + a real result token (pass|fail|error) excludes
# the action's `emit()` *definition* line, which the step's command echo prints
# verbatim as `...ATTEST_RESULT=$1 repo=${REPOSITORY} ... mode=${MODE}` — `$1` is
# not a result token, so it never matches. The marker format is owned by
# verify-image-attestation/action.yml's `emit()`; the fixture asserts the tokens
# this regex anchors on still exist there, so an emit() drift fails CI (rather
# than silently parsing zero markers — see the watchdog's auto-close guard).
shopt -s nullglob
for f in "$LOG_DIR"/*.log; do
  fname="${f##*/}"
  base="${fname%.log}"
  # <workflow>__<epoch>__<run_id>. Split on the literal '__' separators. A
  # workflow base name never contains '__'; an ECR/run id never does either.
  wf="${base%%__*}"
  rest="${base#*__}"
  epoch="${rest%%__*}"
  rid="${rest#*__}"
  # Guard against a malformed name (no '__'): skip rather than emit junk lanes.
  if [[ "$wf" == "$base" || "$epoch" == "$rest" || -z "$epoch" || -z "$rid" ]]; then
    echo "scan-attestation-soak: ignoring unexpected log filename: $fname" >&2
    continue
  fi
  awk -v wf="$wf" -v ep="$epoch" -v rid="$rid" '
    # Match the emitted marker only: notice prefix + a literal result token.
    /(::notice::|##\[notice\])ATTEST_RESULT=(pass|fail|error)([^a-z]|$)/ {
      line = $0
      r = line;    sub(/.*ATTEST_RESULT=/, "", r);    sub(/[^a-z].*/, "", r)
      repo = line; sub(/.*[ \t]repo=/, "", repo);      sub(/[ \t].*/, "", repo)
      mode = line; sub(/.*[ \t]mode=/, "", mode);      sub(/[^a-zA-Z].*/, "", mode)
      # repo + mode are required for a well-formed marker; skip a truncated line
      # rather than emit an empty-field lane.
      if (repo == "" || mode == "") next
      print wf "\t" repo "\t" ep "\t" r "\t" tolower(mode) "\t" rid
    }
  ' "$f"
# Reduce to the LATEST marker per (workflow, repo) lane, then classify. The loop
# streams records (workflow\trepo\tepoch\tresult\tmode\trun_id) into:
#   sort: group by workflow (k1) then repo (k2), newest epoch first (k3 numeric,
#         reverse) within each group, so the first row of each group is latest.
#         run_id (k6 numeric, reverse) breaks an exact same-second epoch tie
#         deterministically (GH run ids are monotonic, so higher == newer) — a
#         tie is realistically impossible for one lane, but this removes the
#         dependence on sort's input order for it.
#   awk : keep that first row per (workflow,repo); compute the fire flag; reorder
#         to the documented output columns. Output stays workflow-then-repo
#         sorted (stable for the fixture). An empty corpus yields no output.
done | LC_ALL=C sort -t "$(printf '\t')" -k1,1 -k2,2 -k3,3nr -k6,6nr \
     | awk -F'\t' 'BEGIN { OFS = "\t" }
         {
           key = $1 FS $2
           if (key == seen) next
           seen = key
           wf = $1; repo = $2; ep = $3; result = $4; mode = $5; rid = $6
           fire = 0
           if (result == "error") fire = 1
           else if (result == "fail" && mode == "enforce") fire = 1
           print result, wf, repo, mode, rid, ep, fire
         }'
shopt -u nullglob
