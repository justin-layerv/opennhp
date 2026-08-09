#!/usr/bin/env bash
# check-control-leg-surfaced.sh
# ----------------------------------------------------------------------------
# Fence the sandbox Control auto-deploy leg in build-and-push.yml.
#
# Failure mode this guards: the Control root (Connector Authority foundation,
# the ca-* runtime functions, the Hub edge and Fargate worker) used to be
# reachable only through control-sandbox-update.yml's attended dispatch. It
# appeared in no CI job and in no Slack message, so it could sit arbitrarily far
# behind main while every notification still rendered fully green. The
# deploy-sandbox-control job and its notify wiring are what changed that, and
# every assertion below pins a piece that is silent when it breaks:
#
#   C1. deploy-sandbox-control is in the notify job's `needs:`. Without it the
#       job's result is not even available to the Slack step.
#   C2. SANDBOX_CONTROL is forwarded from needs.deploy-sandbox-control.result.
#   C3. SANDBOX_CONTROL is in the DEPLOY_FAILED loop. A failed Control apply
#       that is merely *displayed* still renders a green "successful" header —
#       the same class of bug as #2252 and #2229/#2230.
#   C4. Control is rendered in the SANDBOX_STATUS pipeline string, so a reader
#       can see it at all.
#   C5. deploy-sandbox-control holds the SHARED deploy-sandbox-infra writer
#       lock. This is the load-bearing one. Control and cell0 must never apply
#       concurrently — control-sandbox-update.yml shares this same group for
#       exactly that reason — and giving the job its own group is the obvious
#       "cleanup" that silently permits two Terraform applies to interleave
#       across the same sandbox estate. Nothing else would fail if this
#       regressed; it would just corrupt an apply one day.
#   C6. the job sources its runtime gates from the committed gate file rather
#       than literal flags. Every gate's Terraform default is the DARK value and
#       live sandbox is the opposite on all seven, so a job that lost the gate
#       file and fell back to defaults would not deploy the Hub — it would
#       destroy it. A hardcoded flag list would also drift out of lockstep with
#       control-sandbox-update.yml's inputs with nothing to detect it.
#
# Detection is string-grep based, scoped to the relevant job blocks, so it stays
# runnable without a YAML parser — matching check-packer-failure-surfaced.sh,
# which fences the neighbouring wiring in the same file.
#
# NOTE: like that script, the patterns pin one canonical shell/YAML form. A
# behaviour-preserving rewrite trips a false positive on purpose; if you reshape
# these blocks deliberately, update the patterns in lockstep. The fixture test
# alongside (tests/scripts/check-control-leg-surfaced_test.sh) covers each
# assertion with a paired bad fixture.
#
# Usage:
#   ./scripts/check-control-leg-surfaced.sh                 → exit 0 ok, 1 drift
#   BUILD_AND_PUSH_WF=/path/to/fixture.yml ./scripts/check-control-leg-surfaced.sh
# ============================================================================

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

WF="${BUILD_AND_PUSH_WF:-$REPO_ROOT/.github/workflows/build-and-push.yml}"

if [ ! -f "$WF" ]; then
  echo "check-control-leg-surfaced: workflow not found: $WF" >&2
  exit 1
fi

# Extract one job block: from `^  <name>:` to the next 2-space top-level job
# key (or EOF). Scoping matters — `- deploy-sandbox-control` and
# `group: deploy-sandbox-infra` both appear in more than one job, so a
# whole-file grep would match some other job's wiring and pass while the one
# under test was broken.
job_block() { # job_block <job-name>
  awk -v job="  $1:" '
    $0 == job { inblk = 1; print; next }
    inblk && /^  [A-Za-z0-9_-]+:[[:space:]]*$/ { inblk = 0 }
    inblk { print }
  ' "$WF"
}

notify_block="$(job_block notify)"
if [ -z "$notify_block" ]; then
  echo "check-control-leg-surfaced: could not locate the 'notify:' job in $WF" >&2
  exit 1
fi

control_block="$(job_block deploy-sandbox-control)"
if [ -z "$control_block" ]; then
  echo "check-control-leg-surfaced: could not locate the 'deploy-sandbox-control:' job in $WF" >&2
  exit 1
fi

infra_block="$(job_block deploy-sandbox-infra)"
if [ -z "$infra_block" ]; then
  echo "check-control-leg-surfaced: could not locate the 'deploy-sandbox-infra:' job in $WF" >&2
  exit 1
fi

# Extract each job's concurrency group so C5 can assert they are the SAME lock
# rather than that Control names one particular string. Pinning only Control's
# side would leave a rename of INFRA's group green here while silently splitting
# the mutual exclusion the whole design rests on — the two roots would become
# free to apply against the same estate concurrently, with nothing to notice.
group_of() { # group_of <job block>
  printf '%s\n' "$1" \
    | awk '/^    concurrency:/ { inblk = 1; next }
           inblk && /^    [a-z]/ { exit }
           inblk && /^      group:/ { sub(/^      group:[[:space:]]*/, ""); sub(/[[:space:]]*$/, ""); print; exit }'
}
control_group="$(group_of "$control_block")"
infra_group="$(group_of "$infra_block")"

fail=0
need_in() { # need_in <block> <egrep-pattern> <human message>
  # Capture-then-test rather than piping into `grep -qE`: a drained `grep -E`
  # cannot close the pipe early, so the printf builtin never takes EPIPE
  # mid-write and cannot flip a match into a failure. Same reasoning as
  # check-packer-failure-surfaced.sh.
  local block="$1" pattern="$2" message="$3" hits
  hits="$(printf '%s\n' "$block" | grep -cE "$pattern" || true)"
  if [ "$hits" -eq 0 ]; then
    echo "::error::${message}" >&2
    fail=1
  fi
}

# C1
need_in "$notify_block" '^      - deploy-sandbox-control[[:space:]]*$' \
  "notify's needs: must list deploy-sandbox-control, or its result is unavailable to Slack."

# C2
need_in "$notify_block" 'SANDBOX_CONTROL:[[:space:]]*\$\{\{[[:space:]]*needs\.deploy-sandbox-control\.result[[:space:]]*\}\}' \
  "notify must forward SANDBOX_CONTROL from needs.deploy-sandbox-control.result."

# C3
# shellcheck disable=SC2016  # literal grep pattern; the '$' must NOT expand
need_in "$notify_block" 'for result in .*"\$SANDBOX_CONTROL".*; do' \
  "SANDBOX_CONTROL must be in the DEPLOY_FAILED loop, or a failed Control apply renders green."

# C4
need_in "$notify_block" 'SANDBOX_STATUS=".*Control.*"' \
  "the SANDBOX_STATUS pipeline string must render Control."

# C5 — the writer-lock invariant, asserted as an EQUALITY between the two jobs
# rather than as a literal on one side. Control and cell0 must never apply
# concurrently against the same sandbox estate; whichever name the group has,
# both must have it.
if [ -z "$control_group" ]; then
  echo "::error::deploy-sandbox-control declares no concurrency group; it must share cell0's writer lock." >&2
  fail=1
elif [ -z "$infra_group" ]; then
  echo "::error::deploy-sandbox-infra declares no concurrency group; the shared writer lock is gone." >&2
  fail=1
elif [ "$control_group" != "$infra_group" ]; then
  echo "::error::deploy-sandbox-control holds group '$control_group' but deploy-sandbox-infra holds '$infra_group'; Control and cell0 must never apply concurrently." >&2
  fail=1
fi
need_in "$control_block" 'cancel-in-progress:[[:space:]]*false[[:space:]]*$' \
  "deploy-sandbox-control must not cancel an in-flight apply of the shared writer lock."

# C6 — pin the CAPTURE form, not merely "the script is mentioned". Reading the
# gates from the file is necessary but not sufficient: `mapfile -t f < <(reader)`
# also reads from the file and also looks correct, while discarding the reader's
# exit status, so a failing reader yields an empty flag array and the generator
# silently falls through to the dark Terraform defaults. `x="$(reader)"` keeps
# that exit visible to `set -e`. Both halves are needed — the positive pattern
# alone would still pass a workflow that ADDED a process-substitution call.
# shellcheck disable=SC2016  # literal grep pattern; the '$' must NOT expand
need_in "$control_block" 'gate_flag_text="\$\(\.github/scripts/control-sandbox-runtime-gates\.py flags\)"' \
  "deploy-sandbox-control must capture the gate reader's output into a plain assignment so its exit status survives; falling back to Terraform defaults would tear down the Hub."

deny_in() { # deny_in <block> <egrep-pattern> <human message>
  local block="$1" pattern="$2" message="$3" hits
  hits="$(printf '%s\n' "$block" | grep -cE "$pattern" || true)"
  if [ "$hits" -ne 0 ]; then
    echo "::error::${message}" >&2
    fail=1
  fi
}

deny_in "$control_block" '< *<\(.*control-sandbox-runtime-gates\.py' \
  "deploy-sandbox-control must not read gates through process substitution; it discards the reader's exit status and degrades to the dark Terraform defaults."

# C7 — the fully-dark fail-closed guard. This is the single thing standing
# between a committed all-dark gate file and an UNATTENDED teardown of the Hub
# edge, the Hub worker, and the whole ca-* Authority runtime.
#
# It needs its own fence because nothing else can see it go. An all-dark file is
# a VALID shape — it is the documented rollback — so the reader emits zero flags
# without complaint and `verify-tfvars` passes it too (every absent key legally
# agrees with a dark gate). The empty-flag case therefore arises in exactly one
# situation: the teardown. Delete this `if` and an all-dark commit auto-applies
# a teardown with every fence and every gate test still green.
# shellcheck disable=SC2016  # literal grep pattern; the '$' must NOT expand
need_in "$control_block" '\$\{#gate_flags\[@\]\}" -eq 0' \
  "deploy-sandbox-control must fail closed on an empty gate-flag set; an all-dark gate file is a Hub/Authority teardown and must not apply unattended."
need_in "$control_block" 'fully dark' \
  "the empty gate-flag guard must say WHY it refused (a fully dark gate file), or the next reader deletes it as redundant."

if [ "$fail" -ne 0 ]; then
  echo "check-control-leg-surfaced: FAILED" >&2
  exit 1
fi

echo "check-control-leg-surfaced: OK"
