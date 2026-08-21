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
#   C8. a successful Control job is not itself consumer authorization. A
#       superseded leg intentionally succeeds without touching AWS, so Control
#       emits a separate positive output only after this checkout's no-op or
#       apply has been verified; cell0 requires that output before planning.
#   C9. cell1 planning and both runtime refreshes remain descendants of that
#       cell0 plan, and validation remains a descendant of all of them.
#   C10. the upstream `terraform-plan` job remains validation-only. Both cell
#        roots create and consume their saved plans inside their downstream
#        deploy jobs, after the Control barrier; there is no pre-Control plan
#        artifact that can survive the four-operation predecessor.
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

terraform_predeploy_block="$(job_block terraform-plan)"
cell1_infra_block="$(job_block deploy-sandbox-cell1-infra)"
blue_green_block="$(job_block deploy-sandbox-blue-green)"
cell1_blue_green_block="$(job_block deploy-sandbox-cell1-blue-green)"
validate_block="$(job_block deploy-sandbox-validate)"
for required_job in terraform_predeploy_block cell1_infra_block blue_green_block cell1_blue_green_block validate_block; do
  if [ -z "${!required_job}" ]; then
    echo "check-control-leg-surfaced: required rollout job block '$required_job' is missing in $WF" >&2
    exit 1
  fi
done

# Extract each job's concurrency group so C5 can assert they are the SAME lock
# rather than that Control names one particular string. Pinning only Control's
# side would leave a rename of INFRA's group green here while silently splitting
# the mutual exclusion the whole design rests on — the two roots would become
# free to apply against the same estate concurrently, with nothing to notice.
group_of() { # group_of <job block>
  # Feed awk directly from a here-string. With a large real job block,
  # `printf | awk` lets awk exit after the early group match while printf is
  # still writing; under pipefail Linux then reports printf's EPIPE as a false
  # wiring failure.
  awk '/^    concurrency:/ { inblk = 1; next }
       inblk && /^    [a-z]/ { exit }
       inblk && /^      group:/ { sub(/^      group:[[:space:]]*/, ""); sub(/[[:space:]]*$/, ""); print; exit }' \
    <<<"$1"
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

# C8 — successful supersession is not permission to consume an old graph.
need_in "$control_block" 'consumer_rollout_ready:[[:space:]]*\$\{\{[[:space:]]*steps\.authorize-consumers\.outputs\.ready[[:space:]]*\}\}' \
  "deploy-sandbox-control must export a dedicated positive consumer authorization; job success also includes the superseded no-op."
need_in "$control_block" '^        id:[[:space:]]*authorize-consumers[[:space:]]*$' \
  "deploy-sandbox-control must have the source step for consumer_rollout_ready."
need_in "$control_block" "steps\.freshness\.outputs\.fresh == 'true'" \
  "consumer authorization must require this checkout to remain the fresh Control run; superseded runs must not plan cells."
need_in "$control_block" "steps\.plan\.outputs\.control_status == 'converged'.*steps\.verify\.outcome == 'success'" \
  "consumer authorization must require either an exact Control no-op or a verified Control apply; partial applies must stop."
need_in "$control_block" "steps\.promote-detect\.outputs\.promote != 'true'.*steps\.promote-verify\.outcome == 'success'" \
  "consumer authorization must wait for any selector promotion to verify before cell planning."
need_in "$infra_block" 'needs:[[:space:]]*\[[^]]*deploy-sandbox-control[^]]*\]' \
  "deploy-sandbox-infra must be a direct descendant of deploy-sandbox-control so its plan is created after Control."
need_in "$infra_block" "needs\.deploy-sandbox-control\.result == 'success'" \
  "deploy-sandbox-infra must require the Control job itself to succeed."
need_in "$infra_block" "needs\.deploy-sandbox-control\.outputs\.consumer_rollout_ready == 'true'" \
  "deploy-sandbox-infra must require Control's positive same-run authorization, not infer readiness from job success."
deny_in "$control_block" 'needs:[[:space:]]*\[[^]]*deploy-sandbox-infra[^]]*\]' \
  "deploy-sandbox-control must not depend on cell0 infra; that reverses or cycles the Control-first barrier."

# C9 — complete downstream chain: fresh cell plans, both runtime rolls, then
# the live five-alias readback. These checks are deliberately on direct edges;
# relying on a transitive relationship through an unrelated job makes a future
# DAG cleanup able to bypass the barrier silently.
need_in "$cell1_infra_block" 'needs:[[:space:]]*\[[^]]*deploy-sandbox-infra[^]]*\]' \
  "cell1 Terraform must wait for the authorized cell0 Terraform apply."
need_in "$blue_green_block" 'needs:[[:space:]]*\[[^]]*deploy-sandbox-infra[^]]*\]' \
  "cell0 runtime refresh must wait for the fresh cell0 plan/apply."
need_in "$cell1_blue_green_block" 'needs:[[:space:]]*\[[^]]*deploy-sandbox-blue-green[^]]*deploy-sandbox-cell1-infra[^]]*\]' \
  "cell1 runtime refresh must wait for both the cell0 runtime and fresh cell1 plan/apply."
need_in "$validate_block" 'needs:[[:space:]]*\[[^]]*deploy-sandbox-infra[^]]*deploy-sandbox-blue-green[^]]*deploy-sandbox-cell1-blue-green[^]]*deploy-sandbox-control[^]]*\]' \
  "sandbox validation must remain downstream of Control, both fresh cell applies, and both runtime refreshes."
need_in "$validate_block" "needs\.deploy-sandbox-control\.outputs\.consumer_rollout_ready == 'true'" \
  "sandbox validation must re-require the same-run Control authorization before proving the five-alias live graph."

# C10 — plans are born downstream. Match executable lines only, not comments
# explaining why the pre-deploy job intentionally does not plan.
deny_in "$terraform_predeploy_block" '^[[:space:]]+((-[[:space:]]+)?run:[[:space:]]+)?terraform[[:space:]]+plan([[:space:]]|$)' \
  "the upstream terraform-plan job must stay validation-only; a saved cell plan created before Control can encode the four-operation predecessor."
need_in "$infra_block" '^[[:space:]]+if ! terraform plan -out=tfplan' \
  "cell0 must create its saved plan inside the downstream deploy job after Control authorization."
need_in "$infra_block" 'terraform apply.*tfplan' \
  "cell0 must apply the saved plan it created after the Control barrier."
need_in "$cell1_infra_block" '^[[:space:]]+terraform plan -no-color -out=tfplan' \
  "cell1 must create its saved plan inside its downstream deploy job."
need_in "$cell1_infra_block" '^[[:space:]]+terraform apply -no-color -auto-approve tfplan' \
  "cell1 must apply the saved plan it created after the Control barrier."

if [ "$fail" -ne 0 ]; then
  echo "check-control-leg-surfaced: FAILED" >&2
  exit 1
fi

echo "check-control-leg-surfaced: OK"
