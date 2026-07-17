#!/usr/bin/env bash
# deploy-relay.sh — NHP-Relay CD deploy leg (#2624, part of #2208).
# ---------------------------------------------------------------------
# Push the freshly-built relay image tag into the relay's SSM image-tag
# param and trigger an ASG instance refresh so the fleet rolls onto it.
#
# Unlike server/ac (blue/green via blue-green-deploy.yml) the relay is a
# plain single ASG (one instance per AZ), and its user_data reads the
# image tag FROM SSM at boot (modules/relay/user_data.sh.tpl:
#   `aws ssm get-parameter ... -> docker pull $ECR_REPO:$IMAGE_TAG`),
# so put-parameter + instance-refresh is the whole deploy.
#
# WHY A DEDICATED HELPER (not an inline workflow step): this script
# writes /<env>/nhp/relay/image-tag, which matches the
# {,green-}image-tag slot regex policed by
# scripts/check-image-tag-writer-allowlist.{py,sh}. That fence exists to
# keep image-tag writers to a small, auditable set — the original bug was
# the build matrix in build-and-push.yml writing image-tag slots and
# racing a concurrent reader (run 26130904414). Keeping the write in this
# single-purpose, allowlisted file (rather than allowlisting the whole
# build workflow) preserves the fence's ability to catch a future
# build-matrix re-introduction. This file is on the allowlist; add new
# writers there only with the same single-purpose granularity.
#
# Usage: deploy-relay.sh <environment> <app_changed> <image_tag>
#   environment:  sandbox | prod  (prod stays dark; promote-to-prod owns it)
#   app_changed:  "true" if the relay image was (re)built+pushed this run, or
#                 if the caller has already verified the tag exists in ECR.
#                 Only then do we advance the SSM tag — on an infra-only
#                 commit <image_tag> (=github.sha) usually was NOT pushed to
#                 ECR, so writing it would crash-loop the refresh on docker
#                 pull. We still refresh (to propagate launch-template /
#                 user_data / relay.toml changes from terraform apply) on
#                 every build.
#   image_tag:    Docker image tag to deploy (typically the commit SHA).
#
# NO-OP WHEN DARK (deploy_relay=false): `module "relay"` is count-gated on
# var.deploy_relay (terraform/main.tf), so when the relay is off the ASG
# and BOTH SSM params don't exist. The asg-name probe returns
# ParameterNotFound -> clean skip. A genuine absence is a clean skip, but
# a sustained / permission SSM error fails LOUD — never degrade an error
# into a silent skip (the #1634 hidden-skip class).
#
# FLEET READINESS GATE (#2646): after starting the refresh we POLL it to a
# terminal state instead of returning fire-and-forget — succeed on `Successful`,
# FAIL LOUD on `Failed`/`Cancelled` or a bounded-wait timeout. Because the relay
# ASG uses health_check_type=ELB (modules/relay/compute.tf), a `Successful`
# refresh means every replaced instance passed all attached target-group health
# checks through the HTTPS target group's /health/live probe. This proves fleet
# readiness for the relay's only public surface; native UDP SDK traffic bypasses
# the relay and targets the assigned cell's public NHP NLB. A boot-failed or
# crash-looping image therefore turns the deploy red before any cutover.
#
# Environment variables:
#   AWS_REGION:   AWS region (default: us-east-2).
#   GITHUB_STEP_SUMMARY: appended to when set (no-op outside Actions).
#   RELAY_REFRESH_POLL_INTERVAL_SECS: seconds between refresh-status polls
#                 (default: 10). Lowered to 0 by the test harness for speed.
#   RELAY_REFRESH_MAX_ITERATIONS: max status polls before a timeout failure
#                 (default: 90 polls; poll-first timing means up to 89 sleeps,
#                 ~14m50s at the 10s interval, before describe latency).
#
# Exit codes:
#   0 - success (deployed + refresh converged, or a clean dark skip)
#   1 - invalid args / loud SSM, SSM write, ASG, or refresh failure (incl. a
#       Failed/Cancelled refresh or a poll-to-completion timeout)

set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "Usage: $0 <environment> <app_changed> <image_tag>" >&2
  exit 1
fi

ENVIRONMENT="$1"
APP_CHANGED="$2"
IMAGE_TAG="$3"
if [[ "$ENVIRONMENT" != "sandbox" && "$ENVIRONMENT" != "prod" ]]; then
  echo "Invalid environment '$ENVIRONMENT'; expected sandbox or prod." >&2
  exit 1
fi
if [[ "$APP_CHANGED" != "true" && "$APP_CHANGED" != "false" ]]; then
  echo "Invalid app_changed '$APP_CHANGED'; expected true or false." >&2
  exit 1
fi
# aws-actions/configure-aws-credentials exports AWS_REGION into the step env, so
# in CI this inherits the workflow region; the us-east-2 literal is only a local
# fallback and won't silently diverge if the workflow region ever changes.
AWS_REGION="${AWS_REGION:-us-east-2}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SSM_PARAM_NOT_FOUND="__NHP_RELAY_SSM_PARAMETER_NOT_FOUND__"

# Refresh completion-poll cadence (#2646). 90 poll attempts at 10s spacing gives
# up to 89 sleeps (~14m50s) before describe latency. Baseline: an observed
# healthy sandbox roll of the 3-instance one-per-AZ fleet took ~8m15s —
# one-at-a-time at MinHealthyPercentage=50, each instance = ECR pull + boot +
# the 120s warmup. A 10-min cap left too little margin (a slightly slower pull
# could tip past it and false-fail a healthy roll), so this keeps a comfortable
# cushion over the ~8-min baseline while still failing LOUD on a genuinely
# wedged/boot-looping roll rather than hanging CI. Stays inside the
# refresh portion of deploy-sandbox-relay's 45-min timeout; the remaining budget
# covers the downstream 20-min functional DMZ gate plus its final uncached pass.
# The interval is overridable so the fixture suite can drive the poll with a
# no-op sleep.
RELAY_REFRESH_POLL_INTERVAL_SECS="${RELAY_REFRESH_POLL_INTERVAL_SECS:-10}"
RELAY_REFRESH_MAX_ITERATIONS="${RELAY_REFRESH_MAX_ITERATIONS:-90}"
# Consecutive describe-instance-refreshes errors (throttle/IAM) tolerated before
# poll_refresh fails LOUD with the captured cause — a one-off blip is absorbed,
# but a persistent break fails fast + informatively instead of riding the full
# poll ceiling to a generic "did not converge" (mirrors the in-flight branch).
RELAY_REFRESH_MAX_DESCRIBE_ERRORS="${RELAY_REFRESH_MAX_DESCRIBE_ERRORS:-3}"

# The relay image lives in the sandbox-account ECR repo layerv/nhp-relay
# (cross-account pull in prod), tagged by the build matrix with the same SHA
# as server/ac. We don't reference it here — the relay's user_data does the
# `docker pull layerv/nhp-relay:<tag>` at boot off the SSM tag we write below.

RELAY_ASG_PARAM="/${ENVIRONMENT}/nhp/relay/asg-name"
RELAY_IMAGE_TAG_PARAM="/${ENVIRONMENT}/nhp/relay/image-tag"

# shellcheck source=.github/scripts/wait-for-instance-refresh.sh
source "$SCRIPT_DIR/wait-for-instance-refresh.sh"

# Append a line to the GitHub Actions step summary when running in CI.
summary() {
  if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    echo "$1" >> "$GITHUB_STEP_SUMMARY"
  fi
}

# Probe an SSM param that MAY be legitimately absent (relay dark). Prints the
# value (rc 0) on success; prints SSM_PARAM_NOT_FOUND (rc 0) ONLY on a genuine
# `(ParameterNotFound)` AWS error-code token. That explicit sentinel keeps a
# missing dark-relay param distinguishable from a present-but-empty misconfigured
# param, which fails loud below. ANY OTHER error retries the transient case and
# then fails loud (rc 1, last stderr shown). Stderr -> tempfile (not 2>&1) so a
# CLI warning on a successful read can't contaminate the returned value. Mirrors
# deploy-sandbox-qurl's ssm_probe.
ssm_probe() {
  local attempt err out
  err=$(mktemp)
  for attempt in 1 2 3; do
    if out=$(aws ssm get-parameter \
        --name "$1" \
        --query "Parameter.Value" --output text \
        --region "$AWS_REGION" 2>"$err"); then
      rm -f "$err"; printf '%s' "$out"; return 0
    fi
    if grep -q '(ParameterNotFound)' "$err"; then
      rm -f "$err"; printf '%s' "$SSM_PARAM_NOT_FOUND"; return 0
    fi
    if [[ "$attempt" -lt 3 ]]; then sleep "$((attempt * 3))"; fi
  done
  cat "$err" >&2; rm -f "$err"; return 1  # exhausted, non-not-found -> loud
}

echo "============================================"
echo "NHP-Relay Deploy"
echo "============================================"
echo "Environment: $ENVIRONMENT"
echo "App changed: $APP_CHANGED"
echo "Image tag:   $IMAGE_TAG"
echo ""

# Dark check + refresh-target resolution in one read. ssm_probe returns the
# SSM_PARAM_NOT_FOUND sentinel on a deterministic ParameterNotFound (the
# dark/skip signal) and non-zero only on an exhausted non-not-found error
# (IAM/throttle); surface that loudly with an ::error:: + summary, symmetric
# with the refresh-failure path.
if ! ASG_NAME=$(ssm_probe "$RELAY_ASG_PARAM"); then
  echo "::error::Failed to read $RELAY_ASG_PARAM from SSM after retries (IAM/throttle?)"
  summary "- Relay deploy: **failed** — could not read $RELAY_ASG_PARAM"
  exit 1
fi
if [[ "$ASG_NAME" == "$SSM_PARAM_NOT_FOUND" ]]; then
  echo "::notice::$RELAY_ASG_PARAM absent — relay not deployed in ${ENVIRONMENT} (deploy_relay=false); skipping relay deploy."
  summary "- Relay deploy: **skipped** (relay not deployed in ${ENVIRONMENT})"
  exit 0
fi
if [[ -z "$ASG_NAME" ]]; then
  echo "::error::$RELAY_ASG_PARAM resolved to an empty value; expected an ASG name or ParameterNotFound for a dark relay."
  summary "- Relay deploy: **failed** — $RELAY_ASG_PARAM returned an empty value"
  exit 1
fi
if [[ "$ASG_NAME" == "None" ]]; then
  echo "::error::$RELAY_ASG_PARAM resolved to None; expected an ASG name or ParameterNotFound for a dark relay."
  summary "- Relay deploy: **failed** — $RELAY_ASG_PARAM returned \`None\`"
  exit 1
fi
echo "Relay ASG: $ASG_NAME"

# Only advance the image tag when this commit actually built+pushed
# layerv/nhp-relay:<IMAGE_TAG>, or a caller has already verified the tag exists.
# On an ordinary infra-only commit the build matrix step-skipped, so IMAGE_TAG
# (=github.sha) is NOT in ECR; writing it would crash-loop the refresh on
# `docker pull`. Leave the param on the running tag and let the refresh below
# still propagate any terraform change.
if [[ "$APP_CHANGED" == "true" ]]; then
  if [[ -z "$IMAGE_TAG" ]]; then
    echo "::error::Image tag is empty on the app-changed deploy path; refusing to update $RELAY_IMAGE_TAG_PARAM"
    summary "- Relay deploy: **failed** — image tag was empty on the app-changed path"
    exit 1
  fi

  # No ECR-existence pre-check on the normal deploy path (unlike
  # update-ssm-image-tag.sh): this job's `needs` chain
  # (deploy-sandbox-relay -> deploy-sandbox-infra -> build.result == 'success',
  # build matrix fail-fast: false) guarantees the relay image at this tag was
  # pushed to ECR earlier in THIS run on the app-changed path, and same-run
  # eviction is impossible. The deposed-SG recovery caller is the exception: it
  # verifies ECR first, then passes app_changed=true to reuse this SSM write
  # path. If a future workflow gives relay its own narrower path filter, add a
  # relay ECR existence/readiness check before writing github.sha here. Adding
  # the check today would be dead defense plus a stderr-swallowing footgun for
  # the normal same-run path.
  echo "Pinning relay image tag $IMAGE_TAG into $RELAY_IMAGE_TAG_PARAM"
  # --overwrite: the param has lifecycle.ignore_changes=[value] in TF, so
  # CI is the authoritative writer after the bootstrap seed.
  if ! aws ssm put-parameter \
      --name "$RELAY_IMAGE_TAG_PARAM" \
      --type String \
      --value "$IMAGE_TAG" \
      --overwrite \
      --region "$AWS_REGION" >/dev/null; then
    echo "::error::Failed to update SSM parameter $RELAY_IMAGE_TAG_PARAM"
    summary "- Relay deploy: **failed** — could not update $RELAY_IMAGE_TAG_PARAM"
    exit 1
  fi
  echo "SSM parameter updated: $RELAY_IMAGE_TAG_PARAM = $IMAGE_TAG"
  summary "- Relay deploy: image tag set to \`$IMAGE_TAG\`"
else
  echo "::notice::No app code change this commit — keeping the current relay image tag (github.sha was not pushed to ECR); refreshing to propagate any terraform launch-template/user_data change."
  summary "- Relay deploy: image tag unchanged (infra-only commit)"
fi

# Trigger a rolling instance refresh so the fleet picks up the (new or
# unchanged) image tag + any launch-template change, then POLL it to completion
# (the #2646 readiness gate — see the header). A refresh already in progress
# returns InstanceRefreshInProgress; rather than blindly treating that as
# success, we resolve the in-flight refresh id and poll IT too, so that path is
# gated identically (a roll a prior run started must still converge).
#
# --preferences (#2646): the relay ASG is a tiny one-per-AZ fleet, so we pin
# refresh behavior rather than inherit the API default (MinHealthyPercentage=90,
# which on a 3-instance fleet rounds the min-healthy floor up to 3 and can stall
# a roll on "cannot honor min healthy percentage"). 50 rolls one instance at a
# time while keeping the rest in service (matches update-ssm-image-tag.sh's small
# fleets); MaxHealthyPercentage=150 lets the ASG launch a replacement BEFORE
# terminating the old (launch-before-terminate). AWS requires
# MaxHealthyPercentage - MinHealthyPercentage <= 100, so 50/150 is the valid
# pairing that keeps the one-at-a-time floor AND the surge (50/200 is rejected
# with a ValidationException). InstanceWarmup=120 matches the ASG's health_check_grace_period; SkipMatching is
# false because the image tag lives in SSM (read at boot), not the launch
# template — a tag-only change leaves the template identical, so SkipMatching
# would wrongly skip the replacement (same reason as update-ssm-image-tag.sh).
#
# Unconditional roll (accepted): this fires on every successful
# deploy-sandbox-infra, so even an UNRELATED infra change (e.g. a server-only
# terraform apply) rolls the relay fleet. That's deliberate — same rationale as
# blue-green's "refresh on every build" — and accepted: the relay forwards an
# opaque, version-stable protocol, so a churned roll is benign.

# Poll an instance refresh to a terminal state through the shared helper. Fleet
# health verification is implicit: health_check_type=ELB requires each replaced
# instance to pass the attached ALB target group's /health/live probe. Native
# UDP request/ACK validation belongs to the assigned cell NHP NLB, not this
# HTTPS-only relay deployment.
poll_refresh() {
  wait_for_instance_refresh \
    "$1" \
    "$2" \
    "" \
    "$RELAY_REFRESH_MAX_ITERATIONS" \
    "Relay" \
    "$RELAY_REFRESH_POLL_INTERVAL_SECS" \
    "$RELAY_REFRESH_MAX_DESCRIBE_ERRORS"
}

echo ""
echo "Starting instance refresh on $ASG_NAME ..."
REFRESH_ERR=$(mktemp)
REFRESH_ID=""
if REFRESH_ID=$(aws autoscaling start-instance-refresh \
    --auto-scaling-group-name "$ASG_NAME" \
    --preferences '{"MinHealthyPercentage": 50, "MaxHealthyPercentage": 150, "InstanceWarmup": 120, "SkipMatching": false}' \
    --query "InstanceRefreshId" --output text \
    --region "$AWS_REGION" 2>"$REFRESH_ERR"); then
  echo "Started relay instance refresh: $REFRESH_ID"
  summary "- Relay deploy: instance refresh \`$REFRESH_ID\` started on \`$ASG_NAME\`"
elif grep -q 'InstanceRefreshInProgress' "$REFRESH_ERR"; then
  # A roll a prior run started is already cycling (StartInstanceRefresh refused
  # because one is in flight). We don't have its id, so describe the MOST-RECENT
  # refresh and gate on its terminal status. `describe-instance-refreshes` sorts
  # by start time descending (most recent first, in-progress ones first), so
  # --max-records 1 + InstanceRefreshes[0] is that refresh.
  #
  # CRITICAL (no silent-skip, no green-a-failed-roll): this lookup must NOT
  # degrade a transient describe error into a clean success the way 2>/dev/null
  # + "empty == converged" would (the #1634 hidden-skip class) — and it must NOT
  # assume a vanished/most-recent refresh SUCCEEDED. So: retry like ssm_probe,
  # fail LOUD on a persistent describe error, and branch on the actual Status —
  # only `Successful` passes; `Failed`/`Cancelled`/empty fail loud.
  echo "::notice::A relay instance refresh is already in progress on $ASG_NAME; resolving the most-recent refresh to gate on."
  summary "- Relay deploy: instance refresh already in progress on \`$ASG_NAME\` — gating on the most-recent refresh"
  DESC_ERR=$(mktemp)
  RECENT=""
  for desc_attempt in 1 2 3; do
    if RECENT=$(aws autoscaling describe-instance-refreshes \
        --auto-scaling-group-name "$ASG_NAME" \
        --max-records 1 \
        --query "InstanceRefreshes[0].[InstanceRefreshId,Status]" \
        --output text \
        --region "$AWS_REGION" 2>"$DESC_ERR"); then
      break
    fi
    RECENT=""
    if [[ "$desc_attempt" -lt 3 ]]; then sleep "$((desc_attempt * 3))"; fi
  done
  if [[ -z "$RECENT" ]]; then
    # Persistent describe error (IAM/throttle) — surface it loudly, never skip.
    echo "::error::Failed to describe the in-flight relay refresh on $ASG_NAME after retries (IAM/throttle?):"
    cat "$DESC_ERR" >&2
    summary "- Relay deploy: **failed** — could not describe the in-flight refresh on \`$ASG_NAME\`"
    rm -f "$DESC_ERR" "$REFRESH_ERR"
    exit 1
  fi
  rm -f "$DESC_ERR"
  REFRESH_ID=$(printf '%s' "$RECENT" | awk '{print $1}')
  RECENT_STATUS=$(printf '%s' "$RECENT" | awk '{print $2}')
  echo "Most-recent relay refresh on $ASG_NAME: id=$REFRESH_ID status=$RECENT_STATUS"
  case "$RECENT_STATUS" in
    Successful)
      # The in-flight roll converged between the start attempt and this lookup.
      echo "::notice::The in-flight relay refresh ($REFRESH_ID) already completed successfully on $ASG_NAME."
      summary "- Relay deploy: in-flight refresh \`$REFRESH_ID\` **completed successfully** on \`$ASG_NAME\`"
      rm -f "$REFRESH_ERR"
      exit 0
      ;;
    Failed | Cancelled)
      # A failed roll in the race window leaves nothing InProgress/Pending too —
      # do NOT report it green.
      echo "::error::The in-flight relay refresh ($REFRESH_ID) on $ASG_NAME ended $RECENT_STATUS."
      summary "- Relay deploy: **failed** — in-flight refresh \`$REFRESH_ID\` ended $RECENT_STATUS on \`$ASG_NAME\`"
      rm -f "$REFRESH_ERR"
      exit 1
      ;;
    Pending | InProgress)
      # Still rolling — fall through to poll it to completion.
      echo "Polling in-flight relay instance refresh: $REFRESH_ID"
      ;;
    *)
      # Empty id / None / RollbackInProgress / Cancelling / any unexpected token:
      # we KNOW a refresh existed (StartInstanceRefresh said InstanceRefreshInProgress),
      # so an unresolvable or unexpected status is a loud failure, not a pass.
      echo "::error::Could not resolve a usable status for the in-flight relay refresh on $ASG_NAME (got id='$REFRESH_ID' status='$RECENT_STATUS'); refusing to report success."
      summary "- Relay deploy: **failed** — unresolved in-flight refresh status (\`$RECENT_STATUS\`) on \`$ASG_NAME\`"
      rm -f "$REFRESH_ERR"
      exit 1
      ;;
  esac
else
  echo "::error::Failed to start relay instance refresh on $ASG_NAME:"
  cat "$REFRESH_ERR" >&2
  summary "- Relay deploy: **failed** — could not start instance refresh on \`$ASG_NAME\`"
  rm -f "$REFRESH_ERR"
  exit 1
fi
rm -f "$REFRESH_ERR"

# Readiness gate: poll the refresh to a terminal state. A Failed/Cancelled
# refresh or a timeout fails the deploy LOUD (the #6 prerequisite).
echo ""
echo "Waiting for relay instance refresh $REFRESH_ID to converge on $ASG_NAME ..."
if poll_refresh "$ASG_NAME" "$REFRESH_ID"; then
  summary "- Relay deploy: instance refresh \`$REFRESH_ID\` **completed successfully** on \`$ASG_NAME\`"
else
  summary "- Relay deploy: **failed** — instance refresh \`$REFRESH_ID\` did not complete successfully on \`$ASG_NAME\`"
  exit 1
fi
