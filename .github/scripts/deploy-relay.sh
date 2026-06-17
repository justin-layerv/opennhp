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
#   app_changed:  "true" if the relay image was (re)built+pushed this run.
#                 Only then do we advance the SSM tag — on an infra-only
#                 commit <image_tag> (=github.sha) was NOT pushed to ECR,
#                 so writing it would crash-loop the refresh on docker pull.
#                 We still refresh (to propagate launch-template / user_data
#                 / relay.toml changes from terraform apply) on every build.
#   image_tag:    Docker image tag to deploy (typically the commit SHA).
#
# NO-OP WHEN DARK (deploy_relay=false): `module "relay"` is count-gated on
# var.deploy_relay (terraform/main.tf), so when the relay is off the ASG
# and BOTH SSM params don't exist. The asg-name probe returns
# ParameterNotFound -> clean skip. A genuine absence is a clean skip, but
# a sustained / permission SSM error fails LOUD — never degrade an error
# into a silent skip (the #1634 hidden-skip class).
#
# Environment variables:
#   AWS_REGION:   AWS region (default: us-east-2).
#   GITHUB_STEP_SUMMARY: appended to when set (no-op outside Actions).
#
# Exit codes:
#   0 - success (deployed, or a clean dark skip)
#   1 - invalid args / loud SSM, SSM write, or ASG failure

set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "Usage: $0 <environment> <app_changed> <image_tag>" >&2
  exit 1
fi

ENVIRONMENT="$1"
APP_CHANGED="$2"
IMAGE_TAG="$3"
# aws-actions/configure-aws-credentials exports AWS_REGION into the step env, so
# in CI this inherits the workflow region; the us-east-2 literal is only a local
# fallback and won't silently diverge if the workflow region ever changes.
AWS_REGION="${AWS_REGION:-us-east-2}"
SSM_PARAM_NOT_FOUND="__NHP_RELAY_SSM_PARAMETER_NOT_FOUND__"

# The relay image lives in the sandbox-account ECR repo layerv/nhp-relay
# (cross-account pull in prod), tagged by the build matrix with the same SHA
# as server/ac. We don't reference it here — the relay's user_data does the
# `docker pull layerv/nhp-relay:<tag>` at boot off the SSM tag we write below.

RELAY_ASG_PARAM="/${ENVIRONMENT}/nhp/relay/asg-name"
RELAY_IMAGE_TAG_PARAM="/${ENVIRONMENT}/nhp/relay/image-tag"

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
# layerv/nhp-relay:<IMAGE_TAG>. On an infra-only commit the build matrix
# step-skipped, so IMAGE_TAG (=github.sha) is NOT in ECR; writing it would
# crash-loop the refresh on `docker pull`. Leave the param on the running
# tag and let the refresh below still propagate any terraform change.
if [[ "$APP_CHANGED" == "true" ]]; then
  if [[ -z "$IMAGE_TAG" ]]; then
    echo "::error::Image tag is empty on the app-changed deploy path; refusing to update $RELAY_IMAGE_TAG_PARAM"
    summary "- Relay deploy: **failed** — image tag was empty on the app-changed path"
    exit 1
  fi

  # No ECR-existence pre-check (unlike update-ssm-image-tag.sh): this job's
  # `needs` chain (deploy-sandbox-relay -> deploy-sandbox-infra ->
  # build.result == 'success', build matrix fail-fast: false) guarantees the
  # relay image at this tag was pushed to ECR earlier in THIS run on the
  # app-changed path, and same-run eviction is impossible. This depends on the
  # matrix staying all-app-images-on-app-change; if a future workflow gives
  # relay its own narrower path filter, add a relay ECR existence/readiness
  # check before writing github.sha here. Adding the check today would be dead
  # defense plus a stderr-swallowing footgun for no real gain.
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
# unchanged) image tag + any launch-template change. Fire-and-forget: we
# don't poll to completion (single AZ-baseline fleet rolls quickly). A
# refresh already in progress returns InstanceRefreshInProgress, which we
# treat as success (a roll is already happening — the desired end state).
#
# Unconditional roll (accepted): this fires on every successful
# deploy-sandbox-infra, so even an UNRELATED infra change (e.g. a server-only
# terraform apply) rolls the relay fleet. That's deliberate — same rationale as
# blue-green's "refresh on every build" — and accepted: the relay forwards an
# opaque, version-stable protocol and is dark until #6, so a churned roll is
# benign. Adding a readiness gate / completion poll (the blue-green knock-ready
# equivalent) is a #6-time concern, tracked separately; it's unneeded while dark.
echo ""
echo "Starting instance refresh on $ASG_NAME ..."
REFRESH_ERR=$(mktemp)
if REFRESH_ID=$(aws autoscaling start-instance-refresh \
    --auto-scaling-group-name "$ASG_NAME" \
    --query "InstanceRefreshId" --output text \
    --region "$AWS_REGION" 2>"$REFRESH_ERR"); then
  echo "Started relay instance refresh: $REFRESH_ID"
  summary "- Relay deploy: instance refresh \`$REFRESH_ID\` started on \`$ASG_NAME\`"
elif grep -q 'InstanceRefreshInProgress' "$REFRESH_ERR"; then
  echo "::notice::A relay instance refresh is already in progress on $ASG_NAME; treating as success."
  summary "- Relay deploy: instance refresh already in progress on \`$ASG_NAME\`"
else
  echo "::error::Failed to start relay instance refresh on $ASG_NAME:"
  cat "$REFRESH_ERR" >&2
  summary "- Relay deploy: **failed** — could not start instance refresh on \`$ASG_NAME\`"
  rm -f "$REFRESH_ERR"
  exit 1
fi
rm -f "$REFRESH_ERR"
