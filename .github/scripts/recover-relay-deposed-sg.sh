#!/usr/bin/env bash
# recover-relay-deposed-sg.sh - unblock a partially replaced relay node SG.
#
# Terraform can leave module.nhp.module.relay[0].aws_security_group.relay as a
# deposed object when a ForceNew SG edit succeeds through create/update, then
# fails at DeleteSecurityGroup because existing relay instances still have ENIs
# on the old SG. This helper runs before the next sandbox apply: it pins a relay
# image that is known to exist, then reuses deploy-relay.sh to roll the ASG so
# those ENIs move to the current launch-template SG before Terraform retries the
# deposed SG destroy. On an infra-only recovery after an app-changing apply was
# blocked, this can intentionally advance /<env>/nhp/relay/image-tag to the
# first date-ordered recent relay image found in ECR; that is what the downstream
# relay deploy job would have done if infra apply had reached it. It intentionally
# converges back to CI-built images and does not preserve out-of-band SSM pins
# that are newer than the scanned candidate window.
#
# Usage: recover-relay-deposed-sg.sh <environment> <app_changed> <workflow_image_tag>
#   environment:        sandbox; prod requires RECOVER_RELAY_ALLOW_PROD=1 until
#                       #2208 defines prod's recovery/SSM override policy.
#   app_changed:        "true" when this workflow built workflow_image_tag.
#   workflow_image_tag: current workflow github.sha from the setup job.

set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "Usage: $0 <environment> <app_changed> <workflow_image_tag>" >&2
  exit 1
fi

ENVIRONMENT="$1"
APP_CHANGED="$2"
WORKFLOW_IMAGE_TAG="$3"
AWS_REGION="${AWS_REGION:-us-east-2}"
# us-east-2 is the repo's current AWS region default; workflow callers can
# still override AWS_REGION explicitly if relay ever moves regions.
AWS_BIN="${RECOVER_RELAY_AWS_BIN:-aws}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${RECOVER_RELAY_REPO_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
DEPLOY_HELPER="${RECOVER_RELAY_DEPLOY_HELPER:-$SCRIPT_DIR/deploy-relay.sh}"
RELAY_ECR_REPOSITORY="${RELAY_ECR_REPOSITORY:-layerv/nhp-relay}"
RECOVERY_CANDIDATE_LIMIT="${RECOVERY_CANDIDATE_LIMIT:-200}"
RECOVERY_ECR_LOOKUP_MAX_ATTEMPTS="${RECOVERY_ECR_LOOKUP_MAX_ATTEMPTS:-3}"
RECOVERY_ECR_LOOKUP_RETRY_DELAY_SECS="${RECOVERY_ECR_LOOKUP_RETRY_DELAY_SECS:-2}"
RECOVER_RELAY_ALLOW_PROD="${RECOVER_RELAY_ALLOW_PROD:-0}"

if [[ "$ENVIRONMENT" == "prod" && "$RECOVER_RELAY_ALLOW_PROD" != "1" ]]; then
  echo "::error::refusing prod relay SG recovery without RECOVER_RELAY_ALLOW_PROD=1; prod recovery must first define its SSM image-tag override policy in #2208." >&2
  exit 1
fi

if [[ ! "$RECOVERY_CANDIDATE_LIMIT" =~ ^[1-9][0-9]*$ ]]; then
  echo "::error::RECOVERY_CANDIDATE_LIMIT must be a positive integer, got: $(printf %q "$RECOVERY_CANDIDATE_LIMIT")" >&2
  exit 1
fi
if [[ ! "$RECOVERY_ECR_LOOKUP_MAX_ATTEMPTS" =~ ^[1-9][0-9]*$ ]]; then
  echo "::error::RECOVERY_ECR_LOOKUP_MAX_ATTEMPTS must be a positive integer, got: $(printf %q "$RECOVERY_ECR_LOOKUP_MAX_ATTEMPTS")" >&2
  exit 1
fi
if [[ ! "$RECOVERY_ECR_LOOKUP_RETRY_DELAY_SECS" =~ ^[0-9]+$ ]]; then
  echo "::error::RECOVERY_ECR_LOOKUP_RETRY_DELAY_SECS must be a non-negative integer, got: $(printf %q "$RECOVERY_ECR_LOOKUP_RETRY_DELAY_SECS")" >&2
  exit 1
fi

summary() {
  if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    echo "$1" >> "$GITHUB_STEP_SUMMARY"
  fi
}

verify_ecr_image_exists() {
  local tag="$1"

  "$AWS_BIN" ecr describe-images \
    --repository-name "$RELAY_ECR_REPOSITORY" \
    --image-ids "imageTag=$tag" \
    --region "$AWS_REGION" >/dev/null
}

probe_ecr_image() {
  local tag="$1"
  local err
  local attempt

  for ((attempt = 1; attempt <= RECOVERY_ECR_LOOKUP_MAX_ATTEMPTS; attempt++)); do
    err="$(mktemp)"

    if verify_ecr_image_exists "$tag" 2>"$err"; then
      rm -f "$err"
      return 0
    fi

    if grep -Eqi 'ImageNotFoundException|ImageNotFound' "$err"; then
      rm -f "$err"
      return 1
    fi

    if (( attempt < RECOVERY_ECR_LOOKUP_MAX_ATTEMPTS )); then
      echo "Relay SG recovery: ECR lookup for $RELAY_ECR_REPOSITORY:$tag failed; retrying ($attempt/$RECOVERY_ECR_LOOKUP_MAX_ATTEMPTS)..." >&2
      rm -f "$err"
      sleep "$RECOVERY_ECR_LOOKUP_RETRY_DELAY_SECS"
      continue
    fi

    echo "::error::ECR lookup failed while checking relay image $RELAY_ECR_REPOSITORY:$tag after $RECOVERY_ECR_LOOKUP_MAX_ATTEMPTS attempt(s):" >&2
    cat "$err" >&2
    rm -f "$err"
    return 2
  done
}

warn_on_current_ssm_tag_override() {
  local recovery_tag="$1"
  local param="/${ENVIRONMENT}/nhp/relay/image-tag"
  local current_tag
  local err

  # The infra-only recovery path intentionally may advance the relay image tag
  # when a prior app-changing apply was blocked before deploy-sandbox-relay ran.
  # Make any overwrite of a different current pin visible during incidents.
  [[ "$APP_CHANGED" == "true" ]] && return 0

  err="$(mktemp)"
  if current_tag=$("$AWS_BIN" ssm get-parameter \
      --name "$param" \
      --query "Parameter.Value" \
      --output text \
      --region "$AWS_REGION" 2>"$err"); then
    rm -f "$err"
    if [[ -n "$current_tag" && "$current_tag" != "None" && "$current_tag" != "$recovery_tag" ]]; then
      echo "::warning::Infra-only relay SG recovery will update $param from current SSM image tag $current_tag to recovery image tag $recovery_tag so live ENIs move off the deposed SG. Verify no out-of-band hotfix pin is being overwritten." >&2
      summary "- Relay SG recovery: **warning** - current relay image tag \`$current_tag\` will be replaced with recovery tag \`$recovery_tag\`"
    fi
    return 0
  fi

  if grep -q 'ParameterNotFound' "$err"; then
    rm -f "$err"
    return 0
  fi

  echo "::warning::Could not read current relay image tag $param before recovery; continuing because recovery tag $recovery_tag was verified in ECR, but current-pin comparison is unavailable:" >&2
  cat "$err" >&2
  rm -f "$err"
}

resolve_recovery_tag() {
  if [[ "$APP_CHANGED" == "true" ]]; then
    if [[ -z "$WORKFLOW_IMAGE_TAG" ]]; then
      echo "::error::workflow image tag is empty on the app-changed relay SG recovery path" >&2
      return 1
    fi
    printf '%s' "$WORKFLOW_IMAGE_TAG"
    return 0
  fi

  # Infra-only recovery may follow an app-changing merge whose image was built
  # before Terraform apply failed, but whose SSM tag was never advanced. Images
  # are tagged with the workflow's push-head SHA, which may be a merge or
  # multi-commit-push head rather than the commit that last touched app paths.
  # Walk recent history in date order and use the first commit that actually has
  # a relay ECR image instead of assuming any one git path query maps to an image
  # tag. This scan is intentionally bounded by RECOVERY_CANDIDATE_LIMIT; keep the
  # deploy-sandbox-infra checkout fetch-depth above that limit. ECR throttling
  # during the scan fails closed after bounded retries instead of continuing
  # through a possibly-blind candidate walk.
  local candidates
  if ! candidates="$(git -C "$REPO_ROOT" log --date-order --format=%H --max-count="$RECOVERY_CANDIDATE_LIMIT")"; then
    echo "::error::could not inspect git history for relay SG recovery candidates" >&2
    return 1
  fi

  local candidate
  local candidate_status
  local available_candidates
  local shallow
  local scanned=0
  available_candidates="$(grep -c . <<< "$candidates" || true)"
  echo "Relay SG recovery: scanning up to $RECOVERY_CANDIDATE_LIMIT recent commit tag candidates ($available_candidates available in checkout)." >&2
  if shallow="$(git -C "$REPO_ROOT" rev-parse --is-shallow-repository 2>/dev/null)" &&
      [[ "$shallow" == "true" && "$available_candidates" -lt "$RECOVERY_CANDIDATE_LIMIT" ]]; then
    echo "::warning::Relay SG recovery has only $available_candidates of requested $RECOVERY_CANDIDATE_LIMIT commit tag candidates because the checkout history is shallow; keep deploy-sandbox-infra fetch-depth above RECOVERY_CANDIDATE_LIMIT." >&2
  fi
  while IFS= read -r candidate; do
    [[ -z "$candidate" ]] && continue
    scanned=$((scanned + 1))
    if (( scanned % 25 == 0 )); then
      echo "Relay SG recovery: checked $scanned recent commit tag candidates..." >&2
    fi
    set +e
    probe_ecr_image "$candidate"
    candidate_status=$?
    set -e
    case "$candidate_status" in
      0)
        printf '%s' "$candidate"
        return 0
        ;;
      1)
        ;;
      *)
        return 1
        ;;
    esac
  done <<< "$candidates"

  echo "::error::could not find a relay ECR image in the latest $RECOVERY_CANDIDATE_LIMIT commit(s); scanned $scanned candidate(s), refusing deposed SG recovery." >&2
  return 1
}

set +e
RECOVERY_TAG="$(resolve_recovery_tag)"
RESOLVE_STATUS=$?
set -e
if [[ "$RESOLVE_STATUS" -ne 0 || -z "$RECOVERY_TAG" ]]; then
  echo "::error::could not resolve a relay image tag for deposed SG recovery. Check that the deploy-sandbox-infra checkout has enough git history." >&2
  summary "- Relay SG recovery: **failed** - could not resolve a relay image tag"
  exit 1
fi

# Relay image tags are GitHub's git SHA-1 object names today, so require the
# full 40-lowercase-hex shape before handing the tag to the deploy helper.
if [[ ! "$RECOVERY_TAG" =~ ^[0-9a-f]{40}$ ]]; then
  echo "::error::resolved relay recovery image tag is not a full lowercase git SHA: $(printf %q "$RECOVERY_TAG")" >&2
  summary "- Relay SG recovery: **failed** - invalid image tag \`$RECOVERY_TAG\`"
  exit 1
fi

echo "Relay SG recovery image tag: $RECOVERY_TAG"
# The infra-only resolver already found this tag by probing ECR. Keep this final
# check anyway because the app-changed path returns the workflow tag directly and
# still needs the same fail-closed image existence guard.
echo "Verifying ECR image exists: $RELAY_ECR_REPOSITORY:$RECOVERY_TAG"
set +e
probe_ecr_image "$RECOVERY_TAG"
ECR_IMAGE_STATUS=$?
set -e
if [[ "$ECR_IMAGE_STATUS" -eq 1 ]]; then
  echo "::error::relay recovery image $RELAY_ECR_REPOSITORY:$RECOVERY_TAG was not found in ECR; refusing to refresh the ASG onto an unpullable tag." >&2
  summary "- Relay SG recovery: **failed** - missing ECR image \`$RELAY_ECR_REPOSITORY:$RECOVERY_TAG\`"
  exit 1
elif [[ "$ECR_IMAGE_STATUS" -ne 0 ]]; then
  summary "- Relay SG recovery: **failed** - ECR lookup failed for \`$RELAY_ECR_REPOSITORY:$RECOVERY_TAG\`"
  exit 1
fi

warn_on_current_ssm_tag_override "$RECOVERY_TAG"

summary "- Relay SG recovery: verified relay image \`$RECOVERY_TAG\`"

# The image has been verified above, so pass app_changed=true to reuse
# deploy-relay.sh's SSM image-tag write path before it starts and polls the ASG
# refresh. That moves live instance ENIs off the deposed SG before Terraform
# retries DeleteSecurityGroup.
"$DEPLOY_HELPER" "$ENVIRONMENT" true "$RECOVERY_TAG"
