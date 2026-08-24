#!/usr/bin/env bash
# shellcheck disable=SC2016 # Fake scripts intentionally retain runtime variables.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
SCRIPT="$ROOT/.github/scripts/verify-durable-aop-image-provenance.sh"
IMAGE=0123456789012345678901234567890123456789
RUN_ID=32682520698
RUN_ATTEMPT=1
DIGEST=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
MOVED_TAG_DIGEST=sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/bin"
export FAKE_ARGS="$WORK/args" FAKE_DIGEST="$DIGEST" FAKE_TAG_DIGEST="$MOVED_TAG_DIGEST"
: >"$FAKE_ARGS"

cat >"$WORK/bin/aws" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'aws %s\n' "$*" >>"$FAKE_ARGS"
case "$1/$2" in
  sts/get-caller-identity) printf '123456789012\n' ;;
  ecr/describe-images)
    [[ "${FAKE_ECR_TRANSPORT_FAILURE:-}" != true ]] || exit 88
    if [[ "$*" == *"imageDigest="* ]]; then
      digest=${FAKE_ECR_DIGEST:-$FAKE_DIGEST}
      case "${FAKE_ECR_SHAPE:-}" in
        absent) jq -cn '{imageDetails:[]}' ;;
        extra) jq -cn --arg digest "$digest" '{imageDetails:[{imageDigest:$digest}],extra:true}' ;;
        *) jq -cn --arg digest "$digest" '{imageDetails:[{imageDigest:$digest}]}' ;;
      esac
    else
      printf '%s\n' "$FAKE_TAG_DIGEST"
    fi
    ;;
  ecr/get-login-password) printf 'password\n' ;;
  *) exit 99 ;;
esac
EOF
printf '%s\n' '#!/usr/bin/env bash' 'cat >/dev/null' >"$WORK/bin/docker"
cat >"$WORK/bin/gh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'gh %s\n' "$*" >>"$FAKE_ARGS"
source=${FAKE_SOURCE:-0123456789012345678901234567890123456789}
run=${FAKE_RUN_ID:-32682520698}
attempt=${FAKE_RUN_ATTEMPT:-1}
digest=${FAKE_ATTESTATION_DIGEST:-${FAKE_DIGEST#sha256:}}
subject=${FAKE_SUBJECT:-123456789012.dkr.ecr.us-east-2.amazonaws.com/layerv/nhp-server}
invocation="https://github.com/layervai/nhp/actions/runs/${run}/attempts/${attempt}"
certificate_invocation=${FAKE_CERTIFICATE_INVOCATION:-$invocation}
predicate_invocation=${FAKE_PREDICATE_INVOCATION:-$invocation}
event=${FAKE_EVENT:-workflow_dispatch}
workflow_path=${FAKE_WORKFLOW_PATH:-.github/workflows/build-and-push.yml}
workflow_ref=${FAKE_WORKFLOW_REF:-refs/heads/main}
workflow_repository=${FAKE_WORKFLOW_REPOSITORY:-https://github.com/layervai/nhp}
dependency_uri=${FAKE_DEPENDENCY_URI:-git+https://github.com/layervai/nhp@refs/heads/main}
jq -cn --arg source "$source" --arg digest "$digest" --arg subject "$subject" \
  --arg certificate_invocation "$certificate_invocation" --arg predicate_invocation "$predicate_invocation" \
  --arg event "$event" --arg workflow_path "$workflow_path" --arg workflow_ref "$workflow_ref" \
  --arg workflow_repository "$workflow_repository" --arg dependency_uri "$dependency_uri" \
  --arg duplicate "${FAKE_DUPLICATE_RESULT:-}" --arg dependency_extra "${FAKE_DEPENDENCY_EXTRA:-}" '
  {verificationResult:{
    statement:{predicateType:"https://slsa.dev/provenance/v1",subject:[{name:$subject,digest:{sha256:$digest}}],
      predicate:{buildDefinition:{externalParameters:{workflow:{path:$workflow_path,ref:$workflow_ref,repository:$workflow_repository}},
        internalParameters:{github:{event_name:$event}},
        resolvedDependencies:([{digest:{gitCommit:$source},uri:$dependency_uri}] +
          (if $dependency_extra == "true" then [{digest:{gitCommit:$source},uri:"git+https://github.com/other/repo@refs/heads/main"}] else [] end))},
        runDetails:{metadata:{invocationId:$predicate_invocation}}}},
    signature:{certificate:{runInvocationURI:$certificate_invocation}}}} as $result |
  if $duplicate == "true" then [$result,$result] else [$result] end'
EOF
chmod +x "$WORK/bin/aws" "$WORK/bin/docker" "$WORK/bin/gh"

# Ordinary deployment callers retain source-tag resolution.
record=$(PATH="$WORK/bin:$PATH" AWS_REGION=us-east-2 GH_TOKEN=x GITHUB_REPOSITORY=layervai/nhp \
  "$SCRIPT" layerv/nhp-server "$IMAGE")
[[ "$record" == "v1|${IMAGE}|layerv/nhp-server|${MOVED_TAG_DIGEST}" ]]
grep -F -- "--image-ids imageTag=$IMAGE" "$FAKE_ARGS" >/dev/null

# Recovery callers query the immutable digest, bind its exact build attempt,
# and remain stable even though the mutable source tag now points elsewhere.
: >"$FAKE_ARGS"
record=$(PATH="$WORK/bin:$PATH" AWS_REGION=us-east-2 GH_TOKEN=x GITHUB_REPOSITORY=layervai/nhp \
  "$SCRIPT" layerv/nhp-server "$IMAGE" "$RUN_ID" "$RUN_ATTEMPT" "$DIGEST")
[[ "$record" == "v1|${IMAGE}|layerv/nhp-server|${DIGEST}" ]]
args=$(cat "$FAKE_ARGS")
[[ "$args" == *"--image-ids imageDigest=$DIGEST"* && "$args" != *"imageTag="* ]]
[[ "$args" == *"--source-digest $IMAGE"* && "$args" == *"--source-ref refs/heads/main"* ]]
[[ "$args" == *"build-and-push.yml@refs/heads/main"* ]]

for mutation in ecr_digest ecr_absent ecr_shape ecr_transport run attempt source digest subject event workflow_path \
  workflow_ref workflow_repository dependency_uri dependency_count predicate_invocation certificate_invocation duplicate; do
  unset FAKE_ECR_DIGEST FAKE_ECR_SHAPE FAKE_ECR_TRANSPORT_FAILURE FAKE_RUN_ID FAKE_RUN_ATTEMPT FAKE_SOURCE \
    FAKE_ATTESTATION_DIGEST FAKE_SUBJECT FAKE_EVENT FAKE_WORKFLOW_PATH FAKE_WORKFLOW_REF \
    FAKE_WORKFLOW_REPOSITORY FAKE_DEPENDENCY_URI FAKE_DEPENDENCY_EXTRA FAKE_PREDICATE_INVOCATION \
    FAKE_CERTIFICATE_INVOCATION FAKE_DUPLICATE_RESULT
  case "$mutation" in
    ecr_digest) export FAKE_ECR_DIGEST=$MOVED_TAG_DIGEST ;;
    ecr_absent) export FAKE_ECR_SHAPE=absent ;;
    ecr_shape) export FAKE_ECR_SHAPE=extra ;;
    ecr_transport) export FAKE_ECR_TRANSPORT_FAILURE=true ;;
    run) export FAKE_RUN_ID=32682520699 ;;
    attempt) export FAKE_RUN_ATTEMPT=2 ;;
    source) export FAKE_SOURCE=9999999999999999999999999999999999999999 ;;
    digest) export FAKE_ATTESTATION_DIGEST=${MOVED_TAG_DIGEST#sha256:} ;;
    subject) export FAKE_SUBJECT=123456789012.dkr.ecr.us-east-2.amazonaws.com/layerv/nhp-ac ;;
    event) export FAKE_EVENT=push ;;
    workflow_path) export FAKE_WORKFLOW_PATH=.github/workflows/other.yml ;;
    workflow_ref) export FAKE_WORKFLOW_REF=refs/heads/other ;;
    workflow_repository) export FAKE_WORKFLOW_REPOSITORY=https://github.com/other/nhp ;;
    dependency_uri) export FAKE_DEPENDENCY_URI=git+https://github.com/other/nhp@refs/heads/main ;;
    dependency_count) export FAKE_DEPENDENCY_EXTRA=true ;;
    predicate_invocation) export FAKE_PREDICATE_INVOCATION=https://github.com/layervai/nhp/actions/runs/1/attempts/1 ;;
    certificate_invocation) export FAKE_CERTIFICATE_INVOCATION=https://github.com/layervai/nhp/actions/runs/1/attempts/1 ;;
    duplicate) export FAKE_DUPLICATE_RESULT=true ;;
  esac
  if PATH="$WORK/bin:$PATH" AWS_REGION=us-east-2 GH_TOKEN=x GITHUB_REPOSITORY=layervai/nhp \
      "$SCRIPT" layerv/nhp-server "$IMAGE" "$RUN_ID" "$RUN_ATTEMPT" "$DIGEST" >/dev/null 2>&1; then
    echo "recovery provenance accepted mutated $mutation authority" >&2
    exit 1
  fi
done
unset FAKE_ECR_DIGEST FAKE_ECR_SHAPE FAKE_ECR_TRANSPORT_FAILURE FAKE_RUN_ID FAKE_RUN_ATTEMPT FAKE_SOURCE \
  FAKE_ATTESTATION_DIGEST FAKE_SUBJECT FAKE_EVENT FAKE_WORKFLOW_PATH FAKE_WORKFLOW_REF \
  FAKE_WORKFLOW_REPOSITORY FAKE_DEPENDENCY_URI FAKE_DEPENDENCY_EXTRA FAKE_PREDICATE_INVOCATION \
  FAKE_CERTIFICATE_INVOCATION FAKE_DUPLICATE_RESULT

# A legacy image can be manually labeled durable in SSM, but cannot produce
# an exact source-bound signed provenance result.
printf '%s\n' '#!/usr/bin/env bash' 'exit 1' >"$WORK/bin/gh"
if PATH="$WORK/bin:$PATH" AWS_REGION=us-east-2 GH_TOKEN=x GITHUB_REPOSITORY=layervai/nhp \
    "$SCRIPT" layerv/nhp-server "$IMAGE" "$RUN_ID" "$RUN_ATTEMPT" "$DIGEST" >/dev/null 2>&1; then
  echo "unverified legacy image was accepted as durable" >&2
  exit 1
fi

echo "verify-durable-aop-image-provenance: all tests passed"
