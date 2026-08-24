#!/usr/bin/env bash
# Resolve one ordinary NHP image tag, or verify one recovery-pinned image
# digest, and fail closed unless GitHub verifies SLSA provenance from
# build-and-push.yml at the exact source commit. Recovery callers also bind the
# attestation to one exact build run attempt; they never resolve the mutable
# source tag. The canonical record printed on stdout is safe to bind into the
# prepared-slot and cutover ledgers; a caller-supplied protocol-profile label is
# deliberately not part of this proof.

set -euo pipefail

if [[ ($# -ne 2 && $# -ne 5) || ! "$2" =~ ^[0-9a-f]{40}$ ]]; then
  echo "usage: $0 <ecr-repository> <exact-source-sha> [<build-run-id> <build-run-attempt> <exact-digest>]" >&2
  exit 2
fi

repository=$1
source_sha=$2
build_run_id=
build_run_attempt=
expected_digest=
if (( $# == 5 )); then
  build_run_id=$3
  build_run_attempt=$4
  expected_digest=$5
  [[ "$build_run_id" =~ ^[1-9][0-9]*$ && "$build_run_attempt" =~ ^[1-9][0-9]*$ &&
     "$expected_digest" =~ ^sha256:[0-9a-f]{64}$ ]] || {
    echo "recovery image authority is malformed" >&2
    exit 2
  }
fi
region=${AWS_REGION:-}
github_repository=${GITHUB_REPOSITORY:-}
: "${GH_TOKEN:?GH_TOKEN is required for strict provenance verification}"
[[ -n "$region" && "$github_repository" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || {
  echo "AWS_REGION and canonical GITHUB_REPOSITORY are required" >&2
  exit 2
}
[[ "$repository" =~ ^[A-Za-z0-9][A-Za-z0-9._/-]*$ ]] || {
  echo "ECR repository is not canonical: '$repository'" >&2
  exit 2
}

account=$(aws sts get-caller-identity --query Account --output text --region "$region")
[[ "$account" =~ ^[0-9]{12}$ ]] || { echo "AWS account id is malformed" >&2; exit 1; }
if [[ -n "$expected_digest" ]]; then
  image_details=$(aws ecr describe-images \
    --repository-name "$repository" --image-ids "imageDigest=$expected_digest" \
    --output json --region "$region")
  digest=$(jq -er --arg expected "$expected_digest" '
    if (type == "object" and (keys | sort) == ["imageDetails"] and
      (.imageDetails | type == "array" and length == 1) and
      .imageDetails[0].imageDigest == $expected)
    then $expected else empty end
  ' <<<"$image_details") || {
    echo "ECR does not contain the exact recovery digest for $repository" >&2
    exit 1
  }
else
  digest=$(aws ecr describe-images \
    --repository-name "$repository" --image-ids "imageTag=$source_sha" \
    --query 'imageDetails[0].imageDigest' --output text --region "$region")
fi
[[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || {
  echo "ECR returned a noncanonical digest for $repository:$source_sha" >&2
  exit 1
}

registry="${account}.dkr.ecr.${region}.amazonaws.com"
aws ecr get-login-password --region "$region" \
  | docker login --username AWS --password-stdin "$registry" >/dev/null

# The certificate identity binds the exact signer workflow and main ref; the
# source claims additionally bind this image to the source commit selected by
# the immutable parent workflow. Any verification/tooling error is fatal for
# this one-time hard cut.
verified=$(gh attestation verify "oci://${registry}/${repository}@${digest}" \
  --repo "$github_repository" \
  --cert-identity "https://github.com/${github_repository}/.github/workflows/build-and-push.yml@refs/heads/main" \
  --source-ref refs/heads/main --source-digest "$source_sha" \
  --format json)
# Older gh releases once returned success when no matching attestation was
# found. Require a non-empty verified result in addition to the exit status.
if [[ -n "$expected_digest" ]]; then
  invocation="https://github.com/${github_repository}/actions/runs/${build_run_id}/attempts/${build_run_attempt}"
  subject_name="${registry}/${repository}"
  digest_hex=${digest#sha256:}
  jq -e --arg invocation "$invocation" --arg source "$source_sha" \
    --arg subject "$subject_name" --arg digest "$digest_hex" '
    type == "array" and length == 1 and
    .[0].verificationResult.statement.predicateType == "https://slsa.dev/provenance/v1" and
    .[0].verificationResult.statement.predicate.runDetails.metadata.invocationId == $invocation and
    .[0].verificationResult.statement.predicate.buildDefinition.internalParameters.github.event_name == "workflow_dispatch" and
    .[0].verificationResult.statement.predicate.buildDefinition.externalParameters.workflow == {
      path:".github/workflows/build-and-push.yml",ref:"refs/heads/main",repository:"https://github.com/layervai/nhp"} and
    .[0].verificationResult.statement.predicate.buildDefinition.resolvedDependencies == [{
      digest:{gitCommit:$source},uri:"git+https://github.com/layervai/nhp@refs/heads/main"}] and
    .[0].verificationResult.statement.subject == [{name:$subject,digest:{sha256:$digest}}] and
    .[0].verificationResult.signature.certificate.runInvocationURI == $invocation
  ' >/dev/null <<<"$verified"
else
  jq -e 'type == "array" and length > 0' >/dev/null <<<"$verified"
fi

printf 'v1|%s|%s|%s\n' "$source_sha" "$repository" "$digest"
