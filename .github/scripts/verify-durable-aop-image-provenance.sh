#!/usr/bin/env bash
# Resolve one NHP image tag to its immutable ECR digest and fail closed unless
# GitHub verifies SLSA provenance from build-and-push.yml at the exact source
# commit. The canonical record printed on stdout is safe to bind into the
# prepared-slot and cutover ledgers; a caller-supplied protocol-profile label is
# deliberately not part of this proof.

set -euo pipefail

if [[ $# -ne 2 || ! "$2" =~ ^[0-9a-f]{40}$ ]]; then
  echo "usage: $0 <ecr-repository> <exact-source-sha>" >&2
  exit 2
fi

repository=$1
source_sha=$2
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
digest=$(aws ecr describe-images \
  --repository-name "$repository" --image-ids "imageTag=$source_sha" \
  --query 'imageDetails[0].imageDigest' --output text --region "$region")
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
jq -e 'type == "array" and length > 0' >/dev/null <<<"$verified"

printf 'v1|%s|%s|%s\n' "$source_sha" "$repository" "$digest"
