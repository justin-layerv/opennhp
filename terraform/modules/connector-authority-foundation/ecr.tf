resource "aws_ecr_repository" "authority" {
  # The repository name is deliberately stable across environment accounts so
  # the publisher targets one well-known path. ECR namespaces are account-local,
  # while the environment-specific ownership remains explicit in tags and ARN.
  name                 = local.authority_ecr_repository_name
  image_tag_mutability = "IMMUTABLE"

  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.authority_data.arn
  }

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = merge(local.common_tags, {
    Name    = "${local.name_prefix}-ecr-authority"
    Purpose = "Immutable Connector Authority Lambda images"
  })

  lifecycle {
    # Preserve immutable image digests and the publisher target in sandbox too.
    # Unlike disposable sandbox table contents, deleting this repository would
    # invalidate every published digest pin and complicate rollback evidence.
    prevent_destroy = true
  }
}

resource "aws_ssm_parameter" "authority_image_digest" {
  name        = local.authority_image_digest_parameter_name
  description = "Immutable sha256 digest for the separately published Connector Authority Lambda image"
  type        = "String"
  value       = "UNPUBLISHED"

  tags = merge(local.common_tags, {
    Name    = "${local.name_prefix}-authority-image-digest"
    Purpose = "Connector Authority image pin"
  })

  lifecycle {
    # qurl-service publication owns this value after the repository exists.
    # Runtime Terraform must reject UNPUBLISHED and resolve only repo@sha256.
    ignore_changes = [value]
  }
}

# Which image runs is resolved here, deliberately apart from the reviewed
# measurement basis, and the contract states which of the two sources applies.
#
# An earlier revision sourced the digest from this parameter and ALSO compared
# the reviewed basis against it inside authority_contract_identity_valid. That
# comparison was the defect. qurl-service CI rewrites the parameter on every
# push to its main, so the moment it published, the basis no longer matched and
# identity failed closed on every open Control plan until someone hand-rolled
# the basis. The reaction was to pin the digest in the basis, which fixed the
# broken plans and created a second problem: a build could not run in sandbox
# without a commit, a review and an attended apply, so the deployed image drifted
# days behind main and sandbox could no longer measure the builds whose
# measurements the basis is supposed to record.
#
# Both symptoms had one cause: image identity was being asserted as if it were a
# capacity fact. It is not. The basis reviews concurrency, caller limits and
# startup budget -- properties measured about a build -- and none of them are
# invalidated by the digest advancing. So the digest is out of the identity
# comparison entirely, and a publish now shows up as an image_uri diff in the
# plan instead of as a validation failure.
#
# publish_parameter is for environments that are supposed to track main;
# pinned_digest keeps a named image, which is what prod uses and what sandbox
# can fall back to while bisecting a bad build. Either way the liveness proof
# below is unchanged and still fails closed: the resolved digest must exist in
# the Authority ECR repository.
data "aws_ssm_parameter" "authority_image_publish" {
  count = local.authority_runtime_contract_enabled && local.authority_image_tracks_publish ? 1 : 0

  # The known local, deliberately, not aws_ssm_parameter.authority_image_digest.name.
  # Referencing the managed resource would add a dependency edge that defers this
  # read to apply, and a digest that is unknown at plan cannot be checked by
  # authority_contract_identity_valid -- the gate would stop gating and an
  # UNPUBLISHED or malformed value would surface as an apply-time failure
  # instead of a refused plan. Both names come from the same local, so the value
  # read is the same one the resource manages. If the parameter does not exist
  # yet the read fails hard, which is the correct outcome: the runtime contract
  # is null until this foundation exists.
  name = local.authority_image_digest_parameter_name
}

# This read exists only after the exact-main evidence generator has supplied the
# complete atomic runtime contract, and disappears entirely while it is null.
data "aws_ecr_image" "authority_runtime" {
  count = local.authority_runtime_contract_enabled ? 1 : 0

  repository_name = aws_ecr_repository.authority.name
  image_digest    = local.authority_runtime_image_digest
}

locals {
  # A missing or unknown source is neither mode. It resolves to no digest and
  # authority_contract_identity_valid rejects it, so a malformed contract cannot
  # silently fall back to tracking published images.
  authority_image_source         = try(local.authority_contract_global.authority_image_source, null)
  authority_image_tracks_publish = local.authority_image_source == "publish_parameter"
  authority_image_basis_digest   = try(local.authority_contract_global.authority_image_digest, null)

  # Tracking a publisher-owned parameter means qurl-service CI decides what this
  # environment runs, without review in this repository. That is the intended
  # trade for an environment whose job is to track main; prod may not make it.
  # Named rather than inlined into authority_contract_identity_valid so it can
  # be asserted on its own -- a prod-flavoured plan fails identity for a dozen
  # unrelated reasons, so an expect_failures test there proves nothing.
  authority_image_source_permitted = !local.authority_image_tracks_publish || var.environment != "prod"

  # insecure_value, not value, and that couples the read to the parameter TYPE:
  # it is populated only for String/StringList. Were the digest parameter ever
  # recreated as a SecureString this would read null, the resolved digest would
  # fail its shape gate, and the plan would be refused -- fail-closed, but with
  # nothing pointing at the type as the cause. The managed resource above pins
  # type = "String"; keep it that way. Reading `value` instead would mark the
  # digest sensitive and make it unusable in the plan-time shape gate.
  authority_runtime_image_digest = (
    !local.authority_runtime_contract_enabled
    ? null
    : (local.authority_image_tracks_publish
      ? try(trimspace(data.aws_ssm_parameter.authority_image_publish[0].insecure_value), null)
      : local.authority_image_basis_digest
    )
  )
  authority_runtime_image_uri = local.authority_runtime_contract_enabled ? data.aws_ecr_image.authority_runtime[0].image_uri : null
}
