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

# This read exists only after the exact-main evidence generator has supplied the
# complete atomic runtime contract, and disappears entirely while it is null.
#
# The DESIRED digest comes from the reviewed measurement basis, never from the
# publisher-owned SSM parameter. qurl-service's build-and-deploy workflow
# rewrites that parameter on every push to its main, so sourcing the deployed
# image from it made an unrelated repository's CI able to invalidate every nhp
# Control plan: the moment it published, the reviewed basis no longer matched
# the live parameter and authority_contract_identity_valid failed closed on
# every open Control PR until someone hand-rolled the basis. The parameter
# records what was last published; it is not an approval to deploy it.
#
# The security property is preserved and strengthened. This data source still
# fails closed unless the reviewed digest actually exists in the Authority ECR
# repository, which is the real liveness proof; the digest itself now advances
# only through a reviewed change to the in-repo basis, so no external CI can
# move what Control deploys.
data "aws_ecr_image" "authority_runtime" {
  count = local.authority_runtime_contract_enabled ? 1 : 0

  repository_name = aws_ecr_repository.authority.name
  image_digest    = local.authority_contract_global.authority_image_digest
}

locals {
  authority_runtime_image_digest = local.authority_runtime_contract_enabled ? local.authority_contract_global.authority_image_digest : null
  authority_runtime_image_uri    = local.authority_runtime_contract_enabled ? data.aws_ecr_image.authority_runtime[0].image_uri : null
}
