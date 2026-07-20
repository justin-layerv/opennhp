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
