locals {
  # Immutable source tags remain available for rollback for as long as a
  # Control digest pin can reference them. Only failed/interrupted untagged
  # uploads are eligible for automatic cleanup.
  hub_ecr_lifecycle_policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Expire untagged Hub images after 7 days"
      selection = {
        tagStatus   = "untagged"
        countType   = "sinceImagePushed"
        countUnit   = "days"
        countNumber = 7
      }
      action = {
        type = "expire"
      }
    }]
  })
}

resource "aws_ecr_repository" "hub" {
  name                 = local.hub_ecr_repository_name
  image_tag_mutability = "IMMUTABLE"
  force_delete         = false

  # Reuse the existing environment-global Control data key. ECR owns the grants
  # it needs; the dedicated GitHub publisher receives no KMS permissions.
  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.authority_data.arn
  }

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = merge(local.common_tags, {
    Name      = "${local.name_prefix}-ecr-hub"
    Component = "connector-hub"
    Purpose   = "Immutable Connector Hub images"
  })

  lifecycle {
    # A routine sandbox teardown must not invalidate a reviewed runtime digest
    # pin or destroy the publisher's immutable audit trail.
    prevent_destroy = true
  }
}

resource "aws_ecr_lifecycle_policy" "hub" {
  repository = aws_ecr_repository.hub.name
  policy     = local.hub_ecr_lifecycle_policy
}

resource "aws_ssm_parameter" "hub_image_digest" {
  name        = local.hub_image_digest_parameter_name
  description = "Immutable sha256 digest for the separately published Connector Hub image"
  type        = "String"
  value       = "UNPUBLISHED"

  tags = merge(local.common_tags, {
    Name      = "${local.name_prefix}-hub-image-digest"
    Component = "connector-hub"
    Purpose   = "Connector Hub image pin"
  })

  lifecycle {
    # The dedicated NHP publisher owns this value after the repository exists.
    # Runtime Terraform must reject UNPUBLISHED and resolve only repo@sha256.
    ignore_changes = [value]
  }
}
