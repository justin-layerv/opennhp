locals {
  authority_publisher_role_name          = "${local.name_prefix}-connector-authority-publisher"
  authority_publisher_github_environment = local.is_prod ? "production" : "sandbox"
  github_oidc_provider_arn               = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:oidc-provider/token.actions.githubusercontent.com"
  authority_ecr_repository_arn           = "arn:${data.aws_partition.current.partition}:ecr:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:repository/${local.authority_ecr_repository_name}"
  authority_image_digest_parameter_arn   = "arn:${data.aws_partition.current.partition}:ssm:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:parameter${local.authority_image_digest_parameter_name}"
  hub_publisher_role_name                = "${local.name_prefix}-hub-publisher"
  # Hub publication never shares the ordinary sandbox or production deployment
  # lanes. These dedicated GitHub Environments must remain main-only and require
  # human review; live readback of both rules gates carrier activation, and the
  # carrier must repeat that fail-closed preflight before every publication.
  hub_publisher_github_environment = local.is_prod ? "hub-publish-production" : "hub-publish-sandbox"
  hub_publisher_github_subject     = "repo:layervai/nhp:environment:${local.hub_publisher_github_environment}"
  hub_ecr_repository_arn           = "arn:${data.aws_partition.current.partition}:ecr:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:repository/${local.hub_ecr_repository_name}"
  hub_image_digest_parameter_arn   = "arn:${data.aws_partition.current.partition}:ssm:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:parameter${local.hub_image_digest_parameter_name}"
}

# qurl-service publishes the shared Connector Authority image through this
# dedicated role. The GitHub Environment is part of the AWS-verifiable OIDC
# subject, so an ordinary branch, pull-request, or differently named
# environment token cannot assume it. This role is deliberately separate from
# the broad NHP Terraform apply role and has no runtime authority.
resource "aws_iam_role" "authority_publisher" {
  name                 = local.authority_publisher_role_name
  description          = "qurl-service Connector Authority image publisher (${var.environment})"
  max_session_duration = 3600

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "GitHubEnvironmentPublisher"
      Effect = "Allow"
      Principal = {
        Federated = local.github_oidc_provider_arn
      }
      Action = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          "token.actions.githubusercontent.com:sub" = "repo:layervai/qurl-service:environment:${local.authority_publisher_github_environment}"
        }
      }
    }]
  })

  tags = merge(local.common_tags, {
    Name       = local.authority_publisher_role_name
    Purpose    = "Publish immutable Connector Authority images"
    SourceRepo = "layervai/qurl-service"
  })
}

resource "aws_iam_role_policy" "authority_publisher" {
  name = "publish-connector-authority"
  role = aws_iam_role.authority_publisher.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ECRAuthorization"
        Effect   = "Allow"
        Action   = "ecr:GetAuthorizationToken"
        Resource = "*"
      },
      {
        Sid    = "AuthorityRepository"
        Effect = "Allow"
        Action = [
          "ecr:BatchCheckLayerAvailability",
          "ecr:BatchGetImage",
          "ecr:CompleteLayerUpload",
          "ecr:DescribeImages",
          "ecr:GetDownloadUrlForLayer",
          "ecr:InitiateLayerUpload",
          "ecr:PutImage",
          "ecr:UploadLayerPart",
        ]
        Resource = local.authority_ecr_repository_arn
      },
      {
        Sid    = "AuthorityDigestPin"
        Effect = "Allow"
        Action = [
          "ssm:GetParameter",
          "ssm:PutParameter",
        ]
        Resource = local.authority_image_digest_parameter_arn
      },
    ]
  })
}

# NHP publishes the Hub image through a repository-specific role. It is
# deliberately separate from the broad Terraform apply role used by the
# existing server/AC/relay matrix rows.
resource "aws_iam_role" "hub_publisher" {
  name                 = local.hub_publisher_role_name
  description          = "NHP Connector Hub image publisher (${var.environment})"
  max_session_duration = 3600

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "GitHubEnvironmentPublisher"
      Effect = "Allow"
      Principal = {
        Federated = local.github_oidc_provider_arn
      }
      Action = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          "token.actions.githubusercontent.com:sub" = local.hub_publisher_github_subject
        }
      }
    }]
  })

  tags = merge(local.common_tags, {
    Name       = local.hub_publisher_role_name
    Component  = "connector-hub"
    Purpose    = "Publish immutable Connector Hub images"
    SourceRepo = "layervai/nhp"
  })
}

resource "aws_iam_role_policy" "hub_publisher" {
  name = "publish-connector-hub"
  role = aws_iam_role.hub_publisher.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ECRAuthorization"
        Effect   = "Allow"
        Action   = "ecr:GetAuthorizationToken"
        Resource = "*"
      },
      {
        Sid    = "HubRepository"
        Effect = "Allow"
        Action = [
          "ecr:BatchCheckLayerAvailability",
          "ecr:BatchGetImage",
          "ecr:CompleteLayerUpload",
          "ecr:DescribeImages",
          # The carrier must prove scan success before advancing the SSM digest
          # pin; this read-only action grants no repository mutation.
          "ecr:DescribeImageScanFindings",
          "ecr:GetDownloadUrlForLayer",
          "ecr:InitiateLayerUpload",
          "ecr:PutImage",
          "ecr:UploadLayerPart",
        ]
        Resource = local.hub_ecr_repository_arn
      },
      {
        Sid    = "HubDigestPin"
        Effect = "Allow"
        Action = [
          "ssm:GetParameter",
          "ssm:PutParameter",
        ]
        Resource = local.hub_image_digest_parameter_arn
      },
    ]
  })
}
