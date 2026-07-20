locals {
  authority_publisher_role_name          = "${local.name_prefix}-connector-authority-publisher"
  authority_publisher_github_environment = local.is_prod ? "production" : "sandbox"
  github_oidc_provider_arn               = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:oidc-provider/token.actions.githubusercontent.com"
  authority_ecr_repository_arn           = "arn:${data.aws_partition.current.partition}:ecr:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:repository/${local.authority_ecr_repository_name}"
  authority_image_digest_parameter_arn   = "arn:${data.aws_partition.current.partition}:ssm:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:parameter${local.authority_image_digest_parameter_name}"
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
