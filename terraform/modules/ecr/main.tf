# ECR Module
# Creates ECR repositories in primary account (staging)
# For prod account, references cross-account ECR

variable "name_prefix" {
  description = "Prefix for resource names"
  type        = string
}

variable "tags" {
  description = "Tags to apply to resources"
  type        = map(string)
  default     = {}
}

variable "github_org" {
  description = "GitHub organization"
  type        = string
  default     = "layervai"
}

variable "github_repo" {
  description = "GitHub repository"
  type        = string
  default     = "nhp"
}

variable "is_primary_account" {
  description = "Whether this is the primary account that owns ECR repositories"
  type        = bool
  default     = true
}

variable "primary_account_id" {
  description = "AWS account ID of the primary account (for cross-account ECR access)"
  type        = string
  default     = ""
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.name
}

# ============================================================================
# PRIMARY ACCOUNT RESOURCES (staging/sandbox - owns ECR)
# ============================================================================

resource "aws_ecr_repository" "server" {
  count                = var.is_primary_account ? 1 : 0
  name                 = "layerv/nhp-server"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-server"
  })

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_ecr_lifecycle_policy" "server" {
  count      = var.is_primary_account ? 1 : 0
  repository = aws_ecr_repository.server[0].name

  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Keep last 10 images"
      selection = {
        tagStatus   = "any"
        countType   = "imageCountMoreThan"
        countNumber = 10
      }
      action = {
        type = "expire"
      }
    }]
  })
}

resource "aws_ecr_repository" "ac" {
  count                = var.is_primary_account ? 1 : 0
  name                 = "layerv/nhp-ac"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-ac"
  })

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_ecr_lifecycle_policy" "ac" {
  count      = var.is_primary_account ? 1 : 0
  repository = aws_ecr_repository.ac[0].name

  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Keep last 10 images"
      selection = {
        tagStatus   = "any"
        countType   = "imageCountMoreThan"
        countNumber = 10
      }
      action = {
        type = "expire"
      }
    }]
  })
}

# Cross-account pull policy (allows prod account to pull)
resource "aws_ecr_repository_policy" "server_cross_account" {
  count      = var.is_primary_account ? 1 : 0
  repository = aws_ecr_repository.server[0].name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCrossAccountPull"
      Effect    = "Allow"
      Principal = "*"
      Action = [
        "ecr:GetDownloadUrlForLayer",
        "ecr:BatchGetImage",
        "ecr:BatchCheckLayerAvailability"
      ]
      Condition = {
        StringLike = {
          "aws:PrincipalArn" = "arn:aws:iam::*:role/*"
        }
      }
    }]
  })
}

resource "aws_ecr_repository_policy" "ac_cross_account" {
  count      = var.is_primary_account ? 1 : 0
  repository = aws_ecr_repository.ac[0].name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCrossAccountPull"
      Effect    = "Allow"
      Principal = "*"
      Action = [
        "ecr:GetDownloadUrlForLayer",
        "ecr:BatchGetImage",
        "ecr:BatchCheckLayerAvailability"
      ]
      Condition = {
        StringLike = {
          "aws:PrincipalArn" = "arn:aws:iam::*:role/*"
        }
      }
    }]
  })
}

# ============================================================================
# GITHUB OIDC - Created in EACH account
# ============================================================================

resource "aws_iam_openid_connect_provider" "github" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1", "1c58a3a8518e8759bf075b76b750d4f2df264fcd"]

  tags = merge(var.tags, {
    Name = "github-actions"
  })

  lifecycle {
    ignore_changes  = [thumbprint_list]
    prevent_destroy = true
  }
}

resource "aws_iam_role" "github_actions" {
  name        = "nhp-github-actions"
  description = "GitHub Actions role for ${var.github_org}/${var.github_repo}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Federated = aws_iam_openid_connect_provider.github.arn
      }
      Action = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
        }
        StringLike = {
          "token.actions.githubusercontent.com:sub" = "repo:${var.github_org}/${var.github_repo}:*"
        }
      }
    }]
  })

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-github-actions"
  })
}

# ECR permissions - different for primary vs secondary account
resource "aws_iam_role_policy" "ecr_push" {
  name = "ecr-push"
  role = aws_iam_role.github_actions.id

  policy = var.is_primary_account ? jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ECRAuth"
        Effect   = "Allow"
        Action   = ["ecr:GetAuthorizationToken"]
        Resource = "*"
      },
      {
        Sid    = "ECRPush"
        Effect = "Allow"
        Action = [
          "ecr:BatchCheckLayerAvailability",
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage",
          "ecr:PutImage",
          "ecr:InitiateLayerUpload",
          "ecr:UploadLayerPart",
          "ecr:CompleteLayerUpload",
          "ecr:DescribeRepositories",
          "ecr:DescribeImages"
        ]
        Resource = [
          aws_ecr_repository.server[0].arn,
          aws_ecr_repository.ac[0].arn
        ]
      }
    ]
  }) : jsonencode({
    # Secondary account - cross-account ECR pull only
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ECRAuth"
        Effect   = "Allow"
        Action   = ["ecr:GetAuthorizationToken"]
        Resource = "*"
      },
      {
        Sid    = "ECRPull"
        Effect = "Allow"
        Action = [
          "ecr:BatchCheckLayerAvailability",
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage",
          "ecr:DescribeRepositories",
          "ecr:DescribeImages"
        ]
        Resource = [
          "arn:aws:ecr:${local.region}:${var.primary_account_id}:repository/layerv/nhp-server",
          "arn:aws:ecr:${local.region}:${var.primary_account_id}:repository/layerv/nhp-ac"
        ]
      }
    ]
  })
}

# Context Lookups Policy (for CDK/Terraform plan)
resource "aws_iam_role_policy" "context_lookups" {
  name = "context-lookups"
  role = aws_iam_role.github_actions.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ContextLookups"
        Effect = "Allow"
        Action = [
          "ec2:DescribeAvailabilityZones",
          "ec2:DescribeVpcs",
          "ec2:DescribeSubnets",
          "ec2:DescribeRouteTables",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeVpcEndpoints",
          "ec2:DescribeInternetGateways",
          "ec2:DescribeNatGateways",
          "ssm:GetParameter",
          "route53:ListHostedZones",
          "route53:ListHostedZonesByName"
        ]
        Resource = "*"
      }
    ]
  })
}

# ============================================================================
# OUTPUTS - Unified interface regardless of primary/secondary account
# ============================================================================

locals {
  # ECR URLs - either from our resources or cross-account reference
  server_repo_url = var.is_primary_account ? aws_ecr_repository.server[0].repository_url : "${var.primary_account_id}.dkr.ecr.${local.region}.amazonaws.com/layerv/nhp-server"
  ac_repo_url     = var.is_primary_account ? aws_ecr_repository.ac[0].repository_url : "${var.primary_account_id}.dkr.ecr.${local.region}.amazonaws.com/layerv/nhp-ac"
  server_repo_arn = var.is_primary_account ? aws_ecr_repository.server[0].arn : "arn:aws:ecr:${local.region}:${var.primary_account_id}:repository/layerv/nhp-server"
  ac_repo_arn     = var.is_primary_account ? aws_ecr_repository.ac[0].arn : "arn:aws:ecr:${local.region}:${var.primary_account_id}:repository/layerv/nhp-ac"
}

output "server_repo_url" {
  description = "NHP Server ECR repository URL"
  value       = local.server_repo_url
}

output "server_repo_arn" {
  description = "NHP Server ECR repository ARN"
  value       = local.server_repo_arn
}

output "ac_repo_url" {
  description = "NHP AC ECR repository URL"
  value       = local.ac_repo_url
}

output "ac_repo_arn" {
  description = "NHP AC ECR repository ARN"
  value       = local.ac_repo_arn
}

output "github_actions_role_arn" {
  description = "GitHub Actions IAM role ARN"
  value       = aws_iam_role.github_actions.arn
}

output "github_oidc_provider_arn" {
  description = "GitHub OIDC provider ARN"
  value       = aws_iam_openid_connect_provider.github.arn
}
