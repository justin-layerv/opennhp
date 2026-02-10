# ECR Module
# Creates ECR repositories in primary account (sandbox)
# For prod account, references cross-account ECR
#
# ==================== GitHub Actions CI/CD Permissions ====================
#
# This module manages ALL GitHub Actions CI/CD IAM permissions, not just ECR.
# The GitHub Actions role created here is used by CI workflows for:
# - ECR push (container images)
# - Terraform state access (S3/DynamoDB)
# - Infrastructure deployment (EC2, ECS, CloudFront, S3, etc.)
# - QURL link static site (CloudFront, S3, ACM)
#
# This consolidation avoids circular dependencies between modules and keeps
# all CI/CD permissions in one place for easier auditing.
#
# ==================== Organization-Managed Resources ====================
#
# Some organizations manage certain IAM resources centrally via Service Control
# Policies (SCPs). This module supports both self-managed and org-managed scenarios:
#
# 1. OIDC Provider (GitHub Actions):
#    - Set `create_oidc_provider = false` if your organization manages the
#      GitHub OIDC provider centrally or if SCP blocks iam:CreateOpenIDConnectProvider
#    - When false, the module uses a data source to reference the existing provider
#
# 2. GitHub Actions IAM Role:
#    - Named `nhp-${environment}-github-actions` to support multiple environments
#    - Each environment gets its own role with appropriate permissions
#
# See terraform.tfvars for environment-specific settings.
# ============================================================================

# ==================== Variables ====================

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

variable "terraform_state_bucket" {
  description = "S3 bucket name for Terraform state (for GitHub Actions permissions)"
  type        = string
  default     = ""
}

variable "terraform_lock_table" {
  description = "DynamoDB table name for Terraform state locking"
  type        = string
  default     = "terraform-state-lock"
}

variable "secondary_account_ids" {
  description = "List of AWS account IDs that can pull from ECR (for cross-account access)"
  type        = list(string)
  default     = []
}

variable "traefik_plugins_github_repo" {
  description = "GitHub repository for traefik-plugins (e.g., 'traefik-plugins')"
  type        = string
  default     = "traefik-plugins"
}

variable "plugin_repos" {
  description = "List of GitHub repository names that can assume the GitHub Actions role to upload plugins"
  type        = list(string)
  default     = []
}

variable "plugin_bucket_arn" {
  description = "ARN of the S3 bucket for Traefik plugins (from AC module)"
  type        = string
  default     = ""
}

variable "enable_plugin_bucket_policy" {
  description = "Whether to create the plugin bucket write policy (set to true when AC module is deployed)"
  type        = bool
  default     = false
}

variable "environment" {
  description = "Environment name (sandbox, prod) - used to namespace IAM resources"
  type        = string
  default     = "sandbox"
}

variable "create_oidc_provider" {
  description = <<-EOT
    Whether to create the GitHub OIDC provider.

    Set to `false` if:
    - Your organization manages the OIDC provider centrally
    - SCP blocks iam:CreateOpenIDConnectProvider
    - The provider already exists from another deployment

    When false, the module uses a data source to reference the existing provider.
  EOT
  type        = bool
  default     = true
}

variable "deploy_qurl_ecr" {
  description = "Whether to create ECR repository for QURL service"
  type        = bool
  default     = false
}

variable "qurl_github_repo" {
  description = "GitHub repository for QURL service (for GitHub Actions trust policy)"
  type        = string
  default     = "qurl-service"
}

# ==================== Data Sources ====================

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# Data source for existing OIDC provider (used when create_oidc_provider = false)
# This allows referencing an org-managed or pre-existing OIDC provider
data "aws_iam_openid_connect_provider" "github" {
  count = var.create_oidc_provider ? 0 : 1
  url   = "https://token.actions.githubusercontent.com"
}

# ==================== Locals ====================

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.id

  # OIDC Provider ARN - either from created resource or existing data source
  # This abstraction allows the module to work in both self-managed and org-managed scenarios
  oidc_provider_arn = var.create_oidc_provider ? aws_iam_openid_connect_provider.github[0].arn : data.aws_iam_openid_connect_provider.github[0].arn

  # ECR repository names (core repos + optional QURL)
  core_ecr_repos = ["nhp-server", "nhp-ac", "nhp-console"]
  ecr_repos      = var.deploy_qurl_ecr ? concat(local.core_ecr_repos, ["nhp-qurl"]) : local.core_ecr_repos

  # ECR lifecycle policy (shared across repos)
  ecr_lifecycle_policy = jsonencode({
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

  # Cross-account ECR policy (shared across repos)
  # Note: secondary_account_ids should be passed from tfvars for cross-account pull
  ecr_cross_account_policy = length(var.secondary_account_ids) > 0 ? jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "AllowCrossAccountPull"
      Effect = "Allow"
      Principal = {
        AWS = [for account_id in var.secondary_account_ids : "arn:aws:iam::${account_id}:root"]
      }
      Action = [
        "ecr:GetDownloadUrlForLayer",
        "ecr:BatchGetImage",
        "ecr:BatchCheckLayerAvailability"
      ]
    }]
  }) : null
}

# ============================================================================
# PRIMARY ACCOUNT RESOURCES (sandbox - owns ECR)
# ============================================================================

# ECR Repositories - consolidated with for_each
resource "aws_ecr_repository" "main" {
  for_each = var.is_primary_account ? toset(local.ecr_repos) : []

  name                 = "layerv/${each.key}"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-ecr-${each.key}"
    Component = "ecr"
  })

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_ecr_lifecycle_policy" "main" {
  for_each = var.is_primary_account ? toset(local.ecr_repos) : []

  repository = aws_ecr_repository.main[each.key].name
  policy     = local.ecr_lifecycle_policy
}

# Cross-account pull policy (allows specific accounts to pull)
# Only created when secondary_account_ids is provided
resource "aws_ecr_repository_policy" "cross_account" {
  for_each = var.is_primary_account && length(var.secondary_account_ids) > 0 ? toset(local.ecr_repos) : []

  repository = aws_ecr_repository.main[each.key].name
  policy     = local.ecr_cross_account_policy
}

# ============================================================================
# GITHUB OIDC PROVIDER
# ============================================================================
#
# The OIDC provider enables GitHub Actions to authenticate with AWS using
# OpenID Connect, eliminating the need for long-lived credentials.
#
# This resource is CONDITIONAL based on `create_oidc_provider`:
# - true (default): Creates the OIDC provider in this account
# - false: Uses data source to reference existing provider (org-managed or pre-existing)
#
# Set create_oidc_provider = false when:
# - Organization SCP blocks iam:CreateOpenIDConnectProvider
# - OIDC provider is managed centrally by platform team
# - Provider already exists from another terraform workspace
# ============================================================================

resource "aws_iam_openid_connect_provider" "github" {
  count = var.create_oidc_provider ? 1 : 0

  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1", "1c58a3a8518e8759bf075b76b750d4f2df264fcd"]

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-oidc-github"
    Component = "ecr"
  })

  lifecycle {
    ignore_changes  = [thumbprint_list]
    prevent_destroy = true
  }
}

# ============================================================================
# GITHUB ACTIONS IAM ROLE
# ============================================================================
#
# Per-environment IAM role for GitHub Actions CI/CD.
# Named `nhp-${environment}-github-actions` to support parallel environments.
#
# Trust Policy:
# - Allows GitHub Actions from specified org/repo to assume this role
# - Restricts to main branch and named environments (sandbox, production)
# - Supports both nhp and traefik-plugins repositories
#
# Permissions are split across multiple inline policies due to IAM size limits.
# ============================================================================

resource "aws_iam_role" "github_actions" {
  name        = "nhp-${var.environment}-github-actions"
  description = "GitHub Actions role for ${var.github_org}/${var.github_repo} (${var.environment})"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Federated = local.oidc_provider_arn
      }
      Action = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
        }
        # Allow main branch, environment-based deployments, and pull requests for:
        # - Main NHP repo
        # - Traefik plugins repo
        # - NHP server plugin repos (nhp-plugins-passcode, nhp-plugins-oidc, etc.)
        # Environment-based: used by deploy jobs with `environment: sandbox/production`
        # Pull requests: used by terraform-validate job for PR validation
        StringLike = {
          "token.actions.githubusercontent.com:sub" = concat(
            # Main NHP repo
            [
              "repo:${var.github_org}/${var.github_repo}:ref:refs/heads/main",
              "repo:${var.github_org}/${var.github_repo}:environment:sandbox",
              "repo:${var.github_org}/${var.github_repo}:environment:production",
              "repo:${var.github_org}/${var.github_repo}:pull_request"
            ],
            # Traefik plugins repo
            var.traefik_plugins_github_repo != "" ? [
              "repo:${var.github_org}/${var.traefik_plugins_github_repo}:ref:refs/heads/main",
              "repo:${var.github_org}/${var.traefik_plugins_github_repo}:environment:sandbox",
              "repo:${var.github_org}/${var.traefik_plugins_github_repo}:environment:staging",
              "repo:${var.github_org}/${var.traefik_plugins_github_repo}:environment:production"
            ] : [],
            # NHP Server plugin repos (passcode, oidc, etc.)
            flatten([
              for repo in var.plugin_repos : [
                "repo:${var.github_org}/${repo}:ref:refs/heads/main",
                "repo:${var.github_org}/${repo}:environment:sandbox",
                "repo:${var.github_org}/${repo}:environment:production"
              ]
            ]),
            # QURL Service repo
            var.deploy_qurl_ecr && var.qurl_github_repo != "" ? [
              "repo:${var.github_org}/${var.qurl_github_repo}:ref:refs/heads/main",
              "repo:${var.github_org}/${var.qurl_github_repo}:environment:sandbox",
              "repo:${var.github_org}/${var.qurl_github_repo}:environment:production"
            ] : []
          )
        }
      }
    }]
  })

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-github-actions"
    Component = "ecr"
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
        Resource = [for repo in local.ecr_repos : aws_ecr_repository.main[repo].arn]
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
        Resource = [for repo in local.ecr_repos : "arn:aws:ecr:${local.region}:${var.primary_account_id}:repository/layerv/${repo}"]
      }
    ]
  })
}

# Terraform state permissions for GitHub Actions
resource "aws_iam_role_policy" "terraform_state" {
  count = var.terraform_state_bucket != "" ? 1 : 0

  name = "terraform-state"
  role = aws_iam_role.github_actions.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "S3StateAccess"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:ListBucket"
        ]
        Resource = [
          "arn:aws:s3:::${var.terraform_state_bucket}",
          "arn:aws:s3:::${var.terraform_state_bucket}/*"
        ]
      },
      {
        Sid    = "DynamoDBLock"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:DeleteItem"
        ]
        Resource = "arn:aws:dynamodb:${local.region}:${local.account_id}:table/${var.terraform_lock_table}"
      }
    ]
  })
}

# Context Lookups and Terraform Apply Policy
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
          "ec2:DescribeInstances",
          "ec2:DescribeTags",
          "ssm:GetParameter",
          "route53:ListHostedZones",
          "route53:ListHostedZonesByName"
        ]
        Resource = "*"
      },
      {
        Sid    = "ASGRefreshDescribe"
        Effect = "Allow"
        Action = [
          "autoscaling:DescribeInstanceRefreshes",
          "autoscaling:DescribeAutoScalingGroups"
        ]
        Resource = "*"
      },
      {
        Sid    = "ASGRefreshManage"
        Effect = "Allow"
        Action = [
          "autoscaling:StartInstanceRefresh",
          "autoscaling:CancelInstanceRefresh"
        ]
        Resource = "arn:aws:autoscaling:${local.region}:${local.account_id}:autoScalingGroup:*:autoScalingGroupName/layerv-nhp-*"
      },
      {
        Sid    = "SSMHealthCheck"
        Effect = "Allow"
        Action = [
          "ssm:SendCommand",
          "ssm:GetCommandInvocation"
        ]
        Resource = [
          "arn:aws:ec2:${local.region}:${local.account_id}:instance/*",
          "arn:aws:ssm:${local.region}::document/AWS-RunShellScript",
          "arn:aws:ssm:${local.region}:${local.account_id}:document/AWS-RunShellScript"
        ]
      }
    ]
  })
}

# Custom managed policy for Terraform read permissions
# This avoids the chicken-and-egg problem (CI can't add permissions it doesn't have)
# while following least privilege (only read access to services we use)
resource "aws_iam_policy" "terraform_read" {
  name        = "nhp-${var.environment}-github-actions-terraform-read"
  description = "Read-only permissions for Terraform to read resource state (${var.environment})"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EC2Read"
        Effect = "Allow"
        Action = [
          "ec2:Describe*",
          "ec2:Get*"
        ]
        Resource = "*"
      },
      {
        Sid    = "S3Read"
        Effect = "Allow"
        Action = [
          "s3:Get*",
          "s3:List*"
        ]
        Resource = "*"
      },
      {
        Sid    = "IAMRead"
        Effect = "Allow"
        Action = [
          "iam:Get*",
          "iam:List*"
        ]
        Resource = "*"
      },
      {
        Sid    = "Route53Read"
        Effect = "Allow"
        Action = [
          "route53:Get*",
          "route53:List*"
        ]
        Resource = "*"
      },
      {
        Sid    = "CloudWatchRead"
        Effect = "Allow"
        Action = [
          "cloudwatch:Describe*",
          "cloudwatch:Get*",
          "cloudwatch:List*",
          "logs:Describe*",
          "logs:Get*",
          "logs:List*"
        ]
        Resource = "*"
      },
      {
        Sid    = "EFSRead"
        Effect = "Allow"
        Action = [
          "elasticfilesystem:Describe*",
          "elasticfilesystem:List*"
        ]
        Resource = "*"
      },
      {
        Sid    = "LambdaRead"
        Effect = "Allow"
        Action = [
          "lambda:Get*",
          "lambda:List*"
        ]
        Resource = "*"
      },
      {
        Sid    = "AutoScalingRead"
        Effect = "Allow"
        Action = [
          "autoscaling:Describe*"
        ]
        Resource = "*"
      },
      {
        Sid    = "ELBRead"
        Effect = "Allow"
        Action = [
          "elasticloadbalancing:Describe*"
        ]
        Resource = "*"
      },
      {
        Sid    = "SSMRead"
        Effect = "Allow"
        Action = [
          "ssm:Describe*",
          "ssm:Get*",
          "ssm:List*"
        ]
        Resource = "*"
      },
      {
        Sid    = "CloudTrailRead"
        Effect = "Allow"
        Action = [
          "cloudtrail:Describe*",
          "cloudtrail:Get*",
          "cloudtrail:List*"
        ]
        Resource = "*"
      },
      {
        Sid    = "SecurityServicesRead"
        Effect = "Allow"
        Action = [
          "guardduty:Get*",
          "guardduty:List*",
          "securityhub:Describe*",
          "securityhub:Get*",
          "securityhub:List*",
          "config:Describe*",
          "config:Get*",
          "config:List*"
        ]
        Resource = "*"
      },
      {
        Sid    = "KMSRead"
        Effect = "Allow"
        Action = [
          "kms:Describe*",
          "kms:Get*",
          "kms:List*",
          "kms:Decrypt"
        ]
        Resource = "*"
      },
      {
        Sid    = "EventBridgeRead"
        Effect = "Allow"
        Action = [
          "events:Describe*",
          "events:List*"
        ]
        Resource = "*"
      },
      {
        Sid    = "RDSRead"
        Effect = "Allow"
        Action = [
          "rds:Describe*",
          "rds:List*"
        ]
        Resource = "*"
      },
      {
        Sid    = "SNSRead"
        Effect = "Allow"
        Action = [
          "sns:Get*",
          "sns:List*"
        ]
        Resource = "*"
      },
      {
        Sid    = "ACMRead"
        Effect = "Allow"
        Action = [
          "acm:Describe*",
          "acm:Get*",
          "acm:List*"
        ]
        Resource = "*"
      },
      {
        Sid    = "ServiceDiscoveryRead"
        Effect = "Allow"
        Action = [
          "servicediscovery:Get*",
          "servicediscovery:List*"
        ]
        Resource = "*"
      },
      {
        Sid    = "SecretsManagerRead"
        Effect = "Allow"
        Action = [
          "secretsmanager:Describe*",
          "secretsmanager:Get*",
          "secretsmanager:List*"
        ]
        Resource = "arn:aws:secretsmanager:${local.region}:${local.account_id}:secret:layerv-nhp-*"
      },
      {
        Sid    = "WAFRead"
        Effect = "Allow"
        Action = [
          "wafv2:Get*",
          "wafv2:List*"
        ]
        Resource = "*"
      },
      {
        Sid    = "CloudFrontRead"
        Effect = "Allow"
        Action = [
          "cloudfront:Get*",
          "cloudfront:List*"
        ]
        Resource = "*"
      },
      {
        Sid    = "ECRRead"
        Effect = "Allow"
        Action = [
          "ecr:Describe*",
          "ecr:Get*",
          "ecr:List*"
        ]
        Resource = "*"
      },
      {
        Sid    = "ECSRead"
        Effect = "Allow"
        Action = [
          "ecs:Describe*",
          "ecs:List*"
        ]
        Resource = "*"
      },
      {
        Sid    = "DynamoDBRead"
        Effect = "Allow"
        Action = [
          "dynamodb:Describe*",
          "dynamodb:List*"
        ]
        Resource = "*"
      },
      {
        # GetItem needed for terraform plan to refresh aws_dynamodb_table_item state
        Sid    = "DynamoDBGetItem"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem"
        ]
        Resource = "arn:aws:dynamodb:${local.region}:${local.account_id}:table/layerv-nhp-*"
      },
      {
        Sid    = "ChatbotRead"
        Effect = "Allow"
        Action = [
          "chatbot:Describe*",
          "chatbot:Get*",
          "chatbot:List*"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "terraform_read" {
  role       = aws_iam_role.github_actions.name
  policy_arn = aws_iam_policy.terraform_read.arn
}

# Terraform apply permissions - split into customer-managed policies
# Following AWS best practices: use managed policies instead of inline policies
# Part 1: EC2 and Networking
resource "aws_iam_policy" "terraform_apply_ec2" {
  name        = "nhp-${var.environment}-github-actions-terraform-apply-ec2"
  description = "EC2 and networking permissions for Terraform apply (${var.environment})"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EC2Write"
        Effect = "Allow"
        Action = [
          "ec2:CreateLaunchTemplate",
          "ec2:CreateLaunchTemplateVersion",
          "ec2:ModifyLaunchTemplate",
          "ec2:DeleteLaunchTemplate",
          "ec2:DeleteLaunchTemplateVersions",
          "ec2:CreateSecurityGroup",
          "ec2:DeleteSecurityGroup",
          "ec2:AuthorizeSecurityGroup*",
          "ec2:RevokeSecurityGroup*",
          "ec2:ModifySecurityGroupRules",
          "ec2:UpdateSecurityGroupRuleDescriptionsIngress",
          "ec2:UpdateSecurityGroupRuleDescriptionsEgress",
          "ec2:CreateVpc",
          "ec2:DeleteVpc",
          "ec2:ModifyVpcAttribute",
          "ec2:CreateSubnet",
          "ec2:DeleteSubnet",
          "ec2:ModifySubnetAttribute",
          "ec2:CreateRouteTable",
          "ec2:DeleteRouteTable",
          "ec2:CreateRoute",
          "ec2:DeleteRoute",
          "ec2:AssociateRouteTable",
          "ec2:DisassociateRouteTable",
          "ec2:CreateInternetGateway",
          "ec2:DeleteInternetGateway",
          "ec2:AttachInternetGateway",
          "ec2:DetachInternetGateway",
          "ec2:AllocateAddress",
          "ec2:ReleaseAddress",
          "ec2:CreateNatGateway",
          "ec2:DeleteNatGateway",
          "ec2:CreateVpcEndpoint",
          "ec2:DeleteVpcEndpoints",
          "ec2:ModifyVpcEndpoint",
          "ec2:CreateTags",
          "ec2:DeleteTags"
        ]
        Resource = "*"
      },
      {
        Sid    = "ELB"
        Effect = "Allow"
        Action = [
          "elasticloadbalancing:Create*",
          "elasticloadbalancing:Delete*",
          "elasticloadbalancing:Modify*",
          "elasticloadbalancing:Set*",
          "elasticloadbalancing:Register*",
          "elasticloadbalancing:Deregister*",
          "elasticloadbalancing:AddTags",
          "elasticloadbalancing:RemoveTags"
        ]
        Resource = "*"
      },
      {
        Sid    = "AutoScaling"
        Effect = "Allow"
        Action = [
          "autoscaling:CreateAutoScalingGroup",
          "autoscaling:UpdateAutoScalingGroup",
          "autoscaling:DeleteAutoScalingGroup",
          "autoscaling:SetDesiredCapacity",
          "autoscaling:PutScalingPolicy",
          "autoscaling:DeletePolicy",
          "autoscaling:CreateOrUpdateTags",
          "autoscaling:DeleteTags",
          "autoscaling:AttachLoadBalancerTargetGroups",
          "autoscaling:DetachLoadBalancerTargetGroups",
          "autoscaling:PutLifecycleHook",
          "autoscaling:DeleteLifecycleHook"
        ]
        Resource = "arn:aws:autoscaling:${local.region}:${local.account_id}:autoScalingGroup:*:autoScalingGroupName/layerv-nhp-*"
      },
      {
        # Required when creating ASGs that reference launch templates
        # ASG creation implicitly requires ec2:RunInstances to validate the launch template
        Sid    = "EC2RunInstancesForASG"
        Effect = "Allow"
        Action = [
          "ec2:RunInstances"
        ]
        Resource = [
          "arn:aws:ec2:${local.region}:${local.account_id}:launch-template/*",
          "arn:aws:ec2:${local.region}:${local.account_id}:instance/*",
          "arn:aws:ec2:${local.region}:${local.account_id}:volume/*",
          "arn:aws:ec2:${local.region}:${local.account_id}:network-interface/*",
          "arn:aws:ec2:${local.region}:${local.account_id}:security-group/*",
          "arn:aws:ec2:${local.region}:${local.account_id}:subnet/*",
          "arn:aws:ec2:${local.region}::image/*"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "terraform_apply_ec2" {
  role       = aws_iam_role.github_actions.name
  policy_arn = aws_iam_policy.terraform_apply_ec2.arn
}

# Part 2: IAM and Security
resource "aws_iam_policy" "terraform_apply_iam" {
  name        = "nhp-${var.environment}-github-actions-terraform-apply-iam"
  description = "IAM and security permissions for Terraform apply (${var.environment})"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "IAMRoles"
        Effect = "Allow"
        Action = [
          "iam:CreateRole",
          "iam:DeleteRole",
          "iam:UpdateRole",
          "iam:UpdateAssumeRolePolicy",
          "iam:TagRole",
          "iam:UntagRole",
          "iam:PutRolePolicy",
          "iam:DeleteRolePolicy",
          "iam:AttachRolePolicy",
          "iam:DetachRolePolicy",
          "iam:CreateInstanceProfile",
          "iam:DeleteInstanceProfile",
          "iam:AddRoleToInstanceProfile",
          "iam:RemoveRoleFromInstanceProfile",
          "iam:PassRole",
          "iam:TagOpenIDConnectProvider",
          "iam:UntagOpenIDConnectProvider"
        ]
        Resource = [
          "arn:aws:iam::${local.account_id}:role/layerv-nhp-*",
          "arn:aws:iam::${local.account_id}:role/nhp-*-github-actions",
          "arn:aws:iam::${local.account_id}:instance-profile/layerv-nhp-*",
          "arn:aws:iam::${local.account_id}:oidc-provider/*"
        ]
      },
      {
        Sid    = "IAMPolicies"
        Effect = "Allow"
        Action = [
          "iam:CreatePolicy",
          "iam:DeletePolicy",
          "iam:CreatePolicyVersion",
          "iam:DeletePolicyVersion",
          "iam:SetDefaultPolicyVersion",
          "iam:TagPolicy",
          "iam:UntagPolicy"
        ]
        Resource = [
          "arn:aws:iam::${local.account_id}:policy/nhp-*",
          "arn:aws:iam::${local.account_id}:policy/layerv-nhp-*"
        ]
      },
      {
        Sid    = "SecurityServices"
        Effect = "Allow"
        Action = [
          "guardduty:CreateDetector",
          "guardduty:DeleteDetector",
          "guardduty:UpdateDetector",
          "securityhub:EnableSecurityHub",
          "securityhub:DisableSecurityHub",
          "securityhub:EnableImportFindingsForProduct",
          "securityhub:DisableImportFindingsForProduct",
          "config:Put*",
          "config:Delete*",
          "config:Start*",
          "config:Stop*",
          "config:TagResource",
          "config:UntagResource"
        ]
        Resource = "*"
      },
      {
        Sid    = "KMS"
        Effect = "Allow"
        Action = [
          "kms:CreateKey",
          "kms:ScheduleKeyDeletion",
          "kms:CreateAlias",
          "kms:DeleteAlias",
          "kms:UpdateAlias",
          "kms:TagResource",
          "kms:UntagResource",
          "kms:PutKeyPolicy"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "terraform_apply_iam" {
  role       = aws_iam_role.github_actions.name
  policy_arn = aws_iam_policy.terraform_apply_iam.arn
}

# Part 3: Application Services
resource "aws_iam_policy" "terraform_apply_services" {
  name        = "nhp-${var.environment}-github-actions-terraform-apply-services"
  description = "Application services permissions for Terraform apply (${var.environment})"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Route53"
        Effect = "Allow"
        Action = [
          "route53:ChangeResourceRecordSets",
          "route53:CreateHostedZone",
          "route53:DeleteHostedZone",
          "route53:ChangeTagsForResource"
        ]
        Resource = "*"
      },
      {
        Sid    = "CloudWatch"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:DeleteLogGroup",
          "logs:PutRetentionPolicy",
          "logs:AssociateKmsKey",
          "logs:DisassociateKmsKey",
          "logs:TagLogGroup",
          "logs:UntagLogGroup",
          "cloudwatch:PutMetricAlarm",
          "cloudwatch:DeleteAlarms",
          "cloudwatch:PutDashboard",
          "cloudwatch:DeleteDashboards",
          "cloudwatch:TagResource",
          "cloudwatch:UntagResource"
        ]
        Resource = "*"
      },
      {
        Sid    = "SNSChatbot"
        Effect = "Allow"
        Action = [
          "sns:CreateTopic",
          "sns:DeleteTopic",
          "sns:SetTopicAttributes",
          "sns:TagResource",
          "sns:UntagResource",
          "sns:Subscribe",
          "sns:Unsubscribe",
          "chatbot:CreateSlackChannelConfiguration",
          "chatbot:UpdateSlackChannelConfiguration",
          "chatbot:DeleteSlackChannelConfiguration",
          "chatbot:TagResource",
          "chatbot:UntagResource"
        ]
        Resource = "*"
      },
      {
        Sid    = "SecretsManager"
        Effect = "Allow"
        Action = [
          "secretsmanager:CreateSecret",
          "secretsmanager:DeleteSecret",
          "secretsmanager:UpdateSecret",
          "secretsmanager:PutSecretValue",
          "secretsmanager:TagResource",
          "secretsmanager:UntagResource"
        ]
        Resource = "arn:aws:secretsmanager:${local.region}:${local.account_id}:secret:layerv-nhp-*"
      },
      {
        Sid    = "EFS"
        Effect = "Allow"
        Action = [
          "elasticfilesystem:CreateFileSystem",
          "elasticfilesystem:DeleteFileSystem",
          "elasticfilesystem:CreateMountTarget",
          "elasticfilesystem:DeleteMountTarget",
          "elasticfilesystem:CreateAccessPoint",
          "elasticfilesystem:DeleteAccessPoint",
          "elasticfilesystem:Put*",
          "elasticfilesystem:TagResource",
          "elasticfilesystem:UntagResource"
        ]
        Resource = "*"
      },
      {
        Sid    = "ServiceDiscovery"
        Effect = "Allow"
        Action = [
          "servicediscovery:CreatePrivateDnsNamespace",
          "servicediscovery:DeleteNamespace",
          "servicediscovery:CreateService",
          "servicediscovery:DeleteService",
          "servicediscovery:UpdateService",
          "servicediscovery:TagResource",
          "servicediscovery:UntagResource"
        ]
        Resource = "*"
      },
      {
        Sid    = "S3Buckets"
        Effect = "Allow"
        Action = [
          "s3:CreateBucket",
          "s3:DeleteBucket",
          "s3:PutBucketVersioning",
          "s3:PutEncryptionConfiguration",
          "s3:GetEncryptionConfiguration",
          "s3:PutBucketPublicAccessBlock",
          "s3:PutBucketTagging",
          "s3:PutBucketPolicy",
          "s3:DeleteBucketPolicy"
        ]
        Resource = "arn:aws:s3:::layerv-nhp-*"
      },
      {
        Sid    = "EventBridge"
        Effect = "Allow"
        Action = [
          "events:PutRule",
          "events:DeleteRule",
          "events:PutTargets",
          "events:RemoveTargets",
          "events:EnableRule",
          "events:DisableRule",
          "events:TagResource",
          "events:UntagResource"
        ]
        Resource = "arn:aws:events:${local.region}:${local.account_id}:rule/layerv-nhp-*"
      },
      {
        # ECR lifecycle and repository policy management for terraform-managed repos
        Sid    = "ECRManagement"
        Effect = "Allow"
        Action = [
          "ecr:PutLifecyclePolicy",
          "ecr:DeleteLifecyclePolicy",
          "ecr:SetRepositoryPolicy",
          "ecr:DeleteRepositoryPolicy"
        ]
        Resource = "arn:aws:ecr:${local.region}:${local.account_id}:repository/layerv/*"
      },
      {
        # ECS infrastructure management for terraform-managed resources
        # Note: ecs:RegisterTaskDefinition and ecs:DeregisterTaskDefinition require Resource="*"
        # per AWS API requirements (task definitions cannot be scoped by ARN at registration time)
        Sid    = "ECSInfrastructure"
        Effect = "Allow"
        Action = [
          "ecs:CreateCluster",
          "ecs:DeleteCluster",
          "ecs:UpdateCluster",
          "ecs:CreateService",
          "ecs:DeleteService",
          "ecs:UpdateService",
          "ecs:RegisterTaskDefinition",
          "ecs:DeregisterTaskDefinition",
          "ecs:TagResource",
          "ecs:UntagResource"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "terraform_apply_services" {
  role       = aws_iam_role.github_actions.name
  policy_arn = aws_iam_policy.terraform_apply_services.arn
}

# Part 4: Data Services (DynamoDB, RDS, Lambda, SSM, ACM)
resource "aws_iam_policy" "terraform_apply_data" {
  name        = "nhp-${var.environment}-github-actions-terraform-apply-data"
  description = "Data services permissions for Terraform apply (${var.environment})"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DynamoDBTables"
        Effect = "Allow"
        Action = [
          "dynamodb:CreateTable",
          "dynamodb:DeleteTable",
          "dynamodb:UpdateTable",
          "dynamodb:UpdateTimeToLive",
          "dynamodb:UpdateContinuousBackups",
          "dynamodb:TagResource",
          "dynamodb:UntagResource",
          # Item-level operations for aws_dynamodb_table_item resources
          # (e.g., seeding Console AC license in licenses table)
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:DeleteItem"
        ]
        Resource = "arn:aws:dynamodb:${local.region}:${local.account_id}:table/layerv-nhp-*"
      },
      {
        # KMS permissions for DynamoDB/RDS encryption with customer-managed keys
        # CreateGrant is required when creating DynamoDB tables with CMK encryption
        Sid    = "KMSForEncryption"
        Effect = "Allow"
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:GenerateDataKey*",
          "kms:DescribeKey",
          "kms:CreateGrant"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:CallerAccount" = local.account_id
          }
        }
      },
      {
        Sid    = "SSMACMLambda"
        Effect = "Allow"
        Action = [
          "ssm:PutParameter",
          "ssm:DeleteParameter",
          "ssm:AddTagsToResource",
          "ssm:RemoveTagsFromResource",
          "acm:RequestCertificate",
          "acm:DeleteCertificate",
          "acm:AddTagsToCertificate",
          "acm:RemoveTagsFromCertificate",
          "lambda:CreateFunction",
          "lambda:DeleteFunction",
          "lambda:UpdateFunctionCode",
          "lambda:UpdateFunctionConfiguration",
          "lambda:PutFunctionConcurrency",
          "lambda:DeleteFunctionConcurrency",
          "lambda:AddPermission",
          "lambda:RemovePermission",
          "lambda:TagResource",
          "lambda:UntagResource",
          "lambda:InvokeFunction",
          "cloudtrail:CreateTrail",
          "cloudtrail:DeleteTrail",
          "cloudtrail:UpdateTrail",
          "cloudtrail:StartLogging",
          "cloudtrail:StopLogging",
          "cloudtrail:AddTags",
          "cloudtrail:RemoveTags",
          "cloudtrail:PutEventSelectors"
        ]
        Resource = "*"
      },
      {
        Sid    = "RDS"
        Effect = "Allow"
        Action = [
          "rds:CreateDBSubnetGroup",
          "rds:DeleteDBSubnetGroup",
          "rds:ModifyDBSubnetGroup",
          "rds:CreateDBClusterParameterGroup",
          "rds:DeleteDBClusterParameterGroup",
          "rds:ModifyDBClusterParameterGroup",
          "rds:CreateDBParameterGroup",
          "rds:DeleteDBParameterGroup",
          "rds:ModifyDBParameterGroup",
          "rds:CreateDBCluster",
          "rds:DeleteDBCluster",
          "rds:ModifyDBCluster",
          "rds:CreateDBInstance",
          "rds:DeleteDBInstance",
          "rds:ModifyDBInstance",
          "rds:AddTagsToResource",
          "rds:RemoveTagsFromResource",
          "rds:EnableHttpEndpoint",
          "rds:DisableHttpEndpoint"
        ]
        Resource = [
          "arn:aws:rds:${local.region}:${local.account_id}:subgrp:layerv-nhp-*",
          "arn:aws:rds:${local.region}:${local.account_id}:cluster-pg:layerv-nhp-*",
          "arn:aws:rds:${local.region}:${local.account_id}:pg:layerv-nhp-*",
          "arn:aws:rds:${local.region}:${local.account_id}:cluster:layerv-nhp-*",
          "arn:aws:rds:${local.region}:${local.account_id}:db:layerv-nhp-*"
        ]
      },
      {
        Sid    = "LambdaLayer"
        Effect = "Allow"
        Action = [
          "lambda:PublishLayerVersion",
          "lambda:DeleteLayerVersion"
        ]
        Resource = "arn:aws:lambda:${local.region}:${local.account_id}:layer:layerv-nhp-*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "terraform_apply_data" {
  role       = aws_iam_role.github_actions.name
  policy_arn = aws_iam_policy.terraform_apply_data.arn
}

# S3 write permissions for Traefik plugins bucket
# Allows traefik-plugins repo to upload plugins to S3
resource "aws_iam_policy" "plugin_bucket_write" {
  count = var.enable_plugin_bucket_policy ? 1 : 0

  name        = "nhp-${var.environment}-github-actions-plugin-bucket-write"
  description = "S3 plugin bucket write permissions (${var.environment})"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "PluginBucketWrite"
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          var.plugin_bucket_arn,
          "${var.plugin_bucket_arn}/*"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "plugin_bucket_write" {
  count = var.enable_plugin_bucket_policy ? 1 : 0

  role       = aws_iam_role.github_actions.name
  policy_arn = aws_iam_policy.plugin_bucket_write[0].arn
}

# ECS deployment permissions for QURL service
# Allows CI to register task definitions and update ECS services
#
# Wildcard usage explanation:
# - ECSTaskDefinition uses Resource="*" because AWS requires it for ecs:RegisterTaskDefinition
#   (task definitions cannot be scoped by ARN at registration time)
# - ECSServiceDeploy uses "layerv-nhp-*-qurl-api" pattern to allow deployment across
#   environments (sandbox, prod) from the same policy
# - PassRoleForECS uses similar wildcard pattern for execution/task roles
resource "aws_iam_policy" "qurl_ecs_deploy" {
  count = var.deploy_qurl_ecr ? 1 : 0

  name        = "nhp-${var.environment}-github-actions-qurl-ecs-deploy"
  description = "ECS deployment permissions for QURL service (${var.environment})"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # Note: Resource="*" is required by AWS for ecs:RegisterTaskDefinition
        Sid    = "ECSTaskDefinition"
        Effect = "Allow"
        Action = [
          "ecs:RegisterTaskDefinition",
          "ecs:DescribeTaskDefinition",
          "ecs:DeregisterTaskDefinition"
        ]
        Resource = "*"
      },
      {
        Sid    = "ECSServiceDeploy"
        Effect = "Allow"
        Action = [
          "ecs:UpdateService",
          "ecs:DescribeServices",
          "ecs:DescribeClusters"
        ]
        Resource = [
          "arn:aws:ecs:${local.region}:${local.account_id}:cluster/layerv-nhp-*-qurl-api",
          "arn:aws:ecs:${local.region}:${local.account_id}:service/layerv-nhp-*-qurl-api/*"
        ]
      },
      {
        Sid    = "PassRoleForECS"
        Effect = "Allow"
        Action = "iam:PassRole"
        Resource = [
          "arn:aws:iam::${local.account_id}:role/layerv-nhp-*-qurl-api-*"
        ]
        Condition = {
          StringEquals = {
            "iam:PassedToService" = "ecs-tasks.amazonaws.com"
          }
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "qurl_ecs_deploy" {
  count = var.deploy_qurl_ecr ? 1 : 0

  role       = aws_iam_role.github_actions.name
  policy_arn = aws_iam_policy.qurl_ecs_deploy[0].arn
}

# QURL Link static site permissions
# Allows CI to create/manage CloudFront distribution and S3 bucket for qurl.link redirect page
#
# Wildcard usage explanation:
# - CloudFront uses Resource="*" because CloudFront resources are global and distribution
#   ARNs are not known at policy creation time. Actions are scoped to specific operations.
# - S3 bucket ARN uses wildcard pattern "layerv-nhp-*-qurl-link" to support multiple
#   environments (sandbox, prod) from the same policy structure.
# - ACM uses Resource="*" with region condition because certificate ARNs are not known
#   at policy creation time, but is scoped to us-east-1 (CloudFront requirement).
resource "aws_iam_policy" "qurl_link_static" {
  name        = "nhp-${var.environment}-github-actions-qurl-link"
  description = "CloudFront and S3 permissions for QURL link redirect page (${var.environment})"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "CloudFrontDistribution"
        Effect = "Allow"
        Action = [
          "cloudfront:CreateDistribution",
          "cloudfront:GetDistribution",
          "cloudfront:GetDistributionConfig",
          "cloudfront:UpdateDistribution",
          "cloudfront:DeleteDistribution",
          "cloudfront:TagResource",
          "cloudfront:UntagResource",
          "cloudfront:ListTagsForResource"
        ]
        Resource = "*"
      },
      {
        Sid    = "CloudFrontOriginAccessControl"
        Effect = "Allow"
        Action = [
          "cloudfront:CreateOriginAccessControl",
          "cloudfront:GetOriginAccessControl",
          "cloudfront:UpdateOriginAccessControl",
          "cloudfront:DeleteOriginAccessControl",
          "cloudfront:ListOriginAccessControls"
        ]
        Resource = "*"
      },
      {
        Sid    = "CloudFrontResponseHeadersPolicy"
        Effect = "Allow"
        Action = [
          "cloudfront:CreateResponseHeadersPolicy",
          "cloudfront:GetResponseHeadersPolicy",
          "cloudfront:UpdateResponseHeadersPolicy",
          "cloudfront:DeleteResponseHeadersPolicy",
          "cloudfront:ListResponseHeadersPolicies"
        ]
        Resource = "*"
      },
      {
        Sid    = "CloudFrontCachePolicy"
        Effect = "Allow"
        Action = [
          "cloudfront:GetCachePolicy",
          "cloudfront:ListCachePolicies"
        ]
        Resource = "*"
      },
      {
        Sid    = "S3QURLLinkBucket"
        Effect = "Allow"
        Action = [
          "s3:CreateBucket",
          "s3:DeleteBucket",
          "s3:GetBucketPolicy",
          "s3:PutBucketPolicy",
          "s3:DeleteBucketPolicy",
          "s3:GetBucketAcl",
          "s3:PutBucketAcl",
          "s3:GetBucketCORS",
          "s3:PutBucketCORS",
          "s3:GetBucketWebsite",
          "s3:PutBucketWebsite",
          "s3:DeleteBucketWebsite",
          "s3:GetBucketVersioning",
          "s3:PutBucketVersioning",
          "s3:GetBucketPublicAccessBlock",
          "s3:PutBucketPublicAccessBlock",
          "s3:GetBucketOwnershipControls",
          "s3:PutBucketOwnershipControls",
          "s3:GetEncryptionConfiguration",
          "s3:PutEncryptionConfiguration",
          "s3:GetBucketTagging",
          "s3:PutBucketTagging",
          "s3:GetBucketLogging",
          "s3:PutBucketLogging",
          "s3:ListBucket",
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:GetObjectTagging",
          "s3:PutObjectTagging",
          "s3:DeleteObjectTagging"
        ]
        Resource = [
          "arn:aws:s3:::layerv-nhp-*-qurl-link",
          "arn:aws:s3:::layerv-nhp-*-qurl-link/*"
        ]
      },
      {
        # ACM certificates for CloudFront must be in us-east-1
        Sid    = "ACMUsEast1"
        Effect = "Allow"
        Action = [
          "acm:RequestCertificate",
          "acm:DescribeCertificate",
          "acm:DeleteCertificate",
          "acm:ListCertificates",
          "acm:ListTagsForCertificate",
          "acm:AddTagsToCertificate"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = "us-east-1"
          }
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "qurl_link_static" {
  role       = aws_iam_role.github_actions.name
  policy_arn = aws_iam_policy.qurl_link_static.arn
}

# ============================================================================
# OUTPUTS - Unified interface regardless of primary/secondary account
# ============================================================================

output "server_repo_url" {
  description = "NHP Server ECR repository URL"
  value       = var.is_primary_account ? aws_ecr_repository.main["nhp-server"].repository_url : "${var.primary_account_id}.dkr.ecr.${local.region}.amazonaws.com/layerv/nhp-server"
}

output "server_repo_arn" {
  description = "NHP Server ECR repository ARN"
  value       = var.is_primary_account ? aws_ecr_repository.main["nhp-server"].arn : "arn:aws:ecr:${local.region}:${var.primary_account_id}:repository/layerv/nhp-server"
}

output "ac_repo_url" {
  description = "NHP AC ECR repository URL"
  value       = var.is_primary_account ? aws_ecr_repository.main["nhp-ac"].repository_url : "${var.primary_account_id}.dkr.ecr.${local.region}.amazonaws.com/layerv/nhp-ac"
}

output "ac_repo_arn" {
  description = "NHP AC ECR repository ARN"
  value       = var.is_primary_account ? aws_ecr_repository.main["nhp-ac"].arn : "arn:aws:ecr:${local.region}:${var.primary_account_id}:repository/layerv/nhp-ac"
}

output "console_repo_url" {
  description = "Console ECR repository URL"
  value       = var.is_primary_account ? aws_ecr_repository.main["nhp-console"].repository_url : "${var.primary_account_id}.dkr.ecr.${local.region}.amazonaws.com/layerv/nhp-console"
}

output "console_repo_arn" {
  description = "Console ECR repository ARN"
  value       = var.is_primary_account ? aws_ecr_repository.main["nhp-console"].arn : "arn:aws:ecr:${local.region}:${var.primary_account_id}:repository/layerv/nhp-console"
}

output "github_actions_role_arn" {
  description = "GitHub Actions IAM role ARN"
  value       = aws_iam_role.github_actions.arn
}

output "github_oidc_provider_arn" {
  description = "GitHub OIDC provider ARN (created or referenced from existing)"
  value       = local.oidc_provider_arn
}

output "qurl_repo_url" {
  description = "QURL Service ECR repository URL"
  value       = var.deploy_qurl_ecr && var.is_primary_account ? aws_ecr_repository.main["nhp-qurl"].repository_url : var.deploy_qurl_ecr ? "${var.primary_account_id}.dkr.ecr.${local.region}.amazonaws.com/layerv/nhp-qurl" : null
}

output "qurl_repo_arn" {
  description = "QURL Service ECR repository ARN"
  value       = var.deploy_qurl_ecr && var.is_primary_account ? aws_ecr_repository.main["nhp-qurl"].arn : var.deploy_qurl_ecr ? "arn:aws:ecr:${local.region}:${var.primary_account_id}:repository/layerv/nhp-qurl" : null
}
