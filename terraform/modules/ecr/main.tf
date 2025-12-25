# ECR Module
# Creates ECR repositories in primary account (staging)
# For prod account, references cross-account ECR

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

# ==================== Data Sources ====================

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# ==================== Locals ====================

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.name

  # ECR repository names
  ecr_repos = ["nhp-server", "nhp-ac"]

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
# PRIMARY ACCOUNT RESOURCES (staging/sandbox - owns ECR)
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
    Name = "${var.name_prefix}-${each.key}"
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
        # Allow main branch and environment-based deployments
        # Environment-based: used by deploy jobs with `environment: staging/production`
        StringLike = {
          "token.actions.githubusercontent.com:sub" = [
            "repo:${var.github_org}/${var.github_repo}:ref:refs/heads/main",
            "repo:${var.github_org}/${var.github_repo}:environment:staging",
            "repo:${var.github_org}/${var.github_repo}:environment:production"
          ]
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
        Sid      = "ASGRefreshStart"
        Effect   = "Allow"
        Action   = ["autoscaling:StartInstanceRefresh"]
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
  name        = "nhp-github-actions-terraform-read"
  description = "Read-only permissions for Terraform to read resource state"

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
          "kms:List*"
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
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "terraform_read" {
  role       = aws_iam_role.github_actions.name
  policy_arn = aws_iam_policy.terraform_read.arn
}

# Terraform apply permissions - split into inline policies due to size limits
# Part 1: EC2 and Networking
resource "aws_iam_role_policy" "terraform_apply_ec2" {
  name = "terraform-apply-ec2"
  role = aws_iam_role.github_actions.id

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
          "autoscaling:DeleteTags"
        ]
        Resource = "arn:aws:autoscaling:${local.region}:${local.account_id}:autoScalingGroup:*:autoScalingGroupName/layerv-nhp-*"
      }
    ]
  })
}

# Part 2: IAM and Security
resource "aws_iam_role_policy" "terraform_apply_iam" {
  name = "terraform-apply-iam"
  role = aws_iam_role.github_actions.id

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
          "iam:PassRole"
        ]
        Resource = [
          "arn:aws:iam::${local.account_id}:role/layerv-nhp-*",
          "arn:aws:iam::${local.account_id}:instance-profile/layerv-nhp-*"
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
          "iam:SetDefaultPolicyVersion"
        ]
        Resource = "arn:aws:iam::${local.account_id}:policy/nhp-*"
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

# Part 3: Application Services
resource "aws_iam_role_policy" "terraform_apply_services" {
  name = "terraform-apply-services"
  role = aws_iam_role.github_actions.id

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
          "lambda:AddPermission",
          "lambda:RemovePermission",
          "lambda:TagResource",
          "lambda:UntagResource",
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
      }
    ]
  })
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

output "github_actions_role_arn" {
  description = "GitHub Actions IAM role ARN"
  value       = aws_iam_role.github_actions.arn
}

output "github_oidc_provider_arn" {
  description = "GitHub OIDC provider ARN"
  value       = aws_iam_openid_connect_provider.github.arn
}
