# KMS Module
# Customer-Managed Keys for encryption at rest

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  is_prod = var.environment == "prod"
}

# KMS Key for EBS volumes
resource "aws_kms_key" "ebs" {
  description             = "NHP ${var.environment} - KMS key for EBS volume encryption"
  deletion_window_in_days = local.is_prod ? 30 : 7
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EnableRootAccount"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowAutoScalingService"
        Effect = "Allow"
        Principal = {
          Service = "autoscaling.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey",
          "kms:CreateGrant"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:CallerAccount" = data.aws_caller_identity.current.account_id
          }
        }
      },
      {
        # Required for ASG to create encrypted EBS volumes on new instances.
        # The AllowAutoScalingService statement above grants access via service
        # principal with CallerAccount condition, but ASG also needs explicit
        # grants for its service-linked role to perform CreateGrant operations
        # during instance launches with encrypted volumes.
        Sid    = "AllowAutoScalingServiceLinkedRole"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey",
          "kms:CreateGrant"
        ]
        Resource = "*"
      },
      {
        Sid    = "AllowEC2Service"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
      }
    ]
  })

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-kms-ebs"
    Component = "kms"
  })
}

resource "aws_kms_alias" "ebs" {
  name          = "alias/${var.name_prefix}-ebs"
  target_key_id = aws_kms_key.ebs.key_id
}

# KMS Key for EFS
resource "aws_kms_key" "efs" {
  description             = "NHP ${var.environment} - KMS key for EFS encryption"
  deletion_window_in_days = local.is_prod ? 30 : 7
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EnableRootAccount"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowEFSService"
        Effect = "Allow"
        Principal = {
          Service = "elasticfilesystem.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
      }
    ]
  })

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-kms-efs"
    Component = "kms"
  })
}

resource "aws_kms_alias" "efs" {
  name          = "alias/${var.name_prefix}-efs"
  target_key_id = aws_kms_key.efs.key_id
}

# KMS Key for Secrets Manager
resource "aws_kms_key" "secrets" {
  description             = "NHP ${var.environment} - KMS key for Secrets Manager encryption"
  deletion_window_in_days = local.is_prod ? 30 : 7
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EnableRootAccount"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowSecretsManagerService"
        Effect = "Allow"
        Principal = {
          Service = "secretsmanager.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:CallerAccount" = data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-kms-secrets"
    Component = "kms"
  })
}

resource "aws_kms_alias" "secrets" {
  name          = "alias/${var.name_prefix}-secrets"
  target_key_id = aws_kms_key.secrets.key_id
}

# KMS Key for CloudWatch Logs and CloudTrail
resource "aws_kms_key" "logs" {
  description             = "NHP ${var.environment} - KMS key for CloudWatch Logs and CloudTrail"
  deletion_window_in_days = local.is_prod ? 30 : 7
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EnableRootAccount"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowCloudWatchLogs"
        Effect = "Allow"
        Principal = {
          Service = "logs.${data.aws_region.current.id}.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          ArnLike = {
            "kms:EncryptionContext:aws:logs:arn" = "arn:aws:logs:${data.aws_region.current.id}:${data.aws_caller_identity.current.account_id}:*"
          }
        }
      },
      {
        Sid    = "AllowCloudTrail"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action = [
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          StringLike = {
            "kms:EncryptionContext:aws:cloudtrail:arn" = "arn:aws:cloudtrail:*:${data.aws_caller_identity.current.account_id}:trail/*"
          }
        }
      },
      {
        Sid    = "AllowCloudTrailDecrypt"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:Decrypt"
        Resource = "*"
        Condition = {
          Null = {
            "kms:EncryptionContext:aws:cloudtrail:arn" = "false"
          }
        }
      }
    ]
  })

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-kms-logs"
    Component = "kms"
  })
}

resource "aws_kms_alias" "logs" {
  name          = "alias/${var.name_prefix}-logs"
  target_key_id = aws_kms_key.logs.key_id
}

# KMS Key for RDS storage encryption
resource "aws_kms_key" "rds" {
  description             = "NHP ${var.environment} - KMS key for RDS storage encryption"
  deletion_window_in_days = local.is_prod ? 30 : 7
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EnableRootAccount"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowRDSService"
        Effect = "Allow"
        Principal = {
          Service = "rds.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey",
          "kms:CreateGrant"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:CallerAccount" = data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-kms-rds"
    Component = "kms"
  })
}

resource "aws_kms_alias" "rds" {
  name          = "alias/${var.name_prefix}-rds"
  target_key_id = aws_kms_key.rds.key_id
}

# ==================== qURL v2 Issuer Signing Key (#2769) ====================
# Asymmetric ECDSA P-256 SIGN_VERIFY key. qurl-service signs qURL v2 bootstrap
# claims with it (kms:Sign, EcdsaSha256), and its PUBLIC half seeds BOTH the
# qurl-service admission verifier and the NHP server's QURL_V2_ISSUER_TRUST_STORE
# (fetched via kms:GetPublicKey / data.aws_kms_public_key). SIGN_VERIFY +
# ECC_NIST_P256 is the exact algorithm the qurlv2 signer and both independent
# verifiers are pinned to (raw r||s, low-S, SHA-256).
#
# Gated on qurl_v2_issuer_key_enabled so envs that haven't begun the v2 rollout
# create no key. Rotation is intentionally manual: KMS does not auto-rotate
# asymmetric keys, and the `kid` embedded in the signed claims binds a specific
# key — rotating means minting a new key + adding it to the verifiers' trust
# stores, never an in-place swap. The task role gets kms:Sign/GetPublicKey via
# an IAM policy in the qurl-service module (root-account delegation in the key
# policy lets IAM grant it), matching how the encryption keys here are consumed.
resource "aws_kms_key" "qurl_v2_issuer" {
  count = var.qurl_v2_issuer_key_enabled ? 1 : 0

  description              = "NHP ${var.environment} - qURL v2 issuer signing key (ECDSA P-256)"
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "ECC_NIST_P256"
  deletion_window_in_days  = local.is_prod ? 30 : 7

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EnableRootAccount"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
    ]
  })

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-kms-qurl-v2-issuer"
    Component = "kms"
    Purpose   = "qURL v2 issuer signing"
  })
}

resource "aws_kms_alias" "qurl_v2_issuer" {
  count         = var.qurl_v2_issuer_key_enabled ? 1 : 0
  name          = "alias/${var.name_prefix}-qurl-v2-issuer"
  target_key_id = aws_kms_key.qurl_v2_issuer[0].key_id
}

# Symmetric (AES-256) CMK that envelope-encrypts SOFTWARE-custody qURL v2
# resource private keys. qurl-service calls kms:GenerateDataKey per resource to
# wrap the in-process-generated private key, and stores only the wrapped blob in
# the qurl-resource-key-material DynamoDB table. kms:Decrypt is unused by v2
# admission and deliberately NOT granted to any qurl-service principal yet — the
# grant lands with the future delegation-proof read path. A SINGLE shared key
# wraps every software resource key — that is the cost win over the per-resource
# CMKs hardware custody mints at runtime.
#
# Gated on qurl_v2_resource_keys_enabled (software is the default custody once
# the feature is on). Key rotation is enabled and safe: KMS retains prior backing
# material, so already-wrapped DEKs stay decryptable across rotations. The task-role
# grant lives in the qurl-service module (see task_qurl_v2_resource_key_envelope
# — the single authority on which actions are granted; root-account delegation
# in the key policy lets IAM grant it). This key deliberately grants no
# kms:Sign to anyone but the account root admin.
resource "aws_kms_key" "qurl_v2_resource_key_envelope" {
  count = var.qurl_v2_resource_keys_enabled ? 1 : 0

  description             = "NHP ${var.environment} - qURL v2 software-custody resource-key envelope key (AES-256)"
  deletion_window_in_days = local.is_prod ? 30 : 7
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EnableRootAccount"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
    ]
  })

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-kms-qurl-v2-resource-key-envelope"
    Component = "kms"
    Purpose   = "qURL v2 software-custody resource-key envelope encryption"
  })
}

resource "aws_kms_alias" "qurl_v2_resource_key_envelope" {
  count         = var.qurl_v2_resource_keys_enabled ? 1 : 0
  name          = "alias/${var.name_prefix}-qurl-v2-resource-key-envelope"
  target_key_id = aws_kms_key.qurl_v2_resource_key_envelope[0].key_id
}
