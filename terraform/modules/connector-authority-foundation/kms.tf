locals {
  account_root_arn = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"
  # The KMS policy cannot reference the encrypted log-group resource without a
  # dependency cycle, so both its name and the constructed ARN share this path.
  flow_log_group_name = "/layerv/nhp/${var.environment}/control/vpc-flow-logs"
  flow_log_group_arn  = "arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:log-group:${local.flow_log_group_name}"
  kms_enable_account_iam_statement = {
    Sid    = "EnableAccountIAM"
    Effect = "Allow"
    Principal = {
      AWS = local.account_root_arn
    }
    Action   = "kms:*"
    Resource = "*"
  }
}

resource "aws_kms_key" "authority_data" {
  description             = "Connector Authority ${var.environment} data, DynamoDB, Redis, secrets, and logs"
  deletion_window_in_days = local.is_prod ? 30 : 7
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      local.kms_enable_account_iam_statement,
      {
        Sid    = "AllowControlFlowLogs"
        Effect = "Allow"
        Principal = {
          Service = "logs.${data.aws_region.current.region}.${data.aws_partition.current.dns_suffix}"
        }
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey",
          "kms:Encrypt",
          "kms:GenerateDataKey*",
          "kms:ReEncrypt*",
        ]
        Resource = "*"
        Condition = {
          ArnEquals = {
            "kms:EncryptionContext:aws:logs:arn" = local.flow_log_group_arn
          }
        }
      },
    ]
  })

  tags = merge(local.common_tags, {
    Name    = "${local.name_prefix}-authority-data"
    Purpose = "Connector Authority data encryption"
  })
}

resource "aws_kms_alias" "authority_data" {
  name          = "alias/${local.name_prefix}-authority-data"
  target_key_id = aws_kms_key.authority_data.key_id
}

resource "aws_kms_key" "qat1_signing" {
  description              = "Connector Authority ${var.environment} qat1 assignment-ticket signing key"
  deletion_window_in_days  = local.is_prod ? 30 : 7
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "ECC_NIST_P256"

  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [local.kms_enable_account_iam_statement]
  })

  tags = merge(local.common_tags, {
    Name    = "${local.name_prefix}-qat1"
    Purpose = "qat1 assignment-ticket signing"
  })
}

resource "aws_kms_alias" "qat1_signing" {
  name          = "alias/${local.name_prefix}-qat1"
  target_key_id = aws_kms_key.qat1_signing.key_id
}
