locals {
  flow_log_group_arn     = "arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:log-group:/layerv/nhp/${var.environment}/relay-dmz/flow"
  resolver_log_group_arn = "arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:log-group:/layerv/nhp/${var.environment}/relay-dmz/resolver"
}

# A dedicated key keeps the DMZ telemetry boundary independent from the shared
# application log key and avoids changing relay-dark production. Its service
# grant is usable only through regional CloudWatch Logs, in this account, with
# an encryption context naming one of the two DMZ log groups.
resource "aws_kms_key" "logs" {
  description             = "NHP ${var.environment} relay DMZ Flow and Resolver logs"
  deletion_window_in_days = var.environment == "prod" ? 30 : 7
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EnableAccountAdministration"
        Effect = "Allow"
        Principal = {
          AWS = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowDmzCloudWatchLogs"
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
          StringEquals = {
            "kms:CallerAccount" = data.aws_caller_identity.current.account_id
            "kms:ViaService"    = "logs.${data.aws_region.current.region}.${data.aws_partition.current.dns_suffix}"
          }
          ArnEquals = {
            "kms:EncryptionContext:aws:logs:arn" = [
              local.flow_log_group_arn,
              local.resolver_log_group_arn,
            ]
          }
        }
      },
    ]
  })

  tags = merge(local.tags, { Name = "${var.name_prefix}-relay-dmz-logs" })

  depends_on = [terraform_data.apply_role_ready]
}

resource "aws_kms_alias" "logs" {
  name          = "alias/${var.name_prefix}-relay-dmz-logs"
  target_key_id = aws_kms_key.logs.key_id
}
