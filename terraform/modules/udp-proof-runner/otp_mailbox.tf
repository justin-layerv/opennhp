locals {
  proof_account_owner_id             = "${var.name_prefix}-udp-proof"
  proof_account_credential_key_id    = "key_UdpProofOtp1"
  proof_mailbox_recipient            = "qurl-go@${var.proof_mailbox_domain}"
  proof_mailbox_bucket_name          = "${var.name_prefix}-udp-proof-otp-mailbox"
  proof_mailbox_queue_name           = "${var.name_prefix}-udp-proof-otp-mailbox"
  proof_mailbox_object_prefix        = "otp/"
  proof_mailbox_rule_set_name        = "${var.name_prefix}-udp-proof"
  proof_mailbox_rule_name            = "qurl-go-account-otp"
  proof_account_secret_name          = "${var.name_prefix}/udp-proof-account/credential"
  proof_account_secret_arn_pattern   = "arn:${data.aws_partition.current.partition}:secretsmanager:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:secret:${local.proof_account_secret_name}-*"
  proof_account_jit_secret_prefix    = "${local.jit_secret_prefix}credential/"
  proof_account_jit_arn_pattern      = "arn:${data.aws_partition.current.partition}:secretsmanager:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:secret:${local.proof_account_jit_secret_prefix}*"
  proof_account_jit_purpose          = "udp-proof-account-credential-run"
  proof_account_configured           = var.proof_account_credential_sha256 != null
  proof_account_credential_hash      = coalesce(var.proof_account_credential_sha256, "unconfigured")
  proof_account_sha_parameter_arn    = "arn:${data.aws_partition.current.partition}:ssm:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:parameter/${var.environment}/nhp/udp-proof/account-credential-sha256"
  proof_control_api_keys_table_name  = "${var.name_prefix}-control-qurl-api-keys"
  proof_control_customers_table_name = "${var.name_prefix}-control-qurl-customers"
  proof_control_api_keys_table_arn   = "arn:${data.aws_partition.current.partition}:dynamodb:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:table/${local.proof_control_api_keys_table_name}"
  proof_control_customers_table_arn  = "arn:${data.aws_partition.current.partition}:dynamodb:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:table/${local.proof_control_customers_table_name}"
}

# The stable secret container has no Terraform-managed version. An operator
# seeds one lv_test_ credential after the first apply, records only its SHA-256
# in proof_account_credential_sha256, and applies again. The plaintext therefore
# never enters Terraform state, source, GitHub inputs, or an artifact.
resource "aws_secretsmanager_secret" "proof_account_credential" {
  name                    = local.proof_account_secret_name
  description             = "Out-of-band seeded sandbox qurl-go account credential for attended UDP OTP proof"
  kms_key_id              = aws_kms_key.jit.arn
  recovery_window_in_days = 30

  tags = merge(local.tags, {
    Name    = "${var.name_prefix}-udp-proof-account-credential"
    Purpose = "udp-proof-account-credential"
  })
}

resource "aws_ssm_parameter" "proof_account_credential_sha256" {
  count = local.proof_account_configured ? 1 : 0

  name        = "/${var.environment}/nhp/udp-proof/account-credential-sha256"
  description = "Non-secret digest binding the attended UDP proof account credential"
  type        = "String"
  value       = var.proof_account_credential_sha256

  tags = local.tags
}

resource "aws_s3_bucket" "proof_otp_mailbox" {
  bucket        = local.proof_mailbox_bucket_name
  force_destroy = false

  tags = merge(local.tags, { Name = local.proof_mailbox_bucket_name })
}

resource "aws_s3_bucket_ownership_controls" "proof_otp_mailbox" {
  bucket = aws_s3_bucket.proof_otp_mailbox.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "proof_otp_mailbox" {
  bucket = aws_s3_bucket.proof_otp_mailbox.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "proof_otp_mailbox" {
  bucket = aws_s3_bucket.proof_otp_mailbox.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "proof_otp_mailbox" {
  bucket = aws_s3_bucket.proof_otp_mailbox.id

  rule {
    id     = "expire-proof-otp-mail"
    status = "Enabled"

    filter {
      prefix = local.proof_mailbox_object_prefix
    }

    expiration {
      days = 1
    }
  }
}

resource "aws_sqs_queue" "proof_otp_mailbox" {
  name                       = local.proof_mailbox_queue_name
  message_retention_seconds  = 86400
  receive_wait_time_seconds  = 20
  visibility_timeout_seconds = 60
  sqs_managed_sse_enabled    = true

  tags = merge(local.tags, { Name = local.proof_mailbox_queue_name })
}

resource "aws_sqs_queue_policy" "proof_otp_mailbox" {
  queue_url = aws_sqs_queue.proof_otp_mailbox.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "ReceiveOnlyFromProofMailboxBucket"
      Effect    = "Allow"
      Principal = { Service = "s3.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.proof_otp_mailbox.arn
      Condition = {
        ArnEquals = {
          "aws:SourceArn" = aws_s3_bucket.proof_otp_mailbox.arn
        }
        StringEquals = {
          "aws:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}

resource "aws_s3_bucket_notification" "proof_otp_mailbox" {
  bucket = aws_s3_bucket.proof_otp_mailbox.id

  queue {
    queue_arn     = aws_sqs_queue.proof_otp_mailbox.arn
    events        = ["s3:ObjectCreated:*"]
    filter_prefix = local.proof_mailbox_object_prefix
  }

  depends_on = [aws_sqs_queue_policy.proof_otp_mailbox]
}

resource "aws_s3_bucket_policy" "proof_otp_mailbox" {
  bucket = aws_s3_bucket.proof_otp_mailbox.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.proof_otp_mailbox.arn,
          "${aws_s3_bucket.proof_otp_mailbox.arn}/*",
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      },
      {
        Sid       = "AllowExactSESReceiptRule"
        Effect    = "Allow"
        Principal = { Service = "ses.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.proof_otp_mailbox.arn}/${local.proof_mailbox_object_prefix}*"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
          ArnEquals = {
            "aws:SourceArn" = "arn:${data.aws_partition.current.partition}:ses:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:receipt-rule-set/${local.proof_mailbox_rule_set_name}:receipt-rule/${local.proof_mailbox_rule_name}"
          }
        }
      },
    ]
  })
}

resource "aws_ses_receipt_rule_set" "proof_otp_mailbox" {
  rule_set_name = local.proof_mailbox_rule_set_name
}

data "external" "active_ses_receipt_rule_set" {
  program = ["bash", "${path.module}/scripts/read_active_ses_receipt_rule_set.sh"]

  query = {
    region = data.aws_region.current.region
  }

  # When the proof rule is created or changed, defer this read until apply so a
  # foreign regional singleton activated after plan is observed before this
  # module is allowed to activate its own set.
  depends_on = [aws_ses_receipt_rule.proof_otp_mailbox]
}

resource "aws_ses_receipt_rule" "proof_otp_mailbox" {
  name          = local.proof_mailbox_rule_name
  rule_set_name = aws_ses_receipt_rule_set.proof_otp_mailbox.rule_set_name
  recipients    = [local.proof_mailbox_recipient]
  enabled       = true
  scan_enabled  = true
  tls_policy    = "Require"

  s3_action {
    bucket_name       = aws_s3_bucket.proof_otp_mailbox.id
    object_key_prefix = local.proof_mailbox_object_prefix
    position          = 1
  }

  depends_on = [
    aws_s3_bucket_ownership_controls.proof_otp_mailbox,
    aws_s3_bucket_policy.proof_otp_mailbox,
  ]
}

resource "aws_ses_active_receipt_rule_set" "proof_otp_mailbox" {
  rule_set_name = aws_ses_receipt_rule_set.proof_otp_mailbox.rule_set_name

  depends_on = [aws_ses_receipt_rule.proof_otp_mailbox]

  lifecycle {
    precondition {
      condition = (
        data.external.active_ses_receipt_rule_set.result.name == "" ||
        data.external.active_ses_receipt_rule_set.result.name == local.proof_mailbox_rule_set_name
      )
      error_message = "A foreign SES receipt rule set is already active in this region; refusing to replace the regional singleton."
    }
  }
}

resource "aws_route53_record" "proof_otp_mailbox_mx" {
  zone_id = var.proof_mailbox_route53_zone_id
  name    = var.proof_mailbox_domain
  type    = "MX"
  ttl     = 300
  records = ["10 inbound-smtp.${data.aws_region.current.region}.amazonaws.com"]
}
