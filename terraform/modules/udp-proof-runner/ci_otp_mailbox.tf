# -----------------------------------------------------------------------------
# qURL CI OTP mailbox — a CI-readable sibling of the attended proof mailbox.
#
# qURL enrollment sends an 8-digit OTP from noreply@notify.layerv.xyz. The
# attended UDP proof already receives its copy at qurl-go@<proof domain> via
# this module's regional-singleton SES receipt rule set (otp_mailbox.tf). This
# file adds a SECOND, independent inbox — qurl-ci@<ci domain> — so qurl-go /
# qurl-service / qurl-connector integration tests can complete the OTP
# enrollment path without a human in the loop.
#
# Constraints honored:
# - SES allows exactly one ACTIVE receipt rule set per region, and this module
#   owns it (`aws_ses_receipt_rule_set.proof_otp_mailbox`). The CI rule is
#   therefore an ADDITIONAL rule in that set, appended with `after` so the
#   existing `qurl-go-account-otp` rule, its recipient, and its bucket are
#   untouched. Never create or activate a second rule set.
# - The proof mailbox bucket and SQS queue are single-consumer: the attended
#   proof deletes what it reads, so CI must not share them. The CI mailbox is
#   its own bucket, and deliberately has NO SQS queue — CI polls S3 directly
#   (ListBucket on otp/ + GetObject), which cannot steal proof messages.
# -----------------------------------------------------------------------------

locals {
  ci_otp_mailbox_recipient     = "qurl-ci@${var.ci_otp_mailbox_domain}"
  ci_otp_mailbox_bucket_name   = "${var.name_prefix}-qurl-ci-otp-mailbox"
  ci_otp_mailbox_object_prefix = "otp/"
  ci_otp_mailbox_rule_name     = "qurl-ci-account-otp"
  ci_otp_reader_role_name      = "${var.name_prefix}-qurl-ci-otp-reader"

  # The CI mailbox is a qURL CI concern hosted by this module only because the
  # module owns the regional-singleton rule set; keep its resources
  # distinguishable from the attended proof's by Purpose tag.
  ci_otp_tags = merge(local.tags, { Purpose = "qurl-ci-otp" })

  # The only repositories whose GitHub Actions workflows may read the CI OTP
  # mailbox. Condition style mirrors the `nhp-<env>-github-actions` role
  # (terraform/modules/ecr/main.tf): exact `aud` plus a StringLike list of
  # trusted-main and GitHub-Environment `sub` claims. Per the #1121 threat
  # model there is deliberately NO bare `:pull_request` claim — PR-time jobs
  # must go through an approval-gated GitHub Environment to assume even this
  # read-only role.
  ci_otp_reader_github_repositories = [
    "layervai/qurl-go",
    "layervai/qurl-service",
    "layervai/qurl-connector",
  ]
  ci_otp_reader_github_subjects = flatten([
    for repo in local.ci_otp_reader_github_repositories : [
      "repo:${repo}:ref:refs/heads/main",
      "repo:${repo}:environment:sandbox",
    ]
  ])
}

resource "aws_s3_bucket" "ci_otp_mailbox" {
  bucket        = local.ci_otp_mailbox_bucket_name
  force_destroy = false

  tags = merge(local.ci_otp_tags, { Name = local.ci_otp_mailbox_bucket_name })
}

resource "aws_s3_bucket_ownership_controls" "ci_otp_mailbox" {
  bucket = aws_s3_bucket.ci_otp_mailbox.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "ci_otp_mailbox" {
  bucket = aws_s3_bucket.ci_otp_mailbox.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "ci_otp_mailbox" {
  bucket = aws_s3_bucket.ci_otp_mailbox.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "ci_otp_mailbox" {
  bucket = aws_s3_bucket.ci_otp_mailbox.id

  rule {
    id     = "expire-ci-otp-mail"
    status = "Enabled"

    filter {
      prefix = local.ci_otp_mailbox_object_prefix
    }

    expiration {
      days = 1
    }
  }
}

resource "aws_s3_bucket_policy" "ci_otp_mailbox" {
  bucket = aws_s3_bucket.ci_otp_mailbox.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.ci_otp_mailbox.arn,
          "${aws_s3_bucket.ci_otp_mailbox.arn}/*",
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
        Resource  = "${aws_s3_bucket.ci_otp_mailbox.arn}/${local.ci_otp_mailbox_object_prefix}*"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
          ArnEquals = {
            "aws:SourceArn" = "arn:${data.aws_partition.current.partition}:ses:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:receipt-rule-set/${local.proof_mailbox_rule_set_name}:receipt-rule/${local.ci_otp_mailbox_rule_name}"
          }
        }
      },
    ]
  })
}

# Appended AFTER the existing proof rule in the SAME (already active) rule set.
# `after` pins the ordering without reordering or otherwise touching
# `aws_ses_receipt_rule.proof_otp_mailbox`; the recipients are disjoint
# domains, so neither rule can shadow the other regardless of position.
resource "aws_ses_receipt_rule" "ci_otp_mailbox" {
  name          = local.ci_otp_mailbox_rule_name
  rule_set_name = aws_ses_receipt_rule_set.proof_otp_mailbox.rule_set_name
  after         = aws_ses_receipt_rule.proof_otp_mailbox.name
  recipients    = [local.ci_otp_mailbox_recipient]
  enabled       = true
  scan_enabled  = true
  tls_policy    = "Require"

  s3_action {
    bucket_name       = aws_s3_bucket.ci_otp_mailbox.id
    object_key_prefix = local.ci_otp_mailbox_object_prefix
    position          = 1
  }

  depends_on = [
    aws_s3_bucket_ownership_controls.ci_otp_mailbox,
    aws_s3_bucket_policy.ci_otp_mailbox,
  ]
}

resource "aws_route53_record" "ci_otp_mailbox_mx" {
  zone_id = var.proof_mailbox_route53_zone_id
  name    = var.ci_otp_mailbox_domain
  type    = "MX"
  ttl     = 300
  records = ["10 inbound-smtp.${data.aws_region.current.region}.amazonaws.com"]
}

# Standalone read-only role for the qURL client repos' CI. A NEW role rather
# than a widening of any existing one: the shared `nhp-sandbox-github-actions`
# role is apply-equivalent on sandbox, and the proof runner/controller roles
# are bound to the attended proof. This role can do exactly one thing — read
# CI OTP mail under otp/ — so trusting client-repo CI with it is containable.
resource "aws_iam_role" "ci_otp_reader" {
  name        = local.ci_otp_reader_role_name
  description = "Read-only qURL CI OTP mailbox access for qurl-go, qurl-service, and qurl-connector integration tests"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = "sts:AssumeRoleWithWebIdentity"
      Principal = {
        Federated = var.github_oidc_provider_arn
      }
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
        }
        StringLike = {
          "token.actions.githubusercontent.com:sub" = local.ci_otp_reader_github_subjects
        }
      }
    }]
  })

  max_session_duration = 3600
  tags                 = local.ci_otp_tags
}

resource "aws_iam_role_policy" "ci_otp_reader" {
  name = "qurl-ci-otp-mailbox-read"
  role = aws_iam_role.ci_otp_reader.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ListExactCIOTPMailbox"
        Effect   = "Allow"
        Action   = "s3:ListBucket"
        Resource = aws_s3_bucket.ci_otp_mailbox.arn
        Condition = {
          StringLike = {
            "s3:prefix" = "${local.ci_otp_mailbox_object_prefix}*"
          }
        }
      },
      {
        Sid      = "ReadExactCIOTPMailboxObjects"
        Effect   = "Allow"
        Action   = "s3:GetObject"
        Resource = "${aws_s3_bucket.ci_otp_mailbox.arn}/${local.ci_otp_mailbox_object_prefix}*"
      },
    ]
  })
}
