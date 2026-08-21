# =====================================================================
# Agent-OTP CI receive mailbox — SES inbound → S3 → SQS (NON-PROD)
# =====================================================================
#
# The receive half of qurl-go's OTP gate. Its end-to-end test needs a
# code that genuinely ARRIVED BY EMAIL: an OTP is only valid against the
# authority that minted it, so the loop cannot be faked hermetically. This
# gives CI a real mailbox to read.
#
# Flow: SES receives mail for the CI recipient → writes the raw MIME to S3 →
# S3 notifies SQS → the test long-polls SQS, fetches the object, parses the
# MIME, and extracts the code.
#
# WHAT THIS IS NOT: the attended UDP proof removed in #3799 had an evidence
# collector, provenance chains, signed manifests, a JIT runner broker, and
# runner-group pinning, and it ran POST-MERGE where it could never gate
# anything. None of that comes back. This is a mailbox and nothing else — the
# gate is the PR, the runner is GitHub-hosted, and no sandbox EIP, agent quota,
# or environment lock is involved.
#
# NON-PROD ONLY: fenced below the same way the CI send grant is. Production OTP
# mail must never be routed anywhere CI can read it.
#
# DEDICATED SUBDOMAIN: mail is received for a subdomain that exists only for
# this gate. The MX record lands on `ci-otp.<sender domain>`, NOT on the sender
# domain itself — putting an MX on notify.layerv.xyz would change mail routing
# for the domain that sends real customer OTPs.

locals {
  agent_otp_ci_mailbox_enabled = var.agent_otp_ci_mailbox_enabled && local.agent_otp_ses_enabled

  # Receiving subdomain, derived from the sender domain so it can never drift
  # to a different zone. Empty-safe: unused when the gate is off.
  agent_otp_ci_mailbox_domain = (
    local.agent_otp_sender_domain != "" ? "ci-otp.${local.agent_otp_sender_domain}" : ""
  )

  # The single address SES will accept mail for. The receipt rule pins this
  # exact recipient rather than the whole domain, so a stray address under the
  # subdomain is rejected at SMTP time instead of silently landing in the
  # bucket.
  agent_otp_ci_mailbox_recipient = (
    local.agent_otp_ci_mailbox_domain != "" ? "otp-gate@${local.agent_otp_ci_mailbox_domain}" : ""
  )

  agent_otp_ci_mailbox_name = "${local.name_prefix}-agent-otp-ci-mailbox"

  # Object key prefix SES files inbound mail under. The qurl-go reader rejects
  # any notification whose key escapes this prefix, so it is a contract between
  # the two repos, not a filing convention.
  agent_otp_ci_mailbox_prefix = "otp/"

  # SES inbound is region-restricted (a much shorter list than sending) and the
  # MX target is region-specific. us-east-2 is supported; the fence below keeps
  # a future region move from silently producing a mailbox that never receives.
  agent_otp_ci_mailbox_supported_regions = ["us-east-1", "us-east-2", "us-west-2", "eu-west-1"]
  agent_otp_ci_mailbox_mx_target         = "inbound-smtp.${data.aws_region.current.id}.amazonaws.com"
}

# ── Fences ──
resource "terraform_data" "agent_otp_ci_mailbox_fence" {
  count = var.agent_otp_ci_mailbox_enabled ? 1 : 0

  lifecycle {
    precondition {
      condition     = var.environment != "prod"
      error_message = "agent_otp_ci_mailbox_enabled must never be true in prod: it routes OTP mail into an S3 bucket CI can read. The qurl-go OTP gate targets sandbox only."
    }
    precondition {
      condition     = local.agent_otp_ses_enabled
      error_message = "agent_otp_ci_mailbox_enabled=true requires agent_otp_enabled=true — the receiving subdomain is derived from the OTP sender domain, which that gate configures."
    }
    precondition {
      condition     = contains(local.agent_otp_ci_mailbox_supported_regions, data.aws_region.current.id)
      error_message = "SES email RECEIVING is not available in every region. This environment's region does not support it, so the receipt rule would be created but no mail would ever arrive. Move the mailbox to a supported region or leave the gate off."
    }
    precondition {
      condition     = local.agent_otp_zone_id != null && local.agent_otp_zone_id != ""
      error_message = "agent_otp_ci_mailbox_enabled=true but no Route53 zone id resolved — the MX record has nowhere to land and SES would never be delegated the subdomain."
    }
    precondition {
      # An empty repo name yields the trust subject "repo:<org>/:pull_request",
      # which matches nothing: the role would be created and the gate could
      # never assume it.
      condition     = trimspace(var.qurl_go_github_repo) != "" && trimspace(var.github_org) != ""
      error_message = "agent_otp_ci_mailbox_enabled=true requires non-empty github_org and qurl_go_github_repo: they form the OIDC trust subject the mailbox-read role is assumed under."
    }
  }
}

# ── Mail store ──
#
# Objects here are raw emails containing live OTP codes. They are encrypted,
# private, and expire fast: the gate reads a message within seconds, and
# anything still present a day later is abandoned test mail, not something to
# retain.
resource "aws_s3_bucket" "agent_otp_ci_mailbox" {
  count = local.agent_otp_ci_mailbox_enabled ? 1 : 0

  bucket        = local.agent_otp_ci_mailbox_name
  force_destroy = true

  tags = merge(local.agent_otp_tags, {
    Name = local.agent_otp_ci_mailbox_name
  })
}

resource "aws_s3_bucket_public_access_block" "agent_otp_ci_mailbox" {
  count = local.agent_otp_ci_mailbox_enabled ? 1 : 0

  bucket                  = aws_s3_bucket.agent_otp_ci_mailbox[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "agent_otp_ci_mailbox" {
  count = local.agent_otp_ci_mailbox_enabled ? 1 : 0

  bucket = aws_s3_bucket.agent_otp_ci_mailbox[0].id

  rule {
    apply_server_side_encryption_by_default {
      # SSE-S3, not SSE-KMS: SES must be able to write here, and a KMS-encrypted
      # inbound bucket requires granting SES kms:GenerateDataKey on a key whose
      # policy then also has to admit the CI reader. The objects live for at
      # most a day and hold OTP codes for a CI-only account, so the added key
      # surface buys nothing.
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "agent_otp_ci_mailbox" {
  count = local.agent_otp_ci_mailbox_enabled ? 1 : 0

  bucket = aws_s3_bucket.agent_otp_ci_mailbox[0].id

  rule {
    id     = "expire-ci-otp-mail"
    status = "Enabled"

    filter {}

    expiration {
      days = 1
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }
}

# SES needs PutObject, pinned to this account.
#
# aws:SourceAccount, NOT the older aws:Referer: every key in a Condition block
# must be satisfied simultaneously, so each one added is another way a
# legitimate SES write can be denied -- and that denial is silent, mail simply
# never lands with no plan-time or apply-time signal.
#
# aws:SourceArn pinned to this exact receipt rule is DELIBERATELY NOT ADDED
# yet, though it would narrow the write further. When Terraform creates a
# receipt rule with an s3_action, SES runs a write-permission preflight against
# the bucket, and there is field experience of that preflight failing
# (InvalidS3Configuration: Could not write to bucket) when the policy is scoped
# to the specific rule ARN, because the verification write may not carry the
# SourceArn. Current AWS docs endorse the SourceAccount+SourceArn pair, so it
# may well work -- but this graph has never been applied anywhere, and a failed
# CreateReceiptRule blocks the deploy for everyone. The marginal protection
# SourceArn adds over SourceAccount is against someone who already holds SES
# admin in this account creating a second rule aimed at this bucket; that is a
# far smaller risk than breaking the pipeline on an unproven preflight.
#
# FOLLOW-UP: once a real apply confirms the rule creates cleanly, add
#   ArnEquals = { "aws:SourceArn" = "<receipt-rule ARN composed from locals>" }
# alongside SourceAccount. Compose it from locals, not from the receipt-rule
# resource: the rule already depends_on this policy, so a resource reference
# would close a dependency cycle.
resource "aws_s3_bucket_policy" "agent_otp_ci_mailbox" {
  count = local.agent_otp_ci_mailbox_enabled ? 1 : 0

  bucket = aws_s3_bucket.agent_otp_ci_mailbox[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowSESInboundPut"
      Effect    = "Allow"
      Principal = { Service = "ses.amazonaws.com" }
      Action    = "s3:PutObject"
      Resource  = "${aws_s3_bucket.agent_otp_ci_mailbox[0].arn}/${local.agent_otp_ci_mailbox_prefix}*"
      Condition = {
        # aws:SourceAccount, NOT the older aws:Referer idiom. See the block
        # comment above this resource for why SourceArn is deliberately absent
        # for now.
        StringEquals = {
          "aws:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}

# ── Arrival notification ──
resource "aws_sqs_queue" "agent_otp_ci_mailbox" {
  count = local.agent_otp_ci_mailbox_enabled ? 1 : 0

  name = local.agent_otp_ci_mailbox_name
  # Long enough for a gate run to fetch and parse the object, short enough that
  # a crashed run's message returns quickly for the next attempt.
  visibility_timeout_seconds = 60
  # Arrival notifications are worthless once the run that wanted them is over.
  message_retention_seconds = 3600
  sqs_managed_sse_enabled   = true

  tags = merge(local.agent_otp_tags, {
    Name = local.agent_otp_ci_mailbox_name
  })
}

resource "aws_sqs_queue_policy" "agent_otp_ci_mailbox" {
  count = local.agent_otp_ci_mailbox_enabled ? 1 : 0

  queue_url = aws_sqs_queue.agent_otp_ci_mailbox[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowMailboxBucketNotify"
      Effect    = "Allow"
      Principal = { Service = "s3.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.agent_otp_ci_mailbox[0].arn
      Condition = {
        ArnEquals    = { "aws:SourceArn" = aws_s3_bucket.agent_otp_ci_mailbox[0].arn }
        StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id }
      }
    }]
  })
}

resource "aws_s3_bucket_notification" "agent_otp_ci_mailbox" {
  count = local.agent_otp_ci_mailbox_enabled ? 1 : 0

  bucket = aws_s3_bucket.agent_otp_ci_mailbox[0].id

  queue {
    queue_arn     = aws_sqs_queue.agent_otp_ci_mailbox[0].arn
    events        = ["s3:ObjectCreated:*"]
    filter_prefix = local.agent_otp_ci_mailbox_prefix
  }

  depends_on = [aws_sqs_queue_policy.agent_otp_ci_mailbox]
}

# ── SES receiving ──
#
# Receiving requires the domain to be verified. A subdomain of an
# already-verified parent inherits that verification, but this declares its own
# identity so the delegation is explicit: the mailbox does not quietly stop
# working the day someone prunes an unrelated parent-domain identity.
#
# aws_sesv2_email_identity (v2), NOT aws_ses_domain_identity (v1), for two
# reasons: it matches the sender identity in agent_otp_ses.tf, and v1's
# VerifyDomainIdentity/DeleteIdentity are not in the apply role's granted
# action set, so a v1 identity would fail check-terraform-iam-coverage.py and
# then AccessDenied at apply.
resource "aws_sesv2_email_identity" "agent_otp_ci_mailbox" {
  count = local.agent_otp_ci_mailbox_enabled ? 1 : 0

  # Matches the sender identity next door. The mailbox requires
  # agent_otp_enabled, so a fresh stand-up can create both in one apply and
  # race the apply role's SES grants into an AccessDenied without this.
  depends_on = [time_sleep.agent_otp_ses_iam_propagation]

  email_identity = local.agent_otp_ci_mailbox_domain

  dkim_signing_attributes {
    next_signing_key_length = "RSA_2048_BIT"
  }

  tags = merge(local.agent_otp_tags, {
    Name = "${local.agent_otp_ci_mailbox_name}-identity"
  })
}

# PROVIDER — aws.route53_mgmt, matching every other aws_route53_record for the
# layerv.{ai,xyz} zones: the zone lives cross-account in layerv-mgmt and the
# default provider cannot write it.
#
# SESv2 verifies a domain identity via these DKIM CNAMEs rather than a TXT
# challenge. The mailbox never sends, so the signing keys go unused — they are
# simply how v2 proves domain ownership.
resource "aws_route53_record" "agent_otp_ci_mailbox_dkim" {
  count    = local.agent_otp_ci_mailbox_enabled ? 3 : 0
  provider = aws.route53_mgmt

  zone_id = local.agent_otp_zone_id
  name    = "${aws_sesv2_email_identity.agent_otp_ci_mailbox[0].dkim_signing_attributes[0].tokens[count.index]}._domainkey.${local.agent_otp_ci_mailbox_domain}"
  type    = "CNAME"
  ttl     = 600
  records = ["${aws_sesv2_email_identity.agent_otp_ci_mailbox[0].dkim_signing_attributes[0].tokens[count.index]}.dkim.amazonses.com"]
}

resource "aws_route53_record" "agent_otp_ci_mailbox_mx" {
  count    = local.agent_otp_ci_mailbox_enabled ? 1 : 0
  provider = aws.route53_mgmt

  zone_id = local.agent_otp_zone_id
  # The CI subdomain ONLY. An MX on the sender domain itself would change mail
  # routing for the domain that sends real customer OTPs.
  name    = local.agent_otp_ci_mailbox_domain
  type    = "MX"
  ttl     = 600
  records = ["10 ${local.agent_otp_ci_mailbox_mx_target}"]
}

resource "aws_ses_receipt_rule_set" "agent_otp_ci_mailbox" {
  count = local.agent_otp_ci_mailbox_enabled ? 1 : 0

  depends_on = [time_sleep.agent_otp_ses_iam_propagation]

  rule_set_name = local.agent_otp_ci_mailbox_name
}

# NOTE: an account has exactly ONE active receipt rule set. Activating this one
# would displace any other inbound configuration in the account. The fence
# above keeps that away from prod; in sandbox there is no other inbound mail
# (list-receipt-rule-sets was empty when this was written).
resource "aws_ses_active_receipt_rule_set" "agent_otp_ci_mailbox" {
  count = local.agent_otp_ci_mailbox_enabled ? 1 : 0

  # Activate only once the rule exists. Without this the set can go active
  # first, leaving a window where mail to the recipient has no rule behind it.
  # Harmless today (nothing sends yet), but deterministic beats harmless.
  depends_on = [aws_ses_receipt_rule.agent_otp_ci_mailbox]

  rule_set_name = aws_ses_receipt_rule_set.agent_otp_ci_mailbox[0].rule_set_name
}

resource "aws_ses_receipt_rule" "agent_otp_ci_mailbox" {
  count = local.agent_otp_ci_mailbox_enabled ? 1 : 0

  name          = local.agent_otp_ci_mailbox_name
  rule_set_name = aws_ses_receipt_rule_set.agent_otp_ci_mailbox[0].rule_set_name
  # Exactly one address, not the whole subdomain: anything else is rejected at
  # SMTP time rather than silently accumulating in the bucket.
  recipients   = [local.agent_otp_ci_mailbox_recipient]
  enabled      = true
  scan_enabled = true
  tls_policy   = "Require"

  s3_action {
    bucket_name = aws_s3_bucket.agent_otp_ci_mailbox[0].id
    # The reader refuses any notification whose object key escapes this
    # prefix, so it is part of the contract rather than cosmetic filing.
    object_key_prefix = local.agent_otp_ci_mailbox_prefix
    position          = 1
  }

  depends_on = [aws_s3_bucket_policy.agent_otp_ci_mailbox]
}

# ── CI read access ──
#
# A DEDICATED role, for the same reason the send gate has one (see
# agent_otp_ses.tf): nhp-<env>-github-actions carries terraform-apply-equivalent
# permissions on the environment, while this role is needed by both the
# pull_request gate and one protected qurl-go main-branch canary. Granting
# mailbox reads on the shared apply role would hand either caller access to all
# of the apply role's permissions.
#
# NOTE the consumer here is layervai/qurl-go, a PUBLIC repository. The existing
# pull_request OIDC subject does not encode the head repository and is therefore
# not, by itself, a fork boundary. The consumer workflow rejects fork heads
# before AWS authentication, and GitHub withholds its required repository
# secrets from fork pull_request runs. The exact subjects below have no
# environment form or wildcard; regardless of caller, the role can perform only
# the mailbox reads in the inline policy below.
resource "aws_iam_role" "qurl_go_otp_mailbox_gate" {
  count = local.agent_otp_ci_mailbox_enabled ? 1 : 0

  name = "${local.name_prefix}-qurl-go-otp-mailbox-gate"
  # ASCII ONLY. IAM validates role descriptions against a charset that excludes
  # the em dash (U+2014). Terraform plans such a description cleanly and
  # CreateRole then fails at apply, which is how the sibling send-gate role
  # broke main. Keep punctuation in this string to plain ASCII.
  # Keep the existing description byte-for-byte so this rollout changes only
  # the trust document. Its "Per-PR" label predates the protected main canary.
  description = "Per-PR OTP registration gate for ${var.github_org}/${var.qurl_go_github_repo} - drains the CI mailbox queue and reads its messages, nothing else"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = module.ecr.github_oidc_provider_arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          "token.actions.githubusercontent.com:sub" = [
            "repo:${var.github_org}/${var.qurl_go_github_repo}:pull_request",
            "repo:${var.github_org}/${var.qurl_go_github_repo}:ref:refs/heads/main",
          ]
        }
      }
    }]
  })

  depends_on = [terraform_data.agent_otp_ci_mailbox_fence]

  tags = merge(local.agent_otp_tags, {
    Name = "${local.name_prefix}-qurl-go-otp-mailbox-gate"
  })
}

# Scoped to this queue and this bucket; no list, no write, no bucket delete.
resource "aws_iam_role_policy" "qurl_go_otp_mailbox_gate" {
  count = local.agent_otp_ci_mailbox_enabled ? 1 : 0

  name = "agent-otp-ci-mailbox-read"
  role = aws_iam_role.qurl_go_otp_mailbox_gate[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AgentOTPCIMailboxDrainQueue"
        Effect = "Allow"
        # No sqs:GetQueueUrl — the gate is handed the queue URL directly as
        # configuration, so it never has to look one up by name.
        Action = [
          "sqs:ReceiveMessage",
          "sqs:DeleteMessage",
          "sqs:GetQueueAttributes",
        ]
        Resource = [aws_sqs_queue.agent_otp_ci_mailbox[0].arn]
      },
      {
        Sid    = "AgentOTPCIMailboxReadMessage"
        Effect = "Allow"
        Action = ["s3:GetObject"]
        # Prefix-scoped, matching the contract the reader enforces: it rejects
        # any notification whose key escapes otp/, so nothing outside that
        # prefix is ever legitimately fetched.
        Resource = ["${aws_s3_bucket.agent_otp_ci_mailbox[0].arn}/${local.agent_otp_ci_mailbox_prefix}*"]
      },
    ]
  })
}

# ── Outputs consumed by the qurl-go gate ──
#
# qurl-go is a PUBLIC repository, so it must not carry these values as
# literals. They are surfaced here and injected into that workflow as
# configuration.
output "agent_otp_ci_mailbox_queue_url" {
  description = "SQS queue the qurl-go OTP gate long-polls for mail arrival notifications."
  value       = local.agent_otp_ci_mailbox_enabled ? aws_sqs_queue.agent_otp_ci_mailbox[0].url : ""
}

output "agent_otp_ci_mailbox_bucket" {
  description = "S3 bucket holding raw inbound OTP messages for the qurl-go gate."
  value       = local.agent_otp_ci_mailbox_enabled ? aws_s3_bucket.agent_otp_ci_mailbox[0].id : ""
}

output "agent_otp_ci_mailbox_recipient" {
  description = "The only address SES accepts CI OTP mail for."
  # Gated like the other two. The bare local derives from the sender domain
  # alone, so an env with agent_otp_enabled=true but the mailbox OFF would
  # otherwise publish a live-looking otp-gate@ci-otp.<domain> address for a
  # mailbox that was never created. The gate consumes these three as a set;
  # they must appear and disappear together.
  value = local.agent_otp_ci_mailbox_enabled ? local.agent_otp_ci_mailbox_recipient : ""
}

output "qurl_go_otp_mailbox_gate_role_arn" {
  description = "Role the qurl-go pull-request gate and protected main canary assume. Minimal by construction: drain the CI mailbox queue and read its messages, nothing else."
  value       = local.agent_otp_ci_mailbox_enabled ? aws_iam_role.qurl_go_otp_mailbox_gate[0].arn : ""
}
