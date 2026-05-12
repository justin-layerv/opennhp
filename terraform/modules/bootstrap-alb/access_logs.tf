# S3 buckets for ALB access logs + Athena query results.
#
# Access-log bucket: 90d hot tier → Glacier transition → 90d (default,
# tunable via var) lifecycle. Versioning enabled for accidental-delete
# protection. Athena query-results bucket: separate, 30d default
# retention.
#
# **Access-log triage simplicity** is one of the load-bearing reasons
# this stack exists as distinct from `api.layerv.ai`. Mixing bootstrap
# traffic into the broader `api.layerv.ai` access-log bucket would
# mean every anomaly hunt has to filter out customer-admin / billing
# noise. The narrow surface here means the access-log bucket sees ONLY
# `/v1/agent/bootstrap` and 404-probe traffic — both of which are
# high-signal for bootstrap-attack detection.
#
# `force_destroy = false` in BOTH envs — even sandbox rebuilds should
# preserve bootstrap forensics; the cost of destroying logs is
# asymmetric (irrecoverable signal vs cheap rebuild).

# ── ALB access logs bucket ──

locals {
  # `<project>-alb-logs-<env>-<account_id>` — keeps a `*-alb-logs-*`
  # search affordance for operators inspecting S3 console across
  # multiple ALB-emitting stacks in the same account. The cosmetic
  # double `alb-` segment (from `bootstrap-alb` + `-alb-logs-`) was
  # called out in cr round 1; alternatives were considered:
  #
  #   1. `${local.project}-access-logs-...` —
  #      `bootstrap-alb-access-logs-<env>-<acct>`. Reads cleaner but
  #      breaks the `*-alb-logs-*` cross-stack search affordance.
  #   2. Drop the `${local.project}-` prefix → `alb-logs-<env>-<acct>`.
  #      Collides with bucket names from other stacks emitting ALB logs;
  #      not viable in a multi-stack account.
  #
  # Kept the original shape (option-0) to preserve the affordance.
  #
  # Naming-shape note: if a future PR adds bucket-prefix scoping
  # (`arn:aws:s3:::<project>-alb-logs-*`) to nhp's CI role in
  # `terraform/modules/ecr/`, this name fits the pattern. If we ever
  # embed `local.alb_name` verbatim (which collapses to
  # `<name>-<env>-alb-logs-<account>`), a future constrained CI role
  # would 403 every mutation because the IAM pattern's literal
  # `-alb-logs-` segment moves position.
  alb_access_logs_bucket_name      = "${local.project}-alb-logs-${var.environment}-${data.aws_caller_identity.current.account_id}"
  athena_query_results_bucket_name = "${local.project}-athena-${var.environment}-${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket" "alb_access_logs" {
  bucket = local.alb_access_logs_bucket_name

  # `force_destroy = false` in BOTH envs — bootstrap forensics are
  # irrecoverable, and the cost asymmetry of destroying logs vs
  # rebuilding the sandbox env doesn't favor cheap-destroy here. A
  # sandbox teardown that genuinely needs to purge the bucket can flip
  # this to true in a one-commit PR before the destroy plan, then revert.
  force_destroy = false

  tags = merge(local.tags, { Name = local.alb_access_logs_bucket_name })

  # Belt-and-suspenders on the forensics-asymmetry argument:
  # `prevent_destroy = true` blocks Terraform from destroying the
  # bucket even when the bucket is empty (which `force_destroy =
  # false` doesn't prevent — an operator who manually empties the
  # bucket can still destroy it without this fence). Both fences in
  # place means a deliberate sandbox teardown requires (1) flipping
  # `force_destroy = true` AND (2) commenting out this lifecycle
  # block in a one-commit PR, then reverting. Prod should never
  # touch this path.
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_versioning" "alb_access_logs" {
  bucket = aws_s3_bucket.alb_access_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "alb_access_logs" {
  bucket = aws_s3_bucket.alb_access_logs.id

  # SSE-S3 (AES256), NOT a customer-managed KMS CMK — deliberate
  # divergence from CLAUDE.md's "Security Notes → All storage
  # encrypted with KMS CMKs" guideline (search the repo-root
  # CLAUDE.md for that exact heading). ALB access-log delivery does
  # NOT support cross-account CMK (AWS limitation); same-account CMK
  # IS supported in principle, but SSE-S3 is deliberately chosen here
  # for two reasons:
  #   1. The Athena query-results sibling bucket (below) is forced to
  #      SSE-S3 because it inherits the same cross-account access
  #      pattern from Athena's CTAS / SELECT operator-side reads.
  #      Keeping both buckets on SSE-S3 lets the access-log + Athena
  #      workflow run without per-bucket KMS policy adjustments.
  #   2. Access-log data is protocol-layer (no application secrets,
  #      no PII payloads — just request line + source IP + ALB-side
  #      timing). Same-account CMK key-rotation/audit value here is
  #      marginal compared to the access-pattern complexity it adds.
  # The deny-non-TLS bucket policy (below) + bucket-level PAB are
  # the load-bearing access controls.
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "alb_access_logs" {
  bucket = aws_s3_bucket.alb_access_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "alb_access_logs" {
  bucket = aws_s3_bucket.alb_access_logs.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

# Lifecycle: 90d hot (S3 Standard) → Glacier. No expiration — bootstrap
# forensics are cheap to keep at Glacier rates and high-signal years
# later when investigating a long-running compromise. If a future
# compliance ask requires expiry, add a per-env lifecycle override.
#
# Bootstrap logs are protocol-layer (sidecar identity, geographic IPs)
# where the threat-hunt window is years — distinct from app-layer
# request logs whose triage window is bounded by operational SLOs.
#
# **Annual cost-review nudge tracked at #1902.** No automated
# revisit signal today; once the surface is live and traffic
# baseline is observable, the retention posture should be
# revisited annually so the "cheap at Glacier rates" argument
# doesn't accidentally cover unbounded volume growth.
resource "aws_s3_bucket_lifecycle_configuration" "alb_access_logs" {
  bucket = aws_s3_bucket.alb_access_logs.id

  # Lifecycle config references `noncurrent_version_expiration` which
  # is meaningless on a versioning-disabled bucket. Without this
  # explicit dependency, TF resolves them in arbitrary order on first
  # apply and a versioning-not-yet-enabled bucket would silently
  # receive a no-op rule. AWS provider docs flag this as a known
  # ordering pitfall.
  depends_on = [aws_s3_bucket_versioning.alb_access_logs]

  rule {
    id     = "bootstrap-forensics-glacier"
    status = "Enabled"

    filter {}

    transition {
      days = var.access_log_glacier_transition_days
      # `GLACIER` (Flexible Retrieval) over `GLACIER_IR` (Instant
      # Retrieval): Flexible costs less per-GB-month at rest but
      # restore is hours-long. IR is similar pricing above ~128KB
      # with sub-second retrieval. Today's posture favors retention
      # cost over retrieval latency — bootstrap forensics on objects
      # >90d old are typically planned investigations, not
      # time-pressured incidents. If a future incident-response
      # workflow needs sub-second access to objects past the
      # transition boundary, flip this to `GLACIER_IR`.
      storage_class = "GLACIER"
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }

    # ALB log objects use unique timestamp+UUID keys (no overwrite
    # path), so this rule is a no-op in steady state — noncurrent
    # versions only appear when an operator hand-deletes a log object.
    # Kept as insurance: when that does happen, sweep the noncurrent
    # version after 90d so they don't accumulate over the bucket's
    # multi-year lifetime.
    noncurrent_version_expiration {
      noncurrent_days = 90
    }
  }

  # Sweep orphaned delete-markers so they don't accumulate on a
  # versioning-enabled bucket.
  rule {
    id     = "expire-orphan-delete-markers"
    status = "Enabled"

    filter {}

    expiration {
      expired_object_delete_marker = true
    }
  }
}

# Bucket policy: modern service-principal log delivery only.
#
# Previously this policy carried a second statement using the legacy
# AWS-account principal (via `data.aws_elb_service_account`) for
# regions where the modern service principal wasn't yet available.
# That data source is deprecated upstream and emits a `terraform plan`
# warning on newer aws-provider releases. Every region this module
# currently targets (us-east-2 sandbox + prod) supports the modern
# service principal, so the legacy statement is dropped. See
# `main.tf` for the re-add path if a future region requires it.
data "aws_iam_policy_document" "alb_access_logs" {
  # Modern service-principal log delivery; confused-deputy guarded.
  statement {
    sid    = "ELBAccessLogsWriteService"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["logdelivery.elasticloadbalancing.amazonaws.com"]
    }

    actions = ["s3:PutObject"]
    resources = [
      "${aws_s3_bucket.alb_access_logs.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*",
    ]

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }

    # ALB ARN constructed from parts rather than `aws_lb.this.arn` to
    # avoid a cycle with `aws_lb`'s
    # `depends_on = [aws_s3_bucket_policy.alb_access_logs]`.
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:${data.aws_partition.current.partition}:elasticloadbalancing:${data.aws_region.current.id}:${data.aws_caller_identity.current.account_id}:loadbalancer/app/${local.alb_name}/*"]
    }
  }

  # Deny non-TLS access. Belt-and-suspenders alongside the bucket-level
  # public-access-block.
  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.alb_access_logs.arn,
      "${aws_s3_bucket.alb_access_logs.arn}/*",
    ]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "alb_access_logs" {
  bucket = aws_s3_bucket.alb_access_logs.id
  policy = data.aws_iam_policy_document.alb_access_logs.json

  # PAB-before-policy: today's policy doesn't grant public principals,
  # so `BlockPublicPolicy` (set above) wouldn't reject either way —
  # but if a future statement adds a wildcard (`*`) by mistake, PAB
  # being in place first means the policy put fails closed instead
  # of silently widening access.
  depends_on = [aws_s3_bucket_public_access_block.alb_access_logs]
}

# ── Athena query-results bucket ──
#
# Separate bucket so retention shapes can differ from the access-log
# bucket. Athena CTAS / SELECT outputs land here when an operator runs
# queries against the access-log bucket; 30d retention is fine because
# query results are derived data — re-runnable by re-executing the
# underlying query.

resource "aws_s3_bucket" "athena_query_results" {
  bucket = local.athena_query_results_bucket_name

  # Athena query results ARE cheap-rebuild (re-run the underlying
  # query). `force_destroy = true` in BOTH envs because the cost of
  # losing query results to a destroy is bounded; the underlying
  # access-log bucket is the load-bearing forensics surface.
  force_destroy = true

  tags = merge(local.tags, { Name = local.athena_query_results_bucket_name })

  # No `aws_s3_bucket_versioning` resource on this bucket — deliberate
  # divergence from the access-log bucket above (which IS versioned).
  # Versioning here would protect derived, cheap-rebuild data with
  # the same storage cost as the access-log bucket's protections, for
  # no net forensics gain. An AWS Config `s3-bucket-versioning-enabled`
  # rule that flags this resource is expected — point the suppression
  # at this comment.
}

resource "aws_s3_bucket_server_side_encryption_configuration" "athena_query_results" {
  bucket = aws_s3_bucket.athena_query_results.id

  # SSE-S3 (AES256), NOT a customer-managed KMS CMK — deliberate
  # divergence from CLAUDE.md's "All storage encrypted with KMS CMKs"
  # default. Athena query results are derived data (re-runnable from
  # the access-log bucket), low sensitivity, and operator-only
  # accessible via the bucket's IAM principal. A CMK here would add
  # per-decrypt KMS calls on every Athena read for marginal security
  # benefit. The load-bearing forensics surface (the access-log bucket)
  # is constrained to SSE-S3 by AWS — ALB log delivery does not support
  # cross-account CMKs — so this bucket follows the same shape for
  # consistency.
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "athena_query_results" {
  bucket = aws_s3_bucket.athena_query_results.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "athena_query_results" {
  bucket = aws_s3_bucket.athena_query_results.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "athena_query_results" {
  bucket = aws_s3_bucket.athena_query_results.id

  rule {
    id     = "athena-query-results-ttl"
    status = "Enabled"

    filter {}

    expiration {
      days = var.access_log_athena_query_retention_days
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }
}

# Deny-non-TLS bucket policy. Athena results don't need explicit
# write grants beyond the operator's IAM principal, so this is the
# only required statement. PAB-before-policy ordering same as the
# access-log bucket.
data "aws_iam_policy_document" "athena_query_results" {
  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.athena_query_results.arn,
      "${aws_s3_bucket.athena_query_results.arn}/*",
    ]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "athena_query_results" {
  bucket = aws_s3_bucket.athena_query_results.id
  policy = data.aws_iam_policy_document.athena_query_results.json

  depends_on = [aws_s3_bucket_public_access_block.athena_query_results]
}
