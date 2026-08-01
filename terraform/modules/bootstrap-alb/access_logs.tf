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
  #
  # `var.account_id` (not `data.aws_caller_identity.current.account_id`)
  # is deliberate — see `variables.tf::account_id` for the cascade
  # this avoids. tl;dr: the in-module data source defers to apply when
  # the module's caller-side `depends_on = [time_sleep…]` has a pending
  # change, which promotes the bucket name to `(known after apply)` and
  # collides with this resource's `lifecycle.prevent_destroy`.
  alb_access_logs_bucket_name      = "${local.project}-alb-logs-${var.environment}-${var.account_id}"
  athena_query_results_bucket_name = "${local.project}-athena-${var.environment}-${var.account_id}"

  # Regional AWS account ID for ALB access-log delivery (LEGACY method).
  # Required IN ADDITION to the modern service principal — the ALB
  # `ModifyLoadBalancerAttributes` synchronous test-write rejects with
  # `InvalidConfigurationRequest: Access Denied for bucket` in us-east-2
  # when ONLY the modern service principal is granted. Empirically
  # verified on the live `bootstrap-alb-sandbox` ALB after sandbox apply
  # run 26259811292: bucket policy with service-principal-only → 400
  # AccessDenied; same policy with this legacy account added → modify
  # succeeds. The d7775d15 cleanup that dropped the legacy statement
  # ("`aws_elb_service_account` is deprecated") was the regression.
  #
  # Map sourced from
  # https://docs.aws.amazon.com/elasticloadbalancing/latest/application/enable-access-logging.html#attach-bucket-policy
  # rather than the deprecated `data "aws_elb_service_account"` data
  # source (which would emit a `terraform plan` warning on the
  # aws-provider versions this repo pins). Add a new region's entry
  # here at the same time you widen `variables.tf::environment` /
  # whatever else gates region selection — the precondition on
  # `aws_s3_bucket_policy.alb_access_logs` (below) fails plan if the
  # current region isn't in this map, so an unmapped region surfaces at
  # plan time rather than mid-apply.
  alb_log_delivery_account_ids = {
    "us-east-1" = "127311923021"
    "us-east-2" = "033677994240"
    "us-west-1" = "027434742980"
    "us-west-2" = "797873946194"
  }

  alb_log_delivery_account_id = lookup(local.alb_log_delivery_account_ids, data.aws_region.current.id, "")
}

resource "aws_s3_bucket" "alb_access_logs" {
  bucket = local.alb_access_logs_bucket_name

  # `force_destroy = false` in every surviving environment. Sandbox's retirement
  # first applies a separate preparation revision with this set to true, then
  # removes the module while restoring this fence for the still-live production
  # instance.
  force_destroy = false

  tags = merge(local.tags, { Name = local.alb_access_logs_bucket_name })

  # Production bootstrap forensics are irrecoverable. Sandbox removes this
  # lifecycle rule in the separately applied preparation revision; this deletion
  # revision restores it for every surviving module instance.
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
  # divergence from docs/SECURITY.md's "NHP-Specific Security Notes →
  # All storage encrypted with KMS CMKs" guideline (search docs/SECURITY.md
  # for that exact heading). ALB access-log delivery does
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

# Bucket policy: BOTH modern service-principal AND legacy regional ELB
# log-delivery AWS-account principal. Both statements are load-bearing:
#
#   - The modern service principal (`logdelivery.elasticloadbalancing.amazonaws.com`)
#     is what AWS docs recommend for ongoing log delivery; it carries
#     the confused-deputy conditions (SourceAccount + SourceArn).
#   - The legacy AWS-account principal (`arn:<partition>:iam::<regional-elb-acct>:root`)
#     is what ELB actually uses for the synchronous `ModifyLoadBalancerAttributes`
#     test-write that runs when `access_logs.s3.enabled` flips false→true.
#     Without it, the modify call rejects with `InvalidConfigurationRequest:
#     Access Denied for bucket` in us-east-2 even though the modern
#     statement is in place. Empirically verified on the live sandbox
#     ALB after run 26259811292 — see the `alb_log_delivery_account_ids`
#     local for the full evidence trail.
#
# An earlier cleanup (d7775d15) dropped the legacy statement on the
# theory that the modern service principal was sufficient in regions
# where it was supported. That assumption holds for ONGOING delivery
# but NOT for the initial enable-attribute test write, which is what
# this module hits on every ALB recreate. The legacy statement is
# permanently load-bearing here, not a regional fallback.
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

  # Legacy regional ELB log-delivery account principal. Required for
  # the synchronous test-write at `ModifyLoadBalancerAttributes` —
  # see the header comment above. No confused-deputy conditions:
  # the principal IS the AWS-managed ELB log-delivery account, which
  # is already constrained to writing on behalf of ELB itself.
  statement {
    sid    = "ELBAccessLogsWriteLegacy"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.current.partition}:iam::${local.alb_log_delivery_account_id}:root"]
    }

    actions = ["s3:PutObject"]
    resources = [
      "${aws_s3_bucket.alb_access_logs.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*",
    ]
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

  # Fail plan, not mid-apply, when the apply target lands in a region
  # whose ELB log-delivery account ID isn't in
  # `local.alb_log_delivery_account_ids`. An empty string would
  # render `arn:aws:iam:::root` in the policy and AWS would reject
  # the policy put with a generic InvalidPrincipal — surface the
  # actionable error here instead.
  lifecycle {
    precondition {
      condition     = local.alb_log_delivery_account_id != ""
      error_message = "No ALB log-delivery account ID mapped for region ${data.aws_region.current.id}. Add the value to `local.alb_log_delivery_account_ids` in `modules/bootstrap-alb/access_logs.tf` (sourced from https://docs.aws.amazon.com/elasticloadbalancing/latest/application/enable-access-logging.html#attach-bucket-policy)."
    }
  }
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
  # divergence from docs/SECURITY.md's "All storage encrypted with KMS CMKs"
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
