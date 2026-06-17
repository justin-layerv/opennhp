# S3 buckets for the relay ALB's access logs + Athena query results (#2623).
#
# The relay is the INTERNET-FACING knock surface (browser POST /relay/*) — the
# one component #2208 deliberately exposes so nhp-server can go private. Its
# per-request access logs are the post-incident forensics for that surface and
# CANNOT be backfilled, so they must exist before #6 routes real browser traffic
# (today the relay is dark; the dark-launch window's logs are negligible, but the
# gap becomes unrecoverable the moment real users flow).
#
# Mirrors modules/bootstrap-alb/access_logs.tf (the mechanism, not the bootstrap
# triage story). Bucket names sit under the `layerv-nhp-*` prefix so the CI
# terraform-apply role already covers them (modules/ecr S3Buckets statement) — no
# policy widening needed, unlike bootstrap-alb's `bootstrap-alb-*` project. The
# DRY extraction of this shared ALB-access-logs pattern into a module both ALBs
# consume is tracked in #2638 — until then the one real drift coupling is the ELB
# log-delivery account map, flagged inline below.
# (data.aws_region / aws_caller_identity / aws_partition are declared in main.tf.)

locals {
  # Under `layerv-nhp-*` (= var.name_prefix is `layerv-nhp-<env>`), so the CI
  # terraform-apply role's S3Buckets + S3 object statements already grant these
  # (terraform/modules/ecr/main.tf). var.account_id (not
  # data.aws_caller_identity) keeps the name known at PLAN even if module.relay
  # ever gains a caller-side depends_on — a known-after-apply name collides with
  # the prevent_destroy fence below (the cascade bootstrap-alb documents). This
  # file uses var.account_id throughout (bucket names AND the policy doc); the
  # module ALSO declares data.aws_caller_identity (compute.tf's SSM ARN). Two
  # account-id sources is intentional — don't consolidate.
  alb_access_logs_bucket_name      = "${var.name_prefix}-relay-alb-logs-${var.account_id}"
  athena_query_results_bucket_name = "${var.name_prefix}-relay-athena-${var.account_id}"

  # Regional AWS account ID for ALB access-log delivery (LEGACY method).
  # Required IN ADDITION to the modern service principal: the ALB
  # ModifyLoadBalancerAttributes synchronous test-write (run when
  # access_logs.s3.enabled flips false→true) rejects with
  # `InvalidConfigurationRequest: Access Denied for bucket` in us-east-2 when ONLY
  # the modern service principal is granted — empirically verified for
  # bootstrap-alb (its access_logs.tf carries the full evidence trail). The relay
  # ALB is in the same us-east-2 region, so this is load-bearing here too.
  #
  # DRIFT COUPLING: this map is duplicated from
  # modules/bootstrap-alb/access_logs.tf. A future region-add must touch BOTH
  # copies; the precondition on aws_s3_bucket_policy.alb_access_logs (below) fails
  # plan if the current region is unmapped, so an unmapped region surfaces at plan
  # time. Sourced from
  # https://docs.aws.amazon.com/elasticloadbalancing/latest/application/enable-access-logging.html#attach-bucket-policy
  alb_log_delivery_account_ids = {
    "us-east-1" = "127311923021"
    "us-east-2" = "033677994240"
    "us-west-1" = "027434742980"
    "us-west-2" = "797873946194"
  }

  alb_log_delivery_account_id = lookup(local.alb_log_delivery_account_ids, data.aws_region.current.id, "")
}

# ── ALB access-log bucket (the load-bearing forensics surface) ──

resource "aws_s3_bucket" "alb_access_logs" {
  bucket = local.alb_access_logs_bucket_name

  # force_destroy = false in BOTH envs — relay forensics are irrecoverable and the
  # cost asymmetry (lost attack signal vs cheap sandbox rebuild) doesn't favor
  # cheap-destroy. A sandbox teardown that genuinely needs to purge can flip this
  # true + comment out the prevent_destroy block in a one-commit PR, then revert.
  force_destroy = false

  tags = merge(local.tags, { Name = local.alb_access_logs_bucket_name })

  # Belt-and-suspenders on the forensics asymmetry: prevent_destroy blocks a
  # Terraform destroy even when the bucket is empty (which force_destroy=false
  # alone doesn't). Both fences ⇒ a deliberate teardown needs force_destroy=true
  # AND commenting this out. Prod should never touch this path.
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

  # SSE-S3 (AES256), NOT a KMS CMK — deliberate divergence from
  # docs/SECURITY.md's "all storage encrypted with KMS CMKs" default: AWS ALB
  # access-log delivery does NOT support a cross-account CMK, so the delivery
  # principal can only write to an SSE-S3 bucket. The Athena results sibling
  # follows the same shape for consistency.
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

  # BucketOwnerEnforced is REQUIRED for ALB access-log delivery; without it the
  # delivery cascades into a ModifyLoadBalancerAttributes AccessDenied.
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

# Lifecycle: hot (S3 Standard) → Glacier after the transition window. No
# expiration — relay forensics are cheap to keep at Glacier rates and high-signal
# later when investigating a long-running compromise of the internet surface.
# Same unbounded-Glacier posture as bootstrap-alb (annual cost-review nudge
# tracked at #1902); once the relay carries traffic and a volume baseline is
# observable, revisit the retention so "cheap at Glacier rates" doesn't quietly
# cover unbounded growth.
resource "aws_s3_bucket_lifecycle_configuration" "alb_access_logs" {
  bucket = aws_s3_bucket.alb_access_logs.id

  # noncurrent_version_expiration is meaningless on a versioning-disabled bucket;
  # without this explicit dependency TF may resolve them in arbitrary order on
  # first apply and the rule silently no-ops. (AWS provider known ordering pitfall.)
  depends_on = [aws_s3_bucket_versioning.alb_access_logs]

  rule {
    id     = "relay-forensics-glacier"
    status = "Enabled"

    filter {}

    transition {
      days = var.access_log_glacier_transition_days
      # GLACIER (Flexible Retrieval) over GLACIER_IR: lower at-rest cost, hours-long
      # restore. Relay forensics past the transition window are typically planned
      # investigations, not time-pressured incidents. Flip to GLACIER_IR if a
      # future IR workflow needs sub-second access to aged objects.
      storage_class = "GLACIER"
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }

    # ALB log objects use unique timestamp+UUID keys (no overwrite), so noncurrent
    # versions only appear when an operator hand-deletes an object; sweep them
    # after 90d so they don't accumulate over the bucket's multi-year lifetime.
    noncurrent_version_expiration {
      noncurrent_days = 90
    }
  }

  # Sweep orphaned delete-markers on the versioning-enabled bucket.
  rule {
    id     = "expire-orphan-delete-markers"
    status = "Enabled"

    filter {}

    expiration {
      expired_object_delete_marker = true
    }
  }
}

# Bucket policy: BOTH the modern service principal AND the legacy regional ELB
# log-delivery account.
#   - Modern (`logdelivery.elasticloadbalancing.amazonaws.com`): AWS-recommended
#     for ongoing delivery; confused-deputy guarded (SourceAccount + SourceArn).
#   - Legacy (`arn:<partition>:iam::<regional-elb-acct>:root`): what ELB uses for
#     the synchronous ModifyLoadBalancerAttributes test-write on enable. Without
#     it that modify rejects AccessDenied in us-east-2 even with the modern
#     statement present — permanently load-bearing here, not a regional fallback.
data "aws_iam_policy_document" "alb_access_logs" {
  statement {
    sid    = "ELBAccessLogsWriteService"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["logdelivery.elasticloadbalancing.amazonaws.com"]
    }

    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.alb_access_logs.arn}/AWSLogs/${var.account_id}/*"]

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.account_id]
    }

    # ALB ARN built from parts, not aws_lb.relay.arn, to avoid a cycle with
    # aws_lb.relay's depends_on = [aws_s3_bucket_policy.alb_access_logs].
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:${data.aws_partition.current.partition}:elasticloadbalancing:${data.aws_region.current.id}:${var.account_id}:loadbalancer/app/${local.alb_name}/*"]
    }
  }

  # Legacy regional ELB log-delivery account principal (the test-write path). No
  # confused-deputy conditions: the principal IS the AWS-managed ELB log-delivery
  # account, already constrained to writing on behalf of ELB itself.
  statement {
    sid    = "ELBAccessLogsWriteLegacy"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.current.partition}:iam::${local.alb_log_delivery_account_id}:root"]
    }

    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.alb_access_logs.arn}/AWSLogs/${var.account_id}/*"]
  }

  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions   = ["s3:*"]
    resources = [aws_s3_bucket.alb_access_logs.arn, "${aws_s3_bucket.alb_access_logs.arn}/*"]

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

  # PAB-before-policy: fail closed if a future statement adds a wildcard principal.
  depends_on = [aws_s3_bucket_public_access_block.alb_access_logs]

  # Fail plan (not mid-apply) when the apply region has no mapped ELB
  # log-delivery account — an empty string renders `arn:...:iam:::root` and AWS
  # rejects the policy with a generic InvalidPrincipal.
  lifecycle {
    precondition {
      condition     = local.alb_log_delivery_account_id != ""
      error_message = "No ALB log-delivery account ID mapped for region ${data.aws_region.current.id}. Add it to `local.alb_log_delivery_account_ids` in modules/relay/access_logs.tf (and modules/bootstrap-alb in lockstep), sourced from https://docs.aws.amazon.com/elasticloadbalancing/latest/application/enable-access-logging.html#attach-bucket-policy."
    }
  }
}

# ── Athena query-results bucket (derived, cheap-rebuild) ──

resource "aws_s3_bucket" "athena_query_results" {
  bucket = local.athena_query_results_bucket_name

  # Athena results ARE cheap-rebuild (re-run the query), so force_destroy = true
  # in both envs — the access-log bucket above is the load-bearing surface.
  force_destroy = true

  tags = merge(local.tags, { Name = local.athena_query_results_bucket_name })

  # No versioning (deliberate divergence from the access-log bucket): versioning
  # derived, cheap-rebuild data adds the same storage cost for no forensics gain.
  # An AWS Config s3-bucket-versioning-enabled finding here is expected — point
  # the suppression at this comment.
}

resource "aws_s3_bucket_server_side_encryption_configuration" "athena_query_results" {
  bucket = aws_s3_bucket.athena_query_results.id

  # SSE-S3, same shape as the access-log bucket (which is SSE-S3-constrained by
  # ALB delivery). Athena results are low-sensitivity derived data; a CMK would
  # add per-read KMS calls for marginal benefit.
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

data "aws_iam_policy_document" "athena_query_results" {
  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions   = ["s3:*"]
    resources = [aws_s3_bucket.athena_query_results.arn, "${aws_s3_bucket.athena_query_results.arn}/*"]

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
