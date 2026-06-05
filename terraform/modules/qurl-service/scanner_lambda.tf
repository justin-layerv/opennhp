# qurl-scanner Lambda — scheduled EventBridge-driven scan of the qURL
# time-bucket-index GSI.
#
# The Lambda runs the same `cmd/qurl-scanner` binary the CLI uses, packaged
# as a container image (`provided.al2023` base) published by qurl-service
# CI into the `layerv/qurl-scanner-lambda` ECR repo (see modules/ecr/main.tf
# `local.ecr_repos`). The binary auto-detects the Lambda runtime via the
# `AWS_LAMBDA_RUNTIME_API` env var and dispatches to `lambda.Start(handler)`;
# the same image runs as a CLI locally for operator `--bucket=N` replay.
#
# Gating: the ECR repo + SSM image-tag param gate on `deploy_qurl_service`
# (so qurl-service CI can publish images regardless of the Lambda enable
# flag); the Lambda + cron + alarms gate on `qurl_scanner_lambda_enabled`.
# See the prod rollout task ledger
# (`docs/runbooks/prod-rollout-task-ledger.md`, entry for PR #2326) for
# the canonical two-apply rollout sequence, preflight checks, smoke tests,
# rollback steps, and prod flag-flip preconditions — this file deliberately
# does NOT duplicate that here to avoid drift.

# ============================================================================
# SSM image-tag parameter — created ALWAYS when qurl-service is deployed
# ============================================================================

# SSM parameter for the scanner Lambda image tag.
#
# Mirrors the qurl-api SSM image-tag pattern (`aws_ssm_parameter.image_tag`
# above in main.tf): qurl-service CI updates the param value out-of-band
# after each ECR push, so `lifecycle.ignore_changes = [value]` prevents
# Terraform from clobbering CI's writes on subsequent applies.
#
# Lifecycle (see comment block at the top of this file): this resource is
# NOT gated on `qurl_scanner_lambda_enabled` — qurl-service CI needs the
# param to exist so it can push images BEFORE the Lambda is enabled. The
# Lambda function below picks up the param's CURRENT value via a data
# source at plan time (not the resource value, which `ignore_changes`
# would pin at `"latest"` forever).
#
# Empty `qurl_scanner_lambda_image_tag_ssm_param` skips creation entirely
# — useful for envs that don't deploy any qurl-service resources at all.
resource "aws_ssm_parameter" "scanner_lambda_image_tag" {
  count = var.qurl_scanner_lambda_image_tag_ssm_param != "" ? 1 : 0

  name        = var.qurl_scanner_lambda_image_tag_ssm_param
  type        = "String"
  value       = "latest"
  description = "Current container image tag for the qurl-scanner Lambda (managed by qurl-service CI)."

  tags = merge(var.tags, local.scanner_lambda_common_tags, {
    Name = "${local.scanner_lambda_function_name}-image-tag"
  })

  lifecycle {
    ignore_changes = [value]
  }

  # Manufacture a `depends_on` edge from this SSM param to the ECR
  # repo so a greenfield apply cannot land the param before the repo
  # exists — without it, qurl-service CI's "exists=true → push" branch
  # can trip if its next main push happens to land in that window. The
  # edge can't be written as `depends_on = [var.x]` directly (Terraform
  # rejects var references in `depends_on`); the `terraform_data` shim
  # below carries the var as its `input`, and Terraform infers the
  # apply-time ordering from the resource reference.
  depends_on = [terraform_data.scanner_ecr_ready]
}

# Apply-time ordering shim for the ECR-repo → SSM-image-tag-param edge.
#
# `terraform_data.input` accepts an arbitrary value (here, the
# ECR-repo ARN from `module.ecr.qurl_scanner_lambda_repo_arn`). The
# resource itself does nothing at apply time; its purpose is to give
# `aws_ssm_parameter.scanner_lambda_image_tag` a concrete resource to
# `depends_on` whose creation Terraform knows must precede the ECR
# repo's. Without this, the only way to enforce ordering would be a
# coarse module-level `depends_on = [module.ecr]` at the root.
#
# COUNT GATE: no `count` predicate on this resource. Outer
# `module.qurl_service` is already `count = var.deploy_qurl_service
# ? 1 : 0` at the root, so this whole module — including the shim —
# only instantiates when the ECR repo is being provisioned in the
# same apply. There is no caller path where this shim should exist
# but the ECR repo shouldn't.
#
# What the predicate on `count` CANNOT be: anything derived from
# `var.qurl_scanner_lambda_ecr_repo_arn` (the ECR ARN itself). It is
# a computed `aws_ecr_repository.main[...].arn` attribute and is
# unknown-at-plan on the apply that creates the repo, so a
# string-shaped count predicate like `var.X != "" ? 1 : 0` fails
# plan with "Invalid count argument: the count value depends on
# resource attributes that cannot be determined until apply".
# `terraform_data.input`, by contrast, accepts unknown values just
# fine — the shim resource itself becomes "known after apply", but
# the SSM param's `depends_on = [terraform_data.scanner_ecr_ready]`
# is a static reference at plan time so the ordering edge still
# materializes. Regression trail:
# https://github.com/layervai/nhp/actions/runs/27030298517 (#2326
# sandbox-deploy failure → hotfix #2327). #2328 tracks a lint to
# flag the bug-prone `count = <module-output-arn> != ""` pattern at
# PR time, since `terraform validate` doesn't evaluate counts
# against real attributes.
resource "terraform_data" "scanner_ecr_ready" {
  input = var.qurl_scanner_lambda_ecr_repo_arn
}

# Read the CURRENT SSM image-tag value at plan time so the Lambda picks
# up the latest CI-written SHA on every apply.
#
# Why a data source instead of `aws_ssm_parameter.scanner_lambda_image_tag.value`:
# the resource has `lifecycle.ignore_changes = [value]`, so its `value`
# attribute stays pinned at the seeded `"latest"` in Terraform state
# regardless of what CI writes — using it as `image_uri` would mean every
# Lambda invocation runs the image at `repo:latest`, forever.
#
# The data source defers to apply time because of the implicit resource
# reference on `.name`; no `depends_on` needed.
#
# DEPLOY CADENCE: image_uri is resolved at PLAN time, so a
# qurl-service CI image push does NOT
# auto-roll-out to the scanner Lambda. Between Terraform applies the
# scanner runs whatever SHA was current on the most recent apply,
# regardless of what CI subsequently published. Operators / CI need to
# `terraform apply` to take a new image. This is intentional —
# matches the prod-careful posture (no out-of-band Lambda code
# updates) and contrasts with the ECS task def which CI updates
# directly via `update-service`. If an in-cadence redeploy is ever
# required, add `aws lambda update-function-code --image-uri ...` to
# the qurl-service workflow + add `lifecycle { ignore_changes =
# [image_uri] }` to the Lambda resource.
data "aws_ssm_parameter" "scanner_lambda_image_tag_current" {
  # The variable validation in `scanner_lambda_enabled = true` consumers
  # (paired with `qurl_scanner_lambda_image_tag_ssm_param != ""`) is
  # enforced by the chain: `enabled = true` → this data source needs
  # `aws_ssm_parameter.scanner_lambda_image_tag[0]`, which exists iff
  # `qurl_scanner_lambda_image_tag_ssm_param != ""`. Mismatched config
  # fails plan-time with "Invalid index", which is loud enough.
  count = var.qurl_scanner_lambda_enabled ? 1 : 0

  name = aws_ssm_parameter.scanner_lambda_image_tag[0].name
}

# ============================================================================
# Log group — created with the Lambda (KMS-encrypted)
# ============================================================================

locals {
  scanner_lambda_function_name = "${var.name_prefix}-${var.cell_id}-qurl-scanner"

  # Shared tags carried by every scanner Lambda resource. `Name` is
  # per-resource (each gets a distinct suffix), so it stays in the
  # individual merge calls.
  scanner_lambda_common_tags = {
    Component = "qurl-scanner-lambda"
    Cell      = var.cell_id
  }
}

# Encrypted CloudWatch Log Group for the scanner Lambda.
#
# Pre-creating the log group (rather than letting Lambda auto-create it on
# first invocation) is required for:
#   * `kms_key_id` to land — Lambda-auto-created log groups are unencrypted.
#   * `retention_in_days` to be enforced (Lambda's default is "Never expire").
#
# Retention mirrors the ECS task log group's per-env shape
# (`local.is_prod ? 365 : 30`) so prod compliance retention isn't
# sandbox-only by accident. Override via `scanner_lambda_log_retention_days`
# only to pin a specific retention in a multi-tenant test env.
#
# Name MUST match the Lambda's function name with the `/aws/lambda/` prefix
# — Lambda writes to that fixed path regardless of any other config.
resource "aws_cloudwatch_log_group" "scanner_lambda" {
  count = var.qurl_scanner_lambda_enabled ? 1 : 0

  name              = "/aws/lambda/${local.scanner_lambda_function_name}"
  retention_in_days = coalesce(var.scanner_lambda_log_retention_days, local.is_prod ? 365 : 30)
  kms_key_id        = var.logs_kms_key_arn

  tags = merge(var.tags, local.scanner_lambda_common_tags, {
    Name = "${local.scanner_lambda_function_name}-logs"
  })
}

# ============================================================================
# IAM execution role
# ============================================================================

# Trust policy: lambda.amazonaws.com only. EventBridge uses a separate
# `aws_lambda_permission` resource below to invoke the function.
resource "aws_iam_role" "scanner_lambda" {
  count = var.qurl_scanner_lambda_enabled ? 1 : 0

  name        = "${local.scanner_lambda_function_name}-execution"
  description = "Execution role for the qurl-scanner Lambda — DDB Query/UpdateItem on qURL tables + optional SQS SendMessage + CloudWatch Logs."

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })

  tags = merge(var.tags, local.scanner_lambda_common_tags, {
    Name = "${local.scanner_lambda_function_name}-execution"
  })
}

# DynamoDB grants — narrow per-table, with explicit GSI ARNs for Query.
#
# Action breakdown (mirrors the scanner binary's call sites in
# qurl-service/internal/scanner; grep the binary for the canonical list
# before adding anything here):
#   * `qurl_access_tokens` table         : UpdateItem (per-qurl
#                                          `expired_webhook_fired_at`
#                                          idempotency marker write)
#   * `qurl_access_tokens/time-bucket-index` GSI : Query (per-minute scan)
#   * `qurl_access_tokens/resource-token-index` GSI : Query (active-qurl
#                                          precondition before
#                                          `resource.closed` emission)
#   * `qurl_resources` table             : GetItem + UpdateItem
#                                          (`resource_closed_fired_at`,
#                                          `resource_tombstoned_at`,
#                                          `tombstone_ttl`,
#                                          `final_access_count`)
#   * `qurl_sessions` table              : Query (PK = resource_id, with
#                                          TTL filter — see PR-A4a-3
#                                          design note on counter drift
#                                          ruling out the active_count
#                                          counter)
#
# IMPORTANT: GSI Query needs the index ARN explicitly. `${table_arn}` ALONE
# permits operations on the base table; `${table_arn}/index/<name>` is a
# distinct ARN and must be listed separately, or Query against the GSI
# returns AccessDeniedException at runtime.
resource "aws_iam_role_policy" "scanner_lambda_dynamodb" {
  count = var.qurl_scanner_lambda_enabled ? 1 : 0

  name = "dynamodb-access"
  role = aws_iam_role.scanner_lambda[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    # KMS:Decrypt on the secrets-CMK that encrypts every qURL DDB table
    # (`module.dynamodb` is wired with `kms_key_arn = module.kms.secrets_key_arn`,
    # and each `aws_dynamodb_table.qurl_*` carries
    # `server_side_encryption { kms_key_arn = ... }`). Without this grant,
    # any Query / GetItem / UpdateItem against encrypted rows returns
    # `KMSAccessDeniedException` at runtime — DDB transparently decrypts on
    # read through the caller's KMS context. Mirrors the API task role's
    # `Sid = "KMSDecryptDynamoDB"` statement in main.tf.
    #
    # IMPORTANT: an empty-bucket smoke invoke returns zero items and
    # triggers no decryption, so a missing grant stays latent through
    # the entrypoint-only smoke and first surfaces on the first real
    # expiry tick. The rollout runbook requires a data-path smoke
    # before any prod flag flip. The `concat`-with-empty-list shape
    # keeps the statement out of the policy entirely when KMS is not
    # wired (greenfield envs) — same posture the API role uses.
    Statement = concat(
      [
        {
          Sid    = "QurlAccessTokensQuery"
          Effect = "Allow"
          Action = ["dynamodb:Query"]
          Resource = [
            "${var.qurl_access_tokens_table_arn}/index/time-bucket-index",
            "${var.qurl_access_tokens_table_arn}/index/resource-token-index",
          ]
        },
        {
          Sid      = "QurlAccessTokensUpdate"
          Effect   = "Allow"
          Action   = ["dynamodb:UpdateItem"]
          Resource = [var.qurl_access_tokens_table_arn]
        },
        {
          Sid    = "QurlResourcesReadWrite"
          Effect = "Allow"
          Action = [
            "dynamodb:GetItem",
            "dynamodb:UpdateItem",
          ]
          Resource = [var.qurl_resources_table_arn]
        },
        {
          Sid      = "QurlSessionsQuery"
          Effect   = "Allow"
          Action   = ["dynamodb:Query"]
          Resource = [var.qurl_sessions_table_arn]
        },
      ],
      var.secrets_kms_key_arn != null && var.secrets_kms_key_arn != "" ? [{
        Sid      = "KMSDecryptDynamoDB"
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = [var.secrets_kms_key_arn]
      }] : []
    )
  })
}

# CloudWatch Logs writer — scoped to the scanner's log group only (not the
# broad `arn:aws:logs:*:*:*` shape AWS's managed `AWSLambdaBasicExecutionRole`
# would grant).
resource "aws_iam_role_policy" "scanner_lambda_logs" {
  count = var.qurl_scanner_lambda_enabled ? 1 : 0

  name = "cloudwatch-logs"
  role = aws_iam_role.scanner_lambda[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "CloudWatchLogs"
      Effect = "Allow"
      Action = [
        "logs:CreateLogStream",
        "logs:PutLogEvents",
      ]
      Resource = "${aws_cloudwatch_log_group.scanner_lambda[0].arn}:*"
    }]
  })
}

# SQS `SendMessage` — created ONLY when `resource_lifecycle_queue_arn`
# is non-empty. Empty default + `count = 0` keeps an empty-Resource
# statement (which would fail at apply with `Resource ... is invalid`)
# out of the policy entirely. Wire `resource_lifecycle_queue_arn` to
# the queue's ARN once the queue exists; until then the binary defaults
# to log-only emit so the absent grant is correct.
#
# ACTIVATION-PR TODO: the resource-lifecycle queue is created SSE-KMS-
# encrypted (it sits on the regulated emit path). When this gate flips
# non-empty, this policy will also need a `kms:GenerateDataKey` +
# `kms:Decrypt` statement against the QUEUE's KMS key — otherwise
# `SendMessage` fails with `KMSAccessDeniedException` at runtime. See
# the `task_usage_events` policy in main.tf for the precedent pairing
# (`Sid = "QueueAccess"` + `Sid = "KMSEncryptSQS"`). That key ARN
# will need its own input variable threaded from the queue's KMS key
# at the root, mirroring the `usage_events_queue_arn` /
# `usage_events_queue_url` pair already in this module.
resource "aws_iam_role_policy" "scanner_lambda_sqs" {
  count = var.qurl_scanner_lambda_enabled && var.resource_lifecycle_queue_arn != "" ? 1 : 0

  name = "sqs-send-message"
  role = aws_iam_role.scanner_lambda[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "SQSSendMessage"
      Effect   = "Allow"
      Action   = ["sqs:SendMessage"]
      Resource = var.resource_lifecycle_queue_arn
    }]
  })
}

# ============================================================================
# Lambda function (container-image package)
# ============================================================================

resource "aws_lambda_function" "scanner" {
  count = var.qurl_scanner_lambda_enabled ? 1 : 0

  function_name = local.scanner_lambda_function_name
  description   = "qURL expiry scanner — runs every minute via EventBridge, scans the time-bucket-index GSI, emits qurl.expired + resource.closed events per the rollout flags on env vars (default log-only)."
  role          = aws_iam_role.scanner_lambda[0].arn

  # `provided.al2023` custom runtime baked into the image; Lambda invokes
  # `/var/runtime/bootstrap` per the image's CMD. See
  # qurl-service `docker/Dockerfile.scanner-lambda` for the base image
  # digest pin and the rotation instructions.
  #
  # `nonsensitive()` strips the AWS-provider-attached sensitive flag on
  # `data.aws_ssm_parameter.value` so `terraform plan` renders the image
  # tag (a git SHA, not a secret) and reviewers can see which version is
  # being deployed. Without it, the plan diff reads
  # `image_uri = (sensitive value)`, hiding the actual tag change.
  package_type = "Image"
  image_uri    = "${var.qurl_scanner_lambda_ecr_repo_url}:${nonsensitive(data.aws_ssm_parameter.scanner_lambda_image_tag_current[0].value)}"

  # x86_64 matches the `-x86_64` suffix on the `provided.al2023` base
  # image digest pinned in `docker/Dockerfile.scanner-lambda`. The
  # Dockerfile's build stage runs `GOARCH=amd64` for the same reason.
  # Mismatched arch surfaces as a Lambda invoke-time
  # `Runtime.InvalidEntrypoint` / `exec format error`. Flip both
  # the Dockerfile arch suffix AND this attribute together when
  # migrating to arm64.
  architectures = ["x86_64"]

  memory_size = var.scanner_lambda_memory_mb
  timeout     = var.scanner_lambda_timeout_seconds

  # reserved_concurrent_executions = 1 enforces single-invocation-at-a-time
  # semantics: EventBridge's `rate(1 minute)` cadence at 1 invocation per
  # tick stays comfortably under this cap; an over-long tick that
  # straddles the next cron fire gets throttled (visible on the
  # `Throttles` metric) AND leaves a gap on `Invocations` (caught by
  # `scanner_invocation_gap` below). Recovery for the THROTTLED tick is
  # operator `--bucket=N` replay, NOT carry-over — see the
  # async-invoke-config comment block for the full recovery-semantics
  # split (long ticks vs dropped/throttled ticks). Reserved=1 also
  # permanently consumes 1 from the account's reserved-concurrency
  # pool; the cron's 1-invocation-per-minute steady-state stays well
  # under it.
  reserved_concurrent_executions = 1

  # Env vars default to the safest posture:
  #   - EMIT_MODE absent       → binary defaults to log-only (no SQS write)
  #   - QURL_SCANNER_ENABLE_TOMBSTONE_WRITE absent → no resource tombstoning
  #   - QURL_SCANNER_ALLOW_PROD_EMIT absent        → no prod emit
  # An operator flips these in a separate `terraform apply` after the
  # smoke test, SQS queue, and paging alarms are in place — see the
  # prod rollout task ledger. AWS_REGION is auto-populated by the
  # Lambda runtime; QURL_SCANNER_TABLE_PREFIX threads the same
  # `<name_prefix>-<cell>` shape the API container uses.
  environment {
    variables = {
      QURL_SCANNER_TABLE_PREFIX = "${var.name_prefix}-${var.cell_id}"
    }
  }

  # The Lambda runtime expects the image's CMD to map to a `bootstrap`
  # binary at /var/runtime/bootstrap. The Dockerfile sets CMD ["bootstrap"]
  # already, so no `image_config` override is needed.
  #
  # Tracing: passthrough (the binary doesn't emit X-Ray segments today).
  # If a future revision adds X-Ray instrumentation, flip to "Active"
  # AND grant `xray:PutTraceSegments` / `xray:PutTelemetryRecords` on the
  # execution role.

  tags = merge(var.tags, local.scanner_lambda_common_tags, {
    Name = local.scanner_lambda_function_name
  })

  # Ordering fence: the log group MUST exist before the function or
  # Lambda auto-creates an unencrypted, never-expiring group at first
  # invocation, which then conflicts with the encrypted group this
  # module owns. The IAM policies are listed so EventBridge's first
  # invocation after function-create can't hit an Access-Denied window;
  # AWS Lambda IAM policies take effect at invoke time, not create time,
  # so without these depends_on the cron rule could fire before
  # policies propagate. The SQS policy is included conditionally so the
  # full grant set is in place before any tick — but its `count` gate
  # means the reference resolves to a zero-instance no-op edge when
  # `resource_lifecycle_queue_arn` is empty (no spurious dep then).
  # The image-tag data source is an implicit dep already via
  # `image_uri`.
  depends_on = [
    aws_cloudwatch_log_group.scanner_lambda,
    aws_iam_role_policy.scanner_lambda_dynamodb,
    aws_iam_role_policy.scanner_lambda_logs,
    aws_iam_role_policy.scanner_lambda_sqs, # count-gated: a zero-instance ref here is a no-op edge
  ]

  # Plan-time wiring fences — confirm the caller threaded the required
  # inputs before this function tries to create with a malformed
  # `image_uri` or runtime-AccessDenied DDB calls. Resource-level
  # `precondition` (rather than variable-level `validation`) is the
  # idiomatic choice for cross-variable invariants — clearer error
  # locality on plan output, and the failure ties the message to the
  # consumer that needs the value.
  #
  # `enabled = true` without these vars otherwise surfaces as a cryptic
  # null-interpolation error (`image_uri = ":<sha>"`) or a downstream
  # IAM ARN parse failure — neither points at the missing wiring.
  lifecycle {
    precondition {
      condition     = var.qurl_scanner_lambda_ecr_repo_url != ""
      error_message = "qurl_scanner_lambda_enabled=true but qurl_scanner_lambda_ecr_repo_url is empty. Thread `module.ecr.qurl_scanner_lambda_repo_url` from the root (requires `deploy_qurl_service = true`)."
    }
    precondition {
      condition     = var.qurl_access_tokens_table_arn != "" && var.qurl_resources_table_arn != "" && var.qurl_sessions_table_arn != ""
      error_message = "qurl_scanner_lambda_enabled=true but one or more qURL table ARNs are empty. Thread `module.dynamodb.qurl_{access_tokens,resources,sessions}_table_arn` from the root (requires `deploy_qurl_service = true` so the tables exist)."
    }
    precondition {
      condition     = var.secrets_kms_key_arn != null && var.secrets_kms_key_arn != ""
      error_message = "qurl_scanner_lambda_enabled=true but secrets_kms_key_arn is empty. DDB tables are CMK-encrypted; without this the scanner's first non-empty Query returns KMSAccessDeniedException at runtime. Thread `module.kms.secrets_key_arn` from the root."
    }
    precondition {
      condition     = var.logs_kms_key_arn != null && var.logs_kms_key_arn != ""
      error_message = "qurl_scanner_lambda_enabled=true but logs_kms_key_arn is empty. The scanner's CloudWatch log group `kms_key_id` would resolve null, leaving logs unencrypted. Thread `module.kms.logs_key_arn` from the root."
    }
    precondition {
      condition     = var.qurl_scanner_lambda_image_tag_ssm_param != ""
      error_message = "qurl_scanner_lambda_enabled=true but qurl_scanner_lambda_image_tag_ssm_param is empty. The image-tag SSM resource is gated off (count=0), so the `data.aws_ssm_parameter[0]` reference would fail plan with a bare 'Invalid index'. Thread a non-empty SSM parameter name from the root (e.g. `/<name_prefix>/qurl-scanner-lambda-image-tag`) and confirm qurl-service `build-and-deploy.yml` writes to the same path."
    }
  }
}

# Async-invocation failure-handling fence.
#
# EventBridge invokes Lambda asynchronously. Two retry surfaces have to
# be bounded to prevent throttle-driven re-delivery from colliding with
# the next scheduled tick under `reserved_concurrent_executions = 1` +
# `rate(1 minute)`:
#
#   1. `maximum_retry_attempts = 0` — governs FUNCTION-ERROR retries
#      (Lambda's default is 2 with exponential backoff). Disabled here
#      because a function error doesn't get cheaper on retry.
#
#   2. `maximum_event_age_in_seconds = 60` — governs THROTTLE / SYSTEM-
#      ERROR re-delivery (Lambda's default is 21600s / 6h). Without
#      this, a throttled invocation sits on Lambda's internal queue and
#      keeps re-delivering for hours, colliding with every subsequent
#      `rate(1 minute)` tick. Capping at 60s aligns the discard horizon
#      to the cron cadence: a tick that can't run within its minute is
#      abandoned.
#
# RECOVERY SEMANTICS — two distinct failure modes with different
# recovery paths. Conflating them is a real footgun; the alarm
# descriptions and this comment block deliberately keep them apart:
#
#   * LONG TICK (partial bucket scan): a scan that runs but doesn't
#     finish within the configured `timeout` (defaulted to 50s for
#     ~10s of headroom under the rate(1 minute) cadence). The
#     binary's carry-over
#     pagination cursor (persisted to a small DDB state table at the
#     end of each tick — see qurl-service `cmd/qurl-scanner` design)
#     tracks the per-shard LastEvaluatedKey within the IN-PROGRESS
#     bucket. The next tick resumes from the cursor. Self-healing,
#     no operator action.
#
#   * DROPPED TICK (throttled / errored / event-age-expired
#     invocation): the function never runs for that minute. The
#     binary's next successful tick scans `now/60 - 1`, NOT the
#     skipped minute — the cursor mechanism tracks position within
#     the LAST scanned bucket, not which buckets are unscanned.
#     Recovery is an operator `--bucket=N` replay against the missed
#     minute (`aws lambda invoke --payload '{"bucket": N}'`).
#     `scanner_invocation_gap` flags sustained dropped ticks;
#     `scanner_errors_burning` flags errored ticks. Both pages
#     should bring the operator to the runbook with the missed
#     minute(s) ready to replay.
#
# No DLQ — by design. If a future rollout phase needs post-hoc
# forensics on dropped payloads, `destination_config.on_failure` is the
# one-line addition then.
resource "aws_lambda_function_event_invoke_config" "scanner" {
  count = var.qurl_scanner_lambda_enabled ? 1 : 0

  function_name                = aws_lambda_function.scanner[0].function_name
  maximum_retry_attempts       = 0
  maximum_event_age_in_seconds = 60
}

# ============================================================================
# EventBridge cron — `rate(1 minute)` tick
# ============================================================================

resource "aws_cloudwatch_event_rule" "scanner_tick" {
  count = var.qurl_scanner_lambda_enabled ? 1 : 0

  name                = "${local.scanner_lambda_function_name}-tick"
  description         = "Per-minute tick for the qurl-scanner Lambda — scans the time-bucket-index GSI for buckets that just passed."
  schedule_expression = "rate(1 minute)"

  tags = merge(var.tags, local.scanner_lambda_common_tags, {
    Name = "${local.scanner_lambda_function_name}-tick"
  })
}

resource "aws_cloudwatch_event_target" "scanner_tick" {
  count = var.qurl_scanner_lambda_enabled ? 1 : 0

  rule = aws_cloudwatch_event_rule.scanner_tick[0].name
  arn  = aws_lambda_function.scanner[0].arn

  # Steady-state cron tick sends an EMPTY JSON object. The scanner
  # binary unmarshals into `ScannerEvent{Bucket *int64}` from the JSON
  # ROOT; with `Bucket` left nil, `lambdaHandler` uses `now() - 1
  # minute` as the bucket to scan.
  #
  # PRE-MERGE TASK C — operator replay format:
  # For ad-hoc `--bucket=N` replay against a sandbox Lambda, a separate
  # EventBridge rule (created outside Terraform, NOT in this file) must
  # place `{"bucket": N}` at the JSON ROOT, NOT under `detail.bucket`.
  # The scanner binary's `ScannerEvent` reads `Bucket` from the root
  # level; a `detail.bucket` placement (which EventBridge's default
  # input transformer would produce for `aws.events` source events)
  # silently no-ops the override and the Lambda re-scans `now() - 1`
  # instead of the requested bucket. Document this in any runbook that
  # covers manual replay.
  input = jsonencode({})
}

resource "aws_lambda_permission" "scanner_tick" {
  count = var.qurl_scanner_lambda_enabled ? 1 : 0

  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.scanner[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.scanner_tick[0].arn
}

# ============================================================================
# Scan-gap CloudWatch alarm
# ============================================================================
#
# Coverage profile: this alarm catches DELIVERY / THROTTLE gaps, not
# function-error gaps. With `period = 300` (5 min),
# `evaluation_periods = 2` (10 min), and `Sum(Invocations) ≤ 3`:
#   * 1–2 missed ticks across a 10-min window do NOT page — a single
#     missed tick depresses Sum to 4 and `rate(1 minute)` cadence drift
#     against CloudWatch's fixed 5-min wall-clock windows can produce
#     `5,4,5,4...` legitimately. Threshold = 3 absorbs both.
#   * 4+ missed ticks across 10 min DO page — EventBridge delivery-rule
#     misconfig, sustained throttling, or a function deleted /
#     dimension-drifted out of view (via `treat_missing_data = "breaching"`).
#
# Recovery for missed buckets is operator `--bucket=N` replay; the
# binary's carry-over cursor only recovers LONG ticks, not dropped
# ones — see the async-invoke-config comment block.
#
# IMPORTANT — runtime panic gap: AWS Lambda's `Invocations` metric
# INCLUDES errored invocations (per AWS docs, it only excludes
# throttles). A scanner that's invoked every minute but errors every
# tick still produces `Sum(Invocations) = 5` per 5-min window, leaving
# this alarm in OK while zero buckets are scanned. The
# `scanner_errors_burning` companion alarm below closes that gap (any
# `Errors >= 1` over a single 5-min window pages).
#
# Single-tick-miss instrumentation is left for a future custom metric
# (e.g. `scanner_tick_complete` count emitted by the binary) — out of
# scope here. Downstream alarms on `TombstoneErrors` /
# `EmittedNoFence` / `CandidatesUnprocessed` (tracked separately as
# emit-side rollout prerequisites) cover the operator visibility.
#
# `ok_actions` intentionally NOT wired on this alarm. `rate()` cadence
# drift against CloudWatch's wall-clock window means even with the
# threshold = 3 + 2-period gate, ALARM ↔ OK flapping is possible on a
# healthy function — the noise that creates when SNS lands is more
# disruptive than the missed-recovery signal. The companion errors
# alarm (clean signal, no flapping risk) does carry `ok_actions`.
#
# First-enable behavior: the alarm enters ALARM immediately after the
# function is created and stays there until `evaluation_periods ×
# period` (10 min) of data accrue. Harmless today (`alarm_actions` is
# empty), but the operator wiring SNS later should expect a 10-min
# initial breach window on every fresh enable / function replacement.
resource "aws_cloudwatch_metric_alarm" "scanner_invocation_gap" {
  count = var.qurl_scanner_lambda_enabled ? 1 : 0

  alarm_name        = "${local.scanner_lambda_function_name}-invocation-gap"
  alarm_description = "qurl-scanner Lambda has missed ≥ 2 ticks in each of 2 consecutive 5-min windows (Sum(Invocations) ≤ 3 per window). Indicates sustained EventBridge delivery gap, throttling, or a deleted/dimension-drifted function. Recovery: operator --bucket=N replay against the missed minute(s). Runtime errors are caught by the companion `scanner_errors_burning` alarm below."

  namespace   = "AWS/Lambda"
  metric_name = "Invocations"
  statistic   = "Sum"
  period      = 300

  evaluation_periods  = 2
  threshold           = 3
  comparison_operator = "LessThanOrEqualToThreshold"
  treat_missing_data  = "breaching"

  dimensions = {
    FunctionName = aws_lambda_function.scanner[0].function_name
  }

  alarm_actions = var.scanner_lambda_alarm_sns_topic_arn != "" ? [var.scanner_lambda_alarm_sns_topic_arn] : []
  # ok_actions intentionally omitted — see the comment block above.

  tags = merge(var.tags, local.scanner_lambda_common_tags, {
    Name = "${local.scanner_lambda_function_name}-invocation-gap"
  })
}

# Errors-burning companion alarm.
#
# Closes the runtime-panic gap the invocation-gap alarm can't catch:
# Lambda's `Invocations` metric counts errored invocations too, so a
# function that's invoked every minute and errors every tick still
# produces `Sum(Invocations) = 5` per 5-min window. This alarm fires
# when `Sum(Errors) ≥ 1` over any single 5-min window — any tick
# producing a function-level error pages.
#
# Why a single period (no consecutive-breach gate) for Errors but two
# periods for invocation-gap: a single errored tick IS a problem
# (the bucket it owned is not getting scanned and is not auto-
# recoverable — the cursor only saves LONG ticks), whereas an
# isolated delivery gap is tolerable until an operator notices the
# downstream event-count anomaly and runs `--bucket=N`. `Errors`
# is also a clean signal — no minute-boundary jitter, no rate-cadence
# alignment issue — so the page-train concern that motivated the
# 2-period gate on invocation-gap doesn't apply.
#
# `treat_missing_data = "notBreaching"`: if no Errors data flows for
# a period, do NOT alarm. The `Errors` metric is only published when
# there's actual error activity; a healthy steady-state function emits
# zero or no `Errors` data points, and `breaching` here would page on
# every quiet 5-min window. The invocation-gap alarm's `breaching`
# treatment already covers the "function deleted / dimension drifted"
# scenario.
resource "aws_cloudwatch_metric_alarm" "scanner_errors_burning" {
  count = var.qurl_scanner_lambda_enabled ? 1 : 0

  alarm_name        = "${local.scanner_lambda_function_name}-errors-burning"
  alarm_description = "qurl-scanner Lambda is producing function errors (Sum(Errors) ≥ 1 over 5 min). Indicates runtime panic, unhandled exception, or KMS / IAM denial against real data. Recovery: read CloudWatch Logs and either fix-forward or roll the Lambda back to the prior tag via the SSM image-tag param."

  namespace   = "AWS/Lambda"
  metric_name = "Errors"
  statistic   = "Sum"
  period      = 300

  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = aws_lambda_function.scanner[0].function_name
  }

  alarm_actions = var.scanner_lambda_alarm_sns_topic_arn != "" ? [var.scanner_lambda_alarm_sns_topic_arn] : []
  ok_actions    = var.scanner_lambda_alarm_sns_topic_arn != "" ? [var.scanner_lambda_alarm_sns_topic_arn] : []

  tags = merge(var.tags, local.scanner_lambda_common_tags, {
    Name = "${local.scanner_lambda_function_name}-errors-burning"
  })
}
