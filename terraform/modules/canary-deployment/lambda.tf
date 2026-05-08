# Canary Deployment Module - Lambda Function
# Orchestrator Lambda for canary deployment actions (prepare, start, check, rollback, etc.)

# ==============================================================================
# Lambda Package
# ==============================================================================

# NOTE: this module is now re-instantiated as `module.canary_deployment_ac`
# AND `module.canary_deployment_qurl_reverse_tunnel_server` in
# terraform/main.tf — three writers, all resolving `${path.module}` to the
# same source dir, all writing to the same `output_path`. The writes
# are idempotent today because the source content is identical, so a
# corruption window only exists if the `hashicorp/archive` provider's
# truncate-and-write interleaves. Probability is small at the current
# ~2KB zip size but #1763 tracks the proper fix.
#
# Per-component `output_path` is the natural fix BUT requires
# `.github/workflows/promote-to-prod.yml` to upload/download three
# distinct artifacts (one per component) instead of the current single
# `lambda-canary-orchestrator` artifact at the shared path. PR #1745
# leaves the workflow change to #1763 to keep this PR's diff scoped
# to the BG/canary topology.
#
# Adding component-specific Lambda code (e.g. `if component == "ac"` in
# `canary_orchestrator.py`) would make the writes DIVERGE — at that
# point #1763 becomes blocking. If you need per-component behavior
# before #1763 lands, also split the `archive_file` AND add the third
# workflow upload/download pair. See terraform/main.tf NOTE on
# `module.canary_deployment_ac` and #1380.
data "archive_file" "orchestrator" {
  type        = "zip"
  source_file = "${path.module}/lambda/canary_orchestrator.py"
  output_path = "${path.module}/lambda/canary_orchestrator.zip"
}

# ==============================================================================
# Lambda Function
# ==============================================================================

resource "aws_lambda_function" "orchestrator" {
  depends_on = [aws_cloudwatch_log_group.orchestrator]

  filename         = data.archive_file.orchestrator.output_path
  function_name    = "${var.name_prefix}-canary-orchestrator-${var.component}"
  role             = aws_iam_role.orchestrator.arn
  handler          = "canary_orchestrator.handler"
  source_code_hash = data.archive_file.orchestrator.output_base64sha256
  runtime          = "python3.12"
  timeout          = 300
  memory_size      = 256

  environment {
    variables = {
      ENVIRONMENT             = var.environment
      ASG_NAME                = var.asg_name
      NLB_ARN_SUFFIX          = var.nlb_arn_suffix
      TARGET_GROUP_ARN_SUFFIX = var.target_group_arn_suffix
      # Explicit "is this an NLB-less component?" toggle. The Lambda
      # uses this to decide between the NLB metric-query path and the
      # ASG-instance metric-query path. Originally inferred from
      # `not NLB_ARN_SUFFIX or not TARGET_GROUP_ARN_SUFFIX`, but the
      # implicit form is hard to defend against a future caller that
      # passes only one of the two suffixes (the cross-variable
      # `terraform_data.component_invariants` precondition catches
      # that today, but defense-in-depth at the Lambda layer surfaces
      # a misconfig as a hard mismatch instead of silently choosing
      # the wrong path).
      NLB_HEALTH_CHECKS_DISABLED     = tostring(var.disable_nlb_health_checks)
      SNS_TOPIC_ARN                  = var.alerts_sns_topic_arn
      SSM_IMAGE_TAG_PARAM            = var.ssm_image_tag_parameter
      SSM_CANARY_STATE_PARAM         = aws_ssm_parameter.canary_state.name
      SSM_CANARY_EXECUTION_ARN_PARAM = aws_ssm_parameter.canary_execution_arn.name
      MAX_CPU_PERCENT                = tostring(var.max_cpu_percent)
      CHECKPOINT_PERCENTAGES         = jsonencode(var.checkpoint_percentages)
      CHECKPOINT_DELAY               = tostring(var.checkpoint_delay_seconds)
      INSTANCE_WARMUP                = tostring(var.instance_warmup_seconds)
      # Threaded so the SFN-side `StartInstanceRefresh.Preferences.MinHealthyPercentage`
      # and the canary's own NLB-disabled-path health gate stay locked to the
      # same value via Terraform — preventing the two literals from drifting in
      # a future code edit.
      MIN_HEALTHY_PERCENTAGE = tostring(var.min_healthy_percentage)
    }
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-canary-orchestrator-${var.component}"
    Component = "canary"
    Cell      = var.cell_id
  })
}

# ==============================================================================
# Lambda Log Group
# ==============================================================================

resource "aws_cloudwatch_log_group" "orchestrator" {
  name              = "/aws/lambda/${var.name_prefix}-canary-orchestrator-${var.component}"
  retention_in_days = local.is_prod ? 90 : 14
  kms_key_id        = var.logs_kms_key_arn

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-canary-orchestrator-${var.component}-logs"
    Component = "canary"
    Cell      = var.cell_id
  })
}

# ==============================================================================
# Lambda IAM Role
# ==============================================================================

resource "aws_iam_role" "orchestrator" {
  name = "${var.name_prefix}-canary-orchestrator-${var.component}-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-canary-orchestrator-${var.component}-role"
    Component = "canary"
    Cell      = var.cell_id
  })
}

resource "aws_iam_role_policy_attachment" "orchestrator_basic" {
  role       = aws_iam_role.orchestrator.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "orchestrator" {
  name = "${var.name_prefix}-canary-orchestrator-${var.component}-policy"
  role = aws_iam_role.orchestrator.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AutoScalingMutations"
        Effect = "Allow"
        Action = [
          "autoscaling:StartInstanceRefresh",
          "autoscaling:CancelInstanceRefresh",
          "autoscaling:RollbackInstanceRefresh"
        ]
        Resource = var.asg_arn
      },
      {
        Sid    = "DescribeOperations"
        Effect = "Allow"
        Action = [
          "autoscaling:DescribeAutoScalingGroups",
          "autoscaling:DescribeInstanceRefreshes",
          "ec2:DescribeLaunchTemplateVersions",
          "cloudwatch:GetMetricData",
          "cloudwatch:DescribeAlarms"
        ]
        Resource = "*"
      },
      {
        # StartInstanceRefresh with DesiredConfiguration does a dry-run ec2:RunInstances
        # validation. This requires authorization on ALL resource types the launch template
        # references, plus CreateTags for tag specifications and KMS for encrypted volumes.
        Sid    = "RunInstancesForDesiredConfiguration"
        Effect = "Allow"
        Action = [
          "ec2:RunInstances",
          "ec2:CreateTags",
        ]
        Resource = [
          var.launch_template_arn,
          "arn:aws:ec2:${data.aws_region.current.id}:${data.aws_caller_identity.current.account_id}:instance/*",
          "arn:aws:ec2:${data.aws_region.current.id}:${data.aws_caller_identity.current.account_id}:volume/*",
          "arn:aws:ec2:${data.aws_region.current.id}:${data.aws_caller_identity.current.account_id}:network-interface/*",
          "arn:aws:ec2:${data.aws_region.current.id}:${data.aws_caller_identity.current.account_id}:subnet/*",
          "arn:aws:ec2:${data.aws_region.current.id}:${data.aws_caller_identity.current.account_id}:security-group/*",
          "arn:aws:ec2:${data.aws_region.current.id}::image/*",
        ]
      },
      {
        Sid      = "PassRoleForInstanceProfile"
        Effect   = "Allow"
        Action   = ["iam:PassRole"]
        Resource = "*"
        Condition = {
          StringEquals = {
            "iam:PassedToService" = "ec2.amazonaws.com"
          }
        }
      },
      {
        Sid    = "KMSForEncryptedVolumes"
        Effect = "Allow"
        Action = [
          "kms:CreateGrant",
          "kms:DescribeKey",
          "kms:GenerateDataKeyWithoutPlaintext",
          "kms:ReEncryptFrom",
          "kms:ReEncryptTo",
        ]
        Resource = compact([var.ebs_kms_key_arn])
      },
      {
        Sid    = "SSMCanaryState"
        Effect = "Allow"
        Action = [
          "ssm:GetParameter",
          "ssm:PutParameter"
        ]
        Resource = [
          "arn:aws:ssm:${data.aws_region.current.id}:${data.aws_caller_identity.current.account_id}:parameter/${var.environment}/nhp/${var.cell_id}/canary/*",
          "arn:aws:ssm:${data.aws_region.current.id}:${data.aws_caller_identity.current.account_id}:parameter${var.ssm_image_tag_parameter}"
        ]
      },
      {
        Sid    = "SNSNotifications"
        Effect = "Allow"
        Action = [
          "sns:Publish"
        ]
        Resource = var.alerts_sns_topic_arn
      }
    ]
  })
}
