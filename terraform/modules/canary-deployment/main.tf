# Canary Deployment Module
# Step Functions-orchestrated canary deployment with ASG instance refresh checkpoints.
# Uses checkpoint percentages for progressive rollout and Lambda health gates
# at each checkpoint with automatic rollback via RollbackInstanceRefresh API.

data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

locals {
  is_prod = var.environment == "prod"
}

# ==============================================================================
# Cross-variable preconditions
# ==============================================================================
# `component = "frps"` MUST be paired with `disable_nlb_health_checks = true`
# — qurl-reverse-tunnel-server has no NLB, so the NLB-keyed alarms would sit in
# INSUFFICIENT_DATA forever and the canary state machine would never
# advance. Conversely, `component` in {"server","ac"} with
# `disable_nlb_health_checks = true` would silently skip NLB health fences on a
# component that has an NLB and is therefore always rejected. Other half-mixes
# fail at plan time.
resource "terraform_data" "component_invariants" {
  lifecycle {
    precondition {
      condition     = var.component != "frps" || var.disable_nlb_health_checks
      error_message = "component = \"frps\" requires disable_nlb_health_checks = true — qurl-reverse-tunnel-server has no NLB and the NLB-keyed alarms would sit in INSUFFICIENT_DATA forever, blocking the canary from advancing."
    }
    precondition {
      condition     = !contains(["server", "ac"], var.component) || !var.disable_nlb_health_checks
      error_message = "component in {\"server\",\"ac\"} requires disable_nlb_health_checks = false because both components have mandatory NLB-keyed health alarms."
    }
    precondition {
      # NLB / target-group ARN suffixes must be empty when NLB checks are
      # disabled (so the canary_unhealthy / canary_low_healthy alarms
      # stay un-instantiated) and non-empty otherwise (so the dimensions
      # on those alarms actually point at a real target group). The
      # plan-time check uses AND-empty (both must be empty under
      # disabled) — strictly more conservative than the runtime
      # `_check_nlb_mode_consistency` any-empty rule. The runtime check
      # in canary_orchestrator.py is tightened in lockstep to AND-empty
      # so plan-time and runtime agree on the precise "half-mix
      # rejected" set; a future relaxation needs to update both.
      condition = (
        var.disable_nlb_health_checks
        ? var.nlb_arn_suffix == "" && var.target_group_arn_suffix == ""
        : var.nlb_arn_suffix != "" && var.target_group_arn_suffix != ""
      )
      error_message = "nlb_arn_suffix and target_group_arn_suffix must be empty when disable_nlb_health_checks = true (frps), and non-empty otherwise (server/ac). Half-mix would either dangle an alarm against an empty TG dimension or silently skip the alarms on a component that has an NLB."
    }
  }
}

# ==============================================================================
# Step Functions State Machine
# ==============================================================================

resource "aws_sfn_state_machine" "canary_deploy" {
  name     = "${var.name_prefix}-canary-deploy-${var.component}"
  role_arn = aws_iam_role.step_functions.arn

  definition = templatefile("${path.module}/state_machine.asl.json.tpl", {
    orchestrator_lambda_arn = aws_lambda_function.orchestrator.arn
  })

  logging_configuration {
    log_destination        = "${aws_cloudwatch_log_group.step_functions.arn}:*"
    include_execution_data = true
    level                  = "ERROR"
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-canary-deploy-${var.component}"
    Component = "canary"
    Cell      = var.cell_id
  })
}

# ==============================================================================
# Step Functions IAM Role
# ==============================================================================

resource "aws_iam_role" "step_functions" {
  name = "${var.name_prefix}-canary-sfn-${var.component}-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "states.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-canary-sfn-${var.component}-role"
    Component = "canary"
    Cell      = var.cell_id
  })
}

resource "aws_iam_role_policy" "step_functions" {
  name = "${var.name_prefix}-canary-sfn-${var.component}-policy"
  role = aws_iam_role.step_functions.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "InvokeLambda"
        Effect = "Allow"
        Action = [
          "lambda:InvokeFunction"
        ]
        Resource = [
          aws_lambda_function.orchestrator.arn,
          "${aws_lambda_function.orchestrator.arn}:*"
        ]
      },
      {
        Sid    = "PublishSNS"
        Effect = "Allow"
        Action = [
          "sns:Publish"
        ]
        Resource = [
          var.alerts_sns_topic_arn
        ]
      },
      {
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogDelivery",
          "logs:GetLogDelivery",
          "logs:UpdateLogDelivery",
          "logs:DeleteLogDelivery",
          "logs:ListLogDeliveries",
          "logs:PutResourcePolicy",
          "logs:DescribeResourcePolicies",
          "logs:DescribeLogGroups"
        ]
        Resource = "*"
      }
    ]
  })
}

# ==============================================================================
# CloudWatch Log Groups
# ==============================================================================

resource "aws_cloudwatch_log_group" "step_functions" {
  name              = "/aws/vendedlogs/states/${var.name_prefix}-canary-deploy-${var.component}"
  retention_in_days = local.is_prod ? 90 : 14
  kms_key_id        = var.logs_kms_key_arn

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-canary-sfn-${var.component}-logs"
    Component = "canary"
    Cell      = var.cell_id
  })
}

# ==============================================================================
# SSM Parameters for Deployment State
# ==============================================================================

# Canary deployment state: idle, deploying, rolling_back
resource "aws_ssm_parameter" "canary_state" {
  name  = "/${var.environment}/nhp/${var.cell_id}/canary/${var.component}/state"
  type  = "String"
  value = "idle"

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-canary-${var.component}-state"
    Component = "canary"
    Cell      = var.cell_id
  })

  lifecycle {
    ignore_changes = [value]
  }
}

# State machine ARN (for GitHub Actions workflow to find the correct state machine)
resource "aws_ssm_parameter" "canary_state_machine_arn" {
  name  = "/${var.environment}/nhp/${var.cell_id}/canary/${var.component}/state-machine-arn"
  type  = "String"
  value = aws_sfn_state_machine.canary_deploy.arn

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-canary-${var.component}-state-machine-arn"
    Component = "canary"
    Cell      = var.cell_id
  })
}

# Active Step Functions execution ARN (for EventBridge rollback to find active execution)
resource "aws_ssm_parameter" "canary_execution_arn" {
  name  = "/${var.environment}/nhp/${var.cell_id}/canary/${var.component}/execution-arn"
  type  = "String"
  value = "none"

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-canary-${var.component}-execution-arn"
    Component = "canary"
    Cell      = var.cell_id
  })

  lifecycle {
    ignore_changes = [value]
  }
}
