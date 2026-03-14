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
