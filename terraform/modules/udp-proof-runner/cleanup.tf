data "archive_file" "broker" {
  type        = "zip"
  source_file = "${path.module}/lambda/broker.py"
  output_path = "${path.module}/lambda/broker.zip"
}

resource "aws_cloudwatch_log_group" "broker" {
  name              = "/layerv/nhp/${var.environment}/udp-proof-runner-broker"
  retention_in_days = 30

  tags = local.tags
}

resource "aws_lambda_function" "broker" {
  function_name = "${local.runner_name}-broker"
  description   = "Launch exactly one reviewed UDP proof runner and reap expired compute/JIT metadata"
  role          = aws_iam_role.broker.arn
  runtime       = "python3.12"
  handler       = "broker.handler"
  architectures = ["arm64"]

  filename         = data.archive_file.broker.output_path
  source_code_hash = data.archive_file.broker.output_base64sha256

  timeout                        = 30
  reserved_concurrent_executions = 1

  logging_config {
    log_format = "Text"
    log_group  = aws_cloudwatch_log_group.broker.name
  }

  environment {
    variables = {
      ENVIRONMENT                      = var.environment
      EIP_ALLOCATION_ID                = aws_eip.source.id
      JIT_SECRET_PREFIX                = local.jit_secret_prefix
      ACCOUNT_CREDENTIAL_SECRET_PREFIX = local.proof_account_jit_secret_prefix
      LAUNCH_TEMPLATE_ID               = aws_launch_template.runner.id
      LAUNCH_TEMPLATE_VERSION          = tostring(aws_launch_template.runner.latest_version)
      MAX_RUNTIME_SECONDS              = tostring(var.max_runtime_minutes * 60)
      RECOVERY_REQUEST_SECRET_PREFIX   = local.recovery_request_secret_prefix
      RECOVERY_RESPONSE_SECRET_PREFIX  = local.recovery_response_secret_prefix
    }
  }

  tags = local.tags

  # The log group is referenced in logging_config above, so its dependency is
  # already implicit. Only the inline role policy needs an explicit edge.
  depends_on = [
    aws_iam_role_policy.broker,
  ]
}

resource "aws_cloudwatch_event_rule" "sweep" {
  name                = "${local.runner_name}-sweep"
  description         = "Independent fail-closed cleanup for expired UDP proof runners and JIT metadata"
  schedule_expression = "rate(5 minutes)"

  tags = local.tags
}

resource "aws_cloudwatch_event_target" "sweep" {
  rule = aws_cloudwatch_event_rule.sweep.name
  arn  = aws_lambda_function.broker.arn
}

resource "aws_lambda_permission" "events" {
  statement_id  = "AllowScheduledSweep"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.broker.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.sweep.arn
}
