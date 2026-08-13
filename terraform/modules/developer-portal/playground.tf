# Developer Portal - Playground Proxy Lambda
#
# Proxies playground requests to the QURL API with M2M authentication.
# Enforces rate limits, TTL caps, and URL validation.

# ==============================================================================
# Lambda Package
# ==============================================================================

data "archive_file" "playground" {
  type        = "zip"
  source_file = "${path.module}/lambda/playground_proxy.py"
  output_path = "${path.module}/lambda/playground_proxy.zip"
}

# ==============================================================================
# Lambda Function
# ==============================================================================

resource "aws_lambda_function" "playground" {
  depends_on = [aws_cloudwatch_log_group.playground]

  # Cross-variable invariant — single-variable validation blocks can't
  # reference other variables. The binding constraint is API Gateway's
  # 30s integration timeout (see aws_apigatewayv2_integration.playground
  # in api_gateway.tf), NOT the Lambda's 60s timeout (which is just an
  # upper bound). Cap the combined outbound budget at 25s, leaving 5s
  # for base64 decode + DynamoDB rate-limit writes + cold-start M2M
  # token fetch + transport setup before API GW cuts the integration.
  lifecycle {
    precondition {
      condition     = var.playground_upload_timeout_seconds + var.playground_mint_timeout_seconds <= 25
      error_message = "playground_upload_timeout_seconds + playground_mint_timeout_seconds must be <= 25 (leaves 5s headroom inside API Gateway's 30s integration timeout for base64 decode + rate-limit writes + cold-start M2M + transport)."
    }
    precondition {
      condition = (
        (var.playground_demo_target_url == "") ==
        (var.playground_demo_resource_id == "")
        ) && (
        (var.playground_demo_target_url == "") ==
        (var.playground_demo_qurl_site == "")
      )
      error_message = "playground_demo_target_url, playground_demo_resource_id, and playground_demo_qurl_site must be set together (all or none) — a partial config silently disables the demo mint path."
    }
  }

  filename         = data.archive_file.playground.output_path
  function_name    = "${var.name_prefix}-playground-proxy"
  role             = aws_iam_role.playground.arn
  handler          = "playground_proxy.lambda_handler"
  source_code_hash = data.archive_file.playground.output_base64sha256
  runtime          = "python3.12"
  # 60s (was 30s) is an upper bound — the binding budget for any
  # /playground/upload request is API Gateway's 30s integration
  # timeout (see aws_apigatewayv2_integration.playground). The Lambda
  # timeout still matters for URL-mode handlers (which share the
  # function and benefit from CPU scaling with memory at the higher
  # tier) and as a safety net if a misconfigured deploy lifts the
  # API GW limit. The /playground/upload path makes two sequential
  # connector calls (defaults 15s upload + 8s mint = 23s) on top of
  # base64 decode + rate-limit DynamoDB writes + a possible cold-
  # start M2M token fetch. The cross-variable precondition below
  # caps the sum at 25s, leaving 5s headroom under the 30s API GW
  # gate.
  timeout = 60
  # 384 MB (was 256 MB). CPU scales linearly with memory on Lambda, so
  # the bump is primarily about cold-start latency on the upload path
  # (base64 decode of a 4 MB body + multipart forwarding to the
  # connector) — the URL-mode handlers don't need the extra memory but
  # they share the function. Memory headroom is the secondary reason:
  # 4 MB binary + ~5.3 MB base64 + Python string overhead during decode
  # peaks well below 256 MB, so OOM wasn't a real risk at the old size.
  memory_size = 384

  tracing_config {
    mode = "Active"
  }

  environment {
    variables = merge(
      {
        QURL_API_URL                 = var.qurl_api_url
        M2M_SECRET_NAME              = var.playground_m2m_secret_name
        RATE_TABLE_NAME              = aws_dynamodb_table.rate_limits.name
        ALLOWED_ORIGINS              = join(",", var.allowed_origins)
        AUTH0_DOMAIN                 = var.auth0_domain
        PLAYGROUND_IP_RATE_LIMIT     = tostring(var.playground_ip_rate_limit)
        PLAYGROUND_GLOBAL_RATE_LIMIT = tostring(var.playground_global_rate_limit)
        RATE_WINDOW                  = tostring(var.playground_rate_window)
        CONNECTOR_BASE_URL           = var.connector_base_url
        PLAYGROUND_MAX_UPLOAD_BYTES  = tostring(var.playground_max_upload_bytes)
        PLAYGROUND_UPLOAD_TIMEOUT    = tostring(var.playground_upload_timeout_seconds)
        PLAYGROUND_MINT_TIMEOUT      = tostring(var.playground_mint_timeout_seconds)
      },
      var.ci_bypass_secret_name != null ? {
        CI_BYPASS_SECRET_NAME = var.ci_bypass_secret_name
      } : {},
      # Fixed-resource demo: rendered only when configured so the dark
      # default leaves no empty env vars behind. All-or-none is enforced
      # by the lifecycle precondition above.
      var.playground_demo_target_url != "" ? {
        PLAYGROUND_DEMO_TARGET_URL  = var.playground_demo_target_url
        PLAYGROUND_DEMO_RESOURCE_ID = var.playground_demo_resource_id
        PLAYGROUND_DEMO_QURL_SITE   = var.playground_demo_qurl_site
      } : {}
    )
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-playground-proxy"
    Component = local.component
  })
}

# ==============================================================================
# CloudWatch Log Group
# ==============================================================================

resource "aws_cloudwatch_log_group" "playground" {
  name              = "/aws/lambda/${var.name_prefix}-playground-proxy"
  retention_in_days = local.is_prod ? 90 : 14
  kms_key_id        = var.logs_kms_key_arn

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-playground-proxy-logs"
    Component = local.component
  })
}

# ==============================================================================
# IAM Role
# ==============================================================================

resource "aws_iam_role" "playground" {
  name = "${var.name_prefix}-playground-proxy-role"

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
    Name      = "${var.name_prefix}-playground-proxy-role"
    Component = local.component
  })
}

resource "aws_iam_role_policy_attachment" "playground_basic" {
  role       = aws_iam_role.playground.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy_attachment" "playground_xray" {
  role       = aws_iam_role.playground.name
  policy_arn = "arn:aws:iam::aws:policy/AWSXRayDaemonWriteAccess"
}

resource "aws_iam_role_policy" "playground" {
  name = "${var.name_prefix}-playground-proxy-policy"
  role = aws_iam_role.playground.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [
        {
          Sid    = "DynamoDBRateLimits"
          Effect = "Allow"
          Action = [
            "dynamodb:GetItem",
            "dynamodb:PutItem",
            "dynamodb:UpdateItem"
          ]
          Resource = aws_dynamodb_table.rate_limits.arn
        },
        {
          Sid      = "SecretsManagerM2M"
          Effect   = "Allow"
          Action   = ["secretsmanager:GetSecretValue"]
          Resource = "arn:aws:secretsmanager:${data.aws_region.current.id}:${data.aws_caller_identity.current.account_id}:secret:${var.playground_m2m_secret_name}-*"
        },
        {
          Sid      = "CloudWatchMetrics"
          Effect   = "Allow"
          Action   = ["cloudwatch:PutMetricData"]
          Resource = "*"
          Condition = {
            StringEquals = {
              "cloudwatch:namespace" = "LayerV/DeveloperPortal"
            }
          }
        }
      ],
      var.dynamodb_kms_key_arn != null ? [
        {
          Sid    = "KMSDecrypt"
          Effect = "Allow"
          Action = [
            "kms:Decrypt",
            "kms:GenerateDataKey"
          ]
          Resource = var.dynamodb_kms_key_arn
        }
      ] : [],
      var.ci_bypass_secret_name != null ? [
        {
          Sid      = "SecretsManagerCIBypass"
          Effect   = "Allow"
          Action   = ["secretsmanager:GetSecretValue"]
          Resource = "arn:aws:secretsmanager:${data.aws_region.current.id}:${data.aws_caller_identity.current.account_id}:secret:${var.ci_bypass_secret_name}-*"
        }
      ] : []
    )
  })
}

# ==============================================================================
# CloudWatch Alarm (optional)
# ==============================================================================

# Demo-mint failure visibility. handle_demo_mint passes upstream errors
# through and the LiveDemo client silently falls back to simulated links, so
# this log-literal filter + alarm is the ONLY operator signal that the live
# demo is degraded (deleted demo resource, rotated M2M credentials, upstream
# outage). The pattern matches the Lambda's exact logger.warning literal;
# while the demo is unconfigured (dark) the filter simply never matches.
resource "aws_cloudwatch_log_metric_filter" "playground_demo_mint_failures" {
  name           = "${var.name_prefix}-playground-demo-mint-failures"
  log_group_name = aws_cloudwatch_log_group.playground.name
  pattern        = "{ $.message = \"Demo mint upstream failure\" }"

  metric_transformation {
    name      = "PlaygroundDemoMintFailures"
    namespace = "LayerV/DeveloperPortal"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "playground_demo_mint_failures" {
  count               = local.has_sns ? 1 : 0
  alarm_name          = "${var.name_prefix}-playground-demo-mint-failures"
  alarm_description   = "The LiveDemo fixed-resource mint is failing upstream — users are silently getting simulated links. Check the demo resource, playground M2M credentials, and qurl-service health."
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "PlaygroundDemoMintFailures"
  namespace           = "LayerV/DeveloperPortal"
  period              = 900
  statistic           = "Sum"
  threshold           = 2
  treat_missing_data  = "notBreaching"

  alarm_actions = [var.sns_topic_arn]
  ok_actions    = [var.sns_topic_arn]
}

resource "aws_cloudwatch_metric_alarm" "playground_errors" {
  count               = local.has_sns ? 1 : 0
  alarm_name          = "${var.name_prefix}-playground-proxy-errors"
  alarm_description   = "Playground proxy Lambda function errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 300
  statistic           = "Sum"
  threshold           = 5
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = aws_lambda_function.playground.function_name
  }

  alarm_actions = [var.sns_topic_arn]
  ok_actions    = [var.sns_topic_arn]

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-playground-proxy-errors"
    Component = local.component
  })
}
