# Billing - API Gateway HTTP API
#
# HTTP API for billing endpoints with JWT authorizer for authenticated routes
# and unauthenticated webhook endpoint (uses Stripe signature verification).
# CORS is handled at both the API Gateway level (OPTIONS preflight) and
# Lambda level (response headers on non-OPTIONS requests).

# ==============================================================================
# HTTP API
# ==============================================================================

resource "aws_apigatewayv2_api" "billing" {
  name          = "${var.name_prefix}-billing-api"
  protocol_type = "HTTP"

  cors_configuration {
    allow_origins = var.allowed_origins
    allow_methods = ["GET", "POST", "OPTIONS"]
    allow_headers = ["content-type", "authorization"]
    max_age       = 3600
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-billing-api"
    Component = local.component
  })
}

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.billing.id
  name        = "$default"
  auto_deploy = true

  default_route_settings {
    throttling_burst_limit = var.api_throttle_burst_limit
    throttling_rate_limit  = var.api_throttle_rate_limit
  }

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.api_access.arn
    format = jsonencode({
      requestId      = "$context.requestId"
      ip             = "$context.identity.sourceIp"
      requestTime    = "$context.requestTime"
      httpMethod     = "$context.httpMethod"
      routeKey       = "$context.routeKey"
      status         = "$context.status"
      protocol       = "$context.protocol"
      responseLength = "$context.responseLength"
      integrationErr = "$context.integrationErrorMessage"
      errorMessage   = "$context.error.message"
    })
  }

  tags = merge(var.tags, {
    Component = local.component
  })
}

resource "aws_cloudwatch_log_group" "api_access" {
  name              = "/aws/apigateway/${var.name_prefix}-billing"
  retention_in_days = local.is_prod ? 90 : 14
  kms_key_id        = var.logs_kms_key_arn

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-billing-api-access-logs"
    Component = local.component
  })
}

# ==============================================================================
# JWT Authorizer (Auth0)
# ==============================================================================

resource "aws_apigatewayv2_authorizer" "auth0_jwt" {
  api_id           = aws_apigatewayv2_api.billing.id
  authorizer_type  = "JWT"
  name             = "auth0-jwt"
  identity_sources = ["$request.header.Authorization"]

  jwt_configuration {
    audience = [var.auth0_audience]
    issuer   = "https://${var.auth0_domain}/"
  }
}

# ==============================================================================
# Integrations
# ==============================================================================

resource "aws_apigatewayv2_integration" "stripe_webhook" {
  api_id                 = aws_apigatewayv2_api.billing.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.stripe_webhook.invoke_arn
  payload_format_version = "2.0"
}

# ==============================================================================
# Unauthenticated Routes
#
# The webhook route intentionally has no JWT authorizer. Stripe cannot
# present a JWT — it authenticates by signing the request body with a
# shared HMAC-SHA256 secret. The Lambda verifies the Stripe-Signature
# header (timestamp + HMAC) before processing any event.
# ==============================================================================

resource "aws_apigatewayv2_route" "stripe_webhook" {
  api_id    = aws_apigatewayv2_api.billing.id
  route_key = "POST /billing/webhook"
  target    = "integrations/${aws_apigatewayv2_integration.stripe_webhook.id}"
}

# ==============================================================================
# Lambda Permissions (allow API GW to invoke)
# ==============================================================================

resource "aws_lambda_permission" "stripe_webhook" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.stripe_webhook.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.billing.execution_arn}/*/*"
}
