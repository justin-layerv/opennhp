# Developer Portal - API Gateway HTTP API
#
# Separate HTTP API for developer portal endpoints.
# CORS is handled at both the API Gateway level (OPTIONS preflight) and
# Lambda level (response headers on non-OPTIONS requests).

# ==============================================================================
# HTTP API
# ==============================================================================

resource "aws_apigatewayv2_api" "developer_portal" {
  name          = "${var.name_prefix}-developer-portal-api"
  protocol_type = "HTTP"

  cors_configuration {
    allow_origins = var.allowed_origins
    allow_methods = ["GET", "POST", "DELETE", "OPTIONS"]
    allow_headers = ["content-type", "authorization"]
    max_age       = 3600
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-developer-portal-api"
    Component = local.component
  })
}

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.developer_portal.id
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
  name              = "/aws/apigateway/${var.name_prefix}-developer-portal"
  retention_in_days = local.is_prod ? 90 : 14
  kms_key_id        = var.logs_kms_key_arn

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-developer-portal-api-access-logs"
    Component = local.component
  })
}

# ==============================================================================
# Integrations
# ==============================================================================

resource "aws_apigatewayv2_integration" "playground" {
  api_id                 = aws_apigatewayv2_api.developer_portal.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.playground.invoke_arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_integration" "credentials" {
  api_id                 = aws_apigatewayv2_api.developer_portal.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.credentials.invoke_arn
  payload_format_version = "2.0"
}

# ==============================================================================
# Playground Routes (5 routes)
# ==============================================================================

resource "aws_apigatewayv2_route" "playground_health" {
  api_id    = aws_apigatewayv2_api.developer_portal.id
  route_key = "GET /playground/health"
  target    = "integrations/${aws_apigatewayv2_integration.playground.id}"
}

resource "aws_apigatewayv2_route" "playground_create" {
  api_id    = aws_apigatewayv2_api.developer_portal.id
  route_key = "POST /playground/qurl"
  target    = "integrations/${aws_apigatewayv2_integration.playground.id}"
}

resource "aws_apigatewayv2_route" "playground_get" {
  api_id    = aws_apigatewayv2_api.developer_portal.id
  route_key = "GET /playground/qurl/{id}"
  target    = "integrations/${aws_apigatewayv2_integration.playground.id}"
}

resource "aws_apigatewayv2_route" "playground_delete" {
  api_id    = aws_apigatewayv2_api.developer_portal.id
  route_key = "DELETE /playground/qurl/{id}"
  target    = "integrations/${aws_apigatewayv2_integration.playground.id}"
}

resource "aws_apigatewayv2_route" "playground_mint" {
  api_id    = aws_apigatewayv2_api.developer_portal.id
  route_key = "POST /playground/qurl/{id}/mint"
  target    = "integrations/${aws_apigatewayv2_integration.playground.id}"
}

# ==============================================================================
# Credentials Routes (3 routes)
# ==============================================================================

resource "aws_apigatewayv2_route" "credentials_health" {
  api_id    = aws_apigatewayv2_api.developer_portal.id
  route_key = "GET /credentials/health"
  target    = "integrations/${aws_apigatewayv2_integration.credentials.id}"
}

resource "aws_apigatewayv2_route" "credentials_register" {
  api_id    = aws_apigatewayv2_api.developer_portal.id
  route_key = "POST /credentials/register"
  target    = "integrations/${aws_apigatewayv2_integration.credentials.id}"
}

resource "aws_apigatewayv2_route" "credentials_verify" {
  api_id    = aws_apigatewayv2_api.developer_portal.id
  route_key = "GET /credentials/verify"
  target    = "integrations/${aws_apigatewayv2_integration.credentials.id}"
}

# ==============================================================================
# Lambda Permissions (allow API GW to invoke)
# ==============================================================================

resource "aws_lambda_permission" "playground" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.playground.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.developer_portal.execution_arn}/*/*"
}

resource "aws_lambda_permission" "credentials" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.credentials.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.developer_portal.execution_arn}/*/*"
}

# ==============================================================================
# Custom Domain (optional)
# ==============================================================================

resource "aws_apigatewayv2_domain_name" "developer_portal" {
  count       = local.has_custom_domain ? 1 : 0
  domain_name = var.custom_domain

  domain_name_configuration {
    certificate_arn = var.acm_certificate_arn
    endpoint_type   = "REGIONAL"
    security_policy = "TLS_1_2"
  }

  lifecycle {
    precondition {
      condition     = var.acm_certificate_arn != null
      error_message = "acm_certificate_arn must be provided when custom_domain is set."
    }
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-developer-portal-domain"
    Component = local.component
  })
}

resource "aws_apigatewayv2_api_mapping" "developer_portal" {
  count       = local.has_custom_domain ? 1 : 0
  api_id      = aws_apigatewayv2_api.developer_portal.id
  domain_name = aws_apigatewayv2_domain_name.developer_portal[0].id
  stage       = aws_apigatewayv2_stage.default.id
}

resource "aws_route53_record" "developer_portal" {
  count   = local.has_custom_domain && var.hosted_zone_id != null ? 1 : 0
  zone_id = var.hosted_zone_id
  name    = var.custom_domain
  type    = "A"

  alias {
    name                   = aws_apigatewayv2_domain_name.developer_portal[0].domain_name_configuration[0].target_domain_name
    zone_id                = aws_apigatewayv2_domain_name.developer_portal[0].domain_name_configuration[0].hosted_zone_id
    evaluate_target_health = false
  }
}
