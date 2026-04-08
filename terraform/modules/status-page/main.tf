# Status Page Module
#
# Deploys a status page for NHP deployment visibility:
# - Lambda function aggregates status from SSM, ELB, CloudWatch
# - API Gateway (HTTP API) exposes the Lambda as a REST endpoint
# - S3 + CloudFront hosts the static frontend
# - Optional Route53 record for custom domain
# - SSM parameter exports SNS topic ARN for CI/CD notifications
# - Optional NHP authentication via CloudFront Function (dogfooding)

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = ">= 2.0"
    }
  }
}

data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

locals {
  is_prod     = var.environment == "prod"
  bucket_name = "${var.name_prefix}-status-page-${data.aws_caller_identity.current.account_id}"
  has_domain  = var.status_domain != null && var.acm_certificate_arn != null
  frontend_content = templatefile("${path.module}/frontend/index.html", {
    api_url               = "${aws_apigatewayv2_stage.default.invoke_url}/status"
    grafana_dashboard_url = var.grafana_dashboard_url
  })

  # NHP auth: CloudFront Function code with QURL URL and cookie name injected
  nhp_auth_function_code = var.enable_nhp_auth ? templatefile(
    "${path.module}/cloudfront-functions/nhp_auth.js",
    {
      qurl_url    = var.nhp_auth_qurl_url
      cookie_name = var.nhp_auth_cookie_name
    }
  ) : null
}

# ==============================================================================
# Lambda Function - Status Aggregator
# ==============================================================================

data "archive_file" "status_aggregator" {
  type        = "zip"
  source_file = "${path.module}/lambda/status_aggregator.py"
  output_path = "${path.module}/lambda/status_aggregator.zip"
}

resource "aws_lambda_function" "status_aggregator" {
  depends_on = [aws_cloudwatch_log_group.status_aggregator]

  filename         = data.archive_file.status_aggregator.output_path
  function_name    = "${var.name_prefix}-status-aggregator"
  role             = aws_iam_role.status_aggregator.arn
  handler          = "status_aggregator.handler"
  source_code_hash = data.archive_file.status_aggregator.output_base64sha256
  runtime          = "python3.12"
  timeout          = 30
  memory_size      = 128

  environment {
    variables = {
      ENVIRONMENT            = var.environment
      SSM_PREFIX             = var.ssm_prefix
      SERVER_NLB_TG_ARNS     = join(",", var.server_nlb_tg_arns)
      AC_NLB_TG_ARNS         = join(",", var.ac_nlb_tg_arns)
      ALARM_NAME_PREFIX      = var.alarm_name_prefix
      SERVER_NLB_ARN_SUFFIX  = var.server_nlb_arn_suffix
      AC_NLB_ARN_SUFFIX      = var.ac_nlb_arn_suffix
      SERVER_ASG_NAME        = var.server_asg_name
      AC_ASG_NAME            = var.ac_asg_name
      DEPLOYMENT_MODEL       = var.deployment_model
      CANARY_STATE_SSM_PARAM = var.canary_state_ssm_param
      DEPENDENT_SERVICE_URLS = jsonencode(var.dependent_service_urls)
      SSL_CERT_ARNS          = jsonencode(var.ssl_cert_arns)
    }
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-status-aggregator"
    Component = "status-page"
  })
}

resource "aws_cloudwatch_log_group" "status_aggregator" {
  name              = "/aws/lambda/${var.name_prefix}-status-aggregator"
  retention_in_days = local.is_prod ? 90 : 14
  kms_key_id        = var.logs_kms_key_arn

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-status-aggregator-logs"
    Component = "status-page"
  })
}

# ==============================================================================
# Lambda IAM Role
# ==============================================================================

resource "aws_iam_role" "status_aggregator" {
  name = "${var.name_prefix}-status-aggregator-role"

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
    Name      = "${var.name_prefix}-status-aggregator-role"
    Component = "status-page"
  })
}

resource "aws_iam_role_policy_attachment" "status_aggregator_basic" {
  role       = aws_iam_role.status_aggregator.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "status_aggregator" {
  name = "${var.name_prefix}-status-aggregator-policy"
  role = aws_iam_role.status_aggregator.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadSSMParameters"
        Effect = "Allow"
        Action = ["ssm:GetParameters", "ssm:GetParameter"]
        Resource = [
          "arn:aws:ssm:${data.aws_region.current.id}:${data.aws_caller_identity.current.account_id}:parameter${var.ssm_prefix}/*",
          "arn:aws:ssm:${data.aws_region.current.id}:${data.aws_caller_identity.current.account_id}:parameter/${var.environment}/nhp/*/canary/*",
        ]
      },
      {
        Sid    = "DescribeTargetHealth"
        Effect = "Allow"
        Action = [
          "elasticloadbalancing:DescribeTargetHealth"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = data.aws_region.current.id
          }
        }
      },
      {
        Sid    = "DescribeAlarms"
        Effect = "Allow"
        Action = [
          "cloudwatch:DescribeAlarms"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = data.aws_region.current.id
          }
        }
      },
      {
        Sid    = "GetMetricData"
        Effect = "Allow"
        Action = [
          "cloudwatch:GetMetricData"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = data.aws_region.current.id
          }
        }
      },
      {
        Sid    = "DescribeASGs"
        Effect = "Allow"
        Action = [
          "autoscaling:DescribeAutoScalingGroups"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = data.aws_region.current.id
          }
        }
      },
      {
        Sid    = "DescribeACMCertificates"
        Effect = "Allow"
        Action = [
          "acm:DescribeCertificate"
        ]
        Resource = "arn:aws:acm:${data.aws_region.current.id}:${data.aws_caller_identity.current.account_id}:certificate/*"
      }
    ]
  })
}

# ==============================================================================
# API Gateway (HTTP API)
# ==============================================================================

resource "aws_apigatewayv2_api" "status" {
  name          = "${var.name_prefix}-status-api"
  protocol_type = "HTTP"

  # CORS handled by Lambda response headers to avoid circular dependency
  # (CloudFront domain not known until after API GW is created)

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-status-api"
    Component = "status-page"
  })
}

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.status.id
  name        = "$default"
  auto_deploy = true

  default_route_settings {
    throttling_burst_limit = 100
    throttling_rate_limit  = 50
  }

  tags = merge(var.tags, {
    Component = "status-page"
  })
}

resource "aws_apigatewayv2_integration" "status" {
  api_id                 = aws_apigatewayv2_api.status.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.status_aggregator.invoke_arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "status" {
  api_id    = aws_apigatewayv2_api.status.id
  route_key = "GET /status"
  target    = "integrations/${aws_apigatewayv2_integration.status.id}"
}

resource "aws_lambda_permission" "api_gateway" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.status_aggregator.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.status.execution_arn}/*/*"
}

# ==============================================================================
# S3 Bucket - Frontend Static Files
# ==============================================================================

resource "aws_s3_bucket" "status" {
  bucket = local.bucket_name

  tags = merge(var.tags, {
    Name      = local.bucket_name
    Component = "status-page"
  })
}

resource "aws_s3_bucket_versioning" "status" {
  bucket = aws_s3_bucket.status.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "status" {
  bucket = aws_s3_bucket.status.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "status" {
  bucket = aws_s3_bucket.status.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Upload frontend with API URL injected
resource "aws_s3_object" "index" {
  bucket       = aws_s3_bucket.status.id
  key          = "index.html"
  content      = local.frontend_content
  content_type = "text/html"
  etag         = md5(local.frontend_content)

  tags = var.tags
}

# ==============================================================================
# NHP Authentication - CloudFront Function
# ==============================================================================
# Lightweight viewer-request function that checks for an NHP session cookie.
# Unauthenticated requests are redirected to the QURL login portal, which
# triggers the NHP knock flow and sets cookies before redirecting back.

resource "aws_cloudfront_function" "nhp_auth" {
  count = var.enable_nhp_auth ? 1 : 0

  name    = replace("${var.name_prefix}-status-nhp-auth", ".", "-")
  runtime = "cloudfront-js-2.0"
  comment = "NHP auth gate for status page - redirects unauthenticated requests to QURL"
  publish = true
  code    = local.nhp_auth_function_code

  # Enforce the dependency between enable_nhp_auth and nhp_auth_qurl_url at
  # plan time. A `check` block would only emit a warning, which is too easy to
  # miss in CI; a precondition fails the plan/apply outright. The terraform
  # variable validation also catches this, but the precondition gives a clear
  # message at the resource level.
  lifecycle {
    precondition {
      condition     = var.nhp_auth_qurl_url != null && var.nhp_auth_qurl_url != ""
      error_message = "nhp_auth_qurl_url is required when enable_nhp_auth is true."
    }

    # CloudFront Functions have a hard 10 KB code-size limit. Fail at plan
    # time if the rendered function exceeds 8 KB so we have headroom against
    # the limit and catch the regression before AWS rejects the deployment.
    # length() returns characters, but the function is ASCII so 1 char = 1 byte.
    precondition {
      condition     = length(local.nhp_auth_function_code) <= 8192
      error_message = "Rendered nhp_auth.js exceeds 8 KB safety floor (CloudFront Function hard limit is 10 KB). Trim the function before deploying."
    }
  }
}

# ==============================================================================
# CloudFront Distribution
# ==============================================================================

resource "aws_cloudfront_origin_access_control" "status" {
  name                              = "${var.name_prefix}-status-oac"
  description                       = "OAC for status page"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

# Custom cache policy with short TTLs so CloudFront picks up S3 changes quickly.
# The status page is a single small HTML file — aggressive caching isn't needed.
resource "aws_cloudfront_cache_policy" "status" {
  name        = replace("${var.name_prefix}-status-page-cache", ".", "-")
  comment     = "Short TTL cache policy for status page - revalidates within 60s"
  min_ttl     = 0
  default_ttl = 60
  max_ttl     = 300

  parameters_in_cache_key_and_forwarded_to_origin {
    cookies_config {
      cookie_behavior = "none"
    }
    headers_config {
      header_behavior = "none"
    }
    query_strings_config {
      query_string_behavior = "none"
    }
    enable_accept_encoding_gzip   = true
    enable_accept_encoding_brotli = true
  }
}

resource "aws_cloudfront_response_headers_policy" "status" {
  name = replace("${var.name_prefix}-status-security-headers", ".", "-")

  security_headers_config {
    content_security_policy {
      content_security_policy = "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self' ${aws_apigatewayv2_stage.default.invoke_url}"
      override                = true
    }
    strict_transport_security {
      access_control_max_age_sec = 31536000
      include_subdomains         = true
      preload                    = true
      override                   = true
    }
    content_type_options {
      override = true
    }
    frame_options {
      frame_option = "DENY"
      override     = true
    }
    referrer_policy {
      referrer_policy = "strict-origin-when-cross-origin"
      override        = true
    }
  }
}

resource "aws_cloudfront_distribution" "status" {
  enabled             = true
  is_ipv6_enabled     = true
  default_root_object = "index.html"
  aliases             = local.has_domain ? [var.status_domain] : []
  price_class         = "PriceClass_100" # US, Canada, Europe
  comment             = "NHP Status Page - ${var.environment}"

  origin {
    domain_name              = aws_s3_bucket.status.bucket_regional_domain_name
    origin_id                = "S3-${local.bucket_name}"
    origin_access_control_id = aws_cloudfront_origin_access_control.status.id
  }

  default_cache_behavior {
    allowed_methods  = ["GET", "HEAD"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "S3-${local.bucket_name}"

    cache_policy_id            = aws_cloudfront_cache_policy.status.id
    response_headers_policy_id = aws_cloudfront_response_headers_policy.status.id

    viewer_protocol_policy = "redirect-to-https"
    compress               = true

    # NHP auth: CloudFront Function checks for nhp_token cookie on every request.
    # Runs before cache lookup, so even cached responses require authentication.
    dynamic "function_association" {
      for_each = var.enable_nhp_auth ? [1] : []
      content {
        event_type   = "viewer-request"
        function_arn = aws_cloudfront_function.nhp_auth[0].arn
      }
    }
  }

  # Serve index.html for missing-file errors (S3 OAC returns 403 for missing
  # objects, not 404). The 403 fallback is dropped when NHP auth is enabled
  # because the auth gate's loop-detection branch returns its own 403 with a
  # diagnostic body — CloudFront's custom_error_response would otherwise
  # rewrite that 403 to a 200/index.html and strip the diagnostic, leaving
  # operators without the cookie-domain-mismatch hint that loop detection is
  # designed to surface.
  dynamic "custom_error_response" {
    for_each = var.enable_nhp_auth ? [] : [1]
    content {
      error_code            = 403
      response_code         = 200
      response_page_path    = "/index.html"
      error_caching_min_ttl = 10
    }
  }

  custom_error_response {
    error_code            = 404
    response_code         = 200
    response_page_path    = "/index.html"
    error_caching_min_ttl = 10
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    # Use ACM cert for custom domain, or default CloudFront cert
    acm_certificate_arn            = local.has_domain ? var.acm_certificate_arn : null
    ssl_support_method             = local.has_domain ? "sni-only" : null
    minimum_protocol_version       = local.has_domain ? "TLSv1.2_2021" : "TLSv1"
    cloudfront_default_certificate = local.has_domain ? false : true
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-status-page"
    Component = "status-page"
  })
}

# S3 bucket policy for CloudFront OAC
resource "aws_s3_bucket_policy" "status" {
  bucket = aws_s3_bucket.status.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowCloudFrontServicePrincipal"
        Effect = "Allow"
        Principal = {
          Service = "cloudfront.amazonaws.com"
        }
        Action   = "s3:GetObject"
        Resource = "${aws_s3_bucket.status.arn}/*"
        Condition = {
          StringEquals = {
            "AWS:SourceArn" = aws_cloudfront_distribution.status.arn
          }
        }
      }
    ]
  })
}

# ==============================================================================
# Route53 DNS Record (optional)
# ==============================================================================

resource "aws_route53_record" "status" {
  # Use variables (known at plan time) instead of local.has_domain which
  # depends on the computed acm_certificate_arn value
  count   = var.status_domain != null && var.hosted_zone_id != null ? 1 : 0
  zone_id = var.hosted_zone_id
  name    = var.status_domain
  type    = "A"

  alias {
    name                   = aws_cloudfront_distribution.status.domain_name
    zone_id                = aws_cloudfront_distribution.status.hosted_zone_id
    evaluate_target_health = false
  }
}

# ==============================================================================
# SSM Parameter - SNS Topic ARN (for CI/CD workflow notifications)
# ==============================================================================

resource "aws_ssm_parameter" "sns_topic_arn" {
  name  = "/${var.environment}/nhp/monitoring/sns-topic-arn"
  type  = "String"
  value = var.sns_topic_arn

  tags = merge(var.tags, {
    Component = "status-page"
  })
}

# ==============================================================================
# Self-Monitoring Alarms
# ==============================================================================

resource "aws_cloudwatch_metric_alarm" "lambda_errors" {
  alarm_name          = "${var.name_prefix}-status-lambda-errors"
  alarm_description   = "Status aggregator Lambda function errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = aws_lambda_function.status_aggregator.function_name
  }

  alarm_actions = [var.sns_topic_arn]
  ok_actions    = [var.sns_topic_arn]

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-status-lambda-errors"
    Component = "status-page"
  })
}

resource "aws_cloudwatch_metric_alarm" "lambda_duration" {
  alarm_name          = "${var.name_prefix}-status-lambda-duration"
  alarm_description   = "Status aggregator Lambda p99 duration exceeds 10s"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "Duration"
  namespace           = "AWS/Lambda"
  period              = 300
  extended_statistic  = "p99"
  threshold           = 10000
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = aws_lambda_function.status_aggregator.function_name
  }

  alarm_actions = [var.sns_topic_arn]
  ok_actions    = [var.sns_topic_arn]

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-status-lambda-duration"
    Component = "status-page"
  })
}

resource "aws_cloudwatch_metric_alarm" "api_gateway_5xx" {
  alarm_name          = "${var.name_prefix}-status-api-5xx"
  alarm_description   = "Status API Gateway 5xx errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "5xx"
  namespace           = "AWS/ApiGateway"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  treat_missing_data  = "notBreaching"

  dimensions = {
    ApiId = aws_apigatewayv2_api.status.id
  }

  alarm_actions = [var.sns_topic_arn]
  ok_actions    = [var.sns_topic_arn]

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-status-api-5xx"
    Component = "status-page"
  })
}

# Alarm on CloudFront Function execution errors. Because the NHP auth gate
# runs on every viewer-request, a spike in errors here means either a runtime
# regression in nhp_auth.js or a CloudFront-side issue — both of which would
# bypass authentication or 500 legitimate traffic.
resource "aws_cloudwatch_metric_alarm" "nhp_auth_function_errors" {
  count = var.enable_nhp_auth ? 1 : 0

  alarm_name          = "${var.name_prefix}-status-nhp-auth-errors"
  alarm_description   = "NHP auth CloudFront Function execution errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "FunctionExecutionErrors"
  namespace           = "AWS/CloudFront"
  period              = 300
  statistic           = "Sum"
  threshold           = 10
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = aws_cloudfront_function.nhp_auth[0].name
    Region       = "Global"
  }

  alarm_actions = [var.sns_topic_arn]
  ok_actions    = [var.sns_topic_arn]

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-status-nhp-auth-errors"
    Component = "status-page"
  })
}

# CloudFront also publishes FunctionValidationErrors when a function returns a
# response that fails CloudFront's structural validation (missing required
# fields, wrong types, etc.). Execution errors and validation errors are
# different failure modes — a function can compile and run cleanly while still
# returning a response CloudFront refuses to serve. Alarm on both so a future
# refactor that breaks the response shape pages on the same SNS topic.
resource "aws_cloudwatch_metric_alarm" "nhp_auth_function_validation_errors" {
  count = var.enable_nhp_auth ? 1 : 0

  alarm_name          = "${var.name_prefix}-status-nhp-auth-validation-errors"
  alarm_description   = "NHP auth CloudFront Function validation errors (invalid response shape)"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "FunctionValidationErrors"
  namespace           = "AWS/CloudFront"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = aws_cloudfront_function.nhp_auth[0].name
    Region       = "Global"
  }

  alarm_actions = [var.sns_topic_arn]
  ok_actions    = [var.sns_topic_arn]

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-status-nhp-auth-validation-errors"
    Component = "status-page"
  })
}
