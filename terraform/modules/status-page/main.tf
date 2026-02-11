# Status Page Module
#
# Deploys a status page for NHP deployment visibility:
# - Lambda function aggregates status from SSM, ELB, CloudWatch
# - API Gateway (HTTP API) exposes the Lambda as a REST endpoint
# - S3 + CloudFront hosts the static frontend
# - Optional Route53 record for custom domain
# - SSM parameter exports SNS topic ARN for CI/CD notifications

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
  is_prod          = var.environment == "prod"
  bucket_name      = "${var.name_prefix}-status-page-${data.aws_caller_identity.current.account_id}"
  has_domain       = var.status_domain != null && var.acm_certificate_arn != null
  frontend_content = templatefile("${path.module}/frontend/index.html", { api_url = "${aws_apigatewayv2_stage.default.invoke_url}/status" })
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
      ENVIRONMENT        = var.environment
      SSM_PREFIX         = var.ssm_prefix
      SERVER_NLB_TG_ARNS = join(",", var.server_nlb_tg_arns)
      AC_NLB_TG_ARNS     = join(",", var.ac_nlb_tg_arns)
      ALARM_NAME_PREFIX  = var.alarm_name_prefix
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
        Action = ["ssm:GetParameters"]
        Resource = [
          "arn:aws:ssm:${data.aws_region.current.id}:${data.aws_caller_identity.current.account_id}:parameter${var.ssm_prefix}/*"
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
# CloudFront Distribution
# ==============================================================================

resource "aws_cloudfront_origin_access_control" "status" {
  name                              = "${var.name_prefix}-status-oac"
  description                       = "OAC for status page"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

# AWS managed cache policy for static content
data "aws_cloudfront_cache_policy" "caching_optimized" {
  name = "Managed-CachingOptimized"
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

    cache_policy_id            = data.aws_cloudfront_cache_policy.caching_optimized.id
    response_headers_policy_id = aws_cloudfront_response_headers_policy.status.id

    viewer_protocol_policy = "redirect-to-https"
    compress               = true
  }

  # Serve index.html for all paths
  custom_error_response {
    error_code            = 403
    response_code         = 200
    response_page_path    = "/index.html"
    error_caching_min_ttl = 10
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
