# Status Page Module
#
# Deploys a public status page for NHP availability visibility:
# - Lambda function aggregates redacted status from ELB and CloudWatch
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
  is_prod                  = var.environment == "prod"
  bucket_name              = "${var.name_prefix}-status-page-${data.aws_caller_identity.current.account_id}"
  has_domain               = var.status_domain != null && var.acm_certificate_arn != null
  snapshot_cadence_minutes = 5
  status_metric_namespace  = "LayerV/NHP/StatusPage"
  frontend_content = templatefile("${path.module}/frontend/index.html", {
    status_feed_url          = "/status.json"
    snapshot_cadence_minutes = local.snapshot_cadence_minutes
  })
  initial_status_payload = jsonencode({
    environment = var.environment
    timestamp   = null
    overall     = "unknown"
    components  = []
    history     = {}
    incidents   = []
  })
  status_target_group_arns = distinct(compact(concat(
    var.server_nlb_tg_arns,
    var.ac_nlb_tg_arns,
    flatten(values(var.server_nlb_tg_arns_by_color)),
    flatten(values(var.ac_nlb_tg_arns_by_color)),
  )))
  active_color_parameter_names = compact([
    var.server_active_color_parameter,
    var.ac_active_color_parameter,
  ])
  active_color_parameter_arns = [
    for name in local.active_color_parameter_names :
    "arn:aws:ssm:${data.aws_region.current.id}:${data.aws_caller_identity.current.account_id}:parameter${name}"
  ]
  active_color_parameter_statements = length(local.active_color_parameter_arns) > 0 ? [
    {
      Sid      = "ReadActiveColor"
      Effect   = "Allow"
      Action   = ["ssm:GetParameter"]
      Resource = local.active_color_parameter_arns
      Condition = {
        StringEquals = {
          "aws:RequestedRegion" = data.aws_region.current.id
        }
      }
    }
  ] : []
  # No configured target groups means the Lambda makes no ELB calls; the wildcard
  # fallback keeps the IAM JSON valid for that inert module-default case.
  status_target_health_resources = length(local.status_target_group_arns) > 0 ? local.status_target_group_arns : [
    "*"
  ]
  unknown_display_only_component_ids = setsubtract(
    var.display_only_component_ids,
    toset(keys(var.dependent_service_urls)),
  )

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
  # Keep aligned with status_aggregator.py's bounded parallel HTTP probe budget.
  timeout     = 45
  memory_size = 128
  # Viewer traffic reads CloudFront/S3, not this compatibility API. Keep public
  # direct API callers in the same small reserved pool instead of letting them
  # borrow unreserved account concurrency. Five equals the API burst of three
  # plus two async slots for snapshot/incident retries; tune it with the stage
  # throttle and async event-age window if the compatibility API becomes a
  # supported polling path.
  reserved_concurrent_executions = 5

  environment {
    variables = {
      ENVIRONMENT = var.environment
      # *_NLB_TG_ARNS remains the non-blue/green fallback; when *_BY_COLOR and
      # an active-color parameter are configured, the Lambda selects one color.
      SERVER_NLB_TG_ARNS            = join(",", var.server_nlb_tg_arns)
      SERVER_NLB_TG_ARNS_BY_COLOR   = jsonencode(var.server_nlb_tg_arns_by_color)
      SERVER_ACTIVE_COLOR_PARAMETER = var.server_active_color_parameter != null ? var.server_active_color_parameter : ""
      AC_NLB_TG_ARNS                = join(",", var.ac_nlb_tg_arns)
      AC_NLB_TG_ARNS_BY_COLOR       = jsonencode(var.ac_nlb_tg_arns_by_color)
      AC_ACTIVE_COLOR_PARAMETER     = var.ac_active_color_parameter != null ? var.ac_active_color_parameter : ""
      ALARM_NAME_PREFIXES           = join(",", var.alarm_name_prefixes)
      SERVER_ALARM_PREFIXES         = join(",", var.server_alarm_prefixes)
      AC_ALARM_PREFIXES             = join(",", var.ac_alarm_prefixes)
      DEPENDENT_SERVICE_URLS        = jsonencode(var.dependent_service_urls)
      DISPLAY_ONLY_COMPONENT_IDS    = join(",", sort(tolist(var.display_only_component_ids)))
      STATUS_METRIC_NAMESPACE       = local.status_metric_namespace
      STATUS_BUCKET                 = aws_s3_bucket.status.id
    }
  }

  lifecycle {
    precondition {
      condition     = length(local.unknown_display_only_component_ids) == 0
      error_message = "display_only_component_ids must reference configured dependent_service_urls component ids. Unknown display-only ids: ${join(", ", sort(tolist(local.unknown_display_only_component_ids)))}."
    }
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-status-aggregator"
    Component = "status-page"
  })
}

# EventBridge and S3 invoke asynchronously. Keep retry behavior explicit so a
# temporary reserved-concurrency throttle retries instead of silently dropping a
# snapshot or incident refresh event. The one-hour event age is intentional
# headroom over the compatibility API throttle-drain window.
resource "aws_lambda_function_event_invoke_config" "status_aggregator" {
  function_name                = aws_lambda_function.status_aggregator.function_name
  maximum_event_age_in_seconds = 3600
  maximum_retry_attempts       = 2
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
    Statement = concat(
      [
        {
          Sid    = "DescribeTargetHealth"
          Effect = "Allow"
          Action = [
            "elasticloadbalancing:DescribeTargetHealth"
          ]
          Resource = local.status_target_health_resources
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
          # DescribeAlarms does not support resource-level IAM scoping; keep it
          # region-bound here and redact alarm names before publishing status.
          Resource = "*"
          Condition = {
            StringEquals = {
              "aws:RequestedRegion" = data.aws_region.current.id
            }
          }
        },
        {
          Sid      = "PutStatusMetrics"
          Effect   = "Allow"
          Action   = ["cloudwatch:PutMetricData"]
          Resource = "*"
          Condition = {
            StringEquals = {
              "cloudwatch:namespace" = local.status_metric_namespace
            }
          }
        },
      ],
      local.active_color_parameter_statements,
      [
        {
          Sid    = "ReadStatusContent"
          Effect = "Allow"
          Action = ["s3:GetObject"]
          Resource = [
            "${aws_s3_bucket.status.arn}/status.json",
            "${aws_s3_bucket.status.arn}/history.json",
            "${aws_s3_bucket.status.arn}/incidents.json",
          ]
        },
        {
          Sid    = "WriteStatusContent"
          Effect = "Allow"
          Action = ["s3:PutObject"]
          Resource = [
            "${aws_s3_bucket.status.arn}/status.json",
            "${aws_s3_bucket.status.arn}/history.json",
          ]
        },
      ]
    )
  })
}

# ==============================================================================
# API Gateway (HTTP API)
# ==============================================================================
# Compatibility endpoint for operators/integrations. The deployed frontend reads
# same-origin /status.json from CloudFront/S3 so viewer traffic does not fan out
# into Lambda or AWS control-plane APIs during incidents.
# enable_nhp_auth gates only the CloudFront viewer path; this redacted API
# remains public by design.

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

resource "terraform_data" "api_gateway_logging_ready" {
  input = var.api_gateway_logging_ready
}

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.status.id
  name        = "$default"
  auto_deploy = true

  depends_on = [terraform_data.api_gateway_logging_ready]

  # Compatibility API is not the viewer path. Keep bursts below the Lambda's
  # reserved-concurrency pool so direct /status traffic still leaves two slots
  # for scheduled snapshot/incident invokes and a couple of low-rate operators
  # or integrations can read the cached secondary surface.
  default_route_settings {
    throttling_burst_limit = 3
    throttling_rate_limit  = 2
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
    Component = "status-page"
  })
}

resource "aws_cloudwatch_log_group" "api_access" {
  name              = "/aws/apigateway/${var.name_prefix}-status"
  retention_in_days = local.is_prod ? 90 : 14
  kms_key_id        = var.logs_kms_key_arn

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-status-api-access-logs"
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
# EventBridge Schedule - History Snapshots
# ==============================================================================
# Every local.snapshot_cadence_minutes minutes the Lambda records current
# component statuses into history.json, which drives the page's 90-day uptime
# history. The frontend receives the same cadence through templatefile().

resource "aws_cloudwatch_event_rule" "status_snapshot" {
  name                = "${var.name_prefix}-status-snapshot"
  description         = "Records status page component health into history.json"
  schedule_expression = "rate(${local.snapshot_cadence_minutes} minutes)"

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-status-snapshot"
    Component = "status-page"
  })
}

resource "aws_cloudwatch_event_target" "status_snapshot" {
  rule  = aws_cloudwatch_event_rule.status_snapshot.name
  arn   = aws_lambda_function.status_aggregator.arn
  input = jsonencode({ task = "snapshot" })
}

resource "aws_lambda_permission" "eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.status_aggregator.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.status_snapshot.arn
}

resource "aws_lambda_permission" "incident_publish_s3" {
  statement_id  = "AllowStatusBucketIncidentPublishInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.status_aggregator.function_name
  principal     = "s3.amazonaws.com"
  source_arn    = aws_s3_bucket.status.arn
}

# Keep the apply-role barrier on the one resource that exercises
# s3:PutBucketNotification. A module-wide depends_on would defer provider data
# and make status-page IAM/policy values unknown in the saved plan.
resource "terraform_data" "terraform_apply_services_ready" {
  input = var.terraform_apply_services_ready
}

resource "aws_s3_bucket_notification" "status" {
  bucket = aws_s3_bucket.status.id

  # This resource is authoritative for notifications on the dedicated status
  # bucket; fold any future bucket notifications into this resource.
  lambda_function {
    lambda_function_arn = aws_lambda_function.status_aggregator.arn
    events              = ["s3:ObjectCreated:*"]
    # S3 notification filters are prefix/suffix rules, not exact-key rules.
    # The double-filter is an intentional exact-key prefilter; keep the
    # Lambda-side exact-key guard for defense-in-depth.
    filter_prefix = "incidents.json"
    filter_suffix = "incidents.json"
  }

  depends_on = [
    aws_lambda_permission.incident_publish_s3,
    aws_s3_object.incidents,
    aws_s3_object.status_snapshot,
    terraform_data.terraform_apply_services_ready,
  ]
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

resource "aws_s3_bucket_lifecycle_configuration" "status" {
  bucket = aws_s3_bucket.status.id

  rule {
    id     = "expire-noncurrent-status-versions"
    status = "Enabled"

    filter {}

    noncurrent_version_expiration {
      noncurrent_days = 30
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
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

# Favicon (LayerV chevron mark, from the website's app/icon.svg)
resource "aws_s3_object" "favicon" {
  bucket       = aws_s3_bucket.status.id
  key          = "favicon.svg"
  source       = "${path.module}/frontend/favicon.svg"
  content_type = "image/svg+xml"
  etag         = filemd5("${path.module}/frontend/favicon.svg")

  tags = var.tags
}

# Brand wordmark for the header/footer (verbatim copy of the website wordmark)
resource "aws_s3_object" "wordmark" {
  bucket       = aws_s3_bucket.status.id
  key          = "wordmark.svg"
  source       = "${path.module}/frontend/wordmark.svg"
  content_type = "image/svg+xml"
  etag         = filemd5("${path.module}/frontend/wordmark.svg")

  tags = var.tags
}

# Brand webfonts (vendored, OFL-licensed; see frontend/fonts/FONTS-LICENSE.txt).
# Self-hosted so the page keeps default-src 'self' and has no third-party
# runtime dependency during incidents.
resource "aws_s3_object" "fonts" {
  for_each = fileset("${path.module}/frontend/fonts", "*.woff2")

  bucket        = aws_s3_bucket.status.id
  key           = "fonts/${each.value}"
  source        = "${path.module}/frontend/fonts/${each.value}"
  content_type  = "font/woff2"
  cache_control = "public, max-age=31536000, immutable"
  etag          = filemd5("${path.module}/frontend/fonts/${each.value}")

  tags = var.tags
}

# Terraform seeds an empty incident feed once; operators own later updates.
resource "aws_s3_object" "incidents" {
  bucket       = aws_s3_bucket.status.id
  key          = "incidents.json"
  content      = jsonencode({ incidents = [] })
  content_type = "application/json"

  lifecycle {
    ignore_changes = [content, etag, content_type]
  }

  tags = var.tags
}

# Terraform seeds the public read model once; EventBridge/Lambda owns updates.
resource "aws_s3_object" "status_snapshot" {
  bucket        = aws_s3_bucket.status.id
  key           = "status.json"
  content       = local.initial_status_payload
  content_type  = "application/json"
  cache_control = "public, max-age=60"

  lifecycle {
    ignore_changes = [content, etag, content_type]
  }

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
  max_ttl     = 60

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
      # default-src 'self' intentionally covers same-origin fonts, favicon, and
      # wordmark assets; add font-src/img-src if future assets move off-origin.
      content_security_policy = "default-src 'self'; script-src 'self' 'sha256-bFlHsn9Enzj51ySCuKusaEL3SqydjecfjkBGGbeX7AI='; style-src 'self' 'sha256-h10OFbNedvlJHfsFUyApPbAl+d/AAIXBJoq5C1MuJ1w='; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
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

  # Keep NHP-auth loop-detection 403 responses intact so cookie-domain
  # diagnostics are visible when the dogfooding gate is enabled.
  dynamic "custom_error_response" {
    for_each = var.enable_nhp_auth ? [] : [1]
    content {
      error_code            = 403
      response_code         = 404
      response_page_path    = "/index.html"
      error_caching_min_ttl = 60
    }
  }

  custom_error_response {
    error_code            = 404
    response_code         = 404
    response_page_path    = "/index.html"
    error_caching_min_ttl = 60
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
    minimum_protocol_version       = "TLSv1.2_2021"
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
        Action = "s3:GetObject"
        Resource = [
          "${aws_s3_bucket.status.arn}/index.html",
          "${aws_s3_bucket.status.arn}/status.json",
          "${aws_s3_bucket.status.arn}/favicon.svg",
          "${aws_s3_bucket.status.arn}/wordmark.svg",
          "${aws_s3_bucket.status.arn}/fonts/*",
        ]
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
# Route53 DNS Record (optional; marker bounds check-status-page-public-surface.py)
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
  alarm_description   = "Status aggregator Lambda p99 duration exceeds 35s"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "Duration"
  namespace           = "AWS/Lambda"
  period              = 300
  extended_statistic  = "p99"
  # Above the controlled single-URL budgets: initial DNS guard (5s) plus
  # retryable HEAD->GET attempts (~25s), and the non-retried 416
  # HEAD->range-GET->plain-GET fallback (~20s). Redirect revalidation can still
  # push p99 toward this alarm; that is an intentional near-timeout signal. The
  # threshold still leaves 10s before the function timeout.
  threshold          = 35000
  treat_missing_data = "notBreaching"

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

resource "aws_cloudwatch_metric_alarm" "status_snapshot_invocation_gap" {
  alarm_name          = "${var.name_prefix}-status-snapshot-invocation-gap"
  alarm_description   = "Status snapshot EventBridge rule has not invoked its target for three consecutive 5-minute windows. The public page may be serving stale status.json; Lambda Errors/Duration cover runtime failures after invocation."
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 3
  datapoints_to_alarm = 3
  metric_name         = "Invocations"
  namespace           = "AWS/Events"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  treat_missing_data  = "breaching"

  dimensions = {
    RuleName = aws_cloudwatch_event_rule.status_snapshot.name
  }

  alarm_actions = [var.sns_topic_arn]
  ok_actions    = [var.sns_topic_arn]

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-status-snapshot-invocation-gap"
    Component = "status-page"
  })
}

resource "aws_cloudwatch_metric_alarm" "status_snapshot_failed_invocations" {
  alarm_name          = "${var.name_prefix}-status-snapshot-failed-invocations"
  alarm_description   = "Status snapshot EventBridge rule failed to invoke the status aggregator target. The public page may keep serving stale status.json until delivery recovers."
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "FailedInvocations"
  namespace           = "AWS/Events"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  treat_missing_data  = "notBreaching"

  dimensions = {
    RuleName = aws_cloudwatch_event_rule.status_snapshot.name
  }

  alarm_actions = [var.sns_topic_arn]
  ok_actions    = [var.sns_topic_arn]

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-status-snapshot-failed-invocations"
    Component = "status-page"
  })
}

resource "aws_cloudwatch_metric_alarm" "api_gateway_5xx" {
  alarm_name          = "${var.name_prefix}-status-api-5xx"
  alarm_description   = "Compatibility /status API Gateway 5xx errors. Viewers use CloudFront/S3 status.json, but this pages because API consumers have lost the secondary cached public-status surface."
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

# Display-only suppresses only the customer-facing overall rollup. Keep
# per-component HTTP alarms for display-only URLs so ancillary surfaces such as
# the marketing site still page when their configured health URL is persistently
# non-operational.
resource "aws_cloudwatch_metric_alarm" "http_component_non_operational" {
  for_each = var.dependent_service_urls

  alarm_name          = "${var.name_prefix}-status-${replace(each.key, "_", "-")}-non-operational"
  alarm_description   = "Public status HTTP component ${each.key} has reported non-operational (reachable 4xx/degraded, unknown/gray, or major_outage) for three consecutive ${local.snapshot_cadence_minutes}-minute snapshots. Check the configured health URL, Lambda user agent reachability, CDN/WAF rules, and the backing service."
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  datapoints_to_alarm = 3
  metric_name         = "HTTPComponentNonOperational"
  namespace           = local.status_metric_namespace
  period              = 300
  statistic           = "Maximum"
  threshold           = 0
  treat_missing_data  = "notBreaching"

  dimensions = {
    Environment = var.environment
    ComponentId = each.key
  }

  alarm_actions = [var.sns_topic_arn]
  ok_actions    = [var.sns_topic_arn]

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-status-${replace(each.key, "_", "-")}-non-operational"
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
