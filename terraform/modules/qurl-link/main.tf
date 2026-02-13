# QURL Link Redirect Page
#
# Hosts the simple HTML redirect page for qurl.link (or sandbox equivalent).
# The page extracts the access token from the URL fragment and redirects
# to the NHP Server QURL plugin for token resolution.
#
# Flow: User visits link.domain/#at_xxx → Page redirects to NHP Server → NHP knock → Protected resource

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0"
    }
  }
}

locals {
  # Generate the redirect page HTML with the configured resolve URL
  index_html = <<-HTML
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="robots" content="noindex, nofollow">
  <title>QURL - Secure Access</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      color: #fff;
    }
    .container { text-align: center; padding: 2rem; max-width: 400px; }
    .logo {
      font-size: 2.5rem;
      font-weight: bold;
      margin-bottom: 1rem;
      background: linear-gradient(90deg, #00d4ff, #7c3aed);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
    }
    .spinner {
      width: 40px;
      height: 40px;
      margin: 2rem auto;
      border: 3px solid rgba(255, 255, 255, 0.1);
      border-top-color: #00d4ff;
      border-radius: 50%;
      animation: spin 1s linear infinite;
    }
    @keyframes spin { to { transform: rotate(360deg); } }
    .message { color: rgba(255, 255, 255, 0.8); font-size: 1rem; margin-bottom: 1rem; }
    .error-container { display: none; }
    .error-title { font-size: 1.5rem; margin-bottom: 0.5rem; color: #ef4444; }
    .error-message { color: rgba(255, 255, 255, 0.7); font-size: 0.9rem; line-height: 1.5; }
    .loading-container { display: block; }
    .footer { margin-top: 2rem; font-size: 0.75rem; color: rgba(255, 255, 255, 0.4); }
    .footer a { color: rgba(255, 255, 255, 0.6); text-decoration: none; }
    .footer a:hover { color: #00d4ff; }
  </style>
</head>
<body>
  <div class="container">
    <div class="logo">QURL</div>
    <div id="loading" class="loading-container">
      <div class="spinner"></div>
      <p class="message">Verifying access...</p>
    </div>
    <div id="error" class="error-container">
      <h2 class="error-title">Access Link Invalid</h2>
      <p class="error-message">
        This access link may have expired, been revoked, or already used.
        Please request a new access link from the resource owner.
      </p>
    </div>
    <div class="footer">Powered by <a href="https://layerv.ai" target="_blank" rel="noopener noreferrer">LayerV</a></div>
  </div>
  <script>
    (function() {
      'use strict';
      var RESOLVE_URL = '${var.nhp_resolve_url}';
      var token = window.location.hash.substring(1);
      // Token format matches QURL service generation (qurl-service/internal/domain/qurl.go):
      // at_ prefix + 22 base64url chars (lowercase alphanumeric, underscore, hyphen)
      if (!token || !/^at_[a-z0-9_-]{22}$/.test(token)) {
        document.getElementById('loading').style.display = 'none';
        document.getElementById('error').style.display = 'block';
        return;
      }
      // Brief delay to show loading spinner for better UX feedback
      setTimeout(function() {
        window.location.href = RESOLVE_URL + '?token=' + encodeURIComponent(token);
      }, 500);
    })();
  </script>
</body>
</html>
HTML
}

# S3 bucket for the redirect page
resource "aws_s3_bucket" "qurl_link" {
  bucket = var.bucket_name

  tags = merge(var.tags, {
    Name      = var.bucket_name
    Component = "qurl-link"
  })
}

resource "aws_s3_bucket_versioning" "qurl_link" {
  bucket = aws_s3_bucket.qurl_link.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "qurl_link" {
  bucket = aws_s3_bucket.qurl_link.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "qurl_link" {
  bucket = aws_s3_bucket.qurl_link.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# CloudFront Origin Access Control
resource "aws_cloudfront_origin_access_control" "qurl_link" {
  name                              = "${var.domain_name}-oac"
  description                       = "OAC for ${var.domain_name}"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

# S3 bucket for CloudFront access logs (optional)
resource "aws_s3_bucket" "logs" {
  count  = var.enable_access_logs ? 1 : 0
  bucket = "${var.bucket_name}-logs"

  tags = merge(var.tags, {
    Name      = "${var.bucket_name}-logs"
    Component = "qurl-link"
  })
}

resource "aws_s3_bucket_versioning" "logs" {
  count  = var.enable_access_logs ? 1 : 0
  bucket = aws_s3_bucket.logs[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_ownership_controls" "logs" {
  count  = var.enable_access_logs ? 1 : 0
  bucket = aws_s3_bucket.logs[0].id

  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_acl" "logs" {
  count  = var.enable_access_logs ? 1 : 0
  bucket = aws_s3_bucket.logs[0].id
  acl    = "private"

  depends_on = [aws_s3_bucket_ownership_controls.logs]
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  count  = var.enable_access_logs ? 1 : 0
  bucket = aws_s3_bucket.logs[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "logs" {
  count  = var.enable_access_logs ? 1 : 0
  bucket = aws_s3_bucket.logs[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  count  = var.enable_access_logs ? 1 : 0
  bucket = aws_s3_bucket.logs[0].id

  rule {
    id     = "expire-logs"
    status = "Enabled"
    filter {} # Empty filter = applies to all objects (required for forward compatibility)

    expiration {
      days = 90
    }
  }
}

# S3 bucket policy for CloudFront
resource "aws_s3_bucket_policy" "qurl_link" {
  bucket = aws_s3_bucket.qurl_link.id

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
        Resource = "${aws_s3_bucket.qurl_link.arn}/*"
        Condition = {
          StringEquals = {
            "AWS:SourceArn" = aws_cloudfront_distribution.qurl_link.arn
          }
        }
      }
    ]
  })
}

# AWS managed cache policy for static content
data "aws_cloudfront_cache_policy" "caching_optimized" {
  name = "Managed-CachingOptimized"
}

# CloudFront response headers policy with security headers (CSP, HSTS, etc.)
resource "aws_cloudfront_response_headers_policy" "qurl_link" {
  name = replace("${var.domain_name}-security-headers", ".", "-")

  security_headers_config {
    content_security_policy {
      content_security_policy = "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'"
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

# CloudFront distribution
resource "aws_cloudfront_distribution" "qurl_link" {
  enabled             = true
  is_ipv6_enabled     = true
  default_root_object = "index.html"
  aliases             = [var.domain_name]
  price_class         = "PriceClass_100" # US, Canada, Europe
  comment             = "QURL Link Redirect - ${var.domain_name}"

  origin {
    domain_name              = aws_s3_bucket.qurl_link.bucket_regional_domain_name
    origin_id                = "S3-${var.bucket_name}"
    origin_access_control_id = aws_cloudfront_origin_access_control.qurl_link.id
  }

  default_cache_behavior {
    allowed_methods  = ["GET", "HEAD"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "S3-${var.bucket_name}"

    # Use managed CachingOptimized policy instead of deprecated forwarded_values
    cache_policy_id            = data.aws_cloudfront_cache_policy.caching_optimized.id
    response_headers_policy_id = aws_cloudfront_response_headers_policy.qurl_link.id

    viewer_protocol_policy = "redirect-to-https"
    compress               = true
  }

  # Access logging (optional)
  dynamic "logging_config" {
    for_each = var.enable_access_logs ? [1] : []
    content {
      include_cookies = false
      bucket          = aws_s3_bucket.logs[0].bucket_domain_name
      prefix          = "cloudfront/"
    }
  }

  # Return index.html for all paths (handles /#token fragments)
  custom_error_response {
    error_code            = 403
    response_code         = 200
    response_page_path    = "/index.html"
    error_caching_min_ttl = 10 # Short TTL to prevent long error caching
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
    acm_certificate_arn      = var.acm_certificate_arn
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1.2_2021"
  }

  tags = merge(var.tags, {
    Name      = var.domain_name
    Component = "qurl-link"
  })
}

# Note: Route53 DNS records are created externally in main.tf
# This allows for cross-account Route53 access when the zone is in a different account

# Upload index.html to S3
resource "aws_s3_object" "index" {
  bucket        = aws_s3_bucket.qurl_link.id
  key           = "index.html"
  content       = local.index_html
  content_type  = "text/html"
  etag          = md5(local.index_html)
  cache_control = "max-age=3600, must-revalidate" # 1 hour, easier to invalidate than 24h default

  tags = merge(var.tags, { Component = "qurl-link" })
}
