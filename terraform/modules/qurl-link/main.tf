# QURL Link Landing + Access Verification Page
#
# Hosts the qurl.link (or sandbox equivalent) consumer landing page. When the
# URL contains a qURL access token fragment, the same page switches into the
# access-verification flow. In JS-agent mode it extracts the fragment token,
# knocks through the relay, and redirects using the ACK. Legacy mode keeps the
# old resolve POST only for environments not yet cut over.
#
# Flow: User visits link.domain/#at_xxx → JS agent knocks relay → NHP opens access → Protected resource

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
  index_html = templatefile("${path.module}/frontend/index.html", {
    allowed_hosts_json    = jsonencode([var.domain_name])
    js_agent_enabled      = var.js_agent_enabled
    relay_base_url        = local.relay_connect_src_origin
    server_static_pub_b64 = var.server_public_key_b64
  })

  robots_txt = var.robots_tag == null ? "User-agent: *\nAllow: /\n" : "User-agent: *\nDisallow: /\n"

  favicon_svg  = file("${path.module}/frontend/favicon.svg")
  wordmark_svg = file("${path.module}/frontend/layerv-wordmark.svg")
  og_image_png = filebase64("${path.module}/frontend/og-image.png")
  js_agent_js  = var.js_agent_enabled ? file("${path.module}/frontend/nhp-agent.min.js") : ""

  index_content_type     = "text/html"
  robots_content_type    = "text/plain; charset=utf-8"
  favicon_content_type   = "image/svg+xml"
  wordmark_content_type  = "image/svg+xml"
  og_image_content_type  = "image/png"
  js_agent_content_type  = "text/javascript; charset=utf-8"
  html_cache_control     = "max-age=3600, must-revalidate"
  robots_cache_control   = "max-age=3600, must-revalidate"
  favicon_cache_control  = "max-age=86400, must-revalidate"
  wordmark_cache_control = "max-age=86400, must-revalidate"
  og_image_cache_control = "max-age=86400, must-revalidate"
  js_agent_cache_control = "max-age=3600, must-revalidate"

  favicon_keys = ["favicon.ico", "favicon.svg"]
  wordmark_key = "layerv-wordmark.svg"
  og_image_key = "og-image.png"
  js_agent_key = "nhp-agent.min.js"

  relay_connect_src_origin          = var.relay_connect_src_origin == null ? "" : var.relay_connect_src_origin
  js_agent_connect_src              = join(" ", compact(["'self'", local.relay_connect_src_origin]))
  qurl_link_executable_script_types = toset(["", "text/javascript", "application/javascript", "module"])
  # Scoped to the controlled qurl-link template. If a future script embeds a
  # literal </script> or a script attribute containing >, switch this and the
  # smoke mirror to a real parser before relying on hash parity.
  qurl_link_script_matches = regexall("(?is)<script\\b([^>]*)>(.*?)</script>", local.index_html)
  qurl_link_inline_script_bodies = [
    for match in local.qurl_link_script_matches : match[1]
    if trimspace(match[1]) != "" &&
    length(regexall("(?i)(?:^|\\s)src\\s*=", match[0])) == 0 &&
    contains(local.qurl_link_executable_script_types, lower(trimspace(try(regex("(?i)(?:^|\\s)type\\s*=\\s*[\"']?([^\"'\\s>]+)", match[0])[0], ""))))
  ]
  # Rollout compatibility only: the current rendered index_html is hash-pinned
  # per environment above. These extra hashes cover the two exact inline scripts
  # served by the older pre-template, pre-#2701 index.html while old cached HTML
  # and new CSP headers can overlap during CloudFront propagation. Remove after
  # the first prod strict-CSP rollout via #2717.
  #
  # Provenance: derived from the two executable inline <script> bodies in
  # e908489e:terraform/modules/qurl-link/frontend/index.html, which used literal
  # ALLOWED_HOSTS values and no Terraform template substitutions, so the bodies
  # were env-independent. Hashes are SHA-256 over each exact script body,
  # including leading/trailing whitespace, recomputed with a Node crypto script
  # matching the smoke test's executable-script extraction.
  legacy_rollout_script_hashes = [
    "'sha256-lQZ5xt5AMAT1GGKf9WfLPyJL393SyPoCqdlUSIDYdy0='",
    "'sha256-NV09DWZPPAO4Bua9v9d9oQmHfucTzi5onwG88dNPYnU='",
  ]
  qurl_link_script_hashes = distinct(concat([
    for script_body in local.qurl_link_inline_script_bodies : "'sha256-${base64sha256(script_body)}'"
  ], local.legacy_rollout_script_hashes))
  legacy_script_src       = join(" ", local.qurl_link_script_hashes)
  js_agent_script_src     = join(" ", concat(["'self'"], local.qurl_link_script_hashes))
  legacy_csp              = "default-src 'self'; script-src ${local.legacy_script_src}; style-src 'unsafe-inline'"
  js_agent_csp            = "default-src 'self'; script-src ${local.js_agent_script_src}; style-src 'unsafe-inline'; connect-src ${local.js_agent_connect_src}"
  content_security_policy = var.js_agent_enabled ? local.js_agent_csp : local.legacy_csp

  static_invalidation_paths = concat(
    ["/", "/index.html", "/robots.txt"],
    [for key in local.favicon_keys : "/${key}"],
    ["/${local.wordmark_key}"],
    ["/${local.og_image_key}"],
    ["/${local.js_agent_key}"],
  )

  static_content_hash = md5(jsonencode({
    invalidation_paths = local.static_invalidation_paths
    index = {
      body          = local.index_html
      cache_control = local.html_cache_control
      content_type  = local.index_content_type
    }
    robots = {
      body          = local.robots_txt
      cache_control = local.robots_cache_control
      content_type  = local.robots_content_type
    }
    favicon = {
      body          = local.favicon_svg
      cache_control = local.favicon_cache_control
      content_type  = local.favicon_content_type
      keys          = local.favicon_keys
    }
    wordmark = {
      body          = local.wordmark_svg
      cache_control = local.wordmark_cache_control
      content_type  = local.wordmark_content_type
      key           = local.wordmark_key
    }
    og_image = {
      body_base64   = local.og_image_png
      cache_control = local.og_image_cache_control
      content_type  = local.og_image_content_type
      key           = local.og_image_key
    }
    js_agent = {
      enabled       = var.js_agent_enabled
      body          = local.js_agent_js
      cache_control = local.js_agent_cache_control
      content_type  = local.js_agent_content_type
      key           = local.js_agent_key
    }
  }))
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

  dynamic "custom_headers_config" {
    for_each = var.robots_tag == null ? [] : [var.robots_tag]

    content {
      items {
        header   = "X-Robots-Tag"
        override = true
        value    = custom_headers_config.value
      }
    }
  }

  security_headers_config {
    content_security_policy {
      # No form-action directive: the SPA submits a form POST to the NHP resolve
      # endpoint, which responds with a 302 to the protected resource host
      # (*.qurl.site.<env> or a customer-registered custom domain). Browsers
      # enforce form-action on every hop of the redirect chain per the CSP spec,
      # and custom domains are dynamic — they can't be enumerated in a static
      # allowlist — so restricting form-action here breaks the post-resolve
      # redirect. Auth is gated by the NHP knock (source-IP firewall open) plus
      # the qurl-router authorize check at the resource host, not by this CSP.
      # script-src never includes 'unsafe-inline'. The qurl.link verifier is
      # inlined into index.html and protected by sha256 source expressions so
      # the page avoids both inline-anything CSP and a parser-blocking network
      # fetch before token pages can set the verifying class. When
      # js_agent_enabled uploads nhp-agent.min.js, 'self' is added only for
      # that reviewed same-origin bundle.
      # connect-src is likewise explicit only for the agent path: the bundled
      # agent fetches the cross-origin relay over HTTPS. default-src 'self'
      # would otherwise block the real in-browser cutover request.
      # style-src keeps 'unsafe-inline' because the marketing rows use
      # inline style attributes for per-card CSS custom properties, and the
      # no-JS verifier fallback keeps its state flip in a noscript style.
      content_security_policy = local.content_security_policy
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

  lifecycle {
    precondition {
      condition     = !var.js_agent_enabled || local.relay_connect_src_origin != ""
      error_message = "js_agent_enabled requires relay_connect_src_origin so qurl.link CSP permits browser relay fetches. Root callers derive that origin from deploy_relay=true and relay_dns_name; set both before enabling qurl_link_js_agent_enabled."
    }
    precondition {
      condition     = !var.js_agent_enabled || var.server_public_key_b64 != ""
      error_message = "js_agent_enabled requires server_public_key_b64 so the browser JS agent can authenticate relay replies from the NHP server cell."
    }
    precondition {
      # Keep this count in lockstep with the Go smoke CSP test and the Python
      # legacy-hash drift lint; all three mirror the controlled template shape.
      condition     = length(local.qurl_link_inline_script_bodies) == 2
      error_message = "qurl.link index.html must contain exactly two inline executable scripts so Terraform can hash-pin the current template shape in script-src."
    }
  }
}

# CloudFront distribution
resource "aws_cloudfront_distribution" "qurl_link" {
  enabled             = true
  is_ipv6_enabled     = true
  default_root_object = "index.html"
  # Single alias per distribution is load-bearing: the precondition on
  # aws_s3_object.index fences only that var.domain_name appears in the SPA's
  # ALLOWED_HOSTS array (additions). It does NOT fence stale entries — fine
  # while we keep one alias per distribution, since a stale extra is benign.
  # Adding a second alias here requires growing BOTH the precondition
  # (strcontains becomes a per-alias check) AND
  # tests/smoke/16_qurl_link_frontend_test.go::TestQurlLinkFrontend_-
  # AllowlistContainsServingHost (currently asserts a single serving host) into
  # list checks in the same PR.
  aliases     = [var.domain_name]
  price_class = "PriceClass_100" # US, Canada, Europe
  comment     = "QURL Link Redirect - ${var.domain_name}"

  origin {
    domain_name              = aws_s3_bucket.qurl_link.bucket_regional_domain_name
    origin_id                = "S3-${var.bucket_name}"
    origin_access_control_id = aws_cloudfront_origin_access_control.qurl_link.id
  }

  # qurl.link CSP hashes assume CloudFront serves the S3 HTML body byte-for-byte.
  # Any future response-body transform on this distribution must re-derive the
  # script hashes from transformed bytes and update the smoke/lint fences.
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

  # Return index.html for unexpected app paths. Token fragments never reach
  # CloudFront, but direct malformed/shared paths still get the branded page.
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
  content_type  = local.index_content_type
  etag          = md5(local.index_html)
  cache_control = local.html_cache_control # 1 hour, easier to invalidate than 24h default

  tags = merge(var.tags, { Component = "qurl-link" })

  # A domain not in the SPA's rendered allowedHosts array makes every visit show
  # the error page (fail-loud at the right layer, but undiagnosed until
  # a human loads it). A greenfield env or domain rename must edit
  # the template inputs alongside tfvars — this hard-fails plan if the
  # rendered verifier would refuse the serving host.
  lifecycle {
    precondition {
      condition = (
        strcontains(local.index_html, "allowedHosts") &&
        strcontains(local.index_html, "\"${var.domain_name}\"")
      )
      error_message = "Rendered qurl.link verifier allowedHosts does not contain '${var.domain_name}' (or the config literal's shape changed). Without it, this CloudFront distribution will serve the error page for every verifier visit."
    }
  }
}

resource "aws_s3_object" "robots" {
  bucket        = aws_s3_bucket.qurl_link.id
  key           = "robots.txt"
  content       = local.robots_txt
  content_type  = local.robots_content_type
  etag          = md5(local.robots_txt)
  cache_control = local.robots_cache_control

  tags = merge(var.tags, { Component = "qurl-link" })
}

resource "aws_s3_object" "favicon" {
  # Upload the SVG at both the explicit /favicon.svg path and the legacy
  # implicit /favicon.ico request path. The .ico key intentionally serves SVG
  # bytes with an SVG content type so implicit browser/feed-reader requests do
  # not fall through to index.html via the SPA fallback.
  for_each = toset(local.favicon_keys)

  bucket        = aws_s3_bucket.qurl_link.id
  key           = each.key
  content       = local.favicon_svg
  content_type  = local.favicon_content_type
  etag          = md5(local.favicon_svg)
  cache_control = local.favicon_cache_control

  tags = merge(var.tags, { Component = "qurl-link" })
}

resource "aws_s3_object" "wordmark" {
  bucket        = aws_s3_bucket.qurl_link.id
  key           = local.wordmark_key
  content       = local.wordmark_svg
  content_type  = local.wordmark_content_type
  etag          = md5(local.wordmark_svg)
  cache_control = local.wordmark_cache_control

  tags = merge(var.tags, { Component = "qurl-link" })
}

resource "aws_s3_object" "og_image" {
  bucket         = aws_s3_bucket.qurl_link.id
  key            = local.og_image_key
  content_base64 = local.og_image_png
  content_type   = local.og_image_content_type
  source_hash    = filemd5("${path.module}/frontend/og-image.png")
  cache_control  = local.og_image_cache_control

  tags = merge(var.tags, { Component = "qurl-link" })
}

resource "aws_s3_object" "js_agent" {
  count = var.js_agent_enabled ? 1 : 0

  bucket        = aws_s3_bucket.qurl_link.id
  key           = local.js_agent_key
  content       = local.js_agent_js
  content_type  = local.js_agent_content_type
  etag          = md5(local.js_agent_js)
  cache_control = local.js_agent_cache_control

  tags = merge(var.tags, { Component = "qurl-link" })
}
