# Developer Portal Module Variables

variable "environment" {
  description = "Environment name (sandbox, prod)"
  type        = string
}

variable "name_prefix" {
  description = "Name prefix for resources"
  type        = string
}

variable "tags" {
  description = "Tags for all resources"
  type        = map(string)
  default     = {}
}

# ==============================================================================
# Encryption
# ==============================================================================

variable "logs_kms_key_arn" {
  description = "KMS key ARN for CloudWatch Logs encryption"
  type        = string
}

variable "dynamodb_kms_key_arn" {
  description = "KMS key ARN for DynamoDB encryption. If null, uses AWS managed key."
  type        = string
  default     = null
}

# ==============================================================================
# Secrets Manager
# ==============================================================================

variable "playground_m2m_secret_name" {
  description = "Secrets Manager secret name for playground M2M credentials (client_id, client_secret, audience)"
  type        = string
}

variable "auth0_mgmt_secret_name" {
  description = "Secrets Manager secret name for Auth0 management API credentials (used by cleanup Lambda)"
  type        = string
}

# ==============================================================================
# QURL API
# ==============================================================================

variable "qurl_api_url" {
  description = "QURL API base URL (e.g., https://api.layerv.xyz)"
  type        = string
}

variable "auth0_domain" {
  description = "Auth0 domain (e.g., auth.layerv.ai). Used by cleanup Lambda."
  type        = string
}

# ==============================================================================
# CORS
# ==============================================================================

variable "allowed_origins" {
  description = "List of allowed CORS origins"
  type        = list(string)
}

# ==============================================================================
# Custom Domain (optional)
# ==============================================================================

variable "custom_domain" {
  description = "Custom domain for API Gateway (e.g., dev-api.layerv.xyz). If null, uses default API Gateway URL."
  type        = string
  default     = null
}

variable "hosted_zone_id" {
  description = "Route53 hosted zone ID for custom domain. Required when custom_domain is set."
  type        = string
  default     = null
}

variable "acm_certificate_arn" {
  description = "ACM certificate ARN for custom domain. Required when custom_domain is set."
  type        = string
  default     = null
}

# ==============================================================================
# Monitoring
# ==============================================================================

variable "sns_topic_arn" {
  description = "SNS topic ARN for CloudWatch alarms. If null, alarms are not created."
  type        = string
  default     = null
}

# ==============================================================================
# Throttling
# ==============================================================================

variable "api_throttle_burst_limit" {
  description = "API Gateway default throttle burst limit"
  type        = number
  default     = 50
}

variable "api_throttle_rate_limit" {
  description = "API Gateway default throttle rate limit"
  type        = number
  default     = 25
}

# ==============================================================================
# Rate Limiting (Lambda-level, playground only)
# ==============================================================================

variable "playground_ip_rate_limit" {
  description = "Max playground requests per IP per rate window"
  type        = number
  default     = 20
}

variable "playground_global_rate_limit" {
  description = "Max playground requests globally per rate window"
  type        = number
  default     = 500
}

variable "playground_rate_window" {
  description = "Playground rate limit window in seconds"
  type        = number
  default     = 3600
}

# ==============================================================================
# Playground File Upload (POST /playground/upload)
# ==============================================================================

variable "connector_base_url" {
  description = <<-EOT
    Base URL of the qURL S3 connector that handles file uploads +
    mint_link calls. Must be HTTPS — the proxy forwards unauthenticated
    user content. **The default points at the production connector
    (getqurllink.layerv.ai) because no separate sandbox connector is
    deployed today.** Sandbox `/playground/upload` traffic currently
    hits the same connector as prod (which is fine for the demo — the
    connector's qURLs are short-lived and rate-limited), but if a
    sandbox connector is deployed later, set this in the sandbox
    environment's tfvars to point at it. Tracked separately.
  EOT
  type        = string
  default     = "https://getqurllink.layerv.ai"

  validation {
    # HTTPS only + non-empty host. `^https://` alone would accept
    # `https://` (no host) or `https:///api`, which would surface as
    # a runtime urllib failure on the first invocation rather than
    # a plan-time error.
    condition     = can(regex("^https://[^/]+", var.connector_base_url))
    error_message = "connector_base_url must use https:// with a non-empty host."
  }

  validation {
    # No trailing slash — the Lambda builds f'{CONNECTOR_BASE_URL}/api/...'
    # so a trailing slash would produce '//api/...' which some proxies
    # normalize and some don't.
    condition     = !endswith(var.connector_base_url, "/")
    error_message = "connector_base_url must not end with '/'."
  }
}

variable "playground_max_upload_bytes" {
  description = "Max decoded file size in bytes for POST /playground/upload. Stays below Lambda's 6 MiB sync payload limit after base64 + multipart overhead."
  type        = number
  default     = 4 * 1024 * 1024 # 4 MB

  validation {
    # Lower bound 1 MiB: the "max X MB" error string uses integer-MiB
    # division, so a sub-MiB cap would render as "max 0 MB".
    #
    # Upper bound 4 MiB: Lambda's sync invocation request payload limit
    # is 6 MiB total. Base64 inflates the file body by 4/3, so a 4 MiB
    # decoded file = ~5.33 MiB encoded, leaving ~683 KiB of headroom
    # for the multipart envelope (boundary, Content-Disposition,
    # Content-Type headers). Pushing the decoded cap higher would
    # cause API Gateway to reject oversize requests with a 413 BEFORE
    # the Lambda even runs, making the handler's own size-cap error
    # message confusingly absent.
    condition     = var.playground_max_upload_bytes >= 1024 * 1024 && var.playground_max_upload_bytes <= 4 * 1024 * 1024
    error_message = "playground_max_upload_bytes must be in [1 MiB, 4 MiB]. The 4 MiB ceiling comes from Lambda's 6 MiB sync invocation payload limit minus base64 inflation (4/3) and multipart envelope overhead — moving to async invocation or a Function URL (10 MiB sync limit) would let this rise."
  }
}

variable "playground_upload_timeout_seconds" {
  description = "Per-request timeout (seconds) for the connector /api/upload outbound call from /playground/upload. Must fit inside the API Gateway integration timeout (30s default) alongside the mint timeout (sum <= 25s; leaves 5s headroom for base64 decode + DynamoDB rate-limit writes + cold-start M2M fetch + transport setup before API GW cuts the integration)."
  type        = number
  default     = 15

  validation {
    # Upper bound 24s: caps the upload-only contribution. The cross-
    # variable invariant (upload + mint <= 25s) is enforced by a
    # precondition in playground.tf since validation {} blocks can't
    # reference other variables. The 25s sum leaves 5s headroom under
    # API Gateway's 30s integration timeout (the binding constraint —
    # the Lambda's 60s timeout is an upper bound, not the live budget).
    condition     = var.playground_upload_timeout_seconds >= 1 && var.playground_upload_timeout_seconds <= 24
    error_message = "playground_upload_timeout_seconds must be in [1, 24]."
  }
}

variable "playground_mint_timeout_seconds" {
  description = "Per-request timeout (seconds) for the connector /api/mint_link outbound call from /playground/upload. See playground_upload_timeout_seconds for the combined-budget invariant."
  type        = number
  default     = 8

  validation {
    condition     = var.playground_mint_timeout_seconds >= 1 && var.playground_mint_timeout_seconds <= 15
    error_message = "playground_mint_timeout_seconds must be in [1, 15]."
  }
}

# ==============================================================================
# CI Bypass
# ==============================================================================

variable "ci_bypass_secret_name" {
  description = "Secrets Manager secret name for CI bypass key. If set, requests with matching X-CI-Key header skip rate limiting."
  type        = string
  default     = null
}

# ==============================================================================
# Fixed-Resource Demo (the /qurl LiveDemo's "hidden app")
# ==============================================================================
# The demo publishes one constant protected-resource URL whose hostname is
# deliberately dark (no DNS record), so the playground's create path can never
# resolve or SSRF-validate it. When these are set, a create request for exactly
# playground_demo_target_url instead mints a fresh link for the pre-provisioned
# resource. All three must be set together (enforced by a precondition on the
# Lambda); empty (the default) leaves the demo path disabled.

variable "playground_demo_target_url" {
  description = "Exact protected-resource URL the LiveDemo publishes (e.g. https://hidden-app.layerv.ai). Coupled contract: must match the website LiveDemo's published constant byte-for-byte (same case, no trailing slash) — a drifted value silently falls back to the client's simulated links. Empty disables the demo mint path."
  type        = string
  default     = ""

  validation {
    condition     = var.playground_demo_target_url == "" || can(regex("^https://[a-z0-9.-]+(:[0-9]+)?$", var.playground_demo_target_url))
    error_message = "playground_demo_target_url must be https:// with a bare host (no path) — the Lambda matches it by exact string equality."
  }
}

variable "playground_demo_resource_id" {
  description = "qurl-service resource id of the pre-provisioned resource serving the demo page. Must be owned by the account the playground M2M credentials authenticate as, or mint_link fails."
  type        = string
  default     = ""

  validation {
    condition     = var.playground_demo_resource_id == "" || can(regex("^[a-zA-Z0-9_-]{1,64}$", var.playground_demo_resource_id))
    error_message = "playground_demo_resource_id must match the Lambda's QURL id pattern (^[a-zA-Z0-9_-]{1,64}$)."
  }
}

variable "playground_demo_qurl_site" {
  description = "qurl_site URL returned verbatim to the LiveDemo for the demo resource (e.g. https://r_abc.qurl.site)."
  type        = string
  default     = ""

  validation {
    condition     = var.playground_demo_qurl_site == "" || can(regex("^https://[A-Za-z0-9._-]+(:[0-9]+)?$", var.playground_demo_qurl_site))
    error_message = "playground_demo_qurl_site must be https:// with a bare host (no path) — it is returned verbatim to the demo client."
  }
}
