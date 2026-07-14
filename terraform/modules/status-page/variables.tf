# Status Page Module Variables

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
# Domain & DNS
# ==============================================================================

variable "status_domain" {
  description = "Domain for the status page (e.g., status.layerv.xyz). If null, only CloudFront domain is used."
  type        = string
  default     = null
}

variable "hosted_zone_id" {
  description = "Route53 hosted zone ID for the status domain. Required when status_domain is set."
  type        = string
  default     = null
}

variable "acm_certificate_arn" {
  description = "ACM certificate ARN for the status domain (must be in us-east-1 for CloudFront). If null, CloudFront default certificate is used (no custom domain)."
  type        = string
  default     = null
}

variable "alarm_name_prefixes" {
  description = "CloudWatch alarm name prefixes for filtering status-relevant alarms"
  type        = list(string)
  default     = []
}

variable "server_alarm_prefixes" {
  description = "CloudWatch alarm name prefixes whose active alarms should degrade the public server component"
  type        = list(string)
  default     = []
}

variable "ac_alarm_prefixes" {
  description = "CloudWatch alarm name prefixes whose active alarms should degrade the public AC component"
  type        = list(string)
  default     = []
}

variable "sns_topic_arn" {
  description = "SNS topic ARN for deployment event notifications"
  type        = string
}

# ==============================================================================
# Target Group ARNs (for health checks)
# ==============================================================================

variable "server_nlb_tg_arns" {
  description = "Server NLB target group ARNs to check health (blue, optionally green)"
  type        = list(string)
  default     = []
}

variable "server_nlb_tg_arns_by_color" {
  description = "Optional blue/green server target group ARNs keyed by active-color value. When set with server_active_color_parameter, the Lambda checks only the active color; if active-color lookup or mapping fails, the public component becomes unknown instead of aggregating idle-color target groups."
  type        = map(list(string))
  default     = {}
}

variable "server_active_color_parameter" {
  description = "Optional SSM parameter name containing the active server color (blue or green)."
  type        = string
  default     = null
}

variable "ac_nlb_tg_arns" {
  description = "AC NLB target group ARNs to check health (blue, optionally green)"
  type        = list(string)
  default     = []
}

variable "ac_nlb_tg_arns_by_color" {
  description = "Optional blue/green AC target group ARNs keyed by active-color value. When set with ac_active_color_parameter, the Lambda checks only the active color; if active-color lookup or mapping fails, the public component becomes unknown instead of aggregating idle-color target groups."
  type        = map(list(string))
  default     = {}
}

variable "ac_active_color_parameter" {
  description = "Optional SSM parameter name containing the active AC color (blue or green)."
  type        = string
  default     = null
}

# ==============================================================================
# Public HTTP Components
# ==============================================================================

variable "dependent_service_urls" {
  description = "Map of public component id => HTTPS health check URL. The Lambda performs an HTTP HEAD with GET fallback and one retry, then reports the component on the public status page. URLs should be unauthenticated and return 2xx/3xx when healthy; reachable 401/403/404 and repeated 429 responses report degraded. Display names for known ids live in frontend/index.html."
  type        = map(string)
  default     = {}

  validation {
    condition     = alltrue([for url in values(var.dependent_service_urls) : can(regex("^https://", url))])
    error_message = "dependent_service_urls values must be HTTPS URLs."
  }

  validation {
    condition     = alltrue([for id in keys(var.dependent_service_urls) : can(regex("^[a-z0-9_]+$", id))])
    error_message = "dependent_service_urls keys must be lowercase component ids using letters, numbers, and underscores."
  }

  validation {
    condition     = length(var.dependent_service_urls) <= 8
    error_message = "dependent_service_urls can include at most 8 HTTP components so status snapshots stay within the Lambda duration alarm/timeout budget. This total includes built-in qurl_api/qurl_link checks added by the root module."
  }
}

variable "display_only_component_ids" {
  description = "Component ids to render and track in history but exclude from automated component rollup. Active incidents can still escalate the top-level overall status."
  type        = set(string)
  default     = []

  validation {
    condition     = alltrue([for id in var.display_only_component_ids : can(regex("^[a-z0-9_]+$", id))])
    error_message = "display_only_component_ids values must be lowercase component ids using letters, numbers, and underscores."
  }

  validation {
    condition     = length(setintersection(var.display_only_component_ids, toset(["nhp_server", "nhp_ac", "qurl_api", "qurl_link"]))) == 0
    error_message = "display_only_component_ids cannot include core component ids: nhp_server, nhp_ac, qurl_api, qurl_link."
  }
}

# ==============================================================================
# Encryption
# ==============================================================================

variable "logs_kms_key_arn" {
  description = "KMS key ARN for CloudWatch Logs encryption"
  type        = string
}

variable "api_gateway_logging_ready" {
  description = "Opaque dependency token from the root API Gateway logging propagation wait. Used only to order the compatibility API stage access-log configuration."
  type        = string
  default     = ""
}

variable "terraform_apply_services_ready" {
  description = "Opaque dependency token from the root terraform-apply-services IAM propagation wait. Used only to order the authoritative status-bucket notification."
  type        = string
  default     = ""
}

# ==============================================================================
# NHP Authentication (Dogfooding)
# ==============================================================================

variable "enable_nhp_auth" {
  description = <<-EOT
    Protect the status page with NHP authentication via QURL. When enabled,
    unauthenticated CloudFront viewer requests are redirected to the QURL login
    portal. This does not gate the exported compatibility API Gateway URL,
    which remains public and serves only the redacted status payload.

    IMPORTANT: the QURL resource backing nhp_auth_qurl_url must be configured
    so that the nhp_token cookie domain covers the status page host. The
    status page lives at status.<env> (e.g. status.layerv.xyz / status.layerv.ai)
    and the cookie_domain returned by the QURL API must be a suffix of that
    host — otherwise the browser will not send the cookie back and the user
    will bounce between the status page and the QURL link endlessly. The
    CloudFront Function has loop-detection that returns a 403 after the second
    bounce to surface this misconfiguration.
  EOT
  type        = bool
  default     = false
}

variable "nhp_auth_qurl_url" {
  description = "QURL link URL for the status page login portal (e.g., https://qurl.link.layerv.xyz/#at_xxx). Required when enable_nhp_auth is true."
  type        = string
  default     = null

  validation {
    condition     = var.nhp_auth_qurl_url == null || can(regex("^https://", var.nhp_auth_qurl_url))
    error_message = "nhp_auth_qurl_url must be a valid HTTPS URL."
  }

  # The URL is interpolated into a JavaScript single-quoted string literal
  # in nhp_auth.js via templatefile(). Reject characters that would either
  # break out of the string (single quote, backslash, newline) or trigger
  # nested terraform interpolation ('${' / '%{').
  validation {
    condition = var.nhp_auth_qurl_url == null || (
      !can(regex("['\\\\\n\r]", var.nhp_auth_qurl_url)) &&
      !can(regex("\\$\\{", var.nhp_auth_qurl_url)) &&
      !can(regex("%\\{", var.nhp_auth_qurl_url))
    )
    error_message = "nhp_auth_qurl_url must not contain single quotes, backslashes, newlines, or terraform interpolation sequences ($${...} or %%{...}). These would break the CloudFront Function JavaScript template."
  }
}

variable "nhp_auth_cookie_name" {
  description = "Name of the NHP authentication cookie to check. Must match the cookie set by the NHP server QURL resolve flow. CloudFront Functions normalize cookie keys to lowercase, so this value must be lowercase."
  type        = string
  default     = "nhp_token"

  # Cookie name must follow RFC 6265 token charset and be lowercase, since
  # CloudFront Functions key the request.cookies map by lowercase cookie name.
  # Restricting to a strict charset also prevents JavaScript template injection.
  validation {
    condition     = can(regex("^[a-z0-9_-]+$", var.nhp_auth_cookie_name))
    error_message = "nhp_auth_cookie_name must be lowercase alphanumeric, hyphen, or underscore (CloudFront Functions normalize cookie keys to lowercase)."
  }
}
