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

# ==============================================================================
# SSM & Monitoring
# ==============================================================================

variable "ssm_prefix" {
  description = "SSM parameter path prefix (e.g., /sandbox/nhp)"
  type        = string
}

variable "alarm_name_prefix" {
  description = "CloudWatch alarm name prefix for filtering relevant alarms"
  type        = string
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

variable "ac_nlb_tg_arns" {
  description = "AC NLB target group ARNs to check health (blue, optionally green)"
  type        = list(string)
  default     = []
}

# ==============================================================================
# Metrics & ASG
# ==============================================================================

variable "server_nlb_arn_suffix" {
  description = "Server NLB ARN suffix for CloudWatch NLB metric dimensions"
  type        = string
  default     = ""
}

variable "ac_nlb_arn_suffix" {
  description = "AC NLB ARN suffix for CloudWatch NLB metric dimensions"
  type        = string
  default     = ""
}

variable "server_asg_name" {
  description = "Server ASG name for CPU metrics and instance details"
  type        = string
  default     = ""
}

variable "ac_asg_name" {
  description = "AC ASG name for CPU metrics and instance details"
  type        = string
  default     = ""
}

variable "grafana_dashboard_url" {
  description = "URL to the NHP Grafana dashboard (shown in footer)"
  type        = string
  default     = ""
}

# ==============================================================================
# Deployment Model
# ==============================================================================

variable "deployment_model" {
  description = "Deployment strategy: blue_green (two ASGs, NLB switch) or canary (single ASG, progressive rollout)"
  type        = string
  default     = "blue_green"

  validation {
    condition     = contains(["blue_green", "canary"], var.deployment_model)
    error_message = "deployment_model must be 'blue_green' or 'canary'."
  }
}

variable "canary_state_ssm_param" {
  description = "Full SSM parameter name for canary deployment state. Only used when deployment_model is canary."
  type        = string
  default     = ""
}

# ==============================================================================
# Dependent Services
# ==============================================================================

variable "dependent_service_urls" {
  description = "Map of dependent service names to health check URLs. Lambda performs HTTP GET and reports status + response time. Keep total Lambda env vars under 4KB."
  type        = map(string)
  default     = {}
}

# ==============================================================================
# SSL Certificate Monitoring
# ==============================================================================

variable "ssl_cert_arns" {
  description = "Map of label to ACM certificate ARN for SSL expiry monitoring. Lambda checks each cert and reports days remaining."
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

# ==============================================================================
# NHP Authentication (Dogfooding)
# ==============================================================================

variable "enable_nhp_auth" {
  description = <<-EOT
    Protect the status page with NHP authentication via QURL. When enabled,
    unauthenticated requests are redirected to the QURL login portal.

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
