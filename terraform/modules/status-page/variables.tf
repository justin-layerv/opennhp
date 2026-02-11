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
