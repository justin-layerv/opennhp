variable "domain_name" {
  description = "Domain name for the QURL link redirect page (e.g., link.nhp.layerv.xyz)"
  type        = string
}

variable "bucket_name" {
  description = "Name of the S3 bucket for the redirect page"
  type        = string
}

variable "acm_certificate_arn" {
  description = "ARN of the ACM certificate for HTTPS (must be in us-east-1 for CloudFront)"
  type        = string
}

variable "nhp_resolve_url" {
  description = "NHP Server QURL plugin URL (e.g., https://ac.nhp.layerv.xyz/plugins/qurl)"
  type        = string
}

variable "enable_access_logs" {
  description = "Enable CloudFront access logging to S3"
  type        = bool
  default     = false
}

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default     = {}
}
