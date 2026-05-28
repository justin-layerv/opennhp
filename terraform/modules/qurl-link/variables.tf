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

variable "enable_access_logs" {
  description = "Enable CloudFront access logging to S3"
  type        = bool
  default     = false
}

variable "robots_tag" {
  description = "Optional X-Robots-Tag response header value. Deliberately locked to null or 'noindex, nofollow' so non-prod qurl-link hosts that serve byte-identical HTML cannot broaden crawler directives without a module change."
  type        = string
  default     = null

  validation {
    condition     = var.robots_tag == null || lower(trimspace(var.robots_tag)) == "noindex, nofollow"
    error_message = "robots_tag must be null or exactly 'noindex, nofollow'."
  }
}

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default     = {}
}
