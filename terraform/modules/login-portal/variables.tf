variable "domain_name" {
  description = "Domain name for the login portal (e.g., login.layerv.xyz)"
  type        = string
}

variable "bucket_name" {
  description = "Name of the S3 bucket for the login portal"
  type        = string
}

variable "acm_certificate_arn" {
  description = "ARN of the ACM certificate for HTTPS (must be in us-east-1 for CloudFront)"
  type        = string
}

variable "qurl_api_url" {
  description = "QURL API base URL for access code redemption (e.g., https://api.layerv.xyz)"
  type        = string
}

variable "auth0_domain" {
  description = "Auth0 custom domain (e.g., auth.layerv.ai)"
  type        = string
}

variable "auth0_client_id" {
  description = "Auth0 SPA client ID for login"
  type        = string
}

variable "auth0_audience" {
  description = "Auth0 API audience"
  type        = string
}

variable "auth0_redirect_uri" {
  description = "Redirect URI after Auth0 login (e.g., https://staging.layerv.ai/qurl/dashboard/callback/)"
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
