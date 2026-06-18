variable "domain_name" {
  description = "Lowercase DNS name for the QURL link redirect page (e.g., qurl.link.layerv.xyz). Rendered into the verifier host allowlist."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$", var.domain_name))
    error_message = "domain_name must be a lowercase DNS name with no scheme, port, or path, for example qurl.link.layerv.xyz."
  }
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

variable "js_agent_enabled" {
  description = "Upload the browser NHP JS-agent bundle beside the qurl.link verifier shell and render the relay-first verifier. Enabling this requires relay_connect_src_origin and server_public_key_b64. Sandbox enables this for #2208/#2680; prod stays false until the sandbox browser cutover is proven."
  type        = bool
  default     = false
}

variable "relay_connect_src_origin" {
  description = "HTTPS origin the qurl.link browser NHP agent may fetch for relay knocks when js_agent_enabled is true. Must be scheme plus lowercase host, with no port/path. Null is only valid while js_agent_enabled is false."
  type        = string
  default     = null

  validation {
    condition     = var.relay_connect_src_origin == null || can(regex("^https://[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$", var.relay_connect_src_origin))
    error_message = "relay_connect_src_origin must be null or an HTTPS origin with no port/path, for example https://relay.qurl.link.layerv.xyz."
  }
}

variable "server_public_key_b64" {
  description = "Standard-base64 32-byte NHP server static public key rendered into qurl.link when js_agent_enabled is true. Empty only while js_agent_enabled is false."
  type        = string
  default     = ""

  validation {
    condition     = var.server_public_key_b64 == "" || can(regex("^[A-Za-z0-9+/]{43}=$", var.server_public_key_b64))
    error_message = "server_public_key_b64 must be empty or a 44-character standard-base64 encoded 32-byte X25519 public key."
  }
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
