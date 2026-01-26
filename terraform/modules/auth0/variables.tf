# Auth0 module variables

variable "environment" {
  description = "Environment name (sandbox, prod)"
  type        = string
}

variable "api_audience" {
  description = "Auth0 API audience/identifier (e.g., https://api.layerv.xyz)"
  type        = string

  validation {
    condition     = can(regex("^https://", var.api_audience))
    error_message = "api_audience must be an HTTPS URL"
  }
}

# Token lifetime configuration
variable "api_token_lifetime" {
  description = "Token lifetime for API access in seconds (default: 1 hour)"
  type        = number
  default     = 3600

  validation {
    condition     = var.api_token_lifetime >= 300 && var.api_token_lifetime <= 86400
    error_message = "api_token_lifetime must be between 300 (5 min) and 86400 (24 hours) seconds"
  }
}

variable "web_token_lifetime" {
  description = "Token lifetime for web/browser-based apps in seconds (default: 2 hours)"
  type        = number
  default     = 7200

  validation {
    condition     = var.web_token_lifetime >= 300 && var.web_token_lifetime <= 86400
    error_message = "web_token_lifetime must be between 300 (5 min) and 86400 (24 hours) seconds"
  }
}

variable "m2m_token_lifetime" {
  description = "Token lifetime for M2M clients in seconds (default: 1 hour)"
  type        = number
  default     = 3600

  validation {
    condition     = var.m2m_token_lifetime >= 300 && var.m2m_token_lifetime <= 86400
    error_message = "m2m_token_lifetime must be between 300 (5 min) and 86400 (24 hours) seconds"
  }
}
