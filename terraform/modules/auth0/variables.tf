# Auth0 module variables

variable "environment" {
  description = "Environment name (sandbox, prod)"
  type        = string
}

variable "name_prefix" {
  description = "Prefix for resource names (e.g., layerv-nhp-sandbox)"
  type        = string
}

variable "secrets_kms_key_arn" {
  description = "KMS key ARN for encrypting secrets. If null, uses AWS managed key."
  type        = string
  default     = null
}

variable "tags" {
  description = "Tags to apply to resources"
  type        = map(string)
  default     = {}
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
  description = "Token lifetime for web/browser-based apps in seconds (default: 1 hour). Must be <= api_token_lifetime."
  type        = number
  default     = 3600

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

# ==============================================================================
# Secret Rotation Configuration
# ==============================================================================

variable "enable_rotation" {
  description = "Enable automatic secret rotation for Auth0 M2M credentials"
  type        = bool
  default     = false
}

variable "rotation_days" {
  description = "Rotate secret every N days (default: 30)"
  type        = number
  default     = 30

  validation {
    condition     = var.rotation_days >= 1 && var.rotation_days <= 365
    error_message = "rotation_days must be between 1 and 365"
  }
}

variable "auth0_domain" {
  description = "Auth0 tenant domain for Management API (e.g., dev-xxx.us.auth0.com). Required when enable_rotation is true."
  type        = string
  default     = null

  validation {
    # Validates standard Auth0 tenant domain format: {tenant}.{region}.auth0.com
    # Supports regions: us, eu, au, jp (and future regions with similar format)
    condition     = var.auth0_domain == null || can(regex("^[a-zA-Z0-9-]+\\.[a-z]{2,3}\\.auth0\\.com$", var.auth0_domain))
    error_message = "auth0_domain must be a valid Auth0 tenant domain (e.g., dev-xxx.us.auth0.com)"
  }
}

variable "auth0_management_secret_arn" {
  description = "Secrets Manager ARN containing Auth0 Management API credentials (client_id, client_secret). Required when enable_rotation is true."
  type        = string
  default     = null

  validation {
    condition     = var.auth0_management_secret_arn == null || can(regex("^arn:aws:secretsmanager:", var.auth0_management_secret_arn))
    error_message = "auth0_management_secret_arn must be a valid Secrets Manager ARN"
  }
}

# ==============================================================================
# Developer Portal Management M2M Configuration
# ==============================================================================

variable "dev_portal_mgmt_secret_name" {
  description = "Secrets Manager name for developer portal Auth0 Management API credentials. If set, creates a management M2M app with Management API grants."
  type        = string
  default     = null
}

# Separate from auth0_domain (which is only used by the rotation Lambda and
# conditionally passed based on enable_rotation). This variable is always
# passed and used to construct the Management API audience URL.
variable "auth0_tenant_domain" {
  description = "Auth0 tenant domain (e.g., layerv.us.auth0.com). Required when dev_portal_mgmt_secret_name is set, used for Management API audience."
  type        = string
  default     = null

  validation {
    condition     = var.auth0_tenant_domain == null || can(regex("^[a-zA-Z0-9-]+\\.[a-z]{2,3}\\.auth0\\.com$", var.auth0_tenant_domain))
    error_message = "auth0_tenant_domain must be a valid Auth0 tenant domain (e.g., layerv.us.auth0.com)"
  }
}

# ==============================================================================
# SPA Dashboard Configuration
# ==============================================================================

variable "enable_spa_dashboard" {
  description = "Enable SPA dashboard Auth0 client for developer login"
  type        = bool
  default     = false
}

variable "spa_callback_urls" {
  description = "Allowed callback URLs for SPA dashboard (Auth0 redirect after login)"
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for url in var.spa_callback_urls : can(regex("^https://", url))])
    error_message = "All SPA callback URLs must use HTTPS"
  }

  validation {
    condition     = !var.enable_spa_dashboard || length(var.spa_callback_urls) > 0
    error_message = "spa_callback_urls must not be empty when enable_spa_dashboard is true"
  }
}

variable "spa_logout_urls" {
  description = "Allowed logout redirect URLs for SPA dashboard"
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for url in var.spa_logout_urls : can(regex("^https://", url))])
    error_message = "All SPA logout URLs must use HTTPS"
  }
}

variable "spa_web_origins" {
  description = "Allowed web origins for SPA dashboard (CORS)"
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for url in var.spa_web_origins : can(regex("^https://", url))])
    error_message = "All SPA web origins must use HTTPS"
  }
}

# ==============================================================================
# Social Connection Configuration (Google + GitHub)
# ==============================================================================

variable "google_oauth_client_id" {
  description = "Google OAuth2 client ID for social login. If null, Google connection is not created."
  type        = string
  default     = null
  sensitive   = true
}

variable "google_oauth_client_secret" {
  description = "Google OAuth2 client secret for social login."
  type        = string
  default     = null
  sensitive   = true
}

variable "github_oauth_client_id" {
  description = "GitHub OAuth client ID for social login. If null, GitHub connection is not created."
  type        = string
  default     = null
  sensitive   = true
}

variable "github_oauth_client_secret" {
  description = "GitHub OAuth client secret for social login."
  type        = string
  default     = null
  sensitive   = true
}
