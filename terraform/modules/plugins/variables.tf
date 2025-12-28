# Plugins Module Variables
# Unified plugin management for NHP Server and Traefik plugins

variable "environment" {
  description = "Environment name (sandbox, prod)"
  type        = string
}

variable "name_prefix" {
  description = "Name prefix for resources"
  type        = string
}

variable "tags" {
  description = "Tags for resources"
  type        = map(string)
  default     = {}
}

# ============================================================================
# NHP Server Plugins (passcode, oidc, etc.)
# These are Go plugins (.so files) loaded by NHP Server at runtime.
# ============================================================================

variable "server_plugins" {
  description = <<-EOT
    Map of NHP Server plugins to deploy.
    Each plugin specifies:
    - version: S3 key prefix for plugin binary (e.g., "v1.0.0" or "latest")
    - config: Map of configuration values rendered to plugin's config.toml

    Example:
    server_plugins = {
      passcode = {
        version = "v1.0.0"
        config = {
          ResourceMode = "api"
          AuthUrl      = "http://console:8888"
          SigningKey   = "secret-key"
          AesKey       = "aes-key"
        }
      }
      oidc = {
        version = "v2.0.1"
        config = {
          ResourceMode      = "api"
          AuthUrl           = "http://console:8888"
          AUTH0_DOMAIN      = "dev-xyz.auth0.com"
          OIDC_CLIENTID     = "client-id"
          OIDC_CLIENTSECRET = "client-secret"
          AUTH0_CALLBACK_URL = "https://example.com/callback"
        }
      }
    }
  EOT
  type = map(object({
    version = string
    config  = map(string)
  }))
  default = {}
}

# ============================================================================
# Traefik Plugins (nhp-token-validator, etc.)
# These are Traefik middleware plugins loaded by Traefik on AC instances.
# ============================================================================

variable "traefik_plugins" {
  description = <<-EOT
    Map of Traefik plugins to deploy.
    Each plugin specifies:
    - version: S3 key prefix for plugin files (e.g., "v1.0.0" or "latest")
    - config: Optional map of configuration values (if plugin needs config)

    Example:
    traefik_plugins = {
      nhp-token-validator = {
        version = "v1.0.0"
        config  = {}
      }
    }
  EOT
  type = map(object({
    version = string
    config  = optional(map(string), {})
  }))
  default = {}
}

# ============================================================================
# GitHub Actions OIDC Configuration
# Allows plugin repos to upload binaries to S3
# ============================================================================

variable "github_org" {
  description = "GitHub organization name for OIDC trust"
  type        = string
  default     = "layervai"
}

variable "plugin_repos" {
  description = <<-EOT
    List of GitHub repository names that can upload plugins.
    These repos will be granted S3 write access via OIDC.

    Example: ["nhp-plugins-passcode", "nhp-plugins-oidc", "traefik-plugins"]
  EOT
  type        = list(string)
  default     = ["nhp-plugins-passcode", "nhp-plugins-oidc", "traefik-plugins"]
}

variable "github_actions_role_arn" {
  description = "ARN of the GitHub Actions OIDC role (from ecr module) to add S3 permissions to"
  type        = string
  default     = null
}
