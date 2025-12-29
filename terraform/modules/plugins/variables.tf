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
# These plugins are now statically compiled into the server binary.
# No S3 storage needed - this variable is kept for compatibility but unused.
# ============================================================================

variable "server_plugins" {
  description = <<-EOT
    DEPRECATED: NHP Server plugins are now statically compiled.
    This variable is kept for backwards compatibility but is no longer used.
    Plugin configuration is handled by the compute module's server_plugins list.
  EOT
  type        = any
  default     = {}
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
    NHP server plugins are now compiled in - only Traefik plugins use S3.

    Example: ["traefik-plugins"]
  EOT
  type        = list(string)
  default     = ["traefik-plugins"]
}

variable "github_actions_role_arn" {
  description = "ARN of the GitHub Actions OIDC role (from ecr module) to add S3 permissions to"
  type        = string
  default     = null
}
