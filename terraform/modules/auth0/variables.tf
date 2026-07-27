# Auth0 module variables

variable "environment" {
  description = "Environment name (sandbox, prod)"
  type        = string
}

variable "manage_tenant_resources" {
  description = "Whether this environment manages shared Auth0 tenant resources (role, branding, attack protection, email provider/templates). Only one environment should set this to true in a shared tenant."
  type        = bool
  default     = true
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

variable "cleanup_old_credentials" {
  description = <<-EOT
    When true, the rotation Lambda deletes old Auth0 credentials after
    promoting the new one. Reduces the window where old credentials remain
    valid.

    Auth0 Management API scopes required on the management M2M client when
    enabling this:
      - read:client_credentials   (GET    /api/v2/clients/{id}/credentials)
      - delete:client_credentials (DELETE /api/v2/clients/{id}/credentials/{id})

    Without these scopes, cleanup will fail with an Auth0 403 and the rotation
    Lambda will log a non-fatal error (the rotation itself still succeeds).

    Operational note: any service still caching an old credential may briefly
    fail authentication until it re-reads from Secrets Manager — ensure
    consumers have short cache TTLs before enabling.
  EOT
  type        = bool
  default     = false
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
# Rotation Alarm Configuration
# ==============================================================================

variable "alarm_sns_topic_arn" {
  description = "SNS topic ARN for CloudWatch alarm notifications."
  type        = string
  default     = null

  validation {
    condition     = var.alarm_sns_topic_arn == null || can(regex("^arn:aws:sns:", var.alarm_sns_topic_arn))
    error_message = "alarm_sns_topic_arn must be a valid SNS topic ARN"
  }
}

variable "enable_sns_alerts" {
  description = "Static boolean: set true when this module's SNS-routed Auth0 rotation alarms should be created and alarm_sns_topic_arn is wired. Rotation alarms require a destination and gate count on this value to avoid count-depends-on-computed."
  type        = bool
  default     = false
}

variable "rotation_alarm_duration_threshold_ms" {
  description = "Duration threshold in milliseconds for Lambda duration alarm (default: 100000ms / 100s, timeout is 120s)"
  type        = number
  default     = 100000

  validation {
    condition     = var.rotation_alarm_duration_threshold_ms >= 1000 && var.rotation_alarm_duration_threshold_ms <= 120000
    error_message = "rotation_alarm_duration_threshold_ms must be between 1000 and 120000"
  }
}

variable "rotation_alarm_grace_days" {
  description = "Grace period in days after rotation_days before the overdue alarm fires (default: 3)"
  type        = number
  default     = 3

  validation {
    condition     = var.rotation_alarm_grace_days >= 1 && var.rotation_alarm_grace_days <= 30
    error_message = "rotation_alarm_grace_days must be between 1 and 30"
  }
}

variable "rotation_alarm_throttle_threshold" {
  description = "Number of Lambda throttles in two consecutive 5-minute periods before alarming (default: 5)"
  type        = number
  default     = 5

  validation {
    condition     = var.rotation_alarm_throttle_threshold >= 1 && var.rotation_alarm_throttle_threshold <= 100
    error_message = "rotation_alarm_throttle_threshold must be between 1 and 100"
  }
}

# ==============================================================================
# Smoke Test M2M Configuration
# ==============================================================================

variable "enable_smoke_test_client" {
  description = "Create a dedicated Auth0 M2M client for smoke tests with system tier"
  type        = bool
  default     = false
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

# ==============================================================================
# Slack OAuth (qurl-bot-slack workspace-install) Configuration
# ==============================================================================

variable "enable_slack_oauth_client" {
  description = <<-EOT
    Create the Auth0 regular_web client used by qurl-bot-slack for the
    workspace-install OAuth handshake. Sandbox enables this once
    `slackbot.layerv.xyz` is in DNS; prod enables it once the prod-account
    DNS for the Slack bot lands.

    WARNING — one-way switch in prod. Flipping `true` → `false` destroys
    `auth0_client.slack_oauth` (the `count` gate evaluates to 0), which
    invalidates every live workspace binding — affected workspaces would
    need to re-install via `/oauth/qurl/start`. `prevent_destroy` is
    deliberately omitted here because it interacts badly with `count`
    toggles; the operator-level mitigation is to treat this var as
    append-only in prod.
  EOT
  type        = bool
  default     = false
}

# ==============================================================================
# Auth0 client IDs (#3284)
# ==============================================================================
# Since the Auth0 provider was retired (see `removed.tf`), the AWS resources in
# this module take client IDs as inputs instead of reading them off `auth0_*`
# attributes. Auth0 client IDs are PUBLIC identifiers — the dashboard client ID
# is already published as a plaintext SSM parameter and shipped to browsers in
# `NEXT_PUBLIC_AUTH0_CLIENT_ID` — so they live in tfvars, not in secrets.
#
# The matching client SECRETS are not inputs here and never should be: they are
# written straight into Secrets Manager by an operator (`put-secret-value`), so
# they never enter Terraform state or a plan log.
#
# These replaced the former google_oauth_client_id/secret and
# github_oauth_client_id/secret variables, which were dead — their
# `auth0_connection` resources were gated on `<provider>_oauth_client_id !=
# null`, no workflow ever exported the matching `TF_VAR_*`, and the GitHub
# Actions secrets their tfvars comments referenced were never created, so
# `count` was permanently 0 in both environments.

variable "backend_service_client_id" {
  description = "Auth0 client ID of the Website Playground M2M application (legacy resource name `backend_service`). Public identifier. Null leaves the value absent from module outputs."
  type        = string
  default     = null

  validation {
    condition     = var.backend_service_client_id == null || can(regex("^[A-Za-z0-9]{32}$", var.backend_service_client_id))
    error_message = "backend_service_client_id must be a 32-character alphanumeric Auth0 client ID."
  }
}

variable "smoke_test_client_id" {
  description = "Auth0 client ID of the smoke-test M2M application. Public identifier. Required when enable_smoke_test_client is true."
  type        = string
  default     = null

  validation {
    condition     = var.smoke_test_client_id == null || can(regex("^[A-Za-z0-9]{32}$", var.smoke_test_client_id))
    error_message = "smoke_test_client_id must be a 32-character alphanumeric Auth0 client ID."
  }
}

variable "spa_dashboard_client_id" {
  description = "Auth0 client ID of the dashboard SPA. Public identifier — published to SSM and consumed by the website as NEXT_PUBLIC_AUTH0_CLIENT_ID. Required when enable_spa_dashboard is true."
  type        = string
  default     = null

  validation {
    condition     = var.spa_dashboard_client_id == null || can(regex("^[A-Za-z0-9]{32}$", var.spa_dashboard_client_id))
    error_message = "spa_dashboard_client_id must be a 32-character alphanumeric Auth0 client ID."
  }
}

variable "slack_oauth_client_id" {
  description = "Auth0 client ID of the qurl-bot-slack workspace-install application. Public identifier. Required when enable_slack_oauth_client is true."
  type        = string
  default     = null

  validation {
    condition     = var.slack_oauth_client_id == null || can(regex("^[A-Za-z0-9]{32}$", var.slack_oauth_client_id))
    error_message = "slack_oauth_client_id must be a 32-character alphanumeric Auth0 client ID."
  }
}

# ==============================================================================
# Auth0 Custom Domain
# ==============================================================================

variable "auth0_custom_domain" {
  description = "Auth0 custom domain (e.g., auth.layerv.ai) used by the SPA for login. If null, falls back to auth0_tenant_domain for SSM parameter."
  type        = string
  default     = null

  validation {
    condition     = var.auth0_custom_domain == null || can(regex("^[a-zA-Z0-9][a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", var.auth0_custom_domain))
    error_message = "auth0_custom_domain must be a valid domain name (e.g., auth.layerv.ai)"
  }
}

variable "email_ses_region" {
  description = "AWS region where SES domain is verified"
  type        = string
  default     = "us-east-2"
}
