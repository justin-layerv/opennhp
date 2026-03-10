# Auth0 resources for LayerV NHP
#
# This module manages Auth0 configuration for QURL API authentication.
# The Auth0 tenant must be created manually first.
#
# Required Auth0 provider configuration in root module:
#   provider "auth0" {
#     domain        = var.auth0_domain
#     client_id     = var.auth0_client_id      # M2M app client ID
#     client_secret = var.auth0_client_secret  # M2M app client secret
#   }

# ==============================================================================
# API (Resource Server)
# ==============================================================================
# The QURL API that tokens are issued for

resource "auth0_resource_server" "qurl_api" {
  name        = "LayerV API (${var.environment})"
  identifier  = var.api_audience
  signing_alg = "RS256"

  # Token settings (configurable per environment)
  token_lifetime         = var.api_token_lifetime
  token_lifetime_for_web = var.web_token_lifetime

  # Skip consent for first-party applications
  skip_consent_for_verifiable_first_party_clients = true

  # RBAC: enforce policies and include permissions claim in access tokens.
  # Note: RBAC owns the `permissions` claim — Actions cannot override it via
  # setCustomClaim('permissions', ...). The post-login Action below injects
  # default permissions into the namespaced `https://layerv.ai/permissions`
  # claim instead, which the QURL validator checks alongside `scope` and
  # `permissions`.
  enforce_policies = true
  token_dialect    = "access_token_authz"

  # Prevent accidental deletion of API definition
  lifecycle {
    prevent_destroy = true

    precondition {
      condition     = var.web_token_lifetime <= var.api_token_lifetime
      error_message = "web_token_lifetime (${var.web_token_lifetime}s) must be <= api_token_lifetime (${var.api_token_lifetime}s)"
    }
  }
}

# ==============================================================================
# API Scopes
# ==============================================================================

resource "auth0_resource_server_scopes" "qurl_scopes" {
  resource_server_identifier = auth0_resource_server.qurl_api.identifier

  scopes {
    name        = "qurl:read"
    description = "Read QURL resources (list, get, quota)"
  }

  scopes {
    name        = "qurl:write"
    description = "Create, update, delete QURL resources"
  }

  scopes {
    name        = "qurl:admin"
    description = "Administrative access to all QURL resources"
  }

  scopes {
    name        = "qurl:resolve"
    description = "Resolve QURL access tokens via headless API (POST /v1/resolve)"
  }
}

# ==============================================================================
# RBAC Roles
# ==============================================================================
# Default role assigned to all dashboard users. The post-login Action
# auto-injects these permissions into the access token so users get
# access immediately — no manual role assignment required.

resource "auth0_role" "user" {
  count       = var.manage_tenant_resources ? 1 : 0
  name        = "User"
  description = "Default role for QURL dashboard users"
}

data "auth0_role" "user" {
  count = var.manage_tenant_resources ? 0 : 1
  name  = "User"
}

locals {
  user_role_id = var.manage_tenant_resources ? auth0_role.user[0].id : data.auth0_role.user[0].id
}

# Only one environment manages role permissions to avoid drift.
# auth0_role_permissions reads ALL permissions on the role during plan —
# if both envs manage it, they fight (each removes the other's API scopes).
# The post-login Action injects default permissions via custom claim for
# all environments, so prod users still get access even without role_permissions.
resource "auth0_role_permissions" "user" {
  count   = var.manage_tenant_resources ? 1 : 0
  role_id = local.user_role_id

  permissions {
    resource_server_identifier = auth0_resource_server.qurl_api.identifier
    name                       = "qurl:read"
  }

  permissions {
    resource_server_identifier = auth0_resource_server.qurl_api.identifier
    name                       = "qurl:write"
  }
}

# ==============================================================================
# Post-Login Action — Inject Default Permissions
# ==============================================================================
# Every authenticated user gets qurl:read and qurl:write in their access
# token. This Action merges default permissions with any existing RBAC
# permissions so manual role assignments are additive, not required.
#
# Why an Action instead of just RBAC roles?
# - RBAC permissions only appear in the token AFTER a role is assigned.
# - New users have no roles on first login, so they'd get 403.
# - The Action guarantees permissions from the very first token.

resource "auth0_action" "default_permissions" {
  count   = var.manage_tenant_resources ? 1 : 0
  name    = "Post-Login Security Gates"
  runtime = "node18"
  deploy  = true

  supported_triggers {
    id      = "post-login"
    version = "v3"
  }

  code = <<-EOT
    exports.onExecutePostLogin = async (event, api) => {
      // --- Gate 1: Block disposable email domains ---
      // Last updated: 2026-03, source: https://github.com/disposable-email-domains/disposable-email-domains
      const disposableDomains = [
        'mailinator.com', 'guerrillamail.com', 'guerrillamail.de',
        'yopmail.com', 'tempmail.com', 'throwaway.email',
        'temp-mail.org', 'fakeinbox.com', 'sharklasers.com',
        'guerrillamailblock.com', 'grr.la', 'dispostable.com',
        'maildrop.cc', 'mailnesia.com', 'trashmail.com',
        'getnada.com', 'tempail.com', 'mohmal.com',
        'minutemail.com', 'emailondeck.com'
      ];
      const emailDomain = (event.user.email || '').split('@')[1]?.toLowerCase();
      if (emailDomain && disposableDomains.includes(emailDomain)) {
        api.access.deny('Disposable email addresses are not allowed. Please sign up with a permanent email.');
        return;
      }

      // --- Gate 2: Require email verification (email/password only) ---
      // Social logins (Google, GitHub) always have verified emails, so this
      // only blocks unverified email/password signups. Allow first login
      // attempt so the user can receive the verification email.
      if (!event.user.email_verified && event.stats.logins_count > 0) {
        api.access.deny('Please verify your email address before logging in. Check your inbox for a verification link.');
        return;
      }

      // --- Inject default permissions ---
      const defaultPerms = ['qurl:read', 'qurl:write'];
      const rbacPerms = event.authorization?.permissions || [];
      const merged = [...new Set([...rbacPerms, ...defaultPerms])];
      api.accessToken.setCustomClaim('https://layerv.ai/permissions', merged);
    };
  EOT
}

resource "auth0_trigger_actions" "post_login" {
  count   = var.manage_tenant_resources ? 1 : 0
  trigger = "post-login"

  actions {
    id           = auth0_action.default_permissions[0].id
    display_name = auth0_action.default_permissions[0].name
  }
}

# ==============================================================================
# Machine-to-Machine Application (for backend services)
# ==============================================================================
# Used by the developer portal playground proxy to call the QURL API on behalf
# of playground users.  Despite the legacy "backend_service" resource name, this
# client is NOT a general-purpose service account — it runs on the free tier.
# For CI/smoke tests, use the dedicated smoke_test client (system tier).

resource "auth0_client" "backend_service" {
  name        = "Website Playground (${var.environment})"
  description = "M2M client for developer portal playground proxy - ${var.environment}"
  app_type    = "non_interactive"

  # Grant types
  grant_types = ["client_credentials"]

  # JWT configuration
  jwt_configuration {
    alg                 = "RS256"
    lifetime_in_seconds = var.m2m_token_lifetime
  }

  # OIDC conformant
  oidc_conformant = true

  lifecycle {
    prevent_destroy = true
  }
}

# ==============================================================================
# Backend Service - API Grant
# ==============================================================================

resource "auth0_client_grant" "backend_qurl_api" {
  client_id = auth0_client.backend_service.id
  audience  = auth0_resource_server.qurl_api.identifier
  scopes    = ["qurl:read", "qurl:write", "qurl:admin", "qurl:resolve"]
}

# ==============================================================================
# Backend Service - Client Credentials
# ==============================================================================
# Manages the client secret for the M2M application, enabling rotation via Terraform.
# The secret can be rotated by running `terraform apply` - Auth0 will generate a new one.
#
# Note: The Auth0 TF provider returns empty client_secret unless the management
# app (Terraform) has read:client_keys scope on the Management API grant.
# Even with that scope, the provider may still return empty for client_secret_post
# auth method — this is a known provider limitation.
#
# For NEW environments: after initial `terraform apply`, the SM secret will contain
# an empty client_secret. You MUST run the manual fix below before services will work.
#
# If client_secret is empty in Secrets Manager, copy the secret from the Auth0
# dashboard (Applications > Backend Service > Settings) and update SM manually:
#   aws secretsmanager put-secret-value --secret-id <secret-name> \
#     --secret-string '{"client_id":"...","client_secret":"...","audience":"..."}'

resource "auth0_client_credentials" "backend_service" {
  client_id             = auth0_client.backend_service.id
  authentication_method = "client_secret_post"
}

# ==============================================================================
# AWS Secrets Manager - Auth0 Credentials
# ==============================================================================
# Automatically sync Auth0 M2M credentials to Secrets Manager for use by services.
# This eliminates manual secret management and enables automated rotation.

locals {
  is_prod = var.environment == "prod"
}

resource "aws_secretsmanager_secret" "auth0_backend" {
  # Legacy name — this secret is consumed by the developer portal playground
  # proxy, NOT by general backend services.  Kept as-is to avoid a destructive
  # rename (Secrets Manager requires delete + recreate).
  name                    = "${var.name_prefix}-auth0-backend-credentials"
  description             = "Auth0 M2M credentials for website playground proxy (${var.environment}) — NOT for CI/smoke tests"
  recovery_window_in_days = local.is_prod ? 30 : 0
  kms_key_id              = var.secrets_kms_key_arn

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-auth0-backend-credentials"
    Component = "auth0"
    Purpose   = "playground-proxy"
  })
}

resource "aws_secretsmanager_secret_version" "auth0_backend" {
  # Only manage secret version when rotation is disabled
  # When rotation is enabled, the Lambda manages the secret value
  count = var.enable_rotation ? 0 : 1

  secret_id = aws_secretsmanager_secret.auth0_backend.id
  secret_string = jsonencode({
    client_id     = auth0_client.backend_service.client_id
    client_secret = auth0_client_credentials.backend_service.client_secret
    audience      = auth0_resource_server.qurl_api.identifier
  })

  lifecycle {
    create_before_destroy = true
    # The Auth0 TF provider returns empty client_secret unless the management
    # app has read:client_keys scope. To prevent overwriting a manually-set
    # secret value, ignore changes after initial creation.
    ignore_changes = [secret_string]
  }
}

# Initial secret version for rotation-enabled secrets
# This seeds the secret with initial credentials before rotation takes over
resource "aws_secretsmanager_secret_version" "auth0_backend_initial" {
  count = var.enable_rotation ? 1 : 0

  secret_id = aws_secretsmanager_secret.auth0_backend.id
  secret_string = jsonencode({
    client_id     = auth0_client.backend_service.client_id
    client_secret = auth0_client_credentials.backend_service.client_secret
    audience      = auth0_resource_server.qurl_api.identifier
  })

  lifecycle {
    create_before_destroy = true
    # Ignore changes after initial creation - rotation Lambda will manage updates
    ignore_changes = [secret_string]
  }
}

# ==============================================================================
# Secret Rotation Infrastructure
# ==============================================================================
# Automatic rotation of Auth0 M2M client secrets using AWS Secrets Manager
# rotation with a Lambda function that calls the Auth0 Management API.

data "aws_region" "current" {
  count = var.enable_rotation ? 1 : 0
}

data "aws_caller_identity" "current" {
  count = var.enable_rotation ? 1 : 0
}

# IAM Role for Rotation Lambda
resource "aws_iam_role" "auth0_rotation" {
  count = var.enable_rotation ? 1 : 0
  name  = "${var.name_prefix}-auth0-rotation"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-auth0-rotation"
    Component = "auth0"
  })
}

resource "aws_iam_role_policy_attachment" "auth0_rotation_basic" {
  count      = var.enable_rotation ? 1 : 0
  role       = aws_iam_role.auth0_rotation[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "auth0_rotation_secrets" {
  count = var.enable_rotation ? 1 : 0
  name  = "secrets-access"
  role  = aws_iam_role.auth0_rotation[0].id

  # Build policy with conditional KMS statement - only needed for customer-managed keys
  # AWS managed key (aws/secretsmanager) doesn't require explicit IAM permissions
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [
        {
          Effect = "Allow"
          Action = [
            "secretsmanager:GetSecretValue",
            "secretsmanager:PutSecretValue",
            "secretsmanager:UpdateSecretVersionStage",
            "secretsmanager:DescribeSecret"
          ]
          Resource = aws_secretsmanager_secret.auth0_backend.arn
        },
        {
          Effect = "Allow"
          Action = [
            "secretsmanager:GetSecretValue"
          ]
          Resource = var.auth0_management_secret_arn
        }
      ],
      # Only add KMS permissions when using customer-managed key
      var.secrets_kms_key_arn != null ? [
        {
          Effect   = "Allow"
          Action   = ["kms:Decrypt", "kms:GenerateDataKey"]
          Resource = var.secrets_kms_key_arn
        }
      ] : []
    )
  })

  lifecycle {
    precondition {
      condition     = var.auth0_management_secret_arn != null
      error_message = "auth0_management_secret_arn is required when enable_rotation is true"
    }
  }
}

# Lambda Function for Rotation
data "archive_file" "auth0_rotation" {
  count       = var.enable_rotation ? 1 : 0
  type        = "zip"
  source_file = "${path.module}/lambda/rotate_secret.js"
  output_path = "${path.module}/auth0_rotation.zip"
}

# CloudWatch Log Group with retention policy
resource "aws_cloudwatch_log_group" "auth0_rotation" {
  count             = var.enable_rotation ? 1 : 0
  name              = "/aws/lambda/${var.name_prefix}-auth0-rotation"
  retention_in_days = local.is_prod ? 90 : 14

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-auth0-rotation-logs"
    Component = "auth0"
  })
}

resource "aws_lambda_function" "auth0_rotation" {
  count            = var.enable_rotation ? 1 : 0
  function_name    = "${var.name_prefix}-auth0-rotation"
  role             = aws_iam_role.auth0_rotation[0].arn
  handler          = "rotate_secret.handler"
  runtime          = "nodejs20.x"
  timeout          = 120 # Allow extra time for Auth0 API latency
  filename         = data.archive_file.auth0_rotation[0].output_path
  source_code_hash = data.archive_file.auth0_rotation[0].output_base64sha256

  # Prevent race conditions - rotation should only run once at a time
  reserved_concurrent_executions = 1

  environment {
    variables = {
      AUTH0_DOMAIN                = var.auth0_domain
      AUTH0_MANAGEMENT_SECRET_ARN = var.auth0_management_secret_arn
      AUTH0_API_AUDIENCE          = auth0_resource_server.qurl_api.identifier
    }
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-auth0-rotation"
    Component = "auth0"
  })

  # Ensure log group is created before Lambda to avoid race condition
  depends_on = [aws_cloudwatch_log_group.auth0_rotation]

  lifecycle {
    precondition {
      condition     = var.auth0_domain != null
      error_message = "auth0_domain is required when enable_rotation is true"
    }
    precondition {
      condition     = var.auth0_management_secret_arn != null
      error_message = "auth0_management_secret_arn is required when enable_rotation is true"
    }
  }
}

# Permission for Secrets Manager to invoke Lambda
resource "aws_lambda_permission" "auth0_rotation" {
  count         = var.enable_rotation ? 1 : 0
  statement_id  = "AllowSecretsManagerInvocation"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.auth0_rotation[0].function_name
  principal     = "secretsmanager.amazonaws.com"
  # Scope to specific secret for least privilege
  source_arn = aws_secretsmanager_secret.auth0_backend.arn
}

# Secret Rotation Schedule
resource "aws_secretsmanager_secret_rotation" "auth0_backend" {
  count               = var.enable_rotation ? 1 : 0
  secret_id           = aws_secretsmanager_secret.auth0_backend.id
  rotation_lambda_arn = aws_lambda_function.auth0_rotation[0].arn

  rotation_rules {
    automatically_after_days = var.rotation_days
  }

  depends_on = [aws_lambda_permission.auth0_rotation]
}

# ==============================================================================
# Smoke Test M2M Application
# ==============================================================================
# Dedicated M2M client for automated smoke tests. Runs on "system" tier with
# unlimited quotas, isolated from the backend service client used by the
# playground and production services.

resource "auth0_client" "smoke_test" {
  count       = var.enable_smoke_test_client ? 1 : 0
  name        = "Smoke Test (${var.environment})"
  description = "Dedicated M2M client for automated smoke tests - system tier, unlimited quotas - ${var.environment}"
  app_type    = "non_interactive"
  grant_types = ["client_credentials"]

  jwt_configuration {
    alg                 = "RS256"
    lifetime_in_seconds = var.m2m_token_lifetime
  }

  oidc_conformant = true
}

resource "auth0_client_credentials" "smoke_test" {
  count                 = var.enable_smoke_test_client ? 1 : 0
  client_id             = auth0_client.smoke_test[0].id
  authentication_method = "client_secret_post"
}

resource "auth0_client_grant" "smoke_test_qurl_api" {
  count     = var.enable_smoke_test_client ? 1 : 0
  client_id = auth0_client.smoke_test[0].id
  audience  = auth0_resource_server.qurl_api.identifier
  scopes    = ["qurl:read", "qurl:write", "qurl:admin", "qurl:resolve"]
}

resource "aws_secretsmanager_secret" "smoke_test" {
  count                   = var.enable_smoke_test_client ? 1 : 0
  name                    = "${var.name_prefix}-auth0-smoke-test-credentials"
  description             = "Auth0 M2M credentials for smoke tests (${var.environment}) - system tier"
  recovery_window_in_days = 0 # No recovery needed for test credentials
  kms_key_id              = var.secrets_kms_key_arn

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-auth0-smoke-test-credentials"
    Component = "auth0"
    Purpose   = "smoke-tests"
  })
}

resource "aws_secretsmanager_secret_version" "smoke_test" {
  count     = var.enable_smoke_test_client ? 1 : 0
  secret_id = aws_secretsmanager_secret.smoke_test[0].id
  secret_string = jsonencode({
    client_id     = auth0_client.smoke_test[0].client_id
    client_secret = auth0_client_credentials.smoke_test[0].client_secret
    audience      = auth0_resource_server.qurl_api.identifier
  })

  lifecycle {
    create_before_destroy = true
    ignore_changes        = [secret_string] # Same Auth0 provider limitation
  }
}

# ==============================================================================
# Developer Portal Management M2M Application
# ==============================================================================
# Creates an Auth0 M2M application authorized for the Management API,
# used by the developer portal to create/manage developer credentials.
# Only created when dev_portal_mgmt_secret_name is set.

resource "auth0_client" "dev_portal_mgmt" {
  count       = var.dev_portal_mgmt_secret_name != null ? 1 : 0
  name        = "Developer Portal Management (${var.environment})"
  description = "M2M client for developer portal management operations - ${var.environment}"
  app_type    = "non_interactive"
  grant_types = ["client_credentials"]

  oidc_conformant = true

  jwt_configuration {
    alg                 = "RS256"
    lifetime_in_seconds = var.m2m_token_lifetime
  }

  lifecycle {
    prevent_destroy = true

    precondition {
      condition     = var.auth0_tenant_domain != null
      error_message = "auth0_tenant_domain is required when dev_portal_mgmt_secret_name is set"
    }
  }
}

resource "auth0_client_credentials" "dev_portal_mgmt" {
  count                 = var.dev_portal_mgmt_secret_name != null ? 1 : 0
  client_id             = auth0_client.dev_portal_mgmt[0].id
  authentication_method = "client_secret_post"
}

# Grant Management API access with scopes needed for developer credential provisioning
resource "auth0_client_grant" "dev_portal_mgmt_api" {
  count     = var.dev_portal_mgmt_secret_name != null ? 1 : 0
  client_id = auth0_client.dev_portal_mgmt[0].id
  audience  = "https://${var.auth0_tenant_domain}/api/v2/"
  scopes = [
    "create:clients",
    "read:clients",
    "delete:clients",
    "create:client_grants",
    "read:client_grants",
    "delete:client_grants",
  ]
}

# Secrets Manager secret for management credentials
resource "aws_secretsmanager_secret" "dev_portal_mgmt" {
  count                   = var.dev_portal_mgmt_secret_name != null ? 1 : 0
  name                    = var.dev_portal_mgmt_secret_name
  description             = "Auth0 Management API credentials for developer portal (${var.environment})"
  recovery_window_in_days = local.is_prod ? 30 : 0
  kms_key_id              = var.secrets_kms_key_arn

  tags = merge(var.tags, {
    Name      = var.dev_portal_mgmt_secret_name
    Component = "auth0"
  })
}

resource "aws_secretsmanager_secret_version" "dev_portal_mgmt" {
  count     = var.dev_portal_mgmt_secret_name != null ? 1 : 0
  secret_id = aws_secretsmanager_secret.dev_portal_mgmt[0].id
  secret_string = jsonencode({
    client_id     = auth0_client.dev_portal_mgmt[0].client_id
    client_secret = auth0_client_credentials.dev_portal_mgmt[0].client_secret
    audience      = "https://${var.auth0_tenant_domain}/api/v2/"
  })

  lifecycle {
    create_before_destroy = true
    # Auth0 TF provider returns empty client_secret (provider limitation).
    # Prevent overwriting manually-set secret. For new environments, copy the
    # secret from Auth0 dashboard after initial apply (see backend_service comment).
    ignore_changes = [secret_string]
  }
}

# ==============================================================================
# SPA Application (for website dashboard login)
# ==============================================================================
# Auth0 SPA client for the website dashboard. Uses authorization_code + PKCE
# (no client secret). Developers log in via Google/GitHub/email to manage
# API keys, view usage, and handle billing.

resource "auth0_client" "spa_dashboard" {
  count       = var.enable_spa_dashboard ? 1 : 0
  name        = "QURL Dashboard (${var.environment})"
  description = "SPA client for developer dashboard - ${var.environment}"
  app_type    = "spa"

  # SPA uses authorization_code with PKCE (no client secret needed)
  grant_types = ["authorization_code", "refresh_token"]

  # Callbacks and logout URLs
  callbacks           = var.spa_callback_urls
  allowed_logout_urls = var.spa_logout_urls
  web_origins         = var.spa_web_origins

  # Token configuration
  jwt_configuration {
    alg                 = "RS256"
    lifetime_in_seconds = var.web_token_lifetime
  }

  # Refresh token configuration for SPA
  refresh_token {
    rotation_type                = "rotating"
    expiration_type              = "expiring"
    token_lifetime               = 2592000 # 30 days
    idle_token_lifetime          = 1296000 # 15 days
    infinite_idle_token_lifetime = false
    infinite_token_lifetime      = false
    leeway                       = 0
  }

  # OIDC conformant
  oidc_conformant = true

  lifecycle {
    precondition {
      condition     = length(var.spa_callback_urls) > 0
      error_message = "spa_callback_urls must not be empty when enable_spa_dashboard is true"
    }
  }
}

# SPA clients use PKCE (no client secret) — set auth method to "none"
resource "auth0_client_credentials" "spa_dashboard" {
  count                 = var.enable_spa_dashboard ? 1 : 0
  client_id             = auth0_client.spa_dashboard[0].id
  authentication_method = "none"
}

# Grant SPA dashboard access to QURL API scopes
resource "auth0_client_grant" "spa_qurl_api" {
  count     = var.enable_spa_dashboard ? 1 : 0
  client_id = auth0_client.spa_dashboard[0].id
  audience  = auth0_resource_server.qurl_api.identifier
  scopes    = ["qurl:read", "qurl:write"]
}

# ==============================================================================
# Social Connections (Google + GitHub)
# ==============================================================================
# These connections enable social login for the SPA dashboard.
# The connections are created only when the SPA dashboard is enabled and
# corresponding OAuth credentials are provided.

resource "auth0_connection" "google" {
  count                = var.manage_tenant_resources && var.enable_spa_dashboard && var.google_oauth_client_id != null ? 1 : 0
  name                 = "google-oauth2"
  strategy             = "google-oauth2"
  is_domain_connection = false

  options {
    client_id     = var.google_oauth_client_id
    client_secret = var.google_oauth_client_secret
    scopes        = ["email", "profile"]

    set_user_root_attributes = "on_first_login"
  }

  # prevent_destroy: social connections accumulate user data (linked accounts).
  # To remove a connection, first remove it from state with `terraform state rm`.
  lifecycle {
    prevent_destroy = true

    precondition {
      condition     = var.google_oauth_client_secret != null
      error_message = "google_oauth_client_secret is required when google_oauth_client_id is provided"
    }
  }
}

resource "auth0_connection_clients" "google" {
  count         = var.manage_tenant_resources && var.enable_spa_dashboard && var.google_oauth_client_id != null ? 1 : 0
  connection_id = auth0_connection.google[0].id
  enabled_clients = [
    auth0_client.spa_dashboard[0].id,
  ]
}

resource "auth0_connection" "github" {
  count                = var.manage_tenant_resources && var.enable_spa_dashboard && var.github_oauth_client_id != null ? 1 : 0
  name                 = "github"
  strategy             = "github"
  is_domain_connection = false

  options {
    client_id     = var.github_oauth_client_id
    client_secret = var.github_oauth_client_secret
    scopes        = ["user:email", "read:user"]

    set_user_root_attributes = "on_first_login"
  }

  # prevent_destroy: social connections accumulate user data (linked accounts).
  # To remove a connection, first remove it from state with `terraform state rm`.
  lifecycle {
    prevent_destroy = true

    precondition {
      condition     = var.github_oauth_client_secret != null
      error_message = "github_oauth_client_secret is required when github_oauth_client_id is provided"
    }
  }
}

resource "auth0_connection_clients" "github" {
  count         = var.manage_tenant_resources && var.enable_spa_dashboard && var.github_oauth_client_id != null ? 1 : 0
  connection_id = auth0_connection.github[0].id
  enabled_clients = [
    auth0_client.spa_dashboard[0].id,
  ]
}

# ==============================================================================
# SSM Parameters for SPA Dashboard Configuration
# ==============================================================================
# Publish Auth0 SPA configuration to SSM so the website can consume it.
# The website reads these values at build/deploy time as NEXT_PUBLIC_* env vars.

resource "aws_ssm_parameter" "spa_client_id" {
  count       = var.enable_spa_dashboard ? 1 : 0
  name        = "/${var.environment}/auth0/spa-client-id"
  description = "Auth0 SPA dashboard client ID (NEXT_PUBLIC_AUTH0_CLIENT_ID)"
  type        = "String"
  value       = auth0_client.spa_dashboard[0].client_id

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-auth0-spa-client-id"
    Component = "auth0"
  })

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_ssm_parameter" "spa_auth0_domain" {
  count       = var.enable_spa_dashboard ? 1 : 0
  name        = "/${var.environment}/auth0/domain"
  description = "Auth0 domain for SPA dashboard (NEXT_PUBLIC_AUTH0_DOMAIN)"
  type        = "String"
  value       = var.auth0_custom_domain != null ? var.auth0_custom_domain : var.auth0_tenant_domain

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-auth0-domain"
    Component = "auth0"
  })

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_ssm_parameter" "spa_api_audience" {
  count       = var.enable_spa_dashboard ? 1 : 0
  name        = "/${var.environment}/auth0/api-audience"
  description = "Auth0 API audience for SPA dashboard (NEXT_PUBLIC_AUTH0_AUDIENCE)"
  type        = "String"
  value       = auth0_resource_server.qurl_api.identifier

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-auth0-api-audience"
    Component = "auth0"
  })

  lifecycle {
    prevent_destroy = true
  }
}

# ==============================================================================
# Branding (Universal Login page appearance)
# ==============================================================================
# Configures the Auth0 Universal Login page with LayerV branding: logo, colors,
# and theme. This affects the login/signup flow users see.

resource "auth0_branding" "layerv" {
  count    = var.manage_tenant_resources ? 1 : 0
  logo_url = var.branding_logo_url

  colors {
    primary         = var.branding_primary_color
    page_background = var.branding_page_background
  }
}

resource "auth0_branding_theme" "layerv" {
  count      = var.manage_tenant_resources ? 1 : 0
  depends_on = [auth0_branding.layerv]

  borders {
    button_border_radius = 8
    button_border_weight = 0
    buttons_style        = "rounded"
    input_border_radius  = 8
    input_border_weight  = 1
    inputs_style         = "rounded"
    show_widget_shadow   = true
    widget_border_weight = 0
    widget_corner_radius = 12
  }

  colors {
    body_text                 = "#f9fafb"
    error                     = "#ef4444"
    header                    = "#f9fafb"
    icons                     = "#9ca3af"
    input_background          = "#1f2937"
    input_border              = "#374151"
    input_filled_text         = "#f9fafb"
    input_labels_placeholders = "#9ca3af"
    links_focused_components  = "#0099FF"
    primary_button            = "#0099FF"
    primary_button_label      = "#ffffff"
    secondary_button_border   = "#374151"
    secondary_button_label    = "#d1d5db"
    success                   = "#10b981"
    widget_background         = "#0a0f1a"
    widget_border             = "#1f2937"
  }

  fonts {
    links_style         = "normal"
    reference_text_size = 16

    body_text {
      bold = false
      size = 100
    }

    buttons_text {
      bold = true
      size = 100
    }

    input_labels {
      bold = false
      size = 100
    }

    links {
      bold = false
      size = 100
    }

    title {
      bold = true
      size = 150
    }

    subtitle {
      bold = false
      size = 100
    }
  }

  page_background {
    background_color = "#030712"
    page_layout      = "center"
  }

  widget {
    header_text_alignment = "center"
    logo_height           = 40
    logo_position         = "center"
    logo_url              = var.branding_logo_url
    social_buttons_layout = "top"
  }
}

# ==============================================================================
# Attack Protection (Bot Detection, Brute Force, Breached Passwords)
# ==============================================================================
# Tenant-level singleton resource. Bot detection starts in monitoring mode
# to observe traffic before enforcing. Brute force, suspicious IP throttling,
# and breached password detection enforce immediately (low false-positive risk).
#
# Auth0 plan requirement: Bot Detection requires B2C Essentials plan or higher.
# Breached Password Detection requires a higher-tier subscription — not available on current plan.

resource "auth0_attack_protection" "protection" {
  count = var.manage_tenant_resources ? 1 : 0
  bot_detection {
    bot_detection_level             = var.bot_detection_level
    challenge_password_policy       = "when_risky"
    challenge_passwordless_policy   = "when_risky"
    challenge_password_reset_policy = "always"
    monitoring_mode_enabled         = var.bot_detection_monitoring
  }

  brute_force_protection {
    enabled      = true
    max_attempts = var.brute_force_max_attempts
    mode         = "count_per_identifier_and_ip"
    shields      = ["block", "user_notification"]
  }

  suspicious_ip_throttling {
    enabled = true
    shields = ["admin_notification", "block"]

    # Rate = window in seconds over which max_attempts is counted.
    # These are Auth0's documented defaults from the provider docs.
    pre_login {
      max_attempts = 100
      rate         = 864000 # 10 days — long window catches slow-and-steady attacks
    }

    pre_user_registration {
      max_attempts = 50
      rate         = 1200 # 20 minutes — tighter window for signup spam
    }
  }

  # breached_password_detection requires a higher-tier Auth0 subscription.
  # Re-enable if plan is upgraded.
}

# ==============================================================================
# Email Provider (SES)
# ==============================================================================
# IAM user with SES send permissions for Auth0 to send branded transactional
# emails. Access keys are passed directly to Auth0 via the email provider
# resource (stored in Terraform state, encrypted at rest via S3+KMS).
#
# Key rotation procedure:
#   1. Create a second access key: aws iam create-access-key --user-name <user>
#   2. Update Auth0 email provider credentials (terraform apply or Auth0 dashboard)
#   3. Verify email delivery works with the new key
#   4. Delete the old access key: aws iam delete-access-key --access-key-id <old-key>

data "aws_caller_identity" "ses" {}

resource "aws_iam_user" "auth0_ses" {
  count = var.manage_tenant_resources ? 1 : 0
  name  = "${var.name_prefix}-auth0-ses"
  tags  = var.tags

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_iam_user_policy" "auth0_ses_send" {
  count = var.manage_tenant_resources ? 1 : 0
  name  = "ses-send-email"
  user  = aws_iam_user.auth0_ses[0].name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "SESSendEmail"
      Effect = "Allow"
      Action = [
        "ses:SendEmail",
        "ses:SendRawEmail"
      ]
      Resource = [
        "arn:aws:ses:${var.email_ses_region}:${data.aws_caller_identity.ses.account_id}:identity/layerv.xyz",
        "arn:aws:ses:${var.email_ses_region}:${data.aws_caller_identity.ses.account_id}:identity/layerv.ai"
      ]
    }]
  })
}

resource "aws_iam_access_key" "auth0_ses" {
  count = var.manage_tenant_resources ? 1 : 0
  user  = aws_iam_user.auth0_ses[0].name

  lifecycle {
    prevent_destroy = true
  }
}

# Bump trigger to force Auth0 email provider re-creation (credentials aren't
# read back by the provider, so Terraform can't detect external drift).
# To force re-creation: change the input value and apply.
resource "terraform_data" "email_provider_trigger" {
  count = var.manage_tenant_resources ? 1 : 0
  input = "2026-03-09-migrate-tenant-to-prod"
}

resource "auth0_email_provider" "ses" {
  count                = var.manage_tenant_resources ? 1 : 0
  name                 = "ses"
  enabled              = true
  default_from_address = var.email_from_address

  credentials {
    access_key_id     = aws_iam_access_key.auth0_ses[0].id
    secret_access_key = aws_iam_access_key.auth0_ses[0].secret
    region            = var.email_ses_region
  }

  lifecycle {
    replace_triggered_by = [terraform_data.email_provider_trigger[0]]
  }
}

# ==============================================================================
# Email Templates
# ==============================================================================
# Branded email templates for Auth0 transactional emails sent via SES.

resource "auth0_email_template" "verify_email" {
  count      = var.manage_tenant_resources ? 1 : 0
  depends_on = [auth0_email_provider.ses]

  template                = "verify_email"
  body                    = file("${path.module}/email-templates/verify_email.html")
  from                    = var.email_from_address
  subject                 = "Verify your email for LayerV"
  syntax                  = "liquid"
  url_lifetime_in_seconds = 432000 # 5 days
  enabled                 = true
  result_url              = var.email_result_url
}

resource "auth0_email_template" "welcome_email" {
  count      = var.manage_tenant_resources ? 1 : 0
  depends_on = [auth0_email_provider.ses]

  template = "welcome_email"
  body = templatefile("${path.module}/email-templates/welcome_email.html", {
    dashboard_url = "${var.email_result_url}/qurl/dashboard/"
  })
  from                    = var.email_from_address
  subject                 = "Welcome to LayerV"
  syntax                  = "liquid"
  url_lifetime_in_seconds = 0
  enabled                 = true
  result_url              = var.email_result_url
}

resource "auth0_email_template" "reset_email" {
  count      = var.manage_tenant_resources ? 1 : 0
  depends_on = [auth0_email_provider.ses]

  template                = "reset_email"
  body                    = file("${path.module}/email-templates/reset_email.html")
  from                    = var.email_from_address
  subject                 = "Reset your LayerV password"
  syntax                  = "liquid"
  url_lifetime_in_seconds = 432000 # 5 days
  enabled                 = true
  result_url              = var.email_result_url
}

# ==============================================================================
# State Migration: manage_tenant_resources count addition
# ==============================================================================
# These moved blocks handle the migration from non-indexed to indexed resources
# when `count` was added for the manage_tenant_resources pattern.

moved {
  from = auth0_action.default_permissions
  to   = auth0_action.default_permissions[0]
}

moved {
  from = auth0_role.user
  to   = auth0_role.user[0]
}

moved {
  from = auth0_role_permissions.user
  to   = auth0_role_permissions.user[0]
}

moved {
  from = auth0_trigger_actions.post_login
  to   = auth0_trigger_actions.post_login[0]
}

moved {
  from = auth0_branding.layerv
  to   = auth0_branding.layerv[0]
}

moved {
  from = auth0_branding_theme.layerv
  to   = auth0_branding_theme.layerv[0]
}

moved {
  from = auth0_attack_protection.protection
  to   = auth0_attack_protection.protection[0]
}

moved {
  from = aws_iam_user.auth0_ses
  to   = aws_iam_user.auth0_ses[0]
}

moved {
  from = aws_iam_user_policy.auth0_ses_send
  to   = aws_iam_user_policy.auth0_ses_send[0]
}

moved {
  from = aws_iam_access_key.auth0_ses
  to   = aws_iam_access_key.auth0_ses[0]
}

moved {
  from = auth0_email_provider.ses
  to   = auth0_email_provider.ses[0]
}

moved {
  from = auth0_email_template.verify_email
  to   = auth0_email_template.verify_email[0]
}

moved {
  from = auth0_email_template.welcome_email
  to   = auth0_email_template.welcome_email[0]
}

moved {
  from = auth0_email_template.reset_email
  to   = auth0_email_template.reset_email[0]
}
