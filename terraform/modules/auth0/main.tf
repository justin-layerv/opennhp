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

  # Enforce policies
  enforce_policies = true

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
}

# ==============================================================================
# Machine-to-Machine Application (for backend services)
# ==============================================================================
# For service-to-service communication (e.g., QURL internal API calls)

resource "auth0_client" "backend_service" {
  name        = "Backend Service (${var.environment})"
  description = "M2M client for backend services - ${var.environment}"
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
  scopes    = ["qurl:read", "qurl:write", "qurl:admin"]
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
  name                    = "${var.name_prefix}-auth0-backend-credentials"
  description             = "Auth0 M2M client credentials for backend service (${var.environment})"
  recovery_window_in_days = local.is_prod ? 30 : 0
  kms_key_id              = var.secrets_kms_key_arn

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-auth0-backend-credentials"
    Component = "auth0"
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
  scopes    = ["qurl:read", "qurl:write", "qurl:admin"]
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
  count                = var.enable_spa_dashboard && var.google_oauth_client_id != null ? 1 : 0
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
  count         = var.enable_spa_dashboard && var.google_oauth_client_id != null ? 1 : 0
  connection_id = auth0_connection.google[0].id
  enabled_clients = [
    auth0_client.spa_dashboard[0].id,
  ]
}

resource "auth0_connection" "github" {
  count                = var.enable_spa_dashboard && var.github_oauth_client_id != null ? 1 : 0
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
  count         = var.enable_spa_dashboard && var.github_oauth_client_id != null ? 1 : 0
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
