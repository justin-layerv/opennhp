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
# Note: If client_secret is empty in state, remove this resource from state and re-apply:
#   terraform state rm 'module.auth0.auth0_client_credentials.backend_service'
#   terraform state rm 'module.auth0.aws_secretsmanager_secret_version.auth0_backend[0]'

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
  }
}
