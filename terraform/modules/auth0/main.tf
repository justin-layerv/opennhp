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

locals {
  # True when an SNS alert destination is actually wired. trimspace guards
  # against a whitespace-only ARN; try() handles the null default.
  sns_destination_present = try(trimspace(var.alarm_sns_topic_arn) != "", false)
}

resource "terraform_data" "sns_alerts_contract" {
  lifecycle {
    precondition {
      condition     = !var.enable_rotation || !var.enable_sns_alerts || local.sns_destination_present
      error_message = "enable_rotation=true and enable_sns_alerts=true require a non-empty alarm_sns_topic_arn. Keep rotation alarm resource counts gated on enable_sns_alerts, but wire the SNS ARN before enabling the gate."
    }
  }
}

check "sns_alerts_gate_matches_destination" {
  assert {
    condition     = !var.enable_rotation || var.enable_sns_alerts || !local.sns_destination_present
    error_message = "alarm_sns_topic_arn is set but enable_sns_alerts=false, so Auth0 rotation SNS alarms will not be created. Set enable_sns_alerts=true or clear alarm_sns_topic_arn."
  }
}

# ==============================================================================
# API Scopes
# ==============================================================================

# ==============================================================================
# Machine-to-Machine Application (for backend services)
# ==============================================================================
# Used by the developer portal playground proxy to call the QURL API on behalf
# of playground users.  Despite the legacy "backend_service" resource name, this
# client is NOT a general-purpose service account — it runs on the free tier.
# For CI/smoke tests, use the dedicated smoke_test client (system tier).

# ==============================================================================
# Backend Service - API Grant
# ==============================================================================

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
  runtime          = "nodejs22.x"
  timeout          = 120 # Allow extra time for Auth0 API latency
  filename         = data.archive_file.auth0_rotation[0].output_path
  source_code_hash = data.archive_file.auth0_rotation[0].output_base64sha256

  # Prevent race conditions - rotation should only run once at a time
  reserved_concurrent_executions = 1

  environment {
    variables = {
      AUTH0_DOMAIN                  = var.auth0_domain
      AUTH0_MANAGEMENT_SECRET_ARN   = var.auth0_management_secret_arn
      AUTH0_API_AUDIENCE            = var.api_audience
      AUTH0_CLEANUP_OLD_CREDENTIALS = var.cleanup_old_credentials ? "true" : "false"
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

# ==============================================================================
# Developer Portal Management M2M Application
# ==============================================================================
# Creates an Auth0 M2M application authorized for the Management API,
# used by the developer portal to create/manage developer credentials.
# Only created when dev_portal_mgmt_secret_name is set.

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

# ==============================================================================
# SPA Application (for website dashboard login)
# ==============================================================================
# Auth0 SPA client for the website dashboard. Uses authorization_code + PKCE
# (no client secret). Developers log in via Google/GitHub/email to manage
# API keys, view usage, and handle billing.

# ==============================================================================
# Slack OAuth Regular-Web Application (per-workspace admin-install flow)
# ==============================================================================
# Auth0 regular_web client for the qurl-bot-slack workspace-OAuth handshake.
# Workspace admin visits `https://slackbot.layerv.<xyz|ai>/oauth/qurl/start?team=…`,
# authenticates against Auth0, and the bot's `/oauth/qurl/callback` exchanges
# the authorization code for an id_token whose `sub` claim binds the workspace
# to a QURL owner identity. Per-workspace `lv_live_*` API keys are minted
# via qurl-service's `POST /v1/external-identity-bindings` and stored in the
# Slack bot's `workspace_state` DDB table.
#
# Authorization-code flow (no PKCE — server-side handler holds the client
# secret); no refresh tokens (key rotation is admin re-install, tracked as a
# medium-priority follow-up in SLACK_QURL_ROLLOUT.md L551).

# ── Passwordless email connection — qurl-bot-slack `/qurl setup` ──
# NO LONGER MANAGED BY TERRAFORM. The `email` connection
# (sandbox id con_cxZM9f9WZqXOJ6Bn) and its client enablement now live only
# in the Auth0 dashboard. The resource blocks were replaced with the `removed`
# blocks below so Terraform forgets them from state WITHOUT destroying the
# live tenant resources (lifecycle.destroy = false). The connection stays
# enabled on the qurl-bot-slack client, so the bot's `/qurl setup <email>`
# OAuth flow keeps working.
#
# Why removed: setting a connection's `options` (totp / brute_force_protection
# / name) requires the `update:connections_options` Management API scope, which
# the CI Terraform M2M token does not hold. The initial create (#2305) landed,
# but the Management API reads the options back with different values, so every
# subsequent apply tried to PATCH the read-after-create drift and failed with
# `403 Forbidden: Updating the "options" property requires the
# "update:connections_options" scope` — blocking ALL unrelated sandbox infra
# changes on every push to main. The #2309 `ignore_changes` on
# name/brute_force_protection did not cover the full readback drift, so applies
# kept failing.
#
# To re-adopt into Terraform later: grant `update:connections_options` to the
# CI M2M client on the shared tenant's Management API, delete these `removed`
# blocks, re-add the resources, and `terraform import` the live connection id.
# Leaving the `removed` blocks in place is a harmless no-op once state is clean
# (mirrors the smoke_test_customer removed block in environments/sandbox).
# Mirrors the backend_service pattern at L274-309. Same Auth0 provider
# limitation: if the management M2M lacks `read:client_keys`, the provider
# returns an empty `client_secret` and the operator must one-time copy the
# value from the Auth0 dashboard (Applications > qurl-bot-slack > Settings)
# into this secret via `aws secretsmanager put-secret-value`. After that the
# `ignore_changes = [secret_string]` lifecycle keeps subsequent applies
# from overwriting it.
resource "aws_secretsmanager_secret" "slack_oauth" {
  count                   = var.enable_slack_oauth_client ? 1 : 0
  name                    = "${var.name_prefix}-auth0-slack-oauth-credentials"
  description             = "Auth0 regular_web credentials for qurl-bot-slack workspace OAuth (${var.environment})"
  recovery_window_in_days = local.is_prod ? 30 : 0
  kms_key_id              = var.secrets_kms_key_arn

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-auth0-slack-oauth-credentials"
    Component = "auth0"
    Purpose   = "slack-workspace-oauth"
  })
}

# ==============================================================================
# Social Connections (Google + GitHub)
# ==============================================================================
# These connections enable social login for the SPA dashboard.
# The connections are created only when the SPA dashboard is enabled and
# corresponding OAuth credentials are provided.

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
  value       = var.spa_dashboard_client_id

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
  value       = var.api_audience

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

# ==============================================================================
# Attack Protection (Bot Detection, Brute Force, Breached Passwords)
# ==============================================================================
# Tenant-level singleton resource. Bot detection starts in monitoring mode
# to observe traffic before enforcing. Brute force, suspicious IP throttling,
# and breached password detection enforce immediately (low false-positive risk).
#
# Auth0 plan requirement: Bot Detection requires B2C Essentials plan or higher.
# Breached Password Detection requires a higher-tier subscription — not available on current plan.

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

# The `terraform_data.email_provider_trigger` that lived here existed only to
# force `auth0_email_provider.ses` to be re-created, because the provider could
# not read the SMTP credentials back to detect drift. With the email provider
# retired (see removed.tf) the trigger has nothing to trigger, so it is deleted
# rather than left as dead config. It is a `terraform_data` — destroying it is a
# state-only operation that touches no infrastructure.
#
# Rotating this IAM access key now requires re-entering it in the Auth0
# dashboard (Branding > Email Provider); Terraform can no longer push the new
# value. That handoff is called out in the #3284 rollout-ledger entry.

# ==============================================================================
# State Migration: manage_tenant_resources count addition
# ==============================================================================
# These moved blocks handle the migration from non-indexed to indexed resources
# when `count` was added for the manage_tenant_resources pattern.

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
