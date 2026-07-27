# Auth0 module outputs

output "api_identifier" {
  description = "The Auth0 API identifier (audience)"
  value       = var.api_audience
}

output "backend_service_client_id" {
  description = "Website playground M2M client ID (legacy name: 'backend_service')"
  value       = var.backend_service_client_id
}

output "backend_credentials_secret_arn" {
  description = "ARN of Secrets Manager secret for website playground proxy (legacy name: 'backend')"
  value       = aws_secretsmanager_secret.auth0_backend.arn
}

output "rotation_lambda_arn" {
  description = "ARN of the Auth0 secret rotation Lambda function (null if rotation disabled)"
  value       = var.enable_rotation ? aws_lambda_function.auth0_rotation[0].arn : null
}

output "rotation_enabled" {
  description = "Whether secret rotation is enabled"
  value       = var.enable_rotation
}

# Rotation alarm outputs
output "rotation_alarm_arns" {
  description = "ARNs of CloudWatch alarms for Auth0 secret rotation (empty list if rotation or alarms disabled)"
  value = var.enable_rotation && var.enable_sns_alerts ? [
    aws_cloudwatch_metric_alarm.rotation_lambda_errors[0].arn,
    aws_cloudwatch_metric_alarm.rotation_lambda_duration[0].arn,
    aws_cloudwatch_metric_alarm.rotation_overdue[0].arn,
    aws_cloudwatch_metric_alarm.rotation_lambda_throttles[0].arn,
  ] : []
}

output "dev_portal_mgmt_secret_name" {
  description = "Name of the SM secret containing developer portal management credentials (null if not created)"
  value       = var.dev_portal_mgmt_secret_name != null ? aws_secretsmanager_secret.dev_portal_mgmt[0].name : null
}

output "dev_portal_mgmt_secret_arn" {
  description = "ARN of the SM secret containing developer portal management credentials (null if not created)"
  value       = var.dev_portal_mgmt_secret_name != null ? aws_secretsmanager_secret.dev_portal_mgmt[0].arn : null
}

# Smoke Test outputs
output "smoke_test_client_id" {
  description = "Auth0 smoke test M2M client ID (null if not enabled)"
  value       = var.enable_smoke_test_client ? var.smoke_test_client_id : null
}

output "smoke_test_credentials_secret_arn" {
  description = "ARN of Secrets Manager secret for smoke test credentials (null if not enabled)"
  value       = var.enable_smoke_test_client ? aws_secretsmanager_secret.smoke_test[0].arn : null
}

output "smoke_test_credentials_secret_name" {
  description = "Name of Secrets Manager secret for smoke test credentials (null if not enabled)"
  value       = var.enable_smoke_test_client ? aws_secretsmanager_secret.smoke_test[0].name : null
}

# SPA Dashboard outputs
output "spa_dashboard_client_id" {
  description = "Auth0 SPA dashboard client ID (for NEXT_PUBLIC_AUTH0_CLIENT_ID)"
  value       = var.enable_spa_dashboard ? var.spa_dashboard_client_id : null
}

output "spa_dashboard_enabled" {
  description = "Whether the SPA dashboard Auth0 client is enabled"
  value       = var.enable_spa_dashboard
}

output "auth0_domain" {
  description = "Auth0 domain for frontend configuration (NEXT_PUBLIC_AUTH0_DOMAIN). Returns custom domain if set, otherwise tenant domain."
  value       = var.auth0_custom_domain != null ? var.auth0_custom_domain : var.auth0_tenant_domain
}

output "api_audience" {
  description = "Auth0 API audience for frontend configuration (NEXT_PUBLIC_AUTH0_AUDIENCE)"
  value       = var.api_audience
}

# SSM parameter ARNs (for cross-stack references / IAM policies)
output "spa_client_id_ssm_arn" {
  description = "ARN of the SSM parameter containing the SPA client ID"
  value       = var.enable_spa_dashboard ? aws_ssm_parameter.spa_client_id[0].arn : null
}

output "spa_auth0_domain_ssm_arn" {
  description = "ARN of the SSM parameter containing the Auth0 domain"
  value       = var.enable_spa_dashboard ? aws_ssm_parameter.spa_auth0_domain[0].arn : null
}

output "spa_api_audience_ssm_arn" {
  description = "ARN of the SSM parameter containing the API audience"
  value       = var.enable_spa_dashboard ? aws_ssm_parameter.spa_api_audience[0].arn : null
}

# Slack OAuth outputs (qurl-bot-slack workspace-install client)
output "slack_oauth_client_id" {
  description = "Auth0 regular_web client ID for qurl-bot-slack workspace OAuth (null if not enabled)"
  value       = var.enable_slack_oauth_client ? var.slack_oauth_client_id : null
}

output "slack_oauth_credentials_secret_arn" {
  description = <<-EOT
    ARN of the Secrets Manager secret holding {client_id, client_secret,
    audience, domain} for the Slack OAuth client (null if not enabled).

    **Not consumed cross-account.** Per the 2026-05-13 architectural
    update in `SLACK_QURL_ROLLOUT.md`, qurl-bot-slack runs in a different
    AWS account from this module (sandbox: 730883236711 vs 767397897469;
    prod: TBD), and Justin's "in-account only — no cross-account
    principals" rule (`modules/qurl-slack-ddb/main.tf:149` review on
    qurl-integrations-infra #523) applies here too. The consumer
    instead creates its OWN in-account secret in qurl-integrations-infra
    (`qurl-bot-slack/<env>/auth0`, mirroring `qurl-bot-discord`'s
    `var.auth0_secret_arn` pattern — see qurl-integrations-infra #565).

    Terraform manages the secret CONTAINER only. Since #3284 retired the
    Auth0 provider, the version is written entirely by the operator: read
    the client secret from the Auth0 dashboard (Applications >
    qurl-bot-slack > Settings) and `aws secretsmanager put-secret-value`
    it into BOTH this secret AND qurl-integrations-infra's local secret.
    The ARN is exported so the operator can resolve it via
    `terraform output -raw slack_oauth_credentials_secret_arn`.
  EOT
  value       = var.enable_slack_oauth_client ? aws_secretsmanager_secret.slack_oauth[0].arn : null
}

output "slack_oauth_credentials_secret_name" {
  description = "Name of the Secrets Manager secret holding Slack OAuth credentials (null if not enabled). Stable across recreates; safe for `data.aws_secretsmanager_secret` lookups in consumer stacks that don't have cross-stack `terraform_remote_state` wired up."
  value       = var.enable_slack_oauth_client ? aws_secretsmanager_secret.slack_oauth[0].name : null
}
