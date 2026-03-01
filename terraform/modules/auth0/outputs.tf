# Auth0 module outputs

output "api_identifier" {
  description = "The Auth0 API identifier (audience)"
  value       = auth0_resource_server.qurl_api.identifier
}

output "backend_service_client_id" {
  description = "The backend service M2M client ID"
  value       = auth0_client.backend_service.client_id
}

output "backend_service_client_secret" {
  description = "The backend service M2M client secret (stored in Secrets Manager)"
  value       = auth0_client_credentials.backend_service.client_secret
  sensitive   = true
}

output "backend_credentials_secret_arn" {
  description = "ARN of the Secrets Manager secret containing Auth0 backend credentials"
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

output "dev_portal_mgmt_secret_name" {
  description = "Name of the SM secret containing developer portal management credentials (null if not created)"
  value       = var.dev_portal_mgmt_secret_name != null ? aws_secretsmanager_secret.dev_portal_mgmt[0].name : null
}

output "dev_portal_mgmt_secret_arn" {
  description = "ARN of the SM secret containing developer portal management credentials (null if not created)"
  value       = var.dev_portal_mgmt_secret_name != null ? aws_secretsmanager_secret.dev_portal_mgmt[0].arn : null
}

# SPA Dashboard outputs
output "spa_dashboard_client_id" {
  description = "Auth0 SPA dashboard client ID (for NEXT_PUBLIC_AUTH0_CLIENT_ID)"
  value       = var.enable_spa_dashboard ? auth0_client.spa_dashboard[0].client_id : null
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
  value       = auth0_resource_server.qurl_api.identifier
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
