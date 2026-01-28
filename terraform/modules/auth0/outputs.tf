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
