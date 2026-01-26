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
  description = "The backend service M2M client secret (for rotation, store in Secrets Manager)"
  value       = auth0_client_credentials.backend_service.client_secret
  sensitive   = true
}
