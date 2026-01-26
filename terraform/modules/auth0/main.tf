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

resource "auth0_client_credentials" "backend_service" {
  client_id             = auth0_client.backend_service.id
  authentication_method = "client_secret_post"
}
