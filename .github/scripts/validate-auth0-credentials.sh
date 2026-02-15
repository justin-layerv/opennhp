#!/bin/bash
# Validate Auth0 credentials match the tenant configured in terraform.tfvars.
#
# Attempts a Management API token exchange to verify that GitHub secrets
# (AUTH0_CLIENT_ID / AUTH0_CLIENT_SECRET) can authenticate against the
# auth0_domain specified in terraform.tfvars. Fails fast with a clear error
# if the secrets don't match the tenant.
#
# Usage: validate-auth0-credentials.sh <tfvars-path> [environment-label]
#
# Environment variables (required):
#   AUTH0_CLIENT_ID     - M2M client ID
#   AUTH0_CLIENT_SECRET - M2M client secret
#
# Example:
#   AUTH0_CLIENT_ID=xxx AUTH0_CLIENT_SECRET=yyy \
#     ./validate-auth0-credentials.sh terraform/environments/sandbox/terraform.tfvars sandbox

set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <tfvars-path> [environment-label]"
  exit 1
fi

TFVARS_PATH="$1"
ENV_LABEL="${2:-unknown}"

if [[ -z "${AUTH0_CLIENT_ID:-}" || -z "${AUTH0_CLIENT_SECRET:-}" ]]; then
  echo "::error::AUTH0_CLIENT_ID and AUTH0_CLIENT_SECRET must be set"
  exit 1
fi

# Read auth0_domain from tfvars (strip \r for CRLF line endings)
AUTH0_DOMAIN=$(grep -E '^auth0_domain\s*=' "$TFVARS_PATH" | sed 's/.*=\s*"\(.*\)"/\1/' | tr -d '\r')
if [[ -z "$AUTH0_DOMAIN" ]]; then
  echo "::error::Could not read auth0_domain from $TFVARS_PATH"
  exit 1
fi
echo "Validating Auth0 credentials for ${ENV_LABEL} against tenant: $AUTH0_DOMAIN"

# Attempt Management API token exchange
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 \
  --url "https://${AUTH0_DOMAIN}/oauth/token" \
  --header "content-type: application/json" \
  --data "{\"client_id\":\"${AUTH0_CLIENT_ID}\",\"client_secret\":\"${AUTH0_CLIENT_SECRET}\",\"audience\":\"https://${AUTH0_DOMAIN}/api/v2/\",\"grant_type\":\"client_credentials\"}")

if [[ "$HTTP_CODE" -ge 200 && "$HTTP_CODE" -lt 300 ]]; then
  echo "Auth0 credentials validated for ${ENV_LABEL} tenant: $AUTH0_DOMAIN (HTTP ${HTTP_CODE})"
else
  echo "::error::Auth0 credential validation failed for ${ENV_LABEL} (HTTP ${HTTP_CODE}). The GitHub secrets may not match the configured tenant '${AUTH0_DOMAIN}'. Update secrets before merging."
  exit 1
fi
