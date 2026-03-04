#!/bin/bash
# Fetch an Auth0 Management API token via client_credentials grant.
# Outputs the token as a masked GitHub Actions step output for reuse
# across multiple terraform plan/apply steps without additional M2M token consumption.
#
# The token is short-lived (Auth0 default: 24h) but only needs to survive a single
# CI job (minutes). If token caching is ever extended across workflow runs, add
# expiration checking via the "expires_in" field in the token response.
#
# Usage: fetch-auth0-token.sh <tfvars-path> [environment-label]
#
# Environment variables (required):
#   AUTH0_CLIENT_ID     - M2M client ID
#   AUTH0_CLIENT_SECRET - M2M client secret
#
# Outputs (GitHub Actions):
#   auth0_token - The fetched Management API access token (masked)
#
# Example:
#   AUTH0_CLIENT_ID=xxx AUTH0_CLIENT_SECRET=yyy \
#     ./fetch-auth0-token.sh terraform/environments/sandbox/terraform.tfvars sandbox

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

# Fetch token — capture response body AND HTTP status to provide actionable errors
HTTP_CODE=0
RESPONSE=$(curl -s -w "\n%{http_code}" --max-time 10 \
  --url "https://${AUTH0_DOMAIN}/oauth/token" \
  --header "content-type: application/json" \
  --data "{\"client_id\":\"${AUTH0_CLIENT_ID}\",\"client_secret\":\"${AUTH0_CLIENT_SECRET}\",\"audience\":\"https://${AUTH0_DOMAIN}/api/v2/\",\"grant_type\":\"client_credentials\"}") || true

# Split response body and HTTP status code
HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | sed '$d')

if [[ "$HTTP_CODE" -lt 200 || "$HTTP_CODE" -ge 300 ]]; then
  AUTH0_ERROR=$(echo "$BODY" | jq -r '.error // "unknown"' 2>/dev/null || echo "unknown")
  AUTH0_DESC=$(echo "$BODY" | jq -r '.error_description // "no details"' 2>/dev/null || echo "no details")
  echo "::error::Auth0 token fetch failed for ${ENV_LABEL} (HTTP ${HTTP_CODE}): ${AUTH0_ERROR} — ${AUTH0_DESC}"
  exit 1
fi

TOKEN=$(echo "$BODY" | jq -r '.access_token')
if [ -z "$TOKEN" ] || [ "$TOKEN" = "null" ]; then
  echo "::error::Auth0 returned success but no access_token for ${ENV_LABEL}. Response: $(echo "$BODY" | jq -c '.' 2>/dev/null || echo "$BODY")"
  exit 1
fi

echo "Auth0 token fetched for ${ENV_LABEL} (${AUTH0_DOMAIN})"
echo "::add-mask::${TOKEN}"
echo "auth0_token=${TOKEN}" >> "$GITHUB_OUTPUT"
