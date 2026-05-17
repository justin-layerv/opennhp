# Runbook: Create a QURL via the API

**Auth0 Domain:** `https://auth.layerv.ai` (NOT the tenant domain)

**API Endpoint:** `https://api.layerv.xyz` (NOT api.qurl.link)

```bash
# 1. Get Auth0 token
AUTH0_SECRET=$(AWS_PROFILE=layerv aws secretsmanager get-secret-value \
  --secret-id "layerv-nhp-sandbox-auth0-backend-credentials" \
  --query SecretString --output text)
CLIENT_ID=$(echo "$AUTH0_SECRET" | jq -r '.client_id')
CLIENT_SECRET=$(echo "$AUTH0_SECRET" | jq -r '.client_secret')
AUDIENCE=$(echo "$AUTH0_SECRET" | jq -r '.audience')

TOKEN_RESPONSE=$(curl -s --request POST \
  --url "https://auth.layerv.ai/oauth/token" \
  --header "content-type: application/json" \
  --data "{\"client_id\":\"$CLIENT_ID\",\"client_secret\":\"$CLIENT_SECRET\",\"audience\":\"$AUDIENCE\",\"grant_type\":\"client_credentials\"}")
ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token')

# 2. Create QURL (POST /v1/qurls)
# IMPORTANT: expires_in is a DURATION STRING like "1h", "168h", NOT an integer
curl -s --request POST \
  --url "https://api.layerv.xyz/v1/qurls" \
  --header "Authorization: Bearer $ACCESS_TOKEN" \
  --header "Content-Type: application/json" \
  --data '{
    "target_url": "https://example.com",
    "expires_in": "168h",
    "max_sessions": 10,
    "description": "My QURL"
  }' | jq '.data.qurl_link'
```

**Response structure:** `{ "data": { "resource_id": "...", "qurl_link": "https://qurl.link/#at_xxx", "qurl_site": "..." } }`
