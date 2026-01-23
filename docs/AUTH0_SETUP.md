# Auth0 Setup Guide for QURL Service

This guide walks through setting up Auth0 authentication for the QURL API service. It's intended for engineers with no prior Auth0 experience.

## Table of Contents

1. [Background](#background)
2. [Architecture Overview](#architecture-overview)
3. [Prerequisites](#prerequisites)
4. [Auth0 Account Setup](#auth0-account-setup)
5. [Create the API](#create-the-api)
6. [Create an Application](#create-an-application)
7. [Configure Permissions](#configure-permissions)
8. [Terraform Configuration](#terraform-configuration)
9. [Testing the Integration](#testing-the-integration)
10. [Troubleshooting](#troubleshooting)
11. [Security Considerations](#security-considerations)

---

## Background

### What is Auth0?

Auth0 is an Identity-as-a-Service (IDaaS) platform that handles authentication and authorization. Instead of building our own user authentication system, we delegate that responsibility to Auth0, which provides:

- User authentication (login/signup)
- JWT (JSON Web Token) issuance
- Public key infrastructure for token verification
- Social login integrations (Google, GitHub, etc.)
- Multi-factor authentication
- User management dashboard

### Why Auth0 for QURL?

The QURL service is a multi-tenant API where different customers (identified by `owner_id`) manage their own resources. We need to:

1. **Authenticate** - Verify that API requests come from legitimate users
2. **Identify** - Know which customer is making the request (for resource isolation)
3. **Authorize** - Ensure users have permission for the requested operation

Auth0 handles all of this by issuing signed JWT tokens that contain the user's identity and permissions.

### What is a JWT?

A JWT (JSON Web Token) is a signed, base64-encoded JSON object. It looks like:

```
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.Signature
```

It has three parts separated by dots:
1. **Header** - Algorithm and token type
2. **Payload** - Claims (user data, permissions, expiry)
3. **Signature** - Cryptographic signature proving authenticity

Auth0 signs tokens with a private key. QURL verifies them using Auth0's public key (fetched from the JWKS endpoint).

### What is JWKS?

JWKS (JSON Web Key Set) is a JSON document containing Auth0's public keys. QURL fetches this from:

```
https://{your-tenant}.us.auth0.com/.well-known/jwks.json
```

This allows QURL to verify JWT signatures without needing Auth0's private key.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Authentication Flow                             │
└─────────────────────────────────────────────────────────────────────────────┘

  ┌──────────┐         ┌──────────┐         ┌──────────┐         ┌──────────┐
  │  Client  │         │  Auth0   │         │  QURL    │         │ DynamoDB │
  │  (App)   │         │  Tenant  │         │  Service │         │          │
  └────┬─────┘         └────┬─────┘         └────┬─────┘         └────┬─────┘
       │                    │                    │                    │
       │  1. Login Request  │                    │                    │
       │───────────────────>│                    │                    │
       │                    │                    │                    │
       │  2. JWT Token      │                    │                    │
       │<───────────────────│                    │                    │
       │                    │                    │                    │
       │  3. API Request + JWT (Authorization: Bearer <token>)       │
       │─────────────────────────────────────────>                   │
       │                    │                    │                    │
       │                    │  4. Fetch JWKS     │                    │
       │                    │    (cached)        │                    │
       │                    │<───────────────────│                    │
       │                    │                    │                    │
       │                    │  5. Public Keys    │                    │
       │                    │───────────────────>│                    │
       │                    │                    │                    │
       │                    │      6. Verify JWT signature            │
       │                    │         Extract owner_id (sub claim)    │
       │                    │         Check permissions               │
       │                    │                    │                    │
       │                    │                    │  7. Query with     │
       │                    │                    │     owner_id       │
       │                    │                    │───────────────────>│
       │                    │                    │                    │
       │                    │                    │  8. Results        │
       │                    │                    │<───────────────────│
       │                    │                    │                    │
       │  9. API Response                        │                    │
       │<────────────────────────────────────────│                    │
       │                    │                    │                    │
```

### Key Components

| Component | Role |
|-----------|------|
| **Auth0 Tenant** | Manages users, issues JWTs, hosts JWKS |
| **Auth0 API** | Represents the QURL service in Auth0 (defines audience and permissions) |
| **Auth0 Application** | Represents the client app (Console, CLI, etc.) |
| **QURL Service** | Validates JWTs, enforces permissions, serves API requests |
| **JWT Token** | Contains user identity (`sub`), permissions (`scope`), expiry (`exp`) |

---

## Prerequisites

Before starting, ensure you have:

- [ ] Access to create an Auth0 account (or existing Auth0 tenant credentials)
- [ ] Access to the nhp terraform configuration
- [ ] AWS credentials for the target environment (sandbox/production)
- [ ] Understanding of which environment you're configuring

---

## Auth0 Account Setup

### Step 1: Create Auth0 Account

1. Go to [https://auth0.com/signup](https://auth0.com/signup)
2. Sign up with your work email
3. Choose a tenant name (e.g., `layerv` or `layerv-dev`)
4. Select your region (US recommended for lower latency to us-east-2)

Your tenant domain will be: `{tenant-name}.us.auth0.com`

### Step 2: Note Your Tenant Domain

After signup, note your full tenant domain. It will look like:

```
layerv.us.auth0.com
```

This is your `AUTH0_DOMAIN` value.

---

## Create the API

An "API" in Auth0 represents a backend service that will accept tokens. QURL needs one.

### Step 1: Navigate to APIs

1. In Auth0 Dashboard, go to **Applications > APIs**
2. Click **+ Create API**

### Step 2: Configure the API

| Field | Value | Notes |
|-------|-------|-------|
| **Name** | `QURL API` | Display name (can be anything) |
| **Identifier** | `https://api.qurl.link` | This becomes your `AUTH0_AUDIENCE`. Use a URL format but it doesn't need to be a real endpoint. |
| **Signing Algorithm** | `RS256` | **Must be RS256** - QURL only supports RSA signatures |

Click **Create**.

### Step 3: Note the Identifier

The identifier you just set is your `AUTH0_AUDIENCE`:

```
https://api.qurl.link
```

---

## Create an Application

An "Application" in Auth0 represents a client that will request tokens. You need at least one for testing.

### Step 1: Navigate to Applications

1. Go to **Applications > Applications**
2. Click **+ Create Application**

### Step 2: Create Machine-to-Machine Application (for service-to-service)

| Field | Value |
|-------|-------|
| **Name** | `QURL Service Client` |
| **Type** | `Machine to Machine Applications` |

Click **Create**.

### Step 3: Authorize the Application

1. After creation, you'll be asked to authorize APIs
2. Select **QURL API** (the API you created earlier)
3. Select all permissions (we'll create these next)
4. Click **Authorize**

### Step 4: Note the Credentials

Go to the **Settings** tab and note:

| Field | Purpose |
|-------|---------|
| **Domain** | Same as tenant domain |
| **Client ID** | Used by clients to identify themselves |
| **Client Secret** | Used by clients to authenticate (keep secret!) |

---

## Configure Permissions

Permissions (also called "scopes") control what actions a token holder can perform.

### Step 1: Define Permissions

1. Go to **Applications > APIs > QURL API**
2. Click the **Permissions** tab
3. Add these permissions:

| Permission | Description |
|------------|-------------|
| `qurl:read` | Read QURL resources (list, get, quota) |
| `qurl:write` | Create, update, delete QURL resources |

### Step 2: Enable RBAC (Optional but Recommended)

1. Go to the **Settings** tab of your API
2. Scroll to **RBAC Settings**
3. Enable **Enable RBAC**
4. Enable **Add Permissions in the Access Token**

This ensures permissions appear in the token's `permissions` claim.

---

## Terraform Configuration

Now configure the QURL service to use your Auth0 tenant.

### Step 1: Locate terraform.tfvars

For sandbox:
```
terraform/environments/sandbox/terraform.tfvars
```

### Step 2: Add Auth0 Configuration

Find the QURL Service Configuration section and add:

```hcl
# ==============================================================================
# QURL Service - Auth0 Configuration
# ==============================================================================

# Auth0 tenant domain (without https://)
# Example: layerv.us.auth0.com
qurl_auth0_domain = "layerv.us.auth0.com"

# Auth0 API identifier (the "audience" claim in JWTs)
# Must match the Identifier you set when creating the API in Auth0
qurl_auth0_audience = "https://api.qurl.link"

# JWKS caching configuration
# JWKS = JSON Web Key Set - Auth0's public keys for verifying tokens
# These are fetched from: https://{domain}/.well-known/jwks.json

# How long to cache JWKS (seconds). Auth0 rotates keys infrequently,
# so 1 hour (3600) is safe and reduces Auth0 API calls.
qurl_auth0_jwks_cache_ttl_seconds = 3600

# Timeout for fetching JWKS from Auth0 (seconds).
# Should be short - if Auth0 is slow, fail fast.
qurl_auth0_jwks_fetch_timeout_seconds = 10
```

### Step 3: Apply Terraform

```bash
cd terraform/environments/sandbox
AWS_PROFILE=layerv terraform plan
AWS_PROFILE=layerv terraform apply
```

### Environment Variables Set by Terraform

Terraform sets these environment variables in the QURL ECS task:

| Environment Variable | Terraform Variable | Description |
|---------------------|-------------------|-------------|
| `AUTH0_DOMAIN` | `qurl_auth0_domain` | Auth0 tenant domain |
| `AUTH0_AUDIENCE` | `qurl_auth0_audience` | Expected JWT audience |
| `AUTH0_JWKS_CACHE_TTL` | `qurl_auth0_jwks_cache_ttl_seconds` | JWKS cache duration |
| `AUTH0_JWKS_FETCH_TIMEOUT` | `qurl_auth0_jwks_fetch_timeout_seconds` | JWKS fetch timeout |

---

## Testing the Integration

### Step 1: Get a Test Token

Use Auth0's token endpoint to get a machine-to-machine token:

```bash
curl --request POST \
  --url 'https://layerv.us.auth0.com/oauth/token' \
  --header 'content-type: application/json' \
  --data '{
    "client_id": "YOUR_CLIENT_ID",
    "client_secret": "YOUR_CLIENT_SECRET",
    "audience": "https://api.qurl.link",
    "grant_type": "client_credentials"
  }'
```

Response:
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Ijk4ZDM...",
  "token_type": "Bearer",
  "expires_in": 86400
}
```

### Step 2: Decode the Token (Optional)

Visit [https://jwt.io](https://jwt.io) and paste your token to inspect its contents:

```json
{
  "iss": "https://layerv.us.auth0.com/",
  "sub": "abc123@clients",
  "aud": "https://api.qurl.link",
  "iat": 1705900000,
  "exp": 1705986400,
  "scope": "qurl:read qurl:write",
  "permissions": ["qurl:read", "qurl:write"]
}
```

Key claims:
- `iss` - Issuer (must match your Auth0 domain)
- `sub` - Subject (becomes `owner_id` in QURL)
- `aud` - Audience (must match `AUTH0_AUDIENCE`)
- `exp` - Expiry timestamp
- `scope` / `permissions` - Granted permissions

### Step 3: Call the QURL API

```bash
# Set your token
TOKEN="eyJhbGciOiJSUzI1NiIs..."

# Check quota (requires qurl:read)
curl -H "Authorization: Bearer $TOKEN" \
  https://api.qurl.link/v1/quota

# Create a QURL (requires qurl:write)
curl -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"target_url": "https://example.com", "ttl_seconds": 3600}' \
  https://api.qurl.link/v1/qurl
```

### Step 4: Verify Health Check

The QURL service includes an Auth0 health check:

```bash
curl https://api.qurl.link/health/ready
```

If Auth0 is configured correctly, you'll see:
```json
{
  "status": "ready",
  "checks": {
    "auth0": {"status": "healthy", "message": "JWKS endpoint reachable"}
  }
}
```

---

## Troubleshooting

### Error: "invalid token" or "signature verification failed"

**Causes:**
- Wrong `AUTH0_DOMAIN` configured
- Token was issued for a different audience
- Token has expired
- JWKS cache is stale (wait for TTL or restart service)

**Debug:**
1. Decode token at jwt.io
2. Verify `iss` matches `https://{AUTH0_DOMAIN}/`
3. Verify `aud` matches `AUTH0_AUDIENCE`
4. Check `exp` timestamp hasn't passed

### Error: "token audience invalid"

**Cause:** The token's `aud` claim doesn't match `AUTH0_AUDIENCE`.

**Fix:** Ensure you're requesting tokens with the correct `audience` parameter:
```bash
curl --data '{"audience": "https://api.qurl.link", ...}' ...
```

### Error: "insufficient scope"

**Cause:** Token doesn't have required permissions.

**Fix:**
1. Check token has `qurl:read` and/or `qurl:write` in `scope` or `permissions`
2. Ensure the Application is authorized for those permissions in Auth0
3. Ensure RBAC is enabled on the API

### Error: "JWKS fetch failed" or "Auth0 health check failing"

**Causes:**
- Network connectivity issue
- Wrong `AUTH0_DOMAIN`
- Auth0 is down (rare)

**Debug:**
```bash
# Test JWKS endpoint directly
curl https://layerv.us.auth0.com/.well-known/jwks.json
```

### Error: "missing required config: AUTH0_DOMAIN"

**Cause:** Environment variable not set.

**Fix:** Verify terraform applied successfully and ECS task has the environment variables.

---

## Security Considerations

### Token Storage

- **Never** log full JWT tokens (they're bearer credentials)
- **Never** store tokens in localStorage for web apps (use httpOnly cookies)
- Tokens should be short-lived (default 24 hours)

### JWKS Caching

- Cache TTL of 1 hour is safe (Auth0 rarely rotates keys)
- On key rotation, there's a brief window where old tokens fail
- Auth0 typically keeps old keys valid for overlap period

### Audience Validation

- Always validate the `aud` claim
- Prevents tokens issued for other APIs from being accepted
- QURL enforces this automatically

### Scope Enforcement

- QURL checks scopes on every request
- `qurl:read` - GET operations
- `qurl:write` - POST, PUT, DELETE operations
- Missing scope = 403 Forbidden

### Rate Limiting

- Auth0 has rate limits on token endpoints
- QURL caches JWKS to minimize Auth0 API calls
- Consider token caching in clients for high-volume scenarios

---

## Reference

### Auth0 Documentation

- [Get Access Tokens](https://auth0.com/docs/secure/tokens/access-tokens/get-access-tokens)
- [Validate JWTs](https://auth0.com/docs/secure/tokens/json-web-tokens/validate-json-web-tokens)
- [JWKS](https://auth0.com/docs/secure/tokens/json-web-tokens/json-web-key-sets)
- [API Authorization](https://auth0.com/docs/get-started/apis)

### QURL Service Code

| Component | Location |
|-----------|----------|
| JWT Validator | `qurl/pkg/auth0/validator.go` |
| JWKS Caching | `qurl/pkg/auth0/jwks.go` |
| Auth Middleware | `qurl/internal/api/middleware/auth.go` |
| Health Check | `qurl/internal/health/auth0.go` |
| Config | `qurl/internal/config/config.go` |

### Terraform Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `qurl_auth0_domain` | Yes | Auth0 tenant domain |
| `qurl_auth0_audience` | Yes | API identifier |
| `qurl_auth0_jwks_cache_ttl_seconds` | Yes | JWKS cache TTL |
| `qurl_auth0_jwks_fetch_timeout_seconds` | Yes | JWKS fetch timeout |

---

## Checklist

Before considering Auth0 setup complete:

- [ ] Auth0 tenant created
- [ ] API created with correct identifier (audience)
- [ ] Permissions defined (`qurl:read`, `qurl:write`)
- [ ] At least one Application created and authorized
- [ ] Terraform variables configured
- [ ] Terraform applied successfully
- [ ] Test token obtained and verified at jwt.io
- [ ] API call successful with test token
- [ ] Health check shows Auth0 healthy
