# LayerV NHP System Architecture

## Overview

LayerV implements a Network Hiding Protocol (NHP) system based on the Cloud Security Alliance's OpenNHP standard. The system makes protected resources invisible to unauthorized users while providing authenticated access through cryptographic "knocking."

## Repository Structure

LayerV spans multiple repositories, each with a specific role:

| Repository | Purpose | Key Components |
|------------|---------|----------------|
| `nhp` | Core NHP infrastructure | AC, Server, Terraform, CI/CD |
| `console` | Management UI & API | Portal Sites API, User management |
| `website` | Marketing site | Demo UI (CloakDemo component) |
| `demo` | Demo applications | OIDC demo, login page |
| `nhp-plugins-passcode` | Passcode auth plugin | URL validation, token generation |
| `nhp-plugins-oidc` | OIDC auth plugin | Okta integration |
| `traefik-plugins` | Traefik middleware | NHP token validation |
| `StealthDNS` | DNS-level protection | (separate system) |

## Core Components

### 1. NHP Server (`nhp/endpoints/server/`)

The NHP Server receives knock requests and coordinates with ACs to grant access.

**Key Responsibilities:**
- Receives UDP knock packets on port 62206 (via NLB)
- Receives HTTP knock requests on port 443 (via Traefik)
- Loads and manages authentication plugins
- Communicates with AC instances to open firewall rules
- Manages etcd-based configuration

**Key Files:**
- `main.go` - Entry point
- `udpserver.go` - UDP knock handler
- `httpserver.go` - HTTP knock handler, plugin routing
- `config.go` - Configuration loading
- `plugins.go` - Plugin management

**HTTP Routes:**
```
GET /plugins/:aspid          - Plugin entry point (displays login or processes auth)
GET /plugins/:aspid/:resid/valid - Legacy validation endpoint
```

### 2. NHP AC (Access Controller) (`nhp/endpoints/ac/`)

The AC runs on protected servers and manages iptables/ipset rules.

**Key Responsibilities:**
- Dials OUT to NHP Server (server doesn't connect to AC)
- Receives AC operation requests from Server
- Manages iptables/ipset rules to grant/revoke access
- Handles HTTP refresh requests for IP address updates
- Monitors etcd for configuration changes

**Key Files:**
- `main.go` - Entry point
- `udpac.go` - UDP communication with server
- `httpac.go` - HTTP refresh endpoint
- `iptables.go` - Firewall rule management
- `config.go` - Configuration loading

**HTTP Routes:**
```
GET /refresh/:token?srcip=X.X.X.X - Refresh access for new IP
```

### 3. Console API (`console/server/`)

The Console provides the management API and Portal Sites functionality.

**Key Responsibilities:**
- User and organization management
- Portal Sites CRUD operations
- `createPortalSitesByURL` - Public API for website demo
- Resource and policy management

**Key API Endpoints:**
```
POST /api/ps/createPortalSitesByURL  - Create portal site from URL (public)
POST /api/ps/createPortalSites       - Create portal site (authenticated)
GET  /api/ps/findPortalSites         - Get portal site by ID
GET  /api/ps/findSiteByApplicationId - Get site by app ID
```

**Portal Sites Response:**
```json
{
  "code": 0,
  "data": {
    "appId": "abc123def",
    "passcode": "secret123"
  }
}
```

### 4. Passcode Plugin (`nhp-plugins-passcode/`)

Handles passcode-based authentication for the demo flow.

**Authentication Actions:**
| Action | Description |
|--------|-------------|
| `valid` | Validate passcode, open resource |
| `login` | Display login page |
| `refresh` | Refresh existing token |
| `knock` | Knock by existing token |
| `access` | RaaS IAM integration |
| `auth_code` | OAuth code exchange |
| `hmac_auth` | HMAC signature auth |

**Flow:**
```
1. User visits qurl.link/{appId}?passcode={passcode}
2. Plugin validates passcode against config or API
3. On success, calls Server to request AC operation
4. AC opens iptables for user's source IP
5. User gets nhp_token cookie and redirect to resource
```

### 5. Traefik Integration

Traefik acts as the reverse proxy with NHP middleware.

**Configuration:**
- `docker/traefik/` - Container configuration
- `nhp/ac/config/traefik/` - Traefik dynamic config

**NHP Middleware:**
- Validates `nhp-token` cookie
- Blocks unauthenticated requests to protected resources
- Calls AC `/refresh` endpoint when needed

## Domain Architecture

### Production Domains

| Domain | Purpose | Backend |
|--------|---------|---------|
| `home.secure.layerv.xyz` | Console API | Console server on AC |
| `qurl.link` | Login portal | NHP Server → passcode plugin |
| `*.qurl.site` | Protected resources | Traefik → upstream via AC rules |
| `oa.secure.layerv.ai` | OIDC plugin endpoint | NHP Server → okta plugin |
| `demo-login.secure.layerv.xyz` | Okta demo login | Static HTML on AC |

### DNS Flow

```
qurl.link → NLB (us-east-2) → NHP Server (HTTP 443)
                            → NHP Server (UDP 62206)

*.qurl.site → NLB → Traefik on AC → Protected Resource
```

## Authentication Flows

### Flow 1: Website Demo (URL Cloaking)

```
┌─────────────┐     POST /api/ps/createPortalSitesByURL     ┌─────────────┐
│   Website   │ ─────────────────────────────────────────→ │   Console   │
│  (layerv.ai)│                                             │    API      │
└─────────────┘                                             └─────────────┘
       │                                                           │
       │ Returns: { appId, passcode }                              │
       ▼                                                           │
┌─────────────┐                                                    │
│    User     │                                                    │
│   Browser   │                                                    │
└─────────────┘                                                    │
       │                                                           │
       │ GET qurl.link/{appId}?passcode={passcode}                 │
       ▼                                                           ▼
┌─────────────┐     Validate passcode     ┌─────────────┐   Resource
│ NHP Server  │ ◄──────────────────────── │  Passcode   │   Config
│             │                           │   Plugin    │
└─────────────┘                           └─────────────┘
       │
       │ AC Operation Request (via UDP)
       ▼
┌─────────────┐     iptables: allow {srcIp}     ┌─────────────┐
│   NHP AC    │ ──────────────────────────────→ │  Protected  │
│             │                                  │  Resource   │
└─────────────┘                                  └─────────────┘
       │
       │ Returns: { ResourceHost, ACToken }
       ▼
┌─────────────┐
│   User      │  Set-Cookie: nhp_token
│   Browser   │  Redirect: https://{appId}.qurl.site/
└─────────────┘
       │
       │ GET https://{appId}.qurl.site/
       ▼
┌─────────────┐     Check nhp_token     ┌─────────────┐
│   Traefik   │ ───────────────────────→│   NHP AC    │
│             │                          │  (refresh)  │
└─────────────┘                          └─────────────┘
       │
       │ Proxy to upstream (iptables allows)
       ▼
┌─────────────┐
│  Protected  │
│  Resource   │
└─────────────┘
```

### Flow 2: Okta OIDC Demo

```
┌─────────────┐     Visit demo-login.secure.layerv.xyz     ┌─────────────┐
│    User     │ ─────────────────────────────────────────→ │ Demo Login  │
│   Browser   │                                             │    Page     │
└─────────────┘                                             └─────────────┘
       │
       │ Click "Login with Okta"
       │ GET oa.secure.layerv.ai/plugins/oktaoidc?resid=demo-app&action=oauth
       ▼
┌─────────────┐                                   ┌─────────────┐
│ NHP Server  │ ── Initialize Authenticator ───→ │  Okta OIDC  │
│             │                                   │   Plugin    │
└─────────────┘                                   └─────────────┘
       │
       │ Redirect to Okta authorization URL
       ▼
┌─────────────┐     OAuth Authorization     ┌─────────────┐
│    Okta     │ ◄─────────────────────────→ │    User     │
│             │                              │   Browser   │
└─────────────┘                              └─────────────┘
       │
       │ Callback with authorization code
       ▼
┌─────────────┐     Exchange code for token     ┌─────────────┐
│ NHP Server  │ ──────────────────────────────→ │    Okta     │
│             │                                  │             │
└─────────────┘                                  └─────────────┘
       │
       │ Verify ID token, extract user info
       │ Request AC operation
       ▼
┌─────────────┐
│   NHP AC    │  Open iptables for srcIp
└─────────────┘
       │
       │ Set-Cookie: nhp-token
       │ Redirect to protected resource
       ▼
┌─────────────┐
│  Protected  │
│  Resource   │
└─────────────┘
```

## Infrastructure (AWS)

### Sandbox Environment

| Resource | Value |
|----------|-------|
| AWS Account | 767397897469 |
| Region | us-east-2 |
| NLB | layerv-nhp-sandbox-ac-nlb-*.elb.us-east-2.amazonaws.com |
| ASG (Server) | layerv-nhp-sandbox-server-asg |
| ASG (AC) | layerv-nhp-sandbox-ac-asg |
| etcd | etcd.nhp.sandbox.internal:2379 |

### Network Architecture

```
                    Internet
                        │
                        ▼
┌─────────────────────────────────────────────────────────────┐
│                        NLB                                   │
│   UDP 62206 → NHP Server    TCP 443 → Traefik on AC         │
└─────────────────────────────────────────────────────────────┘
                        │
           ┌────────────┴────────────┐
           │                         │
           ▼                         ▼
┌─────────────────┐       ┌─────────────────┐
│   NHP Server    │       │     NHP AC      │
│   EC2 (ASG)     │       │   EC2 (ASG)     │
│                 │       │                 │
│ - UDP listener  │◄─────►│ - Dial to server│
│ - HTTP plugins  │       │ - iptables mgmt │
│ - etcd client   │       │ - Traefik       │
└─────────────────┘       │ - Console API   │
                          └─────────────────┘
                                  │
                                  ▼
                          ┌─────────────────┐
                          │   etcd Cluster  │
                          │   (internal)    │
                          └─────────────────┘
```

## Configuration Management

### etcd Keys

```
/nhp/config/server/base      - Server base configuration
/nhp/config/server/peers     - AC peer configurations
/nhp/config/server/http      - HTTP server configuration
/nhp/config/ac/{acId}/base   - AC base configuration
/nhp/registry/ac/{acId}      - AC registration entries
```

### Secrets Manager

| Secret | Purpose |
|--------|---------|
| `nhp/sandbox/server-private-key` | NHP Server private key |
| `nhp/sandbox/ac-private-key` | NHP AC private key |
| `nhp/etcd/ca-cert` | etcd CA certificate |
| `nhp/etcd/client-cert` | etcd client certificate |
| `nhp/etcd/client-key` | etcd client key |

## Testing Strategy

### Unit Tests (Currently Running in CI)

- `endpoints/ac/config_test.go` - AC configuration loading
- `endpoints/server/config_test.go` - Server configuration loading
- `nhp/**/*_test.go` - Core NHP library tests

### Integration Tests (Need to Run in CI)

Located in `tests/integration/deployment_test.go`:
- `TestEtcd_Connection` - Verify etcd connectivity
- `TestEtcd_NHPConfigExists` - Verify config keys exist
- `TestEtcd_ACRegistry` - Verify AC registration
- `TestNHPServer_UDPReachable` - Verify NLB UDP connectivity
- `TestACCerts_Valid` - Verify certificate validity

### E2E Tests (NOT IMPLEMENTED)

These tests should verify the actual demo flows work:

```go
// Test 1: Website Demo Flow
func TestDemoFlow_CreateAndAccessCloakedURL(t *testing.T) {
    // 1. Call createPortalSitesByURL
    // 2. Verify protected server blocks unauthenticated access
    // 3. Verify QURL with passcode grants access
    // 4. Verify cookie is set correctly
}

// Test 2: Okta OIDC Flow (requires Okta test credentials)
func TestOIDCFlow_OktaAuthentication(t *testing.T) {
    // 1. Initiate OAuth flow
    // 2. Complete authentication
    // 3. Verify access granted
}
```

## Current Gaps

### Documentation Gaps
1. `createPortalSitesByURL` API not documented in NHP_ARCHITECTURE.md
2. Console API endpoints not documented
3. Traefik middleware configuration not documented
4. etcd schema not formally documented

### Testing Gaps
1. No E2E tests for website demo flow
2. No E2E tests for OIDC flow
3. Integration tests skip in CI (private DNS not reachable)
4. Canary timing issue - validation may hit old instances

### Monitoring Gaps
1. No health checks for demo flow
2. No alerting on authentication failures
3. No metrics on knock success/failure rates

## CI/CD Pipeline

### Workflow: build-and-push.yml

```
1. Setup
   └── Determine image tag, detect changes

2. Test
   └── Unit tests (go test ./...)

3. Build
   ├── Build AC Docker image
   └── Build Server Docker image

4. Terraform Plan (sandbox)
   └── Plan infrastructure changes

5. Deploy to Sandbox
   ├── Terraform Apply
   ├── Canary Deploy (1 instance)
   ├── Post-Deployment Validation  ← NEW
   ├── Integration Tests           ← NEW
   └── Full Instance Refresh

6. Notify
   └── Slack notification
```

### Known Issues

**Canary Timing Problem:**
When validation runs after canary deploy, NLB can route to any instance (old or new). To properly validate new code, we need to either:
1. Wait for full instance refresh before validation
2. Target the canary instance directly
3. Add version headers to verify which instance we hit

## Quick Reference

### Key URLs (Sandbox)

| URL | Purpose |
|-----|---------|
| `https://home.secure.layerv.xyz/api/ps/createPortalSitesByURL` | Demo API |
| `https://qurl.link/{appId}?passcode={passcode}` | Login portal |
| `https://{appId}.qurl.site/` | Protected resource |
| `https://oa.secure.layerv.ai/plugins/oktaoidc` | Okta OIDC entry |
| `https://demo-login.secure.layerv.xyz` | Okta demo page |

### Key Commands

```bash
# Check NHP Server logs
AWS_PROFILE=layerv aws logs tail /aws/ec2/nhp-server-sandbox --follow

# Check AC logs
AWS_PROFILE=layerv aws logs tail /aws/ec2/nhp-ac-sandbox --follow

# Test UDP connectivity
nc -u -v {nlb-dns} 62206

# Test demo API
curl -X POST https://home.secure.layerv.xyz/api/ps/createPortalSitesByURL \
  -H "Content-Type: application/json" \
  -d '{"url": "https://httpbin.org"}'
```
