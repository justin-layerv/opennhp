# LayerV NHP System Architecture

## Overview

LayerV implements a Network Hiding Protocol (NHP) system based on the Cloud Security Alliance's
OpenNHP standard. The system makes protected resources **invisible** to unauthorized users—all
ports appear filtered until a valid cryptographic "knock" is received.

**Key Properties:**
- Zero Trust: Resources hidden by default, access granted per-session
- Cryptographic Authentication: Curve25519 keypairs, not passwords
- Network-Level Protection: iptables/ipset rules, not just application auth
- Failopen Safety: If control plane fails, access is allowed (no lockout)

## Repository Structure

LayerV spans multiple repositories:

| Repository | Purpose | Key Components |
|------------|---------|----------------|
| `nhp` | Core NHP infrastructure | AC, Server, Terraform, CI/CD |
| `console` | Management UI & API | Portal Sites API, User management |
| `website` | Marketing site (layerv.ai) | Demo UI (CloakDemo component) |
| `demo` | Demo applications | OIDC demo, login page |
| `nhp-plugins-passcode` | Passcode auth plugin | URL validation, token generation |
| `nhp-plugins-oidc` | OIDC auth plugin | Okta integration |
| `traefik-plugins` | Traefik middleware | NHP token validation |
| `StealthDNS` | DNS-level protection | (separate system) |

---

## Core Components

### 1. NHP Server (`nhp/endpoints/server/`)

The NHP Server receives knock requests and coordinates with ACs to grant access.

**Key Responsibilities:**
- Receives UDP knock packets on port 62206 (via NLB)
- Receives HTTP knock requests on port 443 (via Traefik)
- Loads and manages authentication plugins
- Communicates with AC instances to open firewall rules
- Watches etcd for AC registrations

**Key Files:**
| File | Purpose |
|------|---------|
| `main.go` | Entry point |
| `udpserver.go` | UDP knock handler, AC registry watcher |
| `httpserver.go` | HTTP knock handler, plugin routing |
| `config.go` | Configuration loading, etcd integration |
| `msghandler.go` | NHP message processing |

**HTTP Routes:**
```
GET /plugins/:aspid              - Plugin entry point (login or auth)
GET /plugins/:aspid/:resid/valid - Legacy validation endpoint
```

**Listens On:**
- UDP 62206 (via NLB) - NHP protocol knocks
- TCP 443 (via Traefik) - HTTP auth flows

---

### 2. NHP Access Controller (`nhp/endpoints/ac/`)

The AC runs on protected servers and manages iptables/ipset rules.

**Key Responsibilities:**
- **Dials OUT** to NHP Server (server does NOT connect to AC)
- Receives AC operation requests from Server
- Manages iptables/ipset rules to grant/revoke access
- Handles HTTP refresh requests for IP address updates
- Monitors etcd for configuration changes

**Key Files:**
| File | Purpose |
|------|---------|
| `main.go` | Entry point |
| `udpac.go` | UDP communication with server, connection maintenance |
| `httpac.go` | HTTP refresh endpoint |
| `config.go` | Configuration loading, etcd integration |
| `msghandler.go` | NHP message processing, iptables updates |

**HTTP Routes (via Traefik on 443):**
```
GET /refresh/:token?srcip=X.X.X.X - Refresh access for new IP
```

**Does NOT Listen** for incoming UDP connections—always dials out.

---

### 3. Console API (`console/server/`)

The Console provides the management API and Portal Sites functionality.

**Key Responsibilities:**
- User and organization management
- Portal Sites CRUD operations
- `createPortalSitesByURL` - Public API for website demo
- Resource and policy management

**Key API Endpoints:**
```
POST /api/ps/createPortalSitesByURL  - Create portal site from URL (public, no auth)
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

---

### 4. Authentication Plugins

Plugins handle different authentication methods. They run inside the NHP Server process.

#### Passcode Plugin (`nhp-plugins-passcode/`)

Handles passcode-based authentication for the demo flow.

**Actions:**
| Action | URL Parameter | Description |
|--------|---------------|-------------|
| `valid` | `?passcode=X` | Validate passcode, open resource |
| `login` | (default) | Display login page |
| `refresh` | `?action=refresh` | Refresh existing token |
| `knock` | `?action=knock` | Knock by existing token |
| `access` | `?action=access` | RaaS IAM integration |
| `auth_code` | `?action=auth_code` | OAuth code exchange |
| `hmac_auth` | `?action=hmac_auth` | HMAC signature auth |

#### OIDC/Okta Plugin (`nhp-plugins-oidc/`, `endpoints/server/plugins/okta/`)

Handles OAuth2/OIDC authentication with identity providers.

**Actions:**
| Action | URL Parameter | Description |
|--------|---------------|-------------|
| `oauth` | `?action=oauth` | Initiate OAuth flow, redirect to IdP |
| `valid` | `?action=valid` | Validate after OAuth callback |
| `login` | `?action=login` | Show login page |

---

### 5. Traefik Integration

Traefik runs on AC instances as the reverse proxy with NHP middleware.

**Configuration Locations:**
- `docker/traefik/` - Container configuration
- AC instance `/etc/traefik/` - Dynamic config

**NHP Middleware (`traefik-plugins/`):**
- Validates `nhp_token` cookie on protected requests
- Calls AC `/refresh` endpoint to update iptables for new IPs
- Blocks unauthenticated requests (returns 401 or redirect)

**Listens On:**
- TCP 443 (HTTPS) - TLS termination
- TCP 80 (HTTP) - Redirect to HTTPS

---

## NHP Protocol Deep Dive

### UDP Communication Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           KNOCK FLOW                                    │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   ┌─────────┐     UDP 62206      ┌─────────────┐                        │
│   │  Agent  │ ─────────────────► │ NHP Server  │                        │
│   │ (User)  │     (via NLB)      │             │                        │
│   └─────────┘                    └──────┬──────┘                        │
│                                         │                               │
│                                         │ NHP_AOP (UDP)                 │
│                                         │ (through established conn)    │
│                                         ▼                               │
│                                  ┌─────────────┐                        │
│                                  │   NHP AC    │                        │
│                                  │  (dials to  │                        │
│                                  │   server)   │                        │
│                                  └──────┬──────┘                        │
│                                         │                               │
│                                         │ ipset/iptables update         │
│                                         ▼                               │
│                                  ┌─────────────┐                        │
│                                  │  Firewall   │                        │
│                                  │  (ACCEPT    │                        │
│                                  │  agent IP)  │                        │
│                                  └─────────────┘                        │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### AC-Server Connection (Critical!)

**The AC INITIATES the connection to the server, NOT the other way around.**

This is essential for deployments where ACs are behind NAT or have dynamic IPs.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    AC-SERVER CONNECTION SEQUENCE                        │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   1. AC starts up, reads server peers from server.toml (or etcd)        │
│   2. AC dials UDP connection to each server (OUTBOUND)                  │
│   3. AC sends NHP_AOL (AC Online) message to announce itself            │
│   4. Server responds with NHP_AAK (AC Acknowledge)                      │
│   5. Connection is now established for bidirectional communication      │
│   6. Server can send NHP_AOP (AC Operation) messages to AC              │
│                                                                         │
│   ┌─────────────┐                    ┌─────────────┐                    │
│   │   NHP AC    │ ──── NHP_AOL ────► │ NHP Server  │                    │
│   │             │ ◄─── NHP_AAK ───── │             │                    │
│   │             │                    │             │                    │
│   │             │ ◄─── NHP_AOP ───── │ (on knock)  │                    │
│   └─────────────┘                    └─────────────┘                    │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

**NHP Message Types:**
| Message | Direction | Purpose |
|---------|-----------|---------|
| NHP_AOL | AC → Server | AC announces it's online |
| NHP_AAK | Server → AC | Server acknowledges AC |
| NHP_AOP | Server → AC | AC operation request (open iptables) |
| NHP_KNK | Agent → Server | Knock request |
| NHP_ACK | Server → Agent | Knock acknowledgment |

### Configuration Files

#### Server `ac.toml` (AC peer definitions)
```toml
[[ACs]]
ACId = "sandbox-ac"
Hostname = ""
Ip = "10.100.0.43"        # AC's internal IP
Port = 62206              # AC's NHP port
PubKeyBase64 = "..."      # AC's public key
```

#### AC `server.toml` (Server peer definitions)
```toml
[[Servers]]
Hostname = "nlb.example.com"  # Server NLB DNS
Ip = ""
Port = 62206                  # Server's NHP port
PubKeyBase64 = "..."          # Server's public key
ExpireTime = 1924991999       # Unix timestamp
```

#### AC `config.toml` (Base configuration)
```toml
[AC]
PrivKeyBase64 = "..."         # AC's private key (NEVER in etcd)
DefaultIp = "0.0.0.0"
ListenPort = 62206

[IPTables]
DefaultAcceptTimeoutSec = 60
```

### Failure Modes

#### AC Cannot Reach Server (Failopen)
When the AC cannot establish connection to ANY server:
1. `maintainServerConnectionRoutine` detects all servers failed
2. Calls `a.iptables.AcceptAllInput()` to allow all traffic
3. Logs: `"accept iptables input v2"`

This **failopen** behavior prevents total lockout if the control plane is down.

#### Server Cannot Reach AC
If server has wrong AC IP/port or keys don't match:
1. Server sends NHP_AOP but AC never receives it
2. User's knock succeeds at server but firewall never opens
3. User cannot access protected resource

**Debugging:** Check server logs for "failed to send AOP" or AC logs for connection status.

---

## Authentication Flows

### Flow 1: Website Demo (Passcode)

The marketing website (layerv.ai) uses this flow for the "Cloak URL" demo.

```
┌─────────────┐    POST /api/ps/createPortalSitesByURL    ┌─────────────┐
│   Website   │ ─────────────────────────────────────────►│   Console   │
│ (layerv.ai) │    Body: { url: "https://example.com" }   │    API      │
└─────────────┘                                           └──────┬──────┘
                                                                 │
                        Response: { appId, passcode }            │
                        ◄────────────────────────────────────────┘
                                         │
                                         ▼
┌─────────────┐  GET qurl.link/{appId}?passcode={passcode}  ┌─────────────┐
│    User     │ ───────────────────────────────────────────►│ NHP Server  │
│   Browser   │                                             │ (passcode   │
└─────────────┘                                             │  plugin)    │
       │                                                    └──────┬──────┘
       │                                                           │
       │                                                           │ 1. Validate passcode
       │                                                           │ 2. Request AC operation
       │                                                           │
       │                                                    ┌──────▼──────┐
       │                                                    │   NHP AC    │
       │                                                    │ (ipset add) │
       │                                                    └──────┬──────┘
       │                                                           │
       │    Set-Cookie: nhp_token, nhp_refresh_token               │
       │    Redirect: https://{appId}.qurl.site/                   │
       │◄──────────────────────────────────────────────────────────┘
       │
       │  GET https://{appId}.qurl.site/
       ▼
┌─────────────┐     Validate nhp_token      ┌─────────────┐
│   Traefik   │ ───────────────────────────►│ Traefik NHP │
│             │                              │ Middleware  │
└──────┬──────┘                              └─────────────┘
       │
       │  iptables allows (srcIP in ipset)
       ▼
┌─────────────┐
│  Protected  │
│  Resource   │
└─────────────┘
```

**Key Endpoints:**
- `POST home.secure.layerv.xyz/api/ps/createPortalSitesByURL` - Create cloaked URL
- `GET qurl.link/{appId}?passcode={passcode}` - Authenticate with passcode
- `GET qurl.link/{appId}` - Login page (if no passcode)
- `GET {appId}.qurl.site/` - Access protected resource

**Protected Server Behavior** (`{appId}.qurl.site`):
- All ports filtered (DROP) by default via iptables
- Traefik validates `nhp_token` cookie
- Only authenticated IPs in ipset can connect

---

### Flow 2: OIDC/Okta Demo

For enterprise SSO integration demos.

```
┌─────────────┐  Visit demo-login.secure.layerv.xyz   ┌─────────────┐
│    User     │ ─────────────────────────────────────►│ Demo Login  │
│   Browser   │                                        │    Page     │
└──────┬──────┘                                        └─────────────┘
       │
       │ Click "Login with Okta"
       │ GET oa.secure.layerv.ai/plugins/oktaoidc?resid=demo-app&action=oauth
       ▼
┌─────────────┐                              ┌─────────────┐
│ NHP Server  │  Initialize Authenticator   │  Okta OIDC  │
│             │ ────────────────────────────►│   Plugin    │
└──────┬──────┘                              └─────────────┘
       │
       │ Redirect to Okta authorization URL
       ▼
┌─────────────┐    OAuth Authorization    ┌─────────────┐
│    Okta     │ ◄────────────────────────►│    User     │
│             │                            │   Browser   │
└──────┬──────┘                            └─────────────┘
       │
       │ Callback with authorization code
       ▼
┌─────────────┐   Exchange code for token   ┌─────────────┐
│ NHP Server  │ ───────────────────────────►│    Okta     │
│             │                              │             │
└──────┬──────┘                              └─────────────┘
       │
       │ Verify ID token, request AC operation
       ▼
┌─────────────┐
│   NHP AC    │  Open iptables for srcIp
└──────┬──────┘
       │
       │ Set-Cookie: nhp_token
       │ Redirect to protected resource
       ▼
┌─────────────┐
│  Protected  │
│  Resource   │
└─────────────┘
```

---

### Flow 3: Token Refresh (IP Change)

When a user's IP changes, they need to refresh their access.

```
┌─────────┐     HTTPS 443       ┌──────────┐     HTTP 8888      ┌─────────┐
│  User   │ ──────────────────► │ Traefik  │ ─────────────────► │ NHP AC  │
│ Browser │ /refresh/{token}    │          │    (localhost)     │ (httpac)│
└─────────┘                     └──────────┘                    └────┬────┘
                                                                     │
                                                                     │ Validate token
                                                                     │ Add new srcIP to ipset
                                                                     ▼
                                                              ┌─────────────┐
                                                              │  Firewall   │
                                                              │ (new IP OK) │
                                                              └─────────────┘
```

---

## Domain Architecture

### Production Domains

| Domain | Purpose | Backend |
|--------|---------|---------|
| `home.secure.layerv.xyz` | Console API (sandbox) | Console server on AC |
| `home.secure.layerv.ai` | Console API (prod) | Console server on AC |
| `qurl.link` | Login portal | NHP Server → passcode plugin |
| `*.qurl.site` | Protected resources | Traefik → upstream via AC rules |
| `oa.secure.layerv.ai` | OIDC plugin endpoint | NHP Server → okta plugin |
| `demo-login.secure.layerv.xyz` | Okta demo login page | Static HTML on AC |

### DNS Flow

```
Internet
    │
    ▼
qurl.link ──────────► NLB (us-east-2) ─┬─► NHP Server (HTTP 443)
                                       └─► NHP Server (UDP 62206)

*.qurl.site ────────► NLB ────────────────► Traefik on AC ──► Protected Resource
```

---

## Infrastructure (AWS)

### Environments

| Property | Sandbox | Production |
|----------|---------|------------|
| AWS Account | 767397897469 | (different) |
| Region | us-east-2 | us-east-2 |
| Server ASG | `layerv-nhp-sandbox-server-asg` | `layerv-nhp-prod-server-asg` |
| AC ASG | `layerv-nhp-sandbox-ac-asg` | `layerv-nhp-prod-ac-asg` |
| etcd | `etcd.nhp.sandbox.internal:2379` | `etcd.nhp.prod.internal:2379` |

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
│ - UDP listener  │◄─────►│ - Dials to srv  │
│ - HTTP plugins  │       │ - iptables mgmt │
│ - etcd watcher  │       │ - Traefik       │
└─────────────────┘       │ - Console API   │
                          └─────────────────┘
                                  │
                                  ▼
                          ┌─────────────────┐
                          │   etcd Cluster  │
                          │   (internal)    │
                          └─────────────────┘
```

### Security Groups

| Component | Rule | Purpose |
|-----------|------|---------|
| Server SG | UDP 62206 from 0.0.0.0/0 | Agent knocks via NLB |
| AC SG | UDP 62206 from VPC CIDR | Server-to-AC (though AC dials out) |
| AC SG | TCP 443, 80 from 0.0.0.0/0 | HTTPS via NLB |

---

## Configuration Management

### etcd Keys

```
/nhp/config                    - Shared config (HTTP settings, server peers)
/nhp/ac-registry/{instance-id} - Per-AC registration with public key
```

**etcd config structure** (`/nhp/config`, TOML format):
```toml
[HttpConfig]
EnableHttp = true
HttpListenPort = 8888

[[Servers]]
Hostname = "nlb.example.com"
Port = 62206
PubKeyBase64 = "..."
ExpireTime = 1924991999
```

**AC Registry Entry** (`/nhp/ac-registry/{instance-id}`, TOML format):
```toml
PublicKey = "base64-encoded-public-key"
InstanceId = "i-1234567890abcdef0"
Ip = "10.0.0.100"
Port = 62206
RegisteredAt = 1703980800
IdentityDocument = "base64-encoded-aws-identity-document"
IdentitySignature = "base64-encoded-rsa2048-signature"
```

### Per-AC Key Architecture (Security)

**Private keys are NEVER stored in etcd.** Each AC instance:
1. Generates Curve25519 keypair on first boot
2. Stores private key in AWS Secrets Manager (`{prefix}-ac-{instance-id}`)
3. Registers only the public key + AWS identity in etcd

### AC Startup Flow

1. AC instance starts
2. Generates Curve25519 keypair (or retrieves from Secrets Manager if reboot)
3. Stores private key in Secrets Manager
4. Fetches AWS Instance Identity Document with RSA-2048 signature
5. Registers public key + identity in etcd at `/nhp/ac-registry/{instance-id}`
6. Loads local `config.toml` (with private key reference)
7. Connects to etcd, loads server peers from `/nhp/config`
8. Dials out to NHP servers

### Server-Side AC Trust

The NHP server dynamically discovers ACs by watching `/nhp/ac-registry/` prefix:

1. On startup, loads all existing registry entries
2. If running in AWS, verifies each AC's AWS Instance Identity Document
3. Adds verified ACs as trusted peers
4. Watches for new registrations/deletions and reconciles

**AWS Identity Verification** (when server runs in AWS):
- Verifies RSA-2048 signature using AWS region-specific certificates
- Validates instance ID and private IP match the registration
- Validates AWS account ID matches expected value

### Secrets Manager

| Secret | Purpose |
|--------|---------|
| `nhp/{env}/server-private-key` | NHP Server Curve25519 private key |
| `nhp/{env}/ac-{instance-id}` | Per-AC Curve25519 private key |
| `nhp/etcd/ca-cert` | etcd CA certificate |
| `nhp/etcd/client-cert` | etcd client certificate |
| `nhp/etcd/client-key` | etcd client key |

### Cleanup

- **On termination**: ASG lifecycle hook triggers Lambda to delete etcd entry + secret
- **Weekly audit**: Lambda compares registry to running instances, cleans orphans

**IMPORTANT**: If etcd has no `[[Servers]]` section, AC has no servers to connect to
and will fall back to "accept all" mode (failopen).

---

## Testing

### Unit Tests

Run automatically in CI on every push.

```bash
go test ./nhp/...
go test ./endpoints/ac/...
go test ./endpoints/server/...
```

**Key Test Files:**
- `endpoints/ac/config_test.go` - AC configuration loading
- `endpoints/server/config_test.go` - Server configuration loading, etcd constants
- `nhp/**/*_test.go` - Core NHP library tests

### Integration Tests

Test infrastructure after deployment. Require VPC access and etcd mTLS certs.

**Location:** `tests/integration/deployment_test.go`

```bash
# Run with required environment variables
ETCD_ENDPOINTS=https://etcd.nhp.sandbox.internal:2379 \
ETCD_CA_CERT=/path/to/ca.crt \
ETCD_CLIENT_CERT=/path/to/client.crt \
ETCD_CLIENT_KEY=/path/to/client.key \
go test -v -tags=integration ./tests/integration/...
```

**Tests:**
| Test | Purpose |
|------|---------|
| `TestEtcd_Connection` | Verify etcd connectivity |
| `TestEtcd_NHPConfigExists` | Verify `/nhp/config` key exists |
| `TestEtcd_ACRegistry` | Verify AC registrations |
| `TestNHPServer_UDPReachable` | Verify NLB UDP connectivity |
| `TestACCerts_Valid` | Verify AWS certificate validity |

### E2E Tests

Test the actual demo flows against live infrastructure.

**Location:** `tests/e2e/demo_flow_test.go`

```bash
# Run against sandbox
CONSOLE_API_URL=https://home.secure.layerv.xyz \
LOGIN_PORTAL_DOMAIN=qurl.link \
APPS_DOMAIN=qurl.site \
go test -v -tags=e2e -timeout 5m ./tests/e2e/...
```

**Tests:**
| Test | Purpose |
|------|---------|
| `TestDemoFlow_CreateAndAccessCloakedURL` | Full demo: create URL → auth → access |
| `TestDemoFlow_InvalidPasscode` | Verify invalid passcodes rejected |
| `TestDemoFlow_APIHealth` | Console API health check |

---

## CI/CD Pipeline

### Workflow: `build-and-push.yml`

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
   ├── Post-Deployment Validation
   ├── Integration Tests
   ├── E2E Tests (demo flow)
   └── Full Instance Refresh

6. Deploy to Production (manual approval)
   ├── Terraform Apply
   ├── Canary Deploy
   ├── Validation + E2E Tests
   └── Full Instance Refresh

7. Notify
   └── Slack notification
```

### Known Issues

**Canary Timing:**
When validation runs after canary deploy, NLB can route to any instance (old or new).
E2E tests mitigate this by testing the live system regardless of which instance handles
the request—they create new portal sites, so they verify current behavior.

---

## Debugging & Operations

### Log Locations

**AC Logs (on instance):**
```bash
/opt/layerv/nhp-ac/logs/ac*.log
```

**CloudWatch:**
```bash
# AC logs
AWS_PROFILE=layerv aws logs tail /aws/ec2/nhp-ac-sandbox --follow

# Server logs
AWS_PROFILE=layerv aws logs tail /aws/ec2/nhp-server-sandbox --follow
```

**Docker (if containerized):**
```bash
docker logs nhp-server
docker logs nhp-ac
```

### Common Issues

| Symptom | Likely Cause | Check |
|---------|--------------|-------|
| AC logs "accept iptables input" | Cannot reach any server | Server NLB DNS, security groups |
| Knock succeeds but can't access | AC not receiving AOP | AC-Server connection, key mismatch |
| Protected site shows login | Token expired or IP changed | Cookie expiry, refresh flow |
| 502 on protected resource | Upstream unreachable | Traefik config, target health |

### Verification Commands

```bash
# Check etcd config
ETCDCTL_API=3 etcdctl get /nhp/config --print-value-only

# Check AC registrations
ETCDCTL_API=3 etcdctl get /nhp/ac-registry/ --prefix --keys-only

# Test UDP connectivity
nc -u -v {nlb-dns} 62206

# Test demo API
curl -X POST https://home.secure.layerv.xyz/api/ps/createPortalSitesByURL \
  -H "Content-Type: application/json" \
  -d '{"url": "https://httpbin.org"}'
```

### E2E Test Commands

```bash
# 1. Create a cloaked URL
curl -X POST https://home.secure.layerv.xyz/api/ps/createPortalSitesByURL \
  -H "Content-Type: application/json" \
  -d '{"url": "https://httpbin.org"}'
# Response: {"code":0,"data":{"appId":"abc123","passcode":"secret"}}

# 2. Verify protected server is blocked
curl -I https://abc123.qurl.site/
# Expected: 401/403 or redirect to login

# 3. Authenticate with passcode
curl -c cookies.txt -L "https://qurl.link/abc123?passcode=secret"
# Expected: 200 with httpbin.org content

# 4. Verify port scan shows nothing
nmap -Pn -p 80,443 abc123.qurl.site
# Expected: All ports filtered
```

---

## Quick Reference

### Key URLs (Sandbox)

| URL | Purpose |
|-----|---------|
| `https://home.secure.layerv.xyz/api/ps/createPortalSitesByURL` | Demo API |
| `https://qurl.link/{appId}?passcode={passcode}` | Login portal |
| `https://{appId}.qurl.site/` | Protected resource |
| `https://oa.secure.layerv.ai/plugins/oktaoidc` | Okta OIDC entry |
| `https://demo-login.secure.layerv.xyz` | Okta demo page |

### Key URLs (Production)

| URL | Purpose |
|-----|---------|
| `https://home.secure.layerv.ai/api/ps/createPortalSitesByURL` | Demo API |
| `https://qurl.link/{appId}?passcode={passcode}` | Login portal |
| `https://{appId}.qurl.site/` | Protected resource |

### Ports

| Port | Protocol | Component | Purpose |
|------|----------|-----------|---------|
| 62206 | UDP | NHP Server | Knock packets |
| 443 | TCP | Traefik | HTTPS (TLS termination) |
| 80 | TCP | Traefik | HTTP → HTTPS redirect |
| 8888 | TCP | AC (localhost) | HTTP refresh endpoint |

### Config Files

| File | Location | Purpose |
|------|----------|---------|
| `config.toml` | Server/AC | Base configuration |
| `ac.toml` | Server | AC peer definitions |
| `server.toml` | AC | Server peer definitions |
| `http.toml` | Server | HTTP server settings |
| `remote.toml` | AC | etcd connection settings |
