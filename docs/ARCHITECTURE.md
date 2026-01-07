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
| `nhp` | Core NHP infrastructure | AC, Server, Terraform, CI/CD, Server Plugins |
| `console` | Management UI & API | Portal Sites API, User management |
| `website` | Marketing site (layerv.ai) | Demo UI (CloakDemo component) |
| `demo` | Demo applications | OIDC demo, login page |
| `traefik-plugins` | Traefik middleware | NHP token validation |
| `StealthDNS` | DNS-level protection | (separate system) |

> **Note:** Server plugins (passcode, oidc) are now statically compiled into the NHP Server binary.
> The `nhp-plugins-passcode` and `nhp-plugins-oidc` repos are deprecated.

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
- TCP 8888 (HTTP) - Plugin endpoints (passcode login, auth validation)
  - Accessed via AC Traefik (`/plugins/*` routes) or Demo Gateway nginx

**HTTP Access Paths:**
1. **Via AC Traefik** (primary for terraform): `{resid}.nhp.layerv.xyz/plugins/passcode?action=login`
   - Traefik routes `/plugins/*` to `http://server.nhp.sandbox.internal:8888`
2. **Via Demo Gateway** (for qurl.link): `qurl.link/{appId}`
   - nginx routes to `http://server.nhp.sandbox.internal:8888/plugins/passcode?resid={appId}&action=login`

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

Plugins handle different authentication methods. They run inside the NHP Server process as statically compiled modules.

> **Note:** Server plugins are in `endpoints/server/staticplugins/` (not `plugins/`).
> They are statically compiled into the server binary—no dynamic loading or `.so` files.
> The `plugins/` directory is for upstream OpenNHP dynamic plugins (example, okta) with Makefiles.

#### Passcode Plugin (`endpoints/server/staticplugins/passcode/`)

Handles passcode-based authentication for the demo flow.

**⚠️ IMPORTANT: Portal Sites are ONE-TIME USE**

Each passcode can only be used ONCE. After successful validation, the passcode is consumed
and cannot be reused. Testing requires creating a fresh portal site for each attempt.

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

**Configuration (Manually Provisioned):**

Location: `/home/ubuntu/nhp-server/plugins/passcode/etc/config.toml`
```toml
ResourceMode = "api"
AuthUrl = "http://172.31.26.100:8888"  # Console API on single AC
```

The plugin calls the Console API to validate passcodes and retrieve target URLs.

**nginx Configuration (Manually Provisioned):**

The qurl.link nginx config on NHP Servers handles initial URL routing:

`/etc/nginx/sites-enabled/qurl.link`:
```nginx
server {
    listen 443 ssl proxy_protocol;
    server_name qurl.link www.qurl.link;

    # Route /{appId} to passcode plugin with action=login
    location ~ ^/(?<resid>[^/]+)/?$ {
        proxy_pass http://127.0.0.1:62206/plugins/passcode?resid=$resid&action=login;
        # NOTE: Original query params (like ?passcode=) are NOT forwarded
    }

    location = / { return 404; }
}
```

**⚠️ Query Parameter Behavior:**

When nginx specifies a URI in `proxy_pass` (e.g., `/plugins/passcode?resid=$resid&action=login`),
the original query parameters from the request are **dropped**. This means:
- `qurl.link/abc123?passcode=secret` → plugin receives only `?resid=abc123&action=login`
- The passcode is NOT automatically passed to the plugin

**Login Page Flow:**

The passcode plugin's `action=login` returns an HTML login page. When the user submits the form:

1. JavaScript extracts the passcode from the input field
2. Constructs validation URL: `https://{appId}.secure.layerv.xyz/plugins/passcode?resid={appId}&action=valid&format=json&passcode={passcode}`
3. Submits to `*.secure.layerv.xyz` (NOT qurl.link)
4. The `*.secure.layerv.xyz` nginx config has a catch-all `location /` that proxies all paths

This is why the `*.secure.layerv.xyz` nginx config works while qurl.link's specific location doesn't
need to handle `/plugins/passcode` POST requests.

#### OIDC/Okta Plugin (`endpoints/server/staticplugins/oidc/`)

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
- AC instance `/home/ubuntu/traefik/traefik.toml` - Main config
- AC instance `/home/ubuntu/traefik/dynamic/` - Dynamic config
- Traefik runs as a **native binary** (`/usr/local/bin/traefik`), NOT in Docker

**NHP Middleware (`traefik-plugins/`):**
- Validates `nhp_token` cookie on protected requests
- Calls AC `/refresh` endpoint to update iptables for new IPs
- Blocks unauthenticated requests (returns 401 or redirect)

**Listens On:**
- TCP 443 (HTTPS) - TLS termination
- TCP 80 (HTTP) - Redirect to HTTPS

---

## Plugin Deployment System

NHP uses two types of plugins with different deployment strategies:

| Plugin Type | Deployment | Reason |
|------------|------------|--------|
| **NHP Server plugins** | Statically compiled into server binary | No CGO/dynamic loading needed, simpler deployment |
| **Traefik plugins** | Downloaded from S3 at boot | Source-based, compiled by Traefik at runtime |

### NHP Server Plugins (Statically Compiled)

Server plugins (passcode, oidc, etc.) are statically compiled into the NHP Server binary. This
eliminates the need for CGO and dynamic plugin loading (`.so` files), resulting in simpler
cross-compilation and deployment.

**Plugin Registry Architecture:**
```
nhp/plugins/
└── registry.go             # Plugin registry (maps IDs to factories)

endpoints/server/staticplugins/   # Statically compiled plugins
├── passcode/                     # Passcode authentication plugin
│   ├── main.go                   # Plugin entry, init() registers with registry
│   └── ...
└── oidc/                         # OIDC/OAuth2 authentication plugin
    ├── main.go                   # Plugin entry, init() registers with registry
    └── ...

endpoints/server/plugins/         # Upstream OpenNHP dynamic plugins (with Makefiles)
├── example/
└── okta/
```

**How It Works:**

1. Each plugin has an `init()` function that registers itself with the plugin registry:
   ```go
   func init() {
       plugins.RegisterPlugin("passcode", New)
   }
   ```

2. The server `main.go` imports plugins with blank imports to trigger registration:
   ```go
   import (
       _ "github.com/OpenNHP/opennhp/endpoints/server/staticplugins/oidc"
       _ "github.com/OpenNHP/opennhp/endpoints/server/staticplugins/passcode"
   )
   ```

3. At runtime, the server looks up plugins by `AuthSvcId` from the registry:
   ```go
   h := plugins.GetPluginHandler(aspId, "")
   ```

**Adding a new NHP Server plugin:**
1. Create new directory under `endpoints/server/staticplugins/{plugin-name}/`
2. Implement the `PluginHandler` interface
3. Register the plugin in `init()` using `plugins.RegisterPlugin()`
4. Add blank import in `endpoints/server/main/main.go`
5. Add plugin name to `server_plugins` list in terraform.tfvars
6. Build and deploy

### Traefik Plugins (S3-based)

Traefik plugins are Go source files compiled by Traefik at runtime. They don't have binary
compatibility issues, so they're downloaded from S3 at boot time.

**S3 Structure:**
```
s3://layerv-nhp-{env}-plugins/
├── traefik/
│   └── nhp-token-validator/
│       └── v1.0.0/
│           ├── .traefik.yml
│           ├── go.mod
│           └── *.go
└── configs/
    └── traefik/
        └── nhp-token-validator/config.toml
```

### Terraform Configuration

```hcl
# terraform.tfvars
# NHP Server plugins - list of enabled plugin names (statically compiled)
server_plugins = ["passcode"]

# Traefik plugins - downloaded from S3
traefik_plugins = {
  nhp-token-validator = { version = "latest", config = {} }
}
```

The `server_plugins` list controls which `AuthSvcId` values are valid for authentication.
These plugin names map to the statically compiled plugins in the server binary.

### Plugin CI/CD

| Repo | Plugin Type | Deployment |
|------|-------------|------------|
| `nhp` | NHP Server plugins | Statically compiled into server binary |
| `traefik-plugins` | Traefik middleware | Uploaded to S3, downloaded by AC at boot |

```bash
# Deploy plugin update to running instances (server binary includes all plugins)
aws autoscaling start-instance-refresh \
  --auto-scaling-group-name layerv-nhp-sandbox-server
```

**IAM Trust Policy:**
The `nhp-{env}-github-actions` IAM role trusts repos via GitHub OIDC.
Plugin repos (for Traefik plugins) are configured in `plugin_repos` variable.

### Packer Templates

Packer templates build AMIs with plugins pre-installed:

| Template | Purpose | Distribution |
|----------|---------|--------------|
| `nhp-ac.pkr.hcl` | AC with Traefik plugins | **AWS Marketplace** |
| `nhp-server.pkr.hcl` | NHP Server | Internal only |

```bash
# Build AC AMI for Marketplace
cd packer
packer init nhp-ac.pkr.hcl
packer build \
  -var 'marketplace=true' \
  -var 'product_version=1.0.0' \
  -var 'image_tag=v1.0.0' \
  -var 'plugin_bucket=layerv-nhp-prod-plugins' \
  -var 'plugin_version=v1.0.0' \
  nhp-ac.pkr.hcl
```

**Marketplace AC AMI Features:**
- Native binaries only (no Docker at runtime)
- EBS encryption enabled
- SSH host keys removed (regenerated on boot)
- No cached credentials
- First-boot configuration script for customer customization

**Runtime Architecture:**
AMIs extract binaries from Docker images at build time but run as native systemd services:
```
Build Time:  ECR Image → docker cp → /opt/layerv/{component}/binary
Runtime:     systemd → native binary (no Docker)
```

### Plugin Testing

Integration tests verify the plugin system after deployment:

```bash
PLUGIN_BUCKET=layerv-nhp-sandbox-plugins \
AWS_REGION=us-east-2 \
go test -v -tags=integration ./tests/integration/... -run TestPlugins
```

**Tests:**
| Test | Purpose |
|------|---------|
| `TestPlugins_BucketExists` | Verify S3 bucket is accessible |
| `TestPlugins_ManifestExists` | Verify manifest.json exists and is valid |
| `TestPlugins_TraefikPluginsExist` | Verify Traefik plugin files |

> **Note:** Server plugins are statically compiled—no S3 tests needed for them.

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

**⚠️ This flow uses the Manually Provisioned infrastructure, NOT Terraform-managed.**

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

**Key Endpoints (Manually Provisioned):**
- `POST home.secure.layerv.xyz/api/ps/createPortalSitesByURL` - Create cloaked URL (Console API on 172.31.26.100)
- `GET qurl.link/{appId}` - Shows login page (⚠️ ?passcode= query param is DROPPED by nginx)
- `POST {appId}.secure.layerv.xyz/plugins/passcode?action=valid` - Login page JS submits here to validate passcode
- `GET {appId}.qurl.site/` - Access protected resource

**Detailed Flow:**
1. **Create Portal Site**: Website calls Console API, receives appId + passcode
2. **Show Login Page**: User visits qurl.link/{appId}, nginx proxies to plugin with `action=login`, returns HTML form
3. **Validate Passcode**: Login page JavaScript submits to `{appId}.secure.layerv.xyz` (NOT qurl.link!) with `action=valid`
4. **Authenticate**: Plugin validates passcode with Console API (ONE-TIME USE - passcode is consumed)
5. **Open Firewall**: On success, NHP Server sends NHP_AOP to AC to add user's srcIP to ipset
6. **Set Cookie & Redirect**: Plugin sets nhp_token cookie, redirects to {appId}.qurl.site
7. **Access Resource**: Traefik validates token, iptables allows srcIP, user sees protected content

**Protected Server Behavior** (`{appId}.qurl.site`):
- All ports filtered (DROP) by default via iptables
- Traefik validates `nhp_token` cookie
- Only authenticated IPs in ipset can connect

**Known Issues (Manually Provisioned Demo):**

| Issue | Status | Description |
|-------|--------|-------------|
| Intermittent 404 on first use | Investigating | Fresh passcodes occasionally return nginx 404 on first request |
| Query params dropped by nginx | By design | nginx qurl.link config drops ?passcode=; login page JS handles submission to different domain |
| Single Console API instance | Limitation | Console API runs only on AC at 172.31.26.100 - no redundancy |

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

## Demo Gateway Architecture

The Demo Gateway provides TLS termination and routing for the demo flow, bridging qurl.link traffic
to the NHP Server's HTTP plugin endpoints.

### Architecture Overview

```
Internet
    │
    ├─────────────────────────────────────────────────────────────────────┐
    ▼                                                                     │
┌─────────────────────────────────────────────────────────────────────────┤
│                        Console EC2 (Terraform module: console-ec2)      │
│   NLB (TCP 443) → nginx (TLS) → Console API (Docker, port 8888)         │
│   Domain: console.nhp.layerv.xyz                                        │
│   API: createPortalSitesByURL, portal site management                   │
└─────────────────────────────────────────────────────────────────────────┘
    │
    │ (website calls createPortalSitesByURL, returns appId + passcode)
    │
    ├─────────────────────────────────────────────────────────────────────┐
    ▼                                                                     │
┌─────────────────────────────────────────────────────────────────────────┤
│                        Demo Gateway EC2 (Terraform module: demo-gateway)│
│   NLB (TCP 443) → nginx (TLS termination via certbot)                   │
│   Domain: qurl.link                                                     │
│   Routes: /{appId} → NHP Server HTTP (port 8888)                        │
└─────────────────────────────────────────────────────────────────────────┘
    │
    ▼ (VPC internal, HTTP port 8888)
┌─────────────────────────────────────────────────────────────────────────┐
│                        NHP Server (Terraform module: compute)            │
│   NLB (UDP 62206) - knock packets                                       │
│   HTTP 8888 - passcode plugin endpoint (EnableHttp = true)              │
│   Cloud Map: server.nhp.{env}.internal                                  │
│   NOTE: HTTP listens on 8888 despite http.toml saying 8080              │
└─────────────────────────────────────────────────────────────────────────┘
    │
    ▼ (NHP protocol - opens firewall via AC)
┌─────────────────────────────────────────────────────────────────────────┐
│                        AC (Terraform module: ac)                         │
│   NLB (TCP 443) → Traefik → protected resources                         │
│   Domain: *.qurl.site, *.nhp.layerv.xyz                                 │
└─────────────────────────────────────────────────────────────────────────┘
```

### Demo Flow (Terraform-Managed)

1. **Create Portal Site**: Website → Console EC2 API (`console.nhp.layerv.xyz/api/ps/createPortalSitesByURL`)
2. **Show Login Page**: User → `qurl.link/{appId}` → Demo Gateway nginx → NHP Server HTTP (`/plugins/passcode?action=login`)
3. **Validate Passcode**: Login page JS → `{appId}.secure.layerv.xyz/plugins/passcode?action=valid` → NHP Server
4. **Open Firewall**: NHP Server → AC (NHP_AOP message) → iptables updated
5. **Access Resource**: Redirect → `{appId}.qurl.site` → AC Traefik → protected upstream

### nginx Configuration (Demo Gateway)

The Demo Gateway nginx routes requests to NHP Server's HTTP plugin endpoint:

```nginx
# Route /{appId} to passcode plugin login page
location ~ ^/(?<resid>[a-zA-Z0-9_-]+)/?$ {
    proxy_pass http://server.nhp.sandbox.internal:8888/plugins/passcode?resid=$resid&action=login;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}

# Proxy all /plugins/* requests to NHP Server
location /plugins/ {
    proxy_pass http://server.nhp.sandbox.internal:8888;
    # ... headers
}
```

### Key Differences from Manual Infrastructure

| Aspect | Manual (Legacy) | Terraform (New) |
|--------|-----------------|-----------------|
| Console API | On AC at 172.31.26.100:8888 | Dedicated EC2 (console-ec2 module) |
| qurl.link routing | nginx on NHP Servers | Demo Gateway EC2 (demo-gateway module) |
| TLS for qurl.link | Manual cert management | certbot auto-renewal |
| NHP Server HTTP | nginx proxy on 443 | Direct HTTP on port 8888 |
| Service discovery | Static IPs | Cloud Map DNS |
| /plugins routing | nginx on AC | Traefik on AC routes to NHP Server |

### Terraform Module Configuration

```hcl
# Enable Demo Gateway
deploy_demo_gateway = true
demo_gateway_domain = "qurl.link"
demo_gateway_hosted_zone_id = "Z..." # qurl.link zone in layerv-mgmt
cross_account_route53_role_arn = "arn:aws:iam::165115313779:role/nhp-route53-access"

# Enable Console EC2 (instead of Fargate)
deploy_console_ec2 = true
console_ec2_domain = "console.nhp.layerv.xyz"
console_internal_only = true  # NHP-protected mode
```

### Console NHP Integration

**IMPORTANT:** Console does NOT use nhp-acd for access control. Instead, Console has its own
username/password authentication, and NHP integration happens **client-side after login**.

#### Old Console Architecture (console-login.secure.layerv.xyz)

The old Console serves the Vue app directly - NOT behind nhp-acd:

```
Internet → console-login.secure.layerv.xyz
    │
    ▼
nginx/Traefik (TLS termination)
    │
    ├── /plugins/* → NHP Server HTTP (port 8888) [for auth_code action]
    ├── /api/*     → Console API (gin backend, port 8888)
    └── /*         → Console Vue app (static files)
```

**Login Flow (client-side NHP integration):**

1. User visits `console-login.secure.layerv.xyz` → Vue app loads directly (no NHP blocking)
2. User logs in with **username/password** → Console API validates, returns JWT token (`x-token`)
3. **After successful login**, Vue app JavaScript calls NHP Server:
   ```javascript
   // From console/web/src/pinia/modules/user.js (lines 95-131)
   const authApiUrl = `${loginUrl}/plugins/passcode?resid=console&action=auth_code&code=${token}`
   const authResponse = await fetch(authApiUrl)
   // NHP Server validates JWT with Console API, performs knock, sets nhp_token cookie
   window.location.href = authData.redirect_url  // Redirect to NHP-protected resource
   ```
4. NHP Server validates JWT token with Console API
5. NHP Server performs knock (sends NHP_AOP to AC to add srcIP to ipset)
6. NHP Server sets `nhp_token` and `nhp_refresh_token` cookies
7. User redirected to `redirect_url` (now accessible because knock succeeded)

**Key Insight:** Console login page is accessible WITHOUT nhp_token. NHP tokens are acquired
**after** Console's own authentication succeeds, via client-side JavaScript.

#### New Console Architecture (console.nhp.layerv.xyz)

For new Console to work like old Console, traffic must bypass nhp-acd:

```
Internet → console.nhp.layerv.xyz (Route 53)
    │
    ▼
AC NLB (TCP 443) → Traefik
    │
    └── Host(`console.nhp.layerv.xyz`) → Console internal NLB (port 8888)
            │                            [BYPASSES nhp-acd!]
            ▼
        Console EC2 nginx (port 8888)
            │
            ├── /plugins/* → NHP Server HTTP (server.nhp.sandbox.internal:8888)
            │                [for auth_code action after login]
            ├── /api/*     → Console Docker (port 8080)
            └── /*         → Console Docker (Vue app)
```

**⚠️ DO NOT route Console through nhp-acd** - this blocks the login page from loading.

**Console EC2 nginx routes `/plugins/*` to NHP Server** for post-login NHP authentication.
This is configured via the `nhp_server_endpoint` variable in the console-ec2 Terraform module.

**Terraform Configuration:**

The AC module accepts `console_backend_url` and `console_domain` variables to configure
Console-specific routing that bypasses nhp-acd. The console-ec2 module accepts
`nhp_server_endpoint` to route `/plugins/*` to NHP Server:

```hcl
# In root main.tf, pass to AC module:
console_backend_url = module.console_ec2[0].internal_endpoint  # http://nlb:8888
console_domain      = var.console_ec2_domain                   # console.nhp.layerv.xyz

# In root main.tf, pass to console_ec2 module:
nhp_server_endpoint = "server.${module.data.namespace_name}:8888"  # NHP Server Cloud Map

# In terraform.tfvars:
console_internal_only = true
console_ec2_domain = "console.nhp.layerv.xyz"
# console_admin_password = "your-secure-password"  # Optional, set via TF_VAR for security
```

**AC Traefik Dynamic Config (user_data.sh.tpl):**

```toml
[http.routers]
  # Console-specific route - BYPASSES nhp-acd
  # All Console traffic (including /plugins/*) goes to Console EC2
  [http.routers.console]
    rule = "Host(`console.nhp.layerv.xyz`)"
    service = "console"
    entryPoints = ["https"]
    priority = 20  # Higher than nhp-ac

  # Default route to nhp-acd (for other resources)
  [http.routers.nhp-ac]
    rule = "PathPrefix(`/`)"
    service = "nhp-ac"
    priority = 1

[http.services]
  [http.services.console.loadBalancer]
    [[http.services.console.loadBalancer.servers]]
      url = "http://console-internal-nlb:8888"
```

**Note:** Console EC2 nginx handles `/plugins/*` routing internally (see architecture diagram above).

#### Console Cookie Configuration

Console uses cross-domain cookies for SSO:

```javascript
// From console/web/src/pinia/modules/user.js
const cookieDomain = import.meta.env.VITE_COOKIE_DOMAIN || '.layerv.ai'
// Sets x-token cookie with domain for cross-subdomain access
```

**Two-Domain Architecture:**

New Console uses a two-domain architecture for NHP protection:

| Domain | Purpose | NHP Protection |
|--------|---------|----------------|
| `console.nhp.layerv.xyz` | Login domain | Bypasses nhp-acd (login page accessible) |
| `console2.apps.layerv.xyz` | Protected domain | NHP-protected (requires nhp_token) |

**Login Flow:**
1. User visits `console.nhp.layerv.xyz` (login domain)
2. User logs in with username/password
3. Frontend does NHP knock via `/plugins/passcode?action=auth_code`
4. User redirected to `console2.apps.layerv.xyz` (protected domain)

**Environment Variables (web/.env.production):**

| Variable | Old Console | New Console | Description |
|----------|-------------|-------------|-------------|
| `VITE_LOGIN_URL` | `https://console-login.secure.layerv.ai` | `https://console.nhp.layerv.xyz` | Login domain URL (set via Docker build-arg from SSM) |
| `VITE_COOKIE_DOMAIN` | `.layerv.ai` | `.layerv.xyz` | Cookie domain for SSO |
| `VITE_BASE_PATH` | `https://console-login.secure.layerv.ai` | `https://console.nhp.layerv.xyz` | Base URL |

**VITE_LOGIN_URL Behavior:**
- **Set to login domain URL**: NHP knock only when `window.location.host` matches this URL's host
- **Empty/not set**: NHP auth skipped entirely (Console without NHP integration)
- **localhost**: NHP auth skipped (development mode)

The `VITE_LOGIN_URL` value is stored in SSM parameter `/layerv/nhp/{env}/console/public_url` by
Terraform and read by GitHub Actions during Docker build.

#### Console Database Migrations

Console uses **Docker entrypoint-based migrations** using golang-migrate. Migrations run
automatically on container startup before the Console server starts.

**How it works:**

1. Container starts, `entrypoint.sh` runs
2. Validates required PostgreSQL environment variables (fail-fast)
3. URL-encodes credentials to handle special characters in passwords
4. Runs `portal-migrate up` with PostgreSQL advisory locking
5. golang-migrate tracks applied versions in `schema_migrations` table
6. Console server starts after migrations complete

**Environment Variables:**

| Variable | Required | Description |
|----------|----------|-------------|
| `GVA_CONFIG_PGSQL_PATH` | Yes | PostgreSQL host |
| `GVA_CONFIG_PGSQL_PORT` | No | PostgreSQL port (default: 5432) |
| `GVA_CONFIG_PGSQL_USERNAME` | Yes | Database username |
| `GVA_CONFIG_PGSQL_PASSWORD` | Yes | Database password |
| `GVA_CONFIG_PGSQL_DBNAME` | Yes | Database name |
| `GVA_CONFIG_PGSQL_SSLMODE` | No | SSL mode (default: require) |
| `SKIP_MIGRATIONS` | No | Set to "true" to bypass migrations (debugging only) |
| `GVA_ADMIN_PASSWORD` | No | Admin user password for initial seeding |

**Migration Flow:**

```
Container Start
      │
      ▼
entrypoint.sh
      │
      ├── Validate required env vars (fail fast if missing)
      ├── Build DB connection URL (with URL-encoded credentials)
      ├── Run: portal-migrate up
      │      └── golang-migrate handles locking + versioning
      │
      ▼
Start Console server
```

**Key Features:**
- **Idempotent**: Safe to run multiple times (skips already-applied migrations)
- **Concurrent-safe**: PostgreSQL advisory locking prevents race conditions
- **Version tracking**: `schema_migrations` table tracks applied versions
- **Security**: URL-encoding handles special characters, backticks encoded to prevent injection

#### Two-Part Database Seeding

Console uses a two-part seeding approach:

1. **auto_init.go** (Go code, runs at Console startup):
   - Creates admin user, authorities, and links them
   - Triggered by `GVA_AUTO_INIT=true` environment variable
   - Idempotent - skips if admin user already exists

2. **user_data.sh.tpl** (Terraform, runs at EC2 boot):
   - Seeds the "console" resource in `portal_sites` table
   - Required for NHP `auth_code` flow after Console login
   - Runs after Console container is healthy

**Why Two Parts?**
- auto_init.go doesn't know the Console's internal URL (needed for `AuthUrl` in portal_sites)
- Terraform knows the infrastructure details (internal NLB endpoint, domain, etc.)
- Separating concerns: Go handles app-level seeding, Terraform handles infra-aware seeding

#### Console auth_code Flow (NHP Integration)

After a user logs into Console, the frontend calls NHP Server to acquire NHP tokens:

```
1. User logs in → Console API returns JWT token (x-token)
2. Frontend calls: /plugins/passcode?resid=console&action=auth_code&code={jwt}
3. NHP Server passcode plugin:
   a. Calls Console API to get "console" resource from portal_sites
   b. Gets AuthUrl from resource's ext_info
   c. Calls AuthUrl (Console's /ps/custom_auth_api) with JWT to validate
   d. If valid, performs NHP knock and returns nhp_token cookies
4. Frontend redirects to protected resource with nhp_token
```

**portal_sites "console" Resource Configuration:**

| Field | Value | Description |
|-------|-------|-------------|
| `app_id` | `console` | Resource ID used in `resid=console` |
| `jwt_secret` | Console's signing key | Must match `jwt.signing-key` in config.yaml |
| `ext_info.AuthUrl` | `http://{console-internal}/ps/custom_auth_api` | Token validation endpoint |
| `ext_info.AppSecret` | Random secret | Shared secret for validation |
| `ext_info.Method` | `GET` | HTTP method for AuthUrl call |

**The `/ps/custom_auth_api` Endpoint:**

Console has a public endpoint at `/ps/custom_auth_api` that validates JWT tokens:
- Accepts: `?code={jwt}&secret={app_secret}&state={optional}`
- Validates the secret matches configured AppSecret
- Parses and validates the JWT using Console's signing key
- Returns: `{code: 0, message: "username"}` on success

This endpoint is defined in `console/server/router/portals/sys_portal_sites.go`.

### Cross-Account Route 53

The `qurl.link` and `qurl.site` zones are in the layerv-mgmt account (165115313779).
For ACME DNS-01 challenges and DNS record management:

1. Demo Gateway and Console EC2 instances assume `cross_account_route53_role_arn`
2. This role grants `route53:ChangeResourceRecordSets` on the target zones
3. certbot uses the role for DNS-01 challenges

---

## Infrastructure (AWS)

**IMPORTANT:** LayerV has TWO distinct infrastructure setups that must not be confused:

1. **Manually Provisioned (Legacy)** - EC2 instances created manually, used by current production demo
2. **Terraform-Managed (infra/)** - IaC-managed infrastructure with ASGs, etcd, proper CI/CD

The website demo at `layerv.ai/demo` currently uses the **manually provisioned** infrastructure.

---

### Manually Provisioned Infrastructure (Current Demo)

This legacy setup powers the live demo at https://layerv.ai/demo. It was created manually before
Terraform was adopted and has different conventions than the Terraform-managed infrastructure.

**Components:**

| Component | Instance IDs | Count |
|-----------|-------------|-------|
| NHP Servers | i-0d95881613f4dc5d9, i-00a8e903787a30358, i-0b2cb267606dfcec0 | 3 |
| NHP ACs | i-00c3328ca9bdb6c8b, i-0c54485f3227b0dcd, i-0eaa92076a0c6481c | 3 |
| Console API | Runs on AC at 172.31.26.100:8888 | 1 |

**Load Balancers:**

| NLB Name | DNS | Handles |
|----------|-----|---------|
| `nlb-secure-layerv-xyz` | - | qurl.link, home.secure.layerv.xyz → NHP Servers |
| `nlb-apps-layerv-xyz` | - | *.qurl.site → NHP ACs (Traefik) |

**Directory Structure (Manually Provisioned):**
```
/home/ubuntu/nhp-server/          # NHP Server installation
/home/ubuntu/nhp-server/plugins/  # Plugin directories (passcode, etc.)
/home/ubuntu/nhp-server/logs/     # Server logs
/etc/nginx/sites-enabled/         # nginx configs (qurl.link, *.secure.layerv.xyz)
```

**Key Differences from Terraform-managed:**
- No etcd - configuration is static files
- No ASG - fixed EC2 instances
- Console API runs on ONE AC instance only (172.31.26.100)
- nginx runs on NHP Servers (not Traefik)
- Different directory paths (/home/ubuntu vs /opt/layerv)

---

### Terraform-Managed Infrastructure (infra/)

Modern IaC-managed infrastructure with proper scaling, etcd for dynamic config, and CI/CD integration.

**Environments:**

| Property | Sandbox | Production |
|----------|---------|------------|
| AWS Account | 767397897469 | (different) |
| Region | us-east-2 | us-east-2 |
| VPC CIDR | 10.100.0.0/16 | (different) |
| Server ASG | `layerv-nhp-sandbox-server-asg` | `layerv-nhp-prod-server-asg` |
| AC ASG | `layerv-nhp-sandbox-ac-asg` | `layerv-nhp-prod-ac-asg` |
| etcd (ECS) | `etcd.nhp.sandbox.internal:2379` | `etcd.nhp.prod.internal:2379` |
| NLB | `layerv-nhp-sandbox-nlb` | `layerv-nhp-prod-nlb` |

**Directory Structure (Terraform-managed):**
```
/opt/layerv/nhp-server/etc/       # Server config
/opt/layerv/nhp-server/etc/tls/   # etcd TLS certs
/opt/layerv/nhp-ac/etc/           # AC config
/opt/layerv/nhp-ac/logs/          # AC logs
/opt/layerv/etcd/certs/           # etcd certs (alternative location)
```

**Key Features:**
- etcd for dynamic AC registration and configuration
- ASGs with launch templates for scaling
- Immutable deployments via Docker image tags
- CI/CD pipeline with canary deployments
- Per-AC cryptographic keys stored in Secrets Manager

---

### Network Architecture (Terraform-managed)

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
                          │   (ECS Fargate) │
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
```

### Per-AC Key Architecture (Security)

**Private keys are NEVER stored in etcd.** Each AC instance:
1. Generates Curve25519 keypair on first boot
2. Stores private key in AWS Secrets Manager (`{prefix}-ac-{instance-id}`)
3. Registers only the public key in etcd

### AC Startup Flow

1. AC instance starts
2. Generates Curve25519 keypair (or retrieves from Secrets Manager if reboot)
3. Stores private key in Secrets Manager
4. Registers public key in etcd at `/nhp/ac-registry/{instance-id}`
6. Loads local `config.toml` (with private key reference)
7. Connects to etcd, loads server peers from `/nhp/config`
8. Dials out to NHP servers

### Server-Side AC Trust

The NHP server dynamically discovers ACs by watching `/nhp/ac-registry/` prefix:

1. On startup, loads all existing registry entries
2. Adds ACs as trusted peers based on their public key
3. Watches for new registrations/deletions and reconciles

**Security**: etcd access is protected by mTLS client certificates. Only instances with valid
certificates (provisioned by Terraform) can register. The server trusts AC public keys registered
in etcd because etcd access itself is authenticated.

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

### Immutable Deployments

Docker images are tagged with the commit SHA (`TF_VAR_image_tag`), not just `latest`. This ensures:
- Each deployment creates a new launch template version (because user_data changes)
- Instance refresh correctly detects which instances need replacement
- Rollbacks are straightforward—just deploy a previous commit SHA

The workflow passes `TF_VAR_image_tag=${{ github.sha }}` to Terraform, which flows through
to the user_data scripts that pull the specific image version.

### Known Issues

**Canary Timing:**
When validation runs after canary deploy, NLB can route to any instance (old or new).
E2E tests mitigate this by testing the live system regardless of which instance handles
the request—they create new portal sites, so they verify current behavior.

---

## Debugging & Operations

### Component Dependency Chain

Understanding the startup dependencies helps diagnose failures:

```
etcd cluster running
    ↓
AC starts, generates keypair, registers in etcd (/nhp/ac-registry/{instance-id})
    ↓
Server watches etcd, discovers AC, adds to trusted peers
    ↓
AC dials out to Server (UDP 62206)
    ↓
Server recognizes AC's public key → NHP-AOL/NHP-AAK handshake succeeds
    ↓
System operational: Server can send NHP-AOP to AC on knock requests
```

**If any step fails, the chain breaks.** Common failure points:
- etcd not running → AC can't register → Server doesn't know about AC
- AC missing etcd certs → AC can't connect to etcd
- Key mismatch → ECDH handshake fails

### Log Locations

**AC runs as a native binary** with file-based logs.
**Server runs in Docker** with logs written to files INSIDE the container (not stdout).

**IMPORTANT:** Server logs are NOT available via `docker logs`. The NHP logging library writes to
files at `/nhp-server/logs/server-{date}.log` inside the container. Use `docker exec` to read them.

**Via SSM (recommended for remote diagnosis):**
```bash
# AC logs - file-based (instance ID from ASG)
AWS_PROFILE=layerv aws ssm send-command \
  --instance-ids i-XXXXXXXXX \
  --document-name "AWS-RunShellScript" \
  --parameters 'commands=["tail -100 /opt/layerv/nhp-ac/logs/ac-$(date +%Y-%m-%d).log"]' \
  --output json | jq -r '.Command.CommandId'

# Then get output:
AWS_PROFILE=layerv aws ssm get-command-invocation \
  --command-id XXXXXXXX \
  --instance-id i-XXXXXXXXX \
  --output json | jq -r '.StandardOutputContent'

# Server logs - INSIDE Docker container (NOT docker logs!)
AWS_PROFILE=layerv aws ssm send-command \
  --instance-ids i-XXXXXXXXX \
  --document-name "AWS-RunShellScript" \
  --parameters 'commands=["docker exec nhp-server cat /nhp-server/logs/server-$(date +%Y-%m-%d).log | tail -100"]'
```

**Directly on instance (if SSH/SSM shell access):**
```bash
# AC logs (native binary, file-based)
tail -f /opt/layerv/nhp-ac/logs/ac-$(date +%Y-%m-%d).log
# Also check evaluate logs
tail -f /opt/layerv/nhp-ac/logs/ac-evaluate-$(date +%Y-%m-%d).log

# Server logs - MUST use docker exec (logs are inside container, not stdout)
docker exec nhp-server tail -f /nhp-server/logs/server-$(date +%Y-%m-%d).log

# Also check evaluate and audit logs
docker exec nhp-server ls -la /nhp-server/logs/

# Check if services are running
systemctl status nhp-acd    # AC runs via systemd as native binary
systemctl status nhp-server # Server runs via systemd managing Docker
docker ps | grep nhp        # Only shows nhp-server, AC is not containerized
```

**File locations on instances:**
| Component | Runtime | Config Dir | Log Location |
|-----------|---------|------------|--------------|
| AC | Native binary | `/opt/layerv/nhp-ac/etc/` | `/opt/layerv/nhp-ac/logs/ac-{date}.log` |
| Traefik | Native binary | `/home/ubuntu/traefik/` | N/A (uses stdout/journald) |
| Server | Docker container | `/opt/layerv/nhp-server/etc/` | `/nhp-server/logs/server-{date}.log` (inside container) |
| Server etcd certs | Docker container | `/opt/layerv/nhp-server/etc/tls/` | N/A |
| AC etcd certs | Native binary | `/opt/layerv/nhp-ac/etc/tls/` | N/A |

### Common Issues

| Symptom | Likely Cause | Check |
|---------|--------------|-------|
| AC logs "accept iptables input" | Cannot reach any server | Server NLB DNS, security groups |
| AC logs "device ECDH failed with peer" | Key mismatch between AC and Server | See "ECDH Key Mismatch" below |
| Knock succeeds but can't access | AC not receiving AOP | AC-Server connection, key mismatch |
| Protected site shows login | Token expired or IP changed | Cookie expiry, refresh flow |
| 502 on protected resource | Upstream unreachable | Traefik config, target health |
| 502 on /plugins/* | NHP Server HTTP unreachable | See "NHP Server HTTP Troubleshooting" below |
| AC can't connect to etcd | Missing certs or etcd down | See "etcd Troubleshooting" below |
| Server logs "Reconciling AC peers: 0 entries" | No ACs in etcd registry | Check AC registration in etcd |
| Server no `remote.toml` | Server can't discover ACs via etcd | See "Server etcd Configuration" below |

### ECDH Key Mismatch

**Error:** `[NHP-AOL] message randomization failed: device ECDH failed with peer`

This means the AC's cryptographic handshake with the Server failed. Causes:

1. **Server doesn't know about AC** - No `ac.toml` or AC not in etcd registry
2. **Key mismatch** - AC's public key doesn't match what Server expects
3. **etcd not working** - AC can't register, Server can't discover ACs

**Diagnosis:**
```bash
# On Server: Check if ac.toml exists and has entries
cat /opt/layerv/nhp-server/etc/ac.toml

# On AC: Check server.toml has correct server public key
cat /opt/layerv/nhp-ac/etc/server.toml

# Check etcd AC registry (from any instance with etcdctl)
ETCDCTL_API=3 etcdctl --endpoints=https://etcd.nhp.sandbox.internal:2379 \
  --cacert=/path/to/ca.crt --cert=/path/to/client.crt --key=/path/to/client.key \
  get /nhp/ac-registry/ --prefix --keys-only
```

### etcd Troubleshooting

**Check if etcd is reachable:**
```bash
# DNS resolution
nslookup etcd.nhp.sandbox.internal

# Check if anything is listening (from AC/Server instance)
curl -v --cacert /opt/layerv/etcd/certs/ca.crt \
  --cert /opt/layerv/etcd/certs/client.crt \
  --key /opt/layerv/etcd/certs/client.key \
  https://etcd.nhp.sandbox.internal:2379/health

# Check etcd ECS task (etcd runs in ECS, NOT EC2)
AWS_PROFILE=layerv aws ecs list-tasks --cluster layerv-nhp-sandbox-etcd \
  --query 'taskArns' --output text

# Get etcd task details
AWS_PROFILE=layerv aws ecs describe-tasks --cluster layerv-nhp-sandbox-etcd \
  --tasks $(aws ecs list-tasks --cluster layerv-nhp-sandbox-etcd --query 'taskArns[0]' --output text) \
  --query 'tasks[*].{Status:lastStatus,IP:attachments[0].details[?name==`privateIPv4Address`].value|[0]}' --output table

# Check etcd ECS service
AWS_PROFILE=layerv aws ecs describe-services --cluster layerv-nhp-sandbox-etcd \
  --services etcd --query 'services[*].{Name:serviceName,Desired:desiredCount,Running:runningCount}'
```

**Common etcd issues:**
- No etcd tasks running → Check ECS service, task definition
- DNS resolves but connection fails → etcd crashed, check etcd logs
- Cert errors → Missing `/opt/layerv/etcd/certs/` on AC, check Terraform/user-data

### Server etcd Configuration

**Error:** Server logs "AC registry discovery disabled" or Server has no ACs.

The Server needs `remote.toml` to connect to etcd and discover ACs dynamically. Without it, the Server cannot watch `/nhp/ac-registry/` and will have zero trusted ACs.

**Required files on Server (`/opt/layerv/nhp-server/etc/`):**
```
config.toml       # Base config (always required)
http.toml         # HTTP server settings
remote.toml       # etcd connection (required for AC registry)
tls/ca.crt        # etcd CA certificate
tls/client.crt    # etcd client certificate (mTLS)
tls/client.key    # etcd client key (mTLS)
```

**Verify Server has etcd config:**
```bash
# Check if remote.toml exists
docker exec nhp-server cat /nhp-server/etc/remote.toml

# Check if TLS certs exist
docker exec nhp-server ls -la /nhp-server/etc/tls/

# Check Server logs for etcd connection
docker exec nhp-server cat /nhp-server/logs/server-$(date +%Y-%m-%d).log | grep -i etcd
```

**If missing:** The Terraform user_data template should create `remote.toml` when `multi_tenant=true`
and `etcd_endpoint` is configured. Check `terraform/modules/compute/user_data.sh.tpl`.

### NHP Server HTTP Troubleshooting

**Error:** 502 Bad Gateway when accessing `/plugins/*` on AC.

The AC Traefik routes `/plugins/*` to NHP Server HTTP. If this fails, check:

**1. Verify NHP Server HTTP is listening:**
```bash
# Find NHP Server instance
AWS_PROFILE=layerv aws autoscaling describe-auto-scaling-groups \
  --auto-scaling-group-name layerv-nhp-sandbox-server \
  --query "AutoScalingGroups[0].Instances[0].InstanceId" --output text

# Check what port HTTP is listening on (via SSM)
AWS_PROFILE=layerv aws ssm send-command --instance-ids i-XXXXX \
  --document-name "AWS-RunShellScript" \
  --parameters 'commands=["ss -tlnp | grep -E \"8080|8888\""]'
```

**Port Configuration:**
- NHP Server HTTP listens on port 8888 (configured in both http.toml and etcd)
- AC Traefik routes `/plugins/*` to `http://server.nhp.sandbox.internal:8888`

**2. Check security group allows port 8888:**
```bash
# NHP Server SG should allow TCP 8888 from VPC CIDR
AWS_PROFILE=layerv aws ec2 describe-security-groups \
  --filters "Name=group-name,Values=*nhp*server*" \
  --query "SecurityGroups[0].IpPermissions[?FromPort==\`8888\`]"
```

**3. Check AC Traefik config:**
```bash
# On AC instance - verify /plugins route exists
cat /home/ubuntu/traefik/dynamic.toml | grep -A5 "nhp-plugins"
# Should show: url = "http://server.nhp.sandbox.internal:8888"
```

**4. Test connectivity from AC to NHP Server:**
```bash
# On AC instance
curl -s http://server.nhp.sandbox.internal:8888/health
# 404 is OK (means HTTP is responding), timeout/connection refused is bad
```

### SSM Diagnostic Commands

Quick health check script (run via SSM):
```bash
# Find instances
AWS_PROFILE=layerv aws ec2 describe-instances \
  --filters "Name=tag:Name,Values=*sandbox*" "Name=instance-state-name,Values=running" \
  --query 'Reservations[*].Instances[*].{Id:InstanceId,Name:Tags[?Key==`Name`]|[0].Value,IP:PrivateIpAddress}' \
  --output table

# AC health check
AWS_PROFILE=layerv aws ssm send-command --instance-ids i-XXXXX \
  --document-name "AWS-RunShellScript" \
  --parameters 'commands=[
    "echo === Process Status ===",
    "ps aux | grep nhp-ac | grep -v grep || echo AC not running",
    "echo",
    "echo === Recent Logs ===",
    "tail -20 /opt/layerv/nhp-ac/logs/*.log 2>/dev/null || echo No logs",
    "echo",
    "echo === etcd Connectivity ===",
    "curl -s --max-time 5 --cacert /opt/layerv/etcd/certs/ca.crt --cert /opt/layerv/etcd/certs/client.crt --key /opt/layerv/etcd/certs/client.key https://etcd.nhp.sandbox.internal:2379/health 2>&1 || echo etcd unreachable",
    "echo",
    "echo === Config Files ===",
    "ls -la /opt/layerv/nhp-ac/etc/"
  ]'

# Server health check
AWS_PROFILE=layerv aws ssm send-command --instance-ids i-XXXXX \
  --document-name "AWS-RunShellScript" \
  --parameters 'commands=[
    "echo === Docker Status ===",
    "docker ps | grep nhp-server || echo Server container not running",
    "echo",
    "echo === Listening Ports ===",
    "ss -tuln | grep -E \"(62206|8888)\"",
    "echo",
    "echo === Config Files ===",
    "ls -la /opt/layerv/nhp-server/etc/",
    "echo",
    "echo === AC Config (known ACs) ===",
    "cat /opt/layerv/nhp-server/etc/ac.toml 2>/dev/null || echo No ac.toml - Server has no known ACs!"
  ]'
```

### Target Group Health

```bash
# Find AC target group
AWS_PROFILE=layerv aws elbv2 describe-target-groups \
  --query 'TargetGroups[?contains(TargetGroupName, `sandbox-ac`)].{Name:TargetGroupName,ARN:TargetGroupArn}' --output json

# Check target health
AWS_PROFILE=layerv aws elbv2 describe-target-health \
  --target-group-arn "arn:aws:elasticloadbalancing:..." --output table
```

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
| `ac.toml` | Server | AC peer definitions (static, not used with etcd registry) |
| `server.toml` | AC | Server peer definitions |
| `http.toml` | Server | HTTP server settings |
| `remote.toml` | Server/AC | etcd connection settings (required for AC registry) |
