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
- Reads AC assignments from storage backend (DynamoDB or etcd)

**Key Files:**
| File | Purpose |
|------|---------|
| `main.go` | Entry point |
| `udpserver.go` | UDP knock handler |
| `httpserver.go` | HTTP knock handler, plugin routing |
| `config.go` | Configuration loading |
| `storage.go` | Storage backend interface |
| `dynamodb_storage.go` | DynamoDB storage implementation |
| `etcd_storage.go` | etcd storage implementation (on-prem) |
| `cloudmap.go` | Cloud Map health discovery for stale assignment filtering |
| `msghandler.go` | NHP message processing |
| `requestid.go` | Request ID middleware (OTEL trace correlation) |

**HTTP Middleware Chain** (`httpserver.go`):

The Gin middleware chain order matters. When OTEL tracing is added, the OTEL
middleware (e.g., `otelgin`) **must** be registered before `requestIDMiddleware`
so that the span context is available for trace ID extraction.

```
1. [OTEL middleware]      ← must come first if/when added (not yet configured)
2. requestIDMiddleware    ← extracts trace ID from span context or traceparent header
3. sessions
4. CORS
5. gin.Logger
6. gin.Recovery
```

The request ID resolution priority is: OTEL span context > W3C `traceparent`
header > client `X-Request-ID` header > random generation. See `requestid.go`.

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

> **Note:** The AC daemon does NOT interact with storage backends (DynamoDB/etcd).
> It only connects to NHP Servers listed in its config file. Console manages AC assignments.

**Key Files:**
| File | Purpose |
|------|---------|
| `main.go` | Entry point |
| `udpac.go` | UDP communication with server, connection maintenance |
| `httpac.go` | HTTP refresh endpoint |
| `config.go` | Configuration loading |
| `msghandler.go` | NHP message processing, iptables updates |

**HTTP Routes (via Traefik on 443):**
```
GET /refresh/:token?srcip=X.X.X.X - Refresh access for new IP
```

**Does NOT Listen** for incoming UDP connections—always dials out.

#### AC Registration Flow

ACs must be trusted by the NHP Server before they can receive NHP_AOP (open port) commands.
The trust establishment mechanism differs between cloud and on-prem deployments:

**Cloud Mode (DynamoDB storage backend):**

In cloud deployments, AC trust is established via **license validation**, not pre-registration:

```
┌──────────────────┐     1. NHP_AOL + license  ┌─────────────┐
│     nhp-acd      │ ─────────────────────────►│ NHP Server  │
│   (AC daemon)    │    credentials            │             │
│                  │                           │   2. Validate
│                  │                           │   license vs
│                  │◄─────────────────────────│   DynamoDB
└──────────────────┘     3. NHP_ARD/NHP_AAK    │             │
                         (redirect or ack)     │   4. Add to │
                                               │   peer map  │
                                               └─────────────┘
```

The AC sends `CustomerId`, `LicenseKey`, and `ResourceFQDN` in NHP_AOL.
Server validates against `nhp-licenses` table in DynamoDB. If valid, the AC's
public key (from the NHP_AOL packet) is added to the peer map dynamically.
See `docs/design/PLUGGABLE_STORAGE_BACKEND.md` Section 6.2 for details.

For details on AC registration robustness (handling socket recreation, stale
connections, and re-registration), see `docs/design/AC_REGISTRATION_ROBUSTNESS.md`.

**On-Prem Mode (etcd storage backend):**

In on-prem deployments, AC trust is established via **etcd pre-registration**:

```
┌──────────────────┐     1. Write AC entry     ┌─────────────┐
│  user_data.sh    │ ─────────────────────────►│    etcd     │
│  (on EC2 boot)   │   /nhp/ac-registry/{id}   │             │
└──────────────────┘                           └──────┬──────┘
                                                      │
                                               2. Watch prefix
                                                      │
┌──────────────────┐     3. NHP_AOL            ┌──────▼──────┐
│     nhp-acd      │ ─────────────────────────►│ NHP Server  │
│   (AC daemon)    │                           │             │
│                  │◄─────────────────────────│  (has AC    │
└──────────────────┘     4. NHP_ARD/NHP_AAK    │  in peer    │
                         (redirect or ack)     │  map)       │
                                               └─────────────┘
```

The AC's `user_data.sh.tpl` writes a TOML entry to etcd containing:
- Instance ID
- Public key (Curve25519, base64)
- IP address and port

The NHP Server watches `/nhp/ac-registry/` prefix and adds recognized ACs to its peer map.

**Customer-Deployed ACs** (future):

For ACs deployed in customer environments (not LayerV infrastructure), a Registration Token
model is planned. See `docs/MULTI_TENANT_REGISTRATION_API.md` for the design (not yet implemented).

---

#### Agent Peer Registry (Cloud Mode)

In cloud deployments, agent trust is established via **DDB+LRU lookup on first knock**,
not pre-registration (parallel to the AC `license validation` path above):

```
┌──────────────┐    1. NHP knock                    ┌─────────────┐
│  nhp-agent   │ ─────────────────────────────────►│ NHP Server  │
│              │    (responder runs with             │  (cloud     │
│              │     DisableAgentPeerValidation=     │   mode)     │
│              │     true so unknown-but-registered  │             │
│              │     agent reaches HandleKnockRequest)│             │
└──────────────┘                                    └──────┬──────┘
                                                           │
                                                  2. AgentPeerLookup
                                                     (LRU miss)
                                                           │
                                                           ▼
                                                  ┌─────────────┐
                                                  │ DynamoDB    │
                                                  │ qurl-agent- │
                                                  │ keys table  │
                                                  │ pubkey-index│
                                                  │ GSI         │
                                                  └──────┬──────┘
                                                         │
                                                  3. AddAgentPeer →
                                                     agentPeerMap +
                                                     device.peerMap
                                                  4. Subsequent knocks
                                                     short-circuit on
                                                     agentPeerMap
```

See `endpoints/server/agent_peer_lookup.go` for the implementation contract.

##### Revocation horizon

The 60s LRU TTL on `AgentPeerLookup` is **a cache TTL, not a revocation horizon.**
Once a knock succeeds, `resolveAgentPeerForKnock` writes the resolved peer into
`UdpServer.agentPeerMap`, which has no TTL and no eviction path. Every subsequent
knock from that pubkey short-circuits there before the LRU is consulted. So:

- An agent registered in DDB before a deleted-row revocation continues to be
  admitted **until the nhp-server process restarts** (typically the next ASG
  rolling refresh — hours, not seconds).
- The LRU TTL only bounds how long a cached resolve survives between LRU-miss
  lookups; it is not the revocation horizon for a registered agent.

Active-knock revocation across a running process is tracked as issue #1943.
Passive revocation (process restart) flushes both caches.

**Operational implication for ops:** when revoking an agent from `qurl-agent-keys`,
trigger an ASG instance refresh in the same operation if the agent is currently
trusted by any running server — without the refresh, the agent stays trusted on
existing instances until they cycle.

##### Cross-tenant pubkey uniqueness (deferred-mitigation)

Pubkey uniqueness in `qurl-agent-keys` is enforced **only by a writer-side soft
check** in qurl-service (`internal/repository/dynamodb/agent_keys_repo.go::Upsert`):
on every write, the writer reads the `pubkey-index` GSI; if the pubkey is already
registered to a different `owner_id`, it emits a WARN log and **proceeds with the
write**. The check is eventually consistent (GSI is eventually consistent), so
there is a false-negative window during a tight squat race.

**Auth implication:** an attacker who wins the writer-side soft-uniqueness race
against a victim tenant can register the victim's pubkey under their own
`owner_id`. The reader (`AgentPeerLookup`) admits whichever row DDB returns
first (`Items[0]`), so subsequent agent requests with that pubkey **can be
attributed to the wrong `owner_id`** until the squatter's row is removed.
Multi-tenant separation at the qurl-service auth layer cannot reverse this from
the cached peer alone — the reader-side observation is "pubkey X → admit," not
"pubkey X belongs to owner Y."

**Defense-in-depth signals today:**

- `AgentPeerLookup.queryAndCache` issues the GSI Query with `Limit=2` (not
  `Limit=1`) and emits `MetricAgentLookupPubkeyCollision` + a WARN log whenever
  `Items > 1`. This is a forensic signal, not a fix — the resolver still admits
  `Items[0]`.
- The hard fix is tracked in qurl-service issue #488 (TransactWriteItems against
  a claims sidecar table to enforce true uniqueness at write time).

**Detection has a temporal blind spot.** The collision metric / WARN only fires
inside `queryAndCache`, which runs ONLY on the LRU-miss path. Once a pubkey is
pinned in `UdpServer.agentPeerMap` (no TTL, no eviction), every subsequent knock
from that agent short-circuits at the `alreadyKnown` check in
`resolveAgentPeerForKnock` and the DDB lookup never reruns. Consequence:

- A cross-tenant squat that lands *before* the victim's first knock is observable
  (both rows are visible at first-resolve time, the WARN fires).
- A cross-tenant squat that lands *after* the victim's first knock — the more
  realistic attack window — is NOT observable by the reader. The victim's
  resolution is already pinned; subsequent knocks short-circuit before the GSI
  Query. The squatter only becomes visible on the *next* process restart (or if
  active-knock revocation #1943 ever lands and evicts the pin).

For the post-first-knock attack window, the only signal today is the writer-side
WARN log in qurl-service (`Upsert`'s soft-uniqueness check) — same forensic
limitation as the reader's, scoped to the qurl-service log stream.

Until #488 lands, operators monitoring the cross-tenant attack class should watch
the `MetricAgentLookupPubkeyCollision` counter (covers the pre-first-knock window
only) AND the qurl-service writer-side WARN log (covers the post-first-knock
window). An alarm on this metric — and on the four sibling agent-lookup
metrics — is tracked in nhp issue #1955; the counters themselves ship in PR
#1833.

---

#### Stale Assignment Resilience

When NHP Servers terminate (ASG scale-down, instance refresh, crash), DynamoDB AC assignments
pointing to that server become **stale**. Without mitigation, this causes ACs to be redirected
to dead servers in a failure loop.

**Three-Layer Defense:**

| Layer | Mechanism | Cleanup Time | Enable Via |
|-------|-----------|--------------|------------|
| **Immediate** | ASG lifecycle hook + Lambda | Instant (before termination) | `enable_termination_cleanup = true` |
| **Proactive** | Console health monitor (GSI-based) | 60-90s | Always enabled |
| **Real-time** | NHP Server health filtering | Per-registration | Always enabled (requires Cloud Map) |

**NHP Server Health Filtering (`endpoints/server/cloudmap.go`):**

Before sending an NHP_ARD redirect, the server verifies assigned servers are healthy:

1. Query Cloud Map for currently healthy server IPs (30s cache TTL)
2. Filter assignment's `AssignedServers` to only include healthy ones
3. If NO healthy servers remain → accept AC directly (NHP_AAK), breaking the failure loop
4. If SOME healthy servers remain → send NHP_ARD with filtered list

```
AC ──► NHP Server ──► Check Cloud Map ──► Filter assignment ──► NHP_ARD (or NHP_AAK if all dead)
```

**Fail-Open Design:**
- If Cloud Map is unavailable, all servers are considered healthy (prevents blocking)
- Uses separate 5s timeout context to avoid cascading timeouts from DynamoDB

**Console Health Monitor (`console/server/service/nhp/health_monitor.go`):**

The health monitor's `cleanupStaleAssignments()` function:

1. Gets set of healthy server IPs and IDs from Cloud Map
2. Scans all AC assignments from DynamoDB
3. For each assignment, checks if ANY assigned server is healthy (by IP, InternalIP, or ID)
4. If NONE are healthy → deletes the assignment (AC will re-register fresh)

**Safety Mechanisms:**
- **Fail-safe**: If Cloud Map returns no healthy servers, skip cleanup entirely (likely Cloud Map issue)
- **Grace period**: Skip recently reassigned assignments (5 min) to prevent race conditions
- **Batch deletes**: Uses DynamoDB BatchWriteItem for efficient bulk deletion

**ASG Lifecycle Hook + Lambda (`terraform/modules/compute/`):**

For immediate cleanup before server termination completes:

1. ASG termination triggers lifecycle hook (pauses termination for up to 5 min)
2. EventBridge rule captures lifecycle event
3. Lambda function executes:
   - Queries `server-ac-index` GSI for all ACs assigned to terminating server
   - Updates each assignment to remove the server from `assigned_servers`
   - Deletes assignments with no remaining servers
   - Cleans up index entries
   - Completes lifecycle action (allows termination to proceed)

**Enable via Terraform:**
```hcl
enable_termination_cleanup = true
```

**Key Files:**
- `terraform/modules/compute/lambda/server_termination_cleanup.py` - Lambda function
- `terraform/modules/compute/main.tf` - Lifecycle hook, EventBridge, IAM

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

Packer templates build AMIs for NHP components:

| Template | Purpose | Distribution |
|----------|---------|--------------|
| `nhp-ac.pkr.hcl` | AC with Traefik plugins | **AWS Marketplace** |
| `nhp-server.pkr.hcl` | NHP Server (native binary) | Internal only |
| `nhp-server-docker.pkr.hcl` | NHP Server (Docker runtime) | **Required for Terraform** |

**NHP Server Docker AMI (Required):**

Terraform-managed infrastructure requires the Docker-optimized AMI. Without it,
Terraform fails at plan time — there is no fallback to vanilla Ubuntu.

```bash
# Build and publish AMI (one-time setup per environment)
cd packer
packer init nhp-server-docker.pkr.hcl
AWS_PROFILE=layerv packer build -var 'environment=sandbox' nhp-server-docker.pkr.hcl
```

The AMI ID is automatically published to SSM Parameter Store
(`/{env}/nhp/server/ami-id`). Terraform reads from this parameter.

**AC AMI for Marketplace:**

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
Environment = "sandbox"       # Environment name for CloudWatch metrics (e.g., "sandbox", "prod"). Defaults to "unknown" if omitted.

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
    ├── qurl.link ────────► CloudFront ──► S3 (redirect page)
    │                            │
    │                            ▼
    │   resolve.qurl.link ──► NHP Server NLB:443 ──► Server:8888 (QURL plugin)
    │
    └── *.qurl.site ─────────► AC NLB:443 ──► Traefik ──► Protected Resource
```

---

## QURL Link Architecture

The QURL Link system provides secure, tokenized access to protected resources. Users receive a link
that initiates NHP authentication before granting access. Legacy environments use a plaintext
`#at_...` fragment; JS-agent environments use a `#qv1.<bundle>` fragment containing the qURL access
token, qURL-scoped NHP agent private key, NHP server public key, relay origin, and auth service ID.

### Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              CloudFront                                      │
│   Domain: qurl.link                                                         │
│   Origin: S3 bucket (static redirect page)                                  │
│   Purpose: Serves HTML that extracts token and redirects to resolve endpoint│
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ JavaScript redirect with token
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           NHP Server NLB                                     │
│   Domain: resolve.qurl.link                                                 │
│   Listener: TLS 443 → TCP 8888                                              │
│   Security: CloudFront IPs only (AWS managed prefix list)                   │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           NHP Server                                         │
│   Endpoint: /plugins/qurl (port 8888)                                       │
│   Actions:                                                                  │
│   1. Validate token with QURL Service API                                   │
│   2. Send NHP knock to AC (open firewall for user's IP)                     │
│   3. Redirect user to protected resource (*.qurl.site)                      │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              AC NLB                                          │
│   Domain: *.qurl.site                                                       │
│   Listener: TLS 443 → Traefik                                               │
│   Note: Port 443 blocked by iptables until NHP knock authenticates          │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Authentication Flow

```
1. User clicks link: qurl.link/#qv1.<bundle>
        │
        ▼
2. CloudFront serves S3 redirect page
        │
        ▼
3. JavaScript extracts the bootstrap bundle, clears the fragment, and knocks
   the relay with the qURL-scoped NHP agent key
        │
        ▼
4. NHP Server validates the token and authenticated agent public key with QURL Service API
        │
        ▼
5. NHP Server opens access on the AC
        │
        ▼
6. NHP Server redirects user to: {appId}.qurl.site
        │
        ▼
7. AC allows connection (IP now in ipset)
        │
        ▼
8. User accesses protected resource
```

### Why resolve.qurl.link Routes to NHP Server (not AC)

The AC implements zero-trust networking: **port 443 is blocked by iptables until NHP knock
authenticates the user**. However, `resolve.qurl.link` must be accessible *before* authentication
to initiate the NHP knock. Therefore:

- `resolve.qurl.link` → NHP Server NLB (always accessible)
- `*.qurl.site` → AC NLB (blocked until authenticated)

### Security Model

| Layer | Protection |
|-------|------------|
| CloudFront | DDoS protection, edge caching |
| NHP Server NLB | Security group restricts to CloudFront IPs only |
| QURL Plugin | Token validation, rate limiting |
| AC | Zero-trust iptables, only authenticated IPs allowed |

### Terraform Modules

| Module | Purpose |
|--------|---------|
| `qurl-link` | CloudFront + S3 for redirect page |
| `qurl-service` | ECS Fargate API for token management |
| `compute` | NHP Server NLB with TLS listener for resolve endpoint |
| `ac` | AC NLB for protected resources |

---

## Demo Gateway Architecture (Legacy)

The Demo Gateway provides TLS termination and routing for the demo flow, bridging qurl.link traffic
to the NHP Server's HTTP plugin endpoints.

### Cross-Account Route 53

The `qurl.link` and `qurl.site` zones are in the layerv-mgmt account (165115313779).
For ACME DNS-01 challenges and DNS record management:

1. AC instances assume `cross_account_route53_role_arn`
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

### Storage Backend Architecture

NHP Server supports pluggable storage backends for AC assignments and other data. The storage backend
determines where AC assignment data is stored and retrieved from.

**See `docs/design/PLUGGABLE_STORAGE_BACKEND.md` for detailed design documentation.**

| Mode | Storage Backend | Use Case |
|------|-----------------|----------|
| **Cloud (default)** | DynamoDB Global Tables | AWS deployment, LayerV SaaS |
| **On-prem (feature flag)** | etcd cluster | Self-hosted, air-gapped environments |

**Configuration:**

NHP Server's `storage.toml` determines which backend to use:

```toml
# Cloud deployment (default)
Backend = "dynamodb"

# On-prem deployment
Backend = "etcd"
```

**Data Flow:**

```
┌─────────────┐      Write AC         ┌─────────────┐      Read AC        ┌─────────────┐
│   Console   │ ──────────────────────►│   Storage   │◄────────────────────│ NHP Server  │
│   (API)     │   assignments to DB    │  (DynamoDB  │   assignments       │             │
└─────────────┘                        │  or etcd)   │                     └─────────────┘
                                       └─────────────┘
                                              │
                                              │ AC daemon does NOT
                                              │ read/write storage
                                              ▼
                                       ┌─────────────┐
                                       │   NHP AC    │
                                       │  (daemon)   │
                                       └─────────────┘
```

**Key Points:**
- **Console writes** AC assignments to the storage backend
- **NHP Server reads** AC assignments from the storage backend
- **AC daemon** does NOT interact with storage - it only connects to NHP Servers

**DynamoDB Tables (Cloud Mode):**

| Table | Purpose | Key Schema |
|-------|---------|------------|
| `nhp-ac-assignments` | AC-to-server assignments | PK: `ac_id` |
| `nhp-server-ac-index` | Server-to-AC reverse index | PK: `server_id`, SK: `ac_id` |
| `nhp-licenses` | License validation | PK: `customer_id`, SK: `resource_fqdn` |
| `nhp-resources` | Resource definitions | PK: `customer_id`, SK: `resource_id` |

### etcd Keys (On-Prem Mode)

For on-prem deployments using etcd storage backend:

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

**Private keys are NEVER stored in the storage backend.** The keypair management flow:

1. **Keypair Generation**: Terraform user_data generates Curve25519 keypair on first boot
2. **Private Key Storage**: Private key stored in AWS Secrets Manager (`{prefix}-ac-{instance-id}`)
3. **Assignment Registration**: Console writes AC assignment to storage backend (DynamoDB or etcd)
4. **AC Configuration**: AC loads keypair from local config, connects to NHP Servers

### AC Startup Flow (Cloud Deployments)

For Terraform-managed cloud deployments using DynamoDB:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         AC STARTUP SEQUENCE                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  1. EC2 instance starts, user_data.sh runs                                  │
│     └── Generate Curve25519 keypair                                         │
│     └── Store keypair in Secrets Manager                                    │
│     └── Write config.toml with private key                                  │
│                                                                             │
│  2. AC assignment written to DynamoDB                                       │
│     └── (For customer ACs: happens when AC created via UI/API)              │
│                                                                             │
│  3. nhp-acd daemon starts                                                   │
│     └── Loads config.toml (private key, server list)                        │
│     └── Dials OUT to NHP Servers                                            │
│                                                                             │
│  4. NHP Server reads AC assignment from DynamoDB                            │
│     └── Validates AC's public key matches assignment                        │
│     └── AC is now trusted, can receive NHP_AOP messages                     │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Key Point:** The AC daemon does NOT write to any storage backend. It only:
- Reads its local config file
- Connects to NHP Servers listed in config
- Receives knock validations from Server

### AC Startup Flow (On-Prem Deployments)

For self-hosted deployments using etcd storage backend:

1. AC instance starts, generates keypair
2. AC registers public key in etcd at `/nhp/ac-registry/{instance-id}`
3. Loads local `config.toml`, connects to etcd for server peers
4. Dials out to NHP servers

### Server-Side AC Trust

The NHP Server reads AC assignments from the configured storage backend:

**DynamoDB (Cloud):**
1. On startup, Server connects to DynamoDB
2. Reads AC assignments from `nhp-ac-assignments` table
3. Trusts ACs based on their assignment records

**etcd (On-Prem):**
1. On startup, Server watches `/nhp/ac-registry/` prefix
2. Loads existing registry entries
3. Watches for new registrations/deletions

**Security**: For cloud deployments, DynamoDB access is controlled by IAM. Console must have
write permissions; Server only needs read. For on-prem, etcd access is protected by mTLS.

### Secrets Manager

| Secret | Purpose |
|--------|---------|
| `nhp/{env}/server-private-key` | NHP Server Curve25519 private key |
| `nhp/{env}/ac-{instance-id}` | Per-AC Curve25519 private key |
| `nhp/etcd/ca-cert` | etcd CA certificate |
| `nhp/etcd/client-cert` | etcd client certificate |
| `nhp/etcd/client-key` | etcd client key |

### Cleanup

**Cloud Deployments (DynamoDB):**

Three layers of cleanup ensure stale assignments are removed:

| Layer | Mechanism | Cleanup Time | Enable Via |
|-------|-----------|--------------|------------|
| **Immediate** | ASG lifecycle hook + Lambda | Instant (before termination) | `enable_termination_cleanup = true` |
| **Proactive** | Console health monitor (GSI-based) | 60-90 seconds | Always enabled |
| **Real-time** | NHP Server health filtering | Per-registration | Always enabled |

1. **ASG Lifecycle Hook + Lambda** (`terraform/modules/compute/lambda/`):
   - Triggered on `EC2_INSTANCE_TERMINATING` lifecycle event
   - Queries `server-ac-index` for affected assignments
   - Updates assignments to remove terminating server
   - Deletes assignments with no remaining servers
   - Completes lifecycle hook, allowing termination

2. **Console Health Monitor** (`console/server/service/nhp/health_monitor.go`):
   - GSI-based detection: tracks healthy servers, detects terminations
   - Queries only affected assignments (not full table scan)
   - Full table scan every 24h as consistency fallback
   - Deletes assignments where ALL servers are unhealthy

3. **NHP Server Health Filtering** (`endpoints/server/cloudmap.go`):
   - Filters NHP_ARD redirects to only healthy servers
   - Accepts AC directly if all assigned servers unhealthy
   - 30-second cache TTL for Cloud Map queries

> **Production recommendation**: Enable ASG lifecycle hook for immediate cleanup.
> Console health monitor and server filtering provide defense in depth.

**On-Prem Deployments (etcd):**
- **On termination**: ASG lifecycle hook triggers Lambda to delete etcd entry + secret
- **Weekly audit**: Lambda compares registry to running instances, cleans orphans

**Failopen Behavior:** If AC cannot connect to ANY NHP Server, it falls back to "accept all" mode
(allows all traffic) to prevent total lockout.

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

Docker images are tagged with the commit SHA, not just `latest`. This ensures:
- Each deployment creates a new launch template version (when user_data template changes)
- Rollbacks are straightforward—just deploy a previous commit SHA

**NHP Components (Server, AC):**
The workflow passes `TF_VAR_image_tag=${{ github.sha }}` to Terraform, which flows through
to the user_data scripts that pull the specific image version.

### Known Issues

**Canary Timing:**
When validation runs after canary deploy, NLB can route to any instance (old or new).
E2E tests mitigate this by testing the live system regardless of which instance handles
the request—they verify current behavior.

**AC user_data 16KB Limit (S3 Bootstrap):**
EC2 launch templates have a hard 16KB limit on user_data (after base64 encoding). The AC
`user_data.sh.tpl` template renders to ~53KB raw (~19KB gzip+base64), which exceeds this limit.
To work around this, the AC module uses a two-stage bootstrap:

1. The launch template's user_data contains a minimal bootstrap script (~700 bytes) that
   installs AWS CLI, downloads the full init script from S3, and `exec`s it.
2. The full rendered init script is uploaded to the plugins S3 bucket as `scripts/ac-init.sh`.
3. An `md5(local.user_data)` is embedded in the bootstrap as a comment, which triggers
   launch template version updates when the init script content changes. (Earlier
   versions referenced `aws_s3_object.init_script[0].etag` instead, but that surfaces
   the AWS provider's "inconsistent values for sensitive attribute" bug on user_data
   updates because TF's plan-time etag prediction can disagree with S3's apply-time
   etag computation. `md5(local.user_data)` is fully client-side and stable across
   plan/apply.)

If you add content to `user_data.sh.tpl`, it won't hit the 16KB limit because only the
bootstrap is in user_data. However, if you add new scripts that need to be on the instance
at boot time, upload them to S3 (like `scripts/custom-domain-cert-sync.sh`) and download
them in the init script rather than embedding them inline.

See `terraform/modules/ac/main.tf` — search for `aws_s3_object.init_script` and `BOOTSTRAP`.

---

## Observability

The system publishes metrics to CloudWatch under the `LayerV/NHP` namespace from three sources:

| Source | Metrics | How |
|--------|---------|-----|
| NHP Server (Go) | `KnockRequest`, `AuthSuccess`, `AuthFailure`, `KnockLatency`, `ServerStartupEvent`, `TransactionClosed` | `Publisher` in `endpoints/metrics/publisher.go` — counters and gauges flush every 60 s via `PutMetricData`; latency distributions and one-shot signals (startup, panic detection) emit CloudWatch Embedded Metric Format (EMF) JSON to stdout, auto-extracted at log ingestion (#1107) |
| CloudWatch Agent | `mem_used_percent`, `disk_used_percent` | Installed on Server and AC instances via user_data; config in `/opt/aws/amazon-cloudwatch-agent/etc/` |
| CI Workflows | `DeploymentEvent` | `put-metric-data` in blue-green, canary, and build-and-push workflows with Environment/Component/Strategy dimensions |

Grafana dashboards consume these metrics via a CloudWatch datasource. See `docs/grafana-dashboard-improvements.md` for the phased dashboard improvement plan and `terraform/modules/grafana-dashboards/` for dashboard JSON definitions.

### Alarms Coupled to Fleet Size

A small number of CloudWatch alarms in `terraform/modules/monitoring/` have thresholds that encode an assumption about the number of server instances in the cell. These **must be revisited during capacity-planning changes** — if you scale the fleet past its current size without retuning, the alarm either false-positives on every deploy or becomes deaf to real regressions.

| Alarm | Assumption | Must revisit when |
|-------|-----------|-------------------|
| `server-instance-restart` | Fleet of N servers × 1 start per blue/green deploy = N startup events in a 5-min window; threshold of N (with `GreaterThanThreshold`) fires on the first extra restart. Currently N=3 | Fleet grows past 3 (bump threshold to the new N) |
| `ac-peer-count-low` | Evaluation window is tuned to ride through a single blue/green AC deploy (~15 min of zero peers) with margin | Deploy cadence or AC bring-up time changes materially |

Historical note: an earlier design tried per-instance detection via metric_math `SEARCH+MAX` (#1099, #1108). AWS CloudWatch metric alarms reject the `SEARCH` expression (`ValidationError: SEARCH is not supported on Metric Alarms`), and ASG churn rules out enumerating InstanceIds in TF. The fleet-wide `Sum` form above is the only tractable alarm shape; per-InstanceId resolution is still emitted by `recordServerStartup` (endpoints/server/msghandler.go) and queryable from dashboards for investigation.

The inline Terraform comments on each alarm reference this table and the relevant PR history. Search for `regression class PR #1096` in `terraform/modules/monitoring/main.tf` for the detailed threshold derivations.

### Cost Analytics (Shared Athena Backend)

AWS cost data flows through a single pipeline deployed by **sandbox only**:

```
AWS Data Export (CUR 2.0) → S3 (mgmt account) → Glue Catalog → Athena → Grafana Dashboard
```

The backend infrastructure (S3 bucket, Glue database, Athena workgroup, IAM roles) lives in the mgmt account (`165115313779`) and is deployed by sandbox's `cost_analytics` module (`terraform/modules/cost-analytics/`). Only one environment deploys this to avoid duplicate resources in the shared mgmt account.

**How each environment connects to Grafana:**

| Environment | `deploy_cost_analytics` | Athena config source | Dashboard? |
|-------------|------------------------|---------------------|------------|
| Sandbox | `true` | Module outputs (automatic) | No (`grafana_create_dashboards = false`) |
| Prod | `false` | `grafana_athena_config` (manual) | Yes (`grafana_create_dashboards = true`) |

Prod uses `grafana_athena_config` in `terraform.tfvars` to specify Athena connection details directly, pointing to the same resources sandbox deployed. These values are derived from the `cost_analytics` module outputs — if sandbox's config changes (e.g., `name_prefix`), prod's `grafana_athena_config` must be updated to match.

The two variables are mutually exclusive: setting both `deploy_cost_analytics = true` and `grafana_athena_config` will fail validation.

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
curl -s http://server.nhp.sandbox.internal:8888/health | jq .
# Returns JSON with status "healthy"/"degraded"/"unhealthy" and individual checks

# Knock-readiness (includes AC peer check — used by NLB for knock-traffic routing)
curl -s http://server.nhp.sandbox.internal:8888/health/knock-ready | jq .
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
