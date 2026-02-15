# Technical Design Document

# NHP Pluggable Storage Backend Architecture

## Per-AC Server Assignment with DynamoDB (Cloud) / etcd (On-Prem)

---

| **Document Info** | |
|-------------------|------------------------|
| **Version**       | 2.11 (NHP_ARD Integration)   |
| **Date**          | January 11, 2026       |
| **Author**        | Architecture Team      |
| **Status**        | Ready for Review       |
| **Repository**    | layerv/nhp             |

---

## Reviewers

| Name | Role | Status |
|------|------|--------|
| | Engineering Lead | Pending |
| | Security | Pending |
| | Infrastructure | Pending |
| | Product | Pending |

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Problem Statement](#2-problem-statement)
3. [Goals and Non-Goals](#3-goals-and-non-goals)
4. [Current Architecture](#4-current-architecture)
5. [Proposed Architecture](#5-proposed-architecture)
6. [Detailed Design](#6-detailed-design)
7. [Security Considerations](#7-security-considerations)
8. [Testing Strategy](#8-testing-strategy)
9. [Migration Plan](#9-migration-plan)
10. [Implementation Phases](#10-implementation-phases)
11. [Open Questions](#11-open-questions)
12. [Appendix](#12-appendix)

---

## 1. Executive Summary

This document proposes **eliminating etcd as the default** in the NHP architecture for cloud deployments, replacing it with a **per-AC server assignment model** using DynamoDB Global Tables. **etcd remains available as a feature flag for on-premises deployments** where DynamoDB is not available.

### Key Architectural Changes

| Change | Description |
|--------|-------------|
| **Pluggable storage backend** | DynamoDB (cloud, default) or etcd (on-prem, feature flag) |
| **Per-AC server assignment** | Console assigns 3 servers per AC at signup |
| **Multi-AZ resilience** | 3 assigned servers MUST be in different AZs |
| **Server-to-server forwarding** | Knocks at non-assigned servers are forwarded |
| **DynamoDB Global Tables** | Licenses, AC assignments, resource definitions (cloud) |
| **UDP only** | No HTTP for discovery; all via NHP protocol |
| **NAT traversal preserved** | AC initiates all connections |

### Deployment Modes

| Mode | Storage Backend | Use Case |
|------|-----------------|----------|
| **Cloud (default)** | DynamoDB Global Tables | AWS deployment, SaaS offering |
| **On-prem (feature flag)** | etcd cluster | Self-hosted, air-gapped environments |

### Scale Model (Cloud)

| Metric | Value |
|--------|-------|
| NHP Servers | 1,000s across region |
| Access Controllers | 100,000s |
| Connections per AC | 3 (to assigned servers) |
| Connections per server | ~300 (evenly distributed) |
| Total connections | 300K (very manageable) |

### Key Benefits (Cloud Mode)

- **Simplified operations**: No etcd cluster to manage
- **Reduced attack surface**: No distributed etcd credentials
- **Better resilience**: Multi-AZ server assignment per AC
- **Lower cost**: DynamoDB vs etcd cluster
- **Easier scaling**: Stateless servers, no coordination

---

## 2. Problem Statement

### 2.1 Current Pain Points

**Operational Complexity:**
- etcd cluster requires careful capacity planning and maintenance
- ACs require etcd mTLS certificates provisioned via Terraform
- AC instances must have IAM permissions to access etcd secrets
- etcd connection failures cause AC startup failures
- Certificate rotation requires coordinated redeployment

**Scaling Challenges:**
- Current architecture has AC connecting to ALL servers
- With 1000s of servers, this doesn't scale (100K ACs × 1000 servers = 100M connections)
- etcd becomes bottleneck for watch operations at scale

**Security Concerns:**
- ACs have write access to etcd (registration)
- Compromised AC could write malicious registry entries
- etcd credentials distributed across all AC instances

### 2.2 Business Drivers

- **Scale**: Support 100K+ ACs without architectural limits
- **Resilience**: Multi-AZ failover without single points of failure
- **Operational Efficiency**: Reduce infrastructure complexity
- **Cost**: Eliminate etcd cluster costs

---

## 3. Goals and Non-Goals

### 3.1 Goals

| ID | Goal | Priority |
|----|------|----------|
| G1 | Eliminate etcd as default for cloud deployments | P0 |
| G2 | Retain etcd as feature flag for on-prem deployments | P0 |
| G3 | Implement pluggable storage backend abstraction | P0 |
| G4 | Implement per-AC server assignment (3 servers, different AZs) | P0 |
| G5 | Implement server-to-server knock forwarding | P0 |
| G6 | Use DynamoDB Global Tables for cloud persistent state | P0 |
| G7 | Preserve NAT traversal (AC-initiated connections) | P0 |

### 3.2 Non-Goals

| ID | Non-Goal | Rationale |
|----|----------|-----------|
| NG1 | HTTP-based discovery | UDP only via NHP protocol |
| NG2 | Cell-based architecture | Per-resource FQDN model instead |
| NG3 | Lambda@Edge for routing | NLB + server forwarding instead |
| NG4 | Change NHP cryptographic protocols | Protocol is stable |
| NG5 | Backward compatibility during migration | Clean cutover; no dual-mode operation |
| NG6 | Complete removal of etcd code | Retained for on-prem feature flag |

---

## 4. Current Architecture

### 4.1 AC Registration Flow (Current)

```
┌──────────────────────────────────────────────────────────────────┐
│                     CURRENT ARCHITECTURE                          │
├──────────────────────────────────────────────────────────────────┤
│                                                                   │
│   ┌─────────┐         ┌─────────┐         ┌─────────────┐        │
│   │   AC    │ ──(1)──▶│  etcd   │◀──(3)── │ NHP Server  │        │
│   │         │  Write   │         │  Watch   │             │        │
│   │         │◀──(2)──  │         │         │             │        │
│   │         │  Read    │         │         │             │        │
│   └────┬────┘         └─────────┘         └──────┬──────┘        │
│        │                                         │                │
│        │              ┌─────────┐                │                │
│        └────(4)──────▶│   UDP   │◀──────(5)─────┘                │
│           NHP_AOL     │ Channel │    NHP_AAK                     │
│                       └─────────┘                                 │
│                                                                   │
│   PROBLEM: AC connects to ALL servers (doesn't scale)            │
│                                                                   │
└──────────────────────────────────────────────────────────────────┘
```

### 4.2 Current Data Flows

| Component | etcd Operations | Data |
|-----------|-----------------|------|
| AC | WRITE | `/nhp/ac-registry/{id}` - Public key, IP, port |
| AC | READ | `/nhp/config` - Server addresses, public keys |
| Server | READ | `/nhp/config` - HTTP settings |
| Server | WATCH | `/nhp/ac-registry/*` - AC registrations |

---

## 5. Proposed Architecture

### 5.1 Target State Overview

```
┌──────────────────────────────────────────────────────────────────────────┐
│                    PER-AC SERVER ASSIGNMENT ARCHITECTURE                  │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                           │
│   ┌─────────────────────────────────────────────────────────────────────┐│
│   │                           CONSOLE                                    ││
│   │                                                                      ││
│   │   On AC signup:                                                      ││
│   │   1. Generate license key                                            ││
│   │   2. Assign 3 servers from different AZs                            ││
│   │   3. Store in DynamoDB: {ac_id → [srv1, srv2, srv3]}                ││
│   │                                                                      ││
│   └─────────────────────────────────────────────────────────────────────┘│
│                              │                                            │
│                              ▼                                            │
│   ┌─────────────────────────────────────────────────────────────────────┐│
│   │                      DynamoDB Global Tables                          ││
│   │                                                                      ││
│   │   nhp_licenses:        License validation data                      ││
│   │   nhp_ac_assignments:  AC → [server1, server2, server3]             ││
│   │   nhp_resources:       Resource definitions (replaces etcd config)  ││
│   │                                                                      ││
│   └─────────────────────────────────────────────────────────────────────┘│
│                              ▲                                            │
│                              │                                            │
│   ┌──────────────────────────┴───────────────────────────────────────────┐
│   │                      SERVER POOL (1000s of servers)                   │
│   │                                                                       │
│   │   Each server:                                                        │
│   │   - Registers with Cloud Map on startup (includes AZ)               │
│   │   - Handles AC registrations (NHP_AOL)                               │
│   │   - Reads assignments from DynamoDB (with LRU cache)                │
│   │   - Forwards knocks to assigned servers if needed                    │
│   │   - Sends AOP to ACs it has connections with                         │
│   │                                                                       │
│   │                    ┌─────────────────────┐                           │
│   │                    │   Pool NLB (UDP)    │                           │
│   │                    │  <uuid>.nhp.layerv  │                           │
│   │                    └─────────┬───────────┘                           │
│   └──────────────────────────────┼───────────────────────────────────────┘
│                                  │                                        │
│                                  ▼                                        │
│   ┌───────────────────────────────────────────────────────────────────────┐
│   │                         AC (behind NAT)                               │
│   │                                                                       │
│   │   1. AC connects to FQDN → NLB → any server                          │
│   │   2. Server looks up AC's 3 assigned servers from DynamoDB           │
│   │   3. Server returns NHP_AAK with 3 server IPs (different AZs)        │
│   │   4. AC connects to all 3 assigned servers (punches NAT holes)       │
│   │   5. Only those 3 servers can send AOP to this AC                    │
│   │                                                                       │
│   └───────────────────────────────────────────────────────────────────────┘
│                                                                           │
└──────────────────────────────────────────────────────────────────────────┘
```

### 5.2 Knock Flow with Server-to-Server Forwarding

```
┌──────────────────────────────────────────────────────────────────────────┐
│                         KNOCK FLOW                                        │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                           │
│   AC assigned servers: [Srv1 (AZ-a), Srv2 (AZ-b), Srv3 (AZ-c)]          │
│   AC connected to: Srv1, Srv2, Srv3 (NAT holes punched)                  │
│                                                                           │
│   ═══════════════════════════════════════════════════════════════════    │
│   Case A: Knock arrives at ASSIGNED server (~0.3% of knocks)             │
│   ═══════════════════════════════════════════════════════════════════    │
│                                                                           │
│   User ──NHP_KNK──► NLB ──► Srv2 (assigned)                              │
│                              │                                            │
│                              ├─ Srv2 has AC connection                   │
│                              ├─ Srv2 sends NHP_AOP to AC                 │
│                              ├─ AC opens firewall, sends NHP_ART         │
│                              └─ Srv2 sends NHP_ACK to User               │
│                                                                           │
│   ═══════════════════════════════════════════════════════════════════    │
│   Case B: Knock arrives at NON-assigned server (~99.7% of knocks)        │
│   ═══════════════════════════════════════════════════════════════════    │
│                                                                           │
│   User ──NHP_KNK──► NLB ──► Srv7 (not assigned)                          │
│                              │                                            │
│                              ├─ Srv7 checks: "Do I have AC connection?"  │
│                              ├─ No → Look up DynamoDB → [Srv1,Srv2,Srv3] │
│                              ├─ Srv7 forwards knock to Srv1 (NHP_FWD)    │
│                              │                                            │
│                              ▼                                            │
│                            Srv1 (assigned)                               │
│                              │                                            │
│                              ├─ Srv1 has AC connection                   │
│                              ├─ Srv1 sends NHP_AOP to AC                 │
│                              ├─ AC opens firewall, sends NHP_ART         │
│                              ├─ Srv1 sends NHP_FRT (result) to Srv7      │
│                              │                                            │
│                              ▼                                            │
│                            Srv7 ──NHP_ACK──► User                        │
│                                                                           │
│   ═══════════════════════════════════════════════════════════════════    │
│   Forwarding Failover: If Srv1 fails, Srv7 tries Srv2, then Srv3        │
│   ═══════════════════════════════════════════════════════════════════    │
│                                                                           │
└──────────────────────────────────────────────────────────────────────────┘
```

### 5.3 New Data Flows

| Component | Operation | Storage | Data |
|-----------|-----------|---------|------|
| Console | WRITE | DynamoDB | Licenses, AC assignments, resources |
| Server | READ | DynamoDB (cached) | AC assignments, licenses, resources |
| Server | READ | Cloud Map | Server discovery (for forwarding) |
| Server | WRITE | Cloud Map | Self-registration on startup |
| AC | NHP_AOL | → Server | Customer ID, license key, AC info |
| AC | NHP_AAK | ← Server | Assigned server list (3 IPs) |

### 5.4 Storage Backend Abstraction

The storage layer is abstracted to support multiple backends. All core logic (per-AC assignment, forwarding, Noise K) remains identical regardless of backend.

```go
// StorageBackend interface - implemented by DynamoDB and etcd
type StorageBackend interface {
    // AC assignments
    GetACAssignment(acId string) (*ACAssignment, error)
    GetACsByServer(serverId string) ([]ACAssignment, error)

    // Licenses
    GetLicense(customerId, resourceFqdn string) (*License, error)

    // Resources
    GetResource(customerId, resourceId string) (*Resource, error)
}
```

| Backend | Config Key | Use Case |
|---------|------------|----------|
| `dynamodb` (default) | `storage.backend = "dynamodb"` | AWS cloud deployments |
| `etcd` (feature flag) | `storage.backend = "etcd"` | On-prem, self-hosted |

**Feature Flag in Server Config:**
```toml
[Storage]
Backend = "dynamodb"  # Options: "dynamodb" | "etcd"

[Storage.DynamoDB]
Region = "us-east-2"
ACAssignmentsTable = "nhp_ac_assignments"
LicensesTable = "nhp_licenses"

[Storage.Etcd]
Endpoints = ["etcd.internal:2379"]
TLS = true
```

**On-prem with etcd:**
- Same per-AC assignment model
- Same server-to-server forwarding
- Same Noise K encryption
- Only the storage backend changes

---

## 6. Detailed Design

### 6.1 Console: AZ-Aware Server Assignment

When customer registers AC in Console:

```python
def assign_ac_servers(ac_id, resource_fqdn, customer_id):
    # Get list of healthy servers from Cloud Map (includes AZ metadata)
    all_servers = cloud_map.discover_instances("nhp-servers")

    # Group servers by AZ
    servers_by_az = {}
    for server in all_servers:
        az = server.attributes["availability_zone"]
        servers_by_az.setdefault(az, []).append(server)

    # CRITICAL: Select 1 server from each of 3 different AZs
    available_azs = list(servers_by_az.keys())
    if len(available_azs) < 3:
        raise InsufficientAZsError(f"Need 3 AZs, only {len(available_azs)} available")

    selected_azs = random.sample(available_azs, 3)
    assigned = [random.choice(servers_by_az[az]) for az in selected_azs]

    # Store in DynamoDB
    dynamodb.put_item(
        TableName="nhp_ac_assignments",
        Item={
            "ac_id": ac_id,
            "resource_fqdn": resource_fqdn,
            "customer_id": customer_id,
            "assigned_servers": [
                {"ip": s.ip, "az": s.az, "id": s.id, "internal_ip": s.internal_ip}
                for s in assigned
            ],
            "version": 1,
            "created_at": now()
        }
    )

    return assigned
```

**AZ Distribution Requirements:**
- All regions used MUST have at least 3 AZs
- Supported regions: us-east-1, us-east-2, us-west-2, eu-west-1, etc.
- NOT supported: Regions with only 2 AZs (e.g., ca-west-1)

### 6.2 AC Registration Flow (Using NHP_ARD)

The AC registration flow uses **NHP_ARD (AC Redispatch)** - a new NHP spec message that redirects ACs to their assigned servers.

```
1. AC starts, connects to FQDN (via NLB, hits any server)
2. AC sends NHP_AOL with credentials (customer_id, license_key, ac_id)
3. Server validates license (DynamoDB lookup)
4. Server looks up AC's assigned servers (DynamoDB lookup)
5. Server responds NHP_ARD with targets (3 assigned servers)
6. AC terminates connection to random server
7. AC connects to first target, sends NHP_AOL
8. First target responds NHP_AAK (success, no redirect - chaining prohibited)
9. AC connects to remaining 2 targets, sends NHP_AOL to each
10. All 3 targets respond NHP_AAK
11. All 3 servers store AC in local acConnectionMap
12. AC sends keepalives to all 3 (maintains NAT holes)
```

**NHP_ARD vs NHP_FWD - Different Purposes:**

| Message | Flow | Purpose | When Used |
|---------|------|---------|-----------|
| **NHP_ARD** | AC Registration | Redirect AC to assigned servers | Response to NHP_AOL at non-assigned server |
| **NHP_FWD** | Knock Handling | Forward knock to assigned server | When knock arrives at non-assigned server |

NHP_ARD handles **AC registration redirection**. NHP_FWD handles **knock forwarding**. Both are needed:
- User knocks always hit random server via NLB (user doesn't know assigned servers)
- AC registration only happens once (or on reconnect), uses NHP_ARD
- Knock forwarding happens on every knock to non-assigned server, uses NHP_FWD

**Registration vs Forwarding Keypairs:**

The system uses two types of server keypairs:

| Keypair Type | Purpose | Scope | Storage |
|--------------|---------|-------|---------|
| **Registration keypair** | AC initial registration via NLB | Shared by all servers | SSM Parameter Store (`/nhp/pool/registration-key`) |
| **Server keypair** | Server-to-server forwarding (NHP_FWD/FRT) | Unique per server | SSM Parameter Store (`/nhp/server/{id}/private-key`) |

**Why two keypairs:**
- AC connects via NLB to "any server" - it doesn't know which server will receive the NHP_AOL
- AC config has `ServerPubKeyBase64` = the shared registration public key
- This enables NLB load balancing while maintaining per-server isolation for forwarding
- Forward secrecy for server-to-server traffic (unique ephemeral keys per forward)

### 6.3 Server: Knock Handling with Forwarding

```go
func (s *UdpServer) HandleKnockRequest(ppd *core.PacketParserData) {
    // Parse knock, determine target resource/AC
    acId := s.resolveACForResource(knock.ResourceId)

    // Check if we have connection to this AC
    s.acConnectionMapMutex.Lock()
    acConn, found := s.acConnectionMap[acId]
    s.acConnectionMapMutex.Unlock()

    if found {
        // Case A: We're assigned - handle directly
        s.sendAOPToAC(acConn, knock)
        return
    }

    // Case B: Not assigned - forward to assigned server with failover
    assignment, err := s.assignmentCache.GetAssignment(acId)
    if err != nil {
        s.sendErrorToUser(ppd, "AC_NOT_FOUND")
        return
    }

    // Forward with smart ordering and failover
    response, err := s.forwardWithSmartOrder(assignment, knock)

    if response == nil || !response.Success {
        s.sendErrorToUser(ppd, "ALL_SERVERS_DOWN")
        return
    }

    // Return response to user
    s.sendACKToUser(ppd, response)
}
```

### 6.4 Smart Forwarding with Health Tracking

**Forwarding uses random shuffle + health tracking for optimal load distribution:**

```go
func (s *Server) forwardWithSmartOrder(assignment *Assignment, knock []byte) (*Response, error) {
    servers := make([]ServerInfo, len(assignment.AssignedServers))
    copy(servers, assignment.AssignedServers)

    // Shuffle to distribute load (avoid always hitting same server first)
    rand.Shuffle(len(servers), func(i, j int) {
        servers[i], servers[j] = servers[j], servers[i]
    })

    for _, target := range servers {
        // Skip servers we've recently seen fail (30s decay)
        if s.serverHealth.IsUnhealthy(target.ID) {
            continue
        }

        response, err := s.forwardKnockToServer(target, knock)
        if err != nil {
            s.serverHealth.RecordFailure(target.ID)
            continue
        }
        s.serverHealth.RecordSuccess(target.ID)
        return response, nil
    }

    return nil, errors.New("all servers failed")
}

// Health tracker with 30s decay
type ServerHealthTracker struct {
    failures map[string]time.Time
    mu       sync.RWMutex
}

func (h *ServerHealthTracker) IsUnhealthy(serverID string) bool {
    h.mu.RLock()
    defer h.mu.RUnlock()
    lastFail, exists := h.failures[serverID]
    return exists && time.Since(lastFail) < 30*time.Second
}
```

**Benefits:**
- Load distribution across assigned servers (random order)
- Fast failover past known-bad servers (skip unhealthy)
- Automatic recovery (30s decay)
- Each attempt has 2-second timeout

### 6.5 Server-to-Server Communication

Server-to-server forwarding uses **Noise K pattern** for spec compliance and forward secrecy. Each server has a unique keypair, and public keys are discovered via Cloud Map.

#### 6.5.1 Per-Server Keypairs

```go
// Server config - each server has unique keypair
type ServerConfig struct {
    ServerId      string
    PrivKeyBase64 string  // Unique per server (from SSM Parameter Store)
    PublicIP      string
    InternalIP    string
}
```

**Keypair Persistence (REQUIRED):**

Server keypairs MUST be persisted in SSM Parameter Store to prevent key mismatch on restart. If a server generates a new keypair after restart, other servers have cached the old public key and forwards will fail until peer cache expires (1 hour).

**Two keypairs to load:**
1. **Registration keypair** (`/nhp/pool/registration-key`) - Shared by all servers, used to decrypt NHP_AOL from ACs
2. **Forwarding keypair** (`/nhp/server/{id}/private-key`) - Unique per server, used for NHP_FWD/FRT

```go
func (s *Server) initializeKeypairs() error {
    // 1. Load shared registration keypair (REQUIRED - must exist)
    // This key is provisioned by Terraform; servers never generate it
    regKey, err := s.ssm.GetParameter("/nhp/pool/registration-key", true /* withDecryption */)
    if err != nil {
        return fmt.Errorf("failed to load registration keypair: %w", err)
    }
    s.registrationDevice.SetPrivateKey(regKey)

    // 2. Load per-server forwarding keypair
    fwdParamName := fmt.Sprintf("/nhp/server/%s/private-key", s.config.ServerId)
    fwdKey, err := s.ssm.GetParameter(fwdParamName, true /* withDecryption */)
    if err == nil {
        s.forwardingDevice.SetPrivateKey(fwdKey)
        return nil
    }

    // Distinguish "key doesn't exist" from "SSM unavailable"
    var notFoundErr *ssm.ParameterNotFound
    if !errors.As(err, &notFoundErr) {
        // SSM unavailable (network issue, IAM issue, etc.) - fail startup
        // DO NOT generate new key - this would break peer cache for all servers
        return fmt.Errorf("SSM unavailable, cannot load forwarding keypair: %w", err)
    }

    // Key doesn't exist (first start) - generate new forwarding keypair
    privKey := generatePrivateKey()
    s.forwardingDevice.SetPrivateKey(privKey)

    // REQUIRED: Persist to SSM Parameter Store for restart consistency
    return s.ssm.PutParameter(fwdParamName, privKey, "SecureString")
}
```

**Critical: SSM Error Handling**
- If SSM returns `ParameterNotFound`: Server is starting for first time → generate new key
- If SSM returns any other error (network, IAM, throttle): Fail startup → operator must fix
- Never generate a new key when SSM is temporarily unavailable (breaks peer cache for all servers)

**Why SSM Parameter Store (not Secrets Manager):**
- **Cost:** SSM Standard tier is free (up to 10K parameters); Secrets Manager = $0.40/secret/month
- **At scale:** 1000 servers = $0/month (SSM) vs $400/month (Secrets Manager)
- **Security:** SecureString parameters are KMS-encrypted, equivalent security to Secrets Manager
- **Simplicity:** Same API pattern, fewer moving parts

#### 6.5.2 Key Discovery via Cloud Map

Servers register their public key as a Cloud Map attribute on startup:

```go
func (s *Server) RegisterWithCloudMap() error {
    return s.cloudMap.RegisterInstance(s.config.ServerId, map[string]string{
        "public_key":        s.device.PublicKeyBase64(),
        "internal_ip":       s.config.InternalIP,
        "availability_zone": s.config.AZ,
        "port":              "62206",
    })
}

func (s *Server) DiscoverServerPubKey(serverId string) ([]byte, error) {
    instance, err := s.cloudMap.GetInstance(serverId)
    if err != nil {
        return nil, err
    }
    return base64.StdEncoding.DecodeString(instance.Attributes["public_key"])
}
```

#### 6.5.3 Forwarding with Noise K

NHP_FWD uses the existing Noise infrastructure (reuses `Device.MsgToPacket`):

```go
func (s *UdpServer) forwardKnockToServer(target ServerInfo, knock []byte) (*ForwardResponse, error) {
    // Get or create peer for target server
    peer := s.getOrCreateServerPeer(target)

    // Create forward message
    fwdMsg := &ServerForwardMsg{
        KnockData:     knock,
        SourceServer:  s.config.ServerId,
        UserAddr:      userAddr,
        TransactionId: generateTxId(),
        Timestamp:     time.Now().Unix(),
    }

    // Use existing Noise encryption via Device
    md := &core.MsgData{
        HeaderType:    NHP_FWD,
        PeerPk:        peer.PublicKey(),
        TransactionId: fwdMsg.TransactionId,
        Message:       json.Marshal(fwdMsg),
    }

    mad, err := s.device.MsgToPacket(md)
    if err != nil {
        return nil, err
    }

    // Send via UDP to target server's internal IP (VPC traffic)
    response, err := s.sendAndWait(target.InternalIP, 62206, mad.BasePacket.Content, 2*time.Second)
    if err != nil {
        return nil, err
    }

    // Decrypt response using Noise
    return s.decryptForwardResponse(response)
}
```

**Noise K Pattern Implementation:**

The existing `Device.MsgToPacket()` implements the Noise K pattern per the NHP spec, using handshake tokens `e`, `es`, `ss`. For server-to-server forwarding:
- The sending server's static public key is transmitted in the **Local Public Key Ciphertext** header field (encrypted with the ephemeral DH result)
- The receiving server authenticates the sender by decrypting and verifying the static key
- Forward secrecy is provided by ephemeral keys generated per message

**Cross-Region Limitation:**

Server-to-server forwarding uses VPC internal IPs, requiring all servers in a region to share network connectivity (same VPC, peered VPCs, or Transit Gateway). Cross-region forwarding is not supported in v1; each region operates as an independent server pool with separate AC assignments.

```go
const PeerCacheTTL = 1 * time.Hour  // Re-fetch public key hourly

type PeerEntry struct {
    Peer      *core.Peer
    FetchedAt time.Time
}

func (s *Server) getOrCreateServerPeer(target ServerInfo) *core.Peer {
    s.serverPeerMutex.Lock()
    defer s.serverPeerMutex.Unlock()

    entry, exists := s.serverPeerMap[target.ID]
    if exists && time.Since(entry.FetchedAt) < PeerCacheTTL {
        return entry.Peer
    }

    // Cache miss or expired - discover current public key from Cloud Map
    pubKey, err := s.DiscoverServerPubKey(target.ID)
    if err != nil {
        // If discovery fails and we have stale entry, use it
        if exists {
            return entry.Peer
        }
        return nil
    }

    peer := core.NewPeer(pubKey)
    s.serverPeerMap[target.ID] = &PeerEntry{
        Peer:      peer,
        FetchedAt: time.Now(),
    }
    return peer
}
```

**Peer Cache TTL:**

Server peer public keys are cached for 1 hour. After TTL expiry, the next forward triggers a Cloud Map lookup for the current public key. This ensures key rotations propagate within 1 hour without requiring server restarts. If Cloud Map lookup fails, the stale cached key is used as fallback (better than failing the forward).

#### 6.5.4 Why Noise K (Not Shared Cluster Key)

| Aspect | Noise K | Cluster Key |
|--------|---------|-------------|
| Forward secrecy | ✅ Yes (ephemeral keys) | ❌ No |
| Key compromise blast radius | One server | All servers |
| Spec compliance | ✅ Compliant | ❌ Deviation |
| Key rotation | Per-server, no coordination | Coordinated restart |
| Implementation | Reuse existing Noise code | Separate AES-GCM |
| Performance | ~1ms asymmetric | ~0.1ms symmetric |

**Decision:** Noise K is preferred because:
1. **Forward secrecy** - captured traffic remains protected even if key later compromised
2. **Spec compliance** - "We use Noise everywhere" is stronger security story
3. **Code reuse** - existing `Device.MsgToPacket` already implements Noise
4. **Operational simplicity** - no coordinated key rotation needed

### 6.6 DynamoDB Data Model

**Table: `nhp_licenses`**
```
PK: customer_id (String)
SK: resource_fqdn (String)

Attributes:
  - license_key_hash: String (bcrypt)
  - tier: String (standard | professional | enterprise)
  - max_acs: Number
  - expires_at: Number (Unix timestamp, 0 = never)
  - active: Boolean
```

**Table: `nhp_ac_assignments`**
```
PK: ac_id (String)

Attributes:
  - resource_fqdn: String
  - customer_id: String
  - assigned_servers: List[Map]
      - id: String (server instance ID)
      - ip: String (public IP for AC connection)
      - internal_ip: String (VPC IP for server-to-server)
      - az: String (availability zone)
      - port: Number
  - version: Number (for optimistic locking)
  - reassigned_at: Number (set when Console reassigns - triggers short cache TTL)
  - created_at: Number
  - last_seen: Number
  - ttl: Number

GSI: resource_fqdn-index (find AC by resource)
GSI: customer_id-index (list ACs by customer)
GSI: server_id-index (find ACs by assigned server - for reassignment)
```

**Table: `nhp_resources`**
```
PK: customer_id (String)
SK: resource_id (String)  -- Internal UUID, immutable identifier

Attributes:
  - resource_fqdn: String  -- Customer-facing: {uuid}.nhp.layerv.ai (1:1 with resource_id)
  - ac_id: String          -- Which AC protects this resource
  - dest_host: String
  - dest_port: Number
  - open_time: Number
  - auth_service_id: String
```

**Resource model:** Multiple resources can be protected by a single AC, enabling one AC to guard SSH (port 22), HTTPS (port 443), and RDP (port 3389) on the same host. Each resource has a unique `resource_id` and corresponding `resource_fqdn`.

### 6.7 Caching Strategy with Adaptive TTL

```go
type ACAssignmentCache struct {
    cache    *lru.Cache  // 10K entries
    dynamoDB *DynamoDBClient
}

func (c *ACAssignmentCache) GetAssignment(acId string) (*Assignment, error) {
    // Check cache first
    if cached, ok := c.cache.Get(acId); ok {
        ttl := c.getTTL(cached)
        if time.Since(cached.FetchedAt) < ttl {
            return cached.Assignment, nil
        }
    }

    // Cache miss or stale - fetch from DynamoDB
    assignment, err := c.dynamoDB.GetACAssignment(acId)
    if err != nil {
        return nil, err
    }

    c.cache.Add(acId, &CacheEntry{
        Assignment: assignment,
        FetchedAt:  time.Now(),
    })

    return assignment, nil
}

// Adaptive TTL: Short TTL during reassignment window
func (c *ACAssignmentCache) getTTL(entry *CacheEntry) time.Duration {
    if entry.Assignment.ReassignedAt != nil {
        timeSinceReassign := time.Since(time.Unix(*entry.Assignment.ReassignedAt, 0))
        if timeSinceReassign < 5*time.Minute {
            return 5 * time.Second  // Very short TTL right after reassignment
        }
    }
    return 60 * time.Second  // Normal TTL
}
```

**Cache Parameters:**
- Normal TTL: 60 seconds (balances freshness vs DynamoDB load)
- Reassignment TTL: 5 seconds for 5 minutes after reassignment (ensures quick convergence)
- Size: 10K entries per server
- Invalidation: TTL-based with adaptive duration based on `reassigned_at` field

### 6.8 Extended NHP Message Structures

**ACOnlineMsg (NHP_AOL - Type 10) - Extended:**
```go
type ACOnlineMsg struct {
    // Authentication fields
    ACId          string   `json:"acId"`
    LicenseKey    string   `json:"licenseKey"`  // Globally unique, used for auth

    // Existing fields
    AuthServiceId string   `json:"aspId"`
    ResourceIds   []string `json:"resIds"`

    // Metadata
    ACVersion     string   `json:"version,omitempty"`
}
```

**Note:** `CustomerId` and `ResourceFQDN` were removed from ACOnlineMsg. License keys are globally unique identifiers - no additional context needed for lookup. The server endpoint is configured separately in AC config (`ServerEndpoint`).

**ServerACAckMsg (NHP_AAK - Type 11):**
```go
type ServerACAckMsg struct {
    ErrCode    string `json:"errCode"`
    ErrMsg     string `json:"errMsg,omitempty"`
    ACAddr     string `json:"acAddr"`
    Registered bool   `json:"registered"`
}
```

**Note:** NHP_AAK no longer contains `AssignedServers`. That information is now provided via NHP_ARD (AC Redispatch). NHP_AAK is a simple success/error acknowledgment sent by assigned servers.

**NEW: AC Redispatch Message (NHP_ARD - Type 30) - NHP Spec Addition:**

NHP_ARD redirects an AC to its assigned servers. This is a **spec-compliant message** (not a LayerV extension).

```go
type ACRedispatchMsg struct {
    // Ordered list of redirect targets - AC tries each until successful
    Targets []RedirectTarget `json:"targets"`

    // Seconds until AC should re-register (0 = no limit)
    TTL     int64            `json:"ttl,omitempty"`

    // Reason for redirect
    Reason  string           `json:"reason,omitempty"`  // LOAD_BALANCE, MAINTENANCE, POLICY, GEOGRAPHIC
}

type RedirectTarget struct {
    Address   string `json:"addr"`    // Server endpoint (IP:port or FQDN:port)
    PublicKey string `json:"pubKey"`  // Server's static public key (Curve25519, base64)
    Hint      string `json:"hint,omitempty"`  // Optional metadata (e.g., "az:us-east-1a")
}
```

**NHP_ARD Protocol Rules:**
1. **Only in response to NHP_AOL** - Unsolicited NHP_ARD is prohibited
2. **No redirect chaining** - Server responding to redirected AC MUST send NHP_AAK or error, never NHP_ARD
3. **AC behavior on receive:**
   - Terminate current connection
   - Attempt NHP_AOL to each target in order until successful
   - If all targets fail, retry original server with exponential backoff
4. **AC connects to ALL targets** - For redundancy, AC establishes connections to all targets (not just first success)

**Reason Codes:**
| Code | Description |
|------|-------------|
| `LOAD_BALANCE` | Distributing load across server pool |
| `MAINTENANCE` | Server entering maintenance mode |
| `POLICY` | Policy-based routing (e.g., customer tier) |
| `GEOGRAPHIC` | Geographic optimization |

**Note on RedirectTarget.PublicKey:**
- Each assigned server has a unique keypair (per-server forwarding key)
- AC uses this public key to encrypt NHP_AOL to assigned servers
- Different from registration keypair (shared) used for initial NLB connection

**Server Forward Messages (NHP_FWD - Type 28, NHP_FRT - Type 29) - LayerV Extension:**

NHP_FWD handles **knock forwarding** (different from NHP_ARD which handles AC registration).

**Why NHP_FWD is still needed:**
- User sends NHP_KNK (knock) to pool NLB → hits random server
- User doesn't know which servers are assigned to the AC
- If knock hits non-assigned server, it must be forwarded to assigned server
- NHP_ARD can't help here - the user isn't registering, they're knocking

```go
type ServerForwardMsg struct {
    KnockData     []byte `json:"knockData"`    // Original encrypted knock packet
    SourceServer  string `json:"sourceServer"` // Server that received the knock
    UserAddr      string `json:"userAddr"`     // User's address for response
    TransactionId uint64 `json:"txId"`         // Correlation ID
    Timestamp     int64  `json:"ts"`           // Unix timestamp - reject if >30s old
}

type ServerForwardResultMsg struct {
    TransactionId uint64 `json:"txId"`
    Success       bool   `json:"success"`
    ACKData       []byte `json:"ackData"`      // Response to send to user
    ErrCode       string `json:"errCode,omitempty"`
}
```

**NHP_ARD vs NHP_FWD Summary:**
| Aspect | NHP_ARD | NHP_FWD |
|--------|---------|---------|
| **Purpose** | Redirect AC to assigned servers | Forward knock to assigned server |
| **Triggered by** | NHP_AOL from AC | NHP_KNK from user |
| **Spec status** | ✅ NHP spec (Type 30) | ⚠️ LayerV extension (Type 28/29) |
| **Sender** | Any server → AC | Non-assigned server → Assigned server |
| **Result** | AC reconnects to targets | Knock processed, response forwarded |

### 6.9 AC Reconnection Flow

**Keepalive Parameters:**
```go
const (
    KeepaliveInterval     = 10 * time.Second  // AC sends to each assigned server
    KeepaliveTimeout      = 3 * time.Second   // Response timeout
    KeepaliveMaxRetries   = 3
    ReconnectJitter       = 0.2               // ±20% to prevent thundering herd
    ReregistrationJitter  = 5 * time.Second   // Random 0-5s before re-registration
)
```

**Failure Detection Timeline:**
```
T=0:    Keepalive sent
T=3:    No response (timeout) - start retry sequence
T=3:    Retry 1, wait up to 3s
T=6:    Retry 2, wait up to 3s
T=9:    Retry 3, wait up to 3s
T=12:   Give up, mark server down, trigger re-registration
        Add 0-5s jitter before re-registration
T=12-17: Re-registration via FQDN
```
**Total failure detection: ~12-17 seconds**

**CRITICAL: Re-register on ANY server failure**

When AC detects ANY assigned server is down, it re-registers via FQDN to get the latest assignment. This is essential because:
- Console reassigns AC when server fails (detected via Cloud Map)
- AC will detect that same failure (keepalive timeout)
- Re-registration gets authoritative latest assignment from DynamoDB
- No version-checking overhead during normal operation

```go
func (ac *AC) handleServerDown(deadServer ServerInfo) {
    // Add jitter to prevent thundering herd when server with 300 ACs dies
    jitter := time.Duration(rand.Intn(5000)) * time.Millisecond  // 0-5s
    time.Sleep(jitter)

    // Re-register with retry logic
    for attempt := 1; attempt <= 5; attempt++ {
        err := ac.reRegisterViaFQDN()
        if err == nil {
            return
        }

        log.Warn("Re-registration failed", "attempt", attempt, "error", err)
        backoff := time.Duration(attempt*attempt) * time.Second  // 1s, 4s, 9s, 16s, 25s
        time.Sleep(backoff + jitter)
    }

    // After 5 failures, continue with remaining servers and retry in background
    log.Error("Re-registration failed after 5 attempts, continuing with remaining servers")
    go ac.backgroundReregistrationLoop()
}

func (ac *AC) reRegisterViaFQDN() error {
    // Connect to FQDN (any server via NLB)
    resp, err := ac.sendAOL(ac.fqdn)
    if err != nil {
        return err
    }

    if resp.ErrCode == "OVERLOADED" || resp.ErrCode == "SERVICE_UNAVAILABLE" {
        return fmt.Errorf("server returned %s", resp.ErrCode)
    }

    if resp.ErrCode != "SUCCESS" {
        return fmt.Errorf("registration failed: %s", resp.ErrCode)
    }

    // Get latest assignment (may have changed)
    newServers := resp.AssignedServers
    oldServers := ac.currentServers

    // Keep old connections alive during transition
    ac.connectToServers(newServers)

    go func() {
        time.Sleep(2 * time.Minute)
        ac.disconnectServers(oldServers)
    }()

    ac.currentServers = newServers
    return nil
}

func (ac *AC) backgroundReregistrationLoop() {
    for {
        time.Sleep(30 * time.Second)
        if err := ac.reRegisterViaFQDN(); err == nil {
            log.Info("Background re-registration succeeded")
            return
        }
    }
}
```

**Thundering herd mitigation:** When a server with 300 ACs dies, the 0-5s jitter spreads re-registrations over 5 seconds instead of an instant burst. This keeps DynamoDB load manageable (60 requests/second vs 300 instant).

**Flow when server fails:**
1. AC connected to [A, B, C]
2. Server A fails (Cloud Map detects, Console reassigns to [D, B, C])
3. AC detects A is down (keepalive timeout after 10s + 3 retries = ~17s)
4. AC re-registers via FQDN → gets assignment [D, B, C]
5. AC connects to D, keeps connections to B and C
6. After 2 minutes, AC drops connection to A (already dead anyway)

**Why this works:**
- Console only reassigns when server fails → AC will detect same failure
- Re-registration always gets authoritative latest assignment
- No version-checking overhead on every keepalive
- 2-minute overlap covers cache staleness during transition

**Edge case: AC loses connectivity to healthy server (network blip)**
```
AC connected to [A, B, C]
AC's network to A briefly disrupted (A is actually healthy)
AC detects A is "down" (keepalive timeout)
AC re-registers via FQDN
Gets assignment [A, B, C] (unchanged - A is fine)
AC reconnects to A (which works now)
```
This is handled correctly - re-registration is idempotent and AC gets the authoritative assignment. No special handling needed.

### 6.10 Server Assignment Rebalancing

**When server is removed from pool:**
1. Cloud Map health check fails
2. Console detects via Cloud Map API polling
3. Console queries DynamoDB GSI for ACs assigned to that server
4. Console reassigns affected ACs to new servers (maintaining AZ distribution)
5. On next keepalive, AC gets new assignment

**When server is added to pool:**
1. New server registers with Cloud Map (includes AZ)
2. New ACs get assigned to new server naturally
3. Optional: Console rebalances existing ACs (non-critical)

### 6.11 Rate Limiting

**Attack scenarios to mitigate:**
1. Registration flood - millions of fake NHP_AOL messages exhausting DynamoDB
2. Forward amplification - spoofed source IPs causing DDoS via forwarding

**Rate Limits:**
```go
const (
    RegistrationRateLimit = 10   // per minute, per IP
    KnockRateLimit        = 100  // per second, per IP
    ForwardRateLimit      = 1000 // per second, total server capacity
)

func (s *Server) HandlePacket(packet []byte, srcAddr net.Addr) {
    ip := srcAddr.(*net.UDPAddr).IP.String()
    msgType := parseMessageType(packet)

    switch msgType {
    case NHP_AOL:
        if !s.registrationLimiter.Allow(ip) {
            s.metrics.Inc("registration_rate_limited")
            return  // Silent drop
        }
    case NHP_KNK:
        if !s.knockLimiter.Allow(ip) {
            s.metrics.Inc("knock_rate_limited")
            return
        }
    }
    // Continue processing...
}
```

**DynamoDB Protection:**
```go
// Semaphore to cap concurrent DynamoDB calls
var dynamoSemaphore = make(chan struct{}, 100)

func (s *Server) validateLicense(customerId, licenseKey string) (bool, error) {
    select {
    case dynamoSemaphore <- struct{}{}:
        defer func() { <-dynamoSemaphore }()
    default:
        return false, ErrOverloaded
    }
    // Actual DynamoDB call...
}
```

**Server-side OVERLOADED handling:**
```go
func (s *Server) HandleACOnline(msg *ACOnlineMsg) {
    valid, err := s.validateLicense(msg.CustomerId, msg.LicenseKey)
    if err != nil {
        if errors.Is(err, ErrOverloaded) {
            // Return retryable error - AC should backoff and retry
            s.sendResponse(msg, &ServerACAckMsg{
                ErrCode: "OVERLOADED",
                ErrMsg:  "Server at capacity, retry in 5 seconds",
            })
            return
        }
        // Other errors...
    }
    // Continue registration...
}
```

**AC-side retry logic:**
```go
func (ac *AC) register() error {
    resp, err := ac.sendAOL()
    if err != nil {
        return err
    }

    switch resp.ErrCode {
    case "SUCCESS":
        return nil
    case "OVERLOADED":
        time.Sleep(5*time.Second + jitter())
        return ac.register()  // Retry with backoff
    case "SERVICE_UNAVAILABLE":
        time.Sleep(10*time.Second + jitter())
        return ac.register()  // Retry with longer backoff
    default:
        return fmt.Errorf("registration failed: %s", resp.ErrCode)
    }
}
```

### 6.12 Cloud Map Health Check Configuration

**v1 Configuration:** Cloud Map health check interval 10s, failure threshold 2.

This provides ~20 second server failure detection. Combined with the 2-minute AC connection overlap during reassignment, this ensures minimal knock failures during server failures.

```hcl
# Terraform configuration
resource "aws_service_discovery_service" "nhp_servers" {
  name = "nhp-servers"

  health_check_custom_config {
    failure_threshold = 2
  }
}

# Server registers with 10s heartbeat interval
```

**Detection timeline:**
- Server fails at T=0
- Cloud Map detects at T=20s (2 missed 10s heartbeats)
- Console polls and initiates reassignment at T=25s
- AC detects server down at T=17s (10s keepalive + 7s backoff)
- AC re-registers, gets new assignment at T=20s
- **Total disruption: ~20-25 seconds** (acceptable)

### 6.13 DynamoDB Availability Handling

**What happens when DynamoDB is unavailable:**

| Scenario | Impact | Mitigation |
|----------|--------|------------|
| DynamoDB down during new AC registration | Registration fails | Return `SERVICE_UNAVAILABLE`, AC retries with backoff |
| DynamoDB down during knock (cache hit) | No impact | Serve from cache |
| DynamoDB down during knock (cache miss) | Forward lookup fails | **Fail closed** - reject knock with `SERVICE_UNAVAILABLE` |
| DynamoDB down during Console reassignment | Reassignment blocked | Console retries with exponential backoff |

**Rationale for fail-closed on cache miss:**
- Security > availability for a security product
- DynamoDB has 99.99% SLA - brief outages are rare
- Cache should handle 99%+ of lookups during normal operation
- Better to reject a knock than allow unauthorized access

```go
func (s *Server) HandleKnockRequest(ppd *core.PacketParserData) {
    assignment, err := s.assignmentCache.GetAssignment(acId)
    if err != nil {
        if errors.Is(err, ErrDynamoDBUnavailable) {
            s.sendErrorToUser(ppd, "SERVICE_UNAVAILABLE")
            s.metrics.Inc("knock_dynamodb_unavailable")
            return
        }
        // Other errors...
    }
    // Continue with knock handling...
}
```

**Operational note:** Servers operate on cached data during brief DynamoDB outages. Only new registrations and cache misses are affected. Monitor `knock_dynamodb_unavailable` metric for alerts.

### 6.14 NHP Spec Compliance

This section documents deviations from the official NHP specification and their rationale.

#### 6.14.1 Extended NHP_AOL with License Credentials

**Spec Definition:**
- NHP_AOL (Type 10): "Used by the NHP-AC to connect to and notify the NHP-Server of online status changes"
- Fields: AC ID, Service and Application Info

**LayerV Extension:**
```go
type ACOnlineMsg struct {
    // Standard NHP_AOL fields
    AuthServiceId string   `json:"aspId"`
    ResourceIds   []string `json:"resIds"`

    // LayerV extension: License credentials
    ACId          string   `json:"acId"`
    LicenseKey    string   `json:"licenseKey"`  // Globally unique license key
}
```

**Rationale:** The spec's NHP_AOL says "connect to" - initial connection is part of NHP_AOL semantics. Adding license credentials to initial connection is a LayerV extension for SaaS licensing. The alternative (NHP_REG) is specified for agents, not ACs.

**Note:** `CustomerId` and `ResourceFQDN` were removed in favor of globally unique license keys. This simplifies the authentication model - the license key alone is sufficient for lookup and validation.

#### 6.14.2 Server-to-Server Forwarding (NHP_FWD/NHP_FRT)

**Extension with Compliant Encryption:** NHP_FWD (28) and NHP_FRT (29) are LayerV extensions to the NHP message type space. The encryption uses **Noise K pattern** with per-server keypairs, which is fully spec-compliant.

**Message Type Space:**
- NHP spec defines types 0-17
- LayerV uses 28-29 for forwarding to avoid collision with future spec additions
- Consider proposing these to OpenNHP project for standardization

**Spec Requirement:**
> "In NHP, the modern Noise Protocol Framework is introduced for message encryption and mutual verification"

**LayerV Implementation:**
- Each server has unique keypair (persisted in SSM Parameter Store)
- Servers register public key in Cloud Map on startup
- Forwarding uses existing `Device.MsgToPacket()` Noise infrastructure
- Full forward secrecy via ephemeral keys

**Benefits:**
1. **Forward secrecy:** Captured traffic remains protected even if server key later compromised
2. **Single-server blast radius:** Compromised key only affects that server
3. **Code reuse:** Uses existing Noise infrastructure, no separate crypto path
4. **Operational simplicity:** Per-server key rotation without coordination

**Implementation Details:**
- Key discovery: Cloud Map attribute `public_key` contains base64-encoded server public key
- Peer caching: Servers cache peer objects for known targets
- Same port: NHP_FWD detected by message type, not separate port

#### 6.14.3 Authorization Service Provider (ASP)

**Spec Pattern:**
> "The NHP-Server authenticates the NHP-Agent's identity... locates the corresponding ASP server (typically the identity and access management (IAM) system)"

**LayerV Implementation:**
- ASP = Console + DynamoDB
- License validation via direct DynamoDB lookup (not external ASP query)
- Console issues licenses and manages AC assignments

**Rationale:** For LayerV's SaaS model where we control the full stack, Console + DynamoDB provides the ASP function. The ASP abstraction is preserved for future enterprise IAM integration.

#### 6.14.4 Deployment Topology

**Spec Topology:**
```
NHP-Agent → NHP-Server → NHP-AC → Protected Resource
```

**LayerV Topology:**
```
NHP-Agent → NLB → Server Pool → (forward) → Assigned Server → NHP-AC
```

**Extensions:**
- Load-balanced server pool behind NLB
- Per-AC server assignment (3 servers per AC)
- Server-to-server forwarding for misrouted knocks

**Rationale:** The spec is agnostic to deployment topology. Protocol messages remain compliant; the topology is a scaling implementation detail. This enables horizontal scaling to 1000s of servers and 100Ks of ACs.

#### 6.14.5 Compliance Summary

| Area | Spec Compliance | Notes |
|------|-----------------|-------|
| NHP_KNK (knock) | ✅ Compliant | Standard Noise encryption |
| NHP_ACK (ack) | ✅ Compliant | Standard Noise encryption |
| NHP_AOP (access op) | ✅ Compliant | Standard Noise encryption |
| NHP_AOL (AC online) | ⚠️ Extended | Added license credentials |
| NHP_AAK (AC ack) | ✅ Compliant | Simple success/error ack (no longer contains assigned servers) |
| **NHP_ARD (redispatch)** | ✅ Compliant | **New NHP spec message (Type 30)** - redirects AC to assigned servers |
| NHP_FWD (forward) | ⚠️ Extension | LayerV extension (Type 28), uses compliant Noise K |
| NHP_FRT (forward result) | ⚠️ Extension | LayerV extension (Type 29), uses compliant Noise K |
| ASP pattern | ⚠️ Simplified | Console + DynamoDB |
| Deployment topology | ✅ Compliant | Spec is topology-agnostic |

**Legend:** ✅ Fully compliant | ⚠️ Extended/simplified | ❌ Deviation (documented)

**Note on NHP_ARD vs NHP_FWD:**
- NHP_ARD (Type 30) is **spec-compliant** - it's a new addition to the NHP specification
- NHP_FWD/FRT (Types 28/29) are **LayerV extensions** - needed for knock forwarding in multi-server pools
- Both serve different purposes: ARD for AC registration redirect, FWD for knock forwarding

---

## 7. Security Considerations

### 7.1 Threat Model Changes

| Threat | Current (etcd) | Proposed (DynamoDB) | Status |
|--------|----------------|---------------------|--------|
| Compromised AC writes to etcd | Possible | **Eliminated** | Improved |
| etcd credential leak | High impact | **N/A** | Eliminated |
| AC impersonation | Possible via etcd | License key validation | Improved |
| Server-to-server MITM | N/A | Noise K encryption (per-server keys) | New, mitigated |
| DynamoDB access from AC | N/A | **Impossible** (server-only) | Secure |

### 7.2 Security Controls

**License Key Security:**
- Keys stored as bcrypt hashes in DynamoDB
- Plaintext keys never logged
- Keys transmitted over NHP (encrypted)
- Key rotation supported via Console

**Server-to-Server Security (Noise K):**
- Per-server keypairs (unique to each server)
- Public keys discovered via Cloud Map
- Forward secrecy via ephemeral keys
- Rotation: Restart individual server (no coordination needed)

**DynamoDB Access Control:**
- Servers have read-only IAM role
- Console has read-write IAM role
- ACs have NO DynamoDB access
- All tables encrypted with KMS CMK

### 7.3 Credential Distribution

| Credential | Current | Proposed |
|------------|---------|----------|
| etcd CA cert | All ACs, All Servers | **Eliminated** |
| etcd client cert | All ACs, All Servers | **Eliminated** |
| etcd client key | All ACs, All Servers | **Eliminated** |
| Server keypair | N/A | Per-server (unique, auto-generated) |
| License key | N/A | Per-customer (AC config) |
| NHP keypair | Per-AC | Per-AC (unchanged) |

---

## 8. Testing Strategy

### 8.1 Unit Tests

| Test Area | Description |
|-----------|-------------|
| AZ-aware assignment | Verify 3 servers from 3 different AZs |
| License validation | Verify bcrypt comparison, expiration |
| Server peer discovery | Verify Cloud Map key lookup and caching |
| LRU cache with TTL | Verify cache hit/miss, expiration |
| Message serialization | New NHP_FWD, NHP_FRT messages |

### 8.2 Integration Tests

| Test | Success Criteria |
|------|------------------|
| AC registration | AC sends NHP_AOL, receives 3 server IPs in different AZs |
| Direct knock handling | Knock at assigned server → AOP sent directly |
| Forwarded knock | Knock at non-assigned server → forward → AOP works |
| Forwarding failover | First target down → forward to second succeeds |
| License validation | Invalid license → registration rejected |
| Server reassignment | Server fails → Console reassigns → AC gets new servers |

### 8.3 End-to-End Tests

| Test | Steps | Expected Result |
|------|-------|-----------------|
| Full NAT flow | AC behind NAT, knock at random server | Forwarding works, AOP received |
| AZ failover | Kill all servers in one AZ | AC continues with 2 remaining servers |
| Server replacement | Replace assigned server | AC gets new assignment on keepalive |
| Scale test | 100 ACs, 10 servers, random knocks | All knocks succeed |
| Latency test | Measure with/without forwarding | <5ms additional latency |

### 8.4 Manual Verification Steps

1. Deploy DynamoDB tables in sandbox
2. Deploy 3+ servers across 3 AZs
3. Register test AC via Console
4. Verify AC connects to all 3 assigned servers (different AZs)
5. Send knock, verify AOP received by AC
6. Kill one assigned server
7. Verify knock still works via forwarding to remaining servers
8. Verify Console reassigns AC to new server
9. Check CloudWatch metrics for forwarding latency

---

## 9. Migration Plan

### Phase 1: Parallel Write (Week 1-2)

1. Deploy new DynamoDB tables
2. Update Console to write assignments to BOTH etcd AND DynamoDB
3. Servers continue reading from etcd (no change yet)
4. Verify DynamoDB data matches etcd via audit script

### Phase 2: Server Dual-Read (Week 2-3)

1. Deploy server update with DynamoDB client
2. Server reads from DynamoDB with etcd fallback (feature flag)
3. Monitor for any DynamoDB read failures
4. Gradually shift traffic: 10% → 50% → 100% DynamoDB

### Phase 3: AC Update (Week 3-4)

1. Deploy AC update that handles NHP_AAK with server list
2. AC connects to assigned servers instead of all servers
3. Monitor AC connectivity and knock success rates
4. Add server-to-server forwarding

### Phase 4: etcd Removal (Week 4-5)

1. Stop Console writes to etcd
2. Remove etcd read paths from servers
3. Delete etcd cluster infrastructure
4. Delete `nhp/etcd/` directory from codebase

### Data Migration Script

```bash
# Export from etcd, transform, write to DynamoDB
for ac in $(etcdctl get /nhp/ac-registry --prefix --keys-only); do
    data=$(etcdctl get $ac --print-value-only)
    # Transform and assign servers
    transformed=$(transform_ac_data "$data")
    aws dynamodb put-item --table-name nhp_ac_assignments --item "$transformed"
done
```

### Rollback Plan

- Each phase can be rolled back independently
- Keep etcd running until Phase 4 completion
- Feature flags control read/write paths
- DynamoDB data can be deleted if rollback needed

---

## 10. Implementation Phases

### Phase 1: Core Infrastructure

**Duration:** 2 weeks

**Deliverables:**
- DynamoDB tables (Terraform)
- SSM Parameter Store for keypairs (registration + per-server)
- Cloud Map with AZ attribute
- Server IAM policies

**Files:**
| File | Changes |
|------|---------|
| `terraform/modules/dynamodb/` | NEW - Tables with GSIs |
| `terraform/modules/ssm/` | NEW - SSM Parameter Store for registration keypair; per-server keys created at runtime |
| `terraform/modules/cloudmap/` | Add AZ attribute |
| `terraform/modules/server/iam.tf` | DynamoDB read permissions |

### Phase 2: Server Changes

**Duration:** 2 weeks

**Deliverables:**
- DynamoDB client wrapper
- Assignment cache
- Extended message handling
- Server-to-server forwarding

**Files:**
| File | Changes |
|------|---------|
| `nhp/core/packet.go` | Add NHP_FWD (28), NHP_FRT (29), NHP_ARD (30) |
| `nhp/common/nhpmsg.go` | Add ACRedispatchMsg (NHP_ARD), ServerForwardMsg (NHP_FWD), simplify ServerACAckMsg |
| `endpoints/server/dynamodb.go` | NEW - DynamoDB client |
| `endpoints/server/cache.go` | NEW - LRU cache with TTL |
| `endpoints/server/forward.go` | NEW - Forwarding logic |
| `endpoints/server/msghandler.go` | Extend HandleACOnline |
| `endpoints/server/nhpauth.go` | Add forwarding to knock handling |
| `endpoints/server/config.go` | Add DynamoDB, SSM Parameter Store config |

### Phase 3: AC Changes

**Duration:** 1 week

**Deliverables:**
- Parse assigned servers from NHP_AAK
- Multi-server connection management
- Reconnection logic

**Files:**
| File | Changes |
|------|---------|
| `endpoints/ac/config.go` | Add credentials config |
| `endpoints/ac/udpac.go` | Multi-server connection |
| `endpoints/ac/registration.go` | NEW - Registration flow |

### Phase 4: Console Changes

**Duration:** 1 week

**Deliverables:**
- AZ-aware server assignment
- DynamoDB writes for assignments
- Server failure detection and reassignment

**Files (separate repo):**
| File | Changes |
|------|---------|
| `services/ac.go` | AZ-aware assignment |
| `services/reassignment.go` | NEW - Failure handling |
| `models/ac.go` | Add assigned_servers |

### Phase 5: etcd Removal

**Duration:** 1 week

**Deliverables:**
- Remove all etcd code
- Delete etcd infrastructure
- Update documentation

**Files:**
| File | Changes |
|------|---------|
| `nhp/etcd/` | DELETE entire directory |
| `terraform/modules/etcd/` | DELETE entire module |
| `endpoints/*/config.go` | Remove etcd config |

---

## 11. Open Questions

### Resolved

| # | Question | Decision |
|---|----------|----------|
| 1 | Unique vs shared server keys? | **Unique (Noise K)** - Per-server keypairs via Cloud Map |
| 2 | How many servers per AC? | **3** - One per AZ for resilience |
| 3 | HTTP for discovery? | **No** - UDP only via NHP protocol |
| 4 | Cell-based architecture? | **No** - Per-resource FQDN model |
| 5 | Inter-server encryption? | **Noise K** - Per-server keys, forward secrecy |

### Resolved (from review)

| # | Question | Decision | Reference |
|---|----------|----------|-----------|
| 6 | Forward timeout | **2s per server** | Section 6.5 code |
| 7 | Health check interval | **10s interval, 2 failures** | Section 6.12 |
| 8 | Version mismatch detection | **AC re-registers on any server failure** | Section 6.9 |
| 9 | Keepalive interval | **10s interval, 3s timeout, 3 retries** | Section 6.9 |

### Pending

| # | Question | Options | Recommendation |
|---|----------|---------|----------------|
| 1 | Cache TTL | 30s / 60s / 120s | 60s (with 5s adaptive during reassignment) |

---

## 12. Appendix

### A. Configuration Changes

**AC config.toml (new format):**
```toml
[AC]
ACId = "ac-instance-001"
ServerEndpoint = "server.nhp.sandbox.internal"  # Where to connect
LicenseKey = "lk_xxxxx"                          # Globally unique license key
ServerPubKeyBase64 = "base64-encoded-server-public-key"

PrivKeyBase64 = "..."
ListenPort = 62206

[IPTables]
DefaultAcceptTimeoutSec = 60
```

**Credential Provisioning:** AC credentials (`ACId`, `LicenseKey`, `ServerPubKeyBase64`, `ServerEndpoint`) are provisioned via Console UI download or API. Deployment options include cloud-init user-data, configuration management (Ansible/Puppet), or manual configuration. See Operations Guide for deployment patterns.

**Note:** `CustomerId` and `ResourceFQDN` were removed. `ServerEndpoint` specifies where to connect (internal DNS or public NLB). `LicenseKey` is globally unique and sufficient for authentication.

**Server config.toml (new format):**
```toml
[Server]
ServerId = "srv-001"
PublicIP = "1.2.3.4"
ListenPort = 62206
PrivKeyBase64 = "..."  # Unique per server (auto-generated or from Secrets Manager)

[DynamoDB]
Region = "us-east-2"
LicensesTable = "nhp_licenses"
ACAssignmentsTable = "nhp_ac_assignments"
ResourcesTable = "nhp_resources"

[CloudMap]
Namespace = "nhp.internal"
Service = "nhp-servers"
```

**Note on Server Keypairs:** Each server has a unique keypair that MUST be persisted in SSM Parameter Store. On first start, the server generates a keypair and stores it as a SecureString parameter (`/nhp/server/{id}/private-key`). On subsequent starts, it loads the existing key. This prevents peer cache invalidation issues when servers restart. The public key is registered in Cloud Map for peer discovery.

**Removed from AC:**
- `remote.toml` (etcd connection)
- `/opt/layerv/nhp-ac/etc/tls/*` (etcd certificates)

**Removed from Server:**
- `remote.toml` (etcd connection)
- etcd certificate paths

### B. Error Codes

**All error codes are strings for consistency.**

**Registration Errors (AC retries automatically):**

| Code | Description | AC Retry Backoff |
|------|-------------|------------------|
| SUCCESS | Operation successful | N/A |
| AUTH_FAILED | Invalid customer ID or license key | No retry (fatal) |
| LICENSE_EXPIRED | License past expiration date | No retry (fatal) |
| LICENSE_INACTIVE | License has been revoked | No retry (fatal) |
| AC_NOT_ASSIGNED | No server assignment found | No retry (fatal) |
| OVERLOADED | Server at capacity | 5s backoff |
| SERVICE_UNAVAILABLE | Backend service unavailable (DynamoDB) | 10s backoff |

**Knock Errors (User/client retries):**

| Code | Description | User Guidance |
|------|-------------|---------------|
| FORWARD_FAILED | Could not forward to any assigned server | Retry in 5s |
| ALL_SERVERS_DOWN | All 3 assigned servers unreachable | Retry in 5s |
| RATE_LIMITED | Too many requests | Retry in 1s |

### C. Metrics and Monitoring

**Server Metrics:**
```
nhp_knock_total{result="direct|forwarded|failed"}
nhp_forward_latency_ms
nhp_forward_attempts{result="success|timeout|error"}
nhp_dynamodb_cache_hit_ratio
nhp_ac_connections_total
nhp_registration_total{result="success|failed"}
```

**AC Metrics:**
```
nhp_server_connections_active
nhp_registration_attempts{result="success|failed"}
nhp_aop_received_total
```

**Alerts:**
- AC connections < 2 for > 5 minutes
- Forwarding failure rate > 10%
- DynamoDB cache hit ratio < 50%
- Registration success rate < 95%

### D. Cost Analysis

**DynamoDB:**
- 100K ACs, 60s cache TTL, 99% hit rate
- ~10K reads/day = ~$0.003/day (negligible)

**SSM Parameter Store:**
- N parameters (per-server keypairs + 1 registration keypair) = $0/month (Standard tier SecureString, up to 10K parameters)

**Cloud Map:**
- Free tier covers usage

**Savings:**
- Eliminate 3-node etcd cluster (~$150-300/month)

### E. Console as Single Point of Failure Analysis

**Problem:** Console handles server assignment and reassignment. If Console is down:

| Operation | Impact |
|-----------|--------|
| New AC registration | BLOCKED |
| Existing AC keepalive | Works |
| Existing AC reconnect | Works (assignment in DynamoDB) |
| User knock (normal) | Works |
| Server failure → reassignment | BLOCKED |

**Mitigation:**
- **v1:** Single Console is acceptable; document failure modes
- **Before enterprise:** Console HA via ECS service (2+ replicas, ~$300/month)
- **At scale:** Consider distributed reassignment (servers detect failures, claim reassignment lock)

### F. Architecture Review Feedback Summary

Feedback incorporated from architecture review (v2.1, v2.2, v2.3):

| Issue | Severity | Resolution |
|-------|----------|------------|
| NHP_FWD replay protection | Low | Added `Timestamp` field to NHP_FWD, reject >30s old |
| Cache invalidation during reassignment | **HIGH** | AC keeps old connections for 2 min + adaptive TTL (5s during transition) |
| Reassignment race condition | **HIGH** | Added `reassigned_at` field, triggers short cache TTL |
| Forward order static | Medium | Random shuffle + health tracking with 30s decay |
| Cloud Map health latency | Medium | Committed to 10s interval, 2 failures (Section 6.12) |
| Reconnection backoff | Medium | Documented: 1s/2s/4s, 30s max, 20% jitter |
| Rate limiting | **HIGH** | Added section with specific limits per message type |
| Error code typing | Low | Changed `0` to `SUCCESS` (all strings) |
| Console SPOF | Medium | Documented failure modes, HA plan for enterprise |
| License key logging | Low | Reminder to never log license keys |
| **Version mismatch detection** | **CRITICAL** | AC re-registers on ANY server failure (not version check) |
| **OVERLOADED error handling** | **HIGH** | Added server and AC code for retry with backoff |
| **DynamoDB availability** | **HIGH** | Added section 6.13: fail-closed on cache miss |
| **nhp_resources clarification** | Low | Clarified resource_id vs resource_fqdn relationship |
| Section numbering | Low | Fixed duplicate 6.5, renumbered through 6.13 |
| Keepalive interval | Medium | Added explicit parameters: 10s interval, 3s timeout |
| AC credential provisioning | Medium | Added note about Console UI/API download |
| **Thundering herd** | **HIGH** | Added 0-5s jitter before re-registration |
| **Re-registration failure** | **HIGH** | Added retry with exponential backoff + background loop |
| Error codes: who retries | Low | Split into Registration vs Knock errors |
| Failure detection timeline | Low | Added explicit timeline showing ~12-17s detection |
| Network blip edge case | Low | Documented that re-registration is idempotent |
| **NHP_AOL vs NHP_REG** | Medium | Documented as LayerV extension (NHP_REG is for agents) |
| **Server-to-server encryption** | **HIGH** | Changed to Noise K pattern (per-server keys, forward secrecy) - now compliant |
| **ASP pattern simplification** | Low | Documented Console + DynamoDB as ASP |
| **Deployment topology** | Low | Documented as spec-agnostic implementation detail |

---

## Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-01-10 | Architecture Team | Initial draft (cell-based) |
| 2.0 | 2026-01-11 | Architecture Team | Complete rewrite: per-AC assignment, no etcd, DynamoDB |
| 2.1 | 2026-01-11 | Architecture Team | Incorporated review feedback: replay protection, adaptive TTL, rate limiting, health tracking |
| 2.2 | 2026-01-11 | Architecture Team | Critical fix: AC re-registers on server failure (not version check); DynamoDB availability; OVERLOADED handling |
| 2.3 | 2026-01-11 | Architecture Team | Fixed section numbering; added keepalive parameters; thundering herd mitigation; re-registration retry logic; credential provisioning note |
| 2.4 | 2026-01-11 | Architecture Team | Added NHP Spec Compliance section (6.14); documented deviations and rationale for NHP_AOL extension, cluster key, ASP pattern |
| 2.5 | 2026-01-11 | Architecture Team | Changed server-to-server from cluster key to Noise K pattern; per-server keypairs via Cloud Map; now fully spec compliant |
| 2.6 | 2026-01-11 | Architecture Team | Added Noise K implementation details (e, es, ss tokens); mandatory keypair persistence; NHP_FWD/FRT as extensions (type 28/29); cross-region limitation; updated cost analysis |
| 2.7 | 2026-01-11 | Architecture Team | Added dual keypair model (shared registration + per-server forwarding); SSM Parameter Store instead of Secrets Manager ($0 vs $400/month at 1000 servers); peer cache TTL (1 hour); ServerInfo.PubKeyBase64 clarification |
| 2.8 | 2026-01-11 | Architecture Team | Fixed stale Secrets Manager reference in 6.14.2; updated keypair init to load both registration and forwarding keys; added SSM error handling (distinguish "not found" vs "unavailable") |
| 2.9 | 2026-01-11 | Architecture Team | Moved "backward compatibility during migration" from Goals (G6) to Non-Goals (NG5); clean cutover, no dual-mode |
| 2.10 | 2026-01-11 | Architecture Team | Added etcd as feature flag for on-prem; pluggable StorageBackend interface; DynamoDB default for cloud, etcd for self-hosted |
| 2.11 | 2026-01-13 | Architecture Team | Added NHP_ARD (AC Redispatch, Type 30) - new NHP spec message for AC registration redirect; clarified NHP_ARD vs NHP_FWD purposes; simplified NHP_AAK (removed AssignedServers) |

---

*End of Document*
