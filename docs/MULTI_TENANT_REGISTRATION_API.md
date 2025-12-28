# Multi-Tenant AC Registration API Design

**Version**: 1.0
**Status**: Ready for Implementation
**Last Updated**: December 2025

---

## Executive Summary

This document defines the AC (Access Controller) registration architecture for LayerV's deployment models. The design supports three deployment scenarios:

1. **LayerV-Managed**: NHP Server + AC co-located, operated by LayerV (SaaS)
2. **Customer-Managed**: NHP Server + AC co-located, operated by customer (on-prem/self-hosted)
3. **Customer-Deployed AC**: NHP Server in LayerV cloud, AC in customer environment (hybrid)

The key insight: **AWS Instance Identity verification is inappropriate for cross-account/cross-cloud deployments**. Instead, we adopt the industry-standard **Registration Token** model used by Datadog, Teleport, Cloudflare Tunnel, and similar distributed agent systems.

---

## Infrastructure Overview

### Environment Architecture

LayerV runs **two etcd clusters** (one per environment):

| Environment | etcd Cluster | NHP Server Endpoint | Region |
|-------------|--------------|---------------------|--------|
| Sandbox | `etcd.nhp.sandbox.internal:2379` | `nhp.sandbox.layerv.cloud:62206` | us-east-2 |
| Production | `etcd.nhp.prod.internal:2379` | `nhp.layerv.cloud:62206` | us-east-2 |

Each environment is fully isolated. Customer-deployed ACs connect to the appropriate environment's Server fleet.

### Multi-Region Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              LayerV Global                                   │
│                                                                              │
│   ┌─────────────────────┐                                                    │
│   │      Console        │◄──── Single global instance                        │
│   │  (Token Authority)  │      Validates tokens for all regions              │
│   └──────────┬──────────┘                                                    │
│              │                                                               │
│   ┌──────────┴──────────┬─────────────────────┐                              │
│   │                     │                     │                              │
│   ▼                     ▼                     ▼                              │
│ ┌─────────────┐   ┌─────────────┐   ┌─────────────┐                          │
│ │  us-east-2  │   │  us-west-2  │   │  eu-west-1  │  (Future)                │
│ │ NHP Servers │   │ NHP Servers │   │ NHP Servers │                          │
│ │    etcd     │   │    etcd     │   │    etcd     │                          │
│ └─────────────┘   └─────────────┘   └─────────────┘                          │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘

Customer AC connects to nearest region. Same token works globally.
Token validation always goes to Console (cached 60s at each Server).
```

### Capacity Limits

| Resource | Limit | Notes |
|----------|-------|-------|
| ACs per tenant | 1,000 | Soft limit, increase on request |
| Registrations per token | Configurable | Default unlimited, can set max |
| etcd keys per tenant | ~1,100 | 1000 ACs + 100 config keys |
| Total etcd keys | 100,000 | Across all tenants per cluster |
| Token cache entries | 10,000 | Per Server instance |

---

## Deployment Scenarios

### Scenario 1: LayerV-Managed (SaaS)

LayerV operates everything. Customer accesses protected resources but doesn't manage infrastructure.

```
┌─────────────────────────────────────────────────────────────────┐
│                    LayerV Cloud                                 │
│                                                                 │
│  ┌─────────────┐     ┌─────────────┐     ┌─────────────┐        │
│  │ NHP Server  │────►│    etcd     │◄────│   NHP AC    │        │
│  └─────────────┘     └─────────────┘     └─────────────┘        │
│        │                   │                    │               │
│        │     mTLS          │      mTLS          │               │
│        └───────────────────┴────────────────────┘               │
└─────────────────────────────────────────────────────────────────┘
```

**Trust Model**: etcd mTLS certificates provide mutual authentication.

**AC Registration**: Direct etcd writes with mTLS client certs. No registration API needed.

---

### Scenario 2: Customer-Managed (On-Prem / Self-Hosted)

Customer operates everything in their own environment. LayerV provides software only.

```
┌─────────────────────────────────────────────────────────────────┐
│                    Customer Environment                         │
│                                                                 │
│  ┌─────────────┐     ┌─────────────┐     ┌─────────────┐        │
│  │ NHP Server  │────►│    etcd     │◄────│   NHP AC    │        │
│  └─────────────┘     └─────────────┘     └─────────────┘        │
│        │                   │                    │               │
│        │     mTLS          │      mTLS          │               │
│        └───────────────────┴────────────────────┘               │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │ License Server (optional phone-home to LayerV)          │    │
│  └─────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

**Trust Model**: Customer manages their own etcd mTLS certificates.

**AC Registration**: Direct etcd writes with mTLS client certs. Customer generates certs using provided tooling.

**Licensing Model**:

| License Type | Validation | Use Case |
|--------------|------------|----------|
| Online | Daily phone-home to `license.layerv.cloud` | Internet-connected environments |
| Offline | Cryptographic license file, annual renewal | Air-gapped environments |
| Trial | 30-day, online validation required | Evaluation |

License includes: max ACs, max protected resources, support tier, expiration date.

**Customer Deliverables**:
- Docker images (NHP Server, AC) or native binaries
- Terraform modules for AWS/GCP/Azure
- Helm charts for Kubernetes
- etcd certificate generation scripts
- Operations runbook

---

### Scenario 3: Customer-Deployed AC (Hybrid SaaS)

NHP Server in LayerV cloud, AC in customer's environment. **This is the primary use case for the Registration API.**

```
┌──────────────────────────────┐     ┌──────────────────────────────┐
│     LayerV Cloud             │     │    Customer Environment      │
│                              │     │    (AWS/GCP/Azure/On-Prem)   │
│  ┌─────────────┐             │     │                              │
│  │   Console   │─────────────┼─────┼───► Registration Token       │
│  │    API      │             │     │                              │
│  └──────┬──────┘             │     │     ┌─────────────┐          │
│         │                    │     │     │   NHP AC    │          │
│         ▼                    │     │     │ (Customer)  │          │
│  ┌─────────────┐  HTTP API   │     │     └──────┬──────┘          │
│  │ NHP Server  │◄────────────┼─────┼────────────┘                 │
│  │             │             │     │     POST /v1/ac/register     │
│  └──────┬──────┘             │     │                              │
│         │                    │     │                              │
│         ▼                    │     │                              │
│  ┌─────────────┐             │     │                              │
│  │    etcd     │             │     │                              │
│  └─────────────┘             │     │                              │
└──────────────────────────────┘     └──────────────────────────────┘
```

**Trust Model**: Registration Token authenticates AC to Server.

**AC Registration**: HTTPS POST to Server API with Bearer token.

---

### Scenario Comparison

| Aspect | LayerV-Managed | Customer-Managed | Customer-Deployed AC |
|--------|----------------|------------------|---------------------|
| NHP Server | LayerV operates | Customer operates | LayerV operates |
| NHP AC | LayerV operates | Customer operates | Customer operates |
| etcd | LayerV operates | Customer operates | LayerV operates |
| AC Registration | etcd mTLS | etcd mTLS | **Registration API** |
| Trust Anchor | etcd client cert | etcd client cert | **Registration Token** |
| Customer manages certs | No | Yes | No |
| This doc applies | Partially | Partially | **Fully** |

---

## Registration Flow (Scenario 3)

### Sequence Diagram

```
┌────────┐          ┌────────┐          ┌────────┐          ┌────────┐
│Customer│          │   AC   │          │ Server │          │Console │
└───┬────┘          └───┬────┘          └───┬────┘          └───┬────┘
    │                   │                   │                   │
    │ 1. Create tenant  │                   │                   │
    │───────────────────┼───────────────────┼──────────────────►│
    │                   │                   │                   │
    │ 2. Receive token  │                   │                   │
    │◄──────────────────┼───────────────────┼───────────────────│
    │                   │                   │                   │
    │ lv_ac_acme_7Bj2kX9mNqRsT4uVwYz1Ab... │                   │
    │                   │                   │                   │
    │ 3. Deploy AC with │                   │                   │
    │    token in env   │                   │                   │
    │──────────────────►│                   │                   │
    │                   │                   │                   │
    │                   │ 4. Generate keypair                   │
    │                   │──────────┐        │                   │
    │                   │          │        │                   │
    │                   │◄─────────┘        │                   │
    │                   │                   │                   │
    │                   │ 5. POST /v1/ac/register               │
    │                   │   Authorization: Bearer <token>       │
    │                   │   { public_key, hostname, ip }        │
    │                   │──────────────────►│                   │
    │                   │                   │                   │
    │                   │                   │ 6. Validate token │
    │                   │                   │──────────────────►│
    │                   │                   │                   │
    │                   │                   │ 7. Token valid,   │
    │                   │                   │    tenant: acme   │
    │                   │                   │◄──────────────────│
    │                   │                   │                   │
    │                   │                   │ 8. Store in etcd  │
    │                   │                   │   /nhp/tenants/   │
    │                   │                   │   acme/acs/ac_123 │
    │                   │                   │──────────┐        │
    │                   │                   │          │        │
    │                   │                   │◄─────────┘        │
    │                   │                   │                   │
    │                   │ 9. 201 Created    │                   │
    │                   │   { ac_id, server_public_key,         │
    │                   │     nhp_endpoints }                   │
    │                   │◄──────────────────│                   │
    │                   │                   │                   │
    │                   │ 10. Dial NHP Server (UDP 62206)       │
    │                   │      NHP_AOL message                  │
    │                   │──────────────────►│                   │
    │                   │                   │                   │
    │                   │ 11. NHP_AAK       │                   │
    │                   │◄──────────────────│                   │
    │                   │                   │                   │
    │                   │     [Connected - Ready for knocks]    │
    │                   │                   │                   │
```

### Error Recovery Flows

#### Registration Failure

```
┌────────┐          ┌────────┐          ┌────────┐
│   AC   │          │ Server │          │Console │
└───┬────┘          └───┬────┘          └───┬────┘
    │                   │                   │
    │ POST /v1/ac/register                  │
    │──────────────────►│                   │
    │                   │                   │
    │                   │ Validate token    │
    │                   │──────────────────►│
    │                   │                   │
    │                   │ 401 Invalid token │
    │                   │◄──────────────────│
    │                   │                   │
    │ 401 Unauthorized  │                   │
    │◄──────────────────│                   │
    │                   │                   │
    │ [Retry with backoff: 1s, 2s, 4s, 8s, max 60s]            │
    │ [After 10 failures: exit with error, alert operator]     │
    │                   │                   │
```

#### Registration Success, NHP Connect Failure

```
┌────────┐          ┌────────┐
│   AC   │          │ Server │
└───┬────┘          └───┬────┘
    │                   │
    │ POST /v1/ac/register (succeeds)
    │◄─────────────────►│
    │                   │
    │ Dial NHP Server   │
    │──────────────────►│
    │                   │
    │ [Connection timeout / ECDH failure]
    │                   │
    │ [DO NOT re-register - already registered]
    │ [Retry NHP connect with backoff]
    │ [Log: "Registration OK, NHP connect failed"]
    │                   │
    │ Dial NHP Server (retry)
    │──────────────────►│
    │                   │
```

#### AC Restart (Re-registration)

```
┌────────┐          ┌────────┐
│   AC   │          │ Server │
└───┬────┘          └───┬────┘
    │                   │
    │ [AC restarts, same keypair]
    │                   │
    │ POST /v1/ac/register
    │   { same public_key }
    │──────────────────►│
    │                   │
    │ 409 Conflict      │
    │   { "ac_id": "ac_acme_abc123",
    │     "server_public_key": "...",
    │     "nhp_endpoints": [...] }
    │◄──────────────────│
    │                   │
    │ [Treat 409 as success]
    │ [Use returned ac_id and server info]
    │                   │
    │ Dial NHP Server   │
    │──────────────────►│
    │                   │
```

---

## Registration Token Model

### Token Format

```
Format:  lv_ac_{tenant_prefix}_{random_32_bytes_base64url}
         └─────┬─────┘└────┬────┘└────────────┬───────────┘
           Prefix    Tenant hint     Cryptographic random

Example: lv_ac_acme_7Bj2kX9mNqRsT4uVwYz1AbCdEfGhIjKlMnOpQrSt

Breakdown:
  - "lv_ac_"  : Prefix for AC registration tokens (vs other token types)
  - "acme"    : First 4-8 chars of tenant_id (for quick DB lookup)
  - "_"       : Separator
  - "7Bj2..." : 32 bytes of crypto/rand, base64url encoded (43 chars)

Total length: ~55-60 characters
```

### Token Generation

```go
func GenerateRegistrationToken(tenantID string) (string, error) {
    // 1. Generate 32 bytes of cryptographic randomness
    randomBytes := make([]byte, 32)
    if _, err := crypto_rand.Read(randomBytes); err != nil {
        return "", err
    }

    // 2. Base64url encode (no padding)
    randomPart := base64.RawURLEncoding.EncodeToString(randomBytes)

    // 3. Take first 8 chars of tenant ID as hint
    tenantPrefix := tenantID
    if len(tenantPrefix) > 8 {
        tenantPrefix = tenantPrefix[:8]
    }

    // 4. Combine
    token := fmt.Sprintf("lv_ac_%s_%s", tenantPrefix, randomPart)

    return token, nil
}
```

### Token Storage (Console Database)

```sql
CREATE TABLE ac_registration_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    token_hash VARCHAR(64) NOT NULL,      -- SHA-256 of full token
    token_prefix VARCHAR(20) NOT NULL,    -- "lv_ac_acme" for fast lookup
    name VARCHAR(255),                     -- Human-readable: "Production ACs"
    max_registrations INT DEFAULT 0,       -- 0 = unlimited
    registration_count INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT NOW(),
    last_used_at TIMESTAMP,
    revoked_at TIMESTAMP,
    expires_at TIMESTAMP,                  -- Optional expiration
    allowed_ips CIDR[],                    -- Optional IP allowlist
    UNIQUE(token_hash)
);

-- Index for fast prefix lookup
CREATE INDEX idx_token_prefix ON ac_registration_tokens(token_prefix)
    WHERE revoked_at IS NULL;

-- Index for cleanup of expired tokens
CREATE INDEX idx_token_expires ON ac_registration_tokens(expires_at)
    WHERE expires_at IS NOT NULL AND revoked_at IS NULL;
```

### Token Rotation

Tokens can be rotated without AC downtime using a grace period:

```
┌──────────────────────────────────────────────────────────────────────────┐
│                         Token Rotation Flow                               │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  1. Customer generates new token in Console                              │
│     └── Old token: lv_ac_acme_OLD...  (status: active)                   │
│     └── New token: lv_ac_acme_NEW...  (status: active)                   │
│                                                                          │
│  2. Customer updates AC deployments with new token                       │
│     └── Rolling update, some ACs still have old token                    │
│     └── Both tokens work during transition                               │
│                                                                          │
│  3. After all ACs updated, customer revokes old token                    │
│     └── Old token: lv_ac_acme_OLD...  (status: revoked)                  │
│     └── New token: lv_ac_acme_NEW...  (status: active)                   │
│                                                                          │
│  4. Revocation takes effect within 60s (cache TTL)                       │
│                                                                          │
│  Timeline:                                                               │
│  ─────────────────────────────────────────────────────────────────────   │
│  │ Generate │    Both tokens valid    │ Revoke │ 60s │ Old invalid │    │
│  │ new      │    (grace period)       │ old    │cache│              │    │
│  ─────────────────────────────────────────────────────────────────────   │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## Console Token Validation API

NHP Server calls Console to validate registration tokens.

### Endpoint: POST /internal/v1/validate-token

**Request**:
```http
POST /internal/v1/validate-token HTTP/1.1
Host: console.layerv.cloud
Authorization: Bearer <server-to-server-api-key>
Content-Type: application/json

{
  "token": "lv_ac_acme_7Bj2kX9mNqRsT4uVwYz1AbCdEfGhIjKlMnOpQrSt",
  "client_ip": "203.0.113.50"
}
```

**Response (200 OK - Valid)**:
```json
{
  "valid": true,
  "tenant_id": "acme-corp-uuid-here",
  "token_id": "token-uuid-here",
  "token_name": "Production ACs",
  "max_registrations": 100,
  "current_registrations": 42,
  "expires_at": null,
  "scopes": ["ac:register", "ac:deregister"]
}
```

**Response (200 OK - Invalid)**:
```json
{
  "valid": false,
  "reason": "token_revoked"  // or: "token_expired", "token_not_found", "ip_not_allowed"
}
```

**Response (429 Too Many Requests)**:
```json
{
  "valid": false,
  "reason": "rate_limited",
  "retry_after_seconds": 60
}
```

### Server-Side Caching

```go
type TokenCache struct {
    cache    *lru.Cache  // github.com/hashicorp/golang-lru
    ttl      time.Duration
    negative time.Duration  // Cache invalid tokens shorter
}

func NewTokenCache() *TokenCache {
    cache, _ := lru.New(10000)  // 10k entries max
    return &TokenCache{
        cache:    cache,
        ttl:      60 * time.Second,   // Valid tokens cached 60s
        negative: 10 * time.Second,   // Invalid tokens cached 10s
    }
}

type cachedToken struct {
    info      *TokenInfo
    valid     bool
    expiresAt time.Time
}

func (tc *TokenCache) Get(token string) (*TokenInfo, bool, bool) {
    // Returns: (info, valid, found)
    key := hashToken(token)
    if entry, ok := tc.cache.Get(key); ok {
        cached := entry.(*cachedToken)
        if time.Now().Before(cached.expiresAt) {
            return cached.info, cached.valid, true
        }
        tc.cache.Remove(key)
    }
    return nil, false, false
}

func (tc *TokenCache) Set(token string, info *TokenInfo, valid bool) {
    key := hashToken(token)
    ttl := tc.ttl
    if !valid {
        ttl = tc.negative
    }
    tc.cache.Add(key, &cachedToken{
        info:      info,
        valid:     valid,
        expiresAt: time.Now().Add(ttl),
    })
}
```

---

## Rate Limiting

### Implementation

Rate limiting uses a sliding window counter stored in Redis (shared across Server instances).

```go
type RateLimiter struct {
    redis  *redis.Client
    window time.Duration
    limit  int
}

func NewRateLimiter(redis *redis.Client) *RateLimiter {
    return &RateLimiter{
        redis:  redis,
        window: 1 * time.Minute,
        limit:  10,  // 10 requests per minute per IP
    }
}

func (rl *RateLimiter) Allow(ip string) (bool, int, error) {
    key := fmt.Sprintf("ratelimit:ac-register:%s", ip)
    now := time.Now().Unix()
    windowStart := now - int64(rl.window.Seconds())

    pipe := rl.redis.Pipeline()

    // Remove old entries outside window
    pipe.ZRemRangeByScore(ctx, key, "0", fmt.Sprintf("%d", windowStart))

    // Count current entries
    countCmd := pipe.ZCard(ctx, key)

    // Add current request
    pipe.ZAdd(ctx, key, &redis.Z{Score: float64(now), Member: now})

    // Set expiry on key
    pipe.Expire(ctx, key, rl.window)

    _, err := pipe.Exec(ctx)
    if err != nil {
        return false, 0, err
    }

    count := int(countCmd.Val())
    remaining := rl.limit - count - 1
    if remaining < 0 {
        remaining = 0
    }

    return count < rl.limit, remaining, nil
}
```

### Rate Limit Headers

All registration API responses include rate limit headers:

```http
HTTP/1.1 201 Created
X-RateLimit-Limit: 10
X-RateLimit-Remaining: 7
X-RateLimit-Reset: 1703980860
```

### Rate Limit Response

```http
HTTP/1.1 429 Too Many Requests
X-RateLimit-Limit: 10
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1703980860
Retry-After: 45

{
  "error": "rate_limit_exceeded",
  "message": "Too many registration attempts. Try again in 45 seconds.",
  "retry_after_seconds": 45
}
```

---

## Tenant Isolation in NHP Protocol

### AC-to-Server Binding

When AC connects via NHP protocol, the Server binds the connection to the tenant from registration:

```go
// Server stores tenant binding when AC registers
type ACPeer struct {
    ACID      string
    TenantID  string      // From registration token
    PublicKey []byte
    Endpoint  net.UDPAddr
    // ...
}

// When processing NHP_AOL (AC Online) message
func (s *Server) handleACOnline(msg *NHPMessage, remoteAddr net.UDPAddr) {
    // 1. Verify AC public key matches registered entry
    acPeer := s.findACByPublicKey(msg.SenderPublicKey)
    if acPeer == nil {
        log.Warn("Unknown AC attempted connection: %s", remoteAddr)
        return  // Reject unknown ACs
    }

    // 2. Bind connection to tenant
    conn := &ACConnection{
        Peer:     acPeer,
        TenantID: acPeer.TenantID,  // Tenant locked at registration
        Addr:     remoteAddr,
    }
    s.acConnections[acPeer.ACID] = conn

    // 3. Send NHP_AAK (acknowledgment)
    s.sendACK(conn)
}
```

### Knock Request Tenant Validation

When processing knock requests, Server ensures AC belongs to the correct tenant:

```go
func (s *Server) handleKnock(knock *KnockRequest, user *UserContext) {
    // 1. Determine target resource's tenant
    resource := s.getResource(knock.ResourceID)
    if resource == nil {
        return // Resource not found
    }

    // 2. Find ACs for this tenant
    tenantACs := s.getConnectedACsForTenant(resource.TenantID)
    if len(tenantACs) == 0 {
        log.Warn("No connected ACs for tenant %s", resource.TenantID)
        return
    }

    // 3. Send AOP (AC Operation) only to tenant's ACs
    for _, ac := range tenantACs {
        if ac.TenantID != resource.TenantID {
            // This should never happen, but defense in depth
            log.Error("Tenant mismatch: AC %s tenant %s != resource tenant %s",
                ac.ACID, ac.TenantID, resource.TenantID)
            continue
        }
        s.sendAOP(ac, knock.UserIP, knock.ResourceID)
    }
}
```

### Tenant Context in NHP Messages

NHP messages include tenant context for audit and routing:

```go
type NHPMessage struct {
    Type      uint8
    Version   uint8
    TenantID  string  // Added for multi-tenant support
    // ... other fields
}

// Serialization includes tenant ID in authenticated data
func (m *NHPMessage) Marshal() []byte {
    // Tenant ID is part of authenticated (but not encrypted) header
    // This allows routing without decryption
}
```

---

## Server Key Management

### Shared Server Keypair

All NHP Servers in a cluster share the same Curve25519 keypair:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        Server Key Architecture                           │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│   ┌─────────────────────┐                                                │
│   │  Secrets Manager    │                                                │
│   │  nhp/prod/server-key│◄────── Single source of truth                  │
│   └──────────┬──────────┘                                                │
│              │                                                           │
│              │ Load on startup                                           │
│              │                                                           │
│   ┌──────────┼──────────┬──────────────────┐                             │
│   │          │          │                  │                             │
│   ▼          ▼          ▼                  ▼                             │
│ ┌──────┐  ┌──────┐  ┌──────┐           ┌──────┐                          │
│ │Srv 1 │  │Srv 2 │  │Srv 3 │    ...    │Srv N │  All share same key     │
│ └──────┘  └──────┘  └──────┘           └──────┘                          │
│                                                                          │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │                      NLB (UDP 62206)                             │   │
│   │   Any server can handle any AC connection                        │   │
│   └─────────────────────────────────────────────────────────────────┘   │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### Server Key Rotation

Server keypair rotation requires coordination with all registered ACs:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        Server Key Rotation Plan                          │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  Phase 1: Announce (T-7 days)                                            │
│  ─────────────────────────────                                           │
│  • Generate new server keypair, store in Secrets Manager                 │
│  • Update registration API to return BOTH old and new server keys        │
│  • New registrations receive both keys                                   │
│                                                                          │
│  Response:                                                               │
│  {                                                                       │
│    "server_public_key": "NEW_KEY_BASE64",                                │
│    "server_public_key_previous": "OLD_KEY_BASE64",                       │
│    "nhp_endpoints": [...]                                                │
│  }                                                                       │
│                                                                          │
│  Phase 2: Transition (T-0)                                               │
│  ─────────────────────────                                               │
│  • Deploy servers that accept BOTH old and new AC connections            │
│  • Servers try new key first, fall back to old key                       │
│  • Notify customers: "Re-register ACs or restart them"                   │
│                                                                          │
│  Phase 3: Deprecate (T+7 days)                                           │
│  ────────────────────────────                                            │
│  • Stop accepting old key connections                                    │
│  • Remove old key from Secrets Manager                                   │
│  • Registration API only returns new key                                 │
│                                                                          │
│  AC Behavior:                                                            │
│  • On NHP connect failure: Re-call registration API                      │
│  • Get new server key, reconnect                                         │
│  • Automatic recovery, no manual intervention                            │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## API Design

### Endpoints

| Endpoint | Method | Auth | Purpose |
|----------|--------|------|---------|
| `/v1/ac/register` | POST | Registration Token | Register new AC |
| `/v1/ac/{ac_id}` | DELETE | Registration Token | Deregister AC |
| `/v1/tenant/{tenant_id}/acs` | GET | Console API Token | List tenant's ACs |

### 1. Register AC

**Request**:
```http
POST /v1/ac/register HTTP/1.1
Host: nhp.layerv.cloud
Authorization: Bearer lv_ac_acme_7Bj2kX9mNqRsT4uVwYz1AbCdEfGhIjKlMnOpQrSt
Content-Type: application/json

{
  "public_key": "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=",
  "hostname": "ac-prod-1.acme.com",
  "ip": "10.0.0.50",
  "port": 62206,
  "metadata": {
    "environment": "production",
    "region": "us-west-2",
    "cloud": "aws",
    "instance_id": "i-1234567890abcdef0",
    "version": "1.2.3"
  }
}
```

**Response (201 Created)**:
```json
{
  "ac_id": "ac_acme_a1b2c3d4e5f6",
  "tenant_id": "acme-corp-uuid",
  "server_public_key": "c2VydmVycHVibGlja2V5YmFzZTY0ZW5jb2RlZGhlcmU=",
  "nhp_endpoints": [
    {
      "hostname": "nhp.layerv.cloud",
      "port": 62206
    }
  ],
  "registered_at": "2024-01-15T12:00:00Z"
}
```

**Error Responses**:

| Status | Code | Description |
|--------|------|-------------|
| 400 | `invalid_request` | Malformed JSON or missing required fields |
| 401 | `invalid_token` | Token not found or revoked |
| 403 | `tenant_suspended` | Tenant account suspended |
| 403 | `max_registrations_exceeded` | Token has reached registration limit |
| 403 | `ip_not_allowed` | Client IP not in token's allowlist |
| 409 | `already_registered` | Public key already registered (returns existing ac_id) |
| 422 | `invalid_public_key` | Not a valid 32-byte Curve25519 key |
| 429 | `rate_limit_exceeded` | Too many requests from this IP |
| 503 | `service_unavailable` | Console unreachable for token validation |

**409 Response (Already Registered)**:
```json
{
  "error": "already_registered",
  "message": "This public key is already registered",
  "ac_id": "ac_acme_a1b2c3d4e5f6",
  "server_public_key": "c2VydmVycHVibGlja2V5YmFzZTY0ZW5jb2RlZGhlcmU=",
  "nhp_endpoints": [
    {
      "hostname": "nhp.layerv.cloud",
      "port": 62206
    }
  ]
}
```

### 2. Deregister AC

**Request**:
```http
DELETE /v1/ac/ac_acme_a1b2c3d4e5f6 HTTP/1.1
Host: nhp.layerv.cloud
Authorization: Bearer lv_ac_acme_7Bj2kX9mNqRsT4uVwYz1AbCdEfGhIjKlMnOpQrSt
```

**Response (204 No Content)**

### 3. List Tenant ACs (Console Use)

**Request**:
```http
GET /v1/tenant/acme-corp-uuid/acs HTTP/1.1
Host: nhp.layerv.cloud
Authorization: Bearer <console-internal-api-token>
```

**Response (200 OK)**:
```json
{
  "acs": [
    {
      "ac_id": "ac_acme_a1b2c3d4e5f6",
      "hostname": "ac-prod-1.acme.com",
      "ip": "10.0.0.50",
      "port": 62206,
      "status": "connected",
      "last_seen": "2024-01-15T12:59:00Z",
      "registered_at": "2024-01-15T12:00:00Z",
      "metadata": {
        "environment": "production",
        "version": "1.2.3"
      }
    },
    {
      "ac_id": "ac_acme_x9y8z7w6v5u4",
      "hostname": "ac-prod-2.acme.com",
      "ip": "10.0.0.51",
      "status": "disconnected",
      "last_seen": "2024-01-15T11:30:00Z",
      "registered_at": "2024-01-14T09:00:00Z"
    }
  ],
  "total": 2,
  "connected": 1,
  "disconnected": 1
}
```

---

## etcd Key Structure

```
/nhp/
├── global/
│   └── config                           # Global server config
├── tenants/
│   └── {tenant_id}/
│       ├── config                       # Tenant-specific config
│       └── acs/
│           └── {ac_id}                  # AC registration entry
└── _meta/
    └── ac-last-seen/
        └── {ac_id}                      # Last connection timestamp
```

### AC Registration Entry

```toml
# /nhp/tenants/acme-corp-uuid/acs/ac_acme_a1b2c3d4e5f6

ACId = "ac_acme_a1b2c3d4e5f6"
TenantId = "acme-corp-uuid"
PublicKey = "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY="
Hostname = "ac-prod-1.acme.com"
Ip = "10.0.0.50"
Port = 62206
RegisteredAt = 1705320000

[Metadata]
Environment = "production"
Region = "us-west-2"
Cloud = "aws"
InstanceId = "i-1234567890abcdef0"
Version = "1.2.3"
```

---

## Operational Considerations

### AC Lifecycle States

```
                                 ┌─────────────────┐
                                 │    Unregistered │
                                 └────────┬────────┘
                                          │
                                   Register API
                                   (201 or 409)
                                          │
                                          ▼
┌─────────────────┐              ┌─────────────────┐
│ Registration    │◄──── Retry ──│   Registered    │
│ Failed          │              │   (in etcd)     │
└─────────────────┘              └────────┬────────┘
                                          │
                                    NHP Connect
                                    (NHP_AOL/AAK)
                                          │
                                          ▼
                                 ┌─────────────────┐
                              ┌──│    Connected    │◄─┐
                              │  │  (NHP active)   │  │
                              │  └────────┬────────┘  │
                              │           │           │
                         Keepalive   Disconnect   Reconnect
                              │     (timeout 5m)      │
                              │           │           │
                              │           ▼           │
                              │  ┌─────────────────┐  │
                              └──│  Disconnected   │──┘
                                 │ (awaiting retry)│
                                 └────────┬────────┘
                                          │
                                   No activity
                                   (30 days)
                                          │
                                          ▼
                                 ┌─────────────────┐
                                 │     Stale       │──► Cleanup removes
                                 │ (cleanup target)│
                                 └─────────────────┘
```

### Cleanup Job

Runs as AWS Lambda, triggered by EventBridge schedule (daily at 03:00 UTC):

```go
// lambda/ac-cleanup/main.go

func handler(ctx context.Context) error {
    etcdClient := connectToEtcd()
    defer etcdClient.Close()

    // Get all AC entries
    resp, _ := etcdClient.Get(ctx, "/nhp/tenants/", clientv3.WithPrefix())

    now := time.Now()
    staleThreshold := now.Add(-30 * 24 * time.Hour)

    for _, kv := range resp.Kvs {
        // Parse key: /nhp/tenants/{tenant}/acs/{ac_id}
        if !strings.Contains(string(kv.Key), "/acs/") {
            continue
        }

        var entry ACRegistryEntry
        toml.Unmarshal(kv.Value, &entry)

        // Check last seen timestamp
        lastSeen := getLastSeen(entry.ACId)
        if lastSeen.Before(staleThreshold) {
            // Delete stale entry
            etcdClient.Delete(ctx, string(kv.Key))

            log.Info("Cleaned up stale AC",
                "tenant", entry.TenantId,
                "ac_id", entry.ACId,
                "last_seen", lastSeen)

            // Notify Console for audit
            notifyConsole(entry.TenantId, entry.ACId, "cleaned_up_stale")
        }
    }

    return nil
}
```

### Monitoring & Alerting

| Metric | Source | Warning | Critical |
|--------|--------|---------|----------|
| `ac.registrations.rate` | Server API | > 50/min | > 100/min |
| `ac.registrations.failures` | Server API | > 5/min | > 20/min |
| `ac.token_validation.latency_p99` | Server | > 200ms | > 1s |
| `ac.token_validation.errors` | Server | > 1/min | > 10/min |
| `ac.connected.count` | Server | < 80% expected | < 50% expected |
| `ac.disconnected.duration` | Server | > 10 min | > 30 min |
| `etcd.tenant_keys.count` | etcd | > 80% limit | > 95% limit |

---

## Backwards Compatibility

### Existing LayerV-Managed ACs

Existing ACs using direct etcd registration continue to work:

```
/nhp/ac-registry/{instance-id}     ← Old format (still watched)
/nhp/tenants/{tenant}/acs/{ac_id}  ← New format
```

Server watches both prefixes during transition:

```go
func (s *Server) watchACRegistry() {
    // Watch old format (LayerV-managed, will be deprecated)
    go s.etcdConn.WatchPrefix("/nhp/ac-registry/", s.handleLegacyACEntry)

    // Watch new format (multi-tenant)
    go s.etcdConn.WatchPrefix("/nhp/tenants/", s.handleTenantACEntry)
}
```

### Migration Path

1. **Phase 1**: Deploy new Server with dual-watching (both prefixes)
2. **Phase 2**: New deployments use Registration API
3. **Phase 3**: Migrate existing ACs to Registration API (coordinated)
4. **Phase 4**: Deprecate old `/nhp/ac-registry/` prefix

---

## Security Analysis

### Threat Model

| Threat | Severity | Mitigation | Residual Risk |
|--------|----------|------------|---------------|
| Token theft from env var | Medium | Process isolation, secrets rotation | Memory dump attack |
| Token brute force | Low | Rate limiting (10/min/IP), token entropy (256 bits) | Distributed attack |
| Stolen token → rogue ACs | Medium | Max registrations limit, IP allowlist, quick revocation | Limit reached before detection |
| Revoked token bypass | Low | 60s cache TTL, fail-closed if Console down | 60s window |
| MITM on registration | Medium | TLS required, certificate validation | Compromised CA |
| Tenant isolation bypass | High | Separate etcd prefixes, Server-side tenant binding | Implementation bug |
| Replay attack on registration | Low | Idempotent (same pubkey → same ac_id) | N/A |
| AC impersonation | High | Curve25519 keypairs, ECDH authentication | Key theft |

### Security Controls Summary

1. **Token Security**: 256-bit entropy, hashed storage, HTTPS-only, env var (not file)
2. **Rate Limiting**: 10 req/min/IP via Redis sliding window
3. **Registration Limits**: Per-token max, tenant-wide limits
4. **Tenant Isolation**: etcd prefix, Server-side tenant binding, NHP message context
5. **Audit Logging**: All registration events with IP, timestamp, token hint
6. **Revocation**: 60s max delay via cache TTL

---

## Design Decisions Summary

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Token format | Opaque (not JWT) | Server-side revocation needed anyway; simpler |
| Token validation | Console API call | Console owns token lifecycle; Server stays stateless |
| Cache TTL | 60 seconds | Balance between performance and revocation speed |
| Rate limiting | Redis sliding window | Shared state across Server instances |
| Heartbeat API | None | NHP protocol already has keepalive |
| AC identity | Public key | Stable across restarts; enables idempotent registration |
| Multi-region | Global tokens | Single Console validates all; regional Servers |
| etcd structure | `/nhp/tenants/{id}/acs/` | Clear tenant isolation |

---

## References

- [Datadog Agent Registration](https://docs.datadoghq.com/agent/)
- [Teleport Join Tokens](https://goteleport.com/docs/setup/admin/join-tokens/)
- [Cloudflare Tunnel Connectors](https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/)
- [OpenNHP Specification](https://github.com/OpenNHP/opennhp)
