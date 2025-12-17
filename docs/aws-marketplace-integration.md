# LayerV NHP: AWS Marketplace Integration

**Technical Architecture Proposal**
**Date**: December 2024
**Status**: Draft for Review

---

## Executive Summary

This document outlines the technical architecture for integrating LayerV NHP into the AWS Marketplace. At 1,000 projected customers in Year 1, the deployment model choice has significant cost implications:

| Model | Annual Infrastructure Cost | Cost per Customer |
|-------|---------------------------|-------------------|
| Single-tenant (1 VPC per customer) | ~$850K - $1M | $70-85/mo |
| Multi-tenant (shared control plane) | ~$15-30K | $1.25-2.50/mo |

**Recommendation**: Invest in multi-tenant architecture. Engineering cost (~$50-150K one-time) pays back in < 2 months.

---

## 1. Deployment Architecture

### 1.1 Component Distribution

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        LAYERV AWS ACCOUNT                                   │
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                     SHARED CONTROL PLANE VPC                          │  │
│  │                                                                       │  │
│  │   ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                  │  │
│  │   │ NHP Server  │  │ NHP Server  │  │ NHP Server  │  (Auto-scaled)   │  │
│  │   │   (AZ-a)    │  │   (AZ-b)    │  │   (AZ-c)    │                  │  │
│  │   └──────┬──────┘  └──────┬──────┘  └──────┬──────┘                  │  │
│  │          │                │                │                          │  │
│  │          └────────────────┼────────────────┘                          │  │
│  │                           │                                           │  │
│  │                    ┌──────┴──────┐                                    │  │
│  │                    │     NLB     │  UDP 62206                         │  │
│  │                    │  (Network)  │                                    │  │
│  │                    └──────┬──────┘                                    │  │
│  │                           │                                           │  │
│  │   ┌─────────────┐  ┌──────┴──────┐  ┌─────────────┐                  │  │
│  │   │   NHP-DB    │  │ NAT Gateway │  │  Config DB  │                  │  │
│  │   │  (Primary)  │  │  (Shared)   │  │   (etcd)    │                  │  │
│  │   └─────────────┘  └─────────────┘  └─────────────┘                  │  │
│  │                                                                       │  │
│  │   Future: VPC Endpoint Service for PrivateLink                        │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ UDP 62206 (NHP Protocol)
                                    │ HTTPS (OAuth callbacks)
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         CUSTOMER AWS ACCOUNT                                │
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                        CUSTOMER VPC                                   │  │
│  │                                                                       │  │
│  │   ┌─────────────┐           ┌─────────────────────────────────────┐   │  │
│  │   │   NHP-AC    │           │        PROTECTED RESOURCES          │   │  │
│  │   │  (Access    │ ────────► │  • Internal APIs                    │   │  │
│  │   │  Controller)│           │  • Databases                        │   │  │
│  │   │             │           │  • Admin Panels                     │   │  │
│  │   │ iptables/   │           │  • SSH Bastion                      │   │  │
│  │   │ eBPF filter │           │  • RDP Servers                      │   │  │
│  │   └─────────────┘           └─────────────────────────────────────┘   │  │
│  │                                                                       │  │
│  │   Deployed via: AWS Marketplace AMI or ECS Container                  │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
                                    ▲
                                    │
                    ┌───────────────┴───────────────┐
                    │                               │
              ┌─────┴─────┐                   ┌─────┴─────┐
              │   Agent   │                   │   Agent   │
              │ (Laptop)  │                   │ (Mobile)  │
              └───────────┘                   └───────────┘
```

### 1.2 Authentication Flow

```
┌─────────┐      ┌─────────────┐      ┌─────────┐      ┌─────────┐      ┌──────────┐
│  Agent  │      │ NHP Server  │      │   IdP   │      │ NHP-AC  │      │ Resource │
└────┬────┘      └──────┬──────┘      └────┬────┘      └────┬────┘      └────┬─────┘
     │                  │                  │                │                │
     │ 1. Knock (UDP)   │                  │                │                │
     │ ─────────────────>                  │                │                │
     │                  │                  │                │                │
     │                  │ 2. Validate      │                │                │
     │                  │    (OIDC/OAuth)  │                │                │
     │                  │ ─────────────────>                │                │
     │                  │                  │                │                │
     │                  │ 3. Token         │                │                │
     │                  │ <─────────────────                │                │
     │                  │                  │                │                │
     │                  │ 4. AuthZ (UDP)   │                │                │
     │                  │ ─────────────────────────────────>                │
     │                  │                  │                │                │
     │                  │                  │    5. Open     │                │
     │                  │                  │    iptables    │                │
     │                  │                  │    rule        │                │
     │                  │                  │                │ ─ ─ ─ ─ ─ ─ ─ >
     │                  │                  │                │                │
     │                  │ 6. ACK (UDP)     │                │                │
     │                  │ <─────────────────────────────────                │
     │                  │                  │                │                │
     │ 7. ACK (UDP)     │                  │                │                │
     │ <─────────────────                  │                │                │
     │                  │                  │                │                │
     │ 8. Access Resource (Direct TCP/UDP) │                │                │
     │ ─────────────────────────────────────────────────────────────────────>
     │                  │                  │                │                │
```

### 1.3 Component Responsibilities

| Component | Hosted By | Function |
|-----------|-----------|----------|
| **NHP Server** | LayerV | Receives knocks, authenticates via IdP, authorizes access, instructs ACs |
| **NHP-DB** | LayerV | Stores policies, user mappings, audit logs |
| **Config Store** | LayerV | etcd cluster for tenant configurations (multi-tenant mode) |
| **NHP-AC** | Customer | Enforces access rules via iptables/eBPF, deployed in customer VPC |
| **Agent** | End User | Initiates NHP knock from user device (laptop, mobile) |

---

## 2. Multi-Tenancy Requirements

### 2.1 Current State

The NHP Server currently operates in a **flat namespace**:

```toml
# agent.toml - All agents share one config
[[Agents]]
PubKeyBase64 = "key1..."  # Could be Customer A
[[Agents]]
PubKeyBase64 = "key2..."  # Could be Customer B
# No tenant isolation
```

`OrganizationId` exists in the protocol but is **metadata only** - not used for routing or isolation.

### 2.2 Required Changes

#### 2.2.1 Tenant Router

```go
// New: Route incoming requests by OrganizationId
type TenantRouter struct {
    configStore  ConfigStore           // etcd or similar
    tenantCache  map[string]*TenantConfig
    cacheMutex   sync.RWMutex
}

func (r *TenantRouter) GetTenantConfig(orgId string) (*TenantConfig, error) {
    // 1. Check cache
    // 2. If miss, fetch from configStore
    // 3. Validate tenant is active
    // 4. Return tenant-specific config (keys, ACs, resources)
}
```

#### 2.2.2 Per-Tenant Configuration

Move from file-based to database-backed config:

```go
type TenantConfig struct {
    TenantId        string
    OrganizationId  string              // Customer's org identifier
    Status          TenantStatus        // active, suspended, trial

    // Crypto
    ServerKeyPair   *KeyPair            // Optional: per-tenant keys

    // Peers
    Agents          []*core.UdpPeer     // Tenant's registered agents
    ACs             []*core.UdpPeer     // Tenant's ACs

    // Resources
    AuthServices    map[string]*AuthServiceConfig
    Resources       map[string]*ResourceGroup

    // Limits
    MaxUsers        int
    MaxACs          int
    RateLimits      *RateLimitConfig
}
```

#### 2.2.3 Request Processing Changes

Current flow:
```
Packet → Decrypt → Lookup peer by pubkey → Process
```

Multi-tenant flow:
```
Packet → Decrypt → Extract OrganizationId → Load TenantConfig → Validate peer against tenant → Process
```

**Files requiring modification:**

| File | Changes |
|------|---------|
| `endpoints/server/config.go` | Add TenantRouter, ConfigStore interface |
| `endpoints/server/udpserver.go` | Route by OrganizationId before processing |
| `endpoints/server/msghandler.go` | Pass tenant context through handlers |
| `endpoints/server/tokenstore.go` | Namespace tokens by tenant |
| `nhp/common/nhpmsg.go` | Already has OrganizationId (no change) |

#### 2.2.4 Isolation Requirements

| Requirement | Implementation |
|-------------|----------------|
| Config isolation | Tenant configs stored separately in etcd with prefix `/tenants/{tenantId}/` |
| Key isolation | Option for per-tenant server keypairs (recommended for enterprise) |
| Rate limiting | Per-tenant request quotas to prevent noisy neighbor |
| Audit isolation | Tenant ID tagged on all log entries, separate CloudWatch log groups |
| AC validation | AC public key must belong to requesting tenant |

### 2.3 Estimated Engineering Effort

| Task | Complexity | Estimate |
|------|------------|----------|
| TenantRouter + ConfigStore | Medium | 2-3 weeks |
| etcd integration | Medium | 1-2 weeks |
| Request path changes | Medium | 2-3 weeks |
| Per-tenant rate limiting | Low | 1 week |
| Tenant provisioning API | Medium | 2 weeks |
| Testing + hardening | High | 2-3 weeks |
| **Total** | | **10-14 weeks** |

---

## 3. Cost Analysis

### 3.1 Traffic Profile

**Per NHP authentication:**

| Message | Size |
|---------|------|
| Agent Knock | ~400 bytes |
| Server Cookie (if needed) | ~200 bytes |
| Server ACK | ~600 bytes |
| Server → AC Operation | ~400 bytes |
| AC → Server Result | ~200 bytes |
| **Total NHP traffic** | **~1.8 KB** |

**Per OAuth/OIDC flow (IdP calls):**

| Call | Size |
|------|------|
| OIDC Discovery | ~5 KB |
| Token Exchange | ~2 KB |
| JWKS Fetch | ~3 KB (cached) |
| **Total IdP traffic** | **~10 KB** (first auth), ~2 KB (cached) |

### 3.2 Usage Assumptions

| Metric | Value | Notes |
|--------|-------|-------|
| Customers | 1,000 | Year 1 target |
| Users per customer | 100 | Average |
| Knocks per user/day | 10 | Hourly re-auth during work |
| Working days/month | 22 | |
| **Total knocks/month** | 22M | 1000 × 100 × 10 × 22 |

### 3.3 Single-Tenant Cost Model

**Per customer VPC:**

| Resource | Specification | Monthly Cost |
|----------|---------------|--------------|
| EC2 (NHP Server) | t3.medium (2 vCPU, 4GB) | $30.37 |
| EC2 (NHP-DB) | t3.small (2 vCPU, 2GB) | $15.18 |
| **NAT Gateway** | Required for IdP calls | $32.85 |
| NAT Data Processing | ~50 MB/customer | $2.25 |
| EBS | 50 GB gp3 | $4.00 |
| CloudWatch | Logs + metrics | $5.00 |
| **Per Customer Total** | | **$89.65** |

**At 1,000 customers:**

| Line Item | Monthly | Annual |
|-----------|---------|--------|
| Compute (EC2) | $45,550 | $546,600 |
| **NAT Gateways** | **$32,850** | **$394,200** |
| Storage (EBS) | $4,000 | $48,000 |
| Monitoring | $5,000 | $60,000 |
| **Total** | **$87,400** | **$1,048,800** |

**NAT Gateway alone is 38% of total cost.**

### 3.4 Multi-Tenant Cost Model

**Shared control plane:**

| Resource | Specification | Monthly Cost |
|----------|---------------|--------------|
| EC2 (NHP Server) | c6i.2xlarge × 4 (HA, multi-AZ) | $980 |
| EC2 (NHP-DB) | r6i.large × 2 (HA) | $184 |
| EC2 (etcd) | t3.medium × 3 (cluster) | $91 |
| **NAT Gateway** | 1 (shared) | $33 |
| NAT Data Processing | ~100 GB total | $4.50 |
| Network Load Balancer | For UDP distribution | $50 |
| EBS | 500 GB gp3 | $40 |
| CloudWatch | Aggregated | $100 |
| **Total** | | **$1,482.50** |

**Scaling notes:**
- c6i.2xlarge handles ~50K concurrent connections
- 4 instances provide redundancy + headroom for 1000 customers
- Add instances as customer count grows (~$250/mo per instance)

### 3.5 Cost Comparison

| Metric | Single-Tenant | Multi-Tenant | Savings |
|--------|---------------|--------------|---------|
| Monthly (1000 customers) | $87,400 | $1,500 | $85,900 (98%) |
| Annual (1000 customers) | $1,048,800 | $18,000 | **$1,030,800** |
| Cost per customer | $87.40/mo | $1.50/mo | $85.90/mo |

### 3.6 Break-Even Analysis

Multi-tenant engineering investment: ~$100,000 (assuming $150/hr × 14 weeks × 40 hrs)

```
Monthly savings:     $85,900
Break-even:          100,000 / 85,900 = 1.16 months
```

**Multi-tenant pays for itself in ~5 weeks.**

---

## 4. AWS Marketplace Integration

### 4.1 Product Listings

**Two complementary listings:**

#### 4.1.1 LayerV NHP Control Plane (SaaS)

| Field | Value |
|-------|-------|
| Product Type | SaaS |
| Fulfillment | SaaS Contract + Registration |
| Pricing | Per-user/month subscription |
| Deployment | Customer subscribes, receives OrganizationId + API key |

**Pricing tiers:**

| Tier | Users | Price |
|------|-------|-------|
| Starter | 1-25 | $X/month flat |
| Team | 26-100 | $Y/user/month |
| Business | 101-500 | $Z/user/month |
| Enterprise | 500+ | Custom |

#### 4.1.2 LayerV NHP Access Controller (AMI/Container)

| Field | Value |
|-------|-------|
| Product Type | AMI or Container |
| Fulfillment | CloudFormation Quick Launch |
| Pricing | Free (bundled with SaaS) or BYOL |
| Deployment | One-click into customer VPC |

**CloudFormation parameters:**

```yaml
Parameters:
  OrganizationId:
    Type: String
    Description: Your LayerV Organization ID (from SaaS subscription)

  APIKey:
    Type: String
    NoEcho: true
    Description: Your LayerV API Key

  ControlPlaneEndpoint:
    Type: String
    Default: nhp.layerv.ai
    Description: LayerV NHP Server endpoint

  ProtectedSubnetIds:
    Type: List<AWS::EC2::Subnet::Id>
    Description: Subnets containing resources to protect
```

### 4.2 Customer Onboarding Flow

```
1. Customer subscribes to SaaS listing
                │
                ▼
2. LayerV provisions tenant
   - Generate OrganizationId
   - Create API key
   - Initialize tenant config in etcd
                │
                ▼
3. Customer receives welcome email
   - OrganizationId
   - API Key
   - Link to AC deployment
                │
                ▼
4. Customer deploys AC via Marketplace
   - Launches CloudFormation
   - Enters OrganizationId + API Key
   - AC auto-registers with control plane
                │
                ▼
5. Customer configures protected resources
   - Via LayerV console or API
   - Define resources, access policies
                │
                ▼
6. Customer deploys agents
   - Download from LayerV portal
   - Configure with OrganizationId
   - Users authenticate and access resources
```

### 4.3 Agent Distribution

Agents are **not** distributed via Marketplace (they run on end-user devices, not AWS).

**Distribution channels:**

| Platform | Method |
|----------|--------|
| Windows | MSI installer from LayerV portal |
| macOS | DMG/PKG from LayerV portal |
| Linux | DEB/RPM packages, or .so library |
| iOS | App Store or MDM (XCFramework) |
| Android | Play Store or MDM (AAR) |
| Embedded | SDK integration (nhpdevice.so) |

---

## 5. PrivateLink Support (Future)

### 5.1 Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      LAYERV VPC                                 │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                Network Load Balancer                    │    │
│  │                    (Internal)                           │    │
│  └────────────────────────┬────────────────────────────────┘    │
│                           │                                     │
│  ┌────────────────────────┴────────────────────────────────┐    │
│  │              VPC Endpoint Service                       │    │
│  │         (nhp.vpce.layerv.ai)                           │    │
│  └────────────────────────┬────────────────────────────────┘    │
│                           │                                     │
└───────────────────────────┼─────────────────────────────────────┘
                            │
                     AWS PrivateLink
                     (Private connectivity)
                            │
┌───────────────────────────┼─────────────────────────────────────┐
│                           │           CUSTOMER VPC              │
│  ┌────────────────────────┴────────────────────────────────┐    │
│  │              VPC Interface Endpoint                     │    │
│  │      (vpce-xxx.nhp.layerv.ai)                          │    │
│  └────────────────────────┬────────────────────────────────┘    │
│                           │                                     │
│                    ┌──────┴──────┐                              │
│                    │   NHP-AC    │                              │
│                    └─────────────┘                              │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 5.2 Implementation Requirements

| Task | Notes |
|------|-------|
| Create NLB (internal) | Target NHP servers |
| Create VPC Endpoint Service | Attach to NLB |
| Allowlist customer accounts | Per-customer approval |
| Update AC deployment | Support PrivateLink endpoint as alternative |
| DNS configuration | Private hosted zone for endpoint resolution |

### 5.3 Additional Costs

| Resource | Monthly Cost |
|----------|--------------|
| VPC Endpoint Service | $0.01/hr = $7.30/mo |
| Data processed | $0.01/GB |
| **Per customer endpoint** | ~$7.50/mo + data |

PrivateLink is positioned as **Enterprise tier** feature.

---

## 6. Security Considerations

### 6.1 Control Plane Security

| Layer | Mechanism |
|-------|-----------|
| Network | NHP protocol (UDP 62206) - encrypted, authenticated |
| Transport | All IdP communication over TLS 1.3 |
| Authentication | Mutual authentication via NHP public keys |
| Authorization | Per-tenant policy enforcement |
| Secrets | AWS Secrets Manager for API keys, etcd encryption at rest |

### 6.2 Tenant Isolation (Multi-Tenant)

| Threat | Mitigation |
|--------|------------|
| Tenant A accesses Tenant B's resources | OrganizationId validation on every request |
| Tenant A's AC registers with Tenant B | AC public key must match tenant's registered keys |
| Noisy neighbor DoS | Per-tenant rate limiting |
| Data leakage in logs | Tenant ID tagged, separate log groups |
| Config tampering | etcd ACLs, audit logging |

### 6.3 Customer VPC Security

| Requirement | Implementation |
|-------------|----------------|
| Minimal permissions | AC IAM role: EC2 describe, CloudWatch logs only |
| Network isolation | AC in private subnet, no public IP |
| Outbound control | Security group allows only UDP 62206 to LayerV |
| No inbound from internet | All traffic initiated outbound by AC |

---

## 7. Recommendations

### 7.1 Immediate (0-3 months)

1. **Commit to multi-tenant architecture** - Cost savings justify investment
2. **Begin multi-tenant development** - TenantRouter, etcd integration
3. **Create AWS Seller account** - Start Marketplace onboarding (takes time)
4. **Build AC CloudFormation template** - Customer deployment artifact

### 7.2 Short-term (3-6 months)

1. **Launch SaaS listing** - Control plane subscription
2. **Launch AMI/Container listing** - AC deployment
3. **Build customer console** - Tenant provisioning, resource management
4. **Implement metering** - AWS Marketplace Metering Service integration

### 7.3 Medium-term (6-12 months)

1. **Add PrivateLink support** - Enterprise tier feature
2. **Multi-region deployment** - US, EU, APAC presence
3. **SOC 2 / ISO 27001** - Compliance certifications
4. **Advanced features** - Per-tenant keys, custom IdP integrations

---

## 8. Open Questions

1. **Pricing model finalization** - Per-user vs per-resource vs hybrid?
2. **Free tier?** - Starter tier for evaluation?
3. **Support tiers** - What SLA for each pricing tier?
4. **Multi-region priority** - Which regions first?
5. **Compliance requirements** - FedRAMP, HIPAA needed for target customers?

---

## Appendix A: NHP Protocol Packet Sizes

| Message Type | Direction | Typical Size |
|--------------|-----------|--------------|
| NHP_KNK (Knock) | Agent → Server | 300-500 bytes |
| NHP_ACK (Ack) | Server → Agent | 400-800 bytes |
| NHP_COK (Cookie) | Server → Agent | 200 bytes |
| NHP_AOP (AC Operation) | Server → AC | 300-400 bytes |
| NHP_ART (AC Result) | AC → Server | 200 bytes |
| NHP_AOL (AC Online) | AC → Server | 150 bytes |

**Protocol constants** (from `nhp/core/constants.go`):

```go
PacketBufferSize     = 4096   // Max packet size
HeaderCommonSize     = 24     // Header overhead
SymmetricKeySize     = 32
PublicKeySize        = 32
HashSize             = 32
```

## Appendix B: Outbound Connectivity Requirements

NHP Server requires outbound HTTPS for IdP integration:

```go
// endpoints/server/plugins/okta/auth.go:24-27
provider, err := oidc.NewProvider(
    context.Background(),
    "https://"+conf.AUTH0_DOMAIN+"/",
)

// endpoints/server/plugins/okta/main.go:267
oktaToken, err = oktaAuth.Exchange(ctx.Request.Context(), authorizeCode)
```

**Required outbound access:**

| Destination | Port | Purpose |
|-------------|------|---------|
| Customer IdP (Okta, Auth0, Azure AD) | 443 | OIDC discovery, token exchange |
| OCSP/CRL endpoints | 443 | Certificate validation |

This necessitates NAT Gateway in single-tenant model, or shared NAT in multi-tenant.

## Appendix C: Files Requiring Multi-Tenant Modifications

| File | Current Function | Required Changes |
|------|------------------|------------------|
| `endpoints/server/config.go` | File-based config loading | Add ConfigStore interface, TenantRouter |
| `endpoints/server/udpserver.go` | Single-tenant request handling | Route by OrganizationId, tenant context |
| `endpoints/server/msghandler.go` | Message processing | Pass tenant context to handlers |
| `endpoints/server/tokenstore.go` | Token generation/validation | Namespace tokens by tenant |
| `endpoints/server/httpserver.go` | HTTP API handling | Tenant context in HTTP handlers |
| `nhp/etcd/etcd.go` | etcd connection | Extend for tenant config operations |
| **New files** | | |
| `endpoints/server/tenant.go` | — | TenantRouter, TenantConfig, TenantCache |
| `endpoints/server/configstore.go` | — | ConfigStore interface, etcd implementation |
| `endpoints/server/ratelimit.go` | — | Per-tenant rate limiting |

## Appendix D: Deployment Artifacts

The following deployment artifacts have been created in `/aws/`:

### CloudFormation Template

**Location:** `aws/cloudformation/nhp-ac.yaml`

Deploys NHP-AC into customer VPC with:
- EC2 instance with NHP-AC
- Security Group (UDP 62206)
- IAM Role with minimal permissions
- Secrets Manager for credentials
- CloudWatch Logs and Alarms

### Quick-Start Script

**Location:** `aws/scripts/deploy-ac.sh`

```bash
./aws/scripts/deploy-ac.sh \
  --org-id <organization-id> \
  --api-key <api-key> \
  --vpc-id <vpc-id> \
  --subnet-id <subnet-id>
```

### Customer Onboarding Template

**Location:** `aws/configs/onboarding-template.yaml`

YAML template for collecting customer information:
- Company details
- AWS account info
- IdP configuration
- Protected resources
- Compliance requirements

### Directory Structure

```
aws/
├── cloudformation/
│   └── nhp-ac.yaml              # CloudFormation template
├── scripts/
│   └── deploy-ac.sh             # Deployment script
├── configs/
│   └── onboarding-template.yaml # Customer onboarding form
└── README.md                    # Deployment documentation
```
