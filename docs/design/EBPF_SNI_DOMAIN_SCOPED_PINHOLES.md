# eBPF SNI-Based Domain-Scoped Pinholes

## Status: Future Work

**Author:** posey
**Date:** 2026-03-11
**Priority:** Medium — current middleware-level enforcement is acceptable short-term

## Problem

NHP pinholes are `(srcIP, port, dstIP)` — no domain awareness. Once a user has a port 443 pinhole (from knocking for any QURL on an AC), they can probe all custom domains on that AC via TLS handshake. The TLS certificate reveals the domain exists even though qurl-router blocks content access via `silentDrop`.

### Threat Model

```
Attacker has a valid pinhole (knocked for some QURL):

1. Types stats.mycompany.com in browser
2. TCP handshake succeeds (pinhole allows port 443) ✓
3. TLS handshake succeeds (Traefik serves cert) ✗ ← leaks domain
4. qurl-router: no session → silentDrop (TCP RST)
5. No content served ✓
```

**What's leaked:** The existence of `stats.mycompany.com` on this AC server (via TLS certificate). An attacker with a pinhole can enumerate custom domains by probing SNIs.

**What's protected:** All content. No HTTP response, no data exfiltration. The `silentDrop` ensures the connection is immediately reset after TLS.

### Current Mitigation (Middleware-Level)

The qurl-router enforces session validation for invisible custom domains. Unauthorized requests get `silentDrop` (TCP RST with linger=0). This prevents content access but not domain discovery.

### Why This Is Acceptable Short-Term

- Attacker must already have a valid pinhole (requires legitimate QURL access)
- Only domain names are discoverable, not content
- Non-pinholed attackers see nothing (port 443 timeout from iptables DROP)
- Custom domain names are often public knowledge anyway (DNS records are public)

## Proposed Solution: TC Ingress eBPF SNI Filter

Add a TC (traffic control) ingress eBPF program that inspects TLS ClientHello packets on port 443. The program extracts the SNI hostname and checks it against a `sni_whitelist` BPF map. If the `{srcIP, sniHash}` pair isn't authorized, the packet is dropped before the TLS handshake completes.

### Why TC, Not XDP

- TC hooks run after XDP but before userspace (Traefik)
- TC has access to full `skb` with `bpf_skb_pull_data()` — easier for complex parsing
- TC verifier is more permissive than XDP for packet manipulation
- Existing `tc_egress.c` program in the codebase provides a template
- XDP remains unchanged (L3/L4 firewall), TC adds L7 SNI inspection

### Architecture

```
Packet arrives at port 443:

  XDP (existing)              TC ingress (new)              Traefik
  ┌──────────────┐            ┌──────────────────┐          ┌────────┐
  │ Check ipset/ │  PASS      │ Parse TLS Client │  PASS    │  TLS   │
  │ eBPF white-  │──────────► │ Hello, extract   │────────► │ termi- │
  │ list (L3/L4) │            │ SNI, check       │          │ nation │
  │              │            │ sni_whitelist     │          │        │
  └──────────────┘            └──────────────────┘          └────────┘
        │ DROP                       │ TC_ACT_SHOT
        ▼                            ▼
   (timeout)                  (TLS stalls, no cert)
```

### BPF Maps

```c
// sni_whitelist: authorized {srcIP, domain} pairs
// Populated by AC when processing custom domain knocks
struct sni_key {
    __be32 src_ip;
    __u64  sni_hash;    // FNV-1a 64-bit of lowercase domain
} __attribute__((packed));

struct sni_value {
    __u8  allowed;
    __u64 expire_time;  // nanoseconds since boot (matches knock openTime)
};

// sni_required: set of srcIPs that need SNI verification
// IPs NOT in this set get passthrough (general port 443 access for qurl.site)
struct sni_required_key {
    __be32 src_ip;
} __attribute__((packed));

// sni_verified: connection-level cache to avoid re-parsing every packet
// Keyed by TCP 4-tuple, set after first ClientHello verification
struct sni_conn_key {
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
} __attribute__((packed));
```

### TC Program Logic

```c
SEC("tc")
int tc_sni_filter(struct __sk_buff *skb) {
    // 1. Parse Ethernet → IP → TCP
    // 2. If not TCP port 443 → TC_ACT_OK

    // 3. Fast path: check sni_verified for this connection 4-tuple
    //    → if found → TC_ACT_OK (already authorized)

    // 4. Check if srcIP is in sni_required
    //    → if NOT → TC_ACT_OK (general access, qurl.site user)

    // 5. Check if packet contains TLS ClientHello:
    //    - ContentType == 0x16 (Handshake)
    //    - HandshakeType == 0x01 (ClientHello)
    //    → if not TLS ClientHello → TC_ACT_OK (allow TCP handshake packets)

    // 6. Parse ClientHello extensions → find SNI (type 0x0000)
    // 7. Hash SNI hostname (FNV-1a 64-bit, lowercase)
    // 8. Lookup {srcIP, sniHash} in sni_whitelist
    //    → if found → add to sni_verified → TC_ACT_OK
    //    → if NOT found → TC_ACT_SHOT (drop, TLS never completes)
}
```

### TLS ClientHello Parsing

The ClientHello structure (RFC 8446 §4.1.2):

```
TLS Record:
  ContentType (1 byte) = 0x16 (Handshake)
  Version (2 bytes)
  Length (2 bytes)

Handshake:
  HandshakeType (1 byte) = 0x01 (ClientHello)
  Length (3 bytes)
  ClientVersion (2 bytes)
  Random (32 bytes)
  SessionID (1 byte length + variable)
  CipherSuites (2 bytes length + variable)
  CompressionMethods (1 byte length + variable)
  Extensions (2 bytes length + variable):
    ExtensionType (2 bytes) = 0x0000 (server_name)
    ExtensionLength (2 bytes)
    ServerNameList:
      ListLength (2 bytes)
      NameType (1 byte) = 0x00 (hostname)
      NameLength (2 bytes)
      Name (variable) ← this is the SNI
```

**Known challenges:**
- Variable-length fields require careful BPF verifier-safe iteration
- Use bounded loops with `#pragma unroll` or `bpf_loop()` (kernel >= 5.17)
- ClientHello typically < 512 bytes (fits in one TCP segment)
- Fragmented ClientHello (rare) would not be parseable — fail-closed (DROP)

### Knock Flow Changes

**`ServerACOpsMsg`** gains a `CustomDomain` field:
```go
type ServerACOpsMsg struct {
    // ... existing fields ...
    CustomDomain string `json:"customDomain,omitempty"`
}
```

**NHP Server QURL plugin** already has `ResolveResponse.IsCustomDomain` and `QurlSiteURL`. Extract hostname and pass to AC.

**AC `HandleAccessControl`** populates BPF maps when `CustomDomain != ""`:
```go
ebpf.AddSniWhitelistRule(srcAddr.Ip, acOpsMsg.CustomDomain, openTimeSec)
ebpf.AddSniRequired(srcAddr.Ip, openTimeSec)
```

### Decision: Custom Domain Knock and General Pinhole

Two options for how custom domain knocks interact with the general port 443 pinhole:

**Option A (current plan): Keep general pinhole + add SNI scope**
- Custom domain knock adds `(srcIP, 443, dstIP)` to defaultset (TCP handshake works)
- Also adds `{srcIP, sniHash}` to `sni_whitelist`
- Also adds `srcIP` to `sni_required`
- TC filter: IPs in `sni_required` must pass SNI check; others passthrough
- Tradeoff: user gets general port 443 access (can access qurl.site too)

**Option B: SNI-only pinhole (no general access)**
- Custom domain knock does NOT add to defaultset
- Only adds to `sni_whitelist` + `sni_required`
- Need a separate iptables/eBPF rule: allow TCP SYN for `sni_required` IPs on port 443
- TC filter enforces SNI on first data packet
- Tradeoff: more complex, but custom domain users can't probe qurl.site subdomains

Option A is simpler and recommended for initial implementation.

## Security Properties After Implementation

| Attacker Profile | Port 443 | TLS Handshake | Content |
|------------------|----------|---------------|---------|
| No pinhole | Timeout (DROP) | N/A | N/A |
| Pinhole (qurl.site knock) | Open | Succeeds for qurl.site only | qurl.site content only |
| Pinhole (custom domain knock, Option A) | Open | Succeeds for authorized domain only | Authorized domain only |
| Pinhole (custom domain knock, Option B) | Open* | Succeeds for authorized domain only | Authorized domain only |

*Option B: TCP handshake succeeds but non-authorized TLS stalls.

## Performance Considerations

- **Fast path critical:** `sni_verified` map avoids re-parsing every packet on established connections. Without this, every port 443 packet would be inspected.
- **Map sizes:** `sni_whitelist` — LRU_HASH, 1M entries (same as existing maps). `sni_verified` — LRU_HASH, 1M entries (evicted naturally as connections close).
- **Parsing cost:** ~200ns per ClientHello parse (first packet only, amortized over connection lifetime).

## Future Considerations

- **Encrypted Client Hello (ECH):** TLS 1.3 ECH encrypts the SNI. When widely deployed, this approach won't work. Would need fallback to middleware enforcement or outer-SNI-based policy.
- **IPv6:** Current `sni_key` uses `__be32 src_ip`. Needs extension for IPv6 (`__be128` or separate map).
- **Hash collisions:** 64-bit FNV-1a has negligible collision probability for domain names. If paranoid, store full domain name in BPF map key (max 253 bytes).

## Files That Would Change

| File | Change |
|------|--------|
| `nhp/ebpf/xdp/tc_sni_filter.c` | New TC ingress program |
| `nhp/utils/ebpf/sni.go` | Go helpers for SNI BPF maps |
| `nhp/common/nhpmsg.go` | `CustomDomain` field in `ServerACOpsMsg` |
| `endpoints/ac/msghandler.go` | Populate SNI maps on custom domain knock |
| `endpoints/ac/ebpf/ebpfegine.go` | Load/attach TC ingress program |
| `endpoints/server/staticplugins/qurl/resolver.go` | Pass domain to AC ops |
| `endpoints/server/forward.go` | Include `CustomDomain` in AC message |
| `terraform/modules/ac/user_data.sh.tpl` | TC ingress attachment |
| `Makefile` | Compile `tc_sni_filter.c` |

## References

- Cilium SNI-based network policy: uses eBPF for TLS-aware routing
- Linux TC documentation: `tc-bpf(8)`
- TLS 1.3 spec (RFC 8446 §4.1.2): ClientHello format
- Existing NHP eBPF: `nhp/ebpf/xdp/nhp_ebpf_xdp.c`, `nhp/ebpf/xdp/tc_egress.c`
