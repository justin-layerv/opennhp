#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define ETH_P_ARP 0x0806
#define ETH_P_IP    0x0800
#define IPPROTO_ICMP 1
#define IPPROTO_TCP 6
#define ICMP_ECHO 8
#define ICMP_ECHOREPLY 0
#define ETH_P_IPV6   0x86DD
#define IPPROTO_UDP 17
#define IPPROTO_ICMPV6 58
#define IPV6_NEXTHDR_HOP 0
#define IPV6_NEXTHDR_ROUTING 43
#define IPV6_NEXTHDR_FRAGMENT 44
#define IPV6_NEXTHDR_ESP 50
#define IPV6_NEXTHDR_AH 51
#define IPV6_NEXTHDR_NONE 59
#define IPV6_NEXTHDR_DEST 60
#define IPV6_NEXTHDR_MOBILITY 135
#define IPV6_EXT_MAX_HEADERS 6
// ICMPv6 Echo Request / Echo Reply (RFC 4443 §4) — the v6 equivalents of v4's
// ICMP_ECHO(8)/ICMP_ECHOREPLY(0). Different numbering: 128/129, not 8/0.
#define ICMPV6_ECHO_REQUEST 128
#define ICMPV6_ECHO_REPLY   129
// ICMPv6 Packet Too Big (RFC 4443 §3.2). IPv6 routers never fragment, so PMTUD
// relies ENTIRELY on this message reaching the sender; dropping it blackholes
// any flow whose path MTU is below the sender's assumption. RFC 4890 §4.3.1
// classifies it as a message that MUST NOT be dropped — we PASS it (below).
#define ICMPV6_PKT_TOO_BIG 2
// IPv6 Neighbor Discovery (RFC 4861 §4) — the link-local control plane that is
// to IPv6 what ARP is to IPv4: RS/RA learn the prefix + default route (SLAAC),
// NS/NA resolve a neighbor's link-layer address, Redirect updates next-hop.
// These ride inside ICMPv6 (so, unlike v4 ARP, they share the ETH_P_IPV6
// ethertype and cannot be waved through by the ETH_P_ARP switch arm). We PASS
// the whole 133–137 range unconditionally (the v6 analog of `case ETH_P_ARP:
// return XDP_PASS`); see the ICMPv6 branch below for the rationale. RFC 4890
// §4.4.1 likewise classifies NDP as MUST NOT be dropped on a link.
#define ICMPV6_ND_ROUTER_SOLICIT   133
#define ICMPV6_ND_ROUTER_ADVERT    134
#define ICMPV6_ND_NEIGHBOR_SOLICIT 135
#define ICMPV6_ND_NEIGHBOR_ADVERT  136
#define ICMPV6_ND_REDIRECT         137
#define MAX_ENTRIES 1000000
// MAX_ENTRIES_V6: separate, right-sized ceiling for the IPv6 maps (E2 slice 1).
// Deliberately NOT reused from MAX_ENTRIES (1,000,000): the prod knock NLB is
// IPv4-only, so v6 enforcement scale is far smaller than v4 today. 131072 (128K,
// power of two) is a comfortable near-term v6 ceiling, ≈93 MB of preallocated
// kernel memory across all 6 v6 maps — trivial on an 8 GB c6i.xlarge AC. The
// per-map kernel-memory breakdown lives in docs/design/
// SESSION_ENFORCEMENT_ARCHITECTURE.md ("Capacity / max_entries sizing" → IPv6
// subsection); any bump is a flip-time concern (#2813) and must re-run that math
// against the chosen instance type.
#define MAX_ENTRIES_V6 131072
#define MIN_PORT 0
#define MAX_PORT 65535
#define DNS_PORT 53
#define DHCP_PORT_R 67
#define DHCP_PORT_O 68

enum {
    CT_NEW,
    CT_ESTABLISHED,
};

enum {
    CT_FLAG_NONE = 0,
    CT_FLAG_SYN = 1 << 0,
    CT_FLAG_FIN = 1 << 1,
    CT_FLAG_RST = 1 << 2,
    CT_FLAG_ACK = 1 << 3,
};

enum {
    CT_DIR_INGRESS = 0,
    CT_DIR_EGRESS = 1,
};

// Size pins for the v4 allow-rule key structs — the C<->Go size contract their
// Go serializers in nhp/utils/ebpf/ebpf.go marshal against (ToWlKey/ToSpKey/
// ToPlKey/ToPpKey, plus ToSdKey shared by the two address-only keys
// icmpwhitelist/sdwhitelist). Mirrors the _Static_asserts on the v6 twins below
// (so v4 and v6 have parity): a wrong attribute or accidental field change
// fails the compile of this object (make test-ebpf, run in the eBPF-datapath CI
// job and at local regen) instead of silently diverging into a wrong KeySize.
struct whitelist_key {
    __be32 src_ip;            // 4
    __be32 dst_ip;            // 4
    __be16 dst_port;          // 2
    __u8 protocol;            // 1
} __attribute__((packed));    // = 11 bytes (KeySize for spp)
_Static_assert(sizeof(struct whitelist_key) == 11,
               "whitelist_key must be exactly 11 bytes (packed)");

struct src_port_list_key {
    __be32 src_ip;            // 4
    __be16 dst_port;          // 2
} __attribute__((packed));    // = 6 bytes (KeySize for src_port)
_Static_assert(sizeof(struct src_port_list_key) == 6,
               "src_port_list_key must be exactly 6 bytes (packed)");

struct port_list_key {
    __be32 src_ip;            // 4
    __be16 min_port;          // 2
    __be16 max_port;          // 2
} __attribute__((packed));    // = 8 bytes (KeySize for port_list)
_Static_assert(sizeof(struct port_list_key) == 8,
               "port_list_key must be exactly 8 bytes (packed)");

struct protocol_port_key {
    __be16 dst_port;          // 2
    __u8 protocol;            // 1
} __attribute__((packed));    // = 3 bytes (KeySize for protocol_port)
_Static_assert(sizeof(struct protocol_port_key) == 3,
               "protocol_port_key must be exactly 3 bytes (packed)");

struct icmpwhitelist_key {
    __be32 src_ip;            // 4
    __be32 dst_ip;            // 4
} __attribute__((packed));    // = 8 bytes (KeySize for icmpwhitelist)
_Static_assert(sizeof(struct icmpwhitelist_key) == 8,
               "icmpwhitelist_key must be exactly 8 bytes (packed)");

struct sdwhitelist_key {
    __be32 src_ip;            // 4
    __be32 dst_ip;            // 4
} __attribute__((packed));    // = 8 bytes (KeySize for sdwhitelist)
_Static_assert(sizeof(struct sdwhitelist_key) == 8,
               "sdwhitelist_key must be exactly 8 bytes (packed)");

// ----------------------------------------------------------------------------
// IPv6 allow-rule key structs (E2 slice 1 — DECLARED ONLY, currently inert).
//
// These mirror the IPv4 allow-rule keys above, substituting `struct in6_addr`
// (16 bytes) for each `__be32` address. They REUSE the existing IP-family-
// agnostic `*_value` types (whitelist_value, src_port_list_value, etc.) — the
// value carries only {allowed, expire_time} and has nothing IP-specific.
//
// PACKING: every v6 struct uses `__attribute__((packed))` — never the bare
// `__packed` token. In this translation unit `__packed` is undefined unless a
// future include adds it, so using it can silently leave a struct naturally
// aligned instead of packed (the historical #2818 conn_track surprise). To make
// the C<->Go size contract unambiguous and self-checking, each struct's exact
// packed size is pinned with a `_Static_assert`: a wrong attribute or accidental
// field-type change fails the compile of this .o (`make ebpf`). This TU is
// compiled from source by `make test-ebpf` — both at local regen AND in the
// eBPF-datapath CI job (ebpf-datapath-test.yml, triggered by nhp/ebpf/**
// changes) — so a wrong size fails that compile in CI, not just at the next
// local regen. The end-to-end guard is closed by slice 2's Go serializers +
// golden-byte tests (run in Go CI) and slice 6's `map.KeySize() == GoSize`
// kernel test; all three share these exact byte sizes as the single source of
// truth.

struct whitelist_key_v6 {
    struct in6_addr src_ip;   // 16
    struct in6_addr dst_ip;   // 16
    __be16 dst_port;          //  2
    __u8 protocol;            //  1
} __attribute__((packed));    // = 35 bytes (KeySize for spp_v6)
_Static_assert(sizeof(struct whitelist_key_v6) == 35,
               "whitelist_key_v6 must be exactly 35 bytes (packed)");

struct src_port_list_key_v6 {
    struct in6_addr src_ip;   // 16
    __be16 dst_port;          //  2
} __attribute__((packed));    // = 18 bytes (KeySize for src_port_v6)
_Static_assert(sizeof(struct src_port_list_key_v6) == 18,
               "src_port_list_key_v6 must be exactly 18 bytes (packed)");

struct port_list_key_v6 {
    struct in6_addr src_ip;   // 16
    __be16 min_port;          //  2
    __be16 max_port;          //  2
} __attribute__((packed));    // = 20 bytes (KeySize for port_list_v6)
_Static_assert(sizeof(struct port_list_key_v6) == 20,
               "port_list_key_v6 must be exactly 20 bytes (packed)");

struct icmpwhitelist_key_v6 {
    struct in6_addr src_ip;   // 16
    struct in6_addr dst_ip;   // 16
} __attribute__((packed));    // = 32 bytes (KeySize for icmp_wl_v6)
_Static_assert(sizeof(struct icmpwhitelist_key_v6) == 32,
               "icmpwhitelist_key_v6 must be exactly 32 bytes (packed)");

struct sdwhitelist_key_v6 {
    struct in6_addr src_ip;   // 16
    struct in6_addr dst_ip;   // 16
} __attribute__((packed));    // = 32 bytes (KeySize for sdwhitelist_v6)
_Static_assert(sizeof(struct sdwhitelist_key_v6) == 32,
               "sdwhitelist_key_v6 must be exactly 32 bytes (packed)");

struct whitelist_value {
    __u8 allowed;
    __u64 expire_time;
};

struct icmpwhitelist_value {
    __u8 allowed;
    __u64 expire_time;
};

struct sdwhitelist_value {
    __u8 allowed;
    __u64 expire_time;
};

struct src_port_list_value {
    __u8 allowed;
    __u64 expire_time;
};

struct port_list_value {
    __u8 allowed;
    __u64 expire_time;
};

struct protocol_port_value {
    __u8 allowed;
    __u64 expire_time;
} __attribute__((packed));

// Allow-rule map (src+dst+port+proto). AUTHORITATIVE admission decision:
// presence of an entry here IS the kernel's "this flow is admitted" answer
// on the XDP fast path. Must be BPF_MAP_TYPE_HASH, NOT LRU_HASH: an LRU map
// silently evicts the least-recently-used entry when full, which would drop
// an already-admitted session's allow-rule and "kill a random session"
// (issue #2163). HASH instead returns -E2BIG to user space on insert into a
// full map, so the AC fails the NEW admission closed rather than silently
// revoking an EXISTING one. Rationale: docs/design/SESSION_ENFORCEMENT_ARCHITECTURE.md.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct whitelist_key);
    __type(value, struct whitelist_value);
    __uint(max_entries, MAX_ENTRIES);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} spp SEC(".maps");

// Allow-rule map (src+dst-port). Authoritative — HASH, not LRU_HASH. See
// the spp map above and SESSION_ENFORCEMENT_ARCHITECTURE.md for why an LRU
// allow-rule map silently evicts admitted sessions (#2163).
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct src_port_list_key);
    __type(value, struct src_port_list_value);
    __uint(max_entries, MAX_ENTRIES);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} src_port SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct icmpwhitelist_key);
    __type(value,  struct icmpwhitelist_value);
    __uint(max_entries, MAX_ENTRIES);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} icmpwhitelist SEC(".maps");

// Allow-rule map (src+dst). Authoritative — HASH, not LRU_HASH. See the spp
// map above and SESSION_ENFORCEMENT_ARCHITECTURE.md (#2163).
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct sdwhitelist_key);
    __type(value, struct sdwhitelist_value);
    __uint(max_entries, MAX_ENTRIES);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} sdwhitelist SEC(".maps");

// Allow-rule map (src+port-range). Authoritative — HASH, not LRU_HASH. See
// the spp map above and SESSION_ENFORCEMENT_ARCHITECTURE.md (#2163).
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct port_list_key);
    __type(value,struct port_list_value);
    __uint(max_entries, MAX_ENTRIES);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} port_list SEC(".maps");

// Allow-rule map (proto+dst-port). Authoritative — HASH, not LRU_HASH. See
// the spp map above and SESSION_ENFORCEMENT_ARCHITECTURE.md (#2163).
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct protocol_port_key);
    __type(value,struct protocol_port_value);
    __uint(max_entries, MAX_ENTRIES);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} protocol_port SEC(".maps");

// ----------------------------------------------------------------------------
// IPv6 allow-rule maps (E2 slice 1 — DECLARED ONLY, currently inert).
//
// These are the IPv6 counterparts of the IPv4 allow-rule maps above. Like their
// v4 siblings they are AUTHORITATIVE admission decisions, so they MUST be
// BPF_MAP_TYPE_HASH, never LRU_HASH: an LRU map silently evicts the
// least-recently-used entry when full, which would drop an already-admitted v6
// session's allow-rule and "kill a random session" (the #2163 fail-closed
// decision E6/#2163 makes for v4 — mirrored here). HASH instead returns -E2BIG
// to user space on a full-map insert, so the AC fails a NEW v6 admission CLOSED
// rather than silently revoking an EXISTING one. See the v4 spp map above and
// docs/design/SESSION_ENFORCEMENT_ARCHITECTURE.md.
//
// Each map keys on a v6 key struct (in6_addr addresses) and REUSES the existing
// IP-family-agnostic *_value types. KeySize is the asserted packed size of the
// key struct (see the _Static_asserts near the struct definitions). Sized by
// MAX_ENTRIES_V6 (128K), not MAX_ENTRIES (1M) — see the define for the rationale
// and kernel-memory math. All pinned LIBBPF_PIN_BY_NAME like the v4 maps.
//
// DO NOT regenerate the compiled .o in this slice. These maps are intentionally
// unused, so the committed endpoints/ac/main/etc/nhp_ebpf_xdp.o is deliberately
// left out of sync with this source — the binary regen (which materializes these
// 6 pinned maps) lands with the datapath in slice 3, where it is reviewed
// together with the code that uses them.
//
// NOTE on proto+dst-port: there is deliberately NO `protocol_port_v6` map. The
// `protocol_port` key (struct protocol_port_key = {dst_port, protocol}) carries
// no IP address, so a proto+dst-port allow-rule is IP-family-agnostic by
// construction — one entry there admits the proto+port for BOTH v4 and v6.
// Slice 3's v6 datapath consults the existing `protocol_port` map directly; this
// saves a map (map-count budget) and a duplicate write path. If family-scoped
// proto+port rules are ever required, add a family discriminator to the key (or
// a separate v6 map) at that point — not now.

// Allow-rule map v6 (src+dst+dport+proto). Authoritative — HASH, not LRU_HASH.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct whitelist_key_v6);     // KeySize 35
    __type(value, struct whitelist_value);    // reused v4-agnostic value
    __uint(max_entries, MAX_ENTRIES_V6);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} spp_v6 SEC(".maps");

// Allow-rule map v6 (src+dport). Authoritative — HASH, not LRU_HASH.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct src_port_list_key_v6); // KeySize 18
    __type(value, struct src_port_list_value);
    __uint(max_entries, MAX_ENTRIES_V6);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} src_port_v6 SEC(".maps");

// Allow-rule map v6 (src+dst, ICMPv6). Authoritative — HASH, not LRU_HASH.
// NOTE: named `icmp_wl_v6`, not `icmpwhitelist_v6` — a BPF map name is capped at
// BPF_OBJ_NAME_LEN-1 = 15 chars (libbpf silently truncates longer names, which
// would diverge the kernel/pinned name from the C identifier). `icmpwhitelist`
// (v4) is 13; appending `_v6` would be 16. Keep any future `_v6` map ≤15 chars.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct icmpwhitelist_key_v6); // KeySize 32
    __type(value, struct icmpwhitelist_value);
    __uint(max_entries, MAX_ENTRIES_V6);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} icmp_wl_v6 SEC(".maps");

// Allow-rule map v6 (src+dst). Authoritative — HASH, not LRU_HASH.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct sdwhitelist_key_v6);   // KeySize 32
    __type(value, struct sdwhitelist_value);
    __uint(max_entries, MAX_ENTRIES_V6);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} sdwhitelist_v6 SEC(".maps");

// Allow-rule map v6 (src+port-range). Authoritative — HASH, not LRU_HASH.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct port_list_key_v6);     // KeySize 20
    __type(value, struct port_list_value);
    __uint(max_entries, MAX_ENTRIES_V6);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} port_list_v6 SEC(".maps");

struct ipv4_ct_tuple {
    __be32 daddr;
    __be32 saddr;
    __be16 dport;
    __be16 sport;
    __u8 nexthdr;
    __u8 flags;
};
// conn_track's current ABI is the natural-aligned 16-byte layout: 14 field
// bytes plus 2 bytes of trailing pad. Do not pack this to 14 bytes without a
// pinned-map migration and lockstep Go serializer change; LIBBPF_PIN_BY_NAME
// maps created with 16-byte keys cannot be reopened as 14-byte-key maps.
_Static_assert(sizeof(struct ipv4_ct_tuple) == 16,
               "ipv4_ct_tuple must remain 16 bytes (14 field bytes + 2 trailing pad)");

// IPv6 conntrack tuple (E2 slice 1 — DECLARED ONLY, currently inert).
// Mirrors ipv4_ct_tuple with `struct in6_addr` (16B) addresses. This tuple is
// intentionally packed because conn_track_v6 is new/inert and has no existing
// pinned-map ABI; its exact size is asserted so slice 2's `connTrackKeyV6Size`
// Go constant and slice 6's `map.KeySize() == GoSize` guard have an
// authoritative value.
struct ipv6_ct_tuple {
    struct in6_addr daddr;    // 16
    struct in6_addr saddr;    // 16
    __be16 dport;             //  2
    __be16 sport;             //  2
    __u8 nexthdr;             //  1
    __u8 flags;               //  1
} __attribute__((packed));    // = 38 bytes (KeySize for conn_track_v6)
_Static_assert(sizeof(struct ipv6_ct_tuple) == 38,
               "ipv6_ct_tuple must be exactly 38 bytes (packed)");

struct conn_value {
    __u64 timestamp;
    __u64 last_timestamp;
    __u64 ttl_ns;
    __u8 state;
    __u8 flags;
    __u32 rx_packets;
    __u32 tx_packets;
};

// conn_track: per-flow established-connection cache. It MUST be
// BPF_MAP_TYPE_HASH, not LRU_HASH (#2814).
//
// Datapath (xdp_white_prog): a packet that hits conn_track XDP_PASSes
// immediately; a MISS falls through to the allow-rule maps, and an allow-rule
// match attempts to populate conn_track (BPF_ANY) before passing.
//
// Why HASH even though this is a cache: normal LRU eviction would be benign
// while the allow-rule still exists, because the next packet can re-check the
// authoritative allow-rule and re-cache. That is false after surgical revoke:
// revocation_index.go first tears down the shared allow-rule for the FlowKey,
// then surgicalFlushFlowKey deletes only the revoked 5-tuples and deliberately
// leaves same-allow-tuple siblings alive (#2784). A spared sibling then survives
// solely via its conn_track entry; if an LRU map evicts that cold sibling under
// pressure, the next packet falls through to the now-removed allow-rule and
// XDP_DROPs, reopening the collateral over-flush #2784 fixed.
//
// HASH preserves existing established entries at capacity. A new/uncached flow
// whose BPF_ANY insert gets -E2BIG still returns XDP_PASS after an allow-rule
// match (the update return is intentionally not verdict-bearing), but it remains
// on the slow path until a slot is made available. Expired quiet entries are not
// proactively scavenged today, so sizing/alarming/reaper follow-up remains
// load-bearing for the flip (#2813). The full-cache miss behavior is proven by
// TestConnTrackFullHashCacheMissFallsBackToAllowRule.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct ipv4_ct_tuple);
    __type(value, struct conn_value);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} conn_track SEC(".maps");

// conn_track_v6: IPv6 counterpart of conn_track. The same HASH decision applies
// now that the v6 datapath and surgical v6 conntrack path are wired: do not let
// LRU pressure evict a spared sibling's established-flow cache entry after the
// shared allow-rule has been torn down. Key is ipv6_ct_tuple (KeySize 38), value
// reuses conn_value, and max_entries is the smaller MAX_ENTRIES_V6 ceiling.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES_V6);
    __type(key, struct ipv6_ct_tuple);        // KeySize 38
    __type(value, struct conn_value);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} conn_track_v6 SEC(".maps");

struct event_t {
    __u64 timestamp;
    __u8 action;
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    __u8 protocol;
    __be16 len;
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 1024);
} events SEC(".maps");

// Submit the event details including source and destination IP addresses, source and destination ports, protocol, and total packet length to the user space.
static __always_inline int submit_event(void *ctx, __u8 action, __be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port, __u8 protocol, __be16 len) {
    struct event_t ev = {};
    ev.timestamp = bpf_ktime_get_ns();
    ev.action = action; // 0 = DENY, 1 = ACCEPT
    ev.src_ip = src_ip;
    ev.dst_ip = dst_ip;
    ev.src_port = src_port;
    ev.dst_port = dst_port;
    ev.protocol = protocol;
    ev.len = len;

    // Submit the event details to the user space Perf Buffer.
    return bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));
}

// ----------------------------------------------------------------------------
// IPv6 filter-decision telemetry (E3).
//
// struct event_t above is IPv4-shaped (__be32 src_ip/dst_ip) and cannot hold a
// 128-bit v6 address, so before E3 the v6 datapath emitted ACCEPT events with
// src/dst = 0 (addresses lost) and emitted NOTHING on a v6 DROP (silent). That
// is the observability regression E3 closes: iptables mode (prod today) logs v6
// fully via [NHP-ACCEPT6]/[NHP-DENY6] LOG rules with full v6 addresses, so
// flipping FilterMode to eBPF (E5) would otherwise blind v6 filter logging.
//
// Rather than widen event_t (which would ripple into the proven v4 event
// binary offsets, the v4 Go decoder, and the v4 log format), we add a PARALLEL
// v6 event variant — same precedent as the E2 parallel v6 maps. The v4 path,
// the v4 perf map, and its on-wire layout are left byte-for-byte untouched.
//
// FIELD ORDER mirrors event_t (timestamp, action, src, dst, sport, dport,
// protocol, len) so the Go decoder can parse v4 and v6 events with the same
// field sequence (only the address width differs: 16 bytes vs 4). The real
// `__attribute__((packed))` plus the _Static_assert below pins the 48-byte size
// so any C/Go layout drift is a compile-time failure, mirroring the *_v6 key
// structs.
struct event_t_v6 {
    __u64 timestamp;
    __u8 action;
    struct in6_addr src_ip;
    struct in6_addr dst_ip;
    __be16 src_port;
    __be16 dst_port;
    __u8 protocol;
    __be16 len;
} __attribute__((packed));

// 8 (timestamp) + 1 (action) + 16 (src_ip) + 16 (dst_ip) + 2 (src_port)
//   + 2 (dst_port) + 1 (protocol) + 2 (len) = 48. Mirrored exactly by the Go
// EventV6 struct (binary.Size(EventV6{}) == 48) — the C↔Go contract guard.
_Static_assert(sizeof(struct event_t_v6) == 48,
               "event_t_v6 must be exactly 48 bytes (packed) — keep in lockstep with the Go EventV6 struct");

// Parallel v6 perf map (mirrors `events`). v6 filter-decision events land here
// so the Go reader can decode them with the v6 (16-byte-address) layout without
// disturbing the v4 `events` stream. Same depth as `events` (1024).
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 1024);
} events_v6 SEC(".maps");

// submit_event_v6 mirrors submit_event but emits a struct event_t_v6 to the
// events_v6 perf map, carrying the full 128-bit src/dst addresses. Addresses
// are passed as struct in6_addr (already network byte order, exactly as read
// from ip6h->saddr/daddr); ports/len are __be16 (network order) just like the
// v4 path. action: 0 = DENY, 1 = ACCEPT.
static __always_inline int submit_event_v6(void *ctx, __u8 action, struct in6_addr src_ip, struct in6_addr dst_ip, __be16 src_port, __be16 dst_port, __u8 protocol, __be16 len) {
    struct event_t_v6 ev = {};
    ev.timestamp = bpf_ktime_get_ns();
    ev.action = action; // 0 = DENY, 1 = ACCEPT
    ev.src_ip = src_ip;
    ev.dst_ip = dst_ip;
    ev.src_port = src_port;
    ev.dst_port = dst_port;
    ev.protocol = protocol;
    ev.len = len;

    // Submit the v6 event details to the user space Perf Buffer (events_v6).
    return bpf_perf_event_output(ctx, &events_v6, BPF_F_CURRENT_CPU, &ev, sizeof(ev));
}

// ----------------------------------------------------------------------------
// DENY-telemetry rate limiter (#2849).
//
// E3 (above) gave the malformed/early-drop paths a voice: a truncated header,
// an unsupported nexthdr, a bad IHL, or a truncated L4 header now emits a DENY
// event before XDP_DROP instead of dropping silently. These are packets the
// kernel would discard pre-iptables — XDP sees them at the NIC — so they are an
// attacker-controllable, unbounded emission surface that goes hot the moment
// FilterMode flips to eBPF at the E5 cutover. A single malformed-packet flood
// could swamp the perf buffer (and the userspace reader) with DENY events.
//
// A per-CPU token bucket bounds that surface. The cap is held in a REGULAR
// (non-per-CPU) ARRAY map so userspace can tune it at runtime without
// recompiling/redeploying the object — that runtime-tunability is what lets E5
// adjust the cap without a .o regen, partially easing #2823. The token state is
// per-CPU (the hot path, written every packet — a shared map would need atomics
// and contend across CPUs); a per-CPU bucket trades exactness for lock-free
// speed (the effective aggregate cap is capacity * nr_cpus, which is fine for a
// telemetry guard whose job is bounding, not precise accounting).
//
// Scope: ONLY the malformed/early-drop DENY sites are gated by this. The
// no-match (unauthorized-access) DENY and every ACCEPT emission are left
// unrate-limited on purpose — see should_emit_deny_event() and the call sites.
struct deny_rl_state_t {
    __u64 tokens;          // tokens currently available (<= capacity)
    __u64 last_refill_ns;  // bpf_ktime_get_ns() at the last refill; 0 = uninit
};

// Per-CPU token-bucket state. PERCPU_ARRAY, single entry (key 0): the hot path
// updates this every malformed-DENY decision, so per-CPU avoids cross-CPU
// contention and lets us use a plain (non-atomic) read-modify-write.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct deny_rl_state_t);
    __uint(max_entries, 1);
} deny_rl_state SEC(".maps");

struct deny_rl_config_t {
    __u64 capacity;        // bucket size (max tokens); 0 = limiter disabled
    __u64 refill_per_sec;  // tokens added per second
};

// Runtime config. REGULAR ARRAY (NOT per-CPU): userspace writes one shared copy
// (key 0) that every CPU reads, so the cap can be retuned at the E5 flip with a
// single map update and no object regen (#2823). capacity == 0 (the zero value
// of a freshly created, never-written map) means "unconfigured" → fail OPEN to
// today's always-emit behavior (see should_emit_deny_event()).
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct deny_rl_config_t);
    __uint(max_entries, 1);
} deny_rl_config SEC(".maps");

// Suppression counter. PERCPU_ARRAY, single entry (key 0): incremented (plain
// +=, no atomic — per-CPU) each time a malformed-DENY event is dropped by the
// limiter, so userspace can sum across CPUs to observe how much telemetry the
// rate limiter is shedding. Diagnostics only; does not affect the datapath.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} deny_suppressed SEC(".maps");

// One second in nanoseconds — bpf_ktime_get_ns() is a ns monotonic clock.
#define NS_PER_SEC 1000000000ULL

// should_emit_deny_event decides whether a malformed/early-drop DENY event may
// be emitted, applying the per-CPU token bucket above. Returns 1 = EMIT,
// 0 = SUPPRESS.
//
// Fail-open contract: if the limiter is unconfigured (no config map, or
// capacity == 0) or its state can't be read, we return 1 (emit) so behavior is
// IDENTICAL to today's always-emit datapath until userspace opts in by writing
// a non-zero capacity. The rate limiter can only ever *reduce* emissions, never
// add or block legitimate telemetry on a misconfiguration.
//
// Verifier/overflow notes:
//   - All three map lookups are null-checked before any deref.
//   - State is mutated in place through the per-CPU pointer (no
//     bpf_map_update_elem); per-CPU means no atomics are needed.
//   - Refill is computed overflow-safely by splitting elapsed into
//     whole-seconds and sub-second remainder so neither term can wrap a u64 for
//     any realistic refill_per_sec (whole = (elapsed/1e9)*rate, which only
//     overflows after ~584 years of elapsed time at rate==1; sub = (elapsed%1e9)
//     * rate / 1e9, where elapsed%1e9 < 1e9 keeps the product bounded for any
//     sane rate). The tokens+refill sum is then guarded against wrap before the
//     min(capacity, ...) clamp.
static __always_inline int should_emit_deny_event(void) {
    __u32 key = 0;

    struct deny_rl_config_t *cfg = bpf_map_lookup_elem(&deny_rl_config, &key);
    // Unconfigured (no map entry) or explicitly disabled (capacity 0) →
    // fail open to today's always-emit behavior.
    if (!cfg || cfg->capacity == 0)
        return 1;

    struct deny_rl_state_t *st = bpf_map_lookup_elem(&deny_rl_state, &key);
    if (!st)
        return 1;

    __u64 capacity = cfg->capacity;
    __u64 refill_per_sec = cfg->refill_per_sec;
    __u64 now = bpf_ktime_get_ns();

    if (st->last_refill_ns == 0) {
        // First use on this CPU: start with a full bucket.
        st->tokens = capacity;
        st->last_refill_ns = now;
    } else if (now > st->last_refill_ns) {
        // Refill since the last decision. (now <= last_refill_ns is skipped:
        // ktime is monotonic, so this only guards a same-ns re-entry — no
        // refill is due in that case anyway.)
        __u64 elapsed = now - st->last_refill_ns;

        // Overflow-safe elapsed * refill_per_sec / NS_PER_SEC, split into
        // whole-second and sub-second parts.
        __u64 whole = (elapsed / NS_PER_SEC) * refill_per_sec;
        __u64 sub = (elapsed % NS_PER_SEC) * refill_per_sec / NS_PER_SEC;
        __u64 refill = whole + sub;

        if (refill > 0) {
            __u64 sum = st->tokens + refill;
            // Clamp to capacity, also catching a u64 wrap (sum < tokens).
            if (sum > capacity || sum < st->tokens)
                sum = capacity;
            st->tokens = sum;
            st->last_refill_ns = now;
        }
    }

    // A runtime capacity DECREASE (operator retunes deny_rl_config down at the E5
    // flip) can leave the live token count above the new cap; the refill branch
    // only clamps on the way up, so clamp unconditionally here too — the lower cap
    // then takes effect on THIS decision instead of lagging until the next refill
    // tick. Runtime-tunability without an .o regen is the point of the config map,
    // so a retune-down must not silently keep draining from the old, higher level.
    if (st->tokens > capacity)
        st->tokens = capacity;

    if (st->tokens > 0) {
        st->tokens -= 1;
        return 1; // EMIT
    }

    // Bucket empty: shed this event and bump the per-CPU suppressed counter
    // (plain += is safe — per-CPU map, no cross-CPU contention).
    __u64 *suppressed = bpf_map_lookup_elem(&deny_suppressed, &key);
    if (suppressed)
        *suppressed += 1;
    return 0; // SUPPRESS
}

static __always_inline void reverseTuple(struct ipv4_ct_tuple *key) {
    __u32 tmp_ip = key->daddr;
    __u16 tmp_port = key->dport;
    key->flags = !key->flags;
    key->daddr = key->saddr;
    key->saddr = tmp_ip;
    key->dport = key->sport;
    key->sport = tmp_port;
}

// v6 counterpart of reverseTuple: swaps {daddr,saddr} and {dport,sport} and
// flips the direction flag on an ipv6_ct_tuple, so one map can be probed for both
// the ingress tuple and its reverse (the v4 conntrack two-lookup pattern).
// Addresses are struct in6_addr (16 B), so they swap through a temporary struct
// rather than a scalar.
static __always_inline void reverseTuple_v6(struct ipv6_ct_tuple *key) {
    struct in6_addr tmp_ip = key->daddr;
    __u16 tmp_port = key->dport;
    key->flags = !key->flags;
    key->daddr = key->saddr;
    key->saddr = tmp_ip;
    key->dport = key->sport;
    key->sport = tmp_port;
}

#ifndef __constant_htons
#define __constant_htons(x) ((__u16)((((x) & 0xFF00) >> 8) | (((x) & 0x00FF) << 8)))
#endif

static __always_inline bool check_conn_expiry(struct conn_value *val) {
    __u64 now = bpf_ktime_get_ns();
    return (now > val->timestamp + val->ttl_ns);
}

// ----------------------------------------------------------------------------
// IPv6 admission datapath (E2 slice 3).
//
// The v6 counterpart of the IPv4 flow in xdp_white_prog below: it mirrors the
// same conntrack-fast-path → allow-rule-cascade → fail-CLOSED structure, against
// the v6 maps slice 1 declared (spp_v6, sdwhitelist_v6, src_port_v6,
// port_list_v6, the family-agnostic protocol_port, and icmp_wl_v6). It is
// reached only from the ETH_P_IPV6 switch arm, which previously fail-OPENed
// (`return XDP_PASS`); this slice changes that arm to filtered admission that
// DROPs on no-match. Still INERT in prod: FilterMode defaults to iptables, so the
// XDP program is not loaded until the E5 flip — no runtime change lands here.
//
// IPv6 extension headers: resolve a bounded chain before L4 admission. Direct
// TCP/UDP/ICMPv6 still starts at (ip6h + 1); packets carrying Hop-by-Hop,
// Routing, Destination Options, Mobility, or AH headers advance through those
// headers (with a fixed hop cap and data_end checks at every step) until the
// final TCP/UDP/ICMPv6 protocol is found. Anything unresolved fails CLOSED:
// Fragment (no reassembly/port visibility for non-first fragments), ESP, No
// Next Header, unknown protocols, truncated headers, or a chain longer than
// IPV6_EXT_MAX_HEADERS. This keeps extension headers from bypassing admission
// while admitting the ordinary inspectable chains that terminate in an L4 header.
//
// LIMITATION — DENY/ACCEPT events carry zeroed IPv4 address fields. struct
// event_t is IPv4-shaped (__be32 src_ip/dst_ip); it cannot hold a 128-bit v6
// address. Expanding it ripples into the Go event decoder (slices 2/4) and is
// out of scope here, so v6 events pass 0 for the address fields (ports/protocol
// are still meaningful). The verdict itself is unaffected — only event
// telemetry addresses are truncated for v6.
//
// EVENT len — kept in PARITY with v4. v4 passes iph->tot_len, the entire L3
// datagram length INCLUDING the 20-byte IPv4 header. The v6 fixed header's
// payload_len excludes the 40-byte fixed header, so to report the same basis
// (whole-datagram length) we add sizeof(struct ipv6hdr) back, in network byte
// order, into `total_len` below and pass THAT to submit_event — not the raw
// payload_len. Without this the v6 event would under-report by 40 bytes and the
// slice-2/4 decoder would see two different length semantics across families.
//
// Reached as a helper (not inlined manually) so the v6 locals live in their own
// function scope; combined with the per-rule { } blocks below, this lets clang
// reuse one stack slot for the large v6 key structs instead of summing them
// (the 512-byte BPF stack limit is the real constraint here, not insn count).
static __always_inline bool resolve_ipv6_l4(struct ipv6hdr *ip6h,
                                            void *data_end,
                                            void **l4_out,
                                            __u8 *nexthdr_out,
                                            __u8 *deny_nexthdr_out) {
    __u8 nexthdr = ip6h->nexthdr;
    __u64 offset = sizeof(struct ipv6hdr);

#pragma unroll
    for (int i = 0; i < IPV6_EXT_MAX_HEADERS + 1; i++) {
        if (nexthdr == IPPROTO_TCP ||
            nexthdr == IPPROTO_UDP ||
            nexthdr == IPPROTO_ICMPV6) {
            *l4_out = (void *)ip6h + offset;
            *nexthdr_out = nexthdr;
            return true;
        }

        *deny_nexthdr_out = nexthdr;
        if (i == IPV6_EXT_MAX_HEADERS)
            return false;

        if (nexthdr == IPV6_NEXTHDR_NONE ||
            nexthdr == IPV6_NEXTHDR_ESP ||
            nexthdr == IPV6_NEXTHDR_FRAGMENT) {
            return false;
        }

        if (nexthdr == IPV6_NEXTHDR_HOP ||
            nexthdr == IPV6_NEXTHDR_ROUTING ||
            nexthdr == IPV6_NEXTHDR_DEST ||
            nexthdr == IPV6_NEXTHDR_MOBILITY) {
            // Extension-header ordering/duplicate validation, including
            // Hop-by-Hop first-only and RH0 / segments-left policy, is
            // delegated to the kernel stack after XDP_PASS. XDP only walks far
            // enough to classify the final L4 protocol for admission.
            struct ipv6_opt_hdr *eh = (void *)ip6h + offset;
            if ((void *)(eh + 1) > data_end)
                return false;
            __u64 hdr_len = ((__u64)eh->hdrlen + 1) << 3;
            if ((void *)eh + hdr_len > data_end)
                return false;
            nexthdr = eh->nexthdr;
            offset += hdr_len;
            continue;
        }

        if (nexthdr == IPV6_NEXTHDR_AH) {
            struct ipv6_opt_hdr *ah = (void *)ip6h + offset;
            if ((void *)(ah + 1) > data_end)
                return false;
            // AH semantic validation (minimum RFC 4302 length, SPI/sequence,
            // authentication data) is left to the kernel stack after XDP_PASS;
            // XDP only needs a bounds-safe skip to classify the final L4 header
            // for admission.
            __u64 hdr_len = ((__u64)ah->hdrlen + 2) << 2;
            if ((void *)ah + hdr_len > data_end)
                return false;
            nexthdr = ah->nexthdr;
            offset += hdr_len;
            continue;
        }

        return false;
    }

    // Defensive tail for C control-flow completeness if the cap expression is
    // ever rewritten; the i == IPV6_EXT_MAX_HEADERS guard returns first today.
    *deny_nexthdr_out = nexthdr;
    return false;
}

static __always_inline int xdp_white_prog_v6(struct xdp_md *ctx,
                                             struct ethhdr *eth,
                                             void *data_end) {
    struct ipv6hdr *ip6h = (void *)(eth + 1);
    if ((void *)(ip6h + 1) > data_end) {
        // IPv6 fixed header is truncated — saddr/daddr are NOT readable here, so
        // we emit a DENY with ZEROED addresses (matching iptables, which also
        // cannot log what it cannot parse). E3 surfaces the DROP so it is not
        // silent; the addresses are simply unrecoverable at this point.
        struct in6_addr zero6 = {};
        if (should_emit_deny_event())
            submit_event_v6(ctx, 0, zero6, zero6, 0, 0, 0, 0);
        return XDP_DROP;
    }

    // Event length kept in parity with v4's iph->tot_len (whole L3 datagram):
    // payload_len excludes the 40-byte fixed header, so add it back, staying in
    // network byte order. See the EVENT len note in the header comment above.
    __be16 total_len = bpf_htons(bpf_ntohs(ip6h->payload_len) + sizeof(struct ipv6hdr));

    void *l4 = 0;
    __u8 nexthdr = 0;
    __u8 deny_nexthdr = ip6h->nexthdr;
    if (!resolve_ipv6_l4(ip6h, data_end, &l4, &nexthdr, &deny_nexthdr)) {
        // Fixed header is valid, so saddr/daddr ARE readable. Emit a DENY with
        // real addresses before DROP so unsupported/truncated extension chains
        // and fragments are visible. Ports stay 0 because no trustworthy L4
        // header was resolved; deny_nexthdr identifies the header that stopped
        // parsing (Fragment/ESP/unknown/etc.).
        if (should_emit_deny_event())
            submit_event_v6(ctx, 0, ip6h->saddr, ip6h->daddr, 0, 0, deny_nexthdr, total_len);
        return XDP_DROP;
    }

    // L4 ports. ICMPv6 is portless, so ports stay 0 for it (and the port-based
    // maps below cannot match it — it is admitted only via icmp_wl_v6).
    __be16 sport = 0;
    __be16 dport = 0;
    if (nexthdr == IPPROTO_TCP) {
        struct tcphdr *tcp = l4;
        if ((void *)(tcp + 1) > data_end) {
            // L4 (TCP) header truncated. The IPv6 fixed header is valid, so the
            // addresses are recoverable — emit a DENY with real addrs (E3). The
            // ports are NOT yet parsed at this point, so they are 0 (honest:
            // can't log what wasn't parsed).
            if (should_emit_deny_event())
                submit_event_v6(ctx, 0, ip6h->saddr, ip6h->daddr, 0, 0, nexthdr, total_len);
            return XDP_DROP;
        }
        sport = tcp->source;
        dport = tcp->dest;
    } else if (nexthdr == IPPROTO_UDP) {
        struct udphdr *udp = l4;
        if ((void *)(udp + 1) > data_end) {
            // L4 (UDP) header truncated — same treatment as the TCP case above.
            if (should_emit_deny_event())
                submit_event_v6(ctx, 0, ip6h->saddr, ip6h->daddr, 0, 0, nexthdr, total_len);
            return XDP_DROP;
        }
        sport = udp->source;
        dport = udp->dest;
    }

    __u64 now = bpf_ktime_get_ns();

    // ICMPv6 admission. Unlike v4 (where a non-echo ICMP packet falls THROUGH
    // to the conntrack + src+dst sdwhitelist cascade), this branch is scoped so
    // a DROP here does NOT fall through to the port cascade, and a non-DROP
    // verdict is decided entirely HERE. That makes ICMPv6 type-driven, which is
    // what the v6 control plane needs:
    //
    //   - NDP (133–137 RS/RA/NS/NA/Redirect) and Packet-Too-Big (2) PASS
    //     unconditionally — see below.
    //   - Echo Request (128) is gated by a non-expired, allowed icmp_wl_v6
    //     (src+dst) entry; Echo Reply (129) passes (mirrors v4 type 0).
    //   - every OTHER ICMPv6 type (Dest-Unreach 1, Time-Exceeded 3,
    //     Param-Problem 4, MLD 130–132/143, etc.) fails CLOSED.
    //
    // v4/v6 DIVERGENCE (deliberate, documented): in v4 a non-echo ICMP packet
    // can be admitted by a portless src+dst `sdwhitelist` match (it falls
    // through the ICMP block into the cascade). In v6 it cannot — ICMPv6 is
    // gated SOLELY by this branch (icmp_wl_v6 for echo; the explicit
    // PASS/DROP type filter for everything else), never by sdwhitelist_v6.
    // An operator who relies on a src+dst allow to cover ping in v4 must add an
    // icmp_wl_v6 entry for v6. This is stricter (fail-closed) than v4 and is the
    // intended posture: the error types we do NOT pass (1/3/4) stay dropped
    // rather than being rescuable via a broad src+dst rule.
    if (nexthdr == IPPROTO_ICMPV6) {
        struct icmp6hdr *icmp6 = l4;
        if ((void *)(icmp6 + 1) > data_end) {
            // ICMPv6 L4 header truncated. Fixed header is valid → addresses
            // recoverable; emit a DENY with real addrs (E3), ports 0 (ICMPv6 is
            // portless). This is the L4-header-truncation parity with TCP/UDP
            // above. NOTE: the ICMPv6 *type* denials below (echo-not-allowed,
            // unsupported type) are deliberately left SILENT to mirror the v4
            // ICMP path, which does not emit a DENY on those — see E3 design.
            if (should_emit_deny_event())
                submit_event_v6(ctx, 0, ip6h->saddr, ip6h->daddr, 0, 0, nexthdr, total_len);
            return XDP_DROP;
        }
        __u8 icmp6_type = icmp6->icmp6_type;

        // Neighbor Discovery (133–137) is the IPv6 analog of ARP: it is how the
        // link resolves L2 addresses (NS/NA) and learns the prefix + default
        // route (RS/RA), plus Redirect. The v4 path passes ARP unconditionally
        // (`case ETH_P_ARP: return XDP_PASS`); NDP rides inside ICMPv6 on the
        // ETH_P_IPV6 ethertype, so the equivalent passthrough has to live here.
        // Without it, loading XDP on a v6-bearing interface (AWS/ENA) blackholes
        // neighbor resolution: inbound NS for the AC's own address is dropped →
        // no NA → neighbors can't resolve the AC's MAC → traffic to the AC
        // black-holes. PASS the whole range unconditionally, matching ARP. This
        // is link-local control traffic, not a data path admitted via the maps.
        if (icmp6_type >= ICMPV6_ND_ROUTER_SOLICIT &&
            icmp6_type <= ICMPV6_ND_REDIRECT)
            return XDP_PASS;

        // Packet Too Big (2): IPv6 routers never fragment, so PMTUD depends
        // ENTIRELY on this message getting back to the sender. Its source is a
        // path router whose address we cannot whitelist ahead of time, so —
        // unlike v4, where ICMP errors can fall through to sdwhitelist — there
        // is no map that could admit it; dropping it blackholes every large v6
        // flow. RFC 4890 §4.3.1 classifies PTB as MUST NOT be dropped. PASS it.
        // (Dest-Unreach 1 / Time-Exceeded 3 / Param-Problem 4 are deliberately
        // NOT passed here — they fail closed below, the stricter v4/v6
        // divergence documented above.)
        if (icmp6_type == ICMPV6_PKT_TOO_BIG)
            return XDP_PASS;

        if (icmp6_type == ICMPV6_ECHO_REQUEST && icmp6->icmp6_code == 0) {
            struct icmpwhitelist_key_v6 ikey = {
                .src_ip = ip6h->saddr,
                .dst_ip = ip6h->daddr,
            };
            struct icmpwhitelist_value *iw_val =
                bpf_map_lookup_elem(&icmp_wl_v6, &ikey);
            if (!iw_val)
                return XDP_DROP;
            if (iw_val->expire_time < now) {
                bpf_map_delete_elem(&icmp_wl_v6, &ikey);
                return XDP_DROP;
            }
            if (iw_val->allowed == 1)
                return XDP_PASS;
            return XDP_DROP;
        } else if (icmp6_type == ICMPV6_ECHO_REPLY && icmp6->icmp6_code == 0) {
            // Unconditional PASS — the one fail-OPEN arm in this fail-closed
            // branch. Deliberate v4 parity: v4 PASSes ICMP type 0 (Echo Reply)
            // the same way. An Echo Reply only arrives for a request we sent,
            // so it carries no admission decision of its own.
            return XDP_PASS;
        }
        // Any other ICMPv6 type (errors 1/3/4, MLD, etc.) fails closed.
        return XDP_DROP;
    }

    // conntrack fast path (TCP/UDP only): a hit on a non-expired entry PASSes
    // immediately, mirroring v4. Forward tuple, then reverse tuple.
    struct ipv6_ct_tuple ct_key = {};
    ct_key.daddr = ip6h->daddr;
    ct_key.saddr = ip6h->saddr;
    ct_key.dport = dport;
    ct_key.sport = sport;
    ct_key.nexthdr = nexthdr;
    ct_key.flags = CT_DIR_INGRESS;

    struct conn_value *existing_val = bpf_map_lookup_elem(&conn_track_v6, &ct_key);
    if (existing_val) {
        if (check_conn_expiry(existing_val)) {
            bpf_map_delete_elem(&conn_track_v6, &ct_key);
            return XDP_DROP;
        }
        struct conn_value new_val = *existing_val;
        new_val.tx_packets++;
        new_val.last_timestamp = bpf_ktime_get_ns();
        bpf_map_update_elem(&conn_track_v6, &ct_key, &new_val, BPF_EXIST);
        return XDP_PASS;
    }
    reverseTuple_v6(&ct_key);
    existing_val = bpf_map_lookup_elem(&conn_track_v6, &ct_key);
    if (existing_val) {
        if (check_conn_expiry(existing_val)) {
            bpf_map_delete_elem(&conn_track_v6, &ct_key);
            reverseTuple_v6(&ct_key);
            return XDP_DROP;
        }
        struct conn_value new_val = *existing_val;
        new_val.rx_packets++;
        new_val.last_timestamp = bpf_ktime_get_ns();
        bpf_map_update_elem(&conn_track_v6, &ct_key, &new_val, BPF_EXIST);
        reverseTuple_v6(&ct_key);
        return XDP_PASS;
    }
    reverseTuple_v6(&ct_key);   // restore forward tuple for conntrack population

    // Allow-rule cascade (mirrors the v4 order: spp → sdwhitelist → src_port →
    // port_list → protocol_port). On a non-expired allowed hit: populate
    // conn_track_v6 (so the flow's subsequent packets take the fast path above)
    // and PASS. Each rule's key + lookup is scoped in its own { } block so clang
    // reuses one stack slot for the large v6 key structs (512-byte stack limit).

    // spp_v6 (src + dst + dport + proto)
    {
        struct whitelist_key_v6 key = {
            .src_ip = ip6h->saddr,
            .dst_ip = ip6h->daddr,
            .dst_port = dport,
            .protocol = nexthdr,
        };
        struct whitelist_value *w_val = bpf_map_lookup_elem(&spp_v6, &key);
        if (w_val) {
            if (w_val->expire_time < now) {
                bpf_map_delete_elem(&spp_v6, &key);
                return XDP_DROP;
            }
            if (w_val->allowed == 1) {
                submit_event_v6(ctx, 1, ip6h->saddr, ip6h->daddr, sport, dport, nexthdr, total_len);
                struct conn_value new_val = {
                    .timestamp = bpf_ktime_get_ns(),
                    .last_timestamp = bpf_ktime_get_ns(),
                    .ttl_ns = w_val->expire_time - now,
                    .state = CT_ESTABLISHED,
                    .flags = CT_FLAG_NONE,
                    .rx_packets = 1,
                    .tx_packets = 0,
                };
                bpf_map_update_elem(&conn_track_v6, &ct_key, &new_val, BPF_ANY);
                return XDP_PASS;
            }
        }
    }

    // sdwhitelist_v6 (src + dst)
    {
        struct sdwhitelist_key_v6 sdkey = {
            .src_ip = ip6h->saddr,
            .dst_ip = ip6h->daddr,
        };
        struct sdwhitelist_value *sd_val = bpf_map_lookup_elem(&sdwhitelist_v6, &sdkey);
        if (sd_val) {
            if (sd_val->expire_time < now) {
                bpf_map_delete_elem(&sdwhitelist_v6, &sdkey);
                return XDP_DROP;
            }
            if (sd_val->allowed == 1) {
                submit_event_v6(ctx, 1, ip6h->saddr, ip6h->daddr, sport, dport, nexthdr, total_len);
                struct conn_value new_val = {
                    .timestamp = bpf_ktime_get_ns(),
                    .last_timestamp = bpf_ktime_get_ns(),
                    .ttl_ns = sd_val->expire_time - now,
                    .state = CT_ESTABLISHED,
                    .flags = CT_FLAG_NONE,
                    .rx_packets = 1,
                    .tx_packets = 0,
                };
                bpf_map_update_elem(&conn_track_v6, &ct_key, &new_val, BPF_ANY);
                return XDP_PASS;
            }
        }
    }

    // src_port_v6 (src + dport)
    {
        struct src_port_list_key_v6 spkey = {
            .src_ip = ip6h->saddr,
            .dst_port = dport,
        };
        struct src_port_list_value *sp_val = bpf_map_lookup_elem(&src_port_v6, &spkey);
        if (sp_val) {
            if (sp_val->expire_time < now) {
                bpf_map_delete_elem(&src_port_v6, &spkey);
                return XDP_DROP;
            }
            if (sp_val->allowed == 1) {
                submit_event_v6(ctx, 1, ip6h->saddr, ip6h->daddr, sport, dport, nexthdr, total_len);
                struct conn_value new_val = {
                    .timestamp = bpf_ktime_get_ns(),
                    .last_timestamp = bpf_ktime_get_ns(),
                    .ttl_ns = sp_val->expire_time - now,
                    .state = CT_ESTABLISHED,
                    .flags = CT_FLAG_NONE,
                    .rx_packets = 1,
                    .tx_packets = 0,
                };
                bpf_map_update_elem(&conn_track_v6, &ct_key, &new_val, BPF_ANY);
                return XDP_PASS;
            }
        }
    }

    // port_list_v6 (src + port range)
    {
        struct port_list_key_v6 pl_key = {
            .src_ip = ip6h->saddr,
            .min_port = MIN_PORT,
            .max_port = MAX_PORT,
        };
        struct port_list_value *pl_val = bpf_map_lookup_elem(&port_list_v6, &pl_key);
        if (pl_val) {
            if (pl_val->expire_time < now) {
                bpf_map_delete_elem(&port_list_v6, &pl_key);
                return XDP_DROP;
            }
            if (pl_val->allowed == 1) {
                submit_event_v6(ctx, 1, ip6h->saddr, ip6h->daddr, sport, dport, nexthdr, total_len);
                struct conn_value new_val = {
                    .timestamp = bpf_ktime_get_ns(),
                    .last_timestamp = bpf_ktime_get_ns(),
                    .ttl_ns = pl_val->expire_time - now,
                    .state = CT_ESTABLISHED,
                    .flags = CT_FLAG_NONE,
                    .rx_packets = 1,
                    .tx_packets = 0,
                };
                bpf_map_update_elem(&conn_track_v6, &ct_key, &new_val, BPF_ANY);
                return XDP_PASS;
            }
        }
    }

    // protocol_port (proto + dport) — REUSED v4 map. By design there is no
    // protocol_port_v6: the key carries no IP address, so a proto+dport rule is
    // IP-family-agnostic and one entry admits both families (slice 1 note).
    {
        struct protocol_port_key pp_key = {
            .dst_port = dport,
            .protocol = nexthdr,
        };
        struct protocol_port_value *pp_val = bpf_map_lookup_elem(&protocol_port, &pp_key);
        if (pp_val) {
            if (pp_val->expire_time < now) {
                bpf_map_delete_elem(&protocol_port, &pp_key);
                return XDP_DROP;
            }
            if (pp_val->allowed == 1) {
                submit_event_v6(ctx, 1, ip6h->saddr, ip6h->daddr, sport, dport, nexthdr, total_len);
                struct conn_value new_val = {
                    .timestamp = bpf_ktime_get_ns(),
                    .last_timestamp = bpf_ktime_get_ns(),
                    .ttl_ns = pp_val->expire_time - now,
                    .state = CT_ESTABLISHED,
                    .flags = CT_FLAG_NONE,
                    .rx_packets = 1,
                    .tx_packets = 0,
                };
                bpf_map_update_elem(&conn_track_v6, &ct_key, &new_val, BPF_ANY);
                return XDP_PASS;
            }
        }
    }

    // No allow-rule matched → fail CLOSED (the whole point of this slice: the
    // ETH_P_IPV6 arm no longer fail-OPENs). Emit a DENY event like v4 — now with
    // the full v6 src/dst addresses (E3) so the eBPF path matches the iptables
    // [NHP-DENY6] LOG rule — then DROP.
    // NOT rate-limited (#2849): a no-match DROP is an unauthorized-access audit
    // signal, not a malformed-packet flood, and dropping it would lose security
    // visibility + break parity with the unconditional iptables [NHP-DENY6] LOG.
    submit_event_v6(ctx, 0, ip6h->saddr, ip6h->daddr, sport, dport, nexthdr, total_len);
    return XDP_DROP;
}

SEC("xdp")
static __always_inline int xdp_white_prog(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct tcphdr *tcp;
    struct ipv4_ct_tuple ct_key = {};
    struct ethhdr *eth = data;

    if (data + sizeof(*eth) > data_end) {
        return XDP_DROP;
    }

    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;

    switch (bpf_ntohs(eth->h_proto)) {
        case ETH_P_ARP:  return XDP_PASS;
        case ETH_P_IP:   break;
        case ETH_P_IPV6: return xdp_white_prog_v6(ctx, eth, data_end);
        default:         return XDP_DROP;
    }

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        // IPv4 header truncated — no addresses to log. KEEP SILENT (E3: an
        // IP-header-truncation drop has no recoverable 4-tuple, matching the
        // eth-truncation drops above). The Go reader never sees an event here.
        return XDP_DROP;

    if (iph->ihl < 5) {
        // Malformed IHL (< 5 = header shorter than the 20-byte minimum). The
        // src/dst words are physically present but the header is structurally
        // invalid, so we cannot trust the parse — emit a DENY with ZEROED
        // addresses (E3 residual v4 parity), matching iptables' inability to
        // log a 4-tuple it can't validate. Surfacing the DROP (not silent) is
        // the point; the addresses are reported as 0.
        if (should_emit_deny_event())
            submit_event(ctx, 0, 0, 0, 0, 0, iph->protocol, iph->tot_len);
        return XDP_DROP;
    }

    if (iph->protocol == IPPROTO_TCP) {
        tcp = (void *)(iph + 1);
        if ((void *)(tcp + 1) > data_end) {
            // TCP header truncated. The IPv4 header is valid (bounds + IHL
            // checked above), so the addresses ARE recoverable — emit a DENY
            // with real addrs (E3). Ports are NOT yet parsed here, so they are
            // 0 (honest: can't log what wasn't parsed).
            if (should_emit_deny_event())
                submit_event(ctx, 0, iph->saddr, iph->daddr, 0, 0, iph->protocol, iph->tot_len);
            return XDP_DROP;
        }
        ct_key.nexthdr = IPPROTO_TCP;
        ct_key.sport = tcp->source;
        ct_key.dport = tcp->dest;
        // ct_key.dport = bpf_htons(tcp->dest);
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)(iph + 1);
        if ((void *)(udp + 1) > data_end) {
            // UDP header truncated — same treatment as the TCP case above:
            // real addrs (recoverable), ports 0 (not yet parsed).
            if (should_emit_deny_event())
                submit_event(ctx, 0, iph->saddr, iph->daddr, 0, 0, iph->protocol, iph->tot_len);
            return XDP_DROP;
        }
        ct_key.nexthdr = IPPROTO_UDP;
        ct_key.sport = udp->source;
        ct_key.dport = udp->dest;
        // ct_key.dport = bpf_htons(udp->dest);
    }


    if (iph->protocol == IPPROTO_TCP) {
        void *tcp_start = (void *)iph + (iph->ihl * 4);
        if ((void *)(tcp_start + sizeof(struct tcphdr)) > data_end) {
            // TCP options-aware re-parse (offset by ihl*4) ran off the packet
            // end. The IPv4 header + ports were already parsed (ct_key.sport/
            // dport set above), so the full 4-tuple is recoverable — emit a DENY
            // with real addrs + the parsed ports (E3 residual v4 parity).
            if (should_emit_deny_event())
                submit_event(ctx, 0, iph->saddr, iph->daddr, ct_key.sport, ct_key.dport, iph->protocol, iph->tot_len);
            return XDP_DROP;
        }

        struct tcphdr *tcp = tcp_start;
        if (__constant_htons(tcp->dest) == 22) {
            return XDP_PASS;
        }
    }

    if (iph->protocol == IPPROTO_UDP &&
        (ct_key.dport == bpf_htons(DHCP_PORT_R) || ct_key.dport == bpf_htons(DHCP_PORT_O) || ct_key.sport == bpf_htons(DNS_PORT))) {
        return XDP_PASS;
    }
    __u64 now = bpf_ktime_get_ns();

    // ICMP
    if (iph->protocol == IPPROTO_ICMP) {
        struct icmphdr *icmp = (void *)iph + (iph->ihl * 4);
        if ((void *)(icmp + 1) > data_end)
            return XDP_DROP;
        struct icmpwhitelist_key icmpkey = {
            .src_ip = iph->saddr,
            .dst_ip = iph->daddr,
        };
        //only processes ICMP Echo Requests (type 8, code 0) and ICMP Echo Replies (type 0, code 0)
        if ((icmp->type == ICMP_ECHO && icmp->code == 0) ||
            (icmp->type == ICMP_ECHOREPLY && icmp->code == 0)) {

            if (icmp->type == ICMP_ECHO) {
                //Lookup icmpwhitelist entry
                struct icmpwhitelist_value *iw_val = bpf_map_lookup_elem(&icmpwhitelist, &icmpkey);
                if (!iw_val) {
                    return XDP_DROP;
                }
                __u64 now = bpf_ktime_get_ns();
                // Check if whitelist entry has expired
                if (iw_val->expire_time < now) {
                    bpf_map_delete_elem(&icmpwhitelist, &icmpkey);
                    return XDP_DROP;
                }
                // Check if source IP is icmpwhitelisted and allowed
                if (iw_val->allowed == 1) {
                    return XDP_PASS;
                }
            }  else {
                return XDP_PASS;
            }
        }
    }

    ct_key.saddr = iph->saddr;
    ct_key.daddr = iph->daddr;
    ct_key.flags = CT_DIR_INGRESS;
    struct conn_value *existing_val;

    existing_val = bpf_map_lookup_elem(&conn_track, &ct_key);
    if (existing_val) {
        if (check_conn_expiry(existing_val)) {
            bpf_map_delete_elem(&conn_track, &ct_key);
            return XDP_DROP;
        }
        struct conn_value new_val = *existing_val;
        new_val.tx_packets++;
        new_val.last_timestamp = bpf_ktime_get_ns();
        bpf_map_update_elem(&conn_track, &ct_key, &new_val, BPF_EXIST);
        return XDP_PASS;
    }
    reverseTuple(&ct_key);
    existing_val = bpf_map_lookup_elem(&conn_track, &ct_key);
    if (existing_val) {
        if (check_conn_expiry(existing_val)) {
            bpf_map_delete_elem(&conn_track, &ct_key);
            reverseTuple(&ct_key);
            return XDP_DROP;
        }
        struct conn_value new_val = *existing_val;
        new_val.rx_packets++;
        new_val.last_timestamp = bpf_ktime_get_ns();
        bpf_map_update_elem(&conn_track, &ct_key, &new_val, BPF_EXIST);
        reverseTuple(&ct_key);
        return XDP_PASS;
    }
    reverseTuple(&ct_key);

    struct whitelist_key key = {
        .src_ip = iph->saddr,
        .dst_ip = iph->daddr,
        .dst_port = ct_key.dport,
        .protocol = iph->protocol
    };

    struct sdwhitelist_key sdkey = {
        .src_ip = iph->saddr,
        .dst_ip = iph->daddr
    };

    struct src_port_list_key spkey = {
        .src_ip = iph->saddr,
        .dst_port = ct_key.dport
    };

    struct port_list_key pl_key = {
        .src_ip = iph->saddr,
        .min_port = MIN_PORT,
        .max_port = MAX_PORT
    };
    __u16 dst_port = bpf_ntohs(ct_key.dport);

    struct protocol_port_key pp_key = {
        .dst_port = ct_key.dport,
        .protocol = iph->protocol
    };

    //Lookup whitelist entry
    struct whitelist_value *w_val = bpf_map_lookup_elem(&spp, &key);
    //Lookup sdwhitelist entry
    struct sdwhitelist_value *sd_val = bpf_map_lookup_elem(&sdwhitelist, &sdkey);
    //Lookup src_port_list entry
    struct src_port_list_value *sp_val = bpf_map_lookup_elem(&src_port, &spkey);
    //Lookup port_list entry
    struct port_list_value *pl_val= bpf_map_lookup_elem(&port_list, &pl_key);
    //Lookup protocol_port entry
    struct protocol_port_value *pp_val= bpf_map_lookup_elem(&protocol_port, &pp_key);

    if (w_val) {
        __u64 expire_time = w_val->expire_time;
        if (expire_time < now) {
            bpf_map_delete_elem(&spp, &key);
            return XDP_DROP;
        }
        if (w_val->allowed == 1) {
            submit_event(ctx, 1, iph->saddr, iph->daddr, ct_key.sport, ct_key.dport, iph->protocol, iph->tot_len);
            struct conn_value new_val = {
                .timestamp = bpf_ktime_get_ns(),
                .last_timestamp = bpf_ktime_get_ns(),
                .ttl_ns = expire_time - now,
                .state = CT_ESTABLISHED,
                .flags = CT_FLAG_NONE,
                .rx_packets = 1,
                .tx_packets = 0,
            };
            bpf_map_update_elem(&conn_track, &ct_key, &new_val, BPF_ANY);
            return XDP_PASS;
        }
    }
    if (sd_val) {
        __u64 expire_time = sd_val->expire_time;
        if (expire_time < now) {
            bpf_map_delete_elem(&sdwhitelist, &sdkey);
            return XDP_DROP;
        }
        if (sd_val->allowed == 1) {
            submit_event(ctx, 1, iph->saddr, iph->daddr, ct_key.sport, ct_key.dport, iph->protocol, iph->tot_len);
            struct conn_value new_val = {
                .timestamp = bpf_ktime_get_ns(),
                .last_timestamp = bpf_ktime_get_ns(),
                .ttl_ns = sd_val->expire_time - now,
                .state = CT_ESTABLISHED,
                .flags = CT_FLAG_NONE,
                .rx_packets = 1,
                .tx_packets = 0,
            };
            bpf_map_update_elem(&conn_track, &ct_key, &new_val, BPF_ANY);
            return XDP_PASS;
        }
    }

    if (sp_val) {
        __u64 expire_time = sp_val->expire_time;
        if (expire_time < now) {
            bpf_map_delete_elem(&src_port, &spkey);
            return XDP_DROP;
        }
        if (sp_val->allowed == 1) {
            submit_event(ctx, 1, iph->saddr, iph->daddr, ct_key.sport, ct_key.dport, iph->protocol, iph->tot_len);
            struct conn_value new_val = {
                .timestamp = bpf_ktime_get_ns(),
                .last_timestamp = bpf_ktime_get_ns(),
                .ttl_ns = sp_val->expire_time - now,
                .state = CT_ESTABLISHED,
                .flags = CT_FLAG_NONE,
                .rx_packets = 1,
                .tx_packets = 0,
            };
            bpf_map_update_elem(&conn_track, &ct_key, &new_val, BPF_ANY);
            return XDP_PASS;
        }
    }

    if (pl_val) {
        __u64 expire_time = pl_val->expire_time;
        if (expire_time < now) {
            bpf_map_delete_elem(&port_list, &pl_key);
            return XDP_DROP;
        }
        if (pl_val->allowed == 1) {
            submit_event(ctx, 1, iph->saddr, iph->daddr, ct_key.sport, ct_key.dport, iph->protocol, iph->tot_len);
            struct conn_value new_val = {
                .timestamp = bpf_ktime_get_ns(),
                .last_timestamp = bpf_ktime_get_ns(),
                .ttl_ns = pl_val->expire_time - now,
                .state = CT_ESTABLISHED,
                .flags = CT_FLAG_NONE,
                .rx_packets = 1,
                .tx_packets = 0,
            };
            bpf_map_update_elem(&conn_track, &ct_key, &new_val, BPF_ANY);
            return XDP_PASS;
        }
    }
    if (pp_val) {
        __u64 expire_time = pp_val->expire_time;
        if (expire_time < now) {
            bpf_map_delete_elem(&protocol_port, &pp_key);
            return XDP_DROP;
        }
        if (pp_val->allowed == 1) {
            submit_event(ctx, 1, iph->saddr, iph->daddr, ct_key.sport, ct_key.dport, iph->protocol, iph->tot_len);
            struct conn_value new_val = {
                .timestamp = bpf_ktime_get_ns(),
                .last_timestamp = bpf_ktime_get_ns(),
                .ttl_ns = pp_val->expire_time - now,
                .state = CT_ESTABLISHED,
                .flags = CT_FLAG_NONE,
                .rx_packets = 1,
                .tx_packets = 0,
            };
            bpf_map_update_elem(&conn_track, &ct_key, &new_val, BPF_ANY);
            return XDP_PASS;
        }
    }
    // No rule matched → fail CLOSED. NOT rate-limited (#2849): a no-match DROP is
    // an unauthorized-access audit signal, not a malformed-packet flood, and
    // dropping it would lose security visibility + break parity with the
    // unconditional iptables [NHP-DENY] LOG rule (mirrors the v6 no-match site).
    submit_event(ctx, 0, iph->saddr, iph->daddr, ct_key.sport, ct_key.dport, iph->protocol, iph->tot_len);
    return XDP_DROP;
}

char _license[] SEC("license") = "Dual BSD/GPL";
