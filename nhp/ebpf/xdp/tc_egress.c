#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define TC_ACT_UNSPEC         (-1)
#define TC_ACT_OK               0
#define TC_ACT_SHOT             2
#define TC_ACT_STOLEN           4

#define ETH_P_IP    0x0800
#define ETH_P_IPV6  0x86DD
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IPPROTO_ICMP 1
#define KEY_EXPIRE_TIME_SECONDS 180 * 1000000000ULL
#define MAX_ENTRIES 1000000

struct whitelist_key {
    __be32 src_ip;
    __be32 dst_ip;
    __be16 dst_port;
    __u8 protocol;
} __attribute__((packed));

struct whitelist_value {
    __u8 allowed;
    __u64 expire_time;
};

// These two must match nhp_ebpf_xdp.c's whitelist_key/value byte-for-byte —
// spp is a shared LIBBPF_PIN_BY_NAME map, and the kernel rejects a second load
// whose key/value size disagrees with the already-pinned map. The sizes are
// asserted in both files (XDP: whitelist_key==11) so an independent struct edit
// here fails the eBPF compile instead of boot-failing the AC at load time.
_Static_assert(sizeof(struct whitelist_key) == 11,
               "whitelist_key must be exactly 11 bytes (packed) — must match nhp_ebpf_xdp.c");
_Static_assert(sizeof(struct whitelist_value) == 16,
               "whitelist_value must be exactly 16 bytes — must match nhp_ebpf_xdp.c");

// `spp` is the SAME pinned map as `spp` in nhp_ebpf_xdp.c — both declare
// LIBBPF_PIN_BY_NAME, so at load time they resolve to one kernel map at
// /sys/fs/bpf/spp. Its definition MUST match the XDP declaration byte-for-byte
// (type, key, value, max_entries) or the second object's LoadAndAssign fails
// with an incompatible-pinned-map error and the AC boot-fails under
// FilterMode=EBPFXDP. It MUST be BPF_MAP_TYPE_HASH, not LRU_HASH: #2163 flipped
// the XDP allow-rule maps HASH so a full map fails a NEW admission (-E2BIG)
// instead of silently evicting an EXISTING admitted session ("kill a random
// session"). That fix missed this duplicate here, which stayed LRU_HASH and
// crash-looped every AC once #2961 enabled eBPF filter mode in sandbox. The
// cross-object parity guard is TestSharedPinnedMaps_XdpTcParity in
// nhp/utils/ebpf/maptype_test.go. Rationale: docs/design/SESSION_ENFORCEMENT_ARCHITECTURE.md.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct whitelist_key);
    __type(value, struct whitelist_value);
    __uint(max_entries, MAX_ENTRIES);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} spp SEC(".maps");

SEC("tc/egress")
int tc_egress_prog(struct __sk_buff *ctx)
{

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;

    if (data + sizeof(*eth) > data_end)
        return TC_ACT_OK;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return TC_ACT_OK;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return TC_ACT_OK;

    if (iph->ihl < 5 || iph->version != 4)
        return TC_ACT_OK;

    __be32 src_ip = iph->saddr;
    __be32 dst_ip = iph->daddr;
    __u8 protocol = iph->protocol;

    __be16 sport = 0;

    if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)iph + (iph->ihl * 4);
        if ((void *)(tcp + 1) > data_end)
            return TC_ACT_OK;
        sport = tcp->source;
    } else if (protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)iph + (iph->ihl * 4);
        if ((void *)(udp + 1) > data_end)
            return TC_ACT_OK;
        sport = udp->source;
    } else if (protocol == IPPROTO_ICMP) {
        sport = 0;
    } else {
        return TC_ACT_OK;
    }

    struct whitelist_key spp_key = {
        .src_ip = dst_ip,
        .dst_ip = src_ip,
        .dst_port = sport,
        .protocol = protocol,
    };

    struct whitelist_value spp_value = {
        .allowed = 1,
        .expire_time = bpf_ktime_get_ns() + KEY_EXPIRE_TIME_SECONDS,
    };
    bpf_map_update_elem(&spp, &spp_key, &spp_value, BPF_ANY);

    return TC_ACT_OK;
}


char _license[] SEC("license") = "Dual BSD/GPL";
