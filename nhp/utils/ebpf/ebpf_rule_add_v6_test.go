package ebpf

import (
	"testing"
)

// This file is the cross-platform (no kernel, no /sys/fs/bpf) proof for E2
// slice 4's FAMILY DETECTION. It fences the routing decision EbpfRuleAdd makes
// before it ever touches a pinned map — the part that decides whether an
// admission lands in the v4 maps or the `*_v6` maps. The real-map "right key
// lands in the right v6 map" semantic proof lives in the linux-tagged
// ebpf_rule_add_v6_linux_test.go (runs under the eBPF datapath CI job).
//
// Why this layer matters: the detection predicate is the one place a v6
// admission can be silently misrouted to a v4 map (key rejected / wrong family)
// or a v4/address-less admission misrouted to a non-existent v6 map. Both are
// fail-OPEN admission gaps, so the predicate is pinned exhaustively here,
// including the two adversarial inputs the shorthand `To4()==nil` gets wrong.

// TestIsIPv6Src_DispatchTable is the load-bearing routing fence. Each case is an
// admission source-address string and the family the dispatcher MUST pick.
func TestIsIPv6Src_DispatchTable(t *testing.T) {
	cases := []struct {
		name   string
		srcIP  string
		wantV6 bool
		why    string
	}{
		{
			name:   "plain_ipv6",
			srcIP:  "2001:db8::7",
			wantV6: true,
			why:    "a real global IPv6 address must route to the *_v6 maps",
		},
		{
			name:   "ipv6_loopback",
			srcIP:  "::1",
			wantV6: true,
			why:    "IPv6 loopback is still IPv6",
		},
		{
			name:   "plain_ipv4",
			srcIP:  "10.0.0.1",
			wantV6: false,
			why:    "a dotted-quad IPv4 address must stay on the v4 maps",
		},
		{
			name:   "empty_srcip_maptype6",
			srcIP:  "",
			wantV6: false,
			why: "MapTypeProtocolPort (6) admissions carry NO SrcIP (the map is " +
				"address-less and shared v4/v6). net.ParseIP(\"\") is nil and " +
				"nil.To4() is also nil, so a bare To4()==nil check would wrongly " +
				"classify this as IPv6 and route it to a non-existent v6 " +
				"protocol_port map — breaking every v4 temp-port admission. The " +
				"ip!=nil guard keeps empty SrcIP on the v4 path.",
		},
		{
			name:   "ipv4_mapped_ipv6",
			srcIP:  "::ffff:192.0.2.1",
			wantV6: false,
			why: "an IPv4-mapped IPv6 address has a non-nil To4(), so it routes " +
				"v4 — consistent with parseIP6, which REJECTS ::ffff:a.b.c.d. " +
				"Routing it v6 would hand parseIP6 an address it rejects and the " +
				"admission would error instead of being enforced.",
		},
		{
			name:   "garbage",
			srcIP:  "not-an-ip",
			wantV6: false,
			why: "an unparseable string is net.ParseIP==nil → not v6 → stays on " +
				"the v4 path, where parseIP surfaces the invalid-address error " +
				"(rather than the v6 path swallowing it via a different branch)",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isIPv6Src(tc.srcIP); got != tc.wantV6 {
				t.Errorf("isIPv6Src(%q) = %v, want %v — %s", tc.srcIP, got, tc.wantV6, tc.why)
			}
		})
	}
}

// TestEbpfRuleAddV6_ProtocolPort_Rejected proves the defensive guard in the v6
// dispatcher: MapTypeProtocolPort (6) is address-less and shared v4/v6, so it
// has no `*_v6` map and must NEVER be handled by EbpfRuleAddV6. EbpfRuleAdd's
// isIPv6Src predicate keeps type-6 admissions (no SrcIP) on the v4 path, but if
// that invariant is ever violated the dispatcher must fail LOUD rather than
// silently no-op — a silent miss would be a fail-open admission gap. This needs
// no kernel: the type-6 arm returns its error before any map load.
func TestEbpfRuleAddV6_ProtocolPort_Rejected(t *testing.T) {
	// Even with a v6 SrcIP present, type 6 has no v6 map.
	err := EbpfRuleAddV6(MapTypeProtocolPort, EbpfRuleParams{
		SrcIP:    "2001:db8::7",
		Protocol: "tcp",
		DstPort:  443,
	}, 30)
	if err == nil {
		t.Fatal("EbpfRuleAddV6(MapTypeProtocolPort) = nil, want a loud error — protocol_port is address-less/shared and has no v6 map; a silent no-op here is a fail-open admission gap")
	}
}

// TestEbpfRuleAddV6_UnsupportedMapType_Rejected proves an out-of-range mapType
// errors rather than silently no-op'ing (mirrors EbpfRuleAdd's default arm).
// No kernel needed — the default arm returns before any map load.
func TestEbpfRuleAddV6_UnsupportedMapType_Rejected(t *testing.T) {
	err := EbpfRuleAddV6(999, EbpfRuleParams{SrcIP: "2001:db8::7"}, 30)
	if err == nil {
		t.Fatal("EbpfRuleAddV6(999) = nil, want an unsupported-map-type error")
	}
}

// TestEbpfRuleAddV6_UnsupportedProtocol_Rejected proves an unknown protocol
// string is rejected before any map load (mirrors EbpfRuleAdd). No kernel.
func TestEbpfRuleAddV6_UnsupportedProtocol_Rejected(t *testing.T) {
	err := EbpfRuleAddV6(MapTypeWhitelist, EbpfRuleParams{
		SrcIP:    "2001:db8::7",
		DstIP:    "2001:db8::10",
		Protocol: "sctp",
		DstPort:  443,
	}, 30)
	if err == nil {
		t.Fatal("EbpfRuleAddV6 with protocol=sctp = nil, want an unsupported-protocol error")
	}
}
