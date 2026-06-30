package ac

import "testing"

// These tests run on every platform CI covers (no build tag): the match
// logic + backend selection are pure Go, so the netlink datapath's
// correctness-critical filtering is fenced without a kernel rig — the
// same testability split the eBPF side uses for
// enumerateConnTrackSrcPortsOnMap.

// mustFlowKey is shared with tokenstore_test.go (same signature) — reuse
// it rather than redeclare.

func mustCtTuple(t *testing.T, src, dst string, sport, dport uint16, proto uint8) ctTuple {
	t.Helper()
	s, err := parseIPTo16(src)
	if err != nil {
		t.Fatalf("parseIPTo16(%s): %v", src, err)
	}
	d, err := parseIPTo16(dst)
	if err != nil {
		t.Fatalf("parseIPTo16(%s): %v", dst, err)
	}
	return ctTuple{srcIP: s, dstIP: d, srcPort: sport, dstPort: dport, proto: proto}
}

func TestConntrackMatchSpec(t *testing.T) {
	tests := []struct {
		name        string
		key         FlowKey
		isV6        bool
		wantProto   uint8
		wantFilterP bool
		wantFilterD bool
	}{
		{"tcp-with-port", mustFlowKey(t, "1.2.3.4", "10.0.0.1", 443, FlowProtoTCP), false, 6, true, true},
		{"tcp-wildcard-port", mustFlowKey(t, "1.2.3.4", "10.0.0.1", 0, FlowProtoTCP), false, 6, true, false},
		{"udp-with-port", mustFlowKey(t, "1.2.3.4", "10.0.0.1", 53, FlowProtoUDP), false, 17, true, true},
		{"icmp-v4", mustFlowKey(t, "1.2.3.4", "10.0.0.1", 0, FlowProtoICMP), false, 1, true, false},
		{"icmp-v6", mustFlowKey(t, "2001:db8::1", "2001:db8::2", 0, FlowProtoICMP), true, 58, true, false},
		{"any", mustFlowKey(t, "1.2.3.4", "10.0.0.1", 0, FlowProtoAny), false, 0, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotProto, gotFilterP, gotFilterD := conntrackMatchSpec(tt.key, tt.isV6)
			if gotProto != tt.wantProto || gotFilterP != tt.wantFilterP || gotFilterD != tt.wantFilterD {
				t.Errorf("conntrackMatchSpec = (%d,%v,%v), want (%d,%v,%v)",
					gotProto, gotFilterP, gotFilterD, tt.wantProto, tt.wantFilterP, tt.wantFilterD)
			}
		})
	}
}

// TestCtTupleMatchesKey_SiblingSourcePorts is the core correctness fence:
// two established flows that share an allow-rule tuple but differ in
// source port (e.g. two clients behind one NAT) MUST BOTH match the
// FlowKey, since the allow-rule carries no source port. This mirrors the
// eBPF enumerate test's "both siblings enumerated" guarantee.
func TestCtTupleMatchesKey_SiblingSourcePorts(t *testing.T) {
	key := mustFlowKey(t, "1.2.3.4", "10.0.0.1", 443, FlowProtoTCP)
	sib1 := mustCtTuple(t, "1.2.3.4", "10.0.0.1", 51000, 443, 6)
	sib2 := mustCtTuple(t, "1.2.3.4", "10.0.0.1", 51001, 443, 6)
	if !sib1.matchesKey(key, false) || !sib2.matchesKey(key, false) {
		t.Errorf("both source-port siblings must match the allow-rule key: sib1=%v sib2=%v",
			sib1.matchesKey(key, false), sib2.matchesKey(key, false))
	}
}

func TestCtTupleMatchesKey(t *testing.T) {
	tcp443 := mustFlowKey(t, "1.2.3.4", "10.0.0.1", 443, FlowProtoTCP)
	tcpWild := mustFlowKey(t, "1.2.3.4", "10.0.0.1", 0, FlowProtoTCP)
	anyKey := mustFlowKey(t, "1.2.3.4", "10.0.0.1", 0, FlowProtoAny)
	v6key := mustFlowKey(t, "2001:db8::1", "2001:db8::2", 443, FlowProtoTCP)

	tests := []struct {
		name  string
		key   FlowKey
		isV6  bool
		tuple ctTuple
		want  bool
	}{
		{"tcp-match", tcp443, false, mustCtTuple(t, "1.2.3.4", "10.0.0.1", 5000, 443, 6), true},
		{"tcp-wrong-dport", tcp443, false, mustCtTuple(t, "1.2.3.4", "10.0.0.1", 5000, 80, 6), false},
		{"tcp-wrong-proto", tcp443, false, mustCtTuple(t, "1.2.3.4", "10.0.0.1", 5000, 443, 17), false},
		{"tcp-wrong-src", tcp443, false, mustCtTuple(t, "9.9.9.9", "10.0.0.1", 5000, 443, 6), false},
		{"tcp-wrong-dst", tcp443, false, mustCtTuple(t, "1.2.3.4", "10.9.9.9", 5000, 443, 6), false},
		{"wildcard-port-any-dport", tcpWild, false, mustCtTuple(t, "1.2.3.4", "10.0.0.1", 5000, 8080, 6), true},
		{"wildcard-port-still-checks-proto", tcpWild, false, mustCtTuple(t, "1.2.3.4", "10.0.0.1", 5000, 8080, 17), false},
		{"any-matches-any-proto", anyKey, false, mustCtTuple(t, "1.2.3.4", "10.0.0.1", 5000, 12345, 17), true},
		{"any-matches-icmp", anyKey, false, mustCtTuple(t, "1.2.3.4", "10.0.0.1", 0, 0, 1), true},
		{"any-wrong-dst", anyKey, false, mustCtTuple(t, "1.2.3.4", "10.9.9.9", 5000, 12345, 17), false},
		{"v6-match", v6key, true, mustCtTuple(t, "2001:db8::1", "2001:db8::2", 5000, 443, 6), true},
		{"v6-wrong-dport", v6key, true, mustCtTuple(t, "2001:db8::1", "2001:db8::2", 5000, 80, 6), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.tuple.matchesKey(tt.key, tt.isV6); got != tt.want {
				t.Errorf("matchesKey = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseConntrackBackend(t *testing.T) {
	tests := []struct {
		in      string
		want    ConntrackBackend
		wantOK  bool
		wantStr string
	}{
		{"", BackendExec, true, "exec"},
		{"exec", BackendExec, true, "exec"},
		{"netlink", BackendNetlink, true, "netlink"},
		{"bogus", BackendExec, false, "exec"},
		{"NETLINK", BackendExec, false, "exec"}, // case-sensitive on purpose
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, ok := ParseConntrackBackend(tt.in)
			if got != tt.want || ok != tt.wantOK {
				t.Errorf("ParseConntrackBackend(%q) = (%v,%v), want (%v,%v)", tt.in, got, ok, tt.want, tt.wantOK)
			}
			if got.String() != tt.wantStr {
				t.Errorf("ParseConntrackBackend(%q).String() = %q, want %q", tt.in, got.String(), tt.wantStr)
			}
		})
	}
}

func TestResolveConntrackFlusherConfig(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		cfg := resolveConntrackFlusherConfig()
		if cfg.backend != BackendExec || cfg.poolSize != defaultConntrackNetlinkPoolSize {
			t.Errorf("defaults = (%v,%d), want (exec,%d)", cfg.backend, cfg.poolSize, defaultConntrackNetlinkPoolSize)
		}
	})
	t.Run("with-backend-and-pool", func(t *testing.T) {
		cfg := resolveConntrackFlusherConfig(WithBackend(BackendNetlink), WithNetlinkPoolSize(4))
		if cfg.backend != BackendNetlink || cfg.poolSize != 4 {
			t.Errorf("= (%v,%d), want (netlink,4)", cfg.backend, cfg.poolSize)
		}
	})
	t.Run("pool-size-clamped", func(t *testing.T) {
		cfg := resolveConntrackFlusherConfig(WithNetlinkPoolSize(0))
		if cfg.poolSize != defaultConntrackNetlinkPoolSize {
			t.Errorf("poolSize for 0 = %d, want default %d", cfg.poolSize, defaultConntrackNetlinkPoolSize)
		}
	})
}

func TestNormalizeConntrackPoolSize(t *testing.T) {
	tests := []struct {
		in   int
		want int
	}{
		{0, defaultConntrackNetlinkPoolSize},
		{-5, defaultConntrackNetlinkPoolSize},
		{1, 1},
		{16, 16},
		{maxConntrackNetlinkPoolSize, maxConntrackNetlinkPoolSize},
		{maxConntrackNetlinkPoolSize + 1, maxConntrackNetlinkPoolSize},
		{1_000_000, maxConntrackNetlinkPoolSize}, // typo guard: don't exhaust fds
	}
	for _, tt := range tests {
		if got := normalizeConntrackPoolSize(tt.in); got != tt.want {
			t.Errorf("normalizeConntrackPoolSize(%d) = %d, want %d", tt.in, got, tt.want)
		}
	}
}
