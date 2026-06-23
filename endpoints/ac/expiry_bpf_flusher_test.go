//go:build linux

package ac

import (
	"context"
	"testing"
)

// TestIsIPv4Mapped fences the IPv4 detection used to short-circuit
// BpfFlusher on non-IPv4 keys (the eBPF maps are IPv4-only).
func TestIsIPv4Mapped(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"v4-via-string", "192.0.2.1", true},
		{"v4-mapped-explicit", "::ffff:192.0.2.1", true},
		{"v6-loopback", "::1", false},
		{"v6-doc-prefix", "2001:db8::1", false},
		{"v4-broadcast", "192.0.2.255", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			k, err := MakeFlowKey(c.in, "192.0.2.2", 443, FlowProtoTCP)
			if err != nil {
				t.Fatal(err)
			}
			got := isIPv4Mapped(k.SrcIP)
			if got != c.want {
				t.Errorf("isIPv4Mapped(%s) = %v want %v (bytes=%v)", c.in, got, c.want, k.SrcIP)
			}
		})
	}
}

// TestBpfFlusher_NonIPv4_NoOp fences the early return on non-IPv4
// keys — should NOT propagate to the underlying map (which would
// fail with an unhelpful error and ping the breaker).
//
// Cr round 4 finding 1 added the SkippedCount counter so a
// regression scheduling v6 keys under EBPFXDP becomes visible;
// this test also fences the counter increments alongside the
// no-op behavior.
func TestBpfFlusher_NonIPv4_NoOp(t *testing.T) {
	f := &BpfFlusher{}
	k, err := MakeFlowKey("2001:db8::1", "2001:db8::2", 443, FlowProtoTCP)
	if err != nil {
		t.Fatal(err)
	}
	// On a v6 key the flusher should return nil without ever
	// attempting LoadPinnedMap (which would fail with EACCES /
	// ENOENT in test environments without the BPF program loaded).
	// context.Background() — never pass nil ctx even when the
	// short-circuit doesn't read it
	if err := f.Flush(context.Background(), k); err != nil {
		t.Errorf("BpfFlusher.Flush on v6 key: got err %v, want nil (should short-circuit)", err)
	}
	if got := f.SkippedCount(); got != 1 {
		t.Errorf("SkippedCount after 1 v6 Flush: got %d want 1", got)
	}
	// Second call increments.
	_ = f.Flush(context.Background(), k)
	if got := f.SkippedCount(); got != 2 {
		t.Errorf("SkippedCount after 2 v6 Flushes: got %d want 2", got)
	}
}

// TestBpfFlusher_FlushConn_NonIPv4_NoOp mirrors the allow-rule
// short-circuit for the P4c surgical conntrack path: a v6 ConnFlowKey must
// return nil and bump the skip counter WITHOUT attempting LoadPinnedMap
// (the conntrack map is IPv4-only, struct ipv4_ct_tuple). These assertions
// run on any Linux host because the guard returns before any kernel call.
func TestBpfFlusher_FlushConn_NonIPv4_NoOp(t *testing.T) {
	f := &BpfFlusher{}
	k, err := MakeFlowKey("2001:db8::1", "2001:db8::2", 443, FlowProtoTCP)
	if err != nil {
		t.Fatal(err)
	}
	conn := ConnFlowKey{Flow: k, SrcPort: 43210}
	if err := f.FlushConn(context.Background(), conn); err != nil {
		t.Errorf("FlushConn on v6 key: got err %v, want nil (should short-circuit before LoadPinnedMap)", err)
	}
	if got := f.SkippedCount(); got != 1 {
		t.Errorf("SkippedCount after 1 v6 FlushConn: got %d want 1", got)
	}
}

// TestBpfFlusher_FlushConn_NonConnProto_Errors fences the protocol guard:
// ICMP and "any" allow-rules create NO conntrack entry in the XDP program
// (the established-flow short-circuit is port-keyed), so calling FlushConn
// for them is a caller bug and must surface an error rather than silently
// no-op. The guard runs before LoadPinnedMap, so this is host-independent.
func TestBpfFlusher_FlushConn_NonConnProto_Errors(t *testing.T) {
	f := &BpfFlusher{}
	for _, proto := range []FlowProto{FlowProtoICMP, FlowProtoAny} {
		k, err := MakeFlowKey("192.0.2.1", "192.0.2.2", 0, proto)
		if err != nil {
			t.Fatal(err)
		}
		conn := ConnFlowKey{Flow: k, SrcPort: 43210}
		if err := f.FlushConn(context.Background(), conn); err == nil {
			t.Errorf("FlushConn with protocol %s: got nil, want error (no conntrack entry exists for it)", proto)
		}
	}
	// A non-IPv4 key takes the skip branch BEFORE the protocol switch, so
	// the protocol-guard cases above (all IPv4) must NOT have bumped the
	// skip counter.
	if got := f.SkippedCount(); got != 0 {
		t.Errorf("SkippedCount after protocol-guard cases: got %d want 0 (these are IPv4 keys; the protocol error path must not touch the v6 skip counter)", got)
	}
}

// TestBpfFlusher_FlushConn_CanceledCtx fences the ctx-honoring contract:
// a canceled context short-circuits before any kernel call, symmetric to
// Flush. Without this, a Shutdown-mid-revoke could still issue a map op.
func TestBpfFlusher_FlushConn_CanceledCtx(t *testing.T) {
	f := &BpfFlusher{}
	k, err := MakeFlowKey("192.0.2.1", "192.0.2.2", 443, FlowProtoTCP)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := f.FlushConn(ctx, ConnFlowKey{Flow: k, SrcPort: 43210}); err == nil {
		t.Error("FlushConn with canceled ctx: got nil, want ctx error (must short-circuit before LoadPinnedMap)")
	}
}

// TestConnFlowKey_String fences the log rendering — a ConnFlowKey in logs
// must show the source-port discriminator (the thing that distinguishes
// it from the coarse allow-rule FlowKey), so a revoke-path log line is
// actionable when diagnosing whether the right flow was targeted.
func TestConnFlowKey_String(t *testing.T) {
	k, err := MakeFlowKey("198.51.100.7", "203.0.113.10", 443, FlowProtoTCP)
	if err != nil {
		t.Fatal(err)
	}
	got := ConnFlowKey{Flow: k, SrcPort: 43210}.String()
	want := "198.51.100.7:43210→203.0.113.10:443/tcp"
	if got != want {
		t.Errorf("ConnFlowKey.String() = %q, want %q", got, want)
	}
}
