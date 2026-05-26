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
