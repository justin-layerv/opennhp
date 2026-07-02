//go:build linux

package ebpf

import (
	"errors"
	"os"
	"testing"

	"github.com/cilium/ebpf"
)

// This file is the E2-slice-5 IPv6 surgical-revocation proof at the eBPF map-op
// layer — the v6 twin of conntrack_delete_linux_test.go. The ToCtKeyV6
// golden-byte layout is already fenced by TestConnTrackKeyV6_ToCtKeyV6_GoldenBytes
// in keys_v6_test.go and the connTrackKeyV6FromBytes round trip by
// TestConnTrackKeyV6_RoundTrip (conntrack_enumerate_v6_test.go, untagged); this
// file adds the SEMANTIC proof against a REAL in-kernel v6-conntrack-shaped map:
// deleting one flow's 5-tuple removes EXACTLY that flow and leaves a
// same-allow-rule-tuple sibling (different source port) alive.
//
// DEEPEST PROOF GAP (cannot be closed here): that deleting the conn_track_v6
// entry drops the next REAL v6 packet through the attached XDP program while the
// sibling keeps passing requires a live kernel + traffic — the #2779 kernel-rig
// responsibility. Map-op tests prove the delete targets exactly one flow.

// newTestConnTrackMapV6 creates a real in-kernel HASH map matching the v6
// conntrack key/value shape (KeySize = connTrackKeyV6Size). It delegates to
// newTestConnTrackMapSized (conntrack_delete_linux_test.go), which carries the
// single shared copy of the NHP_REQUIRE_BPF_TESTS loud-skip guard so the v4 and
// v6 acceptance gates can't drift. Returns (nil, false) to signal skip.
func newTestConnTrackMapV6(t *testing.T) (*ebpf.Map, bool) {
	t.Helper()
	return newTestConnTrackMapSized(t, "e2s5_ctv6_test", connTrackKeyV6Size)
}

func newTestFragStateMapV6(t *testing.T) (*ebpf.Map, bool) {
	t.Helper()
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "frag_state_v6_test",
		Type:       ebpf.Hash,
		KeySize:    ipv6FragKeySize,
		ValueSize:  ipv6FragValueSize,
		MaxEntries: 16,
	})
	if err != nil {
		if os.Getenv("NHP_REQUIRE_BPF_TESTS") == "1" {
			t.Fatalf("NHP_REQUIRE_BPF_TESTS=1 but BPF map creation failed — the frag_state_v6 revocation semantic proof cannot run on this runner. err=%v", err)
		}
		t.Skipf("cannot create BPF map on this host (need CAP_BPF / privileged kernel); skipping real-map frag_state_v6 revocation test. err=%v", err)
		return nil, false
	}
	return m, true
}

// TestConnTrackDeleteV6_Surgical_SiblingSurvives is the v6 semantic proof: in a
// REAL v6-conntrack-shaped map, deleting one flow's 5-tuple removes EXACTLY that
// flow and leaves a same-allow-rule-tuple sibling (different source port) alive.
// Asserts the target was genuinely present-then-absent, so a silent no-op cannot
// pass this test green.
func TestConnTrackDeleteV6_Surgical_SiblingSurvives(t *testing.T) {
	m, ok := newTestConnTrackMapV6(t)
	if !ok {
		return // skipped inside helper
	}
	defer func() { _ = m.Close() }()

	const (
		srcStr     = "2001:db8::7"  // shared client (one NAT)
		dstStr     = "2001:db8::10" // shared resource
		proto      = uint8(6)       // TCP
		dport      = uint16(443)    // shared destination port
		targetPort = uint16(43210)  // admission A
		siblingPrt = uint16(43211)  // admission B — same allow-rule tuple
	)
	src, err := parseIP6(srcStr)
	if err != nil {
		t.Fatalf("parseIP6(src): %v", err)
	}
	dst, err := parseIP6(dstStr)
	if err != nil {
		t.Fatalf("parseIP6(dst): %v", err)
	}

	mkKey := func(sport uint16) []byte {
		k := &connTrackKeyV6{DstIP: dst, SrcIP: src, DstPort: dport, SrcPort: sport, NextHdr: proto, Flags: ctDirIngress}
		return k.ToCtKeyV6()
	}
	zeroVal := make([]byte, ctValueSize)

	if err := m.Put(mkKey(targetPort), zeroVal); err != nil {
		t.Fatalf("put target flow: %v", err)
	}
	if err := m.Put(mkKey(siblingPrt), zeroVal); err != nil {
		t.Fatalf("put sibling flow: %v", err)
	}

	// Pre-condition: target present (so the delete is meaningful, not vacuous).
	out := make([]byte, ctValueSize)
	if err := m.Lookup(mkKey(targetPort), &out); err != nil {
		t.Fatalf("pre-delete: target flow should be present, got lookup err %v", err)
	}

	// Surgical delete of EXACTLY the target's 5-tuple via the production path.
	if err := delEbpfConnTrackOnMapV6(m, srcStr, dstStr, proto, targetPort, dport); err != nil {
		t.Fatalf("delEbpfConnTrackOnMapV6(target): %v", err)
	}

	// Assert 1: target GONE.
	if err := m.Lookup(mkKey(targetPort), &out); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Errorf("post-delete: target flow lookup err = %v, want ErrKeyNotExist (target was not actually deleted — a no-op would silently pass)", err)
	}
	// Assert 2: SIBLING survives (same allow-rule tuple, different source port).
	if err := m.Lookup(mkKey(siblingPrt), &out); err != nil {
		t.Errorf("post-delete: sibling flow lookup err = %v, want nil — surgical v6 revoke OVER-FLUSHED a same-tuple sibling from another admission", err)
	}
}

// TestConnTrackDeleteV6_Idempotent_NoEntry proves the breaker-safety contract:
// deleting a non-existent v6 conntrack entry returns nil (ENOENT → nil), so a
// revoke racing kernel GC or a duplicate revoke does not surface an error a
// future revocation breaker could trip on. Mirrors the v4 idempotency proof.
func TestConnTrackDeleteV6_Idempotent_NoEntry(t *testing.T) {
	m, ok := newTestConnTrackMapV6(t)
	if !ok {
		return
	}
	defer func() { _ = m.Close() }()

	if err := delEbpfConnTrackOnMapV6(m, "2001:db8::7", "2001:db8::10", 6, 43210, 443); err != nil {
		t.Errorf("delete of absent v6 conntrack entry = %v, want nil (idempotent ENOENT→nil)", err)
	}
}

func TestFragStateDeletePinnedV6_MissingPinIsTolerated(t *testing.T) {
	err := delEbpfFragStatePinnedForTupleV6("/sys/fs/bpf/nhp-test-missing-frag-state-v6", "2001:db8::7", "2001:db8::10", 6, 43210, 443)
	if err != nil {
		t.Fatalf("missing frag_state_v6 pin purge err = %v, want nil mixed-rollout tolerance", err)
	}
}

func TestFragStateDeleteV6_Surgical_AllTargetFragmentsRemoved(t *testing.T) {
	m, ok := newTestFragStateMapV6(t)
	if !ok {
		return
	}
	defer func() { _ = m.Close() }()

	const (
		srcStr     = "2001:db8::7"
		dstStr     = "2001:db8::10"
		proto      = uint8(6)
		dport      = uint16(443)
		targetPort = uint16(43210)
		siblingPrt = uint16(43211)
		otherDport = uint16(8443)
	)
	src, err := parseIP6(srcStr)
	if err != nil {
		t.Fatalf("parseIP6(src): %v", err)
	}
	dst, err := parseIP6(dstStr)
	if err != nil {
		t.Fatalf("parseIP6(dst): %v", err)
	}

	mkKey := func(srcIP, dstIP [16]byte, id uint32) []byte {
		return (&ipv6FragKey{SrcIP: srcIP, DstIP: dstIP, Identification: id, FragNextHdr: proto}).ToFragKey()
	}
	mkVal := func(sport, dstPort uint16) []byte {
		return (&ipv6FragValue{ExpireTime: 1 << 62, DstPort: dstPort, SrcPort: sport, L4Proto: proto}).ToFragValue()
	}
	targetA := mkKey(src, dst, 0x11111111)
	targetB := mkKey(src, dst, 0x22222222)
	targetReverse := mkKey(dst, src, 0x22222223)
	sibling := mkKey(src, dst, 0x33333333)
	otherPort := mkKey(src, dst, 0x44444444)

	if err := m.Put(targetA, mkVal(targetPort, dport)); err != nil {
		t.Fatalf("put targetA: %v", err)
	}
	if err := m.Put(targetB, mkVal(targetPort, dport)); err != nil {
		t.Fatalf("put targetB: %v", err)
	}
	if err := m.Put(targetReverse, mkVal(dport, targetPort)); err != nil {
		t.Fatalf("put reverse target: %v", err)
	}
	if err := m.Put(sibling, mkVal(siblingPrt, dport)); err != nil {
		t.Fatalf("put sibling: %v", err)
	}
	if err := m.Put(otherPort, mkVal(targetPort, otherDport)); err != nil {
		t.Fatalf("put other dport: %v", err)
	}

	if err := delEbpfFragStateForTupleOnMapV6(m, srcStr, dstStr, proto, targetPort, dport); err != nil {
		t.Fatalf("delEbpfFragStateForTupleOnMapV6(target): %v", err)
	}

	out := make([]byte, ipv6FragValueSize)
	if err := m.Lookup(targetA, &out); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Errorf("targetA lookup err = %v, want ErrKeyNotExist", err)
	}
	if err := m.Lookup(targetB, &out); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Errorf("targetB lookup err = %v, want ErrKeyNotExist", err)
	}
	if err := m.Lookup(targetReverse, &out); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Errorf("targetReverse lookup err = %v, want ErrKeyNotExist", err)
	}
	if err := m.Lookup(sibling, &out); err != nil {
		t.Errorf("sibling lookup err = %v, want nil — deleting one source port must not purge a same-allow-rule sibling", err)
	}
	if err := m.Lookup(otherPort, &out); err != nil {
		t.Errorf("other dport lookup err = %v, want nil — deleting one destination port must not purge another tuple", err)
	}
}

func TestFragStateDeleteV6_Batch_RemovesOnlyBatchSourcePorts(t *testing.T) {
	m, ok := newTestFragStateMapV6(t)
	if !ok {
		return
	}
	defer func() { _ = m.Close() }()

	const (
		srcStr      = "2001:db8::7"
		dstStr      = "2001:db8::10"
		proto       = uint8(6)
		dport       = uint16(443)
		targetPortA = uint16(43210)
		targetPortB = uint16(43211)
		siblingPrt  = uint16(43212)
	)
	src, err := parseIP6(srcStr)
	if err != nil {
		t.Fatalf("parseIP6(src): %v", err)
	}
	dst, err := parseIP6(dstStr)
	if err != nil {
		t.Fatalf("parseIP6(dst): %v", err)
	}

	mkKey := func(id uint32) []byte {
		return (&ipv6FragKey{SrcIP: src, DstIP: dst, Identification: id, FragNextHdr: proto}).ToFragKey()
	}
	mkVal := func(sport uint16) []byte {
		return (&ipv6FragValue{ExpireTime: 1 << 62, DstPort: dport, SrcPort: sport, L4Proto: proto}).ToFragValue()
	}
	targetA := mkKey(0x11111111)
	targetB := mkKey(0x22222222)
	sibling := mkKey(0x33333333)

	if err := m.Put(targetA, mkVal(targetPortA)); err != nil {
		t.Fatalf("put targetA: %v", err)
	}
	if err := m.Put(targetB, mkVal(targetPortB)); err != nil {
		t.Fatalf("put targetB: %v", err)
	}
	if err := m.Put(sibling, mkVal(siblingPrt)); err != nil {
		t.Fatalf("put sibling: %v", err)
	}

	if err := delEbpfFragStateForTuplesOnMapV6(m, srcStr, dstStr, proto, []uint16{targetPortA, targetPortB}, dport); err != nil {
		t.Fatalf("delEbpfFragStateForTuplesOnMapV6(batch): %v", err)
	}

	out := make([]byte, ipv6FragValueSize)
	if err := m.Lookup(targetA, &out); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Errorf("targetA lookup err = %v, want ErrKeyNotExist", err)
	}
	if err := m.Lookup(targetB, &out); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Errorf("targetB lookup err = %v, want ErrKeyNotExist", err)
	}
	if err := m.Lookup(sibling, &out); err != nil {
		t.Errorf("sibling lookup err = %v, want nil — batch delete must not purge source ports outside the revoked batch", err)
	}
}

func TestFragStateDeleteV6_Idempotent_NoEntry(t *testing.T) {
	m, ok := newTestFragStateMapV6(t)
	if !ok {
		return
	}
	defer func() { _ = m.Close() }()

	if err := delEbpfFragStateForTupleOnMapV6(m, "2001:db8::7", "2001:db8::10", 6, 43210, 443); err != nil {
		t.Errorf("delete of absent v6 fragment state = %v, want nil", err)
	}
}
