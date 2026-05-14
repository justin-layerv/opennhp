package server

import (
	"net"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/nhp/core"
)

// Regression fence for #1157 F3 reliability angle.
//
// Pre-fix, HandleACOnline matched existing connections by IP. A
// same-pubkey reconnect from a NEW (IP, port) — NAT rebind, EIP swap,
// AC daemon restart, server-driven peer redispatch — appended a new
// slot instead of replacing the existing one. Under blue/green AC
// churn this filled the slice past MaxACConnsPerID with stale entries
// from already-reconnected AC instances; the FIFO branch then evicted
// a DIFFERENT pubkey's last slot, silently de-listing a live AC
// instance from AOP broadcast while the NLB target group still routed
// client traffic to it → iptables drop → 10s client timeout.
//
// Post-fix the admit policy is pubkey-keyed and lives in
// replaceOrAppendACConn. These tests exercise the helper directly.

func makeACConnFixture(pubkeyB64, ip string, port int) *ACConn {
	addr := &net.UDPAddr{IP: net.ParseIP(ip), Port: port}
	peer := &core.UdpPeer{
		Hostname:     "test-ac",
		Ip:           ip,
		Port:         port,
		PubKeyBase64: pubkeyB64,
		Type:         core.NHP_AC,
	}
	peer.UpdateRecv(time.Now().UnixNano(), addr)
	return &ACConn{
		ConnData: &core.ConnectionData{RemoteAddr: addr},
		ACPeer:   peer,
		ACId:     "test-ac",
	}
}

// buildSaturatedACConnSlice fills a []*ACConn at MaxACConnsPerID with
// distinct pubkeys (seed byte i+1) and distinct IPs (10.0.0.<i+1>).
// Skips the test if the cap is outside the fixture's supported range
// (rotation-shift assertions need cap >= 2; outsider-seed reservation
// caps the upper bound — see outsiderPubkeySeed below).
//
// outsiderPubkeySeed (0xFE) is reserved across the package as the
// "brand-new arrival" seed in distinct-pubkey overflow tests. To keep
// the outsider truly distinct from every saturated entry, the loop
// below emits seeds 1..MaxACConnsPerID and we skip when the cap would
// collide with the reserved seed. Today's cap of 10 is far from this
// boundary; the guard is a future-proofing fence.
const outsiderPubkeySeed = byte(0xFE)

func buildSaturatedACConnSlice(t *testing.T) []*ACConn {
	t.Helper()
	if MaxACConnsPerID >= int(outsiderPubkeySeed) {
		t.Skipf("test fixture seed is single-byte and reserves 0x%02x as the outsider seed; MaxACConnsPerID=%d collides with the saturated range", outsiderPubkeySeed, MaxACConnsPerID)
	}
	if MaxACConnsPerID < 2 {
		t.Skipf("test fixture assumes at least 2 distinct-pubkey slots; MaxACConnsPerID=%d", MaxACConnsPerID)
	}
	out := make([]*ACConn, MaxACConnsPerID)
	for i := 0; i < MaxACConnsPerID; i++ {
		out[i] = makeACConnFixture(testPubkeyB64(byte(i+1)), "10.0.0."+strconv.Itoa(i+1), 47051)
	}
	return out
}

// Pin the contract for the precondition-violating empty-pubkey
// case. Production never reaches here (AAK signature verification
// upstream rejects empty pubkeys), but the helper's observable
// behavior under a test caller that violates the precondition is
// fenced here so a future "loosen the contract" change has to
// update this test. See the godoc on replaceOrAppendACConn for
// the design decision and the two rejected defensive options.
//
// Current behavior: empty pubkey is treated identically to any
// other pubkey — match loop finds no match (no existing slot has
// an empty pubkey and passes the four-field nil-skip), FIFO
// doesn't fire (under cap), helper appends. The new slot carries
// the empty pubkey value, which downstream F3 distinct-count
// logic would see as "the empty string" — observable, not silent.
func TestReplaceOrAppendACConn_EmptyPubkeyIncoming_AppendsAsNormalSlot(t *testing.T) {
	incoming := makeACConnFixture("", "10.0.0.1", 47051)

	out, replaced, stale := replaceOrAppendACConn(nil, incoming)

	if replaced {
		t.Errorf("empty-pubkey incoming on empty existing should not match anything; got replaced=true")
	}
	if stale != nil {
		t.Errorf("empty-pubkey incoming on empty existing should have no stale; got %v", stale)
	}
	if len(out) != 1 || out[0] != incoming {
		t.Fatalf("expected out=[incoming]; got len=%d out[0]==incoming=%v", len(out), len(out) > 0 && out[0] == incoming)
	}
	// The new slot carries the empty pubkey value — that's the
	// invariant-violating shape downstream consumers (F3 cap-gate,
	// log lines) will see. Asserting it here makes the
	// precondition-violation contract observable.
	if got := out[0].ACPeer.PubKeyBase64; got != "" {
		t.Errorf("appended slot pubkey = %q; want empty (helper does not mask the precondition violation)", got)
	}
}

// First-ever AC registration for an acId: existing is empty, no
// match, no FIFO (under cap), helper just appends. Pins the
// entry-point shape — wrapper tests exercise this transitively
// but no helper-level test fences it directly.
func TestReplaceOrAppendACConn_EmptySlice_AppendsCleanly(t *testing.T) {
	pk := testPubkeyB64(0x01)
	incoming := makeACConnFixture(pk, "10.0.0.1", 47051)

	out, replaced, stale := replaceOrAppendACConn(nil, incoming)

	if replaced {
		t.Errorf("empty slice should not produce a replace; got replaced=true")
	}
	if stale != nil {
		t.Errorf("empty slice has nothing to evict; got stale=%v", stale)
	}
	if len(out) != 1 || out[0] != incoming {
		t.Fatalf("expected out=[incoming], got len=%d, out[0]==incoming=%v", len(out), len(out) > 0 && out[0] == incoming)
	}
}

// Primary fix: same-pubkey reconnect from a new IP must replace in
// place, not append.
func TestReplaceOrAppendACConn_SamePubkeyNewIP_ReplacesInPlace(t *testing.T) {
	pk := testPubkeyB64(0x01)
	old := makeACConnFixture(pk, "10.0.0.1", 47051)
	incoming := makeACConnFixture(pk, "10.0.0.2", 38229)

	out, replaced, stale := replaceOrAppendACConn([]*ACConn{old}, incoming)

	if !replaced {
		t.Fatal("same-pubkey reconnect appended instead of replacing — #1157 F3 reliability regression")
	}
	if len(out) != 1 || out[0] != incoming {
		t.Fatalf("expected single slot holding incoming; got len=%d out[0]==incoming=%v", len(out), out[0] == incoming)
	}
	if stale != old {
		t.Errorf("stale must be the displaced connection; got %v", stale)
	}
}

// Defensive nil-skip matches extractPubkeysFromConns (same slice,
// shared invariant). Guards against a future writer that nils slots
// before compaction — a nil deref in the AOL hot path would otherwise
// crash the server.
func TestReplaceOrAppendACConn_NilEntries_AreSkipped(t *testing.T) {
	pk := testPubkeyB64(0x03)
	existing := []*ACConn{
		nil,
		{ACPeer: nil},
		{ACPeer: &core.UdpPeer{PubKeyBase64: pk}, ConnData: nil}, // partial: ConnData nil
		makeACConnFixture(pk, "10.0.0.1", 47051),
	}
	incoming := makeACConnFixture(pk, "10.0.0.1", 47052)

	out, replaced, _ := replaceOrAppendACConn(existing, incoming)

	if !replaced {
		t.Fatal("loop did not match through nil/partial entries (must skip, not stop)")
	}
	if len(out) != 4 {
		t.Fatalf("expected len=4 (nil/partial entries preserved); got %d", len(out))
	}
	if out[3] != incoming {
		t.Fatal("incoming should have replaced the fourth slot")
	}
}

// Same-pubkey same-address (AC re-sent NHP_AOL on the same socket):
// in-place replace happens but no stale to clean up. Guards against a
// future edit that conflates "replace" with "always tear down". Also
// pins the *full struct* overwrite: incoming's ServiceId / Apps /
// ACCipherScheme replace the old slot's values (license rotation or
// plugin-list update on re-register sticks immediately), unlike the
// legacy "same IP, new port" branch which preserved the existing
// struct.
func TestReplaceOrAppendACConn_SamePubkeySameAddr_NoStale(t *testing.T) {
	pk := testPubkeyB64(0x02)
	old := makeACConnFixture(pk, "10.0.0.1", 47051)
	old.ServiceId = "svc-old"
	old.Apps = []string{"app-old"}
	incoming := makeACConnFixture(pk, "10.0.0.1", 47051)
	incoming.ServiceId = "svc-new"
	incoming.Apps = []string{"app-new"}

	out, replaced, stale := replaceOrAppendACConn([]*ACConn{old}, incoming)

	if !replaced || len(out) != 1 {
		t.Fatalf("expected in-place replace, got replaced=%v len=%d", replaced, len(out))
	}
	if stale != nil {
		t.Errorf("stale must be nil when address is unchanged; got %v", stale)
	}
	// Pointer identity proves the full ACConn struct was overwritten,
	// not just selected fields — a future refactor that copied only
	// the ConnData pointer (preserving the old ServiceId / Apps) would
	// stick on the old license/plugin state and is the kind of subtle
	// regression a license-rotation rollout would surface late.
	if out[0] != incoming {
		t.Errorf("slot[0] should be the incoming ACConn pointer; got pointer-different ACConn")
	}
	if got := out[0].ServiceId; got != "svc-new" {
		t.Errorf("ServiceId after replace = %q; want %q (full-struct overwrite)", got, "svc-new")
	}
}

// Security half: a different pubkey arriving from the same IP must
// append, not replace. F3 is the only thing that admits or rejects a
// new pubkey.
func TestReplaceOrAppendACConn_DifferentPubkeySameIP_Appends(t *testing.T) {
	pkA := testPubkeyB64(0xAA)
	pkB := testPubkeyB64(0xBB)
	existing := []*ACConn{makeACConnFixture(pkA, "10.0.0.1", 47051)}
	incoming := makeACConnFixture(pkB, "10.0.0.1", 47052)

	out, replaced, stale := replaceOrAppendACConn(existing, incoming)

	if replaced {
		t.Fatal("different-pubkey arrival replaced legitimate slot")
	}
	if len(out) != 2 || stale != nil {
		t.Fatalf("expected append + nil stale; got len=%d stale=%v", len(out), stale)
	}
}

// Load-bearing reliability assertion: at MaxACConnsPerID distinct
// pubkeys, a same-pubkey reconnect must not displace another AC.
// Pre-fix the IP-based loop missed the match, the slice grew, FIFO
// fired, and a DIFFERENT pubkey lost its slot.
func TestReplaceOrAppendACConn_SamePubkeyReconnect_AtCap_DoesNotEvictOthers(t *testing.T) {
	existing := buildSaturatedACConnSlice(t)
	originals := slices.Clone(existing) // snapshot for post-call identity check
	incoming := makeACConnFixture(existing[0].ACPeer.PubKeyBase64, "10.0.99.1", 38229)

	out, replaced, stale := replaceOrAppendACConn(existing, incoming)

	if !replaced {
		t.Fatal("same-pubkey reconnect failed to match — would have appended and tripped FIFO eviction (#1157 F3 reliability bug)")
	}
	// stale must point at the displaced (old) ACConn so the caller
	// can close the old socket. A regression where the helper
	// dropped this reference would silently leak the old UdpConn
	// in remoteConnectionMap on every NAT-rebind / EIP-swap; pin
	// pointer identity here so a future edit that broadens the
	// match but forgets to return the old conn fails fast.
	if stale != originals[0] {
		t.Errorf("stale must point at the displaced conn (originals[0]); got %v — old socket would not be closed", stale)
	}
	if len(out) != MaxACConnsPerID {
		t.Fatalf("slice size = %d; want %d (no AC should have been displaced)", len(out), MaxACConnsPerID)
	}
	for i := 1; i < MaxACConnsPerID; i++ {
		if out[i] != originals[i] {
			t.Errorf("slot %d changed: legitimate AC was evicted by FIFO under same-pubkey reconnect", i)
		}
	}
	if got := out[0].ConnData.RemoteAddr.String(); got != "10.0.99.1:38229" {
		t.Errorf("slot 0 address = %s, want 10.0.99.1:38229", got)
	}
}

// FIFO backstop fires only on distinct-pubkey overflow. With cap-1
// distinct pubkeys present, a new (different) pubkey evicts the
// oldest and appends.
func TestReplaceOrAppendACConn_DistinctPubkeyOverflow_FIFOEvicts(t *testing.T) {
	existing := buildSaturatedACConnSlice(t)
	originals := slices.Clone(existing) // snapshot for post-shift identity check
	expectedEvictee := existing[0]
	incoming := makeACConnFixture(testPubkeyB64(outsiderPubkeySeed), "10.0.0.99", 47051)

	out, replaced, stale := replaceOrAppendACConn(existing, incoming)

	if replaced {
		t.Fatal("distinct-pubkey overflow took the replacement branch; FIFO should have fired")
	}
	if stale != expectedEvictee {
		gotPK, wantPK := "<nil>", expectedEvictee.ACPeer.PubKeyBase64
		if stale != nil {
			gotPK = stale.ACPeer.PubKeyBase64
		}
		t.Errorf("FIFO evicted wrong entry: got pubkey prefix %.8q, want oldest prefix %.8q", gotPK, wantPK)
	}
	if len(out) != MaxACConnsPerID || out[MaxACConnsPerID-1] != incoming {
		t.Errorf("incoming should be appended at end after FIFO eviction; got len=%d", len(out))
	}
	// Surviving slots must be the originals shifted down by one. Catches
	// a regression that evicts the right entry but swaps any of the
	// surviving slots during the shift.
	for i := 0; i < MaxACConnsPerID-1; i++ {
		if out[i] != originals[i+1] {
			t.Errorf("post-FIFO slot %d holds the wrong original; got pubkey prefix %.8q, want %.8q",
				i, out[i].ACPeer.PubKeyBase64, originals[i+1].ACPeer.PubKeyBase64)
		}
	}
}

// FIFO defense-in-depth: if slot 0 is a partial entry (a future
// invariant break — production never inserts them today), the
// FIFO branch must skip past it and evict the next non-partial
// slot, not crash on stale.ACPeer.PubKeyBase64 inside the
// connection-map lock. Without this guard a single corrupted
// slot would DoS the server on the next overflow.
func TestReplaceOrAppendACConn_FIFOWithPartialSlot0_SkipsToNextRealVictim(t *testing.T) {
	saturated := buildSaturatedACConnSlice(t)
	// Replace slot 0 with a partial entry (ConnData nil). Real
	// slot[1] is now the oldest non-partial entry.
	saturated[0] = &ACConn{ACPeer: &core.UdpPeer{PubKeyBase64: testPubkeyB64(0x01)}}
	expectedEvictee := saturated[1]
	incoming := makeACConnFixture(testPubkeyB64(outsiderPubkeySeed), "10.0.0.99", 47051)

	out, replaced, stale := replaceOrAppendACConn(saturated, incoming)

	if replaced {
		t.Fatal("distinct-pubkey overflow took the replacement branch")
	}
	if stale != expectedEvictee {
		gotPK := "<nil>"
		if stale != nil && stale.ACPeer != nil {
			gotPK = stale.ACPeer.PubKeyBase64
		}
		t.Errorf("FIFO evicted wrong entry: got pubkey prefix %.8q, want oldest non-partial prefix %.8q", gotPK, expectedEvictee.ACPeer.PubKeyBase64)
	}
	// Returned slice should have the partial slot still at index 0
	// (FIFO only evicted the first real entry) and the incoming
	// appended at the end. Length is one less than pre-call (one
	// real entry removed) + one appended → same length.
	if len(out) != MaxACConnsPerID {
		t.Fatalf("slice length = %d, want %d", len(out), MaxACConnsPerID)
	}
	if out[0] == nil || out[0].ACPeer == nil || out[0].ACPeer.PubKeyBase64 != testPubkeyB64(0x01) {
		t.Error("partial slot at index 0 was not preserved across FIFO eviction")
	}
	if out[len(out)-1] != incoming {
		t.Error("incoming should be appended at the end")
	}
}

// Permit-mode behavior shift for the same-IP in-place key rotation
// corner under distinct-pubkey saturation: pre-fix IP-keyed match
// would have replaced the same-IP slot in place; post-fix pubkey-keyed
// admit falls through to FIFO and evicts the oldest distinct-pubkey
// slot, leaving the rotated-IP slot intact. Pin so a future tradeoff
// revisit sees both halves; cross-references the F3 strict-mode
// kernel counterpart TestVerifyACPubkeyCap_SameIPKeyRotation_UnderSaturation_Exceeded.
func TestReplaceOrAppendACConn_SameIPKeyRotation_UnderSaturation_FIFOEvicts(t *testing.T) {
	existing := buildSaturatedACConnSlice(t)
	expectedEvictee := existing[0]
	rotatedAtSlot := MaxACConnsPerID / 2
	preservedSlot := existing[rotatedAtSlot] // capture before mutation; FIFO shifts indices
	incoming := makeACConnFixture(testPubkeyB64(outsiderPubkeySeed), preservedSlot.ConnData.RemoteAddr.IP.String(), 47051)

	out, replaced, stale := replaceOrAppendACConn(existing, incoming)

	if replaced {
		t.Fatal("same-IP-new-pubkey took the replacement branch; pubkey-keyed admit must NOT replace by IP")
	}
	if stale != expectedEvictee {
		gotPK, wantPK := "<nil>", expectedEvictee.ACPeer.PubKeyBase64
		if stale != nil {
			gotPK = stale.ACPeer.PubKeyBase64
		}
		t.Errorf("FIFO evicted wrong entry: got pubkey prefix %.8q, want oldest prefix %.8q", gotPK, wantPK)
	}
	// FIFO shifted indices down by 1; the IP-rotation slot moved
	// from rotatedAtSlot to rotatedAtSlot-1. Pointer identity check
	// catches both overwrite-with-same-pubkey-different-pointer and
	// eviction-of-the-wrong-slot regressions.
	if out[rotatedAtSlot-1] != preservedSlot {
		t.Errorf("same-IP slot was overwritten or evicted; pubkey-keyed admit should have preserved it")
	}
}
