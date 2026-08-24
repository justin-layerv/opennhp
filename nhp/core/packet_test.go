package core

import (
	"net/netip"
	"testing"
)

// TestPacketMinimalLengthPanicsAfterRelease fences the lifecycle
// constraint that motivated the fix in
// endpoints/server/udpserver.go recvPacketRoutine (PR #1115):
// ReleasePoolPacket nils pkt.Content, and Packet.MinimalLength reads
// &pkt.Content[0] via unsafe.Pointer. A second call inside log.Error
// AFTER the release panics with
//
//	runtime error: index out of range [0] with length 0
//
// and crashes the whole process. The public-facing NHP server accepts
// unauthenticated UDP, so any attacker sending a too-short datagram
// could trigger this panic -- a DoS vector, latent since the file was
// introduced 2024-09-03.
//
// Callers that need the length after a release MUST snapshot it
// BEFORE calling ReleasePoolPacket. If a future change adds
// nil-safety to MinimalLength and this test starts passing (no panic
// post-release), remove the caller-side snapshots — the constraint
// no longer holds.
func TestPacketMinimalLengthPanicsAfterRelease(t *testing.T) {
	pool := &PacketBufferPool{}
	pool.Init(PacketBufferPoolSize)
	device := &Device{pool: pool}

	pkt := device.AllocatePoolPacket()
	if pkt == nil {
		t.Fatal("AllocatePoolPacket returned nil from fresh pool")
	}

	// Pre-release: MinimalLength reads Content[0] cleanly.
	if got := pkt.MinimalLength(); got == 0 {
		t.Fatalf("pre-release MinimalLength = %d; want > 0", got)
	}
	pkt.HeaderType = NHP_KNK
	pkt.ReceivedAtNanos = 123
	pkt.ReceivedFrom = netip.MustParseAddrPort("192.0.2.10:62000")
	pkt.SendTo = netip.MustParseAddrPort("192.0.2.11:62206")

	device.ReleasePoolPacket(pkt)
	if pkt.Content != nil {
		t.Fatalf("ReleasePoolPacket should nil pkt.Content; got len=%d", len(pkt.Content))
	}
	if pkt.HeaderType != 0 {
		t.Fatalf("ReleasePoolPacket retained HeaderType %d", pkt.HeaderType)
	}
	if pkt.ReceivedAtNanos != 0 {
		t.Fatalf("ReleasePoolPacket retained receipt time %d", pkt.ReceivedAtNanos)
	}
	if pkt.ReceivedFrom.IsValid() || pkt.SendTo.IsValid() {
		t.Fatalf("ReleasePoolPacket retained transport metadata received=%v send=%v", pkt.ReceivedFrom, pkt.SendTo)
	}

	// Post-release: MinimalLength must panic. A caller that silently
	// succeeds here would be dereferencing freed memory semantics.
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic calling MinimalLength on released packet; " +
				"this test's purpose is to enforce the lifecycle constraint. " +
				"If MinimalLength is now nil-safe, update all recvPacketRoutine " +
				"callers (server, AC, agent, DB) to drop the pre-release " +
				"snapshot and delete this test.")
		}
	}()
	_ = pkt.MinimalLength()
}

// TestNHPRevHeaderType_ACReachability is the wire-reachability proof for the
// qURL v2 revocation push (P4e). The AC's handler unit tests
// (revocation_msghandler_test.go) call HandleUdpACRevocation directly and so
// bypass RecvPrecheck — meaning they would all stay GREEN even if NHP_REV were
// rejected at the receive gate, leaving a handler that can never fire in
// production. This test fences that gap directly:
//
//   - CheckRecvHeaderType(NHP_REV) must be true for an NHP_AC device. This is
//     the gate RecvPrecheck consults (packet.go); without the NHP_AC arm
//     entry, a server-sent NHP_REV is dropped as "header type does not match
//     device" before reaching the AC message routine.
//   - It must NOT be accepted by the other device roles — only the AC receives
//     it.
//   - HeaderTypeToDeviceType(NHP_REV) must be NHP_SERVER: the server is the
//     sender, mirroring the NHP_ARD precedent.
//   - HeaderTypeToString(NHP_REV) must round-trip to a real name (not
//     "UNKNOWN"), which proves the positional nhpHeaderTypeStrings entry is
//     present and iota-aligned with the const.
func TestNHPRevHeaderType_ACReachability(t *testing.T) {
	// AC accepts NHP_REV at the receive gate.
	acDev := &Device{deviceType: NHP_AC}
	if !acDev.CheckRecvHeaderType(NHP_REV) {
		t.Fatal("CheckRecvHeaderType(NHP_REV) = false for NHP_AC; the server-sent " +
			"revocation push would be rejected by RecvPrecheck before reaching " +
			"the AC message routine (add NHP_REV to the NHP_AC arm in packet.go)")
	}

	// No other device role receives NHP_REV — it is a server→AC message only.
	for _, dt := range []struct {
		name string
		typ  int
	}{
		{"NHP_SERVER", NHP_SERVER},
		{"NHP_AGENT", NHP_AGENT},
		{"NHP_RELAY", NHP_RELAY},
		{"NHP_DB", NHP_DB},
	} {
		d := &Device{deviceType: dt.typ}
		if d.CheckRecvHeaderType(NHP_REV) {
			t.Fatalf("CheckRecvHeaderType(NHP_REV) = true for %s; only the AC may receive it", dt.name)
		}
	}

	// The server is the sender.
	if got := HeaderTypeToDeviceType(NHP_REV); got != NHP_SERVER {
		t.Fatalf("HeaderTypeToDeviceType(NHP_REV) = %d, want NHP_SERVER (%d)", got, NHP_SERVER)
	}

	// The positional string table is aligned with the const.
	if got := HeaderTypeToString(NHP_REV); got == "UNKNOWN" || got == "" {
		t.Fatalf("HeaderTypeToString(NHP_REV) = %q; nhpHeaderTypeStrings is missing "+
			"the NHP_REV entry or is misaligned with the const block", got)
	}
}

// TestNHPRVAHeaderType_ServerReachability is the symmetric receive-gate guard
// for the AC's revocation acknowledgement. Handler tests call
// HandleRevocationAck directly, so this pins the wire routing too:
//
//   - CheckRecvHeaderType(NHP_RVA) must be true for an NHP_SERVER device.
//   - It must NOT be accepted by the other device roles — only the server
//     receives the AC's revocation ack.
//   - HeaderTypeToDeviceType(NHP_RVA) must be NHP_AC: the AC is the sender.
//   - HeaderTypeToString(NHP_RVA) must be exactly "NHP-RVA", preserving the
//     three-letter NHP message mnemonic convention.
func TestNHPRVAHeaderType_ServerReachability(t *testing.T) {
	serverDev := &Device{deviceType: NHP_SERVER}
	if !serverDev.CheckRecvHeaderType(NHP_RVA) {
		t.Fatal("CheckRecvHeaderType(NHP_RVA) = false for NHP_SERVER; the AC-sent " +
			"revocation ack would be rejected by RecvPrecheck before reaching " +
			"the server ack handler (add NHP_RVA to the NHP_SERVER arm in packet.go)")
	}

	for _, dt := range []struct {
		name string
		typ  int
	}{
		{"NHP_AC", NHP_AC},
		{"NHP_AGENT", NHP_AGENT},
		{"NHP_RELAY", NHP_RELAY},
		{"NHP_DB", NHP_DB},
	} {
		d := &Device{deviceType: dt.typ}
		if d.CheckRecvHeaderType(NHP_RVA) {
			t.Fatalf("CheckRecvHeaderType(NHP_RVA) = true for %s; only the server may receive it", dt.name)
		}
	}

	if got := HeaderTypeToDeviceType(NHP_RVA); got != NHP_AC {
		t.Fatalf("HeaderTypeToDeviceType(NHP_RVA) = %d, want NHP_AC (%d)", got, NHP_AC)
	}

	if got := HeaderTypeToString(NHP_RVA); got != "NHP-RVA" {
		t.Fatalf("HeaderTypeToString(NHP_RVA) = %q, want %q", got, "NHP-RVA")
	}
}

// TestNHPRelayRecvHeaderType_AllowlistMatrix pins the FULL receive-gate matrix
// for the NHP_RELAY device role. The relay's innerCounter (endpoints/relay)
// runs RecvPrecheck on both the client-POSTed inner packet (handleRelay) and
// the server reply read off the shared socket (recvLoop), so this allowlist is
// the single chokepoint deciding which inner header types can transit the
// HTTPS relay in either direction. The relay handler tests exercise real
// encrypted NHP_KNK/NHP_ACK packets but not the full type matrix — a stray
// addition here (e.g. an AC- or DB-plane type) would silently widen what an
// unauthenticated HTTP client can bounce at a server, so the matrix is pinned
// exhaustively: every type NOT explicitly allowed must be rejected.
//
// The loop bound is the nhpHeaderTypeStrings table, so a future header type
// appended to the const block (and its string entry) lands in this matrix
// automatically with want=false — the fail-closed default a new type should
// have until someone deliberately adds it to the relay allowlist AND this map.
func TestNHPRelayRecvHeaderType_AllowlistMatrix(t *testing.T) {
	relayDev := &Device{deviceType: NHP_RELAY}

	// NHP_KPL is absent by design: RecvPrecheck short-circuits keepalives
	// before consulting CheckRecvHeaderType ("NHP_KPL is handled elsewhere"),
	// so the gate itself reports false for it.
	allowed := map[int]bool{
		NHP_KNK: true, // agent→server knock (client-POSTed)
		NHP_ACK: true, // server→agent knock ack (reply path)
		NHP_COK: true, // server→agent cookie (reply path)
		NHP_RKN: true, // agent→server reknock (client-POSTed)
		NHP_EXT: true, // agent→server disconnect (client-POSTed)
	}

	for typ := 0; typ < len(nhpHeaderTypeStrings); typ++ {
		got := relayDev.CheckRecvHeaderType(typ)
		if want := allowed[typ]; got != want {
			t.Errorf("CheckRecvHeaderType(%s) = %v for NHP_RELAY, want %v",
				HeaderTypeToString(typ), got, want)
		}
	}

	// DHP_KNK is a native-UDP-only request. Keep it out of this HTTPS relay
	// gate even though nativePacketCounter deliberately admits it.
	if relayDev.CheckRecvHeaderType(DHP_KNK) {
		t.Error("NHP_RELAY CheckRecvHeaderType unexpectedly admits native-only DHP_KNK")
	}

}

func TestIsForwardableKnockType(t *testing.T) {
	for _, tc := range []struct {
		name string
		ht   int
		want bool
	}{
		{"NHP_KNK", NHP_KNK, true},
		{"NHP_RKN", NHP_RKN, true},
		{"NHP_EXT", NHP_EXT, true},
		{"DHP_KNK", DHP_KNK, false},
		{"NHP_ACK", NHP_ACK, false},
		{"NHP_AOP", NHP_AOP, false},
		{"NHP_RLY", NHP_RLY, false},
		{"NHP_FWD", NHP_FWD, false},
	} {
		if got := IsForwardableKnockType(tc.ht); got != tc.want {
			t.Errorf("IsForwardableKnockType(%s) = %v, want %v", tc.name, got, tc.want)
		}
	}
}
