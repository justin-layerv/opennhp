package core

import (
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

	device.ReleasePoolPacket(pkt)
	if pkt.Content != nil {
		t.Fatalf("ReleasePoolPacket should nil pkt.Content; got len=%d", len(pkt.Content))
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
