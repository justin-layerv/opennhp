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
