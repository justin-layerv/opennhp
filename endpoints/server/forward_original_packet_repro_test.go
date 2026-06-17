package server

import (
	"bytes"
	"encoding/json"
	"net"
	"testing"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
)

// TestForwardOriginalPacket_ReDecryptableAfterDecrypt is a tight reproducer for
// the cross-server-forward bug surfaced while building the #2546 e2e
// (TestE2E_RelayCrossServer_KnockForwardedToRemoteAC_AckReturnsViaRelay, which
// is t.Skip'd on this bug).
//
// The server-to-server forward path captures the inner knock to re-send to the
// assigned server via exactly one production line:
//
//	endpoints/server/nhpauth.go:207  OriginalPacket: ppd.BasePacketContent()
//
// inside buildKnockAck — the SHARED chokepoint that both the direct UDP knock
// (HandleKnockRequest) and the relayed knock (HandleRelayForward) run through.
// The assigned server then re-decrypts those bytes with the shared registration
// key via ServerForwarder.decryptForwardedKnock (forward.go:506).
//
// BasePacketContent()'s godoc promises "a copy of the original ENCRYPTED packet
// content" (nhp/core/responder.go:908). But decryptBody (responder.go:712)
// decrypts the body IN PLACE — its AEAD Open writes plaintext back into
// ppd.basePacket.Content[header.Size():] (the "reuse ... Content space" line at
// responder.go:727). By the time buildKnockAck calls BasePacketContent(), the
// knock has already been decrypted, so the body region is plaintext, not the
// original ciphertext. The captured bytes therefore fail AEAD authentication
// when the assigned server tries to re-decrypt them — every cross-server
// forward returns DECRYPT_FAILED and the knock is denied.
//
// This test reproduces the corruption with no networking and no forwarder: it
// decrypts a knock through the real core path exactly as a server does, then
// asserts the contract BasePacketContent() promises and the forward path
// depends on — that the returned bytes still equal the original ciphertext and
// remain re-decryptable by a second server holding the same registration key.
//
// It FAILS today (documenting the bug) and will pass once the capture preserves
// the pre-decrypt ciphertext (snapshot the raw packet before decryptBody, or
// decrypt the body out-of-place). Fix is intentionally out of scope here — this
// is a test-only change reporting a real bug; the orchestrator decides scope.
func TestForwardOriginalPacket_ReDecryptableAfterDecrypt(t *testing.T) {
	// Skipped because it FAILS today: it documents a real, unfixed bug in the
	// shared cross-server-forward capture (nhpauth.go:207 + responder.go:727).
	// The fix is out of scope for this test-only change (#2546); remove this
	// Skip in the PR that preserves the pre-decrypt ciphertext so this becomes
	// the regression fence. Verified failing as of this commit (see the PR body
	// / bug #2651 for the captured failure output).
	t.Skip("documents unfixed cross-server-forward bug #2651: BasePacketContent() returns post-decrypt bytes; remove Skip in the #2651 fix that preserves the pre-decrypt ciphertext")

	// Two servers sharing one registration keypair — the production
	// multi-instance posture (docs/design/PER_INSTANCE_SERVER_KEYS.md §1): any
	// server behind the NLB decrypts agent traffic with the shared key. serverA
	// is where the knock lands; serverB is the AC's assigned server that must
	// re-decrypt the forwarded bytes.
	sharedRegKey := make([]byte, 32)
	for i := range sharedRegKey {
		sharedRegKey[i] = byte(i) + 0x42
	}
	cloudMode := &core.DeviceOptions{DisableAgentPeerValidation: true}
	serverA := core.NewDevice(core.NHP_SERVER, sharedRegKey, cloudMode)
	serverB := core.NewDevice(core.NHP_SERVER, sharedRegKey, cloudMode)
	if serverA == nil || serverB == nil {
		t.Fatal("core.NewDevice returned nil")
	}
	serverA.Start()
	defer serverA.Stop()
	serverB.Start()
	defer serverB.Stop()

	agentDev := newSpikeDevice(t, core.NHP_AGENT, 0x11, nil)
	serverPk := decodeBase64PubKey(serverA.PublicKeyBase64())
	serverAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 62206}
	agentDev.AddPeer(&core.UdpPeer{
		PubKeyBase64: serverA.PublicKeyBase64(),
		Ip:           serverAddr.IP.String(),
		Port:         serverAddr.Port,
		Type:         core.NHP_SERVER,
	})

	// Agent encrypts a real NHP_KNK to the shared key — the bytes a server
	// receives (and, on the forward path, would re-send as OriginalPacket).
	conn := newSpikeConn(agentDev, serverAddr)
	knockBody, err := json.Marshal(&common.AgentKnockMsg{
		HeaderType:    core.NHP_KNK,
		UserId:        "repro-user",
		AuthServiceId: "agent",
		ResourceId:    "repro-resource",
	})
	if err != nil {
		t.Fatalf("marshal knock body: %v", err)
	}
	agentDev.SendMsgToPacket(&core.MsgData{
		ConnData:      conn,
		PeerPk:        serverPk,
		HeaderType:    core.NHP_KNK,
		TransactionId: 4242,
		Message:       knockBody,
	})
	originalCiphertext := drainEncryptedPacket(t, conn) // pristine on-wire bytes

	// serverA decrypts the knock exactly as the recv path does (a fresh pool
	// buffer holding a copy of the wire bytes), then captures OriginalPacket the
	// way buildKnockAck does. Using a separate buffer keeps originalCiphertext
	// pristine for the comparison below — the in-place decrypt would otherwise
	// mutate the very slice we compare against.
	recvBuf := bytes.Clone(originalCiphertext)
	ppd, err := serverA.PacketToMsg(&core.PacketData{
		BasePacket: &core.Packet{Content: recvBuf},
		ConnData: &core.ConnectionData{
			Device:     serverA,
			RemoteAddr: &net.UDPAddr{IP: net.IPv4(203, 0, 113, 7), Port: 44444},
		},
	})
	if err != nil {
		t.Fatalf("serverA decrypt of knock failed: %v", err)
	}
	if ppd.Error != nil {
		t.Fatalf("serverA decrypt of knock returned error ppd: %v", ppd.Error)
	}

	// This is the exact value nhpauth.go:207 forwards as req.OriginalPacket.
	forwarded := ppd.BasePacketContent()

	// Contract 1: BasePacketContent() must return the ORIGINAL encrypted bytes
	// (per its godoc). Today it returns the in-place-decrypted buffer, so the
	// body region differs.
	if !bytes.Equal(forwarded, originalCiphertext) {
		firstDiff := -1
		for i := 0; i < len(forwarded) && i < len(originalCiphertext); i++ {
			if forwarded[i] != originalCiphertext[i] {
				firstDiff = i
				break
			}
		}
		t.Errorf("BasePacketContent() != original ciphertext (first differing byte at index %d): decryptBody decrypted the body in place into basePacket.Content, so the bytes forwarded as req.OriginalPacket are no longer the original ciphertext. See nhpauth.go:207 + responder.go:727.",
			firstDiff)
	}

	// Contract 2 (the one the forward path actually depends on): the assigned
	// server, holding the same shared registration key, must be able to
	// re-decrypt the forwarded bytes — this is ServerForwarder.decryptForward
	// edKnock. A control re-decrypt of the pristine ciphertext proves serverB's
	// key is correct, isolating the failure to the captured-bytes corruption.
	if _, ctrlErr := serverB.PacketToMsg(&core.PacketData{
		BasePacket: &core.Packet{Content: bytes.Clone(originalCiphertext)},
		ConnData:   &core.ConnectionData{Device: serverB, RemoteAddr: &net.UDPAddr{IP: net.IPv4(203, 0, 113, 7), Port: 44444}},
	}); ctrlErr != nil {
		t.Fatalf("control: serverB could not decrypt the PRISTINE ciphertext (shared-key setup is wrong, not the bug under test): %v", ctrlErr)
	}

	rePpd, reErr := serverB.PacketToMsg(&core.PacketData{
		BasePacket: &core.Packet{Content: bytes.Clone(forwarded)},
		ConnData:   &core.ConnectionData{Device: serverB, RemoteAddr: &net.UDPAddr{IP: net.IPv4(203, 0, 113, 7), Port: 44444}},
	})
	if reErr != nil {
		t.Errorf("assigned server failed to re-decrypt the forwarded OriginalPacket: %v — every cross-server knock forward (direct via HandleKnockRequest and relayed via HandleRelayForward, both through buildKnockAck) returns DECRYPT_FAILED and denies the knock", reErr)
		return
	}
	if rePpd.Error != nil {
		t.Errorf("assigned server re-decrypt returned error ppd: %v", rePpd.Error)
		return
	}
	if rePpd.HeaderType != core.NHP_KNK {
		t.Errorf("re-decrypted header = %s, want NHP_KNK", core.HeaderTypeToString(rePpd.HeaderType))
	}
}
