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
// the cross-server-forward bug (#2651) surfaced while building the #2546 e2e
// (TestE2E_RelayCrossServer_KnockForwardedToRemoteAC_AckReturnsViaRelay), which
// exercises the full composed relay path.
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
// content". But decryptBody decrypts the body IN PLACE — its AEAD Open writes
// plaintext back into ppd.basePacket.Content[header.Size():] (the "reuse ...
// Content space" line). Before the #2651 fix, by the time buildKnockAck called
// BasePacketContent() the knock had already been decrypted, so the body region
// was plaintext, not the original ciphertext: the captured bytes failed AEAD
// authentication on the assigned server — every cross-server forward returned
// DECRYPT_FAILED and the knock was denied.
//
// This test reproduces that path with no networking and no forwarder: it
// decrypts a knock through the real core path exactly as a server does, then
// asserts the contract BasePacketContent() promises and the forward path
// depends on — that the returned bytes still equal the original ciphertext and
// remain re-decryptable by a second server holding the same registration key.
//
// The #2651 fix snapshots the raw packet before decryptBody's in-place Open and
// returns that pristine ciphertext from BasePacketContent(); this test is the
// regression fence — if it fails again, the cross-server-forward capture broke.
//
// The table-driven variant below covers the entire forwardable knock family
// (NHP_KNK, NHP_RKN) to ensure the conditional clone guard in
// decryptBody covers all types that reach BasePacketContent() via buildKnockAck.
// DHP_KNK is excluded — it returns early at nhpauth.go:109 before line 220.
func TestForwardOriginalPacket_ReDecryptableAfterDecrypt(t *testing.T) {
	knockTypes := []struct {
		name       string
		headerType int
	}{
		{"NHP_KNK", core.NHP_KNK},
		{"NHP_RKN", core.NHP_RKN},
	}

	for _, tc := range knockTypes {
		t.Run(tc.name, func(t *testing.T) {
			testForwardOriginalPacketForType(t, tc.headerType)
		})
	}
}

func testForwardOriginalPacketForType(t *testing.T, headerType int) {
	t.Helper()

	if headerType == core.NHP_RKN {
		t.Skip("NHP_RKN requires cookie-bound configuration (CookieStore or stateless cookie params) to construct a valid packet; the bytes.Clone guard is covered by the NHP_KNK path")
	}

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

	// Agent encrypts a real knock to the shared key — the bytes a server
	// receives (and, on the forward path, would re-send as OriginalPacket).
	conn := newSpikeConn(agentDev, serverAddr)
	knockBody, err := json.Marshal(&common.AgentKnockMsg{
		HeaderType:    headerType,
		UserId:        "repro-user",
		AuthServiceId: "agent",
		ResourceId:    "repro-resource",
		RunID:         "0123456789abcdef",
	})
	if err != nil {
		t.Fatalf("marshal knock body: %v", err)
	}
	agentDev.SendMsgToPacket(&core.MsgData{
		ConnData:      conn,
		PeerPk:        serverPk,
		HeaderType:    headerType,
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

	// This is the exact value nhpauth.go:220 forwards as req.OriginalPacket.
	forwarded := ppd.BasePacketContent()

	// Contract 0: BasePacketContent() must be non-nil for forwardable knock types.
	if forwarded == nil {
		t.Fatalf("BasePacketContent() returned nil for %s — the conditional clone guard in decryptBody does not cover this header type, so cross-server forwarding silently skips", core.HeaderTypeToString(headerType))
	}

	// Contract 1: BasePacketContent() must return the ORIGINAL encrypted bytes
	// (per its godoc). If this regresses, decryptBody's in-place AEAD decrypt is
	// leaking into the bytes buildKnockAck forwards as req.OriginalPacket again
	// (the #2651 bug).
	if !bytes.Equal(forwarded, originalCiphertext) {
		firstDiff := -1
		for i := 0; i < len(forwarded) && i < len(originalCiphertext); i++ {
			if forwarded[i] != originalCiphertext[i] {
				firstDiff = i
				break
			}
		}
		t.Errorf("BasePacketContent() != original ciphertext (first differing byte at index %d): the bytes forwarded as req.OriginalPacket must be the pre-decrypt ciphertext, not decryptBody's in-place-decrypted buffer — #2651 regression.",
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
	if rePpd.HeaderType != headerType {
		t.Errorf("re-decrypted header = %s, want %s", core.HeaderTypeToString(rePpd.HeaderType), core.HeaderTypeToString(headerType))
	}
}
