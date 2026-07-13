package core

import (
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
)

// TestDerivePacketParserData_DoesNotCarryChainKey and its
// responder-side twin fence OpenNHP commit 03619015e: the derive
// functions must never copy the previous transaction's chainKey
// into the new MAD/PPD. The intermediate-chain-key carry-over
// design was abandoned; encryptBody/decryptBody defer-zero the
// chainKey on the way out, so any surviving copy() in derive*
// picks up a zeroed buffer in Go-Go (which both ends symmetrically
// "agree on") but breaks JS-Go interop because a spec-following
// JS implementation does not replicate the zero-carry-over quirk.
//
// Asymmetric assertion: the parent (MAD/PPD) is seeded with a
// non-zero sentinel; the child must come out zero. The newly
// allocated child struct starts zero by default, so this only
// fails if derive* *actively* copies the sentinel — which is
// exactly the regression we want to fence. Do not "fix" the
// asymmetry by also seeding the child; the test would then no
// longer distinguish "derive copied" from "derive did nothing".
func TestDerivePacketParserData_DoesNotCarryChainKey(t *testing.T) {
	dev := newDeviceForChainKeyTest(t)

	mad := &MsgAssemblerData{
		device:       dev,
		CipherScheme: common.CIPHER_SCHEME_CURVE,
		ciphers:      NewCipherSuite(),
	}
	for i := range mad.chainKey {
		mad.chainKey[i] = 0xAB
	}

	pkt := dev.AllocatePoolPacket()
	if pkt == nil {
		t.Fatal("AllocatePoolPacket returned nil")
	}
	t.Cleanup(func() { dev.ReleasePoolPacket(pkt) })

	ppd := mad.derivePacketParserData(pkt, time.Now().UnixNano())

	var zero [SymmetricKeySize]byte
	if ppd.chainKey != zero {
		t.Errorf("derivePacketParserData copied chainKey from parent MAD — OpenNHP 03619015e regression. ppd.chainKey=%x", ppd.chainKey)
	}
}

func TestDeriveMsgAssemblerData_DoesNotCarryChainKey(t *testing.T) {
	dev := newDeviceForChainKeyTest(t)

	ppd := &PacketParserData{
		device:       dev,
		CipherScheme: common.CIPHER_SCHEME_CURVE,
		Ciphers:      NewCipherSuite(),
	}
	for i := range ppd.chainKey {
		ppd.chainKey[i] = 0xCD
	}

	mad := ppd.deriveMsgAssemblerData(NHP_ACK, false, nil, nil)
	if mad == nil {
		t.Fatal("deriveMsgAssemblerData returned nil")
	}
	t.Cleanup(func() { mad.Destroy() })

	var zero [SymmetricKeySize]byte
	if mad.chainKey != zero {
		t.Errorf("deriveMsgAssemblerData copied chainKey from parent PPD — OpenNHP 03619015e regression. mad.chainKey=%x", mad.chainKey)
	}
}

// TestCreateMsgAssemblerData_InitsCanonicalChainKey fences the
// other regression mode: deleting (or skipping) the always-run
// chain-key init block in createMsgAssemblerData. Both branches
// (no-prev / with-prev) must produce the canonical ChainKey0 (a
// non-zero, deterministic value), and they must agree — pre-fix
// code had the with-prev branch carrying over a zeroed chainKey
// from the prior transaction. Companion to the derive-level tests
// above (the derive tests catch a reintroduced copy(); this test
// catches a deleted init block).
func TestCreateMsgAssemblerData_InitsCanonicalChainKey(t *testing.T) {
	dev := newDeviceForChainKeyTest(t)
	silenceGlobalLogger(t)

	peerPk := testPeerPk()

	madNoPrev, err := dev.createMsgAssemblerData(&MsgData{
		HeaderType:    NHP_KNK,
		CipherScheme:  common.CIPHER_SCHEME_CURVE,
		TransactionId: 1,
		PeerPk:        peerPk,
	})
	if err != nil {
		t.Fatalf("no-prev createMsgAssemblerData: %v", err)
	}
	t.Cleanup(madNoPrev.Destroy)

	madWithPrev, err := dev.createMsgAssemblerData(&MsgData{
		HeaderType: NHP_ACK,
		PrevParserData: &PacketParserData{
			device:       dev,
			CipherScheme: common.CIPHER_SCHEME_CURVE,
			Ciphers:      NewCipherSuite(),
			RemotePubKey: peerPk,
			SenderTrxId:  1,
		},
	})
	if err != nil {
		t.Fatalf("with-prev createMsgAssemblerData: %v", err)
	}
	t.Cleanup(madWithPrev.Destroy)

	var zero [SymmetricKeySize]byte
	if madNoPrev.chainKey == zero {
		t.Error("no-prev chainKey is zero — canonical ChainKey0 was not initialized")
	}
	if madWithPrev.chainKey == zero {
		t.Error("with-prev chainKey is zero — OpenNHP 03619015e regression (always-run init block did not run on the carry-over path)")
	}
	if madNoPrev.chainKey != madWithPrev.chainKey {
		t.Errorf("chainKey diverges between branches; both must produce canonical ChainKey0.\nno-prev:   %x\nwith-prev: %x", madNoPrev.chainKey, madWithPrev.chainKey)
	}
}

// TestCreateMsgAssemblerData_WithPrevPropagatesChannels fences the
// round-7 documented behavior: a with-prev caller that sets
// EncryptedPktCh / ResponseMsgCh has those channels propagated
// onto the new MAD. Pre-fix code only set them on the no-prev
// branch (deriveMsgAssemblerData didn't copy them through), so
// today's with-prev callers leave them nil; this test pins the
// new contract so a future caller can actually rely on routing
// through these channels from the carry-over path.
func TestCreateMsgAssemblerData_WithPrevPropagatesChannels(t *testing.T) {
	dev := newDeviceForChainKeyTest(t)
	silenceGlobalLogger(t)

	// Channels are identity-compared (chan is a reference type); nothing
	// is ever sent or received over them.
	encryptedPktCh := make(chan *MsgAssemblerData, 1)
	responseMsgCh := make(chan *PacketParserData, 1)
	mad, err := dev.createMsgAssemblerData(&MsgData{
		HeaderType: NHP_ACK,
		PrevParserData: &PacketParserData{
			device:       dev,
			CipherScheme: common.CIPHER_SCHEME_CURVE,
			Ciphers:      NewCipherSuite(),
			RemotePubKey: testPeerPk(),
			SenderTrxId:  1,
		},
		EncryptedPktCh: encryptedPktCh,
		ResponseMsgCh:  responseMsgCh,
	})
	if err != nil {
		t.Fatalf("createMsgAssemblerData: %v", err)
	}
	t.Cleanup(mad.Destroy)

	if mad.encryptedPktCh != encryptedPktCh {
		t.Errorf("encryptedPktCh not propagated to with-prev MAD: got %v, want %v", mad.encryptedPktCh, encryptedPktCh)
	}
	if mad.ResponseMsgCh != responseMsgCh {
		t.Errorf("ResponseMsgCh not propagated to with-prev MAD: got %v, want %v", mad.ResponseMsgCh, responseMsgCh)
	}
}

// TestCreatePacketParserData_WithPrevPropagatesChannels is the
// responder-side twin of TestCreateMsgAssemblerData_WithPrevPropagatesChannels.
// Pins the new unconditional-copy of pd.DecryptedMsgCh onto the
// derived ppd. Pre-fix, the with-prev branch silently dropped
// this channel because derivePacketParserData didn't copy it
// through. Today's with-prev callers leave it nil; this test
// pins the new contract.
func TestCreatePacketParserData_WithPrevPropagatesChannels(t *testing.T) {
	// Channel is identity-compared; nothing is ever sent/received.
	decryptedMsgCh := make(chan *PacketParserData, 1)
	ppd := runResponderWithPrevHeaderDigestFailure(t, newDeviceForChainKeyTest(t), func(pd *PacketData) {
		pd.DecryptedMsgCh = decryptedMsgCh
	})

	if ppd.decryptedMsgCh != decryptedMsgCh {
		t.Errorf("decryptedMsgCh not propagated to with-prev PPD: got %v, want %v", ppd.decryptedMsgCh, decryptedMsgCh)
	}
}

// TestCreatePacketParserData_InitsCanonicalChainKey is the responder-
// side twin of TestCreateMsgAssemblerData_InitsCanonicalChainKey.
// The packet has no valid header digest so the function returns
// ErrHeaderDigestCheckFailed — but chain-key init runs BEFORE the
// digest validation (see createPacketParserData), and the function uses
// named returns so ppd is populated even on the digest-failure path.
func TestCreatePacketParserData_InitsCanonicalChainKey(t *testing.T) {
	// runResponderWithPrevHeaderDigestFailure pins the
	// errors.Is(err, ErrHeaderDigestCheckFailed) + ppd != nil contract; we
	// inspect chainKey on the returned ppd to confirm the init block
	// ran above the header-digest check.
	ppd := runResponderWithPrevHeaderDigestFailure(t, newDeviceForChainKeyTest(t), nil)

	var zero [SymmetricKeySize]byte
	if ppd.chainKey == zero {
		t.Error("ppd.chainKey is zero — OpenNHP 03619015e regression (always-run init block did not run on the carry-over path)")
	}
}

func newDeviceForChainKeyTest(t *testing.T) *Device {
	t.Helper()
	priv := make([]byte, 32)
	for i := range priv {
		priv[i] = byte(i + 1)
	}
	dev := NewDevice(NHP_AGENT, priv, nil)
	if dev == nil {
		t.Fatal("NewDevice returned nil")
	}
	t.Cleanup(dev.Stop)
	return dev
}
