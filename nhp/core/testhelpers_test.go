package core

import (
	"errors"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/log"
)

// testPeerPk returns the deterministic byte-pattern public key the
// chain-key tests use as a stand-in. Not a valid curve25519 key —
// callers are expected to be on paths where peer-key validation
// doesn't fire (e.g., setPeerPublicKey accepts arbitrary
// PublicKeySize-byte inputs; signing/AEAD steps that would reject
// are gated behind earlier checks the tests don't reach).
func testPeerPk() []byte {
	peerPk := make([]byte, PublicKeySize)
	for i := range peerPk {
		peerPk[i] = byte(i + 1)
	}
	return peerPk
}

// runResponderWithPrevHeaderDigestFailure builds a prev MAD and a junk
// packet, calls createPacketParserData with PrevAssemblerData set
// plus any extra config the caller applies via `configure`, asserts
// the header-digest-failure / bare-return contract (err is ErrHeaderDigestCheckFailed,
// ppd is non-nil), and returns the populated ppd for further
// inspection. Shared by the responder-side chain-key tests in
// derive_chainkey_test.go.
func runResponderWithPrevHeaderDigestFailure(t *testing.T, dev *Device, configure func(*PacketData)) *PacketParserData {
	t.Helper()
	silenceGlobalLogger(t)

	prevMad, err := dev.createMsgAssemblerData(&MsgData{
		HeaderType:    NHP_KNK,
		CipherScheme:  common.CIPHER_SCHEME_CURVE,
		TransactionId: 1,
		PeerPk:        testPeerPk(),
	})
	if err != nil {
		t.Fatalf("build prev MAD: %v", err)
	}
	t.Cleanup(prevMad.Destroy)

	pkt := dev.AllocatePoolPacket()
	if pkt == nil {
		t.Fatal("AllocatePoolPacket returned nil")
	}
	pkt.Content = pkt.Buf[:prevMad.header.Size()]
	// Stamp a supported version so the responder's version gate lets the packet
	// through to the header-digest check this helper is about; without it every
	// caller would trip the earlier gate instead.
	pkt.Header().SetVersion(ProtocolVersionMajor, ProtocolVersionMinor)

	pd := &PacketData{
		BasePacket:        pkt,
		PrevAssemblerData: prevMad,
		InitTime:          time.Now().UnixNano(),
	}
	if configure != nil {
		configure(pd)
	}

	ppd, err := dev.createPacketParserData(pd)
	if !errors.Is(err, ErrHeaderDigestCheckFailed) {
		t.Fatalf("expected ErrHeaderDigestCheckFailed, got %v", err)
	}
	if ppd == nil {
		t.Fatal("ppd nil — createPacketParserData did not populate named return on err path")
	}
	t.Cleanup(ppd.Destroy)

	return ppd
}

// silenceGlobalLogger swaps in a silent logger for the duration of
// the test and restores the prior global on cleanup. Uses Swap (not
// Set) so the prior logger isn't Close()d and its callDepth doesn't
// drift on restore. Used by tests + benchmarks that exercise paths
// which log on the hot path (e.g., createMsgAssemblerData).
//
// Do not call inside a b.Loop() / sub-test loop — NewLogger spawns
// three AsyncLogWriter goroutines per call which would leak per
// iteration. Call once from the test/benchmark setup instead.
//
// Not safe with t.Parallel(): the helper mutates package-global
// state (log.glbLogger); two parallel callers will race on Swap
// and the second's cleanup will restore the first's silent logger.
func silenceGlobalLogger(tb testing.TB) {
	tb.Helper()
	silent := log.NewLogger("", log.LogLevelSilent, "", "")
	prev := log.SwapGlobalLogger(silent)
	tb.Cleanup(func() {
		log.SwapGlobalLogger(prev)
		silent.Close()
	})
}
