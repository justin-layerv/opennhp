package core

import (
	"encoding/json"
	"net"
	"testing"

	"github.com/OpenNHP/opennhp/nhp/common"
)

// TestSendCookie_WireCounterEchoesKnockCounter fences the #2611 / #2529
// regression: the overload cookie (NHP_COK) the server sends in response to a
// KNK must carry, as its cleartext header counter, the *agent's* inbound KNK
// counter (ppd.SenderTrxId) — not a fresh server-side NextCounterIndex().
//
// The NHP-Relay (endpoints/relay) is a one-shot forwarder that never decrypts:
// it registers a pending HTTP request under the KNK's cleartext counter and
// matches the server's reply back to it by that same counter. A COK stamped
// with a server-side counter therefore never correlates — the relay drops it
// and the browser times out under Overload. Echoing SenderTrxId is what every
// other server→agent response already does (the ACK at transaction.go routes
// through PrevParserData, which stamps SenderTrxId on the wire).
//
// The assertion is two-layer, mirroring how the wire counter is actually
// produced: (1) sendCookie must build its MsgData with PrevParserData set and
// no server-side TransactionId (the regression was the no-prev branch with a
// fresh counter); (2) finalizing that MsgData through createMsgAssemblerData —
// the exact step the send worker runs — must yield a header counter equal to
// SenderTrxId (the value the relay reads).
func TestSendCookie_WireCounterEchoesKnockCounter(t *testing.T) {
	dev := newDeviceForChainKeyTest(t) // not Start()ed: msgToPacketQueue is not drained
	silenceGlobalLogger(t)

	const agentTrxID = uint64(0xA11CE)
	ppd := &PacketParserData{
		device:       dev,
		CipherScheme: common.CIPHER_SCHEME_CURVE,
		Ciphers:      NewCipherSuite(),
		RemotePubKey: testPeerPk(),
		SenderTrxId:  agentTrxID,
		ConnData: &ConnectionData{
			Device:      dev,
			RemoteAddr:  &net.UDPAddr{IP: net.IPv4(203, 0, 113, 7), Port: 44444},
			CookieStore: &CookieStore{},
		},
	}

	ppd.sendCookie()

	// sendCookie enqueues the COK MsgData onto the device's send queue.
	var md *MsgData
	select {
	case md = <-dev.msgToPacketQueue:
	default:
		t.Fatal("sendCookie did not enqueue an MsgData")
	}

	if md.HeaderType != NHP_COK {
		t.Fatalf("MsgData.HeaderType = %d, want NHP_COK", md.HeaderType)
	}
	if md.PrevParserData != ppd {
		t.Fatalf("sendCookie must build MsgData with PrevParserData set so the wire counter is the agent's SenderTrxId; got PrevParserData=%v", md.PrevParserData)
	}
	if md.TransactionId != 0 {
		t.Fatalf("sendCookie must not assign a server-side TransactionId — that overwrites the agent's counter on the wire and breaks relay correlation; got TransactionId=%#x", md.TransactionId)
	}

	// The COK payload's TransactionId field has always echoed SenderTrxId; this
	// fences that the sibling did not regress alongside the wire counter.
	var cokMsg common.ServerCookieMsg
	if err := json.Unmarshal(md.Message, &cokMsg); err != nil {
		t.Fatalf("unmarshal ServerCookieMsg: %v", err)
	}
	if cokMsg.TransactionId != agentTrxID {
		t.Errorf("ServerCookieMsg.TransactionId = %#x, want agent SenderTrxId %#x", cokMsg.TransactionId, agentTrxID)
	}

	// Run the same finalization the send worker would, then check the on-wire
	// counter — this is the value the relay actually reads off the COK.
	mad, err := dev.createMsgAssemblerData(md)
	if err != nil {
		t.Fatalf("createMsgAssemblerData: %v", err)
	}
	t.Cleanup(mad.Destroy)

	if got := mad.header.Counter(); got != agentTrxID {
		t.Fatalf("COK wire counter must equal the agent's KNK counter so the relay can match the response.\n"+
			"got=%#x want=%#x — sendCookie likely regressed to the no-prev branch and stamped a server-side counter on the wire",
			got, agentTrxID)
	}
}
