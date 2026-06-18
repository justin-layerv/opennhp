package core

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
)

func TestMsgToPacketRoutineMissingConnDataReturnsError(t *testing.T) {
	silenceGlobalLogger(t)

	for _, tc := range []struct {
		name       string
		headerType int
	}{
		{name: "forward", headerType: NHP_FWD},
		{name: "keepalive", headerType: NHP_KPL},
	} {
		t.Run(tc.name, func(t *testing.T) {
			serverKey := make([]byte, PrivateKeySize)
			serverKey[0] = 1
			peerKey := make([]byte, PrivateKeySize)
			peerKey[0] = 2

			device := NewDevice(NHP_SERVER, serverKey, nil)
			if device == nil {
				t.Fatal("NewDevice returned nil")
			}
			peer := NewDevice(NHP_SERVER, peerKey, nil)
			if peer == nil {
				t.Fatal("NewDevice(peer) returned nil")
			}

			device.Start()
			t.Cleanup(device.Stop)

			responseCh := make(chan *PacketParserData, 1)
			device.SendMsgToPacket(&MsgData{
				HeaderType:    tc.headerType,
				CipherScheme:  common.CIPHER_SCHEME_CURVE,
				TransactionId: 1,
				PeerPk:        peer.staticEcdh.PublicKey(),
				Message:       []byte(`{"probe":true}`),
				ResponseMsgCh: responseCh,
			})

			select {
			case got := <-responseCh:
				if got == nil || got.Error == nil {
					t.Fatalf("got response %#v, want missing ConnData error", got)
				}
				if !strings.Contains(got.Error.Error(), "missing connection data") {
					t.Fatalf("error = %q, want missing connection data", got.Error.Error())
				}
			case <-time.After(2 * time.Second):
				t.Fatal("timed out waiting for missing ConnData error")
			}
		})
	}
}

func TestMsgToPacketRoutineRecoversForwardOutboundPanic(t *testing.T) {
	silenceGlobalLogger(t)

	for _, tc := range []struct {
		name       string
		headerType int
	}{
		{name: "forward-result", headerType: NHP_FRT},
		{name: "forward-transaction", headerType: NHP_FWD},
	} {
		t.Run(tc.name, func(t *testing.T) {
			serverKey := make([]byte, PrivateKeySize)
			serverKey[0] = 1
			peerKey := make([]byte, PrivateKeySize)
			peerKey[0] = 2

			device := NewDevice(NHP_SERVER, serverKey, nil)
			if device == nil {
				t.Fatal("NewDevice returned nil")
			}
			peer := NewDevice(NHP_SERVER, peerKey, nil)
			if peer == nil {
				t.Fatal("NewDevice(peer) returned nil")
			}

			device.Start()
			t.Cleanup(device.Stop)

			sendQueue := make(chan *Packet)
			close(sendQueue)
			connData := &ConnectionData{
				Device:     device,
				RemoteAddr: &net.UDPAddr{IP: net.ParseIP("10.0.1.50"), Port: 62206},
				SendQueue:  sendQueue,
				StopSignal: make(chan struct{}),
			}

			responseCh := make(chan *PacketParserData, 1)
			device.SendMsgToPacket(&MsgData{
				HeaderType:    tc.headerType,
				CipherScheme:  common.CIPHER_SCHEME_CURVE,
				TransactionId: 1,
				PeerPk:        peer.staticEcdh.PublicKey(),
				ConnData:      connData,
				Message:       []byte(`{"probe":true}`),
				ResponseMsgCh: responseCh,
			})

			select {
			case got := <-responseCh:
				if got == nil || got.Error == nil {
					t.Fatalf("got response %#v, want recovered panic error", got)
				}
				if !strings.Contains(got.Error.Error(), "runtime panic encountered") {
					t.Fatalf("error = %q, want runtime panic wrapper", got.Error.Error())
				}
				if !strings.Contains(got.Error.Error(), "send on closed channel") {
					t.Fatalf("error = %q, want send-on-closed cause", got.Error.Error())
				}
			case <-time.After(2 * time.Second):
				t.Fatal("timed out waiting for recovered panic error")
			}

			deadline := time.After(2 * time.Second)
			for device.LocalTransactionCount() != 0 {
				select {
				case <-deadline:
					t.Fatalf("local transactions still active: %d", device.LocalTransactionCount())
				case <-time.After(10 * time.Millisecond):
				}
			}
		})
	}
}
