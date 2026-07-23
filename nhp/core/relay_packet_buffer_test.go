package core

import (
	"bytes"
	"encoding/base64"
	"errors"
	"net"
	"testing"
)

func relayBufferTestKey(fill byte) []byte {
	return bytes.Repeat([]byte{fill}, 32)
}

func TestRelayPacketPoolReleaseClearsOwnership(t *testing.T) {
	pkt := (&Device{}).AllocateRelayPacket()
	if got := pkt.MinimalLength(); got != RelayPacketMinimalLength {
		t.Fatalf("MinimalLength() = %d, want %d", got, RelayPacketMinimalLength)
	}
	if len(pkt.Content) != RelayPacketBufferSize {
		t.Fatalf("new relay packet len = %d, want %d", len(pkt.Content), RelayPacketBufferSize)
	}

	(&Device{}).ReleasePoolPacket(pkt)
	if pkt.Content != nil || pkt.externalBuf != nil || pkt.relayBuf != nil {
		t.Fatal("released relay packet retains pooled buffer ownership")
	}
	// A repeated release is a no-op rather than returning the same buffer twice.
	(&Device{}).ReleasePoolPacket(pkt)
}

func TestRelayExternalPacketPreservesDirectLimitAndRoundTrips(t *testing.T) {
	relay := NewDevice(NHP_RELAY, relayBufferTestKey(0x31), nil)
	server := NewDevice(NHP_SERVER, relayBufferTestKey(0x41), &DeviceOptions{
		DisableRelayPeerValidation: true,
	})
	serverPub, err := base64.StdEncoding.DecodeString(server.PublicKeyBase64())
	if err != nil {
		t.Fatal(err)
	}
	message := bytes.Repeat([]byte{0xA5}, 4000)
	base := MsgData{
		RemoteAddr:    &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 62206},
		PeerPk:        serverPub,
		HeaderType:    NHP_RLY,
		TransactionId: 77,
		Message:       message,
	}

	if _, err := relay.MsgToPacket(&base); !errors.Is(err, ErrPacketSizeExceedsBuffer) {
		t.Fatalf("standard packet assembly error = %v, want ErrPacketSizeExceedsBuffer", err)
	}

	base.ExternalPacket = NewRelayPacket()
	mad, err := relay.MsgToPacket(&base)
	if err != nil {
		t.Fatalf("relay external packet assembly: %v", err)
	}
	if got := len(mad.BasePacket.Content); got <= PacketBufferSize || got > RelayPacketBufferSize {
		t.Fatalf("outer packet length = %d, want (%d,%d]", got, PacketBufferSize, RelayPacketBufferSize)
	}
	wire := bytes.Clone(mad.BasePacket.Content)
	receivedAtNanos := mad.LocalInitTime + 1
	ppd, err := server.PacketToMsg(&PacketData{
		BasePacket: &Packet{Content: wire},
		ConnData: &ConnectionData{
			Device:     server,
			RemoteAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 62207},
		},
		InitTime: receivedAtNanos,
	})
	if err != nil {
		t.Fatalf("decrypt external relay packet: %v", err)
	}
	if ppd == nil || !bytes.Equal(ppd.BodyMessage, message) {
		t.Fatalf("external relay body mismatch: ppd=%#v", ppd)
	}
	if ppd.LocalInitTime != receivedAtNanos {
		t.Fatalf("LocalInitTime = %d, want preserved receipt %d", ppd.LocalInitTime, receivedAtNanos)
	}
}

func TestRelayExternalPacketCapacityFailsWithoutPanic(t *testing.T) {
	relay := NewDevice(NHP_RELAY, relayBufferTestKey(0x51), nil)
	server := NewDevice(NHP_SERVER, relayBufferTestKey(0x61), nil)
	serverPub, err := base64.StdEncoding.DecodeString(server.PublicKeyBase64())
	if err != nil {
		t.Fatal(err)
	}
	_, err = relay.MsgToPacket(&MsgData{
		RemoteAddr:     &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 62206},
		PeerPk:         serverPub,
		HeaderType:     NHP_RLY,
		TransactionId:  88,
		Message:        bytes.Repeat([]byte{0x5A}, 4000),
		ExternalPacket: &Packet{Content: make([]byte, PacketBufferSize)},
	})
	if !errors.Is(err, ErrPacketSizeExceedsBuffer) {
		t.Fatalf("undersized external packet error = %v, want ErrPacketSizeExceedsBuffer", err)
	}
}

func TestRelayExternalPacketTooSmallFailsBeforeHeaderAccess(t *testing.T) {
	relay := NewDevice(NHP_RELAY, relayBufferTestKey(0x71), nil)
	server := NewDevice(NHP_SERVER, relayBufferTestKey(0x81), nil)
	serverPub, err := base64.StdEncoding.DecodeString(server.PublicKeyBase64())
	if err != nil {
		t.Fatal(err)
	}
	_, err = relay.MsgToPacket(&MsgData{
		PeerPk:         serverPub,
		HeaderType:     NHP_RLY,
		Message:        []byte("x"),
		ExternalPacket: &Packet{Content: make([]byte, 1)},
	})
	if !errors.Is(err, ErrPacketSizeExceedsBuffer) {
		t.Fatalf("too-small external packet error = %v, want ErrPacketSizeExceedsBuffer", err)
	}
}

func TestExpandedExternalPacketIsRelayEnvelopeOnly(t *testing.T) {
	server := NewDevice(NHP_SERVER, relayBufferTestKey(0x91), nil)
	serverPub, err := base64.StdEncoding.DecodeString(server.PublicKeyBase64())
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name       string
		deviceType int
		headerType int
	}{
		{name: "direct agent knock", deviceType: NHP_AGENT, headerType: NHP_KNK},
		{name: "agent keepalive", deviceType: NHP_AGENT, headerType: NHP_KPL},
		{name: "unrelated relay ack", deviceType: NHP_RELAY, headerType: NHP_ACK},
		{name: "server-originated relay forward", deviceType: NHP_SERVER, headerType: NHP_RLY},
	}
	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dev := NewDevice(tc.deviceType, relayBufferTestKey(byte(0xA0+i)), nil)
			_, err := dev.MsgToPacket(&MsgData{
				PeerPk:         serverPub,
				HeaderType:     tc.headerType,
				Message:        []byte("x"),
				ExternalPacket: NewRelayPacket(),
			})
			if !errors.Is(err, ErrPacketSizeExceedsBuffer) {
				t.Fatalf("expanded non-envelope packet error = %v, want ErrPacketSizeExceedsBuffer", err)
			}
		})
	}
}

func TestCreateMsgAssemblerDataWithPrevHonorsExternalPacket(t *testing.T) {
	dev := NewDevice(NHP_SERVER, relayBufferTestKey(0xB1), nil)
	t.Cleanup(dev.Stop)
	external := NewRelayPacket()
	mad, err := dev.createMsgAssemblerData(&MsgData{
		HeaderType: NHP_ACK,
		PrevParserData: &PacketParserData{
			device:       dev,
			HeaderType:   NHP_RLY,
			CipherScheme: 0,
			Ciphers:      NewCipherSuite(),
			RemotePubKey: testPeerPk(),
			SenderTrxId:  99,
		},
		ExternalPacket: external,
	})
	if err != nil {
		t.Fatalf("createMsgAssemblerData: %v", err)
	}
	if mad.BasePacket != external {
		t.Fatal("PrevParserData path ignored the caller-provided external packet")
	}
	mad.Destroy()
	if external.Buf != nil || cap(external.Content) != RelayPacketBufferSize {
		t.Fatal("destroy unexpectedly treated the external packet as pool-owned")
	}
}
