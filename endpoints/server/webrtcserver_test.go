package server

import (
	"bytes"
	"testing"

	"github.com/OpenNHP/opennhp/nhp/core"
)

func TestPacketFromWebRTCMessagePreservesReceipt(t *testing.T) {
	device := core.NewDevice(core.NHP_SERVER, testPrivateKey(), nil)
	if device == nil {
		t.Fatal("create server device")
	}
	data := bytes.Repeat([]byte{0x7a}, core.RelayPacketMinimalLength)
	const receivedAtNanos = int64(987654321)

	pkt := packetFromWebRTCMessage(device, data, receivedAtNanos)
	if pkt == nil {
		t.Fatal("valid WebRTC binary message was rejected")
	}
	if pkt.ReceivedAtNanos != receivedAtNanos || !bytes.Equal(pkt.Content, data) {
		t.Fatalf("packet receipt=%d content_equal=%v, want %d and true", pkt.ReceivedAtNanos, bytes.Equal(pkt.Content, data), receivedAtNanos)
	}
	data[0] ^= 0xff
	if bytes.Equal(pkt.Content, data) {
		t.Fatal("packet retained the caller's mutable WebRTC message buffer")
	}
	device.ReleasePoolPacket(pkt)
	if pkt.ReceivedAtNanos != 0 {
		t.Fatalf("released WebRTC packet retained receipt %d", pkt.ReceivedAtNanos)
	}
}

func TestPacketFromWebRTCMessageRejectsInvalidBounds(t *testing.T) {
	device := core.NewDevice(core.NHP_SERVER, testPrivateKey(), nil)
	if device == nil {
		t.Fatal("create server device")
	}
	for name, tc := range map[string]struct {
		data    []byte
		receipt int64
	}{
		"missing receipt": {data: make([]byte, core.RelayPacketMinimalLength), receipt: 0},
		"too short":       {data: make([]byte, core.RelayPacketMinimalLength-1), receipt: 1},
		"too large":       {data: make([]byte, core.PacketBufferSize+1), receipt: 1},
	} {
		t.Run(name, func(t *testing.T) {
			if pkt := packetFromWebRTCMessage(device, tc.data, tc.receipt); pkt != nil {
				device.ReleasePoolPacket(pkt)
				t.Fatal("invalid WebRTC message was admitted")
			}
		})
	}
}
