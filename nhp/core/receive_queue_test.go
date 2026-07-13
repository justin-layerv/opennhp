package core

import (
	"bytes"
	"testing"
)

func TestRecvPacketToMsgFullQueueReportsAndReleasesPacket(t *testing.T) {
	d := NewDevice(NHP_SERVER, bytes.Repeat([]byte{0x42}, PrivateKeySize), nil)
	if d == nil {
		t.Fatal("NewDevice returned nil")
	}
	d.packetToMsgQueue = make(chan *PacketData, 1)
	d.packetToMsgQueue <- &PacketData{}

	var got ReceiveQueueDrop
	d.SetReceiveQueueDropHook(func(reason ReceiveQueueDrop) { got = reason })
	pkt := d.AllocatePoolPacket()
	if pkt == nil || !pkt.PoolAllocated {
		t.Fatal("failed to allocate pool packet")
	}
	if d.RecvPacketToMsg(&PacketData{BasePacket: pkt}) {
		t.Fatal("full decrypt queue admitted packet")
	}
	if got != ReceiveQueueDropDecrypt {
		t.Fatalf("drop reason = %q, want %q", got, ReceiveQueueDropDecrypt)
	}
	if pkt.Buf != nil || pkt.Content != nil {
		t.Fatal("rejected packet was not returned to the device pool")
	}
}

func TestReceiveQueueDepths(t *testing.T) {
	d := NewDevice(NHP_SERVER, bytes.Repeat([]byte{0x43}, PrivateKeySize), nil)
	if d == nil {
		t.Fatal("NewDevice returned nil")
	}
	d.packetToMsgQueue <- &PacketData{}
	d.DecryptedMsgQueue <- &PacketParserData{}
	decrypt, decrypted := d.ReceiveQueueDepths()
	if decrypt != 1 || decrypted != 1 {
		t.Fatalf("ReceiveQueueDepths = (%d, %d), want (1, 1)", decrypt, decrypted)
	}
}
