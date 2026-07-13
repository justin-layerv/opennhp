package core

import (
	"bytes"
	"errors"
	"testing"
)

func TestConsumeEncryptedPacketOwnership(t *testing.T) {
	if _, err := ConsumeEncryptedPacket(nil); err == nil {
		t.Fatal("nil assembler data accepted")
	}

	device := NewDevice(NHP_RELAY, bytes.Repeat([]byte{0x44}, 32), nil)

	t.Run("error releases packet", func(t *testing.T) {
		packet := device.AllocateRelayPacket()
		mad := &MsgAssemblerData{
			device:     device,
			BasePacket: packet,
			Error:      errors.New("forced encryption error"),
		}
		if _, err := ConsumeEncryptedPacket(mad); err == nil {
			t.Fatal("assembler error accepted")
		}
		if packet.Content != nil {
			t.Fatal("error result retained its pooled packet")
		}
	})

	t.Run("success clones before release", func(t *testing.T) {
		packet := device.AllocateRelayPacket()
		copy(packet.Content, "wire")
		packet.Content = packet.Content[:4]
		mad := &MsgAssemblerData{device: device, BasePacket: packet}

		wire, err := ConsumeEncryptedPacket(mad)
		if err != nil {
			t.Fatalf("ConsumeEncryptedPacket: %v", err)
		}
		if string(wire) != "wire" {
			t.Fatalf("wire = %q, want wire", wire)
		}
		if packet.Content != nil {
			t.Fatal("success result retained its pooled packet")
		}
	})

	t.Run("missing packet fails closed", func(t *testing.T) {
		mad := &MsgAssemblerData{device: device}
		if _, err := ConsumeEncryptedPacket(mad); err == nil {
			t.Fatal("missing packet accepted")
		}
	})
}

func TestMsgAssemblerDataDestroyRelayPacketIsIdempotent(t *testing.T) {
	device := NewDevice(NHP_RELAY, bytes.Repeat([]byte{0x45}, 32), nil)
	packet := device.AllocateRelayPacket()
	mad := &MsgAssemblerData{device: device, BasePacket: packet}

	mad.Destroy()
	if packet.Content != nil || packet.externalBuf != nil || packet.relayBuf != nil {
		t.Fatal("first Destroy retained relay-pool ownership")
	}

	// The cleared relayBuf is the exactly-once guard: the second Destroy cannot
	// Put the same backing array into relayPacketPool again.
	mad.Destroy()
	if packet.Content != nil || packet.externalBuf != nil || packet.relayBuf != nil {
		t.Fatal("second Destroy restored relay-pool ownership")
	}
}
