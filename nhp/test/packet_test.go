package test

import (
	"fmt"
	"testing"

	core "github.com/OpenNHP/opennhp/nhp/core"
)

func TestHeaderTypeAndSize(t *testing.T) {
	pkt := &core.Packet{
		//Content: []byte{0x18, 0xca, 0xba, 0xa6, 0x18, 0xcb, 0xba, 0xa4},
		Content: []byte{91, 89, 55, 86, 91, 88, 55, 25},
	}

	tp, sz := pkt.HeaderTypeAndSize()

	fmt.Printf("Header type: %d, payload size: %d", tp, sz)
}
