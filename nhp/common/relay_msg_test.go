package common

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRelayForwardMsgRoundTrip(t *testing.T) {
	orig := &RelayForwardMsg{
		SourceAddr:  &NetAddress{Ip: "203.0.113.7", Port: 55321},
		InnerPacket: "AQIDBAUGBwg=", // base64 of arbitrary inner-packet bytes
	}
	b, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// Lock the on-wire field names -- the js-agent and the relay both serialize
	// against these exact tags.
	for _, key := range []string{`"srcAddr"`, `"innerPkt"`} {
		if !strings.Contains(string(b), key) {
			t.Errorf("marshaled RelayForwardMsg missing field %s: %s", key, b)
		}
	}

	var got RelayForwardMsg
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.InnerPacket != orig.InnerPacket {
		t.Errorf("InnerPacket = %q; want %q", got.InnerPacket, orig.InnerPacket)
	}
	if got.SourceAddr == nil || got.SourceAddr.Ip != orig.SourceAddr.Ip || got.SourceAddr.Port != orig.SourceAddr.Port {
		t.Errorf("SourceAddr = %+v; want %+v", got.SourceAddr, orig.SourceAddr)
	}
}
