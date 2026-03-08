package core

import (
	"strings"
	"testing"
)

func TestUdpPeerName(t *testing.T) {
	tests := []struct {
		name         string
		pubKeyBase64 string
		want         string
	}{
		{
			name:         "empty PubKeyBase64",
			pubKeyBase64: "",
			want:         "unknown",
		},
		{
			name:         "short PubKeyBase64 less than 43 chars",
			pubKeyBase64: "abc",
			want:         "abc",
		},
		{
			name:         "single char PubKeyBase64",
			pubKeyBase64: "X",
			want:         "X",
		},
		{
			name:         "exactly 43 chars PubKeyBase64",
			pubKeyBase64: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq",
			want:         "ABCD...nopq",
		},
		{
			name:         "full length base64 key 44 chars",
			pubKeyBase64: "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=",
			want:         "YWJj...0NTY",
		},
		{
			name:         "42 chars is still short",
			pubKeyBase64: strings.Repeat("A", 42),
			want:         strings.Repeat("A", 42),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &UdpPeer{PubKeyBase64: tt.pubKeyBase64}
			got := p.Name()
			if got != tt.want {
				t.Fatalf("Name() = %q, want %q", got, tt.want)
			}
			// Call again to verify cached result
			got2 := p.Name()
			if got2 != tt.want {
				t.Fatalf("Name() second call = %q, want %q", got2, tt.want)
			}
		})
	}
}
