package core

import (
	"net"
	"strings"
	"testing"
)

// MatchesIP gates the per-IP cap bypass for AC/DB conns in udpserver.go,
// so coverage of all three match conditions plus the negative cases is
// load-bearing for #1504.
func TestUdpPeerMatchesIP(t *testing.T) {
	tests := []struct {
		name              string
		ip                string
		primaryResolvedIp string
		recvAddr          *net.UDPAddr
		query             string
		want              bool
	}{
		{name: "matches static Ip", ip: "10.0.0.1", query: "10.0.0.1", want: true},
		{name: "matches primaryResolvedIp", primaryResolvedIp: "10.0.0.2", query: "10.0.0.2", want: true},
		{name: "matches recvAddr.IP", recvAddr: &net.UDPAddr{IP: net.ParseIP("10.0.0.3"), Port: 62206}, query: "10.0.0.3", want: true},
		{name: "no match", ip: "10.0.0.1", query: "10.0.0.99", want: false},
		{name: "empty Ip and unresolved hostname does not match", query: "10.0.0.1", want: false},
		{name: "static Ip set, recvAddr nil — no match on different IP", ip: "10.0.0.1", query: "10.0.0.2", want: false},
		{name: "recvAddr port differs but IP matches", recvAddr: &net.UDPAddr{IP: net.ParseIP("10.0.0.3"), Port: 9999}, query: "10.0.0.3", want: true},
		// Hostname-configured peers (Hostname set, Ip empty) miss the
		// gate until the first DNS resolve populates primaryResolvedIp
		// or the first recv populates recvAddr. Pinned because misclassifying
		// the first AC knock from a hostname-only peer would count it
		// against the agent cap. Discussed in #1504 review round 5.
		{name: "hostname-only configured peer pre-resolve does not match", query: "10.0.0.4", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &UdpPeer{Ip: tt.ip, primaryResolvedIp: tt.primaryResolvedIp, recvAddr: tt.recvAddr}
			if got := p.MatchesIP(tt.query); got != tt.want {
				t.Errorf("MatchesIP(%q) = %v, want %v", tt.query, got, tt.want)
			}
		})
	}
}

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
