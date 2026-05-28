package core

import (
	"net"
	"strings"
	"testing"
	"time"
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

func TestUdpPeerCheckRecvAddress(t *testing.T) {
	now := int64(100 * time.Second)
	withinHoldTime := now + int64(time.Second)
	// CheckRecvAddress uses strict >, so this is one nanosecond past the boundary.
	afterHoldTime := now + MinimalPeerAddressHoldTime*int64(time.Second) + 1
	var typedNilUDPAddr *net.UDPAddr

	tests := []struct {
		name     string
		recvAddr *net.UDPAddr
		currAddr net.Addr
		currTime int64
		want     bool
	}{
		{
			name:     "hold time expired accepts new address",
			currAddr: &net.UDPAddr{IP: net.ParseIP("10.0.0.4"), Port: 62206},
			currTime: afterHoldTime,
			want:     true,
		},
		{
			name:     "hold time expired ignores previous recv address",
			recvAddr: &net.UDPAddr{IP: net.ParseIP("10.0.0.3"), Port: 62206},
			currAddr: &net.UDPAddr{IP: net.ParseIP("10.0.0.4"), Port: 62207},
			currTime: afterHoldTime,
			want:     true,
		},
		{
			name:     "matching recv address within hold time",
			recvAddr: &net.UDPAddr{IP: net.ParseIP("10.0.0.3"), Port: 62206},
			currAddr: &net.UDPAddr{IP: net.ParseIP("10.0.0.3"), Port: 62206},
			currTime: withinHoldTime,
			want:     true,
		},
		{
			name:     "IPv4 byte representation mismatch still matches",
			recvAddr: &net.UDPAddr{IP: net.IP{10, 0, 0, 3}, Port: 62206},
			currAddr: &net.UDPAddr{IP: net.ParseIP("10.0.0.3"), Port: 62206},
			currTime: withinHoldTime,
			want:     true,
		},
		{
			name:     "different IP rejected within hold time",
			recvAddr: &net.UDPAddr{IP: net.ParseIP("10.0.0.3"), Port: 62206},
			currAddr: &net.UDPAddr{IP: net.ParseIP("10.0.0.4"), Port: 62206},
			currTime: withinHoldTime,
			want:     false,
		},
		{
			name:     "different port rejected within hold time",
			recvAddr: &net.UDPAddr{IP: net.ParseIP("10.0.0.3"), Port: 62206},
			currAddr: &net.UDPAddr{IP: net.ParseIP("10.0.0.3"), Port: 62207},
			currTime: withinHoldTime,
			want:     false,
		},
		{
			name:     "scoped IPv6 zone mismatch rejected within hold time",
			recvAddr: &net.UDPAddr{IP: net.ParseIP("fe80::1"), Port: 62206, Zone: "en0"},
			currAddr: &net.UDPAddr{IP: net.ParseIP("fe80::1"), Port: 62206, Zone: "en1"},
			currTime: withinHoldTime,
			want:     false,
		},
		{
			name:     "non UDP address rejected within hold time",
			recvAddr: &net.UDPAddr{IP: net.ParseIP("10.0.0.3"), Port: 62206},
			currAddr: &net.IPAddr{IP: net.ParseIP("10.0.0.3")},
			currTime: withinHoldTime,
			want:     false,
		},
		{
			name:     "nil recv address rejected within hold time",
			currAddr: &net.UDPAddr{IP: net.ParseIP("10.0.0.3"), Port: 62206},
			currTime: withinHoldTime,
			want:     false,
		},
		{
			name:     "nil current address rejected within hold time",
			recvAddr: &net.UDPAddr{IP: net.ParseIP("10.0.0.3"), Port: 62206},
			currTime: withinHoldTime,
			want:     false,
		},
		{
			name:     "typed nil UDP address rejected within hold time",
			recvAddr: &net.UDPAddr{IP: net.ParseIP("10.0.0.3"), Port: 62206},
			currAddr: typedNilUDPAddr,
			currTime: withinHoldTime,
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &UdpPeer{lastRecvTime: now, recvAddr: tt.recvAddr}
			if got := p.CheckRecvAddress(tt.currTime, tt.currAddr); got != tt.want {
				t.Fatalf("CheckRecvAddress() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUdpPeerCheckRecvAddressHotPathDoesNotAllocate(t *testing.T) {
	now := int64(100 * time.Second)
	currTime := now + int64(time.Second)
	addr := &net.UDPAddr{IP: net.ParseIP("10.0.0.3"), Port: 62206}
	p := &UdpPeer{lastRecvTime: now, recvAddr: addr}

	if !p.CheckRecvAddress(currTime, addr) {
		t.Fatal("CheckRecvAddress() = false, want true")
	}

	allocs := testing.AllocsPerRun(1000, func() {
		_ = p.CheckRecvAddress(currTime, addr)
	})
	if allocs != 0 {
		t.Fatalf("CheckRecvAddress() allocs = %v, want 0", allocs)
	}
}

func BenchmarkUdpPeerCheckRecvAddress(b *testing.B) {
	now := int64(100 * time.Second)
	addr := &net.UDPAddr{IP: net.ParseIP("10.0.0.3"), Port: 62206}

	b.Run("hold_time_expired", func(b *testing.B) {
		p := &UdpPeer{lastRecvTime: now, recvAddr: addr}
		currTime := now + MinimalPeerAddressHoldTime*int64(time.Second) + 1

		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if !p.CheckRecvAddress(currTime, addr) {
				b.Fatal("CheckRecvAddress() = false, want true")
			}
		}
	})

	b.Run("hot_recv_match", func(b *testing.B) {
		p := &UdpPeer{lastRecvTime: now, recvAddr: addr}
		currTime := now + int64(time.Second)

		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if !p.CheckRecvAddress(currTime, addr) {
				b.Fatal("CheckRecvAddress() = false, want true")
			}
		}
	})
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
