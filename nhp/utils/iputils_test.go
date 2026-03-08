package utils

import (
	"fmt"
	"testing"
)

func TestIPv4ToIPv6Mapped(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"IPv4 address", "10.100.0.224", "::ffff:10.100.0.224"},
		{"IPv4 loopback", "127.0.0.1", "::ffff:127.0.0.1"},
		{"IPv6 address unchanged", "2601:500:8700:cd50::1", "2601:500:8700:cd50::1"},
		{"already mapped", "::ffff:10.0.0.1", "::ffff:10.0.0.1"},
		{"invalid returns as-is", "not-an-ip", "not-an-ip"},
		{"empty returns as-is", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IPv4ToIPv6Mapped(tt.input)
			if result != tt.expected {
				t.Errorf("IPv4ToIPv6Mapped(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestNormalizeIPSetEntry(t *testing.T) {
	tests := []struct {
		name     string
		ipType   IPTYPE
		entry    string
		expected string
	}{
		{
			"IPv4 entry unchanged for IPv4 set",
			IPV4,
			"192.168.1.1,443,10.100.0.224",
			"192.168.1.1,443,10.100.0.224",
		},
		{
			"IPv6 src + IPv4 dst mapped for IPv6 set",
			IPV6,
			"2601:500:8700:cd50:44d3:ccdc:cb51:8bc8,443,10.100.0.224",
			"2601:500:8700:cd50:44d3:ccdc:cb51:8bc8,443,::ffff:10.100.0.224",
		},
		{
			"all IPv6 unchanged for IPv6 set",
			IPV6,
			"2601:500::1,443,fd00::1",
			"2601:500::1,443,fd00::1",
		},
		{
			"both IPv4 mapped for IPv6 set",
			IPV6,
			"192.168.1.1,443,10.100.0.224",
			"::ffff:192.168.1.1,443,::ffff:10.100.0.224",
		},
		{
			"UDP protocol spec preserved",
			IPV6,
			"2601:500::1,udp:53,10.100.0.224",
			"2601:500::1,udp:53,::ffff:10.100.0.224",
		},
		{
			"port range preserved",
			IPV6,
			"2601:500::1,1-65535,10.100.0.224",
			"2601:500::1,1-65535,::ffff:10.100.0.224",
		},
		{
			"ICMP spec preserved",
			IPV6,
			"2601:500::1,icmpv6:128/0,10.100.0.224",
			"2601:500::1,icmpv6:128/0,::ffff:10.100.0.224",
		},
		{
			"entry with fewer than 3 parts unchanged",
			IPV6,
			"2601:500::1,443",
			"2601:500::1,443",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NormalizeIPSetEntry(tt.ipType, tt.entry)
			if result != tt.expected {
				t.Errorf("NormalizeIPSetEntry(%v, %q) = %q, want %q", tt.ipType, tt.entry, result, tt.expected)
			}
		})
	}
}

func TestICMPEchoType(t *testing.T) {
	tests := []struct {
		name     string
		ipType   IPTYPE
		expected string
	}{
		{"IPv4 uses icmp type 8", IPV4, "icmp:8/0"},
		{"IPv6 uses icmpv6 type 128", IPV6, "icmpv6:128/0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ICMPEchoType(tt.ipType)
			if result != tt.expected {
				t.Errorf("ICMPEchoType(%v) = %q, want %q", tt.ipType, result, tt.expected)
			}
		})
	}
}

func TestICMPHashString(t *testing.T) {
	tests := []struct {
		name     string
		srcIP    string
		dstIP    string
		ipType   IPTYPE
		expected string
	}{
		{
			"IPv4 ICMP hash uses icmp:8/0",
			"192.168.1.1",
			"10.0.0.1",
			IPV4,
			"192.168.1.1,icmp:8/0,10.0.0.1",
		},
		{
			"IPv6 ICMP hash uses icmpv6:128/0",
			"2001:db8::1",
			"2001:db8::2",
			IPV6,
			"2001:db8::1,icmpv6:128/0,2001:db8::2",
		},
		{
			"IPv6 loopback ICMP hash",
			"::1",
			"fd00::1",
			IPV6,
			"::1,icmpv6:128/0,fd00::1",
		},
		{
			"IPv6 link-local ICMP hash",
			"fe80::1",
			"fe80::2",
			IPV6,
			"fe80::1,icmpv6:128/0,fe80::2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ipHashStr := fmt.Sprintf("%s,%s,%s", tt.srcIP, ICMPEchoType(tt.ipType), tt.dstIP)
			if ipHashStr != tt.expected {
				t.Errorf("ICMP hash string = %q, want %q", ipHashStr, tt.expected)
			}
		})
	}
}

func TestICMPTempsetHashString(t *testing.T) {
	tests := []struct {
		name     string
		netStr   string
		ipType   IPTYPE
		expected string
	}{
		{
			"IPv4 tempset ICMP hash",
			"192.168.1.0/25",
			IPV4,
			"192.168.1.0/25,icmp:8/0",
		},
		{
			"IPv6 tempset ICMP hash",
			"2001:db8::/121",
			IPV6,
			"2001:db8::/121,icmpv6:128/0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			netHashStr := fmt.Sprintf("%s,%s", tt.netStr, ICMPEchoType(tt.ipType))
			if netHashStr != tt.expected {
				t.Errorf("tempset ICMP hash = %q, want %q", netHashStr, tt.expected)
			}
		})
	}
}

func TestICMPEchoTypeConsistencyWithNormalize(t *testing.T) {
	// Verify that ICMPEchoType output works correctly with NormalizeIPSetEntry
	tests := []struct {
		name     string
		srcIP    string
		dstIP    string
		ipType   IPTYPE
		expected string
	}{
		{
			"IPv6 ICMP entry normalizes correctly",
			"2001:db8::1",
			"2001:db8::2",
			IPV6,
			"2001:db8::1,icmpv6:128/0,2001:db8::2",
		},
		{
			"IPv6 ICMP entry with IPv4 dst gets mapped",
			"2001:db8::1",
			"10.0.0.1",
			IPV6,
			"2001:db8::1,icmpv6:128/0,::ffff:10.0.0.1",
		},
		{
			"IPv4 ICMP entry unchanged for IPv4 set",
			"192.168.1.1",
			"10.0.0.1",
			IPV4,
			"192.168.1.1,icmp:8/0,10.0.0.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := fmt.Sprintf("%s,%s,%s", tt.srcIP, ICMPEchoType(tt.ipType), tt.dstIP)
			result := NormalizeIPSetEntry(tt.ipType, raw)
			if result != tt.expected {
				t.Errorf("normalized ICMP entry = %q, want %q", result, tt.expected)
			}
		})
	}
}
