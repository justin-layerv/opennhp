package utils

import (
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
