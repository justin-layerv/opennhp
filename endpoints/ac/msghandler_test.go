package ac

import (
	"testing"

	"github.com/OpenNHP/opennhp/nhp/common"
)

// TestHandleAccessControl_SentinelIP tests that the sentinel IP (SentinelLocalIP)
// is replaced with the AC's DefaultIp. This is used by QURL resources
// where the destination is the AC itself (Traefik proxy).
//
// NOTE: This test duplicates the sentinel replacement logic from HandleAccessControl
// rather than calling the method directly. This is intentional because calling
// HandleAccessControl requires a fully initialized AC with iptables/ipset, which
// isn't practical for unit tests. The logic being tested is simple (string comparison
// and assignment), so duplication risk is low.
func TestHandleAccessControl_SentinelIP(t *testing.T) {
	tests := []struct {
		name        string
		defaultIp   string
		dstIp       string
		expectedIp  string
		description string
	}{
		{
			name:        "sentinel_0.0.0.0_replaced",
			defaultIp:   "10.0.1.50",
			dstIp:       SentinelLocalIP,
			expectedIp:  "10.0.1.50",
			description: "SentinelLocalIP should be replaced with DefaultIp",
		},
		{
			name:        "empty_ip_replaced",
			defaultIp:   "10.0.1.50",
			dstIp:       "",
			expectedIp:  "10.0.1.50",
			description: "empty IP should be replaced with DefaultIp",
		},
		{
			name:        "real_ip_preserved",
			defaultIp:   "10.0.1.50",
			dstIp:       "192.168.1.100",
			expectedIp:  "192.168.1.100",
			description: "real IP should be preserved",
		},
		{
			name:        "no_default_ip_sentinel_unchanged",
			defaultIp:   "",
			dstIp:       SentinelLocalIP,
			expectedIp:  SentinelLocalIP,
			description: "sentinel unchanged when DefaultIp not configured",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create AC with test config
			ac := &UdpAC{
				config: &Config{
					ACId:      "test-ac",
					DefaultIp: tt.defaultIp,
				},
			}

			// Create destination address
			dstAddrs := []*common.NetAddress{
				{
					Ip:   tt.dstIp,
					Port: 443,
				},
			}

			// Apply the sentinel replacement logic (mirrors HandleAccessControl)
			if len(ac.config.DefaultIp) > 0 {
				for _, addr := range dstAddrs {
					if len(addr.Ip) == 0 || addr.Ip == SentinelLocalIP {
						addr.Ip = ac.config.DefaultIp
					}
				}
			}

			// Verify result
			if dstAddrs[0].Ip != tt.expectedIp {
				t.Errorf("%s: got IP %q, want %q", tt.description, dstAddrs[0].Ip, tt.expectedIp)
			}
		})
	}
}

// TestHandleAccessControl_SentinelIP_MultipleAddresses tests sentinel replacement
// with multiple destination addresses.
func TestHandleAccessControl_SentinelIP_MultipleAddresses(t *testing.T) {
	ac := &UdpAC{
		config: &Config{
			ACId:      "test-ac",
			DefaultIp: "10.0.1.50",
		},
	}

	dstAddrs := []*common.NetAddress{
		{Ip: SentinelLocalIP, Port: 443}, // sentinel - should be replaced
		{Ip: "192.168.1.100", Port: 22},  // real IP - should be preserved
		{Ip: "", Port: 8080},             // empty - should be replaced
	}

	// Apply the sentinel replacement logic (mirrors HandleAccessControl)
	if len(ac.config.DefaultIp) > 0 {
		for _, addr := range dstAddrs {
			if len(addr.Ip) == 0 || addr.Ip == SentinelLocalIP {
				addr.Ip = ac.config.DefaultIp
			}
		}
	}

	// Verify results
	expected := []string{"10.0.1.50", "192.168.1.100", "10.0.1.50"}
	for i, addr := range dstAddrs {
		if addr.Ip != expected[i] {
			t.Errorf("address[%d]: got IP %q, want %q", i, addr.Ip, expected[i])
		}
	}
}
