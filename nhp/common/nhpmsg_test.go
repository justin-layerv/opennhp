package common

import (
	"strings"
	"testing"
)

// TestRedirectTarget_Validate_HostnameOnlyRejected is the regression test
// for issue #832. The server's graceful-drain code emitted a RedirectTarget
// with Hostname set but IP empty. The old AC validation accepted it, then
// downstream consumer code that keyed on Target.IP silently broke. The
// contract now requires IP to be populated — Hostname is optional metadata
// only.
func TestRedirectTarget_Validate_HostnameOnlyRejected(t *testing.T) {
	target := RedirectTarget{
		Hostname:     "nlb.example.com",
		Port:         62206,
		PubKeyBase64: "c2hhcmVkLWtleQ==",
		// IP intentionally empty — this is the #832 shape
	}
	err := target.Validate()
	if err == nil {
		t.Fatal("expected hostname-only target to be rejected (#832 regression)")
	}
	if !strings.Contains(err.Error(), "IP is required") {
		t.Errorf("expected error to mention 'IP is required', got: %v", err)
	}
	if !strings.Contains(err.Error(), "#832") {
		t.Errorf("expected error to reference #832 for discoverability, got: %v", err)
	}
}

// TestRedirectTarget_Validate_AllRequiredFields covers every other field
// of the RedirectTarget contract.
func TestRedirectTarget_Validate_AllRequiredFields(t *testing.T) {
	tests := []struct {
		name      string
		target    RedirectTarget
		wantErr   bool
		errSubstr string
	}{
		{
			name: "all fields valid",
			target: RedirectTarget{
				IP:           "10.0.0.1",
				Port:         62206,
				PubKeyBase64: "c2hhcmVkLWtleQ==",
			},
			wantErr: false,
		},
		{
			name: "all fields valid with optional metadata",
			target: RedirectTarget{
				IP:           "10.0.0.1",
				Hostname:     "server-1.nhp.internal",
				Port:         62206,
				PubKeyBase64: "c2hhcmVkLWtleQ==",
				AZ:           "us-east-2a",
				ServerID:     "srv-abc",
			},
			wantErr: false,
		},
		{
			name: "ipv6 is valid",
			target: RedirectTarget{
				IP:           "2001:db8::1",
				Port:         62206,
				PubKeyBase64: "c2hhcmVkLWtleQ==",
			},
			wantErr: false,
		},
		{
			name: "empty IP rejected",
			target: RedirectTarget{
				IP:           "",
				Port:         62206,
				PubKeyBase64: "c2hhcmVkLWtleQ==",
			},
			wantErr:   true,
			errSubstr: "IP is required",
		},
		{
			name: "malformed IP rejected",
			target: RedirectTarget{
				IP:           "not-an-ip",
				Port:         62206,
				PubKeyBase64: "c2hhcmVkLWtleQ==",
			},
			wantErr:   true,
			errSubstr: "not a valid IP",
		},
		{
			name: "port zero rejected",
			target: RedirectTarget{
				IP:           "10.0.0.1",
				Port:         0,
				PubKeyBase64: "c2hhcmVkLWtleQ==",
			},
			wantErr:   true,
			errSubstr: "out of range",
		},
		{
			name: "negative port rejected",
			target: RedirectTarget{
				IP:           "10.0.0.1",
				Port:         -1,
				PubKeyBase64: "c2hhcmVkLWtleQ==",
			},
			wantErr:   true,
			errSubstr: "out of range",
		},
		{
			name: "port above 65535 rejected",
			target: RedirectTarget{
				IP:           "10.0.0.1",
				Port:         65536,
				PubKeyBase64: "c2hhcmVkLWtleQ==",
			},
			wantErr:   true,
			errSubstr: "out of range",
		},
		{
			name: "empty pubkey rejected",
			target: RedirectTarget{
				IP:           "10.0.0.1",
				Port:         62206,
				PubKeyBase64: "",
			},
			wantErr:   true,
			errSubstr: "PubKeyBase64 is required",
		},
		{
			name: "port 1 (min) accepted",
			target: RedirectTarget{
				IP:           "10.0.0.1",
				Port:         1,
				PubKeyBase64: "c2hhcmVkLWtleQ==",
			},
			wantErr: false,
		},
		{
			name: "port 65535 (max) accepted",
			target: RedirectTarget{
				IP:           "10.0.0.1",
				Port:         65535,
				PubKeyBase64: "c2hhcmVkLWtleQ==",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.target.Validate()
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.errSubstr)
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("expected error containing %q, got %q", tt.errSubstr, err.Error())
				}
			} else if err != nil {
				t.Errorf("expected no error, got: %v", err)
			}
		})
	}
}

func TestResourceInfo_DestHost_EmptyHostWithPortSuffix(t *testing.T) {
	res := &ResourceInfo{
		PortSuffix: true,
		Addr:       &NetAddress{Port: 7001, Protocol: "tcp"},
	}

	if got := res.DestHost(); got != "" {
		t.Fatalf("DestHost() = %q, want empty host rather than malformed :port", got)
	}
}

func TestResourceInfo_DestHost_PortSuffixWithZeroPort(t *testing.T) {
	res := &ResourceInfo{
		Hostname:   "connect.layerv.xyz",
		PortSuffix: true,
		Addr:       &NetAddress{Port: 0, Protocol: "tcp"},
	}

	if got := res.DestHost(); got != "" {
		t.Fatalf("DestHost() = %q, want empty host rather than silently dropping required port suffix", got)
	}
}
