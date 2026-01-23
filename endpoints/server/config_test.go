package server

import (
	"testing"

	"github.com/OpenNHP/opennhp/nhp/common"
)

func TestParseACRegistryEntry(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
		check   func(*ACRegistryEntry) bool
	}{
		{
			name: "valid TOML entry",
			input: `# AC Registry Entry
PublicKey = "dGVzdHB1YmtleWJhc2U2NA=="
InstanceId = "i-1234567890abcdef0"
Ip = "10.0.0.100"
Port = 62206
RegisteredAt = 1703980800
`,
			wantErr: false,
			check: func(e *ACRegistryEntry) bool {
				return e.PublicKey == "dGVzdHB1YmtleWJhc2U2NA==" &&
					e.InstanceId == "i-1234567890abcdef0" &&
					e.Ip == "10.0.0.100" &&
					e.Port == 62206 &&
					e.RegisteredAt == 1703980800
			},
		},
		{
			name:    "invalid TOML",
			input:   `not valid toml [[[`,
			wantErr: true,
		},
		{
			name: "minimal entry",
			input: `PublicKey = "abc123"
InstanceId = "i-test"
`,
			wantErr: false,
			check: func(e *ACRegistryEntry) bool {
				return e.PublicKey == "abc123" && e.InstanceId == "i-test"
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry, err := parseACRegistryEntry([]byte(tt.input))
			if (err != nil) != tt.wantErr {
				t.Errorf("parseACRegistryEntry() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && tt.check != nil && !tt.check(entry) {
				t.Errorf("parseACRegistryEntry() check failed, got %+v", entry)
			}
		})
	}
}

func TestACRegistryPrefix(t *testing.T) {
	if ACRegistryPrefix != "/nhp/ac-registry/" {
		t.Errorf("ACRegistryPrefix = %q, want %q", ACRegistryPrefix, "/nhp/ac-registry/")
	}
}

func TestUpdateResources_NilAspData(t *testing.T) {
	// This test verifies that updateResources handles nil aspData entries gracefully.
	// TOML unmarshals empty tables (e.g., "[passcode]" with no fields) as nil pointers.
	// The server should skip these entries without panicking.

	s := &UdpServer{}

	// Create a map with nil entry (simulates TOML empty table)
	aspMap := common.AuthSvcProviderMap{
		"passcode": nil, // Simulate TOML empty table like "[passcode]\n# comment only"
	}

	// Should not panic
	err := s.updateResources(aspMap)
	if err != nil {
		t.Errorf("updateResources() unexpected error = %v", err)
	}

	// Verify the nil entry is preserved in the map (for static plugin lookup)
	if len(s.authServiceMap) != 1 {
		t.Errorf("authServiceMap length = %d, want 1", len(s.authServiceMap))
	}
}

func TestUpdateResources_MixedNilAndValid(t *testing.T) {
	// Test that valid entries are processed even when nil entries exist

	s := &UdpServer{}

	aspMap := common.AuthSvcProviderMap{
		"nil-plugin":   nil, // Empty table
		"valid-plugin": &common.AuthServiceProviderData{PluginPath: ""},
	}

	err := s.updateResources(aspMap)
	if err != nil {
		t.Errorf("updateResources() unexpected error = %v", err)
	}

	// Both entries should be in the map
	if len(s.authServiceMap) != 2 {
		t.Errorf("authServiceMap length = %d, want 2", len(s.authServiceMap))
	}

	// Valid entry should have AuthSvcId set
	if s.authServiceMap["valid-plugin"] != nil && s.authServiceMap["valid-plugin"].AuthSvcId != "valid-plugin" {
		t.Errorf("valid-plugin AuthSvcId = %q, want %q", s.authServiceMap["valid-plugin"].AuthSvcId, "valid-plugin")
	}
}
