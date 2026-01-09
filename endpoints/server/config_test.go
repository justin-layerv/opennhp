package server

import (
	"testing"
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
