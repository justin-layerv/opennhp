package server

import (
	"encoding/base64"
	"encoding/json"
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
IdentityDocument = "eyJhY2NvdW50SWQiOiIxMjM0NTY3ODkwMTIifQ=="
IdentitySignature = "c2lnbmF0dXJl"
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

func TestAWSIdentityDocument_Parse(t *testing.T) {
	doc := AWSIdentityDocument{
		AccountId:        "123456789012",
		InstanceId:       "i-1234567890abcdef0",
		PrivateIp:        "10.0.0.100",
		Region:           "us-east-2",
		AvailabilityZone: "us-east-2a",
	}

	// Test JSON marshaling/unmarshaling
	jsonBytes, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("Failed to marshal AWSIdentityDocument: %v", err)
	}

	var parsed AWSIdentityDocument
	if err := json.Unmarshal(jsonBytes, &parsed); err != nil {
		t.Fatalf("Failed to unmarshal AWSIdentityDocument: %v", err)
	}

	if parsed.AccountId != doc.AccountId {
		t.Errorf("AccountId mismatch: got %s, want %s", parsed.AccountId, doc.AccountId)
	}
	if parsed.InstanceId != doc.InstanceId {
		t.Errorf("InstanceId mismatch: got %s, want %s", parsed.InstanceId, doc.InstanceId)
	}
	if parsed.PrivateIp != doc.PrivateIp {
		t.Errorf("PrivateIp mismatch: got %s, want %s", parsed.PrivateIp, doc.PrivateIp)
	}
}

func TestVerifyAWSIdentity_MissingFields(t *testing.T) {
	tests := []struct {
		name    string
		entry   *ACRegistryEntry
		wantErr bool
	}{
		{
			name: "missing identity document",
			entry: &ACRegistryEntry{
				PublicKey:         "abc123",
				InstanceId:        "i-test",
				Ip:                "10.0.0.1",
				IdentityDocument:  "",
				IdentitySignature: "sig",
			},
			wantErr: true,
		},
		{
			name: "missing identity signature",
			entry: &ACRegistryEntry{
				PublicKey:         "abc123",
				InstanceId:        "i-test",
				Ip:                "10.0.0.1",
				IdentityDocument:  "doc",
				IdentitySignature: "",
			},
			wantErr: true,
		},
		{
			name: "invalid base64 document",
			entry: &ACRegistryEntry{
				PublicKey:         "abc123",
				InstanceId:        "i-test",
				Ip:                "10.0.0.1",
				IdentityDocument:  "not-valid-base64!!!",
				IdentitySignature: base64.StdEncoding.EncodeToString([]byte("sig")),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := verifyAWSIdentity(tt.entry)
			if (err != nil) != tt.wantErr {
				t.Errorf("verifyAWSIdentity() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestVerifyAWSIdentity_InstanceIdMismatch(t *testing.T) {
	// Create a valid JSON document but with mismatched instance ID
	doc := AWSIdentityDocument{
		InstanceId: "i-different",
		PrivateIp:  "10.0.0.1",
		AccountId:  "123456789012",
	}
	docBytes, _ := json.Marshal(doc)
	docB64 := base64.StdEncoding.EncodeToString(docBytes)
	sigB64 := base64.StdEncoding.EncodeToString([]byte("fake-sig"))

	entry := &ACRegistryEntry{
		PublicKey:         "abc123",
		InstanceId:        "i-mismatch",
		Ip:                "10.0.0.1",
		IdentityDocument:  docB64,
		IdentitySignature: sigB64,
	}

	_, err := verifyAWSIdentity(entry)
	if err == nil {
		t.Error("verifyAWSIdentity() should fail on instance ID mismatch")
	}
}

func TestVerifyAWSIdentity_IpMismatch(t *testing.T) {
	// Create a valid JSON document but with mismatched IP
	doc := AWSIdentityDocument{
		InstanceId: "i-test",
		PrivateIp:  "10.0.0.1",
		AccountId:  "123456789012",
	}
	docBytes, _ := json.Marshal(doc)
	docB64 := base64.StdEncoding.EncodeToString(docBytes)
	sigB64 := base64.StdEncoding.EncodeToString([]byte("fake-sig"))

	entry := &ACRegistryEntry{
		PublicKey:         "abc123",
		InstanceId:        "i-test",
		Ip:                "10.0.0.99", // Different IP
		IdentityDocument:  docB64,
		IdentitySignature: sigB64,
	}

	_, err := verifyAWSIdentity(entry)
	if err == nil {
		t.Error("verifyAWSIdentity() should fail on IP mismatch")
	}
}

func TestIsRunningInAWS_NonAWS(t *testing.T) {
	// When not in AWS, this should return false quickly
	result := isRunningInAWS()
	// On a non-AWS machine, this should be false
	// We can't assert false because the test might run in AWS
	t.Logf("isRunningInAWS() = %v", result)
}

func TestACRegistryPrefix(t *testing.T) {
	if ACRegistryPrefix != "/nhp/ac-registry/" {
		t.Errorf("ACRegistryPrefix = %q, want %q", ACRegistryPrefix, "/nhp/ac-registry/")
	}
}
