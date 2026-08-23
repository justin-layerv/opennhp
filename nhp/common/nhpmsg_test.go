package common

import (
	"encoding/json"
	"reflect"
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

// TestServerACOpsMsg_QurlV2Metadata_RoundTrip proves the qURL v2 revocation
// metadata (P4a) survives a marshal/unmarshal cycle of the ac<->server AOP wire
// with the exact values intact, so the AC reads back what the server stamped.
// If a JSON tag is ever renamed on one side only, this catches it.
func TestServerACOpsMsg_QurlV2Metadata_RoundTrip(t *testing.T) {
	orig := &ServerACOpsMsg{
		SessionId:        0x0123456789abcdef,
		UserId:           "u",
		AuthServiceId:    "asp",
		ResourceId:       "res",
		SourceAddrs:      []*NetAddress{{Ip: "203.0.113.9", Port: 5555}},
		DestinationAddrs: []*NetAddress{{Ip: "10.0.0.5", Port: 8443}},
		OpenTime:         60,

		QurlUserPublicKeyHash: "a1b2c3",
		ResourcePublicKeyHash: "d4e5f6",
		QurlSessionId:         "sess_123",
		AdmissionId:           "adm_test123",
		RevocationEpoch:       42,
		Deadline:              1781910300,
	}

	b, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got ServerACOpsMsg
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if got.QurlUserPublicKeyHash != orig.QurlUserPublicKeyHash {
		t.Errorf("QurlUserPublicKeyHash = %q, want %q", got.QurlUserPublicKeyHash, orig.QurlUserPublicKeyHash)
	}
	if got.SessionId != orig.SessionId {
		t.Errorf("NHP SessionId = %#x, want %#x", got.SessionId, orig.SessionId)
	}
	if got.ResourcePublicKeyHash != orig.ResourcePublicKeyHash {
		t.Errorf("ResourcePublicKeyHash = %q, want %q", got.ResourcePublicKeyHash, orig.ResourcePublicKeyHash)
	}
	if got.QurlSessionId != orig.QurlSessionId {
		t.Errorf("QurlSessionId = %q, want %q", got.QurlSessionId, orig.QurlSessionId)
	}
	if got.AdmissionId != orig.AdmissionId {
		t.Errorf("AdmissionId = %q, want %q", got.AdmissionId, orig.AdmissionId)
	}
	if got.RevocationEpoch != orig.RevocationEpoch {
		t.Errorf("RevocationEpoch = %d, want %d", got.RevocationEpoch, orig.RevocationEpoch)
	}
	if got.Deadline != orig.Deadline {
		t.Errorf("Deadline = %d, want %d", got.Deadline, orig.Deadline)
	}
}

// TestServerACOpsMsg_LegacyAOP_OmitsQurlV2Metadata is the load-bearing
// legacy-safety test for P4a: a legacy / non-qURL-v2 AOP leaves the six new
// fields zero-valued, and because they are all omitempty the marshaled wire
// MUST NOT contain their JSON keys at all. This is what keeps the AOP
// byte-identical for pre-v2 servers and ACs — a round-trip test alone does not
// prove it. If anyone drops an omitempty (or adds a non-omitempty field), the
// presence check here fails.
func TestServerACOpsMsg_LegacyAOP_OmitsQurlV2Metadata(t *testing.T) {
	legacy := &ServerACOpsMsg{
		UserId:           "u",
		AuthServiceId:    "asp",
		ResourceId:       "res",
		SourceAddrs:      []*NetAddress{{Ip: "203.0.113.9", Port: 5555}},
		DestinationAddrs: []*NetAddress{{Ip: "10.0.0.5", Port: 8443}},
		OpenTime:         60,
		// qURL v2 fields intentionally left zero — this is the legacy shape.
	}

	b, err := json.Marshal(legacy)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	wire := string(b)

	for _, key := range []string{
		"qurlUsrPubKeyHash",
		"resPubKeyHash",
		"sessId",
		"admId",
		"revEpoch",
		"deadline",
	} {
		if strings.Contains(wire, key) {
			t.Errorf("legacy AOP wire must omit qURL v2 key %q (omitempty regression), got: %s", key, wire)
		}
	}
}

func TestServerListResultMsg_RetryAfterSecondsWireCompatibility(t *testing.T) {
	t.Run("absent field preserves legacy JSON", func(t *testing.T) {
		msg := ServerListResultMsg{
			ErrCode:     ErrSuccess.ErrorCode(),
			ListResults: map[string]any{"resource": "allowed"},
		}
		got, err := json.Marshal(msg)
		if err != nil {
			t.Fatalf("marshal legacy LRT: %v", err)
		}
		const want = `{"errCode":"0","list":{"resource":"allowed"}}`
		if string(got) != want {
			t.Fatalf("legacy LRT JSON = %s, want byte-exact %s", got, want)
		}
	})

	t.Run("positive field emits and round trips", func(t *testing.T) {
		retryAfter := uint32(17)
		msg := ServerListResultMsg{
			ErrCode:           ErrAssignmentUnavailable.ErrorCode(),
			RetryAfterSeconds: &retryAfter,
		}
		got, err := json.Marshal(msg)
		if err != nil {
			t.Fatalf("marshal LRT with retry hint: %v", err)
		}
		const want = `{"errCode":"52200","retryAfterSeconds":17}`
		if string(got) != want {
			t.Fatalf("LRT JSON = %s, want %s", got, want)
		}

		var roundTrip ServerListResultMsg
		if err := json.Unmarshal(got, &roundTrip); err != nil {
			t.Fatalf("unmarshal LRT with retry hint: %v", err)
		}
		if roundTrip.RetryAfterSeconds == nil || *roundTrip.RetryAfterSeconds != retryAfter {
			t.Fatalf("round-trip retryAfterSeconds = %v, want %d", roundTrip.RetryAfterSeconds, retryAfter)
		}
	})
}

// TestServerACOpsMsg_V2AOP_EmitsExpectedKeys pins the on-wire JSON tag names for
// the populated path, so the server stamper and the AC reader cannot drift to
// different keys without a test failing. (RevocationEpoch is omitempty, so 0 is
// absent; a non-zero value is asserted present.)
func TestServerACOpsMsg_V2AOP_EmitsExpectedKeys(t *testing.T) {
	v2 := &ServerACOpsMsg{
		QurlUserPublicKeyHash: "a1b2c3",
		ResourcePublicKeyHash: "d4e5f6",
		QurlSessionId:         "sess_123",
		AdmissionId:           "adm_test123",
		RevocationEpoch:       42,
		Deadline:              1781910300,
	}
	b, err := json.Marshal(v2)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	wire := string(b)
	for _, key := range []string{
		`"qurlUsrPubKeyHash":"a1b2c3"`,
		`"resPubKeyHash":"d4e5f6"`,
		`"qurlSessId":"sess_123"`,
		`"admId":"adm_test123"`,
		`"revEpoch":42`,
		`"deadline":1781910300`,
	} {
		if !strings.Contains(wire, key) {
			t.Errorf("populated AOP wire missing %s, got: %s", key, wire)
		}
	}
}

func TestServerForwardMsg_AdmissionRevocationDataWireCompat(t *testing.T) {
	legacy := &ServerForwardMsg{
		KnockData:     []byte("knock"),
		SourceServer:  "srv-a",
		UserAddr:      "203.0.113.10:54321",
		TransactionId: 1,
		Timestamp:     1781910000,
	}
	legacyBytes, err := json.Marshal(legacy)
	if err != nil {
		t.Fatalf("marshal legacy forward: %v", err)
	}
	if strings.Contains(string(legacyBytes), "admissionRevocationData") {
		t.Fatalf("legacy forward wire must omit admissionRevocationData, got: %s", legacyBytes)
	}
	if strings.Contains(string(legacyBytes), "resolvedResourceData") {
		t.Fatalf("legacy forward wire must omit resolvedResourceData, got: %s", legacyBytes)
	}

	v2 := &ServerForwardMsg{
		KnockData:     []byte("knock"),
		SourceServer:  "srv-a",
		UserAddr:      "203.0.113.10:54321",
		TransactionId: 1,
		Timestamp:     1781910000,
		SessionId:     0x0123456789abcdef,
		AdmissionRevocationData: &ForwardAdmissionRevocationData{
			QurlUserPublicKeyHash: "qhash",
			ResourcePublicKeyHash: "rhash",
			QurlSessionId:         "sess-live",
			AdmissionId:           "adm-123",
			Deadline:              1781910300,
		},
		ResolvedResourceData: &ForwardResolvedResourceData{
			AuthServiceId:         "qurl",
			ResourceId:            "q_123456789ab",
			OpenTime:              300,
			ResourcePublicKeyHash: "rhash",
			Resources: map[string]*ResourceInfo{
				"ac-a": {
					ACId:     "ac-a",
					Hostname: "resource.example",
					Addr:     &NetAddress{Port: 443, Protocol: "tcp"},
				},
			},
		},
	}
	v2Bytes, err := json.Marshal(v2)
	if err != nil {
		t.Fatalf("marshal v2 forward: %v", err)
	}
	wire := string(v2Bytes)
	for _, want := range []string{
		`"admissionRevocationData":`,
		`"sessId":81985529216486895`,
		`"qurlUsrPubKeyHash":"qhash"`,
		`"resPubKeyHash":"rhash"`,
		`"qurlSessId":"sess-live"`,
		`"admId":"adm-123"`,
		`"deadline":1781910300`,
		`"resolvedResourceData":`,
		`"aspId":"qurl"`,
		`"resId":"q_123456789ab"`,
		`"opnTime":300`,
		`"resInfo":`,
	} {
		if !strings.Contains(wire, want) {
			t.Fatalf("forward wire missing %s, got: %s", want, wire)
		}
	}
	var roundTrip ServerForwardMsg
	if err := json.Unmarshal(v2Bytes, &roundTrip); err != nil {
		t.Fatalf("unmarshal v2 forward: %v", err)
	}
	if roundTrip.SessionId != v2.SessionId {
		t.Fatalf("forward NHP SessionId = %#x, want %#x", roundTrip.SessionId, v2.SessionId)
	}
	if roundTrip.AdmissionRevocationData == nil {
		t.Fatalf("unmarshaled v2 forward lost admissionRevocationData: %+v", roundTrip)
	}
	if !reflect.DeepEqual(roundTrip.AdmissionRevocationData, v2.AdmissionRevocationData) {
		t.Fatalf("unmarshaled admissionRevocationData = %+v, want %+v", roundTrip.AdmissionRevocationData, v2.AdmissionRevocationData)
	}
	if !reflect.DeepEqual(roundTrip.ResolvedResourceData, v2.ResolvedResourceData) {
		t.Fatalf("unmarshaled resolvedResourceData = %+v, want %+v", roundTrip.ResolvedResourceData, v2.ResolvedResourceData)
	}
}
