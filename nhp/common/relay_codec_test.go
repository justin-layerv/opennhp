package common

import (
	"encoding/base64"
	"testing"
)

func TestRelayRequestIDContract(t *testing.T) {
	id, err := NewRelayRequestID()
	if err != nil {
		t.Fatalf("NewRelayRequestID: %v", err)
	}
	if !ValidRelayRequestID(id) {
		t.Fatalf("generated request ID %q is invalid", id)
	}
	raw, err := base64.RawURLEncoding.DecodeString(id)
	if err != nil {
		t.Fatalf("decode generated request ID: %v", err)
	}
	if len(raw) != RelayRequestIDBytes {
		t.Fatalf("decoded request ID length = %d, want %d", len(raw), RelayRequestIDBytes)
	}
}

func TestValidRelayRequestIDRejectsWrongShape(t *testing.T) {
	for _, id := range []string{
		"",
		"not-base64!",
		"AQEBAQEBAQEBAQEBAQEBAQ==",
		"AQEBAQEBAQEBAQEBAQEBAR",
		"AQEBAQEBAQEBAQEBAQEBAQ\n",
		"AQEBAQEBAQEBAQEBAQEBAQ\r",
		base64.RawURLEncoding.EncodeToString(make([]byte, RelayRequestIDBytes-1)),
		base64.RawURLEncoding.EncodeToString(make([]byte, RelayRequestIDBytes+1)),
	} {
		if ValidRelayRequestID(id) {
			t.Errorf("ValidRelayRequestID(%q) = true, want false", id)
		}
	}
}

func TestDecodeRelayJSONStrict(t *testing.T) {
	type envelope struct {
		RequestID string `json:"requestId"`
	}
	for name, tc := range map[string]struct {
		input   string
		wantErr bool
	}{
		"one object":     {`{"requestId":"id"}`, false},
		"unknown field":  {`{"requestId":"id","extra":true}`, true},
		"trailing value": {`{"requestId":"id"} {"requestId":"second"}`, true},
	} {
		t.Run(name, func(t *testing.T) {
			var got envelope
			err := DecodeRelayJSONStrict([]byte(tc.input), &got)
			if (err != nil) != tc.wantErr {
				t.Fatalf("DecodeRelayJSONStrict() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}
