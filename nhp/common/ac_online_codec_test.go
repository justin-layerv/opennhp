package common

import (
	"strings"
	"testing"
)

const testACBootID = "00112233445566778899aabbccddeeff"

func TestDecodeACOnlineMsgSessionControlTuple(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		body    string
		wantErr string
	}{
		{name: "complete", body: `{"acId":"ac-1","bootId":"` + testACBootID + `","sessFlushGen":1,"sessFlushComplete":true}`},
		{name: "ordinary extension remains allowed", body: `{"acId":"ac-1","future":{},"bootId":"` + testACBootID + `","sessFlushGen":18446744073709551615,"sessFlushComplete":true}`},
		{name: "legacy tuple absent", body: `{"acId":"ac-1"}`},
		{name: "partial boot", body: `{"bootId":"` + testACBootID + `"}`, wantErr: "must contain"},
		{name: "partial generation", body: `{"sessFlushGen":1}`, wantErr: "must contain"},
		{name: "partial complete", body: `{"sessFlushComplete":true}`, wantErr: "must contain"},
		{name: "duplicate boot", body: `{"bootId":"` + testACBootID + `","bootId":"` + testACBootID + `","sessFlushGen":1,"sessFlushComplete":true}`, wantErr: "duplicate bootId"},
		{name: "duplicate generation", body: `{"bootId":"` + testACBootID + `","sessFlushGen":1,"sessFlushGen":2,"sessFlushComplete":true}`, wantErr: "duplicate sessFlushGen"},
		{name: "duplicate complete", body: `{"bootId":"` + testACBootID + `","sessFlushGen":1,"sessFlushComplete":true,"sessFlushComplete":true}`, wantErr: "duplicate sessFlushComplete"},
		{name: "uppercase boot", body: `{"bootId":"00112233445566778899AABBCCDDEEFF","sessFlushGen":1,"sessFlushComplete":true}`, wantErr: "canonical lowercase"},
		{name: "short boot", body: `{"bootId":"0011","sessFlushGen":1,"sessFlushComplete":true}`, wantErr: "canonical lowercase"},
		{name: "generation zero", body: `{"bootId":"` + testACBootID + `","sessFlushGen":0,"sessFlushComplete":true}`, wantErr: "canonical positive"},
		{name: "generation negative", body: `{"bootId":"` + testACBootID + `","sessFlushGen":-1,"sessFlushComplete":true}`, wantErr: "canonical positive"},
		{name: "generation exponent", body: `{"bootId":"` + testACBootID + `","sessFlushGen":1e1,"sessFlushComplete":true}`, wantErr: "canonical positive"},
		{name: "generation string", body: `{"bootId":"` + testACBootID + `","sessFlushGen":"1","sessFlushComplete":true}`, wantErr: "canonical positive"},
		{name: "generation overflow", body: `{"bootId":"` + testACBootID + `","sessFlushGen":18446744073709551616,"sessFlushComplete":true}`, wantErr: "canonical positive"},
		{name: "complete false", body: `{"bootId":"` + testACBootID + `","sessFlushGen":1,"sessFlushComplete":false}`, wantErr: "must be true"},
		{name: "complete number", body: `{"bootId":"` + testACBootID + `","sessFlushGen":1,"sessFlushComplete":1}`, wantErr: "JSON boolean"},
		{name: "trailing", body: `{"acId":"ac-1"}{}`, wantErr: "trailing"},
		{name: "not object", body: `[]`, wantErr: "one JSON object"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var got ACOnlineMsg
			err := DecodeACOnlineMsg([]byte(tt.body), &got)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("DecodeACOnlineMsg() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("DecodeACOnlineMsg() error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestNHPACBootID(t *testing.T) {
	id, err := NewNHPACBootID()
	if err != nil {
		t.Fatalf("NewNHPACBootID() error = %v", err)
	}
	if !ValidNHPACBootID(id) {
		t.Fatalf("NewNHPACBootID() = %q, not canonical", id)
	}
	if ValidNHPACBootID(strings.ToUpper(id)) {
		t.Fatal("uppercase boot ID accepted")
	}
}
