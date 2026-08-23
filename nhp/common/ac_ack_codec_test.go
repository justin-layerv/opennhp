package common

import (
	"strings"
	"testing"
)

func TestDecodeServerACAckMsgAuthorityTuple(t *testing.T) {
	const boot = "00112233445566778899aabbccddeeff"
	valid := `{"errCode":"0","registered":true,"bootId":"` + boot + `","sessFlushGen":2,"aolTrxId":9,"future":{}}`
	tests := []struct {
		name    string
		body    string
		wantErr string
	}{
		{name: "success", body: valid},
		{name: "reject omits tuple", body: `{"errCode":"52028","errMsg":"not ready"}`},
		{name: "success missing boot", body: `{"errCode":"0","registered":true,"sessFlushGen":2,"aolTrxId":9}`, wantErr: "must contain"},
		{name: "success missing registered", body: strings.Replace(valid, `,"registered":true`, ``, 1), wantErr: "registered:true"},
		{name: "success registered false", body: strings.Replace(valid, `"registered":true`, `"registered":false`, 1), wantErr: "registered:true"},
		{name: "success zero generation", body: strings.Replace(valid, `"sessFlushGen":2`, `"sessFlushGen":0`, 1), wantErr: "sessFlushGen"},
		{name: "success wrong transaction type", body: strings.Replace(valid, `"aolTrxId":9`, `"aolTrxId":"9"`, 1), wantErr: "aolTrxId"},
		{name: "success duplicate transaction", body: strings.Replace(valid, `"aolTrxId":9`, `"aolTrxId":9,"aolTrxId":9`, 1), wantErr: "duplicate aolTrxId"},
		{name: "reject with tuple", body: `{"errCode":"52028","bootId":"` + boot + `","sessFlushGen":2,"aolTrxId":9}`, wantErr: "must omit"},
		{name: "registered wrong type", body: strings.Replace(valid, `"registered":true`, `"registered":1`, 1), wantErr: "registered"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got ServerACAckMsg
			err := DecodeServerACAckMsg([]byte(tt.body), &got)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("DecodeServerACAckMsg() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("DecodeServerACAckMsg() error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}
