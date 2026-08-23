package common

import (
	"encoding/base64"
	"reflect"
	"strings"
	"testing"
)

func testSessionCloseAgentKey() string {
	return base64.StdEncoding.EncodeToString(make([]byte, NHPAgentPublicKeyBytes))
}

func TestDecodeACSessionCloseMsg(t *testing.T) {
	agentKey := testSessionCloseAgentKey()
	eventID := "00112233445566778899aabbccddeeff"
	validExact := `{"kind":"nhp_session_close","scope":"exact","eventId":"` + eventID + `","agentPubKey":"` + agentKey + `","sessionId":77,"sessionIssuedAtMs":1700000000000}`
	tests := []struct {
		name    string
		body    string
		wantErr string
	}{
		{name: "exact", body: validExact},
		{name: "agent", body: `{"kind":"nhp_session_close","scope":"agent","eventId":"` + eventID + `","agentPubKey":"` + agentKey + `","issuedThroughMs":1700000000000}`},
		{name: "run", body: `{"kind":"nhp_session_close","scope":"run","eventId":"` + eventID + `","agentPubKey":"` + agentKey + `","runId":"0123456789abcdef","runAttempt":2}`},
		{name: "exact missing session", body: strings.Replace(validExact, `,"sessionId":77`, ``, 1), wantErr: "exactly"},
		{name: "exact missing issuance", body: strings.Replace(validExact, `,"sessionIssuedAtMs":1700000000000`, ``, 1), wantErr: "exactly"},
		{name: "exact extra", body: strings.Replace(validExact, `}`, `,"runAttempt":1}`, 1), wantErr: "exactly"},
		{name: "exact session zero", body: strings.Replace(validExact, `"sessionId":77`, `"sessionId":0`, 1), wantErr: "sessionId"},
		{name: "exact session exponent", body: strings.Replace(validExact, `"sessionId":77`, `"sessionId":7.7e1`, 1), wantErr: "sessionId"},
		{name: "exact issuance zero", body: strings.Replace(validExact, `"sessionIssuedAtMs":1700000000000`, `"sessionIssuedAtMs":0`, 1), wantErr: "sessionIssuedAtMs"},
		{name: "exact issuance string", body: strings.Replace(validExact, `"sessionIssuedAtMs":1700000000000`, `"sessionIssuedAtMs":"1700000000000"`, 1), wantErr: "sessionIssuedAtMs"},
		{name: "exact duplicate session", body: strings.Replace(validExact, `"sessionId":77`, `"sessionId":77,"sessionId":78`, 1), wantErr: "duplicate sessionId"},
		{name: "exact duplicate issuance", body: strings.Replace(validExact, `"sessionIssuedAtMs":1700000000000`, `"sessionIssuedAtMs":1700000000000,"sessionIssuedAtMs":1700000000001`, 1), wantErr: "duplicate sessionIssuedAtMs"},
		{name: "agent extra", body: `{"kind":"nhp_session_close","scope":"agent","eventId":"` + eventID + `","agentPubKey":"` + agentKey + `","issuedThroughMs":1,"runId":"0123456789abcdef"}`, wantErr: "exactly"},
		{name: "run extra", body: `{"kind":"nhp_session_close","scope":"run","eventId":"` + eventID + `","agentPubKey":"` + agentKey + `","runId":"0123456789abcdef","runAttempt":2,"issuedThroughMs":1}`, wantErr: "exactly"},
		{name: "unknown scope", body: `{"kind":"nhp_session_close","scope":"all","eventId":"` + eventID + `","agentPubKey":"` + agentKey + `","runAttempt":1}`, wantErr: "unknown"},
		{name: "duplicate kind", body: `{"kind":"nhp_session_close","kind":null,"scope":"agent","eventId":"` + eventID + `","agentPubKey":"` + agentKey + `","issuedThroughMs":1}`, wantErr: "duplicate kind"},
		{name: "duplicate cutoff", body: `{"kind":"nhp_session_close","scope":"agent","eventId":"` + eventID + `","agentPubKey":"` + agentKey + `","issuedThroughMs":1,"issuedThroughMs":2}`, wantErr: "duplicate issuedThroughMs"},
		{name: "cutoff zero", body: `{"kind":"nhp_session_close","scope":"agent","eventId":"` + eventID + `","agentPubKey":"` + agentKey + `","issuedThroughMs":0}`, wantErr: "canonical positive"},
		{name: "cutoff exponent", body: `{"kind":"nhp_session_close","scope":"agent","eventId":"` + eventID + `","agentPubKey":"` + agentKey + `","issuedThroughMs":1e3}`, wantErr: "canonical positive"},
		{name: "attempt zero", body: `{"kind":"nhp_session_close","scope":"run","eventId":"` + eventID + `","agentPubKey":"` + agentKey + `","runId":"0123456789abcdef","runAttempt":0}`, wantErr: "canonical positive"},
		{name: "attempt string", body: `{"kind":"nhp_session_close","scope":"run","eventId":"` + eventID + `","agentPubKey":"` + agentKey + `","runId":"0123456789abcdef","runAttempt":"1"}`, wantErr: "canonical positive"},
		{name: "bad run", body: `{"kind":"nhp_session_close","scope":"run","eventId":"` + eventID + `","agentPubKey":"` + agentKey + `","runId":"BAD","runAttempt":1}`, wantErr: "runId"},
		{name: "bad event", body: `{"kind":"nhp_session_close","scope":"agent","eventId":"BAD","agentPubKey":"` + agentKey + `","issuedThroughMs":1}`, wantErr: "eventId"},
		{name: "bad agent", body: `{"kind":"nhp_session_close","scope":"agent","eventId":"` + eventID + `","agentPubKey":"bad","issuedThroughMs":1}`, wantErr: "agentPubKey"},
		{name: "trailing", body: `{"kind":"nhp_session_close"}{}`, wantErr: "trailing"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var got ACSessionCloseMsg
			err := DecodeACSessionCloseMsg([]byte(tt.body), &got)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("DecodeACSessionCloseMsg() error = %v", err)
				}
				if tt.name == "exact" && (got.SessionID != 77 || got.SessionIssuedAtMillis != 1700000000000) {
					t.Fatalf("exact selector = (%d,%d), want (77,1700000000000)", got.SessionID, got.SessionIssuedAtMillis)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("DecodeACSessionCloseMsg() error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestDecodeACSessionCloseMsgErrorDoesNotMutateOutput(t *testing.T) {
	original := ACSessionCloseMsg{Kind: "sentinel", Scope: "sentinel", SessionID: 99, SessionIssuedAtMillis: 88}
	got := original
	err := DecodeACSessionCloseMsg([]byte(`{"kind":"nhp_session_close","scope":"exact"}`), &got)
	if err == nil {
		t.Fatal("malformed exact close decoded successfully")
	}
	if !reflect.DeepEqual(got, original) {
		t.Fatalf("output mutated on error: got %#v, want %#v", got, original)
	}
}

func TestDecodeACSessionCloseAckMsg(t *testing.T) {
	agent := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	const eventID = "00112233445566778899aabbccddeeff"
	const bootID = "ffeeddccbbaa99887766554433221100"
	validRun := `{"kind":"nhp_session_close","scope":"run","eventId":"` + eventID + `","agentPubKey":"` + agent + `","runId":"0123456789abcdef","runAttempt":2,"bootId":"` + bootID + `","flushGeneration":3,"closed":0}`
	validExact := `{"kind":"nhp_session_close","scope":"exact","eventId":"` + eventID + `","agentPubKey":"` + agent + `","sessionId":77,"sessionIssuedAtMs":1700000000000,"bootId":"` + bootID + `","flushGeneration":3,"closed":1}`
	tests := []struct {
		name    string
		body    string
		wantErr string
	}{
		{name: "exact", body: validExact},
		{name: "run", body: validRun},
		{name: "agent", body: `{"kind":"nhp_session_close","scope":"agent","eventId":"` + eventID + `","agentPubKey":"` + agent + `","issuedThroughMs":1700000000000,"bootId":"` + bootID + `","flushGeneration":3,"closed":2}`},
		{name: "exact missing session", body: strings.Replace(validExact, `,"sessionId":77`, ``, 1), wantErr: "field set"},
		{name: "exact missing issuance", body: strings.Replace(validExact, `,"sessionIssuedAtMs":1700000000000`, ``, 1), wantErr: "field set"},
		{name: "exact extra", body: strings.Replace(validExact, `,"closed":1}`, `,"closed":1,"runId":"0123456789abcdef"}`, 1), wantErr: "field set"},
		{name: "exact session zero", body: strings.Replace(validExact, `"sessionId":77`, `"sessionId":0`, 1), wantErr: "sessionId"},
		{name: "exact issuance exponent", body: strings.Replace(validExact, `"sessionIssuedAtMs":1700000000000`, `"sessionIssuedAtMs":17e11`, 1), wantErr: "sessionIssuedAtMs"},
		{name: "exact duplicate session", body: strings.Replace(validExact, `"sessionId":77`, `"sessionId":77,"sessionId":78`, 1), wantErr: "duplicate sessionId"},
		{name: "exact duplicate issuance", body: strings.Replace(validExact, `"sessionIssuedAtMs":1700000000000`, `"sessionIssuedAtMs":1700000000000,"sessionIssuedAtMs":1700000000001`, 1), wantErr: "duplicate sessionIssuedAtMs"},
		{name: "missing boot", body: `{"kind":"nhp_session_close","scope":"run","eventId":"` + eventID + `","agentPubKey":"` + agent + `","runId":"0123456789abcdef","runAttempt":2,"flushGeneration":3,"closed":0}`, wantErr: "bootId"},
		{name: "zero generation", body: strings.Replace(validRun, `"flushGeneration":3`, `"flushGeneration":0`, 1), wantErr: "flushGeneration"},
		{name: "noncanonical generation", body: strings.Replace(validRun, `"flushGeneration":3`, `"flushGeneration":3e0`, 1), wantErr: "flushGeneration"},
		{name: "duplicate event", body: strings.Replace(validRun, `"eventId":"`+eventID+`"`, `"eventId":"`+eventID+`","eventId":"`+eventID+`"`, 1), wantErr: "duplicate eventId"},
		{name: "unknown", body: strings.Replace(validRun, `,"closed":0}`, `,"closed":0,"extra":true}`, 1), wantErr: "field set"},
		{name: "closed negative", body: strings.Replace(validRun, `"closed":0`, `"closed":-1`, 1), wantErr: "closed"},
		{name: "closed leading zero", body: strings.Replace(validRun, `"closed":0`, `"closed":00`, 1), wantErr: "invalid character"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got ACSessionCloseAckMsg
			err := DecodeACSessionCloseAckMsg([]byte(tt.body), &got)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("DecodeACSessionCloseAckMsg() error = %v", err)
				}
				if got.BootID != bootID || got.FlushGeneration != 3 {
					t.Fatalf("target binding = (%q,%d), want (%q,3)", got.BootID, got.FlushGeneration, bootID)
				}
				if tt.name == "exact" && (got.SessionID != 77 || got.SessionIssuedAtMillis != 1700000000000) {
					t.Fatalf("exact selector = (%d,%d), want (77,1700000000000)", got.SessionID, got.SessionIssuedAtMillis)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("DecodeACSessionCloseAckMsg() error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestDecodeACSessionCloseAckMsgErrorDoesNotMutateOutput(t *testing.T) {
	original := ACSessionCloseAckMsg{Kind: "sentinel", Scope: "sentinel", SessionID: 99, SessionIssuedAtMillis: 88, FlushGeneration: 7}
	got := original
	err := DecodeACSessionCloseAckMsg([]byte(`{"kind":"nhp_session_close","scope":"exact"}`), &got)
	if err == nil {
		t.Fatal("malformed exact close acknowledgement decoded successfully")
	}
	if !reflect.DeepEqual(got, original) {
		t.Fatalf("output mutated on error: got %#v, want %#v", got, original)
	}
}

func TestACSessionCloseKindPresentRoutesMalformedPresence(t *testing.T) {
	present, err := ACSessionCloseKindPresent([]byte(`{"kind":null,"scope":"session"}`))
	if err != nil || !present {
		t.Fatalf("presence = %t, error = %v", present, err)
	}
	if _, err := ACSessionCloseKindPresent([]byte(`{"kind":"nhp_session_close","kind":null}`)); err == nil {
		t.Fatal("duplicate kind accepted")
	}
}
