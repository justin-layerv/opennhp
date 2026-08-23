package common

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestValidateAgentKnockRunID(t *testing.T) {
	t.Parallel()

	for _, runID := range []string{
		"",
		"0123456789abcde",
		"0123456789abcdef0",
		"0123456789ABCDEF",
		"0123456789abcdeg",
		" 0123456789abcdef",
		"01234567 89abcde",
	} {
		runID := runID
		t.Run(runID, func(t *testing.T) {
			t.Parallel()
			err := ValidateAgentKnockRunID(runID)
			if !errors.Is(err, ErrInvalidAgentKnockRunID) {
				t.Fatalf("ValidateAgentKnockRunID() error = %v, want ErrInvalidAgentKnockRunID", err)
			}
			if runID != "" && strings.Contains(err.Error(), runID) {
				t.Fatalf("validation error leaks rejected RunID %q: %v", runID, err)
			}
		})
	}

	if err := ValidateAgentKnockRunID("0123456789abcdef"); err != nil {
		t.Fatalf("ValidateAgentKnockRunID(canonical) = %v", err)
	}
}

func TestValidateAgentKnockRunIDForAuthService(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name          string
		authServiceID string
		runID         string
		wantErr       bool
	}{
		{name: "registered agent canonical", authServiceID: RegisteredAgentAuthServiceID, runID: "0123456789abcdef"},
		{name: "registered agent missing", authServiceID: RegisteredAgentAuthServiceID, wantErr: true},
		{name: "other missing", authServiceID: "other"},
		{name: "other canonical", authServiceID: "other", runID: "0123456789abcdef"},
		{name: "other malformed", authServiceID: "other", runID: "0123456789ABCDEF", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateAgentKnockRunIDForAuthService(tc.authServiceID, tc.runID)
			if tc.wantErr {
				if !errors.Is(err, ErrInvalidAgentKnockRunID) {
					t.Fatalf("ValidateAgentKnockRunIDForAuthService() error = %v, want ErrInvalidAgentKnockRunID", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ValidateAgentKnockRunIDForAuthService() = %v", err)
			}
		})
	}
}

func TestAgentKnockMsgRunIDJSONContract(t *testing.T) {
	t.Parallel()

	const canonical = `{"headerType":1,"usrId":"user","devId":"device","aspId":"agent","resId":"connector","runId":"0123456789abcdef","runAttempt":1}`
	tests := []struct {
		name        string
		body        string
		wantErr     bool
		wantRunID   string
		wantAttempt uint64
		wantUserID  string
		wantDataKey any
		wantClass   error
		forbidClass error
	}{
		{name: "canonical", body: canonical, wantRunID: "0123456789abcdef", wantAttempt: 1, wantUserID: "user"},
		{name: "missing accepted generically", body: `{"headerType":1,"usrId":"user","devId":"device","aspId":"agent","resId":"connector"}`, wantUserID: "user"},
		{name: "empty accepted generically", body: `{"headerType":1,"usrId":"user","devId":"device","aspId":"agent","resId":"connector","runId":""}`, wantUserID: "user"},
		{name: "unknown extension remains accepted", body: `{"headerType":1,"usrId":"user","devId":"device","aspId":"agent","resId":"connector","futureField":true}`, wantUserID: "user"},
		{name: "escaped canonical key", body: strings.Replace(canonical, `"runId"`, `"r\u0075nId"`, 1), wantRunID: "0123456789abcdef", wantAttempt: 1, wantUserID: "user"},
		{name: "duplicate unrelated top-level field retains legacy semantics", body: `{"headerType":1,"usrId":"first","usrId":"second","aspId":"other","resId":"connector"}`, wantUserID: "second"},
		{name: "duplicate nested key retains legacy semantics", body: `{"headerType":1,"usrId":"user","devId":"device","aspId":"other","resId":"connector","usrData":{"key":1,"key":2}}`, wantUserID: "user", wantDataKey: float64(2)},
		{name: "duplicate runId", body: strings.Replace(canonical, `"runId":"0123456789abcdef"`, `"runId":"0123456789abcdef","runId":"fedcba9876543210"`, 1), wantErr: true},
		{name: "escaped duplicate runId", body: strings.Replace(canonical, `"runId":"0123456789abcdef"`, `"runId":"0123456789abcdef","r\u0075nId":"fedcba9876543210"`, 1), wantErr: true},
		{name: "runID alias", body: strings.Replace(canonical, `"runId"`, `"runID"`, 1), wantErr: true},
		{name: "escaped runID alias", body: strings.Replace(canonical, `"runId"`, `"run\u0049D"`, 1), wantErr: true},
		{name: "run_id alias", body: strings.Replace(canonical, `"runId"`, `"run_id"`, 1), wantErr: true},
		{name: "RUN_ID alias", body: strings.Replace(canonical, `"runId"`, `"RUN_ID"`, 1), wantErr: true},
		{name: "uppercase invalid", body: strings.Replace(canonical, "0123456789abcdef", "0123456789ABCDEF", 1), wantErr: true, wantClass: ErrInvalidAgentKnockRunID},
		{name: "short invalid", body: strings.Replace(canonical, "0123456789abcdef", "0123456789abcde", 1), wantErr: true, wantClass: ErrInvalidAgentKnockRunID},
		{name: "null is body parse", body: strings.Replace(canonical, `"0123456789abcdef"`, "null", 1), wantErr: true, forbidClass: ErrInvalidAgentKnockRunID},
		{name: "non-string is body parse", body: strings.Replace(canonical, `"0123456789abcdef"`, "123", 1), wantErr: true, forbidClass: ErrInvalidAgentKnockRunID},
		{name: "runAttempt zero", body: strings.Replace(canonical, `"runAttempt":1`, `"runAttempt":0`, 1), wantErr: true},
		{name: "runAttempt null", body: strings.Replace(canonical, `"runAttempt":1`, `"runAttempt":null`, 1), wantErr: true},
		{name: "runAttempt string", body: strings.Replace(canonical, `"runAttempt":1`, `"runAttempt":"1"`, 1), wantErr: true},
		{name: "runAttempt exponent", body: strings.Replace(canonical, `"runAttempt":1`, `"runAttempt":1e0`, 1), wantErr: true},
		{name: "runAttempt overflow", body: strings.Replace(canonical, `"runAttempt":1`, `"runAttempt":18446744073709551616`, 1), wantErr: true},
		{name: "runAttempt duplicate", body: strings.Replace(canonical, `"runAttempt":1`, `"runAttempt":1,"runAttempt":2`, 1), wantErr: true},
		{name: "runAttempt alias", body: strings.Replace(canonical, `"runAttempt"`, `"run_attempt"`, 1), wantErr: true},
		{name: "runAttempt escaped canonical key", body: strings.Replace(canonical, `"runAttempt"`, `"run\u0041ttempt"`, 1), wantRunID: "0123456789abcdef", wantAttempt: 1, wantUserID: "user"},
		{name: "trailing value", body: canonical + `{}`, wantErr: true},
		{name: "top-level null", body: `null`, wantErr: true},
		{name: "top-level scalar", body: `42`, wantErr: true},
		{name: "top-level array", body: `[]`, wantErr: true},
		{name: "nested runId is unrelated", body: `{"headerType":1,"usrId":"user","aspId":"other","resId":"connector","usrData":{"runId":"not-a-binding","mixed":[{"text":"},]\\\""}]}}`, wantUserID: "user"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var msg AgentKnockMsg
			err := json.Unmarshal([]byte(tc.body), &msg)
			if tc.wantErr {
				if err == nil {
					t.Fatal("json.Unmarshal() error = nil, want rejection")
				}
				if tc.wantClass != nil && !errors.Is(err, tc.wantClass) {
					t.Fatalf("json.Unmarshal() error = %v, want class %v", err, tc.wantClass)
				}
				if tc.forbidClass != nil && errors.Is(err, tc.forbidClass) {
					t.Fatalf("json.Unmarshal() error = %v, must not use class %v", err, tc.forbidClass)
				}
				return
			}
			if err != nil {
				t.Fatalf("json.Unmarshal() = %v", err)
			}
			if msg.RunID != tc.wantRunID {
				t.Fatalf("RunID = %q, want %q", msg.RunID, tc.wantRunID)
			}
			if msg.RunAttempt != tc.wantAttempt {
				t.Fatalf("RunAttempt = %d, want %d", msg.RunAttempt, tc.wantAttempt)
			}
			if msg.UserId != tc.wantUserID {
				t.Fatalf("UserId = %q, want %q", msg.UserId, tc.wantUserID)
			}
			if tc.wantDataKey != nil && msg.UserData["key"] != tc.wantDataKey {
				t.Fatalf("UserData[key] = %#v, want %#v", msg.UserData["key"], tc.wantDataKey)
			}
		})
	}
}

func TestAgentKnockMsgStructureErrorsDoNotEchoAttackerControlledInputs(t *testing.T) {
	t.Parallel()

	const secretValue = "customer-secret-do-not-log"
	for name, body := range map[string]string{
		"duplicate runId":   `{"headerType":1,"aspId":"agent","resId":"connector","runId":"customer-secret-do-not-log","runId":"0123456789abcdef"}`,
		"unsupported alias": `{"headerType":1,"aspId":"agent","resId":"connector","RUNID":"0123456789abcdef"}`,
	} {
		name, body := name, body
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var msg AgentKnockMsg
			err := json.Unmarshal([]byte(body), &msg)
			if err == nil {
				t.Fatal("json.Unmarshal() error = nil, want structural rejection")
			}
			if strings.Contains(err.Error(), secretValue) || strings.Contains(err.Error(), "RUNID") {
				t.Fatalf("structural error echoes attacker-controlled value or alias: %v", err)
			}
		})
	}
}

func TestAgentKnockMsgRejectsValuesBeyondEncodingJSONDepthLimit(t *testing.T) {
	t.Parallel()

	// A body beyond encoding/json's nesting limit must return an ordinary parse
	// error. The implementation's top-level-only, non-recursive RunID scan is a
	// source-level property; this test pins only the public rejection contract.
	const depth = 10_001
	body := `{"headerType":1,"aspId":"other","resId":"connector","usrData":` +
		strings.Repeat("[", depth) + `0` + strings.Repeat("]", depth) + `}`
	var msg AgentKnockMsg
	if err := json.Unmarshal([]byte(body), &msg); err == nil {
		t.Fatal("json.Unmarshal() error = nil, want standard nesting-depth rejection")
	}
}

func TestAgentKnockMsgMarshalRunIDWireName(t *testing.T) {
	t.Parallel()

	raw, err := json.Marshal(AgentKnockMsg{
		HeaderType:    1,
		UserId:        "user",
		DeviceId:      "device",
		AuthServiceId: RegisteredAgentAuthServiceID,
		ResourceId:    "connector",
		RunID:         "0123456789abcdef",
		RunAttempt:    1,
	})
	if err != nil {
		t.Fatalf("json.Marshal() = %v", err)
	}
	const want = `{"headerType":1,"usrId":"user","devId":"device","aspId":"agent","resId":"connector","runId":"0123456789abcdef","runAttempt":1}`
	if string(raw) != want {
		t.Fatalf("marshal = %s, want %s", raw, want)
	}
}

func BenchmarkAgentKnockMsgUnmarshal(b *testing.B) {
	representative := []byte(`{"headerType":1,"usrId":"agent-id","devId":"agent-id","orgId":"org","aspId":"agent","resId":"connector-routing-id","runId":"0123456789abcdef","results":{"posture":"ok"},"usrData":{"role":"connector"}}`)
	const maxDecompressedBodySize = 1 << 20 // nhp/core MaxDecompressedBodySize
	ceilingPrefix := []byte(`{"headerType":1,"usrId":"agent-id","devId":"agent-id","aspId":"agent","resId":"connector-routing-id","runId":"0123456789abcdef","padding":"`)
	ceilingSuffix := []byte(`"}`)
	ceiling := make([]byte, 0, maxDecompressedBodySize)
	ceiling = append(ceiling, ceilingPrefix...)
	ceiling = append(ceiling, bytes.Repeat([]byte{'a'}, maxDecompressedBodySize-len(ceilingPrefix)-len(ceilingSuffix))...)
	ceiling = append(ceiling, ceilingSuffix...)
	if len(ceiling) != maxDecompressedBodySize {
		b.Fatalf("ceiling body size = %d, want %d", len(ceiling), maxDecompressedBodySize)
	}

	type encodingJSONBaseline AgentKnockMsg
	bodies := []struct {
		name string
		body []byte
	}{
		{name: "representative", body: representative},
		{name: "compressed_plaintext_ceiling", body: ceiling},
	}

	for _, bodyCase := range bodies {
		b.Run(bodyCase.name, func(b *testing.B) {
			benchmarks := []struct {
				name string
				run  func() error
			}{
				{
					name: "strict_RunID_contract",
					run: func() error {
						var msg AgentKnockMsg
						return json.Unmarshal(bodyCase.body, &msg)
					},
				},
				{
					name: "encoding_json_baseline",
					run: func() error {
						var msg encodingJSONBaseline
						return json.Unmarshal(bodyCase.body, &msg)
					},
				},
			}
			for _, benchmark := range benchmarks {
				b.Run(benchmark.name, func(b *testing.B) {
					b.ReportAllocs()
					b.SetBytes(int64(len(bodyCase.body)))
					for range b.N {
						if err := benchmark.run(); err != nil {
							b.Fatal(err)
						}
					}
				})
			}
		})
	}
}
