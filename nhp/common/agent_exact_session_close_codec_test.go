package common

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
)

func TestDecodeAgentExactSessionCloseMsg(t *testing.T) {
	t.Parallel()
	valid := `{"headerType":3,"aspId":"agent","cellId":"cell-01","sessId":18446744073709551615,"sessIssuedAtMillis":1700000000000,"runId":"0123456789abcdef","runAttempt":2}`
	var got AgentExactSessionCloseMsg
	if err := DecodeAgentExactSessionCloseMsg([]byte(valid), &got); err != nil {
		t.Fatalf("DecodeAgentExactSessionCloseMsg: %v", err)
	}
	if got.HeaderType != 3 || got.AuthServiceID != RegisteredAgentAuthServiceID || got.CellID != "cell-01" ||
		got.SessionID != math.MaxUint64 || got.SessionIssuedAtMillis != 1_700_000_000_000 ||
		got.RunID != "0123456789abcdef" || got.RunAttempt != 2 {
		t.Fatalf("decoded exact close = %#v", got)
	}

	for name, body := range map[string]string{
		"null":              `null`,
		"missing session":   `{"headerType":3,"aspId":"agent","cellId":"cell-01","sessIssuedAtMillis":1700000000000,"runId":"0123456789abcdef","runAttempt":2}`,
		"unknown":           `{"headerType":3,"aspId":"agent","cellId":"cell-01","sessId":1,"sessIssuedAtMillis":1700000000000,"runId":"0123456789abcdef","runAttempt":2,"future":1}`,
		"duplicate session": `{"headerType":3,"aspId":"agent","cellId":"cell-01","sessId":1,"sessId":2,"sessIssuedAtMillis":1700000000000,"runId":"0123456789abcdef","runAttempt":2}`,
		"wrong asp":         `{"headerType":3,"aspId":"oidc","cellId":"cell-01","sessId":1,"sessIssuedAtMillis":1700000000000,"runId":"0123456789abcdef","runAttempt":2}`,
		"empty cell":        `{"headerType":3,"aspId":"agent","cellId":"","sessId":1,"sessIssuedAtMillis":1700000000000,"runId":"0123456789abcdef","runAttempt":2}`,
		"type zero":         `{"headerType":0,"aspId":"agent","cellId":"cell-01","sessId":1,"sessIssuedAtMillis":1700000000000,"runId":"0123456789abcdef","runAttempt":2}`,
		"session zero":      `{"headerType":3,"aspId":"agent","cellId":"cell-01","sessId":0,"sessIssuedAtMillis":1700000000000,"runId":"0123456789abcdef","runAttempt":2}`,
		"issuance zero":     `{"headerType":3,"aspId":"agent","cellId":"cell-01","sessId":1,"sessIssuedAtMillis":0,"runId":"0123456789abcdef","runAttempt":2}`,
		"bad run":           `{"headerType":3,"aspId":"agent","cellId":"cell-01","sessId":1,"sessIssuedAtMillis":1700000000000,"runId":"BAD","runAttempt":2}`,
		"attempt zero":      `{"headerType":3,"aspId":"agent","cellId":"cell-01","sessId":1,"sessIssuedAtMillis":1700000000000,"runId":"0123456789abcdef","runAttempt":0}`,
		"session string":    `{"headerType":3,"aspId":"agent","cellId":"cell-01","sessId":"1","sessIssuedAtMillis":1700000000000,"runId":"0123456789abcdef","runAttempt":2}`,
		"session exponent":  `{"headerType":3,"aspId":"agent","cellId":"cell-01","sessId":1e0,"sessIssuedAtMillis":1700000000000,"runId":"0123456789abcdef","runAttempt":2}`,
		"session overflow":  `{"headerType":3,"aspId":"agent","cellId":"cell-01","sessId":18446744073709551616,"sessIssuedAtMillis":1700000000000,"runId":"0123456789abcdef","runAttempt":2}`,
		"trailing":          `{"headerType":3,"aspId":"agent","cellId":"cell-01","sessId":1,"sessIssuedAtMillis":1700000000000,"runId":"0123456789abcdef","runAttempt":2}{}`,
	} {
		t.Run(name, func(t *testing.T) {
			var out AgentExactSessionCloseMsg
			if err := DecodeAgentExactSessionCloseMsg([]byte(body), &out); err == nil {
				t.Fatalf("DecodeAgentExactSessionCloseMsg(%s) succeeded: %#v", body, out)
			}
		})
	}
}

func TestDecodeAgentExactSessionCloseMsgRejectsNilOutput(t *testing.T) {
	t.Parallel()
	if err := DecodeAgentExactSessionCloseMsg([]byte(`{"headerType":3,"aspId":"agent","cellId":"cell-01","sessId":1,"sessIssuedAtMillis":1700000000000,"runId":"0123456789abcdef","runAttempt":2}`), nil); err == nil {
		t.Fatal("nil output was accepted")
	}
}

func TestDecodeServerExactSessionCloseAckMsgStrictUnion(t *testing.T) {
	t.Parallel()
	const eventID = "0123456789abcdef0123456789abcdef"
	valid := `{"errCode":"0","cellId":"cell-01","sessId":18446744073709551615,"sessIssuedAtMillis":1700000000000,"runId":"0123456789abcdef","runAttempt":2,"closeEventId":"` + eventID + `","state":"closing"}`
	var got ServerExactSessionCloseAckMsg
	if err := DecodeServerExactSessionCloseAckMsg([]byte(valid), &got); err != nil {
		t.Fatalf("DecodeServerExactSessionCloseAckMsg: %v", err)
	}
	if got.ErrCode != ErrSuccess.ErrorCode() || got.CellID != "cell-01" || got.SessionID != math.MaxUint64 ||
		got.SessionIssuedAtMillis != 1_700_000_000_000 || got.RunID != "0123456789abcdef" ||
		got.RunAttempt != 2 || got.CloseEventID != eventID || got.State != "closing" {
		t.Fatalf("decoded close ACK = %#v", got)
	}
	if err := DecodeServerExactSessionCloseAckMsg([]byte(`{"errCode":"52004","errMsg":"denied"}`), &got); err != nil {
		t.Fatalf("decode denial: %v", err)
	}
	if got.ErrCode != "52004" || got.ErrMsg != "denied" || got.SessionID != 0 || got.CloseEventID != "" {
		t.Fatalf("decoded denial = %#v", got)
	}

	for name, body := range map[string]string{
		"missing receipt":    strings.Replace(valid, `,"cellId":"cell-01"`, ``, 1),
		"missing index zero": strings.Replace(valid, `"runAttempt":2,`, ``, 1),
		"unknown":            strings.Replace(valid, `}`, `,"future":1}`, 1),
		"duplicate":          strings.Replace(valid, `"sessId":18446744073709551615`, `"sessId":1,"sessId":18446744073709551615`, 1),
		"success errMsg":     strings.Replace(valid, `"cellId"`, `"errMsg":"", "cellId"`, 1),
		"bad event":          strings.Replace(valid, eventID, strings.ToUpper(eventID), 1),
		"bad state":          strings.Replace(valid, `"closing"`, `"complete"`, 1),
		"deny receipt":       `{"errCode":"52004","errMsg":"denied","sessId":1}`,
		"deny missing msg":   `{"errCode":"52004"}`,
		"deny empty msg":     `{"errCode":"52004","errMsg":""}`,
		"deny padded msg":    `{"errCode":"52004","errMsg":" denied "}`,
		"nondecimal code":    `{"errCode":"denied","errMsg":"denied"}`,
		"noncanonical code":  `{"errCode":"052004","errMsg":"denied"}`,
		"trailing":           valid + `{}`,
	} {
		t.Run(name, func(t *testing.T) {
			var out ServerExactSessionCloseAckMsg
			if err := DecodeServerExactSessionCloseAckMsg([]byte(body), &out); err == nil {
				t.Fatalf("DecodeServerExactSessionCloseAckMsg(%s) succeeded: %#v", body, out)
			}
		})
	}
	if err := DecodeServerExactSessionCloseAckMsg([]byte(valid), nil); err == nil {
		t.Fatal("nil output was accepted")
	}
}

func TestValidateServerExactSessionCloseAckBindsReceipt(t *testing.T) {
	t.Parallel()
	receipt := AgentSessionReceipt{
		CellID: "cell-01", SessionID: 77, SessionIssuedAtMillis: 1_700_000_000_000,
		RunID: "0123456789abcdef", RunAttempt: 2,
	}
	ack := ServerExactSessionCloseAckMsg{
		ErrCode: ErrSuccess.ErrorCode(), CellID: receipt.CellID, SessionID: receipt.SessionID,
		SessionIssuedAtMillis: receipt.SessionIssuedAtMillis, RunID: receipt.RunID,
		RunAttempt: receipt.RunAttempt, CloseEventID: "0123456789abcdef0123456789abcdef", State: "closed",
	}
	if err := ValidateServerExactSessionCloseAck(ack, receipt); err != nil {
		t.Fatalf("ValidateServerExactSessionCloseAck: %v", err)
	}
	for name, mutate := range map[string]func(*ServerExactSessionCloseAckMsg){
		"cell":     func(value *ServerExactSessionCloseAckMsg) { value.CellID = "cell-02" },
		"session":  func(value *ServerExactSessionCloseAckMsg) { value.SessionID++ },
		"issuance": func(value *ServerExactSessionCloseAckMsg) { value.SessionIssuedAtMillis++ },
		"run":      func(value *ServerExactSessionCloseAckMsg) { value.RunID = "fedcba9876543210" },
		"attempt":  func(value *ServerExactSessionCloseAckMsg) { value.RunAttempt++ },
	} {
		t.Run(name, func(t *testing.T) {
			mutated := ack
			mutate(&mutated)
			if err := ValidateServerExactSessionCloseAck(mutated, receipt); err == nil {
				t.Fatalf("mutated ACK accepted: %#v", mutated)
			}
		})
	}
}

func TestAgentSessionReceiptFromKnockAck(t *testing.T) {
	t.Parallel()
	ack := &ServerKnockAckMsg{
		ErrCode: ErrSuccess.ErrorCode(), SessionId: 77, CellId: "cell-01",
		SessionIssuedAtMillis: 1_700_000_000_000, RunID: "0123456789abcdef", RunAttempt: 3, OpenTime: 30,
		AgentAddr: "198.51.100.8:44444", ResourceHost: map[string]string{"resource": "127.0.0.1:443"},
		ACTokens: map[string]string{"resource": "token"},
	}
	receipt, err := AgentSessionReceiptFromKnockAck(ack, ack.RunID, ack.RunAttempt)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.SessionID != ack.SessionId || receipt.CellID != ack.CellId || receipt.RunAttempt != ack.RunAttempt {
		t.Fatalf("receipt = %#v, ack = %#v", receipt, ack)
	}
	if _, err := AgentSessionReceiptFromKnockAck(ack, ack.RunID, ack.RunAttempt+1); err == nil {
		t.Fatal("run-attempt drift was accepted")
	}
}

func TestDecodeRegisteredAgentKnockAckMsgStrictReceiptUnion(t *testing.T) {
	t.Parallel()
	const valid = `{"sessId":77,"cellId":"cell-01","sessIssuedAtMillis":1700000000000,"runId":"0123456789abcdef","runAttempt":3,"errCode":"0","resHost":{"resource":"127.0.0.1:443"},"opnTime":30,"agentAddr":"198.51.100.8:44444","acTokens":{"resource":"token"}}`
	var got ServerKnockAckMsg
	if err := DecodeRegisteredAgentKnockAckMsg([]byte(valid), &got, "0123456789abcdef", 3, "resource"); err != nil {
		t.Fatalf("DecodeRegisteredAgentKnockAckMsg: %v", err)
	}
	if got.SessionId != 77 || got.CellId != "cell-01" || got.RunAttempt != 3 {
		t.Fatalf("decoded ACK = %#v", got)
	}
	receipt, err := DecodeAgentSessionReceiptFromKnockAckJSON([]byte(valid))
	if err != nil || receipt.SessionID != 77 || receipt.RunAttempt != 3 {
		t.Fatalf("DecodeAgentSessionReceiptFromKnockAckJSON = %#v, %v", receipt, err)
	}

	const denial = `{"errCode":"52004","errMsg":"denied","opnTime":0}`
	if err := DecodeRegisteredAgentKnockAckMsg([]byte(denial), &got, "0123456789abcdef", 3, "resource"); err != nil {
		t.Fatalf("decode denial: %v", err)
	}
	if got.ErrCode != "52004" || got.ErrMsg != "denied" || got.SessionId != 0 {
		t.Fatalf("decoded denial = %#v", got)
	}
	if _, err := DecodeAgentSessionReceiptFromKnockAckJSON([]byte(denial)); err == nil {
		t.Fatal("denial was accepted as a receipt")
	}

	for name, body := range map[string]string{
		"missing":                  strings.Replace(valid, `"cellId":"cell-01",`, ``, 1),
		"unknown":                  strings.TrimSuffix(valid, `}`) + `,"future":1}`,
		"duplicate":                strings.Replace(valid, `"sessId":77`, `"sessId":77,"sessId":77`, 1),
		"noncanonical session":     strings.Replace(valid, `"sessId":77`, `"sessId":77.0`, 1),
		"noncanonical issuance":    strings.Replace(valid, `"sessIssuedAtMillis":1700000000000`, `"sessIssuedAtMillis":1700000000000.0`, 1),
		"noncanonical attempt":     strings.Replace(valid, `"runAttempt":3`, `"runAttempt":3.0`, 1),
		"run drift":                valid,
		"attempt drift":            valid,
		"success errMsg":           strings.Replace(valid, `"errCode":"0"`, `"errCode":"0","errMsg":""`, 1),
		"success zero TTL":         strings.Replace(valid, `"opnTime":30`, `"opnTime":0`, 1),
		"success bad addr":         strings.Replace(valid, `"198.51.100.8:44444"`, `"not-an-address"`, 1),
		"success no host":          strings.Replace(valid, `{"resource":"127.0.0.1:443"}`, `{}`, 1),
		"success no token":         strings.Replace(valid, `{"resource":"token"}`, `{}`, 1),
		"success wrong resource":   strings.Replace(valid, `"resource":"token"`, `"sibling":"token"`, 1),
		"success padded key":       strings.ReplaceAll(valid, `"resource":`, `" resource ":`),
		"success whitespace host":  strings.Replace(valid, `"127.0.0.1:443"`, `"   "`, 1),
		"success padded host":      strings.Replace(valid, `"127.0.0.1:443"`, `" 127.0.0.1:443 "`, 1),
		"success whitespace token": strings.Replace(valid, `"resource":"token"`, `"resource":"   "`, 1),
		"success padded token":     strings.Replace(valid, `"resource":"token"`, `"resource":" token "`, 1),
		"deny receipt":             strings.Replace(denial, `}`, `,"sessId":77}`, 1),
		"deny empty msg":           strings.Replace(denial, `"denied"`, `""`, 1),
		"deny positive TTL":        strings.Replace(denial, `"opnTime":0`, `"opnTime":1`, 1),
		"deny host":                strings.Replace(denial, `}`, `,"resHost":null}`, 1),
		"deny token":               strings.Replace(denial, `}`, `,"acTokens":null}`, 1),
		"deny addr":                strings.Replace(denial, `}`, `,"agentAddr":"198.51.100.8:44444"}`, 1),
		"deny padded msg":          strings.Replace(denial, `"denied"`, `" denied "`, 1),
		"deny whitespace msg":      strings.Replace(denial, `"denied"`, `"   "`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			expectedRun := "0123456789abcdef"
			expectedAttempt := uint64(3)
			if name == "run drift" {
				expectedRun = "fedcba9876543210"
			}
			if name == "attempt drift" {
				expectedAttempt = 4
			}
			var out ServerKnockAckMsg
			if err := DecodeRegisteredAgentKnockAckMsg([]byte(body), &out, expectedRun, expectedAttempt, "resource"); err == nil {
				t.Fatalf("malformed/drift registered ACK succeeded: %#v", out)
			}
		})
	}
}

func TestMarshalRegisteredAgentKnockAckMsgCanonicalUnion(t *testing.T) {
	t.Parallel()
	const (
		runID      = "0123456789abcdef"
		resourceID = "connector-conformance-01"
	)
	success := &ServerKnockAckMsg{
		SessionId: 72623859790382856, CellId: "cell0", SessionIssuedAtMillis: 1_800_000_000_000,
		RunID: runID, RunAttempt: 1, ErrCode: ErrSuccess.ErrorCode(),
		ResourceHost: map[string]string{resourceID: "frps.sandbox.example:7000"}, OpenTime: 900,
		AgentAddr: "203.0.113.9:49152", ACTokens: map[string]string{resourceID: "ac-token-conformance-01"},
		PreAccessActions: map[string]*PreAccessInfo{resourceID: nil},
	}
	got, err := MarshalRegisteredAgentKnockAckMsg(success, runID, 1, resourceID)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"errCode":"0","sessId":72623859790382856,"cellId":"cell0","sessIssuedAtMillis":1800000000000,"runId":"0123456789abcdef","runAttempt":1,"resHost":{"connector-conformance-01":"frps.sandbox.example:7000"},"opnTime":900,"agentAddr":"203.0.113.9:49152","acTokens":{"connector-conformance-01":"ac-token-conformance-01"},"preActions":{"connector-conformance-01":null}}`
	if string(got) != want {
		t.Fatalf("canonical success ACK = %s\nwant %s", got, want)
	}
	var decoded ServerKnockAckMsg
	if err := DecodeRegisteredAgentKnockAckMsg(got, &decoded, runID, 1, resourceID); err != nil {
		t.Fatalf("decode marshaled success: %v", err)
	}

	denial := &ServerKnockAckMsg{
		ErrCode: "52004", ErrMsg: "denied", AgentAddr: "203.0.113.9:49152",
		SessionId: 77, CellId: "stale", ResourceHost: map[string]string{resourceID: "stale"},
		ACTokens: map[string]string{resourceID: "stale"},
	}
	got, err = MarshalRegisteredAgentKnockAckMsg(denial, "", 0, "")
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"errCode":"52004","errMsg":"denied","opnTime":0}`; string(got) != want {
		t.Fatalf("canonical denial ACK = %s, want %s", got, want)
	}
	if err := json.Unmarshal(got, &decoded); err != nil {
		t.Fatal(err)
	}

	for name, mutate := range map[string]func(*ServerKnockAckMsg){
		"empty denial message":      func(value *ServerKnockAckMsg) { value.ErrMsg = "" },
		"whitespace denial message": func(value *ServerKnockAckMsg) { value.ErrMsg = " \t " },
		"padded denial message":     func(value *ServerKnockAckMsg) { value.ErrMsg = " denied " },
		"positive denial open time": func(value *ServerKnockAckMsg) { value.OpenTime = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := *denial
			mutate(&candidate)
			if _, err := MarshalRegisteredAgentKnockAckMsg(&candidate, "", 0, ""); err == nil {
				t.Fatalf("invalid denial was marshaled: %#v", candidate)
			}
		})
	}
	for name, mutate := range map[string]func(*ServerKnockAckMsg){
		"padded resource key": func(value *ServerKnockAckMsg) {
			value.ResourceHost = map[string]string{" " + resourceID: "frps.sandbox.example:7000"}
			value.ACTokens = map[string]string{" " + resourceID: "ac-token-conformance-01"}
		},
		"whitespace host": func(value *ServerKnockAckMsg) {
			value.ResourceHost = map[string]string{resourceID: "   "}
		},
		"padded host": func(value *ServerKnockAckMsg) {
			value.ResourceHost = map[string]string{resourceID: " frps.sandbox.example:7000 "}
		},
		"whitespace token": func(value *ServerKnockAckMsg) {
			value.ACTokens = map[string]string{resourceID: "   "}
		},
		"padded token": func(value *ServerKnockAckMsg) {
			value.ACTokens = map[string]string{resourceID: " ac-token-conformance-01 "}
		},
	} {
		t.Run("success "+name, func(t *testing.T) {
			candidate := *success
			candidate.ResourceHost = map[string]string{resourceID: success.ResourceHost[resourceID]}
			candidate.ACTokens = map[string]string{resourceID: success.ACTokens[resourceID]}
			mutate(&candidate)
			if _, err := MarshalRegisteredAgentKnockAckMsg(&candidate, runID, 1, resourceID); err == nil {
				t.Fatalf("invalid success authority was marshaled: %#v", candidate)
			}
		})
	}
}
