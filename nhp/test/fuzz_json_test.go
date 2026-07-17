package test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/OpenNHP/opennhp/nhp/common"
)

// FuzzAgentKnockMsg verifies that the strict AgentKnockMsg decoder never accepts
// input rejected by encoding/json and that every accepted message has a stable
// canonical wire form. This security-critical type carries authentication data.
func FuzzAgentKnockMsg(f *testing.F) {
	for _, seed := range []string{
		`{}`,
		`{"headerType":1,"aspId":"agent","resId":"connector","runId":"0123456789abcdef"}`,
		`{"headerType":1,"aspId":"other","resId":"connector","usrData":{"nested":["}",",","\\\""]}}`,
		`{"runId":"0123456789abcdef","r\u0075nId":"fedcba9876543210"}`,
		`{"RUN_ID":"0123456789abcdef"}`,
		`[]`,
		`null`,
		``,
	} {
		f.Add([]byte(seed))
	}

	f.Fuzz(func(t *testing.T, body []byte) {
		type encodingJSONBaseline common.AgentKnockMsg
		var baseline encodingJSONBaseline
		baselineErr := json.Unmarshal(body, &baseline)

		var msg common.AgentKnockMsg
		if err := json.Unmarshal(body, &msg); err != nil {
			return
		}
		if baselineErr != nil {
			t.Fatalf("strict parser accepted body rejected by encoding/json baseline: %v", baselineErr)
		}
		wire, err := json.Marshal(&msg)
		if err != nil {
			t.Fatalf("marshal accepted message: %v", err)
		}
		var roundTrip common.AgentKnockMsg
		if err := json.Unmarshal(wire, &roundTrip); err != nil {
			t.Fatalf("strict parser rejected its own canonical marshal: %v", err)
		}
		roundTripWire, err := json.Marshal(&roundTrip)
		if err != nil {
			t.Fatalf("marshal round-trip message: %v", err)
		}
		if !bytes.Equal(wire, roundTripWire) {
			t.Fatalf("accepted message is not wire-stable: first=%s second=%s", wire, roundTripWire)
		}
	})
}

// FuzzServerKnockAckMsg tests JSON parsing of server acknowledgment messages.
func FuzzServerKnockAckMsg(f *testing.F) {
	f.Add([]byte(`{"errCode":0,"errMsg":"success"}`))
	f.Add([]byte(`{"errCode":-1,"errMsg":"error"}`))
	f.Add([]byte(`{}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var msg common.ServerKnockAckMsg
		_ = json.Unmarshal(data, &msg)
	})
}

// FuzzACOpsResultMsg tests JSON parsing of AC operation result messages.
func FuzzACOpsResultMsg(f *testing.F) {
	f.Add([]byte(`{"errCode":0,"preAccessAction":{}}`))
	f.Add([]byte(`{}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var msg common.ACOpsResultMsg
		_ = json.Unmarshal(data, &msg)
	})
}

// FuzzDARMsg tests JSON parsing of Data Access Request messages.
// Security-critical for DHP (Data Hiding Protocol).
func FuzzDARMsg(f *testing.F) {
	f.Add([]byte(`{"doId":"test-id","dbId":"db1"}`))
	f.Add([]byte(`{}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var msg common.DARMsg
		_ = json.Unmarshal(data, &msg)
	})
}
