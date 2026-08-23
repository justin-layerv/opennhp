package server

import (
	"encoding/json"
	"testing"

	conformance "github.com/layervai/qurl-conformance"

	"github.com/OpenNHP/opennhp/nhp/common"
)

func TestRegisteredAgentKnockACKMatchesConformanceV4(t *testing.T) {
	t.Parallel()
	vectors, err := conformance.AgentSessionControl()
	if err != nil {
		t.Fatalf("load qurl-conformance agent-session vectors: %v", err)
	}
	if vectors.SchemaVersion != 4 {
		t.Fatalf("agent-session schema = %d, want 4", vectors.SchemaVersion)
	}

	for _, tc := range []struct {
		name string
		body string
	}{
		{name: "success", body: vectors.OverloadReknock.ACK.BodyJSON},
		{name: "denial", body: vectors.DenialACKs.Knock.BodyJSON},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var ack common.ServerKnockAckMsg
			if err := json.Unmarshal([]byte(tc.body), &ack); err != nil {
				t.Fatalf("decode conformance ACK: %v", err)
			}
			resourceID := ""
			if tc.name == "success" {
				for key := range ack.ResourceHost {
					resourceID = key
				}
			}
			got, err := common.MarshalRegisteredAgentKnockAckMsg(
				&ack, ack.RunID, ack.RunAttempt, resourceID,
			)
			if err != nil {
				t.Fatalf("marshal registered-agent ACK: %v", err)
			}
			if string(got) != tc.body {
				t.Fatalf("registered-agent ACK = %s\nwant conformance %s", got, tc.body)
			}
			var decoded common.ServerKnockAckMsg
			if err := common.DecodeRegisteredAgentKnockAckMsg(
				got, &decoded, ack.RunID, ack.RunAttempt, resourceID,
			); err != nil {
				t.Fatalf("strict decode conformance ACK: %v", err)
			}
		})
	}
}
