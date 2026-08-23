package server

import (
	"encoding/json"
	"errors"
	"testing"

	conformance "github.com/layervai/qurl-conformance"

	"github.com/OpenNHP/opennhp/nhp/common"
)

func TestAgentKnockRunIDConformanceSchemaV4(t *testing.T) {
	t.Parallel()

	vectors, err := conformance.AgentKnockApplication()
	if err != nil {
		t.Fatalf("load qurl-conformance agent knock application vectors: %v", err)
	}
	if vectors.SchemaVersion != 4 {
		t.Fatalf("schema version = %d, want 4", vectors.SchemaVersion)
	}

	for _, tc := range vectors.RequestCases {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			t.Parallel()
			var msg common.AgentKnockMsg
			parseErr := json.Unmarshal([]byte(tc.BodyJSON), &msg)
			assertAgentKnockConformanceExpectation(t, "generic_parser", tc.GenericParser, msg.RunID, parseErr)

			nativeErr := parseErr
			if nativeErr == nil {
				// Schema v4 isolates the RunID grammar. The mandatory retry
				// ordinal is covered by the native schema that supersedes this
				// held conformance artifact, so give this focused legacy vector a
				// canonical attempt rather than letting an unrelated missing-field
				// error mask its RunID expectation.
				msg.RunAttempt = 1
				nativeErr = validateRegisteredAgentKnockRunID(&msg)
			}
			assertAgentKnockConformanceExpectation(t, "native_connector", tc.NativeConnector, msg.RunID, nativeErr)
		})
	}
}

func TestRegisteredAgentRunIDGateRejectsNilMessage(t *testing.T) {
	t.Parallel()
	if err := validateRegisteredAgentKnockRunID(nil); !errors.Is(err, common.ErrInvalidAgentKnockRunID) {
		t.Fatalf("nil message error = %v, want ErrInvalidAgentKnockRunID", err)
	}
}

func assertAgentKnockConformanceExpectation(
	t *testing.T,
	entryPoint string,
	want conformance.AgentKnockRequestExpectation,
	parsedRunID string,
	err error,
) {
	t.Helper()
	switch want.Outcome {
	case conformance.ExpectAccept:
		if err != nil {
			t.Fatalf("%s error = %v, want accept", entryPoint, err)
		}
		if want.ParsedRunID == nil {
			t.Fatalf("%s vector has nil parsed_run_id on accept", entryPoint)
		}
		if parsedRunID != *want.ParsedRunID {
			t.Fatalf("%s RunID = %q, want %q", entryPoint, parsedRunID, *want.ParsedRunID)
		}
	case conformance.ExpectReject:
		if err == nil {
			t.Fatalf("%s error = nil, want reject class %q", entryPoint, want.RejectClass)
		}
		switch want.RejectClass {
		case conformance.AgentKnockRejectInvalidRunID, conformance.AgentKnockRejectMissingRunID:
			if !errors.Is(err, common.ErrInvalidAgentKnockRunID) {
				t.Fatalf("%s error = %v, want ErrInvalidAgentKnockRunID for %q", entryPoint, err, want.RejectClass)
			}
		case conformance.AgentKnockRejectBodyParse:
			if errors.Is(err, common.ErrInvalidAgentKnockRunID) {
				t.Fatalf("%s error = %v, body-shape rejection must precede RunID policy", entryPoint, err)
			}
		default:
			t.Fatalf("%s vector has unsupported request reject class %q", entryPoint, want.RejectClass)
		}
	default:
		t.Fatalf("%s vector has unsupported outcome %q", entryPoint, want.Outcome)
	}
}

func TestAgentKnockRunIDConformanceGoldenMarshal(t *testing.T) {
	t.Parallel()

	vectors, err := conformance.AgentKnockApplication()
	if err != nil {
		t.Fatalf("load qurl-conformance agent knock application vectors: %v", err)
	}
	fields := vectors.Request.Fields
	raw, err := json.Marshal(common.AgentKnockMsg{
		HeaderType:    fields.HeaderType,
		UserId:        fields.UserID,
		DeviceId:      fields.DeviceID,
		AuthServiceId: fields.AuthServiceID,
		ResourceId:    fields.KnockResourceID,
		RunID:         fields.RunID,
	})
	if err != nil {
		t.Fatalf("marshal AgentKnockMsg: %v", err)
	}
	if string(raw) != vectors.Request.BodyJSON {
		t.Fatalf("AgentKnockMsg golden drift:\n got: %s\nwant: %s", raw, vectors.Request.BodyJSON)
	}
}
