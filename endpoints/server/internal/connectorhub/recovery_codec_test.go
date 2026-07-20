package connectorhub

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	conformance "github.com/layervai/qurl-conformance"
)

func TestRecoveryRequestGoldenDecodesAndDerivesExactRequestID(t *testing.T) {
	t.Parallel()
	vectors := recoveryVectors(t)
	peer := decodedRecoveryPeer(t, vectors)

	request, rejection, err := DecodeAssignmentRequestClassified(
		vectors.Fixtures.Environment,
		[]byte(vectors.PublicExchanges[conformance.AgentCredentialRecoveryHubPhase].RequestBodyJSON),
		peer,
	)
	if err != nil {
		t.Fatalf("DecodeAssignmentRequestClassified: %v (%s)", err, rejection)
	}
	if request.Mode != ModeRecover || request.AgentID != vectors.Fixtures.AgentID ||
		request.AuthenticatedPeerPublicKeyB64 != vectors.Fixtures.AuthenticatedPeerPublicKeyB64 ||
		request.Credential != vectors.Fixtures.RecoveryCredential ||
		request.HubRequestID() != vectors.Fixtures.HubRequestID {
		t.Fatalf("decoded recovery request drift: %#v", request)
	}
}

func TestRecoveryRequestRejectsPreserveOnlyClosedMode(t *testing.T) {
	t.Parallel()
	vectors := recoveryVectors(t)
	peer := decodedRecoveryPeer(t, vectors)
	for _, test := range vectors.RequestRejects {
		if test.Phase != conformance.AgentCredentialRecoveryHubPhase {
			continue
		}
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			request, rejection, err := decodeAssignmentRequestClassified(vectors.Fixtures.Environment, []byte(test.BodyJSON), peer)
			if err == nil {
				// Credential syntax is checked at the private Authority boundary so
				// malformed values are rejected before lookup but after Hub admission.
				if request.Mode != ModeRecover {
					t.Fatalf("opaque credential decode mode = %d, want recover", request.Mode)
				}
				if body, authorityErr := encodeAuthorityRequest(request); !errors.Is(authorityErr, ErrInvalidAuthorityRequest) || body != nil {
					t.Fatalf("private credential boundary = %q, %v", body, authorityErr)
				}
				request = Request{Mode: request.Mode}
				rejection = RequestRejectionSemantic
				err = ErrInvalidAssignmentRequest
			}
			if !errors.Is(err, ErrInvalidAssignmentRequest) {
				t.Fatalf("error = %v, want ErrInvalidAssignmentRequest", err)
			}
			if rejection != RequestRejection(test.RejectClass) {
				t.Fatalf("rejection = %q, want conformance class %q", rejection, test.RejectClass)
			}
			wantMode := ModeRecover
			if test.Name == "reject_hub_request_wrong_mode" {
				wantMode = ModeRefresh
			}
			if request.Mode != wantMode || request.AgentID != "" || request.Credential != "" || request.HubRequestID() != "" {
				t.Fatalf("rejected request retained more than closed mode: %#v, want mode %d", request, wantMode)
			}
		})
	}
}

func TestRecoverySuccessAndErrorsMatchConformance(t *testing.T) {
	t.Parallel()
	vectors := recoveryVectors(t)
	success := recoverySuccessFixture(t, vectors)
	body, err := EncodeRecoverySuccess(success)
	if err != nil {
		t.Fatalf("EncodeRecoverySuccess: %v", err)
	}
	wantSuccess := vectors.PublicExchanges[conformance.AgentCredentialRecoveryHubPhase].SuccessBodyJSON
	if string(body) != wantSuccess {
		t.Fatalf("success body drift:\n got: %s\nwant: %s", body, wantSuccess)
	}
	assertRecoverySuccessMatchesJSONMarshal(t, success, body)

	kinds := map[string]RecoveryError{
		"52400": RecoveryErrorUnavailable,
		"52401": RecoveryErrorCredentialRejected,
		"52402": RecoveryErrorIdentityRejected,
		"52403": RecoveryErrorRevokeRequired,
		"52404": RecoveryErrorRateLimited,
		"52405": RecoveryErrorInvalidRequest,
		"52406": RecoveryErrorAssignmentRecoveryRequired,
	}
	for _, test := range vectors.ErrorCases {
		if test.Phase != conformance.AgentCredentialRecoveryHubPhase {
			continue
		}
		kind, ok := kinds[test.ErrCode]
		if !ok {
			t.Fatalf("unhandled recovery code %q", test.ErrCode)
		}
		body, err := EncodeRecoveryError(kind)
		if err != nil || string(body) != test.BodyJSON {
			t.Fatalf("error %s = %s, %v; want %s", test.Name, body, err, test.BodyJSON)
		}
	}
	if body, err := EncodeRecoveryError(0); !errors.Is(err, ErrInvalidRecoveryError) || body != nil {
		t.Fatalf("unknown recovery error = %q, %v", body, err)
	}
}

func TestRecoverySuccessRejectsContractDrift(t *testing.T) {
	t.Parallel()
	vectors := recoveryVectors(t)
	valid := recoverySuccessFixture(t, vectors)
	tests := []struct {
		name   string
		mutate func(*RecoverySuccess)
	}{
		{name: "agent", mutate: func(value *RecoverySuccess) { value.AgentID = "Agent" }},
		{name: "grant prefix only", mutate: func(value *RecoverySuccess) { value.RecoveryGrant = conformance.AgentCredentialRecoveryGrantPrefix }},
		{name: "grant whitespace", mutate: func(value *RecoverySuccess) { value.RecoveryGrant += " " }},
		{name: "grant punctuation", mutate: func(value *RecoverySuccess) { value.RecoveryGrant += "." }},
		{name: "grant oversized", mutate: func(value *RecoverySuccess) {
			value.RecoveryGrant = conformance.AgentCredentialRecoveryGrantPrefix + strings.Repeat("a", conformance.AgentCredentialRecoveryMaxGrantBytes)
		}},
		{name: "lifetime short", mutate: func(value *RecoverySuccess) {
			value.RecoveryGrantExpiresAt = value.RecoveryGrantExpiresAt.Add(-time.Second)
		}},
		{name: "lifetime long", mutate: func(value *RecoverySuccess) {
			value.RecoveryGrantExpiresAt = value.RecoveryGrantExpiresAt.Add(time.Second)
		}},
		{name: "not before lease", mutate: func(value *RecoverySuccess) { value.Assignment.LeaseExpiresAt = value.RecoveryGrantExpiresAt }},
		{name: "noncanonical time", mutate: func(value *RecoverySuccess) {
			value.RecoveryGrantIssuedAt = value.RecoveryGrantIssuedAt.Add(time.Nanosecond)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := valid
			test.mutate(&value)
			if body, err := EncodeRecoverySuccess(value); !errors.Is(err, ErrInvalidRecoverySuccess) || body != nil {
				t.Fatalf("EncodeRecoverySuccess = %q, %v", body, err)
			}
		})
	}
}

func TestMaximumRecoveryGrantFitsNHPPacket(t *testing.T) {
	t.Parallel()
	vectors := recoveryVectors(t)
	maximum := recoverySuccessFixture(t, vectors)
	maximum.RecoveryGrant = conformance.AgentCredentialRecoveryGrantPrefix +
		strings.Repeat("a", conformance.AgentCredentialRecoveryMaxGrantBytes-len(conformance.AgentCredentialRecoveryGrantPrefix))

	body, err := EncodeRecoverySuccess(maximum)
	if err != nil {
		t.Fatalf("EncodeRecoverySuccess(maximum grant): %v", err)
	}
	if len(body) > conformance.AgentCredentialRecoveryMaxBodyBytes ||
		len(body)+conformance.AgentCredentialRecoveryPacketOverheadBytes > conformance.AgentCredentialRecoveryMaxPacketBytes {
		t.Fatalf("maximum recovery result is %d body bytes / %d packet bytes", len(body), len(body)+conformance.AgentCredentialRecoveryPacketOverheadBytes)
	}
	if cap(body) != len(body) {
		t.Fatalf("maximum recovery result capacity = %d, want exact %d", cap(body), len(body))
	}
	assertRecoverySuccessMatchesJSONMarshal(t, maximum, body)
}

func assertRecoverySuccessMatchesJSONMarshal(t *testing.T, success RecoverySuccess, got []byte) {
	t.Helper()
	type recoveryListWire struct {
		Query                  string         `json:"query"`
		Version                int            `json:"version"`
		Mode                   string         `json:"mode"`
		AgentID                string         `json:"agent_id"`
		Assignment             assignmentWire `json:"assignment"`
		RecoveryGrant          string         `json:"recovery_grant"`
		RecoveryGrantIssuedAt  string         `json:"recovery_grant_issued_at"`
		RecoveryGrantExpiresAt string         `json:"recovery_grant_expires_at"`
	}
	want, err := json.Marshal(successEnvelope[recoveryListWire]{
		ErrCode: "0",
		List: recoveryListWire{
			Query: assignmentQuery, Version: assignmentVersion, Mode: "recover", AgentID: success.AgentID,
			Assignment: toAssignmentWire(success.Assignment), RecoveryGrant: success.RecoveryGrant,
			RecoveryGrantIssuedAt:  success.RecoveryGrantIssuedAt.Format(time.RFC3339),
			RecoveryGrantExpiresAt: success.RecoveryGrantExpiresAt.Format(time.RFC3339),
		},
	})
	if err != nil {
		t.Fatalf("json.Marshal expected recovery success: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("manual recovery success differs from encoding/json:\n got: %s\nwant: %s", got, want)
	}
}

func recoveryVectors(t *testing.T) *conformance.AgentCredentialRecoveryFile {
	t.Helper()
	vectors, err := conformance.AgentCredentialRecovery()
	if err != nil {
		t.Fatalf("load recovery vectors: %v", err)
	}
	return vectors
}

func decodedRecoveryPeer(t *testing.T, vectors *conformance.AgentCredentialRecoveryFile) []byte {
	t.Helper()
	peer, err := base64.StdEncoding.Strict().DecodeString(vectors.Fixtures.AuthenticatedPeerPublicKeyB64)
	if err != nil {
		t.Fatalf("decode recovery peer: %v", err)
	}
	return peer
}

func recoverySuccessFixture(t *testing.T, vectors *conformance.AgentCredentialRecoveryFile) RecoverySuccess {
	t.Helper()
	issuedAt, err := time.Parse(time.RFC3339, vectors.Fixtures.RecoveryGrantIssuedAt)
	if err != nil {
		t.Fatalf("parse grant issued_at: %v", err)
	}
	expiresAt, err := time.Parse(time.RFC3339, vectors.Fixtures.RecoveryGrantExpiresAt)
	if err != nil {
		t.Fatalf("parse grant expires_at: %v", err)
	}
	lease, err := time.Parse(time.RFC3339, vectors.Fixtures.LeaseExpiresAt)
	if err != nil {
		t.Fatalf("parse lease: %v", err)
	}
	return RecoverySuccess{
		AgentID: vectors.Fixtures.AgentID,
		Assignment: Assignment{
			CellID: vectors.Fixtures.CellID, AssignmentGeneration: vectors.Fixtures.AssignmentGeneration,
			EndpointRevision: vectors.Fixtures.EndpointRevision, LeaseExpiresAt: lease,
			Endpoint: UDPEndpoint{Host: vectors.Fixtures.NHPHost, Port: uint16(vectors.Fixtures.NHPPort), ServerPublicKeyB64: vectors.Fixtures.ServerPublicKeyB64},
		},
		RecoveryGrant: vectors.Fixtures.RecoveryGrant, RecoveryGrantIssuedAt: issuedAt,
		RecoveryGrantExpiresAt: expiresAt,
	}
}
