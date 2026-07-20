package connectorhub

import (
	"bytes"
	"errors"
	"testing"

	conformance "github.com/layervai/qurl-conformance"
)

func TestRecoveryAuthorityRequestMatchesConformance(t *testing.T) {
	t.Parallel()
	vectors := recoveryVectors(t)
	request, err := DecodeAssignmentRequest(
		vectors.Fixtures.Environment,
		[]byte(vectors.PublicExchanges[conformance.AgentCredentialRecoveryHubPhase].RequestBodyJSON),
		decodedRecoveryPeer(t, vectors),
	)
	if err != nil {
		t.Fatalf("DecodeAssignmentRequest: %v", err)
	}
	body, err := encodeAuthorityRequest(request)
	if err != nil {
		t.Fatalf("encodeAuthorityRequest: %v", err)
	}
	want := vectors.PrivateOperations[conformance.AgentCredentialRecoveryIssueOperation].RequestBodyJSON
	if string(body) != want {
		t.Fatalf("private request drift:\n got: %s\nwant: %s", body, want)
	}
	if cap(body) != len(body) {
		t.Fatalf("private request capacity = %d, want exact %d", cap(body), len(body))
	}
}

func TestRecoveryAuthorityMappingsMatchConformance(t *testing.T) {
	t.Parallel()
	vectors := recoveryVectors(t)
	request := recoveryAuthorityFixtureRequest(vectors)
	operation := vectors.PrivateOperations[conformance.AgentCredentialRecoveryIssueOperation]
	for _, mapping := range operation.PublicMappings {
		if mapping.MappingSource != "authority_response" {
			continue
		}
		t.Run(mapping.Name, func(t *testing.T) {
			t.Parallel()
			body, kind, err := decodeAuthorityResponse(request, []byte(mapping.PrivateResponseBodyJSON))
			if err != nil {
				t.Fatalf("decodeAuthorityResponse: %v", err)
			}
			wantKind := authorityResponseSemanticError
			if mapping.PrivateOutcome == "success" {
				wantKind = authorityResponseSuccess
			}
			if kind != wantKind || string(body) != mapping.NHPBodyJSON {
				t.Fatalf("mapping = %d %s, want %d %s", kind, body, wantKind, mapping.NHPBodyJSON)
			}
		})
	}
}

func TestRecoveryAuthorityResponseFailsClosed(t *testing.T) {
	t.Parallel()
	vectors := recoveryVectors(t)
	request := recoveryAuthorityFixtureRequest(vectors)
	valid := vectors.PrivateOperations[conformance.AgentCredentialRecoveryIssueOperation].SuccessBodyJSON
	tests := []struct {
		name string
		body string
	}{
		{name: "unknown error", body: `{"version":1,"error":{"code":"future"}}`},
		{name: "private retry", body: `{"version":1,"error":{"code":"unavailable","retry_after_seconds":5}}`},
		{name: "unknown result field", body: replaceOnce(t, valid, `"recovery_grant_expires_at"`, `"unknown"`)},
		{name: "wrong agent", body: replaceOnce(t, valid, vectors.Fixtures.AgentID, "agent-other")},
		{name: "bad grant", body: replaceOnce(t, valid, vectors.Fixtures.RecoveryGrant, "qrg1.")},
		{name: "short lifetime", body: replaceOnce(t, valid, vectors.Fixtures.RecoveryGrantExpiresAt, "2026-07-20T11:14:59Z")},
		{name: "grant after lease", body: replaceOnce(t, valid, vectors.Fixtures.RecoveryGrantExpiresAt, vectors.Fixtures.LeaseExpiresAt)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			body, _, err := decodeAuthorityResponse(request, []byte(test.body))
			if err == nil || body != nil {
				t.Fatalf("decodeAuthorityResponse = %q, %v", body, err)
			}
		})
	}
}

func TestRecoveryAuthorityRequestRejectsNoncanonicalCredential(t *testing.T) {
	t.Parallel()
	vectors := recoveryVectors(t)
	request := recoveryAuthorityFixtureRequest(vectors)
	request.Credential = "lv_live_bad"
	if body, err := encodeAuthorityRequest(request); !errors.Is(err, ErrInvalidAuthorityRequest) || body != nil {
		t.Fatalf("encodeAuthorityRequest = %q, %v", body, err)
	}
}

func recoveryAuthorityFixtureRequest(vectors *conformance.AgentCredentialRecoveryFile) Request {
	return Request{
		Mode: ModeRecover, AgentID: vectors.Fixtures.AgentID,
		AuthenticatedPeerPublicKeyB64: vectors.Fixtures.AuthenticatedPeerPublicKeyB64,
		Credential:                    vectors.Fixtures.RecoveryCredential, hubRequestID: vectors.Fixtures.HubRequestID,
	}
}

func replaceOnce(t *testing.T, body, old, replacement string) string {
	t.Helper()
	replaced := bytes.Replace([]byte(body), []byte(old), []byte(replacement), 1)
	if bytes.Equal(replaced, []byte(body)) {
		t.Fatalf("fixture token %q not found", old)
	}
	return string(replaced)
}
