package connectorhub

import (
	"encoding/json"

	conformance "github.com/layervai/qurl-conformance"
)

type issueCredentialRecoveryResultWire struct {
	AgentID                string                                         `json:"agent_id"`
	Assignment             conformance.ConnectorAuthorityAssignmentResult `json:"assignment"`
	RecoveryGrant          string                                         `json:"recovery_grant"`
	RecoveryGrantIssuedAt  string                                         `json:"recovery_grant_issued_at"`
	RecoveryGrantExpiresAt string                                         `json:"recovery_grant_expires_at"`
}

func decodeIssueCredentialRecoveryResponse(expectedAgentID string, envelope authorityEnvelope) ([]byte, authorityResponseKind, error) {
	if envelope.errorCode != "" {
		kind, ok := issueCredentialRecoveryError(envelope.errorCode)
		if !ok {
			return nil, 0, ErrInvalidAuthorityResponse
		}
		body, err := EncodeRecoveryError(kind)
		if err != nil {
			return nil, 0, ErrInvalidAuthorityResponse
		}
		return body, authorityResponseSemanticError, nil
	}

	object, err := decodeClosedObject(envelope.result, []string{
		"agent_id", "assignment", "recovery_grant", "recovery_grant_issued_at", "recovery_grant_expires_at",
	})
	if err != nil || validateAuthorityAssignmentShape(object["assignment"]) != nil {
		return nil, 0, ErrInvalidAuthorityResponse
	}

	var result issueCredentialRecoveryResultWire
	if err := json.Unmarshal(envelope.result, &result); err != nil || result.AgentID != expectedAgentID {
		return nil, 0, ErrInvalidAuthorityResponse
	}
	assignment, err := assignmentFromAuthority(result.Assignment)
	if err != nil {
		return nil, 0, err
	}
	issuedAt, err := parseAuthorityTime(result.RecoveryGrantIssuedAt)
	if err != nil {
		return nil, 0, err
	}
	expiresAt, err := parseAuthorityTime(result.RecoveryGrantExpiresAt)
	if err != nil {
		return nil, 0, err
	}
	body, err := EncodeRecoverySuccess(RecoverySuccess{
		AgentID: result.AgentID, Assignment: assignment, RecoveryGrant: result.RecoveryGrant,
		RecoveryGrantIssuedAt: issuedAt, RecoveryGrantExpiresAt: expiresAt,
	})
	if err != nil {
		return nil, 0, ErrInvalidAuthorityResponse
	}
	return body, authorityResponseSuccess, nil
}

func issueCredentialRecoveryError(code string) (RecoveryError, bool) {
	switch code {
	case "invalid_request", "fingerprint_conflict":
		return RecoveryErrorInvalidRequest, true
	case "credential_rejected":
		return RecoveryErrorCredentialRejected, true
	case "identity_rejected":
		return RecoveryErrorIdentityRejected, true
	case "revoke_required":
		return RecoveryErrorRevokeRequired, true
	case "assignment_recovery_required":
		return RecoveryErrorAssignmentRecoveryRequired, true
	case "unavailable":
		return RecoveryErrorUnavailable, true
	default:
		return 0, false
	}
}
