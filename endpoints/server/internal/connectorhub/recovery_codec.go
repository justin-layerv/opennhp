package connectorhub

import (
	"strconv"
	"strings"
	"time"

	conformance "github.com/layervai/qurl-conformance"
)

const recoveryRateLimitRetrySeconds uint32 = 60

// RecoverySuccess is the exact Hub result for an explicit same-agent device-
// credential recovery. The grant is opaque to NHP; only its bounded public
// grammar and Authority-authenticated lifetime are validated here.
type RecoverySuccess struct {
	AgentID                string
	Assignment             Assignment
	RecoveryGrant          string
	RecoveryGrantIssuedAt  time.Time
	RecoveryGrantExpiresAt time.Time
}

// EncodeRecoverySuccess validates and encodes the exact successful Hub
// recovery LRT body. The grant must have the frozen 900-second lifetime and
// expire before the selected assignment lease.
func EncodeRecoverySuccess(success RecoverySuccess) ([]byte, error) {
	if !validAgentID(success.AgentID) || !validAssignment(success.Assignment) ||
		!validRecoveryGrant(success.RecoveryGrant) ||
		!canonicalWireTime(success.RecoveryGrantIssuedAt) ||
		!canonicalWireTime(success.RecoveryGrantExpiresAt) ||
		success.RecoveryGrantExpiresAt.Sub(success.RecoveryGrantIssuedAt) !=
			time.Duration(conformance.AgentCredentialRecoveryGrantLifetimeSeconds)*time.Second ||
		!success.RecoveryGrantExpiresAt.Before(success.Assignment.LeaseExpiresAt) {
		return nil, ErrInvalidRecoverySuccess
	}

	return encodeRecoverySuccess(success)
}

const (
	recoverySuccessPrefix         = `{"errCode":"0","list":{"query":"cell_assignment","version":1,"mode":"recover","agent_id":"`
	recoverySuccessAssignment     = `","assignment":{"cell_id":"`
	recoverySuccessGeneration     = `","assignment_generation":`
	recoverySuccessRevision       = `,"endpoint_revision":`
	recoverySuccessLease          = `,"lease_expires_at":"`
	recoverySuccessEndpoint       = `","nhp_udp_endpoint":{"host":"`
	recoverySuccessPort           = `","port":`
	recoverySuccessServerKey      = `,"server_public_key_b64":"`
	recoverySuccessGrant          = `"}},"recovery_grant":"`
	recoverySuccessGrantIssuedAt  = `","recovery_grant_issued_at":"`
	recoverySuccessGrantExpiresAt = `","recovery_grant_expires_at":"`
	recoverySuccessSuffix         = `"}}`
)

func encodeRecoverySuccess(success RecoverySuccess) ([]byte, error) {
	// The recovery grant is bearer material. Direct construction keeps it out of
	// encoding/json's pooled buffers and leaves exactly one caller-owned public
	// result. These constants mirror successEnvelope and assignmentWire; parity
	// tests compare the golden and maximum bodies to json.Marshal so schema or
	// escaping drift fails locally. Validation restricts every interpolated
	// string here to JSON-safe ASCII.
	generation := strconv.FormatInt(success.Assignment.AssignmentGeneration, 10)
	revision := strconv.FormatInt(success.Assignment.EndpointRevision, 10)
	port := strconv.FormatUint(uint64(success.Assignment.Endpoint.Port), 10)
	lease := success.Assignment.LeaseExpiresAt.Format(time.RFC3339)
	issuedAt := success.RecoveryGrantIssuedAt.Format(time.RFC3339)
	expiresAt := success.RecoveryGrantExpiresAt.Format(time.RFC3339)
	wantBytes := len(recoverySuccessPrefix) + len(success.AgentID) +
		len(recoverySuccessAssignment) + len(success.Assignment.CellID) +
		len(recoverySuccessGeneration) + len(generation) +
		len(recoverySuccessRevision) + len(revision) +
		len(recoverySuccessLease) + len(lease) +
		len(recoverySuccessEndpoint) + len(success.Assignment.Endpoint.Host) +
		len(recoverySuccessPort) + len(port) +
		len(recoverySuccessServerKey) + len(success.Assignment.Endpoint.ServerPublicKeyB64) +
		len(recoverySuccessGrant) + len(success.RecoveryGrant) +
		len(recoverySuccessGrantIssuedAt) + len(issuedAt) +
		len(recoverySuccessGrantExpiresAt) + len(expiresAt) + len(recoverySuccessSuffix)
	if wantBytes > maxApplicationBodyBytes {
		return nil, ErrAssignmentResponseTooLarge
	}
	body := make([]byte, 0, wantBytes)
	body = append(body, recoverySuccessPrefix...)
	body = append(body, success.AgentID...)
	body = append(body, recoverySuccessAssignment...)
	body = append(body, success.Assignment.CellID...)
	body = append(body, recoverySuccessGeneration...)
	body = append(body, generation...)
	body = append(body, recoverySuccessRevision...)
	body = append(body, revision...)
	body = append(body, recoverySuccessLease...)
	body = append(body, lease...)
	body = append(body, recoverySuccessEndpoint...)
	body = append(body, success.Assignment.Endpoint.Host...)
	body = append(body, recoverySuccessPort...)
	body = append(body, port...)
	body = append(body, recoverySuccessServerKey...)
	body = append(body, success.Assignment.Endpoint.ServerPublicKeyB64...)
	body = append(body, recoverySuccessGrant...)
	body = append(body, success.RecoveryGrant...)
	body = append(body, recoverySuccessGrantIssuedAt...)
	body = append(body, issuedAt...)
	body = append(body, recoverySuccessGrantExpiresAt...)
	body = append(body, expiresAt...)
	body = append(body, recoverySuccessSuffix...)
	if len(body) != wantBytes || cap(body) != wantBytes {
		clear(body)
		return nil, ErrAssignmentResponseEncoding
	}
	return body, nil
}

// RecoveryError is the closed 52400-52406 vocabulary for the Hub recovery
// phase. Retry delays are part of the immutable contract, not caller input.
type RecoveryError uint8

const (
	RecoveryErrorUnavailable RecoveryError = iota + 1
	RecoveryErrorCredentialRejected
	RecoveryErrorIdentityRejected
	RecoveryErrorRevokeRequired
	RecoveryErrorRateLimited
	RecoveryErrorInvalidRequest
	RecoveryErrorAssignmentRecoveryRequired
)

// EncodeRecoveryError emits one frozen Hub recovery result. Only unavailable
// and rate-limited outcomes carry their exact authenticated retry delay.
func EncodeRecoveryError(kind RecoveryError) ([]byte, error) {
	spec, ok := recoveryErrorSpec(kind)
	if !ok {
		return nil, ErrInvalidRecoveryError
	}
	var retryAfterSeconds *uint32
	if spec.retryAfterSeconds != 0 {
		retry := spec.retryAfterSeconds
		retryAfterSeconds = &retry
	}
	return marshalBounded(errorWire{
		ErrCode: spec.code, ErrMsg: spec.message, RetryAfterSeconds: retryAfterSeconds,
	})
}

type recoveryErrorWireSpec struct {
	code              string
	message           string
	retryAfterSeconds uint32
}

func recoveryErrorSpec(kind RecoveryError) (recoveryErrorWireSpec, bool) {
	switch kind {
	case RecoveryErrorUnavailable:
		return recoveryErrorWireSpec{code: "52400", message: "credential recovery temporarily unavailable", retryAfterSeconds: 5}, true
	case RecoveryErrorCredentialRejected:
		return recoveryErrorWireSpec{code: "52401", message: "recovery credential rejected"}, true
	case RecoveryErrorIdentityRejected:
		return recoveryErrorWireSpec{code: "52402", message: "recovery identity rejected"}, true
	case RecoveryErrorRevokeRequired:
		return recoveryErrorWireSpec{code: "52403", message: "revoke current device credential before recovery"}, true
	case RecoveryErrorRateLimited:
		return recoveryErrorWireSpec{code: "52404", message: "credential recovery rate limited", retryAfterSeconds: recoveryRateLimitRetrySeconds}, true
	case RecoveryErrorInvalidRequest:
		return recoveryErrorWireSpec{code: "52405", message: "invalid credential recovery request"}, true
	case RecoveryErrorAssignmentRecoveryRequired:
		return recoveryErrorWireSpec{code: "52406", message: "assignment requires operator recovery"}, true
	default:
		return recoveryErrorWireSpec{}, false
	}
}

func validRecoveryGrant(value string) bool {
	if len(value) > conformance.AgentCredentialRecoveryMaxGrantBytes ||
		!strings.HasPrefix(value, conformance.AgentCredentialRecoveryGrantPrefix) ||
		len(value) == len(conformance.AgentCredentialRecoveryGrantPrefix) {
		return false
	}
	for _, character := range []byte(value[len(conformance.AgentCredentialRecoveryGrantPrefix):]) {
		if !recoveryGrantCharacter(character) {
			return false
		}
	}
	return true
}

func recoveryGrantCharacter(value byte) bool {
	return lowerAlphaNumeric(value) || value >= 'A' && value <= 'Z' || value == '_' || value == '-'
}
