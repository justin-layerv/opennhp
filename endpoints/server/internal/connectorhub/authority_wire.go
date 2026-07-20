package connectorhub

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	conformance "github.com/layervai/qurl-conformance"
)

var (
	// ErrInvalidAuthorityRequest identifies an impossible locally produced
	// private request without retaining the credential or any identity value.
	ErrInvalidAuthorityRequest = errors.New("connector hub: invalid authority request")
	// ErrInvalidAuthorityResponse covers every private response framing,
	// structural, and semantic rejection. Authority payloads are never attached
	// to the error because they can contain assignment tickets and identities.
	ErrInvalidAuthorityResponse = errors.New("connector hub: invalid authority response")
)

type authorityResponseKind uint8

const (
	authorityResponseSuccess authorityResponseKind = iota + 1
	authorityResponseSemanticError
)

// encodeAuthorityRequest emits one of the three operation-specific v1 request
// bodies. There is deliberately no generic operation selector or envelope.
func encodeAuthorityRequest(request Request) ([]byte, error) {
	if !validAgentID(request.AgentID) || !validAuthorityPeer(request.AuthenticatedPeerPublicKeyB64) ||
		!validHubRequestID(request.HubRequestID()) {
		return nil, ErrInvalidAuthorityRequest
	}

	var value any
	switch request.Mode {
	case ModeEnroll:
		if !validAuthorityAPIKey(request.Credential) {
			return nil, ErrInvalidAuthorityRequest
		}
		value = conformance.ConnectorAuthorityIssueAssignmentRequest{
			Version: conformance.ConnectorAuthorityLambdaRequestVersion, HubRequestID: request.HubRequestID(),
			AgentID: request.AgentID, AuthenticatedPeerPublicKeyB64: request.AuthenticatedPeerPublicKeyB64,
			Credential: request.Credential,
		}
	case ModeRefresh:
		if request.Credential != "" {
			return nil, ErrInvalidAuthorityRequest
		}
		value = conformance.ConnectorAuthorityRefreshAssignmentRequest{
			Version: conformance.ConnectorAuthorityLambdaRequestVersion, HubRequestID: request.HubRequestID(),
			AgentID: request.AgentID, AuthenticatedPeerPublicKeyB64: request.AuthenticatedPeerPublicKeyB64,
		}
	case ModeRecover:
		if !validAuthorityAPIKey(request.Credential) {
			return nil, ErrInvalidAuthorityRequest
		}
		return encodeCredentialRecoveryAuthorityRequest(request)
	default:
		return nil, ErrInvalidAuthorityRequest
	}

	body, err := json.Marshal(value)
	if err != nil || len(body) > conformance.ConnectorAuthorityLambdaMaxRequestBytes {
		return nil, ErrInvalidAuthorityRequest
	}
	return body, nil
}

const (
	recoveryAuthorityVersionPrefix = `{"version":`
	recoveryAuthorityRequestID     = `,"hub_request_id":"`
	recoveryAuthorityAgentID       = `","agent_id":"`
	recoveryAuthorityPeer          = `","authenticated_peer_public_key_b64":"`
	recoveryAuthorityCredential    = `","recovery_credential":"`
	recoveryAuthoritySuffix        = `"}`
)

func encodeCredentialRecoveryAuthorityRequest(request Request) ([]byte, error) {
	// Recovery credentials are secrets. Build directly into the one buffer the
	// handler owns and wipes instead of leaving a second copy in encoding/json's
	// pooled state. Every value has already been restricted to JSON-safe ASCII.
	version := strconv.Itoa(conformance.ConnectorAuthorityLambdaRequestVersion)
	wantBytes := len(recoveryAuthorityVersionPrefix) + len(version) +
		len(recoveryAuthorityRequestID) + len(request.HubRequestID()) +
		len(recoveryAuthorityAgentID) + len(request.AgentID) +
		len(recoveryAuthorityPeer) + len(request.AuthenticatedPeerPublicKeyB64) +
		len(recoveryAuthorityCredential) + len(request.Credential) + len(recoveryAuthoritySuffix)
	if wantBytes > conformance.ConnectorAuthorityLambdaMaxRequestBytes {
		return nil, ErrInvalidAuthorityRequest
	}
	body := make([]byte, 0, wantBytes)
	body = append(body, recoveryAuthorityVersionPrefix...)
	body = append(body, version...)
	body = append(body, recoveryAuthorityRequestID...)
	body = append(body, request.HubRequestID()...)
	body = append(body, recoveryAuthorityAgentID...)
	body = append(body, request.AgentID...)
	body = append(body, recoveryAuthorityPeer...)
	body = append(body, request.AuthenticatedPeerPublicKeyB64...)
	body = append(body, recoveryAuthorityCredential...)
	body = append(body, request.Credential...)
	body = append(body, recoveryAuthoritySuffix...)
	if len(body) != wantBytes || cap(body) != wantBytes {
		clear(body)
		return nil, ErrInvalidAuthorityRequest
	}
	return body, nil
}

// decodeAuthorityResponse strictly consumes the matching operation-specific
// v1 response and converts it directly through the existing public LRT codec.
// The returned bytes are therefore the canonical public body; no map-based
// JSON round trip can lose int64 precision or reorder the frozen wire shape.
func decodeAuthorityResponse(request Request, raw []byte) ([]byte, authorityResponseKind, error) {
	envelope, err := decodeAuthorityEnvelope(raw)
	if err != nil {
		return nil, 0, err
	}

	switch request.Mode {
	case ModeEnroll:
		return decodeIssueAssignmentResponse(request.AgentID, envelope)
	case ModeRefresh:
		return decodeRefreshAssignmentResponse(request.AgentID, envelope)
	case ModeRecover:
		return decodeIssueCredentialRecoveryResponse(request.AgentID, envelope)
	default:
		return nil, 0, ErrInvalidAuthorityResponse
	}
}

type authorityEnvelope struct {
	result    json.RawMessage
	errorCode string
}

func decodeAuthorityEnvelope(raw []byte) (authorityEnvelope, error) {
	if len(raw) == 0 || len(raw) > conformance.ConnectorAuthorityLambdaMaxResponseBytes || !utf8.Valid(raw) {
		return authorityEnvelope{}, ErrInvalidAuthorityResponse
	}
	object, err := decodeExactObject(raw, []string{"version"}, []string{"version", "result", "error"})
	if err != nil || !bytes.Equal(object["version"], []byte("1")) {
		return authorityEnvelope{}, ErrInvalidAuthorityResponse
	}
	result, hasResult := object["result"]
	errorBody, hasError := object["error"]
	if hasResult == hasError || bytes.Equal(result, []byte("null")) || bytes.Equal(errorBody, []byte("null")) {
		return authorityEnvelope{}, ErrInvalidAuthorityResponse
	}
	if hasResult {
		return authorityEnvelope{result: result}, nil
	}

	errorObject, err := decodeExactObject(errorBody, []string{"code"}, []string{"code", "retry_after_seconds"})
	if err != nil {
		return authorityEnvelope{}, ErrInvalidAuthorityResponse
	}
	// No Hub operation permits retry_after_seconds in an Authority response.
	// Hub-local rate limiting is a separate pre-invoke decision.
	if _, present := errorObject["retry_after_seconds"]; present {
		return authorityEnvelope{}, ErrInvalidAuthorityResponse
	}
	var code string
	if err := json.Unmarshal(errorObject["code"], &code); err != nil || code == "" {
		return authorityEnvelope{}, ErrInvalidAuthorityResponse
	}
	return authorityEnvelope{errorCode: code}, nil
}

func decodeIssueAssignmentResponse(expectedAgentID string, envelope authorityEnvelope) ([]byte, authorityResponseKind, error) {
	if envelope.errorCode != "" {
		kind, ok := issueAssignmentError(envelope.errorCode)
		if !ok {
			return nil, 0, ErrInvalidAuthorityResponse
		}
		body, err := EncodeEnrollError(kind, nil)
		if err != nil {
			return nil, 0, ErrInvalidAuthorityResponse
		}
		return body, authorityResponseSemanticError, nil
	}

	object, err := decodeClosedObject(envelope.result,
		[]string{"agent_id", "registration", "assignment", "assignment_ticket", "assignment_ticket_expires_at"})
	if err != nil {
		return nil, 0, ErrInvalidAuthorityResponse
	}
	if _, err := decodeClosedObject(object["registration"], []string{"key_id", "key_kind"}); err != nil {
		return nil, 0, ErrInvalidAuthorityResponse
	}
	if err := validateAuthorityAssignmentShape(object["assignment"]); err != nil {
		return nil, 0, err
	}

	var result conformance.ConnectorAuthorityIssueAssignmentResult
	if err := json.Unmarshal(envelope.result, &result); err != nil || result.AgentID != expectedAgentID {
		return nil, 0, ErrInvalidAuthorityResponse
	}
	assignment, err := assignmentFromAuthority(result.Assignment)
	if err != nil {
		return nil, 0, err
	}
	ticketExpiry, err := parseAuthorityTime(result.AssignmentTicketExpiresAt)
	if err != nil {
		return nil, 0, err
	}
	body, err := EncodeEnrollSuccess(EnrollSuccess{
		AgentID: result.AgentID,
		Registration: Registration{
			KeyID: result.Registration.KeyID, KeyKind: RegistrationKeyKind(result.Registration.KeyKind),
		},
		Assignment: assignment, AssignmentTicket: result.AssignmentTicket,
		AssignmentTicketExpiresAt: ticketExpiry,
	})
	if err != nil {
		return nil, 0, ErrInvalidAuthorityResponse
	}
	return body, authorityResponseSuccess, nil
}

func decodeRefreshAssignmentResponse(expectedAgentID string, envelope authorityEnvelope) ([]byte, authorityResponseKind, error) {
	if envelope.errorCode != "" {
		kind, ok := refreshAssignmentError(envelope.errorCode)
		if !ok {
			return nil, 0, ErrInvalidAuthorityResponse
		}
		body, err := EncodeRefreshError(kind, nil)
		if err != nil {
			return nil, 0, ErrInvalidAuthorityResponse
		}
		return body, authorityResponseSemanticError, nil
	}

	object, err := decodeClosedObject(envelope.result, []string{"agent_id", "assignment"})
	if err != nil {
		return nil, 0, ErrInvalidAuthorityResponse
	}
	if err := validateAuthorityAssignmentShape(object["assignment"]); err != nil {
		return nil, 0, err
	}
	var result conformance.ConnectorAuthorityRefreshAssignmentResult
	if err := json.Unmarshal(envelope.result, &result); err != nil || result.AgentID != expectedAgentID {
		return nil, 0, ErrInvalidAuthorityResponse
	}
	assignment, err := assignmentFromAuthority(result.Assignment)
	if err != nil {
		return nil, 0, err
	}
	body, err := EncodeRefreshSuccess(RefreshSuccess{AgentID: result.AgentID, Assignment: assignment})
	if err != nil {
		return nil, 0, ErrInvalidAuthorityResponse
	}
	return body, authorityResponseSuccess, nil
}

func validateAuthorityAssignmentShape(raw []byte) error {
	object, err := decodeClosedObject(raw,
		[]string{"cell_id", "assignment_generation", "endpoint_revision", "lease_expires_at", "nhp_udp_endpoint"})
	if err != nil {
		return ErrInvalidAuthorityResponse
	}
	if _, err := decodeClosedObject(object["nhp_udp_endpoint"],
		[]string{"host", "port", "server_public_key_b64"}); err != nil {
		return ErrInvalidAuthorityResponse
	}
	return nil
}

func assignmentFromAuthority(value conformance.ConnectorAuthorityAssignmentResult) (Assignment, error) {
	if value.NHPUDPEndpoint.Port < 1 || value.NHPUDPEndpoint.Port > 65535 {
		return Assignment{}, ErrInvalidAuthorityResponse
	}
	leaseExpiry, err := parseAuthorityTime(value.LeaseExpiresAt)
	if err != nil {
		return Assignment{}, err
	}
	return Assignment{
		CellID: value.CellID, AssignmentGeneration: value.AssignmentGeneration,
		EndpointRevision: value.EndpointRevision, LeaseExpiresAt: leaseExpiry,
		Endpoint: UDPEndpoint{
			Host: value.NHPUDPEndpoint.Host, Port: uint16(value.NHPUDPEndpoint.Port),
			ServerPublicKeyB64: value.NHPUDPEndpoint.ServerPublicKeyB64,
		},
	}, nil
}

func issueAssignmentError(code string) (EnrollError, bool) {
	switch code {
	case "invalid_request":
		return EnrollErrorInvalidInput, true
	case "credential_invalid":
		return EnrollErrorInvalidAPIKey, true
	case "credential_consumed":
		return EnrollErrorBootstrapConsumed, true
	case "unavailable":
		return EnrollErrorAssignmentUnavailable, true
	default:
		return 0, false
	}
}

func refreshAssignmentError(code string) (AssignmentError, bool) {
	switch code {
	case "invalid_request":
		return AssignmentErrorInvalidRequest, true
	case "identity_rejected":
		return AssignmentErrorIdentityRejected, true
	case "reassignment_in_progress":
		return AssignmentErrorReassignmentInProgress, true
	case "unavailable":
		return AssignmentErrorUnavailable, true
	default:
		return 0, false
	}
}

func parseAuthorityTime(value string) (time.Time, error) {
	if !strings.HasSuffix(value, "Z") {
		return time.Time{}, ErrInvalidAuthorityResponse
	}
	parsed, err := time.Parse(time.RFC3339, value)
	// Location checks the parsed semantic instant; the round trip separately
	// pins the only accepted wire spelling (second precision with trailing Z).
	if err != nil || parsed.Location() != time.UTC || parsed.Nanosecond() != 0 || parsed.Format(time.RFC3339) != value {
		return time.Time{}, ErrInvalidAuthorityResponse
	}
	return parsed, nil
}

func validAuthorityAPIKey(value string) bool {
	// Connector Authority v1 deliberately accepts only the canonical qURL
	// API-key wire format. Keep this mirror aligned with qurl-service's
	// apikeyhash.ParseCanonical contract; a future credential kind requires a
	// versioned private contract before Hub may forward it.
	if len(value) != 51 {
		return false
	}
	prefix := "lv_live_"
	if strings.HasPrefix(value, "lv_test_") {
		prefix = "lv_test_"
	} else if !strings.HasPrefix(value, prefix) {
		return false
	}
	encoded := value[len(prefix):]
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	defer clear(decoded)
	// Exact encoded length plus Strict decoding pins the canonical unpadded
	// base64url spelling, including zero trailing pad bits.
	return err == nil && len(decoded) == 32
}

func validAuthorityPeer(value string) bool {
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	return err == nil && len(decoded) == x25519PublicKeyBytes && base64.StdEncoding.EncodeToString(decoded) == value
}

func validHubRequestID(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range []byte(value) {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

// decodeClosedObject decodes a JSON object whose entire key set is both required
// and allowed—the common case where every field must be present exactly once.
func decodeClosedObject(raw []byte, keys []string) (map[string]json.RawMessage, error) {
	return decodeExactObject(raw, keys, keys)
}

func decodeExactObject(raw []byte, required, allowed []string) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, ErrInvalidAuthorityResponse
	}
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, key := range allowed {
		allowedSet[key] = struct{}{}
	}
	object := make(map[string]json.RawMessage, len(allowed))
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok {
			return nil, ErrInvalidAuthorityResponse
		}
		if _, ok := allowedSet[key]; !ok {
			return nil, ErrInvalidAuthorityResponse
		}
		if _, duplicate := object[key]; duplicate {
			return nil, ErrInvalidAuthorityResponse
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, ErrInvalidAuthorityResponse
		}
		object[key] = value
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim('}') {
		return nil, ErrInvalidAuthorityResponse
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, ErrInvalidAuthorityResponse
	}
	for _, key := range required {
		if _, ok := object[key]; !ok {
			return nil, ErrInvalidAuthorityResponse
		}
	}
	return object, nil
}
