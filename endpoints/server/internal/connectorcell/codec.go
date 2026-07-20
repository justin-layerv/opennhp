// Package connectorcell owns strict assigned-cell qURL Connector application
// codecs. It is deliberately dark: a later runtime slice composes it with an
// NHP LST worker and the separately permissioned cell Authority client.
package connectorcell

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"unicode/utf8"

	conformance "github.com/layervai/qurl-conformance"
)

const (
	completionQuery   = "agent_credential_recovery"
	completionVersion = 1
	completionAspID   = "agent"
	x25519KeyBytes    = 32

	// qurl-conformance freezes production-shaped candidates but does not
	// export the device-key prefixes or secret length. Keep this local pin
	// cross-checked against its golden candidate in codec_test.go.
	deviceAPIKeySecretBytes = 32
)

var (
	ErrInvalidAuthenticatedPeer  = errors.New("connector cell: invalid authenticated peer")
	ErrInvalidCompletionRequest  = errors.New("connector cell: invalid credential recovery request")
	ErrCompletionRequestTooLarge = errors.New("connector cell: credential recovery request too large")
	ErrInvalidCompletionSuccess  = errors.New("connector cell: invalid credential recovery success")
	ErrInvalidCompletionError    = errors.New("connector cell: invalid credential recovery error")
	ErrCompletionEncoding        = errors.New("connector cell: credential recovery encoding failed")
)

// RequestRejection is a closed, secret-free telemetry classification.
type RequestRejection string

const (
	RequestRejectionBodyParse RequestRejection = "body_parse"
	RequestRejectionSemantic  RequestRejection = "semantic"
	RequestRejectionPeer      RequestRejection = "authenticated_peer"
	RequestRejectionBodySize  RequestRejection = "body_size"
)

// CompletionRequest is one authenticated same-agent replacement request.
// RecoveryGrant and DeviceAPIKey are secret-bearing and must never be logged.
// They are strings and therefore cannot be wiped. The handler clears the
// Authority request and response byte buffers it owns; callers retain
// responsibility for their public input buffers.
type CompletionRequest struct {
	AgentID                       string
	AuthenticatedPeerPublicKeyB64 string
	RecoveryGrant                 string
	DeviceAPIKey                  string
}

// DecodeCompletionRequest strictly consumes one assigned-cell public request.
func DecodeCompletionRequest(raw, authenticatedPeer []byte) (CompletionRequest, RequestRejection, error) {
	if len(authenticatedPeer) != x25519KeyBytes {
		return CompletionRequest{}, RequestRejectionPeer, ErrInvalidAuthenticatedPeer
	}
	if len(raw) > conformance.AgentCredentialRecoveryMaxBodyBytes {
		return CompletionRequest{}, RequestRejectionBodySize, ErrCompletionRequestTooLarge
	}
	if len(raw) == 0 || !utf8.Valid(raw) {
		return CompletionRequest{}, RequestRejectionBodyParse, ErrInvalidCompletionRequest
	}

	root, err := decodeClosedObject(raw, "usrId", "devId", "aspId", "usrData")
	if err != nil {
		return CompletionRequest{}, requestClass(err), ErrInvalidCompletionRequest
	}
	userID, ok := strictString(root["usrId"])
	agentID, agentOK := strictString(root["devId"])
	aspID, aspOK := strictString(root["aspId"])
	data, dataErr := decodeClosedObject(root["usrData"], "query", "version", "recovery_grant", "device_api_key")
	// The frozen v0.9 contract classifies wrong JSON types for root scalar
	// fields as body_parse. Keep that decision explicit rather than deriving it
	// accidentally from a nil nested-object error.
	if !ok || !agentOK || !aspOK {
		return CompletionRequest{}, RequestRejectionBodyParse, ErrInvalidCompletionRequest
	}
	if dataErr != nil {
		return CompletionRequest{}, requestClass(dataErr), ErrInvalidCompletionRequest
	}
	query, queryOK := strictString(data["query"])
	grant, grantOK := strictString(data["recovery_grant"])
	deviceKey, keyOK := strictString(data["device_api_key"])
	// Compare the raw JSON number token so 1.0 and 1e0 cannot alias version 1.
	if userID != "" || !validAgentID(agentID) || aspID != completionAspID ||
		!queryOK || query != completionQuery || !bytes.Equal(data["version"], []byte("1")) ||
		!grantOK || !validRecoveryGrant(grant) || !keyOK || !validAPIKey(deviceKey) {
		return CompletionRequest{}, RequestRejectionSemantic, ErrInvalidCompletionRequest
	}

	return CompletionRequest{
		AgentID: agentID, AuthenticatedPeerPublicKeyB64: base64.StdEncoding.EncodeToString(authenticatedPeer),
		RecoveryGrant: grant, DeviceAPIKey: deviceKey,
	}, "", nil
}

type completionListWire struct {
	Query          string `json:"query"`
	Version        int    `json:"version"`
	DeviceAPIKeyID string `json:"device_api_key_id"`
}

type completionSuccessWire struct {
	ErrCode string             `json:"errCode"`
	List    completionListWire `json:"list"`
}

// EncodeCompletionSuccess emits the exact secret-free assigned-cell LRT.
func EncodeCompletionSuccess(deviceAPIKeyID string) ([]byte, error) {
	if !validAPIKeyID(deviceAPIKeyID) {
		return nil, ErrInvalidCompletionSuccess
	}
	return marshalBounded(completionSuccessWire{
		ErrCode: "0",
		List:    completionListWire{Query: completionQuery, Version: completionVersion, DeviceAPIKeyID: deviceAPIKeyID},
	})
}

// CompletionError is the closed 52410-52414 assigned-cell vocabulary.
type CompletionError uint8

const (
	CompletionErrorUnavailable CompletionError = iota + 1
	CompletionErrorGrantRejected
	CompletionErrorIdentityRejected
	CompletionErrorConflict
	CompletionErrorInvalidRequest
)

type errorWire struct {
	ErrCode           string  `json:"errCode"`
	ErrMsg            string  `json:"errMsg"`
	RetryAfterSeconds *uint32 `json:"retryAfterSeconds,omitempty"`
}

// EncodeCompletionError emits one frozen error; unavailable always retries at five seconds.
func EncodeCompletionError(kind CompletionError) ([]byte, error) {
	var value errorWire
	switch kind {
	case CompletionErrorUnavailable:
		retry := uint32(5)
		value = errorWire{ErrCode: "52410", ErrMsg: "credential replacement temporarily unavailable", RetryAfterSeconds: &retry}
	case CompletionErrorGrantRejected:
		value = errorWire{ErrCode: "52411", ErrMsg: "credential recovery grant rejected"}
	case CompletionErrorIdentityRejected:
		value = errorWire{ErrCode: "52412", ErrMsg: "credential recovery identity rejected"}
	case CompletionErrorConflict:
		value = errorWire{ErrCode: "52413", ErrMsg: "different replacement credential candidate already recorded"}
	case CompletionErrorInvalidRequest:
		value = errorWire{ErrCode: "52414", ErrMsg: "invalid credential replacement request"}
	default:
		return nil, ErrInvalidCompletionError
	}
	return marshalBounded(value)
}

type classifiedDecodeError struct{ class RequestRejection }

func (e *classifiedDecodeError) Error() string { return ErrInvalidCompletionRequest.Error() }

func requestClass(err error) RequestRejection {
	var classified *classifiedDecodeError
	if errors.As(err, &classified) {
		return classified.class
	}
	return RequestRejectionBodyParse
}

func decodeClosedObject(raw []byte, keys ...string) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, &classifiedDecodeError{class: RequestRejectionBodyParse}
	}
	allowed := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		allowed[key] = struct{}{}
	}
	object := make(map[string]json.RawMessage, len(keys))
	for decoder.More() {
		token, err = decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok {
			return nil, &classifiedDecodeError{class: RequestRejectionBodyParse}
		}
		if _, ok := allowed[key]; !ok {
			return nil, &classifiedDecodeError{class: RequestRejectionBodyParse}
		}
		if _, duplicate := object[key]; duplicate {
			return nil, &classifiedDecodeError{class: RequestRejectionBodyParse}
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, &classifiedDecodeError{class: RequestRejectionBodyParse}
		}
		object[key] = value
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim('}') {
		return nil, &classifiedDecodeError{class: RequestRejectionBodyParse}
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, &classifiedDecodeError{class: RequestRejectionBodyParse}
	}
	if len(object) != len(keys) {
		return nil, &classifiedDecodeError{class: RequestRejectionSemantic}
	}
	return object, nil
}

func strictString(raw json.RawMessage) (string, bool) {
	var value string
	if raw == nil || bytes.Equal(raw, []byte("null")) || json.Unmarshal(raw, &value) != nil {
		return "", false
	}
	return value, true
}

func validAgentID(value string) bool {
	if len(value) < 2 || len(value) > 64 {
		return false
	}
	if !lowerAlphaNumeric(value[0]) || !lowerAlphaNumeric(value[len(value)-1]) {
		return false
	}
	for _, character := range []byte(value[1 : len(value)-1]) {
		if !lowerAlphaNumeric(character) && character != '-' {
			return false
		}
	}
	return true
}

func validRecoveryGrant(value string) bool {
	if len(value) > conformance.AgentCredentialRecoveryMaxGrantBytes ||
		!strings.HasPrefix(value, conformance.AgentCredentialRecoveryGrantPrefix) ||
		len(value) == len(conformance.AgentCredentialRecoveryGrantPrefix) {
		return false
	}
	for _, character := range []byte(value[len(conformance.AgentCredentialRecoveryGrantPrefix):]) {
		if !lowerAlphaNumeric(character) && (character < 'A' || character > 'Z') && character != '_' && character != '-' {
			return false
		}
	}
	return true
}

func validAPIKey(value string) bool {
	if len(value) != len("lv_live_")+base64.RawURLEncoding.EncodedLen(deviceAPIKeySecretBytes) {
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
	return err == nil && len(decoded) == deviceAPIKeySecretBytes
}

func validAPIKeyID(value string) bool {
	if len(value) != conformance.AgentAPIKeyIDTotalLength || !strings.HasPrefix(value, conformance.AgentAPIKeyIDPrefix) {
		return false
	}
	for _, character := range []byte(value[len(conformance.AgentAPIKeyIDPrefix):]) {
		if !lowerAlphaNumeric(character) && (character < 'A' || character > 'Z') {
			return false
		}
	}
	return true
}

func lowerAlphaNumeric(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= '0' && value <= '9'
}

func marshalBounded(value any) ([]byte, error) {
	body, err := json.Marshal(value)
	if err != nil || len(body) > conformance.AgentCredentialRecoveryMaxBodyBytes {
		return nil, ErrCompletionEncoding
	}
	return body, nil
}
