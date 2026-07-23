package connectorcell

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"unicode/utf8"

	conformance "github.com/layervai/qurl-conformance"
)

var (
	ErrInvalidAuthorityRequest  = errors.New("connector cell: invalid authority request")
	ErrInvalidAuthorityResponse = errors.New("connector cell: invalid authority response")
)

const (
	authorityVersionPrefix = `{"version":`
	authorityPeerPrefix    = `,"authenticated_peer_public_key_b64":"`
	authorityAgentPrefix   = `","agent_id":"`
	authorityGrantPrefix   = `","recovery_grant":"`
	authorityKeyPrefix     = `","device_api_key":"`
	authoritySuffix        = `"}`
)

func encodeAuthorityRequest(request CompletionRequest) ([]byte, error) {
	// Reassert the private boundary independently of the public decoder.
	if !validAgentID(request.AgentID) || !validPeer(request.AuthenticatedPeerPublicKeyB64) ||
		!validRecoveryGrant(request.RecoveryGrant) || !validAPIKey(request.DeviceAPIKey) {
		return nil, ErrInvalidAuthorityRequest
	}
	// Build directly into the one buffer the handler owns and wipes. json.Marshal
	// would leave a second secret-bearing copy in encoding/json's pooled state.
	// Validation above restricts every value to a JSON-safe ASCII alphabet, so
	// direct append needs no escaping and the exact capacity cannot grow.
	version := strconv.Itoa(conformance.ConnectorAuthorityLambdaRequestVersion)
	wantBytes := authorityRequestBytes(request, version)
	body := make([]byte, 0, wantBytes)
	body = append(body, authorityVersionPrefix...)
	body = append(body, version...)
	body = append(body, authorityPeerPrefix...)
	body = append(body, request.AuthenticatedPeerPublicKeyB64...)
	body = append(body, authorityAgentPrefix...)
	body = append(body, request.AgentID...)
	body = append(body, authorityGrantPrefix...)
	body = append(body, request.RecoveryGrant...)
	body = append(body, authorityKeyPrefix...)
	body = append(body, request.DeviceAPIKey...)
	body = append(body, authoritySuffix...)
	if len(body) != wantBytes || cap(body) != wantBytes || len(body) > conformance.ConnectorAuthorityLambdaMaxRequestBytes {
		// Current frozen maxima fit (pinned by the max-field test). Keep this wipe
		// fail closed if the private request ceiling ever tightens independently.
		clear(body)
		return nil, ErrInvalidAuthorityRequest
	}
	return body, nil
}

func authorityRequestBytes(request CompletionRequest, version string) int {
	return len(authorityVersionPrefix) + len(version) + len(authorityPeerPrefix) +
		len(request.AuthenticatedPeerPublicKeyB64) + len(authorityAgentPrefix) + len(request.AgentID) +
		len(authorityGrantPrefix) + len(request.RecoveryGrant) + len(authorityKeyPrefix) +
		len(request.DeviceAPIKey) + len(authoritySuffix)
}

type authorityResponseKind uint8

const (
	authorityResponseSuccess authorityResponseKind = iota + 1
	authorityResponseSemanticError
)

// decodeAuthorityResponse accepts only the frozen private contract: version 1
// plus exactly result{device_api_key_id} or error{code}. In particular, private
// retry hints and diagnostics are rejected rather than reflected; the public
// codec owns the fixed retry policy and only unavailable carries a retry hint.
func decodeAuthorityResponse(raw []byte) ([]byte, authorityResponseKind, error) {
	if len(raw) == 0 || len(raw) > conformance.ConnectorAuthorityLambdaMaxResponseBytes || !utf8.Valid(raw) {
		return nil, 0, ErrInvalidAuthorityResponse
	}
	envelope, err := decodeAuthorityObject(raw, []string{"version"}, []string{"version", "result", "error"})
	if err != nil || !bytes.Equal(envelope["version"], []byte("1")) {
		return nil, 0, ErrInvalidAuthorityResponse
	}
	result, hasResult := envelope["result"]
	errorBody, hasError := envelope["error"]
	if hasResult == hasError || bytes.Equal(result, []byte("null")) || bytes.Equal(errorBody, []byte("null")) {
		return nil, 0, ErrInvalidAuthorityResponse
	}
	if hasResult {
		object, err := decodeAuthorityObject(result, []string{"device_api_key_id"}, []string{"device_api_key_id"})
		if err != nil {
			return nil, 0, ErrInvalidAuthorityResponse
		}
		keyID, ok := strictString(object["device_api_key_id"])
		if !ok {
			return nil, 0, ErrInvalidAuthorityResponse
		}
		body, encodeErr := EncodeCompletionSuccess(keyID)
		if encodeErr != nil {
			return nil, 0, ErrInvalidAuthorityResponse
		}
		return body, authorityResponseSuccess, nil
	}

	object, err := decodeAuthorityObject(errorBody, []string{"code"}, []string{"code"})
	if err != nil {
		return nil, 0, ErrInvalidAuthorityResponse
	}
	code, ok := strictString(object["code"])
	if !ok {
		return nil, 0, ErrInvalidAuthorityResponse
	}
	var kind CompletionError
	switch code {
	case "unavailable":
		kind = CompletionErrorUnavailable
	case "grant_rejected":
		kind = CompletionErrorGrantRejected
	case "identity_rejected":
		kind = CompletionErrorIdentityRejected
	case "conflict":
		kind = CompletionErrorConflict
	case "invalid_request":
		kind = CompletionErrorInvalidRequest
	default:
		return nil, 0, ErrInvalidAuthorityResponse
	}
	body, err := EncodeCompletionError(kind)
	if err != nil {
		return nil, 0, ErrInvalidAuthorityResponse
	}
	return body, authorityResponseSemanticError, nil
}

// decodeAuthorityObject deliberately stays separate from the public-request
// decoder: this private trust boundary has a different closed error taxonomy,
// and sharing the walkers would couple public telemetry to Authority failures.
func decodeAuthorityObject(raw []byte, required, allowed []string) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
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
		token, err = decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok {
			return rejectAuthorityObject(object)
		}
		if _, ok := allowedSet[key]; !ok {
			return rejectAuthorityObject(object)
		}
		if _, duplicate := object[key]; duplicate {
			return rejectAuthorityObject(object)
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			clear(value)
			return rejectAuthorityObject(object)
		}
		object[key] = value
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim('}') {
		return rejectAuthorityObject(object)
	}
	if _, err := decoder.Token(); err != io.EOF {
		return rejectAuthorityObject(object)
	}
	for _, key := range required {
		if _, ok := object[key]; !ok {
			return rejectAuthorityObject(object)
		}
	}
	return object, nil
}

func rejectAuthorityObject(object map[string]json.RawMessage) (map[string]json.RawMessage, error) {
	clearRawObject(object)
	return nil, ErrInvalidAuthorityResponse
}

func clearRawObject(object map[string]json.RawMessage) {
	for _, value := range object {
		clear(value)
	}
}

func validPeer(value string) bool {
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	// Unlike the unpadded API-key spelling, the padded peer spelling keeps this
	// round trip as an explicit exact-length and exact-padding canonicality guard.
	return err == nil && len(decoded) == x25519KeyBytes && base64.StdEncoding.EncodeToString(decoded) == value
}
