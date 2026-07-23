// Package connectorcell owns the strict assigned-cell qURL Connector lifecycle
// codecs and one-attempt application handlers composed by the NHP UDP server.
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

	// completionInvalidRequestJSON is fixed wire data, not a template. Keeping
	// the relay rejection on this infallible path makes RelayRejected a truthful
	// policy-decision metric rather than conflating an encoder failure.
	completionInvalidRequestJSON = `{"errCode":"52414","errMsg":"invalid credential replacement request"}`

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
	request, _, rejection, err := decodeRoutedCompletionRequest(raw, authenticatedPeer)
	return request, rejection, err
}

// routedCompletionEnvelope retains the bounded strict-decode values only after
// the allocation-free route probe selected this operation and the body passed
// the public size limit. Every RawMessage is cleared after validation.
type routedCompletionEnvelope struct {
	root      *trackedObject
	data      *trackedObject
	rejection RequestRejection
	err       error
}

func (e *routedCompletionEnvelope) clear() {
	if e == nil {
		return
	}
	if e.root != nil {
		e.root.clear()
	}
	if e.data != nil {
		e.data.clear()
	}
}

// decodeRoutedCompletionRequest uses a two-stage trust boundary: a no-allocation
// structural probe recognizes intent without touching secrets, then the bounded
// strict decoder is the sole path that can construct Authority input. Any exact
// aspId/query pair is routed even when duplicate, unknown, trailing, null, or
// wrongly typed fields make the request invalid, keeping malformed recovery off
// the generic ListService plugin seam.
func decodeRoutedCompletionRequest(raw, authenticatedPeer []byte) (CompletionRequest, bool, RequestRejection, error) {
	routed := routeCompletionIntent(raw)
	if len(authenticatedPeer) != x25519KeyBytes {
		return CompletionRequest{}, routed, RequestRejectionPeer, ErrInvalidAuthenticatedPeer
	}
	if len(raw) > conformance.AgentCredentialRecoveryMaxBodyBytes {
		// The route probe intentionally scans up to core's 1 MiB decrypted-body
		// ceiling so oversized recovery intent cannot escape into generic LST
		// dispatch. Only bodies within this much smaller frozen public limit reach
		// strict decoding or Authority construction.
		return CompletionRequest{}, routed, RequestRejectionBodySize, ErrCompletionRequestTooLarge
	}
	if !routed {
		return CompletionRequest{}, false, RequestRejectionSemantic, ErrInvalidCompletionRequest
	}
	envelope := parseCompletionEnvelope(raw)
	if envelope == nil {
		return CompletionRequest{}, true, RequestRejectionBodyParse, ErrInvalidCompletionRequest
	}
	defer envelope.clear()
	if envelope.err != nil {
		return CompletionRequest{}, true, envelope.rejection, ErrInvalidCompletionRequest
	}

	root := envelope.root
	data := envelope.data
	userID, userOK := trackedStrictString(root, "usrId")
	agentID, agentOK := trackedStrictString(root, "devId")
	aspID, aspOK := trackedStrictString(root, "aspId")
	query, queryOK := trackedStrictString(data, "query")
	grant, grantOK := trackedStrictString(data, "recovery_grant")
	deviceKey, keyOK := trackedStrictString(data, "device_api_key")
	version := trackedSingleValue(data, "version")
	// The frozen v0.9 contract classifies wrong JSON types for root scalar
	// fields as body_parse. Keep that decision explicit rather than deriving it
	// accidentally from semantic validation below.
	if !userOK || !agentOK || !aspOK || !queryOK || !grantOK || !keyOK {
		return CompletionRequest{}, true, RequestRejectionBodyParse, ErrInvalidCompletionRequest
	}
	if userID != "" || !validAgentID(agentID) || aspID != completionAspID || query != completionQuery ||
		!bytes.Equal(version, []byte("1")) || !validRecoveryGrant(grant) || !validAPIKey(deviceKey) {
		return CompletionRequest{}, true, RequestRejectionSemantic, ErrInvalidCompletionRequest
	}

	return CompletionRequest{
		AgentID: agentID, AuthenticatedPeerPublicKeyB64: base64.StdEncoding.EncodeToString(authenticatedPeer),
		RecoveryGrant: grant, DeviceAPIKey: deviceKey,
	}, true, "", nil
}

func parseCompletionEnvelope(raw []byte) *routedCompletionEnvelope {
	// Strict decoding is confined to the frozen public body limit. Oversized
	// routing uses the allocation-free probe and can only select fixed rejection;
	// this parser is the sole path that can produce Authority input.
	if len(raw) == 0 || len(raw) > conformance.AgentCredentialRecoveryMaxBodyBytes {
		return nil
	}
	invalidUTF8 := !utf8.Valid(raw)

	envelope := &routedCompletionEnvelope{}
	root := decodeTrackedObject(raw, func(key string, value json.RawMessage) bool {
		if key == "usrData" {
			data := decodeTrackedObject(value, nil, "query", "version", "recovery_grant", "device_api_key")
			if envelope.data == nil {
				envelope.data = data
			} else {
				data.clear()
			}
			// The nested object has already consumed this encoding. Do not retain
			// a second copy on the root object.
			return false
		}
		return true
	}, "usrId", "devId", "aspId", "usrData")
	envelope.root = root
	// The route probe may conservatively recognize a pair before malformed trailing
	// bytes. Authority input still requires fully valid UTF-8 and strict JSON here.
	if invalidUTF8 {
		envelope.rejection, envelope.err = RequestRejectionBodyParse, ErrInvalidCompletionRequest
		return envelope
	}
	if rejection := root.strictRejection("usrId", "devId", "aspId", "usrData"); rejection != "" {
		envelope.rejection, envelope.err = rejection, ErrInvalidCompletionRequest
		return envelope
	}
	if root.count("usrData") != 1 || envelope.data == nil {
		envelope.rejection, envelope.err = RequestRejectionBodyParse, ErrInvalidCompletionRequest
		return envelope
	}
	if rejection := envelope.data.strictRejection("query", "version", "recovery_grant", "device_api_key"); rejection != "" {
		envelope.rejection, envelope.err = rejection, ErrInvalidCompletionRequest
	}
	return envelope
}

type trackedObject struct {
	values  map[string]*trackedValue
	unknown bool
	syntax  bool
}

type trackedValue struct {
	count int
	value json.RawMessage
}

// decodeTrackedObject scans an object once, retaining at most the first value
// for each allowed key. observe may inspect every allowed occurrence and decide
// whether that first value should be retained. Duplicate encodings are cleared
// immediately, keeping both CPU and retained memory linear in the input size.
func decodeTrackedObject(
	raw []byte,
	observe func(string, json.RawMessage) bool,
	keys ...string,
) *trackedObject {
	object := &trackedObject{values: make(map[string]*trackedValue, len(keys))}
	allowed := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		allowed[key] = struct{}{}
		object.values[key] = &trackedValue{}
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return object
	}
	for decoder.More() {
		token, err = decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok {
			return object
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			clear(value)
			return object
		}
		if _, ok := allowed[key]; !ok {
			object.unknown = true
			clear(value)
			continue
		}
		tracked := object.values[key]
		tracked.count++
		retain := true
		if observe != nil {
			retain = observe(key, value)
		}
		if tracked.count == 1 && retain {
			tracked.value = value
		} else {
			clear(value)
		}
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim('}') {
		return object
	}
	if _, err := decoder.Token(); err != io.EOF {
		return object
	}
	object.syntax = true
	return object
}

func (o *trackedObject) strictRejection(keys ...string) RequestRejection {
	if o == nil || !o.syntax || o.unknown {
		return RequestRejectionBodyParse
	}
	for _, key := range keys {
		switch o.count(key) {
		case 0:
			return RequestRejectionSemantic
		case 1:
		default:
			return RequestRejectionBodyParse
		}
	}
	return ""
}

func (o *trackedObject) clear() {
	if o == nil {
		return
	}
	for _, tracked := range o.values {
		clear(tracked.value)
	}
}

func (o *trackedObject) count(key string) int {
	if o == nil || o.values[key] == nil {
		return 0
	}
	return o.values[key].count
}

func trackedSingleValue(object *trackedObject, key string) json.RawMessage {
	if object == nil || object.count(key) != 1 || object.values[key] == nil {
		return nil
	}
	return object.values[key].value
}

func trackedStrictString(object *trackedObject, key string) (string, bool) {
	return strictString(trackedSingleValue(object, key))
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
		return completionInvalidRequestBody(), nil
	default:
		return nil, ErrInvalidCompletionError
	}
	return marshalBounded(value)
}

func completionInvalidRequestBody() []byte {
	return []byte(completionInvalidRequestJSON)
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
