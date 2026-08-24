package common

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	// RegisteredAgentAuthServiceID is the umbrella auth-service identifier for
	// keypair-backed registered-agent knocks. The endpoint plugin keeps its
	// literal PluginID for the Terraform lockstep lint and tests it against this
	// protocol constant.
	RegisteredAgentAuthServiceID = "agent"

	// AgentKnockRunIDLength is the exact lowercase-hex length of the caller-owned
	// knock/Login cycle identifier (8 random bytes).
	AgentKnockRunIDLength = 16
)

// ErrInvalidAgentKnockRunID classifies a syntactically present but noncanonical
// AgentKnockMsg runId. Error text intentionally excludes the rejected value.
// Server boundaries translate it to the public protocol error
// [ErrKnockRunIDInvalid] (52025).
var ErrInvalidAgentKnockRunID = errors.New("invalid agent knock runId")

// ValidateAgentKnockRunID accepts exactly 16 lowercase hexadecimal ASCII
// characters. It deliberately rejects empty input; generic AgentKnockMsg JSON
// decoding applies it only when runId is nonempty, while the registered-agent
// UDP boundary applies it unconditionally.
func ValidateAgentKnockRunID(runID string) error {
	if len(runID) != AgentKnockRunIDLength {
		return fmt.Errorf("%w: must contain exactly %d lowercase hexadecimal characters", ErrInvalidAgentKnockRunID, AgentKnockRunIDLength)
	}
	for i := 0; i < len(runID); i++ {
		c := runID[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return fmt.Errorf("%w: must contain exactly %d lowercase hexadecimal characters", ErrInvalidAgentKnockRunID, AgentKnockRunIDLength)
		}
	}
	return nil
}

// ValidateAgentKnockRunIDForAuthService applies the outbound RunID policy used
// by agent and SDK edges. Registered-agent knocks require a canonical RunID;
// other auth services may omit it, but any supplied value must be canonical.
// This is intentionally stricter than the server message gate for non-agent
// services, where generic decoding has already validated a nonempty RunID.
func ValidateAgentKnockRunIDForAuthService(authServiceID, runID string) error {
	if runID == "" {
		if authServiceID == RegisteredAgentAuthServiceID {
			return ErrInvalidAgentKnockRunID
		}
		return nil
	}
	return ValidateAgentKnockRunID(runID)
}

// UnmarshalJSON implements the generic AgentKnockMsg parser contract:
//
//   - missing and empty runId remain valid for explicit legacy/non-Connector
//     callers;
//   - every wire body must be one JSON object (null/scalars are rejected);
//   - every malformed nonempty runId is rejected;
//   - duplicate runId/runAttempt fields are rejected before decoding; and
//   - runId/runAttempt aliases are rejected instead of being accepted by encoding/json's
//     case-insensitive field matching.
//
// Unknown non-alias fields remain tolerated for the existing forward-compatible
// NHP message contract, including encoding/json's historical last-value-wins
// behavior for unrelated duplicate fields. The native registered-agent UDP
// boundary separately requires a nonempty canonical value before authentication
// or AC work. Because this method belongs to the shared AgentKnockMsg type, the
// unambiguous shape and canonical-nonempty-value rules deliberately apply before
// auth-service dispatch on every knock. runId is a new field, so no legacy wire
// producer has a prior alias or malformed-value contract to preserve.
func (m *AgentKnockMsg) UnmarshalJSON(data []byte) error {
	if m == nil {
		return errors.New("common.AgentKnockMsg: UnmarshalJSON on nil receiver")
	}
	// Alias avoids recursively invoking this method.
	type agentKnockMsgAlias AgentKnockMsg
	var decoded agentKnockMsgAlias
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	// Run the ambiguity scan only after encoding/json has established valid JSON
	// within its standard nesting limit. The scanner then requires the top-level
	// object and is iterative and allocation-bounded even when a compressed
	// packet expands to the 1 MiB plaintext ceiling; it inspects only top-level
	// key spellings and value types encoding/json cannot enforce for the RunID
	// contract.
	if err := validateAgentKnockJSONStructure(data); err != nil {
		return err
	}
	if decoded.RunID != "" {
		if err := ValidateAgentKnockRunID(decoded.RunID); err != nil {
			return err
		}
	}
	if err := validateNativeSessionOperationProjection(AgentKnockMsg(decoded)); err != nil {
		return err
	}
	if NativeSessionOperationPresent(AgentKnockMsg(decoded)) && len(data) > NativeSessionOperationMaxKnockJSONBytes {
		return errors.New("agent knock JSON native session operation exceeds its wire ceiling")
	}
	*m = AgentKnockMsg(decoded)
	return nil
}

// Ten ASCII bytes in runAttempt can each be represented as one six-byte
// \uXXXX escape, plus quotes. The cap keeps alias classification bounded.
const maxEncodedAgentKnockBindingKeyBytes = 62

type agentKnockJSONKeyClass uint8

const (
	agentKnockJSONKeyOther agentKnockJSONKeyClass = iota
	agentKnockJSONKeyRunID
	agentKnockJSONKeyRunIDAlias
	agentKnockJSONKeyRunAttempt
	agentKnockJSONKeyRunAttemptAlias
	agentKnockJSONKeyOperationID
	agentKnockJSONKeyOperationIDAlias
	agentKnockJSONKeyBindingSHA256
	agentKnockJSONKeyBindingSHA256Alias
	agentKnockJSONKeyOwnerID
	agentKnockJSONKeyOwnerIDAlias
	agentKnockJSONKeyPreparedAtMillis
	agentKnockJSONKeyPreparedAtMillisAlias
	agentKnockJSONKeyExpiresAtMillis
	agentKnockJSONKeyExpiresAtMillisAlias
)

const nativeSessionOperationFieldCount = 5

func validateAgentKnockJSONStructure(data []byte) error {
	i := skipAgentKnockJSONWhitespace(data, 0)
	if i >= len(data) || data[i] != '{' {
		return errors.New("agent knock JSON must be an object")
	}
	i++
	seenRunID := false
	seenRunAttempt := false
	unknownOperationKey := false
	seenOperationFields := make(map[agentKnockJSONKeyClass]struct{}, nativeSessionOperationFieldCount)
	for {
		i = skipAgentKnockJSONWhitespace(data, i)
		if i >= len(data) {
			return errors.New("agent knock JSON object is not closed")
		}
		if data[i] == '}' {
			i++
			break
		}
		if data[i] != '"' {
			return errors.New("agent knock JSON object key is not a string")
		}
		keyEnd := scanAgentKnockJSONStringEnd(data, i)
		if keyEnd < 0 {
			return errors.New("agent knock JSON object key is not closed")
		}
		keyClass := classifyAgentKnockJSONKey(data[i:keyEnd])
		if !canonicalAgentKnockWireKey(data[i:keyEnd]) {
			unknownOperationKey = true
		}
		i = skipAgentKnockJSONWhitespace(data, keyEnd)
		if i >= len(data) || data[i] != ':' {
			return errors.New("agent knock JSON object key has no value")
		}
		i = skipAgentKnockJSONWhitespace(data, i+1)

		switch keyClass {
		case agentKnockJSONKeyRunID:
			if seenRunID {
				return errors.New("agent knock JSON contains duplicate runId")
			}
			seenRunID = true
			if i >= len(data) || data[i] != '"' {
				return errors.New("agent knock JSON runId must be a string")
			}
		case agentKnockJSONKeyRunIDAlias:
			return errors.New("agent knock JSON contains an unsupported runId alias")
		case agentKnockJSONKeyRunAttempt:
			if seenRunAttempt {
				return errors.New("agent knock JSON contains duplicate runAttempt")
			}
			seenRunAttempt = true
		case agentKnockJSONKeyRunAttemptAlias:
			return errors.New("agent knock JSON contains an unsupported runAttempt alias")
		case agentKnockJSONKeyOperationID, agentKnockJSONKeyBindingSHA256, agentKnockJSONKeyOwnerID,
			agentKnockJSONKeyPreparedAtMillis, agentKnockJSONKeyExpiresAtMillis:
			if _, duplicate := seenOperationFields[keyClass]; duplicate {
				return errors.New("agent knock JSON contains a duplicate native session operation field")
			}
			seenOperationFields[keyClass] = struct{}{}
		case agentKnockJSONKeyOperationIDAlias, agentKnockJSONKeyBindingSHA256Alias,
			agentKnockJSONKeyOwnerIDAlias, agentKnockJSONKeyPreparedAtMillisAlias,
			agentKnockJSONKeyExpiresAtMillisAlias:
			return errors.New("agent knock JSON contains an unsupported native session operation field alias")
		}

		valueEnd, delimiter := scanAgentKnockJSONValueEnd(data, i)
		if valueEnd < 0 {
			return errors.New("agent knock JSON value is not closed")
		}
		if keyClass == agentKnockJSONKeyRunAttempt {
			var attempt uint64
			raw := bytes.TrimSpace(data[i:valueEnd])
			if err := json.Unmarshal(raw, &attempt); err != nil || attempt == 0 ||
				!bytes.Equal(raw, []byte(strconv.FormatUint(attempt, 10))) {
				return errors.New("agent knock JSON runAttempt must be a canonical positive uint64 number")
			}
		}
		if keyClass == agentKnockJSONKeyPreparedAtMillis || keyClass == agentKnockJSONKeyExpiresAtMillis {
			var millis int64
			raw := bytes.TrimSpace(data[i:valueEnd])
			if err := json.Unmarshal(raw, &millis); err != nil || millis <= 0 ||
				!bytes.Equal(raw, []byte(strconv.FormatInt(millis, 10))) {
				return errors.New("agent knock JSON native session operation time must be a canonical positive int64 number")
			}
		}
		if keyClass == agentKnockJSONKeyOperationID || keyClass == agentKnockJSONKeyBindingSHA256 ||
			keyClass == agentKnockJSONKeyOwnerID {
			if i >= len(data) || data[i] != '"' {
				return errors.New("agent knock JSON native session operation identifier must be a string")
			}
		}
		switch delimiter {
		case ',':
			i = valueEnd + 1
		case '}':
			i = valueEnd + 1
			if skipAgentKnockJSONWhitespace(data, i) != len(data) {
				return errors.New("agent knock JSON has trailing content")
			}
			if len(seenOperationFields) != 0 && len(seenOperationFields) != nativeSessionOperationFieldCount {
				return errors.New("agent knock JSON native session operation fields must be all present or all absent")
			}
			if len(seenOperationFields) != 0 && unknownOperationKey {
				return errors.New("agent knock JSON native session operation projection contains an unknown field")
			}
			return nil
		default:
			return errors.New("agent knock JSON object is not closed")
		}
	}
	if skipAgentKnockJSONWhitespace(data, i) != len(data) {
		return errors.New("agent knock JSON has trailing content")
	}
	if len(seenOperationFields) != 0 && len(seenOperationFields) != nativeSessionOperationFieldCount {
		return errors.New("agent knock JSON native session operation fields must be all present or all absent")
	}
	if len(seenOperationFields) != 0 && unknownOperationKey {
		return errors.New("agent knock JSON native session operation projection contains an unknown field")
	}
	return nil
}

func canonicalAgentKnockWireKey(raw []byte) bool {
	for _, key := range []string{
		"headerType", "usrId", "devId", "orgId", "aspId", "resId", "runId", "runAttempt",
		"operation_id", "binding_sha256", "owner_id", "prepared_at_ms", "expires_at_ms", "results", "usrData",
	} {
		if bytes.Equal(raw, []byte(strconv.Quote(key))) {
			return true
		}
	}
	return false
}

func classifyAgentKnockJSONKey(raw []byte) agentKnockJSONKeyClass {
	if bytes.Equal(raw, []byte(`"runId"`)) {
		return agentKnockJSONKeyRunID
	}
	if bytes.Equal(raw, []byte(`"runAttempt"`)) {
		return agentKnockJSONKeyRunAttempt
	}
	if len(raw) > maxEncodedAgentKnockBindingKeyBytes {
		return agentKnockJSONKeyOther
	}
	key, err := strconv.Unquote(string(raw))
	if err != nil {
		// encoding/json already validated the key. strconv.Unquote does not
		// accept every JSON-only escape (for example \/); none can spell the
		// ASCII RunID names, so those keys are safely unrelated.
		return agentKnockJSONKeyOther
	}
	if key == "runId" {
		return agentKnockJSONKeyRunID
	}
	if strings.EqualFold(key, "runId") || strings.EqualFold(key, "run_id") {
		return agentKnockJSONKeyRunIDAlias
	}
	if key == "runAttempt" {
		return agentKnockJSONKeyRunAttempt
	}
	if strings.EqualFold(key, "runAttempt") || strings.EqualFold(key, "run_attempt") {
		return agentKnockJSONKeyRunAttemptAlias
	}
	switch key {
	case "operation_id":
		return agentKnockJSONKeyOperationID
	case "binding_sha256":
		return agentKnockJSONKeyBindingSHA256
	case "owner_id":
		return agentKnockJSONKeyOwnerID
	case "prepared_at_ms":
		return agentKnockJSONKeyPreparedAtMillis
	case "expires_at_ms":
		return agentKnockJSONKeyExpiresAtMillis
	case "operationId", "OperationID", "bindingSha256", "BindingSHA256", "ownerId", "OwnerID",
		"preparedAtMs", "PreparedAtMS", "expiresAtMs", "ExpiresAtMS":
		// encoding/json accepts case-insensitive Go-field spellings. Reject the
		// common camel/Pascal aliases explicitly so a second semantic projection
		// cannot hide beside the canonical snake_case wire field.
		switch {
		case strings.Contains(strings.ToLower(key), "operation"):
			return agentKnockJSONKeyOperationIDAlias
		case strings.Contains(strings.ToLower(key), "binding"):
			return agentKnockJSONKeyBindingSHA256Alias
		case strings.Contains(strings.ToLower(key), "owner"):
			return agentKnockJSONKeyOwnerIDAlias
		case strings.Contains(strings.ToLower(key), "prepared"):
			return agentKnockJSONKeyPreparedAtMillisAlias
		default:
			return agentKnockJSONKeyExpiresAtMillisAlias
		}
	}
	for canonical, class := range map[string]agentKnockJSONKeyClass{
		"operation_id": agentKnockJSONKeyOperationIDAlias, "binding_sha256": agentKnockJSONKeyBindingSHA256Alias,
		"owner_id": agentKnockJSONKeyOwnerIDAlias, "prepared_at_ms": agentKnockJSONKeyPreparedAtMillisAlias,
		"expires_at_ms": agentKnockJSONKeyExpiresAtMillisAlias,
	} {
		if strings.EqualFold(key, canonical) || strings.EqualFold(strings.ReplaceAll(key, "-", "_"), canonical) {
			return class
		}
	}
	return agentKnockJSONKeyOther
}

// NativeSessionOperationPresent reports whether the exact additive operation
// projection is present. Generic non-registered knocks may omit it.
func NativeSessionOperationPresent(m AgentKnockMsg) bool {
	return m.NativeSessionOperationID != "" || m.NativeSessionOperationBinding != "" ||
		m.NativeSessionOperationOwnerID != "" || m.NativeSessionOperationPrepared != 0 ||
		m.NativeSessionOperationExpiresAt != 0
}

func validateNativeSessionOperationProjection(m AgentKnockMsg) error {
	if !NativeSessionOperationPresent(m) {
		return nil
	}
	owner := m.NativeSessionOperationOwnerID
	if !validNativeSessionOperationHex(m.NativeSessionOperationID) || !validNativeSessionOperationHex(m.NativeSessionOperationBinding) ||
		owner == "" || len(owner) > 256 || !utf8.ValidString(owner) || strings.TrimSpace(owner) != owner ||
		strings.IndexFunc(owner, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 ||
		m.NativeSessionOperationPrepared <= 0 || m.NativeSessionOperationExpiresAt <= m.NativeSessionOperationPrepared {
		return errors.New("agent knock JSON native session operation projection is invalid")
	}
	return nil
}

func scanAgentKnockJSONStringEnd(data []byte, start int) int {
	escaped := false
	for i := start + 1; i < len(data); i++ {
		switch {
		case escaped:
			escaped = false
		case data[i] == '\\':
			escaped = true
		case data[i] == '"':
			return i + 1
		}
	}
	return -1
}

func scanAgentKnockJSONValueEnd(data []byte, start int) (int, byte) {
	// This scanner deliberately shares one depth counter for arrays and objects.
	// It MUST remain after the successful encoding/json decode in UnmarshalJSON,
	// which proves delimiters are balanced and correctly paired before this
	// allocation-bounded pass skips nested values.
	depth := 0
	for i := start; i < len(data); i++ {
		switch data[i] {
		case '"':
			// Reuse the single string-escape scanner so escape semantics live
			// in one place. scanAgentKnockJSONStringEnd returns the index just
			// past the closing quote; -1 rewinds the loop's post-increment onto
			// it. A negative result is unreachable after encoding/json validated
			// the body, but is handled defensively.
			stringEnd := scanAgentKnockJSONStringEnd(data, i)
			if stringEnd < 0 {
				return -1, 0
			}
			i = stringEnd - 1
		case '{', '[':
			depth++
		case ']':
			depth--
		case '}':
			if depth == 0 {
				return i, '}'
			}
			depth--
		case ',':
			if depth == 0 {
				return i, ','
			}
		}
	}
	return -1, 0
}

func skipAgentKnockJSONWhitespace(data []byte, start int) int {
	for start < len(data) {
		switch data[start] {
		case ' ', '\t', '\r', '\n':
			start++
		default:
			return start
		}
	}
	return start
}
