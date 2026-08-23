package common

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	ACSessionCloseKind       = "nhp_session_close"
	ACSessionCloseScopeExact = "exact"
	ACSessionCloseScopeAgent = "agent"
	ACSessionCloseScopeRun   = "run"
)

// ACSessionCloseMsg is the LayerV session-control NHP_REV body. It is
// deliberately separate from ACRevocationMsg so qURL identity revocation and
// base-session cleanup cannot be decoded under each other's rules.
type ACSessionCloseMsg struct {
	Kind                  string `json:"kind"`
	Scope                 string `json:"scope"`
	EventID               string `json:"eventId"`
	AgentPublicKey        string `json:"agentPubKey"`
	SessionID             uint64 `json:"sessionId,omitempty"`
	SessionIssuedAtMillis int64  `json:"sessionIssuedAtMs,omitempty"`
	IssuedThroughMillis   int64  `json:"issuedThroughMs,omitempty"`
	RunID                 string `json:"runId,omitempty"`
	RunAttempt            uint64 `json:"runAttempt,omitempty"`
}

// ACSessionCloseAckMsg is the strict NHP_RVA convergence result for one
// ACSessionCloseMsg. BootID and FlushGeneration bind the acknowledgement to an
// authoritative persisted AC target.
type ACSessionCloseAckMsg struct {
	Kind                  string `json:"kind"`
	Scope                 string `json:"scope"`
	EventID               string `json:"eventId"`
	AgentPublicKey        string `json:"agentPubKey"`
	SessionID             uint64 `json:"sessionId,omitempty"`
	SessionIssuedAtMillis int64  `json:"sessionIssuedAtMs,omitempty"`
	IssuedThroughMillis   int64  `json:"issuedThroughMs,omitempty"`
	RunID                 string `json:"runId,omitempty"`
	RunAttempt            uint64 `json:"runAttempt,omitempty"`
	BootID                string `json:"bootId"`
	FlushGeneration       uint64 `json:"flushGeneration"`
	Closed                uint64 `json:"closed"`
}

// ACSessionCloseKindPresent reports whether a top-level kind field exists.
// Duplicate kind always fails; callers route any presence to the strict
// session-close decoder so a malformed final value cannot fall through to the
// generic qURL revocation path.
func ACSessionCloseKindPresent(raw []byte) (bool, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return false, err
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return false, errors.New("revocation body must be one JSON object")
	}
	present := false
	for dec.More() {
		nameToken, err := dec.Token()
		if err != nil {
			return false, err
		}
		name, ok := nameToken.(string)
		if !ok {
			return false, errors.New("revocation object key must be a string")
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return false, err
		}
		if name == "kind" {
			if present {
				return false, errors.New("session close contains duplicate kind")
			}
			present = true
		}
	}
	if _, err := dec.Token(); err != nil {
		return false, err
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		if err == nil {
			return false, errors.New("revocation body contains a trailing JSON value")
		}
		return false, err
	}
	return present, nil
}

func DecodeACSessionCloseMsg(raw []byte, out *ACSessionCloseMsg) error {
	if out == nil {
		return errors.New("nil ACSessionCloseMsg output")
	}
	object, err := scanACSessionCloseObject(raw)
	if err != nil {
		return err
	}
	var kind, scope, eventID, agentKey string
	for name, target := range map[string]*string{
		"kind": &kind, "scope": &scope, "eventId": &eventID, "agentPubKey": &agentKey,
	} {
		value, ok := object[name]
		if !ok || json.Unmarshal(value, target) != nil || *target == "" {
			return fmt.Errorf("session close %s must be a nonempty JSON string", name)
		}
	}
	if kind != ACSessionCloseKind {
		return fmt.Errorf("unknown session close kind %q", kind)
	}
	if !ValidNHPACBootID(eventID) {
		return errors.New("session close eventId must be canonical lowercase 128-bit")
	}
	if !ValidNHPAgentPublicKey(agentKey) {
		return errors.New("session close agentPubKey must be a canonical NHP public key")
	}

	decoded := ACSessionCloseMsg{Kind: kind, Scope: scope, EventID: eventID, AgentPublicKey: agentKey}
	switch scope {
	case ACSessionCloseScopeExact:
		if !exactObjectKeys(object, "kind", "scope", "eventId", "agentPubKey", "sessionId", "sessionIssuedAtMs") {
			return errors.New("exact session close must contain exactly kind, scope, eventId, agentPubKey, sessionId, sessionIssuedAtMs")
		}
		sessionID, err := decodeCanonicalPositiveUint64(object["sessionId"])
		if err != nil {
			return fmt.Errorf("session close sessionId: %w", err)
		}
		issuedAt, err := decodeCanonicalPositiveInt64(object["sessionIssuedAtMs"])
		if err != nil {
			return fmt.Errorf("session close sessionIssuedAtMs: %w", err)
		}
		decoded.SessionID = sessionID
		decoded.SessionIssuedAtMillis = issuedAt
	case ACSessionCloseScopeAgent:
		if !exactObjectKeys(object, "kind", "scope", "eventId", "agentPubKey", "issuedThroughMs") {
			return errors.New("agent session close must contain exactly kind, scope, eventId, agentPubKey, issuedThroughMs")
		}
		issued, err := decodeCanonicalPositiveInt64(object["issuedThroughMs"])
		if err != nil {
			return fmt.Errorf("session close issuedThroughMs: %w", err)
		}
		decoded.IssuedThroughMillis = issued
	case ACSessionCloseScopeRun:
		if !exactObjectKeys(object, "kind", "scope", "eventId", "agentPubKey", "runId", "runAttempt") {
			return errors.New("run session close must contain exactly kind, scope, eventId, agentPubKey, runId, runAttempt")
		}
		if err := json.Unmarshal(object["runId"], &decoded.RunID); err != nil ||
			ValidateAgentKnockRunID(decoded.RunID) != nil {
			return errors.New("session close runId must be canonical")
		}
		attempt, err := decodeCanonicalPositiveUint64(object["runAttempt"])
		if err != nil {
			return fmt.Errorf("session close runAttempt: %w", err)
		}
		decoded.RunAttempt = attempt
	default:
		return fmt.Errorf("unknown session close scope %q", scope)
	}
	*out = decoded
	return nil
}

// DecodeACSessionCloseAckMsg decodes the closed LayerV NHP_RVA result shape.
// Unlike the generic qURL revocation acknowledgement, this acknowledgement is
// an authority transition: every echoed selector plus the AC process boot and
// completed flush generation must be present exactly once and canonical.
func DecodeACSessionCloseAckMsg(raw []byte, out *ACSessionCloseAckMsg) error {
	if out == nil {
		return errors.New("nil ACSessionCloseAckMsg output")
	}
	object, err := scanACSessionCloseObject(raw)
	if err != nil {
		return err
	}
	var kind, scope, eventID, agentKey, bootID string
	for name, target := range map[string]*string{
		"kind": &kind, "scope": &scope, "eventId": &eventID,
		"agentPubKey": &agentKey, "bootId": &bootID,
	} {
		value, ok := object[name]
		if !ok || json.Unmarshal(value, target) != nil || *target == "" {
			return fmt.Errorf("session close acknowledgement %s must be a nonempty JSON string", name)
		}
	}
	if kind != ACSessionCloseKind {
		return fmt.Errorf("unknown session close acknowledgement kind %q", kind)
	}
	if !ValidNHPACBootID(eventID) {
		return errors.New("session close acknowledgement eventId must be canonical lowercase 128-bit")
	}
	if !ValidNHPAgentPublicKey(agentKey) {
		return errors.New("session close acknowledgement agentPubKey must be a canonical NHP public key")
	}
	if !ValidNHPACBootID(bootID) {
		return errors.New("session close acknowledgement bootId must be canonical lowercase 128-bit")
	}
	flushGeneration, err := decodeCanonicalPositiveUint64(object["flushGeneration"])
	if err != nil {
		return fmt.Errorf("session close acknowledgement flushGeneration: %w", err)
	}
	closed, err := decodeCanonicalUint64(object["closed"])
	if err != nil {
		return fmt.Errorf("session close acknowledgement closed: %w", err)
	}

	decoded := ACSessionCloseAckMsg{
		Kind: kind, Scope: scope, EventID: eventID, AgentPublicKey: agentKey,
		BootID: bootID, FlushGeneration: flushGeneration, Closed: closed,
	}
	switch scope {
	case ACSessionCloseScopeExact:
		if !exactObjectKeys(object, "kind", "scope", "eventId", "agentPubKey", "sessionId", "sessionIssuedAtMs", "bootId", "flushGeneration", "closed") {
			return errors.New("exact session close acknowledgement has an invalid field set")
		}
		sessionID, err := decodeCanonicalPositiveUint64(object["sessionId"])
		if err != nil {
			return fmt.Errorf("session close acknowledgement sessionId: %w", err)
		}
		issuedAt, err := decodeCanonicalPositiveInt64(object["sessionIssuedAtMs"])
		if err != nil {
			return fmt.Errorf("session close acknowledgement sessionIssuedAtMs: %w", err)
		}
		decoded.SessionID = sessionID
		decoded.SessionIssuedAtMillis = issuedAt
	case ACSessionCloseScopeAgent:
		if !exactObjectKeys(object, "kind", "scope", "eventId", "agentPubKey", "issuedThroughMs", "bootId", "flushGeneration", "closed") {
			return errors.New("agent session close acknowledgement has an invalid field set")
		}
		issued, err := decodeCanonicalPositiveInt64(object["issuedThroughMs"])
		if err != nil {
			return fmt.Errorf("session close acknowledgement issuedThroughMs: %w", err)
		}
		decoded.IssuedThroughMillis = issued
	case ACSessionCloseScopeRun:
		if !exactObjectKeys(object, "kind", "scope", "eventId", "agentPubKey", "runId", "runAttempt", "bootId", "flushGeneration", "closed") {
			return errors.New("run session close acknowledgement has an invalid field set")
		}
		if err := json.Unmarshal(object["runId"], &decoded.RunID); err != nil || ValidateAgentKnockRunID(decoded.RunID) != nil {
			return errors.New("session close acknowledgement runId must be canonical")
		}
		attempt, err := decodeCanonicalPositiveUint64(object["runAttempt"])
		if err != nil {
			return fmt.Errorf("session close acknowledgement runAttempt: %w", err)
		}
		decoded.RunAttempt = attempt
	default:
		return fmt.Errorf("unknown session close acknowledgement scope %q", scope)
	}
	*out = decoded
	return nil
}

func scanACSessionCloseObject(raw []byte) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return nil, errors.New("session close must be one JSON object")
	}
	object := make(map[string]json.RawMessage)
	for dec.More() {
		nameToken, err := dec.Token()
		if err != nil {
			return nil, err
		}
		name, ok := nameToken.(string)
		if !ok {
			return nil, errors.New("session close object key must be a string")
		}
		if _, duplicate := object[name]; duplicate {
			return nil, fmt.Errorf("session close contains duplicate %s", name)
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, err
		}
		object[name] = value
	}
	if tok, err = dec.Token(); err != nil {
		return nil, err
	} else if delim, ok := tok.(json.Delim); !ok || delim != '}' {
		return nil, errors.New("session close object is not closed")
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, errors.New("session close contains a trailing JSON value")
		}
		return nil, err
	}
	return object, nil
}

func exactObjectKeys(object map[string]json.RawMessage, names ...string) bool {
	if len(object) != len(names) {
		return false
	}
	for _, name := range names {
		if _, ok := object[name]; !ok {
			return false
		}
	}
	return true
}

func decodeCanonicalPositiveInt64(raw []byte) (int64, error) {
	if len(raw) == 0 || raw[0] < '1' || raw[0] > '9' {
		return 0, errors.New("must be a canonical positive int64 number")
	}
	for _, b := range raw[1:] {
		if b < '0' || b > '9' {
			return 0, errors.New("must be a canonical positive int64 number")
		}
	}
	var value int64
	if err := json.Unmarshal(raw, &value); err != nil || value <= 0 {
		return 0, errors.New("must be a canonical positive int64 number")
	}
	return value, nil
}

func decodeCanonicalUint64(raw []byte) (uint64, error) {
	if len(raw) == 0 || raw[0] < '0' || raw[0] > '9' || (len(raw) > 1 && raw[0] == '0') {
		return 0, errors.New("must be a canonical uint64 number")
	}
	for _, b := range raw[1:] {
		if b < '0' || b > '9' {
			return 0, errors.New("must be a canonical uint64 number")
		}
	}
	var value uint64
	if err := json.Unmarshal(raw, &value); err != nil {
		return 0, errors.New("must be a canonical uint64 number")
	}
	return value, nil
}
