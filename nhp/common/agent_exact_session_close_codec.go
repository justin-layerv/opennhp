package common

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// AgentExactSessionCloseMsg is the authenticated NHP_EXT application body for
// retiring one server-assigned NHP access session. The initiator identity is
// supplied by the authenticated packet; every remaining candidate field is
// echoed from the immutable admission receipt and exact-matched by the server.
type AgentExactSessionCloseMsg struct {
	HeaderType            int    `json:"headerType"`
	AuthServiceID         string `json:"aspId"`
	CellID                string `json:"cellId"`
	SessionID             uint64 `json:"sessId"`
	SessionIssuedAtMillis int64  `json:"sessIssuedAtMillis"`
	RunID                 string `json:"runId"`
	RunAttempt            uint64 `json:"runAttempt"`
}

// ServerExactSessionCloseAckMsg is the dedicated NHP_ACK body for an exact
// retirement request. A success reports the immutable receipt, deterministic
// close event, and current durable closing/closed state. It deliberately does
// not reuse the resource-admission maps or positive open-time contract.
type ServerExactSessionCloseAckMsg struct {
	ErrCode               string `json:"errCode"`
	ErrMsg                string `json:"errMsg,omitempty"`
	CellID                string `json:"cellId,omitempty"`
	SessionID             uint64 `json:"sessId,omitempty"`
	SessionIssuedAtMillis int64  `json:"sessIssuedAtMillis,omitempty"`
	RunID                 string `json:"runId,omitempty"`
	RunAttempt            uint64 `json:"runAttempt,omitempty"`
	CloseEventID          string `json:"closeEventId,omitempty"`
	State                 string `json:"state,omitempty"`
}

// AgentSessionReceipt is the immutable, server-issued subset of a successful
// registered-agent knock ACK needed to retire exactly that access session.
// Transport routing is deliberately owned by the initiator, not serialized in
// the NHP application body.
type AgentSessionReceipt struct {
	CellID                string `json:"cellId"`
	SessionID             uint64 `json:"sessId"`
	SessionIssuedAtMillis int64  `json:"sessIssuedAtMillis"`
	RunID                 string `json:"runId"`
	RunAttempt            uint64 `json:"runAttempt"`
}

type registeredAgentKnockDenialACK struct {
	ErrCode  string `json:"errCode"`
	ErrMsg   string `json:"errMsg"`
	OpenTime uint32 `json:"opnTime"`
}

// registeredAgentKnockSuccessACK fixes the successful registered-agent ACK
// field order and shape independently of the legacy generic-knock envelope.
// Keep this in sync with the qurl-conformance agent-session ACK vector.
type registeredAgentKnockSuccessACK struct {
	ErrCode               string                    `json:"errCode"`
	SessionID             uint64                    `json:"sessId"`
	CellID                string                    `json:"cellId"`
	SessionIssuedAtMillis int64                     `json:"sessIssuedAtMillis"`
	RunID                 string                    `json:"runId"`
	RunAttempt            uint64                    `json:"runAttempt"`
	ResourceHost          map[string]string         `json:"resHost"`
	OpenTime              uint32                    `json:"opnTime"`
	AuthProviderToken     string                    `json:"aspToken,omitempty"`
	AgentAddr             string                    `json:"agentAddr"`
	ACTokens              map[string]string         `json:"acTokens"`
	PreAccessActions      map[string]*PreAccessInfo `json:"preActions,omitempty"`
	RedirectURL           string                    `json:"redirectUrl,omitempty"`
}

// MarshalRegisteredAgentKnockAckMsg emits the one canonical registered-agent
// ACK union. Denials deliberately project onto the exact minimal three-field
// shape, so stale plugin receipt/resource fields can never leak authority. A
// success retains the exact receipt and resource result and must pass the same
// strict decoder consumers use before the bytes leave the server.
func MarshalRegisteredAgentKnockAckMsg(ack *ServerKnockAckMsg,
	expectedRunID string, expectedRunAttempt uint64, expectedResourceID string,
) ([]byte, error) {
	if ack == nil {
		return nil, errors.New("nil registered-agent ACK")
	}
	if !canonicalDecimalErrorCode(ack.ErrCode) {
		return nil, errors.New("registered-agent ACK errCode must be a canonical decimal string")
	}
	var (
		raw []byte
		err error
	)
	if !IsSuccessErrCode(ack.ErrCode) {
		if ack.ErrMsg == "" || ack.ErrMsg != strings.TrimSpace(ack.ErrMsg) || ack.OpenTime != 0 {
			return nil, errors.New("registered-agent denial must have a trimmed message and zero opnTime")
		}
		raw, err = json.Marshal(registeredAgentKnockDenialACK{
			ErrCode: ack.ErrCode, ErrMsg: ack.ErrMsg, OpenTime: 0,
		})
	} else {
		if ack.ErrMsg != "" {
			return nil, errors.New("registered-agent success must not carry errMsg")
		}
		raw, err = json.Marshal(registeredAgentKnockSuccessACK{
			ErrCode: ack.ErrCode, SessionID: ack.SessionId, CellID: ack.CellId,
			SessionIssuedAtMillis: ack.SessionIssuedAtMillis, RunID: ack.RunID,
			RunAttempt: ack.RunAttempt, ResourceHost: ack.ResourceHost, OpenTime: ack.OpenTime,
			AuthProviderToken: ack.AuthProviderToken, AgentAddr: ack.AgentAddr,
			ACTokens: ack.ACTokens, PreAccessActions: ack.PreAccessActions, RedirectURL: ack.RedirectUrl,
		})
	}
	if err != nil {
		return nil, fmt.Errorf("marshal registered-agent ACK: %w", err)
	}
	var decoded ServerKnockAckMsg
	if err := DecodeRegisteredAgentKnockAckMsg(raw, &decoded, expectedRunID, expectedRunAttempt, expectedResourceID); err != nil {
		return nil, fmt.Errorf("marshal registered-agent ACK: %w", err)
	}
	return raw, nil
}

// DecodeRegisteredAgentKnockAckMsg enforces the registered-agent ACK union
// before its exact-session receipt is retained. It accepts the fixed success
// fields and documented optional success fields, but rejects duplicate, aliased,
// unknown, missing, or drifted receipt fields. A denial carries no session
// authority and must have the exact minimal shape emitted by the server.
func DecodeRegisteredAgentKnockAckMsg(raw []byte, out *ServerKnockAckMsg,
	expectedRunID string, expectedRunAttempt uint64, expectedResourceID string,
) error {
	if out == nil {
		return errors.New("nil registered-agent ACK output")
	}
	object, err := scanACSessionCloseObject(raw)
	if err != nil {
		return err
	}
	errCode, err := decodeNonemptyJSONString(object["errCode"], "registered-agent ACK errCode")
	if err != nil || !canonicalDecimalErrorCode(errCode) {
		return errors.New("registered-agent ACK errCode must be a canonical decimal string")
	}
	if !IsSuccessErrCode(errCode) {
		if !exactObjectKeys(object, "errCode", "errMsg", "opnTime") {
			return errors.New("registered-agent denial has an invalid field set")
		}
		errMsg, err := decodeNonemptyJSONString(object["errMsg"], "registered-agent ACK errMsg")
		if err != nil {
			return err
		}
		if errMsg != strings.TrimSpace(errMsg) {
			return errors.New("registered-agent denial errMsg must be trimmed")
		}
		if openTime, err := decodeCanonicalUint64(object["opnTime"]); err != nil || openTime != 0 {
			return errors.New("registered-agent denial opnTime must be canonical zero")
		}
	} else {
		base := []string{"errCode", "resHost", "opnTime", "agentAddr", "acTokens"}
		required := append(base, "sessId", "cellId", "sessIssuedAtMillis", "runId", "runAttempt")
		for _, key := range required {
			if _, ok := object[key]; !ok {
				return fmt.Errorf("registered-agent ACK is missing %s", key)
			}
		}
		allowed := map[string]struct{}{
			"errCode": {}, "resHost": {}, "opnTime": {}, "agentAddr": {}, "acTokens": {},
			"sessId": {}, "cellId": {}, "sessIssuedAtMillis": {}, "runId": {}, "runAttempt": {},
			"aspToken": {}, "preActions": {}, "redirectUrl": {},
		}
		for key := range object {
			if _, ok := allowed[key]; !ok {
				return fmt.Errorf("registered-agent ACK has unknown field %q", key)
			}
		}
		if _, err := decodeCanonicalPositiveUint64(object["sessId"]); err != nil {
			return fmt.Errorf("registered-agent ACK sessId: %w", err)
		}
		if _, err := decodeCanonicalPositiveInt64(object["sessIssuedAtMillis"]); err != nil {
			return fmt.Errorf("registered-agent ACK sessIssuedAtMillis: %w", err)
		}
		if _, err := decodeCanonicalPositiveUint64(object["runAttempt"]); err != nil {
			return fmt.Errorf("registered-agent ACK runAttempt: %w", err)
		}
		if openTime, err := decodeCanonicalPositiveUint64(object["opnTime"]); err != nil || openTime > uint64(^uint32(0)) {
			return errors.New("registered-agent ACK opnTime must be a canonical positive uint32")
		}
		cellID, err := decodeNonemptyJSONString(object["cellId"], "registered-agent ACK cellId")
		if err != nil || cellID == "" {
			return errors.New("registered-agent ACK cellId is invalid")
		}
		runID, err := decodeNonemptyJSONString(object["runId"], "registered-agent ACK runId")
		if err != nil || ValidateAgentKnockRunID(runID) != nil {
			return errors.New("registered-agent ACK runId is invalid")
		}
	}
	var decoded ServerKnockAckMsg
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return fmt.Errorf("decode registered-agent ACK: %w", err)
	}
	if !IsSuccessErrCode(errCode) {
		if decoded.OpenTime != 0 || decoded.ResourceHost != nil || decoded.ACTokens != nil || decoded.AgentAddr != "" {
			return errors.New("registered-agent denial carries session authority")
		}
	} else {
		if !validAgentAckAddress(decoded.AgentAddr) {
			return errors.New("registered-agent ACK agentAddr is invalid")
		}
		if _, err := AgentSessionReceiptFromKnockAck(&decoded, expectedRunID, expectedRunAttempt); err != nil {
			return err
		}
		if !registeredAgentACKHasResourceAuthority(decoded, expectedResourceID) {
			return errors.New("registered-agent ACK does not carry the requested resource authority")
		}
	}
	*out = decoded
	return nil
}

// DecodeAgentSessionReceiptFromKnockAckJSON strictly decodes the portable ACK
// returned by the SDK and extracts its immutable exact-session receipt. The
// ACK's run binding was already checked against caller authority when it was
// first received; the server exact-matches it again on retirement.
func DecodeAgentSessionReceiptFromKnockAckJSON(raw []byte) (AgentSessionReceipt, error) {
	var preliminary ServerKnockAckMsg
	if err := json.Unmarshal(raw, &preliminary); err != nil {
		return AgentSessionReceipt{}, err
	}
	var strict ServerKnockAckMsg
	if err := DecodeRegisteredAgentKnockAckMsg(raw, &strict, preliminary.RunID, preliminary.RunAttempt, ""); err != nil {
		return AgentSessionReceipt{}, err
	}
	return AgentSessionReceiptFromKnockAck(&strict, strict.RunID, strict.RunAttempt)
}

// AgentSessionReceiptFromKnockAck validates and extracts the immutable receipt
// from an authenticated successful registered-agent ACK. expectedRunID and
// expectedRunAttempt are caller-owned request authority and must echo exactly.
func AgentSessionReceiptFromKnockAck(ack *ServerKnockAckMsg, expectedRunID string,
	expectedRunAttempt uint64,
) (AgentSessionReceipt, error) {
	if ack == nil || !IsSuccessErrCode(ack.ErrCode) || ack.OpenTime == 0 || ack.SessionId == 0 || ack.CellId == "" ||
		ack.SessionIssuedAtMillis <= 0 || ValidateAgentKnockRunID(expectedRunID) != nil ||
		expectedRunAttempt == 0 || ack.RunID != expectedRunID || ack.RunAttempt != expectedRunAttempt ||
		!validAgentAckAddress(ack.AgentAddr) || !registeredAgentACKHasResourceAuthority(*ack, "") {
		return AgentSessionReceipt{}, errors.New("registered-agent ACK has an invalid session receipt")
	}
	receipt := AgentSessionReceipt{
		CellID: ack.CellId, SessionID: ack.SessionId,
		SessionIssuedAtMillis: ack.SessionIssuedAtMillis,
		RunID:                 ack.RunID, RunAttempt: ack.RunAttempt,
	}
	if err := ValidateAgentSessionReceipt(receipt); err != nil {
		return AgentSessionReceipt{}, err
	}
	return receipt, nil
}

func registeredAgentACKHasResourceAuthority(ack ServerKnockAckMsg, expectedResourceID string) bool {
	if len(ack.ResourceHost) == 0 || len(ack.ACTokens) == 0 || len(ack.ResourceHost) != len(ack.ACTokens) {
		return false
	}
	for resourceID, host := range ack.ResourceHost {
		if resourceID == "" || resourceID != strings.TrimSpace(resourceID) ||
			host == "" || host != strings.TrimSpace(host) {
			return false
		}
		token, ok := ack.ACTokens[resourceID]
		if !ok || token == "" || token != strings.TrimSpace(token) {
			return false
		}
	}
	for resourceID, token := range ack.ACTokens {
		if resourceID == "" || resourceID != strings.TrimSpace(resourceID) ||
			token == "" || token != strings.TrimSpace(token) {
			return false
		}
		if _, ok := ack.ResourceHost[resourceID]; !ok {
			return false
		}
	}
	if expectedResourceID != "" {
		if expectedResourceID != strings.TrimSpace(expectedResourceID) {
			return false
		}
		return ack.ResourceHost[expectedResourceID] != "" && ack.ACTokens[expectedResourceID] != ""
	}
	for resourceID, host := range ack.ResourceHost {
		if resourceID != "" && host != "" && ack.ACTokens[resourceID] != "" {
			return true
		}
	}
	return false
}

func validAgentAckAddress(value string) bool {
	host, portText, err := net.SplitHostPort(value)
	if err != nil || net.ParseIP(host) == nil {
		return false
	}
	port, err := strconv.Atoi(portText)
	return err == nil && port > 0 && port <= 65535
}

// ValidateAgentSessionReceipt checks the public receipt fields independently
// of any transport route or authenticated agent key.
func ValidateAgentSessionReceipt(receipt AgentSessionReceipt) error {
	if receipt.CellID == "" || receipt.SessionID == 0 || receipt.SessionIssuedAtMillis <= 0 ||
		receipt.RunAttempt == 0 || ValidateAgentKnockRunID(receipt.RunID) != nil {
		return errors.New("invalid agent session receipt")
	}
	return nil
}

// DecodeAgentExactSessionCloseMsg rejects aliases, unknown or duplicate
// fields, non-canonical numbers, and trailing JSON. The caller still compares
// HeaderType with the authenticated dispatch contract's expected NHP_EXT value.
func DecodeAgentExactSessionCloseMsg(raw []byte, out *AgentExactSessionCloseMsg) error {
	if out == nil {
		return errors.New("nil AgentExactSessionCloseMsg output")
	}
	object, err := scanACSessionCloseObject(raw)
	if err != nil {
		return err
	}
	if !exactObjectKeys(object, "headerType", "aspId", "cellId", "sessId", "sessIssuedAtMillis", "runId", "runAttempt") {
		return errors.New("agent exact session close has an invalid field set")
	}
	headerType, err := decodeCanonicalPositiveUint64(object["headerType"])
	if err != nil || uint64(int(headerType)) != headerType {
		return errors.New("agent exact session close headerType must be a canonical positive int")
	}
	sessionID, err := decodeCanonicalPositiveUint64(object["sessId"])
	if err != nil {
		return fmt.Errorf("agent exact session close sessId: %w", err)
	}
	issuedAt, err := decodeCanonicalPositiveInt64(object["sessIssuedAtMillis"])
	if err != nil {
		return fmt.Errorf("agent exact session close sessIssuedAtMillis: %w", err)
	}
	runAttempt, err := decodeCanonicalPositiveUint64(object["runAttempt"])
	if err != nil {
		return fmt.Errorf("agent exact session close runAttempt: %w", err)
	}
	var authServiceID, cellID, runID string
	for name, target := range map[string]*string{
		"aspId": &authServiceID, "cellId": &cellID, "runId": &runID,
	} {
		if err := json.Unmarshal(object[name], target); err != nil || *target == "" {
			return fmt.Errorf("agent exact session close %s must be a nonempty JSON string", name)
		}
	}
	if authServiceID != RegisteredAgentAuthServiceID {
		return errors.New("agent exact session close aspId is not the registered-agent provider")
	}
	if err := ValidateAgentKnockRunID(runID); err != nil {
		return fmt.Errorf("agent exact session close runId: %w", err)
	}
	decoded := AgentExactSessionCloseMsg{
		HeaderType: int(headerType), AuthServiceID: authServiceID, CellID: cellID,
		SessionID: sessionID, SessionIssuedAtMillis: issuedAt, RunID: runID, RunAttempt: runAttempt,
	}
	canonical, err := json.Marshal(decoded)
	if err != nil || len(canonical) == 0 {
		return errors.New("agent exact session close is not canonical")
	}
	*out = decoded
	return nil
}

// DecodeServerExactSessionCloseAckMsg enforces the dedicated exact-close ACK
// union. Success contains exactly the immutable receipt, deterministic close
// event, and durable state. Denial contains exactly errCode and errMsg. This
// prevents an ordinary resource-admission ACK from being accepted as close
// completion and rejects duplicate, aliased, or future fields fail-closed.
func DecodeServerExactSessionCloseAckMsg(raw []byte, out *ServerExactSessionCloseAckMsg) error {
	if out == nil {
		return errors.New("nil ServerExactSessionCloseAckMsg output")
	}
	object, err := scanACSessionCloseObject(raw)
	if err != nil {
		return err
	}
	errCode, err := decodeNonemptyJSONString(object["errCode"], "exact session close ACK errCode")
	if err != nil || !canonicalDecimalErrorCode(errCode) {
		return errors.New("exact session close ACK errCode must be a canonical decimal string")
	}
	if !IsSuccessErrCode(errCode) {
		if !exactObjectKeys(object, "errCode", "errMsg") {
			return errors.New("exact session close denial must contain exactly errCode and errMsg")
		}
		errMsg, msgErr := decodeNonemptyJSONString(object["errMsg"], "exact session close ACK errMsg")
		if msgErr != nil {
			return msgErr
		}
		if errMsg != strings.TrimSpace(errMsg) {
			return errors.New("exact session close ACK errMsg must be trimmed")
		}
		*out = ServerExactSessionCloseAckMsg{ErrCode: errCode, ErrMsg: errMsg}
		return nil
	}
	if !exactObjectKeys(object, "errCode", "cellId", "sessId", "sessIssuedAtMillis", "runId", "runAttempt", "closeEventId", "state") {
		return errors.New("exact session close success must contain exactly the receipt, close event, and state")
	}
	cellID, err := decodeNonemptyJSONString(object["cellId"], "exact session close ACK cellId")
	if err != nil {
		return err
	}
	sessionID, err := decodeCanonicalPositiveUint64(object["sessId"])
	if err != nil {
		return fmt.Errorf("exact session close ACK sessId: %w", err)
	}
	issuedAt, err := decodeCanonicalPositiveInt64(object["sessIssuedAtMillis"])
	if err != nil {
		return fmt.Errorf("exact session close ACK sessIssuedAtMillis: %w", err)
	}
	runID, err := decodeNonemptyJSONString(object["runId"], "exact session close ACK runId")
	if err != nil || ValidateAgentKnockRunID(runID) != nil {
		return errors.New("exact session close ACK runId is invalid")
	}
	runAttempt, err := decodeCanonicalPositiveUint64(object["runAttempt"])
	if err != nil {
		return fmt.Errorf("exact session close ACK runAttempt: %w", err)
	}
	closeEventID, err := decodeNonemptyJSONString(object["closeEventId"], "exact session close ACK closeEventId")
	if err != nil || !validExactCloseEventID(closeEventID) {
		return errors.New("exact session close ACK closeEventId is invalid")
	}
	state, err := decodeNonemptyJSONString(object["state"], "exact session close ACK state")
	if err != nil || (state != "closing" && state != "closed") {
		return errors.New("exact session close ACK state must be closing or closed")
	}
	decoded := ServerExactSessionCloseAckMsg{
		ErrCode: errCode, CellID: cellID, SessionID: sessionID,
		SessionIssuedAtMillis: issuedAt, RunID: runID, RunAttempt: runAttempt,
		CloseEventID: closeEventID, State: state,
	}
	if err := ValidateAgentSessionReceipt(AgentSessionReceipt{
		CellID: decoded.CellID, SessionID: decoded.SessionID,
		SessionIssuedAtMillis: decoded.SessionIssuedAtMillis,
		RunID:                 decoded.RunID, RunAttempt: decoded.RunAttempt,
	}); err != nil {
		return err
	}
	*out = decoded
	return nil
}

// ValidateServerExactSessionCloseAck binds a decoded success ACK to the exact
// receipt used for the request. A valid-looking ACK for a sibling session is a
// protocol error, not success.
func ValidateServerExactSessionCloseAck(ack ServerExactSessionCloseAckMsg, receipt AgentSessionReceipt) error {
	if err := ValidateAgentSessionReceipt(receipt); err != nil {
		return err
	}
	if !IsSuccessErrCode(ack.ErrCode) || ack.CellID != receipt.CellID || ack.SessionID != receipt.SessionID ||
		ack.SessionIssuedAtMillis != receipt.SessionIssuedAtMillis || ack.RunID != receipt.RunID ||
		ack.RunAttempt != receipt.RunAttempt || !validExactCloseEventID(ack.CloseEventID) ||
		(ack.State != "closing" && ack.State != "closed") {
		return errors.New("exact session close ACK does not match the request receipt")
	}
	return nil
}

func decodeNonemptyJSONString(raw json.RawMessage, field string) (string, error) {
	var value string
	if len(raw) == 0 || json.Unmarshal(raw, &value) != nil || value == "" {
		return "", fmt.Errorf("%s must be a nonempty JSON string", field)
	}
	return value, nil
}

func canonicalDecimalErrorCode(value string) bool {
	if value == "" || (len(value) > 1 && value[0] == '0') {
		return false
	}
	for i := range len(value) {
		if value[i] < '0' || value[i] > '9' {
			return false
		}
	}
	return true
}

func validExactCloseEventID(value string) bool {
	if len(value) != 32 {
		return false
	}
	for i := range len(value) {
		if (value[i] < '0' || value[i] > '9') && (value[i] < 'a' || value[i] > 'f') {
			return false
		}
	}
	return true
}
