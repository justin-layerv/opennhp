package common

import (
	"encoding/json"
	"errors"
	"fmt"
)

// AgentNativeSessionOperationRecoveryMsg is the strict authenticated NHP_EXT
// request used after a lost admission ACK. It carries the same compact
// operation projection as KNK. The authenticated Noise key and server config
// complete the binding; no session receipt is required locally.
type AgentNativeSessionOperationRecoveryMsg struct {
	HeaderType    int    `json:"headerType"`
	UserID        string `json:"usrId"`
	DeviceID      string `json:"devId"`
	AuthServiceID string `json:"aspId"`
	ResourceID    string `json:"resId"`
	RunID         string `json:"runId"`
	RunAttempt    uint64 `json:"runAttempt"`
	OperationID   string `json:"operation_id"`
	BindingSHA256 string `json:"binding_sha256"`
	OwnerID       string `json:"owner_id"`
	PreparedAtMS  int64  `json:"prepared_at_ms"`
	ExpiresAtMS   int64  `json:"expires_at_ms"`
}

type ServerNativeSessionOperationRecoveryAckMsg struct {
	ErrCode               string `json:"errCode"`
	ErrMsg                string `json:"errMsg,omitempty"`
	OperationID           string `json:"operation_id,omitempty"`
	BindingSHA256         string `json:"binding_sha256,omitempty"`
	State                 string `json:"state,omitempty"`
	CellID                string `json:"cellId,omitempty"`
	SessionID             uint64 `json:"sessId,omitempty"`
	SessionIssuedAtMillis int64  `json:"sessIssuedAtMillis,omitempty"`
	RunID                 string `json:"runId,omitempty"`
	RunAttempt            uint64 `json:"runAttempt,omitempty"`
	CloseEventID          string `json:"closeEventId,omitempty"`
}

func DecodeAgentNativeSessionOperationRecoveryMsg(raw []byte, out *AgentNativeSessionOperationRecoveryMsg) error {
	if out == nil {
		return errors.New("nil native session operation recovery output")
	}
	object, err := scanACSessionCloseObject(raw)
	if err != nil {
		return err
	}
	if !exactObjectKeys(object, "headerType", "usrId", "devId", "aspId", "resId", "runId", "runAttempt",
		"operation_id", "binding_sha256", "owner_id", "prepared_at_ms", "expires_at_ms") {
		return errors.New("native session operation recovery has an invalid field set")
	}
	header, err := decodeCanonicalPositiveUint64(object["headerType"])
	if err != nil || uint64(int(header)) != header {
		return errors.New("native session operation recovery headerType must be a canonical positive int")
	}
	attempt, err := decodeCanonicalPositiveUint64(object["runAttempt"])
	if err != nil {
		return fmt.Errorf("native session operation recovery runAttempt: %w", err)
	}
	prepared, err := decodeCanonicalPositiveInt64(object["prepared_at_ms"])
	if err != nil {
		return fmt.Errorf("native session operation recovery prepared_at_ms: %w", err)
	}
	expires, err := decodeCanonicalPositiveInt64(object["expires_at_ms"])
	if err != nil || expires <= prepared {
		return errors.New("native session operation recovery expiry is invalid")
	}
	var userID, deviceID, authID, resourceID, runID, operationID, binding, ownerID string
	for name, target := range map[string]*string{
		"usrId": &userID, "devId": &deviceID, "aspId": &authID, "resId": &resourceID, "runId": &runID,
		"operation_id": &operationID, "binding_sha256": &binding, "owner_id": &ownerID,
	} {
		if err := json.Unmarshal(object[name], target); err != nil || *target == "" {
			return fmt.Errorf("native session operation recovery %s must be a nonempty string", name)
		}
	}
	if userID != deviceID || authID != RegisteredAgentAuthServiceID || ValidateAgentKnockRunID(runID) != nil ||
		!validNativeSessionOperationHex(operationID) || !validNativeSessionOperationHex(binding) {
		return errors.New("native session operation recovery identity is invalid")
	}
	*out = AgentNativeSessionOperationRecoveryMsg{
		HeaderType: int(header), UserID: userID, DeviceID: deviceID, AuthServiceID: authID,
		ResourceID: resourceID, RunID: runID, RunAttempt: attempt, OperationID: operationID,
		BindingSHA256: binding, OwnerID: ownerID, PreparedAtMS: prepared, ExpiresAtMS: expires,
	}
	return nil
}

func (m AgentNativeSessionOperationRecoveryMsg) KnockProjection() AgentKnockMsg {
	return AgentKnockMsg{
		HeaderType: m.HeaderType, UserId: m.UserID, DeviceId: m.DeviceID, AuthServiceId: m.AuthServiceID,
		ResourceId: m.ResourceID, RunID: m.RunID, RunAttempt: m.RunAttempt,
		NativeSessionOperationID: m.OperationID, NativeSessionOperationBinding: m.BindingSHA256,
		NativeSessionOperationOwnerID: m.OwnerID, NativeSessionOperationPrepared: m.PreparedAtMS,
		NativeSessionOperationExpiresAt: m.ExpiresAtMS,
	}
}
