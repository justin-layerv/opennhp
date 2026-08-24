package common

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"
)

const (
	NativeSessionOperationContract          = "durable-native-session-operation-v1"
	nativeSessionOperationSelectorDomain    = "layerv/native-session-operation/v1\x00"
	NativeSessionOperationMaxCreationWindow = 30 * time.Minute
	NativeSessionOperationMaxClockSkew      = 30 * time.Second
	NativeSessionOperationResumeHorizon     = 24 * time.Hour
	NativeSessionOperationPacketMargin      = 125 * time.Second
	NativeSessionOperationAgentKeySchema    = 2
	NativeSessionOperationCredentialKind    = "account"
	NativeSessionOperationConnectorIDClaim  = ""
	// The complete authenticated OP knock JSON, including the existing qURL
	// credential UserData, must fit this exact ceiling. It keeps the direct,
	// forwarded, and relay frames below their no-fragmentation transport caps.
	NativeSessionOperationMaxKnockJSONBytes = 2048
)

// NativeSessionOperationServerBinding is the server-owned portion of the
// immutable operation binding. These values are never accepted from the wire.
// Both rollout colors use the same session-control table in one account and
// region, which makes the operation selector globally single-winner.
type NativeSessionOperationServerBinding struct {
	AWSAccountID        string
	AWSRegion           string
	CellID              string
	SessionControlTable string
	AgentKeysTable      string
	AgentKeySchema      int
	CredentialKind      string
	ConnectorIDClaim    string
}

// Field tags are deliberately in lexical order. encoding/json therefore emits
// the closed sorted-canonical-json-v1 byte form that qurl-go can reproduce
// without depending on Go struct declaration order outside this contract.
type nativeSessionOperationCanonicalBinding struct {
	AgentID             string `json:"agent_id"`
	AgentKeySchema      int    `json:"agent_key_schema_version"`
	AgentPublicKeyB64   string `json:"agent_public_key_b64"`
	AuthServiceID       string `json:"auth_service_id"`
	AWSAccountID        string `json:"aws_account_id"`
	AWSRegion           string `json:"aws_region"`
	BindingSchema       int    `json:"binding_schema"`
	CellID              string `json:"cell_id"`
	ConnectorIDClaim    string `json:"connector_id_claim"`
	CredentialKind      string `json:"enrollment_credential_kind"`
	ExpiresAtMillis     int64  `json:"expires_at_ms"`
	OperationID         string `json:"operation_id"`
	OwnerID             string `json:"owner_id"`
	PreparedAtMillis    int64  `json:"prepared_at_ms"`
	QURLAgentKeysTable  string `json:"qurl_agent_keys_table"`
	ResourceID          string `json:"resource_id"`
	RunAttempt          uint64 `json:"run_attempt"`
	RunID               string `json:"run_id"`
	SessionControlTable string `json:"session_control_table"`
}

func validNativeSessionOperationHex(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	for i := range len(value) {
		c := value[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func validNativeSessionOperationIdentity(value string) bool {
	return value != "" && len(value) <= 256 && strings.TrimSpace(value) == value &&
		strings.IndexFunc(value, func(r rune) bool { return r < 0x20 || r == 0x7f }) < 0
}

func validNativeSessionOperationTable(value string) bool {
	if len(value) < 3 || len(value) > 255 {
		return false
	}
	for i := range len(value) {
		c := value[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}

func validNativeSessionOperationServerBinding(binding NativeSessionOperationServerBinding) bool {
	if len(binding.AWSAccountID) != 12 || binding.AWSRegion == "" || len(binding.AWSRegion) > 64 ||
		!validNativeSessionOperationIdentity(binding.CellID) ||
		!validNativeSessionOperationTable(binding.SessionControlTable) ||
		!validNativeSessionOperationTable(binding.AgentKeysTable) ||
		binding.AgentKeySchema != NativeSessionOperationAgentKeySchema ||
		binding.CredentialKind != NativeSessionOperationCredentialKind ||
		binding.ConnectorIDClaim != NativeSessionOperationConnectorIDClaim {
		return false
	}
	for i := range len(binding.AWSAccountID) {
		if binding.AWSAccountID[i] < '0' || binding.AWSAccountID[i] > '9' {
			return false
		}
	}
	return true
}

// NativeSessionOperationID derives the global selector from only the
// authenticated Noise key and the caller's canonical run tuple. Full request
// drift cannot choose a second row; it collides on this selector and is rejected
// by BindingSHA256.
func NativeSessionOperationID(agentPublicKeyB64, runID string, runAttempt uint64) (string, error) {
	publicKey, err := base64.StdEncoding.DecodeString(agentPublicKeyB64)
	if err != nil || len(publicKey) != 32 || base64.StdEncoding.EncodeToString(publicKey) != agentPublicKeyB64 ||
		ValidateAgentKnockRunID(runID) != nil || runAttempt == 0 {
		return "", errors.New("invalid native session operation selector")
	}
	h := sha256.New()
	_, _ = h.Write([]byte(nativeSessionOperationSelectorDomain))
	_, _ = h.Write(publicKey)
	_, _ = h.Write([]byte(runID))
	var attempt [8]byte
	binary.BigEndian.PutUint64(attempt[:], runAttempt)
	_, _ = h.Write(attempt[:])
	return hex.EncodeToString(h.Sum(nil)), nil
}

// NativeSessionOperationBindingSHA256 computes the exact full request binding
// without duplicating table or deployment authority on the wire.
func NativeSessionOperationBindingSHA256(msg AgentKnockMsg, agentPublicKeyB64 string,
	server NativeSessionOperationServerBinding,
) (string, error) {
	if msg.AuthServiceId != RegisteredAgentAuthServiceID || msg.UserId != msg.DeviceId ||
		!validNativeSessionOperationIdentity(msg.UserId) || !validNativeSessionOperationIdentity(msg.ResourceId) ||
		!validNativeSessionOperationIdentity(msg.NativeSessionOperationOwnerID) ||
		!validNativeSessionOperationServerBinding(server) || msg.NativeSessionOperationPrepared <= 0 ||
		msg.NativeSessionOperationExpiresAt <= msg.NativeSessionOperationPrepared ||
		msg.NativeSessionOperationExpiresAt-msg.NativeSessionOperationPrepared > NativeSessionOperationMaxCreationWindow.Milliseconds() {
		return "", errors.New("invalid native session operation binding")
	}
	operationID, err := NativeSessionOperationID(agentPublicKeyB64, msg.RunID, msg.RunAttempt)
	if err != nil || msg.NativeSessionOperationID != operationID {
		return "", errors.New("invalid native session operation selector binding")
	}
	canonical := nativeSessionOperationCanonicalBinding{
		AgentID: msg.UserId, AgentPublicKeyB64: agentPublicKeyB64,
		AgentKeySchema: server.AgentKeySchema,
		AuthServiceID:  msg.AuthServiceId, AWSAccountID: server.AWSAccountID, AWSRegion: server.AWSRegion,
		BindingSchema: 1, CellID: server.CellID, ExpiresAtMillis: msg.NativeSessionOperationExpiresAt,
		ConnectorIDClaim: server.ConnectorIDClaim, CredentialKind: server.CredentialKind,
		OperationID: operationID, OwnerID: msg.NativeSessionOperationOwnerID,
		PreparedAtMillis: msg.NativeSessionOperationPrepared, QURLAgentKeysTable: server.AgentKeysTable,
		ResourceID: msg.ResourceId, RunAttempt: msg.RunAttempt, RunID: msg.RunID,
		SessionControlTable: server.SessionControlTable,
	}
	body, err := json.Marshal(canonical)
	if err != nil {
		return "", fmt.Errorf("marshal native session operation binding: %w", err)
	}
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:]), nil
}

// ValidateNativeSessionOperation verifies the compact authenticated projection
// against authenticated packet metadata and the exact server configuration.
func ValidateNativeSessionOperation(msg AgentKnockMsg, agentPublicKeyB64 string,
	server NativeSessionOperationServerBinding, now time.Time,
) error {
	if !NativeSessionOperationPresent(msg) || !validNativeSessionOperationHex(msg.NativeSessionOperationID) ||
		!validNativeSessionOperationHex(msg.NativeSessionOperationBinding) {
		return errors.New("invalid native session operation projection")
	}
	wantBinding, err := NativeSessionOperationBindingSHA256(msg, agentPublicKeyB64, server)
	if err != nil || msg.NativeSessionOperationBinding != wantBinding {
		return errors.New("native session operation binding mismatch")
	}
	nowMillis := now.UTC().UnixMilli()
	if nowMillis <= 0 || msg.NativeSessionOperationPrepared > nowMillis+NativeSessionOperationMaxClockSkew.Milliseconds() ||
		nowMillis >= msg.NativeSessionOperationExpiresAt {
		return errors.New("native session operation is outside its admission window")
	}
	return nil
}

// NativeSessionOperationAbsentRecoveryDeadline is exclusive. An authenticated
// recovery may create a deny-only CANCELED tombstone after admission expiry,
// but never after this deadline.
func NativeSessionOperationAbsentRecoveryDeadline(preparedAtMillis, expiresAtMillis int64) (int64, error) {
	if preparedAtMillis <= 0 || expiresAtMillis <= preparedAtMillis ||
		expiresAtMillis-preparedAtMillis > NativeSessionOperationMaxCreationWindow.Milliseconds() {
		return 0, errors.New("invalid native session operation retention inputs")
	}
	resumeMillis := NativeSessionOperationResumeHorizon.Milliseconds()
	marginMillis := NativeSessionOperationPacketMargin.Milliseconds()
	if preparedAtMillis > math.MaxInt64-resumeMillis || expiresAtMillis > math.MaxInt64-marginMillis {
		return 0, errors.New("native session operation retention overflow")
	}
	preparedDeadline := preparedAtMillis + resumeMillis
	expiresDeadline := expiresAtMillis + marginMillis
	if expiresDeadline > preparedDeadline {
		return expiresDeadline, nil
	}
	return preparedDeadline, nil
}
