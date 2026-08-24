package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/layervai/nhp/internalauth"
)

const (
	sessionControlNativeOperationKind          = "native_session_operation"
	sessionControlNativeOperationSchema        = uint64(1)
	sessionControlNativeOperationSK            = "AUTHORITY"
	sessionControlNativeOperationStateMapped   = "MAPPED"
	sessionControlNativeOperationStateCanceled = "CANCELED"
	sessionControlNativeOperationStateClosing  = "CLOSING"
	sessionControlNativeOperationStateClosed   = "CLOSED"
	sessionControlNativeOperationWriteTimeout  = 300 * time.Millisecond
	sessionControlNativeOperationReadTimeout   = 600 * time.Millisecond
	// Recovery and ambiguous admission classification share one strict
	// subsecond ceiling. Child transaction/read deadlines may shorten this
	// budget, but they must never detach from it.
	sessionControlNativeOperationAggregateTimeout = sessionControlNativeOperationWriteTimeout +
		sessionControlNativeOperationReadTimeout
)

var (
	errSessionControlNativeOperationNotFound = errors.New("native session operation not found")
	errSessionControlNativeOperationConflict = errors.New("native session operation conflicts with durable authority")
	errSessionControlNativeOperationExpired  = errors.New("native session operation is outside its recovery horizon")
	errSessionControlNativeOperationCorrupt  = errors.New("native session operation authority is malformed")
)

// sessionControlNativeOperationBinding is copied into SESSION and membership
// rows. The complete immutable request binding lives in OP#.../AUTHORITY.
type sessionControlNativeOperationBinding struct {
	OperationID   string
	BindingSHA256 string
}

func (b sessionControlNativeOperationBinding) present() bool {
	return b.OperationID != "" || b.BindingSHA256 != ""
}

func (b sessionControlNativeOperationBinding) valid() bool {
	return validSessionControlNativeOperationHex(b.OperationID) && validSessionControlNativeOperationHex(b.BindingSHA256)
}

type sessionControlNativeOperation struct {
	Binding             sessionControlNativeOperationBinding
	OwnerID             string
	AgentID             string
	AgentPublicKey      string
	ResourceID          string
	AuthServiceID       string
	RunID               string
	RunAttempt          uint64
	PreparedAtMillis    int64
	ExpiresAtMillis     int64
	AWSAccountID        string
	AWSRegion           string
	CellID              string
	SessionControlTable string
	AgentKeysTable      string
	AgentKeySchema      int
	CredentialKind      string
	ConnectorIDClaim    string
}

type sessionControlNativeOperationAuthority struct {
	Operation              sessionControlNativeOperation
	State                  string
	Candidate              *sessionControlSessionCandidate
	MappedDirectoryVersion uint64
	MappedActiveFenceCount uint64
	TerminalAtMillis       int64
	TTL                    int64
}

type sessionControlNativeOperationRow struct {
	PK                     string `dynamodbav:"pk"`
	SK                     string `dynamodbav:"sk"`
	Kind                   string `dynamodbav:"kind"`
	SchemaVersion          uint64 `dynamodbav:"schema_version"`
	OperationID            string `dynamodbav:"operation_id"`
	BindingSHA256          string `dynamodbav:"binding_sha256"`
	State                  string `dynamodbav:"state"`
	OwnerID                string `dynamodbav:"owner_id"`
	AgentID                string `dynamodbav:"agent_id"`
	AgentPublicKey         string `dynamodbav:"agent_public_key"`
	ResourceID             string `dynamodbav:"resource_id"`
	AuthServiceID          string `dynamodbav:"auth_service_id"`
	RunID                  string `dynamodbav:"run_id"`
	RunAttempt             uint64 `dynamodbav:"run_attempt"`
	PreparedAtMillis       int64  `dynamodbav:"prepared_at_ms"`
	ExpiresAtMillis        int64  `dynamodbav:"expires_at_ms"`
	AWSAccountID           string `dynamodbav:"aws_account_id"`
	AWSRegion              string `dynamodbav:"aws_region"`
	CellID                 string `dynamodbav:"cell_id"`
	SessionControlTable    string `dynamodbav:"session_control_table"`
	AgentKeysTable         string `dynamodbav:"agent_keys_table"`
	AgentKeySchema         int    `dynamodbav:"agent_key_schema_version"`
	CredentialKind         string `dynamodbav:"enrollment_credential_kind"`
	ConnectorIDClaim       string `dynamodbav:"connector_id_claim"`
	MappedSessionID        uint64 `dynamodbav:"mapped_session_id,omitempty"`
	MappedIssuedAtMillis   int64  `dynamodbav:"mapped_issued_at_ms,omitempty"`
	MappedDeadlineMillis   int64  `dynamodbav:"mapped_deadline_ms,omitempty"`
	MappedDirectoryVersion uint64 `dynamodbav:"mapped_directory_version,omitempty"`
	MappedActiveFenceCount uint64 `dynamodbav:"mapped_active_fence_count,omitempty"`
	TerminalAtMillis       int64  `dynamodbav:"terminal_at_ms,omitempty"`
	TTL                    int64  `dynamodbav:"ttl,omitempty"`
}

func validSessionControlNativeOperationHex(value string) bool {
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

func validSessionControlNativeOperationIdentity(value string) bool {
	return value != "" && len(value) <= 256
}

func validateNativeSessionOperationServerBindingConfig(binding common.NativeSessionOperationServerBinding) error {
	if len(binding.AWSAccountID) != 12 || binding.AWSRegion == "" || binding.CellID == "" ||
		binding.SessionControlTable == "" || binding.AgentKeysTable == "" ||
		binding.AgentKeySchema != internalauth.QURLAgentKeysSchemaVersion ||
		binding.CredentialKind != string(internalauth.QURLEnrollmentCredentialKindAccount) ||
		binding.ConnectorIDClaim != "" {
		return errors.New("native session operation server binding is incomplete")
	}
	for i := range len(binding.AWSAccountID) {
		if binding.AWSAccountID[i] < '0' || binding.AWSAccountID[i] > '9' {
			return errors.New("native session operation AWS account is invalid")
		}
	}
	return nil
}

func validateSessionControlNativeOperation(op sessionControlNativeOperation) error {
	serverBinding := common.NativeSessionOperationServerBinding{
		AWSAccountID: op.AWSAccountID, AWSRegion: op.AWSRegion, CellID: op.CellID,
		SessionControlTable: op.SessionControlTable, AgentKeysTable: op.AgentKeysTable,
		AgentKeySchema: op.AgentKeySchema, CredentialKind: op.CredentialKind,
		ConnectorIDClaim: op.ConnectorIDClaim,
	}
	if !op.Binding.valid() || !validSessionControlNativeOperationIdentity(op.OwnerID) ||
		!validSessionControlNativeOperationIdentity(op.AgentID) || !common.ValidNHPAgentPublicKey(op.AgentPublicKey) ||
		!validSessionControlNativeOperationIdentity(op.ResourceID) || op.AuthServiceID != common.RegisteredAgentAuthServiceID ||
		common.ValidateAgentKnockRunID(op.RunID) != nil || op.RunAttempt == 0 || op.PreparedAtMillis <= 0 ||
		op.ExpiresAtMillis <= op.PreparedAtMillis ||
		op.ExpiresAtMillis-op.PreparedAtMillis > common.NativeSessionOperationMaxCreationWindow.Milliseconds() ||
		validateNativeSessionOperationServerBindingConfig(serverBinding) != nil {
		return errSessionControlNativeOperationCorrupt
	}
	operationID, selectorErr := common.NativeSessionOperationID(op.AgentPublicKey, op.RunID, op.RunAttempt)
	if selectorErr != nil || operationID != op.Binding.OperationID {
		return errSessionControlNativeOperationCorrupt
	}
	projection := common.AgentKnockMsg{
		UserId: op.AgentID, DeviceId: op.AgentID, AuthServiceId: op.AuthServiceID,
		ResourceId: op.ResourceID, RunID: op.RunID, RunAttempt: op.RunAttempt,
		NativeSessionOperationID: op.Binding.OperationID, NativeSessionOperationBinding: op.Binding.BindingSHA256,
		NativeSessionOperationOwnerID: op.OwnerID, NativeSessionOperationPrepared: op.PreparedAtMillis,
		NativeSessionOperationExpiresAt: op.ExpiresAtMillis,
	}
	binding, bindingErr := common.NativeSessionOperationBindingSHA256(projection, op.AgentPublicKey, serverBinding)
	if bindingErr != nil || binding != op.Binding.BindingSHA256 {
		return errSessionControlNativeOperationCorrupt
	}
	return nil
}

func validateSessionControlNativeOperationAuthority(authority sessionControlNativeOperationAuthority) error {
	if validateSessionControlNativeOperation(authority.Operation) != nil {
		return errSessionControlNativeOperationCorrupt
	}
	switch authority.State {
	case sessionControlNativeOperationStateMapped, sessionControlNativeOperationStateClosing:
		if authority.Candidate == nil || !validSessionControlSessionCandidate(*authority.Candidate) ||
			authority.Candidate.NativeOperation != authority.Operation.Binding || authority.MappedDirectoryVersion == 0 ||
			authority.MappedActiveFenceCount > sessionControlFenceActiveLimit || authority.TerminalAtMillis != 0 || authority.TTL != 0 {
			return errSessionControlNativeOperationCorrupt
		}
	case sessionControlNativeOperationStateCanceled:
		if authority.Candidate != nil || authority.MappedDirectoryVersion != 0 || authority.MappedActiveFenceCount != 0 ||
			authority.TerminalAtMillis <= 0 || authority.TTL <= 0 ||
			authority.TTL > math.MaxInt64/time.Second.Milliseconds() ||
			authority.TTL*time.Second.Milliseconds() < authority.TerminalAtMillis {
			return errSessionControlNativeOperationCorrupt
		}
	case sessionControlNativeOperationStateClosed:
		if authority.Candidate == nil || !validSessionControlSessionCandidate(*authority.Candidate) ||
			authority.Candidate.NativeOperation != authority.Operation.Binding || authority.MappedDirectoryVersion == 0 ||
			authority.MappedActiveFenceCount > sessionControlFenceActiveLimit || authority.TerminalAtMillis <= 0 ||
			authority.TTL <= 0 || authority.TTL > math.MaxInt64/time.Second.Milliseconds() ||
			authority.TTL*time.Second.Milliseconds() < authority.TerminalAtMillis {
			return errSessionControlNativeOperationCorrupt
		}
	default:
		return errSessionControlNativeOperationCorrupt
	}
	return nil
}

func sessionControlNativeOperationPK(operationID string) string { return "OP#" + operationID }

func sessionControlNativeOperationKey(operationID string) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{
		"pk": &types.AttributeValueMemberS{Value: sessionControlNativeOperationPK(operationID)},
		"sk": &types.AttributeValueMemberS{Value: sessionControlNativeOperationSK},
	}
}

func sessionControlNativeOperationToRow(authority sessionControlNativeOperationAuthority) (sessionControlNativeOperationRow, error) {
	if err := validateSessionControlNativeOperationAuthority(authority); err != nil {
		return sessionControlNativeOperationRow{}, err
	}
	op := authority.Operation
	row := sessionControlNativeOperationRow{
		PK: sessionControlNativeOperationPK(op.Binding.OperationID), SK: sessionControlNativeOperationSK,
		Kind: sessionControlNativeOperationKind, SchemaVersion: sessionControlNativeOperationSchema,
		OperationID: op.Binding.OperationID, BindingSHA256: op.Binding.BindingSHA256, State: authority.State,
		OwnerID: op.OwnerID, AgentID: op.AgentID, AgentPublicKey: op.AgentPublicKey,
		ResourceID: op.ResourceID, AuthServiceID: op.AuthServiceID, RunID: op.RunID, RunAttempt: op.RunAttempt,
		PreparedAtMillis: op.PreparedAtMillis, ExpiresAtMillis: op.ExpiresAtMillis,
		AWSAccountID: op.AWSAccountID, AWSRegion: op.AWSRegion, CellID: op.CellID,
		SessionControlTable: op.SessionControlTable, AgentKeysTable: op.AgentKeysTable,
		AgentKeySchema: op.AgentKeySchema, CredentialKind: op.CredentialKind,
		ConnectorIDClaim: op.ConnectorIDClaim,
		TerminalAtMillis: authority.TerminalAtMillis, TTL: authority.TTL,
		MappedDirectoryVersion: authority.MappedDirectoryVersion,
		MappedActiveFenceCount: authority.MappedActiveFenceCount,
	}
	if authority.Candidate != nil {
		row.MappedSessionID = authority.Candidate.SessionID
		row.MappedIssuedAtMillis = authority.Candidate.IssuedAtMillis
		row.MappedDeadlineMillis = authority.Candidate.ReservationDeadlineMillis
	}
	return row, nil
}

func sessionControlNativeOperationFromRow(row sessionControlNativeOperationRow) (sessionControlNativeOperationAuthority, error) {
	op := sessionControlNativeOperation{
		Binding: sessionControlNativeOperationBinding{OperationID: row.OperationID, BindingSHA256: row.BindingSHA256},
		OwnerID: row.OwnerID, AgentID: row.AgentID, AgentPublicKey: row.AgentPublicKey,
		ResourceID: row.ResourceID, AuthServiceID: row.AuthServiceID, RunID: row.RunID, RunAttempt: row.RunAttempt,
		PreparedAtMillis: row.PreparedAtMillis, ExpiresAtMillis: row.ExpiresAtMillis,
		AWSAccountID: row.AWSAccountID, AWSRegion: row.AWSRegion, CellID: row.CellID,
		SessionControlTable: row.SessionControlTable, AgentKeysTable: row.AgentKeysTable,
		AgentKeySchema: row.AgentKeySchema, CredentialKind: row.CredentialKind,
		ConnectorIDClaim: row.ConnectorIDClaim,
	}
	authority := sessionControlNativeOperationAuthority{Operation: op, State: row.State,
		MappedDirectoryVersion: row.MappedDirectoryVersion, MappedActiveFenceCount: row.MappedActiveFenceCount,
		TerminalAtMillis: row.TerminalAtMillis, TTL: row.TTL}
	if row.MappedSessionID != 0 || row.MappedIssuedAtMillis != 0 || row.MappedDeadlineMillis != 0 {
		candidate := sessionControlSessionCandidate{
			CellID: op.CellID, AgentPublicKey: op.AgentPublicKey, SessionID: row.MappedSessionID,
			IssuedAtMillis: row.MappedIssuedAtMillis, ReservationDeadlineMillis: row.MappedDeadlineMillis,
			RunID: op.RunID, RunAttempt: op.RunAttempt, NativeOperation: op.Binding,
		}
		authority.Candidate = &candidate
	}
	if row.PK != sessionControlNativeOperationPK(row.OperationID) || row.SK != sessionControlNativeOperationSK ||
		row.Kind != sessionControlNativeOperationKind || row.SchemaVersion != sessionControlNativeOperationSchema ||
		validateSessionControlNativeOperationAuthority(authority) != nil {
		return sessionControlNativeOperationAuthority{}, errSessionControlNativeOperationCorrupt
	}
	return authority, nil
}

func sessionControlNativeOperationForKnock(msg *common.AgentKnockMsg, agentPublicKey string,
	server common.NativeSessionOperationServerBinding,
) (sessionControlNativeOperation, error) {
	if msg == nil {
		return sessionControlNativeOperation{}, errSessionControlNativeOperationCorrupt
	}
	wantBinding, err := common.NativeSessionOperationBindingSHA256(*msg, agentPublicKey, server)
	if err != nil || wantBinding != msg.NativeSessionOperationBinding {
		return sessionControlNativeOperation{}, errSessionControlNativeOperationCorrupt
	}
	op := sessionControlNativeOperation{
		Binding: sessionControlNativeOperationBinding{
			OperationID: msg.NativeSessionOperationID, BindingSHA256: msg.NativeSessionOperationBinding,
		},
		OwnerID: msg.NativeSessionOperationOwnerID, AgentID: msg.UserId, AgentPublicKey: agentPublicKey,
		ResourceID: msg.ResourceId, AuthServiceID: msg.AuthServiceId, RunID: msg.RunID, RunAttempt: msg.RunAttempt,
		PreparedAtMillis: msg.NativeSessionOperationPrepared, ExpiresAtMillis: msg.NativeSessionOperationExpiresAt,
		AWSAccountID: server.AWSAccountID, AWSRegion: server.AWSRegion, CellID: server.CellID,
		SessionControlTable: server.SessionControlTable, AgentKeysTable: server.AgentKeysTable,
		AgentKeySchema: server.AgentKeySchema, CredentialKind: server.CredentialKind,
		ConnectorIDClaim: server.ConnectorIDClaim,
	}
	if validateSessionControlNativeOperation(op) != nil {
		return sessionControlNativeOperation{}, errSessionControlNativeOperationCorrupt
	}
	return op, nil
}

func sessionControlNativeOperationToken(action string, operationID string) *string {
	digest := sha256.Sum256([]byte(action + "\x00" + operationID))
	value := "nop-" + action + "-" + hex.EncodeToString(digest[:12])
	return &value
}

func sessionControlNativeOperationDynamoOptions(options *dynamodb.Options) {
	options.RetryMaxAttempts = 1
}

func sessionControlNativeOperationIdentityChecks(op sessionControlNativeOperation, nowSeconds int64) []types.TransactWriteItem {
	claimOwner := internalauth.QURLAgentKeysPublicKeyClaimOwnerPrefix + op.AgentPublicKey
	claim := types.TransactWriteItem{ConditionCheck: &types.ConditionCheck{
		TableName: aws.String(op.AgentKeysTable),
		Key: map[string]types.AttributeValue{
			internalauth.QURLAgentKeysOwnerIDAttr: &types.AttributeValueMemberS{Value: claimOwner},
			internalauth.QURLAgentKeysAgentIDAttr: &types.AttributeValueMemberS{Value: internalauth.QURLAgentKeysPublicKeyClaimAgentID},
		},
		ConditionExpression: aws.String("#claim_owner = :owner AND #claim_scheme = :scheme AND attribute_type(#ttl, :number_type) AND #ttl > :now"),
		ExpressionAttributeNames: map[string]string{
			"#claim_owner":  internalauth.QURLAgentKeysPublicKeyClaimOwnerAttr,
			"#claim_scheme": internalauth.QURLAgentKeysPublicKeyClaimSchemeAttr,
			"#ttl":          internalauth.QURLAgentKeysTTLAttr,
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":owner":       &types.AttributeValueMemberS{Value: op.OwnerID},
			":scheme":      &types.AttributeValueMemberS{Value: internalauth.QURLAgentKeysPublicKeyClaimScheme},
			":number_type": &types.AttributeValueMemberS{Value: "N"},
			":now":         &types.AttributeValueMemberN{Value: strconv.FormatInt(nowSeconds, 10)},
		},
	}}
	registration := types.TransactWriteItem{ConditionCheck: &types.ConditionCheck{
		TableName: aws.String(op.AgentKeysTable),
		Key: map[string]types.AttributeValue{
			internalauth.QURLAgentKeysOwnerIDAttr: &types.AttributeValueMemberS{Value: op.OwnerID},
			internalauth.QURLAgentKeysAgentIDAttr: &types.AttributeValueMemberS{Value: op.AgentID},
		},
		ConditionExpression: aws.String("#public_key = :public_key AND #schema = :schema AND #credential = :credential AND attribute_not_exists(#connector) AND attribute_type(#ttl, :number_type) AND #ttl > :now"),
		ExpressionAttributeNames: map[string]string{
			"#public_key": internalauth.QURLAgentKeysPublicKeyAttr,
			"#schema":     internalauth.QURLAgentKeysSchemaVersionAttr,
			"#credential": internalauth.QURLAgentKeysEnrollmentCredentialKindAttr,
			"#connector":  internalauth.QURLAgentKeysConnectorIDClaimAttr,
			"#ttl":        internalauth.QURLAgentKeysTTLAttr,
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":public_key":  &types.AttributeValueMemberS{Value: op.AgentPublicKey},
			":schema":      &types.AttributeValueMemberN{Value: strconv.Itoa(internalauth.QURLAgentKeysSchemaVersion)},
			":credential":  &types.AttributeValueMemberS{Value: string(internalauth.QURLEnrollmentCredentialKindAccount)},
			":number_type": &types.AttributeValueMemberS{Value: "N"},
			":now":         &types.AttributeValueMemberN{Value: strconv.FormatInt(nowSeconds, 10)},
		},
	}}
	return []types.TransactWriteItem{claim, registration}
}

func (s *dynamoSessionControlStore) validateNativeOperationStore() error {
	if s == nil || !s.nativeOperations || s.operationClient == nil || s.tableName == "" ||
		s.agentKeysTable == "" || s.awsAccountID == "" || s.awsRegion == "" {
		return errors.New("native session operation authority is unavailable")
	}
	return nil
}

func (s *dynamoSessionControlStore) PingNativeSessionOperation(ctx context.Context) error {
	if err := s.validateNativeOperationStore(); err != nil {
		return err
	}
	probe := &dynamodb.TransactGetItemsInput{TransactItems: []types.TransactGetItem{
		{Get: &types.Get{TableName: aws.String(s.tableName), Key: sessionControlNativeOperationKey("__healthcheck__")}},
		{Get: &types.Get{TableName: aws.String(s.agentKeysTable), Key: map[string]types.AttributeValue{
			internalauth.QURLAgentKeysOwnerIDAttr: &types.AttributeValueMemberS{Value: "__healthcheck__"},
			internalauth.QURLAgentKeysAgentIDAttr: &types.AttributeValueMemberS{Value: "__healthcheck__"},
		}}},
	}}
	opCtx, cancel := context.WithTimeout(ctx, sessionControlNativeOperationReadTimeout)
	defer cancel()
	if _, err := s.operationClient.TransactGetItems(opCtx, probe, sessionControlNativeOperationDynamoOptions); err != nil {
		return fmt.Errorf("native session operation startup transaction read: %w", err)
	}
	return nil
}

func (s *dynamoSessionControlStore) classifyMappedNativeOperation(ctx context.Context,
	op sessionControlNativeOperation, expected *sessionControlSessionCandidate,
) (*sessionControlNativeOperationAuthority, *sessionControlSessionAuthority, *sessionControlFenceDirectory, error) {
	if err := s.validateNativeOperationStore(); err != nil {
		return nil, nil, nil, err
	}
	if validateSessionControlNativeOperation(op) != nil || expected == nil || !validSessionControlSessionCandidate(*expected) ||
		expected.NativeOperation != op.Binding {
		return nil, nil, nil, errSessionControlNativeOperationCorrupt
	}
	input := &dynamodb.TransactGetItemsInput{TransactItems: []types.TransactGetItem{
		{Get: &types.Get{TableName: aws.String(s.tableName), Key: sessionControlNativeOperationKey(op.Binding.OperationID)}},
		{Get: &types.Get{TableName: aws.String(s.tableName), Key: sessionControlSessionDynamoKey(expected.SessionID)}},
		{Get: &types.Get{TableName: aws.String(s.tableName), Key: sessionControlAgentSessionDynamoKey(*expected)}},
		{Get: &types.Get{TableName: aws.String(s.tableName), Key: sessionControlFenceDirectoryKey(expected.CellID)}},
	}}
	opCtx, cancel := context.WithTimeout(ctx, sessionControlNativeOperationReadTimeout)
	defer cancel()
	output, err := s.operationClient.TransactGetItems(opCtx, input, sessionControlNativeOperationDynamoOptions)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("classify native session operation: %w", err)
	}
	if len(output.Responses) != 4 || len(output.Responses[0].Item) == 0 {
		return nil, nil, nil, errSessionControlNativeOperationNotFound
	}
	var opRow sessionControlNativeOperationRow
	if attributevalue.UnmarshalMap(output.Responses[0].Item, &opRow) != nil {
		return nil, nil, nil, errSessionControlNativeOperationCorrupt
	}
	authority, err := sessionControlNativeOperationFromRow(opRow)
	if err != nil || authority.Operation != op || authority.Candidate == nil ||
		(authority.State != sessionControlNativeOperationStateMapped && authority.State != sessionControlNativeOperationStateClosing && authority.State != sessionControlNativeOperationStateClosed) {
		return nil, nil, nil, errSessionControlNativeOperationConflict
	}
	// A duplicate packet receives a newly allocated server session candidate,
	// but the immutable operation selector already maps the same authenticated
	// request to its first candidate. Return the exact mapped OP authority so the
	// caller can issue the stable recovery-required denial without consulting a
	// plugin, catalog, GSI, or a second DynamoDB request. The original atomic
	// transaction is the durable proof that its SESSION and membership existed;
	// the recovery path performs the exact-candidate close/classification.
	if *authority.Candidate != *expected {
		return &authority, nil, nil, errSessionControlNativeOperationConflict
	}
	var sessionRow sessionControlSessionRow
	var membershipRow sessionControlSessionMembershipRow
	var directoryRow sessionControlFenceDirectoryRow
	if attributevalue.UnmarshalMap(output.Responses[1].Item, &sessionRow) != nil ||
		attributevalue.UnmarshalMap(output.Responses[2].Item, &membershipRow) != nil ||
		attributevalue.UnmarshalMap(output.Responses[3].Item, &directoryRow) != nil {
		return nil, nil, nil, errSessionControlNativeOperationCorrupt
	}
	session, err := sessionControlSessionFromRow(sessionRow, expected.SessionID)
	if err != nil || session.Candidate != *expected {
		return nil, nil, nil, errSessionControlNativeOperationConflict
	}
	if _, err = sessionControlSessionMembershipFromRow(membershipRow, *expected); err != nil {
		return nil, nil, nil, errSessionControlNativeOperationConflict
	}
	directory, err := sessionControlFenceDirectoryFromRow(directoryRow, expected.CellID)
	if err != nil {
		return nil, nil, nil, errSessionControlNativeOperationConflict
	}
	return &authority, &session, &directory, nil
}

func (s *dynamoSessionControlStore) ReserveNativeSessionOperation(ctx context.Context,
	candidate sessionControlSessionCandidate, op sessionControlNativeOperation,
	snapshot sessionControlFenceSnapshot, now time.Time,
) (*sessionControlSessionAuthority, error) {
	if err := s.validateNativeOperationStore(); err != nil {
		return nil, err
	}
	if !validSessionControlSessionCandidate(candidate) || candidate.NativeOperation != op.Binding ||
		validateSessionControlNativeOperation(op) != nil || now.IsZero() ||
		now.UnixMilli() < op.PreparedAtMillis-common.NativeSessionOperationMaxClockSkew.Milliseconds() ||
		now.UnixMilli() >= op.ExpiresAtMillis {
		return nil, errSessionControlNativeOperationExpired
	}
	if err := validateSessionControlFenceSnapshot(snapshot, candidate.CellID); err != nil {
		return nil, err
	}
	if err := evaluateSessionControlFences(candidate, snapshot); err != nil {
		return nil, err
	}
	planned, err := planSessionControlReservation(candidate, snapshot)
	if err != nil {
		return nil, err
	}
	opAuthority := sessionControlNativeOperationAuthority{Operation: op, State: sessionControlNativeOperationStateMapped,
		Candidate: &candidate, MappedDirectoryVersion: snapshot.DirectoryVersion,
		MappedActiveFenceCount: snapshot.ActiveFenceCount}
	opRow, _ := sessionControlNativeOperationToRow(opAuthority)
	sessionRow, _ := sessionControlSessionToRow(planned)
	membershipRow, _ := sessionControlSessionMembershipToRow(candidate)
	opItem, err := attributevalue.MarshalMap(opRow)
	if err != nil {
		return nil, fmt.Errorf("marshal native session operation: %w", err)
	}
	sessionItem, err := attributevalue.MarshalMap(sessionRow)
	if err != nil {
		return nil, fmt.Errorf("marshal operation session: %w", err)
	}
	membershipItem, err := attributevalue.MarshalMap(membershipRow)
	if err != nil {
		return nil, fmt.Errorf("marshal operation membership: %w", err)
	}
	items := sessionControlNativeOperationIdentityChecks(op, now.Unix())
	directory := sessionControlDirectoryCondition(snapshot)
	directory.ConditionCheck.TableName = aws.String(s.tableName)
	items = append(items, directory,
		types.TransactWriteItem{Put: &types.Put{TableName: aws.String(s.tableName), Item: sessionItem,
			ConditionExpression: aws.String("attribute_not_exists(pk) AND attribute_not_exists(sk)")}},
		types.TransactWriteItem{Put: &types.Put{TableName: aws.String(s.tableName), Item: membershipItem,
			ConditionExpression: aws.String("attribute_not_exists(pk) AND attribute_not_exists(sk)")}},
		types.TransactWriteItem{Put: &types.Put{TableName: aws.String(s.tableName), Item: opItem,
			ConditionExpression: aws.String("attribute_not_exists(pk) AND attribute_not_exists(sk)")}},
	)
	opCtx, cancel := context.WithTimeout(ctx, sessionControlNativeOperationWriteTimeout)
	_, writeErr := s.operationClient.TransactWriteItems(opCtx, &dynamodb.TransactWriteItemsInput{
		ClientRequestToken: sessionControlNativeOperationToken("map", op.Binding.OperationID), TransactItems: items,
	}, sessionControlNativeOperationDynamoOptions)
	cancel()
	if writeErr == nil {
		return &planned, nil
	}
	resultCtx, resultCancel := context.WithTimeout(ctx, sessionControlNativeOperationReadTimeout)
	defer resultCancel()
	if mapped, _, _, classifyErr := s.classifyMappedNativeOperation(resultCtx, op, &candidate); mapped != nil &&
		mapped.Operation == op && (mapped.State == sessionControlNativeOperationStateMapped ||
		mapped.State == sessionControlNativeOperationStateClosing || mapped.State == sessionControlNativeOperationStateClosed) {
		return nil, common.ErrNativeSessionOperationRecoveryRequired
	} else if classifyErr != nil && !errors.Is(classifyErr, errSessionControlNativeOperationNotFound) {
		return nil, classifyErr
	}
	var canceled *types.TransactionCanceledException
	if errors.As(writeErr, &canceled) {
		return nil, errSessionControlNativeOperationConflict
	}
	return nil, fmt.Errorf("reserve native session operation: %w", writeErr)
}

func (s *dynamoSessionControlStore) VerifyMappedNativeSessionOperation(ctx context.Context,
	candidate sessionControlSessionCandidate, op sessionControlNativeOperation,
) (*sessionControlSessionAuthority, *sessionControlFenceDirectory, error) {
	authority, session, directory, err := s.classifyMappedNativeOperation(ctx, op, &candidate)
	if err != nil {
		return nil, nil, err
	}
	if authority == nil || directory.Version != authority.MappedDirectoryVersion ||
		directory.ActiveFenceCount != authority.MappedActiveFenceCount || directory.AdmissionBlocked {
		return nil, nil, errSessionControlSessionFenceStale
	}
	return session, directory, nil
}

func (s *dynamoSessionControlStore) getNativeOperation(ctx context.Context, operationID string) (*sessionControlNativeOperationAuthority, error) {
	if err := s.validateNativeOperationStore(); err != nil {
		return nil, err
	}
	if !validSessionControlNativeOperationHex(operationID) {
		return nil, errSessionControlNativeOperationCorrupt
	}
	opCtx, cancel := context.WithTimeout(ctx, sessionControlNativeOperationReadTimeout)
	defer cancel()
	output, err := s.operationClient.TransactGetItems(opCtx, &dynamodb.TransactGetItemsInput{TransactItems: []types.TransactGetItem{
		{Get: &types.Get{TableName: aws.String(s.tableName), Key: sessionControlNativeOperationKey(operationID)}},
	}}, sessionControlNativeOperationDynamoOptions)
	if err != nil {
		return nil, fmt.Errorf("read native session operation: %w", err)
	}
	if len(output.Responses) != 1 || len(output.Responses[0].Item) == 0 {
		return nil, errSessionControlNativeOperationNotFound
	}
	var row sessionControlNativeOperationRow
	if attributevalue.UnmarshalMap(output.Responses[0].Item, &row) != nil {
		return nil, errSessionControlNativeOperationCorrupt
	}
	authority, err := sessionControlNativeOperationFromRow(row)
	if err != nil {
		return nil, err
	}
	return &authority, nil
}

func (s *dynamoSessionControlStore) ResolveNativeSessionOperation(ctx context.Context,
	operationID string,
) (*sessionControlNativeOperationAuthority, error) {
	if err := s.validateNativeOperationStore(); err != nil {
		return nil, err
	}
	return s.getNativeOperation(ctx, operationID)
}

func nativeSessionOperationTerminalTTL(op sessionControlNativeOperation, terminalAtMillis, retainUntilMillis int64) (int64, error) {
	deadline, err := common.NativeSessionOperationAbsentRecoveryDeadline(op.PreparedAtMillis, op.ExpiresAtMillis)
	if err != nil || terminalAtMillis <= 0 {
		return 0, errSessionControlNativeOperationCorrupt
	}
	marginMillis := common.NativeSessionOperationPacketMargin.Milliseconds()
	if terminalAtMillis > math.MaxInt64-marginMillis {
		return 0, errSessionControlNativeOperationCorrupt
	}
	if terminalMargin := terminalAtMillis + marginMillis; terminalMargin > deadline {
		deadline = terminalMargin
	}
	if retainUntilMillis > deadline {
		deadline = retainUntilMillis
	}
	secondMillis := time.Second.Milliseconds()
	if deadline > math.MaxInt64-(secondMillis-1) {
		return 0, errSessionControlNativeOperationCorrupt
	}
	return (deadline + secondMillis - 1) / secondMillis, nil
}

func (s *dynamoSessionControlStore) nativeOperationForSession(ctx context.Context,
	candidate sessionControlSessionCandidate, requiredState string,
) (*sessionControlNativeOperationAuthority, error) {
	if !candidate.NativeOperation.present() {
		return nil, nil
	}
	current, err := s.getNativeOperation(ctx, candidate.NativeOperation.OperationID)
	if err != nil {
		return nil, err
	}
	if (requiredState != "" && current.State != requiredState) || current.Candidate == nil || *current.Candidate != candidate ||
		current.Operation.Binding != candidate.NativeOperation {
		return nil, errSessionControlNativeOperationConflict
	}
	return current, nil
}

func sessionControlNativeOperationExactTransition(tableName string,
	current, next sessionControlNativeOperationAuthority,
) (types.TransactWriteItem, error) {
	currentRow, err := sessionControlNativeOperationToRow(current)
	if err != nil {
		return types.TransactWriteItem{}, err
	}
	nextRow, err := sessionControlNativeOperationToRow(next)
	if err != nil {
		return types.TransactWriteItem{}, err
	}
	absent := []string{}
	if current.TerminalAtMillis == 0 {
		absent = append(absent, "terminal_at_ms")
	}
	if current.TTL == 0 {
		absent = append(absent, "ttl")
	}
	return sessionControlCloseExactReplace(tableName,
		sessionControlNativeOperationKey(current.Operation.Binding.OperationID), currentRow, nextRow, absent...)
}

func sessionControlNativeOperationPlanClosing(current sessionControlNativeOperationAuthority) (sessionControlNativeOperationAuthority, error) {
	if validateSessionControlNativeOperationAuthority(current) != nil ||
		current.State != sessionControlNativeOperationStateMapped || current.Candidate == nil {
		return sessionControlNativeOperationAuthority{}, errSessionControlNativeOperationConflict
	}
	next := current
	next.State = sessionControlNativeOperationStateClosing
	if validateSessionControlNativeOperationAuthority(next) != nil {
		return sessionControlNativeOperationAuthority{}, errSessionControlNativeOperationCorrupt
	}
	return next, nil
}

func sessionControlNativeOperationPlanClosed(current sessionControlNativeOperationAuthority,
	terminalAtMillis, retainUntilMillis int64,
) (sessionControlNativeOperationAuthority, error) {
	if validateSessionControlNativeOperationAuthority(current) != nil ||
		current.State != sessionControlNativeOperationStateClosing || current.Candidate == nil {
		return sessionControlNativeOperationAuthority{}, errSessionControlNativeOperationConflict
	}
	ttl, err := nativeSessionOperationTerminalTTL(current.Operation, terminalAtMillis, retainUntilMillis)
	if err != nil {
		return sessionControlNativeOperationAuthority{}, err
	}
	next := current
	next.State = sessionControlNativeOperationStateClosed
	next.TerminalAtMillis = terminalAtMillis
	next.TTL = ttl
	if validateSessionControlNativeOperationAuthority(next) != nil {
		return sessionControlNativeOperationAuthority{}, errSessionControlNativeOperationCorrupt
	}
	return next, nil
}

func (s *dynamoSessionControlStore) CancelAbsentNativeSessionOperation(ctx context.Context,
	op sessionControlNativeOperation, now time.Time,
) (*sessionControlNativeOperationAuthority, error) {
	if err := s.validateNativeOperationStore(); err != nil {
		return nil, err
	}
	deadline, err := common.NativeSessionOperationAbsentRecoveryDeadline(op.PreparedAtMillis, op.ExpiresAtMillis)
	if validateSessionControlNativeOperation(op) != nil || err != nil || now.IsZero() {
		return nil, errSessionControlNativeOperationExpired
	}
	// Retention is an absent-row creation boundary, not an existing-row
	// recovery boundary. At or after it, classify the exact row without an
	// attempted write. A live MAPPED/CLOSING or terminal receipt remains usable
	// indefinitely while DynamoDB still contains it; only true absence expires.
	if now.UnixMilli() >= deadline {
		current, readErr := s.getNativeOperation(ctx, op.Binding.OperationID)
		if readErr == nil && current.Operation == op {
			return current, nil
		}
		if readErr == nil {
			return nil, errSessionControlNativeOperationConflict
		}
		if errors.Is(readErr, errSessionControlNativeOperationNotFound) {
			return nil, errSessionControlNativeOperationExpired
		}
		return nil, readErr
	}
	ttl, err := nativeSessionOperationTerminalTTL(op, now.UnixMilli(), 0)
	if err != nil {
		return nil, err
	}
	authority := sessionControlNativeOperationAuthority{
		Operation: op, State: sessionControlNativeOperationStateCanceled,
		TerminalAtMillis: now.UnixMilli(), TTL: ttl,
	}
	row, _ := sessionControlNativeOperationToRow(authority)
	item, err := attributevalue.MarshalMap(row)
	if err != nil {
		return nil, fmt.Errorf("marshal canceled native session operation: %w", err)
	}
	items := sessionControlNativeOperationIdentityChecks(op, now.Unix())
	items = append(items, types.TransactWriteItem{Put: &types.Put{
		TableName: aws.String(s.tableName), Item: item,
		ConditionExpression: aws.String("attribute_not_exists(pk) AND attribute_not_exists(sk)"),
	}})
	opCtx, cancel := context.WithTimeout(ctx, sessionControlNativeOperationWriteTimeout)
	_, writeErr := s.operationClient.TransactWriteItems(opCtx, &dynamodb.TransactWriteItemsInput{
		ClientRequestToken: sessionControlNativeOperationToken("cancel", op.Binding.OperationID), TransactItems: items,
	}, sessionControlNativeOperationDynamoOptions)
	cancel()
	if writeErr == nil {
		return &authority, nil
	}
	resultCtx, resultCancel := context.WithTimeout(ctx, sessionControlNativeOperationReadTimeout)
	defer resultCancel()
	current, readErr := s.getNativeOperation(resultCtx, op.Binding.OperationID)
	if readErr == nil && current.Operation == op {
		return current, nil
	}
	if readErr == nil {
		return nil, errSessionControlNativeOperationConflict
	}
	return nil, fmt.Errorf("cancel absent native session operation: %w", writeErr)
}

func sessionControlNativeOperationAgentPublicKey(raw []byte) (string, error) {
	if len(raw) != 32 {
		return "", errSessionControlNativeOperationCorrupt
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}
