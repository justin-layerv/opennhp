package server

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/layervai/nhp/internalauth"
)

type nativeOperationDynamoFake struct {
	base       *sessionControlSessionDynamoFake
	gets       []*dynamodb.TransactGetItemsInput
	writes     []*dynamodb.TransactWriteItemsInput
	getOptions []dynamodb.Options
	putOptions []dynamodb.Options
	getHook    func(context.Context, *dynamodb.TransactGetItemsInput) (*dynamodb.TransactGetItemsOutput, error)
	writeHook  func(context.Context, *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error)
}

func nativeOperationOptions(options []func(*dynamodb.Options)) dynamodb.Options {
	var result dynamodb.Options
	for _, apply := range options {
		apply(&result)
	}
	return result
}

func (f *nativeOperationDynamoFake) TransactGetItems(ctx context.Context, input *dynamodb.TransactGetItemsInput,
	options ...func(*dynamodb.Options),
) (*dynamodb.TransactGetItemsOutput, error) {
	f.gets = append(f.gets, input)
	f.getOptions = append(f.getOptions, nativeOperationOptions(options))
	if f.getHook != nil {
		return f.getHook(ctx, input)
	}
	return f.read(input)
}

func (f *nativeOperationDynamoFake) read(input *dynamodb.TransactGetItemsInput) (*dynamodb.TransactGetItemsOutput, error) {
	responses := make([]types.ItemResponse, len(input.TransactItems))
	for index, item := range input.TransactItems {
		if item.Get == nil {
			return nil, errors.New("native operation TransactGet has a non-Get member")
		}
		f.base.mu.Lock()
		stored := f.base.items[sessionControlSessionDynamoMapKey(item.Get.Key)]
		f.base.mu.Unlock()
		responses[index].Item = stored
	}
	return &dynamodb.TransactGetItemsOutput{Responses: responses}, nil
}

func (f *nativeOperationDynamoFake) TransactWriteItems(ctx context.Context, input *dynamodb.TransactWriteItemsInput,
	options ...func(*dynamodb.Options),
) (*dynamodb.TransactWriteItemsOutput, error) {
	f.writes = append(f.writes, input)
	f.putOptions = append(f.putOptions, nativeOperationOptions(options))
	if f.writeHook != nil {
		return f.writeHook(ctx, input)
	}
	return &dynamodb.TransactWriteItemsOutput{}, nil
}

func (f *nativeOperationDynamoFake) applyPuts(input *dynamodb.TransactWriteItemsInput) {
	for _, member := range input.TransactItems {
		if member.Put != nil {
			f.base.setItem(member.Put.Item)
		}
	}
}

type nativeOperationFixture struct {
	base      *sessionControlSessionDynamoFake
	ddb       *nativeOperationDynamoFake
	store     *dynamoSessionControlStore
	candidate sessionControlSessionCandidate
	op        sessionControlNativeOperation
	snapshot  sessionControlFenceSnapshot
	now       time.Time
}

func newNativeOperationFixture(t *testing.T) nativeOperationFixture {
	t.Helper()
	base := newSessionControlSessionDynamoFake()
	ddb := &nativeOperationDynamoFake{base: base}
	now := time.UnixMilli(1_800_000_010_000).UTC()
	server := common.NativeSessionOperationServerBinding{
		AWSAccountID: "111122223333", AWSRegion: "us-east-2", CellID: "cell-01",
		SessionControlTable: storeTableNameForTest, AgentKeysTable: "control-qurl-agent-keys",
		AgentKeySchema:   common.NativeSessionOperationAgentKeySchema,
		CredentialKind:   common.NativeSessionOperationCredentialKind,
		ConnectorIDClaim: common.NativeSessionOperationConnectorIDClaim,
	}
	candidate := testSessionControlSessionCandidate(0x51, 201)
	msg := common.AgentKnockMsg{
		UserId: "agent-fixed-a", DeviceId: "agent-fixed-a", AuthServiceId: common.RegisteredAgentAuthServiceID,
		ResourceId: "resource-fixed-a", RunID: candidate.RunID, RunAttempt: candidate.RunAttempt,
		NativeSessionOperationOwnerID:   "auth0|fixed-canary-owner",
		NativeSessionOperationPrepared:  now.Add(-time.Second).UnixMilli(),
		NativeSessionOperationExpiresAt: now.Add(20 * time.Minute).UnixMilli(),
	}
	operationID, err := common.NativeSessionOperationID(candidate.AgentPublicKey, msg.RunID, msg.RunAttempt)
	if err != nil {
		t.Fatal(err)
	}
	msg.NativeSessionOperationID = operationID
	binding, err := common.NativeSessionOperationBindingSHA256(msg, candidate.AgentPublicKey, server)
	if err != nil {
		t.Fatal(err)
	}
	msg.NativeSessionOperationBinding = binding
	op, err := sessionControlNativeOperationForKnock(&msg, candidate.AgentPublicKey, server)
	if err != nil {
		t.Fatal(err)
	}
	candidate.NativeOperation = op.Binding
	snapshot := testSessionControlSessionSnapshot(7)
	seedSessionControlDirectory(t, base, snapshot)
	return nativeOperationFixture{
		base: base, ddb: ddb,
		store: &dynamoSessionControlStore{
			client: base, operationClient: ddb, tableName: storeTableNameForTest,
			agentKeysTable: server.AgentKeysTable, awsAccountID: server.AWSAccountID, awsRegion: server.AWSRegion,
			nativeOperations: true, nowUTC: func() time.Time { return now },
		},
		candidate: candidate, op: op, snapshot: snapshot, now: now,
	}
}

func TestDynamoNativeSessionOperationHealthyAdmissionIsOneSixItemTransaction(t *testing.T) {
	fixture := newNativeOperationFixture(t)
	fixture.ddb.writeHook = func(ctx context.Context, input *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
		deadline, ok := ctx.Deadline()
		if !ok {
			t.Fatal("operation write has no deadline")
		}
		remaining := time.Until(deadline)
		if remaining < 299*time.Millisecond || remaining > 301*time.Millisecond {
			t.Fatalf("operation write deadline = %s, want [299ms,301ms]", remaining)
		}
		return &dynamodb.TransactWriteItemsOutput{}, nil
	}
	reserved, err := fixture.store.ReserveNativeSessionOperation(context.Background(), fixture.candidate,
		fixture.op, fixture.snapshot, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	if reserved == nil || reserved.Candidate != fixture.candidate || len(fixture.ddb.gets) != 0 || len(fixture.base.gets) != 0 ||
		len(fixture.base.queries) != 0 || len(fixture.ddb.writes) != 1 {
		t.Fatalf("healthy path calls: reserved=%#v transact-get=%d get=%d query=%d writes=%d",
			reserved, len(fixture.ddb.gets), len(fixture.base.gets), len(fixture.base.queries), len(fixture.ddb.writes))
	}
	txn := fixture.ddb.writes[0]
	if len(txn.TransactItems) != 6 || fixture.ddb.putOptions[0].RetryMaxAttempts != 1 {
		t.Fatalf("native operation transaction = %#v options=%#v", txn, fixture.ddb.putOptions[0])
	}
	for index := 0; index < 2; index++ {
		check := txn.TransactItems[index].ConditionCheck
		if check == nil || aws.ToString(check.TableName) != fixture.op.AgentKeysTable {
			t.Fatalf("identity condition %d = %#v", index, check)
		}
	}
	claim := txn.TransactItems[0].ConditionCheck
	claimOwner, _ := claim.Key[internalauth.QURLAgentKeysOwnerIDAttr].(*types.AttributeValueMemberS)
	if claimOwner == nil || claimOwner.Value != internalauth.QURLAgentKeysPublicKeyClaimOwnerPrefix+fixture.op.AgentPublicKey ||
		aws.ToString(claim.ConditionExpression) != "#claim_owner = :owner AND #claim_scheme = :scheme AND attribute_type(#ttl, :number_type) AND #ttl > :now" {
		t.Fatalf("claim condition = %#v", claim)
	}
	registration := txn.TransactItems[1].ConditionCheck
	if aws.ToString(registration.ConditionExpression) != "#public_key = :public_key AND #schema = :schema AND #credential = :credential AND attribute_not_exists(#connector) AND attribute_type(#ttl, :number_type) AND #ttl > :now" {
		t.Fatalf("registration condition = %#v", registration)
	}
	if txn.TransactItems[2].ConditionCheck == nil || txn.TransactItems[3].Put == nil ||
		txn.TransactItems[4].Put == nil || txn.TransactItems[5].Put == nil {
		t.Fatalf("session transaction shape = %#v", txn.TransactItems)
	}
	var opRow sessionControlNativeOperationRow
	if err := attributevalue.UnmarshalMap(txn.TransactItems[5].Put.Item, &opRow); err != nil {
		t.Fatal(err)
	}
	if opRow.State != sessionControlNativeOperationStateMapped || opRow.TTL != 0 ||
		opRow.OperationID != fixture.op.Binding.OperationID ||
		opRow.AgentKeySchema != internalauth.QURLAgentKeysSchemaVersion ||
		opRow.CredentialKind != string(internalauth.QURLEnrollmentCredentialKindAccount) ||
		opRow.ConnectorIDClaim != "" {
		t.Fatalf("mapped operation row = %#v", opRow)
	}
}

func TestNativeSessionOperationIdentityConditionsAreExactLiveBaseRows(t *testing.T) {
	fixture := newNativeOperationFixture(t)
	checks := sessionControlNativeOperationIdentityChecks(fixture.op, fixture.now.Unix())
	if len(checks) != 2 {
		t.Fatalf("identity checks = %d, want claim plus registration", len(checks))
	}
	claim := checks[0].ConditionCheck
	registration := checks[1].ConditionCheck
	if claim == nil || registration == nil || aws.ToString(claim.TableName) != fixture.op.AgentKeysTable ||
		aws.ToString(registration.TableName) != fixture.op.AgentKeysTable {
		t.Fatalf("identity tables = %#v/%#v", claim, registration)
	}
	claimOwner, _ := claim.Key[internalauth.QURLAgentKeysOwnerIDAttr].(*types.AttributeValueMemberS)
	claimAgent, _ := claim.Key[internalauth.QURLAgentKeysAgentIDAttr].(*types.AttributeValueMemberS)
	if claimOwner == nil || claimOwner.Value != internalauth.QURLAgentKeysPublicKeyClaimOwnerPrefix+fixture.op.AgentPublicKey ||
		claimAgent == nil || claimAgent.Value != internalauth.QURLAgentKeysPublicKeyClaimAgentID ||
		aws.ToString(claim.ConditionExpression) != "#claim_owner = :owner AND #claim_scheme = :scheme AND attribute_type(#ttl, :number_type) AND #ttl > :now" {
		t.Fatalf("claim authority = %#v", claim)
	}
	registrationOwner, _ := registration.Key[internalauth.QURLAgentKeysOwnerIDAttr].(*types.AttributeValueMemberS)
	registrationAgent, _ := registration.Key[internalauth.QURLAgentKeysAgentIDAttr].(*types.AttributeValueMemberS)
	if registrationOwner == nil || registrationOwner.Value != fixture.op.OwnerID || registrationAgent == nil ||
		registrationAgent.Value != fixture.op.AgentID ||
		aws.ToString(registration.ConditionExpression) != "#public_key = :public_key AND #schema = :schema AND #credential = :credential AND attribute_not_exists(#connector) AND attribute_type(#ttl, :number_type) AND #ttl > :now" {
		t.Fatalf("registration authority = %#v", registration)
	}
	for name, check := range map[string]struct {
		values map[string]types.AttributeValue
		key    string
		want   string
	}{
		"claim owner":      {claim.ExpressionAttributeValues, ":owner", fixture.op.OwnerID},
		"claim scheme":     {claim.ExpressionAttributeValues, ":scheme", internalauth.QURLAgentKeysPublicKeyClaimScheme},
		"registration key": {registration.ExpressionAttributeValues, ":public_key", fixture.op.AgentPublicKey},
		"registration kind": {registration.ExpressionAttributeValues, ":credential",
			string(internalauth.QURLEnrollmentCredentialKindAccount)},
	} {
		value, _ := check.values[check.key].(*types.AttributeValueMemberS)
		if value == nil || value.Value != check.want {
			t.Fatalf("%s = %#v, want %q", name, value, check.want)
		}
	}
	schema, _ := registration.ExpressionAttributeValues[":schema"].(*types.AttributeValueMemberN)
	claimNow, _ := claim.ExpressionAttributeValues[":now"].(*types.AttributeValueMemberN)
	registrationNow, _ := registration.ExpressionAttributeValues[":now"].(*types.AttributeValueMemberN)
	if schema == nil || schema.Value != "2" || claimNow == nil || registrationNow == nil ||
		claimNow.Value != registrationNow.Value || claimNow.Value != fmt.Sprint(fixture.now.Unix()) {
		t.Fatalf("identity schema/time = %#v/%#v/%#v", schema, claimNow, registrationNow)
	}
}

func TestDynamoNativeSessionOperationLostResponseUsesOneFourItemClassifier(t *testing.T) {
	fixture := newNativeOperationFixture(t)
	fixture.ddb.writeHook = func(_ context.Context, input *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
		fixture.ddb.applyPuts(input)
		return nil, context.DeadlineExceeded
	}
	fixture.ddb.getHook = func(ctx context.Context, input *dynamodb.TransactGetItemsInput) (*dynamodb.TransactGetItemsOutput, error) {
		deadline, ok := ctx.Deadline()
		if !ok {
			t.Fatal("operation classifier has no deadline")
		}
		remaining := time.Until(deadline)
		if remaining < 599*time.Millisecond || remaining > 601*time.Millisecond {
			t.Fatalf("classifier deadline = %s, want [599ms,601ms]", remaining)
		}
		return fixture.ddb.read(input)
	}
	_, err := fixture.store.ReserveNativeSessionOperation(context.Background(), fixture.candidate,
		fixture.op, fixture.snapshot, fixture.now)
	if !errors.Is(err, common.ErrNativeSessionOperationRecoveryRequired) {
		t.Fatalf("lost response = %v, want recovery required", err)
	}
	if len(fixture.ddb.gets) != 1 || len(fixture.ddb.gets[0].TransactItems) != 4 ||
		len(fixture.base.gets) != 0 || len(fixture.base.queries) != 0 || fixture.ddb.getOptions[0].RetryMaxAttempts != 1 {
		t.Fatalf("classifier calls: transact=%d base-get=%d query=%d", len(fixture.ddb.gets), len(fixture.base.gets), len(fixture.base.queries))
	}
	for _, member := range fixture.ddb.gets[0].TransactItems {
		if member.Get == nil {
			t.Fatalf("classifier member is not a transactional Get: %#v", member)
		}
	}
}

func TestNativeSessionOperationDeadlineCeilingsAtAdjacentMilliseconds(t *testing.T) {
	for _, parentMillis := range []int{299, 300, 301} {
		t.Run(fmt.Sprintf("write-parent-%d", parentMillis), func(t *testing.T) {
			fixture := newNativeOperationFixture(t)
			want := time.Duration(parentMillis) * time.Millisecond
			if want > sessionControlNativeOperationWriteTimeout {
				want = sessionControlNativeOperationWriteTimeout
			}
			fixture.ddb.writeHook = func(ctx context.Context, _ *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
				deadline, ok := ctx.Deadline()
				remaining := time.Until(deadline)
				if !ok || remaining > want+time.Millisecond || remaining < want-25*time.Millisecond {
					t.Fatalf("write parent %dms gave deadline %s, want ceiling %s", parentMillis, remaining, want)
				}
				return &dynamodb.TransactWriteItemsOutput{}, nil
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Duration(parentMillis)*time.Millisecond)
			defer cancel()
			if _, err := fixture.store.ReserveNativeSessionOperation(ctx, fixture.candidate, fixture.op,
				fixture.snapshot, fixture.now); err != nil {
				t.Fatal(err)
			}
		})
	}

	for _, parentMillis := range []int{599, 600, 601} {
		t.Run(fmt.Sprintf("read-parent-%d", parentMillis), func(t *testing.T) {
			fixture := newNativeOperationFixture(t)
			planned, err := planSessionControlReservation(fixture.candidate, fixture.snapshot)
			if err != nil {
				t.Fatal(err)
			}
			authority := sessionControlNativeOperationAuthority{
				Operation: fixture.op, State: sessionControlNativeOperationStateMapped, Candidate: &fixture.candidate,
				MappedDirectoryVersion: fixture.snapshot.DirectoryVersion,
				MappedActiveFenceCount: fixture.snapshot.ActiveFenceCount,
			}
			opRow, _ := sessionControlNativeOperationToRow(authority)
			sessionRow, _ := sessionControlSessionToRow(planned)
			membershipRow, _ := sessionControlSessionMembershipToRow(fixture.candidate)
			fixture.base.setItem(marshalSessionControlSessionTestRow(t, opRow))
			fixture.base.setItem(marshalSessionControlSessionTestRow(t, sessionRow))
			fixture.base.setItem(marshalSessionControlSessionTestRow(t, membershipRow))
			want := time.Duration(parentMillis) * time.Millisecond
			if want > sessionControlNativeOperationReadTimeout {
				want = sessionControlNativeOperationReadTimeout
			}
			fixture.ddb.getHook = func(ctx context.Context, input *dynamodb.TransactGetItemsInput) (*dynamodb.TransactGetItemsOutput, error) {
				deadline, ok := ctx.Deadline()
				remaining := time.Until(deadline)
				if !ok || remaining > want+time.Millisecond || remaining < want-25*time.Millisecond {
					t.Fatalf("read parent %dms gave deadline %s, want ceiling %s", parentMillis, remaining, want)
				}
				return fixture.ddb.read(input)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Duration(parentMillis)*time.Millisecond)
			defer cancel()
			if _, _, err := fixture.store.VerifyMappedNativeSessionOperation(ctx, fixture.candidate, fixture.op); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestNativeSessionOperationAmbiguityClassifiersRemainInsideCallerAggregate(t *testing.T) {
	const parentBudget = 450 * time.Millisecond
	for _, operation := range []string{"mapped", "canceled"} {
		t.Run(operation, func(t *testing.T) {
			fixture := newNativeOperationFixture(t)
			fixture.ddb.writeHook = func(context.Context,
				*dynamodb.TransactWriteItemsInput,
			) (*dynamodb.TransactWriteItemsOutput, error) {
				return nil, context.DeadlineExceeded
			}
			fixture.ddb.getHook = func(ctx context.Context,
				input *dynamodb.TransactGetItemsInput,
			) (*dynamodb.TransactGetItemsOutput, error) {
				deadline, ok := ctx.Deadline()
				remaining := time.Until(deadline)
				if !ok || remaining > parentBudget+time.Millisecond || remaining < parentBudget-25*time.Millisecond {
					t.Fatalf("%s ambiguity classifier deadline = %s, want caller ceiling %s", operation,
						remaining, parentBudget)
				}
				return fixture.ddb.read(input)
			}
			ctx, cancel := context.WithTimeout(context.Background(), parentBudget)
			defer cancel()
			if operation == "mapped" {
				_, _ = fixture.store.ReserveNativeSessionOperation(ctx, fixture.candidate, fixture.op,
					fixture.snapshot, fixture.now)
			} else {
				_, _ = fixture.store.CancelAbsentNativeSessionOperation(ctx, fixture.op, fixture.now)
			}
			if len(fixture.ddb.gets) != 1 {
				t.Fatalf("%s ambiguity classifier calls = %d, want 1", operation, len(fixture.ddb.gets))
			}
		})
	}
}

func TestNativeSessionOperationExactCloseAmbiguityContextPreservesCallerAggregate(t *testing.T) {
	fixture := newNativeOperationFixture(t)
	const parentBudget = 450 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), parentBudget)
	defer cancel()
	parentDeadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("parent context has no deadline")
	}
	resultCtx, resultCancel := fixture.store.exactCloseResultContext(ctx, fixture.candidate)
	defer resultCancel()
	resultDeadline, ok := resultCtx.Deadline()
	if !ok || !resultDeadline.Equal(parentDeadline) {
		t.Fatalf("native exact-close result deadline = %v, want parent aggregate %v", resultDeadline, parentDeadline)
	}
}

func TestDynamoNativeSessionOperationSameSelectorDriftCannotMapTwice(t *testing.T) {
	fixture := newNativeOperationFixture(t)
	fixture.ddb.writeHook = func(_ context.Context, input *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
		if len(fixture.ddb.writes) == 1 {
			fixture.ddb.applyPuts(input)
			return &dynamodb.TransactWriteItemsOutput{}, nil
		}
		return nil, &types.TransactionCanceledException{}
	}
	if _, err := fixture.store.ReserveNativeSessionOperation(context.Background(), fixture.candidate,
		fixture.op, fixture.snapshot, fixture.now); err != nil {
		t.Fatal(err)
	}
	drifted := fixture.op
	drifted.OwnerID = "auth0|different-owner"
	projection := common.AgentKnockMsg{
		UserId: drifted.AgentID, DeviceId: drifted.AgentID, AuthServiceId: drifted.AuthServiceID,
		ResourceId: drifted.ResourceID, RunID: drifted.RunID, RunAttempt: drifted.RunAttempt,
		NativeSessionOperationID:      drifted.Binding.OperationID,
		NativeSessionOperationOwnerID: drifted.OwnerID, NativeSessionOperationPrepared: drifted.PreparedAtMillis,
		NativeSessionOperationExpiresAt: drifted.ExpiresAtMillis,
	}
	serverBinding := common.NativeSessionOperationServerBinding{
		AWSAccountID: drifted.AWSAccountID, AWSRegion: drifted.AWSRegion, CellID: drifted.CellID,
		SessionControlTable: drifted.SessionControlTable, AgentKeysTable: drifted.AgentKeysTable,
		AgentKeySchema: drifted.AgentKeySchema, CredentialKind: drifted.CredentialKind,
		ConnectorIDClaim: drifted.ConnectorIDClaim,
	}
	driftedBinding, err := common.NativeSessionOperationBindingSHA256(projection, drifted.AgentPublicKey, serverBinding)
	if err != nil {
		t.Fatal(err)
	}
	drifted.Binding.BindingSHA256 = driftedBinding
	driftedCandidate := fixture.candidate
	driftedCandidate.SessionID++
	driftedCandidate.NativeOperation = drifted.Binding
	if _, err := fixture.store.ReserveNativeSessionOperation(context.Background(), driftedCandidate,
		drifted, fixture.snapshot, fixture.now); !errors.Is(err, errSessionControlNativeOperationConflict) {
		t.Fatalf("same-selector drift = %v, want conflict", err)
	}
	if fixture.op.Binding.OperationID != drifted.Binding.OperationID || len(fixture.ddb.writes) != 2 {
		t.Fatalf("selector/write count drifted: %q/%q writes=%d", fixture.op.Binding.OperationID,
			drifted.Binding.OperationID, len(fixture.ddb.writes))
	}
}

func TestDynamoNativeSessionOperationExactDuplicateRequiresRecoveryWithoutSecondMapping(t *testing.T) {
	fixture := newNativeOperationFixture(t)
	fixture.ddb.writeHook = func(_ context.Context, input *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
		if len(fixture.ddb.writes) == 1 {
			fixture.ddb.applyPuts(input)
			return &dynamodb.TransactWriteItemsOutput{}, nil
		}
		return nil, &types.TransactionCanceledException{}
	}
	if _, err := fixture.store.ReserveNativeSessionOperation(context.Background(), fixture.candidate,
		fixture.op, fixture.snapshot, fixture.now); err != nil {
		t.Fatal(err)
	}
	duplicate := fixture.candidate
	duplicate.SessionID++
	duplicate.IssuedAtMillis++
	duplicate.ReservationDeadlineMillis++
	if _, err := fixture.store.ReserveNativeSessionOperation(context.Background(), duplicate,
		fixture.op, fixture.snapshot, fixture.now); !errors.Is(err, common.ErrNativeSessionOperationRecoveryRequired) {
		t.Fatalf("exact duplicate = %v, want recovery required", err)
	}
	if len(fixture.ddb.writes) != 2 || len(fixture.ddb.gets) != 1 || len(fixture.ddb.gets[0].TransactItems) != 4 {
		t.Fatalf("duplicate calls: writes=%d reads=%d", len(fixture.ddb.writes), len(fixture.ddb.gets))
	}
}

func TestDynamoNativeSessionOperationRecoveryExpiryAndTerminalTTL(t *testing.T) {
	fixture := newNativeOperationFixture(t)
	deadline, err := common.NativeSessionOperationAbsentRecoveryDeadline(fixture.op.PreparedAtMillis, fixture.op.ExpiresAtMillis)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name    string
		now     time.Time
		wantErr bool
	}{
		{name: "before retention", now: time.UnixMilli(deadline - 1), wantErr: false},
		{name: "at retention", now: time.UnixMilli(deadline), wantErr: true},
		{name: "after retention", now: time.UnixMilli(deadline + 1), wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			local := newNativeOperationFixture(t)
			_, cancelErr := local.store.CancelAbsentNativeSessionOperation(context.Background(), local.op, test.now)
			if test.wantErr != errors.Is(cancelErr, errSessionControlNativeOperationExpired) {
				t.Fatalf("cancel error = %v, want expired=%v", cancelErr, test.wantErr)
			}
			if test.wantErr && (len(local.ddb.gets) != 1 || len(local.ddb.gets[0].TransactItems) != 1 || len(local.ddb.writes) != 0) {
				t.Fatalf("expired absent recovery calls: reads=%d writes=%d", len(local.ddb.gets), len(local.ddb.writes))
			}
			if !test.wantErr {
				if len(local.ddb.writes) != 1 || len(local.ddb.writes[0].TransactItems) != 3 {
					t.Fatalf("cancel transaction = %#v", local.ddb.writes)
				}
				var row sessionControlNativeOperationRow
				if err := attributevalue.UnmarshalMap(local.ddb.writes[0].TransactItems[2].Put.Item, &row); err != nil {
					t.Fatal(err)
				}
				if row.State != sessionControlNativeOperationStateCanceled || row.TTL <= 0 || row.TerminalAtMillis != test.now.UnixMilli() {
					t.Fatalf("canceled row = %#v", row)
				}
			}
		})
	}
}

func TestDynamoNativeSessionOperationRecoveryIsTransactionFirstAndClassifiesExistingAfterIdentityRotation(t *testing.T) {
	fixture := newNativeOperationFixture(t)
	authority := sessionControlNativeOperationAuthority{
		Operation: fixture.op, State: sessionControlNativeOperationStateMapped, Candidate: &fixture.candidate,
		MappedDirectoryVersion: fixture.snapshot.DirectoryVersion,
		MappedActiveFenceCount: fixture.snapshot.ActiveFenceCount,
	}
	row, err := sessionControlNativeOperationToRow(authority)
	if err != nil {
		t.Fatal(err)
	}
	fixture.base.setItem(marshalSessionControlSessionTestRow(t, row))
	fixture.ddb.writeHook = func(context.Context, *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
		return nil, &types.TransactionCanceledException{}
	}
	current, err := fixture.store.CancelAbsentNativeSessionOperation(context.Background(), fixture.op, fixture.now)
	if err != nil || current == nil || current.Operation != fixture.op || current.State != sessionControlNativeOperationStateMapped {
		t.Fatalf("existing mapped recovery = %#v, %v", current, err)
	}
	if len(fixture.ddb.writes) != 1 || len(fixture.ddb.writes[0].TransactItems) != 3 ||
		len(fixture.ddb.gets) != 1 || len(fixture.ddb.gets[0].TransactItems) != 1 ||
		len(fixture.base.gets) != 0 || len(fixture.base.queries) != 0 {
		t.Fatalf("recovery calls: writes=%d txgets=%d basegets=%d queries=%d", len(fixture.ddb.writes),
			len(fixture.ddb.gets), len(fixture.base.gets), len(fixture.base.queries))
	}
}

func TestNativeSessionOperationCurrentMappedRemainsClassifiableAfterRetention(t *testing.T) {
	fixture := newNativeOperationFixture(t)
	planned, err := planSessionControlReservation(fixture.candidate, fixture.snapshot)
	if err != nil {
		t.Fatal(err)
	}
	authority := sessionControlNativeOperationAuthority{
		Operation: fixture.op, State: sessionControlNativeOperationStateMapped, Candidate: &fixture.candidate,
		MappedDirectoryVersion: fixture.snapshot.DirectoryVersion,
		MappedActiveFenceCount: fixture.snapshot.ActiveFenceCount,
	}
	opRow, _ := sessionControlNativeOperationToRow(authority)
	sessionRow, _ := sessionControlSessionToRow(planned)
	membershipRow, _ := sessionControlSessionMembershipToRow(fixture.candidate)
	fixture.base.setItem(marshalSessionControlSessionTestRow(t, opRow))
	fixture.base.setItem(marshalSessionControlSessionTestRow(t, sessionRow))
	fixture.base.setItem(marshalSessionControlSessionTestRow(t, membershipRow))
	deadline, _ := common.NativeSessionOperationAbsentRecoveryDeadline(fixture.op.PreparedAtMillis, fixture.op.ExpiresAtMillis)
	fixture.store.nowUTC = func() time.Time { return time.UnixMilli(deadline + time.Hour.Milliseconds()) }
	got, _, err := fixture.store.VerifyMappedNativeSessionOperation(context.Background(), fixture.candidate, fixture.op)
	if err != nil || got == nil || got.Candidate != fixture.candidate {
		t.Fatalf("post-retention mapped classifier = %#v, %v", got, err)
	}
	current, err := fixture.store.CancelAbsentNativeSessionOperation(context.Background(), fixture.op,
		time.UnixMilli(deadline+time.Hour.Milliseconds()))
	if err != nil || current == nil || current.State != sessionControlNativeOperationStateMapped ||
		current.Operation != fixture.op || len(fixture.ddb.writes) != 0 {
		t.Fatalf("post-retention recovery classifier = %#v, %v writes=%d", current, err, len(fixture.ddb.writes))
	}
}

func TestDynamoNativeSessionOperationExactCloseAtomicallyMovesMappedToClosing(t *testing.T) {
	fixture := newNativeOperationFixture(t)
	planned, err := planSessionControlReservation(fixture.candidate, fixture.snapshot)
	if err != nil {
		t.Fatal(err)
	}
	seedSessionControlReservation(t, fixture.base, planned)
	authority := sessionControlNativeOperationAuthority{
		Operation: fixture.op, State: sessionControlNativeOperationStateMapped, Candidate: &fixture.candidate,
		MappedDirectoryVersion: fixture.snapshot.DirectoryVersion,
		MappedActiveFenceCount: fixture.snapshot.ActiveFenceCount,
	}
	opRow, err := sessionControlNativeOperationToRow(authority)
	if err != nil {
		t.Fatal(err)
	}
	fixture.base.setItem(marshalSessionControlSessionTestRow(t, opRow))

	close, err := fixture.store.EnsureExactSessionClose(context.Background(), fixture.candidate,
		fixture.candidate.ReservationDeadlineMillis)
	if err != nil {
		t.Fatal(err)
	}
	if close == nil || close.Session.State != sessionControlSessionStateClosing || len(fixture.base.transactions) != 1 {
		t.Fatalf("close/transactions = %#v/%d", close, len(fixture.base.transactions))
	}
	txn := fixture.base.transactions[0]
	if len(txn.TransactItems) != 6 {
		t.Fatalf("native close transaction has %d items, want normal five plus OP", len(txn.TransactItems))
	}
	opWrite := txn.TransactItems[len(txn.TransactItems)-1].Put
	if opWrite == nil {
		t.Fatalf("native close OP member = %#v", txn.TransactItems[len(txn.TransactItems)-1])
	}
	var closing sessionControlNativeOperationRow
	if err := attributevalue.UnmarshalMap(opWrite.Item, &closing); err != nil {
		t.Fatal(err)
	}
	if closing.State != sessionControlNativeOperationStateClosing || closing.OperationID != fixture.op.Binding.OperationID ||
		closing.BindingSHA256 != fixture.op.Binding.BindingSHA256 || closing.TTL != 0 || closing.TerminalAtMillis != 0 {
		t.Fatalf("closing OP = %#v", closing)
	}
	condition := aws.ToString(opWrite.ConditionExpression)
	for _, attribute := range []string{"state", "operation_id", "binding_sha256", "terminal_at_ms", "ttl"} {
		alias := ""
		for name, value := range opWrite.ExpressionAttributeNames {
			if value == attribute {
				alias = name
				break
			}
		}
		if alias == "" || !strings.Contains(condition, alias) {
			t.Fatalf("closing OP exact condition %q does not bind attribute %q via %#v", condition, attribute,
				opWrite.ExpressionAttributeNames)
		}
	}
}

func TestNativeSessionOperationPersistedAuthorityRecomputesExactBinding(t *testing.T) {
	fixture := newNativeOperationFixture(t)
	authority := sessionControlNativeOperationAuthority{
		Operation: fixture.op, State: sessionControlNativeOperationStateMapped, Candidate: &fixture.candidate,
		MappedDirectoryVersion: fixture.snapshot.DirectoryVersion,
		MappedActiveFenceCount: fixture.snapshot.ActiveFenceCount,
	}
	row, err := sessionControlNativeOperationToRow(authority)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := sessionControlNativeOperationFromRow(row)
	if err != nil || decoded.Operation != authority.Operation || decoded.State != authority.State ||
		decoded.Candidate == nil || *decoded.Candidate != fixture.candidate ||
		decoded.MappedDirectoryVersion != authority.MappedDirectoryVersion ||
		decoded.MappedActiveFenceCount != authority.MappedActiveFenceCount ||
		decoded.TerminalAtMillis != authority.TerminalAtMillis || decoded.TTL != authority.TTL {
		t.Fatalf("canonical persisted authority = %#v, %v", decoded, err)
	}
	for name, mutate := range map[string]func(*sessionControlNativeOperationRow){
		"owner":       func(value *sessionControlNativeOperationRow) { value.OwnerID += "-drift" },
		"agent":       func(value *sessionControlNativeOperationRow) { value.AgentID += "-drift" },
		"resource":    func(value *sessionControlNativeOperationRow) { value.ResourceID += "-drift" },
		"run attempt": func(value *sessionControlNativeOperationRow) { value.RunAttempt++ },
		"cell":        func(value *sessionControlNativeOperationRow) { value.CellID += "-drift" },
		"table":       func(value *sessionControlNativeOperationRow) { value.SessionControlTable += "-drift" },
		"schema":      func(value *sessionControlNativeOperationRow) { value.AgentKeySchema++ },
		"credential":  func(value *sessionControlNativeOperationRow) { value.CredentialKind = "bootstrap" },
		"connector":   func(value *sessionControlNativeOperationRow) { value.ConnectorIDClaim = "connector-a" },
	} {
		t.Run(name, func(t *testing.T) {
			drifted := row
			mutate(&drifted)
			if _, err := sessionControlNativeOperationFromRow(drifted); !errors.Is(err, errSessionControlNativeOperationCorrupt) {
				t.Fatalf("persisted binding drift = %v, want corrupt", err)
			}
		})
	}
}

func TestDynamoNativeSessionOperationAmbiguousExactCloseRequiresClosingOperation(t *testing.T) {
	for _, test := range []struct {
		name        string
		commitState string
		wantErr     error
	}{
		{name: "exact closing operation classifies the lost response", commitState: sessionControlNativeOperationStateClosing},
		{name: "mapped operation cannot classify a lost close response", commitState: sessionControlNativeOperationStateMapped,
			wantErr: errSessionControlNativeOperationConflict},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newNativeOperationFixture(t)
			reserved, err := planSessionControlReservation(fixture.candidate, fixture.snapshot)
			if err != nil {
				t.Fatal(err)
			}
			seedSessionControlReservation(t, fixture.base, reserved)
			mapped := sessionControlNativeOperationAuthority{
				Operation: fixture.op, State: sessionControlNativeOperationStateMapped, Candidate: &fixture.candidate,
				MappedDirectoryVersion: fixture.snapshot.DirectoryVersion,
				MappedActiveFenceCount: fixture.snapshot.ActiveFenceCount,
			}
			mappedRow, err := sessionControlNativeOperationToRow(mapped)
			if err != nil {
				t.Fatal(err)
			}
			fixture.base.setItem(marshalSessionControlSessionTestRow(t, mappedRow))
			directory := sessionControlCloseTestDirectory(fixture.snapshot, 1_800_000_000_000)
			expected := expectedSessionControlExactClose(t, reserved, directory, fixture.now.UnixMilli(),
				reserved.RetainUntilMillis)
			fixture.base.transactHook = func(context.Context,
				*dynamodb.TransactWriteItemsInput,
			) (*dynamodb.TransactWriteItemsOutput, error) {
				seedCommittedSessionControlExactClose(t, fixture.base, directory, expected)
				committed := mapped
				if test.commitState == sessionControlNativeOperationStateClosing {
					committed, err = sessionControlNativeOperationPlanClosing(mapped)
					if err != nil {
						t.Fatal(err)
					}
				}
				row, rowErr := sessionControlNativeOperationToRow(committed)
				if rowErr != nil {
					t.Fatal(rowErr)
				}
				fixture.base.setItem(marshalSessionControlSessionTestRow(t, row))
				return nil, context.DeadlineExceeded
			}
			got, err := fixture.store.EnsureExactSessionClose(context.Background(), fixture.candidate,
				fixture.candidate.ReservationDeadlineMillis)
			if test.wantErr != nil {
				if !errors.Is(err, test.wantErr) || got != nil {
					t.Fatalf("ambiguous close = %#v, %v, want %v", got, err, test.wantErr)
				}
				return
			}
			if err != nil || got == nil || got.Session.State != sessionControlSessionStateClosing {
				t.Fatalf("ambiguous close = %#v, %v", got, err)
			}
		})
	}
}

func TestNativeSessionOperationTerminalStateAndTTLContract(t *testing.T) {
	fixture := newNativeOperationFixture(t)
	mapped := sessionControlNativeOperationAuthority{
		Operation: fixture.op, State: sessionControlNativeOperationStateMapped, Candidate: &fixture.candidate,
		MappedDirectoryVersion: fixture.snapshot.DirectoryVersion,
		MappedActiveFenceCount: fixture.snapshot.ActiveFenceCount,
	}
	closing, err := sessionControlNativeOperationPlanClosing(mapped)
	if err != nil {
		t.Fatal(err)
	}
	if closing.TTL != 0 || closing.TerminalAtMillis != 0 {
		t.Fatalf("CLOSING must have no TTL: %#v", closing)
	}
	terminalAt := fixture.now.Add(25 * time.Hour).UnixMilli()
	retainUntil := terminalAt + 3*time.Hour.Milliseconds()
	closed, err := sessionControlNativeOperationPlanClosed(closing, terminalAt, retainUntil)
	if err != nil {
		t.Fatal(err)
	}
	if closed.State != sessionControlNativeOperationStateClosed || closed.TerminalAtMillis != terminalAt ||
		closed.TTL*time.Second.Milliseconds() < retainUntil || closed.TTL <= 0 {
		t.Fatalf("CLOSED terminal authority = %#v", closed)
	}
	write, err := sessionControlNativeOperationExactTransition(storeTableNameForTest, closing, closed)
	if err != nil || write.Put == nil {
		t.Fatalf("CLOSING->CLOSED write = %#v, %v", write, err)
	}
	var row sessionControlNativeOperationRow
	if err := attributevalue.UnmarshalMap(write.Put.Item, &row); err != nil {
		t.Fatal(err)
	}
	if row.State != sessionControlNativeOperationStateClosed || row.TerminalAtMillis != terminalAt || row.TTL != closed.TTL {
		t.Fatalf("terminal row = %#v", row)
	}
}
