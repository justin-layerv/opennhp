package server

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

const sessionControlHealthPK = "CONTROL#__healthcheck__"

// sessionControlStore is the durable authority boundary for NHP session
// admission and close recovery. It is deliberately separate from
// StorageBackend: routing assignments expire and may be rebuilt, while pending
// session-control authority must survive disconnects and process restarts.
type sessionControlStore interface {
	PingSessionControl(context.Context) error
	SnapshotActiveFences(context.Context, string) (*sessionControlFenceSnapshot, error)
	GetTarget(context.Context, sessionControlTargetKey) (*sessionControlTargetAuthority, error)
	ListRequiredTargets(context.Context, string, string) ([]sessionControlTargetAuthority, error)
	PrepareTarget(context.Context, sessionControlTargetCandidate) (*sessionControlTargetPreparation, error)
	ActivateTarget(context.Context, sessionControlTargetActivation) (*sessionControlTargetAuthority, error)
	FinalizeTargetReady(context.Context, sessionControlTargetReadiness) (*sessionControlTargetAuthority, error)
	CancelTargetPreparation(context.Context, sessionControlTargetFence) (*sessionControlTargetAuthority, error)
}

type sessionControlDynamoAPI interface {
	GetItem(context.Context, *dynamodb.GetItemInput, ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error)
	PutItem(context.Context, *dynamodb.PutItemInput, ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error)
	Query(context.Context, *dynamodb.QueryInput, ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error)
	UpdateItem(context.Context, *dynamodb.UpdateItemInput, ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error)
	TransactWriteItems(context.Context, *dynamodb.TransactWriteItemsInput, ...func(*dynamodb.Options)) (*dynamodb.TransactWriteItemsOutput, error)
}

type dynamoSessionControlStore struct {
	client           sessionControlDynamoAPI
	tableName        string
	nowUTC           func() time.Time
	operationTimeout time.Duration
}

func (s *dynamoSessionControlStore) timeout() time.Duration {
	if s != nil && s.operationTimeout > 0 {
		return s.operationTimeout
	}
	return DynamoDBOperationTimeout
}

func NewSessionControlStoreFromStorage(ctx context.Context, storage StorageBackend) (sessionControlStore, error) {
	ddb, err := unwrapDynamoDBStorage(storage)
	if err != nil {
		return nil, fmt.Errorf("session-control store: %w", err)
	}
	if ddb == nil {
		return nil, errors.New("session-control store: DynamoDB backend is required")
	}
	if ddb.config.SessionControlTable == "" {
		return nil, errors.New("session-control store: SessionControlTable is not configured")
	}
	store := &dynamoSessionControlStore{
		client:    ddb.client,
		tableName: ddb.config.SessionControlTable,
		nowUTC:    func() time.Time { return time.Now().UTC() },
	}
	if err := store.PingSessionControl(ctx); err != nil {
		return nil, err
	}
	return store, nil
}

// PingSessionControl verifies the exact composite-key table and the server's
// strongly-consistent GetItem permission. A missing table, wrong key schema,
// or missing IAM/KMS grant fails startup before any AOL/knock listener binds.
func (s *dynamoSessionControlStore) PingSessionControl(ctx context.Context) error {
	if s == nil || s.client == nil {
		return errors.New("session-control store: DynamoDB client is not initialized")
	}
	if s.tableName == "" {
		return errors.New("session-control store: SessionControlTable is not configured")
	}

	ctx, cancel := context.WithTimeout(ctx, s.timeout())
	defer cancel()
	_, err := s.client.GetItem(ctx, sessionControlHealthRead(s.tableName))
	if err != nil {
		return fmt.Errorf("session-control store: strong startup read: %w", err)
	}
	// The due index is a mandatory crash-recovery capability, not an optional
	// accelerator: ACK publication can precede its durable mark, and the only
	// safe restart behavior for an expired RESERVED row is exact close. Probe the
	// named index and Query grant before any listener accepts session admission.
	_, err = s.client.Query(ctx, &dynamodb.QueryInput{
		TableName: aws.String(s.tableName), IndexName: aws.String(sessionControlDueIndexName),
		KeyConditionExpression: aws.String("due_shard = :shard AND due_sort <= :through"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":shard":   &types.AttributeValueMemberS{Value: "SESSION#__healthcheck__#00"},
			":through": &types.AttributeValueMemberS{Value: sessionControlSessionIssuedText(math.MaxInt64) + "#\uffff"},
		},
		Limit: aws.Int32(1),
	})
	if err != nil {
		return fmt.Errorf("session-control store: mandatory due-index startup query: %w", err)
	}
	return nil
}
