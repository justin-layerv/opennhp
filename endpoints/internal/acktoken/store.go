package acktoken

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// OperationTimeout caps a single DynamoDB read. It mirrors the server's
// DynamoDBOperationTimeout (endpoints/server); duplicated here so the shared
// reader carries no dependency on package server — keep the two values in sync.
const OperationTimeout = 5 * time.Second

// Reader is the read-only, fleet-visible ACK-token lookup. nhp-server's
// write path stays on its own DynamoDBStorage; this is the read seam the AC
// validator consumes (and the server validator could adopt later).
type Reader interface {
	LoadACToken(ctx context.Context, token string) (*ACTokenEntry, bool, error)
}

// DynamoDBReader is a minimal, read-only DynamoDB-backed Reader. It owns its
// own dynamodb.Client + table name and carries none of the server's
// DynamoDBStorage baggage (assignments, licenses, resources, the decorator
// chain).
type DynamoDBReader struct {
	client *dynamodb.Client
	table  string
}

// NewDynamoDBReader builds a read-only DynamoDB-backed Reader for the given
// region + table. endpoint is optional (local-dev DynamoDB); pass "" in prod.
// The AWS SDK defers connection, so construction succeeds offline — failures
// surface on the first LoadACToken, which the validator turns into a
// fail-closed 503. Modeled on endpoints/licenseadmin's newDynamoClient.
func NewDynamoDBReader(ctx context.Context, region, table, endpoint string) (*DynamoDBReader, error) {
	if table == "" {
		return nil, errors.New("acktoken: table name required")
	}
	opts := []func(*config.LoadOptions) error{config.WithRegion(region)}
	if endpoint != "" {
		resolver := aws.EndpointResolverWithOptionsFunc(
			func(service, region string, options ...any) (aws.Endpoint, error) {
				return aws.Endpoint{URL: endpoint, SigningRegion: region}, nil
			},
		)
		opts = append(opts, config.WithEndpointResolverWithOptions(resolver))
	}
	awsCfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("acktoken: load AWS config: %w", err)
	}
	return &DynamoDBReader{client: dynamodb.NewFromConfig(awsCfg), table: table}, nil
}

// LoadACToken looks up the entry for token: (entry, true, nil) on hit,
// (nil, false, nil) on miss, (nil, false, err) on a store error. It is a
// read-only port of DynamoDBStorage.LoadACToken — strong-consistency read so
// a knock response's token can't observe a stale miss on a peer process,
// keyed by HashToken so the raw token never lands in DynamoDB.
func (r *DynamoDBReader) LoadACToken(ctx context.Context, token string) (*ACTokenEntry, bool, error) {
	if r == nil || r.client == nil {
		return nil, false, errors.New("acktoken: dynamodb client not initialized")
	}
	if token == "" {
		return nil, false, nil
	}

	ctx, cancel := context.WithTimeout(ctx, OperationTimeout)
	defer cancel()
	result, err := r.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName:      aws.String(r.table),
		ConsistentRead: aws.Bool(true),
		Key: map[string]types.AttributeValue{
			"token_hash": &types.AttributeValueMemberS{Value: HashToken(token)},
		},
	})
	if err != nil {
		return nil, false, fmt.Errorf("acktoken: get item: %w", err)
	}
	if result.Item == nil {
		return nil, false, nil
	}

	var item PersistedItem
	if err := attributevalue.UnmarshalMap(result.Item, &item); err != nil {
		return nil, false, fmt.Errorf("acktoken: unmarshal item: %w", err)
	}
	return EntryFromItem(item), true, nil
}
