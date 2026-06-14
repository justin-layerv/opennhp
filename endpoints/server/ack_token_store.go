package server

import (
	"context"
	"errors"
	"fmt"

	"github.com/OpenNHP/opennhp/endpoints/internal/acktoken"
	"github.com/OpenNHP/opennhp/nhp/log"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// ackTokenStore is the fleet-visible backing store for short-lived
// AC-issued ACK token metadata. The in-process tokenStore remains the
// fast path; this store removes validation affinity when FRPS and NHP
// are independently load-balanced.
//
// The persisted item shape (acktoken.PersistedItem), the marshalers
// (acktoken.ItemFromEntry / EntryFromItem), and the token hasher
// (acktoken.HashToken) live in endpoints/internal/acktoken so the wire schema
// has a single definition that a future fleet-visible reader could share
// without importing package server. Today nhp-server is the only writer
// (StoreACToken) and reader (its /token/validate handler).
type ackTokenStore interface {
	StoreACToken(ctx context.Context, token string, entry *ACTokenEntry) error
	LoadACToken(ctx context.Context, token string) (*ACTokenEntry, bool, error)
}

func NewACKTokenStoreFromStorage(storage StorageBackend) (ackTokenStore, error) {
	ddb, err := unwrapDynamoDBStorage(storage)
	if err != nil || ddb == nil {
		return nil, err
	}
	if ddb.config.AckTokensTable == "" {
		log.Info("ACK token shared store disabled: AckTokensTable not configured")
		return nil, nil
	}
	return ddb, nil
}

func (d *DynamoDBStorage) StoreACToken(ctx context.Context, token string, entry *ACTokenEntry) error {
	if d == nil || d.client == nil {
		return errors.New("ack token store: dynamodb client not initialized")
	}
	if d.config.AckTokensTable == "" {
		return errors.New("ack token store: AckTokensTable not configured")
	}
	if token == "" || entry == nil {
		return nil
	}

	item, err := attributevalue.MarshalMap(acktoken.ItemFromEntry(token, entry))
	if err != nil {
		return fmt.Errorf("ack token store: marshal item: %w", err)
	}

	// Keep a per-operation ceiling for direct StoreACToken callers. When
	// PublishACKTokens passes its aggregate ACK publication context, this
	// nested timeout cannot extend that parent deadline; the aggregate budget
	// remains owned by PublishACKTokens.
	ctx, cancel := context.WithTimeout(ctx, DynamoDBOperationTimeout)
	defer cancel()
	_, err = d.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(d.config.AckTokensTable),
		Item:      item,
	})
	if err != nil {
		return fmt.Errorf("ack token store: put item: %w", err)
	}
	return nil
}

func (d *DynamoDBStorage) LoadACToken(ctx context.Context, token string) (*ACTokenEntry, bool, error) {
	if d == nil || d.client == nil {
		return nil, false, errors.New("ack token store: dynamodb client not initialized")
	}
	if d.config.AckTokensTable == "" {
		return nil, false, errors.New("ack token store: AckTokensTable not configured")
	}
	if token == "" {
		return nil, false, nil
	}

	ctx, cancel := context.WithTimeout(ctx, DynamoDBOperationTimeout)
	defer cancel()
	result, err := d.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(d.config.AckTokensTable),
		// Strong consistency preserves the write-then-validate race
		// contract across NHP instances: once a knock response carries
		// an ACK token, an immediate FRPS validation on a peer process
		// must not observe a stale miss and incorrectly deny it.
		ConsistentRead: aws.Bool(true),
		Key: map[string]types.AttributeValue{
			"token_hash": &types.AttributeValueMemberS{Value: acktoken.HashToken(token)},
		},
	})
	if err != nil {
		return nil, false, fmt.Errorf("ack token store: get item: %w", err)
	}
	if result.Item == nil {
		return nil, false, nil
	}

	var item acktoken.PersistedItem
	if err := attributevalue.UnmarshalMap(result.Item, &item); err != nil {
		return nil, false, fmt.Errorf("ack token store: unmarshal item: %w", err)
	}
	return acktoken.EntryFromItem(item), true, nil
}
