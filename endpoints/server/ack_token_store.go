package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/log"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// ackTokenTTLGraceSeconds keeps DynamoDB's eventual TTL reaper behind the app
// enforced ExpireTime by one minute. The handler still rejects expired entries
// synchronously; the grace only prevents near-expiry rows from disappearing
// before a delayed cross-instance validation can observe and classify them.
const ackTokenTTLGraceSeconds int64 = 60

// ackTokenStore is the fleet-visible backing store for short-lived
// AC-issued ACK token metadata. The in-process tokenStore remains the
// fast path; this store removes validation affinity when FRPS and NHP
// are independently load-balanced.
type ackTokenStore interface {
	StoreACToken(ctx context.Context, token string, entry *ACTokenEntry) error
	LoadACToken(ctx context.Context, token string) (*ACTokenEntry, bool, error)
}

type persistedACKTokenItem struct {
	TokenHash      string `dynamodbav:"token_hash"`
	ResourceID     string `dynamodbav:"resource_id,omitempty"`
	UserPresent    bool   `dynamodbav:"user_present,omitempty"`
	UserID         string `dynamodbav:"user_id,omitempty"`
	DeviceID       string `dynamodbav:"device_id,omitempty"`
	OrganizationID string `dynamodbav:"organization_id,omitempty"`
	AuthServiceID  string `dynamodbav:"auth_service_id,omitempty"`
	OwnerID        string `dynamodbav:"owner_id,omitempty"`
	KnockSrcIP     string `dynamodbav:"knock_src_ip,omitempty"`
	RunID          string `dynamodbav:"run_id,omitempty"`
	OpenTime       int64  `dynamodbav:"open_time,omitempty"`
	ExpiresAtNanos int64  `dynamodbav:"expires_at_nanos"`
	TTL            int64  `dynamodbav:"ttl"`
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

	item, err := attributevalue.MarshalMap(ackTokenItemFromEntry(token, entry))
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
			"token_hash": &types.AttributeValueMemberS{Value: hashACKToken(token)},
		},
	})
	if err != nil {
		return nil, false, fmt.Errorf("ack token store: get item: %w", err)
	}
	if result.Item == nil {
		return nil, false, nil
	}

	var item persistedACKTokenItem
	if err := attributevalue.UnmarshalMap(result.Item, &item); err != nil {
		return nil, false, fmt.Errorf("ack token store: unmarshal item: %w", err)
	}
	entry := ackTokenEntryFromItem(item)
	return entry, true, nil
}

func ackTokenItemFromEntry(token string, entry *ACTokenEntry) persistedACKTokenItem {
	item := persistedACKTokenItem{
		TokenHash:      hashACKToken(token),
		ResourceID:     entry.ResourceId,
		KnockSrcIP:     entry.KnockSrcIP,
		RunID:          entry.RunID,
		OpenTime:       int64(entry.OpenTime),
		ExpiresAtNanos: entry.ExpireTime.UTC().UnixNano(),
		TTL:            entry.ExpireTime.UTC().Unix() + ackTokenTTLGraceSeconds,
	}
	if entry.User != nil {
		item.UserPresent = true
		item.UserID = entry.User.UserId
		item.DeviceID = entry.User.DeviceId
		item.OrganizationID = entry.User.OrganizationId
		item.AuthServiceID = entry.User.AuthServiceId
		item.OwnerID = entry.User.OwnerId
	}
	return item
}

func ackTokenEntryFromItem(item persistedACKTokenItem) *ACTokenEntry {
	var user *common.AgentUser
	// UserPresent preserves a non-nil empty user across round-trip.
	if item.UserPresent {
		user = &common.AgentUser{
			UserId:         item.UserID,
			DeviceId:       item.DeviceID,
			OrganizationId: item.OrganizationID,
			AuthServiceId:  item.AuthServiceID,
			OwnerId:        item.OwnerID,
		}
	}
	return &ACTokenEntry{
		User:       user,
		ResourceId: item.ResourceID,
		// ACTokens is intentionally not persisted in the shared store.
		// /nhp/internal/token/validate does not read it, and future
		// validate-path readers must not depend on local-vs-shared
		// entries carrying identical token snapshots.
		ACTokens:   map[string]string{},
		KnockSrcIP: item.KnockSrcIP,
		RunID:      item.RunID,
		OpenTime:   int(item.OpenTime),
		ExpireTime: time.Unix(0, item.ExpiresAtNanos).UTC(),
	}
}

func hashACKToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
