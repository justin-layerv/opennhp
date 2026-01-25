package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/OpenNHP/opennhp/nhp/log"
)

const (
	// DynamoDBOperationTimeout is the maximum time for a single DynamoDB operation.
	// This provides predictable latency and prevents hung requests.
	DynamoDBOperationTimeout = 5 * time.Second
)

// ============================================================================
// DynamoDB Storage Backend
// See docs/design/PLUGGABLE_STORAGE_BACKEND.md for architecture details.
//
// Default storage backend for cloud deployments (AWS).
// Uses DynamoDB Global Tables for:
// - nhp_licenses: Customer license validation
// - nhp_ac_assignments: AC-to-server assignment mapping
// - nhp_resources: Resource definitions per customer
// ============================================================================

// DynamoDBStorage implements StorageBackend using AWS DynamoDB.
type DynamoDBStorage struct {
	client *dynamodb.Client
	config DynamoDBConfig
}

// NewDynamoDBStorage creates a new DynamoDB storage backend.
func NewDynamoDBStorage(ctx context.Context, cfg DynamoDBConfig) (*DynamoDBStorage, error) {
	// Build AWS config options
	opts := []func(*config.LoadOptions) error{
		config.WithRegion(cfg.Region),
	}

	// If a custom endpoint is specified (local development), add it
	if cfg.Endpoint != "" {
		customResolver := aws.EndpointResolverWithOptionsFunc(
			func(service, region string, options ...interface{}) (aws.Endpoint, error) {
				return aws.Endpoint{
					URL:           cfg.Endpoint,
					SigningRegion: cfg.Region,
				}, nil
			},
		)
		opts = append(opts, config.WithEndpointResolverWithOptions(customResolver))
	}

	// Load AWS config
	awsCfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	client := dynamodb.NewFromConfig(awsCfg)

	storage := &DynamoDBStorage{
		client: client,
		config: cfg,
	}

	// Warm up the connection by pinging DynamoDB.
	// AWS SDK defers connection establishment until the first API call.
	// This ensures any connection issues are detected at startup rather than
	// causing timeouts when the first AC registration attempt happens.
	log.Info("Warming up DynamoDB connection...")
	pingStart := time.Now()
	if err := storage.Ping(ctx); err != nil {
		return nil, fmt.Errorf("failed to ping DynamoDB during initialization: %w", err)
	}
	log.Info("DynamoDB connection established in %v", time.Since(pingStart))

	log.Info("DynamoDB storage initialized: region=%s, licenses=%s, assignments=%s, resources=%s",
		cfg.Region, cfg.LicensesTable, cfg.ACAssignmentsTable, cfg.ResourcesTable)

	return storage, nil
}

// Name returns the backend name.
func (d *DynamoDBStorage) Name() string {
	return "dynamodb"
}

// Close releases resources (no-op for DynamoDB client).
func (d *DynamoDBStorage) Close() error {
	return nil
}

// Ping checks DynamoDB connectivity by describing one of the configured tables.
// This is used for health checks in cloud mode deployments.
func (d *DynamoDBStorage) Ping(ctx context.Context) error {
	if d.client == nil {
		return fmt.Errorf("dynamodb client not initialized")
	}

	// Use the AC assignments table for health check (most commonly accessed)
	tableName := d.config.ACAssignmentsTable
	if tableName == "" {
		tableName = d.config.LicensesTable
	}
	if tableName == "" {
		return fmt.Errorf("no dynamodb tables configured")
	}

	ctx, cancel := context.WithTimeout(ctx, DynamoDBOperationTimeout)
	defer cancel()

	_, err := d.client.DescribeTable(ctx, &dynamodb.DescribeTableInput{
		TableName: aws.String(tableName),
	})
	return err
}

// ============================================================================
// AC Assignment Operations
// ============================================================================

// GetACAssignment retrieves the server assignment for an AC.
func (d *DynamoDBStorage) GetACAssignment(ctx context.Context, acID string) (*ACAssignment, error) {
	ctx, cancel := context.WithTimeout(ctx, DynamoDBOperationTimeout)
	defer cancel()

	result, err := d.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(d.config.ACAssignmentsTable),
		Key: map[string]types.AttributeValue{
			"ac_id": &types.AttributeValueMemberS{Value: acID},
		},
	})
	if err != nil {
		log.Error("DynamoDB GetItem failed for AC %s: %v", acID, err)
		return nil, NewServiceUnavailableError("DynamoDB unavailable", err)
	}

	if result.Item == nil {
		return nil, NewNotFoundError(fmt.Sprintf("AC assignment not found: %s", acID))
	}

	var assignment ACAssignment
	if err := attributevalue.UnmarshalMap(result.Item, &assignment); err != nil {
		log.Error("Failed to unmarshal AC assignment %s: %v", acID, err)
		return nil, &StorageError{Code: ErrCodeValidationFailed, Message: "failed to unmarshal assignment", Err: err}
	}

	return &assignment, nil
}

// GetACsByServer retrieves all ACs assigned to a specific server.
// NOTE: This is deferred to Phase 3 because assigned_servers is a List type
// which cannot be indexed directly in DynamoDB. Options for Phase 3:
// - Add a denormalized server_id attribute for GSI indexing
// - Use DynamoDB Scan with filter (expensive, only for admin/console use)
// - Implement in-memory tracking on the server side
func (d *DynamoDBStorage) GetACsByServer(ctx context.Context, serverID string) ([]ACAssignment, error) {
	log.Warning("GetACsByServer not yet implemented - deferred to Phase 3")
	return nil, NewNotFoundError("GetACsByServer not yet implemented")
}

// ============================================================================
// License Operations
// ============================================================================

// GetLicense retrieves license information using the license key.
// The license key is hashed with SHA256 for DynamoDB lookup (partition key).
// License keys are globally unique, so no customer ID is needed.
func (d *DynamoDBStorage) GetLicense(ctx context.Context, licenseKey string) (*License, error) {
	ctx, cancel := context.WithTimeout(ctx, DynamoDBOperationTimeout)
	defer cancel()

	// Compute SHA256 of license key for lookup
	hash := sha256.Sum256([]byte(licenseKey))
	licenseKeySHA256 := hex.EncodeToString(hash[:])

	result, err := d.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(d.config.LicensesTable),
		Key: map[string]types.AttributeValue{
			"license_key_sha256": &types.AttributeValueMemberS{Value: licenseKeySHA256},
		},
	})
	if err != nil {
		log.Error("DynamoDB GetItem failed for license: %v", err)
		return nil, NewServiceUnavailableError("DynamoDB unavailable", err)
	}

	if result.Item == nil {
		return nil, NewNotFoundError("license not found")
	}

	var license License
	if err := attributevalue.UnmarshalMap(result.Item, &license); err != nil {
		log.Error("Failed to unmarshal license: %v", err)
		return nil, &StorageError{Code: ErrCodeValidationFailed, Message: "failed to unmarshal license", Err: err}
	}

	return &license, nil
}

// ============================================================================
// Resource Operations
// ============================================================================

// GetResource retrieves resource definition by customer and resource ID.
func (d *DynamoDBStorage) GetResource(ctx context.Context, customerID, resourceID string) (*Resource, error) {
	ctx, cancel := context.WithTimeout(ctx, DynamoDBOperationTimeout)
	defer cancel()

	result, err := d.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(d.config.ResourcesTable),
		Key: map[string]types.AttributeValue{
			"customer_id": &types.AttributeValueMemberS{Value: customerID},
			"resource_id": &types.AttributeValueMemberS{Value: resourceID},
		},
	})
	if err != nil {
		log.Error("DynamoDB GetItem failed for resource %s/%s: %v", customerID, resourceID, err)
		return nil, NewServiceUnavailableError("DynamoDB unavailable", err)
	}

	if result.Item == nil {
		return nil, NewNotFoundError(fmt.Sprintf("resource not found: %s/%s", customerID, resourceID))
	}

	var resource Resource
	if err := attributevalue.UnmarshalMap(result.Item, &resource); err != nil {
		log.Error("Failed to unmarshal resource %s/%s: %v", customerID, resourceID, err)
		return nil, &StorageError{Code: ErrCodeValidationFailed, Message: "failed to unmarshal resource", Err: err}
	}

	return &resource, nil
}

// GetResourceByACID retrieves resources associated with a specific AC.
// Uses the ac_id-index GSI with pagination to handle >1MB result sets.
func (d *DynamoDBStorage) GetResourceByACID(ctx context.Context, acID string) ([]Resource, error) {
	// Use longer timeout for paginated queries (3x normal timeout)
	ctx, cancel := context.WithTimeout(ctx, DynamoDBOperationTimeout*3)
	defer cancel()

	var resources []Resource
	var lastEvaluatedKey map[string]types.AttributeValue

	for {
		// Check for context cancellation between pages to avoid wasting DynamoDB read capacity
		select {
		case <-ctx.Done():
			return resources, ctx.Err()
		default:
		}

		input := &dynamodb.QueryInput{
			TableName:              aws.String(d.config.ResourcesTable),
			IndexName:              aws.String("ac_id-index"),
			KeyConditionExpression: aws.String("ac_id = :ac_id"),
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":ac_id": &types.AttributeValueMemberS{Value: acID},
			},
		}

		// Continue from where we left off if paginating
		if lastEvaluatedKey != nil {
			input.ExclusiveStartKey = lastEvaluatedKey
		}

		result, err := d.client.Query(ctx, input)
		if err != nil {
			log.Error("DynamoDB Query failed for resources by AC %s: %v", acID, err)
			return nil, NewServiceUnavailableError("DynamoDB unavailable", err)
		}

		// Unmarshal results from this page
		for _, item := range result.Items {
			var resource Resource
			if err := attributevalue.UnmarshalMap(item, &resource); err != nil {
				log.Error("Failed to unmarshal resource for AC %s: %v", acID, err)
				continue
			}
			resources = append(resources, resource)
		}

		// Check if there are more pages
		if result.LastEvaluatedKey == nil {
			break
		}
		lastEvaluatedKey = result.LastEvaluatedKey
	}

	if len(resources) == 0 {
		return nil, NewNotFoundError(fmt.Sprintf("no resources found for AC: %s", acID))
	}

	return resources, nil
}

// ============================================================================
// Factory Function
// ============================================================================

// CreateStorageBackend creates a storage backend based on configuration.
func CreateStorageBackend(ctx context.Context, cfg StorageConfig) (StorageBackend, error) {
	switch cfg.Backend {
	case "dynamodb", "":
		// DynamoDB is the default
		backend, err := NewDynamoDBStorage(ctx, cfg.DynamoDB)
		if err != nil {
			return nil, err
		}
		// Wrap with cache
		return NewCachedStorage(backend, cfg.Cache), nil

	case "etcd":
		// etcd backend (feature flag for on-prem)
		backend, err := NewEtcdStorage(ctx, cfg.Etcd)
		if err != nil {
			return nil, err
		}
		// Wrap with cache
		return NewCachedStorage(backend, cfg.Cache), nil

	default:
		return nil, fmt.Errorf("unknown storage backend: %s", cfg.Backend)
	}
}
