package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
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
	// (endpoints/internal/acktoken.OperationTimeout mirrors this for the AC's
	// read-only reader — keep the two values in sync.)
	DynamoDBOperationTimeout = 5 * time.Second

	// healthCheckSentinelKey is the well-known key used for DynamoDB health checks.
	// GetItem on this non-existent key returns an empty result (not an error),
	// confirming connectivity and table access with only dynamodb:GetItem permission.
	healthCheckSentinelKey = "__healthcheck__"
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
			func(service, region string, options ...any) (aws.Endpoint, error) {
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

// Ping checks DynamoDB connectivity using a lightweight GetItem call.
// This uses a well-known non-existent key to verify the table is reachable
// without requiring dynamodb:DescribeTable permission. GetItem on a
// non-existent key returns an empty result (not an error), which confirms
// connectivity and table access with only dynamodb:GetItem permission.
func (d *DynamoDBStorage) Ping(ctx context.Context) error {
	if d.client == nil {
		return errors.New("dynamodb client not initialized")
	}

	// Use the AC assignments table for health check (most commonly accessed).
	// We do not fall back to other tables because they have different key schemas
	// (e.g., LicensesTable uses "license_key_sha256", not "ac_id"), which would
	// cause a ValidationException.
	tableName := d.config.ACAssignmentsTable
	if tableName == "" {
		return errors.New("no ACAssignmentsTable configured for DynamoDB health check")
	}

	ctx, cancel := context.WithTimeout(ctx, DynamoDBOperationTimeout)
	defer cancel()

	// Use GetItem with a sentinel key that will never exist.
	// A successful call (even with no item found) confirms DynamoDB connectivity.
	// This only requires dynamodb:GetItem, which is already in the IAM policy.
	_, err := d.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(tableName),
		Key: map[string]types.AttributeValue{
			"ac_id": &types.AttributeValueMemberS{Value: healthCheckSentinelKey},
		},
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

// SaveACAssignment stores or updates an AC assignment.
func (d *DynamoDBStorage) SaveACAssignment(ctx context.Context, assignment *ACAssignment) error {
	ctx, cancel := context.WithTimeout(ctx, DynamoDBOperationTimeout)
	defer cancel()

	item, err := attributevalue.MarshalMap(assignment)
	if err != nil {
		log.Error("Failed to marshal AC assignment %s: %v", assignment.ACID, err)
		return &StorageError{Code: ErrCodeValidationFailed, Message: "failed to marshal assignment", Err: err}
	}

	input := &dynamodb.PutItemInput{
		TableName: aws.String(d.config.ACAssignmentsTable),
		Item:      item,
	}

	// Use conditional writes to prevent lost updates from concurrent modifications.
	// Version 1: new assignment — only succeed if no assignment exists yet.
	// Version >1: update — require the stored version to match the previous value.
	if assignment.Version == 1 {
		input.ConditionExpression = aws.String("attribute_not_exists(ac_id)")
	} else {
		input.ConditionExpression = aws.String("attribute_not_exists(ac_id) OR version = :expected_version")
		input.ExpressionAttributeValues = map[string]types.AttributeValue{
			":expected_version": &types.AttributeValueMemberN{Value: fmt.Sprintf("%d", assignment.Version-1)},
		}
	}

	_, err = d.client.PutItem(ctx, input)
	if err != nil {
		// Check for conditional check failure (version conflict)
		var ccf *types.ConditionalCheckFailedException
		if errors.As(err, &ccf) {
			return NewVersionConflictError(fmt.Sprintf("version conflict for AC %s (expected version %d)", assignment.ACID, assignment.Version-1))
		}
		log.Error("DynamoDB PutItem failed for AC %s: %v", assignment.ACID, err)
		return NewServiceUnavailableError("DynamoDB unavailable", err)
	}

	log.Info("Saved AC assignment %s with %d servers", assignment.ACID, len(assignment.AssignedServers))
	return nil
}

// GetACsByServer retrieves all ACs assigned to a specific server.
// This uses a DynamoDB Scan with client-side filtering because assigned_servers
// is a List of Maps which cannot be indexed with a GSI. The scan is paginated
// to handle tables larger than 1MB.
//
// Performance: O(n) where n is the total number of AC assignments. This is
// acceptable for admin/operational use cases (server failover, load balancing
// dashboards) but should not be used in hot paths. For high-frequency lookups,
// use in-memory tracking on the server side.
func (d *DynamoDBStorage) GetACsByServer(ctx context.Context, serverID string) ([]ACAssignment, error) {
	// Use longer timeout for scan operations (3x normal timeout)
	ctx, cancel := context.WithTimeout(ctx, DynamoDBOperationTimeout*3)
	defer cancel()

	var results []ACAssignment
	var lastEvaluatedKey map[string]types.AttributeValue

	for {
		// Check for context cancellation between pages
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
		}

		input := &dynamodb.ScanInput{
			TableName: aws.String(d.config.ACAssignmentsTable),
		}

		if lastEvaluatedKey != nil {
			input.ExclusiveStartKey = lastEvaluatedKey
		}

		result, err := d.client.Scan(ctx, input)
		if err != nil {
			log.Error("DynamoDB Scan failed for GetACsByServer: %v", err)
			return nil, NewServiceUnavailableError("DynamoDB unavailable", err)
		}

		for _, item := range result.Items {
			var assignment ACAssignment
			if err := attributevalue.UnmarshalMap(item, &assignment); err != nil {
				log.Warning("Failed to unmarshal AC assignment during scan: %v", err)
				continue
			}

			// Client-side filter: check if this AC is assigned to the target server
			for _, server := range assignment.AssignedServers {
				if server.ID == serverID {
					results = append(results, assignment)
					break
				}
			}
		}

		if result.LastEvaluatedKey == nil {
			break
		}
		lastEvaluatedKey = result.LastEvaluatedKey
	}

	return results, nil
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
		// Wrap with metrics, logging, then cache
		metricsWrapped := NewMetricsStorage(backend)
		logged := NewLoggingStorage(metricsWrapped)
		return NewCachedStorage(logged, cfg.Cache), nil

	case "etcd":
		// etcd backend (feature flag for on-prem)
		backend, err := NewEtcdStorage(ctx, cfg.Etcd)
		if err != nil {
			return nil, err
		}
		// Wrap with metrics, logging, then cache
		metricsWrapped := NewMetricsStorage(backend)
		logged := NewLoggingStorage(metricsWrapped)
		return NewCachedStorage(logged, cfg.Cache), nil

	default:
		return nil, fmt.Errorf("unknown storage backend: %s", cfg.Backend)
	}
}
