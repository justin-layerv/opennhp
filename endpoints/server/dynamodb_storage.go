package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
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

	// healthCheckSentinelKey is the well-known key used for DynamoDB health checks.
	// GetItem on this non-existent key returns an empty result (not an error),
	// confirming connectivity and table access with only dynamodb:GetItem permission.
	healthCheckSentinelKey = "__healthcheck__"

	// candidateServerTerminationFencePrefix reserves non-assignment rows in
	// the isolated candidate table. Every candidate assignment write checks
	// the exact fence for each selected physical server in the same DynamoDB
	// transaction, so cleanup can linearize before its strong scan.
	candidateServerTerminationFencePrefix = "__server_termination__#"
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
	client           *dynamodb.Client
	assignmentClient dynamoAssignmentClient
	config           DynamoDBConfig
}

type dynamoAssignmentClient interface {
	GetItem(context.Context, *dynamodb.GetItemInput, ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error)
	PutItem(context.Context, *dynamodb.PutItemInput, ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error)
	TransactWriteItems(context.Context, *dynamodb.TransactWriteItemsInput, ...func(*dynamodb.Options)) (*dynamodb.TransactWriteItemsOutput, error)
}

func (d *DynamoDBStorage) assignmentAPI() dynamoAssignmentClient {
	if d.assignmentClient != nil {
		return d.assignmentClient
	}
	return d.client
}

// NewDynamoDBStorage creates a new DynamoDB storage backend.
func NewDynamoDBStorage(ctx context.Context, cfg DynamoDBConfig) (*DynamoDBStorage, error) {
	if err := validateDynamoDBAssignmentAuthorityConfig(cfg); err != nil {
		return nil, err
	}
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
	if cfg.ACAssignmentAuthorityTable != "" {
		log.Info("DynamoDB candidate assignment routing uses external active authority table=%s", cfg.ACAssignmentAuthorityTable)
	}

	return storage, nil
}

func validateDynamoDBAssignmentAuthorityConfig(cfg DynamoDBConfig) error {
	if cfg.ACAssignmentAuthorityTable == "" {
		return nil
	}
	if cfg.ACAssignmentsTable == "" {
		return errors.New("ACAssignmentAuthorityTable requires ACAssignmentsTable")
	}
	if cfg.ACAssignmentAuthorityTable == cfg.ACAssignmentsTable {
		return errors.New("ACAssignmentAuthorityTable must be distinct from ACAssignmentsTable")
	}
	return nil
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
	if d.config.ACAssignmentAuthorityTable == "" {
		return d.getACAssignmentFromTable(ctx, d.config.ACAssignmentsTable, acID, false)
	}

	// Candidate routing and active revocation authority are independent rows.
	// Read them concurrently under one aggregate deadline: adding the active
	// authority boundary must not add a second full DynamoDB round trip to the
	// healthy AOL path.
	type assignmentRead struct {
		authority  bool
		assignment *ACAssignment
		err        error
	}
	reads := make(chan assignmentRead, 2)
	go func() {
		assignment, err := d.getACAssignmentFromTable(ctx, d.config.ACAssignmentsTable, acID, true)
		reads <- assignmentRead{assignment: assignment, err: err}
	}()
	go func() {
		assignment, err := d.getACAssignmentFromTable(ctx, d.config.ACAssignmentAuthorityTable, acID, true)
		reads <- assignmentRead{authority: true, assignment: assignment, err: err}
	}()
	var route, authority *ACAssignment
	var routeErr, authorityErr error
	for range 2 {
		read := <-reads
		if read.authority {
			authority, authorityErr = read.assignment, read.err
		} else {
			route, routeErr = read.assignment, read.err
		}
	}
	if routeErr != nil && !IsNotFoundError(routeErr) {
		return nil, NewACAssignmentAuthorityError(routeErr)
	}
	if authorityErr != nil {
		if IsNotFoundError(authorityErr) {
			authorityErr = &StorageError{Code: ErrCodeValidationFailed, Message: "active AC assignment authority is missing", Err: authorityErr}
		}
		return nil, NewACAssignmentAuthorityError(authorityErr)
	}
	if route == nil || IsNotFoundError(routeErr) {
		route = &ACAssignment{ACID: acID}
	}
	if err := mergeACAssignmentAuthority(route, authority, acID); err != nil {
		return nil, NewACAssignmentAuthorityError(err)
	}
	return route, nil
}

func (d *DynamoDBStorage) getACAssignmentFromTable(
	ctx context.Context,
	table string,
	acID string,
	consistent bool,
) (*ACAssignment, error) {
	if d.assignmentAPI() == nil {
		return nil, NewServiceUnavailableError("DynamoDB unavailable", errors.New("DynamoDB client not initialized"))
	}

	input := &dynamodb.GetItemInput{
		TableName: aws.String(table),
		Key: map[string]types.AttributeValue{
			"ac_id": &types.AttributeValueMemberS{Value: acID},
		},
	}
	if consistent {
		input.ConsistentRead = aws.Bool(true)
	}
	result, err := d.assignmentAPI().GetItem(ctx, input)
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

func mergeACAssignmentAuthority(route, authority *ACAssignment, acID string) error {
	if route == nil || authority == nil || acID == "" || strings.TrimSpace(acID) != acID ||
		route.ACID != acID || authority.ACID != acID ||
		authority.ResourceFQDN == "" || strings.TrimSpace(authority.ResourceFQDN) != authority.ResourceFQDN ||
		authority.CustomerID == "" || strings.TrimSpace(authority.CustomerID) != authority.CustomerID {
		return &StorageError{Code: ErrCodeValidationFailed, Message: "AC assignment authority identity is malformed"}
	}
	if route.ResourceFQDN != "" && route.ResourceFQDN != authority.ResourceFQDN {
		return &StorageError{Code: ErrCodeValidationFailed, Message: "candidate AC assignment resource identity conflicts with active authority"}
	}
	if route.CustomerID != "" && route.CustomerID != authority.CustomerID {
		return &StorageError{Code: ErrCodeValidationFailed, Message: "candidate AC assignment customer identity conflicts with active authority"}
	}
	route.ResourceFQDN = authority.ResourceFQDN
	route.CustomerID = authority.CustomerID
	route.RevokedPubKeys = append([]string(nil), authority.RevokedPubKeys...)
	return nil
}

func candidateServerTerminationFenceKey(serverID string) (string, error) {
	if serverID == "" || strings.TrimSpace(serverID) != serverID || strings.HasPrefix(serverID, candidateServerTerminationFencePrefix) {
		return "", &StorageError{Code: ErrCodeValidationFailed, Message: "candidate assignment server identity is malformed"}
	}
	return candidateServerTerminationFencePrefix + serverID, nil
}

func candidateAssignmentTransaction(
	table string,
	assignment *ACAssignment,
	put *dynamodb.PutItemInput,
) ([]types.TransactWriteItem, error) {
	if assignment == nil || assignment.ACID == "" || strings.HasPrefix(assignment.ACID, candidateServerTerminationFencePrefix) {
		return nil, &StorageError{Code: ErrCodeValidationFailed, Message: "candidate assignment identity is malformed"}
	}
	serverIDs := make([]string, 0, len(assignment.AssignedServers))
	seen := make(map[string]struct{}, len(assignment.AssignedServers))
	for _, server := range assignment.AssignedServers {
		key, err := candidateServerTerminationFenceKey(server.ID)
		if err != nil {
			return nil, err
		}
		if _, duplicate := seen[key]; duplicate {
			return nil, &StorageError{Code: ErrCodeValidationFailed, Message: "candidate assignment contains duplicate server identities"}
		}
		seen[key] = struct{}{}
		serverIDs = append(serverIDs, key)
	}
	if len(serverIDs) > MaxServersPerAssignment {
		return nil, &StorageError{Code: ErrCodeValidationFailed, Message: "candidate assignment exceeds the server ceiling"}
	}
	sort.Strings(serverIDs)
	items := make([]types.TransactWriteItem, 0, len(serverIDs)+1)
	for _, key := range serverIDs {
		items = append(items, types.TransactWriteItem{ConditionCheck: &types.ConditionCheck{
			TableName: aws.String(table),
			Key: map[string]types.AttributeValue{
				"ac_id": &types.AttributeValueMemberS{Value: key},
			},
			ConditionExpression: aws.String("attribute_not_exists(ac_id)"),
		}})
	}
	items = append(items, types.TransactWriteItem{Put: &types.Put{
		TableName:                 put.TableName,
		Item:                      put.Item,
		ConditionExpression:       put.ConditionExpression,
		ExpressionAttributeNames:  put.ExpressionAttributeNames,
		ExpressionAttributeValues: put.ExpressionAttributeValues,
	}})
	return items, nil
}

// SaveACAssignment stores or updates an AC assignment.
func (d *DynamoDBStorage) SaveACAssignment(ctx context.Context, assignment *ACAssignment) error {
	ctx, cancel := context.WithTimeout(ctx, DynamoDBOperationTimeout)
	defer cancel()
	toSave := assignment
	if d.config.ACAssignmentAuthorityTable != "" {
		authority, err := d.getACAssignmentFromTable(ctx, d.config.ACAssignmentAuthorityTable, assignment.ACID, true)
		if err != nil {
			return NewACAssignmentAuthorityError(err)
		}
		toSave = assignment.Clone()
		if err := mergeACAssignmentAuthority(toSave, authority, assignment.ACID); err != nil {
			return NewACAssignmentAuthorityError(err)
		}
		// The active table is the sole revocation authority. Candidate routing
		// rows deliberately never persist a snapshot that could later be read as
		// an independent or stale denylist.
		toSave.RevokedPubKeys = nil
	}

	item, err := attributevalue.MarshalMap(toSave)
	if err != nil {
		log.Error("Failed to marshal AC assignment %s: %v", toSave.ACID, err)
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

	if d.config.ACAssignmentAuthorityTable != "" {
		items, transactionErr := candidateAssignmentTransaction(d.config.ACAssignmentsTable, toSave, input)
		if transactionErr != nil {
			return NewACAssignmentAuthorityError(transactionErr)
		}
		_, err = d.assignmentAPI().TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: items})
		if err != nil {
			var canceled *types.TransactionCanceledException
			if errors.As(err, &canceled) && len(canceled.CancellationReasons) == len(items) {
				for index := range len(items) - 1 {
					if aws.ToString(canceled.CancellationReasons[index].Code) == "ConditionalCheckFailed" {
						return NewACAssignmentAuthorityError(&StorageError{
							Code: ErrCodeValidationFailed, Message: "candidate assignment selected a terminating server",
						})
					}
				}
				if aws.ToString(canceled.CancellationReasons[len(items)-1].Code) == "ConditionalCheckFailed" {
					return NewACAssignmentAuthorityError(NewVersionConflictError(
						fmt.Sprintf("version conflict for AC %s (expected version %d)", assignment.ACID, assignment.Version-1),
					))
				}
			}
			log.Error("DynamoDB candidate assignment transaction failed for AC %s: %v", assignment.ACID, err)
			return NewACAssignmentAuthorityError(NewServiceUnavailableError("DynamoDB unavailable", err))
		}
		log.Info("Saved candidate AC assignment %s with %d servers behind termination fences", toSave.ACID, len(toSave.AssignedServers))
		return nil
	}

	_, err = d.assignmentAPI().PutItem(ctx, input)
	if err != nil {
		// Check for conditional check failure (version conflict)
		var ccf *types.ConditionalCheckFailedException
		if errors.As(err, &ccf) {
			conflict := NewVersionConflictError(fmt.Sprintf("version conflict for AC %s (expected version %d)", assignment.ACID, assignment.Version-1))
			if d.config.ACAssignmentAuthorityTable != "" {
				return NewACAssignmentAuthorityError(conflict)
			}
			return conflict
		}
		log.Error("DynamoDB PutItem failed for AC %s: %v", assignment.ACID, err)
		unavailable := NewServiceUnavailableError("DynamoDB unavailable", err)
		if d.config.ACAssignmentAuthorityTable != "" {
			return NewACAssignmentAuthorityError(unavailable)
		}
		return unavailable
	}

	log.Info("Saved AC assignment %s with %d servers", toSave.ACID, len(toSave.AssignedServers))
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
