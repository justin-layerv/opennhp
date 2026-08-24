package server

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

type assignmentAuthorityFake struct {
	mu                 sync.Mutex
	rows               map[string]*ACAssignment
	authoritySnapshots []*ACAssignment
	gets               []*dynamodb.GetItemInput
	puts               []*dynamodb.PutItemInput
	transactions       []*dynamodb.TransactWriteItemsInput
	fencedServers      map[string]bool
	getStarted         chan string
	getRelease         <-chan struct{}
	transactionStarted chan struct{}
	transactionRelease <-chan struct{}
}

func (f *assignmentAuthorityFake) GetItem(
	_ context.Context,
	input *dynamodb.GetItemInput,
	_ ...func(*dynamodb.Options),
) (*dynamodb.GetItemOutput, error) {
	table := aws.ToString(input.TableName)
	if f.getStarted != nil {
		f.getStarted <- table
	}
	if f.getRelease != nil {
		<-f.getRelease
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gets = append(f.gets, input)
	row := f.rows[table]
	if table == "active" && len(f.authoritySnapshots) > 0 {
		row = f.authoritySnapshots[0]
		f.authoritySnapshots = f.authoritySnapshots[1:]
	}
	if row == nil {
		return &dynamodb.GetItemOutput{}, nil
	}
	item, err := attributevalue.MarshalMap(row)
	if err != nil {
		return nil, err
	}
	return &dynamodb.GetItemOutput{Item: item}, nil
}

func (f *assignmentAuthorityFake) PutItem(
	_ context.Context,
	input *dynamodb.PutItemInput,
	_ ...func(*dynamodb.Options),
) (*dynamodb.PutItemOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.puts = append(f.puts, input)
	return &dynamodb.PutItemOutput{}, nil
}

func (f *assignmentAuthorityFake) TransactWriteItems(
	_ context.Context,
	input *dynamodb.TransactWriteItemsInput,
	_ ...func(*dynamodb.Options),
) (*dynamodb.TransactWriteItemsOutput, error) {
	if f.transactionStarted != nil {
		f.transactionStarted <- struct{}{}
	}
	if f.transactionRelease != nil {
		<-f.transactionRelease
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.transactions = append(f.transactions, input)
	reasons := make([]types.CancellationReason, len(input.TransactItems))
	for index, item := range input.TransactItems {
		if item.ConditionCheck != nil {
			key := item.ConditionCheck.Key["ac_id"].(*types.AttributeValueMemberS).Value
			if f.fencedServers[key] {
				reasons[index].Code = aws.String("ConditionalCheckFailed")
				return nil, &types.TransactionCanceledException{
					Message:             aws.String("candidate server is terminating"),
					CancellationReasons: reasons,
				}
			}
			continue
		}
		if item.Put == nil {
			return nil, errors.New("unexpected candidate transaction member")
		}
		f.puts = append(f.puts, &dynamodb.PutItemInput{
			TableName:                 item.Put.TableName,
			Item:                      item.Put.Item,
			ConditionExpression:       item.Put.ConditionExpression,
			ExpressionAttributeNames:  item.Put.ExpressionAttributeNames,
			ExpressionAttributeValues: item.Put.ExpressionAttributeValues,
		})
	}
	return &dynamodb.TransactWriteItemsOutput{}, nil
}

func assignmentAuthorityStorage(fake *assignmentAuthorityFake) *DynamoDBStorage {
	return &DynamoDBStorage{
		assignmentClient: fake,
		config: DynamoDBConfig{
			ACAssignmentsTable:         "candidate",
			ACAssignmentAuthorityTable: "active",
		},
	}
}

func authorityRow(revoked ...string) *ACAssignment {
	return &ACAssignment{
		ACID:            "ac-1",
		ResourceFQDN:    "resource.example",
		CustomerID:      "customer-1",
		AssignedServers: []ServerInfo{{ID: "blue-server", InternalIP: "10.0.0.10"}},
		Version:         91,
		CreatedAt:       100,
		LastSeen:        200,
		RevokedPubKeys:  revoked,
		SessionControlTargets: []ACSessionControlTarget{{
			PublicKey: "blue-target", BootID: "blue-boot", FlushGeneration: 9,
		}},
	}
}

func TestDynamoDBAssignmentAuthorityUnsetPreservesSingleTableReadShape(t *testing.T) {
	fake := &assignmentAuthorityFake{rows: map[string]*ACAssignment{
		"active": {ACID: "ac-1", Version: 3, AssignedServers: []ServerInfo{{ID: "blue"}}},
	}}
	storage := &DynamoDBStorage{
		assignmentClient: fake,
		config:           DynamoDBConfig{ACAssignmentsTable: "active"},
	}
	got, err := storage.GetACAssignment(context.Background(), "ac-1")
	if err != nil || got.Version != 3 {
		t.Fatalf("GetACAssignment() = %#v, %v", got, err)
	}
	if len(fake.gets) != 1 || aws.ToString(fake.gets[0].TableName) != "active" || fake.gets[0].ConsistentRead != nil {
		t.Fatalf("ordinary read shape = %#v, want one existing eventually-consistent table read", fake.gets)
	}
}

func TestDynamoDBAssignmentAuthorityConfigRequiresDistinctRouteTable(t *testing.T) {
	for name, cfg := range map[string]DynamoDBConfig{
		"missing-route": {ACAssignmentAuthorityTable: "active"},
		"same-table":    {ACAssignmentsTable: "active", ACAssignmentAuthorityTable: "active"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateDynamoDBAssignmentAuthorityConfig(cfg); err == nil {
				t.Fatal("configuration accepted an unsafe assignment authority shape")
			}
		})
	}
	if err := validateDynamoDBAssignmentAuthorityConfig(DynamoDBConfig{ACAssignmentsTable: "candidate", ACAssignmentAuthorityTable: "active"}); err != nil {
		t.Fatalf("valid split authority rejected: %v", err)
	}
}

func TestDynamoDBAssignmentAuthoritySynthesizesOnlyIdentityAndRevocationWithoutCandidateRoute(t *testing.T) {
	fake := &assignmentAuthorityFake{rows: map[string]*ACAssignment{"active": authorityRow("revoked-key")}}
	got, err := assignmentAuthorityStorage(fake).GetACAssignment(context.Background(), "ac-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.ACID != "ac-1" || got.ResourceFQDN != "resource.example" || got.CustomerID != "customer-1" {
		t.Fatalf("synthetic identity = %#v", got)
	}
	if len(got.RevokedPubKeys) != 1 || got.RevokedPubKeys[0] != "revoked-key" {
		t.Fatalf("synthetic revocation = %#v", got.RevokedPubKeys)
	}
	if got.Version != 0 || len(got.AssignedServers) != 0 || got.CreatedAt != 0 || got.LastSeen != 0 || got.TTL != nil || len(got.SessionControlTargets) != 0 {
		t.Fatalf("active routing/lifecycle leaked into synthetic candidate row: %#v", got)
	}
	if len(fake.gets) != 2 {
		t.Fatalf("GetItem calls = %#v, want candidate and active", fake.gets)
	}
	tables := map[string]bool{}
	for _, get := range fake.gets {
		tables[aws.ToString(get.TableName)] = true
	}
	if !tables["candidate"] || !tables["active"] {
		t.Fatalf("GetItem tables = %#v, want candidate and active", tables)
	}
	for _, get := range fake.gets {
		if !aws.ToBool(get.ConsistentRead) {
			t.Fatalf("GetItem(%s) was not strongly consistent", aws.ToString(get.TableName))
		}
	}
}

func TestDynamoDBAssignmentAuthorityReadsRouteAndAuthorityConcurrently(t *testing.T) {
	started := make(chan string, 2)
	release := make(chan struct{})
	fake := &assignmentAuthorityFake{
		rows:       map[string]*ACAssignment{"active": authorityRow()},
		getStarted: started,
		getRelease: release,
	}
	result := make(chan error, 1)
	go func() {
		_, err := assignmentAuthorityStorage(fake).GetACAssignment(context.Background(), "ac-1")
		result <- err
	}()

	tables := map[string]bool{}
	for range 2 {
		select {
		case table := <-started:
			tables[table] = true
		case <-time.After(time.Second):
			close(release)
			t.Fatal("candidate and active strong reads were not both in flight")
		}
	}
	if !tables["candidate"] || !tables["active"] {
		close(release)
		t.Fatalf("in-flight GetItem tables = %#v, want candidate and active", tables)
	}
	close(release)
	if err := <-result; err != nil {
		t.Fatalf("GetACAssignment() error = %v", err)
	}
}

func TestDynamoDBAssignmentAuthorityKeepsCandidateRoutingAndMergesOnlyAuthorityFields(t *testing.T) {
	ttl := int64(999)
	candidate := &ACAssignment{
		ACID:            "ac-1",
		ResourceFQDN:    "resource.example",
		CustomerID:      "customer-1",
		AssignedServers: []ServerInfo{{ID: "green-server", InternalIP: "10.1.0.10"}},
		Version:         7,
		CreatedAt:       300,
		LastSeen:        400,
		TTL:             &ttl,
		RevokedPubKeys:  []string{"stale-candidate-key"},
		SessionControlTargets: []ACSessionControlTarget{{
			PublicKey: "green-target", BootID: "green-boot", FlushGeneration: 2,
		}},
	}
	fake := &assignmentAuthorityFake{rows: map[string]*ACAssignment{
		"candidate": candidate,
		"active":    authorityRow("current-active-key"),
	}}
	got, err := assignmentAuthorityStorage(fake).GetACAssignment(context.Background(), "ac-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != 7 || len(got.AssignedServers) != 1 || got.AssignedServers[0].ID != "green-server" || got.CreatedAt != 300 || got.LastSeen != 400 || got.TTL == nil || *got.TTL != ttl {
		t.Fatalf("candidate routing/lifecycle was not preserved: %#v", got)
	}
	if len(got.SessionControlTargets) != 1 || got.SessionControlTargets[0].PublicKey != "green-target" {
		t.Fatalf("active target lifecycle leaked into candidate: %#v", got.SessionControlTargets)
	}
	if len(got.RevokedPubKeys) != 1 || got.RevokedPubKeys[0] != "current-active-key" {
		t.Fatalf("active revocation was not authoritative: %#v", got.RevokedPubKeys)
	}
}

func TestDynamoDBAssignmentAuthorityRejectsMissingMalformedOrConflictingIdentity(t *testing.T) {
	emptyResource := authorityRow()
	emptyResource.ResourceFQDN = ""
	spaceResource := authorityRow()
	spaceResource.ResourceFQDN = " resource.example"
	emptyCustomer := authorityRow()
	emptyCustomer.CustomerID = ""
	spaceCustomer := authorityRow()
	spaceCustomer.CustomerID = "customer-1 "
	cases := map[string]map[string]*ACAssignment{
		"missing-active": {
			"candidate": {ACID: "ac-1", Version: 1},
		},
		"wrong-active-acid": {
			"active": {ACID: "ac-2"},
		},
		"empty-active-resource": {
			"active": emptyResource,
		},
		"whitespace-active-resource": {
			"active": spaceResource,
		},
		"empty-active-customer": {
			"active": emptyCustomer,
		},
		"whitespace-active-customer": {
			"active": spaceCustomer,
		},
		"resource-conflict": {
			"candidate": {ACID: "ac-1", ResourceFQDN: "other.example"},
			"active":    authorityRow(),
		},
		"customer-conflict": {
			"candidate": {ACID: "ac-1", CustomerID: "other-customer"},
			"active":    authorityRow(),
		},
	}
	for name, rows := range cases {
		t.Run(name, func(t *testing.T) {
			fake := &assignmentAuthorityFake{rows: rows}
			got, err := assignmentAuthorityStorage(fake).GetACAssignment(context.Background(), "ac-1")
			if err == nil || got != nil {
				t.Fatalf("GetACAssignment() = %#v, %v; want fail closed", got, err)
			}
			var storageErr *StorageError
			if !errors.As(err, &storageErr) || storageErr.Code != ErrCodeValidationFailed {
				t.Fatalf("error = %T %v, want validation StorageError", err, err)
			}
		})
	}
}

func TestDynamoDBAssignmentAuthorityBypassesCacheAndObservesNewRevocation(t *testing.T) {
	fake := &assignmentAuthorityFake{
		rows: map[string]*ACAssignment{
			"candidate": {ACID: "ac-1", ResourceFQDN: "resource.example", CustomerID: "customer-1", Version: 1},
		},
		authoritySnapshots: []*ACAssignment{authorityRow(), authorityRow("newly-revoked")},
	}
	ddb := assignmentAuthorityStorage(fake)
	productionChain := NewLoggingStorage(NewMetricsStorage(ddb))
	cached := NewCachedStorage(productionChain, CacheConfig{MaxEntries: 8, DefaultTTL: 60})
	first, err := cached.GetACAssignment(context.Background(), "ac-1")
	if err != nil || len(first.RevokedPubKeys) != 0 {
		t.Fatalf("first read = %#v, %v", first, err)
	}
	second, err := cached.GetACAssignment(context.Background(), "ac-1")
	if err != nil || len(second.RevokedPubKeys) != 1 || second.RevokedPubKeys[0] != "newly-revoked" {
		t.Fatalf("second read did not observe active revocation = %#v, %v", second, err)
	}
	if len(fake.gets) != 4 {
		t.Fatalf("GetItem calls = %d, want two fresh candidate+authority pairs", len(fake.gets))
	}
}

type opaqueAssignmentAuthorityWrapper struct {
	StorageBackend
}

func TestDynamoDBAssignmentAuthorityUnknownWrapperChainBypassesCache(t *testing.T) {
	ddb := assignmentAuthorityStorage(&assignmentAuthorityFake{rows: map[string]*ACAssignment{
		"active": authorityRow(),
	}})
	// This deliberately models a future decorator that embeds the backend but
	// forgets to expose Backend(). The cache cannot prove that external active
	// revocation authority is absent, so it must fail closed into bypass mode.
	opaque := &opaqueAssignmentAuthorityWrapper{StorageBackend: ddb}
	cached := NewCachedStorage(NewLoggingStorage(opaque), CacheConfig{MaxEntries: 8, DefaultTTL: 60})
	if !cached.bypassACAssignmentCache {
		t.Fatal("opaque assignment-authority wrapper chain enabled the assignment cache")
	}
}

func TestDynamoDBAssignmentAuthorityRevocationAddedDuringCandidatePrepRejectsAdmission(t *testing.T) {
	pubkey := testPubkeyB64(0x42)
	fake := &assignmentAuthorityFake{
		rows: map[string]*ACAssignment{
			"candidate": {ACID: "ac-1", ResourceFQDN: "resource.example", CustomerID: "customer-1", Version: 1},
		},
		authoritySnapshots: []*ACAssignment{authorityRow(), authorityRow(pubkey)},
	}
	cached := NewCachedStorage(assignmentAuthorityStorage(fake), CacheConfig{MaxEntries: 8, DefaultTTL: 60})
	if _, err := cached.GetACAssignment(context.Background(), "ac-1"); err != nil {
		t.Fatalf("candidate preparation read failed: %v", err)
	}

	srv := newTestServerForLicenseGate(t, NewMemoryStorage())
	srv.storage = cached
	verdict := srv.evaluateACPubkeyRevokeVerdict(
		context.Background(), "ac-1", pubkey, 7, "10.0.0.7:62206",
	)
	if verdict != verdictACPubkeyRevokeRevoked {
		t.Fatalf("admission verdict = %v, want freshly observed active revocation", verdict)
	}
	if len(fake.gets) != 4 {
		t.Fatalf("GetItem calls = %d, want preparation and admission to each strongly read candidate+active", len(fake.gets))
	}
}

func TestDynamoDBAssignmentAuthorityCandidateSaveCannotWriteActiveOrPersistRevocationSnapshot(t *testing.T) {
	fake := &assignmentAuthorityFake{rows: map[string]*ACAssignment{"active": authorityRow("revoked-key")}}
	storage := assignmentAuthorityStorage(fake)
	input := &ACAssignment{
		ACID:            "ac-1",
		ResourceFQDN:    "resource.example",
		CustomerID:      "customer-1",
		AssignedServers: []ServerInfo{{ID: "green-server"}},
		Version:         1,
		RevokedPubKeys:  []string{"stale-copy"},
	}
	if err := storage.SaveACAssignment(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	if len(fake.puts) != 1 || aws.ToString(fake.puts[0].TableName) != "candidate" {
		t.Fatalf("PutItem calls = %#v, want candidate only", fake.puts)
	}
	if len(fake.transactions) != 1 || len(fake.transactions[0].TransactItems) != 2 ||
		fake.transactions[0].TransactItems[0].ConditionCheck == nil ||
		fake.transactions[0].TransactItems[1].Put == nil {
		t.Fatalf("candidate transaction = %#v, want one server-fence condition then assignment put", fake.transactions)
	}
	fenceKey := fake.transactions[0].TransactItems[0].ConditionCheck.Key["ac_id"].(*types.AttributeValueMemberS).Value
	if fenceKey != candidateServerTerminationFencePrefix+"green-server" ||
		aws.ToString(fake.transactions[0].TransactItems[0].ConditionCheck.ConditionExpression) != "attribute_not_exists(ac_id)" {
		t.Fatalf("candidate fence condition = %#v", fake.transactions[0].TransactItems[0].ConditionCheck)
	}
	if _, present := fake.puts[0].Item["revoked_pubkeys"]; present {
		t.Fatalf("candidate row persisted a revocation snapshot: %#v", fake.puts[0].Item["revoked_pubkeys"])
	}
	var persisted ACAssignment
	if err := attributevalue.UnmarshalMap(fake.puts[0].Item, &persisted); err != nil {
		t.Fatal(err)
	}
	if persisted.AssignedServers[0].ID != "green-server" || persisted.CustomerID != "customer-1" || persisted.ResourceFQDN != "resource.example" {
		t.Fatalf("persisted candidate row = %#v", persisted)
	}
	if len(input.RevokedPubKeys) != 1 || input.RevokedPubKeys[0] != "stale-copy" {
		t.Fatalf("SaveACAssignment mutated caller input: %#v", input)
	}
}

func TestDynamoDBAssignmentAuthorityCandidateSaveRejectsTerminatingServerBeforePut(t *testing.T) {
	fake := &assignmentAuthorityFake{
		rows:          map[string]*ACAssignment{"active": authorityRow()},
		fencedServers: map[string]bool{candidateServerTerminationFencePrefix + "green-server": true},
	}
	err := assignmentAuthorityStorage(fake).SaveACAssignment(context.Background(), &ACAssignment{
		ACID:            "ac-1",
		ResourceFQDN:    "resource.example",
		CustomerID:      "customer-1",
		AssignedServers: []ServerInfo{{ID: "green-server"}},
		Version:         1,
	})
	if err == nil || len(fake.transactions) != 1 || len(fake.puts) != 0 {
		t.Fatalf("SaveACAssignment() error=%v transactions=%d puts=%d, want fenced rejection", err, len(fake.transactions), len(fake.puts))
	}
	var storageErr *StorageError
	if !errors.As(err, &storageErr) || storageErr.Code != ErrCodeValidationFailed {
		t.Fatalf("SaveACAssignment() error=%T %v, want validation authority failure", err, err)
	}
}

func TestDynamoDBAssignmentAuthorityTerminationFenceLinearizesAfterAuthorityReadBeforePut(t *testing.T) {
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	fake := &assignmentAuthorityFake{
		rows:               map[string]*ACAssignment{"active": authorityRow()},
		fencedServers:      map[string]bool{},
		transactionStarted: started,
		transactionRelease: release,
	}
	result := make(chan error, 1)
	go func() {
		result <- assignmentAuthorityStorage(fake).SaveACAssignment(context.Background(), &ACAssignment{
			ACID:            "ac-1",
			ResourceFQDN:    "resource.example",
			CustomerID:      "customer-1",
			AssignedServers: []ServerInfo{{ID: "green-server"}},
			Version:         1,
		})
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		close(release)
		t.Fatal("candidate assignment transaction did not reach the fence barrier")
	}
	fake.mu.Lock()
	fake.fencedServers[candidateServerTerminationFencePrefix+"green-server"] = true
	fake.mu.Unlock()
	close(release)
	err := <-result
	if err == nil || len(fake.transactions) != 1 || len(fake.puts) != 0 {
		t.Fatalf("SaveACAssignment() error=%v transactions=%d puts=%d, want late-fence rejection", err, len(fake.transactions), len(fake.puts))
	}
	var storageErr *StorageError
	if !errors.As(err, &storageErr) || storageErr.Code != ErrCodeValidationFailed {
		t.Fatalf("SaveACAssignment() error=%T %v, want validation authority failure", err, err)
	}
}

func TestDynamoDBAssignmentAuthorityCandidateSaveRejectsIdentityDriftBeforePut(t *testing.T) {
	fake := &assignmentAuthorityFake{rows: map[string]*ACAssignment{"active": authorityRow()}}
	err := assignmentAuthorityStorage(fake).SaveACAssignment(context.Background(), &ACAssignment{
		ACID:         "ac-1",
		CustomerID:   "attacker",
		ResourceFQDN: "resource.example",
		Version:      1,
	})
	if err == nil || len(fake.puts) != 0 {
		t.Fatalf("SaveACAssignment() error=%v puts=%d, want rejection before write", err, len(fake.puts))
	}
}

// Compile-time check that the fake covers the exact assignment API surface.
var _ dynamoAssignmentClient = (*assignmentAuthorityFake)(nil)
