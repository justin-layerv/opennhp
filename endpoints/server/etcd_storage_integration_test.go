//go:build integration

package server

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
	clientv3 "go.etcd.io/etcd/client/v3"
)

// ============================================================================
// etcd Storage Integration Tests
//
// These tests require a running etcd instance. Run with:
//   go test -tags=integration -v ./server -run TestEtcdStorageIntegration
//
// Start etcd locally:
//   docker run -d --name etcd -p 2379:2379 \
//     quay.io/coreos/etcd:v3.5.9 \
//     /usr/local/bin/etcd --advertise-client-urls http://0.0.0.0:2379 \
//     --listen-client-urls http://0.0.0.0:2379
// ============================================================================

func getEtcdEndpoint() string {
	if ep := os.Getenv("ETCD_ENDPOINT"); ep != "" {
		return ep
	}
	return "localhost:2379"
}

func skipIfNoEtcd(t *testing.T) {
	endpoint := getEtcdEndpoint()
	client, err := clientv3.New(clientv3.Config{
		Endpoints:   []string{endpoint},
		DialTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Skipf("Skipping: cannot connect to etcd at %s: %v", endpoint, err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err = client.Status(ctx, endpoint)
	if err != nil {
		t.Skipf("Skipping: etcd not available at %s: %v", endpoint, err)
	}
}

func setupTestData(t *testing.T, client *clientv3.Client) {
	ctx := context.Background()

	// Create test AC assignment
	assignment := &ACAssignment{
		ACID:         "ac-integration-test",
		ResourceFQDN: "test.nhp.example.com",
		CustomerID:   "cust-integration",
		AssignedServers: []ServerInfo{
			{ID: "srv-1", IP: "10.0.0.1", Port: common.DefaultNHPPort, PubKey: "key1"},
			{ID: "srv-2", IP: "10.0.0.2", Port: common.DefaultNHPPort, PubKey: "key2"},
		},
		Version:   1,
		CreatedAt: time.Now().Unix(),
	}
	assignmentJSON, _ := json.Marshal(assignment)
	_, err := client.Put(ctx, "/nhp/ac-assignments/ac-integration-test", string(assignmentJSON))
	if err != nil {
		t.Fatalf("Failed to seed AC assignment: %v", err)
	}

	// Create test license
	license := &License{
		CustomerID:     "cust-integration",
		ResourceFQDN:   "test.nhp.example.com",
		LicenseKeyHash: "$2a$10$testhash",
		Tier:           "pro",
		MaxACs:         100,
		ExpiresAt:      time.Now().Add(365 * 24 * time.Hour).Unix(),
		Active:         true,
	}
	licenseJSON, _ := json.Marshal(license)
	_, err = client.Put(ctx, "/nhp/licenses/cust-integration/test.nhp.example.com", string(licenseJSON))
	if err != nil {
		t.Fatalf("Failed to seed license: %v", err)
	}

	// Create test resource
	resource := &Resource{
		CustomerID:    "cust-integration",
		ResourceID:    "res-integration",
		ResourceFQDN:  "test.nhp.example.com",
		ACID:          "ac-integration-test",
		DestHost:      "backend.local",
		DestPort:      443,
		OpenTime:      60,
		AuthServiceID: "passcode",
	}
	resourceJSON, _ := json.Marshal(resource)
	_, err = client.Put(ctx, "/nhp/resources/cust-integration/res-integration", string(resourceJSON))
	if err != nil {
		t.Fatalf("Failed to seed resource: %v", err)
	}

	// Create secondary index for resource by AC
	_, err = client.Put(ctx, "/nhp/resources-by-ac/ac-integration-test/res-integration", string(resourceJSON))
	if err != nil {
		t.Fatalf("Failed to seed resource-by-ac index: %v", err)
	}
}

func cleanupTestData(t *testing.T, client *clientv3.Client) {
	ctx := context.Background()
	client.Delete(ctx, "/nhp/ac-assignments/ac-integration-test")
	client.Delete(ctx, "/nhp/licenses/cust-integration/test.nhp.example.com")
	client.Delete(ctx, "/nhp/resources/cust-integration/res-integration")
	client.Delete(ctx, "/nhp/resources-by-ac/ac-integration-test/res-integration")
}

func TestEtcdStorageIntegration_GetACAssignment(t *testing.T) {
	skipIfNoEtcd(t)

	endpoint := getEtcdEndpoint()
	client, _ := clientv3.New(clientv3.Config{
		Endpoints:   []string{endpoint},
		DialTimeout: 5 * time.Second,
	})
	defer client.Close()

	setupTestData(t, client)
	defer cleanupTestData(t, client)

	// Create storage backend
	storage, err := NewEtcdStorage(context.Background(), EtcdStorageConfig{
		Endpoints: []string{endpoint},
	})
	if err != nil {
		t.Fatalf("Failed to create EtcdStorage: %v", err)
	}
	defer storage.Close()

	// Test GetACAssignment
	assignment, err := storage.GetACAssignment(context.Background(), "ac-integration-test")
	if err != nil {
		t.Fatalf("GetACAssignment failed: %v", err)
	}

	if assignment.ACID != "ac-integration-test" {
		t.Errorf("Expected ACID 'ac-integration-test', got '%s'", assignment.ACID)
	}
	if assignment.CustomerID != "cust-integration" {
		t.Errorf("Expected CustomerID 'cust-integration', got '%s'", assignment.CustomerID)
	}
	if len(assignment.AssignedServers) != 2 {
		t.Errorf("Expected 2 assigned servers, got %d", len(assignment.AssignedServers))
	}
}

func TestEtcdStorageIntegration_GetACAssignment_NotFound(t *testing.T) {
	skipIfNoEtcd(t)

	endpoint := getEtcdEndpoint()
	storage, err := NewEtcdStorage(context.Background(), EtcdStorageConfig{
		Endpoints: []string{endpoint},
	})
	if err != nil {
		t.Fatalf("Failed to create EtcdStorage: %v", err)
	}
	defer storage.Close()

	_, err = storage.GetACAssignment(context.Background(), "non-existent-ac")
	if err == nil {
		t.Fatal("Expected error for non-existent AC")
	}
	if !IsNotFoundError(err) {
		t.Errorf("Expected NotFoundError, got %T: %v", err, err)
	}
}

func TestEtcdStorageIntegration_GetLicense(t *testing.T) {
	skipIfNoEtcd(t)

	endpoint := getEtcdEndpoint()
	client, _ := clientv3.New(clientv3.Config{
		Endpoints:   []string{endpoint},
		DialTimeout: 5 * time.Second,
	})
	defer client.Close()

	setupTestData(t, client)
	defer cleanupTestData(t, client)

	storage, err := NewEtcdStorage(context.Background(), EtcdStorageConfig{
		Endpoints: []string{endpoint},
	})
	if err != nil {
		t.Fatalf("Failed to create EtcdStorage: %v", err)
	}
	defer storage.Close()

	license, err := storage.GetLicense(context.Background(), "cust-integration", "test.nhp.example.com")
	if err != nil {
		t.Fatalf("GetLicense failed: %v", err)
	}

	if license.CustomerID != "cust-integration" {
		t.Errorf("Expected CustomerID 'cust-integration', got '%s'", license.CustomerID)
	}
	if license.Tier != "pro" {
		t.Errorf("Expected Tier 'pro', got '%s'", license.Tier)
	}
	if !license.Active {
		t.Error("Expected license to be active")
	}
}

func TestEtcdStorageIntegration_GetResource(t *testing.T) {
	skipIfNoEtcd(t)

	endpoint := getEtcdEndpoint()
	client, _ := clientv3.New(clientv3.Config{
		Endpoints:   []string{endpoint},
		DialTimeout: 5 * time.Second,
	})
	defer client.Close()

	setupTestData(t, client)
	defer cleanupTestData(t, client)

	storage, err := NewEtcdStorage(context.Background(), EtcdStorageConfig{
		Endpoints: []string{endpoint},
	})
	if err != nil {
		t.Fatalf("Failed to create EtcdStorage: %v", err)
	}
	defer storage.Close()

	resource, err := storage.GetResource(context.Background(), "cust-integration", "res-integration")
	if err != nil {
		t.Fatalf("GetResource failed: %v", err)
	}

	if resource.ResourceID != "res-integration" {
		t.Errorf("Expected ResourceID 'res-integration', got '%s'", resource.ResourceID)
	}
	if resource.DestPort != 443 {
		t.Errorf("Expected DestPort 443, got %d", resource.DestPort)
	}
}

func TestEtcdStorageIntegration_GetResourceByACID(t *testing.T) {
	skipIfNoEtcd(t)

	endpoint := getEtcdEndpoint()
	client, _ := clientv3.New(clientv3.Config{
		Endpoints:   []string{endpoint},
		DialTimeout: 5 * time.Second,
	})
	defer client.Close()

	setupTestData(t, client)
	defer cleanupTestData(t, client)

	storage, err := NewEtcdStorage(context.Background(), EtcdStorageConfig{
		Endpoints: []string{endpoint},
	})
	if err != nil {
		t.Fatalf("Failed to create EtcdStorage: %v", err)
	}
	defer storage.Close()

	resources, err := storage.GetResourceByACID(context.Background(), "ac-integration-test")
	if err != nil {
		t.Fatalf("GetResourceByACID failed: %v", err)
	}

	if len(resources) != 1 {
		t.Fatalf("Expected 1 resource, got %d", len(resources))
	}
	if resources[0].ACID != "ac-integration-test" {
		t.Errorf("Expected ACID 'ac-integration-test', got '%s'", resources[0].ACID)
	}
}

func TestEtcdStorageIntegration_GetACsByServer(t *testing.T) {
	skipIfNoEtcd(t)

	endpoint := getEtcdEndpoint()
	client, _ := clientv3.New(clientv3.Config{
		Endpoints:   []string{endpoint},
		DialTimeout: 5 * time.Second,
	})
	defer client.Close()

	setupTestData(t, client)
	defer cleanupTestData(t, client)

	storage, err := NewEtcdStorage(context.Background(), EtcdStorageConfig{
		Endpoints: []string{endpoint},
	})
	if err != nil {
		t.Fatalf("Failed to create EtcdStorage: %v", err)
	}
	defer storage.Close()

	// srv-1 is in the test assignment
	assignments, err := storage.GetACsByServer(context.Background(), "srv-1")
	if err != nil {
		t.Fatalf("GetACsByServer failed: %v", err)
	}

	if len(assignments) != 1 {
		t.Fatalf("Expected 1 assignment for srv-1, got %d", len(assignments))
	}
	if assignments[0].ACID != "ac-integration-test" {
		t.Errorf("Expected ACID 'ac-integration-test', got '%s'", assignments[0].ACID)
	}

	// Non-existent server should return empty slice
	assignments, err = storage.GetACsByServer(context.Background(), "srv-nonexistent")
	if err != nil {
		t.Fatalf("GetACsByServer for non-existent server failed: %v", err)
	}
	if len(assignments) != 0 {
		t.Errorf("Expected 0 assignments for non-existent server, got %d", len(assignments))
	}
}

func TestEtcdStorageIntegration_CachedStorage(t *testing.T) {
	skipIfNoEtcd(t)

	endpoint := getEtcdEndpoint()
	client, _ := clientv3.New(clientv3.Config{
		Endpoints:   []string{endpoint},
		DialTimeout: 5 * time.Second,
	})
	defer client.Close()

	setupTestData(t, client)
	defer cleanupTestData(t, client)

	// Create cached storage with etcd backend
	backend, err := NewEtcdStorage(context.Background(), EtcdStorageConfig{
		Endpoints: []string{endpoint},
	})
	if err != nil {
		t.Fatalf("Failed to create EtcdStorage: %v", err)
	}

	cached := NewCachedStorage(backend, CacheConfig{
		MaxEntries:         100,
		DefaultTTL:         60,
		ReassignmentTTL:    5,
		ReassignmentWindow: 300,
	})
	defer cached.Close()

	ctx := context.Background()

	// First call - cache miss
	assignment1, err := cached.GetACAssignment(ctx, "ac-integration-test")
	if err != nil {
		t.Fatalf("First GetACAssignment failed: %v", err)
	}

	// Second call - should be cache hit (we can't easily verify this without metrics)
	assignment2, err := cached.GetACAssignment(ctx, "ac-integration-test")
	if err != nil {
		t.Fatalf("Second GetACAssignment failed: %v", err)
	}

	// Results should be identical
	if assignment1.ACID != assignment2.ACID {
		t.Errorf("Cache returned different ACID: %s vs %s", assignment1.ACID, assignment2.ACID)
	}

	// Invalidate and verify re-fetch
	cached.InvalidateACAssignment("ac-integration-test")
	assignment3, err := cached.GetACAssignment(ctx, "ac-integration-test")
	if err != nil {
		t.Fatalf("Third GetACAssignment failed: %v", err)
	}
	if assignment3.ACID != "ac-integration-test" {
		t.Errorf("Expected ACID after invalidation, got '%s'", assignment3.ACID)
	}
}
