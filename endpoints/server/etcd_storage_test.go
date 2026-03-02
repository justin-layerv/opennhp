package server

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
)

// ============================================================================
// EtcdStorage Unit Tests
//
// These tests verify the etcd storage backend implementation.
// Tests that require a live etcd instance are tagged with 'integration'.
// ============================================================================

// TestEtcdStorage_KeyFormats verifies the key format functions
func TestEtcdStorage_KeyFormats(t *testing.T) {
	tests := []struct {
		name     string
		testFunc func() string
		expected string
	}{
		{
			name:     "AC assignment key",
			testFunc: func() string { return acAssignmentKey("ac-123") },
			expected: "/nhp/ac-assignments/ac-123",
		},
		{
			name:     "License key with SHA256",
			testFunc: func() string { return licenseEtcdKey("abc123sha256hash") },
			expected: "/nhp/licenses/abc123sha256hash",
		},
		{
			name:     "Resource key",
			testFunc: func() string { return resourceKey("cust-789", "res-abc") },
			expected: "/nhp/resources/cust-789/res-abc",
		},
		{
			name:     "Resource by AC prefix",
			testFunc: func() string { return resourceByACPrefix("ac-xyz") },
			expected: "/nhp/resources-by-ac/ac-xyz/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.testFunc()
			if got != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, got)
			}
		})
	}
}

// TestEtcdStorage_Name verifies the backend name
func TestEtcdStorage_Name(t *testing.T) {
	// Create a storage instance without connecting (just to test Name())
	storage := &EtcdStorage{
		config: EtcdStorageConfig{
			Endpoints: []string{"localhost:2379"},
		},
	}

	if storage.Name() != "etcd" {
		t.Errorf("Expected name 'etcd', got '%s'", storage.Name())
	}
}

// TestEtcdStorage_Close verifies close handles nil connection
func TestEtcdStorage_Close(t *testing.T) {
	// Create a storage instance with nil connection
	storage := &EtcdStorage{
		conn: nil,
		config: EtcdStorageConfig{
			Endpoints: []string{"localhost:2379"},
		},
	}

	// Should not panic
	err := storage.Close()
	if err != nil {
		t.Errorf("Expected nil error on Close with nil conn, got %v", err)
	}
}

// TestNewEtcdStorage_MissingEndpoints verifies error on missing endpoints
func TestNewEtcdStorage_MissingEndpoints(t *testing.T) {
	_, err := NewEtcdStorage(context.Background(), EtcdStorageConfig{
		Endpoints: []string{},
	})

	if err == nil {
		t.Error("Expected error for missing endpoints")
	}

	expectedMsg := "etcd endpoints are required"
	if err.Error() != expectedMsg {
		t.Errorf("Expected error message %q, got %q", expectedMsg, err.Error())
	}
}

// TestEtcdStorage_JSONSerialization verifies data types serialize correctly
func TestEtcdStorage_JSONSerialization(t *testing.T) {
	t.Run("ACAssignment", func(t *testing.T) {
		now := time.Now().Unix()
		assignment := &ACAssignment{
			ACID:         "ac-test-1",
			ResourceFQDN: "test.nhp.example.com",
			CustomerID:   "cust-123",
			AssignedServers: []ServerInfo{
				{ID: "srv-1", IP: "10.0.0.1", InternalIP: "192.168.1.1", AZ: "us-east-1a", Port: common.DefaultNHPPort, PubKey: "key1"},
				{ID: "srv-2", IP: "10.0.0.2", InternalIP: "192.168.1.2", AZ: "us-east-1b", Port: common.DefaultNHPPort, PubKey: "key2"},
				{ID: "srv-3", IP: "10.0.0.3", InternalIP: "192.168.1.3", AZ: "us-east-1c", Port: common.DefaultNHPPort, PubKey: "key3"},
			},
			Version:      1,
			ReassignedAt: &now,
			CreatedAt:    now,
			LastSeen:     now,
		}

		data, err := json.Marshal(assignment)
		if err != nil {
			t.Fatalf("Failed to marshal ACAssignment: %v", err)
		}

		var decoded ACAssignment
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("Failed to unmarshal ACAssignment: %v", err)
		}

		if decoded.ACID != assignment.ACID {
			t.Errorf("ACID mismatch: expected %s, got %s", assignment.ACID, decoded.ACID)
		}
		if len(decoded.AssignedServers) != 3 {
			t.Errorf("Expected 3 assigned servers, got %d", len(decoded.AssignedServers))
		}
		if decoded.AssignedServers[0].ID != "srv-1" {
			t.Errorf("First server ID mismatch: expected srv-1, got %s", decoded.AssignedServers[0].ID)
		}
	})

	t.Run("License", func(t *testing.T) {
		license := &License{
			CustomerID:       "cust-456",
			LicenseKeySHA256: "abc123sha256hash",
			LicenseKeyHash:   "$2a$10$hashedkey",
			ResourceID:       "console",
			Tier:             "enterprise",
			MaxACs:           1000,
			ExpiresAt:        time.Now().Add(365 * 24 * time.Hour).Unix(),
			Active:           true,
		}

		data, err := json.Marshal(license)
		if err != nil {
			t.Fatalf("Failed to marshal License: %v", err)
		}

		var decoded License
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("Failed to unmarshal License: %v", err)
		}

		if decoded.CustomerID != license.CustomerID {
			t.Errorf("CustomerID mismatch: expected %s, got %s", license.CustomerID, decoded.CustomerID)
		}
		if decoded.Tier != "enterprise" {
			t.Errorf("Tier mismatch: expected enterprise, got %s", decoded.Tier)
		}
		if !decoded.Active {
			t.Error("Expected Active to be true")
		}
	})

	t.Run("Resource", func(t *testing.T) {
		resource := &Resource{
			CustomerID:    "cust-789",
			ResourceID:    "res-abc",
			ResourceFQDN:  "backend.example.com",
			ACID:          "ac-xyz",
			DestHost:      "internal.backend.local",
			DestPort:      8443,
			OpenTime:      60,
			AuthServiceID: "auth-svc-1",
		}

		data, err := json.Marshal(resource)
		if err != nil {
			t.Fatalf("Failed to marshal Resource: %v", err)
		}

		var decoded Resource
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("Failed to unmarshal Resource: %v", err)
		}

		if decoded.ResourceID != resource.ResourceID {
			t.Errorf("ResourceID mismatch: expected %s, got %s", resource.ResourceID, decoded.ResourceID)
		}
		if decoded.DestPort != 8443 {
			t.Errorf("DestPort mismatch: expected 8443, got %d", decoded.DestPort)
		}
	})
}

// TestCreateStorageBackend_EtcdRequiresEndpoints verifies factory error handling
func TestCreateStorageBackend_EtcdRequiresEndpoints(t *testing.T) {
	cfg := StorageConfig{
		Backend: "etcd",
		Etcd: EtcdStorageConfig{
			Endpoints: []string{}, // Empty endpoints
		},
	}

	_, err := CreateStorageBackend(context.Background(), cfg)
	if err == nil {
		t.Error("Expected error when creating etcd backend with no endpoints")
	}
}

// TestEtcdStorageConfig_Defaults verifies config structure
func TestEtcdStorageConfig_Defaults(t *testing.T) {
	cfg := EtcdStorageConfig{
		Endpoints:  []string{"etcd1:2379", "etcd2:2379", "etcd3:2379"},
		TLS:        true,
		CACert:     "/etc/ssl/ca.crt",
		ClientCert: "/etc/ssl/client.crt",
		ClientKey:  "/etc/ssl/client.key",
		Username:   "nhp-server",
		Password:   "secret",
	}

	if len(cfg.Endpoints) != 3 {
		t.Errorf("Expected 3 endpoints, got %d", len(cfg.Endpoints))
	}
	if !cfg.TLS {
		t.Error("Expected TLS to be true")
	}
	if cfg.Username != "nhp-server" {
		t.Errorf("Expected username 'nhp-server', got '%s'", cfg.Username)
	}
}

// ============================================================================
// Integration Tests (require live etcd)
// Run with: go test -tags=integration -v
// ============================================================================

// Integration tests would go here with //go:build integration tag
// They would test actual etcd operations against a running etcd instance
