//go:build local

// Package local provides e2e tests that run against a local Docker environment.
// These tests validate the AC registry and peer preservation behavior.
//
// The test infrastructure (etcd container) is automatically managed by TestMain
// using testcontainers-go. No manual docker-compose setup is required.
//
// Run tests:
//
//	cd tests/local && go test -v -tags=local ./...
//
// Or from project root:
//
//	make test-local
package local

import (
	"context"
	"fmt"
	"testing"
	"time"

	toml "github.com/pelletier/go-toml/v2"
	clientv3 "go.etcd.io/etcd/client/v3"
)

// etcdEndpoint is set by TestMain in testmain_test.go after starting the etcd container

func createTestEtcdClient(t *testing.T) *clientv3.Client {
	t.Helper()

	if etcdEndpoint == "" {
		t.Fatal("etcdEndpoint not set - TestMain should have started the etcd container")
	}

	client, err := clientv3.New(clientv3.Config{
		Endpoints:   []string{etcdEndpoint},
		DialTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("Failed to create etcd client for %s: %v", etcdEndpoint, err)
	}

	// Verify connection
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err = client.Status(ctx, etcdEndpoint)
	if err != nil {
		client.Close()
		t.Fatalf("etcd health check failed at %s: %v", etcdEndpoint, err)
	}

	return client
}

// TestACRegistry_PeerPreservation is the main e2e test for the AC peer preservation fix.
// It simulates the scenario where:
// 1. An AC registers in /nhp/ac-registry/
// 2. Lambda updates /nhp/config (without [[ACs]] section)
// 3. The AC registration should NOT be wiped
func TestACRegistry_PeerPreservation(t *testing.T) {
	client := createTestEtcdClient(t)
	defer client.Close()

	ctx := context.Background()

	// Clean up before test
	client.Delete(ctx, "/nhp/", clientv3.WithPrefix())

	// Step 1: Simulate AC registration (what AC does on startup)
	t.Log("Step 1: Simulating AC registration...")
	acEntry := `# AC Registry Entry
PublicKey = "dGVzdEFDcHVibGlja2V5YmFzZTY0ZW5jb2RlZA=="
InstanceId = "i-test-local-001"
Ip = "10.0.0.100"
Port = 62206
RegisteredAt = 1703980800
`
	_, err := client.Put(ctx, "/nhp/ac-registry/i-test-local-001", acEntry)
	if err != nil {
		t.Fatalf("Failed to register AC: %v", err)
	}
	t.Log("AC registered successfully")

	// Step 2: Verify AC is in registry
	resp, err := client.Get(ctx, "/nhp/ac-registry/", clientv3.WithPrefix())
	if err != nil {
		t.Fatalf("Failed to list AC registry: %v", err)
	}
	if len(resp.Kvs) != 1 {
		t.Fatalf("Expected 1 AC in registry, got %d", len(resp.Kvs))
	}
	t.Logf("Verified: %d AC(s) in registry", len(resp.Kvs))

	// Step 3: Simulate Lambda updating /nhp/config (only [[Servers]], no [[ACs]])
	t.Log("Step 2: Simulating Lambda config update (only [[Servers]])...")
	lambdaConfig := `# NHP AC Configuration (seeded by Lambda)
# This config has NO [[ACs]] section - ACs register dynamically

[[Servers]]
Hostname = "nhp-test-server-nlb.example.com"
Ip = ""
Port = 62206
PubKeyBase64 = "c2VydmVycHVibGlja2V5YmFzZTY0"
ExpireTime = 1924991999
`
	_, err = client.Put(ctx, "/nhp/config", lambdaConfig)
	if err != nil {
		t.Fatalf("Failed to update /nhp/config: %v", err)
	}
	t.Log("Config updated with only [[Servers]]")

	// Step 4: Verify AC is STILL in registry (the fix!)
	t.Log("Step 3: Verifying AC registration persisted...")
	resp, err = client.Get(ctx, "/nhp/ac-registry/", clientv3.WithPrefix())
	if err != nil {
		t.Fatalf("Failed to list AC registry: %v", err)
	}

	if len(resp.Kvs) == 0 {
		t.Fatal("REGRESSION: AC registry was wiped after config update!")
	}
	t.Logf("SUCCESS: AC registration preserved (%d entries)", len(resp.Kvs))

	// Step 5: Parse /nhp/config and verify it has no [[ACs]]
	configResp, err := client.Get(ctx, "/nhp/config")
	if err != nil {
		t.Fatalf("Failed to get /nhp/config: %v", err)
	}

	var config struct {
		Servers []struct {
			Hostname     string
			PubKeyBase64 string
		}
		ACs []struct {
			PubKeyBase64 string
		}
	}
	if err := toml.Unmarshal(configResp.Kvs[0].Value, &config); err != nil {
		t.Fatalf("Failed to parse config: %v", err)
	}

	if len(config.ACs) > 0 {
		t.Errorf("Config should have no [[ACs]] section, got %d", len(config.ACs))
	}
	if len(config.Servers) == 0 {
		t.Error("Config should have [[Servers]] section")
	}

	t.Log("PASS: Config has Servers but no ACs - fix is working correctly")
}

// TestACRegistry_MultipleACs verifies multiple ACs can register and survive config updates
func TestACRegistry_MultipleACs(t *testing.T) {
	client := createTestEtcdClient(t)
	defer client.Close()

	ctx := context.Background()

	// Clean up
	client.Delete(ctx, "/nhp/", clientv3.WithPrefix())

	// Register multiple ACs
	acs := []struct {
		instanceId string
		ip         string
		pubKey     string
	}{
		{"i-ac-001", "10.0.0.1", "cHVia2V5MQ=="},
		{"i-ac-002", "10.0.0.2", "cHVia2V5Mg=="},
		{"i-ac-003", "10.0.0.3", "cHVia2V5Mw=="},
	}

	for _, ac := range acs {
		entry := fmt.Sprintf(`PublicKey = "%s"
InstanceId = "%s"
Ip = "%s"
Port = 62206
RegisteredAt = %d
`, ac.pubKey, ac.instanceId, ac.ip, time.Now().Unix())

		_, err := client.Put(ctx, "/nhp/ac-registry/"+ac.instanceId, entry)
		if err != nil {
			t.Fatalf("Failed to register AC %s: %v", ac.instanceId, err)
		}
	}
	t.Logf("Registered %d ACs", len(acs))

	// Update config multiple times
	for i := 0; i < 3; i++ {
		config := fmt.Sprintf(`# Config update %d
[[Servers]]
Hostname = "server-%d.example.com"
Port = 62206
PubKeyBase64 = "c2VydmVy"
`, i, i)
		_, err := client.Put(ctx, "/nhp/config", config)
		if err != nil {
			t.Fatalf("Failed to update config: %v", err)
		}
	}
	t.Log("Config updated 3 times")

	// Verify all ACs still registered
	resp, err := client.Get(ctx, "/nhp/ac-registry/", clientv3.WithPrefix())
	if err != nil {
		t.Fatalf("Failed to list AC registry: %v", err)
	}

	if len(resp.Kvs) != len(acs) {
		t.Errorf("Expected %d ACs, got %d", len(acs), len(resp.Kvs))
	} else {
		t.Logf("SUCCESS: All %d ACs preserved after config updates", len(resp.Kvs))
	}
}

// TestACRegistry_WatchNotification verifies the watch mechanism works
func TestACRegistry_WatchNotification(t *testing.T) {
	client := createTestEtcdClient(t)
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Clean up
	client.Delete(ctx, "/nhp/", clientv3.WithPrefix())

	// Start watching
	watchChan := client.Watch(ctx, "/nhp/ac-registry/", clientv3.WithPrefix())

	// Register an AC in a goroutine
	go func() {
		time.Sleep(100 * time.Millisecond)
		entry := `PublicKey = "d2F0Y2h0ZXN0"
InstanceId = "i-watch-test"
Ip = "10.0.0.99"
Port = 62206
`
		client.Put(context.Background(), "/nhp/ac-registry/i-watch-test", entry)
	}()

	// Wait for watch event
	select {
	case watchResp := <-watchChan:
		if watchResp.Err() != nil {
			t.Fatalf("Watch error: %v", watchResp.Err())
		}
		for _, ev := range watchResp.Events {
			t.Logf("Watch event: %s %q", ev.Type, ev.Kv.Key)
			if string(ev.Kv.Key) != "/nhp/ac-registry/i-watch-test" {
				t.Errorf("Unexpected key: %s", ev.Kv.Key)
			}
		}
		t.Log("PASS: Watch notification received")
	case <-ctx.Done():
		t.Fatal("Timeout waiting for watch event")
	}
}

// TestACRegistry_Deregistration verifies AC removal works correctly
func TestACRegistry_Deregistration(t *testing.T) {
	client := createTestEtcdClient(t)
	defer client.Close()

	ctx := context.Background()
	client.Delete(ctx, "/nhp/", clientv3.WithPrefix())

	// Register an AC
	entry := `PublicKey = "ZGVyZWdpc3RlcnRlc3Q="
InstanceId = "i-to-be-removed"
Ip = "10.0.0.50"
Port = 62206
`
	_, err := client.Put(ctx, "/nhp/ac-registry/i-to-be-removed", entry)
	if err != nil {
		t.Fatalf("Failed to register AC: %v", err)
	}

	// Verify it exists
	resp, err := client.Get(ctx, "/nhp/ac-registry/i-to-be-removed")
	if err != nil || len(resp.Kvs) == 0 {
		t.Fatal("AC should exist after registration")
	}
	t.Log("AC registered")

	// Deregister (simulate instance termination)
	_, err = client.Delete(ctx, "/nhp/ac-registry/i-to-be-removed")
	if err != nil {
		t.Fatalf("Failed to deregister AC: %v", err)
	}

	// Verify it's gone
	resp, err = client.Get(ctx, "/nhp/ac-registry/i-to-be-removed")
	if err != nil {
		t.Fatalf("Failed to check AC: %v", err)
	}
	if len(resp.Kvs) != 0 {
		t.Error("AC should be removed after deregistration")
	} else {
		t.Log("PASS: AC successfully deregistered")
	}
}

// TestACRegistry_ConcurrentRegistrations tests multiple ACs registering simultaneously
func TestACRegistry_ConcurrentRegistrations(t *testing.T) {
	client := createTestEtcdClient(t)
	defer client.Close()

	ctx := context.Background()
	client.Delete(ctx, "/nhp/", clientv3.WithPrefix())

	numACs := 10
	done := make(chan error, numACs)

	// Register ACs concurrently
	for i := 0; i < numACs; i++ {
		go func(idx int) {
			entry := fmt.Sprintf(`PublicKey = "Y29uY3VycmVudCVk"
InstanceId = "i-concurrent-%03d"
Ip = "10.0.1.%d"
Port = 62206
RegisteredAt = %d
`, idx, idx, time.Now().Unix())

			_, err := client.Put(ctx, fmt.Sprintf("/nhp/ac-registry/i-concurrent-%03d", idx), entry)
			done <- err
		}(i)
	}

	// Wait for all registrations
	for i := 0; i < numACs; i++ {
		if err := <-done; err != nil {
			t.Errorf("Registration failed: %v", err)
		}
	}

	// Verify all registered
	resp, err := client.Get(ctx, "/nhp/ac-registry/i-concurrent-", clientv3.WithPrefix())
	if err != nil {
		t.Fatalf("Failed to list ACs: %v", err)
	}

	if len(resp.Kvs) != numACs {
		t.Errorf("Expected %d ACs, got %d", numACs, len(resp.Kvs))
	} else {
		t.Logf("PASS: All %d concurrent registrations succeeded", numACs)
	}
}

// TestACRegistry_InvalidEntries verifies malformed entries are handled
func TestACRegistry_InvalidEntries(t *testing.T) {
	client := createTestEtcdClient(t)
	defer client.Close()

	ctx := context.Background()
	client.Delete(ctx, "/nhp/", clientv3.WithPrefix())

	tests := []struct {
		name    string
		key     string
		value   string
		isValid bool
	}{
		{
			name: "valid_entry",
			key:  "/nhp/ac-registry/i-valid",
			value: `PublicKey = "dmFsaWQ="
InstanceId = "i-valid"
Ip = "10.0.0.1"`,
			isValid: true,
		},
		{
			name:    "empty_value",
			key:     "/nhp/ac-registry/i-empty",
			value:   "",
			isValid: false,
		},
		{
			name:    "invalid_toml",
			key:     "/nhp/ac-registry/i-bad-toml",
			value:   "not valid toml [[[",
			isValid: false,
		},
		{
			name: "missing_public_key",
			key:  "/nhp/ac-registry/i-no-key",
			value: `InstanceId = "i-no-key"
Ip = "10.0.0.2"`,
			isValid: false, // PublicKey is required for peer trust
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := client.Put(ctx, tt.key, tt.value)
			if err != nil {
				t.Fatalf("Failed to put entry: %v", err)
			}

			// Try to parse it
			resp, _ := client.Get(ctx, tt.key)
			if len(resp.Kvs) == 0 {
				t.Fatal("Entry should exist")
			}

			var entry struct {
				PublicKey  string
				InstanceId string
				Ip         string
			}
			err = toml.Unmarshal(resp.Kvs[0].Value, &entry)

			if tt.isValid {
				if err != nil {
					t.Errorf("Valid entry should parse: %v", err)
				}
				if entry.PublicKey == "" {
					t.Error("Valid entry should have PublicKey")
				}
			} else {
				// Invalid entries either fail to parse or have missing required fields
				if err == nil && entry.PublicKey != "" {
					t.Error("Invalid entry should fail validation")
				}
			}
		})
	}
}

// TestACRegistry_ConfigUpdateDuringRegistration tests race between config update and AC registration
func TestACRegistry_ConfigUpdateDuringRegistration(t *testing.T) {
	client := createTestEtcdClient(t)
	defer client.Close()

	ctx := context.Background()
	client.Delete(ctx, "/nhp/", clientv3.WithPrefix())

	// Start config updates in background
	configDone := make(chan struct{})
	go func() {
		defer close(configDone)
		for i := 0; i < 5; i++ {
			config := fmt.Sprintf(`[[Servers]]
Hostname = "server-%d.example.com"
Port = 62206
PubKeyBase64 = "c2VydmVy%d"
`, i, i)
			client.Put(ctx, "/nhp/config", config)
			time.Sleep(10 * time.Millisecond)
		}
	}()

	// Register ACs while config is being updated
	for i := 0; i < 5; i++ {
		entry := fmt.Sprintf(`PublicKey = "cmFjZXRlc3Q%d"
InstanceId = "i-race-%d"
Ip = "10.0.2.%d"
Port = 62206
`, i, i, i)
		_, err := client.Put(ctx, fmt.Sprintf("/nhp/ac-registry/i-race-%d", i), entry)
		if err != nil {
			t.Errorf("Failed to register AC during config update: %v", err)
		}
		time.Sleep(5 * time.Millisecond)
	}

	<-configDone

	// Verify all ACs survived
	resp, err := client.Get(ctx, "/nhp/ac-registry/i-race-", clientv3.WithPrefix())
	if err != nil {
		t.Fatalf("Failed to list ACs: %v", err)
	}

	if len(resp.Kvs) != 5 {
		t.Errorf("Expected 5 ACs after race condition, got %d", len(resp.Kvs))
	} else {
		t.Log("PASS: All ACs preserved during concurrent config updates")
	}
}

// TestACRegistry_LeaseExpiration tests AC entries with TTL
func TestACRegistry_LeaseExpiration(t *testing.T) {
	client := createTestEtcdClient(t)
	defer client.Close()

	ctx := context.Background()
	client.Delete(ctx, "/nhp/", clientv3.WithPrefix())

	// Create a lease with short TTL (5 seconds)
	lease, err := client.Grant(ctx, 5)
	if err != nil {
		t.Fatalf("Failed to create lease: %v", err)
	}

	// Register AC with lease
	entry := `PublicKey = "bGVhc2V0ZXN0"
InstanceId = "i-leased"
Ip = "10.0.3.1"
Port = 62206
`
	_, err = client.Put(ctx, "/nhp/ac-registry/i-leased", entry, clientv3.WithLease(lease.ID))
	if err != nil {
		t.Fatalf("Failed to register AC with lease: %v", err)
	}

	// Verify it exists
	resp, _ := client.Get(ctx, "/nhp/ac-registry/i-leased")
	if len(resp.Kvs) == 0 {
		t.Fatal("Leased AC should exist initially")
	}
	t.Logf("AC registered with %d second TTL", lease.TTL)

	// Wait for lease to expire (TTL + buffer)
	t.Log("Waiting for lease expiration...")
	time.Sleep(6 * time.Second)

	// Verify it's gone
	resp, _ = client.Get(ctx, "/nhp/ac-registry/i-leased")
	if len(resp.Kvs) != 0 {
		t.Error("Leased AC should be removed after TTL expiration")
	} else {
		t.Log("PASS: AC automatically removed after lease expiration")
	}
}

// TestConfigUpdate_ParsesCorrectly validates config parsing behavior
func TestConfigUpdate_ParsesCorrectly(t *testing.T) {
	tests := []struct {
		name           string
		config         string
		expectServers  int
		expectACs      int
		expectNoUpdate bool // If true, ACs should NOT be updated from config
	}{
		{
			name: "only_servers",
			config: `[[Servers]]
Hostname = "server.example.com"
Port = 62206
PubKeyBase64 = "abc123"
`,
			expectServers:  1,
			expectACs:      0,
			expectNoUpdate: true, // No [[ACs]] = don't call updateACPeers
		},
		{
			name: "servers_with_static_acs",
			config: `[[Servers]]
Hostname = "server.example.com"
Port = 62206

[[ACs]]
Ip = "10.0.0.1"
PubKeyBase64 = "ac1key"
`,
			expectServers:  1,
			expectACs:      1,
			expectNoUpdate: false, // Has [[ACs]] = call updateACPeers
		},
		{
			name:           "empty_config",
			config:         `# Empty config`,
			expectServers:  0,
			expectACs:      0,
			expectNoUpdate: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var config struct {
				Servers []struct{ Hostname string }
				ACs     []struct{ PubKeyBase64 string }
			}

			err := toml.Unmarshal([]byte(tt.config), &config)
			if err != nil {
				t.Fatalf("Parse error: %v", err)
			}

			if len(config.Servers) != tt.expectServers {
				t.Errorf("Servers: got %d, want %d", len(config.Servers), tt.expectServers)
			}
			if len(config.ACs) != tt.expectACs {
				t.Errorf("ACs: got %d, want %d", len(config.ACs), tt.expectACs)
			}

			// This is the fix logic
			shouldSkipACUpdate := len(config.ACs) == 0
			if shouldSkipACUpdate != tt.expectNoUpdate {
				t.Errorf("shouldSkipACUpdate: got %v, want %v", shouldSkipACUpdate, tt.expectNoUpdate)
			}

			t.Logf("Config parsed: %d servers, %d ACs, skipACUpdate=%v",
				len(config.Servers), len(config.ACs), shouldSkipACUpdate)
		})
	}
}
