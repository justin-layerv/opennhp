package server

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
)

func TestForwardToTransaction(t *testing.T) {
	t.Run("transaction not found returns error", func(t *testing.T) {
		connData := &core.ConnectionData{
			RemoteTransactionMap: make(map[uint64]*core.RemoteTransaction),
		}

		md := &core.MsgData{}
		err := forwardToTransaction(connData, 42, md, "server-agent", "TestHandler", "user1", "1.2.3.4:5678")

		if !errors.Is(err, common.ErrTransactionIdNotFound) {
			t.Errorf("expected ErrTransactionIdNotFound, got %v", err)
		}
	})

	t.Run("transaction found forwards message", func(t *testing.T) {
		connData := &core.ConnectionData{
			RemoteTransactionMap: make(map[uint64]*core.RemoteTransaction),
		}

		msgCh := make(chan *core.MsgData, 1) // buffered to avoid blocking in test
		connData.RemoteTransactionMap[99] = core.NewRemoteTransactionForTest(99, msgCh)

		md := &core.MsgData{
			HeaderType: core.NHP_ACK,
		}
		err := forwardToTransaction(connData, 99, md, "server-agent", "TestHandler", "user1", "1.2.3.4:5678")

		if err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}

		select {
		case got := <-msgCh:
			if got != md {
				t.Errorf("expected forwarded message to be the same pointer")
			}
		default:
			t.Error("expected message to be sent to NextMsgCh")
		}
	})
}

func TestTempFileCleanupOrder(t *testing.T) {
	// Simulate the temp directory+file created by utils.DownloadFileToTemp
	dir, err := os.MkdirTemp("", "wasm-test-")
	if err != nil {
		t.Fatal(err)
	}

	file := filepath.Join(dir, "test.wasm")
	if err := os.WriteFile(file, []byte("test"), 0600); err != nil {
		_ = os.RemoveAll(dir)
		t.Fatal(err)
	}

	// Reproduce the defer order from onAttestationVerify.
	// LIFO: last defer runs first, so file is removed before directory.
	func() {
		defer func() { _ = os.Remove(filepath.Dir(file)) }() // runs second — removes empty dir
		defer func() { _ = os.Remove(file) }()               // runs first — removes file
	}()

	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Errorf("temp file was not removed: %s", file)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("temp directory was not removed: %s", dir)
		_ = os.RemoveAll(dir) // cleanup on failure
	}
}

// TestAutoAssignAC_VersionIncrement verifies that when autoAssignAC replaces an
// expired assignment (existingVersion > 0), the saved assignment uses
// Version = existingVersion + 1 instead of hardcoded 1. This was the root cause
// of the DynamoDB conditional write failure that caused 502 knock_failed errors.
func TestAutoAssignAC_VersionIncrement(t *testing.T) {
	// CloudMapClient with pre-populated cache — no real AWS API calls.
	cloudMap := &CloudMapClient{
		cachedInstances: []ServerInfo{
			{ID: "i-test-1", IP: "10.0.0.1", InternalIP: "10.0.0.1", AZ: "us-east-2a", Port: 62206},
			{ID: "i-test-2", IP: "10.0.0.2", InternalIP: "10.0.0.2", AZ: "us-east-2b", Port: 62206},
		},
		instancesExpiry: time.Now().Add(time.Hour),
	}

	// Minimal PacketParserData — sendARD will fail (no transaction) but
	// autoAssignAC only logs the warning, so the test still passes.
	ppd := &core.PacketParserData{
		ConnData: &core.ConnectionData{
			RemoteTransactionMap: make(map[uint64]*core.RemoteTransaction),
		},
	}

	aolMsg := &common.ACOnlineMsg{ACId: "layerv-ac-test"}

	tests := []struct {
		name            string
		existingVersion int
		wantVersion     int
	}{
		{"new assignment", 0, 1},
		{"expired v5 replacement", 5, 6},
		{"expired v1 replacement", 1, 2},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Fresh mock per subtest — reuses mockStorageBackend from storage_test.go
			storage := newMockStorageBackend()
			device := core.NewDevice(core.NHP_SERVER, testPrivateKey(), nil)
			if device == nil {
				t.Fatal("Failed to create device")
			}
			defer device.Stop()
			srv := &UdpServer{
				storage:    storage,
				cloudMap:   cloudMap,
				instanceID: "i-test-1",
				config:     &Config{Hostname: "test-server", ListenPort: 62206},
				device:     device,
			}

			_, err := srv.autoAssignAC(ppd, aolMsg, 12345, "10.99.0.1:62206", tc.existingVersion)
			if err != nil {
				t.Fatalf("autoAssignAC returned error: %v", err)
			}

			storage.mu.Lock()
			defer storage.mu.Unlock()

			saved := storage.assignments["layerv-ac-test"]
			if saved == nil {
				t.Fatal("SaveACAssignment was not called")
			}
			if saved.Version != tc.wantVersion {
				t.Errorf("Version = %d, want %d", saved.Version, tc.wantVersion)
			}
			if saved.TTL == nil {
				t.Fatal("TTL should be set")
			}
			if *saved.TTL <= time.Now().Unix() {
				t.Error("TTL should be in the future")
			}
		})
	}
}

// TestAutoAssignAC_FiltersByASG verifies that when the server has an ASG name,
// autoAssignAC filters out servers from different ASGs before selecting.
// This prevents blue/green cross-color assignment during deploys.
func TestAutoAssignAC_FiltersByASG(t *testing.T) {
	// CloudMapClient with 4 servers: 2 blue, 2 green.
	// Shared across subtests (read-only: tests only access cachedInstances).
	cloudMap := &CloudMapClient{
		cachedInstances: []ServerInfo{
			{ID: "i-blue-1", IP: "10.0.0.1", InternalIP: "10.0.0.1", AZ: "us-east-2a", Port: 62206, ASGName: "layerv-nhp-sandbox-server"},
			{ID: "i-blue-2", IP: "10.0.0.2", InternalIP: "10.0.0.2", AZ: "us-east-2b", Port: 62206, ASGName: "layerv-nhp-sandbox-server"},
			{ID: "i-green-1", IP: "10.0.0.3", InternalIP: "10.0.0.3", AZ: "us-east-2a", Port: 62206, ASGName: "layerv-nhp-sandbox-server-green"},
			{ID: "i-green-2", IP: "10.0.0.4", InternalIP: "10.0.0.4", AZ: "us-east-2b", Port: 62206, ASGName: "layerv-nhp-sandbox-server-green"},
		},
		instancesExpiry: time.Now().Add(time.Hour),
	}

	ppd := &core.PacketParserData{
		ConnData: &core.ConnectionData{
			RemoteTransactionMap: make(map[uint64]*core.RemoteTransaction),
		},
	}
	aolMsg := &common.ACOnlineMsg{ACId: "layerv-ac-test-asg"}

	tests := []struct {
		name       string
		instanceID string // server's own instance ID
		asgName    string // server's own ASG
		wantCount  int    // expected number of assigned servers
		wantIDs    map[string]bool
		excludeIDs map[string]bool
	}{
		{
			name:       "blue server filters out green",
			instanceID: "i-blue-1",
			asgName:    "layerv-nhp-sandbox-server",
			wantCount:  2, // only 2 blue servers available
			wantIDs:    map[string]bool{"i-blue-1": true, "i-blue-2": true},
			excludeIDs: map[string]bool{"i-green-1": true, "i-green-2": true},
		},
		{
			name:       "green server filters out blue",
			instanceID: "i-green-1",
			asgName:    "layerv-nhp-sandbox-server-green",
			wantCount:  2, // only 2 green servers available
			wantIDs:    map[string]bool{"i-green-1": true, "i-green-2": true},
			excludeIDs: map[string]bool{"i-blue-1": true, "i-blue-2": true},
		},
		{
			name:       "empty ASG name includes all (fail-open)",
			instanceID: "i-blue-1",
			asgName:    "",
			wantCount:  3, // MaxServersPerAssignment from all 4
			wantIDs:    map[string]bool{"i-blue-1": true, "i-blue-2": true, "i-green-1": true, "i-green-2": true},
			excludeIDs: map[string]bool{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			storage := newMockStorageBackend()
			device := core.NewDevice(core.NHP_SERVER, testPrivateKey(), nil)
			if device == nil {
				t.Fatal("Failed to create device")
			}
			defer device.Stop()

			srv := &UdpServer{
				storage:    storage,
				cloudMap:   cloudMap,
				instanceID: tc.instanceID,
				asgName:    tc.asgName,
				config:     &Config{Hostname: "test-server", ListenPort: 62206},
				device:     device,
			}

			_, err := srv.autoAssignAC(ppd, aolMsg, 99999, "10.99.0.1:62206", 0)
			if err != nil {
				t.Fatalf("autoAssignAC returned error: %v", err)
			}

			storage.mu.Lock()
			defer storage.mu.Unlock()

			saved := storage.assignments["layerv-ac-test-asg"]
			if saved == nil {
				t.Fatal("SaveACAssignment was not called")
			}

			if len(saved.AssignedServers) != tc.wantCount {
				t.Errorf("Expected %d assigned servers, got %d", tc.wantCount, len(saved.AssignedServers))
			}

			for _, s := range saved.AssignedServers {
				if tc.excludeIDs[s.ID] {
					t.Errorf("Server %s should have been filtered out", s.ID)
				}
				// Verify ASGName is stripped from persisted servers
				if s.ASGName != "" {
					t.Errorf("Server %s has ASGName=%q in persisted assignment, expected empty (should be stripped)", s.ID, s.ASGName)
				}
			}

			// Verify all assigned servers are from the expected set
			for _, s := range saved.AssignedServers {
				if !tc.wantIDs[s.ID] {
					t.Errorf("Unexpected server %s in assignment", s.ID)
				}
			}
		})
	}
}

func TestUdpCorrelationCtx(t *testing.T) {
	t.Run("sets correlation ID in context", func(t *testing.T) {
		ctx, cancel := udpCorrelationCtx(time.Second, "ac-123", 456)
		defer cancel()

		got := requestIDFromCtx(ctx)
		want := "udp-ac-123-456"
		if got != want {
			t.Errorf("request ID = %q, want %q", got, want)
		}
	})

	t.Run("sets deadline from timeout", func(t *testing.T) {
		ctx, cancel := udpCorrelationCtx(100*time.Millisecond, "ac-xyz", 1)
		defer cancel()

		deadline, ok := ctx.Deadline()
		if !ok {
			t.Fatal("expected context to have deadline")
		}
		if time.Until(deadline) > 100*time.Millisecond {
			t.Errorf("deadline should be within timeout, got %v", time.Until(deadline))
		}
	})

	t.Run("cancel releases context", func(t *testing.T) {
		ctx, cancel := udpCorrelationCtx(time.Hour, "ac-abc", 99)
		cancel()

		select {
		case <-ctx.Done():
			// expected
		default:
			t.Error("expected context to be canceled after cancel()")
		}
	})
}
