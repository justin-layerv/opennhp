package server

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/endpoints/metrics"
	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
)

func TestForwardToTransaction(t *testing.T) {
	t.Run("transaction not found returns error", func(t *testing.T) {
		s := &UdpServer{}
		connData := &core.ConnectionData{
			RemoteTransactionMap: make(map[uint64]*core.RemoteTransaction),
		}

		md := &core.MsgData{}
		err := s.forwardToTransaction(connData, 42, md, "server-agent", "TestHandler", "user1", "1.2.3.4:5678")

		if !errors.Is(err, common.ErrTransactionIdNotFound) {
			t.Errorf("expected ErrTransactionIdNotFound, got %v", err)
		}
	})

	t.Run("transaction found forwards message", func(t *testing.T) {
		s := &UdpServer{}
		connData := &core.ConnectionData{
			RemoteTransactionMap: make(map[uint64]*core.RemoteTransaction),
		}

		msgCh := make(chan *core.MsgData, 1) // buffered to avoid blocking in test
		connData.RemoteTransactionMap[99] = core.NewRemoteTransactionForTest(99, msgCh)

		md := &core.MsgData{
			HeaderType: core.NHP_ACK,
		}
		err := s.forwardToTransaction(connData, 99, md, "server-agent", "TestHandler", "user1", "1.2.3.4:5678")

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

	t.Run("closed transaction increments MetricTransactionClosed", func(t *testing.T) {
		mp := metrics.NewPublisherForTest(t)
		s := &UdpServer{metrics: mp}

		connData := &core.ConnectionData{
			RemoteTransactionMap: make(map[uint64]*core.RemoteTransaction),
		}
		msgCh := make(chan *core.MsgData) // unbuffered, no reader
		tx := core.NewRemoteTransactionForTest(7, msgCh)
		connData.RemoteTransactionMap[7] = tx
		tx.CloseForTest() // simulate Run() exit between Find and Send

		err := s.forwardToTransaction(connData, 7, &core.MsgData{}, "server-agent", "TestHandler", "user1", "1.2.3.4:5678")
		if !errors.Is(err, common.ErrTransactionClosed) {
			t.Fatalf("expected ErrTransactionClosed, got %v", err)
		}

		counters, _ := mp.CountersForTest(t)
		if counters[MetricTransactionClosed] != 1 {
			t.Errorf("expected %s=1, got %v", MetricTransactionClosed, counters[MetricTransactionClosed])
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

			_, err := srv.autoAssignAC(ppd, aolMsg, 12345, "10.99.0.1:62206", tc.existingVersion, nil)
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

			_, err := srv.autoAssignAC(ppd, aolMsg, 99999, "10.99.0.1:62206", 0, nil)
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

// newColorTestServer builds a UdpServer wired for the blue/green
// color-migration tests: a real device (stopped via t.Cleanup), a test metrics
// publisher, and the given storage / Cloud Map / identity. Returns the server
// and its publisher so the test can assert on counters.
func newColorTestServer(t *testing.T, storage StorageBackend, cloudMap *CloudMapClient, instanceID, asgName, localIP string) (*UdpServer, *metrics.Publisher) {
	t.Helper()
	device := core.NewDevice(core.NHP_SERVER, testPrivateKey(), nil)
	if device == nil {
		t.Fatal("failed to create device")
	}
	t.Cleanup(device.Stop)
	mp := metrics.NewPublisherForTest(t)
	return &UdpServer{
		storage:    storage,
		cloudMap:   cloudMap,
		instanceID: instanceID,
		asgName:    asgName,
		localIp:    localIP,
		config:     &Config{Hostname: instanceID, ListenPort: 62206},
		device:     device,
		metrics:    mp,
	}, mp
}

// newACOnlinePPD returns a minimal PacketParserData for AC-online handler
// tests. sendARD has no real transaction to target, so it logs a warning and
// the handler proceeds — matching the prod accept-locally path.
func newACOnlinePPD() *core.PacketParserData {
	return &core.PacketParserData{
		ConnData: &core.ConnectionData{
			RemoteTransactionMap: make(map[uint64]*core.RemoteTransaction),
		},
	}
}

// TestHandleACServerAssignment_MigratesCrossColorAssignment fences the
// blue/green convergence fix. When an AC whose persisted assignment still
// points at old-color (cross-ASG) servers re-registers onto a freshly
// switched new-color server, the server must reassign it WHOLESALE to the
// new color (so a single re-registration connects the AC to every new-color
// server) instead of grafting only itself onto the stale set. The graft
// behavior left one new server AC-starved past the post-switch knock-ready
// gate — the deploy flake this fixes.
func TestHandleACServerAssignment_MigratesCrossColorAssignment(t *testing.T) {
	const (
		blueASG  = "layerv-nhp-sandbox-server"
		greenASG = "layerv-nhp-sandbox-server-green"
		acID     = "layerv-ac-bluegreen"
	)
	// Cloud Map sees BOTH colors healthy — old (blue) servers have not yet
	// scaled down (scale-down runs after deploy validation).
	cloudMap := &CloudMapClient{
		cachedInstances: []ServerInfo{
			{ID: "i-blue-a", IP: "10.0.0.1", InternalIP: "10.0.0.1", AZ: "us-east-2a", Port: 62206, PubKey: "pk-ba", ASGName: blueASG},
			{ID: "i-blue-b", IP: "10.0.0.2", InternalIP: "10.0.0.2", AZ: "us-east-2b", Port: 62206, PubKey: "pk-bb", ASGName: blueASG},
			{ID: "i-blue-c", IP: "10.0.0.3", InternalIP: "10.0.0.3", AZ: "us-east-2c", Port: 62206, PubKey: "pk-bc", ASGName: blueASG},
			{ID: "i-green-a", IP: "10.0.1.1", InternalIP: "10.0.1.1", AZ: "us-east-2a", Port: 62206, PubKey: "pk-ga", ASGName: greenASG},
			{ID: "i-green-b", IP: "10.0.1.2", InternalIP: "10.0.1.2", AZ: "us-east-2b", Port: 62206, PubKey: "pk-gb", ASGName: greenASG},
			{ID: "i-green-c", IP: "10.0.1.3", InternalIP: "10.0.1.3", AZ: "us-east-2c", Port: 62206, PubKey: "pk-gc", ASGName: greenASG},
		},
		instancesExpiry: time.Now().Add(time.Hour),
	}

	storage := newMockStorageBackend()
	now := time.Now().Unix()
	ttl := now + AssignmentTTLSeconds
	// AC is currently pinned to all three OLD (blue) servers (ASGName stripped,
	// as it is on persist).
	storage.assignments[acID] = &ACAssignment{
		ACID:    acID,
		Version: 5,
		AssignedServers: []ServerInfo{
			{ID: "i-blue-a", IP: "10.0.0.1", InternalIP: "10.0.0.1", AZ: "us-east-2a", Port: 62206, PubKey: "pk-ba"},
			{ID: "i-blue-b", IP: "10.0.0.2", InternalIP: "10.0.0.2", AZ: "us-east-2b", Port: 62206, PubKey: "pk-bb"},
			{ID: "i-blue-c", IP: "10.0.0.3", InternalIP: "10.0.0.3", AZ: "us-east-2c", Port: 62206, PubKey: "pk-bc"},
		},
		CreatedAt: now,
		LastSeen:  now,
		TTL:       &ttl,
	}

	// The AC's NLB re-registration lands on a NEW (green) server.
	srv, mp := newColorTestServer(t, storage, cloudMap, "i-green-a", greenASG, "10.0.1.1")
	aolMsg := &common.ACOnlineMsg{ACId: acID}

	if _, _, err := srv.handleACServerAssignment(newACOnlinePPD(), aolMsg, 12345, "10.99.0.1:62206"); err != nil {
		t.Fatalf("handleACServerAssignment returned error: %v", err)
	}

	storage.mu.Lock()
	saved := storage.assignments[acID]
	storage.mu.Unlock()
	if saved == nil {
		t.Fatal("assignment missing after migration")
	}
	if saved.Version != 6 {
		t.Errorf("expected Version 6 (existing 5 + 1), got %d", saved.Version)
	}
	if len(saved.AssignedServers) != MaxServersPerAssignment {
		t.Errorf("expected %d assigned servers, got %d", MaxServersPerAssignment, len(saved.AssignedServers))
	}
	blueIDs := map[string]bool{"i-blue-a": true, "i-blue-b": true, "i-blue-c": true}
	foundSelf := false
	for _, srvInfo := range saved.AssignedServers {
		if blueIDs[srvInfo.ID] {
			t.Errorf("old-color server %s survived migration — assignment not fully migrated to new color", srvInfo.ID)
		}
		if srvInfo.ID == "i-green-a" {
			foundSelf = true
		}
	}
	if !foundSelf {
		t.Error("answering server i-green-a not included in migrated assignment (self-first guarantee broken)")
	}

	counters, _ := mp.CountersForTest(t)
	if counters[MetricACAssignmentColorMigration] != 1 {
		t.Errorf("expected %s=1, got %v", MetricACAssignmentColorMigration, counters[MetricACAssignmentColorMigration])
	}
}

// TestHandleACServerAssignment_SameColorReconnectDoesNotMigrate guards the
// steady-state path: an AC reconnecting to a same-color server that isn't in
// its assignment (e.g., a sibling that just registered) must take the
// add-self-keep-existing path (updateAssignmentWithSelf), NOT a wholesale
// reassignment. Over-triggering migration would churn assignments on every
// ordinary intra-color reconnect.
func TestHandleACServerAssignment_SameColorReconnectDoesNotMigrate(t *testing.T) {
	const (
		greenASG = "layerv-nhp-sandbox-server-green"
		acID     = "layerv-ac-samecolor"
	)
	cloudMap := &CloudMapClient{
		cachedInstances: []ServerInfo{
			{ID: "i-green-a", IP: "10.0.1.1", InternalIP: "10.0.1.1", AZ: "us-east-2a", Port: 62206, PubKey: "pk-ga", ASGName: greenASG},
			{ID: "i-green-b", IP: "10.0.1.2", InternalIP: "10.0.1.2", AZ: "us-east-2b", Port: 62206, PubKey: "pk-gb", ASGName: greenASG},
			{ID: "i-green-c", IP: "10.0.1.3", InternalIP: "10.0.1.3", AZ: "us-east-2c", Port: 62206, PubKey: "pk-gc", ASGName: greenASG},
		},
		instancesExpiry: time.Now().Add(time.Hour),
	}

	storage := newMockStorageBackend()
	now := time.Now().Unix()
	ttl := now + AssignmentTTLSeconds
	// AC assigned to two same-color (green) servers; reconnects to the third.
	storage.assignments[acID] = &ACAssignment{
		ACID:    acID,
		Version: 2,
		AssignedServers: []ServerInfo{
			{ID: "i-green-b", IP: "10.0.1.2", InternalIP: "10.0.1.2", AZ: "us-east-2b", Port: 62206, PubKey: "pk-gb"},
			{ID: "i-green-c", IP: "10.0.1.3", InternalIP: "10.0.1.3", AZ: "us-east-2c", Port: 62206, PubKey: "pk-gc"},
		},
		CreatedAt: now,
		LastSeen:  now,
		TTL:       &ttl,
	}

	srv, mp := newColorTestServer(t, storage, cloudMap, "i-green-a", greenASG, "10.0.1.1")
	aolMsg := &common.ACOnlineMsg{ACId: acID}

	if _, _, err := srv.handleACServerAssignment(newACOnlinePPD(), aolMsg, 22222, "10.99.0.2:62206"); err != nil {
		t.Fatalf("handleACServerAssignment returned error: %v", err)
	}

	counters, _ := mp.CountersForTest(t)
	if counters[MetricACAssignmentColorMigration] != 0 {
		t.Errorf("expected %s=0 for same-color reconnect, got %v", MetricACAssignmentColorMigration, counters[MetricACAssignmentColorMigration])
	}

	storage.mu.Lock()
	saved := storage.assignments[acID]
	storage.mu.Unlock()
	if saved == nil {
		t.Fatal("assignment missing")
	}
	// add-self-keep-existing: self + the two existing greens.
	foundSelf := false
	for _, srvInfo := range saved.AssignedServers {
		if srvInfo.ID == "i-green-a" {
			foundSelf = true
		}
	}
	if !foundSelf {
		t.Error("expected self (i-green-a) added to assignment via updateAssignmentWithSelf")
	}
}

// TestHandleACServerAssignment_CrossColorSaveFailureDoesNotCountMigration pins
// the metric semantics: ACAssignmentColorMigration counts only DURABLE
// migrations. When cross-color is detected but autoAssignAC can't persist
// (version-conflict cap exhausted), the counter must NOT tick — otherwise the
// rollout-ledger alert ("sustained non-zero = assignments not converging")
// would fire on the very failure mode it is meant to detect, masking it.
func TestHandleACServerAssignment_CrossColorSaveFailureDoesNotCountMigration(t *testing.T) {
	const (
		blueASG  = "layerv-nhp-sandbox-server"
		greenASG = "layerv-nhp-sandbox-server-green"
		acID     = "layerv-ac-savefail"
	)
	cloudMap := &CloudMapClient{
		cachedInstances: []ServerInfo{
			{ID: "i-blue-a", IP: "10.0.0.1", InternalIP: "10.0.0.1", AZ: "us-east-2a", Port: 62206, PubKey: "pk-ba", ASGName: blueASG},
			{ID: "i-green-a", IP: "10.0.1.1", InternalIP: "10.0.1.1", AZ: "us-east-2a", Port: 62206, PubKey: "pk-ga", ASGName: greenASG},
			{ID: "i-green-b", IP: "10.0.1.2", InternalIP: "10.0.1.2", AZ: "us-east-2b", Port: 62206, PubKey: "pk-gb", ASGName: greenASG},
		},
		instancesExpiry: time.Now().Add(time.Hour),
	}

	storage := newMockStorageBackend()
	now := time.Now().Unix()
	ttl := now + AssignmentTTLSeconds
	storage.assignments[acID] = &ACAssignment{
		ACID:            acID,
		Version:         5,
		AssignedServers: []ServerInfo{{ID: "i-blue-a", IP: "10.0.0.1", InternalIP: "10.0.0.1", AZ: "us-east-2a", Port: 62206, PubKey: "pk-ba"}},
		CreatedAt:       now,
		LastSeen:        now,
		TTL:             &ttl,
	}
	// Force every SaveACAssignment to fail with a version conflict so
	// autoAssignAC exhausts its retry cap and falls through without persisting.
	storage.saveOverride = func(*ACAssignment) error {
		return NewVersionConflictError("forced conflict")
	}

	srv, mp := newColorTestServer(t, storage, cloudMap, "i-green-a", greenASG, "10.0.1.1")
	aolMsg := &common.ACOnlineMsg{ACId: acID}

	if _, _, err := srv.handleACServerAssignment(newACOnlinePPD(), aolMsg, 33333, "10.99.0.3:62206"); err != nil {
		t.Fatalf("handleACServerAssignment returned error: %v", err)
	}

	counters, _ := mp.CountersForTest(t)
	if counters[MetricACAssignmentColorMigration] != 0 {
		t.Errorf("expected %s=0 when the migration save failed (counts durable migrations only), got %v",
			MetricACAssignmentColorMigration, counters[MetricACAssignmentColorMigration])
	}
}

type assignmentAuthorityFailureStorage struct{ *mockStorageBackend }

func (s *assignmentAuthorityFailureStorage) GetACAssignment(context.Context, string) (*ACAssignment, error) {
	return nil, NewACAssignmentAuthorityError(errors.New("injected authority failure"))
}

func TestHandleACServerAssignmentCandidateAuthorityFailureDoesNotFallThrough(t *testing.T) {
	storage := &assignmentAuthorityFailureStorage{mockStorageBackend: newMockStorageBackend()}
	srv := &UdpServer{storage: storage}
	_, _, err := srv.handleACServerAssignment(
		newACOnlinePPD(),
		&common.ACOnlineMsg{ACId: "ac-candidate"},
		33334,
		"10.99.0.4:62206",
	)
	if !IsACAssignmentAuthorityError(err) {
		t.Fatalf("handleACServerAssignment error = %v, want candidate authority rejection", err)
	}
}

func TestAutoAssignACCandidateAuthoritySaveFailureDoesNotAcceptDirectly(t *testing.T) {
	const acID = "ac-candidate-save"
	cloudMap := &CloudMapClient{
		cachedInstances: []ServerInfo{{
			ID: "green-1", IP: "10.0.1.1", InternalIP: "10.0.1.1", AZ: "us-east-2a", Port: 62206, ASGName: "green",
		}},
		instancesExpiry: time.Now().Add(time.Hour),
	}
	storage := newMockStorageBackend()
	storage.saveOverride = func(*ACAssignment) error {
		return NewACAssignmentAuthorityError(errors.New("injected candidate write failure"))
	}
	srv, _ := newColorTestServer(t, storage, cloudMap, "green-1", "green", "10.0.1.1")
	_, err := srv.autoAssignAC(
		newACOnlinePPD(),
		&common.ACOnlineMsg{ACId: acID},
		33335,
		"10.99.0.5:62206",
		0,
		nil,
	)
	if !IsACAssignmentAuthorityError(err) {
		t.Fatalf("autoAssignAC error = %v, want candidate authority rejection", err)
	}
}

// TestHandleACServerAssignment_SuppressesCrossColorMigrationWhenTargetWouldShrinkCoverage
// fences the qURL timeout class seen in sandbox: a shared ACId had a healthy
// three-server assignment, but a cross-color registration rewrote it to the one
// visible server in the other color. qURL admission then reached only that
// server's AC connection while browser traffic landed on a different active AC.
func TestHandleACServerAssignment_SuppressesCrossColorMigrationWhenTargetWouldShrinkCoverage(t *testing.T) {
	const (
		blueASG  = "layerv-nhp-sandbox-server"
		greenASG = "layerv-nhp-sandbox-server-green"
		acID     = "layerv-ac-shrink"
	)
	cloudMap := &CloudMapClient{
		cachedInstances: []ServerInfo{
			{ID: "i-blue-a", IP: "10.0.0.1", InternalIP: "10.0.0.1", AZ: "us-east-2a", Port: 62206, PubKey: "pk-ba", ASGName: blueASG},
			{ID: "i-blue-b", IP: "10.0.0.2", InternalIP: "10.0.0.2", AZ: "us-east-2b", Port: 62206, PubKey: "pk-bb", ASGName: blueASG},
			{ID: "i-blue-c", IP: "10.0.0.3", InternalIP: "10.0.0.3", AZ: "us-east-2c", Port: 62206, PubKey: "pk-bc", ASGName: blueASG},
			{ID: "i-green-a", IP: "10.0.1.1", InternalIP: "10.0.1.1", AZ: "us-east-2a", Port: 62206, PubKey: "pk-ga", ASGName: greenASG},
		},
		instancesExpiry: time.Now().Add(time.Hour),
	}

	storage := newMockStorageBackend()
	now := time.Now().Unix()
	ttl := now + AssignmentTTLSeconds
	storage.assignments[acID] = &ACAssignment{
		ACID:    acID,
		Version: 5,
		AssignedServers: []ServerInfo{
			{ID: "i-blue-a", IP: "10.0.0.1", InternalIP: "10.0.0.1", AZ: "us-east-2a", Port: 62206, PubKey: "pk-ba"},
			{ID: "i-blue-b", IP: "10.0.0.2", InternalIP: "10.0.0.2", AZ: "us-east-2b", Port: 62206, PubKey: "pk-bb"},
			{ID: "i-blue-c", IP: "10.0.0.3", InternalIP: "10.0.0.3", AZ: "us-east-2c", Port: 62206, PubKey: "pk-bc"},
		},
		CreatedAt: now,
		LastSeen:  now,
		TTL:       &ttl,
	}

	srv, mp := newColorTestServer(t, storage, cloudMap, "i-green-a", greenASG, "10.0.1.1")
	aolMsg := &common.ACOnlineMsg{ACId: acID}

	redirected, peers, err := srv.handleACServerAssignment(newACOnlinePPD(), aolMsg, 55555, "10.99.0.5:62206")
	if err != nil {
		t.Fatalf("handleACServerAssignment returned error: %v", err)
	}
	if !redirected {
		t.Fatal("expected suppressed migration to redirect/fail closed instead of accepting locally")
	}
	if peers != nil {
		t.Fatalf("expected no assigned peers on redirected path, got %d", len(peers))
	}
	srv.wg.Wait()

	storage.mu.Lock()
	saved := storage.assignments[acID]
	storage.mu.Unlock()
	if saved == nil {
		t.Fatal("assignment missing after suppressed migration")
	}
	if saved.Version != 6 {
		t.Errorf("expected Version to refresh to 6, got %d", saved.Version)
	}
	if len(saved.AssignedServers) != MaxServersPerAssignment {
		t.Fatalf("expected existing %d-server assignment to remain intact, got %d", MaxServersPerAssignment, len(saved.AssignedServers))
	}
	for _, srvInfo := range saved.AssignedServers {
		if srvInfo.ID == "i-green-a" {
			t.Fatal("coverage-shrinking green singleton was persisted")
		}
	}

	counters, _ := mp.CountersForTest(t)
	if counters[MetricACAssignmentColorMigration] != 0 {
		t.Errorf("expected %s=0 when migration is suppressed, got %v", MetricACAssignmentColorMigration, counters[MetricACAssignmentColorMigration])
	}
	if counters[MetricACAssignmentColorMigrationSuppressed] != 1 {
		t.Errorf("expected %s=1, got %v", MetricACAssignmentColorMigrationSuppressed, counters[MetricACAssignmentColorMigrationSuppressed])
	}
}

func TestHandleACServerAssignment_SuppressesCrossColorMigrationWhenTargetWouldLoseAZCoverage(t *testing.T) {
	const (
		blueASG  = "layerv-nhp-sandbox-server"
		greenASG = "layerv-nhp-sandbox-server-green"
		acID     = "layerv-ac-az-shrink"
	)
	cloudMap := &CloudMapClient{
		cachedInstances: []ServerInfo{
			{ID: "i-blue-a", IP: "10.0.0.1", InternalIP: "10.0.0.1", AZ: "us-east-2a", Port: 62206, PubKey: "pk-ba", ASGName: blueASG},
			{ID: "i-blue-b", IP: "10.0.0.2", InternalIP: "10.0.0.2", AZ: "us-east-2b", Port: 62206, PubKey: "pk-bb", ASGName: blueASG},
			{ID: "i-blue-c", IP: "10.0.0.3", InternalIP: "10.0.0.3", AZ: "us-east-2c", Port: 62206, PubKey: "pk-bc", ASGName: blueASG},
			// Three dialable green targets, but all in one AZ. That would
			// preserve count while losing the one-pinhole-per-AZ invariant.
			{ID: "i-green-a", IP: "10.0.1.1", InternalIP: "10.0.1.1", AZ: "us-east-2a", Port: 62206, PubKey: "pk-ga", ASGName: greenASG},
			{ID: "i-green-b", IP: "10.0.1.2", InternalIP: "10.0.1.2", AZ: "us-east-2a", Port: 62206, PubKey: "pk-gb", ASGName: greenASG},
			{ID: "i-green-c", IP: "10.0.1.3", InternalIP: "10.0.1.3", AZ: "us-east-2a", Port: 62206, PubKey: "pk-gc", ASGName: greenASG},
		},
		instancesExpiry: time.Now().Add(time.Hour),
	}

	storage := newMockStorageBackend()
	now := time.Now().Unix()
	ttl := now + AssignmentTTLSeconds
	storage.assignments[acID] = &ACAssignment{
		ACID:    acID,
		Version: 8,
		AssignedServers: []ServerInfo{
			{ID: "i-blue-a", IP: "10.0.0.1", InternalIP: "10.0.0.1", AZ: "us-east-2a", Port: 62206, PubKey: "pk-ba"},
			{ID: "i-blue-b", IP: "10.0.0.2", InternalIP: "10.0.0.2", AZ: "us-east-2b", Port: 62206, PubKey: "pk-bb"},
			{ID: "i-blue-c", IP: "10.0.0.3", InternalIP: "10.0.0.3", AZ: "us-east-2c", Port: 62206, PubKey: "pk-bc"},
		},
		CreatedAt: now,
		LastSeen:  now,
		TTL:       &ttl,
	}

	srv, mp := newColorTestServer(t, storage, cloudMap, "i-green-a", greenASG, "10.0.1.1")
	aolMsg := &common.ACOnlineMsg{ACId: acID}

	redirected, _, err := srv.handleACServerAssignment(newACOnlinePPD(), aolMsg, 55556, "10.99.0.6:62206")
	if err != nil {
		t.Fatalf("handleACServerAssignment returned error: %v", err)
	}
	if !redirected {
		t.Fatal("expected AZ-coverage-losing migration to be suppressed")
	}
	srv.wg.Wait()

	storage.mu.Lock()
	saved := storage.assignments[acID]
	storage.mu.Unlock()
	if saved.Version != 9 {
		t.Errorf("expected Version to refresh to 9, got %d", saved.Version)
	}
	for _, srvInfo := range saved.AssignedServers {
		if srvInfo.ASGName == greenASG || srvInfo.ID == "i-green-a" || srvInfo.ID == "i-green-b" || srvInfo.ID == "i-green-c" {
			t.Fatalf("AZ-coverage-losing green assignment was persisted: %v", saved.AssignedServers)
		}
	}

	counters, _ := mp.CountersForTest(t)
	if counters[MetricACAssignmentColorMigrationSuppressed] != 1 {
		t.Errorf("expected %s=1, got %v", MetricACAssignmentColorMigrationSuppressed, counters[MetricACAssignmentColorMigrationSuppressed])
	}
}

// TestHandleACServerAssignment_MigratesWhenSelfNotYetInSnapshot fences the
// subtlest edge of the migration path: when this server (the answering
// new-color server) has not yet propagated to Cloud Map, the wholesale
// reassign builds the new assignment from a complete visible new-color set and
// can legitimately EXCLUDE self. The result must still be all-new-color (never
// re-create a cross-color set) and preserve coverage; the AC picks up self on a
// later re-registration once it propagates.
func TestHandleACServerAssignment_MigratesWhenSelfNotYetInSnapshot(t *testing.T) {
	const (
		blueASG  = "layerv-nhp-sandbox-server"
		greenASG = "layerv-nhp-sandbox-server-green"
		acID     = "layerv-ac-selfmissing"
	)
	// Cloud Map shows the old (blue) servers + three NEW (green) servers, but
	// NOT this server (i-green-a) — it hasn't registered/propagated yet.
	cloudMap := &CloudMapClient{
		cachedInstances: []ServerInfo{
			{ID: "i-blue-a", IP: "10.0.0.1", InternalIP: "10.0.0.1", AZ: "us-east-2a", Port: 62206, PubKey: "pk-ba", ASGName: blueASG},
			{ID: "i-blue-b", IP: "10.0.0.2", InternalIP: "10.0.0.2", AZ: "us-east-2b", Port: 62206, PubKey: "pk-bb", ASGName: blueASG},
			{ID: "i-blue-c", IP: "10.0.0.3", InternalIP: "10.0.0.3", AZ: "us-east-2c", Port: 62206, PubKey: "pk-bc", ASGName: blueASG},
			{ID: "i-green-d", IP: "10.0.1.4", InternalIP: "10.0.1.4", AZ: "us-east-2a", Port: 62206, PubKey: "pk-gd", ASGName: greenASG},
			{ID: "i-green-b", IP: "10.0.1.2", InternalIP: "10.0.1.2", AZ: "us-east-2b", Port: 62206, PubKey: "pk-gb", ASGName: greenASG},
			{ID: "i-green-c", IP: "10.0.1.3", InternalIP: "10.0.1.3", AZ: "us-east-2c", Port: 62206, PubKey: "pk-gc", ASGName: greenASG},
		},
		instancesExpiry: time.Now().Add(time.Hour),
	}

	storage := newMockStorageBackend()
	now := time.Now().Unix()
	ttl := now + AssignmentTTLSeconds
	storage.assignments[acID] = &ACAssignment{
		ACID:    acID,
		Version: 5,
		AssignedServers: []ServerInfo{
			{ID: "i-blue-a", IP: "10.0.0.1", InternalIP: "10.0.0.1", AZ: "us-east-2a", Port: 62206, PubKey: "pk-ba"},
			{ID: "i-blue-b", IP: "10.0.0.2", InternalIP: "10.0.0.2", AZ: "us-east-2b", Port: 62206, PubKey: "pk-bb"},
			{ID: "i-blue-c", IP: "10.0.0.3", InternalIP: "10.0.0.3", AZ: "us-east-2c", Port: 62206, PubKey: "pk-bc"},
		},
		CreatedAt: now,
		LastSeen:  now,
		TTL:       &ttl,
	}

	// Answering server is i-green-a, which is NOT in the Cloud Map snapshot.
	srv, mp := newColorTestServer(t, storage, cloudMap, "i-green-a", greenASG, "10.0.1.1")
	aolMsg := &common.ACOnlineMsg{ACId: acID}

	if _, _, err := srv.handleACServerAssignment(newACOnlinePPD(), aolMsg, 44444, "10.99.0.4:62206"); err != nil {
		t.Fatalf("handleACServerAssignment returned error: %v", err)
	}

	storage.mu.Lock()
	saved := storage.assignments[acID]
	storage.mu.Unlock()
	if saved == nil {
		t.Fatal("assignment missing after migration")
	}
	if len(saved.AssignedServers) == 0 {
		t.Fatal("migration produced an empty assignment")
	}
	if len(saved.AssignedServers) != MaxServersPerAssignment {
		t.Fatalf("expected migration to preserve %d-server coverage, got %d", MaxServersPerAssignment, len(saved.AssignedServers))
	}
	// All NEW color, no blue survivors → never cross-color.
	blueIDs := map[string]bool{"i-blue-a": true, "i-blue-b": true, "i-blue-c": true}
	for _, srvInfo := range saved.AssignedServers {
		if blueIDs[srvInfo.ID] {
			t.Errorf("old-color server %s survived migration", srvInfo.ID)
		}
		// Self legitimately absent: it's not in the snapshot, so
		// selectServersForAssignment can't inject it (documented edge).
		if srvInfo.ID == "i-green-a" {
			t.Error("did not expect self (i-green-a) in the assignment when it is absent from the Cloud Map snapshot")
		}
	}
	// The reassign still persisted, so the migration counter ticks once.
	counters, _ := mp.CountersForTest(t)
	if counters[MetricACAssignmentColorMigration] != 1 {
		t.Errorf("expected %s=1 (durable migration persisted), got %v", MetricACAssignmentColorMigration, counters[MetricACAssignmentColorMigration])
	}
}

// TestAssignmentIsCrossColor_FailSafePaths confirms the detector returns false
// (preserving the legacy add-self-keep-existing path) on every uncertain
// input, so it never churns assignments when color can't be established.
func TestAssignmentIsCrossColor_FailSafePaths(t *testing.T) {
	const greenASG = "layerv-nhp-sandbox-server-green"
	blueAssigned := []ServerInfo{{ID: "i-blue-a", IP: "10.0.0.1", InternalIP: "10.0.0.1"}}

	bothColors := &CloudMapClient{
		cachedInstances: []ServerInfo{
			{ID: "i-blue-a", IP: "10.0.0.1", InternalIP: "10.0.0.1", AZ: "us-east-2a", ASGName: "layerv-nhp-sandbox-server"},
			{ID: "i-green-a", IP: "10.0.1.1", InternalIP: "10.0.1.1", AZ: "us-east-2a", ASGName: greenASG},
		},
		instancesExpiry: time.Now().Add(time.Hour),
	}
	// Non-nil but empty cached slice → DiscoverServerInstances returns an
	// empty list from the cache (no live AWS call), exercising the
	// "discovery error/empty result → false" branch.
	emptyDiscovery := &CloudMapClient{
		cachedInstances: []ServerInfo{},
		instancesExpiry: time.Now().Add(time.Hour),
	}
	// Every candidate is a different color than self (green) and none has an
	// empty ASGName, so filterServersByASG fails open — a realistic deploy
	// window where the new color hasn't propagated to Cloud Map yet. The
	// detector must still return false (never churn on an unreliable view).
	allCrossColor := &CloudMapClient{
		cachedInstances: []ServerInfo{
			{ID: "i-blue-a", IP: "10.0.0.1", InternalIP: "10.0.0.1", AZ: "us-east-2a", ASGName: "layerv-nhp-sandbox-server"},
			{ID: "i-blue-b", IP: "10.0.0.2", InternalIP: "10.0.0.2", AZ: "us-east-2b", ASGName: "layerv-nhp-sandbox-server"},
		},
		instancesExpiry: time.Now().Add(time.Hour),
	}

	tests := []struct {
		name     string
		srv      *UdpServer
		assigned []ServerInfo
		want     bool
	}{
		{
			name:     "nil cloud map → false",
			srv:      &UdpServer{cloudMap: nil, asgName: greenASG},
			assigned: blueAssigned,
			want:     false,
		},
		{
			name:     "empty input → false",
			srv:      &UdpServer{cloudMap: bothColors, asgName: greenASG},
			assigned: nil,
			want:     false,
		},
		{
			name:     "own ASG unknown → false",
			srv:      &UdpServer{cloudMap: bothColors, asgName: ""},
			assigned: blueAssigned,
			want:     false,
		},
		{
			name: "all assigned same color → false",
			srv:  &UdpServer{cloudMap: bothColors, asgName: greenASG},
			assigned: []ServerInfo{
				{ID: "i-green-a", IP: "10.0.1.1", InternalIP: "10.0.1.1"},
			},
			want: false,
		},
		{
			name:     "discovery returns empty → false",
			srv:      &UdpServer{cloudMap: emptyDiscovery, asgName: greenASG},
			assigned: blueAssigned,
			want:     false,
		},
		{
			name:     "ASG filter fail-open (all candidates cross-color) → false",
			srv:      &UdpServer{cloudMap: allCrossColor, asgName: greenASG},
			assigned: blueAssigned,
			want:     false,
		},
		{
			name: "assigned server with no IP → skipped, not treated as cross-color",
			srv:  &UdpServer{cloudMap: bothColors, asgName: greenASG},
			assigned: []ServerInfo{
				{ID: "i-green-a", IP: "10.0.1.1", InternalIP: "10.0.1.1"}, // same color
				{ID: "i-ghost"}, // no IP at all
			},
			want: false,
		},
		{
			name:     "genuine cross-color → true",
			srv:      &UdpServer{cloudMap: bothColors, asgName: greenASG},
			assigned: blueAssigned,
			want:     true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, discovered := tc.srv.assignmentIsCrossColor(context.Background(), tc.assigned)
			if got != tc.want {
				t.Errorf("assignmentIsCrossColor = %v, want %v", got, tc.want)
			}
			// The discovered snapshot is returned only on a true result (for the
			// caller to reuse) and must be nil otherwise.
			if got && discovered == nil {
				t.Error("expected discovered snapshot on a true result, got nil")
			}
			if !got && discovered != nil {
				t.Errorf("expected nil discovered snapshot on a false result, got %d servers", len(discovered))
			}
		})
	}
}

// TestRefreshAssignmentTTL_GrowsUnderfilledAssignment fences issue #1681.
// When a stored assignment has fewer than MaxServersPerAssignment servers
// and Cloud Map shows additional healthy servers (e.g., a us-east-2c that
// registered after the assignment was created), the next TTL refresh must
// converge by adding the new server. Without growth, an assignment created
// when only N<3 servers were healthy stays at N forever — re-registrations
// to the assigned servers see "this server is in the set, return the set"
// and the missing server never gets added (the prod symptom in #1681).
func TestRefreshAssignmentTTL_GrowsUnderfilledAssignment(t *testing.T) {
	cloudMap := &CloudMapClient{
		cachedInstances: []ServerInfo{
			{ID: "i-a", IP: "10.0.0.1", InternalIP: "10.0.0.1", AZ: "us-east-2a", Port: 62206, PubKey: "pk-a"},
			{ID: "i-b", IP: "10.0.0.2", InternalIP: "10.0.0.2", AZ: "us-east-2b", Port: 62206, PubKey: "pk-b"},
			{ID: "i-c", IP: "10.0.0.3", InternalIP: "10.0.0.3", AZ: "us-east-2c", Port: 62206, PubKey: "pk-c"},
		},
		instancesExpiry: time.Now().Add(time.Hour),
	}

	storage := newMockStorageBackend()
	now := time.Now().Unix()
	ttl := now + AssignmentTTLSeconds
	storage.assignments["ac-grow"] = &ACAssignment{
		ACID:    "ac-grow",
		Version: 5,
		AssignedServers: []ServerInfo{
			{ID: "i-a", IP: "10.0.0.1", InternalIP: "10.0.0.1", AZ: "us-east-2a", Port: 62206, PubKey: "pk-a"},
			{ID: "i-b", IP: "10.0.0.2", InternalIP: "10.0.0.2", AZ: "us-east-2b", Port: 62206, PubKey: "pk-b"},
		},
		LastSeen: now,
		TTL:      &ttl,
	}

	srv := &UdpServer{
		storage:    storage,
		cloudMap:   cloudMap,
		instanceID: "i-a",
		config:     &Config{Hostname: "test", ListenPort: 62206},
	}

	srv.refreshAssignmentTTL("ac-grow")
	srv.wg.Wait() // refresh runs in a goroutine

	storage.mu.Lock()
	defer storage.mu.Unlock()
	saved := storage.assignments["ac-grow"]
	if len(saved.AssignedServers) != MaxServersPerAssignment {
		t.Fatalf("expected %d assigned servers after grow, got %d", MaxServersPerAssignment, len(saved.AssignedServers))
	}
	ids := map[string]bool{}
	for _, s := range saved.AssignedServers {
		ids[s.ID] = true
	}
	for _, want := range []string{"i-a", "i-b", "i-c"} {
		if !ids[want] {
			t.Errorf("expected grown assignment to contain %s, got %v", want, ids)
		}
	}
	if saved.Version != 6 {
		t.Errorf("expected Version=6 (existing+1), got %d", saved.Version)
	}
}

// TestRefreshAssignmentTTL_NoGrowAtMax verifies the no-op path: once the
// assignment is at MaxServersPerAssignment, refresh bumps version+TTL only
// (no Cloud Map call needed beyond the discovery cache check).
func TestRefreshAssignmentTTL_NoGrowAtMax(t *testing.T) {
	cloudMap := &CloudMapClient{
		cachedInstances: []ServerInfo{
			{ID: "i-a", IP: "10.0.0.1", InternalIP: "10.0.0.1", AZ: "us-east-2a", Port: 62206, PubKey: "pk-a"},
			{ID: "i-b", IP: "10.0.0.2", InternalIP: "10.0.0.2", AZ: "us-east-2b", Port: 62206, PubKey: "pk-b"},
			{ID: "i-c", IP: "10.0.0.3", InternalIP: "10.0.0.3", AZ: "us-east-2c", Port: 62206, PubKey: "pk-c"},
			{ID: "i-d", IP: "10.0.0.4", InternalIP: "10.0.0.4", AZ: "us-east-2a", Port: 62206, PubKey: "pk-d"},
		},
		instancesExpiry: time.Now().Add(time.Hour),
	}

	storage := newMockStorageBackend()
	now := time.Now().Unix()
	ttl := now + AssignmentTTLSeconds
	original := []ServerInfo{
		{ID: "i-a", IP: "10.0.0.1", AZ: "us-east-2a", Port: 62206, PubKey: "pk-a"},
		{ID: "i-b", IP: "10.0.0.2", AZ: "us-east-2b", Port: 62206, PubKey: "pk-b"},
		{ID: "i-c", IP: "10.0.0.3", AZ: "us-east-2c", Port: 62206, PubKey: "pk-c"},
	}
	storage.assignments["ac-full"] = &ACAssignment{
		ACID:            "ac-full",
		Version:         3,
		AssignedServers: original,
		LastSeen:        now,
		TTL:             &ttl,
	}

	srv := &UdpServer{
		storage:    storage,
		cloudMap:   cloudMap,
		instanceID: "i-a",
		config:     &Config{Hostname: "test", ListenPort: 62206},
	}

	srv.refreshAssignmentTTL("ac-full")
	srv.wg.Wait()

	storage.mu.Lock()
	defer storage.mu.Unlock()
	saved := storage.assignments["ac-full"]
	if len(saved.AssignedServers) != MaxServersPerAssignment {
		t.Errorf("expected len unchanged at %d, got %d", MaxServersPerAssignment, len(saved.AssignedServers))
	}
	if saved.Version != 4 {
		t.Errorf("expected Version=4 (existing+1), got %d", saved.Version)
	}
}

func TestRefreshAssignmentTTLOnly_DoesNotGrowFromCurrentColor(t *testing.T) {
	const (
		blueASG  = "layerv-nhp-sandbox-server"
		greenASG = "layerv-nhp-sandbox-server-green"
	)
	cloudMap := &CloudMapClient{
		cachedInstances: []ServerInfo{
			{ID: "i-green-a", IP: "10.0.1.1", InternalIP: "10.0.1.1", AZ: "us-east-2a", Port: 62206, PubKey: "pk-ga", ASGName: greenASG},
			{ID: "i-green-b", IP: "10.0.1.2", InternalIP: "10.0.1.2", AZ: "us-east-2b", Port: 62206, PubKey: "pk-gb", ASGName: greenASG},
		},
		instancesExpiry: time.Now().Add(time.Hour),
	}

	storage := newMockStorageBackend()
	now := time.Now().Unix()
	ttl := now + AssignmentTTLSeconds
	storage.assignments["ac-suppressed"] = &ACAssignment{
		ACID:    "ac-suppressed",
		Version: 1,
		AssignedServers: []ServerInfo{
			{ID: "i-blue-a", IP: "10.0.0.1", InternalIP: "10.0.0.1", AZ: "us-east-2a", Port: 62206, PubKey: "pk-ba", ASGName: blueASG},
		},
		LastSeen: now,
		TTL:      &ttl,
	}
	srv := &UdpServer{
		storage:  storage,
		cloudMap: cloudMap,
		asgName:  greenASG,
		config:   &Config{Hostname: "test", ListenPort: 62206},
	}

	srv.refreshAssignmentTTLOnly("ac-suppressed")
	srv.wg.Wait()

	storage.mu.Lock()
	defer storage.mu.Unlock()
	saved := storage.assignments["ac-suppressed"]
	if saved.Version != 2 {
		t.Fatalf("Version = %d, want TTL-only refresh to bump to 2", saved.Version)
	}
	if len(saved.AssignedServers) != 1 || saved.AssignedServers[0].ID != "i-blue-a" {
		t.Fatalf("TTL-only refresh grew or changed suppressed assignment: %+v", saved.AssignedServers)
	}
}

// TestRefreshAssignmentTTL_SkipsCrossASGCandidates verifies growth respects
// the blue/green ASG filter — a green-color server must not be added to a
// blue-color assignment during a deploy when both ASGs share Cloud Map.
func TestRefreshAssignmentTTL_SkipsCrossASGCandidates(t *testing.T) {
	cloudMap := &CloudMapClient{
		cachedInstances: []ServerInfo{
			{ID: "i-blue-a", IP: "10.0.0.1", AZ: "us-east-2a", Port: 62206, PubKey: "pk-a", ASGName: "layerv-nhp-prod-server"},
			{ID: "i-blue-b", IP: "10.0.0.2", AZ: "us-east-2b", Port: 62206, PubKey: "pk-b", ASGName: "layerv-nhp-prod-server"},
			{ID: "i-green-a", IP: "10.0.0.3", AZ: "us-east-2a", Port: 62206, PubKey: "pk-ga", ASGName: "layerv-nhp-prod-server-green"},
			{ID: "i-green-c", IP: "10.0.0.4", AZ: "us-east-2c", Port: 62206, PubKey: "pk-gc", ASGName: "layerv-nhp-prod-server-green"},
		},
		instancesExpiry: time.Now().Add(time.Hour),
	}

	storage := newMockStorageBackend()
	now := time.Now().Unix()
	ttl := now + AssignmentTTLSeconds
	storage.assignments["ac-blue"] = &ACAssignment{
		ACID:    "ac-blue",
		Version: 1,
		AssignedServers: []ServerInfo{
			{ID: "i-blue-a", IP: "10.0.0.1", AZ: "us-east-2a", Port: 62206, PubKey: "pk-a"},
		},
		LastSeen: now,
		TTL:      &ttl,
	}

	srv := &UdpServer{
		storage:    storage,
		cloudMap:   cloudMap,
		instanceID: "i-blue-a",
		asgName:    "layerv-nhp-prod-server",
		config:     &Config{Hostname: "test", ListenPort: 62206},
	}

	srv.refreshAssignmentTTL("ac-blue")
	srv.wg.Wait()

	storage.mu.Lock()
	defer storage.mu.Unlock()
	saved := storage.assignments["ac-blue"]
	for _, s := range saved.AssignedServers {
		if s.ID == "i-green-a" || s.ID == "i-green-c" {
			t.Errorf("cross-ASG server %s leaked into blue assignment", s.ID)
		}
	}
	// Should have grown to include i-blue-b (the only blue candidate)
	wantIDs := map[string]bool{"i-blue-a": true, "i-blue-b": true}
	for _, s := range saved.AssignedServers {
		if !wantIDs[s.ID] {
			t.Errorf("unexpected server %s in blue assignment", s.ID)
		}
	}
	if len(saved.AssignedServers) != 2 {
		t.Errorf("expected 2 blue servers (no green leakage), got %d: %v", len(saved.AssignedServers), saved.AssignedServers)
	}
}

// TestRefreshAssignmentTTL_SkipsCandidatesWithoutPubKey verifies that
// growth never persists a server whose Cloud Map registration hasn't
// completed (PUBLIC_KEY attribute empty). serverInfosToRedirectTargets
// would otherwise hand the AC a target it would drop on validation.
func TestRefreshAssignmentTTL_SkipsCandidatesWithoutPubKey(t *testing.T) {
	cloudMap := &CloudMapClient{
		cachedInstances: []ServerInfo{
			{ID: "i-a", IP: "10.0.0.1", AZ: "us-east-2a", Port: 62206, PubKey: "pk-a"},
			{ID: "i-no-key", IP: "10.0.0.99", AZ: "us-east-2c", Port: 62206 /* PubKey deliberately empty */},
		},
		instancesExpiry: time.Now().Add(time.Hour),
	}

	storage := newMockStorageBackend()
	now := time.Now().Unix()
	ttl := now + AssignmentTTLSeconds
	storage.assignments["ac-no-key"] = &ACAssignment{
		ACID:    "ac-no-key",
		Version: 1,
		AssignedServers: []ServerInfo{
			{ID: "i-a", IP: "10.0.0.1", AZ: "us-east-2a", Port: 62206, PubKey: "pk-a"},
		},
		LastSeen: now,
		TTL:      &ttl,
	}

	srv := &UdpServer{
		storage:    storage,
		cloudMap:   cloudMap,
		instanceID: "i-a",
		config:     &Config{Hostname: "test", ListenPort: 62206},
	}

	srv.refreshAssignmentTTL("ac-no-key")
	srv.wg.Wait()

	storage.mu.Lock()
	defer storage.mu.Unlock()
	saved := storage.assignments["ac-no-key"]
	for _, s := range saved.AssignedServers {
		if s.ID == "i-no-key" {
			t.Errorf("server with empty PubKey leaked into assignment")
		}
	}
}

// TestSaveACAssignment_MockEnforcesVersionConflict fences the regression
// class that #1681 surfaced: refreshAssignmentTTL pre-fix did not bump
// Version, so SaveACAssignment with the same Version was a silent no-op
// against real DDB but appeared to succeed against an unconditional mock.
// The mock now mirrors DDB's `version = expected-1` invariant, so any
// future refresh-path code path that forgets the bump fails its tests.
func TestSaveACAssignment_MockEnforcesVersionConflict(t *testing.T) {
	storage := newMockStorageBackend()
	ctx := context.Background()
	if err := storage.SaveACAssignment(ctx, &ACAssignment{ACID: "ac-cas", Version: 1}); err != nil {
		t.Fatalf("first save (Version=1): %v", err)
	}
	// Save with same Version must conflict (mirrors DDB rejection of a
	// Version-not-bumped overwrite).
	err := storage.SaveACAssignment(ctx, &ACAssignment{ACID: "ac-cas", Version: 1})
	if !IsVersionConflictError(err) {
		t.Errorf("expected VersionConflictError on Save without bump, got %v", err)
	}
	// Save with correct +1 bump succeeds.
	if err := storage.SaveACAssignment(ctx, &ACAssignment{ACID: "ac-cas", Version: 2}); err != nil {
		t.Errorf("expected Save with bumped Version to succeed, got %v", err)
	}
}

// TestRefreshAssignmentTTL_RefusesGrowOnASGFailOpen verifies the fail-open
// safety check: when filterServersByASG would fail open (Cloud Map shows
// only cross-color servers, e.g. during the blue-rotates-out / green-rotates-in
// transition of a deploy), maybeGrowAssignedServers must refuse to grow
// rather than persisting cross-color contamination across the TTL window.
// Symmetric to TestRefreshAssignmentTTL_SkipsCrossASGCandidates, which
// covers the *normal* (mixed cross-color) case.
func TestRefreshAssignmentTTL_RefusesGrowOnASGFailOpen(t *testing.T) {
	cloudMap := &CloudMapClient{
		cachedInstances: []ServerInfo{
			// Only green servers visible — blue siblings rotated out.
			{ID: "i-green-a", IP: "10.0.0.3", AZ: "us-east-2a", Port: 62206, PubKey: "pk-ga", ASGName: "layerv-nhp-prod-server-green"},
			{ID: "i-green-c", IP: "10.0.0.4", AZ: "us-east-2c", Port: 62206, PubKey: "pk-gc", ASGName: "layerv-nhp-prod-server-green"},
		},
		instancesExpiry: time.Now().Add(time.Hour),
	}

	storage := newMockStorageBackend()
	now := time.Now().Unix()
	ttl := now + AssignmentTTLSeconds
	storage.assignments["ac-blue"] = &ACAssignment{
		ACID:    "ac-blue",
		Version: 1,
		AssignedServers: []ServerInfo{
			{ID: "i-blue-a", IP: "10.0.0.1", AZ: "us-east-2a", Port: 62206, PubKey: "pk-a"},
		},
		LastSeen: now,
		TTL:      &ttl,
	}

	srv := &UdpServer{
		storage:    storage,
		cloudMap:   cloudMap,
		instanceID: "i-blue-a",
		asgName:    "layerv-nhp-prod-server",
		config:     &Config{Hostname: "test", ListenPort: 62206},
	}

	srv.refreshAssignmentTTL("ac-blue")
	srv.wg.Wait()

	storage.mu.Lock()
	defer storage.mu.Unlock()
	saved := storage.assignments["ac-blue"]
	if len(saved.AssignedServers) != 1 {
		t.Errorf("expected no growth under ASG fail-open, got %d servers: %v", len(saved.AssignedServers), saved.AssignedServers)
	}
	for _, s := range saved.AssignedServers {
		if s.ID != "i-blue-a" {
			t.Errorf("cross-ASG server %s leaked into blue assignment under fail-open", s.ID)
		}
	}
}

// TestRefreshAssignmentTTL_NoGrowWhenNoNewCandidates verifies the cleanly-
// no-grow path: when every server Cloud Map returns is already in the
// assignment, additions stays empty and the function returns (current, false)
// so refreshAssignmentTTL still bumps version+TTL but doesn't churn the
// AssignedServers list. Behaviorally equivalent to the discovery-error path
// (both exit at the no-additions early return), so this test fences both.
func TestRefreshAssignmentTTL_NoGrowWhenNoNewCandidates(t *testing.T) {
	cloudMap := &CloudMapClient{
		cachedInstances: []ServerInfo{
			{ID: "i-a", IP: "10.0.0.1", AZ: "us-east-2a", Port: 62206, PubKey: "pk-a"},
		},
		instancesExpiry: time.Now().Add(time.Hour),
	}

	storage := newMockStorageBackend()
	now := time.Now().Unix()
	ttl := now + AssignmentTTLSeconds
	storage.assignments["ac-noop"] = &ACAssignment{
		ACID:    "ac-noop",
		Version: 1,
		AssignedServers: []ServerInfo{
			{ID: "i-a", IP: "10.0.0.1", AZ: "us-east-2a", Port: 62206, PubKey: "pk-a"},
		},
		LastSeen: now,
		TTL:      &ttl,
	}

	srv := &UdpServer{
		storage:    storage,
		cloudMap:   cloudMap,
		instanceID: "i-a",
		config:     &Config{Hostname: "test", ListenPort: 62206},
	}

	srv.refreshAssignmentTTL("ac-noop")
	srv.wg.Wait()

	storage.mu.Lock()
	defer storage.mu.Unlock()
	saved := storage.assignments["ac-noop"]
	// Assignment should be unchanged in size; version should still bump
	// (TTL refresh succeeded even though growth had nothing to add).
	if len(saved.AssignedServers) != 1 {
		t.Errorf("expected unchanged size when no growth candidates, got %d", len(saved.AssignedServers))
	}
	if saved.Version != 2 {
		t.Errorf("expected Version=2 (TTL refresh still bumps), got %d", saved.Version)
	}
}

// TestRefreshAssignmentTTL_VersionConflictEmitsRefreshMetric fences the
// cr round-3 metric split: when SaveACAssignment returns a VersionConflictError
// in the refresh path (another server raced ahead), the refresh path swallows
// the error and emits MetricACAssignmentRefreshVersionConflict — NOT
// MetricACAssignmentVersionConflictRetry (which is scoped to the retry-loop
// in saveAssignmentWithRetry). Without this fence a future refactor that
// regresses to the shared metric would silently inflate the contention-load
// alarm.
func TestRefreshAssignmentTTL_VersionConflictEmitsRefreshMetric(t *testing.T) {
	cloudMap := &CloudMapClient{
		cachedInstances: []ServerInfo{
			{ID: "i-a", IP: "10.0.0.1", AZ: "us-east-2a", Port: 62206, PubKey: "pk-a"},
		},
		instancesExpiry: time.Now().Add(time.Hour),
	}

	storage := newMockStorageBackend()
	now := time.Now().Unix()
	ttl := now + AssignmentTTLSeconds
	storage.assignments["ac-conflict"] = &ACAssignment{
		ACID:    "ac-conflict",
		Version: 3,
		AssignedServers: []ServerInfo{
			{ID: "i-a", IP: "10.0.0.1", AZ: "us-east-2a", Port: 62206, PubKey: "pk-a"},
		},
		LastSeen: now,
		TTL:      &ttl,
	}
	// Inject a deterministic VersionConflict on Save — simulates a racing
	// server that bumped Version between this refresh's GetACAssignment and
	// SaveACAssignment.
	storage.saveOverride = func(_ *ACAssignment) error {
		return NewVersionConflictError("simulated concurrent refresh from another server")
	}

	mp := metrics.NewPublisherForTest(t)
	srv := &UdpServer{
		storage:    storage,
		cloudMap:   cloudMap,
		instanceID: "i-a",
		config:     &Config{Hostname: "test", ListenPort: 62206},
		metrics:    mp,
	}

	srv.refreshAssignmentTTL("ac-conflict")
	srv.wg.Wait()

	counters, _ := mp.CountersForTest(t)
	if c := counters[MetricACAssignmentRefreshVersionConflict]; c != 1 {
		t.Errorf("expected MetricACAssignmentRefreshVersionConflict=1 on refresh-time conflict, got %v", c)
	}
	if c := counters[MetricACAssignmentVersionConflictRetry]; c != 0 {
		t.Errorf("retry-scoped metric must not fire from refresh path, got %v", c)
	}
	if c := counters[MetricACAssignmentSaveError]; c != 0 {
		t.Errorf("save-error metric must not fire on a VersionConflict (separate counter), got %v", c)
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
