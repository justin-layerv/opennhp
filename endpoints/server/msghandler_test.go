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
