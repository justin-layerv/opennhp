package server

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"
)

type nativeOperationFenceCacheStore struct {
	*memorySessionControlStore
	mu       sync.Mutex
	calls    int
	snapshot *sessionControlFenceSnapshot
	err      error
	entered  chan struct{}
	release  <-chan struct{}
}

func (s *nativeOperationFenceCacheStore) SnapshotActiveFences(ctx context.Context,
	cellID string,
) (*sessionControlFenceSnapshot, error) {
	s.mu.Lock()
	s.calls++
	entered := s.entered
	release := s.release
	snapshot := s.snapshot
	err := s.err
	s.mu.Unlock()
	if entered != nil {
		select {
		case entered <- struct{}{}:
		default:
		}
	}
	if release != nil {
		select {
		case <-release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if err != nil {
		return nil, err
	}
	if snapshot == nil {
		return nil, nil
	}
	copy := *snapshot
	return &copy, nil
}

func (s *nativeOperationFenceCacheStore) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func TestNativeSessionOperationFenceCacheBootAndStaleAllow(t *testing.T) {
	allow := testSessionControlSessionSnapshot(7)
	cache := &sessionControlNativeOperationFenceCache{}
	if _, err := cache.allowSnapshot(); err == nil {
		t.Fatal("uninitialized cache admitted a session")
	}
	if err := cache.store(allow, testSessionControlCellID); err != nil {
		t.Fatal(err)
	}
	for _, elapsed := range []time.Duration{0, 24 * time.Hour, 365 * 24 * time.Hour} {
		_ = elapsed // The authority deliberately has no age field or age expiry.
		got, err := cache.allowSnapshot()
		if err != nil || !reflect.DeepEqual(got, allow) {
			t.Fatalf("age-independent cached allow = %#v, %v", got, err)
		}
	}
}

func TestNativeSessionOperationFenceCacheRefreshFailureRetainsAllow(t *testing.T) {
	allow := testSessionControlSessionSnapshot(7)
	cache := &sessionControlNativeOperationFenceCache{}
	if err := cache.store(allow, testSessionControlCellID); err != nil {
		t.Fatal(err)
	}
	store := &nativeOperationFenceCacheStore{
		memorySessionControlStore: newMemorySessionControlStore(time.Now().UTC()),
		err:                       errors.New("refresh unavailable"),
	}
	server := &UdpServer{sessionControlStore: store, sessionControlCellID: testSessionControlCellID}
	if err := cache.refresh(context.Background(), server); err == nil {
		t.Fatal("failed refresh was accepted")
	}
	got, err := cache.allowSnapshot()
	if err != nil || !reflect.DeepEqual(got, allow) {
		t.Fatalf("refresh failure invalidated unchanged allow: %#v, %v", got, err)
	}
}

func TestNativeSessionOperationFenceCacheRefreshIsSingleFlightAndDenyFailsClosed(t *testing.T) {
	allow := testSessionControlSessionSnapshot(7)
	deny := allow
	deny.AdmissionBlocked = true
	deny.OverflowCloseCount = 1
	deny.OverflowLeaderEventID = "0123456789abcdef0123456789abcdef"
	deny.OverflowLeaderPreparedDirectoryVersion = 6
	deny.OverflowLeaderSelectedDirectoryVersion = 7
	cache := &sessionControlNativeOperationFenceCache{}
	if err := cache.store(allow, testSessionControlCellID); err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	entered := make(chan struct{}, 1)
	store := &nativeOperationFenceCacheStore{
		memorySessionControlStore: newMemorySessionControlStore(time.Now().UTC()),
		snapshot:                  &deny,
		entered:                   entered,
		release:                   release,
	}
	server := &UdpServer{sessionControlStore: store, sessionControlCellID: testSessionControlCellID}
	for range 32 {
		cache.refreshAsync(server)
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("single-flight refresh did not start")
	}
	if calls := store.callCount(); calls != 1 {
		t.Fatalf("overlapping refresh calls = %d, want 1", calls)
	}
	close(release)
	deadline := time.Now().Add(time.Second)
	for {
		cache.mu.RLock()
		refreshing := cache.refreshing
		cache.mu.RUnlock()
		if !refreshing {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("single-flight refresh did not finish")
		}
		time.Sleep(time.Millisecond)
	}
	if _, err := cache.allowSnapshot(); !errors.Is(err, errSessionControlAdmissionBlocked) {
		t.Fatalf("refreshed deny = %v, want admission blocked", err)
	}
}

func TestNativeSessionOperationStartupIsSandboxOnlyAndBootLoadsStrongSnapshot(t *testing.T) {
	allow := testSessionControlSessionSnapshot(7)
	store := &nativeOperationFenceCacheStore{
		memorySessionControlStore: newMemorySessionControlStore(time.Now().UTC()),
		snapshot:                  &allow,
	}
	server := &UdpServer{
		storageConfig: &StorageConfig{Backend: StorageBackendDynamoDB, DynamoDB: DynamoDBConfig{
			NativeSessionOperations: true,
		}},
		sessionControlStore: store, sessionControlCellID: testSessionControlCellID,
	}
	t.Setenv("NHP_ENVIRONMENT", "prod")
	if err := server.initializeNativeSessionOperationFenceCache(context.Background()); err == nil ||
		server.nativeSessionOperationFences != nil || store.callCount() != 0 {
		t.Fatalf("production startup = cache %#v calls=%d err=%v", server.nativeSessionOperationFences,
			store.callCount(), err)
	}
	t.Setenv("NHP_ENVIRONMENT", "sandbox")
	if err := server.initializeNativeSessionOperationFenceCache(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, err := server.nativeSessionOperationFences.allowSnapshot()
	if err != nil || !reflect.DeepEqual(got, allow) || store.callCount() != 1 {
		t.Fatalf("sandbox boot snapshot = %#v calls=%d err=%v", got, store.callCount(), err)
	}
}
