package server

import (
	"context"
	"errors"
	"sync"
)

// sessionControlNativeOperationFenceCache holds one strong, stable directory
// snapshot. It has no age expiry and no background poll: a stale allow remains
// safe because the six-item transaction conditions the exact directory row. A
// stale deny fails closed and requests a single-flight refresh.
type sessionControlNativeOperationFenceCache struct {
	mu         sync.RWMutex
	snapshot   sessionControlFenceSnapshot
	ready      bool
	refreshing bool
}

func (c *sessionControlNativeOperationFenceCache) store(snapshot sessionControlFenceSnapshot, cellID string) error {
	if err := validateSessionControlFenceSnapshot(snapshot, cellID); err != nil {
		return err
	}
	c.mu.Lock()
	c.snapshot = snapshot
	c.ready = true
	c.mu.Unlock()
	return nil
}

func (c *sessionControlNativeOperationFenceCache) allowSnapshot() (sessionControlFenceSnapshot, error) {
	if c == nil {
		return sessionControlFenceSnapshot{}, errors.New("native session operation fence cache is nil")
	}
	c.mu.RLock()
	snapshot, ready := c.snapshot, c.ready
	c.mu.RUnlock()
	if !ready {
		return sessionControlFenceSnapshot{}, errors.New("native session operation fence cache is not ready")
	}
	if snapshot.AdmissionBlocked {
		return sessionControlFenceSnapshot{}, errSessionControlAdmissionBlocked
	}
	return snapshot, nil
}

func (c *sessionControlNativeOperationFenceCache) refresh(ctx context.Context, s *UdpServer) error {
	if c == nil || s == nil || s.sessionControlStore == nil || !validSessionControlCellID(s.sessionControlCellID) {
		return errors.New("native session operation fence refresh is unavailable")
	}
	snapshot, err := s.sessionControlStore.SnapshotActiveFences(ctx, s.sessionControlCellID)
	if err != nil {
		return err
	}
	if snapshot == nil {
		return errSessionControlFenceCorrupt
	}
	return c.store(*snapshot, s.sessionControlCellID)
}

func (c *sessionControlNativeOperationFenceCache) refreshAsync(s *UdpServer) {
	if c == nil || s == nil {
		return
	}
	c.mu.Lock()
	if c.refreshing {
		c.mu.Unlock()
		return
	}
	c.refreshing = true
	c.mu.Unlock()
	go func() {
		defer func() {
			c.mu.Lock()
			c.refreshing = false
			c.mu.Unlock()
		}()
		ctx, cancel := context.WithTimeout(s.LifecycleCtx(), sessionControlNativeOperationReadTimeout)
		defer cancel()
		_ = c.refresh(ctx, s)
	}()
}

func (s *UdpServer) initializeNativeSessionOperationFenceCache(ctx context.Context) error {
	if !s.nativeSessionOperationEnabled() {
		return nil
	}
	if serverEnvironmentValue() != "sandbox" {
		return errors.New("native session operations are restricted to sandbox")
	}
	cache := &sessionControlNativeOperationFenceCache{}
	if err := cache.refresh(ctx, s); err != nil {
		return err
	}
	s.nativeSessionOperationFences = cache
	return nil
}
