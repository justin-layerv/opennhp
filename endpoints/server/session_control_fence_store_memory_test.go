package server

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"
)

type memorySessionControlFenceStore struct {
	mu          sync.Mutex
	directories map[string]sessionControlFenceDirectory
	metas       map[string]sessionControlFenceAuthority
	active      map[string]map[string]sessionControlFenceAuthority
	now         time.Time
}

func newMemorySessionControlFenceStore(now time.Time) *memorySessionControlFenceStore {
	return &memorySessionControlFenceStore{
		directories: make(map[string]sessionControlFenceDirectory),
		metas:       make(map[string]sessionControlFenceAuthority),
		active:      make(map[string]map[string]sessionControlFenceAuthority),
		now:         now.UTC(),
	}
}

func (s *memorySessionControlFenceStore) setNow(now time.Time) {
	s.mu.Lock()
	s.now = now.UTC()
	s.mu.Unlock()
}

func (s *memorySessionControlFenceStore) PrepareFence(_ context.Context, candidate sessionControlFenceCandidate) (*sessionControlFenceAuthority, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !validSessionControlFenceCandidate(candidate) {
		return nil, errors.New("invalid session-control fence candidate")
	}
	digest, _ := sessionControlFenceSelectorDigest(candidate.Selector)
	if existing, ok := s.metas[candidate.EventID]; ok {
		if existing.CellID != candidate.CellID || existing.Selector != candidate.Selector || existing.SelectorDigest != digest {
			return nil, errSessionControlFenceConflict
		}
		if existing.State == sessionControlFenceRetired {
			return nil, errSessionControlFenceRetired
		}
		active, ok := s.active[candidate.CellID][candidate.EventID]
		if !ok || active != existing {
			return nil, errSessionControlFenceCorrupt
		}
		directory, ok := s.directories[candidate.CellID]
		if !ok || directory.ActiveFenceCount == 0 || existing.PreparedDirectoryVersion > directory.Version {
			return nil, errSessionControlFenceCorrupt
		}
		copy := existing
		return &copy, nil
	}
	directory, ok := s.directories[candidate.CellID]
	if !ok {
		directory = sessionControlFenceDirectory{
			CellID: candidate.CellID, Version: 1,
			CreatedAtMillis: s.now.UnixMilli(), UpdatedAtMillis: s.now.UnixMilli(),
		}
	}
	if directory.ActiveFenceCount >= sessionControlFenceActiveLimit {
		return nil, errSessionControlFenceCapacity
	}
	if directory.Version > ^uint64(0)-4 {
		return nil, errSessionControlFenceCorrupt
	}
	directory.Version++
	directory.ActiveFenceCount++
	directory.UpdatedAtMillis = s.now.UnixMilli()
	fence := sessionControlFenceAuthority{
		CellID: candidate.CellID, EventID: candidate.EventID, Selector: candidate.Selector,
		SelectorDigest: digest, PreparedDirectoryVersion: directory.Version,
		State: sessionControlFencePreparing, Version: 1,
		CreatedAtMillis: s.now.UnixMilli(), PreparedAtMillis: s.now.UnixMilli(), UpdatedAtMillis: s.now.UnixMilli(),
	}
	s.directories[candidate.CellID] = directory
	s.metas[candidate.EventID] = fence
	if s.active[candidate.CellID] == nil {
		s.active[candidate.CellID] = make(map[string]sessionControlFenceAuthority)
	}
	s.active[candidate.CellID][candidate.EventID] = fence
	copy := fence
	return &copy, nil
}

func (s *memorySessionControlFenceStore) MarkFenceConverged(_ context.Context, fence sessionControlFenceAuthority) (*sessionControlFenceAuthority, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := validateSessionControlFenceAuthority(fence); err != nil || fence.State != sessionControlFencePreparing {
		return nil, errors.New("invalid preparing session-control fence")
	}
	if fence.Version >= ^uint64(0)-1 {
		return nil, errSessionControlFenceCorrupt
	}
	current, ok := s.metas[fence.EventID]
	if !ok {
		return nil, errSessionControlFenceNotFound
	}
	if current.State == sessionControlFenceRetired {
		return nil, errSessionControlFenceRetired
	}
	if current.State == sessionControlFenceConverged {
		if sessionControlFenceSameIdentity(current, fence) && current.Version == fence.Version+1 {
			copy := current
			return &copy, nil
		}
		return nil, errSessionControlFenceConflict
	}
	active, ok := s.active[fence.CellID][fence.EventID]
	if !ok || active != current {
		return nil, errSessionControlFenceCorrupt
	}
	if current != fence {
		return nil, errSessionControlFenceConflict
	}
	directory, ok := s.directories[fence.CellID]
	if !ok || directory.ActiveFenceCount == 0 || directory.Version > ^uint64(0)-3 {
		return nil, errSessionControlFenceCorrupt
	}
	directory.Version++
	directory.UpdatedAtMillis = s.now.UnixMilli()
	current.State = sessionControlFenceConverged
	current.Version++
	current.ConvergedAtMillis = s.now.UnixMilli()
	current.ReplayNotBeforeMillis = s.now.Add(sessionControlFenceReplayHorizon).UnixMilli()
	current.UpdatedAtMillis = s.now.UnixMilli()
	s.directories[fence.CellID] = directory
	s.metas[fence.EventID] = current
	s.active[fence.CellID][fence.EventID] = current
	copy := current
	return &copy, nil
}

func (s *memorySessionControlFenceStore) SnapshotActiveFences(_ context.Context, cellID string) (*sessionControlFenceSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !validSessionControlCellID(cellID) {
		return nil, errors.New("invalid session-control fence cell id")
	}
	directory, ok := s.directories[cellID]
	if !ok {
		directory = sessionControlFenceDirectory{
			CellID: cellID, Version: 1, CreatedAtMillis: s.now.UnixMilli(), UpdatedAtMillis: s.now.UnixMilli(),
		}
		s.directories[cellID] = directory
	}
	fences := make([]sessionControlFenceAuthority, 0, len(s.active[cellID]))
	for _, fence := range s.active[cellID] {
		if err := validateSessionControlFenceAuthority(fence); err != nil || fence.State == sessionControlFenceRetired ||
			fence.PreparedDirectoryVersion > directory.Version {
			return nil, errSessionControlFenceCorrupt
		}
		fences = append(fences, fence)
	}
	if len(fences) > sessionControlFenceActiveLimit || uint64(len(fences)) != directory.ActiveFenceCount {
		return nil, errSessionControlFenceCorrupt
	}
	sort.Slice(fences, func(i, j int) bool { return fences[i].EventID < fences[j].EventID })
	return &sessionControlFenceSnapshot{
		CellID: cellID, DirectoryVersion: directory.Version, ActiveFenceCount: directory.ActiveFenceCount,
		AdmissionBlocked: directory.AdmissionBlocked, OverflowCloseCount: directory.OverflowCloseCount, Fences: fences,
	}, nil
}

func (s *memorySessionControlFenceStore) retireFence(_ context.Context, fence sessionControlFenceAuthority) (*sessionControlFenceAuthority, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := validateSessionControlFenceAuthority(fence); err != nil || fence.State != sessionControlFenceConverged {
		return nil, errors.New("invalid converged session-control fence")
	}
	if fence.Version >= ^uint64(0)-1 {
		return nil, errSessionControlFenceCorrupt
	}
	current, ok := s.metas[fence.EventID]
	if !ok {
		return nil, errSessionControlFenceNotFound
	}
	if current.State == sessionControlFenceRetired {
		if sessionControlFenceSameIdentity(current, fence) && current.Version == fence.Version+1 {
			if _, stillActive := s.active[fence.CellID][fence.EventID]; stillActive {
				return nil, errSessionControlFenceCorrupt
			}
			copy := current
			return &copy, nil
		}
		return nil, errSessionControlFenceRetired
	}
	active, ok := s.active[fence.CellID][fence.EventID]
	if !ok || active != current {
		return nil, errSessionControlFenceCorrupt
	}
	if current != fence {
		return nil, errSessionControlFenceConflict
	}
	if s.now.UnixMilli() < fence.ReplayNotBeforeMillis {
		return nil, errSessionControlFenceReplayHorizon
	}
	directory, ok := s.directories[fence.CellID]
	if !ok || directory.ActiveFenceCount == 0 || directory.Version > ^uint64(0)-2 ||
		fence.PreparedDirectoryVersion > directory.Version {
		return nil, errSessionControlFenceCorrupt
	}
	directory.Version++
	directory.ActiveFenceCount--
	directory.UpdatedAtMillis = s.now.UnixMilli()
	current.State = sessionControlFenceRetired
	current.Version++
	current.UpdatedAtMillis = s.now.UnixMilli()
	current.RetiredAtMillis = s.now.UnixMilli()
	current.ExpiresAt = s.now.Unix() + int64(sessionControlFenceIdempotencyTTL/time.Second)
	s.directories[fence.CellID] = directory
	s.metas[fence.EventID] = current
	delete(s.active[fence.CellID], fence.EventID)
	copy := current
	return &copy, nil
}

var _ sessionControlActiveFenceStore = (*memorySessionControlFenceStore)(nil)
