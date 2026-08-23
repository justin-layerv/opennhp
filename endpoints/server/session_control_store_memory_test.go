package server

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"
)

func testACSessionControlPublicKey(seed byte) string {
	return testPubkeyB64(seed)
}

// memorySessionControlStore is the semantic test double for callers that must
// exercise the durable authority state machine without emulating DynamoDB. It
// intentionally uses the same transition planner as the production store.
type memorySessionControlStore struct {
	mu                 sync.Mutex
	targets            map[sessionControlTargetKey]sessionControlTargetAuthority
	owners             map[sessionControlTargetKey]sessionControlOwnerAuthority
	authorities        map[string]sessionControlAuthority
	controlDirectories map[string]sessionControlFenceDirectory
	nowUTC             func() time.Time
	pingErr            error
}

func (s *memorySessionControlStore) SnapshotActiveFences(_ context.Context, cellID string) (*sessionControlFenceSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !validSessionControlCellID(cellID) {
		return nil, errors.New("invalid session-control fence cell id")
	}
	directory, ok := s.controlDirectories[cellID]
	if !ok {
		nowMillis := s.nowUTC().UTC().UnixMilli()
		directory = sessionControlFenceDirectory{CellID: cellID, Version: 1, CreatedAtMillis: nowMillis, UpdatedAtMillis: nowMillis}
		s.controlDirectories[cellID] = directory
	}
	if directory.ActiveFenceCount != 0 {
		return nil, errSessionControlFenceCorrupt
	}
	return &sessionControlFenceSnapshot{
		CellID: cellID, DirectoryVersion: directory.Version, ActiveFenceCount: directory.ActiveFenceCount,
		AdmissionBlocked: directory.AdmissionBlocked, OverflowCloseCount: directory.OverflowCloseCount,
	}, nil
}

func newMemorySessionControlStore(now time.Time) *memorySessionControlStore {
	store := &memorySessionControlStore{
		targets:            make(map[sessionControlTargetKey]sessionControlTargetAuthority),
		owners:             make(map[sessionControlTargetKey]sessionControlOwnerAuthority),
		authorities:        make(map[string]sessionControlAuthority),
		controlDirectories: make(map[string]sessionControlFenceDirectory),
		nowUTC:             func() time.Time { return now.UTC() },
	}
	store.controlDirectories["cell-01"] = sessionControlFenceDirectory{
		CellID: "cell-01", Version: 1, CreatedAtMillis: now.UTC().UnixMilli(), UpdatedAtMillis: now.UTC().UnixMilli(),
	}
	return store
}

func (s *memorySessionControlStore) PingSessionControl(context.Context) error {
	return s.pingErr
}

func (s *memorySessionControlStore) GetTarget(_ context.Context, key sessionControlTargetKey) (*sessionControlTargetAuthority, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	target, ok := s.targets[key]
	if !ok {
		return nil, errSessionControlTargetNotFound
	}
	copy := target
	return &copy, nil
}

func (s *memorySessionControlStore) VerifyReadyTargetAttachment(_ context.Context,
	attachment sessionControlTargetAttachment,
) (*sessionControlTargetAuthority, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !validSessionControlTargetAttachment(attachment) {
		return nil, errors.New("invalid session-control target attachment")
	}
	current, ok := s.targets[sessionControlTargetKey{
		ACID: attachment.Candidate.ACID, PublicKey: attachment.Candidate.PublicKey,
	}]
	if !ok {
		return nil, errSessionControlTargetNotFound
	}
	directory, ok := s.controlDirectories[attachment.Candidate.ControlCellID]
	if !ok || directory.Version != attachment.Snapshot.DirectoryVersion ||
		directory.ActiveFenceCount != attachment.Snapshot.ActiveFenceCount ||
		directory.AdmissionBlocked != attachment.Snapshot.AdmissionBlocked ||
		directory.OverflowCloseCount != attachment.Snapshot.OverflowCloseCount ||
		directory.OverflowLeaderEventID != attachment.Snapshot.OverflowLeaderEventID ||
		directory.OverflowLeaderPreparedDirectoryVersion != attachment.Snapshot.OverflowLeaderPreparedDirectoryVersion ||
		directory.OverflowLeaderSelectedDirectoryVersion != attachment.Snapshot.OverflowLeaderSelectedDirectoryVersion {
		return nil, errSessionControlTargetControlStale
	}
	if current != attachment.Target || !current.exactCandidate(attachment.Candidate) || !current.ready() {
		return nil, errSessionControlTargetConflict
	}
	owner, ok := s.owners[sessionControlTargetKey{ACID: attachment.Candidate.ACID, PublicKey: attachment.Candidate.PublicKey}]
	if !ok || !sessionControlReadyAttachmentExact(current, owner, attachment) {
		return nil, errSessionControlTargetConflict
	}
	copy := current
	return &copy, nil
}

func (s *memorySessionControlStore) ListRequiredTargets(_ context.Context, acID, controlCellID string) ([]sessionControlTargetAuthority, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !canonicalSessionControlACID(acID) || !validSessionControlCellID(controlCellID) {
		return nil, errors.New("invalid session-control authority identity")
	}
	authority, ok := s.authorities[acID]
	if !ok {
		return nil, errSessionControlTargetNotFound
	}
	if authority.ControlCellID != "" && authority.ControlCellID != controlCellID {
		return nil, errSessionControlTargetConflict
	}
	out := make([]sessionControlTargetAuthority, 0)
	for _, target := range s.targets {
		if target.ACID != acID {
			continue
		}
		if err := validateSessionControlTargetAuthority(target); err != nil {
			return nil, err
		}
		if target.required() {
			if target.ControlCellID != controlCellID {
				return nil, errSessionControlTargetCorrupt
			}
			out = append(out, target)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PublicKey < out[j].PublicKey })
	if uint64(len(out)) != authority.ActiveTargetCount {
		return nil, errSessionControlTargetCorrupt
	}
	return out, nil
}

func (s *memorySessionControlStore) PrepareTarget(_ context.Context, candidate sessionControlTargetCandidate) (*sessionControlTargetPreparation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !validSessionControlTargetCandidate(candidate) {
		return nil, errors.New("invalid session-control target candidate")
	}
	now := s.nowUTC().UTC()
	authority, ok := s.authorities[candidate.ACID]
	if !ok {
		authority = sessionControlAuthority{
			ACID:            candidate.ACID,
			Version:         1,
			CreatedAtMillis: now.UnixMilli(),
			UpdatedAtMillis: now.UnixMilli(),
		}
		s.authorities[candidate.ACID] = authority
	}
	key := sessionControlTargetKey{ACID: candidate.ACID, PublicKey: candidate.PublicKey}
	current, exists := s.targets[key]
	var currentPtr *sessionControlTargetAuthority
	if exists {
		currentPtr = &current
	}
	planned, write, err := planSessionControlTargetPreparation(currentPtr, candidate, authority, now)
	if err != nil {
		return nil, err
	}
	if write {
		var currentOwner *sessionControlOwnerAuthority
		if owner, ok := s.owners[key]; ok {
			currentOwner = &owner
		}
		nextOwner, ownerErr := sessionControlOwnerFromTarget(planned.Target, currentOwner, sessionControlOwnerPreparing)
		if ownerErr != nil {
			return nil, ownerErr
		}
		s.targets[key] = planned.Target
		s.owners[key] = nextOwner
	}
	return &planned, nil
}

func (s *memorySessionControlStore) ReprepareTargetForControlAdvance(_ context.Context,
	advance sessionControlTargetControlAdvance,
) (*sessionControlTargetPreparation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !validSessionControlTargetControlAdvance(advance) {
		return nil, errors.New("invalid advanced session-control target preparation")
	}
	key := advance.Target.key()
	current, ok := s.targets[key]
	if !ok {
		return nil, errSessionControlTargetNotFound
	}
	authority, ok := s.authorities[current.ACID]
	if !ok {
		return nil, errSessionControlTargetCorrupt
	}
	if sessionControlTargetAdvancedPreparationCommitted(current, advance, authority) {
		owner, ownerOK := s.owners[key]
		if !ownerOK || !owner.exactTarget(current, sessionControlOwnerPreparing) {
			return nil, errSessionControlOwnerConflict
		}
		return &sessionControlTargetPreparation{Target: current, RequiresActivation: true}, nil
	}
	if current != advance.Target {
		return nil, errSessionControlTargetConflict
	}
	owner, ok := s.owners[key]
	if !ok || !owner.exactTarget(current, sessionControlOwnerActiveUnready) {
		return nil, errSessionControlOwnerConflict
	}
	if owner.PendingCount != 0 {
		return nil, errSessionControlTargetPendingWork
	}
	planned, err := sessionControlTargetAdvancedPreparation(current, authority, s.nowUTC().UTC())
	if err != nil {
		return nil, err
	}
	nextOwner, err := sessionControlOwnerFromTarget(planned.Target, &owner, sessionControlOwnerPreparing)
	if err != nil {
		return nil, err
	}
	s.targets[key] = planned.Target
	s.owners[key] = nextOwner
	return &planned, nil
}

func (s *memorySessionControlStore) cancel(fence sessionControlTargetFence) (*sessionControlTargetAuthority, error) {
	if !validSessionControlTargetFence(fence) {
		return nil, errors.New("invalid session-control target fence")
	}
	if fence.Version >= ^uint64(0)-1 {
		return nil, errSessionControlTargetCorrupt
	}
	if fence.CountedActiveSlot {
		return nil, errSessionControlTargetConflict
	}
	key := sessionControlTargetKey{ACID: fence.ACID, PublicKey: fence.PublicKey}
	current, ok := s.targets[key]
	if !ok {
		return nil, errSessionControlTargetNotFound
	}
	if current.State == sessionControlTargetRetired {
		return nil, errSessionControlTargetRetired
	}
	if current.exactFence(fence) && current.State == sessionControlTargetCanceled && current.Version == fence.Version+1 &&
		current.AuthorityVersion == fence.AuthorityVersion && current.CountedActiveSlot == fence.CountedActiveSlot &&
		current.ActivatedControlVersion == fence.ActivatedControlVersion &&
		current.ReadyControlVersion == fence.ReadyControlVersion &&
		current.AAKEnqueuedAtMillis == fence.AAKEnqueuedAtMillis && current.AAKTransactionID == fence.AAKTransactionID {
		copy := current
		return &copy, nil
	}
	if !current.exactFence(fence) || current.Version != fence.Version ||
		current.State != sessionControlTargetPreparing || current.AuthorityVersion != fence.AuthorityVersion ||
		current.CountedActiveSlot != fence.CountedActiveSlot || current.ActivatedControlVersion != fence.ActivatedControlVersion ||
		current.ReadyControlVersion != fence.ReadyControlVersion ||
		current.AAKEnqueuedAtMillis != fence.AAKEnqueuedAtMillis || current.AAKTransactionID != fence.AAKTransactionID {
		return nil, errSessionControlTargetConflict
	}
	nowMillis := s.nowUTC().UTC().UnixMilli()
	if nowMillis < fence.PreparedAtMillis {
		nowMillis = fence.PreparedAtMillis
	}
	current.State = sessionControlTargetCanceled
	current.Version++
	current.UpdatedAtMillis = nowMillis
	s.targets[key] = current
	copy := current
	return &copy, nil
}

func (s *memorySessionControlStore) ActivateTarget(_ context.Context, activation sessionControlTargetActivation) (*sessionControlTargetAuthority, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !validSessionControlTargetActivation(activation) {
		return nil, errors.New("invalid session-control target activation")
	}
	fence := activation.Fence
	if fence.Version >= ^uint64(0)-2 {
		return nil, errSessionControlTargetCorrupt
	}
	if !fence.CountedActiveSlot && fence.AuthorityVersion >= ^uint64(0)-1 {
		return nil, errSessionControlTargetCorrupt
	}
	key := sessionControlTargetKey{ACID: fence.ACID, PublicKey: fence.PublicKey}
	current, ok := s.targets[key]
	if !ok {
		return nil, errSessionControlTargetNotFound
	}
	directory, ok := s.controlDirectories[activation.ControlCellID]
	if !ok {
		return nil, errSessionControlTargetControlStale
	}
	if directory.AdmissionBlocked {
		return nil, errSessionControlAdmissionBlocked
	}
	expectedAuthorityVersion := fence.AuthorityVersion
	if !fence.CountedActiveSlot {
		expectedAuthorityVersion++
	}
	if current.exactFence(fence) && current.State == sessionControlTargetActive && current.Version == fence.Version+1 &&
		current.AuthorityVersion == expectedAuthorityVersion && current.CountedActiveSlot &&
		current.ActivatedControlVersion == activation.CaughtUpControlVersion && current.ReadyControlVersion == 0 &&
		current.AAKEnqueuedAtMillis == 0 && current.AAKTransactionID == 0 {
		copy := current
		return &copy, nil
	}
	if directory.Version != activation.CaughtUpControlVersion {
		return nil, errSessionControlTargetControlStale
	}
	if current.State == sessionControlTargetRetired {
		return nil, errSessionControlTargetRetired
	}
	authority, ok := s.authorities[fence.ACID]
	if !ok {
		return nil, errSessionControlTargetCorrupt
	}
	if !current.exactFence(fence) || current.Version != fence.Version ||
		current.State != sessionControlTargetPreparing || current.AuthorityVersion != fence.AuthorityVersion ||
		current.CountedActiveSlot != fence.CountedActiveSlot || current.ActivatedControlVersion != fence.ActivatedControlVersion ||
		current.ReadyControlVersion != fence.ReadyControlVersion ||
		current.AAKEnqueuedAtMillis != fence.AAKEnqueuedAtMillis || current.AAKTransactionID != fence.AAKTransactionID ||
		authority.Version != fence.AuthorityVersion {
		return nil, errSessionControlTargetConflict
	}
	if authority.ControlCellID != "" && authority.ControlCellID != activation.ControlCellID {
		return nil, errSessionControlTargetConflict
	}
	if current.CountedActiveSlot && authority.ControlCellID != activation.ControlCellID {
		return nil, errSessionControlTargetConflict
	}
	currentOwner, ok := s.owners[key]
	if !ok || !currentOwner.exactTarget(current, sessionControlOwnerPreparing) {
		return nil, errSessionControlOwnerConflict
	}
	if !current.CountedActiveSlot {
		if authority.ActiveTargetCount >= uint64(MaxACConnsPerID) {
			return nil, errSessionControlTargetCapacity
		}
		authority.Version++
		authority.ActiveTargetCount++
		authority.ControlCellID = activation.ControlCellID
		authority.UpdatedAtMillis = fence.PreparedAtMillis
		s.authorities[fence.ACID] = authority
		current.AuthorityVersion = authority.Version
		current.CountedActiveSlot = true
	}
	current.State = sessionControlTargetActive
	current.Version++
	current.ActivatedControlVersion = activation.CaughtUpControlVersion
	current.ReadyControlVersion = 0
	current.AAKEnqueuedAtMillis = 0
	current.AAKTransactionID = 0
	current.UpdatedAtMillis = fence.PreparedAtMillis
	nextOwner, ownerErr := sessionControlOwnerFromTarget(current, &currentOwner, sessionControlOwnerActiveUnready)
	if ownerErr != nil {
		return nil, ownerErr
	}
	s.targets[key] = current
	s.owners[key] = nextOwner
	copy := current
	return &copy, nil
}

func (s *memorySessionControlStore) FinalizeTargetReady(_ context.Context,
	readiness sessionControlTargetReadiness) (*sessionControlTargetAuthority, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !validSessionControlTargetReadiness(readiness) {
		return nil, errors.New("invalid session-control target readiness")
	}
	fence := readiness.Fence
	key := fence.key()
	current, ok := s.targets[key]
	if !ok {
		return nil, errSessionControlTargetNotFound
	}
	if sessionControlTargetFinalizedExact(current, readiness) {
		copy := current
		return &copy, nil
	}
	directory, ok := s.controlDirectories[readiness.ControlDirectory.CellID]
	if !ok {
		return nil, errSessionControlTargetControlStale
	}
	if directory.AdmissionBlocked {
		return nil, errSessionControlAdmissionBlocked
	}
	expected := readiness.ControlDirectory
	if directory.CellID != expected.CellID || directory.Version != expected.DirectoryVersion ||
		directory.ActiveFenceCount != expected.ActiveFenceCount ||
		directory.AdmissionBlocked != expected.AdmissionBlocked ||
		directory.OverflowCloseCount != expected.OverflowCloseCount {
		return nil, errSessionControlTargetControlStale
	}
	if current.State == sessionControlTargetRetired {
		return nil, errSessionControlTargetRetired
	}
	if !current.exactFence(fence) || current.State != sessionControlTargetActive || current.Version != fence.Version ||
		current.AuthorityVersion != fence.AuthorityVersion ||
		current.CountedActiveSlot != fence.CountedActiveSlot ||
		current.ActivatedControlVersion != fence.ActivatedControlVersion || current.ReadyControlVersion != 0 ||
		current.AAKEnqueuedAtMillis != 0 || current.AAKTransactionID != 0 {
		return nil, errSessionControlTargetConflict
	}
	currentOwner, ok := s.owners[key]
	if !ok || !currentOwner.exactTarget(current, sessionControlOwnerActiveUnready) {
		return nil, errSessionControlOwnerConflict
	}
	current.Version++
	current.ReadyControlVersion = current.ActivatedControlVersion
	current.AAKEnqueuedAtMillis = readiness.AAKEnqueuedAtMillis
	current.AAKTransactionID = readiness.AAKTransactionID
	current.UpdatedAtMillis = readiness.AAKEnqueuedAtMillis
	nextOwner, ownerErr := sessionControlOwnerFromTarget(current, &currentOwner, sessionControlOwnerReady)
	if ownerErr != nil {
		return nil, ownerErr
	}
	s.targets[key] = current
	s.owners[key] = nextOwner
	copy := current
	return &copy, nil
}

func (s *memorySessionControlStore) CancelTargetPreparation(_ context.Context, fence sessionControlTargetFence) (*sessionControlTargetAuthority, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cancel(fence)
}

func (s *memorySessionControlStore) retireTarget(_ context.Context, fence sessionControlTargetFence) (*sessionControlTargetAuthority, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !validSessionControlTargetFence(fence) {
		return nil, errors.New("invalid session-control target fence")
	}
	if fence.Version >= ^uint64(0)-1 {
		return nil, errSessionControlTargetCorrupt
	}
	key := sessionControlTargetKey{ACID: fence.ACID, PublicKey: fence.PublicKey}
	current, ok := s.targets[key]
	if !ok {
		return nil, errSessionControlTargetNotFound
	}
	if current.State == sessionControlTargetRetired {
		if current.exactFence(fence) && current.Version == fence.Version+1 &&
			current.ActivatedControlVersion == fence.ActivatedControlVersion &&
			current.ReadyControlVersion == fence.ReadyControlVersion &&
			current.AAKEnqueuedAtMillis == fence.AAKEnqueuedAtMillis && current.AAKTransactionID == fence.AAKTransactionID {
			copy := current
			return &copy, nil
		}
		return nil, errSessionControlTargetRetired
	}
	if !current.exactFence(fence) || current.Version != fence.Version ||
		current.AuthorityVersion != fence.AuthorityVersion || current.CountedActiveSlot != fence.CountedActiveSlot ||
		current.ActivatedControlVersion != fence.ActivatedControlVersion ||
		current.ReadyControlVersion != fence.ReadyControlVersion ||
		current.AAKEnqueuedAtMillis != fence.AAKEnqueuedAtMillis || current.AAKTransactionID != fence.AAKTransactionID {
		return nil, errSessionControlTargetConflict
	}
	authority, ok := s.authorities[fence.ACID]
	if !ok {
		return nil, errSessionControlTargetCorrupt
	}
	if current.CountedActiveSlot {
		if authority.ActiveTargetCount == 0 {
			return nil, errSessionControlTargetCorrupt
		}
		authority.ActiveTargetCount--
		authority.Version++
		authority.UpdatedAtMillis = s.nowUTC().UTC().UnixMilli()
		s.authorities[fence.ACID] = authority
	}
	nowMillis := s.nowUTC().UTC().UnixMilli()
	if nowMillis < current.UpdatedAtMillis {
		nowMillis = current.UpdatedAtMillis
	}
	current.State = sessionControlTargetRetired
	current.Version++
	current.AuthorityVersion = authority.Version
	current.CountedActiveSlot = false
	current.UpdatedAtMillis = nowMillis
	current.RetiredAtMillis = nowMillis
	s.targets[key] = current
	copy := current
	return &copy, nil
}

func (s *memorySessionControlStore) advanceAuthorityVersionForTest(acID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	authority, ok := s.authorities[acID]
	if !ok {
		return errSessionControlTargetNotFound
	}
	authority.Version++
	authority.UpdatedAtMillis = s.nowUTC().UTC().UnixMilli()
	s.authorities[acID] = authority
	return nil
}

var _ sessionControlStore = (*memorySessionControlStore)(nil)
