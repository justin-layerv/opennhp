package server

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
)

type memorySessionControlSessionModel struct {
	mu                     sync.Mutex
	snapshot               sessionControlFenceSnapshot
	nowMillis              int64
	prepareCurrentReadHook func(int)
	sessions               map[uint64]sessionControlSessionAuthority
	memberships            map[string]sessionControlSessionCandidate
	intents                map[string]sessionControlSessionIntent
	reverse                map[string]sessionControlSessionIntent
	targets                map[sessionControlTargetKey]sessionControlTargetAuthority
	closePreparations      map[string]sessionControlExactClosePreparation
}

func newMemorySessionControlSessionModel(snapshot sessionControlFenceSnapshot) *memorySessionControlSessionModel {
	return &memorySessionControlSessionModel{
		snapshot: snapshot, nowMillis: 1_800_000_010_000,
		sessions:    make(map[uint64]sessionControlSessionAuthority),
		memberships: make(map[string]sessionControlSessionCandidate),
		intents:     make(map[string]sessionControlSessionIntent), reverse: make(map[string]sessionControlSessionIntent),
		targets:           make(map[sessionControlTargetKey]sessionControlTargetAuthority),
		closePreparations: make(map[string]sessionControlExactClosePreparation),
	}
}

func memorySessionMembershipKey(candidate sessionControlSessionCandidate) string {
	return sessionControlAgentSessionPK(candidate.AgentPublicKey) + "/" +
		sessionControlSessionMembershipSK(candidate.IssuedAtMillis, candidate.SessionID)
}

func memorySessionIntentKey(candidate sessionControlSessionCandidate, target sessionControlTargetAuthority) string {
	return sessionControlSessionPK(candidate.SessionID) + "/" + sessionControlSessionIntentSK(target)
}

func memoryTargetSessionKey(candidate sessionControlSessionCandidate, target sessionControlTargetAuthority) string {
	return sessionControlTargetSessionPK(target) + "/" +
		sessionControlSessionMembershipSK(candidate.IssuedAtMillis, candidate.SessionID)
}

func (s *memorySessionControlSessionModel) setSnapshot(snapshot sessionControlFenceSnapshot) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.snapshot = snapshot
}

func (s *memorySessionControlSessionModel) setTarget(target sessionControlTargetAuthority) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.targets[target.key()] = target
}

func memorySessionControlFenceDirectory(snapshot sessionControlFenceSnapshot) sessionControlFenceDirectory {
	return sessionControlFenceDirectory{
		CellID: snapshot.CellID, Version: snapshot.DirectoryVersion,
		ActiveFenceCount: snapshot.ActiveFenceCount, AdmissionBlocked: snapshot.AdmissionBlocked,
		OverflowCloseCount: snapshot.OverflowCloseCount,
	}
}

func (s *memorySessionControlSessionModel) ReserveSession(_ context.Context, candidate sessionControlSessionCandidate,
	snapshot sessionControlFenceSnapshot) (*sessionControlSessionAuthority, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := evaluateSessionControlFences(candidate, snapshot); err != nil {
		return nil, err
	}
	if err := requireSessionControlAdmissionDirectory(memorySessionControlFenceDirectory(s.snapshot), snapshot); err != nil {
		return nil, err
	}
	if current, ok := s.sessions[candidate.SessionID]; ok {
		if current.Candidate != candidate {
			return nil, errSessionControlSessionCollision
		}
		membership, exists := s.memberships[memorySessionMembershipKey(candidate)]
		if !exists || membership != candidate {
			return nil, errSessionControlSessionCorrupt
		}
		copy := current
		return &copy, nil
	}
	if _, partial := s.memberships[memorySessionMembershipKey(candidate)]; partial {
		return nil, errSessionControlSessionCorrupt
	}
	planned, err := planSessionControlReservation(candidate, snapshot)
	if err != nil {
		return nil, err
	}
	s.sessions[candidate.SessionID] = planned
	s.memberships[memorySessionMembershipKey(candidate)] = candidate
	copy := planned
	return &copy, nil
}

func (s *memorySessionControlSessionModel) PrepareSessionIntent(_ context.Context, fence sessionControlSessionFence,
	target sessionControlTargetAuthority, sessionExpiresAtMillis, retainUntilMillis int64,
	snapshot sessionControlFenceSnapshot) (*sessionControlSessionIntentPreparation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := evaluateSessionControlFences(fence.Candidate, snapshot); err != nil {
		return nil, err
	}
	if err := requireSessionControlAdmissionDirectory(memorySessionControlFenceDirectory(s.snapshot), snapshot); err != nil {
		return nil, err
	}
	if err := validateSessionControlSnapshotAfterReservation(fence, snapshot); err != nil {
		return nil, err
	}
	if s.nowMillis >= sessionExpiresAtMillis {
		return nil, errSessionControlSessionFenceDenied
	}
	request := sessionControlSessionIntent{
		Session: fence.Candidate, Target: target, State: sessionControlSessionIntentMayBeAdmitted,
		SessionVersion: fence.Version + 1, SessionExpiresAtMillis: sessionExpiresAtMillis,
		RetainUntilMillis: retainUntilMillis, PreparedDirectoryVersion: snapshot.DirectoryVersion,
		PreparedActiveFenceCount: snapshot.ActiveFenceCount,
	}
	forward, forwardOK := s.intents[memorySessionIntentKey(fence.Candidate, target)]
	reverse, reverseOK := s.reverse[memoryTargetSessionKey(fence.Candidate, target)]
	if forwardOK || reverseOK {
		if !forwardOK || !reverseOK || !sessionControlIntentExact(forward, reverse) {
			return nil, errSessionControlSessionCorrupt
		}
		if !sessionControlIntentSameProcess(forward, request) {
			return nil, errSessionControlSessionConflict
		}
	}
	current, ok := s.sessions[fence.Candidate.SessionID]
	if !ok {
		return nil, errSessionControlSessionNotFound
	}
	if current.Candidate != fence.Candidate {
		return nil, errSessionControlSessionConflict
	}
	if forwardOK && (forward.SessionVersion > current.Version || current.TargetCount == 0 ||
		forward.SessionExpiresAtMillis != current.SessionExpiresAtMillis ||
		forward.RetainUntilMillis > current.RetainUntilMillis ||
		forward.PreparedDirectoryVersion < current.ReservedDirectoryVersion ||
		(forward.PreparedDirectoryVersion == current.ReservedDirectoryVersion &&
			forward.PreparedActiveFenceCount != current.ReservedActiveFenceCount)) {
		return nil, errSessionControlSessionCorrupt
	}
	if current.fence() != fence {
		if current.TargetCount >= sessionControlSessionMaxTargets && !forwardOK {
			return nil, errSessionControlSessionCapacity
		}
		return nil, errSessionControlSessionConflict
	}
	live, ok := s.targets[target.key()]
	if !ok || live != target || live.State != sessionControlTargetActive {
		return nil, errSessionControlSessionTargetConflict
	}
	var planned sessionControlSessionIntentPreparation
	var err error
	if forwardOK {
		planned, err = planSessionControlIntentExtension(current, fence, forward, target,
			sessionExpiresAtMillis, retainUntilMillis, snapshot)
	} else {
		planned, err = planSessionControlIntent(fence, target, sessionExpiresAtMillis, retainUntilMillis, snapshot)
	}
	if err != nil {
		return nil, err
	}
	s.sessions[fence.Candidate.SessionID] = planned.Session
	s.intents[memorySessionIntentKey(fence.Candidate, target)] = planned.Intent
	s.reverse[memoryTargetSessionKey(fence.Candidate, target)] = planned.Intent
	return &planned, nil
}

func (s *memorySessionControlSessionModel) PrepareSessionIntentCurrent(ctx context.Context,
	candidate sessionControlSessionCandidate, target sessionControlTargetAuthority,
	sessionExpiresAtMillis, retainUntilMillis int64,
	snapshot sessionControlFenceSnapshot) (*sessionControlSessionIntentPreparation, error) {
	if validateSessionControlTargetAuthority(target) != nil || !target.ready() ||
		target.ControlCellID != candidate.CellID {
		return nil, errors.New("invalid session-control session intent target")
	}
	for attempt := range sessionControlSessionFanoutAttempts {
		s.mu.Lock()
		current, ok := s.sessions[candidate.SessionID]
		hook := s.prepareCurrentReadHook
		s.mu.Unlock()
		if !ok {
			return nil, errSessionControlSessionNotFound
		}
		if current.Candidate != candidate {
			return nil, errSessionControlSessionCollision
		}
		if current.State == sessionControlSessionStateClosing {
			return nil, errSessionControlSessionFenceDenied
		}
		if current.State != sessionControlSessionStateReserved {
			return nil, errSessionControlSessionConflict
		}
		if current.TargetCount > 0 && current.SessionExpiresAtMillis != sessionExpiresAtMillis {
			return nil, errSessionControlSessionConflict
		}
		if s.nowMillis >= sessionExpiresAtMillis {
			return nil, errSessionControlSessionFenceDenied
		}
		if hook != nil {
			hook(attempt)
		}
		prepared, err := s.PrepareSessionIntent(ctx, current.fence(), target,
			sessionExpiresAtMillis, retainUntilMillis, snapshot)
		if err == nil || !errors.Is(err, errSessionControlSessionConflict) {
			return prepared, err
		}
	}
	return nil, errSessionControlSessionConflict
}

func (s *memorySessionControlSessionModel) VerifySession(_ context.Context,
	candidate sessionControlSessionCandidate, snapshot sessionControlFenceSnapshot) (*sessionControlSessionAuthority, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := evaluateSessionControlFences(candidate, snapshot); err != nil {
		return nil, err
	}
	if err := requireSessionControlAdmissionDirectory(memorySessionControlFenceDirectory(s.snapshot), snapshot); err != nil {
		return nil, err
	}
	current, ok := s.sessions[candidate.SessionID]
	if !ok {
		return nil, errSessionControlSessionNotFound
	}
	if current.Candidate != candidate {
		return nil, errSessionControlSessionCollision
	}
	if membership, ok := s.memberships[memorySessionMembershipKey(candidate)]; !ok || membership != candidate {
		return nil, errSessionControlSessionCorrupt
	}
	if current.State != sessionControlSessionStateReserved {
		return nil, errSessionControlSessionFenceDenied
	}
	if err := validateSessionControlSnapshotAfterReservation(current.fence(), snapshot); err != nil {
		return nil, err
	}
	deadlineMillis := current.SessionExpiresAtMillis
	if current.TargetCount == 0 {
		deadlineMillis = current.Candidate.ReservationDeadlineMillis
	}
	if s.nowMillis >= deadlineMillis {
		return nil, errSessionControlSessionFenceDenied
	}
	copy := current
	return &copy, nil
}

func (s *memorySessionControlSessionModel) MarkSessionAckEnqueued(_ context.Context,
	candidate sessionControlSessionCandidate, snapshot sessionControlFenceSnapshot) (*sessionControlSessionAuthority, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := evaluateSessionControlFences(candidate, snapshot); err != nil {
		return nil, err
	}
	if err := requireSessionControlAdmissionDirectory(memorySessionControlFenceDirectory(s.snapshot), snapshot); err != nil {
		return nil, err
	}
	current, ok := s.sessions[candidate.SessionID]
	if !ok {
		return nil, errSessionControlSessionNotFound
	}
	if current.Candidate != candidate {
		return nil, errSessionControlSessionCollision
	}
	if membership, ok := s.memberships[memorySessionMembershipKey(candidate)]; !ok || membership != candidate {
		return nil, errSessionControlSessionCorrupt
	}
	if err := validateSessionControlSnapshotAfterReservation(current.fence(), snapshot); err != nil {
		return nil, err
	}
	if current.State == sessionControlSessionStateClosing {
		return nil, errSessionControlSessionFenceDenied
	}
	if current.State == sessionControlSessionStateAckEnqueued {
		copy := current
		return &copy, nil
	}
	if current.State != sessionControlSessionStateReserved || current.TargetCount == 0 {
		return nil, errSessionControlSessionConflict
	}
	if s.nowMillis >= current.SessionExpiresAtMillis {
		return nil, errSessionControlSessionFenceDenied
	}
	current.State = sessionControlSessionStateAckEnqueued
	current.AckEnqueuedAtMillis = s.nowMillis
	if current.AckEnqueuedAtMillis < current.Candidate.IssuedAtMillis {
		current.AckEnqueuedAtMillis = current.Candidate.IssuedAtMillis
	}
	if err := validateSessionControlSessionAuthority(current); err != nil {
		return nil, err
	}
	s.sessions[candidate.SessionID] = current
	copy := current
	return &copy, nil
}

func testSessionControlSessionCandidate(seed byte, sessionID uint64) sessionControlSessionCandidate {
	return sessionControlSessionCandidate{
		CellID: "cell-01", AgentPublicKey: testACSessionControlPublicKey(seed), SessionID: sessionID,
		IssuedAtMillis: 1_800_000_000_000, ReservationDeadlineMillis: 1_800_000_030_000,
		RunID: "0123456789abcdef", RunAttempt: 1,
	}
}

func testSessionControlSessionSnapshot(version uint64, fences ...sessionControlFenceAuthority) sessionControlFenceSnapshot {
	return sessionControlFenceSnapshot{
		CellID: "cell-01", DirectoryVersion: version, ActiveFenceCount: uint64(len(fences)), Fences: fences,
	}
}

func testSessionControlSessionFenceAuthority(t *testing.T, event string, selector sessionControlFenceSelector,
	state sessionControlFenceState, directoryVersion uint64) sessionControlFenceAuthority {
	t.Helper()
	digest, err := sessionControlFenceSelectorDigest(selector)
	if err != nil {
		t.Fatal(err)
	}
	fence := sessionControlFenceAuthority{
		CellID: "cell-01", EventID: event, Selector: selector, SelectorDigest: digest,
		PreparedDirectoryVersion: directoryVersion, State: state, Version: 1,
		CreatedAtMillis: 1_800_000_000_000, PreparedAtMillis: 1_800_000_000_000, UpdatedAtMillis: 1_800_000_000_000,
	}
	if state == sessionControlFenceConverged {
		fence.Version = 2
		fence.ConvergedAtMillis = 1_800_000_001_000
		fence.ReplayNotBeforeMillis = 1_800_000_126_000
		fence.UpdatedAtMillis = fence.ConvergedAtMillis
	}
	return fence
}

func testSessionControlSessionTarget(seed byte) sessionControlTargetAuthority {
	return sessionControlTargetAuthority{
		ACID: "ac-session-target", PublicKey: testACSessionControlPublicKey(seed),
		BootID: "00112233445566778899aabbccddeeff", FlushGeneration: 3,
		State: sessionControlTargetActive, Version: 2, AuthorityVersion: 2, CountedActiveSlot: true,
		ControlCellID: "cell-01", ActivatedControlVersion: 1, ReadyControlVersion: 1,
		AAKEnqueuedAtMillis: 1_800_000_000_000, AAKTransactionID: 17,
		CreatedAtMillis: 1_800_000_000_000, PreparedAtMillis: 1_800_000_000_000,
		UpdatedAtMillis: 1_800_000_000_000,
	}
}

func TestMemorySessionControlIntentRequiresFinalizedTargetReadiness(t *testing.T) {
	snapshot := testSessionControlSessionSnapshot(1)
	store := newMemorySessionControlSessionModel(snapshot)
	candidate := testSessionControlSessionCandidate(0x30, 6)
	if _, err := store.ReserveSession(context.Background(), candidate, snapshot); err != nil {
		t.Fatal(err)
	}
	target := testSessionControlSessionTarget(0x31)
	target.ReadyControlVersion = 0
	target.AAKEnqueuedAtMillis = 0
	target.AAKTransactionID = 0
	store.setTarget(target)
	if _, err := store.PrepareSessionIntentCurrent(context.Background(), candidate, target,
		candidate.IssuedAtMillis+60_000, candidate.IssuedAtMillis+90_000, snapshot); err == nil {
		t.Fatal("active but unready target admitted a session intent")
	}
	if _, err := planSessionControlIntent(store.sessions[candidate.SessionID].fence(), target,
		candidate.IssuedAtMillis+60_000, candidate.IssuedAtMillis+90_000, snapshot); err == nil {
		t.Fatal("planner accepted active but unready target")
	}
}

func TestSessionControlSessionFenceEvaluationRules(t *testing.T) {
	candidate := testSessionControlSessionCandidate(0x31, 7)
	agent := candidate.AgentPublicKey
	tests := []struct {
		name     string
		selector sessionControlFenceSelector
		state    sessionControlFenceState
		mutate   func(*sessionControlSessionCandidate)
		denied   bool
	}{
		{name: "exact match preparing", selector: sessionControlFenceSelector{Scope: sessionControlFenceSelectorExact, AgentPublicKey: agent, SessionID: 7, SessionIssuedMillis: candidate.IssuedAtMillis}, state: sessionControlFencePreparing, denied: true},
		{name: "exact sibling allowed", selector: sessionControlFenceSelector{Scope: sessionControlFenceSelectorExact, AgentPublicKey: agent, SessionID: 8, SessionIssuedMillis: candidate.IssuedAtMillis}, state: sessionControlFenceConverged},
		{name: "agent preparing denies newer", selector: sessionControlFenceSelector{Scope: sessionControlFenceSelectorAgent, AgentPublicKey: agent, IssuedThroughMillis: candidate.IssuedAtMillis - 1}, state: sessionControlFencePreparing, denied: true},
		{name: "agent converged denies cutoff", selector: sessionControlFenceSelector{Scope: sessionControlFenceSelectorAgent, AgentPublicKey: agent, IssuedThroughMillis: candidate.IssuedAtMillis}, state: sessionControlFenceConverged, denied: true},
		{name: "agent converged allows newer", selector: sessionControlFenceSelector{Scope: sessionControlFenceSelectorAgent, AgentPublicKey: agent, IssuedThroughMillis: candidate.IssuedAtMillis - 1}, state: sessionControlFenceConverged},
		{name: "run preparing denies run", selector: sessionControlFenceSelector{Scope: sessionControlFenceSelectorRun, AgentPublicKey: agent, RunID: candidate.RunID, RunAttempt: 2}, state: sessionControlFencePreparing, denied: true},
		{name: "run converged permits exact", selector: sessionControlFenceSelector{Scope: sessionControlFenceSelectorRun, AgentPublicKey: agent, RunID: candidate.RunID, RunAttempt: 1}, state: sessionControlFenceConverged},
		{name: "run converged denies other attempt", selector: sessionControlFenceSelector{Scope: sessionControlFenceSelectorRun, AgentPublicKey: agent, RunID: candidate.RunID, RunAttempt: 2}, state: sessionControlFenceConverged, denied: true},
	}
	for index, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fence := testSessionControlSessionFenceAuthority(t, fmt.Sprintf("%032x", index+1), tt.selector, tt.state, 2)
			err := evaluateSessionControlFences(candidate, testSessionControlSessionSnapshot(2, fence))
			if tt.denied && !errors.Is(err, errSessionControlSessionFenceDenied) {
				t.Fatalf("evaluation error = %v, want denied", err)
			}
			if !tt.denied && err != nil {
				t.Fatalf("evaluation error = %v, want allowed", err)
			}
		})
	}
}

func TestSessionControlSessionCandidateAcceptsOptionalCanonicalRunBinding(t *testing.T) {
	candidate := testSessionControlSessionCandidate(0x30, 6)
	if !validSessionControlSessionCandidate(candidate) {
		t.Fatal("registered session candidate rejected")
	}
	candidate.RunID = ""
	candidate.RunAttempt = 0
	if !validSessionControlSessionCandidate(candidate) {
		t.Fatal("generic session candidate rejected")
	}
	candidate.RunAttempt = 1
	if validSessionControlSessionCandidate(candidate) {
		t.Fatal("partial run binding accepted")
	}
	candidate = testSessionControlSessionCandidate(0x30, 6)
	candidate.ReservationDeadlineMillis++
	if validSessionControlSessionCandidate(candidate) {
		t.Fatal("reservation beyond the pending horizon accepted")
	}

	unbound := testSessionControlSessionCandidate(0x30, 6)
	unbound.RunID = ""
	unbound.RunAttempt = 0
	runFence := testSessionControlSessionFenceAuthority(t, "30303030303030303030303030303030", sessionControlFenceSelector{
		Scope: sessionControlFenceSelectorRun, AgentPublicKey: unbound.AgentPublicKey,
		RunID: "0123456789abcdef", RunAttempt: 1,
	}, sessionControlFencePreparing, 2)
	if err := evaluateSessionControlFences(unbound, testSessionControlSessionSnapshot(2, runFence)); err != nil {
		t.Fatalf("run fence denied generic session: %v", err)
	}
}

func TestMemorySessionControlReservationIsIdempotentAndDetectsCrossServerNumericCollision(t *testing.T) {
	snapshot := testSessionControlSessionSnapshot(1)
	store := newMemorySessionControlSessionModel(snapshot)
	left := testSessionControlSessionCandidate(0x32, 99)
	right := testSessionControlSessionCandidate(0x33, 99)
	const workers = 32
	var wait sync.WaitGroup
	errs := make(chan error, workers)
	for index := range workers {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			candidate := left
			if index%2 == 1 {
				candidate = right
			}
			_, err := store.ReserveSession(context.Background(), candidate, snapshot)
			errs <- err
		}(index)
	}
	wait.Wait()
	close(errs)
	var successes, collisions int
	for err := range errs {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, errSessionControlSessionCollision):
			collisions++
		default:
			t.Fatalf("reservation error = %v", err)
		}
	}
	if successes != workers/2 || collisions != workers/2 {
		t.Fatalf("success/collision = %d/%d, want %d/%d", successes, collisions, workers/2, workers/2)
	}
	if got := len(store.sessions); got != 1 {
		t.Fatalf("durable numeric sessions = %d, want 1", got)
	}
}

func TestMemorySessionControlFenceAndReservationHaveAtomicOrdering(t *testing.T) {
	candidate := testSessionControlSessionCandidate(0x34, 100)
	selector := sessionControlFenceSelector{
		Scope: sessionControlFenceSelectorExact, AgentPublicKey: candidate.AgentPublicKey,
		SessionID: candidate.SessionID, SessionIssuedMillis: candidate.IssuedAtMillis,
	}
	fence := testSessionControlSessionFenceAuthority(t, "11111111111111111111111111111111", selector, sessionControlFencePreparing, 2)
	fencedSnapshot := testSessionControlSessionSnapshot(2, fence)

	fenceFirst := newMemorySessionControlSessionModel(fencedSnapshot)
	if _, err := fenceFirst.ReserveSession(context.Background(), candidate, fencedSnapshot); !errors.Is(err, errSessionControlSessionFenceDenied) {
		t.Fatalf("fence-first reservation error = %v, want denied", err)
	}

	reserveSnapshot := testSessionControlSessionSnapshot(1)
	reserveFirst := newMemorySessionControlSessionModel(reserveSnapshot)
	reserved, err := reserveFirst.ReserveSession(context.Background(), candidate, reserveSnapshot)
	if err != nil {
		t.Fatal(err)
	}
	reserveFirst.setSnapshot(fencedSnapshot)
	if _, err := reserveFirst.ReserveSession(context.Background(), candidate, fencedSnapshot); !errors.Is(err, errSessionControlSessionFenceDenied) {
		t.Fatalf("reserve-first fenced replay error = %v, want denied", err)
	}
	if current := reserveFirst.sessions[candidate.SessionID]; current != *reserved {
		t.Fatalf("fenced replay mutated reservation = %#v, want %#v", current, reserved)
	}
}

func TestMemorySessionControlIntentRetryCountsOnceAndRetainsAmbiguousMayBeAdmitted(t *testing.T) {
	snapshot := testSessionControlSessionSnapshot(1)
	store := newMemorySessionControlSessionModel(snapshot)
	candidate := testSessionControlSessionCandidate(0x35, 101)
	reserved, err := store.ReserveSession(context.Background(), candidate, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	target := testSessionControlSessionTarget(0x41)
	store.setTarget(target)
	first, err := store.PrepareSessionIntent(context.Background(), reserved.fence(), target,
		candidate.IssuedAtMillis+60_000, candidate.IssuedAtMillis+90_000, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	idempotent, err := store.PrepareSessionIntent(context.Background(), first.Session.fence(), target,
		candidate.IssuedAtMillis+60_000, candidate.IssuedAtMillis+90_000, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if idempotent.Session.TargetCount != 1 || idempotent.Session.Version != 3 {
		t.Fatalf("exact retry session = %#v, want version 3 and count 1", idempotent.Session)
	}
	extended, err := store.PrepareSessionIntent(context.Background(), idempotent.Session.fence(), target,
		candidate.IssuedAtMillis+60_000, candidate.IssuedAtMillis+150_000, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if extended.Session.TargetCount != 1 || extended.Session.Version != 4 ||
		extended.Session.RetainUntilMillis != candidate.IssuedAtMillis+150_000 ||
		extended.Intent.SessionExpiresAtMillis != candidate.IssuedAtMillis+60_000 ||
		extended.Intent.RetainUntilMillis != candidate.IssuedAtMillis+150_000 ||
		extended.Intent.State != sessionControlSessionIntentMayBeAdmitted || len(store.intents) != 1 || len(store.reverse) != 1 {
		t.Fatalf("extended intent state = %#v session=%#v", extended.Intent, extended.Session)
	}
	// ART denial and timeout deliberately have no destructive state transition.
	if got := store.intents[memorySessionIntentKey(candidate, target)]; got.State != sessionControlSessionIntentMayBeAdmitted {
		t.Fatalf("ambiguous intent state after terminal outcomes = %q", got.State)
	}
}

func TestMemorySessionControlIntentSurvivesSameProcessReconnect(t *testing.T) {
	snapshot := testSessionControlSessionSnapshot(1)
	store := newMemorySessionControlSessionModel(snapshot)
	candidate := testSessionControlSessionCandidate(0x46, 110)
	reserved, err := store.ReserveSession(context.Background(), candidate, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	target := testSessionControlSessionTarget(0x47)
	store.setTarget(target)
	first, err := store.PrepareSessionIntent(context.Background(), reserved.fence(), target,
		candidate.IssuedAtMillis+60_000, candidate.IssuedAtMillis+90_000, snapshot)
	if err != nil {
		t.Fatal(err)
	}

	preparing := target
	preparing.State = sessionControlTargetPreparing
	preparing.Version++
	preparing.AuthorityVersion++
	preparing.ActivatedControlVersion = 0
	preparing.ReadyControlVersion = 0
	preparing.AAKEnqueuedAtMillis = 0
	preparing.AAKTransactionID = 0
	preparing.PreparedAtMillis++
	preparing.UpdatedAtMillis++
	store.setTarget(preparing)
	oldReverseKey := memoryTargetSessionKey(candidate, target)
	if got, ok := store.reverse[memoryTargetSessionKey(candidate, preparing)]; !ok || got != first.Intent ||
		memoryTargetSessionKey(candidate, preparing) != oldReverseKey {
		t.Fatalf("old reverse intent is not discoverable during reconnect: %#v, %v", got, ok)
	}

	reactivated := preparing
	reactivated.State = sessionControlTargetActive
	reactivated.Version++
	reactivated.AuthorityVersion++
	reactivated.ActivatedControlVersion = 2
	reactivated.UpdatedAtMillis++
	reactivated.ReadyControlVersion = 2
	reactivated.AAKEnqueuedAtMillis = reactivated.UpdatedAtMillis
	reactivated.AAKTransactionID++
	newSnapshot := testSessionControlSessionSnapshot(2)
	store.setSnapshot(newSnapshot)
	store.setTarget(reactivated)
	extended, err := store.PrepareSessionIntent(context.Background(), first.Session.fence(), reactivated,
		candidate.IssuedAtMillis+60_000, candidate.IssuedAtMillis+150_000, newSnapshot)
	if err != nil {
		t.Fatal(err)
	}
	if extended.Session.TargetCount != 1 || extended.Intent.Target != reactivated ||
		len(store.intents) != 1 || len(store.reverse) != 1 {
		t.Fatalf("same-process reconnect extension = %#v; forward/reverse=%d/%d",
			extended, len(store.intents), len(store.reverse))
	}

	newProcess := reactivated
	newProcess.BootID = "aabbccddeeff00112233445566778899"
	newProcess.FlushGeneration++
	newProcess.Version += 2
	newProcess.AuthorityVersion += 2
	newProcess.PreparedAtMillis++
	newProcess.UpdatedAtMillis++
	newProcess.AAKEnqueuedAtMillis = newProcess.UpdatedAtMillis
	newProcess.AAKTransactionID++
	store.setTarget(newProcess)
	second, err := store.PrepareSessionIntent(context.Background(), extended.Session.fence(), newProcess,
		candidate.IssuedAtMillis+60_000, candidate.IssuedAtMillis+150_000, newSnapshot)
	if err != nil {
		t.Fatal(err)
	}
	if second.Session.TargetCount != 2 || len(store.intents) != 2 || len(store.reverse) != 2 ||
		memoryTargetSessionKey(candidate, newProcess) == oldReverseKey {
		t.Fatalf("new-process intent = %#v; forward/reverse=%d/%d",
			second, len(store.intents), len(store.reverse))
	}
}

func TestSessionControlTargetExtensionRejectsRollbackAndCrossProcess(t *testing.T) {
	current := testSessionControlSessionTarget(0x48)
	validNext := current
	validNext.Version++
	validNext.AuthorityVersion++
	validNext.ActivatedControlVersion++
	validNext.ReadyControlVersion++
	validNext.PreparedAtMillis++
	validNext.UpdatedAtMillis++
	validNext.AAKEnqueuedAtMillis++
	validNext.AAKTransactionID++
	if !sessionControlTargetCanExtend(current, current) || !sessionControlTargetCanExtend(current, validNext) {
		t.Fatal("exact or monotonic target extension rejected")
	}
	tests := map[string]func(*sessionControlTargetAuthority){
		"version rollback":   func(target *sessionControlTargetAuthority) { target.Version = current.Version - 1 },
		"authority rollback": func(target *sessionControlTargetAuthority) { target.AuthorityVersion = current.AuthorityVersion - 1 },
		"cursor rollback": func(target *sessionControlTargetAuthority) {
			target.ActivatedControlVersion = current.ActivatedControlVersion - 1
		},
		"created time change": func(target *sessionControlTargetAuthority) { target.CreatedAtMillis++ },
		"prepared rollback":   func(target *sessionControlTargetAuthority) { target.PreparedAtMillis = current.PreparedAtMillis - 1 },
		"updated rollback":    func(target *sessionControlTargetAuthority) { target.UpdatedAtMillis = current.UpdatedAtMillis - 1 },
		"boot change":         func(target *sessionControlTargetAuthority) { target.BootID = "ffeeddccbbaa99887766554433221100" },
		"generation change":   func(target *sessionControlTargetAuthority) { target.FlushGeneration++ },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			target := validNext
			mutate(&target)
			if sessionControlTargetCanExtend(current, target) {
				t.Fatalf("rollback/cross-process target accepted: %#v", target)
			}
		})
	}
	older := current
	older.UpdatedAtMillis = older.PreparedAtMillis + 10
	between := older
	between.Version++
	between.AuthorityVersion++
	between.ActivatedControlVersion++
	between.ReadyControlVersion++
	between.PreparedAtMillis = older.PreparedAtMillis + 5
	between.UpdatedAtMillis = older.UpdatedAtMillis + 1
	between.AAKEnqueuedAtMillis = between.UpdatedAtMillis
	between.AAKTransactionID++
	if validateSessionControlTargetAuthority(older) != nil || validateSessionControlTargetAuthority(between) != nil {
		t.Fatal("prepared-vs-updated fixture is not independently valid")
	}
	if sessionControlTargetCanExtend(older, between) {
		t.Fatalf("target prepared between old prepared/updated was accepted: old=%#v next=%#v", older, between)
	}
}

func TestMemorySessionControlConcurrentSameProcessExtensionsKeepExactPair(t *testing.T) {
	snapshot := testSessionControlSessionSnapshot(1)
	store := newMemorySessionControlSessionModel(snapshot)
	candidate := testSessionControlSessionCandidate(0x4d, 113)
	reserved, err := store.ReserveSession(context.Background(), candidate, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	target := testSessionControlSessionTarget(0x4e)
	store.setTarget(target)
	first, err := store.PrepareSessionIntent(context.Background(), reserved.fence(), target,
		candidate.IssuedAtMillis+60_000, candidate.IssuedAtMillis+90_000, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	reactivated := target
	reactivated.Version += 2
	reactivated.AuthorityVersion += 2
	reactivated.PreparedAtMillis++
	reactivated.UpdatedAtMillis++
	reactivated.AAKEnqueuedAtMillis = reactivated.UpdatedAtMillis
	reactivated.AAKTransactionID++
	store.setTarget(reactivated)

	const workers = 16
	var wait sync.WaitGroup
	errs := make(chan error, workers)
	for index := range workers {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			_, err := store.PrepareSessionIntent(context.Background(), first.Session.fence(), reactivated,
				candidate.IssuedAtMillis+60_000, candidate.IssuedAtMillis+150_000+int64(index), snapshot)
			errs <- err
		}(index)
	}
	wait.Wait()
	close(errs)
	var successes, conflicts int
	for err := range errs {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, errSessionControlSessionConflict):
			conflicts++
		default:
			t.Fatalf("concurrent extension error = %v", err)
		}
	}
	if successes != 1 || conflicts != workers-1 {
		t.Fatalf("extension success/conflict = %d/%d, want 1/%d", successes, conflicts, workers-1)
	}
	forward := store.intents[memorySessionIntentKey(candidate, reactivated)]
	reverse := store.reverse[memoryTargetSessionKey(candidate, reactivated)]
	current := store.sessions[candidate.SessionID]
	if forward != reverse || forward.Target != reactivated || forward.SessionVersion != current.Version ||
		current.TargetCount != 1 || len(store.intents) != 1 || len(store.reverse) != 1 {
		t.Fatalf("concurrent extension state: session=%#v forward=%#v reverse=%#v", current, forward, reverse)
	}
}

func TestMemorySessionControlPrepareCurrentRetriesConcurrentMultiTargetFanout(t *testing.T) {
	snapshot := testSessionControlSessionSnapshot(1)
	store := newMemorySessionControlSessionModel(snapshot)
	candidate := testSessionControlSessionCandidate(0x4f, 114)
	if _, err := store.ReserveSession(context.Background(), candidate, snapshot); err != nil {
		t.Fatal(err)
	}
	targets := make([]sessionControlTargetAuthority, MaxACConnsPerID)
	for index := range targets {
		targets[index] = testSessionControlSessionTarget(byte(0x50 + index))
		store.setTarget(targets[index])
	}
	var firstReads sync.WaitGroup
	firstReads.Add(len(targets))
	releaseFirstReads := make(chan struct{})
	store.prepareCurrentReadHook = func(attempt int) {
		if attempt == 0 {
			firstReads.Done()
			<-releaseFirstReads
		}
	}
	var wait sync.WaitGroup
	errs := make(chan error, len(targets))
	for index, target := range targets {
		wait.Add(1)
		go func(index int, target sessionControlTargetAuthority) {
			defer wait.Done()
			_, err := store.PrepareSessionIntentCurrent(context.Background(), candidate, target,
				candidate.IssuedAtMillis+60_000, candidate.IssuedAtMillis+90_000+int64(index), snapshot)
			errs <- err
		}(index, target)
	}
	firstReads.Wait()
	close(releaseFirstReads)
	wait.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("parallel current-fence preparation error = %v", err)
		}
	}
	current := store.sessions[candidate.SessionID]
	if current.Version != uint64(MaxACConnsPerID+1) || current.TargetCount != uint64(MaxACConnsPerID) ||
		len(store.intents) != MaxACConnsPerID || len(store.reverse) != MaxACConnsPerID {
		t.Fatalf("parallel fanout state = %#v forward/reverse=%d/%d", current, len(store.intents), len(store.reverse))
	}
}

func TestMemorySessionControlVerifySessionRequiresExactCurrentAuthority(t *testing.T) {
	snapshot := testSessionControlSessionSnapshot(1)
	store := newMemorySessionControlSessionModel(snapshot)
	candidate := testSessionControlSessionCandidate(0x52, 115)
	reserved, err := store.ReserveSession(context.Background(), candidate, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := store.VerifySession(context.Background(), candidate, snapshot)
	if err != nil || *verified != *reserved {
		t.Fatalf("VerifySession() = %#v, %v; want %#v", verified, err, reserved)
	}
	store.nowMillis = candidate.ReservationDeadlineMillis - 1
	if _, err := store.VerifySession(context.Background(), candidate, snapshot); err != nil {
		t.Fatalf("VerifySession before provisional deadline: %v", err)
	}
	store.nowMillis = candidate.ReservationDeadlineMillis
	if _, err := store.VerifySession(context.Background(), candidate, snapshot); !errors.Is(err, errSessionControlSessionFenceDenied) {
		t.Fatalf("VerifySession at provisional deadline error = %v, want denied", err)
	}
	store.nowMillis = candidate.IssuedAtMillis + 10_000
	collision := candidate
	collision.AgentPublicKey = testACSessionControlPublicKey(0x53)
	if _, err := store.VerifySession(context.Background(), collision, snapshot); !errors.Is(err, errSessionControlSessionCollision) {
		t.Fatalf("numeric collision verify error = %v", err)
	}
	store.setSnapshot(testSessionControlSessionSnapshot(2))
	if _, err := store.VerifySession(context.Background(), candidate, snapshot); !errors.Is(err, errSessionControlSessionFenceStale) {
		t.Fatalf("stale directory verify error = %v", err)
	}
	selector := sessionControlFenceSelector{Scope: sessionControlFenceSelectorExact,
		AgentPublicKey: candidate.AgentPublicKey, SessionID: candidate.SessionID,
		SessionIssuedMillis: candidate.IssuedAtMillis}
	fence := testSessionControlSessionFenceAuthority(t, "52525252525252525252525252525252",
		selector, sessionControlFencePreparing, 2)
	if _, err := store.VerifySession(context.Background(), candidate,
		testSessionControlSessionSnapshot(2, fence)); !errors.Is(err, errSessionControlSessionFenceDenied) {
		t.Fatalf("fenced verify error = %v", err)
	}
}

func TestMemorySessionControlVerifyReservedIntentUsesServingDeadline(t *testing.T) {
	snapshot := testSessionControlSessionSnapshot(1)
	store := newMemorySessionControlSessionModel(snapshot)
	candidate := testSessionControlSessionCandidate(0x53, 117)
	reserved, err := store.ReserveSession(context.Background(), candidate, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	target := testSessionControlSessionTarget(0x54)
	store.setTarget(target)
	prepared, err := store.PrepareSessionIntent(context.Background(), reserved.fence(), target,
		candidate.IssuedAtMillis+60_000, candidate.IssuedAtMillis+90_000, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	store.nowMillis = prepared.Session.SessionExpiresAtMillis - 1
	if _, err := store.VerifySession(context.Background(), candidate, snapshot); err != nil {
		t.Fatalf("VerifySession before serving deadline: %v", err)
	}
	store.nowMillis = prepared.Session.SessionExpiresAtMillis
	if _, err := store.VerifySession(context.Background(), candidate, snapshot); !errors.Is(err, errSessionControlSessionFenceDenied) {
		t.Fatalf("VerifySession at serving deadline error = %v, want denied", err)
	}
}

func TestMemorySessionControlServingExpiryIsImmutableAndFenced(t *testing.T) {
	snapshot := testSessionControlSessionSnapshot(1)
	store := newMemorySessionControlSessionModel(snapshot)
	candidate := testSessionControlSessionCandidate(0x56, 118)
	if _, err := store.ReserveSession(context.Background(), candidate, snapshot); err != nil {
		t.Fatal(err)
	}
	firstTarget := testSessionControlSessionTarget(0x57)
	secondTarget := testSessionControlSessionTarget(0x58)
	store.setTarget(firstTarget)
	store.setTarget(secondTarget)
	expiresAt := candidate.IssuedAtMillis + 60_000
	store.nowMillis = expiresAt
	if _, err := store.PrepareSessionIntentCurrent(context.Background(), candidate, firstTarget,
		expiresAt, candidate.IssuedAtMillis+90_000, snapshot); !errors.Is(err, errSessionControlSessionFenceDenied) {
		t.Fatalf("first intent at expiry error = %v, want denied", err)
	}
	store.nowMillis = expiresAt - 1
	first, err := store.PrepareSessionIntentCurrent(context.Background(), candidate, firstTarget,
		expiresAt, candidate.IssuedAtMillis+90_000, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if first.Session.SessionExpiresAtMillis != expiresAt {
		t.Fatalf("first serving expiry = %d, want %d", first.Session.SessionExpiresAtMillis, expiresAt)
	}
	if _, err := store.PrepareSessionIntentCurrent(context.Background(), candidate, secondTarget,
		expiresAt+1, candidate.IssuedAtMillis+90_001, snapshot); !errors.Is(err, errSessionControlSessionConflict) {
		t.Fatalf("later target changed serving expiry error = %v, want conflict", err)
	}
	if _, err := store.PrepareSessionIntentCurrent(context.Background(), candidate, firstTarget,
		expiresAt+1, candidate.IssuedAtMillis+90_001, snapshot); !errors.Is(err, errSessionControlSessionConflict) {
		t.Fatalf("extension changed serving expiry error = %v, want conflict", err)
	}
	store.nowMillis = expiresAt
	if _, err := store.PrepareSessionIntentCurrent(context.Background(), candidate, secondTarget,
		expiresAt, candidate.IssuedAtMillis+90_000, snapshot); !errors.Is(err, errSessionControlSessionFenceDenied) {
		t.Fatalf("later target at serving expiry error = %v, want denied", err)
	}
	if _, err := store.MarkSessionAckEnqueued(context.Background(), candidate, snapshot); !errors.Is(err, errSessionControlSessionFenceDenied) {
		t.Fatalf("first ACK at serving expiry error = %v, want denied", err)
	}
	store.nowMillis = expiresAt - 1
	acked, err := store.MarkSessionAckEnqueued(context.Background(), candidate, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	store.nowMillis = expiresAt + 1
	replayed, err := store.MarkSessionAckEnqueued(context.Background(), candidate, snapshot)
	if err != nil || *replayed != *acked {
		t.Fatalf("post-expiry ACK replay = %#v, %v; want %#v", replayed, err, acked)
	}
}

func TestMemorySessionControlAckStateIsMonotonicAndFenced(t *testing.T) {
	snapshot := testSessionControlSessionSnapshot(1)
	store := newMemorySessionControlSessionModel(snapshot)
	candidate := testSessionControlSessionCandidate(0x54, 116)
	reserved, err := store.ReserveSession(context.Background(), candidate, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.MarkSessionAckEnqueued(context.Background(), candidate, snapshot); !errors.Is(err, errSessionControlSessionConflict) {
		t.Fatalf("targetless ACK error = %v, want conflict", err)
	}
	target := testSessionControlSessionTarget(0x55)
	store.setTarget(target)
	prepared, err := store.PrepareSessionIntentCurrent(context.Background(), candidate, target,
		candidate.IssuedAtMillis+60_000, candidate.IssuedAtMillis+90_000, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	acked, err := store.MarkSessionAckEnqueued(context.Background(), candidate, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if acked.State != sessionControlSessionStateAckEnqueued || acked.Version != prepared.Session.Version ||
		acked.TargetCount != prepared.Session.TargetCount || acked.AckEnqueuedAtMillis != store.nowMillis {
		t.Fatalf("ACK state changed intent authority = %#v", acked)
	}
	store.nowMillis++
	replayed, err := store.MarkSessionAckEnqueued(context.Background(), candidate, snapshot)
	if err != nil || *replayed != *acked {
		t.Fatalf("ACK replay = %#v, %v; want %#v", replayed, err, acked)
	}
	if _, err := store.VerifySession(context.Background(), candidate, snapshot); !errors.Is(err, errSessionControlSessionFenceDenied) {
		t.Fatalf("acked session verify error = %v, want denied", err)
	}
	if _, err := store.PrepareSessionIntentCurrent(context.Background(), candidate, target,
		candidate.IssuedAtMillis+120_000, candidate.IssuedAtMillis+150_000, snapshot); !errors.Is(err, errSessionControlSessionConflict) {
		t.Fatalf("post-ACK intent error = %v, want conflict", err)
	}

	closing := *acked
	closing.State = sessionControlSessionStateClosing
	closing.CloseEventID = "54545454545454545454545454545454"
	closing.ClosePreparedDirectory = 2
	closing.ClosePreparedAtMillis = closing.Candidate.IssuedAtMillis + 1
	store.sessions[candidate.SessionID] = closing
	store.setSnapshot(testSessionControlSessionSnapshot(2))
	if _, err := store.MarkSessionAckEnqueued(context.Background(), candidate,
		testSessionControlSessionSnapshot(2)); !errors.Is(err, errSessionControlSessionFenceDenied) {
		t.Fatalf("close-first ACK error = %v, want denied", err)
	}
	if _, err := store.VerifySession(context.Background(), candidate,
		testSessionControlSessionSnapshot(2)); !errors.Is(err, errSessionControlSessionFenceDenied) {
		t.Fatalf("closing verify error = %v, want denied", err)
	}
	if reserved.State != sessionControlSessionStateReserved {
		t.Fatalf("reservation fixture mutated = %#v", reserved)
	}
}

func TestSessionControlIntentSatisfiesExactDirectoryCursor(t *testing.T) {
	candidate := testSessionControlSessionCandidate(0x49, 111)
	target := testSessionControlSessionTarget(0x4a)
	requested := sessionControlSessionIntent{
		Session: candidate, Target: target, State: sessionControlSessionIntentMayBeAdmitted,
		SessionVersion: 2, SessionExpiresAtMillis: candidate.IssuedAtMillis + 60_000,
		RetainUntilMillis:        candidate.IssuedAtMillis + 90_000,
		PreparedDirectoryVersion: 3, PreparedActiveFenceCount: 1,
	}
	stored := requested
	stored.RetainUntilMillis++
	if !sessionControlIntentSatisfies(stored, requested) {
		t.Fatal("monotonic retention extension did not satisfy exact request cursor")
	}
	stored.SessionExpiresAtMillis++
	if sessionControlIntentSatisfies(stored, requested) {
		t.Fatal("changed serving expiry satisfied immutable request")
	}
	stored.SessionExpiresAtMillis = requested.SessionExpiresAtMillis
	stored.PreparedDirectoryVersion++
	if sessionControlIntentSatisfies(stored, requested) {
		t.Fatal("future directory cursor satisfied an older transaction")
	}
	stored = requested
	stored.PreparedActiveFenceCount++
	if sessionControlIntentSatisfies(stored, requested) {
		t.Fatal("wrong active-fence count satisfied a transaction")
	}
}

func TestMemorySessionControlIntentRejectsAuthorityAndDirectoryRaces(t *testing.T) {
	newFixture := func(t *testing.T) (*memorySessionControlSessionModel, sessionControlSessionAuthority, sessionControlTargetAuthority, sessionControlFenceSnapshot) {
		t.Helper()
		snapshot := testSessionControlSessionSnapshot(1)
		store := newMemorySessionControlSessionModel(snapshot)
		reserved, err := store.ReserveSession(context.Background(), testSessionControlSessionCandidate(0x36, 102), snapshot)
		if err != nil {
			t.Fatal(err)
		}
		target := testSessionControlSessionTarget(0x42)
		store.setTarget(target)
		return store, *reserved, target, snapshot
	}
	t.Run("target replacement", func(t *testing.T) {
		store, reserved, target, snapshot := newFixture(t)
		replacement := target
		replacement.BootID = "ffeeddccbbaa99887766554433221100"
		replacement.FlushGeneration++
		replacement.Version++
		store.setTarget(replacement)
		if _, err := store.PrepareSessionIntent(context.Background(), reserved.fence(), target,
			reserved.Candidate.IssuedAtMillis+60_000, reserved.Candidate.IssuedAtMillis+90_000, snapshot); !errors.Is(err, errSessionControlSessionTargetConflict) {
			t.Fatalf("replacement error = %v, want target conflict", err)
		}
	})
	t.Run("target retirement", func(t *testing.T) {
		store, reserved, target, snapshot := newFixture(t)
		retired := target
		retired.State = sessionControlTargetRetired
		retired.CountedActiveSlot = false
		retired.RetiredAtMillis = retired.UpdatedAtMillis
		store.setTarget(retired)
		if _, err := store.PrepareSessionIntent(context.Background(), reserved.fence(), target,
			reserved.Candidate.IssuedAtMillis+60_000, reserved.Candidate.IssuedAtMillis+90_000, snapshot); !errors.Is(err, errSessionControlSessionTargetConflict) {
			t.Fatalf("retirement error = %v, want target conflict", err)
		}
	})
	t.Run("directory advance", func(t *testing.T) {
		store, reserved, target, snapshot := newFixture(t)
		store.setSnapshot(testSessionControlSessionSnapshot(2))
		if _, err := store.PrepareSessionIntent(context.Background(), reserved.fence(), target,
			reserved.Candidate.IssuedAtMillis+60_000, reserved.Candidate.IssuedAtMillis+90_000, snapshot); !errors.Is(err, errSessionControlSessionFenceStale) {
			t.Fatalf("directory advance error = %v, want fence stale", err)
		}
	})
}

func TestMemorySessionControlIntentRejectsMismatchesPartialPairAndCap(t *testing.T) {
	snapshot := testSessionControlSessionSnapshot(1)
	store := newMemorySessionControlSessionModel(snapshot)
	candidate := testSessionControlSessionCandidate(0x37, 103)
	reserved, err := store.ReserveSession(context.Background(), candidate, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	target := testSessionControlSessionTarget(0x43)
	store.setTarget(target)

	wrongSubject := reserved.fence()
	wrongSubject.Candidate.AgentPublicKey = testACSessionControlPublicKey(0x38)
	if _, err := store.PrepareSessionIntent(context.Background(), wrongSubject, target,
		candidate.IssuedAtMillis+60_000, candidate.IssuedAtMillis+90_000, snapshot); !errors.Is(err, errSessionControlSessionConflict) {
		t.Fatalf("subject mismatch error = %v, want conflict", err)
	}
	wrongTarget := target
	wrongTarget.PublicKey = testACSessionControlPublicKey(0x44)
	if _, err := store.PrepareSessionIntent(context.Background(), reserved.fence(), wrongTarget,
		candidate.IssuedAtMillis+60_000, candidate.IssuedAtMillis+90_000, snapshot); !errors.Is(err, errSessionControlSessionTargetConflict) {
		t.Fatalf("target mismatch error = %v, want target conflict", err)
	}

	prepared, err := store.PrepareSessionIntent(context.Background(), reserved.fence(), target,
		candidate.IssuedAtMillis+60_000, candidate.IssuedAtMillis+90_000, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	delete(store.reverse, memoryTargetSessionKey(candidate, target))
	if _, err := store.PrepareSessionIntent(context.Background(), reserved.fence(), target,
		candidate.IssuedAtMillis+60_000, candidate.IssuedAtMillis+90_000, snapshot); !errors.Is(err, errSessionControlSessionCorrupt) {
		t.Fatalf("partial pair error = %v, want corrupt", err)
	}
	store.reverse[memoryTargetSessionKey(candidate, target)] = prepared.Intent
	current := store.sessions[candidate.SessionID]
	current.TargetCount = sessionControlSessionMaxTargets
	current.Version = sessionControlSessionMaxTargets + 1
	store.sessions[candidate.SessionID] = current
	extended, err := store.PrepareSessionIntent(context.Background(), current.fence(), target,
		candidate.IssuedAtMillis+60_000, candidate.IssuedAtMillis+150_000, snapshot)
	if err != nil || extended.Session.TargetCount != sessionControlSessionMaxTargets {
		t.Fatalf("same-target extension at cap = %#v, %v", extended, err)
	}
	newTarget := testSessionControlSessionTarget(0x45)
	store.setTarget(newTarget)
	if _, err := store.PrepareSessionIntent(context.Background(), extended.Session.fence(), newTarget,
		candidate.IssuedAtMillis+60_000, candidate.IssuedAtMillis+90_000, snapshot); !errors.Is(err, errSessionControlSessionCapacity) {
		t.Fatalf("target cap error = %v, want capacity", err)
	}
}

func TestMemorySessionControlIntentRejectsImpossibleSessionPair(t *testing.T) {
	for _, tt := range []struct {
		name   string
		mutate func(*sessionControlSessionAuthority, *sessionControlSessionIntent)
	}{
		{
			name: "intent predates reservation cursor",
			mutate: func(session *sessionControlSessionAuthority, _ *sessionControlSessionIntent) {
				session.ReservedDirectoryVersion = 2
			},
		},
		{
			name: "same cursor has different active count",
			mutate: func(_ *sessionControlSessionAuthority, intent *sessionControlSessionIntent) {
				intent.PreparedActiveFenceCount = 1
			},
		},
		{
			name: "intent serving expiry differs from session",
			mutate: func(_ *sessionControlSessionAuthority, intent *sessionControlSessionIntent) {
				intent.SessionExpiresAtMillis++
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			baseSnapshot := testSessionControlSessionSnapshot(1)
			store := newMemorySessionControlSessionModel(baseSnapshot)
			candidate := testSessionControlSessionCandidate(0x4b, 112)
			reserved, err := store.ReserveSession(context.Background(), candidate, baseSnapshot)
			if err != nil {
				t.Fatal(err)
			}
			target := testSessionControlSessionTarget(0x4c)
			store.setTarget(target)
			prepared, err := store.PrepareSessionIntent(context.Background(), reserved.fence(), target,
				candidate.IssuedAtMillis+60_000, candidate.IssuedAtMillis+90_000, baseSnapshot)
			if err != nil {
				t.Fatal(err)
			}
			session := prepared.Session
			intent := prepared.Intent
			tt.mutate(&session, &intent)
			store.sessions[candidate.SessionID] = session
			store.intents[memorySessionIntentKey(candidate, target)] = intent
			store.reverse[memoryTargetSessionKey(candidate, target)] = intent
			snapshot := testSessionControlSessionSnapshot(2)
			store.setSnapshot(snapshot)
			_, err = store.PrepareSessionIntent(context.Background(), session.fence(), target,
				candidate.IssuedAtMillis+60_000, candidate.IssuedAtMillis+150_000, snapshot)
			if !errors.Is(err, errSessionControlSessionCorrupt) {
				t.Fatalf("PrepareSessionIntent() error = %v, want corrupt", err)
			}
		})
	}
}
