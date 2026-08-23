package server

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func testSessionControlFenceCandidate(eventID string, selector sessionControlFenceSelector) sessionControlFenceCandidate {
	return sessionControlFenceCandidate{CellID: "cell-01", EventID: eventID, Selector: selector}
}

func testSessionControlExactFenceSelector(seed byte) sessionControlFenceSelector {
	return sessionControlFenceSelector{
		Scope: sessionControlFenceSelectorExact, AgentPublicKey: testACSessionControlPublicKey(seed),
		SessionID: 7, SessionIssuedMillis: 1_800_000_000_000,
	}
}

func TestSessionControlFenceLifecycleRetainsActiveThroughReplayHorizon(t *testing.T) {
	started := time.Unix(1_800_000_000, 0).UTC()
	store := newMemorySessionControlFenceStore(started)
	candidate := testSessionControlFenceCandidate("00112233445566778899aabbccddeeff", testSessionControlExactFenceSelector(0x61))

	prepared, err := store.PrepareFence(context.Background(), candidate)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.State != sessionControlFencePreparing || prepared.Version != 1 || prepared.PreparedDirectoryVersion != 2 {
		t.Fatalf("prepared fence = %#v", prepared)
	}
	replayed, err := store.PrepareFence(context.Background(), candidate)
	if err != nil || *replayed != *prepared {
		t.Fatalf("prepare replay = %#v, %v; want %#v", replayed, err, prepared)
	}
	snapshot, err := store.SnapshotActiveFences(context.Background(), candidate.CellID)
	if err != nil || snapshot.DirectoryVersion != 2 || snapshot.ActiveFenceCount != 1 || len(snapshot.Fences) != 1 || snapshot.Fences[0] != *prepared {
		t.Fatalf("preparing snapshot = %#v, %v", snapshot, err)
	}

	convergedAt := started.Add(10 * time.Second)
	store.setNow(convergedAt)
	converged, err := store.MarkFenceConverged(context.Background(), *prepared)
	if err != nil {
		t.Fatal(err)
	}
	if converged.State != sessionControlFenceConverged || converged.Version != 2 ||
		converged.ReplayNotBeforeMillis != convergedAt.Add(sessionControlFenceReplayHorizon).UnixMilli() {
		t.Fatalf("converged fence = %#v", converged)
	}
	convergenceReplay, err := store.MarkFenceConverged(context.Background(), *prepared)
	if err != nil || *convergenceReplay != *converged {
		t.Fatalf("convergence replay = %#v, %v; want %#v", convergenceReplay, err, converged)
	}
	snapshot, err = store.SnapshotActiveFences(context.Background(), candidate.CellID)
	if err != nil || snapshot.DirectoryVersion != 3 || snapshot.ActiveFenceCount != 1 || snapshot.Fences[0] != *converged {
		t.Fatalf("converged snapshot = %#v, %v", snapshot, err)
	}
	if _, err := store.retireFence(context.Background(), *converged); !errors.Is(err, errSessionControlFenceReplayHorizon) {
		t.Fatalf("early retirement error = %v, want replay horizon", err)
	}

	store.setNow(time.UnixMilli(converged.ReplayNotBeforeMillis))
	retired, err := store.retireFence(context.Background(), *converged)
	if err != nil {
		t.Fatal(err)
	}
	if retired.State != sessionControlFenceRetired || retired.Version != 3 ||
		retired.ExpiresAt != retired.RetiredAtMillis/1_000+int64(sessionControlFenceIdempotencyTTL/time.Second) {
		t.Fatalf("retired fence = %#v", retired)
	}
	retirementReplay, err := store.retireFence(context.Background(), *converged)
	if err != nil || *retirementReplay != *retired {
		t.Fatalf("retirement replay = %#v, %v; want %#v", retirementReplay, err, retired)
	}
	snapshot, err = store.SnapshotActiveFences(context.Background(), candidate.CellID)
	if err != nil || snapshot.DirectoryVersion != 4 || snapshot.ActiveFenceCount != 0 || len(snapshot.Fences) != 0 {
		t.Fatalf("retired snapshot = %#v, %v", snapshot, err)
	}
	if _, err := store.PrepareFence(context.Background(), candidate); !errors.Is(err, errSessionControlFenceRetired) {
		t.Fatalf("retired event prepare error = %v, want retired", err)
	}
}

func TestSessionControlFenceEmptySnapshotInitializesVersionOne(t *testing.T) {
	store := newMemorySessionControlFenceStore(time.Unix(1_800_000_050, 0).UTC())
	snapshot, err := store.SnapshotActiveFences(context.Background(), "cell-02")
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.DirectoryVersion != 1 || snapshot.ActiveFenceCount != 0 || len(snapshot.Fences) != 0 {
		t.Fatalf("empty snapshot = %#v", snapshot)
	}
	if directory := store.directories["cell-02"]; directory.Version != 1 || directory.ActiveFenceCount != 0 {
		t.Fatalf("initialized directory = %#v", directory)
	}
}

func TestSessionControlFenceSelectorUnionAndCellPolicyAreClosed(t *testing.T) {
	agentKey := testACSessionControlPublicKey(0x62)
	valid := []sessionControlFenceSelector{
		{Scope: sessionControlFenceSelectorExact, AgentPublicKey: agentKey, SessionID: 1, SessionIssuedMillis: 2},
		{Scope: sessionControlFenceSelectorAgent, AgentPublicKey: agentKey, IssuedThroughMillis: 3},
		{Scope: sessionControlFenceSelectorRun, AgentPublicKey: agentKey, RunID: "0123456789abcdef", RunAttempt: 4},
	}
	for _, selector := range valid {
		if err := validateSessionControlFenceSelector(selector); err != nil {
			t.Fatalf("valid selector %#v rejected: %v", selector, err)
		}
	}
	invalid := []sessionControlFenceSelector{
		{},
		{Scope: sessionControlFenceSelectorExact, AgentPublicKey: agentKey, SessionID: 1, SessionIssuedMillis: 2, RunAttempt: 1},
		{Scope: sessionControlFenceSelectorAgent, AgentPublicKey: agentKey, IssuedThroughMillis: 3, SessionID: 1},
		{Scope: sessionControlFenceSelectorRun, AgentPublicKey: agentKey, RunID: "BAD", RunAttempt: 1},
	}
	for _, selector := range invalid {
		if err := validateSessionControlFenceSelector(selector); err == nil {
			t.Fatalf("invalid selector accepted: %#v", selector)
		}
	}
	for _, cellID := range []string{"cell0", "cell-01", "a"} {
		if !validSessionControlCellID(cellID) {
			t.Fatalf("valid cell id %q rejected", cellID)
		}
	}
	for _, cellID := range []string{"", "Cell0", "-cell", "cell-", "cell--0", "cell_0", "abcdefghijklmnopqrstuvwxyz1234567"} {
		if validSessionControlCellID(cellID) {
			t.Fatalf("invalid cell id %q accepted", cellID)
		}
	}
}

func TestSessionControlFenceConcurrentPrepareIsIdempotentAndCountsOnce(t *testing.T) {
	store := newMemorySessionControlFenceStore(time.Unix(1_800_000_100, 0))
	candidate := testSessionControlFenceCandidate("11111111111111111111111111111111", testSessionControlExactFenceSelector(0x63))
	const workers = 32
	results := make(chan *sessionControlFenceAuthority, workers)
	errs := make(chan error, workers)
	var wait sync.WaitGroup
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			fence, err := store.PrepareFence(context.Background(), candidate)
			if err != nil {
				errs <- err
				return
			}
			results <- fence
		}()
	}
	wait.Wait()
	close(results)
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent prepare error = %v", err)
	}
	var first *sessionControlFenceAuthority
	for result := range results {
		if first == nil {
			first = result
		} else if *result != *first {
			t.Fatalf("concurrent prepare mismatch: %#v vs %#v", result, first)
		}
	}
	directory := store.directories[candidate.CellID]
	if directory.ActiveFenceCount != 1 || directory.Version != 2 {
		t.Fatalf("directory after concurrent prepare = %#v", directory)
	}
}

func TestSessionControlFenceSnapshotFailsClosedOnCountOrMembershipDrift(t *testing.T) {
	store := newMemorySessionControlFenceStore(time.Unix(1_800_000_200, 0))
	candidate := testSessionControlFenceCandidate("22222222222222222222222222222222", testSessionControlExactFenceSelector(0x64))
	prepared, err := store.PrepareFence(context.Background(), candidate)
	if err != nil {
		t.Fatal(err)
	}
	directory := store.directories[candidate.CellID]
	directory.ActiveFenceCount = 0
	store.directories[candidate.CellID] = directory
	if _, err := store.SnapshotActiveFences(context.Background(), candidate.CellID); !errors.Is(err, errSessionControlFenceCorrupt) {
		t.Fatalf("count drift error = %v, want corrupt", err)
	}
	directory.ActiveFenceCount = 1
	store.directories[candidate.CellID] = directory
	active := store.active[candidate.CellID][candidate.EventID]
	active.PreparedDirectoryVersion = directory.Version + 1
	store.active[candidate.CellID][candidate.EventID] = active
	if _, err := store.SnapshotActiveFences(context.Background(), candidate.CellID); !errors.Is(err, errSessionControlFenceCorrupt) {
		t.Fatalf("future membership error = %v, want corrupt", err)
	}
	if got := store.metas[candidate.EventID]; got != *prepared {
		t.Fatalf("snapshot corruption test mutated meta = %#v", got)
	}
}

func TestSessionControlFenceImmutableSelectorAndVersionCeilingsFailClosed(t *testing.T) {
	store := newMemorySessionControlFenceStore(time.Unix(1_800_000_300, 0))
	candidate := testSessionControlFenceCandidate("33333333333333333333333333333333", testSessionControlExactFenceSelector(0x65))
	prepared, err := store.PrepareFence(context.Background(), candidate)
	if err != nil {
		t.Fatal(err)
	}
	changed := candidate
	changed.Selector.SessionID++
	if _, err := store.PrepareFence(context.Background(), changed); !errors.Is(err, errSessionControlFenceConflict) {
		t.Fatalf("selector mutation error = %v, want conflict", err)
	}
	ceiling := *prepared
	ceiling.Version = ^uint64(0) - 1
	store.metas[candidate.EventID] = ceiling
	store.active[candidate.CellID][candidate.EventID] = ceiling
	if _, err := store.MarkFenceConverged(context.Background(), ceiling); !errors.Is(err, errSessionControlFenceCorrupt) {
		t.Fatalf("fence version ceiling error = %v, want corrupt", err)
	}
}

func TestSessionControlFenceConcurrentImmutableMutationCannotBeOverwritten(t *testing.T) {
	store := newMemorySessionControlFenceStore(time.Unix(1_800_000_400, 0))
	candidate := testSessionControlFenceCandidate("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", testSessionControlExactFenceSelector(0x6c))
	prepared, err := store.PrepareFence(context.Background(), candidate)
	if err != nil {
		t.Fatal(err)
	}
	mutated := *prepared
	mutated.CreatedAtMillis++
	mutated.PreparedAtMillis++
	mutated.UpdatedAtMillis++
	store.metas[candidate.EventID] = mutated
	store.active[candidate.CellID][candidate.EventID] = mutated
	if _, err := store.MarkFenceConverged(context.Background(), *prepared); !errors.Is(err, errSessionControlFenceConflict) {
		t.Fatalf("immutable mutation mark error = %v, want conflict", err)
	}
	if got := store.metas[candidate.EventID]; got != mutated || got.State != sessionControlFencePreparing {
		t.Fatalf("immutable mutation was overwritten: %#v", got)
	}
}

func TestSessionControlFenceRetiredReplayRequiresActiveAbsence(t *testing.T) {
	started := time.Unix(1_800_000_500, 0)
	store := newMemorySessionControlFenceStore(started)
	candidate := testSessionControlFenceCandidate("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", testSessionControlExactFenceSelector(0x6d))
	prepared, err := store.PrepareFence(context.Background(), candidate)
	if err != nil {
		t.Fatal(err)
	}
	converged, err := store.MarkFenceConverged(context.Background(), *prepared)
	if err != nil {
		t.Fatal(err)
	}
	store.setNow(time.UnixMilli(converged.ReplayNotBeforeMillis))
	if _, err := store.retireFence(context.Background(), *converged); err != nil {
		t.Fatal(err)
	}
	store.active[candidate.CellID][candidate.EventID] = *converged
	if _, err := store.retireFence(context.Background(), *converged); !errors.Is(err, errSessionControlFenceCorrupt) {
		t.Fatalf("retired replay with lingering ACTIVE error = %v, want corrupt", err)
	}
}
