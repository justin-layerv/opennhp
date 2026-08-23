package server

import (
	"context"
	"errors"
	"math"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
)

func seedSessionControlLifecycleCleanupAudit(t *testing.T, fixture *sessionControlCleanupFixture,
	ownerPK string, seed uint64) {
	t.Helper()
	task, err := fixture.store.getCloseTask(context.Background(), ownerPK, fixture.close.EventID)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := fixture.store.getOwner(context.Background(), task.CellID, task.ACID, task.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	cleanedAt := fixture.store.nowUTC().UnixMilli()
	for _, candidate := range []int64{fixture.complete.CompletedAtMillis, task.UpdatedAtMillis, owner.UpdatedAtMillis} {
		if cleanedAt < candidate {
			cleanedAt = candidate
		}
	}
	if cleanedAt <= 0 || cleanedAt > math.MaxInt64-sessionControlFenceReplayHorizon.Milliseconds() {
		t.Fatalf("invalid seeded cleanup time %d", cleanedAt)
	}
	nextOwner, err := planSessionControlOwnerTaskCleanup(*owner, cleanedAt)
	if err != nil {
		t.Fatal(err)
	}
	request := sessionControlCleanupRequest(*fixture, ownerPK, seed)
	inputDigest, err := sessionControlCloseTaskCleanupInputDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	retainUntil := cleanedAt + sessionControlFenceReplayHorizon.Milliseconds()
	if retainUntil < fixture.complete.RetainUntilMillis {
		retainUntil = fixture.complete.RetainUntilMillis
	}
	audit := sessionControlCloseTaskAudit{CellID: request.CellID, EventID: request.EventID,
		OwnerPK: ownerPK, ManifestIndex: task.ManifestIndex, Complete: fixture.complete,
		AckedTask: *task, OwnerBefore: *owner, OwnerAfter: nextOwner, OperationID: request.OperationID,
		OperationInputDigest: inputDigest, CleanedAtMillis: cleanedAt, RetainUntilMillis: retainUntil}
	audit.AuditDigest, err = sessionControlCloseTaskAuditDigest(audit)
	if err != nil || validateSessionControlCloseTaskAudit(audit) != nil {
		t.Fatalf("invalid seeded cleanup audit: %#v, %v", audit, err)
	}
	row, err := sessionControlCloseTaskAuditToRow(audit)
	if err != nil {
		t.Fatal(err)
	}
	fixture.fake.setItem(marshalSessionControlSessionTestRow(t, row))
	seedSessionControlTaskOwner(t, fixture.fake, nextOwner)
	fixture.fake.mu.Lock()
	delete(fixture.fake.items, sessionControlSessionDynamoMapKey(sessionControlCloseTaskKey(ownerPK, task.EventID)))
	fixture.fake.mu.Unlock()
}

func advanceSessionControlLifecycleUntilTerminal(t *testing.T, s *UdpServer,
	store sessionControlCloseLifecycleStore, session sessionControlSessionAuthority, maxAttempts int) int {
	t.Helper()
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		err := s.advanceDurableExactCloseLifecycle(context.Background(), store, session)
		if err == nil {
			return attempt
		}
		if !sessionControlLifecycleRetryable(err) {
			t.Fatalf("advance lifecycle attempt %d: %v", attempt, err)
		}
	}
	t.Fatalf("lifecycle did not reach terminal authority in %d attempts", maxAttempts)
	return 0
}

func TestSessionControlLifecycleRecoveryAdvancesAckedCloseThroughTerminal(t *testing.T) {
	fixture := newSessionControlCompletionFixture(t, 1, true, true)
	installSessionControlTerminalTransactionFake(fixture.fake)
	fixture.store.nowUTC = func() time.Time {
		return time.UnixMilli(fixture.fence.ReplayNotBeforeMillis).UTC()
	}
	session, err := fixture.store.getSessionItem(context.Background(), fixture.candidate.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	s := &UdpServer{sessionControlCellID: fixture.candidate.CellID, sessionControlStore: fixture.store}
	advanceSessionControlLifecycleUntilTerminal(t, s, fixture.store, *session,
		len(fixture.taskSet.ManifestDigests)+2)
	closed, err := fixture.store.getSessionItem(context.Background(), fixture.candidate.SessionID)
	if err != nil || closed.State != sessionControlSessionStateClosed {
		t.Fatalf("advanced lifecycle session = %#v, %v", closed, err)
	}
	if _, err = fixture.store.getCloseTaskAudit(context.Background(), fixture.ownerPK,
		fixture.close.EventID); err != nil {
		t.Fatalf("advanced lifecycle cleanup audit: %v", err)
	}
	if _, err = fixture.store.getCloseClosed(context.Background(), fixture.close.EventID); err != nil {
		t.Fatalf("advanced lifecycle terminal marker: %v", err)
	}
}

func TestSessionControlLifecycleRecoveryResumesAfterCompleteAndClearsClosingDueAuthority(t *testing.T) {
	fixture := newSessionControlTerminalFixture(t, 1)
	session, err := fixture.store.getSessionItem(context.Background(), fixture.candidate.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	row, err := sessionControlSessionToRow(*session)
	if err != nil || session.State != sessionControlSessionStateClosing ||
		row.DueShard != sessionControlClosingSessionDueShard(session.Candidate) ||
		row.DueSort != sessionControlClosingSessionDueSort(*session) {
		t.Fatalf("completed close lost recovery authority: session=%#v row=%#v err=%v", session, row, err)
	}
	s := &UdpServer{sessionControlCellID: fixture.candidate.CellID, sessionControlStore: fixture.store}
	advanceSessionControlLifecycleUntilTerminal(t, s, fixture.store, *session, 1)
	closed, err := fixture.store.getSessionItem(context.Background(), fixture.candidate.SessionID)
	if err != nil || closed.State != sessionControlSessionStateClosed {
		t.Fatalf("terminal recovery session = %#v, %v", closed, err)
	}
	closedRow, err := sessionControlSessionToRow(*closed)
	if err != nil || closedRow.DueShard != "" || closedRow.DueSort != "" {
		t.Fatalf("terminal recovery retained due authority: row=%#v err=%v", closedRow, err)
	}
	if _, err = fixture.store.getCloseClosed(context.Background(), fixture.close.EventID); err != nil {
		t.Fatalf("terminal recovery marker: %v", err)
	}
}

func TestSessionControlLifecycleRecoveryUsesCleanChunksAsMaxFanoutCrashCursor(t *testing.T) {
	fixture := newSessionControlCleanupFixture(t, int(sessionControlSessionMaxTargets))
	installSessionControlTerminalTransactionFake(fixture.fake)
	fixture.store.nowUTC = func() time.Time {
		return time.UnixMilli(fixture.fence.ReplayNotBeforeMillis).UTC()
	}
	session, err := fixture.store.getSessionItem(context.Background(), fixture.candidate.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	s := &UdpServer{sessionControlCellID: fixture.candidate.CellID, sessionControlStore: fixture.store}
	manifestCount := len(fixture.complete.ManifestDigests)
	if manifestCount != int(sessionControlCloseManifestLimit) {
		t.Fatalf("max fanout manifests = %d, want %d", manifestCount, sessionControlCloseManifestLimit)
	}
	ownerTotal := uint64(0)
	for index := 0; index < manifestCount; index++ {
		manifest, readErr := fixture.store.getCloseManifest(context.Background(), fixture.close.EventID, uint64(index))
		if readErr != nil {
			t.Fatal(readErr)
		}
		ownerTotal += uint64(len(manifest.Refs))
		// Model a restart with an immutable audit prefix already committed. The
		// remaining real cleanup per manifest proves the lifecycle advances only
		// one durable unit before yielding, while avoiding 1,024 repeated
		// Dynamo-shaped transaction classifiers under the package-wide race gate.
		for refIndex, ref := range manifest.Refs[:len(manifest.Refs)-1] {
			seedSessionControlLifecycleCleanupAudit(t, &fixture, ref.OwnerPK,
				uint64(0xf000+index*sessionControlCloseManifestOwnerLimit+refIndex))
		}
	}
	if ownerTotal != sessionControlSessionMaxTargets {
		t.Fatalf("max fanout owner total = %d, want %d", ownerTotal, sessionControlSessionMaxTargets)
	}
	for index := 0; index < manifestCount; index++ {
		err = s.advanceDurableExactCloseLifecycle(context.Background(), fixture.store, *session)
		if !errors.Is(err, errSessionControlTerminalConflict) {
			t.Fatalf("manifest %d cleanup = %v, want durable retry", index, err)
		}
		if _, readErr := fixture.store.GetExactCloseCleanChunk(context.Background(), fixture.candidate,
			fixture.close.EventID, uint64(index)); !errors.Is(readErr, errSessionControlTerminalNotFound) {
			t.Fatalf("manifest %d cleanup published chunk early: %v", index, readErr)
		}
		err = s.advanceDurableExactCloseLifecycle(context.Background(), fixture.store, *session)
		if !errors.Is(err, errSessionControlTerminalConflict) {
			t.Fatalf("manifest %d chunk advance = %v, want durable retry", index, err)
		}
		chunk, readErr := fixture.store.GetExactCloseCleanChunk(context.Background(), fixture.candidate,
			fixture.close.EventID, uint64(index))
		if readErr != nil || chunk.OwnerCount == 0 || chunk.OwnerCount > sessionControlCloseManifestOwnerLimit {
			t.Fatalf("manifest %d progress = %#v, %v", index, chunk, readErr)
		}
		if index+1 < manifestCount {
			if _, readErr = fixture.store.GetExactCloseCleanChunk(context.Background(), fixture.candidate,
				fixture.close.EventID, uint64(index+1)); !errors.Is(readErr, errSessionControlTerminalNotFound) {
				t.Fatalf("attempt %d advanced more than one manifest: %v", index, readErr)
			}
		}
	}
	if err = s.advanceDurableExactCloseLifecycle(context.Background(), fixture.store, *session); err != nil {
		t.Fatalf("terminal attempt after %d durable chunks: %v", manifestCount, err)
	}
	closed, err := fixture.store.getSessionItem(context.Background(), fixture.candidate.SessionID)
	if err != nil || closed.State != sessionControlSessionStateClosed {
		t.Fatalf("max fanout terminal session = %#v, %v", closed, err)
	}
}

func TestSessionControlLifecycleRecoveryMakesLatencyBoundedManifestProgress(t *testing.T) {
	fixture := newSessionControlCleanupFixture(t, int(sessionControlCloseManifestOwnerLimit))
	manifest, err := fixture.store.getCloseManifest(context.Background(), fixture.close.EventID, 0)
	if err != nil {
		t.Fatal(err)
	}
	// Model a restart at the worst intra-manifest boundary: 47 durable audits
	// precede the only remaining TASK. No process-local cursor is retained.
	for index, ref := range manifest.Refs[:len(manifest.Refs)-1] {
		if _, err = fixture.store.CleanupAckedExactCloseTask(context.Background(),
			sessionControlCleanupRequest(fixture, ref.OwnerPK, uint64(0xe000+index))); err != nil {
			t.Fatal(err)
		}
	}
	installSessionControlTerminalTransactionFake(fixture.fake)
	fixture.store.operationTimeout = DynamoDBOperationTimeout
	fixture.store.nowUTC = func() time.Time {
		return time.UnixMilli(fixture.fence.ReplayNotBeforeMillis).UTC()
	}
	const readLatency = 10 * time.Millisecond
	fixture.fake.getHook = func(ctx context.Context, input *dynamodb.GetItemInput,
		_ int) (*dynamodb.GetItemOutput, error) {
		timer := time.NewTimer(readLatency)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timer.C:
		}
		fixture.fake.mu.Lock()
		item := fixture.fake.items[sessionControlSessionDynamoMapKey(input.Key)]
		fixture.fake.mu.Unlock()
		return &dynamodb.GetItemOutput{Item: item}, nil
	}
	session, err := fixture.store.getSessionItem(context.Background(), fixture.candidate.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	s := &UdpServer{sessionControlCellID: fixture.candidate.CellID, sessionControlStore: fixture.store}
	for phase := 0; phase < 2; phase++ {
		attemptCtx, cancel := context.WithTimeout(context.Background(), DynamoDBOperationTimeout)
		started := time.Now()
		err = s.advanceDurableExactCloseLifecycle(attemptCtx, fixture.store, *session)
		elapsed := time.Since(started)
		cancel()
		if !errors.Is(err, errSessionControlTerminalConflict) || elapsed >= DynamoDBOperationTimeout {
			t.Fatalf("latency phase %d = %v after %s", phase, err, elapsed)
		}
	}
	chunk, err := fixture.store.GetExactCloseCleanChunk(context.Background(), fixture.candidate,
		fixture.close.EventID, 0)
	if err != nil || chunk.OwnerCount != sessionControlCloseManifestOwnerLimit {
		t.Fatalf("latency-bounded CLEANCHUNK = %#v, %v", chunk, err)
	}
}
