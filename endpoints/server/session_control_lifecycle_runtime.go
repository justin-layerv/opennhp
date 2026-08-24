package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

// sessionControlCloseLifecycleStore is the narrow durable state-machine
// capability used by recovery after a SESSION has entered CLOSING. The SESSION
// row itself remains due-indexed until the terminal CLOSING->CLOSED transaction,
// so a crash at every materialization/completion/cleanup seam is rediscoverable
// without a scan or a second lifecycle authority.
type sessionControlCloseLifecycleStore interface {
	EnsureExactSessionClose(context.Context, sessionControlSessionCandidate, int64) (*sessionControlExactClosePreparation, error)
	MarkFenceConverged(context.Context, sessionControlFenceAuthority) (*sessionControlFenceAuthority, error)
	SelectOldestOverflowCloseLeader(context.Context, string) (*sessionControlOverflowLeader, error)
	MaterializeNormalExactClose(context.Context, sessionControlSessionCandidate, string) (*sessionControlCloseTaskSet, error)
	MaterializeSelectedOverflowExactClose(context.Context, sessionControlSessionCandidate, string) (*sessionControlCloseTaskSet, error)
	PrepareExactCloseAckChunk(context.Context, sessionControlSessionCandidate, string, uint64) (*sessionControlCloseAckChunk, error)
	CompleteNormalExactClose(context.Context, sessionControlSessionCandidate, string, int64) (*sessionControlCloseComplete, error)
	PromoteCompletedOverflowExactClose(context.Context, sessionControlSessionCandidate, string, int64) (*sessionControlCloseComplete, error)
	ListCompletedExactCloseTasksPage(context.Context, string, string, *sessionControlCompletedCloseTaskCursor, int32) (*sessionControlCompletedCloseTaskPage, error)
	CleanupAckedExactCloseTask(context.Context, sessionControlCloseTaskCleanupRequest) (*sessionControlCloseTaskAudit, error)
	GetExactCloseCleanChunk(context.Context, sessionControlSessionCandidate, string, uint64) (*sessionControlCloseCleanChunk, error)
	PrepareExactCloseCleanChunk(context.Context, sessionControlSessionCandidate, string, uint64) (*sessionControlCloseCleanChunk, error)
	FinalizeTerminalExactClose(context.Context, sessionControlSessionCandidate, string) (*sessionControlCloseClosedAudit, error)
}

var _ sessionControlCloseLifecycleStore = (*dynamoSessionControlStore)(nil)

func sessionControlLifecycleCleanupOperationID(eventID, ownerPK string) string {
	digest := sha256.Sum256([]byte("v1\x00cleanup\x00" + eventID + "\x00" + ownerPK))
	return hex.EncodeToString(digest[:16])
}

func sessionControlLifecycleRetryable(err error) bool {
	return errors.Is(err, errSessionControlMaterializationConflict) ||
		errors.Is(err, errSessionControlMaterializationCapacity) ||
		errors.Is(err, errSessionControlCompletionNotFound) ||
		errors.Is(err, errSessionControlCompletionConflict) ||
		errors.Is(err, errSessionControlCleanupNotFound) ||
		errors.Is(err, errSessionControlCleanupConflict) ||
		errors.Is(err, errSessionControlTerminalNotFound) ||
		errors.Is(err, errSessionControlTerminalConflict) ||
		errors.Is(err, errSessionControlFenceReplayHorizon) ||
		errors.Is(err, errSessionControlCloseConflict)
}

func sessionControlLifecycleManifestCursor(complete sessionControlCloseComplete,
	manifestIndex uint64) (*sessionControlCompletedCloseTaskCursor, int32, error) {
	if validateSessionControlCloseComplete(complete) != nil ||
		manifestIndex >= uint64(len(complete.ManifestDigests)) ||
		len(complete.ChunkOwnerCounts) != len(complete.ManifestDigests) ||
		len(complete.ChunkSourceCounts) != len(complete.ManifestDigests) {
		return nil, 0, errSessionControlCleanupCorrupt
	}
	var seenOwners, seenSources uint64
	for index := uint64(0); index < manifestIndex; index++ {
		owners, sources := complete.ChunkOwnerCounts[index], complete.ChunkSourceCounts[index]
		if seenOwners > ^uint64(0)-owners || seenSources > ^uint64(0)-sources {
			return nil, 0, errSessionControlCleanupCorrupt
		}
		seenOwners += owners
		seenSources += sources
	}
	ownerCount := complete.ChunkOwnerCounts[manifestIndex]
	if ownerCount == 0 || ownerCount > uint64(sessionControlCloseCleanupPageLimit) {
		return nil, 0, errSessionControlCleanupCorrupt
	}
	return &sessionControlCompletedCloseTaskCursor{CellID: complete.CellID, EventID: complete.EventID,
		CompleteDigest: complete.CompleteDigest, ManifestIndex: manifestIndex,
		SeenOwners: seenOwners, SeenSources: seenSources}, int32(ownerCount), nil
}

func sessionControlLifecycleManifestPageComplete(page *sessionControlCompletedCloseTaskPage,
	complete sessionControlCloseComplete, manifestIndex uint64, ownerCount int32) bool {
	if page == nil || len(page.Items) != int(ownerCount) {
		return false
	}
	if manifestIndex+1 == uint64(len(complete.ManifestDigests)) {
		return page.Next == nil
	}
	if page.Next == nil || page.Next.CellID != complete.CellID || page.Next.EventID != complete.EventID ||
		page.Next.CompleteDigest != complete.CompleteDigest || page.Next.ManifestIndex != manifestIndex+1 ||
		page.Next.RefIndex != 0 {
		return false
	}
	var owners, sources uint64
	for index := uint64(0); index <= manifestIndex; index++ {
		if owners > ^uint64(0)-complete.ChunkOwnerCounts[index] ||
			sources > ^uint64(0)-complete.ChunkSourceCounts[index] {
			return false
		}
		owners += complete.ChunkOwnerCounts[index]
		sources += complete.ChunkSourceCounts[index]
	}
	return page.Next.SeenOwners == owners && page.Next.SeenSources == sources
}

// advanceDurableExactCloseLifecycle executes only idempotent, store-fenced
// transitions. Any incomplete phase returns and is retried from the CLOSING
// session's durable due row; no process-local cursor is correctness authority.
func (s *UdpServer) advanceDurableExactCloseLifecycle(ctx context.Context,
	store sessionControlCloseLifecycleStore, session sessionControlSessionAuthority,
) error {
	if s == nil || store == nil || session.State != sessionControlSessionStateClosing ||
		validateSessionControlSessionAuthority(session) != nil ||
		session.CloseEventID != sessionControlExactCloseEventID(session.Candidate) {
		return errSessionControlSessionCorrupt
	}
	preparation, err := store.EnsureExactSessionClose(ctx, session.Candidate, session.RetainUntilMillis)
	if err != nil {
		return err
	}
	if preparation == nil || preparation.Session.State != sessionControlSessionStateClosing ||
		preparation.EventID != session.CloseEventID {
		return errSessionControlCloseCorrupt
	}

	complete := preparation.Complete
	if complete == nil {
		var taskSet *sessionControlCloseTaskSet
		if preparation.Overflow {
			leader, leaderErr := store.SelectOldestOverflowCloseLeader(ctx, session.Candidate.CellID)
			if leaderErr != nil {
				return leaderErr
			}
			if leader == nil || leader.Work.EventID != preparation.EventID {
				return errSessionControlMaterializationConflict
			}
			taskSet, err = store.MaterializeSelectedOverflowExactClose(ctx, session.Candidate, preparation.EventID)
		} else {
			taskSet, err = store.MaterializeNormalExactClose(ctx, session.Candidate, preparation.EventID)
		}
		if err != nil {
			return err
		}
		if taskSet == nil || taskSet.EventID != preparation.EventID {
			return errSessionControlMaterializationCorrupt
		}
		for index := range taskSet.ManifestDigests {
			if _, err = store.PrepareExactCloseAckChunk(ctx, session.Candidate, preparation.EventID, uint64(index)); err != nil {
				return err
			}
		}
		if preparation.Overflow {
			complete, err = store.PromoteCompletedOverflowExactClose(ctx, session.Candidate,
				preparation.EventID, preparation.Session.RetainUntilMillis)
		} else {
			// Materialization plus every immutable ACK chunk proves that this
			// normal fence has reached every required target. Publish CONVERGED
			// before COMPLETE. This is also required for the zero-target case,
			// where there are no chunk iterations to provide another transition
			// point. MarkFenceConverged is exact and idempotent, so a crash after
			// its commit resumes safely through the same call.
			if preparation.Fence == nil {
				return errSessionControlFenceCorrupt
			}
			converged := preparation.Fence
			switch preparation.Fence.State {
			case sessionControlFencePreparing:
				var convergeErr error
				converged, convergeErr = store.MarkFenceConverged(ctx, *preparation.Fence)
				if convergeErr != nil {
					return convergeErr
				}
			case sessionControlFenceConverged:
				// A previous attempt can commit convergence and lose the response.
				// EnsureExactSessionClose returns that exact durable authority, so
				// continue to COMPLETE without trying to transition it again.
			default:
				return errSessionControlFenceCorrupt
			}
			if converged == nil || converged.State != sessionControlFenceConverged ||
				converged.CellID != preparation.Fence.CellID || converged.EventID != preparation.Fence.EventID ||
				converged.SelectorDigest != preparation.Fence.SelectorDigest ||
				converged.PreparedDirectoryVersion != preparation.Fence.PreparedDirectoryVersion {
				return errSessionControlFenceCorrupt
			}
			complete, err = store.CompleteNormalExactClose(ctx, session.Candidate,
				preparation.EventID, preparation.Session.RetainUntilMillis)
		}
		if err != nil {
			return err
		}
	}
	if complete == nil || !sessionControlCloseCompleteMatchesCandidate(*complete, session.Candidate, session.CloseEventID) {
		return errSessionControlCompletionCorrupt
	}

	// CLEANCHUNK is the durable inter-manifest cursor; TASKAUDIT is the durable
	// intra-manifest cursor. Clean at most one live task per worker attempt and
	// yield. After all refs are audits, a later attempt publishes the immutable
	// CLEANCHUNK and yields again. This bounds the production five-second worker
	// budget even at the 48-owner normal-manifest maximum while a restart still
	// skips every already-proven manifest.
	for index := range complete.ManifestDigests {
		manifestIndex := uint64(index)
		if _, readErr := store.GetExactCloseCleanChunk(ctx, session.Candidate,
			session.CloseEventID, manifestIndex); readErr == nil {
			continue
		} else if !errors.Is(readErr, errSessionControlTerminalNotFound) {
			return readErr
		}
		cursor, ownerCount, cursorErr := sessionControlLifecycleManifestCursor(*complete, manifestIndex)
		if cursorErr != nil {
			return cursorErr
		}
		page, pageErr := store.ListCompletedExactCloseTasksPage(ctx, session.Candidate.CellID,
			session.CloseEventID, cursor, ownerCount)
		if pageErr != nil {
			return pageErr
		}
		if !sessionControlLifecycleManifestPageComplete(page, *complete, manifestIndex, ownerCount) {
			return errSessionControlCleanupCorrupt
		}
		for _, item := range page.Items {
			if item.Task == nil {
				if item.Audit == nil {
					return errSessionControlCleanupCorrupt
				}
				continue
			}
			request := sessionControlCloseTaskCleanupRequest{CellID: session.Candidate.CellID,
				EventID: session.CloseEventID, OwnerPK: item.OwnerPK,
				OperationID: sessionControlLifecycleCleanupOperationID(session.CloseEventID, item.OwnerPK)}
			if _, err = store.CleanupAckedExactCloseTask(ctx, request); err != nil {
				return err
			}
			return errSessionControlTerminalConflict
		}
		if _, err = store.PrepareExactCloseCleanChunk(ctx, session.Candidate,
			session.CloseEventID, manifestIndex); err != nil {
			return err
		}
		return errSessionControlTerminalConflict
	}
	_, err = store.FinalizeTerminalExactClose(ctx, session.Candidate, session.CloseEventID)
	return err
}
