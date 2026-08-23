package server

import (
	"context"
	"errors"
	"fmt"
	"math"
	"reflect"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

type sessionControlCloseCompletionInventory struct {
	TaskSet   sessionControlCloseTaskSet
	Manifests []sessionControlCloseManifest
	Chunks    []sessionControlCloseAckChunk
	Closed    uint64
}

func (s *dynamoSessionControlStore) readCloseCompletionInventory(ctx context.Context,
	close *sessionControlExactClosePreparation) (sessionControlCloseCompletionInventory, error) {
	if close == nil || !validSessionControlExactCloseWorkMode(close.Work.Mode) {
		return sessionControlCloseCompletionInventory{}, errSessionControlCompletionCorrupt
	}
	taskSet, err := s.getCloseTaskSet(ctx, close.EventID)
	if err != nil {
		return sessionControlCloseCompletionInventory{}, err
	}
	if taskSet.CellID != close.Work.CellID || taskSet.EventID != close.EventID ||
		taskSet.SelectorDigest != close.Work.SelectorDigest || taskSet.SessionVersion != close.Work.SessionVersion ||
		taskSet.ExpectedTargetCount != close.Work.ExpectedTargetCount ||
		taskSet.PreparedDirectoryVersion != close.Work.PreparedDirectoryVersion ||
		taskSet.WorkMode != close.Work.Mode {
		return sessionControlCloseCompletionInventory{}, errSessionControlCompletionCorrupt
	}
	inventory := sessionControlCloseCompletionInventory{TaskSet: *taskSet,
		Manifests: make([]sessionControlCloseManifest, 0, len(taskSet.ManifestDigests)),
		Chunks:    make([]sessionControlCloseAckChunk, 0, len(taskSet.ManifestDigests))}
	var sourceTotal, ownerTotal uint64
	for index := range taskSet.ManifestDigests {
		manifest, manifestErr := s.getCloseManifest(ctx, close.EventID, uint64(index))
		if manifestErr != nil {
			return sessionControlCloseCompletionInventory{}, manifestErr
		}
		chunk, chunkErr := s.getCloseAckChunk(ctx, close.EventID, uint64(index))
		if chunkErr != nil {
			return sessionControlCloseCompletionInventory{}, chunkErr
		}
		if manifest.WorkMode != close.Work.Mode ||
			manifest.ManifestDigest != taskSet.ManifestDigests[index] ||
			uint64(len(manifest.Refs)) != taskSet.ManifestOwnerCounts[index] ||
			!sessionControlCloseAckChunkMatchesAuthority(*chunk, close.Session, close.Work, *taskSet, *manifest) ||
			chunk.SourceCount != taskSet.ManifestSourceCounts[index] ||
			chunk.OwnerCount != taskSet.ManifestOwnerCounts[index] ||
			chunk.SourceCount > taskSet.SourceCount-sourceTotal ||
			chunk.OwnerCount > taskSet.OwnerCount-ownerTotal ||
			chunk.AckClosedTotal > math.MaxUint64-inventory.Closed {
			return sessionControlCloseCompletionInventory{}, errSessionControlCompletionCorrupt
		}
		sourceTotal += chunk.SourceCount
		ownerTotal += chunk.OwnerCount
		inventory.Closed += chunk.AckClosedTotal
		inventory.Manifests = append(inventory.Manifests, *manifest)
		inventory.Chunks = append(inventory.Chunks, *chunk)
	}
	if sourceTotal != taskSet.SourceCount || ownerTotal != taskSet.OwnerCount ||
		(taskSet.OwnerCount == 0 && (len(inventory.Manifests) != 0 || len(inventory.Chunks) != 0)) {
		return sessionControlCloseCompletionInventory{}, errSessionControlCompletionCorrupt
	}
	return inventory, nil
}

func sessionControlFenceDirectoryReplace(tableName string, current,
	next sessionControlFenceDirectory) (types.TransactWriteItem, error) {
	currentRow, err := sessionControlFenceDirectoryToRow(current)
	if err != nil {
		return types.TransactWriteItem{}, err
	}
	nextRow, err := sessionControlFenceDirectoryToRow(next)
	if err != nil {
		return types.TransactWriteItem{}, err
	}
	currentItem, err := attributevalue.MarshalMap(currentRow)
	if err != nil {
		return types.TransactWriteItem{}, err
	}
	nextItem, err := attributevalue.MarshalMap(nextRow)
	if err != nil {
		return types.TransactWriteItem{}, err
	}
	condition, names, values := sessionControlExactItemCondition(currentItem)
	return types.TransactWriteItem{Put: &types.Put{TableName: aws.String(tableName), Item: nextItem,
		ConditionExpression: aws.String(condition), ExpressionAttributeNames: names,
		ExpressionAttributeValues: values}}, nil
}

func sessionControlOverflowHeaderDelete(tableName string,
	work sessionControlCloseWork) (types.TransactWriteItem, error) {
	condition := sessionControlOverflowHeaderCondition(work)
	if condition.ConditionCheck == nil {
		return types.TransactWriteItem{}, errSessionControlCompletionCorrupt
	}
	return types.TransactWriteItem{Delete: &types.Delete{TableName: aws.String(tableName),
		Key: condition.ConditionCheck.Key, ConditionExpression: condition.ConditionCheck.ConditionExpression,
		ExpressionAttributeNames:  condition.ConditionCheck.ExpressionAttributeNames,
		ExpressionAttributeValues: condition.ConditionCheck.ExpressionAttributeValues}}, nil
}

func sessionControlConvergedFencePut(tableName string, fence sessionControlFenceAuthority,
	active bool) (types.TransactWriteItem, error) {
	row, err := sessionControlFenceToRow(fence, active)
	if err != nil {
		return types.TransactWriteItem{}, err
	}
	item, err := attributevalue.MarshalMap(row)
	if err != nil {
		return types.TransactWriteItem{}, err
	}
	return types.TransactWriteItem{Put: &types.Put{TableName: aws.String(tableName), Item: item,
		ConditionExpression: aws.String("attribute_not_exists(pk) AND attribute_not_exists(sk)")}}, nil
}

func buildOverflowCloseComplete(candidate sessionControlSessionCandidate,
	close *sessionControlExactClosePreparation, inventory sessionControlCloseCompletionInventory,
	fence sessionControlFenceAuthority, completedDirectoryVersion uint64,
	completedAtMillis, retainUntilMillis int64) (sessionControlCloseComplete, error) {
	complete := sessionControlCloseComplete{CellID: candidate.CellID, EventID: close.EventID,
		SelectorDigest: close.Work.SelectorDigest, AgentPublicKey: candidate.AgentPublicKey,
		SessionID: candidate.SessionID, SessionIssuedMillis: candidate.IssuedAtMillis,
		SessionVersion: close.Session.Version, ExpectedTargetCount: close.Session.TargetCount,
		PreparedDirectoryVersion: close.Session.ClosePreparedDirectory, WorkMode: close.Work.Mode,
		TaskSetDigest: inventory.TaskSet.TaskSetDigest, SourceCount: inventory.TaskSet.SourceCount,
		OwnerCount: inventory.TaskSet.OwnerCount, AckClosedTotal: inventory.Closed,
		ManifestDigests: append(make([]string, 0, len(inventory.TaskSet.ManifestDigests)),
			inventory.TaskSet.ManifestDigests...),
		ChunkDigests:      make([]string, 0, len(inventory.Chunks)),
		ChunkSourceCounts: make([]uint64, 0, len(inventory.Chunks)),
		ChunkOwnerCounts:  make([]uint64, 0, len(inventory.Chunks)),
		FenceVersion:      fence.Version, CompletedDirectoryVersion: completedDirectoryVersion,
		FenceReplayNotBeforeMillis: fence.ReplayNotBeforeMillis, CompletedAtMillis: completedAtMillis,
		RetainUntilMillis: retainUntilMillis}
	for _, chunk := range inventory.Chunks {
		complete.ChunkDigests = append(complete.ChunkDigests, chunk.ChunkDigest)
		complete.ChunkSourceCounts = append(complete.ChunkSourceCounts, chunk.SourceCount)
		complete.ChunkOwnerCounts = append(complete.ChunkOwnerCounts, chunk.OwnerCount)
	}
	var err error
	complete.CompleteDigest, err = sessionControlCloseCompleteDigest(complete)
	if err != nil || validateSessionControlCloseComplete(complete) != nil ||
		!sessionControlCloseCompleteMatchesAuthority(complete, close.Session, close.Work, inventory.TaskSet) {
		return sessionControlCloseComplete{}, errSessionControlCompletionCorrupt
	}
	return complete, nil
}

func (s *dynamoSessionControlStore) classifyOverflowCloseCompleteWinner(ctx context.Context,
	candidate sessionControlSessionCandidate, eventID string,
	desired sessionControlCloseComplete) (*sessionControlCloseComplete, error) {
	current, err := s.getCloseComplete(ctx, eventID)
	if err != nil {
		return nil, err
	}
	if current.WorkMode != sessionControlCloseWorkModeOverflow ||
		!sessionControlCloseCompleteMatchesCandidate(*current, candidate, eventID) {
		return nil, errSessionControlCompletionConflict
	}
	// Concurrent initial promoters may clamp their completion timestamp against
	// different local clocks. The winner's derived replay/retention timestamps
	// are authoritative; every non-time authority field must still be exact.
	normalized := *current
	normalized.CompletedAtMillis = desired.CompletedAtMillis
	normalized.FenceReplayNotBeforeMillis = desired.FenceReplayNotBeforeMillis
	normalized.RetainUntilMillis = desired.RetainUntilMillis
	normalized.CompleteDigest = desired.CompleteDigest
	if !reflect.DeepEqual(normalized, desired) {
		return nil, errSessionControlCompletionConflict
	}
	return current, nil
}

// PromoteCompletedOverflowExactClose atomically turns the selected completed
// overflow event into a converged active fence, removes its pending header,
// advances the deterministic leader, and publishes the common COMPLETE audit.
// Exact ordered header mirrors plus the directory count serialize clearing or
// advancing admission against concurrent overflow close creation.
func (s *dynamoSessionControlStore) PromoteCompletedOverflowExactClose(ctx context.Context,
	candidate sessionControlSessionCandidate, eventID string,
	minimumRetainUntilMillis int64) (*sessionControlCloseComplete, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	if !validSessionControlSessionCandidate(candidate) || eventID != sessionControlExactCloseEventID(candidate) ||
		minimumRetainUntilMillis < 0 {
		return nil, errors.New("invalid overflow session-control close promotion")
	}
	opCtx, cancel := context.WithTimeout(ctx, s.timeout())
	defer cancel()
	if existing, err := s.getCloseComplete(opCtx, eventID); err == nil {
		if !sessionControlCloseCompleteMatchesCandidate(*existing, candidate, eventID) ||
			existing.WorkMode != sessionControlCloseWorkModeOverflow {
			return nil, errSessionControlCompletionConflict
		}
		if minimumRetainUntilMillis <= existing.RetainUntilMillis {
			return existing, nil
		}
		cancel()
		return s.extendCloseCompleteRetention(ctx, candidate, *existing, minimumRetainUntilMillis)
	} else if !errors.Is(err, errSessionControlCompletionNotFound) {
		return nil, err
	}
	for range sessionControlCloseCompletionAttempts {
		directory, overflowOrder, err := s.readStableOverflowOrder(opCtx, candidate.CellID, 2)
		if err != nil {
			return nil, err
		}
		if len(overflowOrder) == 0 || directory.ActiveFenceCount >= sessionControlFenceActiveLimit ||
			directory.OverflowLeaderEventID != eventID || overflowOrder[0].Work.EventID != eventID ||
			directory.OverflowLeaderPreparedDirectoryVersion != overflowOrder[0].Work.PreparedDirectoryVersion {
			return nil, errSessionControlCompletionConflict
		}
		stable, err := s.readStableExactCloseState(opCtx, candidate, eventID)
		if err != nil {
			return nil, err
		}
		close, err := classifySessionControlExactClose(candidate, eventID, stable)
		if err != nil {
			return nil, err
		}
		if stable.Directory != directory || !sessionControlOverflowLeaderMatchesClose(directory, close) ||
			!close.Overflow || close.Work != overflowOrder[0].Work || close.Work.State != sessionControlCloseWorkStatePending {
			return nil, errSessionControlCompletionConflict
		}
		inventory, err := s.readCloseCompletionInventory(opCtx, close)
		if err != nil {
			return nil, err
		}
		now, err := s.now()
		if err != nil {
			return nil, err
		}
		completedAt := now.UnixMilli()
		for _, value := range []int64{directory.UpdatedAtMillis, close.Work.UpdatedAtMillis,
			close.Session.ClosePreparedAtMillis} {
			if value > completedAt {
				completedAt = value
			}
		}
		for _, chunk := range inventory.Chunks {
			if chunk.CreatedAtMillis > completedAt {
				completedAt = chunk.CreatedAtMillis
			}
		}
		if completedAt > math.MaxInt64-sessionControlFenceReplayHorizon.Milliseconds() {
			return nil, errSessionControlCompletionCorrupt
		}
		fence := sessionControlFenceAuthority{CellID: candidate.CellID, EventID: eventID,
			Selector: close.Work.Selector, SelectorDigest: close.Work.SelectorDigest,
			PreparedDirectoryVersion: close.Work.PreparedDirectoryVersion, State: sessionControlFenceConverged,
			Version: 2, CreatedAtMillis: close.Work.CreatedAtMillis, PreparedAtMillis: close.Work.CreatedAtMillis,
			ConvergedAtMillis:     completedAt,
			ReplayNotBeforeMillis: completedAt + sessionControlFenceReplayHorizon.Milliseconds(),
			UpdatedAtMillis:       completedAt}
		if validateSessionControlFenceAuthority(fence) != nil {
			return nil, errSessionControlCompletionCorrupt
		}
		retain, err := sessionControlCloseCompleteRetention(completedAt, close.Session.RetainUntilMillis,
			fence.ReplayNotBeforeMillis, minimumRetainUntilMillis)
		if err != nil {
			return nil, err
		}
		nextDirectory := directory
		nextDirectory.Version++
		nextDirectory.ActiveFenceCount++
		nextDirectory.OverflowCloseCount--
		nextDirectory.AdmissionBlocked = nextDirectory.OverflowCloseCount > 0
		nextDirectory.OverflowLeaderEventID = ""
		nextDirectory.OverflowLeaderPreparedDirectoryVersion = 0
		nextDirectory.OverflowLeaderSelectedDirectoryVersion = 0
		if len(overflowOrder) > 1 {
			next := overflowOrder[1].Work
			nextDirectory.OverflowLeaderEventID = next.EventID
			nextDirectory.OverflowLeaderPreparedDirectoryVersion = next.PreparedDirectoryVersion
			nextDirectory.OverflowLeaderSelectedDirectoryVersion = nextDirectory.Version
		}
		if completedAt > nextDirectory.UpdatedAtMillis {
			nextDirectory.UpdatedAtMillis = completedAt
		}
		if validateSessionControlFenceDirectory(nextDirectory) != nil {
			return nil, errSessionControlCompletionCorrupt
		}
		complete, err := buildOverflowCloseComplete(candidate, close, inventory, fence,
			nextDirectory.Version, completedAt, retain)
		if err != nil {
			return nil, err
		}
		directoryWrite, err := sessionControlFenceDirectoryReplace(s.tableName, directory, nextDirectory)
		if err != nil {
			return nil, err
		}
		headerDelete, err := sessionControlOverflowHeaderDelete(s.tableName, close.Work)
		if err != nil {
			return nil, err
		}
		orderDelete, err := sessionControlOverflowOrderDelete(s.tableName, overflowOrder[0])
		if err != nil {
			return nil, err
		}
		metaPut, err := sessionControlConvergedFencePut(s.tableName, fence, false)
		if err != nil {
			return nil, err
		}
		activePut, err := sessionControlConvergedFencePut(s.tableName, fence, true)
		if err != nil {
			return nil, err
		}
		sessionWrite := sessionControlSessionCloseRetentionUpdate(close.Session, retain)
		sessionWrite.Update.TableName = aws.String(s.tableName)
		taskSetCheck, err := sessionControlCloseTaskSetCondition(s.tableName, inventory.TaskSet)
		if err != nil {
			return nil, err
		}
		transaction := []types.TransactWriteItem{directoryWrite, headerDelete, orderDelete, metaPut, activePut,
			sessionWrite, taskSetCheck}
		for _, chunk := range inventory.Chunks {
			check, checkErr := sessionControlCloseAckChunkCondition(s.tableName, chunk)
			if checkErr != nil {
				return nil, checkErr
			}
			transaction = append(transaction, check)
		}
		completePut, err := sessionControlCloseCompletePut(s.tableName, complete, nil)
		if err != nil {
			return nil, err
		}
		transaction = append(transaction, completePut)
		var nextHeader *sessionControlCloseWork
		var nextOrder *sessionControlOverflowOrder
		if len(overflowOrder) > 1 {
			nextHeader = &overflowOrder[1].Work
			headerCheck := sessionControlOverflowHeaderCondition(*nextHeader)
			headerCheck.ConditionCheck.TableName = aws.String(s.tableName)
			order := overflowOrder[1]
			nextOrder = &order
			orderCheck, checkErr := sessionControlOverflowOrderCondition(s.tableName, order)
			if checkErr != nil {
				return nil, checkErr
			}
			transaction = append(transaction, headerCheck, orderCheck)
		}
		if len(transaction) > 32 {
			return nil, errSessionControlCompletionCorrupt
		}
		token, err := sessionControlCloseCompletionToken(s.tableName, "overflow-promote", directory,
			nextDirectory, close.Session, close.Work, inventory.TaskSet, inventory.Manifests,
			inventory.Chunks, fence, complete, nextHeader, nextOrder)
		if err != nil {
			return nil, err
		}
		_, writeErr := s.client.TransactWriteItems(opCtx, &dynamodb.TransactWriteItemsInput{
			ClientRequestToken: token, TransactItems: transaction})
		if writeErr == nil {
			return &complete, nil
		}
		var canceled *types.TransactionCanceledException
		if errors.As(writeErr, &canceled) {
			if current, classifyErr := s.classifyOverflowCloseCompleteWinner(opCtx, candidate, eventID,
				complete); classifyErr == nil {
				if current.RetainUntilMillis >= minimumRetainUntilMillis {
					return current, nil
				}
				cancel()
				return s.extendCloseCompleteRetention(ctx, candidate, *current, minimumRetainUntilMillis)
			}
			continue
		}
		resultCtx, resultCancel := s.sessionResultContext(ctx)
		current, classifyErr := s.classifyOverflowCloseCompleteWinner(resultCtx, candidate, eventID, complete)
		resultCancel()
		if classifyErr == nil {
			if current.RetainUntilMillis >= minimumRetainUntilMillis {
				return current, nil
			}
			cancel()
			return s.extendCloseCompleteRetention(ctx, candidate, *current, minimumRetainUntilMillis)
		}
		return nil, fmt.Errorf("promote overflow session-control exact close: %w", writeErr)
	}
	return nil, errSessionControlCompletionConflict
}
