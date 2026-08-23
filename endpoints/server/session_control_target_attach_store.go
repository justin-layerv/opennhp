package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

const sessionControlTargetAttachmentReadAttempts = 4

// sessionControlTargetAttachment is a publication fence for a second server
// receiving AOL from an already READY physical AC process. The target is
// global per AC public key/process, so attaching another local socket must not
// version it as if a new process had appeared.
type sessionControlTargetAttachment struct {
	Candidate sessionControlTargetCandidate
	Target    sessionControlTargetAuthority
	Snapshot  sessionControlFenceSnapshot
}

func validSessionControlTargetAttachment(attachment sessionControlTargetAttachment) bool {
	return validSessionControlTargetCandidate(attachment.Candidate) &&
		validateSessionControlTargetAuthority(attachment.Target) == nil &&
		attachment.Target.exactCandidate(attachment.Candidate) && attachment.Target.ready() &&
		validateSessionControlFenceSnapshot(attachment.Snapshot, attachment.Candidate.ControlCellID) == nil &&
		!attachment.Snapshot.AdmissionBlocked
}

func sessionControlFenceSnapshotsExact(left, right sessionControlFenceSnapshot) bool {
	return left.CellID == right.CellID && left.DirectoryVersion == right.DirectoryVersion &&
		left.ActiveFenceCount == right.ActiveFenceCount && left.AdmissionBlocked == right.AdmissionBlocked &&
		left.OverflowCloseCount == right.OverflowCloseCount &&
		left.OverflowLeaderEventID == right.OverflowLeaderEventID &&
		left.OverflowLeaderPreparedDirectoryVersion == right.OverflowLeaderPreparedDirectoryVersion &&
		left.OverflowLeaderSelectedDirectoryVersion == right.OverflowLeaderSelectedDirectoryVersion &&
		slices.Equal(left.Fences, right.Fences)
}

func sessionControlReadyAttachmentExact(target sessionControlTargetAuthority,
	owner sessionControlOwnerAuthority, attachment sessionControlTargetAttachment,
) bool {
	return target == attachment.Target && target.exactCandidate(attachment.Candidate) && target.ready() &&
		owner.PendingCount == 0 && owner.exactTarget(target, sessionControlOwnerReady)
}

func sessionControlAttachmentDirectoryFence(snapshot sessionControlFenceSnapshot) sessionControlTargetDirectoryFence {
	return sessionControlTargetDirectoryFence{
		CellID: snapshot.CellID, DirectoryVersion: snapshot.DirectoryVersion,
		ActiveFenceCount: snapshot.ActiveFenceCount, AdmissionBlocked: snapshot.AdmissionBlocked,
		OverflowCloseCount:                     snapshot.OverflowCloseCount,
		OverflowLeaderEventID:                  snapshot.OverflowLeaderEventID,
		OverflowLeaderPreparedDirectoryVersion: snapshot.OverflowLeaderPreparedDirectoryVersion,
		OverflowLeaderSelectedDirectoryVersion: snapshot.OverflowLeaderSelectedDirectoryVersion,
	}
}

func sessionControlAttachmentToken(attachment sessionControlTargetAttachment,
	owner sessionControlOwnerAuthority,
) *string {
	hasher := sha256.New()
	for _, part := range []any{
		"v1", attachment.Candidate.ACID, attachment.Candidate.PublicKey,
		attachment.Candidate.BootID, attachment.Candidate.FlushGeneration,
		attachment.Candidate.ControlCellID, attachment.Target.Version,
		attachment.Target.AuthorityVersion, attachment.Target.ActivatedControlVersion,
		attachment.Target.ReadyControlVersion, attachment.Target.AAKEnqueuedAtMillis,
		attachment.Target.AAKTransactionID, attachment.Target.CreatedAtMillis,
		attachment.Target.PreparedAtMillis, attachment.Target.UpdatedAtMillis,
		attachment.Snapshot.DirectoryVersion, attachment.Snapshot.ActiveFenceCount,
		attachment.Snapshot.AdmissionBlocked, attachment.Snapshot.OverflowCloseCount,
		attachment.Snapshot.OverflowLeaderEventID,
		attachment.Snapshot.OverflowLeaderPreparedDirectoryVersion,
		attachment.Snapshot.OverflowLeaderSelectedDirectoryVersion,
		owner.LifecycleVersion, owner.WorkVersion, owner.TaskCount, owner.PendingCount,
		owner.Phase, owner.BootID, owner.FlushGeneration, owner.TargetVersion,
		owner.TargetAuthorityVersion, owner.TargetCountedActiveSlot,
		owner.ActivatedControlVersion, owner.ReadyControlVersion,
		owner.TargetCreatedAtMillis, owner.TargetPreparedAtMillis, owner.TargetUpdatedAtMillis,
		owner.AAKEnqueuedAtMillis, owner.AAKTransactionID, owner.CreatedAtMillis,
		owner.UpdatedAtMillis,
	} {
		_, _ = fmt.Fprintf(hasher, "\x00%v", part)
	}
	token := "sc-attach-" + hex.EncodeToString(hasher.Sum(nil)[:12])
	return aws.String(token)
}

func sessionControlAttachmentTargetCondition(tableName string,
	target sessionControlTargetAuthority,
) types.TransactWriteItem {
	values := sessionControlTargetTransactionValues(target.fence())
	values[":current_state"] = &types.AttributeValueMemberS{Value: string(sessionControlTargetActive)}
	values[":updated_at"] = &types.AttributeValueMemberN{Value: fmt.Sprint(target.UpdatedAtMillis)}
	return types.TransactWriteItem{ConditionCheck: &types.ConditionCheck{
		TableName: aws.String(tableName), Key: sessionControlTargetDynamoKey(target.key()),
		ConditionExpression: aws.String(sessionControlTargetTransactionCondition() +
			" AND updated_at_ms = :updated_at AND attribute_not_exists(retired_at_ms) AND attribute_not_exists(#ttl)"),
		ExpressionAttributeNames:  map[string]string{"#state": "state", "#version": "version", "#ttl": "ttl"},
		ExpressionAttributeValues: values,
	}}
}

func sessionControlAttachmentOwnerCondition(tableName string,
	owner sessionControlOwnerAuthority,
) types.TransactWriteItem {
	condition, names, values := sessionControlOwnerCondition(owner)
	return types.TransactWriteItem{ConditionCheck: &types.ConditionCheck{
		TableName: aws.String(tableName), Key: sessionControlOwnerKey(owner.CellID, owner.ACID, owner.PublicKey),
		ConditionExpression: aws.String(condition), ExpressionAttributeNames: names, ExpressionAttributeValues: values,
	}}
}

// classifyReadyTargetAttachment is used only after a condition transaction
// failed. It brackets a fresh strong CONTROL snapshot with strong TARGET and
// OWNER reads. A transport-ambiguous transaction may be accepted only when the
// complete authority is still exact; a definite conditional cancellation is
// never converted into success.
func (s *dynamoSessionControlStore) classifyReadyTargetAttachment(ctx context.Context,
	attachment sessionControlTargetAttachment, allowExactSuccess bool,
) (*sessionControlTargetAuthority, error) {
	key := sessionControlTargetKey{ACID: attachment.Candidate.ACID, PublicKey: attachment.Candidate.PublicKey}
	for range sessionControlTargetAttachmentReadAttempts {
		beforeTarget, err := s.getTarget(ctx, key)
		if err != nil {
			return nil, err
		}
		beforeOwner, err := s.getOwner(ctx, attachment.Candidate.ControlCellID,
			attachment.Candidate.ACID, attachment.Candidate.PublicKey)
		if err != nil {
			return nil, err
		}
		currentSnapshot, err := s.SnapshotActiveFences(ctx, attachment.Candidate.ControlCellID)
		if err != nil {
			return nil, err
		}
		afterTarget, err := s.getTarget(ctx, key)
		if err != nil {
			return nil, err
		}
		afterOwner, err := s.getOwner(ctx, attachment.Candidate.ControlCellID,
			attachment.Candidate.ACID, attachment.Candidate.PublicKey)
		if err != nil {
			return nil, err
		}
		if *beforeTarget != *afterTarget || *beforeOwner != *afterOwner {
			continue
		}
		if !sessionControlFenceSnapshotsExact(*currentSnapshot, attachment.Snapshot) {
			return nil, errSessionControlTargetControlStale
		}
		if !sessionControlReadyAttachmentExact(*afterTarget, *afterOwner, attachment) {
			return nil, errSessionControlTargetConflict
		}
		if !allowExactSuccess {
			return nil, errSessionControlTargetConflict
		}
		copy := *afterTarget
		return &copy, nil
	}
	return nil, errSessionControlTargetConflict
}

// VerifyReadyTargetAttachment atomically condition-checks the exact READY
// TARGET, exact READY OWNER with pending_count=0, and exact CONTROL directory.
// It writes and versions nothing. This is the durable pre-AAK publication
// authorization for another assigned server attaching to the same physical AC
// process.
func (s *dynamoSessionControlStore) VerifyReadyTargetAttachment(ctx context.Context,
	attachment sessionControlTargetAttachment,
) (*sessionControlTargetAuthority, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	if ctx == nil || !validSessionControlTargetAttachment(attachment) {
		return nil, errors.New("invalid session-control target attachment")
	}
	opCtx, cancel := context.WithTimeout(ctx, s.timeout())
	owner, err := s.getOwner(opCtx, attachment.Candidate.ControlCellID,
		attachment.Candidate.ACID, attachment.Candidate.PublicKey)
	if err != nil {
		cancel()
		return nil, err
	}
	if !sessionControlReadyAttachmentExact(attachment.Target, *owner, attachment) {
		cancel()
		return nil, errSessionControlTargetConflict
	}
	directoryCheck := sessionControlTargetDirectoryCondition(sessionControlAttachmentDirectoryFence(attachment.Snapshot))
	directoryCheck.ConditionCheck.TableName = aws.String(s.tableName)
	_, writeErr := s.client.TransactWriteItems(opCtx, &dynamodb.TransactWriteItemsInput{
		ClientRequestToken: sessionControlAttachmentToken(attachment, *owner),
		TransactItems: []types.TransactWriteItem{
			sessionControlAttachmentTargetCondition(s.tableName, attachment.Target),
			sessionControlAttachmentOwnerCondition(s.tableName, *owner),
			directoryCheck,
		},
	})
	operationErr := opCtx.Err()
	cancel()
	if writeErr == nil {
		copy := attachment.Target
		return &copy, nil
	}
	resultCtx, resultCancel := s.sessionResultContext(ctx)
	defer resultCancel()
	var canceled *types.TransactionCanceledException
	if errors.As(writeErr, &canceled) {
		return s.classifyReadyTargetAttachment(resultCtx, attachment, false)
	}
	classified, classifyErr := s.classifyReadyTargetAttachment(resultCtx, attachment, true)
	if classifyErr == nil {
		return classified, nil
	}
	if operationErr != nil {
		return nil, fmt.Errorf("verify session-control target attachment: %w", operationErr)
	}
	return nil, fmt.Errorf("verify session-control target attachment: %w", writeErr)
}
