package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

const (
	sessionControlOwnerKind       = "target_work_directory"
	sessionControlOwnerSchema     = uint64(1)
	sessionControlOwnerSK         = "DIRECTORY"
	sessionControlOwnerPKPrefix   = "TARGETWORK#"
	sessionControlOwnerTaskLimit  = sessionControlFenceActiveLimit + 1
	sessionControlOwnerReadLimit  = sessionControlOwnerTaskLimit + 1
	sessionControlOwnerQueryLimit = int32(100)
)

type sessionControlOwnerPhase string

const (
	sessionControlOwnerPreparing       sessionControlOwnerPhase = "preparing"
	sessionControlOwnerActiveUnready   sessionControlOwnerPhase = "active_unready"
	sessionControlOwnerReady           sessionControlOwnerPhase = "ready"
	sessionControlOwnerDecommissioning sessionControlOwnerPhase = "decommissioning"
	sessionControlOwnerRetired         sessionControlOwnerPhase = "retired"
)

var (
	errSessionControlOwnerNotFound = errors.New("session-control target-work owner not found")
	errSessionControlOwnerConflict = errors.New("session-control target-work owner changed concurrently")
	errSessionControlOwnerCorrupt  = errors.New("session-control target-work owner authority is malformed")
	errSessionControlOwnerCapacity = errors.New("session-control target-work owner task capacity is exhausted")
)

// sessionControlOwnerAuthority is the stable, public-key-scoped bridge between
// target lifecycle and close-task inventory. LifecycleVersion changes only
// with target lifecycle. WorkVersion changes with every physical task mutation
// and every admitted session intent, serializing recovery decommission against
// admission without adding a second authority row. Counts remain exact physical
// task authority and are bracket-verified before readiness.
type sessionControlOwnerAuthority struct {
	CellID                  string
	ACID                    string
	PublicKey               string
	LifecycleVersion        uint64
	WorkVersion             uint64
	TaskCount               uint64
	PendingCount            uint64
	Phase                   sessionControlOwnerPhase
	BootID                  string
	FlushGeneration         uint64
	TargetVersion           uint64
	TargetAuthorityVersion  uint64
	TargetCountedActiveSlot bool
	ActivatedControlVersion uint64
	ReadyControlVersion     uint64
	TargetCreatedAtMillis   int64
	TargetPreparedAtMillis  int64
	TargetUpdatedAtMillis   int64
	AAKEnqueuedAtMillis     int64
	AAKTransactionID        uint64
	CreatedAtMillis         int64
	UpdatedAtMillis         int64
	RetiredAtMillis         int64
}

type sessionControlOwnerFence = sessionControlOwnerAuthority

type sessionControlOwnerRow struct {
	PK                      string                   `dynamodbav:"pk"`
	SK                      string                   `dynamodbav:"sk"`
	Kind                    string                   `dynamodbav:"kind"`
	SchemaVersion           uint64                   `dynamodbav:"schema_version"`
	CellID                  string                   `dynamodbav:"cell_id"`
	ACID                    string                   `dynamodbav:"ac_id"`
	PublicKey               string                   `dynamodbav:"public_key"`
	LifecycleVersion        uint64                   `dynamodbav:"lifecycle_version"`
	WorkVersion             uint64                   `dynamodbav:"work_version"`
	TaskCount               uint64                   `dynamodbav:"task_count"`
	PendingCount            uint64                   `dynamodbav:"pending_count"`
	Phase                   sessionControlOwnerPhase `dynamodbav:"phase"`
	BootID                  string                   `dynamodbav:"boot_id"`
	FlushGeneration         uint64                   `dynamodbav:"flush_generation"`
	TargetVersion           uint64                   `dynamodbav:"target_version"`
	TargetAuthorityVersion  uint64                   `dynamodbav:"target_authority_version"`
	TargetCountedActiveSlot bool                     `dynamodbav:"target_counted_active_slot"`
	ActivatedControlVersion uint64                   `dynamodbav:"activated_control_version"`
	ReadyControlVersion     uint64                   `dynamodbav:"ready_control_version"`
	TargetCreatedAtMillis   int64                    `dynamodbav:"target_created_at_ms"`
	TargetPreparedAtMillis  int64                    `dynamodbav:"target_prepared_at_ms"`
	TargetUpdatedAtMillis   int64                    `dynamodbav:"target_updated_at_ms"`
	AAKEnqueuedAtMillis     int64                    `dynamodbav:"aak_enqueued_at_ms"`
	AAKTransactionID        uint64                   `dynamodbav:"aak_transaction_id"`
	CreatedAtMillis         int64                    `dynamodbav:"created_at_ms"`
	UpdatedAtMillis         int64                    `dynamodbav:"updated_at_ms"`
	RetiredAtMillis         int64                    `dynamodbav:"retired_at_ms,omitempty"`
}

func (owner sessionControlOwnerAuthority) exactTarget(target sessionControlTargetAuthority,
	phase sessionControlOwnerPhase) bool {
	return owner.CellID == target.ControlCellID && owner.ACID == target.ACID && owner.PublicKey == target.PublicKey &&
		owner.Phase == phase && owner.BootID == target.BootID && owner.FlushGeneration == target.FlushGeneration &&
		owner.TargetVersion == target.Version && owner.TargetAuthorityVersion == target.AuthorityVersion &&
		owner.TargetCountedActiveSlot == target.CountedActiveSlot &&
		owner.ActivatedControlVersion == target.ActivatedControlVersion &&
		owner.ReadyControlVersion == target.ReadyControlVersion &&
		owner.TargetCreatedAtMillis == target.CreatedAtMillis && owner.TargetPreparedAtMillis == target.PreparedAtMillis &&
		owner.TargetUpdatedAtMillis == target.UpdatedAtMillis && owner.AAKEnqueuedAtMillis == target.AAKEnqueuedAtMillis &&
		owner.AAKTransactionID == target.AAKTransactionID
}

func sessionControlOwnerPK(cellID, acID, publicKey string) string {
	canonical := fmt.Sprintf("v1\x00%s\x00%s\x00%s", cellID, acID, publicKey)
	digest := sha256.Sum256([]byte(canonical))
	return sessionControlOwnerPKPrefix + hex.EncodeToString(digest[:])
}

func sessionControlOwnerKey(cellID, acID, publicKey string) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{
		"pk": &types.AttributeValueMemberS{Value: sessionControlOwnerPK(cellID, acID, publicKey)},
		"sk": &types.AttributeValueMemberS{Value: sessionControlOwnerSK},
	}
}

func sessionControlOwnerAttributesPresent(item map[string]types.AttributeValue) bool {
	for _, name := range []string{
		"lifecycle_version", "work_version", "task_count", "pending_count",
		"flush_generation", "target_version", "target_authority_version",
		"activated_control_version", "ready_control_version", "aak_enqueued_at_ms",
		"aak_transaction_id", "created_at_ms", "updated_at_ms",
	} {
		if _, ok := item[name].(*types.AttributeValueMemberN); !ok {
			return false
		}
	}
	if _, ok := item["target_counted_active_slot"].(*types.AttributeValueMemberBOOL); !ok {
		return false
	}
	return true
}

func validSessionControlOwnerPhase(phase sessionControlOwnerPhase) bool {
	switch phase {
	case sessionControlOwnerPreparing, sessionControlOwnerActiveUnready, sessionControlOwnerReady,
		sessionControlOwnerDecommissioning, sessionControlOwnerRetired:
		return true
	default:
		return false
	}
}

func validateSessionControlOwnerAuthority(owner sessionControlOwnerAuthority) error {
	if !validSessionControlCellID(owner.CellID) || !validSessionControlTargetKey(sessionControlTargetKey{ACID: owner.ACID, PublicKey: owner.PublicKey}) ||
		!validSessionControlOwnerPhase(owner.Phase) || !validSessionControlTargetCandidate(sessionControlTargetCandidate{
		ACID: owner.ACID, PublicKey: owner.PublicKey, BootID: owner.BootID,
		FlushGeneration: owner.FlushGeneration, ControlCellID: owner.CellID,
	}) || owner.LifecycleVersion == 0 || owner.LifecycleVersion == ^uint64(0) ||
		owner.WorkVersion == 0 || owner.WorkVersion == ^uint64(0) || owner.TaskCount > sessionControlOwnerTaskLimit ||
		owner.PendingCount > owner.TaskCount || owner.TargetVersion == 0 || owner.TargetVersion == ^uint64(0) ||
		owner.TargetAuthorityVersion == 0 || owner.TargetCreatedAtMillis <= 0 ||
		owner.TargetPreparedAtMillis < owner.TargetCreatedAtMillis || owner.TargetUpdatedAtMillis < owner.TargetPreparedAtMillis ||
		owner.CreatedAtMillis <= 0 || owner.UpdatedAtMillis < owner.CreatedAtMillis ||
		!validSessionControlTargetReadyAudit(owner.ActivatedControlVersion, owner.ReadyControlVersion,
			owner.AAKEnqueuedAtMillis, owner.AAKTransactionID, owner.TargetPreparedAtMillis) {
		return errSessionControlOwnerCorrupt
	}
	switch owner.Phase {
	case sessionControlOwnerPreparing:
		if owner.ActivatedControlVersion != 0 || owner.ReadyControlVersion != 0 || owner.RetiredAtMillis != 0 {
			return errSessionControlOwnerCorrupt
		}
	case sessionControlOwnerActiveUnready:
		if !owner.TargetCountedActiveSlot || owner.ActivatedControlVersion == 0 || owner.RetiredAtMillis != 0 ||
			(owner.ReadyControlVersion > 0 && owner.PendingCount == 0) {
			return errSessionControlOwnerCorrupt
		}
	case sessionControlOwnerReady:
		if !owner.TargetCountedActiveSlot || owner.PendingCount != 0 || owner.ReadyControlVersion == 0 ||
			owner.ReadyControlVersion != owner.ActivatedControlVersion || owner.RetiredAtMillis != 0 {
			return errSessionControlOwnerCorrupt
		}
	case sessionControlOwnerDecommissioning:
		if !owner.TargetCountedActiveSlot || owner.TaskCount != 0 || owner.PendingCount != 0 ||
			owner.ReadyControlVersion == 0 || owner.ReadyControlVersion != owner.ActivatedControlVersion ||
			owner.RetiredAtMillis != 0 {
			return errSessionControlOwnerCorrupt
		}
	case sessionControlOwnerRetired:
		if owner.TaskCount != 0 || owner.PendingCount != 0 || owner.TargetCountedActiveSlot ||
			owner.RetiredAtMillis != owner.UpdatedAtMillis {
			return errSessionControlOwnerCorrupt
		}
	}
	return nil
}

func planSessionControlOwnerTaskInsert(current sessionControlOwnerAuthority, updatedAtMillis int64) (sessionControlOwnerAuthority, error) {
	if validateSessionControlOwnerAuthority(current) != nil ||
		(current.Phase != sessionControlOwnerPreparing && current.Phase != sessionControlOwnerActiveUnready &&
			current.Phase != sessionControlOwnerReady) ||
		current.TaskCount >= sessionControlOwnerTaskLimit || current.WorkVersion >= ^uint64(0)-1 {
		if current.TaskCount >= sessionControlOwnerTaskLimit {
			return sessionControlOwnerAuthority{}, errSessionControlOwnerCapacity
		}
		return sessionControlOwnerAuthority{}, errSessionControlOwnerCorrupt
	}
	next := current
	next.WorkVersion++
	next.TaskCount++
	next.PendingCount++
	if next.Phase == sessionControlOwnerReady {
		next.Phase = sessionControlOwnerActiveUnready
	}
	if updatedAtMillis > next.UpdatedAtMillis {
		next.UpdatedAtMillis = updatedAtMillis
	}
	if validateSessionControlOwnerAuthority(next) != nil {
		return sessionControlOwnerAuthority{}, errSessionControlOwnerCorrupt
	}
	return next, nil
}

func planSessionControlOwnerDecommission(current sessionControlOwnerAuthority) (sessionControlOwnerAuthority, error) {
	if validateSessionControlOwnerAuthority(current) != nil || current.Phase != sessionControlOwnerReady ||
		current.TaskCount != 0 || current.PendingCount != 0 || current.LifecycleVersion >= ^uint64(0)-1 {
		return sessionControlOwnerAuthority{}, errSessionControlOwnerCorrupt
	}
	next := current
	next.LifecycleVersion++
	next.Phase = sessionControlOwnerDecommissioning
	if validateSessionControlOwnerAuthority(next) != nil {
		return sessionControlOwnerAuthority{}, errSessionControlOwnerCorrupt
	}
	return next, nil
}

func planSessionControlOwnerAdmission(current sessionControlOwnerAuthority,
	updatedAtMillis int64,
) (sessionControlOwnerAuthority, error) {
	if validateSessionControlOwnerAuthority(current) != nil || current.Phase != sessionControlOwnerReady ||
		current.PendingCount != 0 || current.WorkVersion >= ^uint64(0)-1 {
		return sessionControlOwnerAuthority{}, errSessionControlOwnerCorrupt
	}
	next := current
	next.WorkVersion++
	if updatedAtMillis > next.UpdatedAtMillis {
		next.UpdatedAtMillis = updatedAtMillis
	}
	if validateSessionControlOwnerAuthority(next) != nil {
		return sessionControlOwnerAuthority{}, errSessionControlOwnerCorrupt
	}
	return next, nil
}

func planSessionControlOwnerTaskAck(current sessionControlOwnerAuthority, updatedAtMillis int64) (sessionControlOwnerAuthority, error) {
	if validateSessionControlOwnerAuthority(current) != nil || current.PendingCount == 0 || current.WorkVersion >= ^uint64(0)-1 ||
		current.Phase == sessionControlOwnerRetired {
		return sessionControlOwnerAuthority{}, errSessionControlOwnerCorrupt
	}
	next := current
	next.WorkVersion++
	next.PendingCount--
	if next.PendingCount == 0 && next.ReadyControlVersion > 0 {
		next.Phase = sessionControlOwnerReady
	}
	if updatedAtMillis > next.UpdatedAtMillis {
		next.UpdatedAtMillis = updatedAtMillis
	}
	if validateSessionControlOwnerAuthority(next) != nil {
		return sessionControlOwnerAuthority{}, errSessionControlOwnerCorrupt
	}
	return next, nil
}

func planSessionControlOwnerTaskCleanup(current sessionControlOwnerAuthority, updatedAtMillis int64) (sessionControlOwnerAuthority, error) {
	if validateSessionControlOwnerAuthority(current) != nil || current.TaskCount == 0 || current.PendingCount >= current.TaskCount ||
		current.WorkVersion >= ^uint64(0)-1 || current.Phase == sessionControlOwnerRetired {
		return sessionControlOwnerAuthority{}, errSessionControlOwnerCorrupt
	}
	next := current
	next.WorkVersion++
	next.TaskCount--
	if updatedAtMillis > next.UpdatedAtMillis {
		next.UpdatedAtMillis = updatedAtMillis
	}
	if validateSessionControlOwnerAuthority(next) != nil {
		return sessionControlOwnerAuthority{}, errSessionControlOwnerCorrupt
	}
	return next, nil
}

func sessionControlOwnerFromTarget(target sessionControlTargetAuthority, current *sessionControlOwnerAuthority,
	phase sessionControlOwnerPhase) (sessionControlOwnerAuthority, error) {
	if validateSessionControlTargetAuthority(target) != nil {
		return sessionControlOwnerAuthority{}, errSessionControlOwnerCorrupt
	}
	owner := sessionControlOwnerAuthority{
		CellID: target.ControlCellID, ACID: target.ACID, PublicKey: target.PublicKey,
		LifecycleVersion: 1, WorkVersion: 1, Phase: phase,
		BootID: target.BootID, FlushGeneration: target.FlushGeneration,
		TargetVersion: target.Version, TargetAuthorityVersion: target.AuthorityVersion,
		TargetCountedActiveSlot: target.CountedActiveSlot,
		ActivatedControlVersion: target.ActivatedControlVersion, ReadyControlVersion: target.ReadyControlVersion,
		TargetCreatedAtMillis: target.CreatedAtMillis, TargetPreparedAtMillis: target.PreparedAtMillis,
		TargetUpdatedAtMillis: target.UpdatedAtMillis, AAKEnqueuedAtMillis: target.AAKEnqueuedAtMillis,
		AAKTransactionID: target.AAKTransactionID, CreatedAtMillis: target.CreatedAtMillis,
		UpdatedAtMillis: target.UpdatedAtMillis,
	}
	if current != nil {
		if validateSessionControlOwnerAuthority(*current) != nil || current.CellID != target.ControlCellID ||
			current.ACID != target.ACID || current.PublicKey != target.PublicKey || current.Phase == sessionControlOwnerRetired ||
			current.LifecycleVersion >= ^uint64(0)-1 {
			return sessionControlOwnerAuthority{}, errSessionControlOwnerCorrupt
		}
		owner.LifecycleVersion = current.LifecycleVersion + 1
		owner.WorkVersion = current.WorkVersion
		owner.TaskCount = current.TaskCount
		owner.PendingCount = current.PendingCount
		owner.CreatedAtMillis = current.CreatedAtMillis
		if target.UpdatedAtMillis < current.UpdatedAtMillis {
			owner.UpdatedAtMillis = current.UpdatedAtMillis
		}
	}
	if phase == sessionControlOwnerRetired {
		owner.RetiredAtMillis = owner.UpdatedAtMillis
	}
	if err := validateSessionControlOwnerAuthority(owner); err != nil {
		return sessionControlOwnerAuthority{}, err
	}
	return owner, nil
}

func sessionControlOwnerToRow(owner sessionControlOwnerAuthority) (sessionControlOwnerRow, error) {
	if err := validateSessionControlOwnerAuthority(owner); err != nil {
		return sessionControlOwnerRow{}, err
	}
	return sessionControlOwnerRow{
		PK: sessionControlOwnerPK(owner.CellID, owner.ACID, owner.PublicKey), SK: sessionControlOwnerSK,
		Kind: sessionControlOwnerKind, SchemaVersion: sessionControlOwnerSchema,
		CellID: owner.CellID, ACID: owner.ACID, PublicKey: owner.PublicKey,
		LifecycleVersion: owner.LifecycleVersion, WorkVersion: owner.WorkVersion,
		TaskCount: owner.TaskCount, PendingCount: owner.PendingCount, Phase: owner.Phase,
		BootID: owner.BootID, FlushGeneration: owner.FlushGeneration,
		TargetVersion: owner.TargetVersion, TargetAuthorityVersion: owner.TargetAuthorityVersion,
		TargetCountedActiveSlot: owner.TargetCountedActiveSlot,
		ActivatedControlVersion: owner.ActivatedControlVersion, ReadyControlVersion: owner.ReadyControlVersion,
		TargetCreatedAtMillis: owner.TargetCreatedAtMillis, TargetPreparedAtMillis: owner.TargetPreparedAtMillis,
		TargetUpdatedAtMillis: owner.TargetUpdatedAtMillis, AAKEnqueuedAtMillis: owner.AAKEnqueuedAtMillis,
		AAKTransactionID: owner.AAKTransactionID, CreatedAtMillis: owner.CreatedAtMillis,
		UpdatedAtMillis: owner.UpdatedAtMillis, RetiredAtMillis: owner.RetiredAtMillis,
	}, nil
}

func sessionControlOwnerFromItem(item map[string]types.AttributeValue, cellID, acID, publicKey string) (sessionControlOwnerAuthority, error) {
	if len(item) == 0 {
		return sessionControlOwnerAuthority{}, errSessionControlOwnerNotFound
	}
	if _, hasTTL := item["ttl"]; hasTTL || !sessionControlOwnerAttributesPresent(item) {
		return sessionControlOwnerAuthority{}, errSessionControlOwnerCorrupt
	}
	var row sessionControlOwnerRow
	if err := attributevalue.UnmarshalMap(item, &row); err != nil {
		return sessionControlOwnerAuthority{}, fmt.Errorf("%w: decode target-work owner", errSessionControlOwnerCorrupt)
	}
	owner := sessionControlOwnerAuthority{
		CellID: row.CellID, ACID: row.ACID, PublicKey: row.PublicKey,
		LifecycleVersion: row.LifecycleVersion, WorkVersion: row.WorkVersion,
		TaskCount: row.TaskCount, PendingCount: row.PendingCount, Phase: row.Phase,
		BootID: row.BootID, FlushGeneration: row.FlushGeneration,
		TargetVersion: row.TargetVersion, TargetAuthorityVersion: row.TargetAuthorityVersion,
		TargetCountedActiveSlot: row.TargetCountedActiveSlot,
		ActivatedControlVersion: row.ActivatedControlVersion, ReadyControlVersion: row.ReadyControlVersion,
		TargetCreatedAtMillis: row.TargetCreatedAtMillis, TargetPreparedAtMillis: row.TargetPreparedAtMillis,
		TargetUpdatedAtMillis: row.TargetUpdatedAtMillis, AAKEnqueuedAtMillis: row.AAKEnqueuedAtMillis,
		AAKTransactionID: row.AAKTransactionID, CreatedAtMillis: row.CreatedAtMillis,
		UpdatedAtMillis: row.UpdatedAtMillis, RetiredAtMillis: row.RetiredAtMillis,
	}
	if row.Kind != sessionControlOwnerKind || row.SchemaVersion != sessionControlOwnerSchema ||
		row.PK != sessionControlOwnerPK(row.CellID, row.ACID, row.PublicKey) || row.SK != sessionControlOwnerSK ||
		row.CellID != cellID || row.ACID != acID || row.PublicKey != publicKey || validateSessionControlOwnerAuthority(owner) != nil {
		return sessionControlOwnerAuthority{}, errSessionControlOwnerCorrupt
	}
	return owner, nil
}

func (s *dynamoSessionControlStore) getOwner(ctx context.Context, cellID, acID, publicKey string) (*sessionControlOwnerAuthority, error) {
	result, err := s.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(s.tableName), ConsistentRead: aws.Bool(true),
		Key: sessionControlOwnerKey(cellID, acID, publicKey),
	})
	if err != nil {
		return nil, fmt.Errorf("session-control target-work owner strong read: %w", err)
	}
	owner, err := sessionControlOwnerFromItem(result.Item, cellID, acID, publicKey)
	if err != nil {
		return nil, err
	}
	return &owner, nil
}

func sessionControlOwnerCondition(owner sessionControlOwnerAuthority) (string, map[string]string, map[string]types.AttributeValue) {
	condition := "kind = :owner_kind AND schema_version = :owner_schema AND cell_id = :owner_cell AND ac_id = :owner_ac_id AND public_key = :owner_public_key AND lifecycle_version = :owner_lifecycle_version AND work_version = :owner_work_version AND task_count = :owner_task_count AND pending_count = :owner_pending_count AND #owner_phase = :owner_phase AND boot_id = :owner_boot_id AND flush_generation = :owner_flush_generation AND target_version = :owner_target_version AND target_authority_version = :owner_target_authority_version AND target_counted_active_slot = :owner_target_counted AND activated_control_version = :owner_activated_cursor AND ready_control_version = :owner_ready_cursor AND target_created_at_ms = :owner_target_created AND target_prepared_at_ms = :owner_target_prepared AND target_updated_at_ms = :owner_target_updated AND aak_enqueued_at_ms = :owner_aak_at AND aak_transaction_id = :owner_aak_id AND created_at_ms = :owner_created AND updated_at_ms = :owner_updated AND attribute_not_exists(#ttl)"
	values := map[string]types.AttributeValue{
		":owner_kind":                     &types.AttributeValueMemberS{Value: sessionControlOwnerKind},
		":owner_schema":                   &types.AttributeValueMemberN{Value: fmt.Sprint(sessionControlOwnerSchema)},
		":owner_cell":                     &types.AttributeValueMemberS{Value: owner.CellID},
		":owner_ac_id":                    &types.AttributeValueMemberS{Value: owner.ACID},
		":owner_public_key":               &types.AttributeValueMemberS{Value: owner.PublicKey},
		":owner_lifecycle_version":        &types.AttributeValueMemberN{Value: fmt.Sprint(owner.LifecycleVersion)},
		":owner_work_version":             &types.AttributeValueMemberN{Value: fmt.Sprint(owner.WorkVersion)},
		":owner_task_count":               &types.AttributeValueMemberN{Value: fmt.Sprint(owner.TaskCount)},
		":owner_pending_count":            &types.AttributeValueMemberN{Value: fmt.Sprint(owner.PendingCount)},
		":owner_phase":                    &types.AttributeValueMemberS{Value: string(owner.Phase)},
		":owner_boot_id":                  &types.AttributeValueMemberS{Value: owner.BootID},
		":owner_flush_generation":         &types.AttributeValueMemberN{Value: fmt.Sprint(owner.FlushGeneration)},
		":owner_target_version":           &types.AttributeValueMemberN{Value: fmt.Sprint(owner.TargetVersion)},
		":owner_target_authority_version": &types.AttributeValueMemberN{Value: fmt.Sprint(owner.TargetAuthorityVersion)},
		":owner_target_counted":           &types.AttributeValueMemberBOOL{Value: owner.TargetCountedActiveSlot},
		":owner_activated_cursor":         &types.AttributeValueMemberN{Value: fmt.Sprint(owner.ActivatedControlVersion)},
		":owner_ready_cursor":             &types.AttributeValueMemberN{Value: fmt.Sprint(owner.ReadyControlVersion)},
		":owner_target_created":           &types.AttributeValueMemberN{Value: fmt.Sprint(owner.TargetCreatedAtMillis)},
		":owner_target_prepared":          &types.AttributeValueMemberN{Value: fmt.Sprint(owner.TargetPreparedAtMillis)},
		":owner_target_updated":           &types.AttributeValueMemberN{Value: fmt.Sprint(owner.TargetUpdatedAtMillis)},
		":owner_aak_at":                   &types.AttributeValueMemberN{Value: fmt.Sprint(owner.AAKEnqueuedAtMillis)},
		":owner_aak_id":                   &types.AttributeValueMemberN{Value: fmt.Sprint(owner.AAKTransactionID)},
		":owner_created":                  &types.AttributeValueMemberN{Value: fmt.Sprint(owner.CreatedAtMillis)},
		":owner_updated":                  &types.AttributeValueMemberN{Value: fmt.Sprint(owner.UpdatedAtMillis)},
	}
	if owner.RetiredAtMillis == 0 {
		condition += " AND attribute_not_exists(retired_at_ms)"
	} else {
		condition += " AND retired_at_ms = :owner_retired"
		values[":owner_retired"] = &types.AttributeValueMemberN{Value: fmt.Sprint(owner.RetiredAtMillis)}
	}
	return condition, map[string]string{"#owner_phase": "phase", "#ttl": "ttl"}, values
}

func sessionControlOwnerPut(tableName string, owner sessionControlOwnerAuthority, absent bool) (types.TransactWriteItem, error) {
	row, err := sessionControlOwnerToRow(owner)
	if err != nil {
		return types.TransactWriteItem{}, err
	}
	item, err := attributevalue.MarshalMap(row)
	if err != nil {
		return types.TransactWriteItem{}, fmt.Errorf("marshal target-work owner: %w", err)
	}
	put := &types.Put{TableName: aws.String(tableName), Item: item}
	if absent {
		put.ConditionExpression = aws.String("attribute_not_exists(pk) AND attribute_not_exists(sk)")
	}
	return types.TransactWriteItem{Put: put}, nil
}

func sessionControlOwnerReplace(tableName string, current, next sessionControlOwnerAuthority) (types.TransactWriteItem, error) {
	row, err := sessionControlOwnerToRow(next)
	if err != nil {
		return types.TransactWriteItem{}, err
	}
	item, err := attributevalue.MarshalMap(row)
	if err != nil {
		return types.TransactWriteItem{}, fmt.Errorf("marshal replacement target-work owner: %w", err)
	}
	condition, names, values := sessionControlOwnerCondition(current)
	return types.TransactWriteItem{Put: &types.Put{
		TableName: aws.String(tableName), Item: item, ConditionExpression: aws.String(condition),
		ExpressionAttributeNames: names, ExpressionAttributeValues: values,
	}}, nil
}

func sessionControlOwnerTransitionToken(action string, current *sessionControlOwnerAuthority,
	next sessionControlOwnerAuthority) *string {
	hasher := sha256.New()
	_, _ = fmt.Fprintf(hasher, "v1\x00%s", action)
	if current != nil {
		_, _ = hasher.Write([]byte("\x00current"))
		sessionControlHashOwnerAuthority(hasher, *current)
	} else {
		_, _ = hasher.Write([]byte("\x00absent"))
	}
	_, _ = hasher.Write([]byte("\x00next"))
	sessionControlHashOwnerAuthority(hasher, next)
	token := "sc-own-" + hex.EncodeToString(hasher.Sum(nil)[:12])
	return aws.String(token)
}

func sessionControlHashOwnerAuthority(hasher interface{ Write([]byte) (int, error) }, owner sessionControlOwnerAuthority) {
	_, _ = fmt.Fprintf(hasher,
		"\x00%s\x00%s\x00%s\x00%d\x00%d\x00%d\x00%d\x00%s\x00%s\x00%d\x00%d\x00%d\x00%t\x00%d\x00%d\x00%d\x00%d\x00%d\x00%d\x00%d\x00%d\x00%d\x00%d",
		owner.CellID, owner.ACID, owner.PublicKey, owner.LifecycleVersion, owner.WorkVersion,
		owner.TaskCount, owner.PendingCount, owner.Phase, owner.BootID, owner.FlushGeneration,
		owner.TargetVersion, owner.TargetAuthorityVersion, owner.TargetCountedActiveSlot,
		owner.ActivatedControlVersion, owner.ReadyControlVersion, owner.TargetCreatedAtMillis,
		owner.TargetPreparedAtMillis, owner.TargetUpdatedAtMillis, owner.AAKEnqueuedAtMillis,
		owner.AAKTransactionID, owner.CreatedAtMillis, owner.UpdatedAtMillis, owner.RetiredAtMillis)
}
