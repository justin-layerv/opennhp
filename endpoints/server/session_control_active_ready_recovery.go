package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

const (
	// Retiring the three journaled v4 predecessors advanced the exact live
	// AUTHORITY header from v7 to v10 without changing its creation lineage.
	sandboxActiveReadyAuthorityVersion         = 10
	sandboxActiveReadyAuthorityCreatedAtMillis = 1787485637722
	sandboxActiveReadyAuthorityUpdatedAtMillis = 1787590756221
)

func sandboxActiveReadyAuthorityIsExact(authority sessionControlAuthority) bool {
	return authority.ACID == sandboxStaleTargetRetirementACID &&
		authority.ControlCellID == sandboxStaleTargetRetirementCellID &&
		authority.Version == sandboxActiveReadyAuthorityVersion &&
		authority.ActiveTargetCount == sandboxActiveReadyPredecessorCount &&
		authority.CreatedAtMillis == sandboxActiveReadyAuthorityCreatedAtMillis &&
		authority.UpdatedAtMillis == sandboxActiveReadyAuthorityUpdatedAtMillis
}

// SandboxStaleTargetOwnerFence is the complete immutable OWNER authority that
// the recovery journals before it closes admission for one ACTIVE/READY
// predecessor. Decimal strings prevent JSON number rounding.
type SandboxStaleTargetOwnerFence struct {
	CellID                  string `json:"cell_id"`
	ACID                    string `json:"ac_id"`
	PublicKey               string `json:"public_key"`
	LifecycleVersion        string `json:"lifecycle_version"`
	WorkVersion             string `json:"work_version"`
	TaskCount               string `json:"task_count"`
	PendingCount            string `json:"pending_count"`
	Phase                   string `json:"phase"`
	BootID                  string `json:"boot_id"`
	FlushGeneration         string `json:"flush_generation"`
	TargetVersion           string `json:"target_version"`
	TargetAuthorityVersion  string `json:"target_authority_version"`
	TargetCountedActiveSlot bool   `json:"target_counted_active_slot"`
	ActivatedControlVersion string `json:"activated_control_version"`
	ReadyControlVersion     string `json:"ready_control_version"`
	TargetCreatedAtMillis   string `json:"target_created_at_ms"`
	TargetPreparedAtMillis  string `json:"target_prepared_at_ms"`
	TargetUpdatedAtMillis   string `json:"target_updated_at_ms"`
	AAKEnqueuedAtMillis     string `json:"aak_enqueued_at_ms"`
	AAKTransactionID        string `json:"aak_transaction_id"`
	CreatedAtMillis         string `json:"created_at_ms"`
	UpdatedAtMillis         string `json:"updated_at_ms"`
	RetiredAtMillis         string `json:"retired_at_ms"`
}

func sandboxStaleTargetPublicOwner(owner sessionControlOwnerAuthority) SandboxStaleTargetOwnerFence {
	return SandboxStaleTargetOwnerFence{
		CellID: owner.CellID, ACID: owner.ACID, PublicKey: owner.PublicKey,
		LifecycleVersion: decimal(owner.LifecycleVersion), WorkVersion: decimal(owner.WorkVersion),
		TaskCount: decimal(owner.TaskCount), PendingCount: decimal(owner.PendingCount), Phase: string(owner.Phase),
		BootID: owner.BootID, FlushGeneration: decimal(owner.FlushGeneration),
		TargetVersion: decimal(owner.TargetVersion), TargetAuthorityVersion: decimal(owner.TargetAuthorityVersion),
		TargetCountedActiveSlot: owner.TargetCountedActiveSlot,
		ActivatedControlVersion: decimal(owner.ActivatedControlVersion), ReadyControlVersion: decimal(owner.ReadyControlVersion),
		TargetCreatedAtMillis:  decimalMillis(owner.TargetCreatedAtMillis),
		TargetPreparedAtMillis: decimalMillis(owner.TargetPreparedAtMillis),
		TargetUpdatedAtMillis:  decimalMillis(owner.TargetUpdatedAtMillis),
		AAKEnqueuedAtMillis:    decimalMillis(owner.AAKEnqueuedAtMillis), AAKTransactionID: decimal(owner.AAKTransactionID),
		CreatedAtMillis: decimalMillis(owner.CreatedAtMillis), UpdatedAtMillis: decimalMillis(owner.UpdatedAtMillis),
		RetiredAtMillis: decimalMillis(owner.RetiredAtMillis),
	}
}

func sandboxStaleTargetOwnerDigest(owner sessionControlOwnerAuthority) string {
	hasher := sha256.New()
	sessionControlHashOwnerAuthority(hasher, owner)
	return hex.EncodeToString(hasher.Sum(nil))
}

func sandboxStaleTargetOwnerFromPublic(value SandboxStaleTargetOwnerFence) (sessionControlOwnerAuthority, error) {
	parseUint := func(name, raw string) (uint64, error) {
		parsed, err := strconv.ParseUint(raw, 10, 64)
		if err != nil || strconv.FormatUint(parsed, 10) != raw {
			return 0, fmt.Errorf("invalid owner %s", name)
		}
		return parsed, nil
	}
	parseMillis := func(name, raw string) (int64, error) {
		parsed, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || strconv.FormatInt(parsed, 10) != raw {
			return 0, fmt.Errorf("invalid owner %s", name)
		}
		return parsed, nil
	}
	owner := sessionControlOwnerAuthority{
		CellID: value.CellID, ACID: value.ACID, PublicKey: value.PublicKey,
		Phase: sessionControlOwnerPhase(value.Phase), BootID: value.BootID,
		TargetCountedActiveSlot: value.TargetCountedActiveSlot,
	}
	var err error
	uintFields := []struct {
		name string
		raw  string
		to   *uint64
	}{
		{"lifecycle version", value.LifecycleVersion, &owner.LifecycleVersion},
		{"work version", value.WorkVersion, &owner.WorkVersion},
		{"task count", value.TaskCount, &owner.TaskCount},
		{"pending count", value.PendingCount, &owner.PendingCount},
		{"flush generation", value.FlushGeneration, &owner.FlushGeneration},
		{"target version", value.TargetVersion, &owner.TargetVersion},
		{"target authority version", value.TargetAuthorityVersion, &owner.TargetAuthorityVersion},
		{"activated control version", value.ActivatedControlVersion, &owner.ActivatedControlVersion},
		{"ready control version", value.ReadyControlVersion, &owner.ReadyControlVersion},
		{"AAK transaction", value.AAKTransactionID, &owner.AAKTransactionID},
	}
	for _, field := range uintFields {
		*field.to, err = parseUint(field.name, field.raw)
		if err != nil {
			return sessionControlOwnerAuthority{}, err
		}
	}
	millisFields := []struct {
		name string
		raw  string
		to   *int64
	}{
		{"target created timestamp", value.TargetCreatedAtMillis, &owner.TargetCreatedAtMillis},
		{"target prepared timestamp", value.TargetPreparedAtMillis, &owner.TargetPreparedAtMillis},
		{"target updated timestamp", value.TargetUpdatedAtMillis, &owner.TargetUpdatedAtMillis},
		{"AAK timestamp", value.AAKEnqueuedAtMillis, &owner.AAKEnqueuedAtMillis},
		{"created timestamp", value.CreatedAtMillis, &owner.CreatedAtMillis},
		{"updated timestamp", value.UpdatedAtMillis, &owner.UpdatedAtMillis},
		{"retired timestamp", value.RetiredAtMillis, &owner.RetiredAtMillis},
	}
	for _, field := range millisFields {
		*field.to, err = parseMillis(field.name, field.raw)
		if err != nil {
			return sessionControlOwnerAuthority{}, err
		}
	}
	if validateSessionControlOwnerAuthority(owner) != nil {
		return sessionControlOwnerAuthority{}, errors.New("predecessor owner fence is malformed")
	}
	return owner, nil
}

func (s *dynamoSessionControlStore) sandboxTargetSessionPartitionEmpty(ctx context.Context,
	target sessionControlTargetAuthority,
) error {
	result, err := s.client.Query(ctx, &dynamodb.QueryInput{
		TableName: aws.String(s.tableName), ConsistentRead: aws.Bool(true), Limit: aws.Int32(1),
		KeyConditionExpression: aws.String("pk = :pk"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk": &types.AttributeValueMemberS{Value: sessionControlTargetSessionPK(target)},
		},
	})
	if err != nil {
		return fmt.Errorf("strong reverse target-session inventory: %w", err)
	}
	if result == nil || result.Count != 0 || len(result.Items) != 0 || len(result.LastEvaluatedKey) != 0 {
		return errSessionControlSessionConflict
	}
	return nil
}

func snapshotSandboxActiveReadyPredecessors(ctx context.Context, client sessionControlDynamoAPI,
	tableName string,
) (SandboxStaleTargetRetirementPlan, error) {
	if ctx == nil || client == nil || tableName != SandboxStaleTargetRetirementTable {
		return SandboxStaleTargetRetirementPlan{}, errors.New("invalid sandbox ACTIVE/READY predecessor snapshot authority")
	}
	store := &dynamoSessionControlStore{client: client, tableName: tableName, nowUTC: func() time.Time { return time.Now().UTC() }}
	read := func() (SandboxStaleTargetRetirementPlan, error) {
		directory, err := store.getFenceDirectory(ctx, sandboxStaleTargetRetirementCellID)
		if err != nil || directory.Version != sandboxActiveReadyDirectoryVersion || directory.ActiveFenceCount != 0 || directory.AdmissionBlocked ||
			directory.OverflowCloseCount != 0 || directory.OverflowLeaderEventID != "" ||
			directory.OverflowLeaderPreparedDirectoryVersion != 0 || directory.OverflowLeaderSelectedDirectoryVersion != 0 {
			return SandboxStaleTargetRetirementPlan{}, errSessionControlFenceConflict
		}
		targets, err := store.ListRequiredTargets(ctx, sandboxStaleTargetRetirementACID, sandboxStaleTargetRetirementCellID)
		if err != nil {
			return SandboxStaleTargetRetirementPlan{}, err
		}
		if len(targets) != sandboxActiveReadyPredecessorCount {
			return SandboxStaleTargetRetirementPlan{}, errSessionControlTargetConflict
		}
		authority, authorityErr := store.getAuthority(ctx, sandboxStaleTargetRetirementACID)
		if authorityErr != nil || !sandboxActiveReadyAuthorityIsExact(*authority) {
			return SandboxStaleTargetRetirementPlan{}, errSessionControlTargetConflict
		}
		sort.Slice(targets, func(i, j int) bool { return targets[i].PublicKey < targets[j].PublicKey })
		out := make([]SandboxStaleTargetRetirementPlanTarget, len(targets))
		for index, target := range targets {
			if target.State != sessionControlTargetActive || !target.ready() || !target.CountedActiveSlot ||
				target.AuthorityVersion != 7 || target.ActivatedControlVersion != directory.Version {
				return SandboxStaleTargetRetirementPlan{}, errSessionControlTargetConflict
			}
			snapshot, snapshotErr := store.SnapshotOwnerExactCloseTasks(ctx, target.ControlCellID, target.ACID, target.PublicKey)
			if snapshotErr != nil || snapshot == nil || len(snapshot.Tasks) != 0 ||
				!snapshot.Owner.exactTarget(target, sessionControlOwnerReady) ||
				snapshot.Owner.TaskCount != 0 || snapshot.Owner.PendingCount != 0 {
				return SandboxStaleTargetRetirementPlan{}, errSessionControlOwnerConflict
			}
			if err := store.sandboxTargetSessionPartitionEmpty(ctx, target); err != nil {
				return SandboxStaleTargetRetirementPlan{}, err
			}
			stableTarget, targetErr := store.getTarget(ctx, target.key())
			stableOwner, ownerErr := store.getOwner(ctx, target.ControlCellID, target.ACID, target.PublicKey)
			if targetErr != nil || ownerErr != nil || *stableTarget != target || *stableOwner != snapshot.Owner {
				return SandboxStaleTargetRetirementPlan{}, errSessionControlTargetConflict
			}
			fence := target.fence()
			owner := snapshot.Owner
			publicOwner := sandboxStaleTargetPublicOwner(owner)
			out[index] = SandboxStaleTargetRetirementPlanTarget{
				ID: fmt.Sprintf("active-ready-predecessor-%d", index+1), Fence: sandboxStaleTargetPublicFence(fence),
				FenceSHA256: sandboxStaleTargetFenceDigest(fence), Owner: &publicOwner,
				OwnerSHA256: sandboxStaleTargetOwnerDigest(owner),
			}
		}
		return SandboxStaleTargetRetirementPlan{
			Schema: SandboxActiveReadyPredecessorPlanSchema, Table: tableName, Region: SandboxStaleTargetRetirementRegion,
			ACID: sandboxStaleTargetRetirementACID, ControlCellID: sandboxStaleTargetRetirementCellID, Targets: out,
		}, nil
	}
	before, err := read()
	if err != nil {
		return SandboxStaleTargetRetirementPlan{}, err
	}
	after, err := read()
	if err != nil {
		return SandboxStaleTargetRetirementPlan{}, err
	}
	beforeValue, _ := sandboxCanonicalValue(before)
	afterValue, _ := sandboxCanonicalValue(after)
	if beforeValue != afterValue {
		return SandboxStaleTargetRetirementPlan{}, errSessionControlTargetConflict
	}
	return after, nil
}

// SnapshotSandboxActiveReadyPredecessorsForRecovery precommits the exact
// homogeneous v7 ACTIVE/READY trio only after the v4 incident targets are gone.
func SnapshotSandboxActiveReadyPredecessorsForRecovery(ctx context.Context, client *dynamodb.Client,
	tableName string,
) (SandboxStaleTargetRetirementPlan, error) {
	if client == nil {
		return SandboxStaleTargetRetirementPlan{}, errors.New("invalid sandbox ACTIVE/READY predecessor snapshot client")
	}
	return snapshotSandboxActiveReadyPredecessors(ctx, client, tableName)
}

const (
	sandboxActiveReadyLatchReceiptSchema      = "layerv.durable-aop-active-ready-latch-receipt.v1"
	sandboxActiveReadyQuiescenceReceiptSchema = "layerv.durable-aop-active-ready-quiescence-receipt.v1"
)

type SandboxActiveReadyLatchReceipt struct {
	Schema          string                       `json:"schema"`
	TargetID        string                       `json:"target_id"`
	FenceSHA256     string                       `json:"fence_sha256"`
	Owner           SandboxStaleTargetOwnerFence `json:"owner"`
	OwnerSHA256     string                       `json:"owner_sha256"`
	DirectorySHA256 string                       `json:"directory_sha256"`
}

type SandboxActiveReadyQuiescenceReceipt struct {
	Schema             string `json:"schema"`
	TargetID           string `json:"target_id"`
	FenceSHA256        string `json:"fence_sha256"`
	OwnerSHA256        string `json:"owner_sha256"`
	OwnerTaskCount     string `json:"owner_task_count"`
	OwnerPendingCount  string `json:"owner_pending_count"`
	TargetSessionPK    string `json:"target_session_pk"`
	TargetSessionCount string `json:"target_session_count"`
	DirectorySHA256    string `json:"directory_sha256"`
}
type sandboxActiveReadyJournalTarget struct {
	FenceSHA256       string                               `json:"fence_sha256"`
	ID                string                               `json:"id"`
	LatchReceipt      *SandboxActiveReadyLatchReceipt      `json:"latch_receipt,omitempty"`
	QuiescenceReceipt *SandboxActiveReadyQuiescenceReceipt `json:"quiescence_receipt,omitempty"`
	Receipt           *SandboxStaleTargetRetirementReceipt `json:"receipt,omitempty"`
	Status            string                               `json:"status"`
}

func sandboxActiveReadyLedgerObjectIsClosed(value any) bool {
	targets, ok := value.([]any)
	if !ok || len(targets) > sandboxActiveReadyPredecessorCount {
		return false
	}
	for _, rawTarget := range targets {
		target, ok := rawTarget.(map[string]any)
		if !ok {
			return false
		}
		status, _ := target["status"].(string)
		switch status {
		case "pending":
			if !sandboxExactObjectKeys(target, "fence_sha256", "id", "status") {
				return false
			}
		case "latched":
			if !sandboxExactObjectKeys(target, "fence_sha256", "id", "latch_receipt", "status") ||
				!sandboxExactObjectKeys(target["latch_receipt"], "directory_sha256", "fence_sha256", "owner", "owner_sha256", "schema", "target_id") {
				return false
			}
		case "quiescent":
			if !sandboxExactObjectKeys(target, "fence_sha256", "id", "latch_receipt", "quiescence_receipt", "status") ||
				!sandboxExactObjectKeys(target["latch_receipt"], "directory_sha256", "fence_sha256", "owner", "owner_sha256", "schema", "target_id") ||
				!sandboxExactObjectKeys(target["quiescence_receipt"], "directory_sha256", "fence_sha256", "owner_pending_count",
					"owner_sha256", "owner_task_count", "schema", "target_id", "target_session_count", "target_session_pk") {
				return false
			}
		case "retired":
			if !sandboxExactObjectKeys(target, "fence_sha256", "id", "latch_receipt", "quiescence_receipt", "receipt", "status") ||
				!sandboxExactObjectKeys(target["receipt"], "authority_version", "counted_active_slot", "public_key",
					"retired_at_ms", "retired_target_sha256", "schema", "target_id", "version") {
				return false
			}
		default:
			return false
		}
	}
	return true
}
func sandboxTargetFromFenceAndOwner(fence sessionControlTargetFence,
	owner sessionControlOwnerAuthority,
) sessionControlTargetAuthority {
	return sessionControlTargetAuthority{
		ACID: fence.ACID, PublicKey: fence.PublicKey, BootID: fence.BootID,
		FlushGeneration: fence.FlushGeneration, State: sessionControlTargetActive,
		Version: fence.Version, AuthorityVersion: fence.AuthorityVersion, CountedActiveSlot: fence.CountedActiveSlot,
		ControlCellID: fence.ControlCellID, ActivatedControlVersion: fence.ActivatedControlVersion,
		ReadyControlVersion: fence.ReadyControlVersion, AAKEnqueuedAtMillis: fence.AAKEnqueuedAtMillis,
		AAKTransactionID: fence.AAKTransactionID, CreatedAtMillis: fence.CreatedAtMillis,
		PreparedAtMillis: fence.PreparedAtMillis, UpdatedAtMillis: owner.TargetUpdatedAtMillis,
	}
}

func sandboxLatchReceipt(targetID string, fence sessionControlTargetFence, owner sessionControlOwnerAuthority,
	directory SandboxFenceDirectoryRecoveryReceipt,
) *SandboxActiveReadyLatchReceipt {
	return &SandboxActiveReadyLatchReceipt{
		Schema: sandboxActiveReadyLatchReceiptSchema, TargetID: targetID,
		FenceSHA256: sandboxStaleTargetFenceDigest(fence), Owner: sandboxStaleTargetPublicOwner(owner),
		OwnerSHA256: sandboxStaleTargetOwnerDigest(owner), DirectorySHA256: directory.DirectorySHA256,
	}
}

func classifySandboxActiveReadyDecommissionWithClient(ctx context.Context, client sessionControlDynamoAPI,
	targetID string, fence sessionControlTargetFence, expectedOwner sessionControlOwnerAuthority,
	directoryReceipt SandboxFenceDirectoryRecoveryReceipt,
) (*SandboxActiveReadyLatchReceipt, error) {
	directory, err := sandboxDirectoryFromRecoveryReceipt(directoryReceipt, "0")
	if err != nil || directory.Version != sandboxActiveReadyDirectoryVersion {
		return nil, errSessionControlFenceCorrupt
	}
	target := sandboxTargetFromFenceAndOwner(fence, expectedOwner)
	store := &dynamoSessionControlStore{client: client, tableName: SandboxStaleTargetRetirementTable,
		nowUTC: func() time.Time { return time.Now().UTC() }}
	currentTarget, targetErr := store.getTarget(ctx, target.key())
	currentOwner, ownerErr := store.getOwner(ctx, target.ControlCellID, target.ACID, target.PublicKey)
	currentAuthority, authorityErr := store.getAuthority(ctx, target.ACID)
	currentDirectory, directoryErr := store.getFenceDirectory(ctx, target.ControlCellID)
	if targetErr != nil || ownerErr != nil || authorityErr != nil || directoryErr != nil ||
		*currentTarget != target || *currentOwner != expectedOwner ||
		!sandboxActiveReadyAuthorityIsExact(*currentAuthority) || *currentDirectory != directory {
		return nil, errSessionControlOwnerConflict
	}
	return sandboxLatchReceipt(targetID, fence, expectedOwner, directoryReceipt), nil
}

func beginSandboxActiveReadyDecommissionWithClient(ctx context.Context, client sessionControlDynamoAPI,
	targetID string, fence sessionControlTargetFence, readyOwner sessionControlOwnerAuthority,
	directoryReceipt SandboxFenceDirectoryRecoveryReceipt,
) (*SandboxActiveReadyLatchReceipt, error) {
	if ctx == nil || client == nil || targetID == "" || readyOwner.Phase != sessionControlOwnerReady {
		return nil, errors.New("invalid sandbox ACTIVE/READY latch authority")
	}
	directory, err := sandboxDirectoryFromRecoveryReceipt(directoryReceipt, "0")
	if err != nil {
		return nil, err
	}
	if directory.Version != sandboxActiveReadyDirectoryVersion {
		return nil, errSessionControlFenceCorrupt
	}
	target := sandboxTargetFromFenceAndOwner(fence, readyOwner)
	if validateSessionControlTargetAuthority(target) != nil || !target.ready() ||
		!readyOwner.exactTarget(target, sessionControlOwnerReady) || readyOwner.TaskCount != 0 || readyOwner.PendingCount != 0 {
		return nil, errors.New("ACTIVE/READY latch fence is malformed")
	}
	store := &dynamoSessionControlStore{client: client, tableName: SandboxStaleTargetRetirementTable,
		nowUTC: func() time.Time { return time.Now().UTC() }}
	nextOwner, err := planSessionControlOwnerDecommission(readyOwner)
	if err != nil {
		return nil, err
	}
	currentOwner, err := store.getOwner(ctx, target.ControlCellID, target.ACID, target.PublicKey)
	if err != nil {
		return nil, err
	}
	if *currentOwner == nextOwner {
		return classifySandboxActiveReadyDecommissionWithClient(ctx, client, targetID, fence, nextOwner,
			directoryReceipt)
	}
	if *currentOwner != readyOwner {
		return nil, errSessionControlOwnerConflict
	}
	currentTarget, err := store.getTarget(ctx, target.key())
	if err != nil || *currentTarget != target {
		return nil, errSessionControlTargetConflict
	}
	authority, err := store.getAuthority(ctx, target.ACID)
	if err != nil || !sandboxActiveReadyAuthorityIsExact(*authority) {
		return nil, errSessionControlTargetConflict
	}
	ownerWrite, err := sessionControlOwnerReplace(store.tableName, readyOwner, nextOwner)
	if err != nil {
		return nil, err
	}
	targetValues := sessionControlTargetTransactionValues(fence)
	targetValues[":current_state"] = &types.AttributeValueMemberS{Value: string(sessionControlTargetActive)}
	targetCheck := types.TransactWriteItem{ConditionCheck: &types.ConditionCheck{
		TableName: aws.String(store.tableName), Key: sessionControlTargetDynamoKey(target.key()),
		ConditionExpression:       aws.String(sessionControlTargetTransactionCondition() + " AND attribute_not_exists(retired_at_ms) AND attribute_not_exists(#ttl)"),
		ExpressionAttributeNames:  map[string]string{"#state": "state", "#version": "version", "#ttl": "ttl"},
		ExpressionAttributeValues: targetValues,
	}}
	authorityCheck := types.TransactWriteItem{ConditionCheck: &types.ConditionCheck{
		TableName: aws.String(store.tableName), Key: sessionControlAuthorityDynamoKey(target.ACID),
		ConditionExpression:      aws.String("kind = :kind AND schema_version = :schema AND ac_id = :ac_id AND #version = :version AND active_target_count = :count AND control_cell_id = :cell AND created_at_ms = :created_at AND updated_at_ms = :updated_at AND attribute_not_exists(#ttl)"),
		ExpressionAttributeNames: map[string]string{"#version": "version", "#ttl": "ttl"},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":kind":       &types.AttributeValueMemberS{Value: sessionControlAuthorityKind},
			":schema":     &types.AttributeValueMemberN{Value: fmt.Sprint(sessionControlAuthoritySchema)},
			":ac_id":      &types.AttributeValueMemberS{Value: target.ACID},
			":version":    &types.AttributeValueMemberN{Value: fmt.Sprint(sandboxActiveReadyAuthorityVersion)},
			":count":      &types.AttributeValueMemberN{Value: fmt.Sprint(sandboxActiveReadyPredecessorCount)},
			":cell":       &types.AttributeValueMemberS{Value: target.ControlCellID},
			":created_at": &types.AttributeValueMemberN{Value: fmt.Sprint(sandboxActiveReadyAuthorityCreatedAtMillis)},
			":updated_at": &types.AttributeValueMemberN{Value: fmt.Sprint(sandboxActiveReadyAuthorityUpdatedAtMillis)},
		},
	}}
	directoryValues := sessionControlFenceDirectoryConditionValues(directory)
	delete(directoryValues, ":next_version")
	directoryCheck := types.TransactWriteItem{ConditionCheck: &types.ConditionCheck{
		TableName: aws.String(store.tableName), Key: sessionControlFenceDirectoryKey(directory.CellID),
		ConditionExpression:       aws.String(sessionControlFenceDirectoryCondition()),
		ExpressionAttributeNames:  map[string]string{"#version": "version", "#ttl": "ttl"},
		ExpressionAttributeValues: directoryValues,
	}}
	opCtx, cancel := context.WithTimeout(ctx, store.timeout())
	_, err = client.TransactWriteItems(opCtx, &dynamodb.TransactWriteItemsInput{
		ClientRequestToken: sessionControlOwnerTransitionToken("decommission", &readyOwner, nextOwner),
		TransactItems:      []types.TransactWriteItem{targetCheck, authorityCheck, directoryCheck, ownerWrite},
	})
	cancel()
	if err != nil {
		resultCtx, resultCancel := store.sessionResultContext(ctx)
		receipt, classifyErr := classifySandboxActiveReadyDecommissionWithClient(resultCtx, client, targetID,
			fence, nextOwner, directoryReceipt)
		resultCancel()
		if classifyErr != nil {
			return nil, fmt.Errorf("latch ACTIVE/READY predecessor: %w", err)
		}
		return receipt, nil
	}
	return sandboxLatchReceipt(targetID, fence, nextOwner, directoryReceipt), nil
}

func verifySandboxActiveReadyQuiescenceWithClient(ctx context.Context, client sessionControlDynamoAPI,
	targetID string, fence sessionControlTargetFence, expectedOwner sessionControlOwnerAuthority,
	directoryReceipt SandboxFenceDirectoryRecoveryReceipt,
) (*SandboxActiveReadyQuiescenceReceipt, error) {
	if ctx == nil || client == nil || expectedOwner.Phase != sessionControlOwnerDecommissioning {
		return nil, errors.New("invalid sandbox ACTIVE/READY quiescence authority")
	}
	directory, err := sandboxDirectoryFromRecoveryReceipt(directoryReceipt, "0")
	if err != nil {
		return nil, err
	}
	if directory.Version != sandboxActiveReadyDirectoryVersion {
		return nil, errSessionControlFenceCorrupt
	}
	target := sandboxTargetFromFenceAndOwner(fence, expectedOwner)
	store := &dynamoSessionControlStore{client: client, tableName: SandboxStaleTargetRetirementTable,
		nowUTC: func() time.Time { return time.Now().UTC() }}
	beforeTarget, err := store.getTarget(ctx, target.key())
	if err != nil || *beforeTarget != target {
		return nil, errSessionControlTargetConflict
	}
	snapshot, err := store.SnapshotOwnerExactCloseTasks(ctx, target.ControlCellID, target.ACID, target.PublicKey)
	if err != nil || snapshot == nil || snapshot.Owner != expectedOwner || len(snapshot.Tasks) != 0 {
		return nil, errSessionControlOwnerConflict
	}
	if err := store.sandboxTargetSessionPartitionEmpty(ctx, target); err != nil {
		return nil, err
	}
	afterTarget, targetErr := store.getTarget(ctx, target.key())
	afterOwner, ownerErr := store.getOwner(ctx, target.ControlCellID, target.ACID, target.PublicKey)
	afterDirectory, directoryErr := store.getFenceDirectory(ctx, directory.CellID)
	if targetErr != nil || ownerErr != nil || directoryErr != nil || *afterTarget != target ||
		*afterOwner != expectedOwner || *afterDirectory != directory {
		return nil, errSessionControlTargetConflict
	}
	return &SandboxActiveReadyQuiescenceReceipt{
		Schema: sandboxActiveReadyQuiescenceReceiptSchema, TargetID: targetID,
		FenceSHA256: sandboxStaleTargetFenceDigest(fence), OwnerSHA256: sandboxStaleTargetOwnerDigest(expectedOwner),
		OwnerTaskCount: "0", OwnerPendingCount: "0", TargetSessionPK: sessionControlTargetSessionPK(target),
		TargetSessionCount: "0", DirectorySHA256: directoryReceipt.DirectorySHA256,
	}, nil
}

type sandboxActiveReadyOperation string

const (
	sandboxActiveReadyLatch      sandboxActiveReadyOperation = "latch"
	sandboxActiveReadyQuiescence sandboxActiveReadyOperation = "quiescence"
	sandboxActiveReadyRetire     sandboxActiveReadyOperation = "retire"
)

type sandboxActiveReadyJournalAuthority struct {
	Fence              sessionControlTargetFence
	ReadyOwner         sessionControlOwnerAuthority
	DecommissionOwner  sessionControlOwnerAuthority
	Directory          SandboxFenceDirectoryRecoveryReceipt
	Index              int
	CurrentIsSuccessor bool
	SuccessorTarget    sandboxActiveReadyJournalTarget
}

func sandboxValidateActiveReadyLatchReceipt(receipt *SandboxActiveReadyLatchReceipt, targetID string,
	fence sessionControlTargetFence, owner sessionControlOwnerAuthority, directory SandboxFenceDirectoryRecoveryReceipt,
) bool {
	if receipt == nil {
		return false
	}
	parsedOwner, err := sandboxStaleTargetOwnerFromPublic(receipt.Owner)
	return err == nil && receipt.Schema == sandboxActiveReadyLatchReceiptSchema && receipt.TargetID == targetID &&
		receipt.FenceSHA256 == sandboxStaleTargetFenceDigest(fence) && parsedOwner == owner &&
		receipt.OwnerSHA256 == sandboxStaleTargetOwnerDigest(owner) && receipt.DirectorySHA256 == directory.DirectorySHA256
}

func sandboxValidateActiveReadyQuiescenceReceipt(receipt *SandboxActiveReadyQuiescenceReceipt, targetID string,
	fence sessionControlTargetFence, owner sessionControlOwnerAuthority, directory SandboxFenceDirectoryRecoveryReceipt,
) bool {
	if receipt == nil {
		return false
	}
	target := sandboxTargetFromFenceAndOwner(fence, owner)
	return receipt.Schema == sandboxActiveReadyQuiescenceReceiptSchema && receipt.TargetID == targetID &&
		receipt.FenceSHA256 == sandboxStaleTargetFenceDigest(fence) &&
		receipt.OwnerSHA256 == sandboxStaleTargetOwnerDigest(owner) && receipt.OwnerTaskCount == "0" &&
		receipt.OwnerPendingCount == "0" && receipt.TargetSessionPK == sessionControlTargetSessionPK(target) &&
		receipt.TargetSessionCount == "0" && receipt.DirectorySHA256 == directory.DirectorySHA256
}

func sandboxValidateActiveReadyJournalTarget(target sandboxActiveReadyJournalTarget, planTarget SandboxStaleTargetRetirementPlanTarget,
	fence sessionControlTargetFence, readyOwner, decommissionOwner sessionControlOwnerAuthority,
	directory SandboxFenceDirectoryRecoveryReceipt,
) bool {
	if target.ID != planTarget.ID || target.FenceSHA256 != planTarget.FenceSHA256 {
		return false
	}
	switch target.Status {
	case "pending":
		return target.LatchReceipt == nil && target.QuiescenceReceipt == nil && target.Receipt == nil
	case "latched":
		return sandboxValidateActiveReadyLatchReceipt(target.LatchReceipt, target.ID, fence, decommissionOwner, directory) &&
			target.QuiescenceReceipt == nil && target.Receipt == nil
	case "quiescent":
		return sandboxValidateActiveReadyLatchReceipt(target.LatchReceipt, target.ID, fence, decommissionOwner, directory) &&
			sandboxValidateActiveReadyQuiescenceReceipt(target.QuiescenceReceipt, target.ID, fence, decommissionOwner, directory) &&
			target.Receipt == nil
	case "retired":
		return sandboxValidateActiveReadyLatchReceipt(target.LatchReceipt, target.ID, fence, decommissionOwner, directory) &&
			sandboxValidateActiveReadyQuiescenceReceipt(target.QuiescenceReceipt, target.ID, fence, decommissionOwner, directory) &&
			sandboxValidateRetirementReceipt(target.Receipt, target.ID, fence)
	default:
		return false
	}
}

func sandboxActiveReadyExpectedSuccessor(target sandboxActiveReadyJournalTarget,
	operation sandboxActiveReadyOperation, successor sandboxActiveReadyJournalTarget,
) (sandboxActiveReadyJournalTarget, bool) {
	expected := target
	switch operation {
	case sandboxActiveReadyLatch:
		if target.Status != "pending" || successor.Status != "latched" {
			return expected, false
		}
		expected.Status = "latched"
		expected.LatchReceipt = successor.LatchReceipt
	case sandboxActiveReadyQuiescence:
		if target.Status != "latched" || successor.Status != "quiescent" {
			return expected, false
		}
		expected.Status = "quiescent"
		expected.QuiescenceReceipt = successor.QuiescenceReceipt
	case sandboxActiveReadyRetire:
		if target.Status != "quiescent" || successor.Status != "retired" {
			return expected, false
		}
		expected.Status = "retired"
		expected.Receipt = successor.Receipt
	default:
		return expected, false
	}
	return expected, true
}

func sandboxActiveReadyStatusAtOperation(index, selected int, operation sandboxActiveReadyOperation,
	status string,
) bool {
	switch operation {
	case sandboxActiveReadyLatch:
		return (index < selected && status == "quiescent") ||
			(index == selected && status == "pending") || (index > selected && status == "pending")
	case sandboxActiveReadyQuiescence:
		return (index < selected && status == "quiescent") ||
			(index == selected && status == "latched") || (index > selected && status == "pending")
	case sandboxActiveReadyRetire:
		return (index < selected && status == "retired") ||
			(index == selected && status == "quiescent") || (index > selected && status == "quiescent")
	default:
		return false
	}
}

func sandboxActiveReadyQuiescentLedgerDigest(targets []sandboxActiveReadyJournalTarget) (string, bool) {
	quiescent := make([]sandboxActiveReadyJournalTarget, len(targets))
	for index, target := range targets {
		if target.LatchReceipt == nil || target.QuiescenceReceipt == nil {
			return "", false
		}
		quiescent[index] = target
		quiescent[index].Status = "quiescent"
		quiescent[index].Receipt = nil
	}
	value, err := sandboxCanonicalValue(quiescent)
	return sandboxCanonicalDigest(value), err == nil
}

func sandboxActiveReadyJournalStatusValid(journal sandboxActiveReadyRecoveryJournal) bool {
	switch journal.Status {
	case "latching":
		seenPending := false
		seenLatched := false
		for _, target := range journal.Targets {
			switch target.Status {
			case "quiescent":
				if seenPending || seenLatched {
					return false
				}
			case "latched":
				if seenPending || seenLatched {
					return false
				}
				seenLatched = true
			case "pending":
				seenPending = true
			default:
				return false
			}
		}
		return journal.QuiescenceSHA256 == ""
	case "quiescent":
		for _, target := range journal.Targets {
			if target.Status != "quiescent" {
				return false
			}
		}
	case "retiring":
		seenQuiescent := false
		for _, target := range journal.Targets {
			if target.Status == "retired" && !seenQuiescent {
				continue
			}
			if target.Status != "quiescent" {
				return false
			}
			seenQuiescent = true
		}
	case "complete":
		for _, target := range journal.Targets {
			if target.Status != "retired" {
				return false
			}
		}
	default:
		return false
	}
	quiescenceDigest, ok := sandboxActiveReadyQuiescentLedgerDigest(journal.Targets)
	return ok && journal.QuiescenceSHA256 == quiescenceDigest
}

func sandboxResolveJournaledActiveReadyAuthority(stateSnapshot, currentJournalSnapshot,
	referencedJournalSnapshot, currentReadySnapshot, referencedReadySnapshot SandboxRecoveryParameterSnapshot,
	targetID string, operation sandboxActiveReadyOperation,
) (sandboxActiveReadyJournalAuthority, error) {
	var authority sandboxActiveReadyJournalAuthority
	resolved, err := sandboxResolveJournalSnapshots(stateSnapshot, currentJournalSnapshot, referencedJournalSnapshot)
	if err != nil {
		return authority, err
	}
	mainJournal := resolved.Referenced
	readyRef := mainJournal.Runtime.ReadyPredecessorRef
	if readyRef == nil || readyRef.Parameter != SandboxActiveReadyRecoveryJournalParameter || readyRef.Version <= 0 ||
		!sandboxExactHex(readyRef.SHA256, 32) || mainJournal.Runtime.PredecessorPlan.Targets != nil ||
		mainJournal.Runtime.PredecessorPlanSHA256 != "" || len(mainJournal.Runtime.PredecessorTargets) != 0 ||
		referencedReadySnapshot.Version != readyRef.Version ||
		sandboxCanonicalDigest(referencedReadySnapshot.Value) != readyRef.SHA256 {
		return authority, errors.New("ACTIVE/READY predecessor journal is malformed")
	}
	if operation == sandboxActiveReadyRetire {
		if mainJournal.Status != "ready_predecessor_retiring" {
			return authority, errors.New("ACTIVE/READY retirement is not at the post-refresh boundary")
		}
	} else if mainJournal.Status != "ready_predecessor_latching" {
		return authority, errors.New("ACTIVE/READY latch or quiescence is not at its pre-refresh boundary")
	}
	readyJournal, readyObject, err := sandboxDecodeActiveReadyJournal(referencedReadySnapshot)
	if err != nil || !sandboxActiveReadyJournalObjectIsClosed(readyObject) ||
		readyJournal.Schema != sandboxActiveReadyJournalSchema || readyJournal.SourceStateVersion != 30 ||
		readyJournal.SourceStateSHA256 != "4268c108fe2685c5a475d05f2ec98d5d58c54618dc3934289b97bc0da855dca6" ||
		readyJournal.SourceMainJournalParameter != SandboxStaleTargetRecoveryJournalParameter ||
		readyJournal.SourceMainJournalVersion != 8 ||
		readyJournal.SourceMainJournalSHA256 != "49a0da6ea26c551ed99f51ad1e1a4608aa89ab7d1f97a40f22c2c12ce99b1a5c" ||
		readyJournal.OrchestratorSHA != resolved.State.Repair.OrchestratorSHA ||
		readyJournal.FenceDrainSHA256 != mainJournal.Runtime.FenceDrain.DirectorySHA256 ||
		!sandboxActiveReadyJournalStatusValid(readyJournal) {
		return authority, errors.New("referenced ACTIVE/READY audit journal is malformed")
	}
	plan := readyJournal.Plan
	planValue, _ := sandboxCanonicalValue(plan)
	fences, err := sandboxValidatePlan(plan, SandboxActiveReadyPredecessorPlanSchema)
	if err != nil || readyJournal.PlanSHA256 != sandboxCanonicalDigest(planValue) ||
		len(readyJournal.Targets) != len(fences) || !sandboxValidateDirectoryReceipt(mainJournal.Runtime.FenceDrain, "0") ||
		mainJournal.Runtime.FenceDrain.Version != "250" {
		return authority, errors.New("ACTIVE/READY predecessor plan or zero-directory receipt drifted")
	}
	selected := -1
	for index := range plan.Targets {
		if plan.Targets[index].ID == targetID {
			selected = index
			break
		}
	}
	if selected < 0 {
		return authority, errors.New("target ID is not in the referenced ACTIVE/READY plan")
	}
	for index := range fences {
		planTarget := plan.Targets[index]
		readyOwner, ownerErr := sandboxStaleTargetOwnerFromPublic(*planTarget.Owner)
		decommissionOwner, decommissionErr := planSessionControlOwnerDecommission(readyOwner)
		if ownerErr != nil || decommissionErr != nil ||
			!sandboxValidateActiveReadyJournalTarget(readyJournal.Targets[index], planTarget,
				fences[index], readyOwner, decommissionOwner, mainJournal.Runtime.FenceDrain) {
			return authority, errors.New("ACTIVE/READY predecessor ledger drifted from its plan")
		}
		if index == selected {
			authority = sandboxActiveReadyJournalAuthority{Fence: fences[index], ReadyOwner: readyOwner,
				DecommissionOwner: decommissionOwner, Directory: mainJournal.Runtime.FenceDrain, Index: index}
		}
	}
	selectedLedger := readyJournal.Targets[selected]
	for index, target := range readyJournal.Targets {
		if !sandboxActiveReadyStatusAtOperation(index, selected, operation, target.Status) {
			return authority, errors.New("ACTIVE/READY target order is not at the selected journal operation")
		}
	}
	currentReadyIsReference := currentReadySnapshot == referencedReadySnapshot
	currentReadyIsSuccessor := currentReadySnapshot.Version == referencedReadySnapshot.Version+1
	if !currentReadyIsReference && !currentReadyIsSuccessor {
		return authority, errors.New("current ACTIVE/READY journal is neither the reference nor one successor")
	}
	if resolved.CurrentIsSuccessor {
		if !currentReadyIsSuccessor {
			return authority, errors.New("main journal successor does not reference an ACTIVE/READY successor")
		}
		successorMain, successorMainObject, decodeErr := sandboxDecodeStaleTargetJournal(currentJournalSnapshot)
		if decodeErr != nil || !sandboxStaleTargetJournalObjectIsClosed(successorMainObject) ||
			successorMain.Runtime.ReadyPredecessorRef == nil {
			return authority, errors.New("main journal ACTIVE/READY ref successor is malformed")
		}
		expectedMain := mainJournal
		expectedRef := *readyRef
		expectedRef.Version = currentReadySnapshot.Version
		expectedRef.SHA256 = sandboxCanonicalDigest(currentReadySnapshot.Value)
		expectedMain.Runtime.ReadyPredecessorRef = &expectedRef
		expectedMainValue, _ := sandboxCanonicalValue(expectedMain)
		successorMainValue, _ := sandboxCanonicalValue(successorMain)
		if expectedMainValue != successorMainValue {
			return authority, errors.New("main journal successor changed more than the ACTIVE/READY ref")
		}
	}
	authority.CurrentIsSuccessor = currentReadyIsSuccessor
	if currentReadyIsSuccessor {
		successor, successorObject, decodeErr := sandboxDecodeActiveReadyJournal(currentReadySnapshot)
		if decodeErr != nil || !sandboxActiveReadyJournalObjectIsClosed(successorObject) ||
			len(successor.Targets) != len(readyJournal.Targets) {
			return authority, errors.New("ACTIVE/READY journal successor is malformed")
		}
		successorTarget := successor.Targets[selected]
		expectedTarget, ok := sandboxActiveReadyExpectedSuccessor(selectedLedger, operation, successorTarget)
		if !ok || !sandboxValidateActiveReadyJournalTarget(successorTarget, plan.Targets[selected], authority.Fence,
			authority.ReadyOwner, authority.DecommissionOwner, authority.Directory) {
			return authority, errors.New("ACTIVE/READY journal successor has an invalid selected receipt")
		}
		expectedJournal := readyJournal
		expectedJournal.Targets = append([]sandboxActiveReadyJournalTarget(nil), readyJournal.Targets...)
		expectedJournal.Targets[selected] = expectedTarget
		if operation == sandboxActiveReadyQuiescence && selected == len(readyJournal.Targets)-1 {
			expectedJournal.Status = "quiescent"
			expectedJournal.QuiescenceSHA256, _ = sandboxActiveReadyQuiescentLedgerDigest(expectedJournal.Targets)
		} else if operation == sandboxActiveReadyRetire {
			expectedJournal.Status = "retiring"
			if selected == len(readyJournal.Targets)-1 {
				expectedJournal.Status = "complete"
			}
		}
		expectedValue, _ := sandboxCanonicalValue(expectedJournal)
		successorValue, _ := sandboxCanonicalValue(successor)
		if expectedValue != successorValue {
			return authority, errors.New("ACTIVE/READY journal successor changed more than the selected receipt")
		}
		authority.SuccessorTarget = successorTarget
	}
	return authority, nil
}

func latchSandboxJournaledActiveReadyWithClient(ctx context.Context, client sessionControlDynamoAPI,
	targetID string, stateSnapshot, currentJournalSnapshot, referencedJournalSnapshot,
	currentReadySnapshot, referencedReadySnapshot SandboxRecoveryParameterSnapshot,
) (*SandboxActiveReadyLatchReceipt, error) {
	authority, err := sandboxResolveJournaledActiveReadyAuthority(stateSnapshot, currentJournalSnapshot,
		referencedJournalSnapshot, currentReadySnapshot, referencedReadySnapshot, targetID, sandboxActiveReadyLatch)
	if err != nil {
		return nil, err
	}
	var receipt *SandboxActiveReadyLatchReceipt
	if authority.CurrentIsSuccessor {
		receipt, err = classifySandboxActiveReadyDecommissionWithClient(ctx, client, targetID, authority.Fence,
			authority.DecommissionOwner, authority.Directory)
	} else {
		receipt, err = beginSandboxActiveReadyDecommissionWithClient(ctx, client, targetID, authority.Fence,
			authority.ReadyOwner, authority.Directory)
	}
	if err != nil {
		return nil, err
	}
	if authority.CurrentIsSuccessor && (authority.SuccessorTarget.LatchReceipt == nil ||
		*authority.SuccessorTarget.LatchReceipt != *receipt) {
		return nil, errors.New("journal successor latch receipt differs from the exact DDB owner authority")
	}
	return receipt, nil
}

// LatchSandboxJournaledActiveReadyPredecessorForRecovery changes only the
// selected journaled READY owner to DECOMMISSIONING. It accepts no caller fence.
func LatchSandboxJournaledActiveReadyPredecessorForRecovery(ctx context.Context, client *dynamodb.Client,
	targetID string, stateSnapshot, currentJournalSnapshot, referencedJournalSnapshot,
	currentReadySnapshot, referencedReadySnapshot SandboxRecoveryParameterSnapshot,
) (*SandboxActiveReadyLatchReceipt, error) {
	if client == nil {
		return nil, errors.New("invalid sandbox ACTIVE/READY latch client")
	}
	return latchSandboxJournaledActiveReadyWithClient(ctx, client, targetID, stateSnapshot,
		currentJournalSnapshot, referencedJournalSnapshot, currentReadySnapshot, referencedReadySnapshot)
}

func verifySandboxJournaledActiveReadyQuiescenceWithClient(ctx context.Context, client sessionControlDynamoAPI,
	targetID string, stateSnapshot, currentJournalSnapshot, referencedJournalSnapshot,
	currentReadySnapshot, referencedReadySnapshot SandboxRecoveryParameterSnapshot,
) (*SandboxActiveReadyQuiescenceReceipt, error) {
	authority, err := sandboxResolveJournaledActiveReadyAuthority(stateSnapshot, currentJournalSnapshot,
		referencedJournalSnapshot, currentReadySnapshot, referencedReadySnapshot, targetID, sandboxActiveReadyQuiescence)
	if err != nil {
		return nil, err
	}
	receipt, err := verifySandboxActiveReadyQuiescenceWithClient(ctx, client, targetID, authority.Fence,
		authority.DecommissionOwner, authority.Directory)
	if err != nil {
		return nil, err
	}
	if authority.CurrentIsSuccessor && (authority.SuccessorTarget.QuiescenceReceipt == nil ||
		*authority.SuccessorTarget.QuiescenceReceipt != *receipt) {
		return nil, errors.New("journal successor quiescence receipt differs from the exact DDB inventory")
	}
	return receipt, nil
}

// VerifySandboxJournaledActiveReadyPredecessorQuiescenceForRecovery requires
// physical zero OWNER tasks and reverse target-session rows after the latch.
func VerifySandboxJournaledActiveReadyPredecessorQuiescenceForRecovery(ctx context.Context, client *dynamodb.Client,
	targetID string, stateSnapshot, currentJournalSnapshot, referencedJournalSnapshot,
	currentReadySnapshot, referencedReadySnapshot SandboxRecoveryParameterSnapshot,
) (*SandboxActiveReadyQuiescenceReceipt, error) {
	if client == nil {
		return nil, errors.New("invalid sandbox ACTIVE/READY quiescence client")
	}
	return verifySandboxJournaledActiveReadyQuiescenceWithClient(ctx, client, targetID, stateSnapshot,
		currentJournalSnapshot, referencedJournalSnapshot, currentReadySnapshot, referencedReadySnapshot)
}

func sandboxActiveReadyAuthorityBeforeRetirement(journal sandboxActiveReadyRecoveryJournal,
	index int,
) (sessionControlAuthority, error) {
	if index < 0 || index >= sandboxActiveReadyPredecessorCount || len(journal.Targets) != sandboxActiveReadyPredecessorCount {
		return sessionControlAuthority{}, errors.New("invalid ACTIVE/READY retirement authority index")
	}
	updatedAt := int64(sandboxActiveReadyAuthorityUpdatedAtMillis)
	if index > 0 {
		previous := journal.Targets[index-1]
		if previous.Status != "retired" || previous.Receipt == nil {
			return sessionControlAuthority{}, errors.New("prior ACTIVE/READY retirement receipt is absent")
		}
		parsed, err := strconv.ParseInt(previous.Receipt.RetiredAtMillis, 10, 64)
		if err != nil || parsed <= 0 || strconv.FormatInt(parsed, 10) != previous.Receipt.RetiredAtMillis {
			return sessionControlAuthority{}, errors.New("prior ACTIVE/READY retirement timestamp is malformed")
		}
		updatedAt = parsed
	}
	return sessionControlAuthority{
		ACID: sandboxStaleTargetRetirementACID, ControlCellID: sandboxStaleTargetRetirementCellID,
		Version:           uint64(sandboxActiveReadyAuthorityVersion + index),
		ActiveTargetCount: uint64(sandboxActiveReadyPredecessorCount - index),
		CreatedAtMillis:   sandboxActiveReadyAuthorityCreatedAtMillis, UpdatedAtMillis: updatedAt,
	}, nil
}

func retireSandboxJournaledActiveReadyWithClient(ctx context.Context, client sessionControlDynamoAPI,
	targetID string, stateSnapshot, currentJournalSnapshot, referencedJournalSnapshot,
	currentReadySnapshot, referencedReadySnapshot SandboxRecoveryParameterSnapshot,
	nowUTC func() time.Time,
) (*SandboxStaleTargetRetirementReceipt, error) {
	if nowUTC == nil {
		return nil, errors.New("invalid sandbox ACTIVE/READY retirement clock")
	}
	authority, err := sandboxResolveJournaledActiveReadyAuthority(stateSnapshot, currentJournalSnapshot,
		referencedJournalSnapshot, currentReadySnapshot, referencedReadySnapshot, targetID, sandboxActiveReadyRetire)
	if err != nil {
		return nil, err
	}
	referenced, _, err := sandboxDecodeActiveReadyJournal(referencedReadySnapshot)
	if err != nil {
		return nil, err
	}
	expectedPreAuthority, err := sandboxActiveReadyAuthorityBeforeRetirement(referenced, authority.Index)
	if err != nil {
		return nil, err
	}
	store := &dynamoSessionControlStore{client: client, tableName: SandboxStaleTargetRetirementTable, nowUTC: nowUTC}
	current, err := store.getTarget(ctx, authority.Fence.key())
	if err != nil {
		return nil, err
	}
	var retired *sessionControlTargetAuthority
	if current.State == sessionControlTargetRetired {
		retired, err = store.classifyRetiredTarget(ctx, authority.Fence)
	} else if authority.CurrentIsSuccessor {
		return nil, errors.New("journal successor exists before the exact DDB retirement")
	} else {
		quiescence, verifyErr := verifySandboxActiveReadyQuiescenceWithClient(ctx, client, targetID,
			authority.Fence, authority.DecommissionOwner, authority.Directory)
		if verifyErr != nil {
			return nil, verifyErr
		}
		if referenced.Targets[authority.Index].QuiescenceReceipt == nil ||
			*referenced.Targets[authority.Index].QuiescenceReceipt != *quiescence {
			return nil, errors.New("live quiescence differs from the precommitted receipt")
		}
		directory, directoryErr := sandboxDirectoryFromRecoveryReceipt(authority.Directory, "0")
		if directoryErr != nil {
			return nil, directoryErr
		}
		if directory.Version != sandboxActiveReadyDirectoryVersion {
			return nil, errSessionControlFenceCorrupt
		}
		retired, err = store.retireDecommissioningTargetWithAuthority(ctx, authority.Fence, directory,
			expectedPreAuthority)
	}
	if err != nil || retired == nil || !sessionControlRetiredTargetMatchesFence(*retired, authority.Fence) {
		return nil, errSessionControlTargetConflict
	}
	retiredOwner, ownerErr := store.getOwner(ctx, authority.Fence.ControlCellID, authority.Fence.ACID,
		authority.Fence.PublicKey)
	expectedRetiredOwner, expectedOwnerErr := sessionControlOwnerFromTarget(*retired,
		&authority.DecommissionOwner, sessionControlOwnerRetired)
	currentAuthority, authorityErr := store.getAuthority(ctx, authority.Fence.ACID)
	expectedPostAuthority := expectedPreAuthority
	expectedPostAuthority.Version++
	expectedPostAuthority.ActiveTargetCount--
	expectedPostAuthority.UpdatedAtMillis = retired.RetiredAtMillis
	if ownerErr != nil || expectedOwnerErr != nil || *retiredOwner != expectedRetiredOwner ||
		authorityErr != nil || *currentAuthority != expectedPostAuthority {
		return nil, errSessionControlTargetConflict
	}
	receipt := &SandboxStaleTargetRetirementReceipt{
		Schema: SandboxStaleTargetRetirementReceiptSchema, TargetID: targetID, PublicKey: retired.PublicKey,
		Version: decimal(retired.Version), AuthorityVersion: decimal(retired.AuthorityVersion),
		CountedActiveSlot: retired.CountedActiveSlot, RetiredAtMillis: decimalMillis(retired.RetiredAtMillis),
		RetiredTargetSHA256: sandboxRetiredTargetDigest(*retired),
	}
	if authority.CurrentIsSuccessor && (authority.SuccessorTarget.Receipt == nil ||
		*authority.SuccessorTarget.Receipt != *receipt) {
		return nil, errors.New("journal successor retirement receipt differs from the exact DDB authority")
	}
	return receipt, nil
}

// RetireSandboxJournaledActiveReadyPredecessorForRecovery is the dedicated
// post-refresh DECOMMISSIONING retirement. The caller supplies only a plan ID.
func RetireSandboxJournaledActiveReadyPredecessorForRecovery(ctx context.Context, client *dynamodb.Client,
	targetID string, stateSnapshot, currentJournalSnapshot, referencedJournalSnapshot,
	currentReadySnapshot, referencedReadySnapshot SandboxRecoveryParameterSnapshot,
) (*SandboxStaleTargetRetirementReceipt, error) {
	if client == nil {
		return nil, errors.New("invalid sandbox ACTIVE/READY retirement client")
	}
	return retireSandboxJournaledActiveReadyWithClient(ctx, client, targetID, stateSnapshot,
		currentJournalSnapshot, referencedJournalSnapshot, currentReadySnapshot, referencedReadySnapshot,
		func() time.Time { return time.Now().UTC() })
}
