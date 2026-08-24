package server

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
)

const (
	SandboxStaleTargetRetirementPlanSchema     = "layerv.durable-aop-stale-target-retirement-plan.v1"
	SandboxStaleTargetRetirementReceiptSchema  = "layerv.durable-aop-stale-target-retirement-receipt.v1"
	SandboxStaleTargetPredecessorPlanSchema    = "layerv.durable-aop-predecessor-target-plan.v1"
	SandboxStaleTargetRetirementTable          = "layerv-nhp-sandbox-cell0-nhp-session-control"
	SandboxStaleTargetRetirementRegion         = "us-east-2"
	SandboxStaleTargetFenceDrainCellID         = "cell0"
	SandboxStaleTargetRecoveryStateParameter   = "/sandbox/nhp/cutovers/durable-aop-v1/state"
	SandboxStaleTargetRecoveryJournalParameter = "/sandbox/nhp/cutovers/durable-aop-v1/stale-target-retirement"

	sandboxStaleTargetRetirementACID   = "layerv-ac-tf"
	sandboxStaleTargetRetirementCellID = "cell0"
)

const (
	sandboxStaleTargetJournalEnvelopeSchema = "layerv.durable-aop-stale-target-journal-envelope.v1"
	sandboxStaleTargetJournalSchema         = "layerv.durable-aop-stale-target-retirement-journal.v1"
	sandboxStaleTargetRuntimeSourceSHA      = "f32335420d67fd235a6fb6598a1fc3d8eaf8dda7"
	sandboxStaleTargetRuntimeManifest       = "906c0461bf3d44175750b91ec9251de114da0c3646750287656803e3783d5ed0"
	sandboxStaleTargetRuntimeBuildRunID     = "32682520698"
	sandboxStaleTargetRuntimeBuildAttempt   = "1"
	sandboxStaleTargetRuntimeServerDigest   = "sha256:0921191723fd6a4919f22e0dded5775411bb08a682dc9d9f9a69fdcded7674c9"
	sandboxStaleTargetRuntimeACDigest       = "sha256:773bd37e915ac767f57e7656b5c038a8f2c70348901b1e81572584d6cfad566e"
	sandboxStaleTargetSourceStateVersion    = "22"
	sandboxStaleTargetSourceStateSHA256     = "b972283f4d37bfa6b2d672b531a6d87a5ab305e0973d5a24d5d19e75f45ef348"
	sandboxStaleTargetJournalDecodedLimit   = 64 * 1024
	sandboxRecoveryRepairSourceSHA          = "422b1d9acac53d50fe5602158fb02c8120ef108d"
	sandboxRecoveryServerDigest             = "sha256:d758d39bf760e44bcdba4e56d464ff98e7adc887ebe426a06a7ab9e261fccfcb"
	sandboxRecoveryACDigest                 = "sha256:16188f567aa0e169a70eed8e75c370ffda532e1d3bce0eec8f439be582d559fb"
)

const sandboxStaleTargetExpectedInitialFenceCount = 8

// SandboxFenceDirectoryRecoveryReceipt is a lossless, decimal-string snapshot
// of the strongly read CONTROL/DIRECTORY row. The controller persists the
// exact eight-fence starting authority before refreshing either server fleet,
// then requires a stable zero-fence successor before the first stale-target
// retirement transaction.
type SandboxFenceDirectoryRecoveryReceipt struct {
	Schema                                 string `json:"schema"`
	CellID                                 string `json:"cell_id"`
	Version                                string `json:"version"`
	ActiveFenceCount                       string `json:"active_fence_count"`
	AdmissionBlocked                       bool   `json:"admission_blocked"`
	OverflowCloseCount                     string `json:"overflow_close_count"`
	OverflowLeaderEventID                  string `json:"overflow_leader_event_id"`
	OverflowLeaderPreparedDirectoryVersion string `json:"overflow_leader_prepared_directory_version"`
	OverflowLeaderSelectedDirectoryVersion string `json:"overflow_leader_selected_directory_version"`
	CreatedAtMillis                        string `json:"created_at_ms"`
	UpdatedAtMillis                        string `json:"updated_at_ms"`
	DirectorySHA256                        string `json:"directory_sha256"`
}

const sandboxFenceDirectoryRecoveryReceiptSchema = "layerv.durable-aop-fence-directory-receipt.v1"

// SandboxStaleTargetFence is the immutable public recovery representation of
// one incident target fence. Decimal values are strings so JSON tooling cannot
// round a fence or timestamp before it reaches the exact store transaction.
type SandboxStaleTargetFence struct {
	ACID                    string `json:"ac_id"`
	PublicKey               string `json:"public_key"`
	BootID                  string `json:"boot_id"`
	FlushGeneration         string `json:"flush_generation"`
	Version                 string `json:"version"`
	AuthorityVersion        string `json:"authority_version"`
	CountedActiveSlot       bool   `json:"counted_active_slot"`
	ControlCellID           string `json:"control_cell_id"`
	ActivatedControlVersion string `json:"activated_control_version"`
	ReadyControlVersion     string `json:"ready_control_version"`
	AAKEnqueuedAtMillis     string `json:"aak_enqueued_at_ms"`
	AAKTransactionID        string `json:"aak_transaction_id"`
	CreatedAtMillis         string `json:"created_at_ms"`
	PreparedAtMillis        string `json:"prepared_at_ms"`
}

func snapshotSandboxPreparingPredecessors(ctx context.Context, client sessionControlDynamoAPI,
	tableName string,
) (SandboxStaleTargetRetirementPlan, error) {
	if ctx == nil || client == nil || tableName != SandboxStaleTargetRetirementTable {
		return SandboxStaleTargetRetirementPlan{}, errors.New("invalid sandbox predecessor snapshot authority")
	}
	store := &dynamoSessionControlStore{client: client, tableName: tableName, nowUTC: func() time.Time { return time.Now().UTC() }}
	read := func() (SandboxStaleTargetRetirementPlan, error) {
		targets, err := store.ListRequiredTargets(ctx, sandboxStaleTargetRetirementACID, sandboxStaleTargetRetirementCellID)
		if err != nil {
			return SandboxStaleTargetRetirementPlan{}, err
		}
		if len(targets) == 0 || len(targets) > MaxACConnsPerID {
			return SandboxStaleTargetRetirementPlan{}, errSessionControlTargetCorrupt
		}
		sort.Slice(targets, func(i, j int) bool { return targets[i].PublicKey < targets[j].PublicKey })
		out := make([]SandboxStaleTargetRetirementPlanTarget, len(targets))
		for index, target := range targets {
			if target.State != sessionControlTargetPreparing || !target.CountedActiveSlot ||
				target.ActivatedControlVersion != 0 || target.ReadyControlVersion != 0 ||
				target.AAKEnqueuedAtMillis != 0 || target.AAKTransactionID != 0 {
				return SandboxStaleTargetRetirementPlan{}, errSessionControlTargetConflict
			}
			owner, ownerErr := store.getOwner(ctx, target.ControlCellID, target.ACID, target.PublicKey)
			if ownerErr != nil {
				return SandboxStaleTargetRetirementPlan{}, ownerErr
			}
			if !owner.exactTarget(target, sessionControlOwnerPreparing) || owner.TaskCount != 0 || owner.PendingCount != 0 {
				return SandboxStaleTargetRetirementPlan{}, errSessionControlOwnerConflict
			}
			fence := target.fence()
			out[index] = SandboxStaleTargetRetirementPlanTarget{
				ID: fmt.Sprintf("predecessor-%d", index+1), Fence: sandboxStaleTargetPublicFence(fence),
				FenceSHA256: sandboxStaleTargetFenceDigest(fence),
			}
		}
		return SandboxStaleTargetRetirementPlan{
			Schema: SandboxStaleTargetPredecessorPlanSchema, Table: tableName,
			Region: SandboxStaleTargetRetirementRegion, ACID: sandboxStaleTargetRetirementACID,
			ControlCellID: sandboxStaleTargetRetirementCellID, Targets: out,
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
	if len(before.Targets) != len(after.Targets) {
		return SandboxStaleTargetRetirementPlan{}, errSessionControlTargetConflict
	}
	for index := range before.Targets {
		if before.Targets[index] != after.Targets[index] {
			return SandboxStaleTargetRetirementPlan{}, errSessionControlTargetConflict
		}
	}
	return after, nil
}

// SnapshotSandboxPreparingPredecessorsForRecovery strongly double-reads the
// bounded counted-target inventory plus exact pending0 owners. It is exposed
// only to the incident command so schema 3 can precommit every predecessor
// fence before starting the replacement AC refresh.
func SnapshotSandboxPreparingPredecessorsForRecovery(ctx context.Context, client *dynamodb.Client,
	tableName string,
) (SandboxStaleTargetRetirementPlan, error) {
	if client == nil {
		return SandboxStaleTargetRetirementPlan{}, errors.New("invalid sandbox predecessor snapshot client")
	}
	return snapshotSandboxPreparingPredecessors(ctx, client, tableName)
}

func sandboxStaleTargetFenceFromPublic(value SandboxStaleTargetFence) (sessionControlTargetFence, error) {
	parseUint := func(name, raw string) (uint64, error) {
		parsed, err := strconv.ParseUint(raw, 10, 64)
		if err != nil || strconv.FormatUint(parsed, 10) != raw {
			return 0, fmt.Errorf("invalid %s", name)
		}
		return parsed, nil
	}
	parseMillis := func(name, raw string) (int64, error) {
		parsed, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || strconv.FormatInt(parsed, 10) != raw {
			return 0, fmt.Errorf("invalid %s", name)
		}
		return parsed, nil
	}
	flush, err := parseUint("flush generation", value.FlushGeneration)
	if err != nil {
		return sessionControlTargetFence{}, err
	}
	version, err := parseUint("version", value.Version)
	if err != nil {
		return sessionControlTargetFence{}, err
	}
	authorityVersion, err := parseUint("authority version", value.AuthorityVersion)
	if err != nil {
		return sessionControlTargetFence{}, err
	}
	activated, err := parseUint("activated control version", value.ActivatedControlVersion)
	if err != nil {
		return sessionControlTargetFence{}, err
	}
	ready, err := parseUint("ready control version", value.ReadyControlVersion)
	if err != nil {
		return sessionControlTargetFence{}, err
	}
	aakMillis, err := parseMillis("AAK timestamp", value.AAKEnqueuedAtMillis)
	if err != nil {
		return sessionControlTargetFence{}, err
	}
	aakTransaction, err := parseUint("AAK transaction", value.AAKTransactionID)
	if err != nil {
		return sessionControlTargetFence{}, err
	}
	created, err := parseMillis("created timestamp", value.CreatedAtMillis)
	if err != nil {
		return sessionControlTargetFence{}, err
	}
	prepared, err := parseMillis("prepared timestamp", value.PreparedAtMillis)
	if err != nil {
		return sessionControlTargetFence{}, err
	}
	fence := sessionControlTargetFence{
		ACID: value.ACID, PublicKey: value.PublicKey, BootID: value.BootID,
		FlushGeneration: flush, Version: version, AuthorityVersion: authorityVersion,
		CountedActiveSlot: value.CountedActiveSlot, ControlCellID: value.ControlCellID,
		ActivatedControlVersion: activated, ReadyControlVersion: ready,
		AAKEnqueuedAtMillis: aakMillis, AAKTransactionID: aakTransaction,
		CreatedAtMillis: created, PreparedAtMillis: prepared,
	}
	if !validSessionControlTargetFence(fence) || fence.ACID != sandboxStaleTargetRetirementACID ||
		fence.ControlCellID != sandboxStaleTargetRetirementCellID || !fence.CountedActiveSlot ||
		fence.ActivatedControlVersion != 0 || fence.ReadyControlVersion != 0 ||
		fence.AAKEnqueuedAtMillis != 0 || fence.AAKTransactionID != 0 {
		return sessionControlTargetFence{}, errors.New("predecessor fence is not an exact counted PREPARING authority")
	}
	return fence, nil
}

type SandboxStaleTargetRetirementPlanTarget struct {
	ID          string                  `json:"id"`
	Fence       SandboxStaleTargetFence `json:"fence"`
	FenceSHA256 string                  `json:"fence_sha256"`
}

type SandboxStaleTargetRetirementPlan struct {
	Schema        string                                   `json:"schema"`
	Table         string                                   `json:"table"`
	Region        string                                   `json:"region"`
	ACID          string                                   `json:"ac_id"`
	ControlCellID string                                   `json:"control_cell_id"`
	Targets       []SandboxStaleTargetRetirementPlanTarget `json:"targets"`
}

type SandboxStaleTargetRetirementReceipt struct {
	Schema              string `json:"schema"`
	TargetID            string `json:"target_id"`
	PublicKey           string `json:"public_key"`
	Version             string `json:"version"`
	AuthorityVersion    string `json:"authority_version"`
	CountedActiveSlot   bool   `json:"counted_active_slot"`
	RetiredAtMillis     string `json:"retired_at_ms"`
	RetiredTargetSHA256 string `json:"retired_target_sha256"`
}

var sandboxStaleTargetRetirementFences = []struct {
	id    string
	fence sessionControlTargetFence
}{
	{
		id: "stale-ac-target-1",
		fence: sessionControlTargetFence{
			ACID: sandboxStaleTargetRetirementACID, PublicKey: "Y+o42/xowFCAAADhthQNa8PLhHAghhGJT7b08kN4SXk=",
			BootID: "77814aa28f9cd61e09d121d8b313396a", FlushGeneration: 3,
			Version: 607, AuthorityVersion: 4, CountedActiveSlot: true,
			ControlCellID:   sandboxStaleTargetRetirementCellID,
			CreatedAtMillis: 1787485643707, PreparedAtMillis: 1787487069703,
		},
	},
	{
		id: "stale-ac-target-2",
		fence: sessionControlTargetFence{
			ACID: sandboxStaleTargetRetirementACID, PublicKey: "YvLUFK5dhFH2Gjc51j0z7OfDLZhmWlNDEHcR+SK04Dc=",
			BootID: "bd73eadee25bb33be0b3825033107850", FlushGeneration: 9,
			Version: 533, AuthorityVersion: 4, CountedActiveSlot: true,
			ControlCellID:   sandboxStaleTargetRetirementCellID,
			CreatedAtMillis: 1787485637722, PreparedAtMillis: 1787487069740,
		},
	},
	{
		id: "stale-ac-target-3",
		fence: sessionControlTargetFence{
			ACID: sandboxStaleTargetRetirementACID, PublicKey: "mTt4xLsjleUYgVvihpoIHbIyDlWURZYqqsz1Eh7CmRM=",
			BootID: "1406ba3c94ae49866d59eb198a919c88", FlushGeneration: 3,
			Version: 545, AuthorityVersion: 4, CountedActiveSlot: true,
			ControlCellID:   sandboxStaleTargetRetirementCellID,
			CreatedAtMillis: 1787485881723, PreparedAtMillis: 1787487086631,
		},
	},
}

func decimal(value uint64) string { return strconv.FormatUint(value, 10) }

func decimalMillis(value int64) string { return strconv.FormatInt(value, 10) }

func sandboxStaleTargetPublicFence(fence sessionControlTargetFence) SandboxStaleTargetFence {
	return SandboxStaleTargetFence{
		ACID: fence.ACID, PublicKey: fence.PublicKey, BootID: fence.BootID,
		FlushGeneration: decimal(fence.FlushGeneration), Version: decimal(fence.Version),
		AuthorityVersion: decimal(fence.AuthorityVersion), CountedActiveSlot: fence.CountedActiveSlot,
		ControlCellID:           fence.ControlCellID,
		ActivatedControlVersion: decimal(fence.ActivatedControlVersion), ReadyControlVersion: decimal(fence.ReadyControlVersion),
		AAKEnqueuedAtMillis: decimalMillis(fence.AAKEnqueuedAtMillis), AAKTransactionID: decimal(fence.AAKTransactionID),
		CreatedAtMillis: decimalMillis(fence.CreatedAtMillis), PreparedAtMillis: decimalMillis(fence.PreparedAtMillis),
	}
}

func sandboxStaleTargetFenceDigest(fence sessionControlTargetFence) string {
	hasher := sha256.New()
	for _, part := range []any{
		"v1", fence.ACID, fence.PublicKey, fence.BootID, fence.FlushGeneration,
		fence.Version, fence.AuthorityVersion, fence.CountedActiveSlot, fence.ControlCellID,
		fence.ActivatedControlVersion, fence.ReadyControlVersion, fence.AAKEnqueuedAtMillis,
		fence.AAKTransactionID, fence.CreatedAtMillis, fence.PreparedAtMillis,
	} {
		_, _ = fmt.Fprintf(hasher, "\x00%v", part)
	}
	return hex.EncodeToString(hasher.Sum(nil))
}

func sandboxFenceDirectoryDigest(directory sessionControlFenceDirectory) string {
	hasher := sha256.New()
	for _, part := range []any{
		"v1", directory.CellID, directory.Version, directory.ActiveFenceCount,
		directory.AdmissionBlocked, directory.OverflowCloseCount, directory.OverflowLeaderEventID,
		directory.OverflowLeaderPreparedDirectoryVersion, directory.OverflowLeaderSelectedDirectoryVersion,
		directory.CreatedAtMillis, directory.UpdatedAtMillis,
	} {
		_, _ = fmt.Fprintf(hasher, "\x00%v", part)
	}
	return hex.EncodeToString(hasher.Sum(nil))
}

func sandboxFenceDirectoryReceipt(directory sessionControlFenceDirectory) SandboxFenceDirectoryRecoveryReceipt {
	return SandboxFenceDirectoryRecoveryReceipt{
		Schema: sandboxFenceDirectoryRecoveryReceiptSchema, CellID: directory.CellID,
		Version: decimal(directory.Version), ActiveFenceCount: decimal(directory.ActiveFenceCount),
		AdmissionBlocked: directory.AdmissionBlocked, OverflowCloseCount: decimal(directory.OverflowCloseCount),
		OverflowLeaderEventID:                  directory.OverflowLeaderEventID,
		OverflowLeaderPreparedDirectoryVersion: decimal(directory.OverflowLeaderPreparedDirectoryVersion),
		OverflowLeaderSelectedDirectoryVersion: decimal(directory.OverflowLeaderSelectedDirectoryVersion),
		CreatedAtMillis:                        decimalMillis(directory.CreatedAtMillis), UpdatedAtMillis: decimalMillis(directory.UpdatedAtMillis),
		DirectorySHA256: sandboxFenceDirectoryDigest(directory),
	}
}

func snapshotSandboxFenceDirectoryForRecovery(ctx context.Context, client sessionControlDynamoAPI,
	tableName, cellID string, requireDrained bool,
) (*SandboxFenceDirectoryRecoveryReceipt, error) {
	if ctx == nil || client == nil || tableName != SandboxStaleTargetRetirementTable ||
		cellID != SandboxStaleTargetFenceDrainCellID {
		return nil, errors.New("invalid sandbox fence-directory recovery authority")
	}
	store := &dynamoSessionControlStore{client: client, tableName: tableName, nowUTC: func() time.Time { return time.Now().UTC() }}
	first, err := store.getFenceDirectory(ctx, cellID)
	if err != nil {
		return nil, err
	}
	second, err := store.getFenceDirectory(ctx, cellID)
	if err != nil {
		return nil, err
	}
	if *first != *second {
		return nil, errSessionControlFenceConflict
	}
	if requireDrained {
		if second.ActiveFenceCount != 0 || second.AdmissionBlocked || second.OverflowCloseCount != 0 ||
			second.OverflowLeaderEventID != "" || second.OverflowLeaderPreparedDirectoryVersion != 0 ||
			second.OverflowLeaderSelectedDirectoryVersion != 0 {
			return nil, errSessionControlFenceConflict
		}
	} else if second.ActiveFenceCount != sandboxStaleTargetExpectedInitialFenceCount {
		return nil, errSessionControlFenceConflict
	}
	receipt := sandboxFenceDirectoryReceipt(*second)
	return &receipt, nil
}

// SnapshotSandboxFenceDirectoryForRecovery pins the incident's stable
// eight-fence starting authority. It performs no write and is unavailable on
// the ordinary session-control store interface.
func SnapshotSandboxFenceDirectoryForRecovery(ctx context.Context, client *dynamodb.Client,
	tableName, cellID string,
) (*SandboxFenceDirectoryRecoveryReceipt, error) {
	if client == nil {
		return nil, errors.New("invalid sandbox fence-directory snapshot client")
	}
	return snapshotSandboxFenceDirectoryForRecovery(ctx, client, tableName, cellID, false)
}

// VerifySandboxFenceDirectoryDrainedForRecovery requires a stable, fully open
// zero-fence directory. The controller invokes it once per recovery attempt;
// an incomplete drain fails immediately and retains the hard lock and journal.
func VerifySandboxFenceDirectoryDrainedForRecovery(ctx context.Context, client *dynamodb.Client,
	tableName, cellID string,
) (*SandboxFenceDirectoryRecoveryReceipt, error) {
	if client == nil {
		return nil, errors.New("invalid sandbox fence-directory verification client")
	}
	return snapshotSandboxFenceDirectoryForRecovery(ctx, client, tableName, cellID, true)
}

// SandboxStaleTargetRetirementPlanForIncident returns the only target set the
// recovery command can retire. The ordinary UdpServer store interface remains
// unable to invoke permanent target retirement.
func SandboxStaleTargetRetirementPlanForIncident() SandboxStaleTargetRetirementPlan {
	targets := make([]SandboxStaleTargetRetirementPlanTarget, len(sandboxStaleTargetRetirementFences))
	for index, target := range sandboxStaleTargetRetirementFences {
		targets[index] = SandboxStaleTargetRetirementPlanTarget{
			ID: target.id, Fence: sandboxStaleTargetPublicFence(target.fence),
			FenceSHA256: sandboxStaleTargetFenceDigest(target.fence),
		}
	}
	return SandboxStaleTargetRetirementPlan{
		Schema: SandboxStaleTargetRetirementPlanSchema, Table: SandboxStaleTargetRetirementTable,
		Region: SandboxStaleTargetRetirementRegion, ACID: sandboxStaleTargetRetirementACID,
		ControlCellID: sandboxStaleTargetRetirementCellID, Targets: targets,
	}
}

func sandboxStaleTargetFenceByID(targetID string) (sessionControlTargetFence, error) {
	for _, target := range sandboxStaleTargetRetirementFences {
		if target.id == targetID {
			return target.fence, nil
		}
	}
	return sessionControlTargetFence{}, errors.New("stale session-control target is not in the exact incident plan")
}

func sandboxRetiredTargetDigest(target sessionControlTargetAuthority) string {
	hasher := sha256.New()
	for _, part := range []any{
		"v1", target.ACID, target.PublicKey, target.BootID, target.FlushGeneration,
		target.State, target.Version, target.AuthorityVersion, target.CountedActiveSlot,
		target.ControlCellID, target.ActivatedControlVersion, target.ReadyControlVersion,
		target.AAKEnqueuedAtMillis, target.AAKTransactionID, target.CreatedAtMillis,
		target.PreparedAtMillis, target.UpdatedAtMillis, target.RetiredAtMillis,
	} {
		_, _ = fmt.Fprintf(hasher, "\x00%v", part)
	}
	return hex.EncodeToString(hasher.Sum(nil))
}

func retireSandboxStaleTargetWithClient(ctx context.Context, client sessionControlDynamoAPI,
	tableName, targetID string, nowUTC func() time.Time,
) (*SandboxStaleTargetRetirementReceipt, error) {
	if ctx == nil || client == nil || tableName != SandboxStaleTargetRetirementTable || nowUTC == nil {
		return nil, errors.New("invalid sandbox stale-target retirement authority")
	}
	fence, err := sandboxStaleTargetFenceByID(targetID)
	if err != nil {
		return nil, err
	}
	store := &dynamoSessionControlStore{client: client, tableName: tableName, nowUTC: nowUTC}
	retired, err := store.retireTarget(ctx, fence)
	if err != nil {
		return nil, err
	}
	if retired == nil || !sessionControlRetiredTargetMatchesFence(*retired, fence) {
		return nil, errSessionControlTargetCorrupt
	}
	return &SandboxStaleTargetRetirementReceipt{
		Schema: SandboxStaleTargetRetirementReceiptSchema, TargetID: targetID,
		PublicKey: retired.PublicKey, Version: decimal(retired.Version),
		AuthorityVersion: decimal(retired.AuthorityVersion), CountedActiveSlot: retired.CountedActiveSlot,
		RetiredAtMillis: decimalMillis(retired.RetiredAtMillis), RetiredTargetSHA256: sandboxRetiredTargetDigest(*retired),
	}, nil
}

// RetireSandboxStaleTargetForIncident is the recovery command's only write
// capability. It accepts an exact compile-time incident target ID, not a
// caller-provided target fence or arbitrary table.
func RetireSandboxStaleTargetForIncident(ctx context.Context, client *dynamodb.Client,
	tableName, targetID string,
) (*SandboxStaleTargetRetirementReceipt, error) {
	if client == nil {
		return nil, errors.New("invalid sandbox stale-target retirement client")
	}
	return retireSandboxStaleTargetWithClient(ctx, client, tableName, targetID, func() time.Time { return time.Now().UTC() })
}

// SandboxRecoveryParameterSnapshot is one exact SSM parameter value and its
// service version. The incident command obtains these snapshots from the fixed
// state and journal parameter names; no command-line value can supply them.
type SandboxRecoveryParameterSnapshot struct {
	Value   string
	Version int64
}

type sandboxStaleTargetJournalRef struct {
	Parameter string `json:"parameter"`
	SHA256    string `json:"sha256"`
	Version   int64  `json:"version"`
}

type sandboxStaleTargetRecoveryOwner struct {
	Intent map[string]any `json:"intent"`
	Status string         `json:"status"`
}

type sandboxStaleTargetRecoveryRepair struct {
	ACAttestation            string                          `json:"ac_attestation"`
	ACProvenance             string                          `json:"ac_provenance"`
	ACRefreshID              string                          `json:"ac_refresh_id"`
	BuildRunAttempt          string                          `json:"build_run_attempt"`
	BuildRunID               string                          `json:"build_run_id"`
	Cell0Attestation         string                          `json:"cell0_attestation"`
	Cell0RefreshID           string                          `json:"cell0_refresh_id"`
	Cell1Attestation         string                          `json:"cell1_attestation"`
	Cell1RefreshID           string                          `json:"cell1_refresh_id"`
	ConnectorLifecycle       string                          `json:"connector_lifecycle"`
	CustomerLifecycle        string                          `json:"customer_lifecycle"`
	OrchestratorSHA          string                          `json:"orchestrator_sha"`
	Owner                    sandboxStaleTargetRecoveryOwner `json:"owner"`
	RuntimeManifest          string                          `json:"runtime_manifest"`
	ServerProvenance         string                          `json:"server_provenance"`
	SourceSHA                string                          `json:"source_sha"`
	StaleTargetRetirementRef sandboxStaleTargetJournalRef    `json:"stale_target_retirement_ref"`
}

type sandboxStaleTargetRecoveryOriginalLock struct {
	CreatedAt       int64  `json:"created_at"`
	ExpiresAt       int64  `json:"expires_at"`
	Image           string `json:"image"`
	Kind            string `json:"kind"`
	OrchestratorSHA string `json:"orchestrator_sha"`
	Owner           string `json:"owner"`
	Schema          int    `json:"schema"`
}

type sandboxStaleTargetRecoveryOriginal struct {
	Lock         sandboxStaleTargetRecoveryOriginalLock `json:"lock"`
	LockSHA256   string                                 `json:"lock_sha256"`
	LockVersion  int64                                  `json:"lock_version"`
	StateSHA256  string                                 `json:"state_sha256"`
	StateVersion int64                                  `json:"state_version"`
}

type sandboxStaleTargetRecoveryState struct {
	Original sandboxStaleTargetRecoveryOriginal `json:"original"`
	Phase    string                             `json:"phase"`
	Repair   sandboxStaleTargetRecoveryRepair   `json:"repair"`
	Schema   int                                `json:"schema"`
}

type sandboxStaleTargetJournalEnvelope struct {
	Encoding string `json:"encoding"`
	Payload  string `json:"payload"`
	Schema   string `json:"schema"`
}

type sandboxStaleTargetRefreshPreferences struct {
	InstanceWarmup       int  `json:"InstanceWarmup"`
	MaxHealthyPercentage int  `json:"MaxHealthyPercentage"`
	MinHealthyPercentage int  `json:"MinHealthyPercentage"`
	SkipMatching         bool `json:"SkipMatching"`
}

type sandboxStaleTargetRuntimeComponent struct {
	ASG            string `json:"asg"`
	Attestation    string `json:"attestation"`
	IntentSHA256   string `json:"intent_sha256"`
	PriorRefreshID string `json:"prior_refresh_id"`
	RefreshID      string `json:"refresh_id"`
}

type sandboxStaleTargetJournalTarget struct {
	FenceSHA256 string                               `json:"fence_sha256"`
	ID          string                               `json:"id"`
	Receipt     *SandboxStaleTargetRetirementReceipt `json:"receipt,omitempty"`
	Status      string                               `json:"status"`
}

type sandboxStaleTargetJournalRuntime struct {
	AC                    sandboxStaleTargetRuntimeComponent   `json:"ac"`
	ACProvenance          string                               `json:"ac_provenance"`
	BuildRunAttempt       string                               `json:"build_run_attempt"`
	BuildRunID            string                               `json:"build_run_id"`
	Cell0                 sandboxStaleTargetRuntimeComponent   `json:"cell0"`
	Cell1                 sandboxStaleTargetRuntimeComponent   `json:"cell1"`
	FenceDrain            SandboxFenceDirectoryRecoveryReceipt `json:"fence_drain"`
	FenceStart            SandboxFenceDirectoryRecoveryReceipt `json:"fence_start"`
	PredecessorPlan       SandboxStaleTargetRetirementPlan     `json:"predecessor_plan"`
	PredecessorPlanSHA256 string                               `json:"predecessor_plan_sha256"`
	PredecessorTargets    []sandboxStaleTargetJournalTarget    `json:"predecessor_targets"`
	Preferences           sandboxStaleTargetRefreshPreferences `json:"preferences"`
	RuntimeManifest       string                               `json:"runtime_manifest"`
	ServerProvenance      string                               `json:"server_provenance"`
	SourceSHA             string                               `json:"source_sha"`
}

type sandboxStaleTargetJournal struct {
	IncidentPlan       SandboxStaleTargetRetirementPlan  `json:"incident_plan"`
	IncidentPlanSHA256 string                            `json:"incident_plan_sha256"`
	IncidentTargets    []sandboxStaleTargetJournalTarget `json:"incident_targets"`
	Runtime            sandboxStaleTargetJournalRuntime  `json:"runtime"`
	Schema             string                            `json:"schema"`
	SourceStateSHA256  string                            `json:"source_state_sha256"`
	SourceStateVersion string                            `json:"source_state_version"`
	Status             string                            `json:"status"`
}

func sandboxCanonicalJSON(raw string, output any) (map[string]any, error) {
	if raw == "" || len(raw) >= sandboxStaleTargetJournalDecodedLimit {
		return nil, errors.New("recovery authority is empty or exceeds its bound")
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.UseNumber()
	var generic any
	if err := decoder.Decode(&generic); err != nil {
		return nil, err
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return nil, errors.New("recovery authority contains more than one JSON value")
	}
	object, ok := generic.(map[string]any)
	if !ok {
		return nil, errors.New("recovery authority is not an object")
	}
	canonical, err := json.Marshal(generic)
	if err != nil || string(canonical) != raw {
		return nil, errors.New("recovery authority is not canonical JSON")
	}
	closed := json.NewDecoder(strings.NewReader(raw))
	closed.DisallowUnknownFields()
	if err := closed.Decode(output); err != nil {
		return nil, err
	}
	if closed.Decode(&extra) != io.EOF {
		return nil, errors.New("recovery authority is not one closed JSON value")
	}
	return object, nil
}

func sandboxExactObjectKeys(value any, expected ...string) bool {
	object, ok := value.(map[string]any)
	if !ok || len(object) != len(expected) {
		return false
	}
	for _, key := range expected {
		if _, present := object[key]; !present {
			return false
		}
	}
	return true
}

func sandboxExactHex(raw string, bytesCount int) bool {
	decoded, err := hex.DecodeString(raw)
	return err == nil && len(decoded) == bytesCount && hex.EncodeToString(decoded) == raw
}

func sandboxCanonicalDigest(raw string) string {
	digest := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(digest[:])
}

func sandboxCanonicalValue(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var generic any
	if err := decoder.Decode(&generic); err != nil {
		return "", err
	}
	canonical, err := json.Marshal(generic)
	if err != nil {
		return "", err
	}
	return string(canonical), nil
}

func sandboxValidateRecoveryState(snapshot SandboxRecoveryParameterSnapshot) (sandboxStaleTargetRecoveryState, error) {
	var state sandboxStaleTargetRecoveryState
	root, err := sandboxCanonicalJSON(snapshot.Value, &state)
	if err != nil || snapshot.Version <= 0 || !sandboxExactObjectKeys(root, "original", "phase", "repair", "schema") {
		return state, errors.New("schema-3 recovery state is malformed")
	}
	original := root["original"]
	repair := root["repair"]
	repairObject, ok := repair.(map[string]any)
	if !ok {
		return state, errors.New("schema-3 recovery repair authority is malformed")
	}
	owner, _ := repairObject["owner"].(map[string]any)
	ownerIntent, _ := owner["intent"].(map[string]any)
	expectedServerProvenance := "v1|" + sandboxRecoveryRepairSourceSHA + "|layerv/nhp-server|" + sandboxRecoveryServerDigest
	expectedACProvenance := "v1|" + sandboxRecoveryRepairSourceSHA + "|layerv/nhp-ac|" + sandboxRecoveryACDigest
	if state.Schema != 3 || state.Phase != "repaired" ||
		!sandboxExactObjectKeys(original, "lock", "lock_sha256", "lock_version", "state_sha256", "state_version") ||
		!sandboxExactObjectKeys(repair, "ac_attestation", "ac_provenance", "ac_refresh_id", "build_run_attempt",
			"build_run_id", "cell0_attestation", "cell0_refresh_id", "cell1_attestation", "cell1_refresh_id",
			"connector_lifecycle", "customer_lifecycle", "orchestrator_sha", "owner", "runtime_manifest",
			"server_provenance", "source_sha", "stale_target_retirement_ref") ||
		!sandboxExactObjectKeys(owner, "intent", "status") || state.Repair.Owner.Status != "ready" ||
		!sandboxExactObjectKeys(ownerIntent, "action", "before_row_sha256", "client_id", "email",
			"expected_assigned_cell_id", "expected_created_at", "expected_row_sha256", "expected_updated_at",
			"expected_usage", "provisioned_at", "region", "schema", "source_sha", "subject", "table") ||
		state.Repair.SourceSHA != sandboxRecoveryRepairSourceSHA || state.Repair.BuildRunID != "32656742290" ||
		state.Repair.BuildRunAttempt != "1" || state.Repair.RuntimeManifest != "2895963905453d61874858171529968efe8e18e5450d41842854fd2784d1ec78" ||
		state.Repair.ServerProvenance != expectedServerProvenance || state.Repair.ACProvenance != expectedACProvenance ||
		state.Repair.Cell0Attestation != "v2|durable-aop-v1|"+sandboxRecoveryRepairSourceSHA+"|layerv/nhp-server|"+sandboxRecoveryServerDigest+"|layerv-nhp-sandbox-server" ||
		state.Repair.Cell1Attestation != "v2|durable-aop-v1|"+sandboxRecoveryRepairSourceSHA+"|layerv/nhp-server|"+sandboxRecoveryServerDigest+"|layerv-nhp-sandbox-cell1-server-green" ||
		state.Repair.ACAttestation != "v2|durable-aop-v1|"+sandboxRecoveryRepairSourceSHA+"|layerv/nhp-ac|"+sandboxRecoveryACDigest+"|layerv-nhp-sandbox-ac-green" ||
		state.Repair.Cell0RefreshID != "ea9dae3d-22f8-478e-a9ec-91eb9b9f53fb" ||
		state.Repair.Cell1RefreshID != "dc5ab358-ef4e-45a8-bf81-d18112a2ce9c" ||
		state.Repair.ACRefreshID != "b58f804d-6ed2-4f15-90df-749e2e0f93fb" ||
		state.Repair.CustomerLifecycle != "" || state.Repair.ConnectorLifecycle != "" ||
		state.Repair.Owner.Intent["schema"] != "layerv.durable-aop-customer-owner-intent.v1" ||
		state.Repair.Owner.Intent["action"] != "create" || state.Repair.Owner.Intent["before_row_sha256"] != "absent" ||
		state.Repair.Owner.Intent["client_id"] != "oScYkXhLitBPO6gBjxo4Rwyw37AdoNPy" ||
		state.Repair.Owner.Intent["subject"] != "oScYkXhLitBPO6gBjxo4Rwyw37AdoNPy@clients" ||
		state.Repair.Owner.Intent["email"] != "oscykxhlitbpo6gbjxo4rwyw37adonpy-clients@machine.notify.layerv.xyz" ||
		state.Repair.Owner.Intent["table"] != "layerv-nhp-sandbox-control-qurl-customers" ||
		state.Repair.Owner.Intent["region"] != SandboxStaleTargetRetirementRegion ||
		state.Repair.Owner.Intent["source_sha"] != sandboxRecoveryRepairSourceSHA ||
		state.Repair.Owner.Intent["provisioned_at"] != "2026-08-24T00:38:03Z" ||
		state.Repair.Owner.Intent["expected_row_sha256"] != "cac7d0380fc97736575d2701ef0ccc08927b511cd8646c83785c1be8b30f1b8b" ||
		state.Repair.Owner.Intent["expected_created_at"] != "2026-08-24T00:38:03Z" ||
		state.Repair.Owner.Intent["expected_updated_at"] != "2026-08-24T00:38:03Z" ||
		state.Repair.Owner.Intent["expected_usage"] != "0" || state.Repair.Owner.Intent["expected_assigned_cell_id"] != "" ||
		state.Original.StateVersion != 7 || state.Original.LockVersion != 2 ||
		state.Original.StateSHA256 != "e7ed20adde2ce9e143c9505027a73e415e5dd3d4a9d0c950c912d6398cc5d13e" ||
		state.Original.LockSHA256 != "6c7224d78837a4d56547409439d9bce30efa9b214367c4f19fd13cc3fe3b2ebd" ||
		state.Original.Lock.Schema != 1 || state.Original.Lock.Kind != "durable-aop-cutover-recovery" ||
		state.Original.Lock.Image != "e9b11398a4cea98da6ae5b41cfe635562e1b7c72" ||
		state.Original.Lock.OrchestratorSHA != "e9b11398a4cea98da6ae5b41cfe635562e1b7c72" ||
		state.Original.Lock.Owner != "nhp:32635672597:durable-aop-cutover:e9b11398a4cea98da6ae5b41cfe635562e1b7c72" ||
		state.Original.Lock.CreatedAt != 1787485146 || state.Original.Lock.ExpiresAt != 253402300799 ||
		!sandboxExactHex(state.Repair.OrchestratorSHA, 20) {
		return state, errors.New("schema-3 recovery state is not the exact incident authority")
	}
	return state, nil
}

func sandboxStaleTargetPlanObjectIsClosed(value any) bool {
	object, ok := value.(map[string]any)
	if !ok || !sandboxExactObjectKeys(object, "ac_id", "control_cell_id", "region", "schema", "table", "targets") {
		return false
	}
	targets, ok := object["targets"].([]any)
	if !ok || len(targets) == 0 || len(targets) > 3 {
		return false
	}
	for _, rawTarget := range targets {
		target, ok := rawTarget.(map[string]any)
		if !ok || !sandboxExactObjectKeys(target, "fence", "fence_sha256", "id") ||
			!sandboxExactObjectKeys(target["fence"], "aak_enqueued_at_ms", "aak_transaction_id", "ac_id",
				"activated_control_version", "authority_version", "boot_id", "control_cell_id", "counted_active_slot",
				"created_at_ms", "flush_generation", "prepared_at_ms", "public_key", "ready_control_version", "version") {
			return false
		}
	}
	return true
}

func sandboxStaleTargetLedgerObjectIsClosed(value any) bool {
	targets, ok := value.([]any)
	if !ok || len(targets) == 0 || len(targets) > 3 {
		return false
	}
	for _, rawTarget := range targets {
		target, ok := rawTarget.(map[string]any)
		if !ok {
			return false
		}
		status, _ := target["status"].(string)
		if status == "pending" {
			if !sandboxExactObjectKeys(target, "fence_sha256", "id", "status") {
				return false
			}
			continue
		}
		if status != "retired" || !sandboxExactObjectKeys(target, "fence_sha256", "id", "receipt", "status") ||
			!sandboxExactObjectKeys(target["receipt"], "authority_version", "counted_active_slot", "public_key",
				"retired_at_ms", "retired_target_sha256", "schema", "target_id", "version") {
			return false
		}
	}
	return true
}

func sandboxStaleTargetJournalObjectIsClosed(root map[string]any) bool {
	runtime, ok := root["runtime"].(map[string]any)
	if !ok || !sandboxExactObjectKeys(runtime, "ac", "ac_provenance", "build_run_attempt", "build_run_id",
		"cell0", "cell1", "fence_drain", "fence_start", "predecessor_plan", "predecessor_plan_sha256",
		"predecessor_targets", "preferences", "runtime_manifest", "server_provenance", "source_sha") ||
		!sandboxStaleTargetPlanObjectIsClosed(root["incident_plan"]) ||
		!sandboxStaleTargetLedgerObjectIsClosed(root["incident_targets"]) ||
		!sandboxStaleTargetPlanObjectIsClosed(runtime["predecessor_plan"]) ||
		!sandboxStaleTargetLedgerObjectIsClosed(runtime["predecessor_targets"]) ||
		!sandboxExactObjectKeys(runtime["preferences"], "InstanceWarmup", "MaxHealthyPercentage",
			"MinHealthyPercentage", "SkipMatching") {
		return false
	}
	for _, key := range []string{"cell0", "cell1", "ac"} {
		if !sandboxExactObjectKeys(runtime[key], "asg", "attestation", "intent_sha256", "prior_refresh_id", "refresh_id") {
			return false
		}
	}
	for _, key := range []string{"fence_start", "fence_drain"} {
		if !sandboxExactObjectKeys(runtime[key], "active_fence_count", "admission_blocked", "cell_id", "created_at_ms",
			"directory_sha256", "overflow_close_count", "overflow_leader_event_id",
			"overflow_leader_prepared_directory_version", "overflow_leader_selected_directory_version",
			"schema", "updated_at_ms", "version") {
			return false
		}
	}
	return true
}

func sandboxDecodeStaleTargetJournal(snapshot SandboxRecoveryParameterSnapshot) (sandboxStaleTargetJournal, map[string]any, error) {
	var envelope sandboxStaleTargetJournalEnvelope
	envelopeObject, err := sandboxCanonicalJSON(snapshot.Value, &envelope)
	if err != nil || snapshot.Version <= 0 || !sandboxExactObjectKeys(envelopeObject, "encoding", "payload", "schema") ||
		envelope.Schema != sandboxStaleTargetJournalEnvelopeSchema || envelope.Encoding != "gzip-base64" {
		return sandboxStaleTargetJournal{}, nil, errors.New("stale-target journal envelope is malformed")
	}
	compressed, err := base64.StdEncoding.Strict().DecodeString(envelope.Payload)
	if err != nil || len(compressed) == 0 {
		return sandboxStaleTargetJournal{}, nil, errors.New("stale-target journal payload is malformed")
	}
	compressedReader := bytes.NewReader(compressed)
	reader, err := gzip.NewReader(compressedReader)
	if err != nil {
		return sandboxStaleTargetJournal{}, nil, errors.New("stale-target journal gzip is malformed")
	}
	reader.Multistream(false)
	decoded, readErr := io.ReadAll(io.LimitReader(reader, sandboxStaleTargetJournalDecodedLimit+1))
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil || len(decoded) == 0 || len(decoded) > sandboxStaleTargetJournalDecodedLimit ||
		compressedReader.Len() != 0 {
		return sandboxStaleTargetJournal{}, nil, errors.New("stale-target journal gzip is malformed or exceeds its bound")
	}
	var journal sandboxStaleTargetJournal
	journalObject, err := sandboxCanonicalJSON(string(decoded), &journal)
	if err != nil {
		return journal, nil, fmt.Errorf("decode stale-target journal: %w", err)
	}
	return journal, journalObject, nil
}

func sandboxValidateDirectoryReceipt(receipt SandboxFenceDirectoryRecoveryReceipt, active string) bool {
	parseUint := func(raw string) (uint64, bool) {
		value, err := strconv.ParseUint(raw, 10, 64)
		return value, err == nil && strconv.FormatUint(value, 10) == raw
	}
	parseMillis := func(raw string) (int64, bool) {
		value, err := strconv.ParseInt(raw, 10, 64)
		return value, err == nil && value > 0 && strconv.FormatInt(value, 10) == raw
	}
	version, versionOK := parseUint(receipt.Version)
	activeCount, activeOK := parseUint(receipt.ActiveFenceCount)
	overflowCount, overflowOK := parseUint(receipt.OverflowCloseCount)
	overflowPrepared, overflowPreparedOK := parseUint(receipt.OverflowLeaderPreparedDirectoryVersion)
	overflowSelected, overflowSelectedOK := parseUint(receipt.OverflowLeaderSelectedDirectoryVersion)
	created, createdOK := parseMillis(receipt.CreatedAtMillis)
	updated, updatedOK := parseMillis(receipt.UpdatedAtMillis)
	directory := sessionControlFenceDirectory{
		CellID: receipt.CellID, Version: version, ActiveFenceCount: activeCount,
		AdmissionBlocked: receipt.AdmissionBlocked, OverflowCloseCount: overflowCount,
		OverflowLeaderEventID:                  receipt.OverflowLeaderEventID,
		OverflowLeaderPreparedDirectoryVersion: overflowPrepared,
		OverflowLeaderSelectedDirectoryVersion: overflowSelected,
		CreatedAtMillis:                        created, UpdatedAtMillis: updated,
	}
	return versionOK && activeOK && overflowOK && overflowPreparedOK && overflowSelectedOK && createdOK && updatedOK &&
		receipt.Schema == sandboxFenceDirectoryRecoveryReceiptSchema && receipt.CellID == SandboxStaleTargetFenceDrainCellID &&
		receipt.ActiveFenceCount == active && !receipt.AdmissionBlocked && receipt.OverflowCloseCount == "0" &&
		receipt.OverflowLeaderEventID == "" && receipt.OverflowLeaderPreparedDirectoryVersion == "0" &&
		receipt.OverflowLeaderSelectedDirectoryVersion == "0" && receipt.DirectorySHA256 == sandboxFenceDirectoryDigest(directory)
}

func sandboxValidateRuntimeComponent(component sandboxStaleTargetRuntimeComponent, label, asg, provenance,
	orchestratorSHA, planDigest string,
) bool {
	expectedAttestation := fmt.Sprintf("v2|durable-aop-v1|%s|%s", strings.TrimPrefix(provenance, "v1|"), asg)
	if component.ASG != asg || component.Attestation != expectedAttestation || component.PriorRefreshID == "" ||
		component.RefreshID == "" || !sandboxExactHex(component.IntentSHA256, 32) {
		return false
	}
	hasher := sha256.New()
	_, _ = fmt.Fprintf(hasher, "v2\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n", label, asg,
		sandboxStaleTargetRuntimeSourceSHA, sandboxStaleTargetRuntimeBuildRunID, sandboxStaleTargetRuntimeBuildAttempt,
		provenance, orchestratorSHA,
		`{"MinHealthyPercentage":100,"MaxHealthyPercentage":200,"InstanceWarmup":60,"SkipMatching":false}`,
		component.PriorRefreshID, planDigest)
	return hex.EncodeToString(hasher.Sum(nil)) == component.IntentSHA256
}

func sandboxValidateRetirementReceipt(receipt *SandboxStaleTargetRetirementReceipt, targetID string,
	fence sessionControlTargetFence,
) bool {
	if receipt == nil {
		return false
	}
	retiredAt, err := strconv.ParseInt(receipt.RetiredAtMillis, 10, 64)
	return receipt.Schema == SandboxStaleTargetRetirementReceiptSchema && receipt.TargetID == targetID &&
		receipt.PublicKey == fence.PublicKey && receipt.Version == decimal(fence.Version+1) &&
		receipt.AuthorityVersion == decimal(fence.AuthorityVersion+1) && !receipt.CountedActiveSlot &&
		err == nil && retiredAt > 0 && strconv.FormatInt(retiredAt, 10) == receipt.RetiredAtMillis &&
		sandboxExactHex(receipt.RetiredTargetSHA256, 32)
}

func sandboxValidatePlan(plan SandboxStaleTargetRetirementPlan, expectedSchema string) ([]sessionControlTargetFence, error) {
	if plan.Schema != expectedSchema || plan.Table != SandboxStaleTargetRetirementTable ||
		plan.Region != SandboxStaleTargetRetirementRegion || plan.ACID != sandboxStaleTargetRetirementACID ||
		plan.ControlCellID != sandboxStaleTargetRetirementCellID || len(plan.Targets) == 0 || len(plan.Targets) > 3 {
		return nil, errors.New("stale-target plan is not the exact sandbox authority")
	}
	fences := make([]sessionControlTargetFence, len(plan.Targets))
	seen := make(map[string]bool, len(plan.Targets))
	seenPublicKeys := make(map[string]bool, len(plan.Targets))
	for index, target := range plan.Targets {
		if target.ID != fmt.Sprintf("predecessor-%d", index+1) && expectedSchema == SandboxStaleTargetPredecessorPlanSchema {
			return nil, errors.New("predecessor target ID is not canonical")
		}
		if target.ID == "" || seen[target.ID] || seenPublicKeys[target.Fence.PublicKey] {
			return nil, errors.New("stale-target plan contains a duplicate target authority")
		}
		seen[target.ID] = true
		seenPublicKeys[target.Fence.PublicKey] = true
		fence, err := sandboxStaleTargetFenceFromPublic(target.Fence)
		if err != nil || target.FenceSHA256 != sandboxStaleTargetFenceDigest(fence) {
			return nil, errors.New("stale-target plan fence or digest is malformed")
		}
		fences[index] = fence
	}
	return fences, nil
}

func sandboxResolveJournaledPredecessorFence(stateSnapshot, currentJournalSnapshot,
	referencedJournalSnapshot SandboxRecoveryParameterSnapshot, targetID string,
) (sessionControlTargetFence, error) {
	state, err := sandboxValidateRecoveryState(stateSnapshot)
	if err != nil {
		return sessionControlTargetFence{}, err
	}
	ref := state.Repair.StaleTargetRetirementRef
	if ref.Parameter != SandboxStaleTargetRecoveryJournalParameter || ref.Version <= 0 || !sandboxExactHex(ref.SHA256, 32) ||
		referencedJournalSnapshot.Version != ref.Version ||
		sandboxCanonicalDigest(referencedJournalSnapshot.Value) != ref.SHA256 {
		return sessionControlTargetFence{}, errors.New("schema-3 state and referenced stale-target journal differ")
	}
	currentIsReference := currentJournalSnapshot.Version == ref.Version &&
		currentJournalSnapshot.Value == referencedJournalSnapshot.Value
	currentIsOneSuccessor := currentJournalSnapshot.Version == ref.Version+1
	if !currentIsReference && !currentIsOneSuccessor {
		return sessionControlTargetFence{}, errors.New("current stale-target journal is neither the reference nor one successor")
	}
	journal, journalObject, err := sandboxDecodeStaleTargetJournal(referencedJournalSnapshot)
	if err != nil {
		return sessionControlTargetFence{}, err
	}
	if !sandboxExactObjectKeys(journalObject, "incident_plan", "incident_plan_sha256", "incident_targets", "runtime",
		"schema", "source_state_sha256", "source_state_version", "status") ||
		!sandboxStaleTargetJournalObjectIsClosed(journalObject) ||
		journal.Schema != sandboxStaleTargetJournalSchema ||
		(journal.Status != "predecessor_retiring" && journal.Status != "complete") ||
		journal.SourceStateVersion != sandboxStaleTargetSourceStateVersion ||
		journal.SourceStateSHA256 != sandboxStaleTargetSourceStateSHA256 {
		return sessionControlTargetFence{}, errors.New("stale-target journal is not at the exact predecessor retirement boundary")
	}
	incidentPlanValue, _ := sandboxCanonicalValue(journal.IncidentPlan)
	exactIncidentPlanValue, _ := sandboxCanonicalValue(SandboxStaleTargetRetirementPlanForIncident())
	if incidentPlanValue != exactIncidentPlanValue || journal.IncidentPlanSHA256 != sandboxCanonicalDigest(incidentPlanValue) ||
		len(journal.IncidentTargets) != 3 {
		return sessionControlTargetFence{}, errors.New("stale-target incident plan drifted")
	}
	for index, target := range journal.IncidentTargets {
		fence := sandboxStaleTargetRetirementFences[index].fence
		if target.ID != sandboxStaleTargetRetirementFences[index].id || target.FenceSHA256 != sandboxStaleTargetFenceDigest(fence) ||
			target.Status != "retired" || !sandboxValidateRetirementReceipt(target.Receipt, target.ID, fence) {
			return sessionControlTargetFence{}, errors.New("stale-target incident ledger is incomplete or malformed")
		}
	}
	runtime := journal.Runtime
	predecessorPlanValue, _ := sandboxCanonicalValue(runtime.PredecessorPlan)
	fences, err := sandboxValidatePlan(runtime.PredecessorPlan, SandboxStaleTargetPredecessorPlanSchema)
	if err != nil || runtime.PredecessorPlanSHA256 != sandboxCanonicalDigest(predecessorPlanValue) ||
		len(runtime.PredecessorTargets) != len(fences) || runtime.SourceSHA != sandboxStaleTargetRuntimeSourceSHA ||
		runtime.BuildRunID != sandboxStaleTargetRuntimeBuildRunID || runtime.BuildRunAttempt != sandboxStaleTargetRuntimeBuildAttempt ||
		runtime.RuntimeManifest != sandboxStaleTargetRuntimeManifest ||
		runtime.ServerProvenance != "v1|"+sandboxStaleTargetRuntimeSourceSHA+"|layerv/nhp-server|"+sandboxStaleTargetRuntimeServerDigest ||
		runtime.ACProvenance != "v1|"+sandboxStaleTargetRuntimeSourceSHA+"|layerv/nhp-ac|"+sandboxStaleTargetRuntimeACDigest ||
		runtime.Preferences != (sandboxStaleTargetRefreshPreferences{InstanceWarmup: 60, MaxHealthyPercentage: 200,
			MinHealthyPercentage: 100, SkipMatching: false}) ||
		!sandboxValidateDirectoryReceipt(runtime.FenceStart, "8") || !sandboxValidateDirectoryReceipt(runtime.FenceDrain, "0") ||
		!sandboxValidateRuntimeComponent(runtime.Cell0, "cell0", "layerv-nhp-sandbox-server", runtime.ServerProvenance,
			state.Repair.OrchestratorSHA, "-") ||
		!sandboxValidateRuntimeComponent(runtime.Cell1, "cell1", "layerv-nhp-sandbox-cell1-server-green", runtime.ServerProvenance,
			state.Repair.OrchestratorSHA, "-") ||
		!sandboxValidateRuntimeComponent(runtime.AC, "ac", "layerv-nhp-sandbox-ac-green", runtime.ACProvenance,
			state.Repair.OrchestratorSHA, runtime.PredecessorPlanSHA256) {
		return sessionControlTargetFence{}, errors.New("stale-target journal runtime authority drifted")
	}
	selected := -1
	firstPending := -1
	seenPending := false
	for index, target := range runtime.PredecessorTargets {
		planTarget := runtime.PredecessorPlan.Targets[index]
		if target.ID != planTarget.ID || target.FenceSHA256 != planTarget.FenceSHA256 {
			return sessionControlTargetFence{}, errors.New("predecessor ledger differs from its plan")
		}
		switch target.Status {
		case "pending":
			if firstPending < 0 {
				firstPending = index
			}
			seenPending = true
			if target.Receipt != nil || journal.Status == "complete" {
				return sessionControlTargetFence{}, errors.New("pending predecessor has impossible receipt or terminal status")
			}
		case "retired":
			if seenPending || !sandboxValidateRetirementReceipt(target.Receipt, target.ID, fences[index]) {
				return sessionControlTargetFence{}, errors.New("retired predecessor ledger is malformed or out of order")
			}
		default:
			return sessionControlTargetFence{}, errors.New("predecessor ledger status is invalid")
		}
		if target.ID == targetID {
			selected = index
		}
	}
	if selected < 0 {
		return sessionControlTargetFence{}, errors.New("target ID is not in the referenced predecessor plan")
	}
	if journal.Runtime.PredecessorTargets[selected].Status == "pending" && selected != firstPending {
		return sessionControlTargetFence{}, errors.New("target ID is not the first pending predecessor")
	}
	if journal.Status == "complete" && seenPending {
		return sessionControlTargetFence{}, errors.New("complete predecessor journal contains pending targets")
	}
	if currentIsOneSuccessor {
		if journal.Status != "predecessor_retiring" || journal.Runtime.PredecessorTargets[selected].Status != "pending" {
			return sessionControlTargetFence{}, errors.New("only one selected pending predecessor can produce a journal successor")
		}
		successorState := state
		successorState.Repair.StaleTargetRetirementRef.Version = currentJournalSnapshot.Version
		successorState.Repair.StaleTargetRetirementRef.SHA256 = sandboxCanonicalDigest(currentJournalSnapshot.Value)
		successorStateValue, encodeErr := sandboxCanonicalValue(successorState)
		if encodeErr != nil {
			return sessionControlTargetFence{}, encodeErr
		}
		successorStateSnapshot := SandboxRecoveryParameterSnapshot{Value: successorStateValue, Version: stateSnapshot.Version}
		successorFence, successorErr := sandboxResolveJournaledPredecessorFence(successorStateSnapshot,
			currentJournalSnapshot, currentJournalSnapshot, targetID)
		if successorErr != nil || successorFence != fences[selected] {
			return sessionControlTargetFence{}, errors.New("current stale-target journal is not a valid selected-target successor")
		}
		successorJournal, _, decodeErr := sandboxDecodeStaleTargetJournal(currentJournalSnapshot)
		if decodeErr != nil || successorJournal.Status != "predecessor_retiring" ||
			successorJournal.Runtime.PredecessorTargets[selected].Status != "retired" ||
			!sandboxValidateRetirementReceipt(successorJournal.Runtime.PredecessorTargets[selected].Receipt,
				targetID, fences[selected]) {
			return sessionControlTargetFence{}, errors.New("selected predecessor successor receipt is malformed")
		}
		expectedSuccessor := journal
		expectedSuccessor.Runtime.PredecessorTargets = append([]sandboxStaleTargetJournalTarget(nil),
			journal.Runtime.PredecessorTargets...)
		expectedSuccessor.Runtime.PredecessorTargets[selected] = successorJournal.Runtime.PredecessorTargets[selected]
		expectedValue, expectedErr := sandboxCanonicalValue(expectedSuccessor)
		currentValue, currentErr := sandboxCanonicalValue(successorJournal)
		if expectedErr != nil || currentErr != nil || expectedValue != currentValue {
			return sessionControlTargetFence{}, errors.New("current stale-target journal changed more than the selected target receipt")
		}
	}
	return fences[selected], nil
}

func retireSandboxJournaledPredecessorWithClient(ctx context.Context, client sessionControlDynamoAPI,
	targetID string, stateSnapshot, currentJournalSnapshot, referencedJournalSnapshot SandboxRecoveryParameterSnapshot,
	nowUTC func() time.Time,
) (*SandboxStaleTargetRetirementReceipt, error) {
	if ctx == nil || client == nil || nowUTC == nil {
		return nil, errors.New("invalid sandbox predecessor retirement authority")
	}
	fence, err := sandboxResolveJournaledPredecessorFence(stateSnapshot, currentJournalSnapshot,
		referencedJournalSnapshot, targetID)
	if err != nil {
		return nil, err
	}
	store := &dynamoSessionControlStore{client: client, tableName: SandboxStaleTargetRetirementTable, nowUTC: nowUTC}
	var retired *sessionControlTargetAuthority
	var expectedReceipt *SandboxStaleTargetRetirementReceipt
	if currentJournalSnapshot.Version == referencedJournalSnapshot.Version+1 {
		// A journal successor can exist only after the DDB retirement committed.
		// Classify the exact retired rows without acquiring any write path, then
		// require the durable receipt to equal those rows before the controller
		// may adopt the successor into its state reference.
		journal, _, decodeErr := sandboxDecodeStaleTargetJournal(currentJournalSnapshot)
		if decodeErr != nil {
			return nil, decodeErr
		}
		for _, target := range journal.Runtime.PredecessorTargets {
			if target.ID == targetID {
				expectedReceipt = target.Receipt
				break
			}
		}
		if expectedReceipt == nil {
			return nil, errors.New("journal successor lacks the selected retirement receipt")
		}
		retired, err = store.classifyRetiredTarget(ctx, fence)
	} else {
		retired, err = store.retireTarget(ctx, fence)
	}
	if err != nil {
		return nil, err
	}
	if retired == nil || !sessionControlRetiredTargetMatchesFence(*retired, fence) {
		return nil, errSessionControlTargetCorrupt
	}
	receipt := &SandboxStaleTargetRetirementReceipt{
		Schema: SandboxStaleTargetRetirementReceiptSchema, TargetID: targetID, PublicKey: retired.PublicKey,
		Version: decimal(retired.Version), AuthorityVersion: decimal(retired.AuthorityVersion),
		CountedActiveSlot: retired.CountedActiveSlot, RetiredAtMillis: decimalMillis(retired.RetiredAtMillis),
		RetiredTargetSHA256: sandboxRetiredTargetDigest(*retired),
	}
	if expectedReceipt != nil && *expectedReceipt != *receipt {
		return nil, errors.New("journal successor receipt differs from the exact retired DDB authority")
	}
	return receipt, nil
}

// RetireSandboxJournaledPredecessorForRecovery derives its fence only from the
// currently referenced exact durable SSM journal. The caller can select only a
// target ID already present in that immutable plan; it cannot provide a table,
// region, AC, cell, fence, journal version, or journal bytes. This seam remains
// outside the ordinary sessionControlStore runtime interface.
func RetireSandboxJournaledPredecessorForRecovery(ctx context.Context, client *dynamodb.Client,
	targetID string, stateSnapshot, currentJournalSnapshot,
	referencedJournalSnapshot SandboxRecoveryParameterSnapshot,
) (*SandboxStaleTargetRetirementReceipt, error) {
	if client == nil {
		return nil, errors.New("invalid sandbox predecessor retirement client")
	}
	return retireSandboxJournaledPredecessorWithClient(ctx, client, targetID, stateSnapshot,
		currentJournalSnapshot, referencedJournalSnapshot, func() time.Time { return time.Now().UTC() })
}
