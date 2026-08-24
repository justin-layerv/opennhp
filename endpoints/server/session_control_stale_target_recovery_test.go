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
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

func canonicalSandboxRecoveryJSON(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var generic any
	if err := decoder.Decode(&generic); err != nil {
		t.Fatal(err)
	}
	encoded, err = json.Marshal(generic)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func sandboxRecoveryRuntimeComponent(t *testing.T, label, asg, provenance, orchestrator, planDigest string) sandboxStaleTargetRuntimeComponent {
	t.Helper()
	component := sandboxStaleTargetRuntimeComponent{
		ASG: asg, PriorRefreshID: label + "-prior", RefreshID: label + "-refresh",
		Attestation: fmt.Sprintf("v2|durable-aop-v1|%s|%s", strings.TrimPrefix(provenance, "v1|"), asg),
	}
	hasher := sha256.New()
	_, _ = fmt.Fprintf(hasher, "v2\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n", label, asg,
		sandboxStaleTargetRuntimeSourceSHA, sandboxStaleTargetRuntimeBuildRunID, sandboxStaleTargetRuntimeBuildAttempt,
		provenance, orchestrator,
		`{"MinHealthyPercentage":100,"MaxHealthyPercentage":200,"InstanceWarmup":60,"SkipMatching":false}`,
		component.PriorRefreshID, planDigest)
	component.IntentSHA256 = hex.EncodeToString(hasher.Sum(nil))
	return component
}

func sandboxRecoveryRetirementReceipt(targetID string, fence sessionControlTargetFence) *SandboxStaleTargetRetirementReceipt {
	return &SandboxStaleTargetRetirementReceipt{
		Schema: SandboxStaleTargetRetirementReceiptSchema, TargetID: targetID, PublicKey: fence.PublicKey,
		Version: decimal(fence.Version + 1), AuthorityVersion: decimal(fence.AuthorityVersion + 1),
		CountedActiveSlot: false, RetiredAtMillis: "1787540000000",
		RetiredTargetSHA256: strings.Repeat("a", 64),
	}
}

func sandboxRecoveryJournalAuthority(t *testing.T, targetStatus, journalStatus string) (
	SandboxRecoveryParameterSnapshot, SandboxRecoveryParameterSnapshot, SandboxRecoveryParameterSnapshot,
	sessionControlTargetFence,
) {
	return sandboxRecoveryJournalAuthorityWithTargets(t, []string{targetStatus}, journalStatus)
}

func sandboxRecoveryJournalAuthorityWithTargets(t *testing.T, targetStatuses []string, journalStatus string) (
	SandboxRecoveryParameterSnapshot, SandboxRecoveryParameterSnapshot, SandboxRecoveryParameterSnapshot,
	sessionControlTargetFence,
) {
	t.Helper()
	if len(targetStatuses) == 0 || len(targetStatuses) > len(sandboxStaleTargetRetirementFences) {
		t.Fatalf("invalid predecessor fixture size %d", len(targetStatuses))
	}
	orchestrator := "abcdefabcdefabcdefabcdefabcdefabcdefabcd"
	incidentPlan := SandboxStaleTargetRetirementPlanForIncident()
	incidentPlanJSON := canonicalSandboxRecoveryJSON(t, incidentPlan)
	incidentTargets := make([]sandboxStaleTargetJournalTarget, len(incidentPlan.Targets))
	for index, target := range incidentPlan.Targets {
		fence := sandboxStaleTargetRetirementFences[index].fence
		incidentTargets[index] = sandboxStaleTargetJournalTarget{
			ID: target.ID, FenceSHA256: target.FenceSHA256, Status: "retired",
			Receipt: sandboxRecoveryRetirementReceipt(target.ID, fence),
		}
	}
	predecessorFence := sandboxStaleTargetRetirementFences[0].fence
	predecessorPlan := SandboxStaleTargetRetirementPlan{
		Schema: SandboxStaleTargetPredecessorPlanSchema, Table: SandboxStaleTargetRetirementTable,
		Region: SandboxStaleTargetRetirementRegion, ACID: sandboxStaleTargetRetirementACID,
		ControlCellID: sandboxStaleTargetRetirementCellID,
	}
	predecessorTargets := make([]sandboxStaleTargetJournalTarget, len(targetStatuses))
	for index, targetStatus := range targetStatuses {
		fence := sandboxStaleTargetRetirementFences[index].fence
		id := fmt.Sprintf("predecessor-%d", index+1)
		predecessorPlan.Targets = append(predecessorPlan.Targets, SandboxStaleTargetRetirementPlanTarget{
			ID: id, Fence: sandboxStaleTargetPublicFence(fence), FenceSHA256: sandboxStaleTargetFenceDigest(fence),
		})
		predecessorTargets[index] = sandboxStaleTargetJournalTarget{
			ID: id, FenceSHA256: sandboxStaleTargetFenceDigest(fence), Status: targetStatus,
		}
		if targetStatus == "retired" {
			predecessorTargets[index].Receipt = sandboxRecoveryRetirementReceipt(id, fence)
		}
	}
	predecessorPlanJSON := canonicalSandboxRecoveryJSON(t, predecessorPlan)
	startDirectory := sandboxFenceDirectoryReceipt(sessionControlFenceDirectory{
		CellID: SandboxStaleTargetFenceDrainCellID, Version: 19, ActiveFenceCount: 8,
		CreatedAtMillis: 1787530000000, UpdatedAtMillis: 1787535000000,
	})
	drainedDirectory := sandboxFenceDirectoryReceipt(sessionControlFenceDirectory{
		CellID: SandboxStaleTargetFenceDrainCellID, Version: 27, ActiveFenceCount: 0,
		CreatedAtMillis: 1787530000000, UpdatedAtMillis: 1787545000000,
	})
	serverProvenance := "v1|" + sandboxStaleTargetRuntimeSourceSHA + "|layerv/nhp-server|" + sandboxStaleTargetRuntimeServerDigest
	acProvenance := "v1|" + sandboxStaleTargetRuntimeSourceSHA + "|layerv/nhp-ac|" + sandboxStaleTargetRuntimeACDigest
	journal := sandboxStaleTargetJournal{
		Schema: sandboxStaleTargetJournalSchema, Status: journalStatus,
		SourceStateVersion: sandboxStaleTargetSourceStateVersion, SourceStateSHA256: sandboxStaleTargetSourceStateSHA256,
		IncidentPlan: incidentPlan, IncidentPlanSHA256: sandboxCanonicalDigest(incidentPlanJSON), IncidentTargets: incidentTargets,
		Runtime: sandboxStaleTargetJournalRuntime{
			SourceSHA: sandboxStaleTargetRuntimeSourceSHA, BuildRunID: sandboxStaleTargetRuntimeBuildRunID,
			BuildRunAttempt: sandboxStaleTargetRuntimeBuildAttempt, RuntimeManifest: sandboxStaleTargetRuntimeManifest,
			ServerProvenance: serverProvenance, ACProvenance: acProvenance,
			Preferences: sandboxStaleTargetRefreshPreferences{InstanceWarmup: 60, MaxHealthyPercentage: 200, MinHealthyPercentage: 100},
			Cell0:       sandboxRecoveryRuntimeComponent(t, "cell0", "layerv-nhp-sandbox-server", serverProvenance, orchestrator, "-"),
			Cell1:       sandboxRecoveryRuntimeComponent(t, "cell1", "layerv-nhp-sandbox-cell1-server-green", serverProvenance, orchestrator, "-"),
			AC: sandboxRecoveryRuntimeComponent(t, "ac", "layerv-nhp-sandbox-ac-green", acProvenance, orchestrator,
				sandboxCanonicalDigest(predecessorPlanJSON)),
			FenceStart: startDirectory, FenceDrain: drainedDirectory, PredecessorPlan: predecessorPlan,
			PredecessorPlanSHA256: sandboxCanonicalDigest(predecessorPlanJSON),
			PredecessorTargets:    predecessorTargets,
		},
	}
	journalJSON := canonicalSandboxRecoveryJSON(t, journal)
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	writer.Header.ModTime = time.Unix(0, 0)
	if _, err := writer.Write([]byte(journalJSON)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	envelopeJSON := canonicalSandboxRecoveryJSON(t, sandboxStaleTargetJournalEnvelope{
		Encoding: "gzip-base64", Payload: base64.StdEncoding.EncodeToString(compressed.Bytes()),
		Schema: sandboxStaleTargetJournalEnvelopeSchema,
	})
	ref := sandboxStaleTargetJournalRef{
		Parameter: SandboxStaleTargetRecoveryJournalParameter, SHA256: sandboxCanonicalDigest(envelopeJSON), Version: 9,
	}
	ownerIntent := map[string]any{
		"schema": "layerv.durable-aop-customer-owner-intent.v1", "action": "create", "before_row_sha256": "absent",
		"client_id": "oScYkXhLitBPO6gBjxo4Rwyw37AdoNPy", "subject": "oScYkXhLitBPO6gBjxo4Rwyw37AdoNPy@clients",
		"email": "oscykxhlitbpo6gbjxo4rwyw37adonpy-clients@machine.notify.layerv.xyz",
		"table": "layerv-nhp-sandbox-control-qurl-customers", "region": SandboxStaleTargetRetirementRegion,
		"source_sha": sandboxRecoveryRepairSourceSHA, "provisioned_at": "2026-08-24T00:38:03Z",
		"expected_row_sha256": "cac7d0380fc97736575d2701ef0ccc08927b511cd8646c83785c1be8b30f1b8b",
		"expected_created_at": "2026-08-24T00:38:03Z", "expected_updated_at": "2026-08-24T00:38:03Z",
		"expected_usage": "0", "expected_assigned_cell_id": "",
	}
	repairServerProvenance := "v1|" + sandboxRecoveryRepairSourceSHA + "|layerv/nhp-server|" + sandboxRecoveryServerDigest
	repairACProvenance := "v1|" + sandboxRecoveryRepairSourceSHA + "|layerv/nhp-ac|" + sandboxRecoveryACDigest
	state := sandboxStaleTargetRecoveryState{
		Schema: 3, Phase: "repaired",
		Original: sandboxStaleTargetRecoveryOriginal{
			StateVersion: 7, StateSHA256: "e7ed20adde2ce9e143c9505027a73e415e5dd3d4a9d0c950c912d6398cc5d13e",
			LockVersion: 2, LockSHA256: "6c7224d78837a4d56547409439d9bce30efa9b214367c4f19fd13cc3fe3b2ebd",
			Lock: sandboxStaleTargetRecoveryOriginalLock{
				Schema: 1, Kind: "durable-aop-cutover-recovery", Image: "e9b11398a4cea98da6ae5b41cfe635562e1b7c72",
				OrchestratorSHA: "e9b11398a4cea98da6ae5b41cfe635562e1b7c72",
				Owner:           "nhp:32635672597:durable-aop-cutover:e9b11398a4cea98da6ae5b41cfe635562e1b7c72",
				CreatedAt:       1787485146, ExpiresAt: 253402300799,
			},
		},
		Repair: sandboxStaleTargetRecoveryRepair{
			OrchestratorSHA: orchestrator, SourceSHA: sandboxRecoveryRepairSourceSHA,
			BuildRunID: "32656742290", BuildRunAttempt: "1",
			RuntimeManifest:  "2895963905453d61874858171529968efe8e18e5450d41842854fd2784d1ec78",
			ServerProvenance: repairServerProvenance, ACProvenance: repairACProvenance,
			Cell0Attestation: "v2|durable-aop-v1|" + sandboxRecoveryRepairSourceSHA + "|layerv/nhp-server|" + sandboxRecoveryServerDigest + "|layerv-nhp-sandbox-server",
			Cell1Attestation: "v2|durable-aop-v1|" + sandboxRecoveryRepairSourceSHA + "|layerv/nhp-server|" + sandboxRecoveryServerDigest + "|layerv-nhp-sandbox-cell1-server-green",
			ACAttestation:    "v2|durable-aop-v1|" + sandboxRecoveryRepairSourceSHA + "|layerv/nhp-ac|" + sandboxRecoveryACDigest + "|layerv-nhp-sandbox-ac-green",
			Cell0RefreshID:   "ea9dae3d-22f8-478e-a9ec-91eb9b9f53fb", Cell1RefreshID: "dc5ab358-ef4e-45a8-bf81-d18112a2ce9c",
			ACRefreshID:              "b58f804d-6ed2-4f15-90df-749e2e0f93fb",
			Owner:                    sandboxStaleTargetRecoveryOwner{Status: "ready", Intent: ownerIntent},
			StaleTargetRetirementRef: ref,
		},
	}
	stateSnapshot := SandboxRecoveryParameterSnapshot{Value: canonicalSandboxRecoveryJSON(t, state), Version: 31}
	journalSnapshot := SandboxRecoveryParameterSnapshot{Value: envelopeJSON, Version: 9}
	return stateSnapshot, journalSnapshot, journalSnapshot, predecessorFence
}

func mutateSandboxRecoveryJSON(t *testing.T, raw string, mutate func(map[string]any)) string {
	t.Helper()
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.UseNumber()
	var value map[string]any
	if err := decoder.Decode(&value); err != nil {
		t.Fatal(err)
	}
	mutate(value)
	return canonicalSandboxRecoveryJSON(t, value)
}

func mutateSandboxRecoveryJournal(t *testing.T, snapshot SandboxRecoveryParameterSnapshot,
	mutate func(map[string]any),
) SandboxRecoveryParameterSnapshot {
	t.Helper()
	var envelope sandboxStaleTargetJournalEnvelope
	if err := json.Unmarshal([]byte(snapshot.Value), &envelope); err != nil {
		t.Fatal(err)
	}
	compressed, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		t.Fatal(err)
	}
	decoded := new(bytes.Buffer)
	if _, err := decoded.ReadFrom(reader); err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	journalJSON := mutateSandboxRecoveryJSON(t, decoded.String(), mutate)
	var recompressed bytes.Buffer
	writer := gzip.NewWriter(&recompressed)
	writer.Header.ModTime = time.Unix(0, 0)
	if _, err := writer.Write([]byte(journalJSON)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	envelope.Payload = base64.StdEncoding.EncodeToString(recompressed.Bytes())
	snapshot.Value = canonicalSandboxRecoveryJSON(t, envelope)
	return snapshot
}

func sandboxRecoveryReceiptJSON(t *testing.T, receipt *SandboxStaleTargetRetirementReceipt) any {
	t.Helper()
	encoded, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		t.Fatal(err)
	}
	return value
}

func mutateSandboxRecoveryJournalTargetRetired(t *testing.T, snapshot SandboxRecoveryParameterSnapshot,
	index int, receipt *SandboxStaleTargetRetirementReceipt,
) SandboxRecoveryParameterSnapshot {
	t.Helper()
	return mutateSandboxRecoveryJournal(t, snapshot, func(value map[string]any) {
		target := value["runtime"].(map[string]any)["predecessor_targets"].([]any)[index].(map[string]any)
		target["status"] = "retired"
		target["receipt"] = sandboxRecoveryReceiptJSON(t, receipt)
	})
}

func seedSandboxStaleTargetRetirement(t *testing.T, targetIndex int) (*sessionControlSessionDynamoFake,
	sessionControlTargetFence, sessionControlTargetAuthority, sessionControlOwnerAuthority, sessionControlAuthority) {
	t.Helper()
	fence := sandboxStaleTargetRetirementFences[targetIndex].fence
	target := sessionControlTargetAuthority{
		ACID: fence.ACID, PublicKey: fence.PublicKey, BootID: fence.BootID,
		FlushGeneration: fence.FlushGeneration, State: sessionControlTargetPreparing,
		Version: fence.Version, AuthorityVersion: fence.AuthorityVersion,
		CountedActiveSlot: fence.CountedActiveSlot, ControlCellID: fence.ControlCellID,
		ActivatedControlVersion: fence.ActivatedControlVersion, ReadyControlVersion: fence.ReadyControlVersion,
		AAKEnqueuedAtMillis: fence.AAKEnqueuedAtMillis, AAKTransactionID: fence.AAKTransactionID,
		CreatedAtMillis: fence.CreatedAtMillis, PreparedAtMillis: fence.PreparedAtMillis,
		UpdatedAtMillis: fence.PreparedAtMillis,
	}
	fake := newSessionControlSessionDynamoFake()
	owner := seedSessionControlTarget(t, fake, target)
	authority := sessionControlAuthority{
		ACID: fence.ACID, ControlCellID: fence.ControlCellID, Version: 5, ActiveTargetCount: 4,
		CreatedAtMillis: fence.CreatedAtMillis, UpdatedAtMillis: fence.PreparedAtMillis,
	}
	row, err := sessionControlAuthorityToRow(authority)
	if err != nil {
		t.Fatal(err)
	}
	fake.setItem(marshalSessionControlSessionTestRow(t, row))
	return fake, fence, target, owner, authority
}

func commitSandboxStaleTargetRetirement(t *testing.T, fake *sessionControlSessionDynamoFake,
	target sessionControlTargetAuthority, owner sessionControlOwnerAuthority, authority sessionControlAuthority, retiredAt int64,
) sessionControlTargetAuthority {
	t.Helper()
	retired := target
	retired.State = sessionControlTargetRetired
	retired.Version++
	retired.AuthorityVersion++
	retired.CountedActiveSlot = false
	retired.UpdatedAtMillis = retiredAt
	retired.RetiredAtMillis = retiredAt
	retiredOwner, err := sessionControlOwnerFromTarget(retired, &owner, sessionControlOwnerRetired)
	if err != nil {
		t.Fatal(err)
	}
	authority.Version++
	authority.ActiveTargetCount--
	authority.UpdatedAtMillis = retiredAt
	for _, value := range []any{retired, retiredOwner, authority} {
		var row any
		switch typed := value.(type) {
		case sessionControlTargetAuthority:
			row, err = sessionControlTargetToRow(typed)
		case sessionControlOwnerAuthority:
			row, err = sessionControlOwnerToRow(typed)
		case sessionControlAuthority:
			row, err = sessionControlAuthorityToRow(typed)
		}
		if err != nil {
			t.Fatal(err)
		}
		item, marshalErr := attributevalue.MarshalMap(row)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		fake.setItem(item)
	}
	return retired
}

func seedSandboxPreparingPredecessorSnapshot(t *testing.T, count int, activeCount uint64) (
	*sessionControlSessionDynamoFake, []sessionControlTargetAuthority, []map[string]types.AttributeValue,
) {
	t.Helper()
	fake := newSessionControlSessionDynamoFake()
	targets := make([]sessionControlTargetAuthority, count)
	items := make([]map[string]types.AttributeValue, count)
	for index := range count {
		fence := sandboxStaleTargetRetirementFences[index].fence
		targets[index] = sessionControlTargetAuthority{
			ACID: fence.ACID, PublicKey: fence.PublicKey, BootID: fence.BootID,
			FlushGeneration: fence.FlushGeneration, State: sessionControlTargetPreparing,
			Version: fence.Version, AuthorityVersion: fence.AuthorityVersion,
			CountedActiveSlot: fence.CountedActiveSlot, ControlCellID: fence.ControlCellID,
			ActivatedControlVersion: fence.ActivatedControlVersion, ReadyControlVersion: fence.ReadyControlVersion,
			AAKEnqueuedAtMillis: fence.AAKEnqueuedAtMillis, AAKTransactionID: fence.AAKTransactionID,
			CreatedAtMillis: fence.CreatedAtMillis, PreparedAtMillis: fence.PreparedAtMillis,
			UpdatedAtMillis: fence.PreparedAtMillis,
		}
		seedSessionControlTarget(t, fake, targets[index])
		row, err := sessionControlTargetToRow(targets[index])
		if err != nil {
			t.Fatal(err)
		}
		items[index] = marshalSessionControlSessionTestRow(t, row)
	}
	authority := sessionControlAuthority{
		ACID: sandboxStaleTargetRetirementACID, ControlCellID: sandboxStaleTargetRetirementCellID,
		Version: 12, ActiveTargetCount: activeCount,
		CreatedAtMillis: targets[0].CreatedAtMillis, UpdatedAtMillis: targets[count-1].PreparedAtMillis,
	}
	row, err := sessionControlAuthorityToRow(authority)
	if err != nil {
		t.Fatal(err)
	}
	fake.setItem(marshalSessionControlSessionTestRow(t, row))
	return fake, targets, items
}

func TestSnapshotSandboxPreparingPredecessorsIsBoundedStrongSortedAndStable(t *testing.T) {
	fake, targets, items := seedSandboxPreparingPredecessorSnapshot(t, 2, 2)
	fake.queryHook = func(_ context.Context, input *dynamodb.QueryInput, call int) (*dynamodb.QueryOutput, error) {
		if call >= 2 || input.ConsistentRead == nil || !*input.ConsistentRead || input.Limit == nil ||
			*input.Limit != sessionControlTargetQueryLimit || input.ExclusiveStartKey != nil {
			t.Fatalf("predecessor query %d = %#v", call, input)
		}
		return &dynamodb.QueryOutput{Items: []map[string]types.AttributeValue{items[1], items[0]}}, nil
	}
	plan, err := snapshotSandboxPreparingPredecessors(context.Background(), fake,
		SandboxStaleTargetRetirementTable)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Schema != SandboxStaleTargetPredecessorPlanSchema || plan.Table != SandboxStaleTargetRetirementTable ||
		plan.Region != SandboxStaleTargetRetirementRegion || plan.ACID != sandboxStaleTargetRetirementACID ||
		plan.ControlCellID != sandboxStaleTargetRetirementCellID || len(plan.Targets) != 2 || len(fake.queries) != 2 {
		t.Fatalf("predecessor plan = %#v; queries=%d", plan, len(fake.queries))
	}
	for index, target := range targets {
		if plan.Targets[index].ID != fmt.Sprintf("predecessor-%d", index+1) ||
			plan.Targets[index].Fence != sandboxStaleTargetPublicFence(target.fence()) ||
			plan.Targets[index].FenceSHA256 != sandboxStaleTargetFenceDigest(target.fence()) {
			t.Fatalf("predecessor target %d = %#v", index, plan.Targets[index])
		}
	}
}

func TestSnapshotSandboxPreparingPredecessorsRejectsInventoryDriftAndPendingWork(t *testing.T) {
	t.Run("inventory drift", func(t *testing.T) {
		fake, _, items := seedSandboxPreparingPredecessorSnapshot(t, 3, 2)
		fake.queryHook = func(_ context.Context, _ *dynamodb.QueryInput, call int) (*dynamodb.QueryOutput, error) {
			if call == 0 {
				return &dynamodb.QueryOutput{Items: items[:2]}, nil
			}
			return &dynamodb.QueryOutput{Items: []map[string]types.AttributeValue{items[0], items[2]}}, nil
		}
		if _, err := snapshotSandboxPreparingPredecessors(context.Background(), fake,
			SandboxStaleTargetRetirementTable); !errors.Is(err, errSessionControlTargetConflict) {
			t.Fatalf("inventory drift error = %v", err)
		}
	})

	t.Run("pending owner work", func(t *testing.T) {
		fake, targets, items := seedSandboxPreparingPredecessorSnapshot(t, 2, 2)
		owner, err := sessionControlOwnerFromTarget(targets[0], nil, sessionControlOwnerPreparing)
		if err != nil {
			t.Fatal(err)
		}
		owner.TaskCount = 1
		owner.PendingCount = 1
		owner.WorkVersion = 1
		row, err := sessionControlOwnerToRow(owner)
		if err != nil {
			t.Fatal(err)
		}
		fake.setItem(marshalSessionControlSessionTestRow(t, row))
		fake.queryHook = func(context.Context, *dynamodb.QueryInput, int) (*dynamodb.QueryOutput, error) {
			return &dynamodb.QueryOutput{Items: items}, nil
		}
		if _, err := snapshotSandboxPreparingPredecessors(context.Background(), fake,
			SandboxStaleTargetRetirementTable); !errors.Is(err, errSessionControlOwnerConflict) {
			t.Fatalf("pending owner error = %v", err)
		}
	})
}

func TestSandboxStaleTargetRetirementPlanIsExactAndClosed(t *testing.T) {
	plan := SandboxStaleTargetRetirementPlanForIncident()
	if plan.Schema != SandboxStaleTargetRetirementPlanSchema || plan.Table != SandboxStaleTargetRetirementTable ||
		plan.Region != SandboxStaleTargetRetirementRegion || plan.ACID != sandboxStaleTargetRetirementACID ||
		plan.ControlCellID != sandboxStaleTargetRetirementCellID || len(plan.Targets) != 3 {
		t.Fatalf("incident plan = %#v", plan)
	}
	seen := map[string]bool{}
	for index, target := range plan.Targets {
		expected := sandboxStaleTargetRetirementFences[index]
		if seen[target.ID] || target.ID != expected.id || target.Fence != sandboxStaleTargetPublicFence(expected.fence) ||
			target.FenceSHA256 != sandboxStaleTargetFenceDigest(expected.fence) || len(target.FenceSHA256) != 64 {
			t.Fatalf("incident target %d = %#v", index, target)
		}
		seen[target.ID] = true
	}
	plan.Targets[0].Fence.PublicKey = "caller mutation"
	replay := SandboxStaleTargetRetirementPlanForIncident()
	if replay.Targets[0].Fence.PublicKey != sandboxStaleTargetRetirementFences[0].fence.PublicKey {
		t.Fatal("caller mutated the compile-time incident plan")
	}
}

func TestSandboxStaleTargetRetirementUsesExactStoreTransactionAndClassifiesLostResponse(t *testing.T) {
	for index, targetSpec := range sandboxStaleTargetRetirementFences {
		t.Run(targetSpec.id, func(t *testing.T) {
			fake, _, target, owner, authority := seedSandboxStaleTargetRetirement(t, index)
			const retiredAt = int64(1787535000000)
			retired := commitSandboxStaleTargetRetirement(t, fake, target, owner, authority, retiredAt)
			// Put the predecessor rows back. The transaction hook commits the exact
			// successor and loses its response before the store can observe success.
			predecessorRow, _ := sessionControlTargetToRow(target)
			predecessorOwner, _ := sessionControlOwnerToRow(owner)
			predecessorAuthority, _ := sessionControlAuthorityToRow(authority)
			fake.setItem(marshalSessionControlSessionTestRow(t, predecessorRow))
			fake.setItem(marshalSessionControlSessionTestRow(t, predecessorOwner))
			fake.setItem(marshalSessionControlSessionTestRow(t, predecessorAuthority))
			fake.transactHook = func(context.Context, *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
				commitSandboxStaleTargetRetirement(t, fake, target, owner, authority, retiredAt)
				return nil, context.DeadlineExceeded
			}
			receipt, err := retireSandboxStaleTargetWithClient(context.Background(), fake,
				SandboxStaleTargetRetirementTable, targetSpec.id, func() time.Time { return time.UnixMilli(retiredAt).UTC() })
			if err != nil {
				t.Fatal(err)
			}
			if receipt.Schema != SandboxStaleTargetRetirementReceiptSchema || receipt.TargetID != targetSpec.id ||
				receipt.PublicKey != retired.PublicKey || receipt.Version != decimal(retired.Version) ||
				receipt.AuthorityVersion != decimal(retired.AuthorityVersion) || receipt.CountedActiveSlot ||
				receipt.RetiredAtMillis != decimalMillis(retiredAt) ||
				receipt.RetiredTargetSHA256 != sandboxRetiredTargetDigest(retired) {
				t.Fatalf("retirement receipt = %#v", receipt)
			}
			if len(fake.transactions) != 1 || len(fake.transactions[0].TransactItems) != 3 {
				t.Fatalf("retirement transactions = %#v", fake.transactions)
			}

			fake.transactHook = nil
			replayed, replayErr := retireSandboxStaleTargetWithClient(context.Background(), fake,
				SandboxStaleTargetRetirementTable, targetSpec.id, func() time.Time { return time.UnixMilli(retiredAt + 1).UTC() })
			if replayErr != nil || *replayed != *receipt || len(fake.transactions) != 1 {
				t.Fatalf("retirement replay = %#v, %v; transactions=%d", replayed, replayErr, len(fake.transactions))
			}
		})
	}
}

func TestSandboxStaleTargetRetirementRejectsEveryCallerSelectedAuthorityBeforeDynamoDB(t *testing.T) {
	fake := newSessionControlSessionDynamoFake()
	for name, authority := range map[string][2]string{
		"wrong table":  {"other-table", sandboxStaleTargetRetirementFences[0].id},
		"wrong target": {SandboxStaleTargetRetirementTable, "caller-target"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := retireSandboxStaleTargetWithClient(context.Background(), fake, authority[0], authority[1], time.Now)
			if err == nil {
				t.Fatal("caller-selected retirement authority was accepted")
			}
		})
	}
	if _, err := retireSandboxStaleTargetWithClient(nil, fake, SandboxStaleTargetRetirementTable,
		sandboxStaleTargetRetirementFences[0].id, time.Now); err == nil {
		t.Fatal("nil recovery context was accepted")
	}
	if len(fake.gets) != 0 || len(fake.transactions) != 0 {
		t.Fatalf("rejected recovery reached DynamoDB: gets=%d transactions=%d", len(fake.gets), len(fake.transactions))
	}
}

func TestSandboxStaleTargetRetirementRejectsResidualOwnerWork(t *testing.T) {
	fake, _, _, owner, _ := seedSandboxStaleTargetRetirement(t, 0)
	owner.TaskCount = 1
	owner.WorkVersion++
	ownerRow, err := sessionControlOwnerToRow(owner)
	if err != nil {
		t.Fatal(err)
	}
	fake.setItem(marshalSessionControlSessionTestRow(t, ownerRow))
	_, err = retireSandboxStaleTargetWithClient(context.Background(), fake,
		SandboxStaleTargetRetirementTable, sandboxStaleTargetRetirementFences[0].id, time.Now)
	if err == nil || (!errors.Is(err, errSessionControlOwnerCorrupt) && !errors.Is(err, errSessionControlOwnerConflict)) {
		t.Fatalf("residual owner work error = %v", err)
	}
	if len(fake.transactions) != 0 {
		t.Fatal("residual owner work reached retirement transaction")
	}
}

func TestSandboxJournaledPredecessorFenceIsClosedAndUsesExactRetirement(t *testing.T) {
	fake, fence, target, owner, authority := seedSandboxStaleTargetRetirement(t, 0)
	public := sandboxStaleTargetPublicFence(fence)
	parsed, err := sandboxStaleTargetFenceFromPublic(public)
	if err != nil || parsed != fence {
		t.Fatalf("parsed fence = %#v, %v", parsed, err)
	}
	for name, mutate := range map[string]func(*SandboxStaleTargetFence){
		"leading zero": func(value *SandboxStaleTargetFence) { value.Version = "0607" },
		"ready":        func(value *SandboxStaleTargetFence) { value.ReadyControlVersion = "1" },
		"not counted":  func(value *SandboxStaleTargetFence) { value.CountedActiveSlot = false },
		"wrong AC":     func(value *SandboxStaleTargetFence) { value.ACID = "other" },
	} {
		t.Run(name, func(t *testing.T) {
			mutated := public
			mutate(&mutated)
			if _, parseErr := sandboxStaleTargetFenceFromPublic(mutated); parseErr == nil {
				t.Fatal("mutated predecessor fence was accepted")
			}
		})
	}
	const retiredAt = int64(1787539000000)
	fake.transactHook = func(context.Context, *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
		commitSandboxStaleTargetRetirement(t, fake, target, owner, authority, retiredAt)
		return nil, context.DeadlineExceeded
	}
	store := &dynamoSessionControlStore{client: fake, tableName: SandboxStaleTargetRetirementTable,
		nowUTC: func() time.Time { return time.UnixMilli(retiredAt).UTC() }}
	retired, err := store.retireTarget(context.Background(), parsed)
	if err != nil || retired.State != sessionControlTargetRetired || retired.CountedActiveSlot {
		t.Fatalf("journaled predecessor retirement = %#v, %v", retired, err)
	}
}

func TestSandboxJournaledPredecessorDerivesOnlyCurrentReferencedPlanFence(t *testing.T) {
	state, current, historical, expectedFence := sandboxRecoveryJournalAuthority(t, "pending", "predecessor_retiring")
	fence, err := sandboxResolveJournaledPredecessorFence(state, current, historical, "predecessor-1")
	if err != nil || fence != expectedFence {
		t.Fatalf("derived predecessor fence = %#v, %v", fence, err)
	}

	fake, _, target, owner, authority := seedSandboxStaleTargetRetirement(t, 0)
	const retiredAt = int64(1787540000000)
	fake.transactHook = func(context.Context, *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
		commitSandboxStaleTargetRetirement(t, fake, target, owner, authority, retiredAt)
		return nil, context.DeadlineExceeded
	}
	receipt, err := retireSandboxJournaledPredecessorWithClient(context.Background(), fake, "predecessor-1",
		state, current, historical, func() time.Time { return time.UnixMilli(retiredAt).UTC() })
	if err != nil || receipt.TargetID != "predecessor-1" || receipt.PublicKey != expectedFence.PublicKey ||
		receipt.Version != decimal(expectedFence.Version+1) || receipt.AuthorityVersion != decimal(expectedFence.AuthorityVersion+1) ||
		len(fake.transactions) != 1 {
		t.Fatalf("journal-derived retirement = %#v, %v; transactions=%d", receipt, err, len(fake.transactions))
	}

	completeState, completeCurrent, completeHistorical, completeFence := sandboxRecoveryJournalAuthority(t, "retired", "complete")
	completeFake, _, completeTarget, completeOwner, completeAuthority := seedSandboxStaleTargetRetirement(t, 0)
	retired := commitSandboxStaleTargetRetirement(t, completeFake, completeTarget, completeOwner, completeAuthority, retiredAt)
	replayed, err := retireSandboxJournaledPredecessorWithClient(context.Background(), completeFake, "predecessor-1",
		completeState, completeCurrent, completeHistorical, time.Now)
	if err != nil || replayed.PublicKey != completeFence.PublicKey || replayed.RetiredTargetSHA256 != sandboxRetiredTargetDigest(retired) ||
		len(completeFake.transactions) != 0 {
		t.Fatalf("complete journal replay = %#v, %v; transactions=%d", replayed, err, len(completeFake.transactions))
	}
}

func TestSandboxJournaledPredecessorAdoptsOnlyExactSingleReceiptSuccessorAfterDynamoDBReplay(t *testing.T) {
	state, _, historical, expectedFence := sandboxRecoveryJournalAuthority(t, "pending", "predecessor_retiring")
	fake, _, target, owner, authority := seedSandboxStaleTargetRetirement(t, 0)
	const retiredAt = int64(1787540000000)
	retired := commitSandboxStaleTargetRetirement(t, fake, target, owner, authority, retiredAt)
	expectedReceipt := sandboxRecoveryRetirementReceipt("predecessor-1", expectedFence)
	expectedReceipt.RetiredTargetSHA256 = sandboxRetiredTargetDigest(retired)
	successor := mutateSandboxRecoveryJournalTargetRetired(t, historical, 0, expectedReceipt)
	successor.Version++

	derived, err := sandboxResolveJournaledPredecessorFence(state, successor, historical, "predecessor-1")
	if err != nil || derived != expectedFence {
		t.Fatalf("single exact journal successor fence = %#v, %v", derived, err)
	}
	replayed, err := retireSandboxJournaledPredecessorWithClient(context.Background(), fake, "predecessor-1",
		state, successor, historical, time.Now)
	if err != nil || replayed.TargetID != expectedReceipt.TargetID || replayed.PublicKey != expectedReceipt.PublicKey ||
		replayed.Version != expectedReceipt.Version || replayed.AuthorityVersion != expectedReceipt.AuthorityVersion ||
		replayed.RetiredAtMillis != expectedReceipt.RetiredAtMillis ||
		replayed.RetiredTargetSHA256 != expectedReceipt.RetiredTargetSHA256 || len(fake.transactions) != 0 {
		t.Fatalf("orphan journal DDB replay = %#v, %v; transactions=%d", replayed, err, len(fake.transactions))
	}
}

func TestSandboxJournaledPredecessorRejectsEveryNonExactSuccessorBeforeDynamoDB(t *testing.T) {
	state, _, historical, fence := sandboxRecoveryJournalAuthority(t, "pending", "predecessor_retiring")
	receipt := sandboxRecoveryRetirementReceipt("predecessor-1", fence)
	validSuccessor := mutateSandboxRecoveryJournalTargetRetired(t, historical, 0, receipt)
	validSuccessor.Version++

	wrongReceipt := mutateSandboxRecoveryJournalTargetRetired(t, historical, 0, receipt)
	wrongReceipt = mutateSandboxRecoveryJournal(t, wrongReceipt, func(value map[string]any) {
		value["runtime"].(map[string]any)["predecessor_targets"].([]any)[0].(map[string]any)["receipt"].(map[string]any)["version"] = "609"
	})
	wrongReceipt.Version++
	extraChange := mutateSandboxRecoveryJournal(t, validSuccessor, func(value map[string]any) {
		value["runtime"].(map[string]any)["source_sha"] = strings.Repeat("f", 40)
	})
	twoState, _, twoHistorical, _ := sandboxRecoveryJournalAuthorityWithTargets(t,
		[]string{"pending", "pending"}, "predecessor_retiring")
	secondFence := sandboxStaleTargetRetirementFences[1].fence
	wrongTargetSuccessor := mutateSandboxRecoveryJournalTargetRetired(t, twoHistorical, 1,
		sandboxRecoveryRetirementReceipt("predecessor-2", secondFence))
	wrongTargetSuccessor.Version++
	stateDrift := state
	stateDrift.Value = mutateSandboxRecoveryJSON(t, state.Value, func(value map[string]any) {
		value["repair"].(map[string]any)["stale_target_retirement_ref"].(map[string]any)["sha256"] = strings.Repeat("0", 64)
	})

	tests := map[string]struct {
		state      SandboxRecoveryParameterSnapshot
		current    SandboxRecoveryParameterSnapshot
		historical SandboxRecoveryParameterSnapshot
		targetID   string
	}{
		"wrong transitioned target": {twoState, wrongTargetSuccessor, twoHistorical, "predecessor-1"},
		"out-of-order target":       {twoState, wrongTargetSuccessor, twoHistorical, "predecessor-2"},
		"wrong receipt":             {state, wrongReceipt, historical, "predecessor-1"},
		"extra journal change":      {state, extraChange, historical, "predecessor-1"},
		"second successor": {
			state, SandboxRecoveryParameterSnapshot{Value: validSuccessor.Value, Version: historical.Version + 2},
			historical, "predecessor-1",
		},
		"state reference drift": {stateDrift, validSuccessor, historical, "predecessor-1"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			fake := newSessionControlSessionDynamoFake()
			if _, err := retireSandboxJournaledPredecessorWithClient(context.Background(), fake, test.targetID,
				test.state, test.current, test.historical, time.Now); err == nil {
				t.Fatal("non-exact journal successor was accepted")
			}
			if len(fake.gets) != 0 || len(fake.transactions) != 0 {
				t.Fatalf("rejected successor reached DynamoDB: gets=%d transactions=%d", len(fake.gets), len(fake.transactions))
			}
		})
	}
}

func TestSandboxJournaledPredecessorRejectsValidLookingSuccessorReceiptThatDiffersFromDynamoDB(t *testing.T) {
	state, _, historical, fence := sandboxRecoveryJournalAuthority(t, "pending", "predecessor_retiring")
	for name, mutate := range map[string]func(*SandboxStaleTargetRetirementReceipt){
		"wrong retired target digest": func(receipt *SandboxStaleTargetRetirementReceipt) {
			receipt.RetiredTargetSHA256 = strings.Repeat("f", 64)
		},
		"wrong retired time": func(receipt *SandboxStaleTargetRetirementReceipt) {
			receipt.RetiredAtMillis = "1787540000001"
		},
	} {
		t.Run(name, func(t *testing.T) {
			fake, _, target, owner, authority := seedSandboxStaleTargetRetirement(t, 0)
			const retiredAt = int64(1787540000000)
			retired := commitSandboxStaleTargetRetirement(t, fake, target, owner, authority, retiredAt)
			receipt := sandboxRecoveryRetirementReceipt("predecessor-1", fence)
			receipt.RetiredTargetSHA256 = sandboxRetiredTargetDigest(retired)
			mutate(receipt)
			successor := mutateSandboxRecoveryJournalTargetRetired(t, historical, 0, receipt)
			successor.Version++
			if _, err := retireSandboxJournaledPredecessorWithClient(context.Background(), fake, "predecessor-1",
				state, successor, historical, time.Now); err == nil {
				t.Fatal("valid-looking journal receipt drift was accepted")
			}
			if len(fake.gets) == 0 || len(fake.transactions) != 0 {
				t.Fatalf("receipt drift classification gets=%d transactions=%d", len(fake.gets), len(fake.transactions))
			}
		})
	}
}

func TestSandboxJournaledPredecessorRejectsUnreferencedOrMalformedAuthorityBeforeDynamoDB(t *testing.T) {
	validState, validCurrent, validHistorical, _ := sandboxRecoveryJournalAuthority(t, "pending", "predecessor_retiring")
	malformedEnvelope := SandboxRecoveryParameterSnapshot{Value: `{}`, Version: validCurrent.Version}
	malformedState := validState
	malformedState.Value = mutateSandboxRecoveryJSON(t, validState.Value, func(value map[string]any) {
		value["repair"].(map[string]any)["stale_target_retirement_ref"].(map[string]any)["sha256"] = sandboxCanonicalDigest(malformedEnvelope.Value)
	})
	tests := map[string]struct {
		state      SandboxRecoveryParameterSnapshot
		current    SandboxRecoveryParameterSnapshot
		historical SandboxRecoveryParameterSnapshot
		targetID   string
	}{
		"non-plan target": {validState, validCurrent, validHistorical, "caller-target"},
		"stale current journal version": {
			validState, SandboxRecoveryParameterSnapshot{Value: validCurrent.Value, Version: validCurrent.Version + 1},
			validHistorical, "predecessor-1",
		},
		"malformed envelope": {
			malformedState, malformedEnvelope, malformedEnvelope, "predecessor-1",
		},
		"historical version mismatch": {
			validState, validCurrent,
			SandboxRecoveryParameterSnapshot{Value: validHistorical.Value, Version: validHistorical.Version - 1}, "predecessor-1",
		},
	}
	stateRefDrift := validState
	stateRefDrift.Value = mutateSandboxRecoveryJSON(t, validState.Value, func(value map[string]any) {
		value["repair"].(map[string]any)["stale_target_retirement_ref"].(map[string]any)["parameter"] = "/caller/journal"
	})
	tests["state reference drift"] = struct {
		state      SandboxRecoveryParameterSnapshot
		current    SandboxRecoveryParameterSnapshot
		historical SandboxRecoveryParameterSnapshot
		targetID   string
	}{stateRefDrift, validCurrent, validHistorical, "predecessor-1"}
	digestDrift := validState
	digestDrift.Value = mutateSandboxRecoveryJSON(t, validState.Value, func(value map[string]any) {
		value["repair"].(map[string]any)["stale_target_retirement_ref"].(map[string]any)["sha256"] = strings.Repeat("0", 64)
	})
	tests["journal digest drift"] = struct {
		state      SandboxRecoveryParameterSnapshot
		current    SandboxRecoveryParameterSnapshot
		historical SandboxRecoveryParameterSnapshot
		targetID   string
	}{digestDrift, validCurrent, validHistorical, "predecessor-1"}
	planDrift := mutateSandboxRecoveryJournal(t, validHistorical, func(value map[string]any) {
		value["runtime"].(map[string]any)["predecessor_plan"].(map[string]any)["targets"].([]any)[0].(map[string]any)["fence_sha256"] = strings.Repeat("f", 64)
	})
	planDriftState := validState
	planDriftState.Value = mutateSandboxRecoveryJSON(t, validState.Value, func(value map[string]any) {
		value["repair"].(map[string]any)["stale_target_retirement_ref"].(map[string]any)["sha256"] = sandboxCanonicalDigest(planDrift.Value)
	})
	tests["predecessor fence digest drift"] = struct {
		state      SandboxRecoveryParameterSnapshot
		current    SandboxRecoveryParameterSnapshot
		historical SandboxRecoveryParameterSnapshot
		targetID   string
	}{planDriftState, planDrift, planDrift, "predecessor-1"}
	extraEnvelope := validHistorical
	extraEnvelope.Value = mutateSandboxRecoveryJSON(t, validHistorical.Value, func(value map[string]any) { value["extra"] = true })
	extraState := validState
	extraState.Value = mutateSandboxRecoveryJSON(t, validState.Value, func(value map[string]any) {
		value["repair"].(map[string]any)["stale_target_retirement_ref"].(map[string]any)["sha256"] = sandboxCanonicalDigest(extraEnvelope.Value)
	})
	tests["open envelope"] = struct {
		state      SandboxRecoveryParameterSnapshot
		current    SandboxRecoveryParameterSnapshot
		historical SandboxRecoveryParameterSnapshot
		targetID   string
	}{extraState, extraEnvelope, extraEnvelope, "predecessor-1"}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			fake := newSessionControlSessionDynamoFake()
			if _, err := retireSandboxJournaledPredecessorWithClient(context.Background(), fake, test.targetID,
				test.state, test.current, test.historical, time.Now); err == nil {
				t.Fatal("unreferenced or malformed predecessor authority was accepted")
			}
			if len(fake.gets) != 0 || len(fake.transactions) != 0 {
				t.Fatalf("rejected predecessor reached DynamoDB: gets=%d transactions=%d", len(fake.gets), len(fake.transactions))
			}
		})
	}
}

func seedSandboxFenceDirectoryRecovery(t *testing.T, fake *sessionControlSessionDynamoFake,
	active uint64,
) sessionControlFenceDirectory {
	t.Helper()
	directory := sessionControlFenceDirectory{
		CellID: SandboxStaleTargetFenceDrainCellID, Version: 19, ActiveFenceCount: active,
		CreatedAtMillis: 1787530000000, UpdatedAtMillis: 1787535000000,
	}
	row, err := sessionControlFenceDirectoryToRow(directory)
	if err != nil {
		t.Fatal(err)
	}
	fake.setItem(marshalSessionControlSessionTestRow(t, row))
	return directory
}

func TestSandboxFenceDirectoryRecoveryPinsStablePositiveCapacityBoundThenRequiresStableZero(t *testing.T) {
	for _, count := range []uint64{1, 82, sessionControlFenceActiveLimit} {
		t.Run(decimal(count), func(t *testing.T) {
			fake := newSessionControlSessionDynamoFake()
			initial := seedSandboxFenceDirectoryRecovery(t, fake, count)
			receipt, err := snapshotSandboxFenceDirectoryForRecovery(context.Background(), fake,
				SandboxStaleTargetRetirementTable, SandboxStaleTargetFenceDrainCellID, false)
			if err != nil || receipt.ActiveFenceCount != decimal(count) ||
				receipt.DirectorySHA256 != sandboxFenceDirectoryDigest(initial) ||
				receipt.Schema != sandboxFenceDirectoryRecoveryReceiptSchema || len(fake.gets) != 2 {
				t.Fatalf("initial fence directory = %#v, %v; reads=%d", receipt, err, len(fake.gets))
			}
		})
	}

	fake := newSessionControlSessionDynamoFake()
	initial := seedSandboxFenceDirectoryRecovery(t, fake, 82)
	drained := initial
	drained.Version++
	drained.ActiveFenceCount = 0
	drained.UpdatedAtMillis++
	row, rowErr := sessionControlFenceDirectoryToRow(drained)
	if rowErr != nil {
		t.Fatal(rowErr)
	}
	fake.setItem(marshalSessionControlSessionTestRow(t, row))
	receipt, err := snapshotSandboxFenceDirectoryForRecovery(context.Background(), fake,
		SandboxStaleTargetRetirementTable, SandboxStaleTargetFenceDrainCellID, true)
	if err != nil || receipt.ActiveFenceCount != "0" || receipt.DirectorySHA256 != sandboxFenceDirectoryDigest(drained) ||
		len(fake.gets) != 2 {
		t.Fatalf("drained fence directory = %#v, %v; reads=%d", receipt, err, len(fake.gets))
	}
}

func TestSandboxValidateStartingDirectoryReceiptRequiresCanonicalCapacityBound(t *testing.T) {
	for _, count := range []uint64{1, 82, sessionControlFenceActiveLimit} {
		directory := sessionControlFenceDirectory{
			CellID: SandboxStaleTargetFenceDrainCellID, Version: 83, ActiveFenceCount: count,
			CreatedAtMillis: 1787530000000, UpdatedAtMillis: 1787553983425,
		}
		if !sandboxValidateStartingDirectoryReceipt(sandboxFenceDirectoryReceipt(directory)) {
			t.Fatalf("valid starting fence count %d was rejected", count)
		}
	}

	base := sandboxFenceDirectoryReceipt(sessionControlFenceDirectory{
		CellID: SandboxStaleTargetFenceDrainCellID, Version: 83, ActiveFenceCount: 82,
		CreatedAtMillis: 1787530000000, UpdatedAtMillis: 1787553983425,
	})
	for name, active := range map[string]string{
		"zero": "0", "above capacity": "1025", "leading zero": "082", "negative": "-1", "overflow": "18446744073709551616",
	} {
		t.Run(name, func(t *testing.T) {
			receipt := base
			receipt.ActiveFenceCount = active
			if sandboxValidateStartingDirectoryReceipt(receipt) {
				t.Fatal("invalid starting fence count was accepted")
			}
		})
	}
}

func TestSandboxFenceDirectoryRecoveryRejectsInvalidStartOrHalfDrainedAuthority(t *testing.T) {
	for name, mutate := range map[string]func(map[string]types.AttributeValue){
		"zero": func(item map[string]types.AttributeValue) {
			item["active_fence_count"] = &types.AttributeValueMemberN{Value: "0"}
		},
		"above capacity": func(item map[string]types.AttributeValue) {
			item["active_fence_count"] = &types.AttributeValueMemberN{Value: "1025"}
		},
		"admission blocked": func(item map[string]types.AttributeValue) {
			item["admission_blocked"] = &types.AttributeValueMemberBOOL{Value: true}
		},
		"pending overflow": func(item map[string]types.AttributeValue) {
			item["admission_blocked"] = &types.AttributeValueMemberBOOL{Value: true}
			item["overflow_close_count"] = &types.AttributeValueMemberN{Value: "1"}
		},
		"overflow leader": func(item map[string]types.AttributeValue) {
			item["admission_blocked"] = &types.AttributeValueMemberBOOL{Value: true}
			item["overflow_close_count"] = &types.AttributeValueMemberN{Value: "1"}
			item["overflow_leader_event_id"] = &types.AttributeValueMemberS{Value: "11111111111111111111111111111111"}
			item["overflow_leader_prepared_directory_version"] = &types.AttributeValueMemberN{Value: "1"}
			item["overflow_leader_selected_directory_version"] = &types.AttributeValueMemberN{Value: "2"}
		},
	} {
		t.Run("start "+name, func(t *testing.T) {
			fake := newSessionControlSessionDynamoFake()
			directory := seedSandboxFenceDirectoryRecovery(t, fake, 82)
			row, err := sessionControlFenceDirectoryToRow(directory)
			if err != nil {
				t.Fatal(err)
			}
			item := marshalSessionControlSessionTestRow(t, row)
			mutate(item)
			fake.setItem(item)
			if _, err = snapshotSandboxFenceDirectoryForRecovery(context.Background(), fake,
				SandboxStaleTargetRetirementTable, SandboxStaleTargetFenceDrainCellID, false); err == nil {
				t.Fatal("invalid starting directory was accepted")
			}
		})
	}

	for name, mutate := range map[string]func(*sessionControlFenceDirectory){
		"active fence":     func(value *sessionControlFenceDirectory) { value.ActiveFenceCount = 1 },
		"pending overflow": func(value *sessionControlFenceDirectory) { value.AdmissionBlocked = true; value.OverflowCloseCount = 1 },
		"overflow leader": func(value *sessionControlFenceDirectory) {
			value.AdmissionBlocked = true
			value.OverflowCloseCount = 1
			value.OverflowLeaderEventID = "11111111111111111111111111111111"
			value.OverflowLeaderPreparedDirectoryVersion = 1
			value.OverflowLeaderSelectedDirectoryVersion = 2
		},
	} {
		t.Run(name, func(t *testing.T) {
			fake := newSessionControlSessionDynamoFake()
			directory := seedSandboxFenceDirectoryRecovery(t, fake, 0)
			mutate(&directory)
			row, err := sessionControlFenceDirectoryToRow(directory)
			if err != nil {
				t.Fatal(err)
			}
			fake.setItem(marshalSessionControlSessionTestRow(t, row))
			if _, err = snapshotSandboxFenceDirectoryForRecovery(context.Background(), fake,
				SandboxStaleTargetRetirementTable, SandboxStaleTargetFenceDrainCellID, true); err == nil {
				t.Fatal("half-drained directory was accepted")
			}
		})
	}

	for name, test := range map[string]struct {
		active  uint64
		drained bool
	}{"starting": {active: 82}, "drained": {drained: true}} {
		t.Run("torn "+name, func(t *testing.T) {
			fake := newSessionControlSessionDynamoFake()
			initial := seedSandboxFenceDirectoryRecovery(t, fake, test.active)
			fake.getHook = func(_ context.Context, input *dynamodb.GetItemInput, call int) (*dynamodb.GetItemOutput, error) {
				value := initial
				if call == 1 {
					value.Version++
					value.UpdatedAtMillis++
				}
				row, err := sessionControlFenceDirectoryToRow(value)
				if err != nil {
					t.Fatal(err)
				}
				return &dynamodb.GetItemOutput{Item: marshalSessionControlSessionTestRow(t, row)}, nil
			}
			if _, err := snapshotSandboxFenceDirectoryForRecovery(context.Background(), fake,
				SandboxStaleTargetRetirementTable, SandboxStaleTargetFenceDrainCellID, test.drained); err == nil {
				t.Fatal("directory mutation between strong reads was accepted")
			}
		})
	}
}
