package server

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func sandboxActiveReadySizeEnvelope(t *testing.T, schema string, value any) string {
	t.Helper()
	canonical := canonicalSandboxRecoveryJSON(t, value)
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	writer.Header.ModTime = time.Unix(0, 0)
	if _, err := writer.Write([]byte(canonical)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return canonicalSandboxRecoveryJSON(t, sandboxStaleTargetJournalEnvelope{
		Encoding: "gzip-base64", Payload: base64.StdEncoding.EncodeToString(compressed.Bytes()), Schema: schema,
	})
}

func TestSandboxActiveReadyMaximalJournalsFitStandardSSMParameters(t *testing.T) {
	_, current, _, _ := sandboxRecoveryJournalAuthorityWithTargets(t,
		[]string{"retired", "retired", "retired"}, "ready_predecessor_retiring")
	plan, fences, owners := sandboxActiveReadyTestPlan(t)
	directory := sandboxFenceDirectoryReceipt(sessionControlFenceDirectory{
		CellID: sandboxStaleTargetRetirementCellID, Version: sandboxActiveReadyDirectoryVersion,
		CreatedAtMillis: 1_800_000_000_000, UpdatedAtMillis: 1_800_000_000_250,
	})
	ledger := sandboxActiveReadyTestLedger(t, plan, fences, owners,
		[]string{"retired", "retired", "retired"}, directory)
	planValue := canonicalSandboxRecoveryJSON(t, plan)
	subJournal := sandboxActiveReadyRecoveryJournal{
		Schema: sandboxActiveReadyJournalSchema, Status: "complete",
		SourceStateVersion:         30,
		SourceStateSHA256:          "4268c108fe2685c5a475d05f2ec98d5d58c54618dc3934289b97bc0da855dca6",
		SourceMainJournalParameter: SandboxStaleTargetRecoveryJournalParameter,
		SourceMainJournalVersion:   8,
		SourceMainJournalSHA256:    "49a0da6ea26c551ed99f51ad1e1a4608aa89ab7d1f97a40f22c2c12ce99b1a5c",
		OrchestratorSHA:            strings.Repeat("f", 40), FenceDrainSHA256: directory.DirectorySHA256,
		Plan: plan, PlanSHA256: sandboxCanonicalDigest(planValue),
		QuiescenceSHA256: strings.Repeat("e", 64), Targets: ledger,
	}
	subEnvelope := sandboxActiveReadySizeEnvelope(t, sandboxActiveReadyJournalEnvelopeSchema, subJournal)
	if size := len([]byte(subEnvelope)); size > 4096 {
		t.Fatalf("maximal ACTIVE/READY audit sub-journal envelope is %d bytes, exceeds the 4096-byte SSM limit", size)
	} else if size < 2000 {
		t.Fatalf("maximal ACTIVE/READY audit sub-journal unexpectedly shrank to %d bytes", size)
	} else {
		t.Logf("maximal ACTIVE/READY audit sub-journal envelope: %d/4096 bytes", size)
	}

	ref := sandboxStaleTargetJournalRef{
		Parameter: SandboxActiveReadyRecoveryJournalParameter,
		Version:   16,
		SHA256:    sandboxCanonicalDigest(subEnvelope),
	}
	current = mutateSandboxRecoveryJournal(t, current, func(value map[string]any) {
		value["status"] = "complete"
		runtime := value["runtime"].(map[string]any)
		delete(runtime, "ready_predecessor_plan")
		delete(runtime, "ready_predecessor_plan_sha256")
		delete(runtime, "ready_predecessor_quiescence_sha256")
		delete(runtime, "ready_predecessor_targets")
		runtime["ready_predecessor_ref"] = sandboxActiveReadyJSONValue(t, ref)
	})
	if size := len([]byte(current.Value)); size > 4096 {
		t.Fatalf("maximal slim recovery journal envelope is %d bytes, exceeds the 4096-byte SSM limit", size)
	} else if size < 2500 {
		t.Fatalf("maximal slim recovery journal unexpectedly shrank to %d bytes", size)
	} else {
		t.Logf("maximal slim recovery journal envelope: %d/4096 bytes", size)
	}
}
