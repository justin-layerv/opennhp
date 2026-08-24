package server

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

const (
	SandboxActiveReadyRecoveryJournalParameter = "/sandbox/nhp/cutovers/durable-aop-v1/active-ready-predecessors"

	sandboxActiveReadyJournalEnvelopeSchema = "layerv.durable-aop-active-ready-predecessor-journal-envelope.v1"
	sandboxActiveReadyJournalSchema         = "layerv.durable-aop-active-ready-predecessor-journal.v1"
)

// sandboxActiveReadyRecoveryJournal is the fixed, encrypted SSM audit
// sub-journal for the full READY predecessor fences and their ordered receipts.
// The main recovery journal carries only an exact parameter/version/digest ref.
type sandboxActiveReadyRecoveryJournal struct {
	FenceDrainSHA256           string                            `json:"fence_drain_sha256"`
	OrchestratorSHA            string                            `json:"orchestrator_sha"`
	Plan                       SandboxStaleTargetRetirementPlan  `json:"plan"`
	PlanSHA256                 string                            `json:"plan_sha256"`
	QuiescenceSHA256           string                            `json:"quiescence_sha256"`
	Schema                     string                            `json:"schema"`
	SourceMainJournalParameter string                            `json:"source_main_journal_parameter"`
	SourceMainJournalSHA256    string                            `json:"source_main_journal_sha256"`
	SourceMainJournalVersion   int64                             `json:"source_main_journal_version"`
	SourceStateSHA256          string                            `json:"source_state_sha256"`
	SourceStateVersion         int64                             `json:"source_state_version"`
	Status                     string                            `json:"status"`
	Targets                    []sandboxActiveReadyJournalTarget `json:"targets"`
}

func sandboxDecodeActiveReadyJournal(snapshot SandboxRecoveryParameterSnapshot) (
	sandboxActiveReadyRecoveryJournal, map[string]any, error,
) {
	var envelope sandboxStaleTargetJournalEnvelope
	envelopeObject, err := sandboxCanonicalJSON(snapshot.Value, &envelope)
	if err != nil || snapshot.Version <= 0 || !sandboxExactObjectKeys(envelopeObject, "encoding", "payload", "schema") ||
		envelope.Schema != sandboxActiveReadyJournalEnvelopeSchema || envelope.Encoding != "gzip-base64" {
		return sandboxActiveReadyRecoveryJournal{}, nil, errors.New("ACTIVE/READY journal envelope is malformed")
	}
	compressed, err := base64.StdEncoding.Strict().DecodeString(envelope.Payload)
	if err != nil || len(compressed) == 0 {
		return sandboxActiveReadyRecoveryJournal{}, nil, errors.New("ACTIVE/READY journal payload is malformed")
	}
	compressedReader := bytes.NewReader(compressed)
	reader, err := gzip.NewReader(compressedReader)
	if err != nil {
		return sandboxActiveReadyRecoveryJournal{}, nil, errors.New("ACTIVE/READY journal gzip is malformed")
	}
	reader.Multistream(false)
	decoded, readErr := io.ReadAll(io.LimitReader(reader, sandboxStaleTargetJournalDecodedLimit+1))
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil || len(decoded) == 0 || len(decoded) > sandboxStaleTargetJournalDecodedLimit ||
		compressedReader.Len() != 0 {
		return sandboxActiveReadyRecoveryJournal{}, nil,
			errors.New("ACTIVE/READY journal gzip is malformed or exceeds its bound")
	}
	var journal sandboxActiveReadyRecoveryJournal
	object, err := sandboxCanonicalJSON(string(decoded), &journal)
	if err != nil {
		return journal, nil, fmt.Errorf("decode ACTIVE/READY journal: %w", err)
	}
	return journal, object, nil
}

func sandboxActiveReadyJournalObjectIsClosed(root map[string]any) bool {
	return sandboxExactObjectKeys(root, "fence_drain_sha256", "orchestrator_sha", "plan", "plan_sha256",
		"quiescence_sha256", "schema", "source_main_journal_parameter", "source_main_journal_sha256",
		"source_main_journal_version", "source_state_sha256", "source_state_version", "status", "targets") &&
		sandboxStaleTargetPlanObjectIsClosed(root["plan"]) && sandboxActiveReadyLedgerObjectIsClosed(root["targets"])
}

// ReferencedSandboxActiveReadyJournalVersionForRecovery returns only the fixed
// sub-journal version selected by the exact schema-3 state/main-journal pair.
// The incident command uses it to load the historical sub-journal before the
// full five-snapshot resolver authorizes any DynamoDB operation.
func ReferencedSandboxActiveReadyJournalVersionForRecovery(stateSnapshot, currentMainSnapshot,
	referencedMainSnapshot SandboxRecoveryParameterSnapshot,
) (int64, error) {
	resolved, err := sandboxResolveJournalSnapshots(stateSnapshot, currentMainSnapshot, referencedMainSnapshot)
	if err != nil {
		return 0, err
	}
	ref := resolved.Referenced.Runtime.ReadyPredecessorRef
	if ref == nil || ref.Parameter != SandboxActiveReadyRecoveryJournalParameter || ref.Version <= 0 ||
		!sandboxExactHex(ref.SHA256, 32) {
		return 0, errors.New("main recovery journal lacks the exact ACTIVE/READY audit reference")
	}
	return ref.Version, nil
}
