package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/OpenNHP/opennhp/endpoints/server"
)

func TestRunPrintsOnlyExactIncidentPlanWithoutAWS(t *testing.T) {
	var output bytes.Buffer
	if err := run(context.Background(), []string{"plan"}, &output); err != nil {
		t.Fatal(err)
	}
	var plan server.SandboxStaleTargetRetirementPlan
	if err := json.Unmarshal(output.Bytes(), &plan); err != nil {
		t.Fatal(err)
	}
	if plan.Schema != server.SandboxStaleTargetRetirementPlanSchema || len(plan.Targets) != 3 {
		t.Fatalf("plan output = %#v", plan)
	}
}

func TestRunRejectsMalformedOrCallerSelectedRetirementBeforeAWS(t *testing.T) {
	for name, args := range map[string][]string{
		"missing command":   nil,
		"arbitrary command": {"delete"},
		"wrong table":       {"retire", "--table", "other", "--target-id", "stale-ac-target-1", "--region", server.SandboxStaleTargetRetirementRegion},
		"wrong region":      {"retire", "--table", server.SandboxStaleTargetRetirementTable, "--target-id", "stale-ac-target-1", "--region", "us-west-1"},
		"extra input":       {"retire", "--table", server.SandboxStaleTargetRetirementTable, "--target-id", "stale-ac-target-1", "--region", server.SandboxStaleTargetRetirementRegion, "extra"},
		"caller fence":      {"retire-predecessor", "--target-id", "predecessor-1", "--fence-json", `{}`},
		"caller table":      {"retire-predecessor", "--target-id", "predecessor-1", "--table", server.SandboxStaleTargetRetirementTable},
		"caller region":     {"retire-predecessor", "--target-id", "predecessor-1", "--region", server.SandboxStaleTargetRetirementRegion},
	} {
		t.Run(name, func(t *testing.T) {
			if err := run(context.Background(), args, &bytes.Buffer{}); err == nil {
				t.Fatal("malformed retirement command was accepted")
			}
		})
	}
}

func TestReferencedJournalVersionSelectsOnlyFixedCanonicalReference(t *testing.T) {
	state := `{"repair":{"stale_target_retirement_ref":{"parameter":"/sandbox/nhp/cutovers/durable-aop-v1/stale-target-retirement","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","version":9}}}`
	version, err := referencedJournalVersion(state)
	if err != nil || version != 9 {
		t.Fatalf("journal version = %d, %v", version, err)
	}
	for name, raw := range map[string]string{
		"arbitrary parameter": `{"repair":{"stale_target_retirement_ref":{"parameter":"/caller","sha256":"aa","version":9}}}`,
		"string version":      `{"repair":{"stale_target_retirement_ref":{"parameter":"/sandbox/nhp/cutovers/durable-aop-v1/stale-target-retirement","sha256":"aa","version":"9"}}}`,
		"fractional version":  `{"repair":{"stale_target_retirement_ref":{"parameter":"/sandbox/nhp/cutovers/durable-aop-v1/stale-target-retirement","sha256":"aa","version":9.0}}}`,
		"zero version":        `{"repair":{"stale_target_retirement_ref":{"parameter":"/sandbox/nhp/cutovers/durable-aop-v1/stale-target-retirement","sha256":"aa","version":0}}}`,
		"extra reference key": `{"repair":{"stale_target_retirement_ref":{"extra":true,"parameter":"/sandbox/nhp/cutovers/durable-aop-v1/stale-target-retirement","sha256":"aa","version":9}}}`,
		"trailing JSON":       `{"repair":{"stale_target_retirement_ref":{"parameter":"/sandbox/nhp/cutovers/durable-aop-v1/stale-target-retirement","sha256":"aa","version":9}}}{}`,
		"missing repair":      `{}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := referencedJournalVersion(raw); err == nil {
				t.Fatal("caller-selected journal authority was accepted")
			}
		})
	}
}

func TestReadRecoveryParameterUsesExactBoundedAWSCLIContract(t *testing.T) {
	directory := t.TempDir()
	logPath := filepath.Join(directory, "aws.log")
	awsPath := filepath.Join(directory, "aws")
	script := `#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >"$FAKE_AWS_LOG"
printf 'AWS_PAGER=%s\n' "${AWS_PAGER-unset}" >>"$FAKE_AWS_LOG"
printf '%s' "${FAKE_AWS_RESPONSE-}"
exit "${FAKE_AWS_STATUS-0}"
`
	if err := os.WriteFile(awsPath, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", directory+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("FAKE_AWS_LOG", logPath)
	t.Setenv("AWS_PAGER", "hostile")
	valid := `{"Value":"{\"schema\":3}","Version":9}`
	t.Setenv("FAKE_AWS_RESPONSE", valid)
	snapshot, err := readRecoveryParameter(context.Background(), server.SandboxStaleTargetRecoveryStateParameter)
	if err != nil || snapshot.Value != `{"schema":3}` || snapshot.Version != 9 {
		t.Fatalf("parameter snapshot = %#v, %v", snapshot, err)
	}
	logBytes, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	log := string(logBytes)
	expectedArgs := "ssm get-parameter --name " + server.SandboxStaleTargetRecoveryStateParameter +
		" --region us-east-2 --query {Value:Parameter.Value,Version:Parameter.Version} --output json --no-cli-pager\n"
	if log != expectedArgs+"AWS_PAGER=\n" {
		t.Fatalf("aws invocation = %q", log)
	}

	for name, response := range map[string]string{
		"empty":              "",
		"null":               `null`,
		"unknown":            `{"Other":true,"Value":"x","Version":9}`,
		"duplicate":          `{"Value":"x","Value":"y","Version":9}`,
		"missing value":      `{"Version":9}`,
		"empty value":        `{"Value":"","Version":9}`,
		"zero version":       `{"Value":"x","Version":0}`,
		"fractional version": `{"Value":"x","Version":9.0}`,
		"string version":     `{"Value":"x","Version":"9"}`,
		"extra JSON":         `{"Value":"x","Version":9}{}`,
		"malformed":          `{`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("FAKE_AWS_STATUS", "0")
			t.Setenv("FAKE_AWS_RESPONSE", response)
			if _, err := readRecoveryParameter(context.Background(), server.SandboxStaleTargetRecoveryStateParameter); err == nil {
				t.Fatal("malformed AWS parameter response was accepted")
			}
		})
	}
	t.Run("nonzero", func(t *testing.T) {
		t.Setenv("FAKE_AWS_RESPONSE", valid)
		t.Setenv("FAKE_AWS_STATUS", "7")
		if _, err := readRecoveryParameter(context.Background(), server.SandboxStaleTargetRecoveryStateParameter); err == nil ||
			!strings.Contains(err.Error(), "read fixed recovery parameter") {
			t.Fatalf("nonzero aws result = %v", err)
		}
	})
}

func TestRunJournaledPredecessorBracketsStableStateAndJournalBeforeRetirement(t *testing.T) {
	state := server.SandboxRecoveryParameterSnapshot{
		Value:   `{"repair":{"stale_target_retirement_ref":{"parameter":"/sandbox/nhp/cutovers/durable-aop-v1/stale-target-retirement","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","version":9}}}`,
		Version: 31,
	}
	current := server.SandboxRecoveryParameterSnapshot{Value: `{"current":true}`, Version: 9}
	historical := current
	expectedReads := []string{
		server.SandboxStaleTargetRecoveryStateParameter,
		server.SandboxStaleTargetRecoveryJournalParameter,
		server.SandboxStaleTargetRecoveryJournalParameter + ":9",
		server.SandboxStaleTargetRecoveryStateParameter,
		server.SandboxStaleTargetRecoveryJournalParameter,
	}
	reads := 0
	reader := func(_ context.Context, name string) (server.SandboxRecoveryParameterSnapshot, error) {
		if reads >= len(expectedReads) || name != expectedReads[reads] {
			t.Fatalf("parameter read %d = %q", reads, name)
		}
		reads++
		if name == server.SandboxStaleTargetRecoveryStateParameter {
			return state, nil
		}
		if name == server.SandboxStaleTargetRecoveryJournalParameter+":9" {
			return historical, nil
		}
		return current, nil
	}
	retirements := 0
	retirer := func(_ context.Context, targetID string, gotState, gotCurrent,
		gotHistorical server.SandboxRecoveryParameterSnapshot,
	) (*server.SandboxStaleTargetRetirementReceipt, error) {
		if targetID != "predecessor-1" || gotState != state || gotCurrent != current || gotHistorical != historical {
			t.Fatalf("retirement authority = %q %#v %#v %#v", targetID, gotState, gotCurrent, gotHistorical)
		}
		retirements++
		return &server.SandboxStaleTargetRetirementReceipt{
			Schema: server.SandboxStaleTargetRetirementReceiptSchema, TargetID: targetID,
		}, nil
	}
	var output bytes.Buffer
	if err := runJournaledPredecessor(context.Background(), "predecessor-1", &output, reader, retirer); err != nil {
		t.Fatal(err)
	}
	if reads != 5 || retirements != 1 || !bytes.Contains(output.Bytes(), []byte(`"target_id":"predecessor-1"`)) {
		t.Fatalf("reads=%d retirements=%d output=%s", reads, retirements, output.String())
	}
}

func TestRunJournaledPredecessorPassesOneStableUnreferencedSuccessorForExactDynamoDBReplay(t *testing.T) {
	state := server.SandboxRecoveryParameterSnapshot{
		Value:   `{"repair":{"stale_target_retirement_ref":{"parameter":"/sandbox/nhp/cutovers/durable-aop-v1/stale-target-retirement","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","version":9}}}`,
		Version: 31,
	}
	historical := server.SandboxRecoveryParameterSnapshot{Value: `{"target":"pending"}`, Version: 9}
	current := server.SandboxRecoveryParameterSnapshot{Value: `{"target":"retired","receipt":"exact"}`, Version: 10}
	reads := 0
	reader := func(_ context.Context, parameter string) (server.SandboxRecoveryParameterSnapshot, error) {
		reads++
		switch parameter {
		case server.SandboxStaleTargetRecoveryStateParameter:
			return state, nil
		case server.SandboxStaleTargetRecoveryJournalParameter:
			return current, nil
		case server.SandboxStaleTargetRecoveryJournalParameter + ":9":
			return historical, nil
		default:
			return server.SandboxRecoveryParameterSnapshot{}, fmt.Errorf("unexpected parameter %s", parameter)
		}
	}
	replays := 0
	retirer := func(_ context.Context, targetID string, gotState, gotCurrent,
		gotHistorical server.SandboxRecoveryParameterSnapshot,
	) (*server.SandboxStaleTargetRetirementReceipt, error) {
		if targetID != "predecessor-1" || gotState != state || gotCurrent != current || gotHistorical != historical {
			t.Fatalf("orphan replay authority = %q %#v %#v %#v", targetID, gotState, gotCurrent, gotHistorical)
		}
		replays++
		return &server.SandboxStaleTargetRetirementReceipt{
			Schema: server.SandboxStaleTargetRetirementReceiptSchema, TargetID: targetID,
		}, nil
	}
	var output bytes.Buffer
	if err := runJournaledPredecessor(context.Background(), "predecessor-1", &output, reader, retirer); err != nil {
		t.Fatal(err)
	}
	if reads != 5 || replays != 1 || !bytes.Contains(output.Bytes(), []byte(`"target_id":"predecessor-1"`)) {
		t.Fatalf("reads=%d replays=%d output=%s", reads, replays, output.String())
	}
}

func TestRunJournaledPredecessorRejectsDriftOrUnplannedTargetBeforeRetirement(t *testing.T) {
	baseState := server.SandboxRecoveryParameterSnapshot{
		Value:   `{"repair":{"stale_target_retirement_ref":{"parameter":"/sandbox/nhp/cutovers/durable-aop-v1/stale-target-retirement","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","version":9}}}`,
		Version: 31,
	}
	baseCurrent := server.SandboxRecoveryParameterSnapshot{Value: `{"current":true}`, Version: 9}
	for name, mutate := range map[string]func(int, string, server.SandboxRecoveryParameterSnapshot) server.SandboxRecoveryParameterSnapshot{
		"state drift": func(call int, parameter string, value server.SandboxRecoveryParameterSnapshot) server.SandboxRecoveryParameterSnapshot {
			if call == 3 && parameter == server.SandboxStaleTargetRecoveryStateParameter {
				value.Version++
			}
			return value
		},
		"current journal drift": func(call int, parameter string, value server.SandboxRecoveryParameterSnapshot) server.SandboxRecoveryParameterSnapshot {
			if call == 4 && parameter == server.SandboxStaleTargetRecoveryJournalParameter {
				value.Value = `{"current":"changed"}`
			}
			return value
		},
	} {
		t.Run(name, func(t *testing.T) {
			call := 0
			reader := func(_ context.Context, parameter string) (server.SandboxRecoveryParameterSnapshot, error) {
				var value server.SandboxRecoveryParameterSnapshot
				switch parameter {
				case server.SandboxStaleTargetRecoveryStateParameter:
					value = baseState
				case server.SandboxStaleTargetRecoveryJournalParameter, server.SandboxStaleTargetRecoveryJournalParameter + ":9":
					value = baseCurrent
				default:
					return value, fmt.Errorf("unexpected parameter %s", parameter)
				}
				value = mutate(call, parameter, value)
				call++
				return value, nil
			}
			retirements := 0
			retirer := func(context.Context, string, server.SandboxRecoveryParameterSnapshot,
				server.SandboxRecoveryParameterSnapshot, server.SandboxRecoveryParameterSnapshot,
			) (*server.SandboxStaleTargetRetirementReceipt, error) {
				retirements++
				return nil, nil
			}
			if err := runJournaledPredecessor(context.Background(), "predecessor-1", &bytes.Buffer{}, reader, retirer); err == nil {
				t.Fatal("drifted read bracket was accepted")
			}
			if retirements != 0 {
				t.Fatal("drifted read bracket reached retirement")
			}
		})
	}

	for name, targetID := range map[string]string{"historical mismatch": "predecessor-1", "non-plan target": "caller-target"} {
		t.Run(name, func(t *testing.T) {
			reader := func(_ context.Context, parameter string) (server.SandboxRecoveryParameterSnapshot, error) {
				if parameter == server.SandboxStaleTargetRecoveryStateParameter {
					return baseState, nil
				}
				if parameter == server.SandboxStaleTargetRecoveryJournalParameter+":9" && name == "historical mismatch" {
					return server.SandboxRecoveryParameterSnapshot{Value: `{"historical":"wrong"}`, Version: 9}, nil
				}
				return baseCurrent, nil
			}
			retirements := 0
			retirer := func(_ context.Context, selected string, _ server.SandboxRecoveryParameterSnapshot,
				current, historical server.SandboxRecoveryParameterSnapshot,
			) (*server.SandboxStaleTargetRetirementReceipt, error) {
				if selected != "predecessor-1" || current != historical {
					return nil, errors.New("journal-derived authority rejected before DynamoDB")
				}
				retirements++
				return nil, nil
			}
			if err := runJournaledPredecessor(context.Background(), targetID, &bytes.Buffer{}, reader, retirer); err == nil {
				t.Fatal("unreferenced command authority was accepted")
			}
			if retirements != 0 {
				t.Fatal("unreferenced command authority reached retirement")
			}
		})
	}
}
