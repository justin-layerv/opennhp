// Command session-control-stale-target-retirement is an incident-only admin
// capability. It can print the compile-time recovery plan or retire one exact
// allowlisted stale target. Its predecessor-fence command is invoked only by
// the schema-3 controller after that controller has durably precommitted and
// digest-bound the exact plan; it is not exposed through a runtime interface.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"

	"github.com/OpenNHP/opennhp/endpoints/server"
)

func emitJSON(out io.Writer, value any) error {
	encoder := json.NewEncoder(out)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(value)
}

func readRecoveryParameter(ctx context.Context, name string) (server.SandboxRecoveryParameterSnapshot, error) {
	args := []string{"ssm", "get-parameter", "--name", name, "--region", server.SandboxStaleTargetRetirementRegion,
		"--query", "{Value:Parameter.Value,Version:Parameter.Version}", "--output", "json", "--no-cli-pager"}
	if strings.HasPrefix(name, server.SandboxActiveReadyRecoveryJournalParameter) {
		args = append(args, "--with-decryption")
	}
	command := exec.CommandContext(ctx, "aws", args...)
	command.Env = append(os.Environ(), "AWS_PAGER=")
	output, err := command.Output()
	if err != nil {
		return server.SandboxRecoveryParameterSnapshot{}, fmt.Errorf("read fixed recovery parameter %s: %w", name, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(output))
	decoder.UseNumber()
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return server.SandboxRecoveryParameterSnapshot{}, errors.New("fixed recovery parameter response is malformed")
	}
	seen := map[string]bool{}
	var value string
	var version json.Number
	for decoder.More() {
		token, tokenErr := decoder.Token()
		key, ok := token.(string)
		if tokenErr != nil || !ok || seen[key] || (key != "Value" && key != "Version") {
			return server.SandboxRecoveryParameterSnapshot{}, errors.New("fixed recovery parameter response is open or duplicated")
		}
		seen[key] = true
		if key == "Value" {
			if err := decoder.Decode(&value); err != nil {
				return server.SandboxRecoveryParameterSnapshot{}, errors.New("fixed recovery parameter value is malformed")
			}
		} else {
			var rawVersion any
			if err := decoder.Decode(&rawVersion); err != nil {
				return server.SandboxRecoveryParameterSnapshot{}, errors.New("fixed recovery parameter version is malformed")
			}
			var ok bool
			version, ok = rawVersion.(json.Number)
			if !ok {
				return server.SandboxRecoveryParameterSnapshot{}, errors.New("fixed recovery parameter version is not a JSON number")
			}
		}
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') || !seen["Value"] || !seen["Version"] || value == "" {
		return server.SandboxRecoveryParameterSnapshot{}, errors.New("fixed recovery parameter response is malformed")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return server.SandboxRecoveryParameterSnapshot{}, errors.New("fixed recovery parameter response contains extra JSON")
	}
	parsedVersion, err := strconv.ParseInt(version.String(), 10, 64)
	if err != nil || parsedVersion <= 0 || strconv.FormatInt(parsedVersion, 10) != version.String() {
		return server.SandboxRecoveryParameterSnapshot{}, errors.New("fixed recovery parameter version is not canonical")
	}
	return server.SandboxRecoveryParameterSnapshot{Value: value, Version: parsedVersion}, nil
}

func referencedJournalVersion(state string) (int64, error) {
	var value map[string]any
	decoder := json.NewDecoder(strings.NewReader(state))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return 0, errors.New("schema-3 recovery state cannot select a journal version")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return 0, errors.New("schema-3 recovery state contains trailing JSON")
	}
	repair, ok := value["repair"].(map[string]any)
	if !ok {
		return 0, errors.New("schema-3 recovery state lacks repair authority")
	}
	ref, ok := repair["stale_target_retirement_ref"].(map[string]any)
	if !ok || len(ref) != 3 || ref["parameter"] != server.SandboxStaleTargetRecoveryJournalParameter {
		return 0, errors.New("schema-3 recovery state lacks the fixed journal reference")
	}
	version, ok := ref["version"].(json.Number)
	if !ok {
		return 0, errors.New("schema-3 recovery journal version is not a JSON number")
	}
	parsed, err := strconv.ParseInt(version.String(), 10, 64)
	if err != nil || parsed <= 0 || strconv.FormatInt(parsed, 10) != version.String() {
		return 0, errors.New("schema-3 recovery journal version is not canonical")
	}
	return parsed, nil
}

type recoveryParameterReader func(context.Context, string) (server.SandboxRecoveryParameterSnapshot, error)

type journaledPredecessorRetirer func(context.Context, string, server.SandboxRecoveryParameterSnapshot,
	server.SandboxRecoveryParameterSnapshot, server.SandboxRecoveryParameterSnapshot) (*server.SandboxStaleTargetRetirementReceipt, error)

type journaledActiveReadyOperation func(context.Context, string, server.SandboxRecoveryParameterSnapshot,
	server.SandboxRecoveryParameterSnapshot, server.SandboxRecoveryParameterSnapshot,
	server.SandboxRecoveryParameterSnapshot, server.SandboxRecoveryParameterSnapshot) (any, error)

type activeReadyVersionSelector func(server.SandboxRecoveryParameterSnapshot,
	server.SandboxRecoveryParameterSnapshot, server.SandboxRecoveryParameterSnapshot) (int64, error)

func runJournaledPredecessor(ctx context.Context, targetID string, out io.Writer, read recoveryParameterReader,
	retire journaledPredecessorRetirer,
) error {
	stateBefore, err := read(ctx, server.SandboxStaleTargetRecoveryStateParameter)
	if err != nil {
		return err
	}
	version, err := referencedJournalVersion(stateBefore.Value)
	if err != nil {
		return err
	}
	currentBefore, err := read(ctx, server.SandboxStaleTargetRecoveryJournalParameter)
	if err != nil {
		return err
	}
	historical, err := read(ctx, server.SandboxStaleTargetRecoveryJournalParameter+":"+strconv.FormatInt(version, 10))
	if err != nil {
		return err
	}
	stateAfter, err := read(ctx, server.SandboxStaleTargetRecoveryStateParameter)
	if err != nil {
		return err
	}
	currentAfter, err := read(ctx, server.SandboxStaleTargetRecoveryJournalParameter)
	if err != nil {
		return err
	}
	if stateBefore != stateAfter || currentBefore != currentAfter {
		return errors.New("schema-3 state or current stale-target journal changed during the retirement read bracket")
	}
	receipt, err := retire(ctx, targetID, stateBefore, currentBefore, historical)
	if err != nil {
		return fmt.Errorf("retire exact sandbox stale target: %w", err)
	}
	return emitJSON(out, receipt)
}

func runJournaledActiveReady(ctx context.Context, targetID string, out io.Writer, read recoveryParameterReader,
	selectVersion activeReadyVersionSelector, operation journaledActiveReadyOperation,
) error {
	stateBefore, err := read(ctx, server.SandboxStaleTargetRecoveryStateParameter)
	if err != nil {
		return err
	}
	mainVersion, err := referencedJournalVersion(stateBefore.Value)
	if err != nil {
		return err
	}
	mainCurrentBefore, err := read(ctx, server.SandboxStaleTargetRecoveryJournalParameter)
	if err != nil {
		return err
	}
	mainHistorical, err := read(ctx, server.SandboxStaleTargetRecoveryJournalParameter+":"+strconv.FormatInt(mainVersion, 10))
	if err != nil {
		return err
	}
	readyVersion, err := selectVersion(stateBefore, mainCurrentBefore, mainHistorical)
	if err != nil {
		return err
	}
	readyCurrentBefore, err := read(ctx, server.SandboxActiveReadyRecoveryJournalParameter)
	if err != nil {
		return err
	}
	readyHistorical, err := read(ctx, server.SandboxActiveReadyRecoveryJournalParameter+":"+strconv.FormatInt(readyVersion, 10))
	if err != nil {
		return err
	}
	stateAfter, err := read(ctx, server.SandboxStaleTargetRecoveryStateParameter)
	if err != nil {
		return err
	}
	mainCurrentAfter, err := read(ctx, server.SandboxStaleTargetRecoveryJournalParameter)
	if err != nil {
		return err
	}
	readyCurrentAfter, err := read(ctx, server.SandboxActiveReadyRecoveryJournalParameter)
	if err != nil {
		return err
	}
	if stateBefore != stateAfter || mainCurrentBefore != mainCurrentAfter || readyCurrentBefore != readyCurrentAfter {
		return errors.New("schema-3 state, main journal, or ACTIVE/READY journal changed during the operation read bracket")
	}
	receipt, err := operation(ctx, targetID, stateBefore, mainCurrentBefore, mainHistorical,
		readyCurrentBefore, readyHistorical)
	if err != nil {
		return fmt.Errorf("apply exact sandbox ACTIVE/READY recovery operation: %w", err)
	}
	return emitJSON(out, receipt)
}

func run(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 1 && args[0] == "plan" {
		return emitJSON(out, server.SandboxStaleTargetRetirementPlanForIncident())
	}
	flags := flag.NewFlagSet("session-control-stale-target-retirement", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var tableName, targetID, region, cellID string
	flags.StringVar(&tableName, "table", "", "exact session-control table")
	flags.StringVar(&targetID, "target-id", "", "exact incident target ID")
	flags.StringVar(&region, "region", "", "exact AWS region")
	flags.StringVar(&cellID, "cell-id", "", "exact control cell")
	if len(args) == 0 || (args[0] != "retire" && args[0] != "snapshot-predecessors" &&
		args[0] != "retire-predecessor" && args[0] != "snapshot-fence-directory" &&
		args[0] != "verify-fence-drain" && args[0] != "snapshot-active-ready-predecessors" &&
		args[0] != "latch-active-ready-predecessor" && args[0] != "verify-active-ready-predecessor-quiescence" &&
		args[0] != "retire-active-ready-predecessor") || flags.Parse(args[1:]) != nil || flags.NArg() != 0 {
		return errors.New("usage: session-control-stale-target-retirement plan | snapshot-predecessors --table TABLE --region REGION | snapshot-fence-directory --table TABLE --cell-id cell0 --region REGION | verify-fence-drain --table TABLE --cell-id cell0 --region REGION | retire --table TABLE --target-id ID --region REGION | retire-predecessor --target-id ID | snapshot-active-ready-predecessors | latch-active-ready-predecessor --target-id ID | verify-active-ready-predecessor-quiescence --target-id ID | retire-active-ready-predecessor --target-id ID")
	}
	directoryMode := args[0] == "snapshot-fence-directory" || args[0] == "verify-fence-drain"
	predecessorMode := args[0] == "retire-predecessor"
	activeReadySnapshotMode := args[0] == "snapshot-active-ready-predecessors"
	activeReadyTargetMode := args[0] == "latch-active-ready-predecessor" ||
		args[0] == "verify-active-ready-predecessor-quiescence" || args[0] == "retire-active-ready-predecessor"
	fixedMode := predecessorMode || activeReadySnapshotMode || activeReadyTargetMode
	if (!fixedMode && (tableName != server.SandboxStaleTargetRetirementTable || region != server.SandboxStaleTargetRetirementRegion)) ||
		(predecessorMode && (tableName != "" || region != "" || cellID != "")) ||
		((activeReadySnapshotMode || activeReadyTargetMode) && (tableName != "" || region != "" || cellID != "")) ||
		((args[0] == "retire" || args[0] == "retire-predecessor" || activeReadyTargetMode) && targetID == "") ||
		((args[0] == "snapshot-predecessors" || directoryMode) && targetID != "") ||
		(activeReadySnapshotMode && targetID != "") ||
		(directoryMode && cellID != server.SandboxStaleTargetFenceDrainCellID) ||
		(!directoryMode && !fixedMode && cellID != "") {
		return errors.New("retirement table, region, or target ID is not the exact incident authority")
	}
	if predecessorMode {
		return runJournaledPredecessor(ctx, targetID, out, readRecoveryParameter,
			func(callCtx context.Context, selectedID string, state, current, historical server.SandboxRecoveryParameterSnapshot) (*server.SandboxStaleTargetRetirementReceipt, error) {
				awsConfig, err := config.LoadDefaultConfig(callCtx, config.WithRegion(server.SandboxStaleTargetRetirementRegion))
				if err != nil {
					return nil, fmt.Errorf("load AWS configuration: %w", err)
				}
				return server.RetireSandboxJournaledPredecessorForRecovery(callCtx, dynamodb.NewFromConfig(awsConfig),
					selectedID, state, current, historical)
			})
	}
	if activeReadyTargetMode {
		return runJournaledActiveReady(ctx, targetID, out, readRecoveryParameter,
			server.ReferencedSandboxActiveReadyJournalVersionForRecovery,
			func(callCtx context.Context, selectedID string, state, currentMain, historicalMain,
				currentReady, historicalReady server.SandboxRecoveryParameterSnapshot,
			) (any, error) {
				awsConfig, err := config.LoadDefaultConfig(callCtx, config.WithRegion(server.SandboxStaleTargetRetirementRegion))
				if err != nil {
					return nil, fmt.Errorf("load AWS configuration: %w", err)
				}
				client := dynamodb.NewFromConfig(awsConfig)
				switch args[0] {
				case "latch-active-ready-predecessor":
					return server.LatchSandboxJournaledActiveReadyPredecessorForRecovery(callCtx, client, selectedID,
						state, currentMain, historicalMain, currentReady, historicalReady)
				case "verify-active-ready-predecessor-quiescence":
					return server.VerifySandboxJournaledActiveReadyPredecessorQuiescenceForRecovery(callCtx, client,
						selectedID, state, currentMain, historicalMain, currentReady, historicalReady)
				default:
					return server.RetireSandboxJournaledActiveReadyPredecessorForRecovery(callCtx, client, selectedID,
						state, currentMain, historicalMain, currentReady, historicalReady)
				}
			})
	}
	awsConfig, err := config.LoadDefaultConfig(ctx, config.WithRegion(server.SandboxStaleTargetRetirementRegion))
	if err != nil {
		return fmt.Errorf("load AWS configuration: %w", err)
	}
	client := dynamodb.NewFromConfig(awsConfig)
	if activeReadySnapshotMode {
		plan, snapshotErr := server.SnapshotSandboxActiveReadyPredecessorsForRecovery(ctx, client,
			server.SandboxStaleTargetRetirementTable)
		if snapshotErr != nil {
			return fmt.Errorf("snapshot exact sandbox ACTIVE/READY predecessors: %w", snapshotErr)
		}
		return emitJSON(out, plan)
	}
	if directoryMode {
		var receipt *server.SandboxFenceDirectoryRecoveryReceipt
		if args[0] == "snapshot-fence-directory" {
			receipt, err = server.SnapshotSandboxFenceDirectoryForRecovery(ctx, client, tableName, cellID)
		} else {
			receipt, err = server.VerifySandboxFenceDirectoryDrainedForRecovery(ctx, client, tableName, cellID)
		}
		if err != nil {
			return fmt.Errorf("read exact sandbox fence directory: %w", err)
		}
		return emitJSON(out, receipt)
	}
	if args[0] == "snapshot-predecessors" {
		plan, snapshotErr := server.SnapshotSandboxPreparingPredecessorsForRecovery(ctx, client, tableName)
		if snapshotErr != nil {
			return fmt.Errorf("snapshot exact sandbox predecessors: %w", snapshotErr)
		}
		return emitJSON(out, plan)
	}
	var receipt *server.SandboxStaleTargetRetirementReceipt
	if args[0] == "retire" {
		receipt, err = server.RetireSandboxStaleTargetForIncident(ctx, client, tableName, targetID)
	}
	if err != nil {
		return fmt.Errorf("retire exact sandbox stale target: %w", err)
	}
	return emitJSON(out, receipt)
}

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
