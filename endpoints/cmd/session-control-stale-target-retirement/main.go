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
	command := exec.CommandContext(ctx, "aws", "ssm", "get-parameter", "--name", name,
		"--region", server.SandboxStaleTargetRetirementRegion, "--query",
		"{Value:Parameter.Value,Version:Parameter.Version}", "--output", "json", "--no-cli-pager")
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
		args[0] != "verify-fence-drain") || flags.Parse(args[1:]) != nil || flags.NArg() != 0 {
		return errors.New("usage: session-control-stale-target-retirement plan | snapshot-predecessors --table TABLE --region REGION | snapshot-fence-directory --table TABLE --cell-id cell0 --region REGION | verify-fence-drain --table TABLE --cell-id cell0 --region REGION | retire --table TABLE --target-id ID --region REGION | retire-predecessor --target-id ID")
	}
	directoryMode := args[0] == "snapshot-fence-directory" || args[0] == "verify-fence-drain"
	predecessorMode := args[0] == "retire-predecessor"
	if (!predecessorMode && (tableName != server.SandboxStaleTargetRetirementTable || region != server.SandboxStaleTargetRetirementRegion)) ||
		(predecessorMode && (tableName != "" || region != "" || cellID != "")) ||
		((args[0] == "retire" || args[0] == "retire-predecessor") && targetID == "") ||
		((args[0] == "snapshot-predecessors" || directoryMode) && targetID != "") ||
		(directoryMode && cellID != server.SandboxStaleTargetFenceDrainCellID) ||
		(!directoryMode && !predecessorMode && cellID != "") {
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
	awsConfig, err := config.LoadDefaultConfig(ctx, config.WithRegion(server.SandboxStaleTargetRetirementRegion))
	if err != nil {
		return fmt.Errorf("load AWS configuration: %w", err)
	}
	client := dynamodb.NewFromConfig(awsConfig)
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
