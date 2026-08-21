//go:build smoke

package smoke

// Tier 1: Connector Authority CloudWatch alarm <-> publisher dimension and
// operator-routing contract (issue #3455).
//
// The sibling AC fence (09_ac_alarm_dimension_contract_test.go, issue #968) is
// the precedent: an alarm whose dimension set matches no stream the publisher
// emits watches nothing and, with treat_missing_data=notBreaching, sits in a
// permanently green OK. Three AC alarms were silently non-functional for months
// for exactly that reason. The Authority set is 135 alarms across 13 functions
// with a zero-traffic baseline, so the same mistake would be invisible.
//
// This file fences the DEPLOYED side in the two ways that need no traffic:
//
//  1. TestAuthorityAlarms_DimensionsMatchPublisher — each alarm's configured
//     dimension set equals the set its publisher emits. AWS/Lambda alarms key
//     on {FunctionName}; custom LayerV/ConnectorAuthority alarms key on the EMF
//     publisher's prefix (EnvironmentID, AuthorityOperation, CellID for cell
//     operations only) plus that metric's own dynamic dimensions.
//
//  2. TestAuthorityAlarms_AreActionable — every Authority alarm carries at
//     least one operator action. An alarm with no action is strictly worse than
//     no alarm: it shows green while nothing is watching.
//
// There is deliberately NO "publisher streams exist" test here, unlike the AC
// file. That test needs a regularly-firing proxy metric, and the Authority
// graph is dark — no function has ever been invoked, so no stream exists for
// any of these metrics yet. Proving the dim sets select real streams is the
// synthetic-failure page-receipt step in
// docs/runbooks/prod-rollout-ledger/2026-07-26-issue-3455-authority-operator-alerts.md.
// Add the streams-exist half here once the native UDP path carries traffic.

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
)

const (
	authorityMetricsNamespace = "LayerV/ConnectorAuthority"
	authorityLambdaNamespace  = "AWS/Lambda"
)

// authorityOperation is one Authority operation: the function-name suffix, the
// PascalCase qurl-conformance name the handler reports as AuthorityOperation,
// and whether it is a cell operation (which is what decides CellID's presence).
type authorityOperation struct {
	suffix         string
	conformance    string
	cell           bool
	admissionGated bool
	completes      bool
}

// The frozen sandbox graph: 3 Hub operations plus 5 per provisioned cell. Kept
// in lockstep with terraform/modules/connector-authority-foundation and
// layervai/qurl-service internal/connectorauthorityruntime/config.go.
func authorityOperations() []authorityOperation {
	return []authorityOperation{
		{suffix: "ia", conformance: "IssueAssignment"},
		{suffix: "ra", conformance: "RefreshAssignment"},
		{suffix: "icr", conformance: "IssueCredentialRecovery"},
		{suffix: "iro", conformance: "IssueRegistrationOTP", cell: true},
		{suffix: "ar", conformance: "ActivateRegistration", cell: true, admissionGated: true},
		{suffix: "cr", conformance: "CompleteRegistration", cell: true, admissionGated: true, completes: true},
		{suffix: "ccr", conformance: "CompleteCredentialRecovery", cell: true},
		{suffix: "creso", conformance: "ResolveConnectorResource", cell: true},
	}
}

func authorityCells() []string { return []string{"cell0", "cell1"} }

type authorityAlarmCase struct {
	alarmName string
	wantDims  map[string]string
	publisher string
}

// authorityIdentityDims reproduces authorityTelemetry.emitPoint's identity
// prefix: EnvironmentID and AuthorityOperation always, CellID if and only if
// the operation is a cell operation.
func authorityIdentityDims(op authorityOperation, cell string) map[string]string {
	dims := map[string]string{
		"EnvironmentID":      testConfig.Environment,
		"AuthorityOperation": op.conformance,
	}
	if op.cell {
		dims["CellID"] = cell
	}
	return dims
}

func withDim(base map[string]string, name, value string) map[string]string {
	out := make(map[string]string, len(base)+1)
	for k, v := range base {
		out[k] = v
	}
	out[name] = value
	return out
}

func authorityAlarmCases() []authorityAlarmCase {
	var cases []authorityAlarmCase
	for _, op := range authorityOperations() {
		cells := []string{""}
		if op.cell {
			cells = authorityCells()
		}
		for _, cell := range cells {
			fn := fmt.Sprintf("layerv-nhp-%s-ca-%s", testConfig.Environment, op.suffix)
			if op.cell {
				fn += "-" + cell
			}
			lambdaDims := map[string]string{"FunctionName": fn}
			for _, suffix := range []string{
				"provisioned-concurrency-spillover",
				"errors",
				"throttles",
				"duration",
				"concurrency-exhaustion",
				"async-invocation",
			} {
				cases = append(cases, authorityAlarmCase{
					alarmName: fn + "-" + suffix,
					wantDims:  lambdaDims,
					publisher: "AWS/Lambda function-wide {FunctionName} stream",
				})
			}

			identity := authorityIdentityDims(op, cell)
			for _, outcome := range []string{"internal", "unavailable"} {
				cases = append(cases, authorityAlarmCase{
					alarmName: fmt.Sprintf("%s-terminal-outcome-%s", fn, outcome),
					wantDims:  withDim(identity, "Outcome", outcome),
					publisher: "EMF qurl.connector_authority.invocation.total",
				})
			}
			if !op.admissionGated {
				continue
			}
			for _, outcome := range []string{"limited", "unavailable"} {
				cases = append(cases, authorityAlarmCase{
					alarmName: fmt.Sprintf("%s-admission-%s", fn, outcome),
					wantDims:  withDim(identity, "Outcome", outcome),
					publisher: "EMF qurl.connector_registration.adapter_admission.total",
				})
			}
			// These two counters carry no dynamic dimension at all, so the
			// identity prefix alone is the complete emitted set.
			cases = append(cases,
				authorityAlarmCase{
					alarmName: fn + "-adapter-contract-violation",
					wantDims:  identity,
					publisher: "EMF qurl.connector_registration.adapter_contract_violation.total",
				},
				authorityAlarmCase{
					alarmName: fn + "-adapter-late-result",
					wantDims:  identity,
					publisher: "EMF qurl.connector_registration.adapter_late_result.total",
				},
			)
			if !op.completes {
				continue
			}
			cases = append(cases, authorityAlarmCase{
				alarmName: fn + "-completion-identity-authority_fence",
				wantDims:  withDim(identity, "Cause", "authority_fence"),
				publisher: "EMF qurl.connector_registration.completion_identity_rejected.total",
			})
		}
	}
	return cases
}

// describeAuthorityAlarms fetches every deployed Authority metric alarm in one
// prefix-paginated sweep. Per-alarm DescribeAlarms would be 106 sequential
// round-trips on this graph — enough to invite CloudWatch API throttling.
func describeAuthorityAlarms(ctx context.Context, t *testing.T) map[string]cwtypes.MetricAlarm {
	t.Helper()
	prefix := fmt.Sprintf("layerv-nhp-%s-ca-", testConfig.Environment)
	alarms := map[string]cwtypes.MetricAlarm{}
	paginator := cloudwatch.NewDescribeAlarmsPaginator(testConfig.CWClient, &cloudwatch.DescribeAlarmsInput{
		AlarmNamePrefix: aws.String(prefix),
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			t.Fatalf("describe alarms %s*: %v", prefix, err)
		}
		for _, alarm := range page.MetricAlarms {
			alarms[aws.ToString(alarm.AlarmName)] = alarm
		}
	}
	return alarms
}

func TestAuthorityAlarms_DimensionsMatchPublisher(t *testing.T) {
	if testConfig.CWClient == nil {
		t.Skip("CloudWatch client not configured")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	deployed := describeAuthorityAlarms(ctx, t)

	cases := authorityAlarmCases()
	resolved := 0 // subtests run synchronously, so no lock is needed
	for _, tc := range cases {
		tc := tc
		t.Run(tc.alarmName, func(t *testing.T) {
			alarm, found := deployed[tc.alarmName]
			if !found {
				// The runtime slice is gated per environment; skip rather than
				// fail so this fence is updated deliberately. An all-skip fails
				// the parent below.
				t.Skipf("alarm %s not found — the Authority runtime may be dark in this env; update this test if the name changed", tc.alarmName)
			}
			resolved++

			wantNamespace := authorityMetricsNamespace
			if len(tc.wantDims) == 1 {
				if _, lambdaKeyed := tc.wantDims["FunctionName"]; lambdaKeyed {
					wantNamespace = authorityLambdaNamespace
				}
			}
			if aws.ToString(alarm.Namespace) != wantNamespace {
				t.Fatalf("alarm %s namespace = %q, want %q", tc.alarmName, aws.ToString(alarm.Namespace), wantNamespace)
			}
			if !dimsEqual(alarm.Dimensions, tc.wantDims) {
				t.Fatalf("alarm %s dimensions = %v, want %v (must match the %s dim set exactly, or the alarm watches a non-existent stream and never fires — issues #968, #3455)",
					tc.alarmName, alarmDimsToMap(alarm.Dimensions), tc.wantDims, tc.publisher)
			}
			// notBreaching is correct for a zero-baseline counter, but it is
			// also what makes a wrong dim set look healthy. Pin it so the
			// choice stays deliberate and the ledger's page receipt stays the
			// real proof.
			if aws.ToString(alarm.TreatMissingData) != "notBreaching" {
				t.Fatalf("alarm %s treat_missing_data = %q, want notBreaching", tc.alarmName, aws.ToString(alarm.TreatMissingData))
			}
			t.Logf("alarm %s dimensions = %v (matches %s)", tc.alarmName, alarmDimsToMap(alarm.Dimensions), tc.publisher)
		})
	}

	if resolved == 0 {
		t.Fatalf("none of the %d expected Connector Authority alarms resolved (looked for layerv-nhp-%s-ca-*) — every alarm name likely changed and this fence is silently disabled. Update authorityAlarmCases (issue #3455).",
			len(cases), testConfig.Environment)
	}
}

// TestAuthorityAlarms_AreActionable is the fence for the condition #3455 exists
// to remove: 11 deployed alarms with AlarmActions: []. It sweeps every deployed
// alarm under the Authority prefix — metric AND composite — rather than a
// name list, so an alarm family added later without routing still fails here.
func TestAuthorityAlarms_AreActionable(t *testing.T) {
	if testConfig.CWClient == nil {
		t.Skip("CloudWatch client not configured")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	prefix := fmt.Sprintf("layerv-nhp-%s-ca-", testConfig.Environment)
	var unrouted []string
	total := 0
	destinations := map[string]int{}

	paginator := cloudwatch.NewDescribeAlarmsPaginator(testConfig.CWClient, &cloudwatch.DescribeAlarmsInput{
		AlarmNamePrefix: aws.String(prefix),
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			t.Fatalf("describe alarms %s*: %v", prefix, err)
		}
		for _, alarm := range page.MetricAlarms {
			total++
			if len(alarm.AlarmActions) == 0 {
				unrouted = append(unrouted, aws.ToString(alarm.AlarmName))
				continue
			}
			destinations[strings.Join(alarm.AlarmActions, ",")]++
		}
		for _, alarm := range page.CompositeAlarms {
			total++
			if len(alarm.AlarmActions) == 0 {
				unrouted = append(unrouted, aws.ToString(alarm.AlarmName))
				continue
			}
			destinations[strings.Join(alarm.AlarmActions, ",")]++
		}
	}

	if total == 0 {
		t.Skipf("no alarms found under %s* — the Authority runtime may be dark in this env", prefix)
	}
	if len(unrouted) > 0 {
		sort.Strings(unrouted)
		t.Fatalf("%d of %d Connector Authority alarms have no alarm_actions and can never page an operator: %s (issue #3455)",
			len(unrouted), total, strings.Join(unrouted, ", "))
	}
	// A family quietly pointed at a different topic still satisfies "has an
	// action", so require one reviewed destination set across the whole graph.
	if len(destinations) != 1 {
		keys := make([]string, 0, len(destinations))
		for k := range destinations {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		t.Fatalf("Connector Authority alarms route to %d different destination sets, want exactly 1: %s (issue #3455)",
			len(destinations), strings.Join(keys, " | "))
	}
	t.Logf("all %d Connector Authority alarms route to a single operator destination set", total)
}
