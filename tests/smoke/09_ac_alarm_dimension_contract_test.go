//go:build smoke

package smoke

// Tier 1: AC CloudWatch alarm <-> metric-publisher dimension contract.
//
// Regression fence for issue #968. CloudWatch alarms select their metric
// stream by EXACT dimension match, so an alarm whose dimension set doesn't
// match any stream the publisher emits watches a non-existent stream and sits
// in permanent OK (treat_missing_data=notBreaching) — it can never page. Four
// AC alarms were audited in #968; three (disk_usage_high, registration_failure,
// server_connection_failure) had been silently non-functional for months
// because of exactly this mismatch.
//
// This file fences the contract from the *deployed* side, in two parts:
//
//   1. TestACAlarms_DimensionsMatchPublisher — each alarm's configured
//      dimension set equals the canonical set its publisher emits. This is the
//      direct, never-flaky fence: it reads alarm config, no metric timing
//      involved. It also catches the inverse regression the #968 review worried
//      about — a future maintainer "upgrading" the bash-published disk/cert
//      alarms to the 3-dim Go set (or "simplifying" the Go alarms back to
//      {Component}), either of which silently re-breaks them.
//
//   2. TestACAlarms_PublisherStreamsExistForAlarmDims — the dim sets the alarms
//      watch are streams the publisher actually produces, proven via
//      regularly-firing proxy metrics (the failure metrics themselves are only
//      emitted on failure, so a healthy fleet correctly has no stream for them).
//
// The dual-publish unit fences (endpoints/ac/registration_failure_metric_test.go)
// cover that the failure paths emit the base counter at all; this covers that
// the deployed alarms and publisher agree on the dimension set.

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
)

const nhpMetricsNamespace = "LayerV/NHP"

// acAlarmDimCase describes one alarm and the dimension set it must key on to
// match its publisher. The publisher conventions (see
// terraform/modules/ac/monitoring.tf and terraform/CLAUDE.md "Metric / Alarm
// Dim-Set Rules"):
//   - Go-published metrics carry the base set [Component, Environment, Region].
//   - bash/CLI-published maintenance metrics carry [Component] only.
type acAlarmDimCase struct {
	alarmSuffix string            // appended to "layerv-nhp-<env>"
	wantDims    map[string]string // exact dimension set the alarm must use
	publisher   string            // human label for failure messages
}

func acAlarmDimCases() []acAlarmDimCase {
	base := map[string]string{
		"Component":   "AC",
		"Environment": testConfig.Environment,
		"Region":      testConfig.AWSRegion,
	}
	bash := map[string]string{"Component": "AC"}
	return []acAlarmDimCase{
		{"-ac-registration-failure", base, "Go publisher acBaseDims (recordRegistrationFailure)"},
		{"-ac-server-connection-failure", base, "Go publisher acBaseDims (recordServerConnectionFailure)"},
		{"-ac-disk-usage-high", bash, "disk-monitor.sh CLI put-metric-data"},
		{"-ac-cert-sync-failures", bash, "custom-domain-cert-sync.sh CLI put-metric-data"},
	}
}

func TestACAlarms_DimensionsMatchPublisher(t *testing.T) {
	if testConfig.CWClient == nil {
		t.Skip("CloudWatch client not configured")
	}

	cases := acAlarmDimCases()
	resolved := 0 // alarms that actually exist; subtests run synchronously so no lock needed
	for _, tc := range cases {
		tc := tc
		alarmName := fmt.Sprintf("layerv-nhp-%s%s", testConfig.Environment, tc.alarmSuffix)
		t.Run(alarmName, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()

			resp, err := testConfig.CWClient.DescribeAlarms(ctx, &cloudwatch.DescribeAlarmsInput{
				AlarmNames: []string{alarmName},
			})
			if err != nil {
				t.Fatalf("describe alarm %s: %v", alarmName, err)
			}
			if len(resp.MetricAlarms) == 0 {
				// May be disabled in this env (count gated on
				// enable_cloudwatch_alarms / enable_ssm_maintenance) or
				// renamed. Skip rather than fail so the test is updated
				// deliberately — but if ALL of them vanish, the parent fails
				// below (a silently-skipped fence is worse than none).
				t.Skipf("alarm %s not found — may be disabled in this env or renamed; update this test if intentional", alarmName)
			}
			resolved++

			alarmDims := resp.MetricAlarms[0].Dimensions
			if !dimsEqual(alarmDims, tc.wantDims) {
				t.Fatalf("alarm %s dimensions = %v, want %v (must match the %s dim set exactly, or the alarm watches a non-existent stream and never fires — issue #968)",
					alarmName, alarmDimsToMap(alarmDims), tc.wantDims, tc.publisher)
			}
			t.Logf("alarm %s dimensions = %v (matches %s)", alarmName, alarmDimsToMap(alarmDims), tc.publisher)
		})
	}

	// If NONE of the expected alarms resolved, the name_prefix convention or all
	// four alarm names changed — the fence is silently disabled, which is exactly
	// the failure mode #968 is about. Fail loudly rather than green-on-all-skips.
	//
	// This assumes the smoke envs run with alarms enabled. They do:
	// enable_cloudwatch_alarms defaults to true (terraform/modules/ac/variables.tf)
	// and is not overridden in any environment's tfvars, so an all-skip here means
	// a rename, not an intentionally-alarms-disabled env. If a future smoke env
	// sets enable_cloudwatch_alarms=false, gate this Fatalf on that env.
	//
	// It also assumes name_prefix == "layerv-nhp-<env>" (the prefix the alarm
	// names are built from below). That holds across every smoke env:
	// name_prefix = "layerv-nhp-${var.environment}" in terraform/main.tf and both
	// environments/{sandbox,prod}/main.tf (only the non-smoke mgmt account
	// differs). If that ever diverges for a smoke env, update acAlarmDimCases.
	if resolved == 0 {
		t.Fatalf("none of the %d expected AC alarms resolved (looked for layerv-nhp-%s-ac-*) — the name_prefix or every alarm name likely changed; this fence is silently disabled. Update acAlarmDimCases (issue #968).",
			len(cases), testConfig.Environment)
	}
}

func TestACAlarms_PublisherStreamsExistForAlarmDims(t *testing.T) {
	if testConfig.CWClient == nil {
		t.Skip("CloudWatch client not configured")
	}

	baseDims := map[string]string{
		"Component":   "AC",
		"Environment": testConfig.Environment,
		"Region":      testConfig.AWSRegion,
	}

	// Proxy for the Go base-dim path. RegistrationSuccess is published on every
	// AC registration via the same acBaseDims + Publisher.IncrCounter path that
	// recordRegistrationFailure / recordServerConnectionFailure use, so its
	// presence at exactly [Component, Environment, Region] proves the dim set
	// the registration_failure / server_connection_failure alarms watch is one
	// the publisher actually produces. (The failure metrics themselves are
	// absent on a healthy fleet — correctly — so we can't probe them directly.)
	t.Run("RegistrationSuccess_base_dims", func(t *testing.T) {
		streams := listMetricStreams(t, "RegistrationSuccess")
		if len(streams) == 0 {
			t.Skipf("no RegistrationSuccess streams in %s region %s in the last 3h — env may be too fresh or idle; cannot verify base-dim publish path",
				nhpMetricsNamespace, testConfig.AWSRegion)
		}
		if !anyStreamHasExactDims(streams, baseDims) {
			t.Fatalf("RegistrationSuccess has %d stream(s) but none with the exact base dim set %v — the registration_failure/server_connection_failure alarms key on this set and would never fire (issue #968). Streams seen: %s",
				len(streams), baseDims, describeStreams(streams))
		}
	})

	// disk_usage_high keys on {Component=AC}. The #968 regression was
	// disk-monitor.sh tagging InstanceId, which split the data across per-instance
	// streams so the {Component=AC} stream never existed.
	//
	// listMetricStreams filters with RecentlyActive=PT3H (server-side), so the OLD
	// per-instance {Component=AC,InstanceId} streams — which would otherwise linger
	// in ListMetrics for ~14 days after disk-monitor.sh stops publishing them —
	// are excluded. Without that filter this would false-red for two weeks right
	// after the fix deploys, exactly when operators are confirming it. So any
	// InstanceId stream returned here is one STILL being published (a real
	// regression), and a returned {Component=AC} stream means the fix is live.
	//
	// Residual window: PT3H is the only value AWS ListMetrics accepts, so for up
	// to ~3h immediately after the new disk-monitor.sh first runs, the last
	// pre-cutover InstanceId datapoint is still inside PT3H and this would flag it.
	// That is tolerable — the smoke suite runs report-only/burn-in on the promote
	// leg (see the ledger entry) — but an operator confirming the fix in that
	// first 3h window may see one transient red here; it clears once the last
	// InstanceId datapoint ages past 3h.
	t.Run("DiskUsagePercent_component_only", func(t *testing.T) {
		streams := listMetricStreams(t, "DiskUsagePercent")

		activeComponentAC := false
		for _, s := range streams {
			if dimHasName(s.Dimensions, "InstanceId") {
				t.Fatalf("DiskUsagePercent has an actively-published InstanceId stream (%s) in the last 3h — disk-monitor.sh re-introduced the per-instance dimension and the {Component=AC} alarm/dashboard no longer match (issue #968 regression)",
					alarmDimsToMap(s.Dimensions))
			}
			if dimsEqual(s.Dimensions, map[string]string{"Component": "AC"}) {
				activeComponentAC = true
			}
		}
		if !activeComponentAC {
			t.Skipf("no {Component=AC} DiskUsagePercent datapoint in %s region %s in the last 3h — the disk-monitor SSM association may not have run since deploy; cannot verify the {Component=AC} stream the alarm/dashboard key on",
				nhpMetricsNamespace, testConfig.AWSRegion)
		}
	})
}

// dimHasName reports whether the dimension set contains a dimension with the
// given name.
func dimHasName(dims []cwtypes.Dimension, name string) bool {
	for _, d := range dims {
		if aws.ToString(d.Name) == name {
			return true
		}
	}
	return false
}

// listMetricStreams returns the published streams for a metric name in the
// LayerV/NHP namespace (each stream is a distinct dimension set), restricted to
// those active in the last 3 hours. Unfiltered ListMetrics returns any stream
// with a datapoint in the previous ~14 days; RecentlyActive=PT3H (the only value
// AWS supports) is the server-side recency filter that excludes streams which
// have aged out of active publishing — load-bearing for the disk InstanceId
// regression check, see TestACAlarms_PublisherStreamsExistForAlarmDims.
func listMetricStreams(t *testing.T, metricName string) []cwtypes.Metric {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	var out []cwtypes.Metric
	p := cloudwatch.NewListMetricsPaginator(testConfig.CWClient, &cloudwatch.ListMetricsInput{
		Namespace:      aws.String(nhpMetricsNamespace),
		MetricName:     aws.String(metricName),
		RecentlyActive: cwtypes.RecentlyActivePt3h,
	})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			t.Fatalf("list metrics %s/%s: %v", nhpMetricsNamespace, metricName, err)
		}
		out = append(out, page.Metrics...)
	}
	return out
}

func anyStreamHasExactDims(streams []cwtypes.Metric, want map[string]string) bool {
	for _, s := range streams {
		if dimsEqual(s.Dimensions, want) {
			return true
		}
	}
	return false
}

func dimsEqual(got []cwtypes.Dimension, want map[string]string) bool {
	if len(got) != len(want) {
		return false
	}
	for _, d := range got {
		if v, ok := want[aws.ToString(d.Name)]; !ok || v != aws.ToString(d.Value) {
			return false
		}
	}
	return true
}

// alarmDimsToMap renders a dimension set as a map for display/comparison. Go
// prints map[string]string in sorted-key order, so it is the single canonical
// formatter used both for the alarm-vs-want comparison message and for stream
// listings (describeStreams).
func alarmDimsToMap(dims []cwtypes.Dimension) map[string]string {
	m := make(map[string]string, len(dims))
	for _, d := range dims {
		m[aws.ToString(d.Name)] = aws.ToString(d.Value)
	}
	return m
}

func describeStreams(streams []cwtypes.Metric) string {
	out := make([]string, len(streams))
	for i, s := range streams {
		out[i] = fmt.Sprintf("%v", alarmDimsToMap(s.Dimensions))
	}
	return strings.Join(out, "; ")
}
