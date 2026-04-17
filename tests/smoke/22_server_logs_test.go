//go:build smoke

package smoke

// Tier 3: CloudWatch Logs Insights scans for known error patterns
// in the nhp-server log group. A zero-match result means the
// regression class hasn't manifested in the last 15 minutes.
//
// Fences:
//   PR #985 — RedirectTarget.Validate errors (built invalid drain target)
//   PRs #761/#820 — forward recursion / too-many-pending-forwards
//
// Tier 3 (not Tier 1) because these are indirect observation via log
// scanning — they depend on the server actually having served enough
// production traffic in the 15-minute lookback window to expose the
// bug class. A Tier 1 fence for the same bugs would be a direct
// endpoint assertion; that belongs in the 01_/02_ range when the
// specific HTTP shape is stable enough to assert on.

import (
	"context"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	cwltypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
)

// cwErrorCountField is the field name every log-scan query in this
// file aggregates under (`stats count(*) as errorCount`). Single
// source of truth for both query construction and result parsing so
// a rename in one place doesn't silently skip extraction in the other.
const cwErrorCountField = "errorCount"

// nhpServerLogGroup derives the log group name from the environment.
// The log group follows the convention /layerv/nhp/{env}/cell0/server,
// verified 2026-04-09 against sandbox.
func nhpServerLogGroup(env string) string {
	return fmt.Sprintf("/layerv/nhp/%s/cell0/server", env)
}

// runLogInsightsQuery starts a CloudWatch Logs Insights query (which
// must aggregate under cwErrorCountField) and polls until complete,
// returning the parsed errorCount value.
//
// The query is expected to be an aggregation, so getResp.Results
// returns exactly one row containing the count field — reading
// len(Results) would always yield 1 regardless of actual matches
// and silently mask regressions.
// cwLogsQueryTimeout bounds both the CWL API context and the polling
// deadline. Single source of truth so a slow GetQueryResults call
// can't outlive the polling loop's own timeout expectation.
const cwLogsQueryTimeout = 45 * time.Second

func runLogInsightsQuery(t *testing.T, logGroup, query string, lookbackMinutes int) int {
	t.Helper()
	t.Logf("CWL query on %s (last %dm): %s", logGroup, lookbackMinutes, query)
	ctx, cancel := context.WithTimeout(context.Background(), cwLogsQueryTimeout)
	defer cancel()

	now := time.Now()
	startResp, err := testConfig.CWLogsClient.StartQuery(ctx, &cloudwatchlogs.StartQueryInput{
		LogGroupName: aws.String(logGroup),
		StartTime:    aws.Int64(now.Add(-time.Duration(lookbackMinutes) * time.Minute).Unix()),
		EndTime:      aws.Int64(now.Unix()),
		QueryString:  aws.String(query),
		Limit:        aws.Int32(10),
	})
	if err != nil {
		t.Fatalf("start CWL Insights query: %v\nlog group: %s\nquery: %s", err, logGroup, query)
	}
	queryID := aws.ToString(startResp.QueryId)

	// Poll with exponential backoff. Fast queries (typical for a 15-min
	// lookback on a small log group) complete in a few hundred ms, so
	// a fixed 2s sleep was eating most of the runtime on the happy path.
	// Start at 250ms, double up to 2s. The ctx deadline above bounds
	// the total time; no separate application deadline needed.
	wait := 250 * time.Millisecond
	const maxWait = 2 * time.Second
	for {
		select {
		case <-ctx.Done():
			t.Fatalf("CWL query %s exceeded %s timeout: %v", queryID, cwLogsQueryTimeout, ctx.Err())
		case <-time.After(wait):
		}
		if wait < maxWait {
			wait *= 2
			if wait > maxWait {
				wait = maxWait
			}
		}
		getResp, err := testConfig.CWLogsClient.GetQueryResults(ctx, &cloudwatchlogs.GetQueryResultsInput{
			QueryId: aws.String(queryID),
		})
		if err != nil {
			t.Fatalf("get CWL query results %s: %v", queryID, err)
		}
		switch getResp.Status {
		case cwltypes.QueryStatusComplete:
			return extractErrorCount(t, queryID, getResp.Results)
		case cwltypes.QueryStatusFailed, cwltypes.QueryStatusCancelled, cwltypes.QueryStatusTimeout:
			t.Fatalf("CWL query %s ended with status %s", queryID, getResp.Status)
		}
	}
}

// extractErrorCount pulls the cwErrorCountField field out of a single-row
// stats query result. CWL returns no rows when the aggregation saw
// zero events, which we treat as zero.
func extractErrorCount(t *testing.T, queryID string, rows [][]cwltypes.ResultField) int {
	t.Helper()
	if len(rows) == 0 {
		return 0
	}
	for _, field := range rows[0] {
		if aws.ToString(field.Field) != cwErrorCountField {
			continue
		}
		count, err := strconv.Atoi(aws.ToString(field.Value))
		if err != nil {
			t.Fatalf("CWL query %s: parse %s=%q: %v", queryID, cwErrorCountField, aws.ToString(field.Value), err)
		}
		return count
	}
	t.Fatalf("CWL query %s returned row without %s field — check the query uses `stats count(*) as %s`",
		queryID, cwErrorCountField, cwErrorCountField)
	return 0 // unreachable
}

// TestServerLogs_NoKnownRegressionErrors scans the nhp-server log
// group for error patterns that indicate specific regression classes
// are active. Zero matches per pattern = healthy.
//
// Each case is a regression fence for a named past incident —
// the test is the live signal that the class hasn't come back.
func TestServerLogs_NoKnownRegressionErrors(t *testing.T) {
	requireCWLogs(t)
	logGroup := nhpServerLogGroup(testConfig.Environment)

	cases := []struct {
		name     string
		query    string
		errLabel string // human-readable class name for the failure message
		fence    string // PR number(s) whose regression this fences
	}{
		{
			name: "InvalidDrainTarget",
			query: `filter @message like /RedirectTarget\.Validate/ or @message like /built invalid drain target/
| stats count(*) as ` + cwErrorCountField,
			errLabel: "RedirectTarget.Validate",
			fence:    "PR #985",
		},
		{
			name: "ForwarderDeadloop",
			query: `filter @message like /too many pending forwards/ or @message like /forward recursion detected/
| stats count(*) as ` + cwErrorCountField,
			errLabel: "forwarder loop",
			fence:    "PRs #761/#820",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			matches := runLogInsightsQuery(t, logGroup, tc.query, 15)
			if matches > 0 {
				t.Fatalf("found %d %s error(s) in %s over the last 15 minutes — %s regression class may be active",
					matches, tc.errLabel, logGroup, tc.fence)
			}
			t.Logf("no %s errors in %s (last 15m)", tc.errLabel, logGroup)
		})
	}
}
