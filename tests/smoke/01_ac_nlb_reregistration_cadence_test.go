//go:build smoke

package smoke

// Tier 1: CloudWatch Logs Insights scan against the AC log group for
// the periodic NLB re-registration safety net's emission. The safety
// net (checkPeriodicNLBReregistration in endpoints/ac/registration.go)
// is the only mechanism that catches an AC latched onto a stale-color
// server after a blue/green switch — checkAllUnconnected requires
// every assigned server to be unconnected, which doesn't happen when
// the AC successfully connected to the wrong color.
//
// Indirect observation (log scan) rather than a direct probe: the
// last-NLB-registration timestamp is held in an internal atomic with
// no exported endpoint. Adding one for the smoke harness alone
// violates CLAUDE.md rule 10 ("no test-only endpoints in production
// binaries"). Delete (don't weaken) this fence when the relationship
// is structurally enforced — CLAUDE.md rule 5.
//
// Regression fence for PR #1726.

import (
	"testing"
)

// TestACLogs_NLBReregistrationFiresWithinDeployGate asserts the
// "periodic NLB re-registration triggered" log line appears from at
// least minNLBReregistrationDistinctACs distinct AC log streams in
// the lookback window. A below-threshold result means the safety net
// has stopped firing on most/all of the fleet and the next blue/green
// deploy is one wrong-color latch away from a knock-readiness timeout. The compile-time fence
// (TestNLBReregistration_BoundedByDeployGate) catches a tuning
// regression; this runtime fence catches a "loop disabled" regression
// that compile-time checks cannot see.
//
// Threshold sizing: deliberately set low (2). The chicken-and-egg
// of PR #1726's own deploy puts the lookback partly against the
// pre-fix 30-min cadence and partly against the new 90 s cadence
// after only ~5 min of post-restart activity, so the worst-case
// total during the very first post-merge smoke run is ~0–3 matches.
// Set to 2 so a single fleet-wide tick visible in the lookback is
// the floor — distinguishes "loop alive" from "loop dead" without
// false-positiving on the first deploy. #1694 owns per-environment
// recalibration once steady-state is established; the threshold
// here is intentionally minimal and is expected to rise to ~15
// (well below the steady-state ~30 expected, well above first-deploy
// chicken-and-egg variance) when #1694's burn-in observer reports
// the actual baseline.
//
// Burn-in gating: until #1694 lands a recalibrated threshold, this
// fence runs in report-only mode (continue-on-error: true in
// build-and-push.yml). Flipping to continue-on-error: false on this
// specific test before #1694 is merged is a regression — the
// threshold of 2 is too weak to be load-bearing for a hard CI
// failure.
func TestACLogs_NLBReregistrationFiresWithinDeployGate(t *testing.T) {
	requireCWLogs(t)

	logGroup := nhpACLogGroup(testConfig.Environment)

	const minNLBReregistrationDistinctACs = 2
	const lookbackMinutes = 15

	// LOAD-BEARING: this literal must match
	// endpoints/ac/registration.go::periodicNLBRefreshLogSubstring.
	// Cross-module imports between tests/smoke and endpoints/ac add
	// non-trivial overhead (separate Go modules per CLAUDE.md), so
	// the value is duplicated here and pinned by the unit fence
	// TestCheckPeriodicNLBReregistration_LogFormatStable, which also
	// asserts this smoke file contains the literal verbatim. A reword
	// at the production constant must update this query in lockstep;
	// #1714's structured-tag work closes the duplication permanently.
	//
	// `like "…"` is quoted-literal substring match (NOT a regex), so
	// metacharacters in the production constant cannot silently break
	// this fence. The earlier `like /…/` regex form was a footgun.
	//
	// cwErrorCountField is reused as a generic count-aggregation field
	// even though this test counts a *legitimate* emission, not an
	// error. The misleading name is tracked in #1736 (rename to
	// cwCountField); using it here keeps the field name consistent
	// across the smoke suite until the rename lands.
	//
	// count_distinct(@logStream) (vs raw count(*)) makes the threshold
	// reflect *fleet breadth*, not just total emissions: "≥ 2 distinct
	// ACs emitted" catches a "loop dies on N-1 of N ACs" regression
	// that a raw match count would silently let pass.
	query := `filter @message like "periodic NLB re-registration triggered"
| stats count_distinct(@logStream) as ` + cwErrorCountField

	distinctACs := runLogInsightsQuery(t, logGroup, query, lookbackMinutes)

	if distinctACs < minNLBReregistrationDistinctACs {
		t.Fatalf("only %d distinct AC log stream(s) emitted 'periodic NLB re-registration triggered' "+
			"in %s over the last %dm — minimum is %d. The safety net the blue/green "+
			"post-switch gate (verify-knock-ready.sh) and the canary state machine "+
			"both depend on may have been disabled or its cadence pushed back fleet-wide. "+
			"This metric is fleet-breadth-keyed so a partial-fleet regression (loop "+
			"dies on N-1 of N ACs) is still caught. See "+
			"endpoints/ac/registration.go::checkPeriodicNLBReregistration and the "+
			"PR #1726 comment block on DefaultNLBReregistrationInterval. "+
			"FIRST CHECK ASSIGNED-SERVER REACHABILITY, not the loop itself: when ACs "+
			"cannot reach their assigned servers' private IPs on UDP 62206, "+
			"checkAllUnconnected re-registers through the NLB every ~30s, that keeps "+
			"resetting lastNLBRegistrationNano, and the periodic loop never reaches its "+
			"interval — so a pure connectivity break presents here as a silent loop. "+
			"Grep the AC log group for 'Failed to connect to assigned server'; if it is "+
			"there, the fault is the server security group's UDP 62206 ingress, not cadence.",
			distinctACs, logGroup, lookbackMinutes, minNLBReregistrationDistinctACs)
	}

	// Stable prefix so #1694's burn-in observer can grep smoke logs
	// for the per-deploy baseline without parsing free-form Logf,
	// matching the convention established in
	// 09_ac_redispatch_loop_test.go.
	//
	// expected_distinct_acs_sandbox is the AC fleet size in the
	// sandbox tfvars (`ac_min_capacity = 3`); since each AC fires
	// the periodic loop independently, every healthy AC contributes
	// at least one match to the lookback window at 90s cadence. Prod
	// fleet sizes differ; #1694's burn-in observer recalibrates
	// per-environment from observed runtime values.
	const expectedDistinctACsSandbox = 3
	t.Logf("smoke-baseline ac_nlb_reregistration_cadence distinct_acs=%d window_minutes=%d threshold=%d expected_distinct_acs_sandbox=%d log_group=%s",
		distinctACs, lookbackMinutes, minNLBReregistrationDistinctACs, expectedDistinctACsSandbox, logGroup)
}
