//go:build smoke

package smoke

// Tier 1: CloudWatch Logs Insights scan against the AC log group for the
// re-registration-loop signatures fixed by PR #1685 (issue #1680).
//
// Per CLAUDE.md, Tier 1 = "regression guards for fenced bug classes"; this
// test fences the operational signature of #1680 and is the canonical
// regression guard for that bug class. The implementation is indirect
// (log scanning rather than direct device-pool probe — a direct probe is
// not currently exposed from outside the process), but the contract being
// fenced is a specific bug class fresh from a fixed PR, which matches the
// Tier 1 description rather than Tier 3's "capability coverage / informational
// telemetry" framing.
//
// Threshold derivation lives at the const itself; recalibration during the
// 30-day burn-in window is tracked in #1694.

import (
	"fmt"
	"testing"
)

// nhpACLogGroup mirrors nhpServerLogGroup. AC log group convention:
// /layerv/nhp/{env}/ac (no /cell0/ segment because ACs are not
// cell-partitioned the way servers are). The format is owned by the
// aws_cloudwatch_log_group.ac resource in terraform/modules/ac/main.tf
// (resource-name reference rather than a line number so this stays
// valid as the Terraform file evolves) — verified 2026-05-06 against
// the active sandbox AC ASG.
//
// Reuses smoke-harness helpers from the rest of tests/smoke/:
//   - cwErrorCountField, runLogInsightsQuery — defined in
//     22_server_logs_test.go
//   - requireCWLogs, testConfig — defined in config.go / setup_test.go
func nhpACLogGroup(env string) string {
	return fmt.Sprintf("/layerv/nhp/%s/ac", env)
}

// TestACLogs_NoRedispatchLoopSignature scans the AC log group for the two
// log lines that, in combination, were the operational signature of the
// 2026-05-06 prod cell0 incident (#1680):
//
//  1. "All N connected servers appear down, triggering re-registration"
//     emitted by checkServerHealth when every connected assigned server
//     has missed enough keepalives. In healthy operation this fires only
//     when a server actually fails.
//
//  2. "Refresh NHP_AOL to <addr> failed: peer not found in peer pool"
//     emitted by handleRefreshResponse when the AC's local peer pool
//     rejected the server's NHP_AAK. The bug class evicted the active
//     peer at every keepalive cycle, so this line was firing ~hundreds
//     of times per 15 minutes per AC during the incident.
//
// The PR fixed the eviction; both lines should be effectively absent in
// healthy operation. A non-zero rate that exceeds redispatchLoopThreshold
// indicates the bug class is back (or a near relative is firing) and the
// deploy is untrustworthy.
//
// Threshold: ACs occasionally re-register on legitimate server-side events
// (server termination, blue/green color flip, registration NLB rotation),
// so a small non-zero floor is normal. Production observation during the
// incident peaked at >250 matches per 15 minutes across the cell. Healthy
// steady-state is 0–5. The const redispatchLoopThreshold below sits well
// above the incident floor and well below the incident peak — see the
// derivation block at the const itself for the floor math (~10 ACs × 3
// servers × 2–3 re-registrations per rolling-refresh cycle).
//
// Recalibration plan: this test runs in burn-in mode (per CLAUDE.md rule
// 11, smoke runs report-only until 30 days of green sandbox) — that soak
// window is the right time to observe the actual baseline during a full
// deploy cycle and tune redispatchLoopThreshold before flipping
// continue-on-error to false. #1694 owns the per-environment calibration.
//
// Regression fence for PR #1685 (sync reconcile that ended the prod loop).
func TestACLogs_NoRedispatchLoopSignature(t *testing.T) {
	requireCWLogs(t)

	logGroup := nhpACLogGroup(testConfig.Environment)

	// redispatchLoopThreshold is sized to absorb legitimate deploy churn
	// without tripping on a healthy rolling refresh. The smoke job ships
	// in burn-in posture (continue-on-error=true per CLAUDE.md rule 11)
	// until #1694 lands per-environment recalibration; flipping to
	// continue-on-error=false BEFORE #1694 must not happen, because a
	// false-positive at that point blocks the sandbox deploy.
	//
	// Floor estimate: ~10 ACs × 3 servers × 2–3 re-registrations per
	// rolling-refresh cycle = 60–90 matches in the lookback window
	// during an active deploy. Healthy steady state: 0–5. Prod incident
	// peak: >250 in 15 min across the cell.
	//
	// Threshold 150 sits ~2× above the active-deploy churn floor and
	// well below the incident peak. The 2× headroom is intentionally
	// conservative for the burn-in window — rather than pin the
	// threshold tight to the modeled floor and rely on report-only mode
	// to absorb false positives, ship a value that doesn't fight the
	// model. #1694 picks up the per-environment calibration based on
	// actual sandbox observation; the burn-in posture exists so the
	// initial value can be revised without operational consequence.
	//
	// Acknowledged blind spot: a regression at 30–50% of incident
	// intensity (75–125 matches/15min) silently passes this fence. The
	// metric layer (MetricReconcileOverlap, #1693) is the primary
	// signal; this smoke fence is the secondary signal that catches
	// the high-intensity recurrence. #1694 must shrink the blind spot
	// during recalibration before continue-on-error: false flips.
	const redispatchLoopThreshold = 150
	const lookbackMinutes = 15

	// LOAD-BEARING: these query strings substring-match against the
	// human-readable text of two specific log.Warning emissions in
	// endpoints/ac/registration.go (checkServerHealth and
	// handleRefreshResponse, respectively). A future refactor that softens
	// or rewords those log lines silently breaks this fence — there is no
	// compile-time link between the smoke query and the emission site.
	// #1714 tracks adding a stable structured tag at the emission sites
	// so this fence becomes refactor-safe; until that lands, treat these
	// query strings as part of the public contract of the AC log surface.
	cases := []struct {
		name     string
		query    string
		errLabel string
	}{
		{
			name: "AllServersAppearDown",
			query: `filter @message like /servers appear down, triggering re-registration/
| stats count(*) as ` + cwErrorCountField,
			errLabel: "checkServerHealth re-registration trigger",
		},
		{
			name: "RefreshAOLPeerNotFound",
			query: `filter @message like /Refresh NHP_AOL to .* failed: peer not found in peer pool/
| stats count(*) as ` + cwErrorCountField,
			errLabel: "AC-side peer-pool rejection on keepalive",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			matches := runLogInsightsQuery(t, logGroup, tc.query, lookbackMinutes)
			if matches > redispatchLoopThreshold {
				t.Fatalf("found %d %s log line(s) in %s over the last %dm — threshold is %d. PR #1685 (issue #1680) regression class may be active.",
					matches, tc.errLabel, logGroup, lookbackMinutes, redispatchLoopThreshold)
			}
			// Stable prefix so #1694's burn-in observer can grep smoke logs
			// for the per-deploy baseline without parsing free-form Logf.
			t.Logf("smoke-baseline ac_redispatch_loop case=%s matches=%d window_minutes=%d threshold=%d log_group=%s",
				tc.name, matches, lookbackMinutes, redispatchLoopThreshold, logGroup)
		})
	}
}
