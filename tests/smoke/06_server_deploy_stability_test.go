//go:build smoke

package smoke

import (
	"context"
	"testing"
	"time"
)

// nRestartsProbeBudget is the collective deadline for all parallel
// per-instance NRestarts probes. Each probe is one SSM round-trip
// (~4-10 s under normal conditions); budget is generous enough to
// absorb eventual-consistency retries without swallowing a real SSM
// outage.
const nRestartsProbeBudget = 2 * time.Minute

// TestServerDeployStability_NRestartsZero fences the crash-loop class of
// bug fixed in PR #1096 (panic: send on closed channel in
// RemoteTransaction.Run cleanup under HandleACOnline load).
//
// The operational signal in that incident was: on every sandbox
// blue/green deploy, the nhp-server process crashed 5–8 times per
// instance as ACs re-registered and raced the transaction cleanup.
// systemd restarted the process with a ~5 s gap each time. The
// verify-knock-ready post-switch probe still "succeeded" because its
// acceptance criterion was "all instances reported ready once within
// 5 minutes" — a state that arrives between crash cycles. The
// verification effectively granted the bug slack instead of catching it.
//
// systemd's NRestarts counter is the crispest, cheapest regression
// signal we have. It is incremented only when the unit exits
// unexpectedly and is re-executed per Restart=; a user-driven
// `systemctl restart` does not bump it. On a healthy freshly-launched
// server instance, NRestarts is 0. Any non-zero value means a panic or
// unexpected exit has happened during this boot.
//
// Tier 1 because:
//   - it fences a specific bug class we've already paid for,
//   - it's an unconditional post-deploy observation that can't be fooled
//     by eventually-consistent retries, and
//   - the failure mode it catches is directly customer-impacting (knock
//     downtime during every deploy).
//
// Regression fence for PR #1096 (panic: send on closed channel).
func TestServerDeployStability_NRestartsZero(t *testing.T) {
	// Prod burns SSM probes in for 30 days before enabling them
	// (CLAUDE.md smoke-test rule 11). Until that clears, skip rather
	// than fail-closed noisily — the sandbox run still fences the bug.
	skipIfNoSSMProbes(t)

	asgName := requireActiveServerASG(t)

	instances := describeInServiceInstances(t, asgName)
	if len(instances) == 0 {
		t.Fatalf("no InService instances in %s — blue/green deploy left the active color empty", asgName)
	}

	// Shared deadline across all parallel probes. If SSM is broken
	// for the fleet (IAM, throttling, partition), a collective
	// deadline-exceeded cancels every in-flight probe at once, which
	// is the right failure shape for a regression fence -- the
	// deploy is untrustworthy until SSM comes back. If the test
	// ever evolves to need per-instance timeout isolation, give
	// each subtest its own context.WithTimeout inside the t.Run body.
	ctx, cancel := context.WithTimeout(context.Background(), nRestartsProbeBudget)
	defer cancel()

	// Probe every instance in parallel — each SSM round-trip is
	// ~4-10s, and a Tier 1 test that could cost ~fleet-size × 10s
	// serial is needlessly slow. A subtest per instance also
	// attributes any failure directly to the offending instance in
	// the test output.
	for _, inst := range instances {
		t.Run(inst, func(t *testing.T) {
			t.Parallel()

			n, err := probeServerNRestarts(ctx, inst)
			if err != nil {
				// Fail closed — if we can't confirm a zero counter, we
				// cannot confirm the deploy was clean.
				t.Fatalf("NRestarts probe failed: %v", err)
			}
			if n != 0 {
				t.Fatalf("nhp-server NRestarts=%d — the process crashed %d time(s) during this deploy. "+
					"This is the regression class fixed by PR #1096 (panic: send on closed channel). "+
					"Investigate journalctl -u nhp-server on this instance before re-deploying.", n, n)
			}
			t.Logf("NRestarts=0 (OK)")
		})
	}
}
