//go:build smoke

package smoke

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// nRestartsProbeBudget is the collective deadline for all parallel
// per-instance NRestarts probes. Each probe is one SSM round-trip
// (~4-10 s under normal conditions); budget is generous enough to
// absorb eventual-consistency retries without swallowing a real SSM
// outage.
const nRestartsProbeBudget = 2 * time.Minute

// TestServerDeployStability_NoApplicationCrash fences the crash-loop class of
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
// server instance, NRestarts is 0.
//
// A non-zero value is the TRIGGER for a verdict, not the verdict. docker
// failing to start the container increments the counter exactly as a Go
// panic does — exit 125, no Go code executed, healed by Restart=always in
// seconds. This test used to call that a crash and name PR #1096 in the
// failure message; the blue/green deploy gate made the identical mistake
// and sandbox deploy 31340465407 (2026-08-09) paid four hours of blocked
// deploys for it when a transient CloudWatch Logs failure in docker's
// awslogs driver tripped it. So on a non-zero counter this collects the
// evidence that separates the two (see restart_evidence.go) and fails only
// on an application crash, an unconverged unit, or evidence it cannot
// account for.
//
// Tier 1 because:
//   - it fences a specific bug class we've already paid for,
//   - it's an unconditional post-deploy observation that can't be fooled
//     by eventually-consistent retries, and
//   - the failure mode it catches is directly customer-impacting (knock
//     downtime during every deploy).
//
// Regression fence for PR #1096 (panic: send on closed channel).
func TestServerDeployStability_NoApplicationCrash(t *testing.T) {
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
	//
	// MUST use t.Cleanup(cancel), not defer cancel(): t.Parallel()
	// subtests below PAUSE until this parent function body returns,
	// then run in parallel. A defer'd cancel fires on parent return,
	// BEFORE the subtests start, handing them an already-canceled
	// context. t.Cleanup fires after the test AND all its subtests
	// complete -- the correct scope here. See pkg.go.dev docs on
	// testing.T.Cleanup ("Cleanup registers a function to be called
	// when the test (or subtest) and ALL ITS SUBTESTS complete").
	// TestParallelSubtestsDontInheritCanceledCtx below locks this
	// invariant in with no SSM dependency.
	ctx, cancel := context.WithTimeout(context.Background(), nRestartsProbeBudget)
	t.Cleanup(cancel)

	// Probe every instance in parallel — each SSM round-trip is
	// ~4-10s, and a Tier 1 test that could cost ~fleet-size × 10s
	// serial is needlessly slow. A subtest per instance also
	// attributes any failure directly to the offending instance in
	// the test output.
	for _, inst := range instances {
		t.Run(inst, func(t *testing.T) {
			t.Parallel()

			// Load-bearing sanity check: if someone reverts the parent's
			// t.Cleanup(cancel) back to defer cancel(), every SSM
			// SendCommand below will fail with "context canceled" before
			// any real probe runs, which produces a noisy but misleading
			// error message. Short-circuit with a specific pointer at the
			// root cause so the next reader doesn't chase an SSM red
			// herring.
			if err := ctx.Err(); err != nil {
				t.Fatalf("parent ctx canceled before subtest started (ctx.Err=%v); parent must use t.Cleanup(cancel), not defer cancel(), when subtests call t.Parallel() -- see comment above on context creation", err)
			}

			n, err := probeServerNRestarts(ctx, inst)
			if err != nil {
				// Fail closed — if we can't confirm a zero counter, we
				// cannot confirm the deploy was clean.
				t.Fatalf("NRestarts probe failed: %v", err)
			}
			if n == 0 {
				t.Logf("NRestarts=0 (OK)")
				return
			}

			// Non-zero counter: the unit restarted, but the counter alone
			// cannot say whether nhp-server crashed or whether docker
			// failed to start the container at all. Collect the evidence
			// that can. Only reached on the rare unhealthy path, so the
			// healthy fleet still costs one SSM round-trip per instance.
			ev, err := probeServerRestartEvidence(ctx, inst, n)
			if err != nil {
				t.Fatalf("nhp-server NRestarts=%d and the restart-evidence probe failed: %v — "+
					"cannot confirm whether this was an application crash", n, err)
			}

			verdict, detail := classifyRestartEvidence(ev)
			if !verdict.passes() {
				t.Fatalf("nhp-server restart classified as %q. %s", verdict, detail)
			}
			// Passing, but an operator should still see that the container
			// runtime blipped during the deploy.
			t.Logf("WARNING: nhp-server restarted during this deploy, but not because of an "+
				"application crash (%s). %s", verdict, detail)
		})
	}
}

// TestParallelSubtestsDontInheritCanceledCtx is a regression fence for
// the specific bug class that broke TestServerDeployStability_NoApplicationCrash
// (smoke run 24612063961 against main-post-#1112).
//
// The broken pattern: parent test builds a ctx with context.WithTimeout
// and defers cancel; loop creates subtests that call t.Parallel() and
// reference the parent ctx. t.Parallel() subtests pause until the parent
// FUNCTION BODY returns; defer cancel fires on that return, BEFORE the
// subtests unblock; subtests then run with an already-canceled context
// and every network/SSM call fails immediately.
//
// Fix: use t.Cleanup(cancel) instead. Cleanup fires after the test AND
// all its subtests complete (per testing.T.Cleanup godoc).
//
// This fence reproduces the lifecycle without any SSM/AWS dependency:
// if a future edit swaps t.Cleanup back to defer, every subtest below
// hits ctx.Err() != nil and the whole suite fails loudly with the same
// root-cause pointer as the smoke path above.
func TestParallelSubtestsDontInheritCanceledCtx(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)

	for i := 0; i < 3; i++ {
		t.Run(fmt.Sprintf("subtest-%d", i), func(t *testing.T) {
			t.Parallel()
			if err := ctx.Err(); err != nil {
				t.Fatalf("parent ctx was canceled before subtest ran (ctx.Err=%v); parent must use t.Cleanup(cancel), not defer cancel(), when subtests call t.Parallel()", err)
			}
		})
	}
}
