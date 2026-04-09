//go:build smoke

package smoke

// Tier 1: blue/green deployment state consistency.
//
// Capability: the small set of invariants the blue/green flip
// maintains between SSM, ASGs, and the NLB listener config.
//
// Regression fences:
//
//	PR #997 — TF apply could silently undo the blue/green flip by
//	          reverting ignore_changes on listener.default_action and
//	          asg.desired_capacity. TestBlueGreen_ActiveListenersPointToActiveColorTGs
//	          fences the runtime shape of that class.
//	MEMORY gotcha #11 — inactive-color ASG must be scaled to zero
//	                     (or warm-standby min_size) or it can steal
//	                     traffic.
//	MEMORY gotcha #32 — deployed-commit-previous records the rollback
//	                    target. Currently sandbox-skipped — see
//	                    follow-up issue #1010.
//
// All tests in this file read state from SSM parameters under
// /{env}/nhp/{server,ac}/* which the blue/green deploy workflow
// writes. Derived inactive/active ASG and TG ARNs come from those
// params — no NHP_INACTIVE_* env vars needed.

import (
	"context"
	"fmt"
	"regexp"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
)

// sha40Pattern matches a 40-char git commit SHA.
var sha40Pattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

// TestBlueGreen_DeployedCommitSSMParamExists fences the invariant
// that /{env}/nhp/deploy/deployed-commit is a valid 40-char SHA.
// Without it, rollback tooling can't compute the current state.
func TestBlueGreen_DeployedCommitSSMParamExists(t *testing.T) {
	name := "/" + testConfig.Environment + "/nhp/deploy/deployed-commit"
	val, ok := getSSMParameter(t, name)
	if !ok {
		t.Fatalf("SSM parameter %s is missing", name)
	}
	if !sha40Pattern.MatchString(val) {
		t.Fatalf("SSM parameter %s = %q, want a 40-char SHA", name, val)
	}
}

// TestBlueGreen_DeployedCommitPreviousExists fences MEMORY gotcha #32.
// The promote-to-prod pipeline writes deployed-commit-previous before
// overwriting deployed-commit, giving rollback tooling a recorded
// target.
//
// Currently skipped in sandbox because the sandbox deploy workflow
// does not write this param (observed 2026-04-08: only
// deployed-commit + deployed-at are written by build-and-push.yml).
// Tracked as follow-up in issue #1010 — sandbox should match the
// prod invariant so a sandbox rollback has the same ergonomics as
// a prod rollback.
func TestBlueGreen_DeployedCommitPreviousExists(t *testing.T) {
	if testConfig.Environment == "sandbox" {
		t.Skip("sandbox deploy pipeline does not currently write deployed-commit-previous — follow-up needed")
	}
	name := "/" + testConfig.Environment + "/nhp/deploy/deployed-commit-previous"
	val, ok := getSSMParameter(t, name)
	if !ok {
		t.Fatalf("SSM parameter %s is missing — rollback target unrecorded", name)
	}
	if !sha40Pattern.MatchString(val) {
		t.Fatalf("SSM parameter %s = %q, want a 40-char SHA", name, val)
	}
}

// listenerToTGCheck describes a single "listener X should default
// to TG Y" assertion derived from SSM. The ARNs are resolved at
// test time from the active-color SSM params.
type listenerToTGCheck struct {
	label          string // human-readable: "server/udp", "ac/tcp"
	listenerSSM    string // SSM param holding the listener ARN
	activeTGSSMKey string // SSM key pattern, with %s replaced by active color
}

// TestBlueGreen_ActiveListenersPointToActiveColorTGs fences PR #997's
// runtime shape by comparing each NLB listener's default-action TG
// ARN to the active-color TG ARN recorded in SSM. Exact ARN
// comparison (not substring — TG names abbreviate "green" to "grn"
// per the 32-char AWS TG name limit, see
// terraform/modules/compute/blue_green.tf:241).
//
// Wrapped in assertEventually because there's a brief window during
// a blue/green flip where SSM active-color and the listener default
// action are updated via separate API calls.
//
// Regression fence for PR #997.
func TestBlueGreen_ActiveListenersPointToActiveColorTGs(t *testing.T) {
	active := requireActiveColor(t)
	env := testConfig.Environment

	// Three listeners to verify: server UDP (NHP wire protocol),
	// server HTTPS (QURL resolve), AC TCP (customer proxied traffic).
	// If any listener SSM param is missing the test fails rather than
	// skips — all three exist in sandbox and prod today.
	checks := []listenerToTGCheck{
		{
			label:          "server/udp",
			listenerSSM:    "/" + env + "/nhp/server/udp-listener-arn",
			activeTGSSMKey: "/" + env + "/nhp/server/" + active + "-udp-tg-arn",
		},
		{
			label:          "server/https",
			listenerSSM:    "/" + env + "/nhp/server/https-listener-arn",
			activeTGSSMKey: "/" + env + "/nhp/server/" + active + "-https-tg-arn",
		},
		{
			label:          "ac/tcp",
			listenerSSM:    "/" + env + "/nhp/ac/tcp-listener-arn",
			activeTGSSMKey: "/" + env + "/nhp/ac/" + active + "-tcp-tg-arn",
		},
	}

	assertEventually(t, 30*time.Second, 5*time.Second, func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		for _, c := range checks {
			listenerARN, ok := getSSMParameter(t, c.listenerSSM)
			if !ok {
				return fmt.Errorf("%s: listener SSM param %s missing", c.label, c.listenerSSM)
			}
			expectedTG, ok := getSSMParameter(t, c.activeTGSSMKey)
			if !ok {
				return fmt.Errorf("%s: active TG SSM param %s missing", c.label, c.activeTGSSMKey)
			}

			resp, err := testConfig.ELBClient.DescribeListeners(ctx, &elasticloadbalancingv2.DescribeListenersInput{
				ListenerArns: []string{listenerARN},
			})
			if err != nil {
				return fmt.Errorf("%s: describe listener %s: %v", c.label, listenerARN, err)
			}
			if len(resp.Listeners) == 0 {
				return fmt.Errorf("%s: listener %s not found", c.label, listenerARN)
			}

			var actualTG string
			for _, a := range resp.Listeners[0].DefaultActions {
				if a.TargetGroupArn != nil {
					actualTG = *a.TargetGroupArn
					break
				}
			}
			if actualTG == "" {
				return fmt.Errorf("%s: listener %s has no target group in default action", c.label, listenerARN)
			}
			if actualTG != expectedTG {
				return fmt.Errorf("%s: listener default TG = %s, want %s (active color = %s) — PR #997 class drift",
					c.label, actualTG, expectedTG, active)
			}
		}
		return nil
	})
}

// TestBlueGreen_InactiveASGScaledToZeroOrMin fences MEMORY gotcha #11.
// The inactive-color ASGs (derived from the active color via
// inactiveColor()) must have desired_capacity == 0 OR
// desired_capacity == min_size (warm-standby mode). Anything else
// means the inactive color is still consuming capacity and can race
// the active color for traffic.
//
// ASG names come from /{env}/nhp/{server,ac}/{blue,green}-asg-name.
// No env vars needed.
func TestBlueGreen_InactiveASGScaledToZeroOrMin(t *testing.T) {
	inactive := inactiveColor(t)
	env := testConfig.Environment

	components := []struct {
		label    string
		ssmParam string
	}{
		{"server", "/" + env + "/nhp/server/" + inactive + "-asg-name"},
		{"ac", "/" + env + "/nhp/ac/" + inactive + "-asg-name"},
	}

	for _, c := range components {
		t.Run(c.label, func(t *testing.T) {
			asgName, ok := getSSMParameter(t, c.ssmParam)
			if !ok {
				t.Fatalf("SSM parameter %s missing — can't locate inactive %s ASG", c.ssmParam, c.label)
			}
			desired, minSize := describeASGCapacity(t, asgName)
			// Accept desired==0 OR desired==min (warm-standby mode).
			// A non-zero desired that exceeds the warm-standby floor
			// is the regression.
			if desired != 0 && desired != minSize {
				t.Fatalf("inactive %s ASG %s: desired=%d min=%d — expected 0 or warm-standby min",
					c.label, asgName, desired, minSize)
			}
			t.Logf("inactive %s ASG %s: desired=%d min=%d (OK)",
				c.label, asgName, desired, minSize)
		})
	}
}
