//go:build smoke

package smoke

// Tier 1: blue/green deployment state consistency.
//
// Capability: the small set of invariants the blue/green flip
// maintains between SSM, ASGs, and the NLB listener config.
//
// Sibling of 04_canary_state_test.go — same tier, same level of
// fence, but for the canary deploy regime that prod uses (#1330).
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
//	                    target. Maintained by both prod
//	                    (promote-to-prod.yml) and sandbox
//	                    (build-and-push.yml, since #1010 was fixed).
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
// The deploy pipeline writes deployed-commit-previous before overwriting
// deployed-commit, giving rollback tooling a recorded target. Both prod
// (promote-to-prod.yml) and sandbox (build-and-push.yml, since #1010 was
// fixed) maintain this invariant — the test runs in both environments.
func TestBlueGreen_DeployedCommitPreviousExists(t *testing.T) {
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
	activeTGSSMKey string // SSM key for the active-color TG ARN this listener must point to
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
	skipIfNotBlueGreen(t)
	// The server and the AC flip blue/green INDEPENDENTLY — each has its own
	// active-color SSM param and its own ASG/TG set, and a per-component deploy
	// can leave them on different colors (observed in sandbox: server=blue
	// while the AC had rolled to green). Resolve each component's expected TG
	// against THAT component's active color; cross-checking the AC listener
	// against the server's color is the bug that surfaced once the server/https
	// short-circuit below was removed for JS-agent envs.
	serverActive := requireActiveColor(t)
	acActive := requireActiveACColor(t)
	env := testConfig.Environment

	// Listeners to verify: AC TCP (customer proxied traffic) always; server/udp
	// (assigned-cell SDK knock), server/internal-udp (relay NHP knock), and
	// server/https (QURL resolve) only where their respective surfaces are
	// deployed. The public UDP listener is an invariant:
	//   - server/udp:          always required
	//   - server/internal-udp: internal relay listener SSM param exists
	//   - server/https:        testConfig.ResolveEndpointEnabled   (qurl_link_js_agent)
	// The public UDP and legacy HTTPS resolve surfaces are independent. Any
	// parameter listed below that is missing fails the test rather than skipping.
	checks := []listenerToTGCheck{
		{
			label:          "ac/tcp",
			listenerSSM:    "/" + env + "/nhp/ac/tcp-listener-arn",
			activeTGSSMKey: "/" + env + "/nhp/ac/" + acActive + "-tcp-tg-arn",
		},
		{
			label:          "server/udp",
			listenerSSM:    "/" + env + "/nhp/server/udp-listener-arn",
			activeTGSSMKey: "/" + env + "/nhp/server/" + serverActive + "-udp-tg-arn",
		},
	}
	internalListenerSSM := "/" + env + "/nhp/server/internal-udp-listener-arn"
	if _, ok := getSSMParameter(t, internalListenerSSM); ok {
		checks = append(checks, listenerToTGCheck{
			label:          "server/internal-udp",
			listenerSSM:    internalListenerSSM,
			activeTGSSMKey: "/" + env + "/nhp/server/" + serverActive + "-internal-udp-tg-arn",
		})
	} else if relayASG, relayDeployed := getSSMParameter(t, "/"+env+"/nhp/relay/asg-name"); relayDeployed {
		t.Fatalf("relay ASG %s is deployed but internal relay listener SSM param %s is missing", relayASG, internalListenerSSM)
	}
	if testConfig.ResolveEndpointEnabled {
		checks = append(checks, listenerToTGCheck{
			label:          "server/https",
			listenerSSM:    "/" + env + "/nhp/server/https-listener-arn",
			activeTGSSMKey: "/" + env + "/nhp/server/" + serverActive + "-https-tg-arn",
		})
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
				return fmt.Errorf("%s: describe listener %s: %w", c.label, listenerARN, err)
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
				return fmt.Errorf("%s: listener default TG = %s, want %s (per %s) — PR #997 class drift",
					c.label, actualTG, expectedTG, c.activeTGSSMKey)
			}
		}
		return nil
	})
}

// TestBlueGreen_InactiveASGScaledToZeroOrMin fences MEMORY gotcha #11.
// The inactive-color ASGs (derived from each component's active color
// via inactiveColorForComponent()) must have desired_capacity == 0 OR
// desired_capacity == min_size (warm-standby mode). Anything else
// means the inactive color is still consuming capacity and can race
// the active color for traffic.
//
// The server and AC flip independently, so the inactive color is resolved
// per component — using the server's inactive color for the AC ASG would
// check the AC's ACTIVE fleet when the colors diverge (server=blue, AC=green).
//
// ASG names come from /{env}/nhp/{server,ac}/{blue,green}-asg-name.
// No env vars needed.
func TestBlueGreen_InactiveASGScaledToZeroOrMin(t *testing.T) {
	skipIfNotBlueGreen(t)
	env := testConfig.Environment

	components := []struct {
		label    string
		ssmParam string
	}{
		{"server", "/" + env + "/nhp/server/" + inactiveColorForComponent(t, "server") + "-asg-name"},
		{"ac", "/" + env + "/nhp/ac/" + inactiveColorForComponent(t, "ac") + "-asg-name"},
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
