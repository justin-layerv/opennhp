//go:build smoke

package smoke

// Tier 1: canary deployment state consistency.
//
// Capability: the post-deploy invariants the canary state machine
// maintains in SSM. Sibling of 04_blue_green_state_test.go — same
// tier, same level of fence, but for the canary deploy regime that
// prod uses (sandbox runs blue/green).
//
// All tests in this file gate on skipIfNotCanary so the same suite
// runs cleanly against blue/green sandbox and canary prod without
// per-env wiring at the CI level.
//
// Workflow-ordering assumption: TestCanary_StateIdle does a single
// SSM read (no eventual-consistency retry) because smoke runs
// strictly after the canary state machine's complete handler in
// promote-to-prod.yml::deploy-server. A future workflow refactor
// that decouples those (e.g., parallelizing smoke with the canary
// completion) would require revisiting the read shape.
//
// Trust boundary: the SSM keys read here are Terraform-owned. Smoke
// does not validate against ssm:PutParameter writers — anyone with
// PutParameter on /{env}/nhp/{cell_id}/canary/* already has a
// blast radius wider than these tests.
//
// Regression fence for #1330 (smoke assumed blue/green; 4 tests
// broke during the 2026-04-24 prod release because the suite had
// no canary equivalents and the helpers couldn't tell deploy modes
// apart). These tests fence the canary-side state-machine SSM
// contract so the next prod release surfaces a stuck deploy or
// rollback at the smoke gate, not via customer-facing flows.

import (
	"strings"
	"testing"
)

// canaryStateValueIdle is the value the canary orchestrator writes
// after a successful deploy completes (and clears any prior
// rolling_back state on the next deploy's start gate). Smoke runs
// post-deploy in promote-to-prod.yml — by the time we're here, the
// state machine's complete handler has already fired and the SSM
// PutParameter call has already returned (synchronous AWS API, no
// SFN→SSM eventual-consistency window to wait out).
//
// Source: terraform/modules/canary-deployment/lambda/canary_orchestrator.py
//
//	handle_complete: set_ssm_value(SSM_CANARY_STATE_PARAM, 'idle')
const canaryStateValueIdle = "idle"

// canaryComponents are the components for which the canary
// deployment module instantiates a state machine. The
// "enable_canary_deployment ⇒ deploy_ac" precondition on
// aws_ssm_parameter.deploy_mode (terraform/main.tf) guarantees both
// state machines exist whenever this test file runs, so the list is
// safe to hardcode. A future server-only canary env would need that
// precondition relaxed AND this list trimmed in the same PR; a
// future addition (e.g., db) would need the list extended AND a
// matching canary-deployment module instance in terraform/main.tf.
//
// Fixed-size array literal because this is a wire-contract value
// the suite never mutates.
var canaryComponents = [...]string{"server", "ac"}

// TestCanary_StateIdle fences the post-deploy invariant that the
// canary state for both server and AC is "idle". The two non-idle
// values mean different things:
//
//   - "deploying:<timestamp>" — a deploy is in flight or the
//     orchestrator's complete handler never ran. The state machine's
//     handle_prepare hard-blocks the next deploy on this prefix
//     (canary_orchestrator.py::handle_prepare).
//   - "rolling_back" — written by handle_alarm_rollback /
//     handle_rollback. handle_prepare does NOT hard-block this; the
//     next deploy can start, but it indicates the orchestrator's
//     complete handler never ran for the previous deploy, leaving
//     observability blind on the canary state.
//
// Both cases are invisible from customer-facing flows; smoke catches
// them now so operators can intervene before the next release window.
//
// Single-shot read on purpose: handle_complete's PutParameter is
// synchronous, smoke runs after the deploy job in promote-to-prod.yml
// completes, and getSSMParameter t.Fatalfs on infra errors anyway —
// an assertEventually wrapper around the latter would only retry the
// missing/wrong-value branches and provide false reassurance against
// genuinely transient infra errors that can't be retried through it.
func TestCanary_StateIdle(t *testing.T) {
	skipIfNotCanary(t)

	for _, component := range canaryComponents {
		t.Run(component, func(t *testing.T) {
			name := "/" + testConfig.Environment + "/nhp/" + testConfig.CellID + "/canary/" + component + "/state"
			val, ok := getSSMParameter(t, name)
			if !ok {
				t.Fatalf("SSM parameter %s missing — canary state machine not provisioned for %s", name, component)
			}
			// Distinguish the two non-idle modes in the failure
			// message so operators don't have to re-read the file
			// header comment to know what to do.
			switch {
			case val == canaryStateValueIdle:
				return
			case strings.HasPrefix(val, "deploying:"):
				t.Fatalf("SSM parameter %s = %q — orchestrator's complete handler never ran (handle_prepare will hard-block the next deploy)", name, val)
			case val == "rolling_back":
				t.Fatalf("SSM parameter %s = %q — previous deploy rolled back and was never cleared (next deploy can start, but canary observability is blind)", name, val)
			default:
				t.Fatalf("SSM parameter %s = %q — unknown canary state, want %q", name, val, canaryStateValueIdle)
			}
		})
	}
}

// TestCanary_StateMachineARNExists fences the invariant that the
// /{env}/nhp/{cell_id}/canary/{component}/state-machine-arn SSM key
// is present and well-formed. The promote-to-prod workflow reads
// this key to dispatch the right state machine — a missing key
// would route the next deploy through the first-deploy direct-SSM
// fallback in promote-to-prod.yml::deploy-server. We don't attempt
// to fence that workflow-level fall-through here (it's outside
// smoke's reach); we just ensure the input it depends on is present.
//
// LayerV-commercial-partition-only: the ARN prefix check below
// matches "arn:aws:" (commercial) but not "arn:aws-us-gov:" or
// "arn:aws-cn:". Onboarding a Govcloud or China customer requires
// widening the prefix. Grep this marker when you do.
func TestCanary_StateMachineARNExists(t *testing.T) {
	skipIfNotCanary(t)

	// SFN state machine ARN shape:
	//
	//	arn:aws:states:<region>:<account>:stateMachine:<name>
	//
	// "arn:aws:" is commercial-partition only; Govcloud
	// (arn:aws-us-gov:) and China (arn:aws-cn:) would need a broader
	// prefix. LayerV deploys commercial-only today. Including the
	// region segment also catches a wrong-region cross-paste.
	wantPrefix := "arn:aws:states:" + testConfig.AWSRegion + ":"

	for _, component := range canaryComponents {
		t.Run(component, func(t *testing.T) {
			name := "/" + testConfig.Environment + "/nhp/" + testConfig.CellID + "/canary/" + component + "/state-machine-arn"
			val, ok := getSSMParameter(t, name)
			if !ok {
				t.Fatalf("SSM parameter %s missing — canary state machine ARN unrecorded", name)
			}
			if !strings.HasPrefix(val, wantPrefix) {
				t.Fatalf("SSM parameter %s = %q, want prefix %q", name, val, wantPrefix)
			}
			// Full SFN ARN has exactly 7 colon-separated segments.
			// SFN state-machine names are constrained to
			// [a-zA-Z0-9_-]+ (no colons), so > 7 segments is just as
			// malformed as < 7 — use exact equality. "stateMachine"
			// must be the resource-type segment and the name segment
			// must be non-empty.
			parts := strings.Split(val, ":")
			if len(parts) != 7 || parts[5] != "stateMachine" || parts[6] == "" {
				t.Fatalf("SSM parameter %s = %q is not a well-formed SFN state machine ARN", name, val)
			}
		})
	}
}
