//go:build smoke

package smoke

// Tier 2: knock lifecycle — the invariant that every active-color
// server instance reports non-zero AC peers on /health/knock-ready,
// and that a 200 from knock-ready is consistent with a successful
// user-facing resolve flow.
//
// These tests fence the worst failure mode in the whole system:
// the NLB routes knock traffic to a server that reports
// knock-ready but can't actually serve a knock. The Tier 1 health
// test hits ONE endpoint (public HTTPS → whichever instance the
// NLB picks), which is not enough to catch "one instance is stuck
// at zero peers while the others report healthy" — that's exactly
// what these tests cover.

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

// TestKnock_ReadyPerInstanceReflectsACPeers fences fleet-wide
// knock-ready consistency. For every InService instance in the
// active-color server ASG, SSM-probe /health/knock-ready from the
// host loopback and assert:
//
//  1. HTTP exit 0 (curl -sf returns non-zero on 4xx/5xx)
//  2. JSON body parses as a readiness response
//  3. checks.ac_peers.status == "pass"
//  4. message matches the "N AC peer(s) connected" shape with N>0
//
// The per-instance probe is what distinguishes this from the
// public-HTTPS health test: a broken single instance hiding
// behind the NLB round-robin will only be caught by iterating
// every instance directly.
func TestKnock_ReadyPerInstanceReflectsACPeers(t *testing.T) {
	skipIfNoSSMProbes(t)
	asgName := requireActiveServerASG(t)

	instances := describeInServiceInstances(t, asgName)
	if len(instances) == 0 {
		t.Fatalf("no InService instances in ASG %s", asgName)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	for _, instance := range instances {
		body, err := probeHealthKnockReadyFromHost(ctx, instance)
		if err != nil {
			t.Errorf("instance %s: curl /health/knock-ready failed: %v", instance, err)
			continue
		}

		var parsed healthReadyResponse
		if err := json.Unmarshal([]byte(body), &parsed); err != nil {
			t.Errorf("instance %s: parse knock-ready body: %v\nbody: %s",
				instance, err, truncate([]byte(body), 256))
			continue
		}

		ac, ok := parsed.Checks["ac_peers"]
		if !ok {
			t.Errorf("instance %s: ac_peers check missing from knock-ready body", instance)
			continue
		}
		if ac.Status != "pass" {
			t.Errorf("instance %s: ac_peers.status=%q want pass (message=%q)",
				instance, ac.Status, ac.Message)
			continue
		}

		m := knockReadyPeerCountPattern.FindStringSubmatch(ac.Message)
		if m == nil {
			t.Errorf("instance %s: ac_peers.message=%q does not match %q",
				instance, ac.Message, knockReadyPeerCountPattern.String())
			continue
		}
		if m[1] == "0" {
			t.Errorf("instance %s: peer count is zero (message=%q)", instance, ac.Message)
		}
	}
}

// TestKnock_ReadyConsistentWithUserResolve is the lie detector for the
// "knock-ready=200 but resolve fails" direction — i.e., the gate
// promises NLB the server can serve a knock, then doesn't.
//
// Both the knock-ready probe and the resolve attempt go through the
// public NLB. AWS NLB hashes each new TCP connection by 5-tuple (or
// 3-tuple for UDP) over the healthy-target set — so two independent
// HTTPS calls from the same client are independent hashes and not
// guaranteed to land on the same server instance. That asymmetry
// shapes the outcomes:
//
//	knock-ready = 200 AND resolve succeeds → healthy (pass)
//	knock-ready = 503 AND resolve fails    → consistent unhealthy (pass)
//	knock-ready = 200 AND resolve fails    → the server is lying
//	                                         to the NLB (FAIL)
//	knock-ready = 503 AND resolve succeeds → NLB routed resolve to a
//	                                         healthier instance than
//	                                         the one knock-ready
//	                                         landed on; expected
//	                                         multi-instance behavior,
//	                                         informational only.
//
// The fourth case is informational because the two probes are
// routed by NLB independently — the asymmetry is a property of the
// routing, not of the gate. Sustained per-instance failures are
// surfaced by TestKnock_ReadyPerInstanceReflectsACPeers via SSM.
func TestKnock_ReadyConsistentWithUserResolve(t *testing.T) {
	ctx := context.Background()

	// Probe public knock-ready once.
	resp, body := doGet(t, testConfig.NHPServerBaseURL, "/health/knock-ready", nil)
	knockReady200 := resp.StatusCode == 200
	if !knockReady200 && resp.StatusCode != 503 {
		t.Fatalf("knock-ready returned unexpected status %d (body: %s)",
			resp.StatusCode, truncate(body, 200))
	}
	// X-Request-ID is set by endpoints/server/requestid.go's middleware
	// on every HTTP response; it links this probe to the matching
	// server-side request log line in CloudWatch. NLB itself doesn't
	// add a target-identifying header, so this server-generated ID is
	// the best handle the client has without SSM-probing every
	// instance.
	knockReadyRequestID := extractRequestID(resp)

	// Attempt a full mint → resolve → 302 flow. We call MintQURL
	// and doGetNoRedirect directly (not mintSmokeQURL) because both
	// mint and resolve can fail with a non-t.Fatalf error, and the
	// whole point of this test is to compare their outcomes against
	// knock-ready.
	//
	// Important: do NOT wrap the mint call in a recover(). MintQURL's
	// only hard failure path is requireAuth0 which calls t.Fatal →
	// runtime.Goexit(). recover() does not catch runtime.Goexit, so
	// a defer-recover wrapper here would silently swallow Auth0
	// breakage and let the test report "consistent healthy" against
	// a broken setup. If Auth0 is missing, this test must fatal
	// loudly — the workflow's Auth0-skip guard handles the outer
	// surface.
	resolveRequestID, resolveErr := attemptMintAndResolve(ctx, t)

	// All four quadrants are named explicitly (no `default:`) so the
	// switch body reads 1:1 with the diagnostic table in the test doc.
	// Both request IDs are included in every arm because NLB can route
	// knock-ready and resolve to different instances — the pair of IDs
	// is what lets an operator grep the two instance-side log lines
	// that participated in the observation.
	switch {
	case knockReady200 && resolveErr == nil:
		t.Logf("consistent: knock-ready 200 AND resolve succeeded (knock-ready req_id=%s, resolve req_id=%s)",
			knockReadyRequestID, resolveRequestID)
	case !knockReady200 && resolveErr != nil:
		t.Logf("consistent: knock-ready 503 AND resolve failed (knock-ready req_id=%s, resolve req_id=%s, resolve err=%v)",
			knockReadyRequestID, resolveRequestID, resolveErr)
	case knockReady200 && resolveErr != nil:
		t.Fatalf("inconsistent: knock-ready 200 but resolve FAILED — the server is lying to the NLB. knock-ready req_id=%s, resolve req_id=%s, resolve err: %v",
			knockReadyRequestID, resolveRequestID, resolveErr)
	case !knockReady200 && resolveErr == nil:
		// NLB routed each call to a different instance, and the resolve
		// target was healthy. Not a bug. Logged with both req_ids so
		// flake investigations can correlate against CloudWatch and
		// the per-instance test's output. The nlbAsymmetryTag prefix
		// lets CI aggregation grep frequency without re-parsing (#1214).
		//
		// Note on req_ids: endpoints/server/requestid.go generates a
		// fresh random 16-char hex ID per request when no upstream
		// traceparent / X-Request-ID is provided (the smoke client
		// sends neither), so two probes to the same instance still
		// get different IDs.
		t.Logf("informational %s: knock-ready 503 AND resolve succeeded — NLB routed resolve around the 503 instance (knock-ready req_id=%s, resolve req_id=%s)",
			nlbAsymmetryTag, knockReadyRequestID, resolveRequestID)
	}
}

// nlbAsymmetryTag is the grep-tag prefix emitted by the informational
// "knock-ready 503 AND resolve succeeded" log line. Named so CI
// aggregation in #1214 has a single definition to align against; any
// change here should land alongside a change to the aggregator.
const nlbAsymmetryTag = "nlb_asymmetry=1"

// attemptMintAndResolve mints a QURL and attempts to resolve it,
// returning the resolve response's X-Request-ID (for CloudWatch
// correlation) plus a non-nil error on any failure short of a hard
// fatal. Used only by TestKnock_ReadyConsistentWithUserResolve,
// which needs to compare the resolve outcome against an independent
// knock-ready probe and — crucially on a multi-instance NLB fleet —
// log the resolve-side instance handle even when resolve fails.
//
// The mint is via MintQURL (not the test-fataling mintSmokeQURL
// wrapper) so that a transient mint failure can be captured as part
// of the "resolve fails" side of the lie-detector comparison.
//
// Callers must invoke this from a test that has Auth0 set up —
// if Auth0 is missing, MintQURL's internal requireAuth0 call
// will t.Fatal, which is the intended behavior.
//
// On mint failure, returns requestIDMissing (the same sentinel used
// for "response had no X-Request-ID"): the caller's log always carries
// the accompanying err, so a single sentinel keeps the log grammar
// uniform.
func attemptMintAndResolve(ctx context.Context, t *testing.T) (requestID string, err error) {
	t.Helper()
	// 120s TTL matches the happy-path tests in 10_resolve_test.go
	// (mintSmokeQURL uses the same value). The test body completes
	// in well under a second; the TTL is a cleanup fallback in
	// case t.Cleanup is preempted.
	minted, err := MintQURL(ctx, t, MintOptions{
		Label:     t.Name(),
		TargetURL: "https://example.com",
		ExpiresIn: "120s",
	})
	if err != nil {
		return requestIDMissing, fmt.Errorf("mint: %w", err)
	}
	t.Cleanup(func() {
		DeleteQURL(context.Background(), t, minted.Data.ResourceID)
	})

	resolveResp, resolveBody := doPostFormNoRedirect(t, testConfig.NHPServerBaseURL,
		"/plugins/qurl", "token="+minted.AccessToken(), nil)
	requestID = extractRequestID(resolveResp)
	if resolveResp.StatusCode != 302 {
		// Include a truncated body in the error so the load-bearing
		// "lying to NLB" fatal carries enough context to diagnose
		// without a CloudWatch trip. 256 bytes is enough to surface
		// a typical JSON error body's status/code/message fields.
		return requestID, fmt.Errorf("resolve status=%d body=%s, want 302",
			resolveResp.StatusCode, truncate(resolveBody, 256))
	}
	return requestID, nil
}
