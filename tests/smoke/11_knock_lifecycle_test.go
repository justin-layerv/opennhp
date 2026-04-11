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

// TestKnock_ReadyConsistentWithUserResolve is the lie detector.
// It probes the public /health/knock-ready endpoint once, then
// immediately attempts a full mint → resolve round-trip. The two
// outcomes must be consistent:
//
//	knock-ready = 200 AND resolve succeeds → healthy (pass)
//	knock-ready = 503 AND resolve fails    → consistent unhealthy (pass)
//	knock-ready = 200 AND resolve fails    → the server is lying
//	                                         to the NLB (FAIL)
//	knock-ready = 503 AND resolve succeeds → the gate is overcautious
//	                                         (fail, but different class)
//
// A lying-to-NLB outcome is the class we care most about — it
// means the deploy gate and the customer see different states.
func TestKnock_ReadyConsistentWithUserResolve(t *testing.T) {
	ctx := context.Background()

	// Probe public knock-ready once.
	resp, body := doGet(t, testConfig.NHPServerBaseURL, "/health/knock-ready", nil)
	knockReady200 := resp.StatusCode == 200
	if !knockReady200 && resp.StatusCode != 503 {
		t.Fatalf("knock-ready returned unexpected status %d (body: %s)",
			resp.StatusCode, truncate(body, 200))
	}

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
	resolveErr := attemptMintAndResolve(ctx, t)

	switch {
	case knockReady200 && resolveErr == nil:
		t.Logf("consistent: knock-ready 200 AND resolve succeeded")
	case !knockReady200 && resolveErr != nil:
		t.Logf("consistent: knock-ready 503 AND resolve failed (%v)", resolveErr)
	case knockReady200 && resolveErr != nil:
		t.Fatalf("inconsistent: knock-ready 200 but resolve FAILED — the server is lying to the NLB. resolve err: %v", resolveErr)
	default:
		t.Fatalf("inconsistent: knock-ready 503 but resolve succeeded — the gate is over-cautious")
	}
}

// attemptMintAndResolve mints a QURL and attempts to resolve it,
// returning a non-nil error on any failure short of a hard fatal.
// Used only by TestKnock_ReadyConsistentWithUserResolve, which
// needs to compare the resolve outcome against an independent
// knock-ready probe. The mint is via MintQURL (not the
// test-fataling mintSmokeQURL wrapper) so that a transient mint
// failure can be captured as part of the "resolve fails" side of
// the lie-detector comparison.
//
// Callers must invoke this from a test that has Auth0 set up —
// if Auth0 is missing, MintQURL's internal requireAuth0 call
// will t.Fatal, which is the intended behavior.
func attemptMintAndResolve(ctx context.Context, t *testing.T) error {
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
		return fmt.Errorf("mint: %w", err)
	}
	t.Cleanup(func() {
		DeleteQURL(context.Background(), t, minted.Data.ResourceID)
	})

	resolveResp, _ := doPostFormNoRedirect(t, testConfig.NHPServerBaseURL,
		"/plugins/qurl", "token="+minted.AccessToken(), nil)
	if resolveResp.StatusCode != 302 {
		return fmt.Errorf("resolve status=%d, want 302", resolveResp.StatusCode)
	}
	return nil
}
