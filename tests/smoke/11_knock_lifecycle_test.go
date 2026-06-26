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
