//go:build smoke

package smoke

// Tier 1: NHP server health endpoints.
//
// Capability: the /health/* endpoints the NLB and ASG use to gate traffic
// and lifecycle decisions. This file fences:
//
//	PR #991  — knock-ready must reflect AC peer count (not ready's shape)
//	PR #1005 — knock-ready was used as the deploy gate but was wired
//	           against a Docker image that couldn't run its own health probe
//	PR #1006 — AC EIP pool deadlock surfaced as knock-ready flapping after
//	           blue/green flip
//
// Every assertion here is checked against the /health endpoints of the
// deployed nhp-server over public HTTPS. No SSM probes — this file is
// safe to run in prod on day 1.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"testing"
	"time"
)

// healthLiveResponse matches the minimum shape the server returns from
// /health/live. Extra fields are ignored.
type healthLiveResponse struct {
	Status  string `json:"status"`
	Service string `json:"service"`
}

// healthReadyResponse matches /health/ready and /health/knock-ready.
type healthReadyResponse struct {
	Status string                      `json:"status"`
	Checks map[string]*healthCheckItem `json:"checks"`
}

type healthCheckItem struct {
	Name     string `json:"name"`
	Status   string `json:"status"`
	Message  string `json:"message"`
	Critical bool   `json:"critical"`
}

// TestHealthLive_Returns200 fences the "/health/live is the simplest
// possible liveness check" contract: it must always return 200 with
// status=healthy, regardless of dependencies, middleware ordering, or
// AC peer count.
//
// Regression fence for PR #991 (middleware ordering bugs could move
// health behind auth; this is the canary that surfaces it immediately).
func TestHealthLive_Returns200(t *testing.T) {
	// /health/* lives on the nhp-server HTTP surface at NHPServerBaseURL.
	// Envs running the JS-agent + relay topology take nhp-server private
	// (no public resolve.qurl.link), so this fence skips there and runs
	// where the surface is live (prod + the localhost stack). The relay's
	// own /health/live is ALB-internal-only and not a substitute.
	skipIfResolveEndpointDisabled(t)
	resp, body := doGet(t, testConfig.NHPServerBaseURL, "/health/live", nil)
	assertStatusCode(t, resp, 200)

	var parsed healthLiveResponse
	unmarshalJSON(t, body, &parsed)

	if parsed.Status != "healthy" {
		t.Fatalf("status = %q, want healthy", parsed.Status)
	}
	if parsed.Service == "" {
		t.Fatalf("service field is empty — the server isn't identifying itself")
	}
}

// TestHealthReady_NoCriticalFailures fences the /health/ready
// contract: the endpoint returns 200, top-level status is in
// {healthy, degraded}, and no critical check has status "fail".
// Deliberately does NOT hardcode a specific check name (like
// "storage" or "etcd") so this test doesn't need updating every
// time the health manager's checker registration changes — the
// invariant is "zero critical failures", not "this specific check
// exists."
func TestHealthReady_NoCriticalFailures(t *testing.T) {
	skipIfResolveEndpointDisabled(t)
	resp, body := doGet(t, testConfig.NHPServerBaseURL, "/health/ready", nil)
	assertStatusCode(t, resp, 200)

	var parsed healthReadyResponse
	unmarshalJSON(t, body, &parsed)

	if parsed.Status != "healthy" && parsed.Status != "degraded" {
		t.Fatalf("status = %q, want healthy or degraded\nbody: %s", parsed.Status, truncate(body, 512))
	}

	if len(parsed.Checks) == 0 {
		t.Fatalf("/health/ready has no checks registered — the readiness manager is empty\nbody: %s", truncate(body, 512))
	}

	for name, c := range parsed.Checks {
		if c.Critical && c.Status == "fail" {
			t.Fatalf("critical check %q is failing: status=%q message=%q\nbody: %s",
				name, c.Status, c.Message, truncate(body, 512))
		}
	}
}

// TestHealthStartup_Returns200 fences the contract the Kubernetes-style
// startup probe is supposed to provide: once the server has finished
// booting, /health/startup returns 200. Before #1011's fix, nothing
// flipped startupReady from inside the process — the readiness checks
// auto-flip it but only when CheckStartup is called within the
// StartupTimeout window, and the first external probe typically arrives
// after that window has elapsed. The fix added an in-process warmer
// (HttpServer.warmStartupProbe) that polls CheckStartup until it
// succeeds or the deadline passes.
//
// Regression fence for PR #1119 (warmStartupProbe goroutine).
//
// Wrapped in assertEventually because the warmer's first probe + the
// 2s tick + a freshly-rolled instance landing inside its 60s startup
// window can produce a single-shot 503 even on a healthy fleet. The
// retry budget aligns this test with TestHealthKnockReady_ReflectsACPeerCount
// below, which absorbs the same convergence window.
func TestHealthStartup_Returns200(t *testing.T) {
	skipIfResolveEndpointDisabled(t)
	assertEventually(t, postFlipMaxWait, postFlipPollInterval, func() error {
		resp, body := doGet(t, testConfig.NHPServerBaseURL, "/health/startup", nil)
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("/health/startup = %d; body=%s", resp.StatusCode, truncate(body, 512))
		}
		return nil
	})
}

// knockReadyPeerCountPattern matches the ac_peers check's message
// field. The server emits exactly two shapes today, both expressed as
// anchored alternates so drift on either side breaks the regex
// instead of silently matching a mutated suffix:
//
//	"3 AC peer(s) connected"
//	"3 AC peer(s) connected (cached, live=0 for 5s, within 30s grace)"
//
// The cached-suffix variant is emitted by ACPeerChecker during its
// debounce grace window, when the live count has briefly dropped to 0
// but a previously-seen non-zero count is still within the window.
// The captured digit is the cached count in that variant (the "live"
// count when the grace marker is absent), so the existing
// m[1] != "0" assertion retains the same semantic in both shapes.
//
// The server formats both variants in endpoints/server/health/acpeer.go.
// Any drift there breaks this regex — that's intentional: the smoke
// suite is the place downstream consumers learn the contract changed.
var knockReadyPeerCountPattern = regexp.MustCompile(
	`^(\d+) AC peer\(s\) connected( \(cached, live=0 for \d+[^,]+, within \S+ grace\))?$`,
)

// Post-flip convergence retry budget. Shared between the
// knock-ready health tests (Tier 1) and the resolve happy-path
// tests (Tier 2 in 10_resolve_test.go). The names are neutral
// ("postFlip*") because the same 10-15s convergence window affects
// both code paths — after a blue/green flip, the NLB may route
// to servers that haven't fully registered their AC peers yet.
//
// The window is sized for the worst-case observed at 2026-04-08 on
// sandbox. maxWait=20s gives headroom without masking a genuinely
// broken flip. pollInterval=5s produces 4 attempts, enough to
// distinguish "mid-flip" from "broken" while keeping log output
// legible.
//
// Negative-path tests (unknown/malformed tokens, access-denied
// pages) do NOT get a retry budget — their expected behavior (403)
// is always active and a single flaky fire is itself a signal.
const (
	postFlipMaxWait      = 20 * time.Second
	postFlipPollInterval = 5 * time.Second
)

// TestHealthKnockReady_ReflectsACPeerCount fences the load-bearing
// invariant that knock-ready returns 200 iff at least one AC peer is
// connected. Three overlapping assertions:
//
//  1. HTTP 200
//  2. ac_peers.status == "pass"
//  3. message regex matches AND the captured count is > 0
//
// The triple-check is deliberate: if someone changes the server's
// message format, assertion (3) catches it even if (1) and (2) keep
// reporting healthy for the wrong reason.
//
// Retries with postFlipMaxWait/postFlipPollInterval to tolerate
// transient post-flip windows where the new servers are still
// seeing their first AC connections.
//
// Regression fence for PRs #991, #1005, #1006.
func TestHealthKnockReady_ReflectsACPeerCount(t *testing.T) {
	skipIfResolveEndpointDisabled(t)
	assertEventually(t, postFlipMaxWait, postFlipPollInterval, func() error {
		resp, body := doGet(t, testConfig.NHPServerBaseURL, "/health/knock-ready", nil)
		if resp.StatusCode != 200 {
			return fmt.Errorf("status=%d body=%s", resp.StatusCode, truncate(body, 256))
		}

		var parsed healthReadyResponse
		if err := json.Unmarshal(body, &parsed); err != nil {
			return fmt.Errorf("parse body: %w; body=%s", err, truncate(body, 256))
		}

		ac, ok := parsed.Checks["ac_peers"]
		if !ok {
			return fmt.Errorf("ac_peers check missing; body=%s", truncate(body, 256))
		}
		if ac.Status != "pass" {
			return fmt.Errorf("ac_peers.status=%q want pass (message=%q)", ac.Status, ac.Message)
		}

		m := knockReadyPeerCountPattern.FindStringSubmatch(ac.Message)
		if m == nil {
			return fmt.Errorf("ac_peers.message=%q does not match %q", ac.Message, knockReadyPeerCountPattern.String())
		}
		if m[1] == "0" {
			return fmt.Errorf("ac_peers count is zero (message=%q)", ac.Message)
		}
		return nil
	})
}

// TestHealthKnockReady_ACPeerCheckerIsCritical fences the structural
// guard that the ac_peers check is registered with critical=true.
// Without this, the endpoint could silently return 200 with an
// ac_peers=fail child when zero ACs are connected, which is exactly
// the false-healthy state we can't afford.
func TestHealthKnockReady_ACPeerCheckerIsCritical(t *testing.T) {
	skipIfResolveEndpointDisabled(t)
	_, body := doGet(t, testConfig.NHPServerBaseURL, "/health/knock-ready", nil)

	var parsed healthReadyResponse
	unmarshalJSON(t, body, &parsed)

	ac, ok := parsed.Checks["ac_peers"]
	if !ok {
		t.Fatalf("ac_peers check missing from knock-ready body: %s", truncate(body, 512))
	}
	if !ac.Critical {
		t.Fatalf("ac_peers.critical = false, want true — structural guard for PR #1005 regression class")
	}
}

// TestHealthKnockReady_DistinctFromReady fences the invariant that
// /health/knock-ready and /health/ready have distinct JSON shapes:
// knock-ready includes the ac_peers check, ready does not. A silent
// alias of knock-ready to ready would regress the whole NLB gating
// strategy. Both endpoints returning 200 is fine; their bodies
// differing is the test.
func TestHealthKnockReady_DistinctFromReady(t *testing.T) {
	skipIfResolveEndpointDisabled(t)
	_, readyBody := doGet(t, testConfig.NHPServerBaseURL, "/health/ready", nil)
	_, knockBody := doGet(t, testConfig.NHPServerBaseURL, "/health/knock-ready", nil)

	var ready, knock healthReadyResponse
	unmarshalJSON(t, readyBody, &ready)
	unmarshalJSON(t, knockBody, &knock)

	if _, ok := ready.Checks["ac_peers"]; ok {
		t.Fatalf("/health/ready should NOT include ac_peers check (found in body: %s)", truncate(readyBody, 512))
	}
	if _, ok := knock.Checks["ac_peers"]; !ok {
		t.Fatalf("/health/knock-ready MUST include ac_peers check (body: %s)", truncate(knockBody, 512))
	}
}
