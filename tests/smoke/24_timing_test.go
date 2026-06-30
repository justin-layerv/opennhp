//go:build smoke

package smoke

// Tier 3: informational timing tests. These tests measure real-world
// latency from the test runner's perspective and LOG the results but
// NEVER FAIL on latency breach.
//
// Infrastructure errors (connection refused, DNS failure, 5xx) still
// fatal the test via doGet/doRequest's t.Fatalf — a test that can't
// reach the endpoint isn't making a timing observation, it's surfacing
// a real problem. "Never fails" applies only to the latency threshold
// decision, not to the ability to collect samples.
//
// Why log-only: emitting metrics or failing on SLO breach commits to
// an SLO the team hasn't formalized yet. Phase 2 follow-up: document
// the SLO in docs/SLOs.md, then enable metric emission and failure
// thresholds.
//
// Why serial sampling: each test collects N sequential samples rather
// than firing them in parallel. Parallel requests would shave wallclock
// but measure connection-pool contention and DNS batching, not the
// per-request latency distribution we want to observe. The resolve
// test (n=3) is additionally serial to avoid racing AC ipset entries
// for the same client IP.

import (
	"math"
	"testing"
	"time"
)

// TestTiming_HealthResponseP95 measures 20 samples of
// /health/live and logs the p95 response time. Does NOT fail.
func TestTiming_HealthResponseP95(t *testing.T) {
	skipIfResolveEndpointDisabled(t) // /health/* lives on the resolve surface; gone under the JS-agent topology
	const samples = 20
	durations := make([]time.Duration, 0, samples)

	for i := 0; i < samples; i++ {
		start := time.Now()
		resp, _ := doGet(t, testConfig.NHPServerBaseURL, "/health/live", nil)
		elapsed := time.Since(start)
		if resp.StatusCode == 200 {
			durations = append(durations, elapsed)
		} else {
			t.Logf("/health/live sample %d: status %d, dropping from distribution", i, resp.StatusCode)
		}
	}

	if len(durations) == 0 {
		t.Log("no successful /health/live samples to measure")
		return
	}

	p95 := percentile(durations, 95)
	median := percentile(durations, 50)
	t.Logf("/health/live timing: median=%s p95=%s (n=%d) — informational only, no SLO threshold",
		median.Round(time.Millisecond), p95.Round(time.Millisecond), len(durations))
}

// TestTiming_KnockReadyMedian measures 20 samples of
// /health/knock-ready and logs the median. Does NOT fail.
func TestTiming_KnockReadyMedian(t *testing.T) {
	skipIfResolveEndpointDisabled(t) // /health/* lives on the resolve surface; gone under the JS-agent topology
	const samples = 20
	durations := make([]time.Duration, 0, samples)

	for i := 0; i < samples; i++ {
		start := time.Now()
		resp, _ := doGet(t, testConfig.NHPServerBaseURL, "/health/knock-ready", nil)
		elapsed := time.Since(start)
		if resp.StatusCode == 200 {
			durations = append(durations, elapsed)
		} else {
			t.Logf("/health/knock-ready sample %d: status %d, dropping from distribution", i, resp.StatusCode)
		}
	}

	if len(durations) == 0 {
		t.Log("no successful /health/knock-ready samples to measure")
		return
	}

	median := percentile(durations, 50)
	p95 := percentile(durations, 95)
	t.Logf("/health/knock-ready timing: median=%s p95=%s (n=%d) — informational only",
		median.Round(time.Millisecond), p95.Round(time.Millisecond), len(durations))
}

// percentile returns the value at the given percentile (0-100) from
// a slice of durations using the nearest-rank method. The input
// slice is NOT sorted in place — a copy is made.
func percentile(durations []time.Duration, pct int) time.Duration {
	if len(durations) == 0 {
		return 0
	}
	sorted := make([]time.Duration, len(durations))
	copy(sorted, durations)
	// Simple insertion sort — fine for n<=20.
	for i := 1; i < len(sorted); i++ {
		key := sorted[i]
		j := i - 1
		for j >= 0 && sorted[j] > key {
			sorted[j+1] = sorted[j]
			j--
		}
		sorted[j+1] = key
	}
	// Nearest-rank method: 1-indexed rank = ceil(p/100 * n), clamped
	// to [1, n]. Convert to a 0-indexed array position.
	//
	// Previously used integer-division rank = pct*n/100, which puts
	// p95 of n=20 at index 19 (the max), not index 18 (the 19th value
	// out of 20) as the method requires. Doesn't matter for today's
	// informational logging but would be wrong when Phase 2 formalizes
	// these as SLO assertions.
	rank := int(math.Ceil(float64(pct) * float64(len(sorted)) / 100.0))
	if rank < 1 {
		rank = 1
	}
	if rank > len(sorted) {
		rank = len(sorted)
	}
	return sorted[rank-1]
}

// TestPercentile fences the nearest-rank rank math so a future
// refactor (e.g. for Phase 2 SLO assertions) doesn't silently shift
// percentile boundaries. Pure-function, no infra required — runs
// under `go test -tags=smoke` alongside the rest of the suite.
func TestPercentile(t *testing.T) {
	ms := func(n int) time.Duration { return time.Duration(n) * time.Millisecond }
	n20 := make([]time.Duration, 20)
	for i := range n20 {
		n20[i] = ms(i + 1) // 1ms..20ms
	}

	cases := []struct {
		name  string
		input []time.Duration
		pct   int
		want  time.Duration
	}{
		{"empty returns zero", nil, 50, 0},
		{"n=1 p50", []time.Duration{ms(7)}, 50, ms(7)},
		{"n=1 p100", []time.Duration{ms(7)}, 100, ms(7)},
		{"n=20 p50 -> 10th value", n20, 50, ms(10)},
		{"n=20 p95 -> 19th value", n20, 95, ms(19)},
		{"n=20 p100 -> max", n20, 100, ms(20)},
		{"pct=0 clamps to first", n20, 0, ms(1)},
		{"unsorted input sorts before ranking",
			[]time.Duration{ms(5), ms(1), ms(3), ms(2), ms(4)}, 80, ms(4)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := percentile(tc.input, tc.pct); got != tc.want {
				t.Fatalf("percentile(%v, %d) = %v, want %v", tc.input, tc.pct, got, tc.want)
			}
		})
	}
}
