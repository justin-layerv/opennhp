//go:build smoke

package smoke

// Tier 1: AC eBPF object deploy-layout fence.
//
// Capability: when the AC runs FilterMode=EBPFXDP, nhp-acd loads
// eBPF objects from etc/<name>.o relative to its systemd
// WorkingDirectory (/opt/layerv/nhp-ac). The Docker image build guard
// proves the objects exist at /nhp-ac/etc inside the image; this smoke
// proves the same non-empty files survived the user_data docker-cp
// extraction into the host tree that production actually runs.
//
// Regression fence for PR #2810 (image-only eBPF object guard did not
// cover the deployed /opt/layerv/nhp-ac extraction path; see #2812).
//
// This test requires SSM probes and is gated by the active-color AC
// FilterMode. While the active fleet is still in iptables mode it
// skips cleanly. After E5 flips an AC color to EBPFXDP and that color
// becomes active, missing or empty objects are a hard smoke failure
// before promotion continues to the next environment. Standby-color
// pre-flip verification is intentionally out of scope for this smoke
// because requireActiveACASG only targets the serving ASG; standby boot
// risk remains covered by the image guard, and this smoke proves the
// post-flip host layout before promotion to the next environment.
// SSM probe failures remain hard failures even before E5 because the
// test cannot prove it is safe to skip without reading FilterMode.

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestACEBPFObjects_PresentInDeployedLayoutWhenFilterModeEBPFXDP(t *testing.T) {
	skipIfNoSSMProbes(t)
	asgName := requireActiveACASG(t)

	instances := describeInServiceInstances(t, asgName)
	for attempts := 0; len(instances) == 0 && attempts < 3; attempts++ {
		t.Logf("no InService instances in ASG %s; retrying in case the active AC is mid-refresh", asgName)
		time.Sleep(5 * time.Second)
		instances = describeInServiceInstances(t, asgName)
	}
	if len(instances) == 0 {
		t.Fatalf("no InService instances in ASG %s", asgName)
	}

	// Probe instances concurrently so the degraded all-EBPFXDP path is
	// bounded by one instance's retry budget, not by active fleet size.
	ctx, cancel := context.WithTimeout(context.Background(), acEBPFProbeTimeout)
	defer cancel()

	checked := 0
	hadFailures := false
	results := make(chan acEBPFProbeResult, len(instances))
	for _, instance := range instances {
		go func(instance string) {
			results <- probeACEBPFInstance(ctx, instance)
		}(instance)
	}
	for range instances {
		result := <-results
		if result.err != nil {
			t.Errorf("instance %s: %v", result.instanceID, result.err)
			hadFailures = true
			continue
		}
		if !result.checked {
			t.Logf("instance %s: FilterMode=%d; eBPF objects are not load-bearing yet", result.instanceID, result.mode)
			continue
		}

		checked++
	}

	if hadFailures {
		t.FailNow()
	}

	if checked == 0 {
		t.Skip("active AC instances are not running FilterMode=EBPFXDP; eBPF object layout smoke is gated until the E5 flip")
	}
}

const (
	acEBPFProbeAttempts   = 4
	acEBPFProbeRetryDelay = 2 * time.Second
	// Every instance uses at least the FilterMode probe; EBPFXDP
	// instances use two more object probes. Each SSM call can poll for
	// up to ~45s, and each probe can run up to four attempts for
	// SSM/refresh races. Ten minutes budgets the degraded single-
	// instance path with real slack, and concurrent probing keeps wall
	// time from scaling linearly with active fleet size.
	acEBPFProbeTimeout = 10 * time.Minute
)

type acEBPFProbeResult struct {
	instanceID string
	mode       int
	checked    bool
	err        error
}

func probeACEBPFInstance(ctx context.Context, instanceID string) acEBPFProbeResult {
	mode, err := probeACFilterModeWithRetry(ctx, instanceID)
	if err != nil {
		return acEBPFProbeResult{instanceID: instanceID, err: err}
	}
	if mode != acFilterModeEBPFXDP {
		return acEBPFProbeResult{instanceID: instanceID, mode: mode}
	}
	if err := probeACEBPFObjectsPresentWithRetry(ctx, instanceID); err != nil {
		return acEBPFProbeResult{instanceID: instanceID, mode: mode, checked: true, err: err}
	}
	return acEBPFProbeResult{instanceID: instanceID, mode: mode, checked: true}
}

func probeACFilterModeWithRetry(ctx context.Context, instanceID string) (int, error) {
	var lastErr error
	for attempt := 1; attempt <= acEBPFProbeAttempts; attempt++ {
		mode, err := probeACFilterMode(ctx, instanceID)
		if err == nil {
			return mode, nil
		}
		lastErr = err
		if err := waitBeforeACProbeRetry(ctx, attempt); err != nil {
			return 0, fmt.Errorf("read AC FilterMode after attempt %d: %w", attempt, err)
		}
	}
	return 0, fmt.Errorf("read AC FilterMode after %d attempts: %w", acEBPFProbeAttempts, lastErr)
}

func probeACEBPFObjectsPresentWithRetry(ctx context.Context, instanceID string) error {
	var lastErr error
	for attempt := 1; attempt <= acEBPFProbeAttempts; attempt++ {
		err := probeACEBPFObjectsPresent(ctx, instanceID)
		if err == nil {
			return nil
		}
		lastErr = err
		if err := waitBeforeACProbeRetry(ctx, attempt); err != nil {
			return fmt.Errorf("check AC eBPF objects after attempt %d: %w", attempt, err)
		}
	}
	return fmt.Errorf("check AC eBPF objects after %d attempts: %w", acEBPFProbeAttempts, lastErr)
}

func waitBeforeACProbeRetry(ctx context.Context, attempt int) error {
	if attempt >= acEBPFProbeAttempts {
		return nil
	}
	timer := time.NewTimer(acEBPFProbeRetryDelay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
