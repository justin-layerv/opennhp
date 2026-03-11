package health

import (
	"context"
	"fmt"
	"time"
)

// ACPeerCounter provides AC connection counts for health checking.
// Implemented by the UDP server to avoid import cycles (health -> server).
type ACPeerCounter interface {
	// ACPeerCount returns the number of connected AC peers.
	ACPeerCount() int
}

// ACPeerChecker checks whether the server has any connected AC peers.
// A server with zero AC connections cannot process knock requests,
// so this checker is used on the NLB knock-traffic health check endpoint
// to prevent routing knock requests to servers that would fail them.
type ACPeerChecker struct {
	counter ACPeerCounter
}

// ACPeerCheckerConfig holds configuration for the AC peer checker.
type ACPeerCheckerConfig struct {
	// Counter provides access to the AC peer count.
	Counter ACPeerCounter
}

// NewACPeerChecker creates a new AC peer health checker.
func NewACPeerChecker(cfg *ACPeerCheckerConfig) *ACPeerChecker {
	return &ACPeerChecker{
		counter: cfg.Counter,
	}
}

// Name returns the checker name.
func (c *ACPeerChecker) Name() string {
	return "ac_peers"
}

// IsCritical returns true — a server with no AC peers cannot serve knock traffic.
func (c *ACPeerChecker) IsCritical() bool {
	return true
}

// Check counts connected AC peers and fails if zero.
func (c *ACPeerChecker) Check(_ context.Context) *CheckResult {
	start := time.Now()
	result := &CheckResult{
		Name:      c.Name(),
		Timestamp: start,
		Critical:  c.IsCritical(),
	}

	if c.counter == nil {
		result.Status = CheckStatusSkip
		result.Message = "AC peer counter not configured"
		result.SetDuration(time.Since(start))
		return result
	}

	count := c.counter.ACPeerCount()
	if count == 0 {
		result.Status = CheckStatusFail
		result.Message = "no AC peers connected"
	} else {
		result.Status = CheckStatusPass
		result.Message = fmt.Sprintf("%d AC peer(s) connected", count)
	}

	result.SetDuration(time.Since(start))
	return result
}

// Compile-time interface check.
var _ Checker = (*ACPeerChecker)(nil)
