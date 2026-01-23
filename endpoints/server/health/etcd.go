package health

import (
	"context"
	"time"
)

// EtcdPinger is the interface for checking etcd connectivity.
// This is implemented by storage backends that use etcd.
type EtcdPinger interface {
	// Ping checks if etcd is reachable and responsive.
	Ping(ctx context.Context) error
}

// EtcdChecker performs health checks against etcd.
type EtcdChecker struct {
	client  EtcdPinger
	timeout time.Duration
}

// EtcdCheckerConfig holds configuration for the etcd health checker.
type EtcdCheckerConfig struct {
	// Client is the etcd client to use for health checks.
	// If nil, the check will be skipped.
	Client EtcdPinger
	// Timeout is the maximum time to wait for the health check.
	// Default: 5 seconds.
	Timeout time.Duration
}

// NewEtcdChecker creates a new etcd health checker.
func NewEtcdChecker(cfg *EtcdCheckerConfig) *EtcdChecker {
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	return &EtcdChecker{
		client:  cfg.Client,
		timeout: timeout,
	}
}

// Name returns the checker name.
func (c *EtcdChecker) Name() string {
	return "etcd"
}

// IsCritical returns true - etcd is critical for NHP server operation.
func (c *EtcdChecker) IsCritical() bool {
	return true
}

// Check performs the etcd health check.
func (c *EtcdChecker) Check(ctx context.Context) *CheckResult {
	start := time.Now()
	result := &CheckResult{
		Name:      c.Name(),
		Timestamp: start,
		Critical:  c.IsCritical(),
	}

	// If no client is configured, skip the check
	if c.client == nil {
		result.Status = CheckStatusSkip
		result.Message = "etcd client not configured"
		result.SetDuration(time.Since(start))
		return result
	}

	// Create timeout context
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	// Ping etcd
	err := c.client.Ping(ctx)
	if err != nil {
		result.Status = CheckStatusFail
		result.Message = "etcd unreachable: " + err.Error()
		result.SetDuration(time.Since(start))
		return result
	}

	result.Status = CheckStatusPass
	result.Message = "etcd is healthy"
	result.SetDuration(time.Since(start))
	return result
}

// Compile-time interface check
var _ Checker = (*EtcdChecker)(nil)
