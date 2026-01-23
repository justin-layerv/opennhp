package health

import (
	"context"
	"time"
)

// DynamoDBPinger is the interface for DynamoDB health check operations.
// Storage backends that use DynamoDB should implement this interface.
type DynamoDBPinger interface {
	Ping(ctx context.Context) error
}

// DynamoDBChecker checks DynamoDB connectivity.
type DynamoDBChecker struct {
	client  DynamoDBPinger
	timeout time.Duration
}

// DynamoDBCheckerConfig holds configuration for the DynamoDB checker.
type DynamoDBCheckerConfig struct {
	// Client is the DynamoDB client that implements Ping.
	Client DynamoDBPinger
	// Timeout is the maximum time to wait for the check.
	Timeout time.Duration
}

// NewDynamoDBChecker creates a new DynamoDB health checker.
func NewDynamoDBChecker(cfg *DynamoDBCheckerConfig) *DynamoDBChecker {
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	return &DynamoDBChecker{
		client:  cfg.Client,
		timeout: timeout,
	}
}

// Name returns the identifier for this checker.
func (c *DynamoDBChecker) Name() string {
	return "dynamodb"
}

// IsCritical returns true as DynamoDB is critical for cloud mode operation.
func (c *DynamoDBChecker) IsCritical() bool {
	return true
}

// Check performs the DynamoDB health check.
func (c *DynamoDBChecker) Check(ctx context.Context) *CheckResult {
	start := time.Now()
	result := &CheckResult{
		Name:      c.Name(),
		Timestamp: start,
		Critical:  c.IsCritical(),
	}

	// Handle case where client is not configured
	if c.client == nil {
		result.Status = CheckStatusSkip
		result.Message = "DynamoDB client not configured"
		result.SetDuration(time.Since(start))
		return result
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	// Perform the ping
	if err := c.client.Ping(ctx); err != nil {
		result.Status = CheckStatusFail
		result.Message = err.Error()
	} else {
		result.Status = CheckStatusPass
		result.Message = "DynamoDB connection successful"
	}

	result.SetDuration(time.Since(start))
	return result
}

// Ensure DynamoDBChecker implements Checker interface.
var _ Checker = (*DynamoDBChecker)(nil)
