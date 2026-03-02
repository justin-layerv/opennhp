package server

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/servicediscovery"
	sdtypes "github.com/aws/aws-sdk-go-v2/service/servicediscovery/types"
	"golang.org/x/sync/singleflight"

	"github.com/OpenNHP/opennhp/nhp/log"
)

// ============================================================================
// Cloud Map Client for Server Health Discovery
// See docs/ARCHITECTURE.md "Stale DynamoDB Assignment Resilience" for details.
//
// This client queries AWS Cloud Map to discover which NHP servers are currently
// healthy. It's used in handleACServerAssignment to filter out stale assignments
// pointing to terminated servers.
//
// Key features:
// - Configurable TTL cache to balance freshness vs API load
// - Fail-open: If Cloud Map is unavailable, we accept ACs directly
// - Thread-safe with RWMutex for concurrent access
// - Singleflight pattern prevents thundering herd on cache refresh
// ============================================================================

const (
	// DefaultCloudMapCacheTTL is the default cache TTL if not configured.
	// 30 seconds balances freshness (catch terminated servers) vs API load.
	DefaultCloudMapCacheTTL = 30 * time.Second

	// DefaultCloudMapOperationTimeout is the default timeout for Cloud Map API calls.
	DefaultCloudMapOperationTimeout = 5 * time.Second
)

// HealthChecker is the interface for checking server health.
// This allows for easy mocking in tests.
type HealthChecker interface {
	// GetHealthyServerIPs returns a set of IP addresses for currently healthy servers.
	GetHealthyServerIPs(ctx context.Context) (map[string]bool, error)

	// InvalidateCache forces the next GetHealthyServerIPs call to refresh.
	InvalidateCache()
}

// CloudMapConfig configures the Cloud Map client.
type CloudMapConfig struct {
	// Region is the AWS region for Cloud Map (e.g., "us-east-2")
	Region string `toml:"Region"`

	// NamespaceName is the Cloud Map namespace (e.g., "nhp.sandbox.internal")
	NamespaceName string `toml:"NamespaceName"`

	// ServiceName is the service name within the namespace (e.g., "server")
	ServiceName string `toml:"ServiceName"`

	// Enabled controls whether Cloud Map health filtering is active.
	// When false, all assigned servers are considered healthy.
	Enabled bool `toml:"Enabled"`

	// CacheTTL is how long to cache Cloud Map discovery results.
	// Default: 30 seconds. Set to 0 to use default.
	CacheTTL int `toml:"CacheTTL"`

	// OperationTimeout is the maximum time for a Cloud Map API call in seconds.
	// Default: 5 seconds. Set to 0 to use default.
	OperationTimeout int `toml:"OperationTimeout"`
}

// GetCacheTTL returns the configured cache TTL or the default.
func (c CloudMapConfig) GetCacheTTL() time.Duration {
	if c.CacheTTL > 0 {
		return time.Duration(c.CacheTTL) * time.Second
	}
	return DefaultCloudMapCacheTTL
}

// GetOperationTimeout returns the configured operation timeout or the default.
func (c CloudMapConfig) GetOperationTimeout() time.Duration {
	if c.OperationTimeout > 0 {
		return time.Duration(c.OperationTimeout) * time.Second
	}
	return DefaultCloudMapOperationTimeout
}

// CloudMapClient queries Cloud Map to discover healthy NHP servers.
// It caches results to avoid excessive API calls and uses singleflight
// to prevent thundering herd on cache refresh.
//
// Implements the HealthChecker interface.
type CloudMapClient struct {
	client           *servicediscovery.Client
	namespaceName    string
	serviceName      string
	cacheTTL         time.Duration
	operationTimeout time.Duration

	// Cache
	cacheMu     sync.RWMutex
	cachedIPs   map[string]bool // Set of healthy server IPs
	cacheExpiry time.Time

	// Singleflight to deduplicate concurrent refresh requests
	sfGroup singleflight.Group
}

// Compile-time check that CloudMapClient implements HealthChecker
var _ HealthChecker = (*CloudMapClient)(nil)

// NewCloudMapClient creates a new Cloud Map client.
func NewCloudMapClient(ctx context.Context, cfg CloudMapConfig) (*CloudMapClient, error) {
	if cfg.NamespaceName == "" {
		return nil, errors.New("cloudmap namespace name is required")
	}
	if cfg.ServiceName == "" {
		return nil, errors.New("cloudmap service name is required")
	}

	// Build AWS config options
	opts := []func(*config.LoadOptions) error{}
	if cfg.Region != "" {
		opts = append(opts, config.WithRegion(cfg.Region))
	}

	// Load AWS config
	awsCfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config for Cloud Map: %w", err)
	}

	client := servicediscovery.NewFromConfig(awsCfg)

	cm := &CloudMapClient{
		client:           client,
		namespaceName:    cfg.NamespaceName,
		serviceName:      cfg.ServiceName,
		cacheTTL:         cfg.GetCacheTTL(),
		operationTimeout: cfg.GetOperationTimeout(),
		cachedIPs:        make(map[string]bool),
	}

	log.Info("Cloud Map client initialized: namespace=%s, service=%s, cacheTTL=%v, timeout=%v",
		cfg.NamespaceName, cfg.ServiceName, cm.cacheTTL, cm.operationTimeout)

	return cm, nil
}

// GetHealthyServerIPs returns a set of IP addresses for currently healthy servers.
// Results are cached to reduce API calls. Uses singleflight to deduplicate
// concurrent refresh requests.
// Returns nil error and empty map if cache is fresh but no healthy servers found.
func (c *CloudMapClient) GetHealthyServerIPs(ctx context.Context) (map[string]bool, error) {
	// Check cache first (read lock)
	c.cacheMu.RLock()
	if time.Now().Before(c.cacheExpiry) && c.cachedIPs != nil {
		// Cache hit - return copy to prevent caller modification
		result := make(map[string]bool, len(c.cachedIPs))
		for k, v := range c.cachedIPs {
			result[k] = v
		}
		c.cacheMu.RUnlock()
		log.Debug("Cloud Map cache hit: %d healthy servers", len(result))
		return result, nil
	}
	c.cacheMu.RUnlock()

	// Cache miss - use singleflight to deduplicate concurrent refresh requests
	result, err, _ := c.sfGroup.Do("refresh", func() (any, error) {
		return c.refreshCache()
	})

	if err != nil {
		return nil, err
	}

	// Return a copy of the result
	ips := result.(map[string]bool)
	copy := make(map[string]bool, len(ips))
	for k, v := range ips {
		copy[k] = v
	}
	return copy, nil
}

// refreshCache fetches fresh data from Cloud Map and updates the cache.
// This is called via singleflight to prevent thundering herd.
func (c *CloudMapClient) refreshCache() (map[string]bool, error) {
	// Double-check cache under write lock (another goroutine in singleflight may have updated)
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()

	if time.Now().Before(c.cacheExpiry) && c.cachedIPs != nil {
		log.Debug("Cloud Map cache hit (after singleflight): %d healthy servers", len(c.cachedIPs))
		return c.cachedIPs, nil
	}

	// Fetch from Cloud Map with fresh context (separate timeout from parent)
	fetchCtx, cancel := context.WithTimeout(context.Background(), c.operationTimeout)
	defer cancel()

	result, err := c.client.DiscoverInstances(fetchCtx, &servicediscovery.DiscoverInstancesInput{
		NamespaceName: aws.String(c.namespaceName),
		ServiceName:   aws.String(c.serviceName),
		HealthStatus:  sdtypes.HealthStatusFilterHealthy,
	})
	if err != nil {
		log.Warning("Cloud Map DiscoverInstances failed: %v", err)
		return nil, fmt.Errorf("cloud map discovery failed: %w", err)
	}

	// Build IP set from discovered instances
	ips := make(map[string]bool)
	for _, instance := range result.Instances {
		// Cloud Map ECS/EC2 integrations typically use AWS_INSTANCE_IPV4
		if ip, ok := instance.Attributes["AWS_INSTANCE_IPV4"]; ok && ip != "" {
			ips[ip] = true
			log.Debug("Cloud Map discovered healthy server: %s", ip)
		}
		// Also check the standard IP attribute
		if ip, ok := instance.Attributes["ip"]; ok && ip != "" {
			ips[ip] = true
		}
	}

	// Update cache
	c.cachedIPs = ips
	c.cacheExpiry = time.Now().Add(c.cacheTTL)

	log.Debug("Cloud Map cache refreshed: %d healthy servers", len(ips))
	return ips, nil
}

// IsServerHealthy checks if a specific server IP is in the healthy set.
// This is a convenience method that calls GetHealthyServerIPs.
func (c *CloudMapClient) IsServerHealthy(ctx context.Context, serverIP string) (bool, error) {
	healthyIPs, err := c.GetHealthyServerIPs(ctx)
	if err != nil {
		return false, err
	}
	return healthyIPs[serverIP], nil
}

// InvalidateCache forces the next GetHealthyServerIPs call to refresh from Cloud Map.
// Useful for testing or when an external event indicates the cache is stale.
func (c *CloudMapClient) InvalidateCache() {
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()
	c.cacheExpiry = time.Time{} // Zero time is always before Now()
	log.Debug("Cloud Map cache invalidated")
}

// FilterHealthyServers filters a list of server assignments to only include
// servers that are currently healthy according to the health checker.
// If health check fails, returns the original list (fail-open).
// If no healthy servers remain, returns an empty slice.
func FilterHealthyServers(ctx context.Context, healthChecker HealthChecker, servers []ServerInfo) []ServerInfo {
	// Check both interface nil and underlying value nil.
	// Go interfaces can be non-nil while holding a nil concrete pointer.
	// Example: var c *CloudMapClient = nil; var h HealthChecker = c
	// In this case, h != nil (interface has type info) but h.Method() panics.
	if healthChecker == nil || reflect.ValueOf(healthChecker).IsNil() {
		// Health checker not configured - return all servers
		return servers
	}

	healthyIPs, err := healthChecker.GetHealthyServerIPs(ctx)
	if err != nil {
		// Health check unavailable - fail-open, return all servers
		log.Warning("Health check unavailable, skipping health filter: %v", err)
		return servers
	}

	if len(healthyIPs) == 0 {
		// No healthy servers registered - this is unusual
		log.Warning("Health check returned 0 healthy servers - possible configuration issue")
		// Fail-open: return all servers rather than blocking all ACs
		return servers
	}

	// Filter to only healthy servers
	healthy := make([]ServerInfo, 0, len(servers))
	for _, srv := range servers {
		// Check both IP and InternalIP since Cloud Map may have either
		if healthyIPs[srv.IP] || healthyIPs[srv.InternalIP] {
			healthy = append(healthy, srv)
		} else {
			log.Debug("Filtering out unhealthy server %s (IP=%s, InternalIP=%s)",
				srv.ID, srv.IP, srv.InternalIP)
		}
	}

	log.Debug("Health filter: %d/%d servers healthy", len(healthy), len(servers))
	return healthy
}
