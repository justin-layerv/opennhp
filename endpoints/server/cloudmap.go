package server

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/servicediscovery"
	sdtypes "github.com/aws/aws-sdk-go-v2/service/servicediscovery/types"

	"golang.org/x/sync/singleflight"

	"github.com/OpenNHP/opennhp/nhp/common"
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

	// DiscoverInstances has no continuation token and returns at most 100
	// entries. A full page is therefore ambiguous and must not be treated as an
	// authoritative fleet snapshot. Deployment keeps every cell below this cap.
	cloudMapDiscoverMaxResults int32 = 100

	// Cloud Map instance attribute keys — shared between registerWithCloudMap (writer)
	// and refreshInstancesCache (reader).
	CloudMapAttrIPv4     = "AWS_INSTANCE_IPV4"
	CloudMapAttrIP       = "ip" // fallback IP attribute
	CloudMapAttrAZ       = "AVAILABILITY_ZONE"
	CloudMapAttrPort     = "NHP_PORT"
	CloudMapAttrHTTPPort = "HTTP_PORT"
	CloudMapAttrKey      = "PUBLIC_KEY"
	CloudMapAttrASG      = "ASG_NAME"
)

// HealthChecker is the interface for checking server health.
// This allows for easy mocking in tests.
type HealthChecker interface {
	// GetHealthyServerIPs returns a set of IP addresses for currently healthy servers.
	GetHealthyServerIPs(ctx context.Context) (map[string]bool, error)

	// InvalidateCache forces the next GetHealthyServerIPs call to refresh.
	InvalidateCache()

	// IsNil returns true if the underlying implementation is nil.
	// This avoids the Go typed-nil interface pitfall where a nil concrete
	// pointer assigned to the interface makes the interface non-nil.
	IsNil() bool
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

	// ServiceID is the Cloud Map service ID (srv-xxx) for RegisterInstance calls.
	// Required for server-side auto-assignment to register public keys.
	ServiceID string `toml:"ServiceID"`

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
	client           cloudMapAPI
	namespaceName    string
	serviceName      string
	serviceID        string // srv-xxx for RegisterInstance
	cacheTTL         time.Duration
	operationTimeout time.Duration

	// Server instances cache (full ServerInfo with attributes).
	// GetHealthyServerIPs derives from this cache, avoiding duplicate API calls.
	instancesMu     sync.RWMutex
	cachedInstances []ServerInfo
	instancesExpiry time.Time

	// Singleflight to deduplicate concurrent refresh requests
	sfGroup singleflight.Group

	// discoverFreshFn is a narrow test seam for exercising cache-staleness
	// recovery without an AWS client. Production clients leave it nil.
	discoverFreshFn func(context.Context) ([]ServerInfo, error)
}

type cloudMapAPI interface {
	DiscoverInstances(context.Context, *servicediscovery.DiscoverInstancesInput, ...func(*servicediscovery.Options)) (*servicediscovery.DiscoverInstancesOutput, error)
	RegisterInstance(context.Context, *servicediscovery.RegisterInstanceInput, ...func(*servicediscovery.Options)) (*servicediscovery.RegisterInstanceOutput, error)
	DeregisterInstance(context.Context, *servicediscovery.DeregisterInstanceInput, ...func(*servicediscovery.Options)) (*servicediscovery.DeregisterInstanceOutput, error)
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
		serviceID:        cfg.ServiceID,
		cacheTTL:         cfg.GetCacheTTL(),
		operationTimeout: cfg.GetOperationTimeout(),
	}

	log.Info("Cloud Map client initialized: namespace=%s, service=%s, cacheTTL=%v, timeout=%v",
		cfg.NamespaceName, cfg.ServiceName, cm.cacheTTL, cm.operationTimeout)

	return cm, nil
}

// GetHealthyServerIPs returns a set of IP addresses for currently healthy servers.
// Derived from DiscoverServerInstances to avoid duplicate Cloud Map API calls.
// Returns nil error and empty map if cache is fresh but no healthy servers found.
func (c *CloudMapClient) GetHealthyServerIPs(ctx context.Context) (map[string]bool, error) {
	instances, err := c.DiscoverServerInstances(ctx)
	if err != nil {
		return nil, err
	}

	ips := make(map[string]bool, len(instances))
	for _, inst := range instances {
		if inst.IP != "" {
			ips[inst.IP] = true
		}
		if inst.InternalIP != "" && inst.InternalIP != inst.IP {
			ips[inst.InternalIP] = true
		}
	}
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

// InvalidateCache forces the next call to refresh from Cloud Map.
// Useful for testing or when an external event indicates the cache is stale.
// IsNil returns true if the receiver is nil.
func (c *CloudMapClient) IsNil() bool {
	return c == nil
}

func (c *CloudMapClient) InvalidateCache() {
	c.instancesMu.Lock()
	c.instancesExpiry = time.Time{} // Zero time is always before Now()
	c.instancesMu.Unlock()
	log.Debug("Cloud Map cache invalidated")
}

// DiscoverServerInstances returns full ServerInfo for all healthy servers.
// Results are cached with the same TTL as GetHealthyServerIPs.
func (c *CloudMapClient) DiscoverServerInstances(ctx context.Context) ([]ServerInfo, error) {
	// Check instances cache first
	c.instancesMu.RLock()
	if time.Now().Before(c.instancesExpiry) && c.cachedInstances != nil {
		result := make([]ServerInfo, len(c.cachedInstances))
		copy(result, c.cachedInstances)
		c.instancesMu.RUnlock()
		return result, nil
	}
	c.instancesMu.RUnlock()

	// Cache miss - refresh via singleflight
	result, err, _ := c.sfGroup.Do("refresh-instances", func() (any, error) {
		return c.refreshInstancesCache(ctx, false)
	})
	if err != nil {
		return nil, err
	}

	instances, ok := result.([]ServerInfo)
	if !ok {
		return nil, fmt.Errorf("unexpected result type %T from singleflight refresh-instances", result)
	}
	out := make([]ServerInfo, len(instances))
	copy(out, instances)
	return out, nil
}

// DiscoverServerInstancesFresh bypasses a still-valid cache under a separate
// singleflight key. Fleet-close fanout uses this on retry, and the receiver
// uses it once after a membership miss, because the ordinary 30-second cache
// TTL is as long as the entire close event. The force refresh is serialized by
// instancesMu with ordinary refreshes and therefore wins with the newest
// completed snapshot rather than racing an older cache write.
func (c *CloudMapClient) DiscoverServerInstancesFresh(ctx context.Context) ([]ServerInfo, error) {
	if c == nil {
		return nil, errors.New("cloud map client is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if c.discoverFreshFn != nil {
		instances, err := c.discoverFreshFn(ctx)
		if err != nil {
			return nil, err
		}
		out := make([]ServerInfo, len(instances))
		copy(out, instances)
		return out, nil
	}
	result, err, _ := c.sfGroup.Do("force-refresh-instances", func() (any, error) {
		return c.refreshInstancesCache(ctx, true)
	})
	if err != nil {
		return nil, err
	}
	instances, ok := result.([]ServerInfo)
	if !ok {
		return nil, fmt.Errorf("unexpected result type %T from force-refresh-instances", result)
	}
	out := make([]ServerInfo, len(instances))
	copy(out, instances)
	return out, nil
}

// refreshInstancesCache fetches full server instance details from Cloud Map.
func (c *CloudMapClient) refreshInstancesCache(ctx context.Context, force bool) ([]ServerInfo, error) {
	c.instancesMu.Lock()
	defer c.instancesMu.Unlock()

	if !force && time.Now().Before(c.instancesExpiry) && c.cachedInstances != nil {
		return c.cachedInstances, nil
	}

	if c.client == nil {
		return nil, errors.New("cloud map discovery client is unavailable")
	}
	timeout := c.operationTimeout
	if timeout <= 0 {
		timeout = DefaultCloudMapOperationTimeout
	}
	fetchCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	result, err := c.client.DiscoverInstances(fetchCtx, &servicediscovery.DiscoverInstancesInput{
		NamespaceName: aws.String(c.namespaceName),
		ServiceName:   aws.String(c.serviceName),
		HealthStatus:  sdtypes.HealthStatusFilterHealthy,
		MaxResults:    aws.Int32(cloudMapDiscoverMaxResults),
	})
	if err != nil {
		log.Warning("Cloud Map DiscoverInstances (full) failed: %v", err)
		return nil, fmt.Errorf("cloud map discovery failed: %w", err)
	}

	if len(result.Instances) >= int(cloudMapDiscoverMaxResults) {
		return nil, fmt.Errorf("cloud map discovery returned the maximum %d instances; snapshot may be truncated", cloudMapDiscoverMaxResults)
	}

	serversByID := make(map[string]ServerInfo, len(result.Instances))
	for _, inst := range result.Instances {
		instanceID := aws.ToString(inst.InstanceId)
		if instanceID == "" {
			return nil, errors.New("cloud map discovery returned an instance without an ID")
		}
		ip := inst.Attributes[CloudMapAttrIPv4]
		if ip == "" {
			ip = inst.Attributes[CloudMapAttrIP]
		}
		if ip == "" {
			continue
		}

		port := common.DefaultNHPPort
		if portStr, ok := inst.Attributes[CloudMapAttrPort]; ok {
			if p, err := strconv.Atoi(portStr); err == nil {
				port = p
			}
		}
		httpPort := 0
		if portStr, ok := inst.Attributes[CloudMapAttrHTTPPort]; ok {
			if p, err := strconv.Atoi(portStr); err == nil && p > 0 && p <= 65535 {
				httpPort = p
			}
		}

		srv := ServerInfo{
			ID:         instanceID,
			IP:         ip,
			InternalIP: ip, // Cloud Map registers VPC IPs
			AZ:         inst.Attributes[CloudMapAttrAZ],
			Port:       port,
			HTTPPort:   httpPort,
			PubKey:     inst.Attributes[CloudMapAttrKey],
			ASGName:    inst.Attributes[CloudMapAttrASG],
		}
		if prior, exists := serversByID[instanceID]; exists {
			if prior != srv {
				return nil, fmt.Errorf("cloud map discovery returned conflicting rows for instance %s", instanceID)
			}
			continue
		}
		serversByID[instanceID] = srv
	}
	servers := make([]ServerInfo, 0, len(serversByID))
	for _, server := range serversByID {
		servers = append(servers, server)
	}
	sort.Slice(servers, func(i, j int) bool { return servers[i].ID < servers[j].ID })

	c.cachedInstances = servers
	c.instancesExpiry = time.Now().Add(c.cacheTTL)

	log.Debug("Cloud Map instances cache refreshed: %d servers", len(servers))
	return servers, nil
}

// RegisterInstanceAttributes registers or updates this server's attributes in Cloud Map.
// IMPORTANT: RegisterInstance REPLACES all attributes for the instance ID. Must include
// all attributes (IP, AZ, port) alongside any new ones (PUBLIC_KEY).
func (c *CloudMapClient) RegisterInstanceAttributes(ctx context.Context, instanceID string, attrs map[string]string) error {
	if c.serviceID == "" {
		return fmt.Errorf("cloud map service ID not configured (required for RegisterInstance)")
	}

	ctx, cancel := context.WithTimeout(ctx, c.operationTimeout)
	defer cancel()

	_, err := c.client.RegisterInstance(ctx, &servicediscovery.RegisterInstanceInput{
		ServiceId:  aws.String(c.serviceID),
		InstanceId: aws.String(instanceID),
		Attributes: attrs,
	})
	if err != nil {
		return fmt.Errorf("cloud map RegisterInstance failed: %w", err)
	}

	// Debug-level: this is called on every refresh tick (every 5 min per
	// server). The boot-time INFO "Registered with Cloud Map: ..." in
	// registerWithCloudMapWithRetry is the once-per-process audit log.
	// Refresh-tick failures still log at WARNING / increment a metric.
	log.Debug("Registered Cloud Map instance %s with %d attributes", instanceID, len(attrs))
	return nil
}

// DeregisterInstance removes this server from Cloud Map.
// Called on graceful shutdown so peers stop selecting this server for native
// forwarding and fleet trust.
func (c *CloudMapClient) DeregisterInstance(ctx context.Context, instanceID string) error {
	if c.serviceID == "" {
		return fmt.Errorf("cloud map service ID not configured")
	}

	ctx, cancel := context.WithTimeout(ctx, c.operationTimeout)
	defer cancel()

	_, err := c.client.DeregisterInstance(ctx, &servicediscovery.DeregisterInstanceInput{
		ServiceId:  aws.String(c.serviceID),
		InstanceId: aws.String(instanceID),
	})
	if err != nil {
		return fmt.Errorf("cloud map DeregisterInstance failed: %w", err)
	}

	log.Info("Deregistered Cloud Map instance %s", instanceID)
	return nil
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
	if healthChecker == nil || healthChecker.IsNil() {
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

// filterServersByASG filters servers to only those in the same ASG as this server.
// This prevents blue/green cross-color assignment during deploys where both ASGs
// register instances in the same CloudMap service.
//
// Returns the filtered list and a bool indicating whether fail-open was triggered
// (all servers were cross-color, so the original list was returned unfiltered).
//
// Backward-compat rules (fail-open):
//   - selfASG == "": this server doesn't know its ASG (IMDS failed) → no filtering
//   - srv.ASGName == "": that server hasn't been updated yet → include it (gradual rollout)
//   - No matches after filtering: edge case safety → return all servers
func filterServersByASG(servers []ServerInfo, selfASG string) ([]ServerInfo, bool) {
	if selfASG == "" {
		return servers, false
	}
	filtered := make([]ServerInfo, 0, len(servers))
	for _, srv := range servers {
		if srv.ASGName == selfASG || srv.ASGName == "" {
			filtered = append(filtered, srv)
		}
	}
	if len(filtered) == 0 {
		if len(servers) == 0 {
			return servers, false
		}
		log.Info("ASG filter: all %d servers are cross-color (selfASG=%s), failing open", len(servers), selfASG)
		return servers, true
	}
	if len(filtered) < len(servers) {
		log.Info("ASG filter: %d/%d servers match ASG %s (removed %d cross-color)", len(filtered), len(servers), selfASG, len(servers)-len(filtered))
	} else {
		log.Debug("ASG filter: %d/%d servers match ASG %s", len(filtered), len(servers), selfASG)
	}
	return filtered, false
}
