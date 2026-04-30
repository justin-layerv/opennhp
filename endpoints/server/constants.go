package server

import (
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
)

const (
	MaxACConnsPerID             = 10                              // max AC connections per AC ID (blue/green)
	MaxConcurrentConnection     = 20480                           // global cap on remoteConnectionMap and blockAddrMap entries; per-IP fairness via MaxAgentConnsPerIP
	OverloadConnectionThreshold = MaxConcurrentConnection * 4 / 5 // 80%
	// MaxAgentConnsPerIP: per-source-IP cap on agent UdpConn entries
	// (AC/DB bypass via the IP gate in admitNewConnection). 16 leaves
	// headroom for a small-office NAT (~10 simultaneous knockers);
	// evictions on legit traffic should be near-zero. Sustained
	// MetricAgentConnPerIPEvictions on a known-NAT IP argues for
	// raising the cap once #1526 makes it configurable.
	MaxAgentConnsPerIP              = 16
	BlockAddrRefreshRate            = 20                                   // 20 seconds
	BlockAddrExpireTime             = 90                                   // 90 seconds
	PreCheckThreatCountBeforeBlock  = 5                                    // block source address if packet precheck errors exceeds this count
	DefaultAgentConnectionTimeoutMs = common.ClientSideConnectionTimeoutMs // 30 seconds to delete idle connection
	DefaultACConnectionTimeoutMs    = common.ServerSideConnectionTimeoutMs // 300 seconds to delete idle connection
	DefaultDBConnectionTimeoutMs    = common.ServerSideConnectionTimeoutMs // 300 seconds to delete idle connection
	PacketQueueSizePerConnection    = 256
)

// Compile-time assertion that MaxAgentConnsPerIP ≥ 1. The eviction
// loop in admitNewConnection assumes a non-empty bucket implies a
// non-nil Front; if the cap is ever set to 0, this constant fails to
// compile. Replace with a config-load clamp once #1526 makes the cap
// dynamic.
const _ = uint(MaxAgentConnsPerIP - 1)

// http APIs
const (
	DefaultHttpRequestReadTimeoutMs   = 4500 // millisecond
	DefaultHttpResponseWriteTimeoutMs = 5500 // millisecond
	DefaultHttpServerIdleTimeoutMs    = 6000 // millisecond
)

// broadcast
const (
	// DefaultBroadcastTimeout caps per-goroutine time in processACOperationBroadcast.
	// Individual NHP transactions have their own ~4.7s timeout (HttpRequestReadTimeout +
	// overhead). This 10s ceiling is ~2x that value to allow for network jitter while
	// still bounding worst-case resource usage.
	DefaultBroadcastTimeout = 10 * time.Second
)

// knock
const (
	DefaultIpOpenTime         = 120 // second, align with ipset default timeout
	ACOpenCompensationTime    = 5   // second
	TokenStoreRefreshInterval = common.TokenStoreRefreshInterval
)
