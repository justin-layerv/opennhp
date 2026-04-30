package server

import (
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
)

const (
	MaxACConnsPerID = 10 // max AC connections per AC ID (blue/green)
	// MaxConcurrentConnection caps both remoteConnectionMap (keyed by
	// IP:port — counts unique connection tuples) and blockAddrMap
	// (keyed by IP only post-#1160 T3-12 — counts unique source IPs).
	// Under the old IP:port keying for blockAddrMap, a port-rotating
	// attacker on a single source IP could singlehandedly fill the
	// block-map cap; the IP-only keying made this constant's name
	// closer to its effective semantics for the block-map case.
	// NOTE(#1504): remoteConnectionMap still keys on IP:port and is
	// still vulnerable to the same pattern. When #1504 lands and
	// re-keys remoteConnectionMap, this comment block should be
	// trimmed to the steady-state "both maps key on IP" form.
	MaxConcurrentConnection         = 20480
	OverloadConnectionThreshold     = MaxConcurrentConnection * 4 / 5      // 80%
	BlockAddrRefreshRate            = 20                                   // 20 seconds
	BlockAddrExpireTime             = 90                                   // 90 seconds
	PreCheckThreatCountBeforeBlock  = 5                                    // block source address if packet precheck errors exceeds this count
	DefaultAgentConnectionTimeoutMs = common.ClientSideConnectionTimeoutMs // 30 seconds to delete idle connection
	DefaultACConnectionTimeoutMs    = common.ServerSideConnectionTimeoutMs // 300 seconds to delete idle connection
	DefaultDBConnectionTimeoutMs    = common.ServerSideConnectionTimeoutMs // 300 seconds to delete idle connection
	PacketQueueSizePerConnection    = 256
)

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
