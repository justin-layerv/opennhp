package server

import (
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
)

const (
	MaxACConnsPerID                 = 10 // max AC connections per AC ID (blue/green)
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
