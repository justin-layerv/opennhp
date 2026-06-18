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
//
// Contract: `IdleTimeoutMs >= proxy_origin_keepalive + buffer` whenever this
// server runs behind a connection-pooling proxy. CloudFront's
// `origin_keepalive_timeout` is set to 30s in
// `terraform/main.tf::aws_cloudfront_distribution.qurl_resolve`, so 36s here
// keeps the documented 5s buffer with 1s of real slack above the contract
// floor. A lower value re-opens the resolve.qurl.link 502 race (CF reuses
// an idle conn the server has FIN'd; next POST gets RST; CF surfaces 502
// because POSTs aren't retried). LayerV diverges from upstream OpenNHP
// defaults (4500/5500/6000); see docs/UPSTREAM_SYNC.md.
const (
	DefaultHttpRequestReadTimeoutMs   = 30000 // millisecond
	DefaultHttpResponseWriteTimeoutMs = 30000 // millisecond
	DefaultHttpServerIdleTimeoutMs    = 36000 // millisecond
)

// broadcast
const (
	// DefaultBroadcastTimeout caps per-goroutine time in
	// processACOperationBroadcast — i.e., how long the server waits for an
	// AC peer to ACK an NHP-AOP. It's intentionally independent of the
	// HTTP envelope timeouts above (those bound CF↔server connection
	// state; this one bounds AC-side processing). 10s is sized to absorb
	// AC startup jitter and short network blips while still cutting off
	// a wedged AC before it drains the broadcast budget.
	DefaultBroadcastTimeout = 10 * time.Second
)

// knock
const (
	DefaultIpOpenTime              = 120 // second, align with ipset default timeout
	ACOpenCompensationTime         = 5   // second
	TokenStoreRefreshInterval      = common.TokenStoreRefreshInterval
	DefaultCookieTimeWindowSeconds = 60
)
