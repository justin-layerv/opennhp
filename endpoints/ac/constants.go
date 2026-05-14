package ac

import "github.com/OpenNHP/opennhp/nhp/common"

const (
	MaxConcurrentConnection      = 256
	DefaultConnectionTimeoutMs   = common.ServerSideConnectionTimeoutMs
	PacketQueueSizePerConnection = 256

	ReportToServerInterval         = common.ReportToServerInterval
	MinimalServerDiscoveryInterval = common.MinimalServerDiscoveryInterval
	ServerKeepaliveInterval        = common.ServerKeepaliveInterval
	ServerDiscoveryRetryBeforeFail = common.ServerDiscoveryRetryBeforeFail

	TokenStoreRefreshInterval = common.TokenStoreRefreshInterval
	TempPortOpenTime          = 30

	// CloseWindowOpenTimeSec is the doubly-loaded sentinel: a hand-set
	// openTimeSec=1 means "close everything" (collapse the tempset
	// alongside the defaultset). RemainingFirewallSeconds can also
	// organically return 1 in the (1.0, 2.0)s window post-refresh,
	// which trips the same path — see HandleAccessControl.
	CloseWindowOpenTimeSec = 1

	IPSET_DEFAULT_NAME      = "defaultset"
	IPSET_DEFAULT_DOWN_NAME = "defaultset_down"

	// SentinelLocalIP is a sentinel value meaning "local to this AC".
	// Used by QURL resources where the destination is the AC itself.
	// The AC replaces this with its own DefaultIp when creating ipset rules.
	SentinelLocalIP = "0.0.0.0"
)
