package server

import (
	"context"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
)

// ============================================================================
// ForwarderDeps Interface
// ============================================================================
//
// ForwarderDeps defines the dependencies that ServerForwarder needs from the
// server. This interface enables testing the forwarder with mock implementations
// without requiring a full UdpServer instance.
//
// For production use, UdpServer implements this interface.
// For testing, MockForwarderServer provides a controllable implementation.
// ============================================================================

// ForwarderDeps is the interface that ServerForwarder depends on.
type ForwarderDeps interface {
	// GetHostname returns the server's hostname/ID used in forward messages.
	GetHostname() string

	// GetDevice returns the core.Device for Noise protocol operations.
	GetDevice() *core.Device

	// SendMessage queues a message for sending via the server's send channel.
	SendMessage(md *core.MsgData)

	// FindACConnectionsForKnock finds all AC connections that can handle a knock.
	// Returns multiple connections when blue/green ACs register with the same AC ID.
	FindACConnectionsForKnock(knkMsg *common.AgentKnockMsg) []*ACConn

	// FindAuthSvcProvider finds the auth service provider by ID.
	FindAuthSvcProvider(authSvcId string) *common.AuthServiceProviderData

	// ProcessACOperation sends an AOP to an AC and waits for the ART response.
	ProcessACOperation(
		knkMsg *common.AgentKnockMsg,
		acConn *ACConn,
		srcAddr *common.NetAddress,
		dstAddrs []*common.NetAddress,
		openTime uint32,
	) (*common.ACOpsResultMsg, error)

	// ProcessACOperationBroadcast sends AOP to all AC connections in parallel.
	// parentCtx carries context values (e.g., request ID) for log correlation
	// but its cancellation is intentionally discarded — broadcast goroutines
	// must run independently to open pinholes on every AC. Callers without a
	// request context should pass context.Background(); never pass nil.
	// Returns the first successful result.
	ProcessACOperationBroadcast(
		parentCtx context.Context,
		knkMsg *common.AgentKnockMsg,
		conns []*ACConn,
		srcAddr *common.NetAddress,
		dstAddrs []*common.NetAddress,
		openTime uint32,
	) (*common.ACOpsResultMsg, error)

	// PublishACKTokens persists every AC token in ackMsg.ACTokens so
	// PR-2b's /nhp/internal/token/validate can resolve them. The forward
	// receiver routes its single-resource ackMsg through this chokepoint
	// after a successful broadcast so the empty-token guard, the
	// maps.Clone isolation, and any future metrics/logging applied in
	// PublishACKTokens reach the forward path identically to the local
	// UDP/HTTP knock paths.
	PublishACKTokens(knkMsg *common.AgentKnockMsg, ackMsg *common.ServerKnockAckMsg, srcIp string, openTime int)
}

// Compile-time check that UdpServer implements ForwarderDeps.
var _ ForwarderDeps = (*UdpServer)(nil)
