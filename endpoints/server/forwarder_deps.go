package server

import (
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
	// Returns the first successful result.
	ProcessACOperationBroadcast(
		knkMsg *common.AgentKnockMsg,
		conns []*ACConn,
		srcAddr *common.NetAddress,
		dstAddrs []*common.NetAddress,
		openTime uint32,
	) (*common.ACOpsResultMsg, error)
}

// Compile-time check that UdpServer implements ForwarderDeps.
var _ ForwarderDeps = (*UdpServer)(nil)
