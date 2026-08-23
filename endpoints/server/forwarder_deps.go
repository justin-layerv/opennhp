package server

import (
	"context"
	"time"

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
	// It returns only local/prequeue failures; protocol responses still arrive
	// through NHP_FRT handling.
	SendMessage(md *core.MsgData) error

	// IncrForwarderMetric increments a forwarder-owned counter. Production binds
	// this to the server metrics publisher; tests can capture or no-op it.
	IncrForwarderMetric(name string)

	// FindACConnectionsForResource finds all AC connections that can handle a
	// knock for an already-resolved resource. The forward receiver resolves
	// qURL placement once, then reuses the same ResourceData for AC selection and
	// ACK construction so future health-aware placement cannot drift between
	// those two decisions. Returns multiple connections when blue/green ACs
	// register with the same AC ID.
	FindACConnectionsForResource(knkMsg *common.AgentKnockMsg, resData *common.ResourceData) []*ACConn

	// ResolveAuthSvcProvider is the "do-the-right-thing" lookup:
	// in-memory first, then falls back to the DDB-backed resolver
	// (#1976) on miss when cloud mode is wired. Returns nil on any
	// failure (genuine unknown aspId, transient DDB error, graceful
	// shutdown) — the caller's reject path owns the wire-level
	// error code. Mocks SHOULD delegate to FindAuthSvcProvider to
	// preserve existing test semantics (mocks don't typically wire
	// a DDB-backed resolver).
	//
	// Callers SHOULD pass LifecycleCtx() (or a context derived from
	// it) so an in-flight DDB lookup abandons promptly on server
	// shutdown — the helper's three-way error switch surfaces
	// context.Canceled via an Info-level "shutdown" log and skips
	// the DDB-error counter, but only if the passed ctx is the one
	// that cancels.
	ResolveAuthSvcProvider(ctx context.Context, authSvcId, logPrefix string) *common.AuthServiceProviderData

	// LifecycleCtx returns the parent server's lifecycle context.
	// Canceled by UdpServer.Stop(), so async work derived from it
	// abandons promptly on shutdown. Mocks SHOULD return
	// context.Background to keep existing test semantics — they
	// don't run an Stop() that would cancel a real lifecycleCtx.
	LifecycleCtx() context.Context

	// ProcessACOperation sends an AOP to an AC and waits for the ART response.
	// res carries qURL v2 revocation metadata (P4a) to stamp onto the AOP, or
	// nil for legacy callers.
	ProcessACOperation(
		knkMsg *common.AgentKnockMsg,
		acConn *ACConn,
		srcAddr *common.NetAddress,
		dstAddrs []*common.NetAddress,
		openTime uint32,
		res *common.ResourceData,
	) (*common.ACOpsResultMsg, error)

	// ProcessACOperationBroadcast sends AOP to all AC connections in parallel.
	// parentCtx carries context values (e.g., request ID) for log correlation
	// but its cancellation is intentionally discarded — broadcast goroutines
	// must run independently to open pinholes on every AC. Callers without a
	// request context should pass context.Background(); never pass nil.
	// Returns the first successful result.
	//
	// res carries qURL v2 revocation metadata (P4a) to stamp onto the AOP, or
	// nil for legacy paths. On the forward-receiver path it is the locally
	// resolved catalog ResourceData with any origin admission metadata carried on
	// NHP_FWD overlaid, so routing stays receiver-local while targeted
	// revocation metadata survives the hop.
	ProcessACOperationBroadcast(
		parentCtx context.Context,
		knkMsg *common.AgentKnockMsg,
		conns []*ACConn,
		srcAddr *common.NetAddress,
		dstAddrs []*common.NetAddress,
		openTime uint32,
		res *common.ResourceData,
	) (*common.ACOpsResultMsg, error)

	// PublishACKTokens persists every AC token in ackMsg.ACTokens so
	// PR-2b's /nhp/internal/token/validate can resolve them. The forward
	// receiver routes its single-resource ackMsg through this chokepoint
	// after a successful broadcast so the empty-token guard, the
	// maps.Clone isolation, and any future metrics/logging applied in
	// PublishACKTokens reach the forward path identically to the native UDP
	// knock path.
	//
	// ownerId is the server-resolved tenant identity from the pubkey-
	// bound agent registry lookup; pass "" on paths without pubkey-
	// resolved identity. See `PublishACKTokens` godoc in tokenstore.go.
	PublishACKTokens(ctx context.Context, knkMsg *common.AgentKnockMsg, ackMsg *common.ServerKnockAckMsg, srcIp string, openTime int, ownerId string) error

	// ResolveOwnerIDByPubKey returns the server-resolved tenant
	// identity for a base64-encoded agent public key, or "" if the
	// lookup fails (unknown pubkey, DDB outage, non-cloud-mode,
	// graceful shutdown). Used by the forward-receiver path to
	// resolve owner_id locally — without this, the receiver would
	// stamp "" on every ACK token entry and downstream consumers
	// (qurl-reverse-tunnel-server's tunnel-auth plugin) would see
	// inconsistent OwnerId across NLB-hashed instances depending on
	// which server's `/nhp/internal/token/validate` they hit.
	//
	// Hits DDB on cache miss (one Query per cold pubkey on this
	// instance), then populates the local LRU so subsequent calls
	// for the same pubkey are cache hits. The DDB cost is bounded —
	// every server reads from the same `qurl-agent-keys` table, and
	// the pubkey-index GSI projects owner_id with a KEYS_ONLY shape.
	//
	// Fail-safe contract: any failure returns "" (not an error). The
	// caller stamps "" on the ACK entry, which downstream consumers
	// treat as "identity not resolved at this hop" per the existing
	// empty-OwnerId contract. Never blocks a knock on lookup failure.
	ResolveOwnerIDByPubKey(ctx context.Context, pubKeyB64 string) string
}

// Compile-time check that UdpServer implements ForwarderDeps.
var _ ForwarderDeps = (*UdpServer)(nil)

// forwardedNHPSessionDeps is the fail-closed session-reservation seam used by
// authenticated NHP_FWD receivers. It stays separate from ForwarderDeps so
// transport-only test doubles need not implement session state they never use.
type forwardedNHPSessionDeps interface {
	VerifyForwardedDurableNHPSession(context.Context, *common.AgentKnockMsg) (common.AgentSessionReceipt, error)
	ReserveForwardedNHPSession(agentPubKeyB64 string, sessionID uint64, issuedAt, expiresAt time.Time) error
	ReleaseForwardedNHPSession(agentPubKeyB64 string, sessionID uint64, issuedAt time.Time)
	CompensateForwardedNHPSession(agentPubKeyB64 string, sessionID uint64, issuedAt time.Time) bool
}
