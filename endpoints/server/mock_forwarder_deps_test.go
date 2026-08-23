package server

import (
	"context"
	"sync"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
)

// MockForwarderDeps implements ForwarderDeps for testing.
//
// tokensMu guards storedTokens so StoreACToken / GetStoredACToken stay
// -race-safe, mirroring mockACForwarderDeps. The two mocks must stay
// consistent — anyone copying this pattern into a concurrent test
// shouldn't trip the detector on one and not the other.
type MockForwarderDeps struct {
	hostname      string
	device        *core.Device
	sendCh        chan *core.MsgData
	acConns       []*ACConn
	aspData       *common.AuthServiceProviderData
	processResult *common.ACOpsResultMsg
	processErr    error
	tokensMu      sync.Mutex
	storedTokens  map[string]*ACTokenEntry
	// lifecycleCtx is what LifecycleCtx() returns. Defaults to
	// context.Background() (the typical mock posture). Tests that
	// need to exercise the resolver's shutdown-classification branch
	// from the forwarder seam can set this to a pre-canceled
	// context via SetLifecycleCtx.
	lifecycleCtx context.Context
	// resolveCtxMu guards lastResolveCtx — the ctx capture for
	// LastResolveCtx() so a future test can fence the forwarder's
	// f.deps.LifecycleCtx() plumbing. Also guards resolvedOwnerIDs
	// (the pre-installed pubkey→ownerID map for
	// ResolveOwnerIDByPubKey). Both fields share one mutex for
	// convenience (one less field to manage); the two are never
	// acquired together so a split into two mutexes would also be
	// safe — no real lock-order hazard either way.
	resolveCtxMu      sync.Mutex
	lastResolveCtx    context.Context
	resolvedOwnerIDs  map[string]string
	metricsMu         sync.Mutex
	counters          map[string]int
	forwardedSessions *liveNHPSessionRegistry
}

func (m *MockForwarderDeps) VerifyForwardedDurableNHPSession(_ context.Context,
	knkMsg *common.AgentKnockMsg,
) (common.AgentSessionReceipt, error) {
	if knkMsg == nil || knkMsg.AuthServiceId != common.RegisteredAgentAuthServiceID {
		return common.AgentSessionReceipt{}, nil
	}
	return common.AgentSessionReceipt{
		CellID: testSessionControlCellID, SessionID: knkMsg.NHPSessionId,
		SessionIssuedAtMillis: knkMsg.NHPSessionIssuedAt.UnixMilli(),
		RunID:                 knkMsg.RunID, RunAttempt: knkMsg.RunAttempt,
	}, nil
}

// NewMockForwarderDeps creates a new mock with sensible defaults.
func NewMockForwarderDeps() *MockForwarderDeps {
	return &MockForwarderDeps{
		hostname:          "test-server",
		sendCh:            make(chan *core.MsgData, 10),
		storedTokens:      make(map[string]*ACTokenEntry),
		forwardedSessions: newLiveNHPSessionRegistry(),
	}
}

func (m *MockForwarderDeps) ReserveForwardedNHPSession(agentPubKeyB64 string, sessionID uint64, issuedAt, expiresAt time.Time) error {
	agentPubKey, err := decodeAgentPublicKey(agentPubKeyB64)
	if err != nil {
		return err
	}
	return m.forwardedSessions.reserveExact(agentPubKey, sessionID, issuedAt, expiresAt)
}

func (m *MockForwarderDeps) ReleaseForwardedNHPSession(agentPubKeyB64 string, sessionID uint64, issuedAt time.Time) {
	agentPubKey, err := decodeAgentPublicKey(agentPubKeyB64)
	if err == nil {
		m.forwardedSessions.release(agentPubKey, sessionID, issuedAt)
	}
}

func (m *MockForwarderDeps) CompensateForwardedNHPSession(agentPubKeyB64 string, sessionID uint64, issuedAt time.Time) bool {
	agentPubKey, err := decodeAgentPublicKey(agentPubKeyB64)
	if err != nil {
		return false
	}
	snapshot, ok := m.forwardedSessions.snapshotExactSessionForCompensation(agentPubKey, sessionID, issuedAt)
	return !ok || m.forwardedSessions.completeExactSessionClose(agentPubKey, snapshot)
}

func (m *MockForwarderDeps) GetHostname() string {
	return m.hostname
}

func (m *MockForwarderDeps) GetDevice() *core.Device {
	return m.device
}

func (m *MockForwarderDeps) SendMessage(md *core.MsgData) error {
	// This unit-test mock only captures the MsgData. Production UdpServer
	// synthesizes outbound server-peer ConnData in connDataForOutboundAddr;
	// E2E transport doubles that need packets to leave a socket do their own
	// test-only connection synthesis.
	if m.sendCh != nil {
		m.sendCh <- md
	}
	return nil
}

func (m *MockForwarderDeps) IncrForwarderMetric(name string) {
	m.metricsMu.Lock()
	defer m.metricsMu.Unlock()
	if m.counters == nil {
		m.counters = make(map[string]int)
	}
	m.counters[name]++
}

func (m *MockForwarderDeps) MetricCount(name string) int {
	m.metricsMu.Lock()
	defer m.metricsMu.Unlock()
	return m.counters[name]
}

func (m *MockForwarderDeps) FindACConnectionsForResource(knkMsg *common.AgentKnockMsg, _ *common.ResourceData) []*ACConn {
	return m.acConns
}

// ResolveAuthSvcProvider returns the pre-set aspData and captures
// the ctx for test verification (LastResolveCtx). The capture lets
// tests fence that callers thread the right context — specifically
// the forwarder's lifecycle ctx plumbing, which is not otherwise
// exercisable through mocks (the real resolver's shutdown-classification
// branch needs a real ResourceLookup; tracked as #2126).
//
// FindAuthSvcProvider is no longer on the ForwarderDeps interface
// (the forwarder uses ResolveAuthSvcProvider uniformly post-bridge);
// tests inject aspData via SetAuthServiceProvider directly.
func (m *MockForwarderDeps) ResolveAuthSvcProvider(ctx context.Context, _, _ string) *common.AuthServiceProviderData {
	m.resolveCtxMu.Lock()
	m.lastResolveCtx = ctx
	m.resolveCtxMu.Unlock()
	return m.aspData
}

// LastResolveCtx returns the ctx passed to the most recent
// ResolveAuthSvcProvider call, or nil if never called. Used by
// TestForwarder_ThreadsLifecycleCtxToResolver to fence the
// f.deps.LifecycleCtx() plumbing — the only way to observe the
// shutdown-classification seam through a mock.
func (m *MockForwarderDeps) LastResolveCtx() context.Context {
	m.resolveCtxMu.Lock()
	defer m.resolveCtxMu.Unlock()
	return m.lastResolveCtx
}

// LifecycleCtx returns the test-set lifecycle context (default
// context.Background). Tests that need to exercise the resolver's
// shutdown-classification path from the forwarder seam use
// SetLifecycleCtx to inject a pre-canceled context.
func (m *MockForwarderDeps) LifecycleCtx() context.Context {
	if m.lifecycleCtx == nil {
		return context.Background()
	}
	return m.lifecycleCtx
}

// SetLifecycleCtx overrides the default context.Background returned
// by LifecycleCtx. Used by TestForwarder_ShutdownSuppressesCounters
// (and any future test that needs the forwarder's resolver path to
// observe a canceled ctx).
func (m *MockForwarderDeps) SetLifecycleCtx(ctx context.Context) {
	m.lifecycleCtx = ctx
}

func (m *MockForwarderDeps) ProcessACOperation(
	knkMsg *common.AgentKnockMsg,
	acConn *ACConn,
	srcAddr *common.NetAddress,
	dstAddrs []*common.NetAddress,
	openTime uint32,
	res *common.ResourceData,
) (*common.ACOpsResultMsg, error) {
	return m.processResult, m.processErr
}

func (m *MockForwarderDeps) ProcessACOperationBroadcast(
	_ context.Context,
	knkMsg *common.AgentKnockMsg,
	conns []*ACConn,
	srcAddr *common.NetAddress,
	dstAddrs []*common.NetAddress,
	openTime uint32,
	res *common.ResourceData,
) (*common.ACOpsResultMsg, error) {
	if len(conns) > 0 {
		return m.ProcessACOperation(knkMsg, conns[0], srcAddr, dstAddrs, openTime, res)
	}
	return m.processResult, m.processErr
}

// SetHostname sets the hostname for testing.
func (m *MockForwarderDeps) SetHostname(hostname string) {
	m.hostname = hostname
}

// SetDevice sets the device for testing.
func (m *MockForwarderDeps) SetDevice(device *core.Device) {
	m.device = device
}

// SetACConnection sets the AC connections to return.
func (m *MockForwarderDeps) SetACConnection(acConn *ACConn) {
	if acConn != nil {
		m.acConns = []*ACConn{acConn}
	} else {
		m.acConns = nil
	}
}

// SetAuthServiceProvider sets the auth service provider to return.
func (m *MockForwarderDeps) SetAuthServiceProvider(aspData *common.AuthServiceProviderData) {
	m.aspData = aspData
}

// SetProcessACResult sets the result for ProcessACOperation.
func (m *MockForwarderDeps) SetProcessACResult(result *common.ACOpsResultMsg, err error) {
	m.processResult = result
	m.processErr = err
}

// GetSendChannel returns the send channel for test verification.
func (m *MockForwarderDeps) GetSendChannel() chan *core.MsgData {
	return m.sendCh
}

// StoreACToken records the token+entry pair for test verification.
// Empty tokens are silently ignored to mirror common.TokenStore.Store.
func (m *MockForwarderDeps) StoreACToken(token string, entry *ACTokenEntry) {
	if token == "" {
		return
	}
	m.tokensMu.Lock()
	defer m.tokensMu.Unlock()
	if m.storedTokens == nil {
		m.storedTokens = make(map[string]*ACTokenEntry)
	}
	m.storedTokens[token] = entry
}

// GetStoredACToken returns the entry recorded for the given token, or nil
// if none. Used by tests fencing the PR-2a ACK-path store-on-issue
// invariant on the forward receiver.
func (m *MockForwarderDeps) GetStoredACToken(token string) *ACTokenEntry {
	m.tokensMu.Lock()
	defer m.tokensMu.Unlock()
	return m.storedTokens[token]
}

// PublishACKTokens mirrors the production UdpServer.PublishACKTokens
// semantics so tests fencing the forward path see the same chokepoint
// behavior: every non-empty ackMsg.ACTokens entry is recorded via
// StoreACToken with the maps.Clone snapshot already taken in
// NewACKTokenEntry.
func (m *MockForwarderDeps) PublishACKTokens(_ context.Context, knkMsg *common.AgentKnockMsg, ackMsg *common.ServerKnockAckMsg, srcIp string, openTime int, ownerId string) error {
	sessionExpireTime := knkMsg.NHPSessionIssuedAt.Add(time.Duration(openTime) * time.Second)
	for name, token := range ackMsg.ACTokens {
		if token == "" {
			continue
		}
		m.StoreACToken(token, NewACKTokenEntry(knkMsg, name, ackMsg.ACTokens, srcIp, openTime, ownerId, ackMsg.SessionId, sessionExpireTime))
	}
	return nil
}

// ResolveOwnerIDByPubKey returns the pubkey→ownerID mapping the test
// pre-installed via SetResolvedOwnerID, or "" if no mapping exists.
// Mirrors the production UdpServer.ResolveOwnerIDByPubKey semantics
// (fail-safe empty return on unknown pubkey). Tests fencing the
// forward-receiver path's owner_id propagation pre-install the
// mapping for the agent pubkeys they generate.
func (m *MockForwarderDeps) ResolveOwnerIDByPubKey(_ context.Context, pubKeyB64 string) string {
	m.resolveCtxMu.Lock()
	defer m.resolveCtxMu.Unlock()
	if m.resolvedOwnerIDs == nil {
		return ""
	}
	return m.resolvedOwnerIDs[pubKeyB64]
}

// SetResolvedOwnerID pre-installs a pubkey→ownerID mapping that
// ResolveOwnerIDByPubKey will return. Used by forward-receiver tests
// to fence that the resolved owner_id propagates through
// PublishACKTokens onto the stored ACK entry.
func (m *MockForwarderDeps) SetResolvedOwnerID(pubKeyB64, ownerID string) {
	m.resolveCtxMu.Lock()
	defer m.resolveCtxMu.Unlock()
	if m.resolvedOwnerIDs == nil {
		m.resolvedOwnerIDs = make(map[string]string)
	}
	m.resolvedOwnerIDs[pubKeyB64] = ownerID
}
