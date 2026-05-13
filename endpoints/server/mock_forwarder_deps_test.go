package server

import (
	"context"
	"sync"

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
}

// NewMockForwarderDeps creates a new mock with sensible defaults.
func NewMockForwarderDeps() *MockForwarderDeps {
	return &MockForwarderDeps{
		hostname:     "test-server",
		sendCh:       make(chan *core.MsgData, 10),
		storedTokens: make(map[string]*ACTokenEntry),
	}
}

func (m *MockForwarderDeps) GetHostname() string {
	return m.hostname
}

func (m *MockForwarderDeps) GetDevice() *core.Device {
	return m.device
}

func (m *MockForwarderDeps) SendMessage(md *core.MsgData) {
	if m.sendCh != nil {
		m.sendCh <- md
	}
}

func (m *MockForwarderDeps) FindACConnectionsForKnock(knkMsg *common.AgentKnockMsg) []*ACConn {
	return m.acConns
}

func (m *MockForwarderDeps) FindAuthSvcProvider(authSvcId string) *common.AuthServiceProviderData {
	return m.aspData
}

func (m *MockForwarderDeps) ProcessACOperation(
	knkMsg *common.AgentKnockMsg,
	acConn *ACConn,
	srcAddr *common.NetAddress,
	dstAddrs []*common.NetAddress,
	openTime uint32,
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
) (*common.ACOpsResultMsg, error) {
	if len(conns) > 0 {
		return m.ProcessACOperation(knkMsg, conns[0], srcAddr, dstAddrs, openTime)
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
func (m *MockForwarderDeps) PublishACKTokens(knkMsg *common.AgentKnockMsg, ackMsg *common.ServerKnockAckMsg, srcIp string, openTime int) {
	for name, token := range ackMsg.ACTokens {
		if token == "" {
			continue
		}
		m.StoreACToken(token, NewACKTokenEntry(knkMsg, name, ackMsg.ACTokens, srcIp, openTime))
	}
}
