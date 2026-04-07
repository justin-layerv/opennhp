package server

import (
	"context"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
)

// MockForwarderDeps implements ForwarderDeps for testing.
type MockForwarderDeps struct {
	hostname      string
	device        *core.Device
	sendCh        chan *core.MsgData
	acConns       []*ACConn
	aspData       *common.AuthServiceProviderData
	processResult *common.ACOpsResultMsg
	processErr    error
}

// NewMockForwarderDeps creates a new mock with sensible defaults.
func NewMockForwarderDeps() *MockForwarderDeps {
	return &MockForwarderDeps{
		hostname: "test-server",
		sendCh:   make(chan *core.MsgData, 10),
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
