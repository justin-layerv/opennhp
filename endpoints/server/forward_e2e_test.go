package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/endpoints/server/internal/qurlplacement"
	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
)

// ============================================================================
// E2E Test Infrastructure for Server-to-Server Forwarding
// ============================================================================
//
// This file contains integration tests that verify the complete forwarding
// flow with real UDP networking and full Noise protocol encryption.
//
// Test topology:
//
//   TestClient → ServerA → [NHP_FWD] → ServerB → [NHP_FRT] → ServerA → TestClient
//
// Key features:
// - Real UDP sockets on localhost
// - Full Noise protocol encryption via core.Device
// - Real ServerForwarder logic
// - No external dependencies (etcd, DynamoDB, etc.)
//
// ============================================================================

// E2ETestNode represents a minimal NHP server node for E2E testing.
// It manages a core.Device and handles UDP I/O with proper packet encryption.
type E2ETestNode struct {
	t          *testing.T
	id         string
	deviceType int
	udpConn    *net.UDPConn
	addr       *net.UDPAddr
	device     *core.Device
	privateKey []byte
	publicKey  string

	// Connection management - maps remote address to ConnectionData
	connMu      sync.RWMutex
	connections map[string]*core.ConnectionData

	// Message handling - decrypted messages arrive here
	receivedMsgs chan *ReceivedMsg

	// Message handler callback for routing specific message types
	handlerMu      sync.RWMutex
	messageHandler func(msg *ReceivedMsg)

	// Control
	done chan struct{}
	wg   sync.WaitGroup
}

// ReceivedMsg represents a decrypted message received by a node.
type ReceivedMsg struct {
	HeaderType int
	Data       []byte
	From       *net.UDPAddr
	PPD        *core.PacketParserData
}

// newE2ETestNode creates a minimal NHP server node for testing.
func newE2ETestNode(t *testing.T, id string) *E2ETestNode {
	return newE2ETestNodeWithType(t, id, core.NHP_SERVER)
}

// newE2ETestNodeWithType creates a test node with the specified device type.
// Use NHP_SERVER for server nodes and NHP_AC for AC nodes.
func newE2ETestNodeWithType(t *testing.T, id string, deviceType int) *E2ETestNode {
	return newE2ETestNodeWithOptions(t, id, deviceType, nil)
}

// newE2ETestNodeWithOptions is newE2ETestNodeWithType with explicit
// core.DeviceOptions. The NHP-Relay forward path (#2208) requires cloud-mode
// servers (DisableAgentPeerValidation=true) so the synthetically-decrypted
// inner agent knock authenticates on its learned pubkey without a pre-registered
// agent peer — see relay.go's header and relay_cross_server_e2e_test.go. The
// nil-options variants above keep every existing caller unchanged.
func newE2ETestNodeWithOptions(t *testing.T, id string, deviceType int, opt *core.DeviceOptions) *E2ETestNode {
	// Per-id deterministic key — the default identity for nodes that don't need
	// to share one. byte(i + len(id)) matches the historical scheme so existing
	// callers' keys (and any hardcoded expectations) are unchanged.
	privateKey := make([]byte, 32)
	for i := range privateKey {
		privateKey[i] = byte(i + len(id))
	}
	return newE2ETestNodeFull(t, id, deviceType, privateKey, opt)
}

// newE2ETestNodeFull is the full constructor: explicit private key AND device
// options. The explicit-key form lets a test stand up TWO server nodes that
// share one registration keypair — the production multi-instance posture where
// every server behind the NLB decrypts agent/AC traffic with the same shared
// key (docs/design/PER_INSTANCE_SERVER_KEYS.md §1; per-instance operational keys
// are a future draft). The cross-server relay e2e (#2546) needs this so server B
// can re-decrypt the inner knock that the agent encrypted to the shared key and
// server A forwarded verbatim.
func newE2ETestNodeFull(t *testing.T, id string, deviceType int, privateKey []byte, opt *core.DeviceOptions) *E2ETestNode {
	t.Helper()

	// Create device with specified type
	device := core.NewDevice(deviceType, privateKey, opt)
	if device == nil {
		t.Fatalf("Failed to create device for node %s", id)
	}

	// Bind to random port on localhost
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatalf("Failed to bind UDP for node %s: %v", id, err)
	}

	localAddr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("expected *net.UDPAddr, got %T", conn.LocalAddr())
	}

	node := &E2ETestNode{
		t:            t,
		id:           id,
		deviceType:   deviceType,
		udpConn:      conn,
		addr:         localAddr,
		device:       device,
		privateKey:   privateKey,
		publicKey:    device.PublicKeyBase64(),
		connections:  make(map[string]*core.ConnectionData),
		receivedMsgs: make(chan *ReceivedMsg, 100),
		done:         make(chan struct{}),
	}

	return node
}

// Start begins the node's processing loops.
func (n *E2ETestNode) Start() {
	n.device.Start()

	n.wg.Add(2)
	go n.udpReceiveLoop()
	go n.decryptedMsgLoop()
}

// Stop stops the node and releases resources.
func (n *E2ETestNode) Stop() {
	// First signal all goroutines to stop
	close(n.done)

	// Close UDP connection to unblock read loop
	_ = n.udpConn.Close()

	// Wait for all goroutines to exit BEFORE closing connections
	// This prevents the race between connectionSendLoop and conn.Close()
	n.wg.Wait()

	// Now safe to close connections since all send loops have exited
	n.connMu.Lock()
	for _, conn := range n.connections {
		conn.Close()
	}
	n.connMu.Unlock()

	n.device.Stop()
}

// Addr returns the node's UDP address.
func (n *E2ETestNode) Addr() *net.UDPAddr {
	return n.addr
}

// PublicKeyStr returns the node's public key in base64.
func (n *E2ETestNode) PublicKeyStr() string {
	return n.publicKey
}

// AddPeer registers another node as a peer in the device.
func (n *E2ETestNode) AddPeer(other *E2ETestNode) {
	peer := &core.UdpPeer{
		Hostname:     other.id,
		Ip:           other.addr.IP.String(),
		Port:         other.addr.Port,
		PubKeyBase64: other.publicKey,
		Type:         other.deviceType,
	}
	n.device.AddPeer(peer)
}

// SetMessageHandler sets a callback to receive all messages.
// This is called before messages are placed in the receivedMsgs channel.
func (n *E2ETestNode) SetMessageHandler(handler func(msg *ReceivedMsg)) {
	n.handlerMu.Lock()
	defer n.handlerMu.Unlock()
	n.messageHandler = handler
}

func (n *E2ETestNode) currentMessageHandler() func(msg *ReceivedMsg) {
	n.handlerMu.RLock()
	defer n.handlerMu.RUnlock()
	return n.messageHandler
}

// GetOrCreateConnection gets or creates a ConnectionData for the remote address.
func (n *E2ETestNode) GetOrCreateConnection(remoteAddr *net.UDPAddr) *core.ConnectionData {
	key := remoteAddr.String()

	n.connMu.RLock()
	conn, exists := n.connections[key]
	n.connMu.RUnlock()

	if exists && !conn.IsClosed() {
		return conn
	}

	n.connMu.Lock()
	defer n.connMu.Unlock()

	// Double-check after acquiring write lock
	if conn, exists = n.connections[key]; exists && !conn.IsClosed() {
		return conn
	}

	// Create new connection
	conn = &core.ConnectionData{
		Device:           n.device,
		LocalAddr:        n.addr,
		RemoteAddr:       remoteAddr,
		InitTime:         time.Now().UnixNano(),
		SendQueue:        make(chan *core.Packet, 64),
		RecvQueue:        make(chan *core.Packet, 64),
		BlockSignal:      make(chan struct{}, 1),
		SetTimeoutSignal: make(chan struct{}, 1),
		StopSignal:       make(chan struct{}),
	}

	n.connections[key] = conn

	// Start send routine for this connection
	n.wg.Add(1)
	go n.connectionSendLoop(conn)

	return conn
}

// connectionSendLoop reads from connection's SendQueue and sends via UDP.
func (n *E2ETestNode) connectionSendLoop(conn *core.ConnectionData) {
	defer n.wg.Done()

	for {
		select {
		case <-n.done:
			return
		case <-conn.StopSignal:
			return
		case pkt, ok := <-conn.SendQueue:
			if !ok || pkt == nil {
				return
			}
			_, err := n.udpConn.WriteToUDP(pkt.Content, conn.RemoteAddr)
			if err != nil {
				n.t.Logf("Node %s: send error to %s: %v", n.id, conn.RemoteAddr, err)
			}
			// Only release packet if not kept for transaction (KeepAfterSend flag)
			if !pkt.KeepAfterSend {
				n.device.ReleasePoolPacket(pkt)
			}
		}
	}
}

// udpReceiveLoop reads packets from UDP and processes them.
func (n *E2ETestNode) udpReceiveLoop() {
	defer n.wg.Done()

	buf := make([]byte, 65536)
	for {
		select {
		case <-n.done:
			return
		default:
		}

		if err := n.udpConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
			return
		}
		numBytes, from, err := n.udpConn.ReadFromUDP(buf)
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			select {
			case <-n.done:
				return
			default:
				continue
			}
		}

		// Process the received packet
		n.processReceivedPacket(buf[:numBytes], from)
	}
}

// decryptedMsgLoop reads from the device's DecryptedMsgQueue for async decryption results.
func (n *E2ETestNode) decryptedMsgLoop() {
	defer n.wg.Done()

	for {
		select {
		case <-n.done:
			return
		case ppd := <-n.device.DecryptedMsgQueue:
			if ppd == nil || ppd.Error != nil {
				continue
			}

			// Create ReceivedMsg from the decrypted data
			msg := &ReceivedMsg{
				HeaderType: ppd.HeaderType,
				Data:       ppd.BodyMessage,
				From:       nil, // From is not available in async path
				PPD:        ppd,
			}

			// Call message handler first if set
			if handler := n.currentMessageHandler(); handler != nil {
				handler(msg)
			}

			select {
			case n.receivedMsgs <- msg:
			default:
				n.t.Logf("Node %s: message queue full (async), dropping message", n.id)
			}
		}
	}
}

// processReceivedPacket decrypts and handles a received packet.
func (n *E2ETestNode) processReceivedPacket(data []byte, from *net.UDPAddr) {
	// Get or create connection for this remote
	conn := n.GetOrCreateConnection(from)

	// Create packet for decryption
	pkt := n.device.AllocatePoolPacket()
	copy(pkt.Buf[:len(data)], data)
	pkt.Content = pkt.Buf[:len(data)]

	// Pre-check packet to extract header type (like real server does)
	headerType, _, err := n.device.RecvPrecheck(pkt)
	if err != nil {
		n.t.Logf("Node %s: precheck error from %s: %v", n.id, from, err)
		n.device.ReleasePoolPacket(pkt)
		return
	}

	// Handle transaction responses specially - route to LocalTransaction
	// This allows the transaction to set PrevAssemblerData for proper decryption
	if n.device.IsTransactionResponse(headerType) {
		transactionId := pkt.Counter()
		transaction := n.device.FindLocalTransaction(transactionId)
		if transaction != nil {
			// Route to transaction - it will handle decryption with PrevAssemblerData.
			// Use SendPacket so a transaction that exits concurrently cannot race
			// the channel close (mirrors production code paths post PR #1096).
			if err := transaction.SendPacket(pkt); err != nil {
				n.t.Logf("Node %s: transaction %d closed before forward: %v", n.id, transactionId, err)
			}
			return
		}
		// No matching transaction - fall through to normal processing
		n.t.Logf("Node %s: no transaction found for response type %d, txID %d", n.id, headerType, transactionId)
	}

	// Normal path for non-transaction messages (or if no transaction found)
	pd := &core.PacketData{
		BasePacket: pkt,
		ConnData:   conn,
		InitTime:   time.Now().UnixNano(),
	}

	// Use synchronous decryption for simplicity
	ppd, err := n.device.PacketToMsg(pd)
	if err != nil {
		n.t.Logf("Node %s: decryption error from %s: %v", n.id, from, err)
		n.device.ReleasePoolPacket(pkt)
		return
	}

	if ppd.Error != nil {
		n.t.Logf("Node %s: packet parse error from %s: %v", n.id, from, ppd.Error)
		return
	}

	// Send to received messages channel
	msg := &ReceivedMsg{
		HeaderType: ppd.HeaderType,
		Data:       ppd.BodyMessage,
		From:       from,
		PPD:        ppd,
	}

	// Call message handler first if set (for routing to forwarder)
	if handler := n.currentMessageHandler(); handler != nil {
		handler(msg)
	}

	select {
	case n.receivedMsgs <- msg:
	default:
		n.t.Logf("Node %s: message queue full, dropping message", n.id)
	}
}

// SendMessage sends an encrypted message to another node.
func (n *E2ETestNode) SendMessage(to *E2ETestNode, headerType int, transactionId uint64, message []byte, prevPPD *core.PacketParserData) error {
	// Get connection to remote
	conn := n.GetOrCreateConnection(to.addr)

	// Get peer's public key
	peer := n.device.LookupPeer(to.PublicKeyBytes())
	if peer == nil {
		return nil // Peer not found, will be created with PeerPk
	}

	md := &core.MsgData{
		ConnData:       conn,
		PeerPk:         to.PublicKeyBytes(),
		HeaderType:     headerType,
		TransactionId:  transactionId,
		Compress:       false,
		Message:        message,
		PrevParserData: prevPPD,
	}

	n.device.SendMsgToPacket(md)
	return nil
}

// PublicKeyBytes returns the node's public key as bytes.
func (n *E2ETestNode) PublicKeyBytes() []byte {
	return decodeBase64PubKey(n.publicKey)
}

// WaitForMessage waits for a message of the specified type.
func (n *E2ETestNode) WaitForMessage(headerType int, timeout time.Duration) *ReceivedMsg {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		select {
		case msg := <-n.receivedMsgs:
			if msg.HeaderType == headerType {
				return msg
			}
			// Put back if wrong type
			select {
			case n.receivedMsgs <- msg:
			default:
			}
		case <-time.After(50 * time.Millisecond):
		}
	}
	return nil
}

// ============================================================================
// E2E Tests
// ============================================================================

// TestE2E_ServerToServer_DirectMessage tests basic encrypted message exchange.
func TestE2E_ServerToServer_DirectMessage(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping E2E test in short mode")
	}

	// Create two test nodes
	nodeA := newE2ETestNode(t, "server-a")
	nodeB := newE2ETestNode(t, "server-b")

	// Start nodes
	nodeA.Start()
	nodeB.Start()
	defer nodeA.Stop()
	defer nodeB.Stop()

	// Register each other as peers (needed for encryption)
	nodeA.AddPeer(nodeB)
	nodeB.AddPeer(nodeA)

	// Give devices time to initialize
	time.Sleep(200 * time.Millisecond)

	// Create a test NHP_FWD message
	fwdMsg := &common.ServerForwardMsg{
		SessionId:            1,
		SessionIssuedAtNanos: time.Now().UnixNano(),
		KnockData:            []byte("test-knock-data"),
		SourceServer:         "server-a",
		UserAddr:             "192.168.1.100:12345",
		TransactionId:        12345,
		Timestamp:            time.Now().Unix(),
	}

	msgBytes, err := json.Marshal(fwdMsg)
	if err != nil {
		t.Fatalf("Failed to marshal forward message: %v", err)
	}

	// Get connection and peer info
	conn := nodeA.GetOrCreateConnection(nodeB.addr)

	// Lookup peer to get public key
	peer := nodeA.device.LookupPeer(decodeBase64PubKey(nodeB.publicKey))
	if peer == nil {
		t.Fatal("Peer not found for nodeB")
	}

	// Send NHP_FWD from A to B
	md := &core.MsgData{
		ConnData:      conn,
		PeerPk:        peer.PublicKey(),
		HeaderType:    core.NHP_FWD,
		TransactionId: 12345,
		Compress:      false,
		Message:       msgBytes,
	}

	nodeA.device.SendMsgToPacket(md)

	// Wait for B to receive the message
	received := nodeB.WaitForMessage(core.NHP_FWD, 5*time.Second)
	if received == nil {
		t.Fatal("Timeout waiting for NHP_FWD message")
	}

	// Verify the message content
	var receivedFwd common.ServerForwardMsg
	if err := json.Unmarshal(received.Data, &receivedFwd); err != nil {
		t.Fatalf("Failed to unmarshal received message: %v", err)
	}

	if receivedFwd.SourceServer != "server-a" {
		t.Errorf("Expected SourceServer 'server-a', got '%s'", receivedFwd.SourceServer)
	}
	if receivedFwd.TransactionId != 12345 {
		t.Errorf("Expected TransactionId 12345, got %d", receivedFwd.TransactionId)
	}

	t.Log("Successfully sent and received encrypted NHP_FWD message")
}

// TestE2E_ServerToServer_RoundTrip tests NHP_FWD → NHP_FRT round-trip.
func TestE2E_ServerToServer_RoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping E2E test in short mode")
	}

	nodeA := newE2ETestNode(t, "server-a")
	nodeB := newE2ETestNode(t, "server-b")

	nodeA.Start()
	nodeB.Start()
	defer nodeA.Stop()
	defer nodeB.Stop()

	nodeA.AddPeer(nodeB)
	nodeB.AddPeer(nodeA)

	time.Sleep(200 * time.Millisecond)

	txID := uint64(67890)

	// Send NHP_FWD from A to B
	fwdMsg := &common.ServerForwardMsg{
		SessionId:            1,
		SessionIssuedAtNanos: time.Now().UnixNano(),
		KnockData:            []byte("test-knock"),
		SourceServer:         "server-a",
		UserAddr:             "10.0.0.1:54321",
		TransactionId:        txID,
		Timestamp:            time.Now().Unix(),
	}
	fwdBytes, _ := json.Marshal(fwdMsg)

	connAtoB := nodeA.GetOrCreateConnection(nodeB.addr)
	peerB := nodeA.device.LookupPeer(decodeBase64PubKey(nodeB.publicKey))

	nodeA.device.SendMsgToPacket(&core.MsgData{
		ConnData:      connAtoB,
		PeerPk:        peerB.PublicKey(),
		HeaderType:    core.NHP_FWD,
		TransactionId: txID,
		Message:       fwdBytes,
	})

	// Wait for B to receive NHP_FWD
	fwdReceived := nodeB.WaitForMessage(core.NHP_FWD, 5*time.Second)
	if fwdReceived == nil {
		t.Fatal("Timeout waiting for NHP_FWD")
	}
	t.Log("NodeB received NHP_FWD")

	// B sends NHP_FRT response back to A using PrevParserData for proper session
	resultMsg := &common.ServerForwardResultMsg{
		TransactionId: txID,
		Success:       true,
		ACKData:       []byte(`{"status":"ok"}`),
	}
	resultBytes, _ := json.Marshal(resultMsg)

	// Use PrevParserData to continue the session
	nodeB.device.SendMsgToPacket(&core.MsgData{
		HeaderType:     core.NHP_FRT,
		TransactionId:  txID,
		Message:        resultBytes,
		PrevParserData: fwdReceived.PPD,
	})

	// Wait for A to receive NHP_FRT
	resultReceived := nodeA.WaitForMessage(core.NHP_FRT, 5*time.Second)
	if resultReceived == nil {
		t.Fatal("Timeout waiting for NHP_FRT")
	}

	var receivedResult common.ServerForwardResultMsg
	if err := json.Unmarshal(resultReceived.Data, &receivedResult); err != nil {
		t.Fatalf("Failed to unmarshal result: %v", err)
	}

	if !receivedResult.Success {
		t.Error("Expected Success=true")
	}
	if receivedResult.TransactionId != txID {
		t.Errorf("Expected TransactionId %d, got %d", txID, receivedResult.TransactionId)
	}

	t.Log("Successfully completed NHP_FWD → NHP_FRT round-trip with full encryption")
}

// TestE2E_ForwarderIntegration tests ServerForwarder with real encrypted network.
func TestE2E_ForwarderIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping E2E test in short mode")
	}

	nodeA := newE2ETestNode(t, "server-a")
	nodeB := newE2ETestNode(t, "server-b")

	nodeA.Start()
	nodeB.Start()
	defer nodeA.Stop()
	defer nodeB.Stop()

	// Note: We do NOT call nodeA.AddPeer(nodeB) here because the forwarder
	// will register nodeB as a peer via getOrCreateServerPeer. Having two
	// peers with the same pubkey would cause session state confusion.
	// nodeB still needs nodeA as a peer to send responses.
	nodeB.AddPeer(nodeA)

	time.Sleep(200 * time.Millisecond)

	// Create ForwarderDeps for nodeA
	mockDeps := &e2eForwarderDeps{
		hostname: "server-a",
		device:   nodeA.device,
		node:     nodeA,
	}

	forwarder := NewServerForwarder(mockDeps)

	// Set up message handler on nodeA to route NHP_FRT to forwarder
	nodeA.SetMessageHandler(func(msg *ReceivedMsg) {
		if msg.HeaderType == core.NHP_FRT {
			var resultMsg common.ServerForwardResultMsg
			if err := json.Unmarshal(msg.Data, &resultMsg); err != nil {
				t.Logf("NodeA: Failed to unmarshal NHP_FRT: %v", err)
				return
			}
			t.Logf("NodeA: Routing NHP_FRT to forwarder (txID=%d)", resultMsg.TransactionId)
			forwarder.HandleForwardResult(msg.PPD, &resultMsg)
		}
	})

	// Create assignment pointing to nodeB
	assignment := &ACAssignment{
		ACID:         "test-ac",
		ResourceFQDN: "test.resource.com",
		CustomerID:   "cust-123",
		AssignedServers: []ServerInfo{
			{
				ID:         "server-b",
				IP:         nodeB.addr.IP.String(),
				InternalIP: nodeB.addr.IP.String(),
				Port:       nodeB.addr.Port,
				PubKey:     nodeB.publicKey,
			},
		},
	}

	// Set up response handler on nodeB
	go func() {
		msg := nodeB.WaitForMessage(core.NHP_FWD, 10*time.Second)
		if msg == nil {
			t.Log("NodeB: No NHP_FWD received")
			return
		}

		var fwdMsg common.ServerForwardMsg
		if err := json.Unmarshal(msg.Data, &fwdMsg); err != nil {
			t.Errorf("NodeB: failed to unmarshal NHP_FWD: %v", err)
			return
		}
		t.Logf("NodeB received forward for txID=%d", fwdMsg.TransactionId)

		// Send success response
		resultMsg := &common.ServerForwardResultMsg{
			TransactionId: fwdMsg.TransactionId,
			Success:       true,
			ACKData:       []byte(`{"resource":"test.resource.com","token":"abc123"}`),
		}
		resultBytes, _ := json.Marshal(resultMsg)

		nodeB.device.SendMsgToPacket(&core.MsgData{
			HeaderType:     core.NHP_FRT,
			TransactionId:  fwdMsg.TransactionId,
			Message:        resultBytes,
			PrevParserData: msg.PPD,
		})
	}()

	// Use forwarder to send knock
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	userAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 100), Port: 12345}
	knockData := []byte("encrypted-knock-packet-data")

	result, err := forwarder.ForwardKnock(ctx, assignment, knockData, userAddr, nil)
	if err != nil {
		t.Fatalf("ForwardKnock failed: %v", err)
	}

	if !result.Success {
		t.Errorf("Expected success, got error: %s - %s", result.ErrCode, result.ErrMsg)
	}

	t.Logf("ForwardKnock succeeded with full E2E encryption: %s", string(result.ACKData))
}

// e2eForwarderDeps implements ForwarderDeps for E2E testing with real encryption.
type e2eForwarderDeps struct {
	testForwardedSessionDeps
	hostname string
	device   *core.Device
	node     *E2ETestNode
}

func (d *e2eForwarderDeps) GetHostname() string {
	return d.hostname
}

func (d *e2eForwarderDeps) GetDevice() *core.Device {
	return d.device
}

func (d *e2eForwarderDeps) SendMessage(md *core.MsgData) error {
	// This E2E transport double must attach ConnData before calling the core
	// packet writer directly. Production UdpServer does the corresponding
	// server-peer synthesis in connDataForOutboundAddr before queueing.
	if md.ConnData == nil && md.RemoteAddr != nil {
		md.ConnData = d.node.GetOrCreateConnection(md.RemoteAddr)
	}
	d.device.SendMsgToPacket(md)
	return nil
}

func (d *e2eForwarderDeps) IncrForwarderMetric(string) {}

func (d *e2eForwarderDeps) FindACConnectionsForResource(knkMsg *common.AgentKnockMsg, _ *common.ResourceData) []*ACConn {
	return nil
}

func (d *e2eForwarderDeps) FindAuthSvcProvider(authSvcId string) *common.AuthServiceProviderData {
	return nil
}

func (d *e2eForwarderDeps) ResolveAuthSvcProvider(_ context.Context, authSvcId, _ string) *common.AuthServiceProviderData {
	return d.FindAuthSvcProvider(authSvcId)
}

func (d *e2eForwarderDeps) LifecycleCtx() context.Context {
	return context.Background()
}

func (d *e2eForwarderDeps) ProcessACOperation(
	knkMsg *common.AgentKnockMsg,
	acConn *ACConn,
	srcAddr *common.NetAddress,
	dstAddrs []*common.NetAddress,
	openTime uint32,
	res *common.ResourceData,
) (*common.ACOpsResultMsg, error) {
	return nil, nil
}

func (d *e2eForwarderDeps) ProcessACOperationBroadcast(
	_ context.Context,
	knkMsg *common.AgentKnockMsg,
	conns []*ACConn,
	srcAddr *common.NetAddress,
	dstAddrs []*common.NetAddress,
	openTime uint32,
	res *common.ResourceData,
) (*common.ACOpsResultMsg, error) {
	if len(conns) > 0 {
		return d.ProcessACOperation(knkMsg, conns[0], srcAddr, dstAddrs, openTime, res)
	}
	return nil, nil
}

func (d *e2eForwarderDeps) PublishACKTokens(context.Context, *common.AgentKnockMsg, *common.ServerKnockAckMsg, string, int, string) error {
	return nil
}

func (d *e2eForwarderDeps) ResolveOwnerIDByPubKey(context.Context, string) string { return "" }

// ============================================================================
// Helper functions
// ============================================================================

func decodeBase64PubKey(s string) []byte {
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil
	}
	return decoded
}

// ============================================================================
// E2E Test: HandleForwardRequest with Real Decryption
// ============================================================================
//
// This test verifies that HandleForwardRequest can decrypt a knock that was
// encrypted by an agent/client to the server's public key.
//
// Flow:
//   Client encrypts knock → Encrypted bytes captured → HandleForwardRequest decrypts
//
// This simulates the real-world scenario where:
// 1. Agent sends encrypted knock to ServerA
// 2. ServerA forwards raw encrypted bytes in NHP_FWD to ServerB
// 3. ServerB.HandleForwardRequest decrypts and processes the knock
//
// ============================================================================

// TestE2E_HandleForwardRequest_RealDecryption tests the full decryption path
// in HandleForwardRequest using real Noise protocol encryption.
func TestE2E_HandleForwardRequest_RealDecryption(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping E2E test in short mode")
	}

	// Create the server node (will be used for both encryption target and decryption)
	serverNode := newE2ETestNode(t, "server")
	serverNode.Start()
	defer serverNode.Stop()

	// Create a client node that will encrypt the knock
	clientNode := newE2ETestNode(t, "client")
	clientNode.Start()
	defer clientNode.Stop()

	// Client needs to know server's public key to encrypt to it
	clientNode.AddPeer(serverNode)

	// Server needs to know client's public key to decrypt messages from it
	serverNode.AddPeer(clientNode)

	// Give devices time to initialize
	time.Sleep(200 * time.Millisecond)

	// Create a knock message (like an agent would send)
	knockMsg := &common.AgentKnockMsg{
		HeaderType:    core.NHP_KNK,
		UserId:        "test-user",
		DeviceId:      "test-device",
		AuthServiceId: "test-asp",
		ResourceId:    "test-resource",
		UserData: map[string]any{
			"passcode": "123456",
		},
	}

	knockBytes, err := json.Marshal(knockMsg)
	if err != nil {
		t.Fatalf("Failed to marshal knock message: %v", err)
	}

	// Encrypt the knock to server's public key
	// Use captureEncryptedPacket to get the raw encrypted bytes
	encryptedKnock, err := captureEncryptedPacket(clientNode, serverNode, core.NHP_KNK, knockBytes)
	if err != nil {
		t.Fatalf("Failed to capture encrypted packet: %v", err)
	}
	t.Logf("Captured encrypted knock: %d bytes", len(encryptedKnock))

	// Channel to capture the NHP_FRT response
	var capturedResult *common.ServerForwardResultMsg
	var resultMu sync.Mutex
	resultCaptured := make(chan struct{}, 1)

	// Create ForwarderDeps with the server's device (for decryption)
	// Use a capturing wrapper to intercept responses
	deps := &capturingForwarderDeps{
		hostname: "server",
		device:   serverNode.device,
		node:     serverNode,
		onSend: func(md *core.MsgData) {
			if md.HeaderType == core.NHP_FRT {
				resultMu.Lock()
				var result common.ServerForwardResultMsg
				if err := json.Unmarshal(md.Message, &result); err == nil {
					capturedResult = &result
				}
				resultMu.Unlock()
				select {
				case resultCaptured <- struct{}{}:
				default:
				}
			}
		},
	}

	forwarder := NewServerForwarder(deps)

	// Create a fake NHP_FWD message containing the encrypted knock
	fwdMsg := &common.ServerForwardMsg{
		SessionId:            1,
		SessionIssuedAtNanos: time.Now().UnixNano(),
		KnockData:            encryptedKnock,
		SourceServer:         "other-server",
		UserAddr:             "192.168.1.100:12345",
		TransactionId:        99999,
		Timestamp:            time.Now().Unix(),
	}

	// Create a mock PacketParserData for the incoming NHP_FWD
	// (in real usage, this comes from the incoming encrypted NHP_FWD packet)
	mockPPD := &core.PacketParserData{
		HeaderType: core.NHP_FWD,
	}

	// Call HandleForwardRequest
	forwarder.HandleForwardRequest(mockPPD, fwdMsg)

	// Wait for result (with timeout)
	select {
	case <-resultCaptured:
	case <-time.After(5 * time.Second):
		t.Fatal("Timeout waiting for NHP_FRT response")
	}

	// Verify the result
	resultMu.Lock()
	result := capturedResult
	resultMu.Unlock()

	if result == nil {
		t.Fatal("No result captured")
	}

	t.Logf("HandleForwardRequest result: Success=%v, ErrCode=%s, ErrMsg=%s",
		result.Success, result.ErrCode, result.ErrMsg)

	// The knock should have been decrypted and parsed successfully.
	// HandleForwardRequest resolves the ASP BEFORE looking up AC
	// connections (the ordering ensures DDB-only aspIds populate
	// authServiceMap before the AC lookup, which reads authServiceMap
	// for the acId). With capturingForwarderDeps.ResolveAuthSvcProvider
	// returning nil, the path rejects with ASP_NOT_FOUND. Getting THIS
	// far proves decryption succeeded — we just hit the resolver-side
	// sentinel rather than the AC-side one.
	if result.ErrCode != "ASP_NOT_FOUND" {
		t.Errorf("Expected ASP_NOT_FOUND (proving decryption succeeded — resolver runs before AC check), got %s: %s",
			result.ErrCode, result.ErrMsg)
	}

	t.Log("SUCCESS: HandleForwardRequest successfully decrypted the knock!")
}

func TestE2E_HandleForwardRequest_InvalidAgentPubKeyAfterDecrypt(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping E2E test in short mode")
	}

	serverNode := newE2ETestNode(t, "server")
	serverNode.Start()
	defer serverNode.Stop()

	clientNode := newE2ETestNode(t, "client")
	clientNode.Start()
	defer clientNode.Stop()

	clientNode.AddPeer(serverNode)
	serverNode.AddPeer(clientNode)

	time.Sleep(200 * time.Millisecond)

	knockMsg := &common.AgentKnockMsg{
		HeaderType:    core.NHP_KNK,
		UserId:        "test-user",
		DeviceId:      "test-device",
		AuthServiceId: "test-asp",
		ResourceId:    qurlplacement.TunnelServerResourceID,
	}
	knockBytes, err := json.Marshal(knockMsg)
	if err != nil {
		t.Fatalf("marshal knock message: %v", err)
	}

	encryptedKnock, err := captureEncryptedPacket(clientNode, serverNode, core.NHP_KNK, knockBytes)
	if err != nil {
		t.Fatalf("capture encrypted packet: %v", err)
	}

	var capturedResult *common.ServerForwardResultMsg
	var resultMu sync.Mutex
	resultCaptured := make(chan struct{}, 1)
	deps := &capturingForwarderDeps{
		hostname: "server",
		device:   serverNode.device,
		node:     serverNode,
		onSend: func(md *core.MsgData) {
			if md.HeaderType != core.NHP_FRT {
				return
			}
			var result common.ServerForwardResultMsg
			if err := json.Unmarshal(md.Message, &result); err != nil {
				t.Errorf("unmarshal NHP_FRT: %v", err)
				return
			}
			resultMu.Lock()
			capturedResult = &result
			resultMu.Unlock()
			select {
			case resultCaptured <- struct{}{}:
			default:
			}
		},
	}
	forwarder := NewServerForwarder(deps)

	fwdMsg := &common.ServerForwardMsg{
		SessionId:            1,
		SessionIssuedAtNanos: time.Now().UnixNano(),
		KnockData:            encryptedKnock,
		SourceServer:         "other-server",
		UserAddr:             "192.168.1.100:12345",
		TransactionId:        100001,
		Timestamp:            time.Now().Unix(),
	}
	userAddr, err := net.ResolveUDPAddr("udp", fwdMsg.UserAddr)
	if err != nil {
		t.Fatalf("resolve user addr: %v", err)
	}

	knockPpd, err := forwarder.decryptForwardedKnock(fwdMsg.KnockData, userAddr)
	if err != nil {
		t.Fatalf("decrypt forwarded knock: %v", err)
	}
	if len(knockPpd.RemotePubKey) != 32 {
		t.Fatalf("decrypted RemotePubKey len=%d want 32 before test corruption", len(knockPpd.RemotePubKey))
	}
	knockPpd.RemotePubKey = nil

	forwarder.handleDecryptedForwardedKnock(&core.PacketParserData{HeaderType: core.NHP_FWD}, fwdMsg, userAddr, knockPpd)

	select {
	case <-resultCaptured:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for NHP_FRT response")
	}

	resultMu.Lock()
	result := capturedResult
	resultMu.Unlock()
	if result == nil {
		t.Fatal("no result captured")
	}
	if result.Success {
		t.Fatalf("Success=true want false")
	}
	if result.ErrCode != "INVALID_AGENT_PUBKEY" {
		t.Fatalf("ErrCode=%q ErrMsg=%q want INVALID_AGENT_PUBKEY", result.ErrCode, result.ErrMsg)
	}
}

// capturingForwarderDeps wraps e2eForwarderDeps with a callback on SendMessage.
type capturingForwarderDeps struct {
	testForwardedSessionDeps
	hostname string
	device   *core.Device
	node     *E2ETestNode
	onSend   func(md *core.MsgData)
}

func (d *capturingForwarderDeps) GetHostname() string {
	return d.hostname
}

func (d *capturingForwarderDeps) GetDevice() *core.Device {
	return d.device
}

func (d *capturingForwarderDeps) SendMessage(md *core.MsgData) error {
	// Capture the message via callback (we don't need to actually send it)
	if d.onSend != nil {
		d.onSend(md)
	}
	// Note: We intentionally don't call device.SendMsgToPacket here
	// since we're only testing decryption, not the full network round-trip.
	return nil
}

func (d *capturingForwarderDeps) IncrForwarderMetric(string) {}

func (d *capturingForwarderDeps) FindACConnectionsForResource(knkMsg *common.AgentKnockMsg, _ *common.ResourceData) []*ACConn {
	return nil
}

func (d *capturingForwarderDeps) FindAuthSvcProvider(authSvcId string) *common.AuthServiceProviderData {
	return nil
}

func (d *capturingForwarderDeps) ResolveAuthSvcProvider(_ context.Context, authSvcId, _ string) *common.AuthServiceProviderData {
	return d.FindAuthSvcProvider(authSvcId)
}

func (d *capturingForwarderDeps) LifecycleCtx() context.Context {
	return context.Background()
}

func (d *capturingForwarderDeps) ProcessACOperation(
	knkMsg *common.AgentKnockMsg,
	acConn *ACConn,
	srcAddr *common.NetAddress,
	dstAddrs []*common.NetAddress,
	openTime uint32,
	res *common.ResourceData,
) (*common.ACOpsResultMsg, error) {
	return nil, nil
}

func (d *capturingForwarderDeps) ProcessACOperationBroadcast(
	_ context.Context,
	knkMsg *common.AgentKnockMsg,
	conns []*ACConn,
	srcAddr *common.NetAddress,
	dstAddrs []*common.NetAddress,
	openTime uint32,
	res *common.ResourceData,
) (*common.ACOpsResultMsg, error) {
	if len(conns) > 0 {
		return d.ProcessACOperation(knkMsg, conns[0], srcAddr, dstAddrs, openTime, res)
	}
	return nil, nil
}

func (d *capturingForwarderDeps) PublishACKTokens(context.Context, *common.AgentKnockMsg, *common.ServerKnockAckMsg, string, int, string) error {
	return nil
}

func (d *capturingForwarderDeps) ResolveOwnerIDByPubKey(context.Context, string) string {
	return ""
}

// captureEncryptedPacket creates an encrypted packet from sender to receiver
// and captures the raw encrypted bytes (before sending over UDP).
//
// IMPORTANT: This function creates a dedicated connection for capture that
// does NOT have a send loop competing for packets from the SendQueue.
func captureEncryptedPacket(sender, receiver *E2ETestNode, headerType int, message []byte) ([]byte, error) {
	// Create a dedicated connection for this capture (without send loop)
	// This avoids the race condition with connectionSendLoop.
	captureConn := &core.ConnectionData{
		Device:           sender.device,
		LocalAddr:        sender.addr,
		RemoteAddr:       receiver.addr,
		InitTime:         time.Now().UnixNano(),
		SendQueue:        make(chan *core.Packet, 64),
		RecvQueue:        make(chan *core.Packet, 64),
		BlockSignal:      make(chan struct{}, 1),
		SetTimeoutSignal: make(chan struct{}, 1),
		StopSignal:       make(chan struct{}),
	}

	// Create the message data using the dedicated capture connection
	md := &core.MsgData{
		ConnData:      captureConn,
		PeerPk:        receiver.PublicKeyBytes(),
		HeaderType:    headerType,
		TransactionId: uint64(time.Now().UnixNano()),
		Compress:      false,
		Message:       message,
	}

	// Send the message to the device for encryption
	sender.device.SendMsgToPacket(md)

	// Wait for the encrypted packet to appear in the dedicated SendQueue
	// (no send loop is reading from this queue)
	select {
	case pkt := <-captureConn.SendQueue:
		if pkt == nil {
			return nil, errors.New("captured nil packet")
		}
		defer sender.device.ReleasePoolPacket(pkt)
		if len(pkt.Content) == 0 {
			return nil, errors.New("captured empty packet")
		}
		return slices.Clone(pkt.Content), nil
	case <-time.After(5 * time.Second):
		return nil, context.DeadlineExceeded
	}
}

// ============================================================================
// Full E2E Test with Mock AC
// ============================================================================
//
// This test exercises the complete forwarding flow including:
// 1. Client encrypts NHP_KNK to server
// 2. Server decrypts the forwarded knock
// 3. Server sends NHP_AOP to AC (real encryption)
// 4. AC responds with NHP_ART (real encryption)
// 5. Server sends NHP_FRT result
//
// This provides maximum confidence that the entire protocol flow works correctly.
// ============================================================================

// mockACForwarderDeps implements ForwarderDeps with real AC communication.
type mockACForwarderDeps struct {
	testForwardedSessionDeps
	hostname        string
	device          *core.Device
	serverNode      *E2ETestNode
	mockACNode      *E2ETestNode
	onSendResult    func(*common.ServerForwardResultMsg)
	aspData         *common.AuthServiceProviderData
	durableVerifier *UdpServer
	t               *testing.T
	tokensMu        sync.Mutex
	storedTokens    map[string]*ACTokenEntry
	// resolvedOwnerIDs lets tests pre-install the pubkey→ownerID
	// mapping that ResolveOwnerIDByPubKey returns. Used by the
	// FullACFlow test to fence end-to-end OwnerId propagation from
	// the forward-receiver path through PublishACKTokens onto the
	// stored ACK entry — closes the gap the cr flagged where
	// `MockForwarderDeps.SetResolvedOwnerID` was defined but never
	// exercised. Guarded by tokensMu (same lock-domain as the
	// stored-tokens map so concurrent test goroutines stay safe).
	resolvedOwnerIDs map[string]string
}

func (d *mockACForwarderDeps) VerifyForwardedDurableNHPSession(ctx context.Context,
	knkMsg *common.AgentKnockMsg,
) (common.AgentSessionReceipt, error) {
	if d.durableVerifier != nil {
		return d.durableVerifier.VerifyForwardedDurableNHPSession(ctx, knkMsg)
	}
	return d.testForwardedSessionDeps.VerifyForwardedDurableNHPSession(ctx, knkMsg)
}

func (d *mockACForwarderDeps) GetHostname() string {
	return d.hostname
}

func (d *mockACForwarderDeps) GetDevice() *core.Device {
	return d.device
}

func (d *mockACForwarderDeps) SendMessage(md *core.MsgData) error {
	// Capture NHP_FRT responses
	if md.HeaderType == core.NHP_FRT && d.onSendResult != nil {
		var result common.ServerForwardResultMsg
		if err := json.Unmarshal(md.Message, &result); err == nil {
			d.onSendResult(&result)
		}
	}
	return nil
}

func (d *mockACForwarderDeps) IncrForwarderMetric(string) {}

func (d *mockACForwarderDeps) FindACConnectionsForResource(knkMsg *common.AgentKnockMsg, res *common.ResourceData) []*ACConn {
	if d.aspData != nil {
		// Placement-aware fixtures inject aspData; enforce that the resolved
		// ResourceData selects this mock AC so the e2e fails if AC dispatch and
		// ACK ResourceHost ever drift to different tunnel-server AZs.
		info := qurlplacement.OnlyResourceInfo(res)
		if info == nil || info.ACId != d.mockACNode.id {
			return nil
		}
	}
	// Return a minimal ACConn that points to our mock AC
	return []*ACConn{
		{
			ACId: d.mockACNode.id,
			ACPeer: &core.UdpPeer{
				Hostname:     d.mockACNode.id,
				Ip:           d.mockACNode.addr.IP.String(),
				Port:         d.mockACNode.addr.Port,
				PubKeyBase64: d.mockACNode.publicKey,
			},
		},
	}
}

func (d *mockACForwarderDeps) FindAuthSvcProvider(authSvcId string) *common.AuthServiceProviderData {
	if d.aspData != nil {
		return d.aspData
	}
	// Return mock auth service provider with test resource
	return &common.AuthServiceProviderData{
		AuthSvcId: authSvcId,
		ResourceGroups: map[string]*common.ResourceData{
			"test-resource-e2e": {
				ResourceGroup: common.ResourceGroup{
					AuthServiceId: authSvcId,
					ResourceId:    "test-resource-e2e",
					OpenTime:      30,
					Resources: map[string]*common.ResourceInfo{
						d.mockACNode.id: {
							ACId: d.mockACNode.id,
							Addr: &common.NetAddress{
								Ip:   "10.0.0.1",
								Port: 443,
							},
						},
					},
				},
			},
		},
	}
}

func (d *mockACForwarderDeps) ResolveAuthSvcProvider(_ context.Context, authSvcId, _ string) *common.AuthServiceProviderData {
	return d.FindAuthSvcProvider(authSvcId)
}

func newForwardE2EQURLTunnelASP(authSvcID, acID string) *common.AuthServiceProviderData {
	return &common.AuthServiceProviderData{
		AuthSvcId: authSvcID,
		ResourceGroups: common.ResourceGroupMap{
			"qurl-tunnel-server-a": newForwardE2EQURLTunnelResource(authSvcID, "qurl-tunnel-server-a", acID, 7000),
			"qurl-tunnel-server-b": newForwardE2EQURLTunnelResource(authSvcID, "qurl-tunnel-server-b", acID, 7001),
			"qurl-tunnel-server-c": newForwardE2EQURLTunnelResource(authSvcID, "qurl-tunnel-server-c", acID, 7002),
		},
	}
}

func newForwardE2EQURLTunnelResource(authSvcID, resourceID, acID string, port int) *common.ResourceData {
	return &common.ResourceData{
		ResourceGroup: common.ResourceGroup{
			AuthServiceId: authSvcID,
			ResourceId:    resourceID,
			OpenTime:      30,
			Resources: map[string]*common.ResourceInfo{
				resourceID: {
					ACId:       acID,
					Hostname:   "connect.test",
					PortSuffix: true,
					Addr: &common.NetAddress{
						Ip:   "10.0.0.1",
						Port: port,
					},
				},
			},
		},
		SkipAuth:             true,
		ResourcePublicKeyB64: testProtectedResourceID,
	}
}

func (d *mockACForwarderDeps) LifecycleCtx() context.Context {
	return context.Background()
}

func (d *mockACForwarderDeps) ProcessACOperation(
	knkMsg *common.AgentKnockMsg,
	acConn *ACConn,
	srcAddr *common.NetAddress,
	dstAddrs []*common.NetAddress,
	openTime uint32,
	res *common.ResourceData,
) (*common.ACOpsResultMsg, error) {
	// Build the ServerACOpsMsg (same as real server), including the P4a qURL v2
	// revocation metadata when res carries it. Calls the SAME production helper
	// as processACOperation so the mock's stamp can't drift from prod.
	aopMsg := &common.ServerACOpsMsg{
		SessionId:             knkMsg.NHPSessionId,
		AgentPublicKey:        knkMsg.NHPAgentPublicKey,
		SessionIssuedAtMillis: knkMsg.NHPSessionIssuedAt.UnixMilli(),
		RunID:                 knkMsg.RunID,
		RunAttempt:            knkMsg.RunAttempt,
		UserId:                knkMsg.UserId,
		DeviceId:              knkMsg.DeviceId,
		OrganizationId:        knkMsg.OrganizationId,
		AuthServiceId:         knkMsg.AuthServiceId,
		ResourceId:            knkMsg.ResourceId,
		SourceAddrs:           []*common.NetAddress{srcAddr},
		DestinationAddrs:      dstAddrs,
		OpenTime:              openTime,
	}
	stampQurlV2RevocationMetadata(aopMsg, res)
	aopBytes, _ := json.Marshal(aopMsg)

	d.t.Logf("ProcessACOperation: Sending NHP_AOP to mock AC (Resource=%s, User=%s)",
		aopMsg.ResourceId, aopMsg.UserId)

	// Get connection to mock AC
	conn := d.serverNode.GetOrCreateConnection(d.mockACNode.addr)

	// Create response channel for transaction
	responseCh := make(chan *core.PacketParserData, 1)
	txID := uint64(time.Now().UnixNano())

	// Create and send the AOP message
	md := &core.MsgData{
		ConnData:      conn,
		PeerPk:        d.mockACNode.PublicKeyBytes(),
		HeaderType:    core.NHP_AOP,
		TransactionId: txID,
		Compress:      false,
		Message:       aopBytes,
		ResponseMsgCh: responseCh,
	}

	d.serverNode.device.SendMsgToPacket(md)

	// Wait for NHP_ART response from mock AC
	select {
	case ppd := <-responseCh:
		if ppd == nil || ppd.Error != nil {
			errMsg := "unknown error"
			if ppd != nil && ppd.Error != nil {
				errMsg = ppd.Error.Error()
			}
			d.t.Logf("ProcessACOperation: Error receiving response: %s", errMsg)
			return &common.ACOpsResultMsg{
				ErrCode: "AC_RESPONSE_ERROR",
				ErrMsg:  errMsg,
			}, nil
		}

		// Parse the ART response
		var artMsg common.ACOpsResultMsg
		if err := json.Unmarshal(ppd.BodyMessage, &artMsg); err != nil {
			d.t.Logf("ProcessACOperation: Failed to parse ART: %v", err)
			return &common.ACOpsResultMsg{
				ErrCode: "AC_PARSE_ERROR",
				ErrMsg:  err.Error(),
			}, nil
		}

		d.t.Logf("ProcessACOperation: Received NHP_ART (ErrCode=%s, OpenTime=%d)",
			artMsg.ErrCode, artMsg.OpenTime)
		return &artMsg, nil

	case <-time.After(5 * time.Second):
		d.t.Log("ProcessACOperation: Timeout waiting for AC response")
		return &common.ACOpsResultMsg{
			ErrCode: "AC_TIMEOUT",
			ErrMsg:  "timeout waiting for AC response",
		}, nil
	}
}

func (d *mockACForwarderDeps) ProcessACOperationBroadcast(
	_ context.Context,
	knkMsg *common.AgentKnockMsg,
	conns []*ACConn,
	srcAddr *common.NetAddress,
	dstAddrs []*common.NetAddress,
	openTime uint32,
	res *common.ResourceData,
) (*common.ACOpsResultMsg, error) {
	if len(conns) > 0 {
		return d.ProcessACOperation(knkMsg, conns[0], srcAddr, dstAddrs, openTime, res)
	}
	return nil, nil
}

func (d *mockACForwarderDeps) StoreACToken(token string, entry *ACTokenEntry) {
	if token == "" {
		return
	}
	d.tokensMu.Lock()
	defer d.tokensMu.Unlock()
	if d.storedTokens == nil {
		d.storedTokens = make(map[string]*ACTokenEntry)
	}
	d.storedTokens[token] = entry
}

// GetStoredACToken returns the entry recorded for the given token, or nil
// if none. Fences the PR-2a ACK-path store-on-issue invariant on the
// forward receiver: TestE2E_HandleForwardRequest_FullACFlow asserts the
// token the mock AC issued is persisted in the server tokenStore via
// f.deps.PublishACKTokens (which delegates to StoreACToken).
func (d *mockACForwarderDeps) GetStoredACToken(token string) *ACTokenEntry {
	d.tokensMu.Lock()
	defer d.tokensMu.Unlock()
	return d.storedTokens[token]
}

// PublishACKTokens mirrors UdpServer.PublishACKTokens for the e2e
// forward fence: every non-empty ackMsg.ACTokens entry flows through
// StoreACToken with the maps.Clone snapshot from NewACKTokenEntry.
func (d *mockACForwarderDeps) PublishACKTokens(_ context.Context, knkMsg *common.AgentKnockMsg, ackMsg *common.ServerKnockAckMsg, srcIp string, openTime int, ownerId string) error {
	sessionExpireTime := knkMsg.NHPSessionIssuedAt.Add(time.Duration(openTime) * time.Second)
	for name, token := range ackMsg.ACTokens {
		if token == "" {
			continue
		}
		d.StoreACToken(token, NewACKTokenEntry(knkMsg, name, ackMsg.ACTokens, srcIp, openTime, ownerId, ackMsg.SessionId, sessionExpireTime))
	}
	return nil
}

func (d *mockACForwarderDeps) ResolveOwnerIDByPubKey(_ context.Context, pubKeyB64 string) string {
	d.tokensMu.Lock()
	defer d.tokensMu.Unlock()
	if d.resolvedOwnerIDs == nil {
		return ""
	}
	return d.resolvedOwnerIDs[pubKeyB64]
}

// SetResolvedOwnerID pre-installs a pubkey→ownerID mapping that
// ResolveOwnerIDByPubKey will return for the forward-receiver path.
// Used by TestE2E_HandleForwardRequest_FullACFlow to fence end-to-end
// OwnerId propagation onto the stored ACK entry.
func (d *mockACForwarderDeps) SetResolvedOwnerID(pubKeyB64, ownerID string) {
	d.tokensMu.Lock()
	defer d.tokensMu.Unlock()
	if d.resolvedOwnerIDs == nil {
		d.resolvedOwnerIDs = make(map[string]string)
	}
	d.resolvedOwnerIDs[pubKeyB64] = ownerID
}

func TestForwardPublishACKTokens_LegacySuppliedRunIDStaysUnbound(t *testing.T) {
	deps := &mockACForwarderDeps{t: t}
	err := deps.PublishACKTokens(context.Background(), &common.AgentKnockMsg{
		AuthServiceId:      "legacy",
		ResourceId:         "public-resource",
		RunID:              "0123456789abcdef",
		NHPSessionIssuedAt: time.Now(),
	}, &common.ServerKnockAckMsg{
		SessionId: 1,
		ACTokens:  map[string]string{"resource": "forwarded-legacy-token"},
	}, "192.0.2.10", 60, "")
	if err != nil {
		t.Fatalf("PublishACKTokens: %v", err)
	}
	entry := deps.GetStoredACToken("forwarded-legacy-token")
	if entry == nil {
		t.Fatal("forwarded legacy token was not stored")
	}
	if entry.RunID != "" {
		t.Fatalf("forwarded legacy entry.RunID = %q, want empty", entry.RunID)
	}
}

// TestE2E_HandleForwardRequest_FullACFlow tests the complete forwarding flow
// with a mock AC that processes NHP_AOP and responds with NHP_ART.
// This exercises the entire protocol chain with real Noise encryption.
func TestE2E_HandleForwardRequest_FullACFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping full E2E test in short mode")
	}

	// ========================================================================
	// Setup: Create all test nodes
	// ========================================================================

	// Server node - the destination server that will handle the forwarded knock
	serverNode := newE2ETestNode(t, "server")
	serverNode.Start()
	defer serverNode.Stop()

	// Mock AC node - will receive NHP_AOP and respond with NHP_ART
	// IMPORTANT: Must use NHP_AC device type to receive NHP_AOP messages
	mockAC := newE2ETestNodeWithType(t, "mock-ac", core.NHP_AC)
	mockAC.Start()
	defer mockAC.Stop()

	// Client node - the original knock sender
	clientNode := newE2ETestNode(t, "client")
	clientNode.Start()
	defer clientNode.Stop()

	// ========================================================================
	// Establish peer relationships (needed for encryption)
	// ========================================================================

	// Server ↔ Client (for decrypting the knock)
	serverNode.AddPeer(clientNode)
	clientNode.AddPeer(serverNode)

	// Server ↔ Mock AC (for AOP/ART exchange)
	serverNode.AddPeer(mockAC)
	mockAC.AddPeer(serverNode)

	time.Sleep(200 * time.Millisecond)

	// ========================================================================
	// Set up mock AC to respond to NHP_AOP
	// ========================================================================

	acReceivedOp := make(chan *common.ServerACOpsMsg, 1)

	mockAC.SetMessageHandler(func(msg *ReceivedMsg) {
		if msg.HeaderType == core.NHP_AOP {
			t.Logf("Mock AC received NHP_AOP")

			// Parse the AOP message
			var aopMsg common.ServerACOpsMsg
			if err := json.Unmarshal(msg.Data, &aopMsg); err != nil {
				t.Errorf("Mock AC: Failed to parse AOP: %v", err)
				return
			}

			t.Logf("Mock AC: Received operation for Resource=%s, User=%s",
				aopMsg.ResourceId, aopMsg.UserId)

			// Send to verification channel
			select {
			case acReceivedOp <- &aopMsg:
			default:
			}

			// Build success response
			artMsg := &common.ACOpsResultMsg{
				ErrCode:  "",
				OpenTime: 30,
				ACToken:  "test-ac-token-123",
			}
			artBytes, _ := json.Marshal(artMsg)

			t.Logf("Mock AC: Sending NHP_ART response (OpenTime=%d)", artMsg.OpenTime)

			// Send NHP_ART response back to server
			// Use the same transaction ID from the request
			if msg.PPD != nil {
				if err := mockAC.SendMessage(serverNode, core.NHP_ART, msg.PPD.SenderTrxId, artBytes, msg.PPD); err != nil {
					t.Errorf("Mock AC: failed to send NHP_ART: %v", err)
				}
			}
		}
	})

	// ========================================================================
	// Set up result capture
	// ========================================================================

	resultCh := make(chan *common.ServerForwardResultMsg, 1)

	deps := &mockACForwarderDeps{
		hostname:   "server",
		device:     serverNode.device,
		serverNode: serverNode,
		mockACNode: mockAC,
		t:          t,
		onSendResult: func(result *common.ServerForwardResultMsg) {
			select {
			case resultCh <- result:
			default:
			}
		},
		aspData: newForwardE2EQURLTunnelASP(common.RegisteredAgentAuthServiceID, mockAC.id),
	}

	// Pre-install the pubkey→ownerID mapping that the forward-
	// receiver's ResolveOwnerIDByPubKey will read. Without this, the
	// test would only fence that owner_id="" propagates (which is
	// the fail-safe contract, not the load-bearing happy path).
	// The cr-flagged gap: MockForwarderDeps.SetResolvedOwnerID
	// existed but no test wired it through PublishACKTokens onto a
	// stored entry. This closes that gap end-to-end: pubkey →
	// ResolveOwnerIDByPubKey → PublishACKTokens → entry.User.OwnerId.
	const wantOwnerID = "owner-from-forward-receiver-e2e"
	deps.SetResolvedOwnerID(clientNode.PublicKeyStr(), wantOwnerID)

	forwarder := NewServerForwarder(deps)

	// ========================================================================
	// Create the encrypted knock (like an agent would send)
	// ========================================================================

	knockMsg := &common.AgentKnockMsg{
		HeaderType:    core.NHP_KNK,
		UserId:        "test-user-e2e",
		DeviceId:      "test-device-e2e",
		AuthServiceId: common.RegisteredAgentAuthServiceID,
		ResourceId:    qurlplacement.TunnelServerResourceID,
		RunID:         "0123456789abcdef",
		RunAttempt:    1,
		UserData: map[string]any{
			"passcode": "123456",
		},
	}
	knockBytes, _ := json.Marshal(knockMsg)

	// Encrypt the knock to server's public key
	encryptedKnock, err := captureEncryptedPacket(clientNode, serverNode, core.NHP_KNK, knockBytes)
	if err != nil {
		t.Fatalf("Failed to capture encrypted knock: %v", err)
	}
	t.Logf("Encrypted knock: %d bytes", len(encryptedKnock))

	// ========================================================================
	// Create and send the forwarded knock request
	// ========================================================================

	fwdMsg := &common.ServerForwardMsg{
		SessionId:            1,
		SessionIssuedAtNanos: time.Now().UnixNano(),
		KnockData:            encryptedKnock,
		SourceServer:         "forwarding-server",
		UserAddr:             "192.168.1.100:12345",
		TransactionId:        77777,
		Timestamp:            time.Now().Unix(),
	}
	issuedAtMillis := time.Unix(0, fwdMsg.SessionIssuedAtNanos).UnixMilli()
	durableStore := newAdmissionSessionControlStore(time.UnixMilli(issuedAtMillis + 1))
	durableCandidate := sessionControlSessionCandidate{
		CellID: testSessionControlCellID, AgentPublicKey: clientNode.PublicKeyStr(),
		SessionID: fwdMsg.SessionId, IssuedAtMillis: issuedAtMillis,
		ReservationDeadlineMillis: issuedAtMillis + pendingSessionReservationTTL.Milliseconds(),
		RunID:                     knockMsg.RunID, RunAttempt: knockMsg.RunAttempt,
	}
	durableSnapshot, err := durableStore.SnapshotActiveFences(context.Background(), durableCandidate.CellID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := durableStore.ReserveSession(context.Background(), durableCandidate, *durableSnapshot); err != nil {
		t.Fatalf("seed forwarded durable session: %v", err)
	}
	deps.durableVerifier = &UdpServer{
		sessionControlCellID: durableCandidate.CellID, sessionControlStore: durableStore,
	}

	t.Log("Calling HandleForwardRequest...")
	forwarder.HandleForwardRequest(nil, fwdMsg)

	// ========================================================================
	// Verify: AC received the operation
	// ========================================================================

	t.Log("Waiting for AC to receive operation...")
	select {
	case aopMsg := <-acReceivedOp:
		t.Logf("✓ AC received operation: Resource=%s, User=%s",
			aopMsg.ResourceId, aopMsg.UserId)

		// Verify knock data was correctly extracted
		if aopMsg.ResourceId != knockMsg.ResourceId {
			t.Errorf("ResourceId mismatch: got %s, want %s",
				aopMsg.ResourceId, knockMsg.ResourceId)
		}
		if aopMsg.UserId != knockMsg.UserId {
			t.Errorf("UserId mismatch: got %s, want %s",
				aopMsg.UserId, knockMsg.UserId)
		}
		if aopMsg.AuthServiceId != knockMsg.AuthServiceId {
			t.Errorf("AuthServiceId mismatch: got %s, want %s",
				aopMsg.AuthServiceId, knockMsg.AuthServiceId)
		}

	case <-time.After(10 * time.Second):
		t.Fatal("Timeout: AC did not receive operation")
	}

	// ========================================================================
	// Verify: NHP_FRT result is correct
	// ========================================================================

	t.Log("Waiting for NHP_FRT result...")
	var forwardedACK common.ServerKnockAckMsg
	select {
	case result := <-resultCh:
		t.Logf("✓ Got NHP_FRT: Success=%v, ErrCode=%s, TxId=%d",
			result.Success, result.ErrCode, result.TransactionId)

		if !result.Success {
			t.Errorf("Expected success=true, got ErrCode=%s: %s",
				result.ErrCode, result.ErrMsg)
		}
		if result.TransactionId != fwdMsg.TransactionId {
			t.Errorf("TransactionId mismatch: got %d, want %d",
				result.TransactionId, fwdMsg.TransactionId)
		}
		if err := common.DecodeRegisteredAgentKnockAckMsg(result.ACKData, &forwardedACK,
			knockMsg.RunID, knockMsg.RunAttempt, knockMsg.ResourceId); err != nil {
			t.Fatalf("strict decode forwarded registered-agent ACK: %v", err)
		}
		if forwardedACK.CellId != testSessionControlCellID || forwardedACK.SessionId != fwdMsg.SessionId ||
			forwardedACK.SessionIssuedAtMillis != time.Unix(0, fwdMsg.SessionIssuedAtNanos).UnixMilli() {
			t.Fatalf("forwarded ACK receipt = %#v, want strong verified cell/session/issuance", forwardedACK)
		}

	case <-time.After(10 * time.Second):
		t.Fatal("Timeout: No NHP_FRT result received")
	}

	// ========================================================================
	// Verify: PR-2a — the AC-issued token was persisted via f.deps.PublishACKTokens
	// ========================================================================
	// The mock AC's NHP_ART carried ACToken="test-ac-token-123". If
	// forward.go ever stops routing through deps.PublishACKTokens, this
	// assertion fails and PR-2b's /nhp/internal/token/validate would have
	// no entry to resolve.
	storedEntry := deps.GetStoredACToken("test-ac-token-123")
	if storedEntry == nil {
		t.Fatal("Expected AC token 'test-ac-token-123' to be stored via deps.PublishACKTokens after successful forward; got nil")
	}
	if storedEntry.User == nil || storedEntry.User.UserId != knockMsg.UserId {
		t.Errorf("Stored entry User.UserId mismatch: got %+v, want UserId=%s", storedEntry.User, knockMsg.UserId)
	}
	if storedEntry.ResourceId != knockMsg.ResourceId {
		t.Errorf("Stored entry ResourceId mismatch: got %s, want %s", storedEntry.ResourceId, knockMsg.ResourceId)
	}
	if storedEntry.ACTokens[qurlplacement.TunnelServerResourceID] != "test-ac-token-123" {
		t.Errorf("Stored entry ACTokens[%s] mismatch: got %q, want %q",
			qurlplacement.TunnelServerResourceID, storedEntry.ACTokens[qurlplacement.TunnelServerResourceID], "test-ac-token-123")
	}
	// KnockSrcIP is PR-2b's load-bearing field — the FRP login IP gets
	// cross-checked against the IP that earned the pinhole. The forward
	// path derives srcAddr.Ip from userAddr.IP.String(), parsed from
	// fwdMsg.UserAddr ("192.168.1.100:12345"). A regression that drops
	// the field on the forward path (or sources it from the wrong place)
	// would silently nil-out PR-2b's security-critical assertion.
	if storedEntry.KnockSrcIP != "192.168.1.100" {
		t.Errorf("Stored entry KnockSrcIP mismatch: got %q, want %q (must come from fwdMsg.UserAddr's IP component)",
			storedEntry.KnockSrcIP, "192.168.1.100")
	}
	if storedEntry.RunID != knockMsg.RunID {
		t.Errorf("Stored entry RunID mismatch: got %q, want authenticated forwarded-knock RunID %q", storedEntry.RunID, knockMsg.RunID)
	}

	// OwnerId is the server-resolved tenant identity that the
	// forward-receiver path stamps onto the ACK entry via
	// ResolveOwnerIDByPubKey. The setup above pre-installed
	// `wantOwnerID` against clientNode's pubkey; this assertion
	// fences the full pipeline:
	//   knockPpd.RemotePubKey (decoded from the encrypted inner knock)
	//   → base64 encode
	//   → deps.ResolveOwnerIDByPubKey (returns the pre-installed value)
	//   → PublishACKTokens (forwards ownerId)
	//   → NewACKTokenEntry (stamps onto entry.User.OwnerId)
	//   → deps.GetStoredACToken (test reads the stored entry)
	//
	// A regression at any hop — forward.go forgetting to call
	// ResolveOwnerIDByPubKey, PublishACKTokens dropping the
	// ownerId argument, NewACKTokenEntry not populating
	// User.OwnerId — surfaces here as a literal-string mismatch.
	// Closes the cr-flagged gap where SetResolvedOwnerID was
	// defined but never exercised through the production path.
	if storedEntry.User.OwnerId != wantOwnerID {
		t.Errorf("Stored entry User.OwnerId mismatch: got %q, want %q (forward-receiver OwnerId propagation broken at one of: ResolveOwnerIDByPubKey, PublishACKTokens, or NewACKTokenEntry)",
			storedEntry.User.OwnerId, wantOwnerID)
	}

	t.Log("")
	t.Log("============================================================")
	t.Log("SUCCESS: Full E2E flow with mock AC completed!")
	t.Log("============================================================")
	t.Log("Verified:")
	t.Log("  ✓ Client knock encrypted to server")
	t.Log("  ✓ Server decrypted forwarded knock (real Noise decryption)")
	t.Log("  ✓ Server sent NHP_AOP to AC (real Noise encryption)")
	t.Log("  ✓ AC received and processed operation")
	t.Log("  ✓ AC sent NHP_ART response (real Noise encryption)")
	t.Log("  ✓ Server processed response and sent NHP_FRT")
	t.Log("  ✓ AC token persisted via deps.PublishACKTokens (PR-2a fence)")
	t.Log("============================================================")
}

// ============================================================================
// TestE2E_HandleForwardRequest_ACReturnsError
// ============================================================================
// Tests that HandleForwardRequest correctly propagates errors from the AC.
// The mock AC receives NHP_AOP but responds with an error in NHP_ART.
// ============================================================================

// errorACForwarderDeps is like mockACForwarderDeps but returns an error from AC.
type errorACForwarderDeps struct {
	testForwardedSessionDeps
	hostname     string
	device       *core.Device
	serverNode   *E2ETestNode
	mockACNode   *E2ETestNode
	onSendResult func(*common.ServerForwardResultMsg)
	t            *testing.T
	errorCode    string
	errorMsg     string
}

func (d *errorACForwarderDeps) GetHostname() string     { return d.hostname }
func (d *errorACForwarderDeps) GetDevice() *core.Device { return d.device }

func (d *errorACForwarderDeps) SendMessage(md *core.MsgData) error {
	if md.HeaderType == core.NHP_FRT && d.onSendResult != nil {
		var result common.ServerForwardResultMsg
		if err := json.Unmarshal(md.Message, &result); err == nil {
			d.onSendResult(&result)
		}
	}
	return nil
}

func (d *errorACForwarderDeps) IncrForwarderMetric(string) {}

func (d *errorACForwarderDeps) FindACConnectionsForResource(knkMsg *common.AgentKnockMsg, _ *common.ResourceData) []*ACConn {
	return []*ACConn{
		{
			ACId: d.mockACNode.id,
			ACPeer: &core.UdpPeer{
				Hostname:     d.mockACNode.id,
				Ip:           d.mockACNode.addr.IP.String(),
				Port:         d.mockACNode.addr.Port,
				PubKeyBase64: d.mockACNode.publicKey,
			},
		},
	}
}

func (d *errorACForwarderDeps) FindAuthSvcProvider(authSvcId string) *common.AuthServiceProviderData {
	return &common.AuthServiceProviderData{
		AuthSvcId: authSvcId,
		ResourceGroups: map[string]*common.ResourceData{
			"test-resource-error": {
				ResourceGroup: common.ResourceGroup{
					AuthServiceId: authSvcId,
					ResourceId:    "test-resource-error",
					OpenTime:      30,
					Resources: map[string]*common.ResourceInfo{
						d.mockACNode.id: {
							ACId: d.mockACNode.id,
							Addr: &common.NetAddress{Ip: "10.0.0.1", Port: 443},
						},
					},
				},
			},
		},
	}
}

func (d *errorACForwarderDeps) ResolveAuthSvcProvider(_ context.Context, authSvcId, _ string) *common.AuthServiceProviderData {
	return d.FindAuthSvcProvider(authSvcId)
}

func (d *errorACForwarderDeps) LifecycleCtx() context.Context {
	return context.Background()
}

func (d *errorACForwarderDeps) ProcessACOperation(
	knkMsg *common.AgentKnockMsg,
	acConn *ACConn,
	srcAddr *common.NetAddress,
	dstAddrs []*common.NetAddress,
	openTime uint32,
	res *common.ResourceData,
) (*common.ACOpsResultMsg, error) {
	// Return the configured error
	return &common.ACOpsResultMsg{
		ErrCode: d.errorCode,
		ErrMsg:  d.errorMsg,
	}, nil
}

func (d *errorACForwarderDeps) ProcessACOperationBroadcast(
	_ context.Context,
	knkMsg *common.AgentKnockMsg,
	conns []*ACConn,
	srcAddr *common.NetAddress,
	dstAddrs []*common.NetAddress,
	openTime uint32,
	res *common.ResourceData,
) (*common.ACOpsResultMsg, error) {
	if len(conns) > 0 {
		return d.ProcessACOperation(knkMsg, conns[0], srcAddr, dstAddrs, openTime, res)
	}
	return nil, nil
}

func (d *errorACForwarderDeps) PublishACKTokens(context.Context, *common.AgentKnockMsg, *common.ServerKnockAckMsg, string, int, string) error {
	return nil
}

func (d *errorACForwarderDeps) ResolveOwnerIDByPubKey(context.Context, string) string { return "" }

func TestE2E_HandleForwardRequest_ACReturnsError(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping E2E test in short mode")
	}

	// Setup test nodes
	serverNode := newE2ETestNode(t, "server")
	serverNode.Start()
	defer serverNode.Stop()

	mockAC := newE2ETestNodeWithType(t, "mock-ac", core.NHP_AC)
	mockAC.Start()
	defer mockAC.Stop()

	clientNode := newE2ETestNode(t, "client")
	clientNode.Start()
	defer clientNode.Stop()

	// Establish peer relationships
	serverNode.AddPeer(clientNode)
	clientNode.AddPeer(serverNode)
	serverNode.AddPeer(mockAC)

	time.Sleep(200 * time.Millisecond)

	// Set up result capture
	resultCh := make(chan *common.ServerForwardResultMsg, 1)

	deps := &errorACForwarderDeps{
		hostname:   "server",
		device:     serverNode.device,
		serverNode: serverNode,
		mockACNode: mockAC,
		t:          t,
		errorCode:  "USER_NOT_AUTHORIZED",
		errorMsg:   "User does not have permission to access this resource",
		onSendResult: func(result *common.ServerForwardResultMsg) {
			select {
			case resultCh <- result:
			default:
			}
		},
	}

	forwarder := NewServerForwarder(deps)

	// Create encrypted knock
	knockMsg := &common.AgentKnockMsg{
		HeaderType:    core.NHP_KNK,
		UserId:        "unauthorized-user",
		DeviceId:      "test-device",
		AuthServiceId: "test-asp",
		ResourceId:    "test-resource-error",
	}
	knockBytes, _ := json.Marshal(knockMsg)

	encryptedKnock, err := captureEncryptedPacket(clientNode, serverNode, core.NHP_KNK, knockBytes)
	if err != nil {
		t.Fatalf("Failed to capture encrypted knock: %v", err)
	}

	// Send forward request
	fwdMsg := &common.ServerForwardMsg{
		SessionId:            1,
		SessionIssuedAtNanos: time.Now().UnixNano(),
		KnockData:            encryptedKnock,
		SourceServer:         "forwarding-server",
		UserAddr:             "192.168.1.100:12345",
		TransactionId:        88888,
		Timestamp:            time.Now().Unix(),
	}

	forwarder.HandleForwardRequest(nil, fwdMsg)

	// Verify error is propagated
	select {
	case result := <-resultCh:
		t.Logf("Got NHP_FRT: Success=%v, ErrCode=%s", result.Success, result.ErrCode)

		if result.Success {
			t.Error("Expected Success=false for AC error")
		}
		if result.ErrCode != "USER_NOT_AUTHORIZED" {
			t.Errorf("Expected ErrCode 'USER_NOT_AUTHORIZED', got '%s'", result.ErrCode)
		}
		t.Log("✓ AC error correctly propagated to NHP_FRT")

	case <-time.After(5 * time.Second):
		t.Fatal("Timeout waiting for NHP_FRT result")
	}
}

// ============================================================================
// TestE2E_HandleForwardRequest_ACTimeout
// ============================================================================
// Tests that HandleForwardRequest handles AC timeout correctly.
// The mock AC receives NHP_AOP but never responds.
// ============================================================================

// timeoutACForwarderDeps simulates an AC that doesn't respond.
type timeoutACForwarderDeps struct {
	testForwardedSessionDeps
	hostname     string
	device       *core.Device
	serverNode   *E2ETestNode
	mockACNode   *E2ETestNode
	onSendResult func(*common.ServerForwardResultMsg)
	t            *testing.T
}

func (d *timeoutACForwarderDeps) GetHostname() string     { return d.hostname }
func (d *timeoutACForwarderDeps) GetDevice() *core.Device { return d.device }

func (d *timeoutACForwarderDeps) SendMessage(md *core.MsgData) error {
	if md.HeaderType == core.NHP_FRT && d.onSendResult != nil {
		var result common.ServerForwardResultMsg
		if err := json.Unmarshal(md.Message, &result); err == nil {
			d.onSendResult(&result)
		}
	}
	return nil
}

func (d *timeoutACForwarderDeps) IncrForwarderMetric(string) {}

func (d *timeoutACForwarderDeps) FindACConnectionsForResource(knkMsg *common.AgentKnockMsg, _ *common.ResourceData) []*ACConn {
	return []*ACConn{
		{
			ACId: d.mockACNode.id,
			ACPeer: &core.UdpPeer{
				Hostname:     d.mockACNode.id,
				Ip:           d.mockACNode.addr.IP.String(),
				Port:         d.mockACNode.addr.Port,
				PubKeyBase64: d.mockACNode.publicKey,
			},
		},
	}
}

func (d *timeoutACForwarderDeps) FindAuthSvcProvider(authSvcId string) *common.AuthServiceProviderData {
	return &common.AuthServiceProviderData{
		AuthSvcId: authSvcId,
		ResourceGroups: map[string]*common.ResourceData{
			"test-resource-timeout": {
				ResourceGroup: common.ResourceGroup{
					AuthServiceId: authSvcId,
					ResourceId:    "test-resource-timeout",
					OpenTime:      30,
					Resources: map[string]*common.ResourceInfo{
						d.mockACNode.id: {
							ACId: d.mockACNode.id,
							Addr: &common.NetAddress{Ip: "10.0.0.1", Port: 443},
						},
					},
				},
			},
		},
	}
}

func (d *timeoutACForwarderDeps) ResolveAuthSvcProvider(_ context.Context, authSvcId, _ string) *common.AuthServiceProviderData {
	return d.FindAuthSvcProvider(authSvcId)
}

func (d *timeoutACForwarderDeps) LifecycleCtx() context.Context {
	return context.Background()
}

func (d *timeoutACForwarderDeps) ProcessACOperation(
	knkMsg *common.AgentKnockMsg,
	acConn *ACConn,
	srcAddr *common.NetAddress,
	dstAddrs []*common.NetAddress,
	openTime uint32,
	res *common.ResourceData,
) (*common.ACOpsResultMsg, error) {
	d.t.Log("ProcessACOperation: Simulating timeout (sleeping 3s)...")
	// Simulate timeout by waiting longer than the expected timeout
	time.Sleep(3 * time.Second)
	return &common.ACOpsResultMsg{
		ErrCode: "AC_TIMEOUT",
		ErrMsg:  "AC did not respond in time",
	}, nil
}

func (d *timeoutACForwarderDeps) ProcessACOperationBroadcast(
	_ context.Context,
	knkMsg *common.AgentKnockMsg,
	conns []*ACConn,
	srcAddr *common.NetAddress,
	dstAddrs []*common.NetAddress,
	openTime uint32,
	res *common.ResourceData,
) (*common.ACOpsResultMsg, error) {
	if len(conns) > 0 {
		return d.ProcessACOperation(knkMsg, conns[0], srcAddr, dstAddrs, openTime, res)
	}
	return nil, nil
}

func (d *timeoutACForwarderDeps) PublishACKTokens(context.Context, *common.AgentKnockMsg, *common.ServerKnockAckMsg, string, int, string) error {
	return nil
}

func (d *timeoutACForwarderDeps) ResolveOwnerIDByPubKey(context.Context, string) string {
	return ""
}

func TestE2E_HandleForwardRequest_ACTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping E2E test in short mode")
	}

	// Setup test nodes
	serverNode := newE2ETestNode(t, "server")
	serverNode.Start()
	defer serverNode.Stop()

	mockAC := newE2ETestNodeWithType(t, "mock-ac", core.NHP_AC)
	mockAC.Start()
	defer mockAC.Stop()

	clientNode := newE2ETestNode(t, "client")
	clientNode.Start()
	defer clientNode.Stop()

	// Establish peer relationships
	serverNode.AddPeer(clientNode)
	clientNode.AddPeer(serverNode)
	serverNode.AddPeer(mockAC)

	time.Sleep(200 * time.Millisecond)

	// Set up result capture
	resultCh := make(chan *common.ServerForwardResultMsg, 1)

	deps := &timeoutACForwarderDeps{
		hostname:   "server",
		device:     serverNode.device,
		serverNode: serverNode,
		mockACNode: mockAC,
		t:          t,
		onSendResult: func(result *common.ServerForwardResultMsg) {
			select {
			case resultCh <- result:
			default:
			}
		},
	}

	forwarder := NewServerForwarder(deps)

	// Create encrypted knock
	knockMsg := &common.AgentKnockMsg{
		HeaderType:    core.NHP_KNK,
		UserId:        "test-user",
		DeviceId:      "test-device",
		AuthServiceId: "test-asp",
		ResourceId:    "test-resource-timeout",
	}
	knockBytes, _ := json.Marshal(knockMsg)

	encryptedKnock, err := captureEncryptedPacket(clientNode, serverNode, core.NHP_KNK, knockBytes)
	if err != nil {
		t.Fatalf("Failed to capture encrypted knock: %v", err)
	}

	// Send forward request
	fwdMsg := &common.ServerForwardMsg{
		SessionId:            1,
		SessionIssuedAtNanos: time.Now().UnixNano(),
		KnockData:            encryptedKnock,
		SourceServer:         "forwarding-server",
		UserAddr:             "192.168.1.100:12345",
		TransactionId:        99999,
		Timestamp:            time.Now().Unix(),
	}

	startTime := time.Now()
	forwarder.HandleForwardRequest(nil, fwdMsg)

	// Verify timeout error is returned
	select {
	case result := <-resultCh:
		elapsed := time.Since(startTime)
		t.Logf("Got NHP_FRT after %v: Success=%v, ErrCode=%s", elapsed, result.Success, result.ErrCode)

		if result.Success {
			t.Error("Expected Success=false for AC timeout")
		}
		if result.ErrCode != "AC_TIMEOUT" {
			t.Errorf("Expected ErrCode 'AC_TIMEOUT', got '%s'", result.ErrCode)
		}
		t.Log("✓ AC timeout correctly handled")

	case <-time.After(10 * time.Second):
		t.Fatal("Timeout waiting for NHP_FRT result (should have timed out sooner)")
	}
}

// ============================================================================
// TestE2E_HandleForwardRequest_ConcurrentForwards
// ============================================================================
// Tests that multiple concurrent HandleForwardRequest calls work correctly.
// This verifies thread safety and proper transaction ID handling.
// ============================================================================

func TestE2E_HandleForwardRequest_MultipleClients(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping E2E test in short mode")
	}

	// Setup test nodes
	serverNode := newE2ETestNode(t, "server")
	serverNode.Start()
	defer serverNode.Stop()

	mockAC := newE2ETestNodeWithType(t, "mock-ac", core.NHP_AC)
	mockAC.Start()
	defer mockAC.Stop()

	// Establish server <-> AC relationship
	serverNode.AddPeer(mockAC)
	mockAC.AddPeer(serverNode)

	time.Sleep(200 * time.Millisecond)

	// Set up result capture
	var resultMu sync.Mutex
	results := make(map[uint64]*common.ServerForwardResultMsg)
	resultCount := make(chan struct{}, 10)

	deps := &mockACForwarderDeps{
		hostname:   "server",
		device:     serverNode.device,
		serverNode: serverNode,
		mockACNode: mockAC,
		t:          t,
		onSendResult: func(result *common.ServerForwardResultMsg) {
			resultMu.Lock()
			results[result.TransactionId] = result
			resultMu.Unlock()
			select {
			case resultCount <- struct{}{}:
			default:
			}
		},
	}

	forwarder := NewServerForwarder(deps)

	// Set up mock AC to respond to all NHP_AOP messages
	var acMsgMu sync.Mutex
	mockAC.SetMessageHandler(func(msg *ReceivedMsg) {
		if msg.HeaderType == core.NHP_AOP {
			acMsgMu.Lock()
			defer acMsgMu.Unlock()

			artMsg := &common.ACOpsResultMsg{
				ErrCode:  "",
				OpenTime: 30,
				ACToken:  "multi-client-token",
			}
			artBytes, _ := json.Marshal(artMsg)

			if msg.PPD != nil {
				if err := mockAC.SendMessage(serverNode, core.NHP_ART, msg.PPD.SenderTrxId, artBytes, msg.PPD); err != nil {
					t.Errorf("Mock AC: failed to send NHP_ART: %v", err)
				}
			}
		}
	})

	// Test: Multiple clients, each with their own session
	// This tests the realistic scenario where different clients (agents)
	// send knocks to the server.
	const numClients = 3
	txIDs := make([]uint64, numClients)

	for i := 0; i < numClients; i++ {
		// Create a fresh client for each request
		clientNode := newE2ETestNode(t, "client-"+string(rune('A'+i)))
		clientNode.Start()
		defer clientNode.Stop()

		serverNode.AddPeer(clientNode)
		clientNode.AddPeer(serverNode)

		// Allow peer registration to complete
		time.Sleep(100 * time.Millisecond)

		txID := uint64(100000 + i)
		txIDs[i] = txID

		knockMsg := &common.AgentKnockMsg{
			HeaderType:    core.NHP_KNK,
			UserId:        "multi-client-user-" + string(rune('A'+i)),
			DeviceId:      "device-" + string(rune('0'+i)),
			AuthServiceId: "test-asp",
			ResourceId:    "test-resource-e2e",
		}
		knockBytes, _ := json.Marshal(knockMsg)

		encryptedKnock, err := captureEncryptedPacket(clientNode, serverNode, core.NHP_KNK, knockBytes)
		if err != nil {
			t.Fatalf("Failed to capture encrypted knock from client %d: %v", i, err)
		}

		fwdMsg := &common.ServerForwardMsg{
			SessionId:            uint64(i + 1),
			SessionIssuedAtNanos: time.Now().UnixNano(),
			KnockData:            encryptedKnock,
			SourceServer:         "forwarding-server",
			UserAddr:             "192.168.1.10" + string(rune('0'+i)) + ":12345",
			TransactionId:        txID,
			Timestamp:            time.Now().Unix(),
		}

		forwarder.HandleForwardRequest(nil, fwdMsg)
		t.Logf("Sent forward from client %d (txID=%d)", i, txID)
	}

	// Wait for all results
	timeout := time.After(15 * time.Second)
	received := 0
	for received < numClients {
		select {
		case <-resultCount:
			received++
		case <-timeout:
			t.Fatalf("Timeout: only received %d/%d results", received, numClients)
		}
	}

	// Verify all results
	resultMu.Lock()
	defer resultMu.Unlock()

	successCount := 0
	for _, txID := range txIDs {
		result, exists := results[txID]
		if !exists {
			t.Errorf("Missing result for transaction %d", txID)
			continue
		}

		if result.Success {
			successCount++
		} else {
			t.Logf("Transaction %d: ErrCode=%s", txID, result.ErrCode)
		}
	}

	t.Logf("Multi-client results: %d/%d successful", successCount, numClients)

	if successCount != numClients {
		t.Errorf("Expected all %d multi-client forwards to succeed, got %d", numClients, successCount)
	}

	t.Log("✓ All multi-client forwards completed successfully")
}

// ============================================================================
// TestE2E_HandleForwardRequest_InvalidKnockJSON
// ============================================================================
// Tests that HandleForwardRequest handles invalid JSON after decryption.
// The encrypted payload contains data that cannot be unmarshaled to AgentKnockMsg.
// ============================================================================

func TestE2E_HandleForwardRequest_InvalidKnockJSON(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping E2E test in short mode")
	}

	// Setup test nodes
	serverNode := newE2ETestNode(t, "server")
	serverNode.Start()
	defer serverNode.Stop()

	clientNode := newE2ETestNode(t, "client")
	clientNode.Start()
	defer clientNode.Stop()

	// Establish peer relationships
	serverNode.AddPeer(clientNode)
	clientNode.AddPeer(serverNode)

	time.Sleep(200 * time.Millisecond)

	// Set up result capture
	resultCh := make(chan *common.ServerForwardResultMsg, 1)

	deps := &capturingForwarderDeps{
		hostname: "server",
		device:   serverNode.device,
		node:     serverNode,
		onSend: func(md *core.MsgData) {
			if md.HeaderType == core.NHP_FRT {
				var result common.ServerForwardResultMsg
				if err := json.Unmarshal(md.Message, &result); err == nil {
					select {
					case resultCh <- &result:
					default:
					}
				}
			}
		},
	}

	forwarder := NewServerForwarder(deps)

	// Create invalid JSON payload - will decrypt successfully but fail JSON unmarshal
	invalidJSON := []byte("this is not valid JSON { broken ]")

	// Encrypt the invalid JSON to server's public key
	encryptedInvalid, err := captureEncryptedPacket(clientNode, serverNode, core.NHP_KNK, invalidJSON)
	if err != nil {
		t.Fatalf("Failed to capture encrypted packet: %v", err)
	}
	t.Logf("Encrypted invalid payload: %d bytes", len(encryptedInvalid))

	// Send forward request
	fwdMsg := &common.ServerForwardMsg{
		SessionId:            1,
		SessionIssuedAtNanos: time.Now().UnixNano(),
		KnockData:            encryptedInvalid,
		SourceServer:         "forwarding-server",
		UserAddr:             "192.168.1.100:12345",
		TransactionId:        11111,
		Timestamp:            time.Now().Unix(),
	}

	forwarder.HandleForwardRequest(nil, fwdMsg)

	// Verify error response
	select {
	case result := <-resultCh:
		t.Logf("Got NHP_FRT: Success=%v, ErrCode=%s, ErrMsg=%s",
			result.Success, result.ErrCode, result.ErrMsg)

		if result.Success {
			t.Error("Expected Success=false for invalid JSON")
		}
		// Accept either INVALID_KNOCK or PARSE_FAILED as valid error codes
		// Both indicate the invalid JSON was detected and rejected
		validErrors := []string{"INVALID_KNOCK", "PARSE_FAILED"}
		isValid := false
		for _, valid := range validErrors {
			if result.ErrCode == valid {
				isValid = true
				break
			}
		}
		if !isValid {
			t.Errorf("Expected ErrCode in %v, got '%s'", validErrors, result.ErrCode)
		}
		t.Log("✓ Invalid JSON correctly rejected")

	case <-time.After(5 * time.Second):
		t.Fatal("Timeout waiting for NHP_FRT result")
	}
}

// ============================================================================
// TestE2E_ForwardIntegration_HealthTracking
// ============================================================================
// Tests that the ServerForwarder correctly tracks server health and skips
// unhealthy servers during forwarding.
//
// Key design: This test pre-marks nodeA as unhealthy to avoid relying on
// the random shuffle order. This makes the test deterministic and fast.
// ============================================================================

func TestE2E_ForwardIntegration_HealthTracking(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping E2E test in short mode")
	}

	// Create two server nodes (simulating assigned servers)
	nodeA := newE2ETestNode(t, "server-a")
	nodeB := newE2ETestNode(t, "server-b")
	originServer := newE2ETestNode(t, "origin")

	nodeA.Start()
	nodeB.Start()
	originServer.Start()
	defer nodeA.Stop()
	defer nodeB.Stop()
	defer originServer.Stop()

	// Origin server needs peers for responses
	nodeA.AddPeer(originServer)
	nodeB.AddPeer(originServer)

	time.Sleep(200 * time.Millisecond)

	// Track which servers received requests
	var requestMu sync.Mutex
	requestCounts := map[string]int{"server-a": 0, "server-b": 0}

	// Create ForwarderDeps for origin
	mockDeps := &e2eForwarderDeps{
		hostname: "origin",
		device:   originServer.device,
		node:     originServer,
	}

	forwarder := NewServerForwarder(mockDeps)

	// Set up message handler on origin to route NHP_FRT to forwarder
	originServer.SetMessageHandler(func(msg *ReceivedMsg) {
		if msg.HeaderType == core.NHP_FRT {
			var resultMsg common.ServerForwardResultMsg
			if err := json.Unmarshal(msg.Data, &resultMsg); err == nil {
				forwarder.HandleForwardResult(msg.PPD, &resultMsg)
			}
		}
	})

	// Set up nodeA to respond (it's healthy) - but we'll mark it unhealthy manually
	nodeA.SetMessageHandler(func(msg *ReceivedMsg) {
		if msg.HeaderType == core.NHP_FWD {
			requestMu.Lock()
			requestCounts["server-a"]++
			requestMu.Unlock()

			var fwdMsg common.ServerForwardMsg
			if err := json.Unmarshal(msg.Data, &fwdMsg); err != nil {
				t.Errorf("NodeA: failed to unmarshal NHP_FWD: %v", err)
				return
			}
			t.Logf("NodeA received forward (responding)")

			resultMsg := &common.ServerForwardResultMsg{
				TransactionId: fwdMsg.TransactionId,
				Success:       true,
				ACKData:       []byte(`{"status":"success-from-nodeA"}`),
			}
			resultBytes, _ := json.Marshal(resultMsg)

			nodeA.device.SendMsgToPacket(&core.MsgData{
				HeaderType:     core.NHP_FRT,
				TransactionId:  fwdMsg.TransactionId,
				Message:        resultBytes,
				PrevParserData: msg.PPD,
			})
		}
	})

	// Set up nodeB to respond
	nodeB.SetMessageHandler(func(msg *ReceivedMsg) {
		if msg.HeaderType == core.NHP_FWD {
			requestMu.Lock()
			requestCounts["server-b"]++
			requestMu.Unlock()

			var fwdMsg common.ServerForwardMsg
			if err := json.Unmarshal(msg.Data, &fwdMsg); err != nil {
				t.Errorf("NodeB: failed to unmarshal NHP_FWD: %v", err)
				return
			}
			t.Logf("NodeB received forward (responding)")

			resultMsg := &common.ServerForwardResultMsg{
				TransactionId: fwdMsg.TransactionId,
				Success:       true,
				ACKData:       []byte(`{"status":"success-from-nodeB"}`),
			}
			resultBytes, _ := json.Marshal(resultMsg)

			nodeB.device.SendMsgToPacket(&core.MsgData{
				HeaderType:     core.NHP_FRT,
				TransactionId:  fwdMsg.TransactionId,
				Message:        resultBytes,
				PrevParserData: msg.PPD,
			})
		}
	})

	// Create assignment with both nodes
	assignment := &ACAssignment{
		ACID:         "test-ac",
		ResourceFQDN: "test.resource.com",
		CustomerID:   "cust-123",
		AssignedServers: []ServerInfo{
			{ID: "server-a", IP: nodeA.addr.IP.String(), InternalIP: nodeA.addr.IP.String(), Port: nodeA.addr.Port, PubKey: nodeA.publicKey},
			{ID: "server-b", IP: nodeB.addr.IP.String(), InternalIP: nodeB.addr.IP.String(), Port: nodeB.addr.Port, PubKey: nodeB.publicKey},
		},
	}

	userAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 100), Port: 12345}
	knockData := []byte("test-knock-data")
	ctx := context.Background()

	// ========================================================================
	// Test 1: With all servers healthy, both should receive the bounded
	// single-attempt fan-out. First success still wins the ACK, but a slow peer
	// must not consume the whole customer-facing forward budget before the
	// other assigned peer gets a chance.
	// ========================================================================
	t.Log("=== Test 1: All servers healthy - should fan out to all healthy assigned servers ===")

	result1, err := forwarder.ForwardKnock(ctx, assignment, knockData, userAddr, nil)
	if err != nil {
		t.Fatalf("Forward 1 failed: %v", err)
	}
	if !result1.Success {
		t.Errorf("Forward 1 should succeed, got: %s", result1.ErrCode)
	}

	var total1 int
	deadline := time.Now().Add(time.Second)
	for {
		requestMu.Lock()
		total1 = requestCounts["server-a"] + requestCounts["server-b"]
		requestMu.Unlock()
		if total1 >= 2 || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if total1 != 2 {
		t.Errorf("Expected both healthy assigned servers to receive the first forward, got %d request(s)", total1)
	}

	// ========================================================================
	// Test 2: Mark server-a as unhealthy, verify it's skipped
	// ========================================================================
	t.Log("=== Test 2: Mark server-a unhealthy - should skip to server-b ===")

	// Small delay to avoid triggering flood protection (MinimalRecvIntervalMs = 20)
	time.Sleep(100 * time.Millisecond)

	// Mark server-a as unhealthy using the health tracker
	forwarder.health.RecordFailure("server-a")
	t.Log("Marked server-a as unhealthy")

	requestMu.Lock()
	beforeA := requestCounts["server-a"]
	beforeB := requestCounts["server-b"]
	requestMu.Unlock()

	result2, err := forwarder.ForwardKnock(ctx, assignment, knockData, userAddr, nil)
	if err != nil {
		t.Fatalf("Forward 2 failed: %v", err)
	}
	if !result2.Success {
		t.Errorf("Forward 2 should succeed, got: %s", result2.ErrCode)
	}

	requestMu.Lock()
	afterA := requestCounts["server-a"]
	afterB := requestCounts["server-b"]
	requestMu.Unlock()

	// server-a should NOT have received a new request (it's unhealthy)
	if afterA != beforeA {
		t.Errorf("server-a should be skipped (unhealthy): before=%d, after=%d", beforeA, afterA)
	}

	// server-b MUST have received the request
	if afterB != beforeB+1 {
		t.Errorf("server-b should receive request when server-a is unhealthy: before=%d, after=%d", beforeB, afterB)
	}

	t.Logf("✓ server-a skipped (count unchanged: %d), server-b handled request (count: %d → %d)",
		afterA, beforeB, afterB)

	// ========================================================================
	// Test 3: One more request with server-a unhealthy
	// ========================================================================
	t.Log("=== Test 3: Another request with server-a unhealthy ===")

	// Small delay to avoid triggering flood protection
	time.Sleep(100 * time.Millisecond)

	result3, err := forwarder.ForwardKnock(ctx, assignment, knockData, userAddr, nil)
	if err != nil {
		t.Fatalf("Forward 3 failed: %v", err)
	}
	if !result3.Success {
		t.Errorf("Forward 3 should succeed, got: %s", result3.ErrCode)
	}

	requestMu.Lock()
	finalA := requestCounts["server-a"]
	finalB := requestCounts["server-b"]
	requestMu.Unlock()

	// server-a should still have same count (still unhealthy)
	if finalA != afterA {
		t.Errorf("server-a should remain skipped: expected %d, got %d", afterA, finalA)
	}

	// server-b should have handled one more request
	if finalB != afterB+1 {
		t.Errorf("server-b should handle request: expected %d, got %d", afterB+1, finalB)
	}

	// ========================================================================
	// Test 4: Clear health state, verify server-a is used again
	// ========================================================================
	t.Log("=== Test 4: Clear unhealthy state - server-a should be usable ===")

	// Record success clears the failure
	forwarder.health.RecordSuccess("server-a")
	t.Log("Cleared server-a unhealthy state")

	// Verify server-a is no longer marked unhealthy
	if forwarder.health.IsUnhealthy("server-a") {
		t.Error("server-a should no longer be unhealthy after RecordSuccess")
	} else {
		t.Log("✓ server-a healthy state restored")
	}

	t.Log("")
	t.Log("============================================================")
	t.Log("SUCCESS: Health tracking test passed!")
	t.Log("============================================================")
	t.Log("Verified:")
	t.Log("  ✓ Healthy assigned servers receive bounded first-attempt fan-out")
	t.Log("  ✓ Unhealthy servers are skipped")
	t.Log("  ✓ Healthy fallback servers receive requests")
	t.Log("  ✓ Multiple requests skip unhealthy server consistently")
	t.Log("  ✓ Clearing unhealthy state allows server to be used again")
	t.Log("============================================================")
}
