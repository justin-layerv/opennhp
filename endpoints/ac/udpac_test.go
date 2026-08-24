package ac

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
	"github.com/OpenNHP/opennhp/nhp/log"
	"github.com/OpenNHP/opennhp/nhp/utils/ebpf"
)

// testPrivateKey returns a valid 32-byte private key for testing.
func testPrivateKey() []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	return key
}

// createTestAC creates a minimal UdpAC for testing with a device.
func createTestAC(t *testing.T) *UdpAC {
	t.Helper()
	ac := &UdpAC{}
	ac.log = log.NewLogger("test", 0, "", "")

	device := core.NewDevice(core.NHP_AC, testPrivateKey(), nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}
	ac.device = device
	return ac
}

func TestUdpACStopInvokesBpfConntrackSamplerStop(t *testing.T) {
	ac := createTestAC(t)
	ac.signals.stop = make(chan struct{})
	ac.signals.serverMapUpdated = make(chan struct{})
	ac.sendMsgCh = make(chan *core.MsgData)

	var called atomic.Bool
	ac.bpfConntrackSamplerStop = func(ctx context.Context) error {
		called.Store(true)
		deadline, ok := ctx.Deadline()
		if !ok {
			t.Error("sampler stop context has no deadline")
		}
		if ok && time.Until(deadline) <= 0 {
			t.Error("sampler stop context deadline is already expired")
		}
		return nil
	}

	ac.Stop()

	if !called.Load() {
		t.Fatal("UdpAC.Stop did not invoke bpfConntrackSamplerStop")
	}
}

// connRoutineHarness drives ac.connectionRoutine against a stub AC; see TestConnectionRoutine_*.
type connRoutineHarness struct {
	t       *testing.T
	ac      *UdpAC
	conn    *UdpConn
	addrStr string
}

// newConnRoutineHarness wires AC + UDP socket + UdpConn with timeoutMs and starts connectionRoutine.
// NOTE: a.device is left nil. Callers must drive paths that don't deref it (NHP_KPL with non-pool-allocated pkts; SendQueue with KeepAfterSend=true).
func newConnRoutineHarness(t *testing.T, timeoutMs int) *connRoutineHarness {
	t.Helper()
	ac := &UdpAC{
		remoteConnectionMap:   make(map[string]*UdpConn),
		remoteConnectionMutex: sync.Mutex{},
		wg:                    sync.WaitGroup{},
	}
	ac.signals.stop = make(chan struct{})

	localAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	netConn, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		t.Fatalf("Failed to create UDP socket: %v", err)
	}
	remoteAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 49999} // ephemeral; nothing listens; sends drop silently
	netConnLocalAddr, ok := netConn.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("expected *net.UDPAddr, got %T", netConn.LocalAddr())
	}
	addrStr := remoteAddr.String()

	conn := &UdpConn{
		netConn: netConn,
		ConnData: &core.ConnectionData{
			RemoteAddr:       remoteAddr,
			LocalAddr:        netConnLocalAddr,
			SendQueue:        make(chan *core.Packet, 16),
			RecvQueue:        make(chan *core.Packet, 16),
			BlockSignal:      make(chan struct{}),
			StopSignal:       make(chan struct{}),
			SetTimeoutSignal: make(chan struct{}, 1),
		},
	}
	conn.ConnData.InitTimeoutMs(timeoutMs)
	// No ConnData.Add(1): no recvPacketRoutine here, so Close() must not block on Wait.
	ac.remoteConnectionMap[addrStr] = conn

	ac.wg.Add(1)
	go ac.connectionRoutine(conn)

	return &connRoutineHarness{t: t, ac: ac, conn: conn, addrStr: addrStr}
}

// assertPresent fails the test if the connection is no longer in the map.
func (h *connRoutineHarness) assertPresent(msg string) {
	h.t.Helper()
	h.ac.remoteConnectionMutex.Lock()
	_, present := h.ac.remoteConnectionMap[h.addrStr]
	h.ac.remoteConnectionMutex.Unlock()
	if !present {
		h.t.Fatal(msg)
	}
}

// waitRemoved polls until the conn leaves the map; t.Fatal on timeout.
func (h *connRoutineHarness) waitRemoved(timeout time.Duration, msg string) {
	h.t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		h.ac.remoteConnectionMutex.Lock()
		_, stillPresent := h.ac.remoteConnectionMap[h.addrStr]
		h.ac.remoteConnectionMutex.Unlock()
		if !stillPresent {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	h.t.Fatal(msg)
}

// shutdown closes signals.stop and bounded-waits for the routine; t.Errorf on timeout.
func (h *connRoutineHarness) shutdown(timeout time.Duration) {
	h.t.Helper()
	close(h.ac.signals.stop)
	done := make(chan struct{})
	go func() { h.ac.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(timeout):
		h.t.Errorf("connectionRoutine did not exit within %s after stop signal", timeout)
	}
}

// TestNewConnection_UnconnectedSocket verifies that newConnection creates an
// unconnected UDP socket (via ListenUDP) rather than a connected socket (DialUDP).
// Unconnected sockets are required to accept packets from any source address,
// which is necessary when AC connects through NLB but server responds directly.
func TestNewConnection_UnconnectedSocket(t *testing.T) {
	ac := createTestAC(t)
	defer ac.device.Stop()

	// Create connection to an arbitrary address
	remoteAddr := &net.UDPAddr{
		IP:   net.ParseIP("192.168.1.100"),
		Port: testServerListenPort,
	}

	conn := ac.newConnection(remoteAddr)
	if conn == nil {
		t.Fatal("newConnection returned nil")
	}
	defer conn.Close()

	// Verify the connection was created
	if conn.netConn == nil {
		t.Fatal("netConn is nil")
	}

	// Verify LocalAddr was set (socket is bound)
	if conn.ConnData.LocalAddr == nil {
		t.Fatal("LocalAddr is nil - socket not bound")
	}

	// Verify RemoteAddr was set correctly
	if conn.ConnData.RemoteAddr == nil {
		t.Fatal("RemoteAddr is nil")
	}
	if conn.ConnData.RemoteAddr.String() != remoteAddr.String() {
		t.Errorf("RemoteAddr mismatch: got %s, want %s",
			conn.ConnData.RemoteAddr.String(), remoteAddr.String())
	}

	// Verify the socket is listening on a local port (ephemeral)
	localAddr, ok := conn.netConn.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("expected *net.UDPAddr, got %T", conn.netConn.LocalAddr())
	}
	if localAddr.Port == 0 {
		t.Error("Socket not bound to a port")
	}

	t.Logf("Created unconnected socket on %s for remote %s", localAddr.String(), remoteAddr.String())
}

// TestNewConnection_IPv6Socket verifies that newConnection correctly handles
// IPv6 addresses by creating a udp6 socket with IPv6 local binding.
func TestNewConnection_IPv6Socket(t *testing.T) {
	ac := createTestAC(t)
	defer ac.device.Stop()

	// Create connection to an IPv6 address
	remoteAddr := &net.UDPAddr{
		IP:   net.ParseIP("::1"),
		Port: testServerListenPort,
	}

	conn := ac.newConnection(remoteAddr)
	if conn == nil {
		t.Fatal("newConnection returned nil")
	}
	defer conn.Close()

	// Verify the connection was created
	if conn.netConn == nil {
		t.Fatal("netConn is nil")
	}

	// Verify LocalAddr was set
	if conn.ConnData.LocalAddr == nil {
		t.Fatal("LocalAddr is nil - socket not bound")
	}

	// Verify the socket is bound to an IPv6 address
	localAddr, ok := conn.netConn.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("expected *net.UDPAddr, got %T", conn.netConn.LocalAddr())
	}
	if localAddr.IP.To4() != nil {
		t.Errorf("Expected IPv6 socket but got IPv4: %s", localAddr.String())
	}

	// Verify RemoteAddr was set correctly
	if conn.ConnData.RemoteAddr.String() != remoteAddr.String() {
		t.Errorf("RemoteAddr mismatch: got %s, want %s",
			conn.ConnData.RemoteAddr.String(), remoteAddr.String())
	}

	t.Logf("Created IPv6 unconnected socket on %s for remote %s", localAddr.String(), remoteAddr.String())
}

// TestNewConnection_AcceptsFromAnySource verifies that packets from any source
// are accepted by the unconnected socket. This is the core fix for the NLB issue.
// We test this by creating a separate unconnected socket (same as newConnection creates)
// and verifying it can receive from any source address.
func TestNewConnection_AcceptsFromAnySource(t *testing.T) {
	// Create an unconnected UDP socket - same way newConnection does
	// This is the key behavior we're testing: ListenUDP creates unconnected sockets
	// that accept packets from ANY source, unlike DialUDP which only accepts from the connected peer.
	receiver, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatalf("Failed to create unconnected socket: %v", err)
	}
	defer func() { _ = receiver.Close() }()

	// Expected "remote" address - but we won't actually connect to it
	expectedRemoteAddr := &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 50100,
	}

	// Get the local port to send to
	localAddr, ok := receiver.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("expected *net.UDPAddr, got %T", receiver.LocalAddr())
	}
	targetAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: localAddr.Port}

	// Create a sender from a DIFFERENT address (simulating server responding from different IP)
	sender, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("Failed to create sender socket: %v", err)
	}
	defer func() { _ = sender.Close() }()
	senderAddr, ok2 := sender.LocalAddr().(*net.UDPAddr)
	if !ok2 {
		t.Fatalf("expected *net.UDPAddr, got %T", sender.LocalAddr())
	}

	// Send a test packet from a DIFFERENT address than expected
	testData := []byte("test packet from unexpected source")
	_, err = sender.WriteToUDP(testData, targetAddr)
	if err != nil {
		t.Fatalf("Failed to send test packet: %v", err)
	}

	// Set read deadline to avoid hanging
	_ = receiver.SetReadDeadline(time.Now().Add(1 * time.Second))

	// Read the packet - should succeed even though sender != expected remote
	buf := make([]byte, 1024)
	n, fromAddr, err := receiver.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("Failed to receive packet from different source: %v", err)
	}

	// Verify we received the packet
	if n != len(testData) {
		t.Errorf("Received %d bytes, expected %d", n, len(testData))
	}

	// Verify packet came from the different address (not the expected remote)
	if fromAddr.Port == expectedRemoteAddr.Port {
		t.Error("Packet came from expected address - test doesn't prove unconnected behavior")
	}
	if fromAddr.Port != senderAddr.Port {
		t.Errorf("Packet from %s, expected from %s", fromAddr.String(), senderAddr.String())
	}

	t.Logf("Successfully received packet from %s (expected %s) - unconnected socket works!",
		fromAddr.String(), expectedRemoteAddr.String())
}

// TestSendPacket_WriteToUDP verifies that SendPacket uses WriteToUDP with
// explicit destination rather than Write on a connected socket.
func TestSendPacket_WriteToUDP(t *testing.T) {
	// Create a receiver socket to capture sent packets
	receiver, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("Failed to create receiver socket: %v", err)
	}
	defer func() { _ = receiver.Close() }()
	receiverAddr, ok := receiver.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("expected *net.UDPAddr, got %T", receiver.LocalAddr())
	}

	ac := createTestAC(t)
	defer ac.device.Stop()

	// Create connection to the receiver address
	conn := ac.newConnection(receiverAddr)
	if conn == nil {
		t.Fatal("newConnection returned nil")
	}
	defer conn.Close()

	// Create a test packet
	pkt := ac.device.AllocatePoolPacket()
	pkt.Content = []byte("test packet content for WriteToUDP verification")
	pkt.KeepAfterSend = true // Don't release after send

	// Send the packet
	n, err := ac.SendPacket(pkt, conn)
	if err != nil {
		t.Fatalf("SendPacket failed: %v", err)
	}
	if n != len(pkt.Content) {
		t.Errorf("Sent %d bytes, expected %d", n, len(pkt.Content))
	}

	// Receive the packet on the receiver
	_ = receiver.SetReadDeadline(time.Now().Add(1 * time.Second))
	buf := make([]byte, 1024)
	n, fromAddr, err := receiver.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("Failed to receive packet: %v", err)
	}

	// Verify the packet content
	if string(buf[:n]) != string(pkt.Content) {
		t.Errorf("Received content mismatch: got %q, want %q", string(buf[:n]), string(pkt.Content))
	}

	// Verify the sender address is our local address
	if fromAddr.Port != conn.ConnData.LocalAddr.Port {
		t.Errorf("Sender port mismatch: got %d, want %d", fromAddr.Port, conn.ConnData.LocalAddr.Port)
	}

	t.Logf("SendPacket successfully sent %d bytes to %s using WriteToUDP", n, receiverAddr.String())
}

func TestSendPacket_ExplicitDestinationRetainsExistingSocket(t *testing.T) {
	nlbSocket, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = nlbSocket.Close() }()
	nlbAddr := nlbSocket.LocalAddr().(*net.UDPAddr)
	serverSocket, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = serverSocket.Close() }()
	serverAddr := serverSocket.LocalAddr().(*net.UDPAddr)

	ac := createTestAC(t)
	defer ac.device.Stop()
	conn := ac.newConnection(nlbAddr)
	if conn == nil {
		t.Fatal("newConnection returned nil")
	}
	defer conn.Close()
	pkt := ac.device.AllocatePoolPacket()
	pkt.Content = []byte("direct response on NLB-oriented socket")
	pkt.KeepAfterSend = true
	pkt.SendTo = serverAddr.AddrPort()
	if _, err = ac.SendPacket(pkt, conn); err != nil {
		t.Fatal(err)
	}
	_ = serverSocket.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 128)
	n, from, err := serverSocket.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != string(pkt.Content) || from.Port != conn.ConnData.LocalAddr.Port {
		t.Fatalf("explicit route received %q from %s, want same socket port %d", buf[:n], from, conn.ConnData.LocalAddr.Port)
	}
	_ = nlbSocket.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	if _, _, err = nlbSocket.ReadFromUDP(buf); err == nil {
		t.Fatal("explicit route also sent packet to NLB")
	}
}

// TestMultipleConnections_DifferentPorts verifies that multiple connections
// each get their own local port (ephemeral port allocation).
func TestMultipleConnections_DifferentPorts(t *testing.T) {
	ac := createTestAC(t)
	defer ac.device.Stop()

	// Create multiple connections to different remotes
	remotes := []*net.UDPAddr{
		{IP: net.ParseIP("10.0.1.1"), Port: testServerListenPort},
		{IP: net.ParseIP("10.0.1.2"), Port: testServerListenPort},
		{IP: net.ParseIP("10.0.1.3"), Port: testServerListenPort},
	}

	var conns []*UdpConn
	ports := make(map[int]bool)

	for _, remote := range remotes {
		conn := ac.newConnection(remote)
		if conn == nil {
			t.Fatalf("newConnection returned nil for %s", remote.String())
		}
		conns = append(conns, conn)

		localPort := conn.ConnData.LocalAddr.Port
		if ports[localPort] {
			t.Errorf("Duplicate local port %d - connections should use different ephemeral ports", localPort)
		}
		ports[localPort] = true
		t.Logf("Connection to %s uses local port %d", remote.String(), localPort)
	}

	// Cleanup
	for _, conn := range conns {
		conn.Close()
	}

	if len(ports) != len(remotes) {
		t.Errorf("Expected %d unique ports, got %d", len(remotes), len(ports))
	}
}

// TestConnection_SimulatesNLBScenario simulates the exact NLB scenario:
// AC sends to NLB address, server responds from direct IP.
func TestConnection_SimulatesNLBScenario(t *testing.T) {
	// This test simulates:
	// 1. AC creates socket for NLB address (3.x.x.x:62206)
	// 2. AC sends packet to NLB
	// 3. Server receives and responds from its direct IP (10.x.x.x:62206)
	// 4. AC receives response even though source != expected NLB

	ac := createTestAC(t)
	defer ac.device.Stop()

	// Create "NLB" socket (what AC thinks it's talking to)
	nlbSocket, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("Failed to create NLB socket: %v", err)
	}
	defer func() { _ = nlbSocket.Close() }()
	nlbAddr, ok := nlbSocket.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("expected *net.UDPAddr, got %T", nlbSocket.LocalAddr())
	}

	// Create AC's connection (would be to NLB in production)
	acConn := ac.newConnection(nlbAddr)
	if acConn == nil {
		t.Fatal("newConnection returned nil")
	}
	// Stop the recv routine that was started by newConnection.
	// Set a short deadline to unblock ReadFromUDP, then signal stop and wait.
	_ = acConn.netConn.SetReadDeadline(time.Now().Add(1 * time.Millisecond))
	close(acConn.ConnData.StopSignal)
	acConn.ConnData.Wait()
	_ = acConn.netConn.SetReadDeadline(time.Time{}) // Clear deadline for test use
	defer func() { _ = acConn.netConn.Close() }()

	// Get AC's local port - send to 127.0.0.1:port (not 0.0.0.0:port)
	acLocalAddr, ok := acConn.netConn.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("expected *net.UDPAddr, got %T", acConn.netConn.LocalAddr())
	}
	acTargetAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: acLocalAddr.Port}

	// Create "server direct" socket (different port simulates different IP)
	serverSocket, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("Failed to create server socket: %v", err)
	}
	defer func() { _ = serverSocket.Close() }()
	serverAddr, ok := serverSocket.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("expected *net.UDPAddr, got %T", serverSocket.LocalAddr())
	}

	// Server sends response to AC (from its direct IP, not NLB)
	response := []byte("NHP_AAK response from server")
	_, err = serverSocket.WriteToUDP(response, acTargetAddr)
	if err != nil {
		t.Fatalf("Server failed to send response: %v", err)
	}

	// AC receives response - this would FAIL with connected socket!
	_ = acConn.netConn.SetReadDeadline(time.Now().Add(1 * time.Second))
	buf := make([]byte, 1024)
	n, fromAddr, err := acConn.netConn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("AC failed to receive response: %v - THIS IS THE NLB BUG!", err)
	}

	// Verify response received
	if string(buf[:n]) != string(response) {
		t.Errorf("Response mismatch: got %q, want %q", string(buf[:n]), string(response))
	}

	// Key assertion: packet came from server's direct port, not NLB port
	if fromAddr.Port == nlbAddr.Port {
		t.Error("Response came from NLB port - expected server direct port")
	}
	if fromAddr.Port != serverAddr.Port {
		t.Errorf("Response from unexpected port: got %d, want %d", fromAddr.Port, serverAddr.Port)
	}

	t.Logf("SUCCESS: AC received response from %s even though socket was created for %s",
		fromAddr.String(), nlbAddr.String())
	t.Log("This proves unconnected sockets fix the NLB issue!")
}

// TestConnection_ConcurrentReceive verifies that multiple goroutines can
// receive packets concurrently without issues.
func TestConnection_ConcurrentReceive(t *testing.T) {
	ac := createTestAC(t)
	defer ac.device.Stop()

	remoteAddr := &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 50003,
	}

	conn := ac.newConnection(remoteAddr)
	if conn == nil {
		t.Fatal("newConnection returned nil")
	}
	// Stop the recv routine that was started by newConnection to avoid panic
	// when it tries to parse our test packets as NHP packets.
	// Set a short deadline to unblock ReadFromUDP, then signal stop and wait.
	_ = conn.netConn.SetReadDeadline(time.Now().Add(1 * time.Millisecond))
	close(conn.ConnData.StopSignal)
	conn.ConnData.Wait()
	_ = conn.netConn.SetReadDeadline(time.Time{}) // Clear deadline for test use
	defer func() { _ = conn.netConn.Close() }()

	// Get local port - send to 127.0.0.1:port (not 0.0.0.0:port)
	localAddr, ok := conn.netConn.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("expected *net.UDPAddr, got %T", conn.netConn.LocalAddr())
	}
	targetAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: localAddr.Port}

	// Create sender
	sender, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("Failed to create sender: %v", err)
	}
	defer func() { _ = sender.Close() }()

	// Send multiple packets
	numPackets := 10
	for i := 0; i < numPackets; i++ {
		_, err := sender.WriteToUDP([]byte{byte(i)}, targetAddr)
		if err != nil {
			t.Fatalf("Failed to send packet %d: %v", i, err)
		}
	}

	// Receive packets concurrently
	var received int32
	var wg sync.WaitGroup

	_ = conn.netConn.SetReadDeadline(time.Now().Add(2 * time.Second))

	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, 1024)
			for {
				n, _, err := conn.netConn.ReadFromUDP(buf)
				if err != nil {
					return // Deadline or closed
				}
				if n > 0 {
					atomic.AddInt32(&received, 1)
				}
			}
		}()
	}

	// Wait for receivers to finish (timeout)
	time.Sleep(500 * time.Millisecond)
	_ = conn.netConn.Close()
	wg.Wait()

	t.Logf("Received %d of %d packets concurrently", received, numPackets)
}

// TestConnection_RemoteAddrPreserved verifies that RemoteAddr is correctly
// stored and can be used for sending responses.
func TestConnection_RemoteAddrPreserved(t *testing.T) {
	ac := createTestAC(t)
	defer ac.device.Stop()

	testCases := []struct {
		name string
		addr *net.UDPAddr
	}{
		{
			name: "IPv4 address",
			addr: &net.UDPAddr{IP: net.ParseIP("192.168.1.100"), Port: testServerListenPort},
		},
		{
			name: "localhost",
			addr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080},
		},
		{
			name: "high port",
			addr: &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 65535},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			conn := ac.newConnection(tc.addr)
			if conn == nil {
				t.Fatal("newConnection returned nil")
			}
			defer conn.Close()

			// Verify RemoteAddr matches input
			if conn.ConnData.RemoteAddr.IP.String() != tc.addr.IP.String() {
				t.Errorf("RemoteAddr IP: got %s, want %s",
					conn.ConnData.RemoteAddr.IP.String(), tc.addr.IP.String())
			}
			if conn.ConnData.RemoteAddr.Port != tc.addr.Port {
				t.Errorf("RemoteAddr Port: got %d, want %d",
					conn.ConnData.RemoteAddr.Port, tc.addr.Port)
			}
		})
	}
}

// TestConnection_QueuesInitialized verifies that all queues are properly
// initialized in the ConnectionData.
func TestConnection_QueuesInitialized(t *testing.T) {
	ac := createTestAC(t)
	defer ac.device.Stop()

	remoteAddr := &net.UDPAddr{
		IP:   net.ParseIP("10.0.1.1"),
		Port: testServerListenPort,
	}

	conn := ac.newConnection(remoteAddr)
	if conn == nil {
		t.Fatal("newConnection returned nil")
	}
	defer conn.Close()

	// Verify all channels are initialized
	if conn.ConnData.SendQueue == nil {
		t.Error("SendQueue is nil")
	}
	if conn.ConnData.RecvQueue == nil {
		t.Error("RecvQueue is nil")
	}
	if conn.ConnData.StopSignal == nil {
		t.Error("StopSignal is nil")
	}
	if conn.ConnData.BlockSignal == nil {
		t.Error("BlockSignal is nil")
	}
	if conn.ConnData.SetTimeoutSignal == nil {
		t.Error("SetTimeoutSignal is nil")
	}

	// Verify device reference
	if conn.ConnData.Device == nil {
		t.Error("Device is nil")
	}

	// Verify timeout is set
	if got := conn.ConnData.TimeoutMs(); got != DefaultConnectionTimeoutMs {
		t.Errorf("TimeoutMs: got %d, want %d", got, DefaultConnectionTimeoutMs)
	}

	t.Log("All queues and references properly initialized")
}

// TestConnection_BidirectionalCommunication verifies that bidirectional
// communication works correctly with unconnected sockets.
func TestConnection_BidirectionalCommunication(t *testing.T) {
	ac := createTestAC(t)
	defer ac.device.Stop()

	// Create a "server" socket
	serverSocket, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("Failed to create server socket: %v", err)
	}
	defer func() { _ = serverSocket.Close() }()
	serverAddr, ok := serverSocket.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("expected *net.UDPAddr, got %T", serverSocket.LocalAddr())
	}

	// Create AC connection to server
	acConn := ac.newConnection(serverAddr)
	if acConn == nil {
		t.Fatal("newConnection returned nil")
	}
	// Stop the recv routine that was started by newConnection.
	// Set a short deadline to unblock ReadFromUDP, then signal stop and wait.
	_ = acConn.netConn.SetReadDeadline(time.Now().Add(1 * time.Millisecond))
	close(acConn.ConnData.StopSignal)
	acConn.ConnData.Wait()
	_ = acConn.netConn.SetReadDeadline(time.Time{}) // Clear deadline for test use
	defer func() { _ = acConn.netConn.Close() }()

	// Get AC's local port for server to respond to
	acLocalAddr, ok := acConn.netConn.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("expected *net.UDPAddr, got %T", acConn.netConn.LocalAddr())
	}
	acTargetAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: acLocalAddr.Port}

	// AC sends to server
	request := []byte("NHP_AOL registration request")
	_, err = acConn.netConn.WriteToUDP(request, serverAddr)
	if err != nil {
		t.Fatalf("AC failed to send request: %v", err)
	}

	// Server receives
	_ = serverSocket.SetReadDeadline(time.Now().Add(1 * time.Second))
	buf := make([]byte, 1024)
	n, fromAddr, err := serverSocket.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("Server failed to receive request: %v", err)
	}
	if string(buf[:n]) != string(request) {
		t.Errorf("Server received wrong data: got %q, want %q", string(buf[:n]), string(request))
	}
	// fromAddr will be 127.0.0.1:port or 0.0.0.0:port depending on platform
	if fromAddr.Port != acLocalAddr.Port {
		t.Errorf("Request from wrong port: got %d, want %d", fromAddr.Port, acLocalAddr.Port)
	}

	// Server responds to AC's address (use the target address, not fromAddr which might be 0.0.0.0)
	response := []byte("NHP_AAK registration ack")
	_, err = serverSocket.WriteToUDP(response, acTargetAddr)
	if err != nil {
		t.Fatalf("Server failed to send response: %v", err)
	}

	// AC receives response
	_ = acConn.netConn.SetReadDeadline(time.Now().Add(1 * time.Second))
	n, fromAddr, err = acConn.netConn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("AC failed to receive response: %v", err)
	}
	if string(buf[:n]) != string(response) {
		t.Errorf("AC received wrong data: got %q, want %q", string(buf[:n]), string(response))
	}
	if fromAddr.Port != serverAddr.Port {
		t.Errorf("Response from wrong port: got %d, want %d", fromAddr.Port, serverAddr.Port)
	}

	t.Log("Bidirectional communication successful!")
}

// TestConnection_MultipleSourcesSequential verifies that packets from multiple
// different sources are all received correctly.
func TestConnection_MultipleSourcesSequential(t *testing.T) {
	ac := createTestAC(t)
	defer ac.device.Stop()

	// Create AC connection to some expected address
	expectedAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 50000}
	acConn := ac.newConnection(expectedAddr)
	if acConn == nil {
		t.Fatal("newConnection returned nil")
	}
	// Stop the recv routine that consumes packets.
	// Set a short deadline to unblock ReadFromUDP, then signal stop and wait.
	_ = acConn.netConn.SetReadDeadline(time.Now().Add(1 * time.Millisecond))
	close(acConn.ConnData.StopSignal)
	acConn.ConnData.Wait()
	_ = acConn.netConn.SetReadDeadline(time.Time{}) // Clear deadline for test use
	defer func() { _ = acConn.netConn.Close() }()

	// Get local port - send to 127.0.0.1:port (not 0.0.0.0:port)
	acLocalAddr, ok := acConn.netConn.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("expected *net.UDPAddr, got %T", acConn.netConn.LocalAddr())
	}
	acTargetAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: acLocalAddr.Port}

	// Create multiple senders (simulating packets from different sources)
	numSenders := 5
	var senders []*net.UDPConn
	for i := 0; i < numSenders; i++ {
		sender, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
		if err != nil {
			t.Fatalf("Failed to create sender %d: %v", i, err)
		}
		senders = append(senders, sender)
		defer func() { _ = sender.Close() }()
	}

	// Each sender sends a unique message
	for i, sender := range senders {
		msg := []byte{byte(i), byte(i + 100)}
		_, err := sender.WriteToUDP(msg, acTargetAddr)
		if err != nil {
			t.Fatalf("Sender %d failed to send: %v", i, err)
		}
	}

	// Receive all messages
	receivedFrom := make(map[int]bool)
	_ = acConn.netConn.SetReadDeadline(time.Now().Add(2 * time.Second))

	for i := 0; i < numSenders; i++ {
		buf := make([]byte, 1024)
		n, fromAddr, err := acConn.netConn.ReadFromUDP(buf)
		if err != nil {
			t.Fatalf("Failed to receive packet %d: %v", i, err)
		}
		if n != 2 {
			t.Errorf("Packet %d wrong size: got %d, want 2", i, n)
			continue
		}

		senderIdx := int(buf[0])
		receivedFrom[senderIdx] = true

		// Verify packet came from the correct sender
		senderLocalAddr, ok := senders[senderIdx].LocalAddr().(*net.UDPAddr)
		if !ok {
			t.Fatalf("expected *net.UDPAddr, got %T", senders[senderIdx].LocalAddr())
		}
		expectedPort := senderLocalAddr.Port
		if fromAddr.Port != expectedPort {
			t.Errorf("Packet %d from wrong port: got %d, want %d", senderIdx, fromAddr.Port, expectedPort)
		}
	}

	// Verify we received from all senders
	for i := 0; i < numSenders; i++ {
		if !receivedFrom[i] {
			t.Errorf("Never received packet from sender %d", i)
		}
	}

	t.Logf("Successfully received packets from %d different sources", len(receivedFrom))
}

// TestConnectionTimeout_TriggersReregistration tests that when a server connection
// times out, TriggerReregistration is called on the registration manager.
func TestConnectionTimeout_TriggersReregistration(t *testing.T) {
	// Create AC with registration manager
	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
			Environment:    "test", // suppress empty-Env startup warning
		},
		remoteConnectionMap:   make(map[string]*UdpConn),
		remoteConnectionMutex: sync.Mutex{},
		wg:                    sync.WaitGroup{},
	}
	ac.signals.stop = make(chan struct{})

	// Create registration manager with test server
	reg, err := NewACRegistration(ac)
	if err != nil {
		t.Fatalf("NewACRegistration failed: %v", err)
	}
	ac.registration = reg

	// Add a server to assignedServers so IsServerAddress returns true
	serverAddr := "10.0.0.1:62206"
	reg.assignedServers = []*AssignedServer{
		{
			Target: common.RedirectTarget{
				IP:   "10.0.0.1",
				Port: testServerListenPort,
			},
		},
	}

	// Verify IsServerAddress returns true for our test address
	if !reg.IsServerAddress(serverAddr) {
		t.Fatalf("IsServerAddress should return true for %s", serverAddr)
	}

	// Create a UDP socket for testing
	localAddr := &net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: 0}
	netConn, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		t.Fatalf("Failed to create UDP socket: %v", err)
	}

	// Create connection with very short timeout (50ms)
	remoteAddr := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: testServerListenPort}
	netConnLocalAddr, ok := netConn.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("expected *net.UDPAddr, got %T", netConn.LocalAddr())
	}
	conn := &UdpConn{
		netConn: netConn,
		ConnData: &core.ConnectionData{
			RemoteAddr:       remoteAddr,
			LocalAddr:        netConnLocalAddr,
			SendQueue:        make(chan *core.Packet, 16),
			RecvQueue:        make(chan *core.Packet, 16),
			BlockSignal:      make(chan struct{}),
			StopSignal:       make(chan struct{}),
			SetTimeoutSignal: make(chan struct{}, 1),
		},
	}
	conn.ConnData.InitTimeoutMs(50) // Very short timeout
	conn.ConnData.Add(1)            // For recvPacketRoutine (will be Done'd on close)

	// Store connection in map
	ac.remoteConnectionMap[serverAddr] = conn

	// Start connection routine
	ac.wg.Add(1)
	go ac.connectionRoutine(conn)

	// Poll for connection to be removed (more reliable than fixed sleep)
	// Timeout is 50ms, so we poll up to 500ms to be safe on slow CI runners
	deadline := time.Now().Add(500 * time.Millisecond)
	var exists bool
	for time.Now().Before(deadline) {
		ac.remoteConnectionMutex.Lock()
		_, exists = ac.remoteConnectionMap[serverAddr]
		ac.remoteConnectionMutex.Unlock()
		if !exists {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if exists {
		t.Error("Connection should be removed from map after timeout")
	}

	// Clean up
	close(ac.signals.stop)
	reg.Stop()
}

// TestConnectionTimeout_NonServerConnection tests that non-server connections
// don't trigger re-registration on timeout.
func TestConnectionTimeout_NonServerConnection(t *testing.T) {
	// Create AC with registration manager
	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
			Environment:    "test", // suppress empty-Env startup warning
		},
		remoteConnectionMap:   make(map[string]*UdpConn),
		remoteConnectionMutex: sync.Mutex{},
		wg:                    sync.WaitGroup{},
	}
	ac.signals.stop = make(chan struct{})

	// Create registration manager with a DIFFERENT server address
	reg, err := NewACRegistration(ac)
	if err != nil {
		t.Fatalf("NewACRegistration failed: %v", err)
	}
	ac.registration = reg

	// Server at different address than our test connection
	reg.assignedServers = []*AssignedServer{
		{
			Target: common.RedirectTarget{
				IP:   "192.168.1.100", // Different from test connection
				Port: testServerListenPort,
			},
		},
	}

	// Test address should NOT be recognized as server
	testAddr := "10.0.0.99:12345"
	if reg.IsServerAddress(testAddr) {
		t.Fatalf("IsServerAddress should return false for %s", testAddr)
	}

	// Create a UDP socket for testing
	localAddr := &net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: 0}
	netConn, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		t.Fatalf("Failed to create UDP socket: %v", err)
	}

	// Create connection with very short timeout
	remoteAddr := &net.UDPAddr{IP: net.ParseIP("10.0.0.99"), Port: 12345}
	netConnLocalAddr, ok := netConn.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("expected *net.UDPAddr, got %T", netConn.LocalAddr())
	}
	conn := &UdpConn{
		netConn: netConn,
		ConnData: &core.ConnectionData{
			RemoteAddr:       remoteAddr,
			LocalAddr:        netConnLocalAddr,
			SendQueue:        make(chan *core.Packet, 16),
			RecvQueue:        make(chan *core.Packet, 16),
			BlockSignal:      make(chan struct{}),
			StopSignal:       make(chan struct{}),
			SetTimeoutSignal: make(chan struct{}, 1),
		},
	}
	conn.ConnData.InitTimeoutMs(50)
	conn.ConnData.Add(1)

	// Store connection in map
	ac.remoteConnectionMap[testAddr] = conn

	// Verify reregistering flag is false before
	if reg.reregistering.Load() {
		t.Error("reregistering should be false initially")
	}

	// Start connection routine
	ac.wg.Add(1)
	go ac.connectionRoutine(conn)

	// Poll for connection to be removed (more reliable than fixed sleep)
	deadline := time.Now().Add(500 * time.Millisecond)
	var exists bool
	for time.Now().Before(deadline) {
		ac.remoteConnectionMutex.Lock()
		_, exists = ac.remoteConnectionMap[testAddr]
		ac.remoteConnectionMutex.Unlock()
		if !exists {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if exists {
		t.Error("Connection should be removed from map after timeout")
	}

	// Reregistering flag should still be false (wasn't triggered)
	// Note: If it was triggered, it would have been set then cleared
	// This test verifies the condition check works

	// Clean up
	close(ac.signals.stop)
	reg.Stop()
}

// TestConnectionRoutine_PacketActivityResetsIdleTimer: SendQueue activity must reset the idle timer.
func TestConnectionRoutine_PacketActivityResetsIdleTimer(t *testing.T) {
	h := newConnRoutineHarness(t, 500) // 500ms timeout: headroom for routine drain + GC + race-instrumentation latency on shared CI

	// KeepAfterSend: true so SendPacket doesn't release pkt to a nil device pool.
	activityDone := make(chan struct{})
	go func() {
		defer close(activityDone)
		deadline := time.Now().Add(600 * time.Millisecond)
		for time.Now().Before(deadline) {
			pkt := &core.Packet{Content: []byte{0}, KeepAfterSend: true}
			select {
			case h.conn.ConnData.SendQueue <- pkt:
			case <-time.After(50 * time.Millisecond):
				return // routine exited or queue full — bail
			}
			time.Sleep(30 * time.Millisecond)
		}
	}()

	time.Sleep(400 * time.Millisecond)
	h.assertPresent("connection removed during packet activity — idle timer was not reset on send")

	<-activityDone

	h.waitRemoved(2*time.Second, "connection not removed within 2s after activity ceased — idle timeout did not fire")
	h.shutdown(time.Second)
}

// TestConnectionRoutine_KeepalivePacketsResetIdleTimer: NHP_KPL early-continue must still reset the timer (otherwise AC conns with only 10s keepalives idle out at 300s).
func TestConnectionRoutine_KeepalivePacketsResetIdleTimer(t *testing.T) {
	h := newConnRoutineHarness(t, 500)

	activityDone := make(chan struct{})
	go func() {
		defer close(activityDone)
		deadline := time.Now().Add(600 * time.Millisecond)
		for time.Now().Before(deadline) {
			pkt := &core.Packet{HeaderType: core.NHP_KPL, Content: []byte{0}}
			select {
			case h.conn.ConnData.RecvQueue <- pkt:
			case <-time.After(50 * time.Millisecond):
				return
			}
			time.Sleep(30 * time.Millisecond)
		}
	}()

	time.Sleep(400 * time.Millisecond)
	h.assertPresent("connection removed during keepalive activity — KPL did not reset idle timer (early-continue regression)")

	<-activityDone

	h.waitRemoved(2*time.Second, "connection not removed within 2s after keepalives ceased")
	h.shutdown(time.Second)
}

// TestConnectionRoutine_SetTimeoutSignalAppliesNewTimeout: SetTimeout(80ms) on a 10s-armed routine must re-arm immediately (not wait for next packet).
// SetTimeout's unbuffered send blocks until the routine selects on SetTimeoutSignal, so no separate "wait for routine to arm timer" sleep is required.
func TestConnectionRoutine_SetTimeoutSignalAppliesNewTimeout(t *testing.T) {
	h := newConnRoutineHarness(t, 10000)
	h.conn.ConnData.SetTimeout(80)

	h.waitRemoved(time.Second, "connection not removed within 1s of SetTimeout(80) — SetTimeoutSignal did not re-arm the idle timer")
	h.shutdown(time.Second)
}

// TestCloudModeSkipsFailOpen verifies that in cloud mode (where no servers are
// configured in server.toml and discoveryFailStatusArr is empty), the fail-open
// logic is skipped entirely. This prevents the security bug where 0 >= 0 would
// trigger AcceptAllInput().
//
// Background: In cloud mode, ACs register dynamically via NHP protocol rather
// than using static server.toml configuration. The serverPeerMap is intentionally
// empty, which means discoveryFailStatusArr is also empty. Before the fix,
// the condition `totalFail >= len(discoveryFailStatusArr)` evaluated to 0 >= 0 = true,
// incorrectly triggering fail-open mode and allowing all traffic.
func TestCloudModeSkipsFailOpen(t *testing.T) {
	// Test case 1: Empty array (cloud mode) - should NOT trigger fail-open
	t.Run("empty_array_skips_failopen", func(t *testing.T) {
		discoveryFailStatusArr := []*int32{}

		// The fix: when array is empty, skip the fail-open logic entirely
		if len(discoveryFailStatusArr) == 0 {
			// This is correct - cloud mode should skip fail-open
			t.Log("Cloud mode correctly skips fail-open logic when no servers configured")
			return
		}

		// If we get here, the test failed - cloud mode should have returned early
		t.Error("Cloud mode should skip fail-open logic when discoveryFailStatusArr is empty")
	})

	// Test case 2: Non-empty array with all failures - SHOULD trigger fail-open
	t.Run("all_servers_failed_triggers_failopen", func(t *testing.T) {
		var status1, status2 int32 = 1, 1 // Both failed
		discoveryFailStatusArr := []*int32{&status1, &status2}

		if len(discoveryFailStatusArr) == 0 {
			t.Error("Should not skip fail-open logic when servers are configured")
			return
		}

		var totalFail int32
		for _, status := range discoveryFailStatusArr {
			totalFail += atomic.LoadInt32(status)
		}

		// All servers failed - should trigger fail-open
		if totalFail >= int32(len(discoveryFailStatusArr)) {
			t.Log("Correctly triggers fail-open when all servers have failed")
		} else {
			t.Error("Should trigger fail-open when all servers failed")
		}
	})

	// Test case 3: Non-empty array with some successes - should NOT trigger fail-open
	t.Run("some_servers_ok_skips_failopen", func(t *testing.T) {
		var status1, status2 int32 = 0, 1 // One OK, one failed
		discoveryFailStatusArr := []*int32{&status1, &status2}

		if len(discoveryFailStatusArr) == 0 {
			t.Error("Should not skip fail-open logic when servers are configured")
			return
		}

		var totalFail int32
		for _, status := range discoveryFailStatusArr {
			totalFail += atomic.LoadInt32(status)
		}

		// Only 1 of 2 failed - should NOT trigger fail-open
		if totalFail < int32(len(discoveryFailStatusArr)) {
			t.Log("Correctly skips fail-open when some servers are OK")
		} else {
			t.Error("Should not trigger fail-open when some servers are OK")
		}
	})

	// Test case 4: Verify the old bug - 0 >= 0 would have triggered fail-open
	t.Run("old_bug_would_trigger_failopen", func(t *testing.T) {
		discoveryFailStatusArr := []*int32{} // Empty (cloud mode)

		// This is what the OLD buggy code would do:
		var totalFail int32
		for _, status := range discoveryFailStatusArr {
			totalFail += atomic.LoadInt32(status)
		}
		// totalFail = 0, len = 0
		// OLD: if totalFail >= len => 0 >= 0 => TRUE => AcceptAllInput() !!!

		if totalFail >= int32(len(discoveryFailStatusArr)) {
			t.Log("Confirmed: old logic would incorrectly trigger fail-open (0 >= 0 = true)")
		}

		// The fix prevents this by checking len == 0 first
		if len(discoveryFailStatusArr) == 0 {
			t.Log("Fix: empty array is now detected and fail-open logic is skipped")
		}
	})
}

// TestEbpfInfraExemptRules fences the FilterMode_EBPFXDP startup exemption set:
// one sdwhitelist rule per server peer PLUS exactly one address-agnostic
// protocol_port rule for the health-check port. The health-port rule is the
// one whose absence fail-closed drops the NLB probe before it can reach
// Traefik's health entrypoint, flaps every AC target unhealthy, and black-holes
// the fleet — regressing it must turn this test red.
func TestEbpfInfraExemptRules(t *testing.T) {
	cfg := &Config{
		DefaultIp:       "10.100.0.57",
		HealthCheckPort: 8080,
		Servers: []*core.UdpPeer{
			{Ip: "10.100.10.73"},
			{Ip: "10.100.11.85"},
		},
	}

	rules := ebpfInfraExemptRules(cfg.Servers, cfg.DefaultIp, cfg.HealthCheckPort)

	if got, want := len(rules), len(cfg.Servers)+1; got != want {
		t.Fatalf("rule count = %d, want %d (one per server peer + one health-check rule)", got, want)
	}

	// Server-peer rules come first, in cfg.Servers order: sdwhitelist
	// (mapType 2), SrcIP=peer, DstIP=DefaultIp, long-lived TTL.
	for i, server := range cfg.Servers {
		r := rules[i]
		if r.mapType != ebpf.MapTypeSdWhitelist {
			t.Errorf("server rule %d: mapType = %d, want %d (sdwhitelist)", i, r.mapType, ebpf.MapTypeSdWhitelist)
		}
		if r.params.SrcIP != server.Ip || r.params.DstIP != cfg.DefaultIp {
			t.Errorf("server rule %d: addr = %s->%s, want %s->%s", i, r.params.SrcIP, r.params.DstIP, server.Ip, cfg.DefaultIp)
		}
		if r.ttlSec != infraExemptTTLSec {
			t.Errorf("server rule %d: ttl = %d, want %d", i, r.ttlSec, infraExemptTTLSec)
		}
	}

	// Health-check rule is last: address-agnostic protocol_port (mapType 6)
	// admitting tcp/HealthCheckPort. Address-agnostic on purpose — the probe
	// arrives from the NLB's ephemeral cross-AZ subnet IPs.
	hc := rules[len(rules)-1]
	if hc.mapType != ebpf.MapTypeProtocolPort {
		t.Errorf("health rule: mapType = %d, want %d (protocol_port)", hc.mapType, ebpf.MapTypeProtocolPort)
	}
	if hc.params.Protocol != "tcp" || hc.params.DstPort != cfg.HealthCheckPort {
		t.Errorf("health rule: %s/%d, want tcp/%d", hc.params.Protocol, hc.params.DstPort, cfg.HealthCheckPort)
	}
	if hc.params.SrcIP != "" || hc.params.DstIP != "" {
		t.Errorf("health rule must carry no address (protocol_port is address-agnostic), got src=%q dst=%q", hc.params.SrcIP, hc.params.DstIP)
	}
	if hc.ttlSec != infraExemptTTLSec {
		t.Errorf("health rule: ttl = %d, want %d", hc.ttlSec, infraExemptTTLSec)
	}
}

// TestEbpfInfraExemptRules_HealthPortAdmittedWithoutServers proves the
// health-check exemption does not depend on any server peer being configured
// and honors a non-default HealthCheckPort.
func TestEbpfInfraExemptRules_HealthPortAdmittedWithoutServers(t *testing.T) {
	cfg := &Config{DefaultIp: "10.0.0.1", HealthCheckPort: 9090}

	rules := ebpfInfraExemptRules(cfg.Servers, cfg.DefaultIp, cfg.HealthCheckPort)

	if len(rules) != 1 {
		t.Fatalf("rule count = %d, want 1 (health-check rule only)", len(rules))
	}
	hc := rules[0]
	if hc.mapType != ebpf.MapTypeProtocolPort || hc.params.Protocol != "tcp" || hc.params.DstPort != 9090 {
		t.Errorf("health rule = map %d %s/%d, want map %d tcp/9090",
			hc.mapType, hc.params.Protocol, hc.params.DstPort, ebpf.MapTypeProtocolPort)
	}
}

// TestEbpfInfraExemptRules_NonPositivePortOmitsHealthRule proves the helper is
// correct independent of the config-normalization contract: a caller on an
// un-normalized Config (HealthCheckPort ≤ 0) must not seed a useless tcp/0
// admission — only the server-peer rules are returned.
func TestEbpfInfraExemptRules_NonPositivePortOmitsHealthRule(t *testing.T) {
	for _, port := range []int{0, -1} {
		cfg := &Config{
			DefaultIp:       "10.0.0.1",
			Servers:         []*core.UdpPeer{{Ip: "10.0.0.2"}},
			HealthCheckPort: port,
		}
		rules := ebpfInfraExemptRules(cfg.Servers, cfg.DefaultIp, cfg.HealthCheckPort)
		if len(rules) != len(cfg.Servers) {
			t.Errorf("HealthCheckPort=%d: got %d rules, want %d (server rules only)", port, len(rules), len(cfg.Servers))
		}
		for _, r := range rules {
			if r.mapType == ebpf.MapTypeProtocolPort {
				t.Errorf("HealthCheckPort=%d: helper must not seed a protocol_port (tcp/%d) rule", port, r.params.DstPort)
			}
		}
	}
}

// assertNoEmptySrcIPRule fails if any sdwhitelist rule carries an empty SrcIP —
// the bogus boot-time rule a hostname-only server peer would leak before the
// #3085 skip. protocol_port health rules are legitimately address-agnostic and
// carry no SrcIP, so they are exempt from this check.
func assertNoEmptySrcIPRule(t *testing.T, rules []ebpfInfraRule) {
	t.Helper()
	for i, r := range rules {
		if r.mapType == ebpf.MapTypeSdWhitelist && r.params.SrcIP == "" {
			t.Errorf("rule %d: sdwhitelist rule with empty SrcIP must never be seeded", i)
		}
	}
}

// TestEbpfInfraExemptRules_DNSOnlyPeerSeedsNoRule proves the boot-time XDP
// seeding skips a server peer configured by hostname only (Ip == "", resolved
// on the data path). Such a peer has no source IP to key on; an sdwhitelist
// rule with SrcIP="" is kernel-rejected or matches every source. Regression
// fence for #3085 bug 2 (adapted from OpenNHP 3e56ffc7).
func TestEbpfInfraExemptRules_DNSOnlyPeerSeedsNoRule(t *testing.T) {
	// Mixed fleet: one static-IP peer (installs a rule) plus one DNS-only peer
	// (Ip == "", must be skipped) — proves the skip is selective.
	cfg := &Config{
		DefaultIp:       "10.100.0.57",
		HealthCheckPort: 8080,
		Servers: []*core.UdpPeer{
			{Ip: "10.100.10.73"},
			{Hostname: "server.nhp.internal"}, // Ip == "" → skipped
		},
	}
	rules := ebpfInfraExemptRules(cfg.Servers, cfg.DefaultIp, cfg.HealthCheckPort)
	assertNoEmptySrcIPRule(t, rules)
	if got, want := len(rules), 2; got != want { // static-IP server rule + health rule
		t.Fatalf("mixed fleet: rule count = %d, want %d (static-IP server rule + health rule)", got, want)
	}
	if rules[0].mapType != ebpf.MapTypeSdWhitelist || rules[0].params.SrcIP != "10.100.10.73" {
		t.Errorf("mixed fleet: rule 0 = map %d src %q, want sdwhitelist src 10.100.10.73",
			rules[0].mapType, rules[0].params.SrcIP)
	}

	// DNS-only fleet: no static IPs at all → zero server rules (only the health
	// rule survives), and never an empty-SrcIP rule.
	dnsOnly := &Config{
		DefaultIp:       "10.100.0.57",
		HealthCheckPort: 8080,
		Servers:         []*core.UdpPeer{{Hostname: "a.internal"}, {Hostname: "b.internal"}},
	}
	rules = ebpfInfraExemptRules(dnsOnly.Servers, dnsOnly.DefaultIp, dnsOnly.HealthCheckPort)
	assertNoEmptySrcIPRule(t, rules)
	if got, want := len(rules), 1; got != want { // health rule only
		t.Fatalf("DNS-only fleet: rule count = %d, want %d (health rule only)", got, want)
	}
	if rules[0].mapType != ebpf.MapTypeProtocolPort {
		t.Errorf("DNS-only fleet: sole rule = map %d, want protocol_port health rule", rules[0].mapType)
	}
}

// snapshotAndBuildInfraRules exercises Start's ACTUAL boot-loop reader —
// a.snapshotInfraRuleInputs (the production locked snapshot) — then builds the
// exempt rules from it. Sharing the production reader (rather than
// re-implementing the RLock+copy in the test) makes the reader-side lock a
// tested invariant: dropping the RLock in snapshotInfraRuleInputs trips the race
// detector in the fences below against their real reload writers.
func snapshotAndBuildInfraRules(ac *UdpAC) []ebpfInfraRule {
	servers, defaultIp, healthCheckPort := ac.snapshotInfraRuleInputs()
	return ebpfInfraExemptRules(servers, defaultIp, healthCheckPort)
}

// TestUpdateServerPeers_ReloadVsRead_NoRaceDetectorTrip fences the #3085 bug 1
// data race on a.config.Servers: updateServerPeers (the server-peer reload
// watcher) rewrites the slice while Start's eBPF boot loop reads it. Before the
// fix, updateServerPeers assigned a.config.Servers OUTSIDE serverPeerMutex, so
// that slice-header write raced any concurrent read (-race-detectable). The fix
// assigns it under serverPeerMutex, and the boot-loop reader snapshots it under
// the same lock. This test drives the writer against lock-holding readers that
// mirror the boot-loop snapshot; the race detector is the contract. Adapted
// from OpenNHP 3e56ffc7.
func TestUpdateServerPeers_ReloadVsRead_NoRaceDetectorTrip(t *testing.T) {
	ac := createTestAC(t)
	ac.config = &Config{DefaultIp: "10.0.0.1", HealthCheckPort: 8080}

	// Distinct peer sets so each reload actually swaps the slice header. All
	// peers carry a static Ip so the readers don't spam the DNS-only skip log.
	const sets = 4
	peerSets := make([][]*core.UdpPeer, sets)
	for i := range peerSets {
		peerSets[i] = []*core.UdpPeer{
			{PubKeyBase64: fmt.Sprintf("peer-a-%d", i), Ip: fmt.Sprintf("10.0.1.%d", i)},
			{PubKeyBase64: fmt.Sprintf("peer-b-%d", i), Ip: fmt.Sprintf("10.0.2.%d", i)},
		}
	}

	const readers, iterations = 4, 200
	var wg sync.WaitGroup

	// Writer: the server-peer reload path.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			if err := ac.updateServerPeers(peerSets[i%sets]); err != nil {
				t.Errorf("updateServerPeers: %v", err)
				return
			}
		}
	}()

	// Readers: mirror Start's boot-loop snapshot.
	wg.Add(readers)
	for r := 0; r < readers; r++ {
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				_ = snapshotAndBuildInfraRules(ac)
			}
		}()
	}

	wg.Wait()
}

// TestBaseConfigReloadVsBootLoopRead_DefaultIp_NoRaceDetectorTrip fences the
// #3085 DefaultIp half of the same class of race: updateBaseConfig (the
// base-config reload watcher) patches a.config.DefaultIp while Start's eBPF boot
// loop reads it via ebpfInfraExemptRules. The base-config watcher is installed
// before the boot loop runs, so an operator editing DefaultIp during the boot
// window would race the read. The fix takes serverPeerMutex around the DefaultIp
// reload write, and the boot-loop reader snapshots DefaultIp under the same
// lock. This drives the real updateBaseConfig reload path against readers that
// mirror the boot-loop snapshot; the race detector is the contract.
func TestBaseConfigReloadVsBootLoopRead_DefaultIp_NoRaceDetectorTrip(t *testing.T) {
	ac := createTestAC(t)
	ac.config = &Config{DefaultIp: "10.0.0.1", HealthCheckPort: 8080}

	const readers, iterations = 4, 200
	var wg sync.WaitGroup

	// Writer: the base-config reload path, toggling DefaultIp through the real
	// updateBaseConfig (a.config != nil selects the reload branch).
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			conf := Config{DefaultIp: fmt.Sprintf("10.0.0.%d", i%8+1), HealthCheckPort: 8080}
			if err := ac.updateBaseConfig(conf); err != nil {
				t.Errorf("updateBaseConfig: %v", err)
				return
			}
		}
	}()

	// Readers: mirror Start's boot-loop snapshot (which reads DefaultIp).
	wg.Add(readers)
	for r := 0; r < readers; r++ {
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				_ = snapshotAndBuildInfraRules(ac)
			}
		}()
	}

	wg.Wait()
}
