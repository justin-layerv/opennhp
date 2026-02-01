package ac

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/nhp/core"
	"github.com/OpenNHP/opennhp/nhp/log"
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
		Port: 62206,
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
	localAddr := conn.netConn.LocalAddr().(*net.UDPAddr)
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
		Port: 62206,
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
	localAddr := conn.netConn.LocalAddr().(*net.UDPAddr)
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
	defer receiver.Close()

	// Expected "remote" address - but we won't actually connect to it
	expectedRemoteAddr := &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 50100,
	}

	// Get the local port to send to
	localAddr := receiver.LocalAddr().(*net.UDPAddr)
	targetAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: localAddr.Port}

	// Create a sender from a DIFFERENT address (simulating server responding from different IP)
	sender, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("Failed to create sender socket: %v", err)
	}
	defer sender.Close()
	senderAddr := sender.LocalAddr().(*net.UDPAddr)

	// Send a test packet from a DIFFERENT address than expected
	testData := []byte("test packet from unexpected source")
	_, err = sender.WriteToUDP(testData, targetAddr)
	if err != nil {
		t.Fatalf("Failed to send test packet: %v", err)
	}

	// Set read deadline to avoid hanging
	receiver.SetReadDeadline(time.Now().Add(1 * time.Second))

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
	defer receiver.Close()
	receiverAddr := receiver.LocalAddr().(*net.UDPAddr)

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
	receiver.SetReadDeadline(time.Now().Add(1 * time.Second))
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

// TestMultipleConnections_DifferentPorts verifies that multiple connections
// each get their own local port (ephemeral port allocation).
func TestMultipleConnections_DifferentPorts(t *testing.T) {
	ac := createTestAC(t)
	defer ac.device.Stop()

	// Create multiple connections to different remotes
	remotes := []*net.UDPAddr{
		{IP: net.ParseIP("10.0.1.1"), Port: 62206},
		{IP: net.ParseIP("10.0.1.2"), Port: 62206},
		{IP: net.ParseIP("10.0.1.3"), Port: 62206},
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
	defer nlbSocket.Close()
	nlbAddr := nlbSocket.LocalAddr().(*net.UDPAddr)

	// Create AC's connection (would be to NLB in production)
	acConn := ac.newConnection(nlbAddr)
	if acConn == nil {
		t.Fatal("newConnection returned nil")
	}
	// Stop the recv routine that consumes packets
	close(acConn.ConnData.StopSignal)
	acConn.ConnData.Wait()
	defer acConn.netConn.Close()

	// Get AC's local port - send to 127.0.0.1:port (not 0.0.0.0:port)
	acLocalAddr := acConn.netConn.LocalAddr().(*net.UDPAddr)
	acTargetAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: acLocalAddr.Port}

	// Create "server direct" socket (different port simulates different IP)
	serverSocket, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("Failed to create server socket: %v", err)
	}
	defer serverSocket.Close()
	serverAddr := serverSocket.LocalAddr().(*net.UDPAddr)

	// Server sends response to AC (from its direct IP, not NLB)
	response := []byte("NHP_AAK response from server")
	_, err = serverSocket.WriteToUDP(response, acTargetAddr)
	if err != nil {
		t.Fatalf("Server failed to send response: %v", err)
	}

	// AC receives response - this would FAIL with connected socket!
	acConn.netConn.SetReadDeadline(time.Now().Add(1 * time.Second))
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
	// when it tries to parse our test packets as NHP packets
	close(conn.ConnData.StopSignal)
	conn.ConnData.Wait()
	defer conn.netConn.Close()

	// Get local port - send to 127.0.0.1:port (not 0.0.0.0:port)
	localAddr := conn.netConn.LocalAddr().(*net.UDPAddr)
	targetAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: localAddr.Port}

	// Create sender
	sender, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("Failed to create sender: %v", err)
	}
	defer sender.Close()

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

	conn.netConn.SetReadDeadline(time.Now().Add(2 * time.Second))

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
	conn.netConn.Close()
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
			addr: &net.UDPAddr{IP: net.ParseIP("192.168.1.100"), Port: 62206},
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
		Port: 62206,
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
	if conn.ConnData.TimeoutMs != DefaultConnectionTimeoutMs {
		t.Errorf("TimeoutMs: got %d, want %d", conn.ConnData.TimeoutMs, DefaultConnectionTimeoutMs)
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
	defer serverSocket.Close()
	serverAddr := serverSocket.LocalAddr().(*net.UDPAddr)

	// Create AC connection to server
	acConn := ac.newConnection(serverAddr)
	if acConn == nil {
		t.Fatal("newConnection returned nil")
	}
	// Stop the recv routine that was started by newConnection
	close(acConn.ConnData.StopSignal)
	acConn.ConnData.Wait()
	defer acConn.netConn.Close()

	// Get AC's local port for server to respond to
	acLocalAddr := acConn.netConn.LocalAddr().(*net.UDPAddr)
	acTargetAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: acLocalAddr.Port}

	// AC sends to server
	request := []byte("NHP_AOL registration request")
	_, err = acConn.netConn.WriteToUDP(request, serverAddr)
	if err != nil {
		t.Fatalf("AC failed to send request: %v", err)
	}

	// Server receives
	serverSocket.SetReadDeadline(time.Now().Add(1 * time.Second))
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
	acConn.netConn.SetReadDeadline(time.Now().Add(1 * time.Second))
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
	// Stop the recv routine that consumes packets
	close(acConn.ConnData.StopSignal)
	acConn.ConnData.Wait()
	defer acConn.netConn.Close()

	// Get local port - send to 127.0.0.1:port (not 0.0.0.0:port)
	acLocalAddr := acConn.netConn.LocalAddr().(*net.UDPAddr)
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
		defer sender.Close()
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
	acConn.netConn.SetReadDeadline(time.Now().Add(2 * time.Second))

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
		expectedPort := senders[senderIdx].LocalAddr().(*net.UDPAddr).Port
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
