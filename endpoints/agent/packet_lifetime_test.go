package agent

import (
	"bytes"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
	"github.com/OpenNHP/opennhp/nhp/log"
)

// TestTransactionCompletionCannotRecyclePacketWhileUDPSendIsBlocked fences
// the ownership boundary between core's local transaction and UdpAgent's
// physical sender. A transaction must retain its assembler packet for response
// decryption, while SendPacket needs independently owned wire bytes until the
// UDP write completes.
//
// The blocking logger is a deterministic seam immediately before net.Conn.Write:
// it holds SendPacket after it has accepted the packet but before the socket
// consumes pkt.Content. Completing the transaction in that window used to run
// MsgAssemblerData.Destroy on the SAME pooled Packet, nil pkt.Content, and make
// the pending UDP write send an empty datagram (as well as race under load).
func TestTransactionCompletionCannotRecyclePacketWhileUDPSendIsBlocked(t *testing.T) {
	logger := log.NewLogger("", log.LogLevelSilent, "", "")
	enteredSend := make(chan struct{})
	releaseSend := make(chan struct{})
	var enteredOnce, releaseOnce sync.Once
	logger.Info = func(format string, _ ...any) {
		if strings.HasPrefix(format, "Send [") {
			enteredOnce.Do(func() { close(enteredSend) })
			<-releaseSend
		}
	}
	previousLogger := log.SwapGlobalLogger(logger)
	t.Cleanup(func() {
		releaseOnce.Do(func() { close(releaseSend) })
		log.SwapGlobalLogger(previousLogger)
		logger.Close()
	})

	agentKey := make([]byte, core.PrivateKeySize)
	agentKey[0] = 1
	serverKey := make([]byte, core.PrivateKeySize)
	serverKey[0] = 2
	agentDevice := core.NewDevice(core.NHP_AGENT, agentKey, nil)
	if agentDevice == nil {
		t.Fatal("NewDevice(agent) returned nil")
	}
	serverECDH, err := core.ECDHFromKey(core.ECC_CURVE25519, serverKey)
	if err != nil {
		t.Fatalf("derive server public key: %v", err)
	}
	serverPublicKey := serverECDH.PublicKey()

	receiver, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	t.Cleanup(func() { _ = receiver.Close() })
	sender, err := net.DialUDP("udp4", nil, receiver.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("DialUDP: %v", err)
	}
	t.Cleanup(func() { _ = sender.Close() })

	connection := &core.ConnectionData{
		Device:               agentDevice,
		LocalAddr:            sender.LocalAddr().(*net.UDPAddr),
		RemoteAddr:           receiver.LocalAddr().(*net.UDPAddr),
		CookieStore:          &core.CookieStore{},
		SendQueue:            make(chan *core.Packet, 1),
		RecvQueue:            make(chan *core.Packet, 1),
		BlockSignal:          make(chan struct{}, 1),
		SetTimeoutSignal:     make(chan struct{}, 1),
		StopSignal:           make(chan struct{}),
		RemoteTransactionMap: make(map[uint64]*core.RemoteTransaction),
	}

	agentDevice.Start()
	t.Cleanup(agentDevice.Stop)
	t.Cleanup(connection.Close)

	const transactionID = uint64(0x7a11_51fe_c001_cafe)
	agentDevice.SendMsgToPacket(&core.MsgData{
		RemoteAddr:    connection.RemoteAddr,
		ConnData:      connection,
		CipherScheme:  common.CIPHER_SCHEME_CURVE,
		TransactionId: transactionID,
		HeaderType:    core.NHP_REG,
		Compress:      true,
		Message:       []byte(`{"usrId":"packet-owner","otp":"synthetic-test-only"}`),
		PeerPk:        serverPublicKey,
	})

	var wirePacket *core.Packet
	select {
	case wirePacket = <-connection.SendQueue:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for encrypted transaction packet")
	}
	if wirePacket == nil || wirePacket.Buf == nil || len(wirePacket.Content) == 0 {
		t.Fatalf("encrypted packet = %#v, want owned wire bytes", wirePacket)
	}
	if wirePacket.HeaderType != core.NHP_REG {
		t.Fatalf("HeaderType = %d, want NHP_REG", wirePacket.HeaderType)
	}
	if !wirePacket.PoolAllocated {
		t.Fatal("wire packet is not pool allocated")
	}
	wantWire := append([]byte(nil), wirePacket.Content...)

	type sendResult struct {
		n   int
		err error
	}
	sendResultCh := make(chan sendResult, 1)
	udpAgent := &UdpAgent{device: agentDevice}
	go func() {
		n, err := udpAgent.SendPacket(wirePacket, &UdpConn{ConnData: connection, netConn: sender})
		sendResultCh <- sendResult{n: n, err: err}
	}()

	select {
	case <-enteredSend:
	case <-time.After(2 * time.Second):
		// A send-log wording change must fail this structural seam instead of
		// letting the test pass without exercising the blocked-write window.
		t.Fatal("SendPacket did not reach the blocked pre-write seam")
	}

	transaction := agentDevice.FindLocalTransaction(transactionID)
	if transaction == nil {
		t.Fatal("local transaction disappeared before completion")
	}
	if err := transaction.SendExternalMsg(&core.PacketParserData{}); err != nil {
		t.Fatalf("complete local transaction: %v", err)
	}
	select {
	case <-transaction.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("local transaction did not finish")
	}
	if wirePacket.Buf == nil || !bytes.Equal(wirePacket.Content, wantWire) {
		t.Fatal("transaction completion recycled the packet while SendPacket still owned it")
	}

	releaseOnce.Do(func() { close(releaseSend) })
	select {
	case result := <-sendResultCh:
		if result.err != nil {
			t.Fatalf("SendPacket: %v", result.err)
		}
		if result.n != len(wantWire) {
			t.Fatalf("SendPacket wrote %d bytes, want %d", result.n, len(wantWire))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("SendPacket did not return after unblock")
	}
	if wirePacket.KeepAfterSend {
		t.Fatal("wire packet is still transaction-owned; sender needs an independent releasable packet")
	}
	if wirePacket.Buf != nil || wirePacket.Content != nil {
		t.Fatal("SendPacket did not release its independently owned pool packet")
	}

	if err := receiver.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	gotWire := make([]byte, core.PacketBufferSize)
	n, _, err := receiver.ReadFromUDP(gotWire)
	if err != nil {
		t.Fatalf("ReadFromUDP: %v", err)
	}
	if !bytes.Equal(gotWire[:n], wantWire) {
		t.Fatalf("UDP datagram changed while transaction completed: got %d bytes, want %d", n, len(wantWire))
	}
}
