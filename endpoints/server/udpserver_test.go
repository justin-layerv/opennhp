package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"

	"github.com/OpenNHP/opennhp/endpoints/metrics"
	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
)

const maxRelayEnvelopeBytes = 5844

func TestPacketFromUDPDatagramRelayEnvelopeBoundary(t *testing.T) {
	serverDev := newSpikeDevice(t, core.NHP_SERVER, 0x22, &core.DeviceOptions{DisableRelayPeerValidation: true})
	relayDev := newSpikeDevice(t, core.NHP_RELAY, 0x55, nil)
	serverPub := decodeBase64PubKey(serverDev.PublicKeyBase64())
	inner := make([]byte, core.PacketBufferSize)
	body, err := json.Marshal(&common.RelayForwardMsg{
		SourceAddr: &common.NetAddress{
			Ip:   "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
			Port: 65535,
		},
		InnerPacket: base64.StdEncoding.EncodeToString(inner),
		RequestID:   testRelayRequestID,
	})
	if err != nil {
		t.Fatal(err)
	}
	mad, err := relayDev.MsgToPacket(&core.MsgData{
		PeerPk:         serverPub,
		HeaderType:     core.NHP_RLY,
		TransactionId:  991122,
		Compress:       false,
		Message:        body,
		ExternalPacket: core.NewRelayPacket(),
	})
	if err != nil {
		t.Fatalf("encrypt maximum relay envelope: %v", err)
	}
	raw := append([]byte(nil), mad.BasePacket.Content...)
	if len(raw) != maxRelayEnvelopeBytes {
		t.Fatalf("maximum relay request = %d bytes, want %d", len(raw), maxRelayEnvelopeBytes)
	}

	receivedAtNanos := time.Now().UnixNano()
	pkt, clearType, err := packetFromUDPDatagram(serverDev, raw, receivedAtNanos)
	if err != nil {
		t.Fatalf("receive gate rejected maximum relay envelope: %v", err)
	}
	if clearType != core.NHP_RLY || pkt.Buf != nil || len(pkt.Content) != len(raw) {
		t.Fatalf("admitted packet = type %s, pool=%v, len=%d; want external NHP_RLY len %d", core.HeaderTypeToString(clearType), pkt.Buf != nil, len(pkt.Content), len(raw))
	}
	if pkt.ReceivedAtNanos != receivedAtNanos {
		t.Fatalf("relay receipt = %d, want %d", pkt.ReceivedAtNanos, receivedAtNanos)
	}
	ppd, err := serverDev.PacketToMsg(&core.PacketData{
		BasePacket: pkt,
		ConnData: &core.ConnectionData{
			Device: serverDev, RemoteAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 44444},
		},
		InitTime: pkt.ReceivedAtNanos,
	})
	if err != nil {
		t.Fatalf("decrypt admitted maximum relay envelope: %v", err)
	}
	if ppd.HeaderType != core.NHP_RLY || !bytes.Equal(ppd.BodyMessage, body) {
		t.Fatal("maximum relay envelope changed across the receive gate")
	}

	oversizedDirect := append([]byte(nil), raw[:core.PacketBufferSize+1]...)
	preamble := binary.BigEndian.Uint32(oversizedDirect[:4])
	_, payloadSize := (&core.Packet{Content: oversizedDirect}).HeaderTypeAndSize()
	binary.BigEndian.PutUint32(oversizedDirect[4:8], preamble^uint32(core.NHP_KNK<<16|payloadSize))
	if pkt, gotType, gateErr := packetFromUDPDatagram(serverDev, oversizedDirect, receivedAtNanos); gateErr == nil || pkt != nil || gotType != core.NHP_KNK {
		t.Fatalf("4097-byte direct gate = pkt %#v, type %s, err %v; want pre-crypto rejection", pkt, core.HeaderTypeToString(gotType), gateErr)
	}

	aboveTransport := make([]byte, core.RelayPacketBufferSize+1)
	copy(aboveTransport, raw)
	if pkt, gotType, gateErr := packetFromUDPDatagram(serverDev, aboveTransport, receivedAtNanos); gateErr == nil || pkt != nil || gotType != core.NHP_RLY {
		t.Fatalf("6145-byte relay gate = pkt %#v, type %s, err %v; want observable transport rejection", pkt, core.HeaderTypeToString(gotType), gateErr)
	}
	if pkt, _, gateErr := packetFromUDPDatagram(serverDev, raw, 0); gateErr == nil || pkt != nil {
		t.Fatalf("missing receipt gate = pkt %#v, err %v; want rejection", pkt, gateErr)
	}
}

func BenchmarkPacketFromUDPDatagram(b *testing.B) {
	device := core.NewDevice(core.NHP_SERVER, testPrivateKey(), nil)
	if device == nil {
		b.Fatal("create server device")
	}

	benchmarks := []struct {
		name       string
		headerType int
		size       int
		wantError  bool
	}{
		// These measure admission/copy only, not Noise decryption. Direct
		// datagrams take the <=PacketBufferSize fast path; relay also includes
		// oversized-envelope length validation. maxRelayEnvelopeBytes is pinned by
		// TestPacketFromUDPDatagramRelayEnvelopeBoundary; core.RelayPacketBufferSize
		// defines the containing relay pool's ceiling.
		{name: "direct-512", headerType: core.NHP_KNK, size: 512},
		{name: "direct-pool-ceiling", headerType: core.NHP_KNK, size: core.PacketBufferSize},
		{name: fmt.Sprintf("relay-%d", maxRelayEnvelopeBytes), headerType: core.NHP_RLY, size: maxRelayEnvelopeBytes},
		// Oversized-direct formats the rejected header name; over-limit exits
		// before that formatting, so their allocation profiles intentionally differ.
		{name: "reject-direct-oversized", headerType: core.NHP_KNK, size: core.PacketBufferSize + 1, wantError: true},
		{name: "reject-relay-over-limit", headerType: core.NHP_RLY, size: core.RelayPacketBufferSize + 1, wantError: true},
	}
	for _, benchmark := range benchmarks {
		b.Run(benchmark.name, func(b *testing.B) {
			// Reused across iterations: packetFromUDPDatagram must only read raw
			// and copy admitted bytes into packet-pool storage.
			raw := make([]byte, benchmark.size)
			header := (&core.Packet{Content: raw}).Header()
			header.SetTypeAndPayloadSize(benchmark.headerType, benchmark.size-header.Size())
			b.ReportAllocs()
			if !benchmark.wantError {
				b.SetBytes(int64(benchmark.size))
			}
			for b.Loop() {
				pkt, gotType, err := packetFromUDPDatagram(device, raw, 1)
				// Rejections deliberately retain the parsed clear-header type; pin that
				// observability contract alongside their error and nil-packet result.
				if gotType != benchmark.headerType {
					b.Fatalf("header type = %s, want %s", core.HeaderTypeToString(gotType), core.HeaderTypeToString(benchmark.headerType))
				}
				if benchmark.wantError {
					if err == nil || pkt != nil {
						b.Fatalf("reject %s datagram = packet %v, error %v", benchmark.name, pkt != nil, err)
					}
					continue
				}
				if err != nil {
					b.Fatalf("admit %s datagram: %v", benchmark.name, err)
				}
				device.ReleasePoolPacket(pkt)
			}
		})
	}
}

func TestPacketFromUDPDatagramPreservesDirectReceipt(t *testing.T) {
	device := core.NewDevice(core.NHP_SERVER, testPrivateKey(), nil)
	if device == nil {
		t.Fatal("create server device")
	}
	raw := make([]byte, core.PacketBufferSize)
	header := (&core.Packet{Content: raw}).Header()
	header.SetTypeAndPayloadSize(core.NHP_KNK, len(raw)-header.Size())
	const receivedAtNanos = int64(123456789)

	pkt, clearType, err := packetFromUDPDatagram(device, raw, receivedAtNanos)
	if err != nil {
		t.Fatalf("packetFromUDPDatagram: %v", err)
	}
	defer device.ReleasePoolPacket(pkt)
	if clearType != core.NHP_KNK || pkt.ReceivedAtNanos != receivedAtNanos {
		t.Fatalf("direct packet type=%s receipt=%d, want NHP_KNK and %d", core.HeaderTypeToString(clearType), pkt.ReceivedAtNanos, receivedAtNanos)
	}
}

func TestRecvPacketRoutineKeepaliveMaintainsExistingTupleOnly(t *testing.T) {
	serverListen, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP server: %v", err)
	}
	remote, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		_ = serverListen.Close()
		t.Fatalf("ListenUDP remote: %v", err)
	}

	server := newTestUdpServer(t)
	server.listenConn = serverListen
	server.listenAddr = serverListen.LocalAddr().(*net.UDPAddr)
	server.listenAddrStr = server.listenAddr.String()
	server.signals.stop = make(chan struct{})
	cacheCh := make(chan *preCheckThreatCache, 1)
	server.observePreCheckThreatCache = func(cache *preCheckThreatCache) { cacheCh <- cache }
	server.wg.Add(1)
	go server.recvPacketRoutine()
	var threats *preCheckThreatCache
	select {
	case threats = <-cacheCh:
	case <-time.After(time.Second):
		t.Fatal("receive routine did not expose its precheck cache")
	}
	t.Cleanup(func() {
		close(server.signals.stop)
		_ = serverListen.Close()
		_ = remote.Close()
		server.wg.Wait()
	})

	write := func(wire []byte) {
		t.Helper()
		if _, err := remote.WriteToUDP(wire, server.listenAddr); err != nil {
			t.Fatalf("WriteToUDP: %v", err)
		}
	}
	remoteAddr := remote.LocalAddr().(*net.UDPAddr)
	remoteIP := remoteAddr.IP.String()
	if got := threats.Increment(remoteIP); got != 1 {
		t.Fatalf("seed precheck threat count = %d, want 1", got)
	}
	if got := threats.Increment(remoteIP); got != 2 {
		t.Fatalf("seed precheck threat count = %d, want 2", got)
	}
	kpl := make([]byte, core.RelayPacketMinimalLength)

	// A valid KPL from an unknown tuple is structurally accepted but cannot
	// establish server connection state.
	write(kpl)
	waitFor(t, time.Second, "unknown KPL read", func() bool {
		return atomic.LoadUint64(&server.stats.totalRecvBytes) >= uint64(len(kpl))
	})
	server.remoteConnectionMapMutex.Lock()
	_, found := server.remoteConnectionMap[remoteAddr.String()]
	server.remoteConnectionMapMutex.Unlock()
	if found {
		t.Fatal("unknown unauthenticated KPL created a UDP connection")
	}
	if got, ok := threats.Count(remoteIP); !ok || got != 2 {
		t.Fatalf("unknown KPL precheck threat count = %d, present=%v; want unchanged 2", got, ok)
	}

	// Once the same tuple is established by authenticated traffic, KPL may
	// maintain it. The receive timestamp and queued packet are both observable
	// before the connection routine consumes the keepalive.
	recvQueue := make(chan *core.Packet, 1)
	conn := &UdpConn{
		evictSignal: make(chan struct{}),
		ConnData: &core.ConnectionData{
			Device:           server.device,
			RemoteAddr:       remoteAddr,
			RecvQueue:        recvQueue,
			SendQueue:        make(chan *core.Packet, 1),
			StopSignal:       make(chan struct{}),
			BlockSignal:      make(chan struct{}),
			SetTimeoutSignal: make(chan struct{}, 1),
		},
	}
	atomic.StoreInt64(&conn.ConnData.LastLocalRecvTime, 1)
	server.remoteConnectionMapMutex.Lock()
	server.remoteConnectionMap[remoteAddr.String()] = conn
	server.remoteConnectionMapMutex.Unlock()

	write(kpl)
	waitFor(t, time.Second, "known KPL refresh", func() bool {
		return atomic.LoadInt64(&conn.ConnData.LastLocalRecvTime) > 1
	})
	select {
	case pkt := <-recvQueue:
		if pkt.HeaderType != core.NHP_KPL {
			t.Fatalf("queued type = %s, want NHP_KPL", core.HeaderTypeToString(pkt.HeaderType))
		}
		server.device.ReleasePoolPacket(pkt)
	case <-time.After(time.Second):
		t.Fatal("known KPL was not forwarded to the existing connection")
	}
	if got, ok := threats.Count(remoteIP); !ok || got != 2 {
		t.Fatalf("known KPL precheck threat count = %d, present=%v; want unchanged 2", got, ok)
	}

	// Appendix A2.1 deliberately short-circuits KPL structural validation in
	// the current 1.1 parser, so this test does not invent a "malformed KPL"
	// shape. It pins only the real authority boundary: unknown tuples cannot be
	// created, while an existing tuple can be maintained without clearing its
	// source-IP threat history.
	server.remoteConnectionMapMutex.Lock()
	stored, found := server.remoteConnectionMap[remoteAddr.String()]
	mapLen := len(server.remoteConnectionMap)
	server.remoteConnectionMapMutex.Unlock()
	if !found || stored != conn || mapLen != 1 {
		t.Fatalf("known KPL changed connection map: found=%v stored=%p want=%p len=%d", found, stored, conn, mapLen)
	}
}

func TestPacketDataForInboundUsesEachPacketReceipt(t *testing.T) {
	connData := &core.ConnectionData{}
	first := &core.Packet{ReceivedAtNanos: 101}
	second := &core.Packet{ReceivedAtNanos: 202}
	atomic.StoreInt64(&connData.LastLocalRecvTime, 999)

	firstData := packetDataForInbound(connData, first)
	secondData := packetDataForInbound(connData, second)
	if firstData.InitTime != 101 || secondData.InitTime != 202 {
		t.Fatalf("packet receipts = (%d, %d), want (101, 202)", firstData.InitTime, secondData.InitTime)
	}
	if firstData.InitTime == atomic.LoadInt64(&connData.LastLocalRecvTime) {
		t.Fatal("first queued packet inherited mutable connection receipt time")
	}
}

func TestRegisterReceiveQueueMetricsRequiresInitializedDevice(t *testing.T) {
	server := &UdpServer{metrics: metrics.NewPublisherForTest(t)}
	if err := server.registerReceiveQueueMetrics(); err == nil {
		t.Fatal("registerReceiveQueueMetrics accepted a nil device")
	}

	server.device = core.NewDevice(
		core.NHP_SERVER,
		bytes.Repeat([]byte{0x5a}, core.PrivateKeySize),
		nil,
	)
	if server.device == nil {
		t.Fatal("NewDevice returned nil")
	}
	if err := server.registerReceiveQueueMetrics(); err != nil {
		t.Fatalf("registerReceiveQueueMetrics: %v", err)
	}

	for {
		pkt := server.device.AllocatePoolPacket()
		if pkt == nil {
			t.Fatal("AllocatePoolPacket returned nil")
		}
		if !server.device.RecvPacketToMsg(&core.PacketData{BasePacket: pkt}) {
			break
		}
	}

	gauges := server.metrics.GaugesForTest(t)
	if gauges[MetricPacketDecryptQueueDepth] <= 0 {
		t.Fatalf("%s = %v, want positive depth", MetricPacketDecryptQueueDepth, gauges[MetricPacketDecryptQueueDepth])
	}
	if gauges[MetricDecryptedMessageQueueDepth] != 0 {
		t.Fatalf("%s = %v, want 0", MetricDecryptedMessageQueueDepth, gauges[MetricDecryptedMessageQueueDepth])
	}
	counters, _ := server.metrics.CountersForTest(t)
	if counters[MetricPacketDecryptQueueDrop] != 1 {
		t.Fatalf("%s = %v, want 1", MetricPacketDecryptQueueDrop, counters[MetricPacketDecryptQueueDrop])
	}
}

func TestCombinedOverloadSourcesCannotClearEachOther(t *testing.T) {
	server := &UdpServer{device: core.NewDevice(
		core.NHP_SERVER,
		bytes.Repeat([]byte{0x6b}, core.PrivateKeySize),
		nil,
	)}
	if server.device == nil {
		t.Fatal("NewDevice returned nil")
	}

	server.setConnectionOverload(true)
	server.setHandlerOverload(true)
	server.setConnectionOverload(false)
	if !server.device.IsOverload() {
		t.Fatal("connection recovery cleared active handler pressure")
	}
	server.setHandlerOverload(false)
	if server.device.IsOverload() {
		t.Fatal("device remained overloaded after both sources recovered")
	}

	server.setConnectionOverload(true)
	server.setHandlerOverload(true)
	server.setHandlerOverload(false)
	if !server.device.IsOverload() {
		t.Fatal("handler recovery cleared active connection pressure")
	}
	server.setConnectionOverload(false)
	if server.device.IsOverload() {
		t.Fatal("device remained overloaded after reverse-order recovery")
	}
}

func TestHandlerOverloadRejectsStaleActivationAfterRecovery(t *testing.T) {
	server := &UdpServer{
		device: core.NewDevice(
			core.NHP_SERVER,
			bytes.Repeat([]byte{0x6c}, core.PrivateKeySize),
			nil,
		),
		handlerSem:          make(chan struct{}, 4),
		protectedHandlerSem: make(chan struct{}, 1),
	}
	if server.device == nil {
		t.Fatal("NewDevice returned nil")
	}

	for i := 0; i < cap(server.handlerSem); i++ {
		server.handlerSem <- struct{}{}
	}
	server.setHandlerOverload(true)
	if !server.device.IsOverload() {
		t.Fatal("full handler partition did not enable overload")
	}

	// Drain to the 75% recovery threshold and clear pressure as the final
	// releaser would. A shedder carrying an earlier full-partition decision
	// must re-check occupancy instead of re-enabling overload in a quiet window.
	<-server.handlerSem
	server.setHandlerOverload(false)
	server.setHandlerOverload(true)
	if server.handlerOverload.Load() || server.device.IsOverload() {
		t.Fatal("stale saturation decision re-enabled overload after recovery")
	}
}

func newSendMessageTestServer(t *testing.T, sendCh chan *core.MsgData) *UdpServer {
	t.Helper()
	server := newTestUdpServer(t)
	server.listenAddr = &net.UDPAddr{IP: net.ParseIP("10.0.0.10"), Port: common.DefaultNHPPort}
	server.listenAddrStr = "10.0.0.10:62206"
	server.sendMsgCh = sendCh
	server.signals.stop = make(chan struct{})
	t.Cleanup(func() {
		select {
		case <-server.signals.stop:
		default:
			close(server.signals.stop)
		}
		server.wg.Wait()
	})
	return server
}

func parsedIncomingKnockForSendMessageRoutineTest(t *testing.T, server *UdpServer, transactionID uint64) *core.PacketParserData {
	t.Helper()

	agentKey := testPrivateKey()
	agentKey[0] = 0x7f
	agentDevice := core.NewDevice(core.NHP_AGENT, agentKey, nil)
	if agentDevice == nil {
		t.Fatal("core.NewDevice(agent) returned nil")
	}
	server.device.AddPeer(&core.UdpPeer{
		PubKeyBase64: agentDevice.PublicKeyBase64(),
		Type:         core.NHP_AGENT,
	})
	serverPeer := &core.UdpPeer{
		PubKeyBase64: server.device.PublicKeyBase64(),
		Type:         core.NHP_SERVER,
	}
	agentConn := &core.ConnectionData{
		Device:      agentDevice,
		RemoteAddr:  &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: common.DefaultNHPPort},
		InitTime:    time.Now().UnixNano(),
		CookieStore: &core.CookieStore{},
	}
	mad, err := agentDevice.MsgToPacket(&core.MsgData{
		ConnData:      agentConn,
		PeerPk:        serverPeer.PublicKey(),
		HeaderType:    core.NHP_KNK,
		TransactionId: transactionID,
		Message:       []byte(`{"probe":true}`),
	})
	if err != nil {
		t.Fatalf("agent MsgToPacket: %v", err)
	}

	serverConn := &core.ConnectionData{
		Device:           server.device,
		LocalAddr:        server.listenAddr,
		RemoteAddr:       &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000},
		InitTime:         time.Now().UnixNano(),
		CookieStore:      &core.CookieStore{},
		SendQueue:        make(chan *core.Packet, 1),
		RecvQueue:        make(chan *core.Packet, 1),
		BlockSignal:      make(chan struct{}),
		StopSignal:       make(chan struct{}),
		SetTimeoutSignal: make(chan struct{}, 1),
	}
	ppd, err := server.device.PacketToMsg(&core.PacketData{
		BasePacket: &core.Packet{
			Content:    append([]byte(nil), mad.BasePacket.Content...),
			HeaderType: core.NHP_KNK,
		},
		ConnData: serverConn,
		InitTime: time.Now().UnixNano(),
	})
	if err != nil {
		t.Fatalf("server PacketToMsg: %v", err)
	}
	if ppd == nil || ppd.Error != nil {
		t.Fatalf("server PacketToMsg returned error parser data: %+v", ppd)
	}
	if ppd.SenderTrxId != transactionID {
		t.Fatalf("parsed SenderTrxId = %d, want %d", ppd.SenderTrxId, transactionID)
	}
	return ppd
}

func testServerPeerPk(seed byte) []byte {
	peerPk := make([]byte, core.PublicKeySize)
	for i := range peerPk {
		peerPk[i] = seed
	}
	return peerPk
}

func addServerPeerTarget(t *testing.T, server *UdpServer, remoteAddr *net.UDPAddr) []byte {
	t.Helper()
	peerPk := testServerPeerPk(byte(remoteAddr.Port))
	server.device.AddPeer(&core.UdpPeer{
		Ip:           remoteAddr.IP.String(),
		Port:         remoteAddr.Port,
		PubKeyBase64: base64.StdEncoding.EncodeToString(peerPk),
		Type:         core.NHP_SERVER,
	})
	return peerPk
}

func newForwardMsgData(remoteAddr *net.UDPAddr, transactionID uint64, peerPk []byte) *core.MsgData {
	return &core.MsgData{
		RemoteAddr:    remoteAddr,
		HeaderType:    core.NHP_FWD,
		CipherScheme:  common.CIPHER_SCHEME_CURVE,
		TransactionId: transactionID,
		PeerPk:        peerPk,
		Message:       []byte(`{"probe":true}`),
	}
}

func requireSendMessageFailure(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("SendMessage failure = nil, want error containing %q", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("SendMessage failure = %q, want containing %q", err, want)
	}
}

func TestSendMessageCreatesOutboundConnectionForRemoteAddr(t *testing.T) {
	sendCh := make(chan *core.MsgData, 1)
	server := newSendMessageTestServer(t, sendCh)
	remoteAddr := &net.UDPAddr{IP: net.ParseIP("10.0.1.50"), Port: common.DefaultNHPPort}
	peerPk := addServerPeerTarget(t, server, remoteAddr)
	md := newForwardMsgData(remoteAddr, 42, peerPk)

	if err := server.SendMessage(md); err != nil {
		t.Fatalf("SendMessage failed: %v", err)
	}

	select {
	case got := <-sendCh:
		if got != md {
			t.Fatalf("queued MsgData pointer = %p, want %p", got, md)
		}
		if got.ConnData == nil {
			t.Fatal("SendMessage queued outbound server message with nil ConnData")
		}
		if got.ConnData.RemoteAddr.String() != remoteAddr.String() {
			t.Fatalf("ConnData.RemoteAddr = %s, want %s", got.ConnData.RemoteAddr, remoteAddr)
		}
	case <-time.After(time.Second):
		t.Fatal("SendMessage did not queue outbound message")
	}

	server.remoteConnectionMapMutex.Lock()
	stored := server.remoteConnectionMap[remoteAddr.String()]
	server.remoteConnectionMapMutex.Unlock()
	if stored == nil {
		t.Fatalf("remoteConnectionMap missing outbound connection for %s", remoteAddr)
	}
	if stored.ConnData != md.ConnData {
		t.Fatal("remoteConnectionMap stored a different ConnData than the queued outbound message")
	}
	if !stored.isServerPeer {
		t.Fatal("outbound server-peer connection was not marked as trusted server peer")
	}
	if stored.perIPElem != nil {
		t.Fatal("server-peer connection should bypass agent per-IP eviction bucket")
	}
	if _, found := server.connectionsByIP[remoteAddr.IP.String()]; found {
		t.Fatal("server-peer connection leaked into connectionsByIP")
	}
}

func TestSendMessageRoutineAllowsPrevParserDataWithoutConnData(t *testing.T) {
	sendCh := make(chan *core.MsgData, 1)
	server := newSendMessageTestServer(t, sendCh)
	server.device.Start()
	ppd := parsedIncomingKnockForSendMessageRoutineTest(t, server, 42)

	done := make(chan struct{})
	server.wg.Add(1)
	go func() {
		server.sendMessageRoutine()
		close(done)
	}()

	sendCh <- &core.MsgData{
		HeaderType:     core.NHP_ACK,
		PrevParserData: ppd,
		Message:        []byte(`{"ok":true}`),
	}
	select {
	case pkt := <-ppd.ConnData.SendQueue:
		if pkt == nil {
			t.Fatal("sendMessageRoutine delivered nil packet")
		}
		defer server.device.ReleasePoolPacket(pkt)
		if pkt.Counter() != 42 {
			t.Fatalf("generic send packet counter = %d, want original transaction id 42", pkt.Counter())
		}
		if pkt.HeaderType != core.NHP_ACK {
			t.Fatalf("generic send packet HeaderType = %s, want NHP_ACK", core.HeaderTypeToString(pkt.HeaderType))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("sendMessageRoutine did not deliver nil-ConnData response through PrevParserData")
	}
	close(sendCh)

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("sendMessageRoutine did not exit after send channel close")
	}
}

func TestSendMessageOutboundConnectionRoutineWritesUDP(t *testing.T) {
	serverListen, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("ListenUDP server: %v", err)
	}
	remote, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		_ = serverListen.Close()
		t.Fatalf("ListenUDP remote: %v", err)
	}
	t.Cleanup(func() {
		_ = remote.Close()
		_ = serverListen.Close()
	})

	sendCh := make(chan *core.MsgData, 1)
	server := newSendMessageTestServer(t, sendCh)
	server.listenConn = serverListen
	server.listenAddr = serverListen.LocalAddr().(*net.UDPAddr)
	server.listenAddrStr = server.listenAddr.String()

	remoteAddr := remote.LocalAddr().(*net.UDPAddr)
	peerPk := addServerPeerTarget(t, server, remoteAddr)
	md := newForwardMsgData(remoteAddr, 42, peerPk)
	if err := server.SendMessage(md); err != nil {
		t.Fatalf("SendMessage failed: %v", err)
	}
	select {
	case <-sendCh:
	case <-time.After(time.Second):
		t.Fatal("SendMessage did not queue outbound message")
	}
	if md.ConnData == nil {
		t.Fatal("SendMessage did not attach ConnData")
	}

	payload := []byte("server-peer-routine-send")
	md.ConnData.ForwardOutboundPacket(&core.Packet{
		HeaderType: core.NHP_FWD,
		Content:    payload,
	})

	if err := remote.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 128)
	n, from, err := remote.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("remote did not receive packet from connectionRoutine: %v", err)
	}
	if got := string(buf[:n]); got != string(payload) {
		t.Fatalf("remote payload = %q, want %q", got, payload)
	}
	if from.String() != server.listenAddr.String() {
		t.Fatalf("remote saw sender %s, want server listen addr %s", from, server.listenAddr)
	}
}

func TestSendMessageReusesOutboundConnectionForRemoteAddr(t *testing.T) {
	sendCh := make(chan *core.MsgData, 2)
	server := newSendMessageTestServer(t, sendCh)
	remoteAddr := &net.UDPAddr{IP: net.ParseIP("10.0.1.50"), Port: common.DefaultNHPPort}
	peerPk := addServerPeerTarget(t, server, remoteAddr)
	first := newForwardMsgData(remoteAddr, 42, peerPk)
	second := newForwardMsgData(remoteAddr, 43, peerPk)

	if err := server.SendMessage(first); err != nil {
		t.Fatalf("first SendMessage failed: %v", err)
	}
	if err := server.SendMessage(second); err != nil {
		t.Fatalf("second SendMessage failed: %v", err)
	}

	var queued []*core.MsgData
	for len(queued) < 2 {
		select {
		case got := <-sendCh:
			queued = append(queued, got)
		case <-time.After(time.Second):
			t.Fatalf("queued %d messages, want 2", len(queued))
		}
	}
	if queued[0].ConnData == nil || queued[1].ConnData == nil {
		t.Fatalf("queued ConnData = (%v, %v), want both non-nil", queued[0].ConnData, queued[1].ConnData)
	}
	if queued[0].ConnData != queued[1].ConnData {
		t.Fatal("SendMessage created a new outbound ConnData instead of reusing the live connection")
	}
	server.remoteConnectionMapMutex.Lock()
	mapLen := len(server.remoteConnectionMap)
	stored := server.remoteConnectionMap[remoteAddr.String()]
	server.remoteConnectionMapMutex.Unlock()
	if mapLen != 1 {
		t.Fatalf("remoteConnectionMap len = %d, want 1", mapLen)
	}
	if stored == nil || stored.ConnData != first.ConnData {
		t.Fatal("remoteConnectionMap did not keep the reused outbound connection")
	}
}

func TestSendMessagePromotesInboundServerPeerConnectionForReciprocalForward(t *testing.T) {
	sendCh := make(chan *core.MsgData, 1)
	server := newSendMessageTestServer(t, sendCh)
	remoteAddr := &net.UDPAddr{IP: net.ParseIP("10.0.1.50"), Port: common.DefaultNHPPort}
	existing := &UdpConn{
		evictSignal: make(chan struct{}),
		ConnData: &core.ConnectionData{
			Device:               server.device,
			LocalAddr:            server.listenAddr,
			RemoteAddr:           remoteAddr,
			RemoteTransactionMap: make(map[uint64]*core.RemoteTransaction),
			SendQueue:            make(chan *core.Packet, PacketQueueSizePerConnection),
			RecvQueue:            make(chan *core.Packet, PacketQueueSizePerConnection),
			BlockSignal:          make(chan struct{}),
			SetTimeoutSignal:     make(chan struct{}, 1),
			StopSignal:           make(chan struct{}),
		},
	}
	existing.ConnData.InitTimeoutMs(DefaultAgentConnectionTimeoutMs)
	server.admitNewConnection(existing, remoteAddr.String())
	if existing.perIPElem == nil {
		t.Fatal("generic inbound conn was not inserted into the per-IP bucket")
	}

	peerPk := addServerPeerTarget(t, server, remoteAddr)
	md := newForwardMsgData(remoteAddr, 44, peerPk)
	if err := server.SendMessage(md); err != nil {
		t.Fatalf("SendMessage failed: %v", err)
	}

	select {
	case got := <-sendCh:
		if got != md {
			t.Fatalf("queued MsgData pointer = %p, want %p", got, md)
		}
	case <-time.After(time.Second):
		t.Fatal("SendMessage did not queue reciprocal forward")
	}
	if md.ConnData != existing.ConnData {
		t.Fatal("SendMessage did not reuse the inbound server-peer tuple")
	}
	if !existing.isServerPeer {
		t.Fatal("reciprocal forward did not promote tuple to server-peer")
	}
	if existing.perIPElem != nil {
		t.Fatal("promoted server-peer tuple remained in the per-IP bucket")
	}
	if _, found := server.connectionsByIP[remoteAddr.IP.String()]; found {
		t.Fatal("promoted server-peer tuple left an empty per-IP bucket behind")
	}
}

func TestSendMessageDropsOutboundForUnknownServerPeerTarget(t *testing.T) {
	sendCh := make(chan *core.MsgData, 1)
	server := newSendMessageTestServer(t, sendCh)
	remoteAddr := &net.UDPAddr{IP: net.ParseIP("10.0.1.50"), Port: common.DefaultNHPPort}
	existing := &UdpConn{
		evictSignal: make(chan struct{}),
		ConnData: &core.ConnectionData{
			Device:               server.device,
			LocalAddr:            server.listenAddr,
			RemoteAddr:           remoteAddr,
			RemoteTransactionMap: make(map[uint64]*core.RemoteTransaction),
			SendQueue:            make(chan *core.Packet, PacketQueueSizePerConnection),
			RecvQueue:            make(chan *core.Packet, PacketQueueSizePerConnection),
			BlockSignal:          make(chan struct{}),
			SetTimeoutSignal:     make(chan struct{}, 1),
			StopSignal:           make(chan struct{}),
		},
	}
	server.remoteConnectionMap[remoteAddr.String()] = existing

	md := newForwardMsgData(remoteAddr, 44, testServerPeerPk(0x44))
	err := server.SendMessage(md)

	select {
	case got := <-sendCh:
		t.Fatalf("queued MsgData %#v for unknown server peer target, want drop", got)
	default:
	}
	requireSendMessageFailure(t, err, "not a known server peer target")
	if md.ConnData != nil {
		t.Fatal("SendMessage attached ConnData for unknown server peer target")
	}
	if server.remoteConnectionMap[remoteAddr.String()] != existing {
		t.Fatal("SendMessage replaced the existing tuple owner")
	}
	counters, _ := server.metrics.CountersForTest(t)
	if got := counters[MetricServerForwardTargetDrop]; got != 1 {
		t.Fatalf("MetricServerForwardTargetDrop = %v, want 1", got)
	}
}

func TestSendMessageDropsOutboundWhenTupleOwnedByNonPromotableConn(t *testing.T) {
	sendCh := make(chan *core.MsgData, 1)
	server := newSendMessageTestServer(t, sendCh)
	remoteAddr := &net.UDPAddr{IP: net.ParseIP("10.0.1.50"), Port: common.DefaultNHPPort}
	existing := &UdpConn{
		isACConnection: true,
		evictSignal:    make(chan struct{}),
		ConnData: &core.ConnectionData{
			Device:               server.device,
			LocalAddr:            server.listenAddr,
			RemoteAddr:           remoteAddr,
			RemoteTransactionMap: make(map[uint64]*core.RemoteTransaction),
			SendQueue:            make(chan *core.Packet, PacketQueueSizePerConnection),
			RecvQueue:            make(chan *core.Packet, PacketQueueSizePerConnection),
			BlockSignal:          make(chan struct{}),
			SetTimeoutSignal:     make(chan struct{}, 1),
			StopSignal:           make(chan struct{}),
		},
	}
	server.remoteConnectionMap[remoteAddr.String()] = existing

	peerPk := addServerPeerTarget(t, server, remoteAddr)
	md := newForwardMsgData(remoteAddr, 45, peerPk)
	err := server.SendMessage(md)

	select {
	case got := <-sendCh:
		t.Fatalf("queued MsgData %#v for AC-owned tuple, want drop", got)
	default:
	}
	requireSendMessageFailure(t, err, "already owned by non-promotable connection")
	if md.ConnData != nil {
		t.Fatal("SendMessage attached ConnData from non-promotable tuple owner")
	}
	if server.remoteConnectionMap[remoteAddr.String()] != existing {
		t.Fatal("SendMessage replaced the non-promotable tuple owner")
	}
	counters, _ := server.metrics.CountersForTest(t)
	if got := counters[MetricServerForwardTargetDrop]; got != 1 {
		t.Fatalf("MetricServerForwardTargetDrop = %v, want 1", got)
	}
}

func TestSendMessageDropsOutboundConnectionAtGlobalCap(t *testing.T) {
	sendCh := make(chan *core.MsgData, 1)
	server := newSendMessageTestServer(t, sendCh)
	server.device.SetOverload(false)
	fillRemoteConnectionMap(server, MaxConcurrentConnection)

	remoteAddr := &net.UDPAddr{IP: net.ParseIP("10.0.1.50"), Port: common.DefaultNHPPort}
	peerPk := addServerPeerTarget(t, server, remoteAddr)
	md := newForwardMsgData(remoteAddr, 42, peerPk)
	err := server.SendMessage(md)

	select {
	case got := <-sendCh:
		t.Fatalf("queued MsgData %#v at global cap, want drop", got)
	default:
	}
	requireSendMessageFailure(t, err, "maximum concurrent connection cap reached")
	if md.ConnData != nil {
		t.Fatal("SendMessage attached ConnData at global cap, want nil/drop")
	}
	if !server.device.IsOverload() {
		t.Fatal("device overload flag was not set at global cap")
	}
	counters, _ := server.metrics.CountersForTest(t)
	if got := counters[MetricGlobalCapRejections]; got != 1 {
		t.Fatalf("MetricGlobalCapRejections = %v, want 1", got)
	}
}

func TestSendMessageDropsOutboundWhenServerStopping(t *testing.T) {
	sendCh := make(chan *core.MsgData, 1)
	server := newSendMessageTestServer(t, sendCh)
	close(server.signals.stop)

	remoteAddr := &net.UDPAddr{IP: net.ParseIP("10.0.1.50"), Port: common.DefaultNHPPort}
	peerPk := addServerPeerTarget(t, server, remoteAddr)
	md := newForwardMsgData(remoteAddr, 42, peerPk)
	err := server.SendMessage(md)

	select {
	case got := <-sendCh:
		t.Fatalf("queued MsgData %#v while server stopping, want drop", got)
	default:
	}
	requireSendMessageFailure(t, err, "server stopping")
	if !errors.Is(err, errOutboundServerStopping) {
		t.Fatalf("SendMessage error = %v, want errOutboundServerStopping", err)
	}
	if md.ConnData != nil {
		t.Fatal("SendMessage attached ConnData while server stopping, want nil/drop")
	}
	server.remoteConnectionMapMutex.Lock()
	_, found := server.remoteConnectionMap[remoteAddr.String()]
	server.remoteConnectionMapMutex.Unlock()
	if found {
		t.Fatal("server stopping path left synthetic outbound connection in remoteConnectionMap")
	}
}

// TestBuildServerMetricDimensions tests that buildServerMetricDimensions returns
// correct CloudWatch dimensions based on environment variables, including the
// default fallback values ("unknown" and "cell0") when env vars are unset.
func TestBuildServerMetricDimensions(t *testing.T) {
	t.Run("defaults when env vars unset", func(t *testing.T) {
		// Use t.Setenv for automatic cleanup and parallel safety.
		// Setting to "" is equivalent to unset for our logic (Getenv returns "" for both).
		t.Setenv("NHP_ENVIRONMENT", "")
		t.Setenv("NHP_CELL_ID", "")

		dims := buildServerMetricDimensions()

		if len(dims) != 2 {
			t.Fatalf("Expected 2 dimensions, got %d", len(dims))
		}

		if *dims[0].Name != "Environment" || *dims[0].Value != "unknown" {
			t.Errorf("Expected Environment=unknown, got %s=%s", *dims[0].Name, *dims[0].Value)
		}
		if *dims[1].Name != "Cell" || *dims[1].Value != "cell0" {
			t.Errorf("Expected Cell=cell0, got %s=%s", *dims[1].Name, *dims[1].Value)
		}
	})

	t.Run("custom values from env vars", func(t *testing.T) {
		t.Setenv("NHP_ENVIRONMENT", "sandbox")
		t.Setenv("NHP_CELL_ID", "cell3")

		dims := buildServerMetricDimensions()

		if len(dims) != 2 {
			t.Fatalf("Expected 2 dimensions, got %d", len(dims))
		}

		if *dims[0].Name != "Environment" || *dims[0].Value != "sandbox" {
			t.Errorf("Expected Environment=sandbox, got %s=%s", *dims[0].Name, *dims[0].Value)
		}
		if *dims[1].Name != "Cell" || *dims[1].Value != "cell3" {
			t.Errorf("Expected Cell=cell3, got %s=%s", *dims[1].Name, *dims[1].Value)
		}
	})

	t.Run("partial env vars", func(t *testing.T) {
		t.Setenv("NHP_ENVIRONMENT", "production")
		t.Setenv("NHP_CELL_ID", "")

		dims := buildServerMetricDimensions()

		if *dims[0].Value != "production" {
			t.Errorf("Expected Environment=production, got %s", *dims[0].Value)
		}
		if *dims[1].Value != "cell0" {
			t.Errorf("Expected Cell=cell0 (default), got %s", *dims[1].Value)
		}
	})
}

func TestFindACConnectionsForResource_ReturnsResolvedACConn(t *testing.T) {
	wantConn := &ACConn{
		ACId:     "ac-a",
		ConnData: &core.ConnectionData{LastLocalRecvTime: time.Now().UnixNano()},
	}
	s := &UdpServer{
		metrics: metrics.NewPublisherForTest(t),
		acConnectionMap: map[string][]*ACConn{
			"ac-a": {wantConn},
		},
	}
	res := &common.ResourceData{
		ResourceGroup: common.ResourceGroup{
			ResourceId: "qurl-tunnel-server",
			Resources: map[string]*common.ResourceInfo{
				"qurl-tunnel-server": {ACId: "ac-a"},
			},
		},
	}

	got := s.FindACConnectionsForResource(&common.AgentKnockMsg{
		AuthServiceId: "agent",
		ResourceId:    "qurl-tunnel-server",
	}, res)
	if len(got) != 1 || got[0] != wantConn {
		t.Fatalf("FindACConnectionsForResource returned %+v, want selected AC conn %+v", got, wantConn)
	}
}

func TestFindACConnectionsForResource_NilResourceReturnsNil(t *testing.T) {
	s := &UdpServer{
		metrics: metrics.NewPublisherForTest(t),
		acConnectionMap: map[string][]*ACConn{
			"ac-a": {{ACId: "ac-a", ConnData: &core.ConnectionData{LastLocalRecvTime: time.Now().UnixNano()}}},
		},
	}

	got := s.FindACConnectionsForResource(&common.AgentKnockMsg{
		AuthServiceId: "agent",
		ResourceId:    "qurl-tunnel-server",
	}, nil)
	if got != nil {
		t.Fatalf("FindACConnectionsForResource with nil resource returned %+v, want nil", got)
	}
}

func TestFindACConnectionsForResource_MultiEntryResourceReturnsNil(t *testing.T) {
	s := &UdpServer{
		metrics: metrics.NewPublisherForTest(t),
		acConnectionMap: map[string][]*ACConn{
			"ac-a": {{ACId: "ac-a", ConnData: &core.ConnectionData{LastLocalRecvTime: time.Now().UnixNano()}}},
			"ac-b": {{ACId: "ac-b", ConnData: &core.ConnectionData{LastLocalRecvTime: time.Now().UnixNano()}}},
		},
	}
	res := &common.ResourceData{
		ResourceGroup: common.ResourceGroup{
			ResourceId: "multi-entry",
			Resources: map[string]*common.ResourceInfo{
				"entry-a": {ACId: "ac-a"},
				"entry-b": {ACId: "ac-b"},
			},
		},
	}

	got := s.FindACConnectionsForResource(&common.AgentKnockMsg{
		AuthServiceId: "agent",
		ResourceId:    "multi-entry",
	}, res)
	if got != nil {
		t.Fatalf("FindACConnectionsForResource with multi-entry resource returned %+v, want nil", got)
	}
}

// testPrivateKey returns a valid 32-byte private key for testing.
func testPrivateKey() []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	return key
}

// TestRunRegisterWithRetry_FirstCallSucceeds fences the happy path:
// a single successful register call returns immediately with no
// MetricCloudMapRegisterFailure increment.
func TestRunRegisterWithRetry_FirstCallSucceeds(t *testing.T) {
	mp := metrics.NewPublisherForTest(t)
	device := core.NewDevice(core.NHP_SERVER, testPrivateKey(), nil)
	if device == nil {
		t.Fatal("NewDevice returned nil")
	}
	defer device.Stop()
	s := &UdpServer{metrics: mp, device: device}

	calls := 0
	register := func() error {
		calls++
		return nil
	}
	if err := s.runRegisterWithRetry(register, 3, time.Millisecond); err != nil {
		t.Fatalf("runRegisterWithRetry() error = %v", err)
	}

	if calls != 1 {
		t.Errorf("expected 1 register call, got %d", calls)
	}
	counters, _ := mp.CountersForTest(t)
	if counters[MetricCloudMapRegisterFailure] != 0 {
		t.Errorf("expected no failure metric on first-call success, got %v", counters[MetricCloudMapRegisterFailure])
	}
}

// TestRunRegisterWithRetry_RetriesThenSucceeds fences the transient-hiccup
// recovery path: register errors twice then succeeds on attempt 3 — exactly
// the prod scenario that #1681 was vulnerable to. No failure metric should
// fire because the budget didn't exhaust.
func TestRunRegisterWithRetry_RetriesThenSucceeds(t *testing.T) {
	mp := metrics.NewPublisherForTest(t)
	device := core.NewDevice(core.NHP_SERVER, testPrivateKey(), nil)
	if device == nil {
		t.Fatal("NewDevice returned nil")
	}
	defer device.Stop()
	s := &UdpServer{metrics: mp, device: device}

	calls := 0
	register := func() error {
		calls++
		if calls < 3 {
			return fmt.Errorf("transient failure %d", calls)
		}
		return nil
	}
	if err := s.runRegisterWithRetry(register, 3, time.Millisecond); err != nil {
		t.Fatalf("runRegisterWithRetry() error = %v", err)
	}

	if calls != 3 {
		t.Errorf("expected 3 register calls (2 fail + 1 success), got %d", calls)
	}
	counters, _ := mp.CountersForTest(t)
	if counters[MetricCloudMapRegisterFailure] != 0 {
		t.Errorf("expected no failure metric when budget didn't exhaust, got %v", counters[MetricCloudMapRegisterFailure])
	}
}

// TestRunRegisterWithRetry_ExhaustsBudget fences the fail-closed path: every
// attempt fails. The failure metric must increment exactly once and Start's
// caller must receive the terminal error; an undiscoverable server must not
// admit session-control work.
func TestRunRegisterWithRetry_ExhaustsBudget(t *testing.T) {
	mp := metrics.NewPublisherForTest(t)
	device := core.NewDevice(core.NHP_SERVER, testPrivateKey(), nil)
	if device == nil {
		t.Fatal("NewDevice returned nil")
	}
	defer device.Stop()
	s := &UdpServer{metrics: mp, device: device}

	calls := 0
	register := func() error {
		calls++
		return errors.New("Cloud Map down")
	}
	if err := s.runRegisterWithRetry(register, 3, time.Millisecond); err == nil {
		t.Fatal("runRegisterWithRetry() error = nil, want exhausted registration failure")
	}

	if calls != 3 {
		t.Errorf("expected 3 register calls (full budget), got %d", calls)
	}
	counters, _ := mp.CountersForTest(t)
	if counters[MetricCloudMapRegisterFailure] != 1 {
		t.Errorf("expected MetricCloudMapRegisterFailure=1 on exhaustion, got %v", counters[MetricCloudMapRegisterFailure])
	}
}

// TestCloudMapRegisterRefreshRoutine_ExitsOnStop fences the shutdown path:
// the refresh goroutine must return promptly when s.signals.stop is closed,
// even mid-tick. Without this, server shutdown would be blocked on the
// 5-minute ticker for any AC currently in the refresh loop.
func TestCloudMapRegisterRefreshRoutine_ExitsOnStop(t *testing.T) {
	s := &UdpServer{}
	s.signals.stop = make(chan struct{})
	close(s.signals.stop) // pre-close so the routine exits on first iteration

	s.wg.Add(1)
	done := make(chan struct{})
	go func() {
		s.cloudMapRegisterRefreshRoutine()
		close(done)
	}()

	select {
	case <-done:
		// expected
	case <-time.After(time.Second):
		t.Fatal("cloudMapRegisterRefreshRoutine did not exit within 1s after stop closed")
	}
	s.wg.Wait()
}

// TestRunRefreshLoop_TickEmitsMetrics fences the refresh goroutine's per-tick
// behavior: a successful register call increments
// MetricCloudMapRegisterRefresh; a failing call increments
// MetricCloudMapRegisterRefreshFailure (without exiting the loop). Without
// this fence a regression in the per-tick handling would only be visible in
// CloudWatch — the heartbeat alarm would catch it eventually but not at
// review time.
func TestRunRefreshLoop_TickEmitsMetrics(t *testing.T) {
	mp := metrics.NewPublisherForTest(t)
	s := &UdpServer{metrics: mp}
	s.signals.stop = make(chan struct{})
	s.running.Store(true) // simulate post-Start state so tick handler doesn't early-return

	tickCh := make(chan time.Time, 2)
	var calls int32
	register := func() error {
		n := atomic.AddInt32(&calls, 1)
		if n == 2 {
			return errors.New("simulated Cloud Map RegisterInstance failure")
		}
		return nil
	}

	s.wg.Add(1)
	done := make(chan struct{})
	go func() {
		s.runRefreshLoop(tickCh, register)
		close(done)
	}()

	tickCh <- time.Now() // success tick
	tickCh <- time.Now() // failure tick

	// Wait for both ticks to be drained. The select's ordering is
	// nondeterministic, but with 2 ticks queued and stop still open, the
	// loop drains both before it can pick stop. Poll the call count to
	// avoid sleeping past tick processing.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&calls) >= 2 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("expected 2 register calls, got %d", got)
	}

	close(s.signals.stop)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("runRefreshLoop did not exit within 1s after stop closed")
	}
	s.wg.Wait()

	counters, _ := mp.CountersForTest(t)
	if counters[MetricCloudMapRegisterRefresh] != 1 {
		t.Errorf("expected MetricCloudMapRegisterRefresh=1, got %v", counters[MetricCloudMapRegisterRefresh])
	}
	if counters[MetricCloudMapRegisterRefreshFailure] != 1 {
		t.Errorf("expected MetricCloudMapRegisterRefreshFailure=1, got %v", counters[MetricCloudMapRegisterRefreshFailure])
	}
}

// TestRunRefreshLoop_SkipsWhenNotRunning fences the Stop()-race guard: a
// tick that lands after s.running has been set to false (Stop has begun
// but stop channel not yet closed) must NOT call the registrar — that
// would re-assert the registration after Stop's DeregisterInstance,
// negating the "deregister before terminating" guarantee.
func TestRunRefreshLoop_SkipsWhenNotRunning(t *testing.T) {
	mp := metrics.NewPublisherForTest(t)
	s := &UdpServer{metrics: mp}
	s.signals.stop = make(chan struct{})
	// running is false (zero value); represents post-Stop, pre-stop-close window

	tickCh := make(chan time.Time, 1)
	var calls int32
	register := func() error {
		atomic.AddInt32(&calls, 1)
		return nil
	}

	s.wg.Add(1)
	done := make(chan struct{})
	go func() {
		s.runRefreshLoop(tickCh, register)
		close(done)
	}()

	tickCh <- time.Now()

	select {
	case <-done:
		// Expected: tick handler sees !s.running and returns
	case <-time.After(time.Second):
		t.Fatal("runRefreshLoop did not exit within 1s after tick with running=false")
	}
	s.wg.Wait()

	if got := atomic.LoadInt32(&calls); got != 0 {
		t.Errorf("expected 0 register calls when running=false, got %d", got)
	}
	counters, _ := mp.CountersForTest(t)
	if counters[MetricCloudMapRegisterRefresh] != 0 {
		t.Errorf("expected no refresh metric when running=false, got %v", counters[MetricCloudMapRegisterRefresh])
	}
}

// TestInstanceIdentityAccessors_NoDataRace fences the cr round-3 fix for the
// data race on s.instanceID/instanceAZ/asgName: refresh-time IMDS re-fetch
// is concurrent with packet-handler reads of these fields. Without the
// instanceIdentityMu, `go test -race` flags this; with it, the test is a
// quiet pass (and would catch a future change that drops the lock).
func TestInstanceIdentityAccessors_NoDataRace(t *testing.T) {
	s := &UdpServer{}
	stop := make(chan struct{})
	var readers, writers sync.WaitGroup

	// 4 reader goroutines hammer the getters (the same pattern used by
	// every NHP_AAK on the AAK handler path).
	for i := 0; i < 4; i++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_ = s.InstanceID()
					_ = s.InstanceAZ()
					_ = s.ASGName()
					_, _, _ = s.snapshotInstanceIdentity()
				}
			}
		}()
	}

	// 1 writer goroutine simulates fetchInstanceIdentityFromIMDS by taking
	// the write lock and updating all three fields together.
	writers.Add(1)
	go func() {
		defer writers.Done()
		for i := 0; i < 200; i++ {
			s.instanceIdentityMu.Lock()
			s.instanceID = fmt.Sprintf("i-%016x", i)
			s.instanceAZ = "us-east-2a"
			s.asgName = "layerv-nhp-test-server"
			s.instanceIdentityMu.Unlock()
		}
	}()

	writers.Wait()
	close(stop)
	readers.Wait()
}

// This is critical for cloud mode where ac.toml is not loaded and updateACPeers
// is never called, leaving acPeerMap nil.
func TestAddACPeer_NilMap(t *testing.T) {
	// Create a minimal UdpServer with nil acPeerMap (simulates cloud mode startup)
	device := core.NewDevice(core.NHP_SERVER, testPrivateKey(), nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}
	defer device.Stop()

	s := &UdpServer{
		device: device,
		// acPeerMap intentionally NOT initialized - this is the bug we're testing
	}

	// Create a mock AC peer
	acPeer := &core.UdpPeer{
		Ip:           "10.0.0.100",
		Port:         common.DefaultNHPPort,
		PubKeyBase64: "dGVzdHB1YmtleQ==", // "testpubkey" base64
		ExpireTime:   common.FarFutureExpiry,
	}
	acPeer.Type = core.NHP_AC

	// This should NOT panic - the fix initializes the map if nil
	s.AddACPeer(acPeer)

	// Verify the peer was added
	if s.acPeerMap == nil {
		t.Fatal("acPeerMap should be initialized after AddACPeer")
	}

	if len(s.acPeerMap) != 1 {
		t.Errorf("Expected 1 peer in acPeerMap, got %d", len(s.acPeerMap))
	}

	// Verify the peer is accessible by public key
	if _, exists := s.acPeerMap[acPeer.PublicKeyBase64()]; !exists {
		t.Error("Peer not found in acPeerMap by public key")
	}
}

// TestAddAgentPeer_NilMap fences the cloud-mode crash where the
// first knock-driven resolveAgentPeerForKnock calls AddAgentPeer
// before agentPeerMap is ever initialized (no etc/agent.toml in
// cloud mode = updateAgentPeers never runs). Mirrors
// TestAddACPeer_NilMap; without the lazy-init in AddAgentPeer
// this panics with "assignment to entry in nil map" on the first
// fresh-agent knock and the ASG hot-loops on restarts.
func TestAddAgentPeer_NilMap(t *testing.T) {
	device := core.NewDevice(core.NHP_SERVER, testPrivateKey(), nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}
	defer device.Stop()

	s := &UdpServer{
		device: device,
		// agentPeerMap intentionally NOT initialized - this is the bug we're testing
	}

	agent := &core.UdpPeer{
		PubKeyBase64: "YWdlbnRwdWJrZXk=", // "agentpubkey"
		ExpireTime:   common.FarFutureExpiry,
	}
	agent.Type = core.NHP_AGENT

	// This should NOT panic - the fix initializes the map if nil.
	// First insertion: should return true (newly added).
	if added := s.AddAgentPeer(agent); !added {
		t.Error("AddAgentPeer returned false on first insertion; expected true (newly added)")
	}

	if s.agentPeerMap == nil {
		t.Fatal("agentPeerMap should be initialized after AddAgentPeer")
	}
	if len(s.agentPeerMap) != 1 {
		t.Errorf("Expected 1 peer in agentPeerMap, got %d", len(s.agentPeerMap))
	}
	if _, exists := s.agentPeerMap[agent.PublicKeyBase64()]; !exists {
		t.Error("Peer not found in agentPeerMap by public key")
	}

	// Second insertion of the same pubkey: must return false. This is
	// the load-bearing assertion for MetricAgentFirstResolve single-counting
	// under singleflight piggyback (see AddAgentPeer godoc + the gating
	// in resolveAgentPeerForKnock). Without this signal, N concurrent
	// piggybackers all increment the resolve counter for one logical
	// first-resolve.
	if added := s.AddAgentPeer(agent); added {
		t.Error("AddAgentPeer returned true on second insertion of same pubkey; expected false (already present)")
	}

	// Sanity: map still has exactly one entry.
	if len(s.agentPeerMap) != 1 {
		t.Errorf("after re-insert: len(agentPeerMap)=%d want 1 (must not duplicate)", len(s.agentPeerMap))
	}
}

// TestAgentPeerMap_ReadersDoNotRaceWithAdds fences the unlocked-
// read regression on agentPeerMap. Historically agentPeerMap was
// populated once at boot from agent.toml and was effectively
// immutable; UpdateTee* / GetTee* read it without taking
// agentPeerMapMutex. With knock-driven AddAgentPeer inserting
// concurrently in cloud mode, those readers race under `-race`.
// lookupAgentPeer centralizes the read under the mutex; this test
// exercises both readers and AddAgentPeer concurrently to catch a
// future regression that removes the lock.
//
// Must be run with `-race`. Race-detector clean = pass; data race
// = fail with "DATA RACE" output. The functional assertions (no
// panic, return shapes correct) backstop a future case where the
// race-detector is off.
func TestAgentPeerMap_ReadersDoNotRaceWithAdds(t *testing.T) {
	device := core.NewDevice(core.NHP_SERVER, testPrivateKey(), &core.DeviceOptions{
		DisableAgentPeerValidation: true,
	})
	if device == nil {
		t.Fatal("Failed to create device")
	}
	defer device.Stop()

	s := &UdpServer{
		device:       device,
		agentPeerMap: map[string]*core.UdpPeer{},
	}

	// Pre-seed one peer so the GetTee/UpdateTee paths have something
	// to read even when the writer goroutines haven't run yet —
	// without it, the readers' empty-map fast-return short-circuits
	// before the locked Map access and the race condition the test
	// is fencing wouldn't be exercised on slow scheduler interleavings.
	seedPubkey := make([]byte, 32)
	for i := range seedPubkey {
		seedPubkey[i] = byte(i)
	}
	seedAgent := &core.UdpPeer{
		PubKeyBase64: base64.StdEncoding.EncodeToString(seedPubkey),
		Type:         core.NHP_AGENT,
		ExpireTime:   common.FarFutureExpiry,
	}
	if added := s.AddAgentPeer(seedAgent); !added {
		t.Fatalf("seed AddAgentPeer returned false; expected true")
	}

	const writers = 8
	const readers = 8
	const iterations = 200

	var wg sync.WaitGroup
	wg.Add(writers + readers*2)

	// Writers: insert N distinct fresh pubkeys.
	for w := 0; w < writers; w++ {
		go func(idx int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				pk := make([]byte, 32)
				pk[0] = byte(idx + 1)
				pk[1] = byte(i)
				agent := &core.UdpPeer{
					PubKeyBase64: base64.StdEncoding.EncodeToString(pk),
					Type:         core.NHP_AGENT,
					ExpireTime:   common.FarFutureExpiry,
				}
				s.AddAgentPeer(agent)
			}
		}(w)
	}

	// Readers: race UpdateTee and GetTee on the seed pubkey
	// against the writers' inserts.
	for r := 0; r < readers; r++ {
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				s.UpdateTeePublicKeyAndConsumerEphemeralPublicKey(
					"tee-pub", "consumer-eph", seedPubkey)
			}
		}()
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				_, _ = s.GetTeePublicKeyBase64AndConsumerEphemeralPublicKeyBase64(seedPubkey)
			}
		}()
	}

	wg.Wait()

	// Functional sanity: the seed peer has the values UpdateTee set
	// (last writer wins; "tee-pub" / "consumer-eph" since all
	// writers set the same value).
	teePub, consumerEph := s.GetTeePublicKeyBase64AndConsumerEphemeralPublicKeyBase64(seedPubkey)
	if teePub != "tee-pub" || consumerEph != "consumer-eph" {
		t.Errorf("post-race read: tee=%q consumer=%q want tee-pub/consumer-eph",
			teePub, consumerEph)
	}
}

// TestAddAgentPeer_QueryAndCacheShapeDoesNotPromoteToPeerGroup
// fences the implicit PeerGroup-avoidance invariant from the
// AgentPeerLookup godoc: peers built by queryAndCache have empty
// Ip/Port/Hostname, so two distinct queryAndCache-shape peers with
// the same pubkey land on udpPeersShareAddress(empty, empty)==true
// and device.AddPeer takes the overwrite branch instead of
// promoting to a PeerGroup.
//
// A future change populating Ip/Port at construct time would break
// the invariant silently — the package godoc warns about this but
// nothing fences it at PR time. This test converts that implicit
// contract into a regression fence. Round-16 review item 3.
func TestAddAgentPeer_QueryAndCacheShapeDoesNotPromoteToPeerGroup(t *testing.T) {
	device := core.NewDevice(core.NHP_SERVER, testPrivateKey(), &core.DeviceOptions{
		DisableAgentPeerValidation: true,
	})
	if device == nil {
		t.Fatal("Failed to create device")
	}
	defer device.Stop()

	rawPubkey := make([]byte, 32)
	for i := range rawPubkey {
		rawPubkey[i] = byte(0x40 + i)
	}
	pubKeyB64 := base64.StdEncoding.EncodeToString(rawPubkey)

	// Two queryAndCache-shape peers: same pubkey, empty addressing.
	// Distinct pointers — what singleflight would protect against in
	// production. Here we exercise the AddPeer path directly to
	// fence the udpPeersShareAddress equality even without
	// singleflight.
	first := &core.UdpPeer{PubKeyBase64: pubKeyB64, Type: core.NHP_AGENT}
	second := &core.UdpPeer{PubKeyBase64: pubKeyB64, Type: core.NHP_AGENT}

	device.AddPeer(first)
	device.AddPeer(second)

	got := device.LookupPeer(rawPubkey)
	if got == nil {
		t.Fatal("LookupPeer returned nil after two AddPeer calls")
	}
	if _, ok := got.(*core.PeerGroup); ok {
		t.Errorf("LookupPeer returned *core.PeerGroup; want *core.UdpPeer " +
			"(queryAndCache peers have empty Ip/Port/Hostname so " +
			"udpPeersShareAddress should be true and AddPeer should take " +
			"the overwrite branch — see AgentPeerLookup godoc)")
	}
	if _, ok := got.(*core.UdpPeer); !ok {
		t.Errorf("LookupPeer returned %T; want *core.UdpPeer", got)
	}
}

// TestAddACPeer_ExistingMap tests that AddACPeer works correctly when map is already initialized.
func TestAddACPeer_ExistingMap(t *testing.T) {
	device := core.NewDevice(core.NHP_SERVER, testPrivateKey(), nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}
	defer device.Stop()

	s := &UdpServer{
		device:    device,
		acPeerMap: make(map[string]*core.UdpPeer),
	}

	// Add first peer
	peer1 := &core.UdpPeer{
		Ip:           "10.0.0.1",
		Port:         common.DefaultNHPPort,
		PubKeyBase64: "cGVlcjE=", // "peer1"
		ExpireTime:   common.FarFutureExpiry,
	}
	peer1.Type = core.NHP_AC
	s.AddACPeer(peer1)

	// Add second peer
	peer2 := &core.UdpPeer{
		Ip:           "10.0.0.2",
		Port:         common.DefaultNHPPort,
		PubKeyBase64: "cGVlcjI=", // "peer2"
		ExpireTime:   common.FarFutureExpiry,
	}
	peer2.Type = core.NHP_AC
	s.AddACPeer(peer2)

	// Verify both peers are in the map
	if len(s.acPeerMap) != 2 {
		t.Errorf("Expected 2 peers in acPeerMap, got %d", len(s.acPeerMap))
	}
}

// TestAddACPeer_NonACPeer tests that non-AC peers are not added to acPeerMap.
func TestAddACPeer_NonACPeer(t *testing.T) {
	device := core.NewDevice(core.NHP_SERVER, testPrivateKey(), nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}
	defer device.Stop()

	s := &UdpServer{
		device:    device,
		acPeerMap: make(map[string]*core.UdpPeer),
	}

	// Create a peer with wrong type (not NHP_AC)
	peer := &core.UdpPeer{
		Ip:           "10.0.0.1",
		Port:         common.DefaultNHPPort,
		PubKeyBase64: "bm90YWM=", // "notac"
		ExpireTime:   common.FarFutureExpiry,
	}
	peer.Type = core.NHP_AGENT // Not an AC

	s.AddACPeer(peer)

	// Verify peer was NOT added (wrong type)
	if len(s.acPeerMap) != 0 {
		t.Errorf("Expected 0 peers in acPeerMap for non-AC peer, got %d", len(s.acPeerMap))
	}
}

// TestCloudModePeer_RecvAddrInitialized tests that a peer created in cloud mode
// has its recvAddr properly initialized after UpdateRecv is called.
// This is critical because in cloud mode, peer validation is disabled
// (DisableACPeerValidation=true), so responder.go skips the UpdateRecv call.
// The fix in HandleACOnline must call UpdateRecv explicitly.
func TestCloudModePeer_RecvAddrInitialized(t *testing.T) {
	// Simulate cloud mode peer creation (as done in msghandler.go HandleACOnline)
	acPeer := &core.UdpPeer{
		Hostname:     "test-ac",
		Ip:           "10.0.0.100",
		Port:         common.DefaultNHPPort,
		PubKeyBase64: "dGVzdHB1YmtleQ==",
		ExpireTime:   0,
	}
	acPeer.Type = core.NHP_AC

	// Before UpdateRecv, recvAddr.String() returns "<nil>" (the bug we're fixing)
	// Note: RecvAddr() returns net.Addr interface which is not nil even when
	// the underlying *net.UDPAddr is nil (Go interface semantics)
	if acPeer.RecvAddr().String() != "<nil>" {
		t.Errorf("Expected recvAddr.String() to be '<nil>' before UpdateRecv, got '%s'", acPeer.RecvAddr().String())
	}

	// Simulate the fix: call UpdateRecv with the connection address
	remoteAddr := &net.UDPAddr{
		IP:   net.ParseIP("10.0.0.100"),
		Port: common.DefaultNHPPort,
	}
	acPeer.UpdateRecv(time.Now().UnixNano(), remoteAddr)

	// After UpdateRecv, recvAddr should have valid address
	if acPeer.RecvAddr().String() == "<nil>" {
		t.Fatal("Expected recvAddr to be set after UpdateRecv, still got '<nil>'")
	}

	// Verify the address matches
	if acPeer.RecvAddr().String() != "10.0.0.100:62206" {
		t.Errorf("Expected recvAddr to be '10.0.0.100:62206', got '%s'", acPeer.RecvAddr().String())
	}
}

// TestCloudModePeer_RecvAddrUsedInACConn tests that an ACConn created with a
// properly initialized peer can be used in processACOperation without nil address.
func TestCloudModePeer_RecvAddrUsedInACConn(t *testing.T) {
	device := core.NewDevice(core.NHP_SERVER, testPrivateKey(), nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}
	defer device.Stop()

	// Create peer as done in cloud mode
	acPeer := &core.UdpPeer{
		Hostname:     "test-ac",
		Ip:           "10.0.0.100",
		Port:         common.DefaultNHPPort,
		PubKeyBase64: "dGVzdHB1YmtleQ==",
		ExpireTime:   0,
	}
	acPeer.Type = core.NHP_AC

	// Initialize recvAddr (the fix)
	remoteAddr := &net.UDPAddr{
		IP:   net.ParseIP("10.0.0.100"),
		Port: common.DefaultNHPPort,
	}
	acPeer.UpdateRecv(time.Now().UnixNano(), remoteAddr)

	// Create ACConn as done in HandleACOnline
	acConn := &ACConn{
		ACPeer: acPeer,
		ACId:   "test-ac",
	}

	// This is the line that failed with nil in processACOperation
	acAddrStr := acConn.ACPeer.RecvAddr().String()

	if acAddrStr == "<nil>" {
		t.Error("ACConn.ACPeer.RecvAddr() returned <nil>, processACOperation would fail")
	}

	if acAddrStr != "10.0.0.100:62206" {
		t.Errorf("Expected address '10.0.0.100:62206', got '%s'", acAddrStr)
	}
}

// TestACConnectionCleanup_OnSamePubkeyReregistration tests that when an
// AC re-registers with the SAME pubkey from a different source port, the
// old stale connection is cleaned up. Pre-fix this test used different
// pubkeys and implicitly exercised the IP-keyed match; post-fix it uses
// shared pubkeys (testPubkeyB64(0x42)) so the assertion is specifically
// "pubkey-keyed match replaces in place + cleans up the old conn." The
// rename makes the keyed-on-pubkey invariant visible in the test name,
// not just the fixture.
func TestACConnectionCleanup_OnSamePubkeyReregistration(t *testing.T) {
	device := core.NewDevice(core.NHP_SERVER, testPrivateKey(), nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}
	defer device.Stop()

	s := &UdpServer{
		device:              device,
		acPeerMap:           make(map[string]*core.UdpPeer),
		acConnectionMap:     make(map[string][]*ACConn),
		remoteConnectionMap: make(map[string]*UdpConn),
	}

	acId := "test-ac"
	pubkey := testPubkeyB64(0x42)
	oldACConn := makeACConnFixture(pubkey, "10.0.0.100", 47051)
	newACConn := makeACConnFixture(pubkey, "10.0.0.100", 38229)
	oldAddr := oldACConn.ConnData.RemoteAddr.String()
	s.acConnectionMap[acId] = []*ACConn{oldACConn}
	s.remoteConnectionMap[oldAddr] = &UdpConn{ConnData: oldACConn.ConnData, isACConnection: true}

	// Drive the live helper so this test fences the production
	// admit path, not a hand-copy of it.
	s.acConnectionMapMutex.Lock()
	existingConns, _, staleConn := replaceOrAppendACConn(s.acConnectionMap[acId], newACConn)
	s.acConnectionMap[acId] = existingConns
	s.acConnectionMapMutex.Unlock()

	if staleConn != nil {
		s.remoteConnectionMapMutex.Lock()
		delete(s.remoteConnectionMap, staleConn.ConnData.RemoteAddr.String())
		s.remoteConnectionMapMutex.Unlock()
	}

	if _, exists := s.remoteConnectionMap[oldAddr]; exists {
		t.Error("old remoteConnectionMap entry should be cleaned up after re-registration")
	}
	conns := s.acConnectionMap[acId]
	if len(conns) != 1 {
		t.Fatalf("expected 1 AC connection after same-pubkey re-registration, got %d", len(conns))
	}
	if conns[0].ConnData.RemoteAddr.Port != 38229 {
		t.Errorf("expected new connection port 38229, got %d", conns[0].ConnData.RemoteAddr.Port)
	}
}

// TestACPeer_RecvAddrUpdatedOnReregistration tests that when an existing AC peer
// re-registers from a different source port, its RecvAddr is updated.
// This is critical because processACOperation uses ACPeer.RecvAddr() to send
// knock operations to the AC.
func TestACPeer_RecvAddrUpdatedOnReregistration(t *testing.T) {
	// Create peer as it would be created on first registration
	acPeer := &core.UdpPeer{
		Hostname:     "test-ac",
		Ip:           "10.0.0.100",
		Port:         47051, // Original port
		PubKeyBase64: "dGVzdHB1YmtleQ==",
		ExpireTime:   0,
	}
	acPeer.Type = core.NHP_AC

	// Initialize recvAddr with original address
	oldRemoteAddr := &net.UDPAddr{IP: net.ParseIP("10.0.0.100"), Port: 47051}
	acPeer.UpdateRecv(time.Now().UnixNano(), oldRemoteAddr)

	// Verify original address
	if acPeer.RecvAddr().String() != "10.0.0.100:47051" {
		t.Fatalf("Expected initial recvAddr '10.0.0.100:47051', got '%s'", acPeer.RecvAddr().String())
	}

	// Simulate re-registration from new port (as done in HandleACOnline fix)
	newRemoteAddr := &net.UDPAddr{IP: net.ParseIP("10.0.0.100"), Port: 38229}
	acPeer.UpdateRecv(time.Now().UnixNano(), newRemoteAddr)

	// Verify address is updated
	if acPeer.RecvAddr().String() != "10.0.0.100:38229" {
		t.Errorf("Expected updated recvAddr '10.0.0.100:38229', got '%s'", acPeer.RecvAddr().String())
	}
}

// TestACConnectionCleanup_SameConnection tests that cleanup doesn't happen
// when the AC sends NHP_AOL from the same connection (no port change).
func TestACConnectionCleanup_SameConnection(t *testing.T) {
	device := core.NewDevice(core.NHP_SERVER, testPrivateKey(), nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}
	defer device.Stop()

	s := &UdpServer{
		device:              device,
		acPeerMap:           make(map[string]*core.UdpPeer),
		acConnectionMap:     make(map[string][]*ACConn),
		remoteConnectionMap: make(map[string]*UdpConn),
	}

	acId := "test-ac"

	// Create connection
	remoteAddr := &net.UDPAddr{IP: net.ParseIP("10.0.0.100"), Port: 47051}
	connData := &core.ConnectionData{
		RemoteAddr: remoteAddr,
	}
	peer := &core.UdpPeer{
		Ip:           "10.0.0.100",
		Port:         47051,
		PubKeyBase64: "c2FtZXBlZXI=",
	}
	peer.Type = core.NHP_AC
	peer.UpdateRecv(time.Now().UnixNano(), remoteAddr)

	acConn := &ACConn{
		ConnData: connData,
		ACPeer:   peer,
		ACId:     acId,
	}
	udpConn := &UdpConn{
		ConnData:       connData,
		isACConnection: true,
	}

	// Store connection
	s.acConnectionMap[acId] = []*ACConn{acConn}
	s.remoteConnectionMap[remoteAddr.String()] = udpConn

	// Simulate re-registration from SAME connection (same IP, same port → update in-place, no stale conn)
	s.acConnectionMapMutex.Lock()
	existingConns := s.acConnectionMap[acId]
	var staleConn *ACConn
	for i, existing := range existingConns {
		if existing.ConnData.RemoteAddr.IP.Equal(connData.RemoteAddr.IP) {
			oldAddr := existing.ConnData.RemoteAddr.String()
			newAddr := connData.RemoteAddr.String()
			if oldAddr != newAddr {
				staleConn = existing
			}
			existingConns[i] = acConn
			break
		}
	}
	s.acConnectionMap[acId] = existingConns
	s.acConnectionMapMutex.Unlock()

	// Same address → no stale connection to clean up
	if staleConn != nil {
		t.Error("Same address should not produce a stale connection")
	}

	// Verify: connection should still exist in remoteConnectionMap
	if _, exists := s.remoteConnectionMap[remoteAddr.String()]; !exists {
		t.Error("Connection should NOT be removed when re-registering from same connection")
	}
}

// TestMultiACRegistration tests that multiple ACs with the same AC ID but
// different IPs are stored as separate entries (blue/green deployment).
func TestMultiACRegistration(t *testing.T) {
	device := core.NewDevice(core.NHP_SERVER, testPrivateKey(), nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}
	defer device.Stop()

	s := &UdpServer{
		device:              device,
		acPeerMap:           make(map[string]*core.UdpPeer),
		acConnectionMap:     make(map[string][]*ACConn),
		remoteConnectionMap: make(map[string]*UdpConn),
	}

	acId := "test-ac"

	// Register first AC instance (blue) from IP 10.0.0.1
	blueAddr := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 47051}
	blueConnData := &core.ConnectionData{RemoteAddr: blueAddr}
	bluePeer := &core.UdpPeer{Ip: "10.0.0.1", Port: 47051, PubKeyBase64: "Ymx1ZQ=="}
	bluePeer.Type = core.NHP_AC
	bluePeer.UpdateRecv(time.Now().UnixNano(), blueAddr)
	blueACConn := &ACConn{ConnData: blueConnData, ACPeer: bluePeer, ACId: acId}

	s.acConnectionMapMutex.Lock()
	s.acConnectionMap[acId] = append(s.acConnectionMap[acId], blueACConn)
	s.acConnectionMapMutex.Unlock()

	// Register second AC instance (green) from IP 10.0.0.2
	greenAddr := &net.UDPAddr{IP: net.ParseIP("10.0.0.2"), Port: 47051}
	greenConnData := &core.ConnectionData{RemoteAddr: greenAddr}
	greenPeer := &core.UdpPeer{Ip: "10.0.0.2", Port: 47051, PubKeyBase64: "Z3JlZW4="}
	greenPeer.Type = core.NHP_AC
	greenPeer.UpdateRecv(time.Now().UnixNano(), greenAddr)
	greenACConn := &ACConn{ConnData: greenConnData, ACPeer: greenPeer, ACId: acId}

	// Simulate the new registration logic: different IP → append
	s.acConnectionMapMutex.Lock()
	existingConns := s.acConnectionMap[acId]
	found := false
	for _, existing := range existingConns {
		if existing.ConnData.RemoteAddr.IP.Equal(greenConnData.RemoteAddr.IP) {
			found = true
			break
		}
	}
	if !found {
		existingConns = append(existingConns, greenACConn)
	}
	s.acConnectionMap[acId] = existingConns
	s.acConnectionMapMutex.Unlock()

	// Verify both connections are stored
	conns := s.acConnectionMap[acId]
	if len(conns) != 2 {
		t.Fatalf("Expected 2 AC connections for same AC ID (blue/green), got %d", len(conns))
	}

	// Verify they have different IPs
	ip1 := conns[0].ConnData.RemoteAddr.IP.String()
	ip2 := conns[1].ConnData.RemoteAddr.IP.String()
	if ip1 == ip2 {
		t.Errorf("Expected different IPs for blue/green, both are %s", ip1)
	}

	t.Logf("Multi-AC registration: blue=%s, green=%s", ip1, ip2)
}

// TestMultiACConnectionTimeout tests that connection timeout cleanup removes
// only the matching entry from the slice, not the entire AC ID key.
func TestMultiACConnectionTimeout(t *testing.T) {
	device := core.NewDevice(core.NHP_SERVER, testPrivateKey(), nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}
	defer device.Stop()

	s := &UdpServer{
		device:              device,
		acPeerMap:           make(map[string]*core.UdpPeer),
		acConnectionMap:     make(map[string][]*ACConn),
		remoteConnectionMap: make(map[string]*UdpConn),
	}

	acId := "test-ac"

	// Create two AC connections (blue and green)
	blueAddr := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 47051}
	blueConnData := &core.ConnectionData{RemoteAddr: blueAddr}
	blueACConn := &ACConn{ConnData: blueConnData, ACId: acId}

	greenAddr := &net.UDPAddr{IP: net.ParseIP("10.0.0.2"), Port: 47051}
	greenConnData := &core.ConnectionData{RemoteAddr: greenAddr}
	greenACConn := &ACConn{ConnData: greenConnData, ACId: acId}

	s.acConnectionMap[acId] = []*ACConn{blueACConn, greenACConn}

	// Simulate blue connection timing out (connectionRoutine cleanup)
	blueUdpConn := &UdpConn{ConnData: blueConnData, isACConnection: true}

	s.acConnectionMapMutex.Lock()
	for acIdKey, conns := range s.acConnectionMap {
		for i, acConn := range conns {
			if acConn.ConnData.Equal(blueUdpConn.ConnData) {
				s.acConnectionMap[acIdKey] = append(conns[:i], conns[i+1:]...)
				if len(s.acConnectionMap[acIdKey]) == 0 {
					delete(s.acConnectionMap, acIdKey)
				}
				break
			}
		}
	}
	s.acConnectionMapMutex.Unlock()

	// Verify: green connection should still be there
	conns, exists := s.acConnectionMap[acId]
	if !exists {
		t.Fatal("AC ID key should still exist after removing one of two connections")
	}
	if len(conns) != 1 {
		t.Fatalf("Expected 1 remaining connection, got %d", len(conns))
	}
	if !conns[0].ConnData.RemoteAddr.IP.Equal(net.ParseIP("10.0.0.2")) {
		t.Errorf("Expected green connection (10.0.0.2) to remain, got %s", conns[0].ConnData.RemoteAddr.IP)
	}
}

// TestMaxACConnsPerID tests that the cap on connections per AC ID works correctly.
func TestMaxACConnsPerID(t *testing.T) {
	device := core.NewDevice(core.NHP_SERVER, testPrivateKey(), nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}
	defer device.Stop()

	s := &UdpServer{
		device:              device,
		acPeerMap:           make(map[string]*core.UdpPeer),
		acConnectionMap:     make(map[string][]*ACConn),
		remoteConnectionMap: make(map[string]*UdpConn),
	}

	acId := "test-ac"
	const maxConns = 10

	// Register maxConns AC instances
	for i := 0; i < maxConns; i++ {
		addr := &net.UDPAddr{IP: net.ParseIP(fmt.Sprintf("10.0.0.%d", i+1)), Port: 47051}
		connData := &core.ConnectionData{RemoteAddr: addr}
		acConn := &ACConn{ConnData: connData, ACId: acId}
		s.acConnectionMap[acId] = append(s.acConnectionMap[acId], acConn)
	}

	if len(s.acConnectionMap[acId]) != maxConns {
		t.Fatalf("Expected %d connections, got %d", maxConns, len(s.acConnectionMap[acId]))
	}

	// Register one more (should evict oldest)
	newAddr := &net.UDPAddr{IP: net.ParseIP("10.0.1.1"), Port: 47051}
	newConnData := &core.ConnectionData{RemoteAddr: newAddr}
	newACConn := &ACConn{ConnData: newConnData, ACId: acId}

	existingConns := s.acConnectionMap[acId]
	if len(existingConns) >= maxConns {
		existingConns = existingConns[1:] // evict oldest
	}
	existingConns = append(existingConns, newACConn)
	s.acConnectionMap[acId] = existingConns

	// Verify count stays at max
	if len(s.acConnectionMap[acId]) != maxConns {
		t.Errorf("Expected %d connections after cap eviction, got %d", maxConns, len(s.acConnectionMap[acId]))
	}

	// Verify newest is the last entry
	lastConn := s.acConnectionMap[acId][maxConns-1]
	if !lastConn.ConnData.RemoteAddr.IP.Equal(net.ParseIP("10.0.1.1")) {
		t.Errorf("Expected newest connection (10.0.1.1) as last entry, got %s", lastConn.ConnData.RemoteAddr.IP)
	}
}

// TestMaxACConnsForAnyID tests the gauge helper that returns the max
// connection count across all AC IDs.
func TestMaxACConnsForAnyID(t *testing.T) {
	device := core.NewDevice(core.NHP_SERVER, testPrivateKey(), nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}
	defer device.Stop()

	s := &UdpServer{
		device:          device,
		acConnectionMap: make(map[string][]*ACConn),
	}

	// Empty map → 0
	if got := s.MaxACConnsForAnyID(); got != 0 {
		t.Errorf("empty map: expected 0, got %d", got)
	}

	// One AC ID with 1 connection
	s.acConnectionMap["ac-1"] = []*ACConn{{ACId: "ac-1"}}
	if got := s.MaxACConnsForAnyID(); got != 1 {
		t.Errorf("single conn: expected 1, got %d", got)
	}

	// Two AC IDs: ac-1 has 1, ac-2 has 3 → max is 3
	s.acConnectionMap["ac-2"] = []*ACConn{{ACId: "ac-2"}, {ACId: "ac-2"}, {ACId: "ac-2"}}
	if got := s.MaxACConnsForAnyID(); got != 3 {
		t.Errorf("multi-AC: expected 3, got %d", got)
	}
}

// TestTotalACConns tests the gauge helper that returns the total
// connection count across all AC IDs.
func TestTotalACConns(t *testing.T) {
	device := core.NewDevice(core.NHP_SERVER, testPrivateKey(), nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}
	defer device.Stop()

	s := &UdpServer{
		device:          device,
		acConnectionMap: make(map[string][]*ACConn),
	}

	// Empty map → 0
	if got := s.TotalACConns(); got != 0 {
		t.Errorf("empty map: expected 0, got %d", got)
	}

	// ac-1: 1 conn, ac-2: 2 conns → total 3
	s.acConnectionMap["ac-1"] = []*ACConn{{ACId: "ac-1"}}
	s.acConnectionMap["ac-2"] = []*ACConn{{ACId: "ac-2"}, {ACId: "ac-2"}}
	if got := s.TotalACConns(); got != 3 {
		t.Errorf("multi-AC: expected 3, got %d", got)
	}
}

// mockACResponder reads from sendMsgCh and sends mock AC responses.
// delay controls how long before responding; if nil error, sends a success ART response.
func mockACResponder(sendMsgCh <-chan *core.MsgData, delay time.Duration, respErr error) {
	go func() {
		for md := range sendMsgCh {
			go func(md *core.MsgData) {
				time.Sleep(delay)
				ppd := &core.PacketParserData{
					HeaderType: core.NHP_ART,
					Error:      respErr,
				}
				if respErr == nil {
					ppd.BodyMessage, ppd.Error = successARTBodyForAOP(md, 0)
				}
				md.ResponseMsgCh <- ppd
			}(md)
		}
	}()
}

// successARTBodyForAOP mirrors the AC's 1.2 requirement to echo the exact
// process-owner and numeric session carried by the authenticated AOP. A
// nonzero sessionOverride is reserved for mismatch-path tests.
func successARTBodyForAOP(md *core.MsgData, sessionOverride uint64) ([]byte, error) {
	var aop common.ServerACOpsMsg
	err := common.DecodeServerACOpsMsg(md.Message, &aop)
	if err != nil {
		return nil, err
	}
	sessionID := aop.SessionId
	if sessionOverride != 0 {
		sessionID = sessionOverride
	}
	return json.Marshal(&common.ACOpsResultMsg{
		SessionOwnerId: aop.SessionOwnerId,
		SessionId:      sessionID,
		ErrCode:        common.ErrSuccess.ErrorCode(),
	})
}

// newTestServerForBroadcast creates a minimal UdpServer suitable for
// processACOperation and processACOperationBroadcast tests.
func newTestServerForBroadcast(t *testing.T) (*UdpServer, chan *core.MsgData) {
	t.Helper()
	device := core.NewDevice(core.NHP_SERVER, testPrivateKey(), nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}
	t.Cleanup(func() { device.Stop() })

	sendCh := make(chan *core.MsgData, core.SendQueueSize)

	s := &UdpServer{
		device:                 device,
		sendMsgCh:              sendCh,
		acPeerMap:              make(map[string]*core.UdpPeer),
		acConnectionMap:        make(map[string][]*ACConn),
		remoteConnectionMap:    make(map[string]*UdpConn),
		srcIpAssociatedAddrMap: make(map[string][]*common.NetAddress),
	}
	s.running.Store(true)

	return s, sendCh
}

// newTestACConn creates a mock ACConn with a valid peer for testing.
// device is optional; if provided, ConnectionData.Close() won't panic on flush.
func newTestACConn(t *testing.T, ip string, port int, acId string, device ...*core.Device) *ACConn {
	t.Helper()
	addr := &net.UDPAddr{IP: net.ParseIP(ip), Port: port}
	peer := &core.UdpPeer{
		Ip:           ip,
		Port:         port,
		PubKeyBase64: "dGVzdHB1YmtleQ==", // "testpubkey" - not a valid curve point but valid base64
		ExpireTime:   common.FarFutureExpiry,
	}
	peer.Type = core.NHP_AC
	peer.UpdateRecv(time.Now().UnixNano(), addr)

	// Initialize all channels that ConnectionData.Close() needs to avoid nil-channel panics
	connData := &core.ConnectionData{
		RemoteAddr:       addr,
		StopSignal:       make(chan struct{}),
		SendQueue:        make(chan *core.Packet, 1),
		RecvQueue:        make(chan *core.Packet, 1),
		BlockSignal:      make(chan struct{}, 1),
		SetTimeoutSignal: make(chan struct{}, 1),
	}
	if len(device) > 0 && device[0] != nil {
		connData.Device = device[0]
	}

	return &ACConn{
		ConnData: connData,
		ACPeer:   peer,
		ACId:     acId,
	}
}

func reserveTestNHPSession(t *testing.T, s *UdpServer, knk *common.AgentKnockMsg, openTime uint32) {
	t.Helper()
	if s == nil || knk == nil {
		t.Fatal("test NHP session reservation requires a server and knock")
	}
	agentKey := bytes.Repeat([]byte{0x7a}, core.PublicKeySize)
	knk.NHPAgentPublicKey = base64.StdEncoding.EncodeToString(agentKey)
	expiresAt := knk.NHPSessionIssuedAt.Add(time.Duration(openTime) * time.Second)
	if err := s.sessionRegistry().reserveExact(agentKey, knk.NHPSessionId, knk.NHPSessionIssuedAt, expiresAt); err != nil {
		t.Fatalf("reserve test NHP session %d: %v", knk.NHPSessionId, err)
	}
}

// TestBroadcast_ReturnsOnFirstSuccess verifies that the broadcast returns
// immediately on the first AC success (low latency) while remaining goroutines
// continue in the background so all ACs still get the ipset pinhole.
func TestBroadcast_ReturnsOnFirstSuccess(t *testing.T) {
	s, sendCh := newTestServerForBroadcast(t)

	// Track how many AOP messages complete (one per goroutine)
	var aopCount atomic.Int32
	var allDone sync.WaitGroup
	allDone.Add(3)

	// Respond to all AOP messages with success, but at different speeds
	go func() {
		for md := range sendCh {
			go func(md *core.MsgData) {
				n := aopCount.Add(1)
				// Stagger responses: 0ms, 50ms, 100ms
				time.Sleep(time.Duration(n-1) * 50 * time.Millisecond)
				body, bodyErr := successARTBodyForAOP(md, 0)
				md.ResponseMsgCh <- &core.PacketParserData{
					HeaderType:  core.NHP_ART,
					BodyMessage: body,
					Error:       bodyErr,
				}
				allDone.Done()
			}(md)
		}
	}()

	conns := []*ACConn{
		newTestACConn(t, "10.0.0.1", 47051, "test-ac"),
		newTestACConn(t, "10.0.0.2", 47051, "test-ac"),
		newTestACConn(t, "10.0.0.3", 47051, "test-ac"),
	}

	knkMsg := &common.AgentKnockMsg{UserId: "test-user", NHPSessionId: 1, NHPSessionIssuedAt: time.Now()}
	reserveTestNHPSession(t, s, knkMsg, 60)
	srcAddr := &common.NetAddress{Ip: "192.168.1.100", Port: 443}
	dstAddrs := []*common.NetAddress{{Ip: "10.0.0.1", Port: 8080}}

	artMsg, err := s.processACOperationBroadcast(context.Background(), knkMsg, conns, srcAddr, dstAddrs, 60, nil)

	if err != nil {
		t.Fatalf("Expected success, got error: %v", err)
	}
	if artMsg == nil {
		t.Fatal("Expected non-nil artMsg")
	}
	if artMsg.ErrCode != common.ErrSuccess.ErrorCode() {
		t.Errorf("Expected success error code, got %s", artMsg.ErrCode)
	}

	// Wait for background goroutines to finish, then verify all 3 AOP messages completed
	allDone.Wait()
	if aopCount.Load() != 3 {
		t.Errorf("Expected all 3 AOP messages sent, got %d", aopCount.Load())
	}
}

// TestBroadcast_PartialFailureStillSucceeds verifies that when some ACs fail
// but at least one succeeds, the broadcast returns success and remaining
// goroutines complete in the background.
func TestBroadcast_PartialFailureStillSucceeds(t *testing.T) {
	s, sendCh := newTestServerForBroadcast(t)

	var aopCount atomic.Int32
	var allDone sync.WaitGroup
	allDone.Add(3)

	go func() {
		for md := range sendCh {
			go func(md *core.MsgData) {
				n := aopCount.Add(1)
				if n == 2 {
					// Second AC succeeds
					body, bodyErr := successARTBodyForAOP(md, 0)
					md.ResponseMsgCh <- &core.PacketParserData{
						HeaderType:  core.NHP_ART,
						BodyMessage: body,
						Error:       bodyErr,
					}
				} else {
					// Others fail
					md.ResponseMsgCh <- &core.PacketParserData{
						HeaderType: core.NHP_ART,
						Error:      common.ErrServerACOpsFailed,
					}
				}
				allDone.Done()
			}(md)
		}
	}()

	conns := []*ACConn{
		newTestACConn(t, "10.0.0.1", 47051, "test-ac"),
		newTestACConn(t, "10.0.0.2", 47051, "test-ac"),
		newTestACConn(t, "10.0.0.3", 47051, "test-ac"),
	}

	knkMsg := &common.AgentKnockMsg{UserId: "test-user", NHPSessionId: 1, NHPSessionIssuedAt: time.Now()}
	reserveTestNHPSession(t, s, knkMsg, 60)
	srcAddr := &common.NetAddress{Ip: "192.168.1.100", Port: 443}
	dstAddrs := []*common.NetAddress{{Ip: "10.0.0.1", Port: 8080}}

	artMsg, err := s.processACOperationBroadcast(context.Background(), knkMsg, conns, srcAddr, dstAddrs, 60, nil)

	if err != nil {
		t.Fatalf("Expected success (partial), got error: %v", err)
	}
	if artMsg == nil {
		t.Fatal("Expected non-nil artMsg")
	}
	// Wait for background goroutines, then verify all 3 were attempted
	allDone.Wait()
	if aopCount.Load() != 3 {
		t.Errorf("Expected all 3 AOP messages sent, got %d", aopCount.Load())
	}
}

// TestBroadcastCancellation_AllFail verifies that when all ACs fail,
// the broadcast returns the last error.
func TestBroadcastCancellation_AllFail(t *testing.T) {
	s, sendCh := newTestServerForBroadcast(t)

	// All ACs respond with errors (use generic error, not timeout,
	// to avoid triggering conn.Close() which needs a fully initialized Device)
	go func() {
		for md := range sendCh {
			go func(md *core.MsgData) {
				md.ResponseMsgCh <- &core.PacketParserData{
					HeaderType: core.NHP_ART,
					Error:      common.ErrServerACOpsFailed,
				}
			}(md)
		}
	}()

	conns := []*ACConn{
		newTestACConn(t, "10.0.0.1", 47051, "test-ac"),
		newTestACConn(t, "10.0.0.2", 47051, "test-ac"),
	}

	knkMsg := &common.AgentKnockMsg{UserId: "test-user", NHPSessionId: 1, NHPSessionIssuedAt: time.Now()}
	reserveTestNHPSession(t, s, knkMsg, 60)
	srcAddr := &common.NetAddress{Ip: "192.168.1.100", Port: 443}
	dstAddrs := []*common.NetAddress{{Ip: "10.0.0.1", Port: 8080}}

	_, err := s.processACOperationBroadcast(context.Background(), knkMsg, conns, srcAddr, dstAddrs, 60, nil)

	if err == nil {
		t.Fatal("Expected error when all ACs fail")
	}
}

// TestBroadcastCancellation_SingleConn verifies the single-connection
// optimization (no broadcast overhead).
func TestBroadcastCancellation_SingleConn(t *testing.T) {
	s, sendCh := newTestServerForBroadcast(t)
	mockACResponder(sendCh, 0, nil)

	conns := []*ACConn{
		newTestACConn(t, "10.0.0.1", 47051, "test-ac"),
	}

	knkMsg := &common.AgentKnockMsg{UserId: "test-user", NHPSessionId: 1, NHPSessionIssuedAt: time.Now()}
	reserveTestNHPSession(t, s, knkMsg, 60)
	srcAddr := &common.NetAddress{Ip: "192.168.1.100", Port: 443}
	dstAddrs := []*common.NetAddress{{Ip: "10.0.0.1", Port: 8080}}

	artMsg, err := s.processACOperationBroadcast(context.Background(), knkMsg, conns, srcAddr, dstAddrs, 60, nil)

	if err != nil {
		t.Fatalf("Expected success for single conn, got: %v", err)
	}
	if artMsg == nil {
		t.Fatal("Expected non-nil artMsg")
	}
}

// TestBroadcast_TimeoutReturnsFirstSuccess verifies that when some ACs hang
// beyond DefaultBroadcastTimeout, the broadcast still returns the first success
// and the background goroutine completes (does not leak).
func TestBroadcast_TimeoutReturnsFirstSuccess(t *testing.T) {
	s, sendCh := newTestServerForBroadcast(t)

	var allDone sync.WaitGroup
	allDone.Add(3)

	// AC 1 responds fast (success), AC 2 responds fast (success),
	// AC 3 never responds — its per-goroutine context.WithTimeout will fire.
	var respondCount atomic.Int32
	go func() {
		for md := range sendCh {
			go func(md *core.MsgData) {
				n := respondCount.Add(1)
				defer allDone.Done()
				if n <= 2 {
					// Respond immediately with success
					body, bodyErr := successARTBodyForAOP(md, 0)
					md.ResponseMsgCh <- &core.PacketParserData{
						HeaderType:  core.NHP_ART,
						BodyMessage: body,
						Error:       bodyErr,
					}
				}
				// n == 3: never respond — the goroutine's context timeout will
				// cause processACOperation to return an error. We just need to
				// wait for the channel to be consumed or closed.
				// Since we can't block forever in a test, simulate the timeout
				// by responding with an error after a short delay.
				if n == 3 {
					time.Sleep(200 * time.Millisecond)
					md.ResponseMsgCh <- &core.PacketParserData{
						HeaderType: core.NHP_ART,
						Error:      fmt.Errorf("simulated timeout"),
					}
				}
			}(md)
		}
	}()

	conns := []*ACConn{
		newTestACConn(t, "10.0.0.1", 47051, "test-ac"),
		newTestACConn(t, "10.0.0.2", 47051, "test-ac"),
		newTestACConn(t, "10.0.0.3", 47051, "test-ac"),
	}

	knkMsg := &common.AgentKnockMsg{UserId: "test-user", NHPSessionId: 1, NHPSessionIssuedAt: time.Now()}
	reserveTestNHPSession(t, s, knkMsg, 60)
	srcAddr := &common.NetAddress{Ip: "192.168.1.100", Port: 443}
	dstAddrs := []*common.NetAddress{{Ip: "10.0.0.1", Port: 8080}}

	artMsg, err := s.processACOperationBroadcast(context.Background(), knkMsg, conns, srcAddr, dstAddrs, 60, nil)

	if err != nil {
		t.Fatalf("Expected success (first AC responded), got error: %v", err)
	}
	if artMsg == nil {
		t.Fatal("Expected non-nil artMsg")
	}

	// Wait for all goroutines including the "timed out" one
	allDone.Wait()
	if respondCount.Load() != 3 {
		t.Errorf("Expected 3 responders, got %d", respondCount.Load())
	}
}

// TestBroadcast_ParentContextCancellationDoesNotAbort verifies the contract
// that processACOperationBroadcast uses context.WithoutCancel on the parent
// context so that broadcast goroutines continue even if the parent (e.g. HTTP
// request) context is canceled mid-flight. The parent's values (request ID)
// must still be preserved for log correlation.
func TestBroadcast_ParentContextCancellationDoesNotAbort(t *testing.T) {
	s, sendCh := newTestServerForBroadcast(t)

	var aopCount atomic.Int32
	var allDone sync.WaitGroup
	allDone.Add(3)

	// All ACs succeed immediately.
	go func() {
		for md := range sendCh {
			go func(md *core.MsgData) {
				defer allDone.Done()
				aopCount.Add(1)
				body, bodyErr := successARTBodyForAOP(md, 0)
				md.ResponseMsgCh <- &core.PacketParserData{
					HeaderType:  core.NHP_ART,
					BodyMessage: body,
					Error:       bodyErr,
				}
			}(md)
		}
	}()

	conns := []*ACConn{
		newTestACConn(t, "10.0.0.1", 47051, "test-ac"),
		newTestACConn(t, "10.0.0.2", 47051, "test-ac"),
		newTestACConn(t, "10.0.0.3", 47051, "test-ac"),
	}

	knkMsg := &common.AgentKnockMsg{UserId: "test-user", NHPSessionId: 1, NHPSessionIssuedAt: time.Now()}
	reserveTestNHPSession(t, s, knkMsg, 60)
	srcAddr := &common.NetAddress{Ip: "192.168.1.100", Port: 443}
	dstAddrs := []*common.NetAddress{{Ip: "10.0.0.1", Port: 8080}}

	// Build a parent context carrying a request ID, then cancel it before
	// invoking the broadcast. A naive context.WithTimeout(parentCtx, ...) would
	// inherit the cancellation and abort all goroutines immediately. With
	// context.WithoutCancel the broadcast must still run to completion.
	parentCtx, cancel := context.WithCancel(ContextWithRequestID(context.Background(), "req-broadcast-777"))
	cancel()

	artMsg, err := s.processACOperationBroadcast(parentCtx, knkMsg, conns, srcAddr, dstAddrs, 60, nil)
	if err != nil {
		t.Fatalf("broadcast must succeed even with canceled parent ctx, got err=%v", err)
	}
	if artMsg == nil {
		t.Fatal("expected non-nil artMsg from broadcast")
	}

	allDone.Wait()
	if aopCount.Load() != 3 {
		t.Errorf("expected all 3 ACs to complete, got %d", aopCount.Load())
	}
}

// TestProcessACOperation_ContextAlreadyCanceled verifies that
// processACOperation returns immediately when the context is already canceled.
func TestProcessACOperation_ContextAlreadyCanceled(t *testing.T) {
	s, sendCh := newTestServerForBroadcast(t)

	// Slow responder — should not matter since context is already canceled
	go func() {
		for md := range sendCh {
			go func(md *core.MsgData) {
				time.Sleep(10 * time.Second)
				md.ResponseMsgCh <- &core.PacketParserData{
					HeaderType: core.NHP_ART,
				}
			}(md)
		}
	}()

	conn := newTestACConn(t, "10.0.0.1", 47051, "test-ac")
	knkMsg := &common.AgentKnockMsg{UserId: "test-user", NHPSessionId: 1, NHPSessionIssuedAt: time.Now()}
	reserveTestNHPSession(t, s, knkMsg, 60)
	srcAddr := &common.NetAddress{Ip: "192.168.1.100", Port: 443}
	dstAddrs := []*common.NetAddress{{Ip: "10.0.0.1", Port: 8080}}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	start := time.Now()
	_, err := s.processACOperation(ctx, knkMsg, conn, srcAddr, dstAddrs, 60, nil)
	elapsed := time.Since(start)

	if !errors.Is(err, context.Canceled) {
		t.Errorf("Expected context.Canceled, got: %v", err)
	}

	if elapsed > 1*time.Second {
		t.Errorf("Should have returned immediately, took %v", elapsed)
	}
}

func TestProcessACOperation_RejectsMismatchedARTSessionID(t *testing.T) {
	s, sendCh := newTestServerForBroadcast(t)
	go func() {
		md := <-sendCh
		body, bodyErr := successARTBodyForAOP(md, 456)
		if bodyErr == nil {
			var art common.ACOpsResultMsg
			bodyErr = json.Unmarshal(body, &art)
			art.ACToken = "must-not-be-used"
			if bodyErr == nil {
				body, bodyErr = json.Marshal(&art)
			}
		}
		md.ResponseMsgCh <- &core.PacketParserData{HeaderType: core.NHP_ART, BodyMessage: body, Error: bodyErr}
	}()
	conn := newTestACConn(t, "10.0.0.1", 47051, "test-ac")
	knock := &common.AgentKnockMsg{UserId: "test-user", NHPSessionId: 123, NHPSessionIssuedAt: time.Now()}
	reserveTestNHPSession(t, s, knock, 60)
	result, err := s.processACOperation(context.Background(), knock, conn,
		&common.NetAddress{Ip: "192.168.1.100", Port: 443},
		[]*common.NetAddress{{Ip: "10.0.0.1", Port: 8080}}, 60, nil)
	if !errors.Is(err, common.ErrACOperationFailed) {
		t.Fatalf("mismatched ART error = %v, want ErrACOperationFailed", err)
	}
	if result == nil || result.ErrCode != common.ErrACOperationFailed.ErrorCode() || result.ACToken != "" {
		t.Fatalf("mismatched ART result = %+v, want fail-closed result without token", result)
	}
}

func TestProcessACOperation_RejectsMissingOrExpiredSessionBeforeSend(t *testing.T) {
	for name, knock := range map[string]*common.AgentKnockMsg{
		"zero session id":       {UserId: "test-user", NHPSessionIssuedAt: time.Now()},
		"missing issuance time": {UserId: "test-user", NHPSessionId: 123},
		"expired lifetime":      {UserId: "test-user", NHPSessionId: 123, NHPSessionIssuedAt: time.Now().Add(-time.Minute)},
	} {
		t.Run(name, func(t *testing.T) {
			s, sendCh := newTestServerForBroadcast(t)
			conn := newTestACConn(t, "10.0.0.1", 47051, "test-ac")
			result, err := s.processACOperation(context.Background(), knock, conn,
				&common.NetAddress{Ip: "192.168.1.100", Port: 443},
				[]*common.NetAddress{{Ip: "10.0.0.1", Port: 8080}}, 30, nil)
			if !errors.Is(err, common.ErrACOperationFailed) || result == nil || result.ErrCode != common.ErrACOperationFailed.ErrorCode() {
				t.Fatalf("invalid session result = %+v, %v; want fail closed", result, err)
			}
			select {
			case sent := <-sendCh:
				t.Fatalf("invalid session emitted AOP: %+v", sent)
			default:
			}
		})
	}
}

func TestProcessACOperation_RejectsNonCanonicalACIDBeforeAOP(t *testing.T) {
	for _, acID := range []string{"", "   ", " ac-a", "ac-a ", "ac\n-a", string([]byte{0xff})} {
		t.Run(fmt.Sprintf("%q", acID), func(t *testing.T) {
			s, sendCh := newTestServerForBroadcast(t)
			knock := &common.AgentKnockMsg{UserId: "test-user", NHPSessionId: 124, NHPSessionIssuedAt: time.Now()}
			result, err := s.processACOperation(context.Background(), knock, newTestACConn(t, "10.0.0.1", 47051, acID),
				&common.NetAddress{Ip: "192.168.1.100", Port: 443},
				[]*common.NetAddress{{Ip: "10.0.0.1", Port: 8080}}, 30, nil)
			if !errors.Is(err, common.ErrACOperationFailed) || result == nil || result.ErrCode != common.ErrACOperationFailed.ErrorCode() {
				t.Fatalf("non-canonical AC id result = %+v, %v; want fail closed", result, err)
			}
			select {
			case sent := <-sendCh:
				t.Fatalf("non-canonical AC id emitted AOP: %+v", sent)
			default:
			}
		})
	}
}

// TestDrainACConnections verifies that drainACConnections sends NHP_ARD to all
// connected ACs and uses fire-and-forget (no ResponseMsgCh). The drain ARD
// must carry a RedirectTarget that passes RedirectTarget.Validate(): IP
// populated (resolved from the NLB hostname), Port, and PubKeyBase64 all
// set. See #832 — the previous behavior emitted a hostname-only target,
// which downstream consumer code on the AC could not use.
func TestDrainACConnections(t *testing.T) {
	s, sendCh := newTestServerForBroadcast(t)

	// Inject a deterministic hostname resolver so the test doesn't depend on
	// real DNS for "test-nlb.example.com".
	prevLookup := hostLookup
	t.Cleanup(func() { hostLookup = prevLookup })
	hostLookup = func(host string) ([]string, error) {
		if host == "test-nlb.example.com" {
			return []string{"198.51.100.42"}, nil
		}
		return nil, fmt.Errorf("unexpected lookup: %s", host)
	}

	// Set NLB config
	s.config = &Config{
		Hostname:   "test-nlb.example.com",
		ListenPort: 62206,
	}

	// Add two AC connections
	ac1 := newTestACConn(t, "10.0.0.1", 47051, "ac-1")
	ac2 := newTestACConn(t, "10.0.0.2", 47051, "ac-2")
	s.acConnectionMap["ac-1"] = []*ACConn{ac1}
	s.acConnectionMap["ac-2"] = []*ACConn{ac2}

	// Run drain in background (it sleeps 100ms at the end)
	go s.drainACConnections()

	// Collect sent messages
	var msgs []*core.MsgData
	timeout := time.After(2 * time.Second)
	for i := 0; i < 2; i++ {
		select {
		case md := <-sendCh:
			msgs = append(msgs, md)
		case <-timeout:
			t.Fatalf("expected 2 drain messages, got %d", len(msgs))
		}
	}

	for _, md := range msgs {
		if md.HeaderType != core.NHP_ARD {
			t.Errorf("expected NHP_ARD header type, got %d", md.HeaderType)
		}
		if md.ResponseMsgCh != nil {
			t.Error("drain should be fire-and-forget (nil ResponseMsgCh)")
		}

		var ardMsg common.ACRedispatchMsg
		if err := json.Unmarshal(md.Message, &ardMsg); err != nil {
			t.Fatalf("failed to unmarshal ARD: %v", err)
		}
		if len(ardMsg.Targets) != 1 {
			t.Fatalf("expected 1 target, got %d", len(ardMsg.Targets))
		}
		target := ardMsg.Targets[0]
		if target.Hostname != "test-nlb.example.com" {
			t.Errorf("expected hostname test-nlb.example.com, got %s", target.Hostname)
		}
		if target.IP != "198.51.100.42" {
			t.Errorf("expected drain target IP 198.51.100.42 (resolved from NLB hostname), got %q", target.IP)
		}
		if target.Port != 62206 {
			t.Errorf("expected port 62206, got %d", target.Port)
		}
		if err := target.Validate(); err != nil {
			t.Errorf("drain target failed Validate(): %v", err)
		}
	}
}

// TestDrainACConnections_NoACs verifies that drainACConnections is a no-op
// when no ACs are connected.
func TestDrainACConnections_NoACs(t *testing.T) {
	s, sendCh := newTestServerForBroadcast(t)
	s.config = &Config{
		Hostname:   "test-nlb.example.com",
		ListenPort: 62206,
	}

	// No ACs connected — drain should return immediately
	done := make(chan struct{})
	go func() {
		s.drainACConnections()
		close(done)
	}()

	select {
	case <-done:
		// good — returned quickly
	case <-time.After(1 * time.Second):
		t.Fatal("drainACConnections should return immediately with no ACs")
	}

	// Verify nothing was sent
	select {
	case md := <-sendCh:
		t.Fatalf("unexpected message sent: %+v", md)
	default:
		// good
	}
}

// TestUdpServer_DrainARD_PopulatesIP is the unit-level regression for #832.
// It exercises buildDrainRedirectTarget directly to prove the drain code
// path now emits a RedirectTarget that passes Validate() — i.e. IP is set
// from DNS resolution, not left empty with only Hostname as a hint.
func TestUdpServer_DrainARD_PopulatesIP(t *testing.T) {
	prevLookup := hostLookup
	t.Cleanup(func() { hostLookup = prevLookup })
	hostLookup = func(host string) ([]string, error) {
		if host == "nlb.example.com" {
			return []string{"203.0.113.10"}, nil
		}
		return nil, fmt.Errorf("unexpected lookup: %s", host)
	}

	target, err := buildDrainRedirectTarget("nlb.example.com", 62206, "c2hhcmVkLWtleQ==")
	if err != nil {
		t.Fatalf("buildDrainRedirectTarget failed: %v", err)
	}
	if target.IP != "203.0.113.10" {
		t.Errorf("Target.IP = %q, want %q (#832: IP must be populated)", target.IP, "203.0.113.10")
	}
	if target.Hostname != "nlb.example.com" {
		t.Errorf("Target.Hostname = %q, want %q", target.Hostname, "nlb.example.com")
	}
	if target.Port != 62206 {
		t.Errorf("Target.Port = %d, want 62206", target.Port)
	}
	if target.PubKeyBase64 == "" {
		t.Error("Target.PubKeyBase64 should be set")
	}
	if err := target.Validate(); err != nil {
		t.Errorf("drain target failed Validate(): %v", err)
	}
}

// TestUdpServer_DrainARD_ResolverFailure verifies the drain returns an error
// when DNS resolution fails, so the caller can skip the drain entirely
// rather than emitting an invalid target.
func TestUdpServer_DrainARD_ResolverFailure(t *testing.T) {
	prevLookup := hostLookup
	t.Cleanup(func() { hostLookup = prevLookup })
	hostLookup = func(host string) ([]string, error) {
		return nil, fmt.Errorf("no such host: %s", host)
	}

	_, err := buildDrainRedirectTarget("nlb.example.com", 62206, "c2hhcmVkLWtleQ==")
	if err == nil {
		t.Fatal("expected resolver failure to return error")
	}
	if !strings.Contains(err.Error(), "nlb.example.com") {
		t.Errorf("expected error to mention hostname, got: %v", err)
	}
}

// TestUdpServer_DrainARD_EmptyHostname verifies that an empty hostname is
// rejected at the helper level rather than producing a bogus target.
func TestUdpServer_DrainARD_EmptyHostname(t *testing.T) {
	_, err := buildDrainRedirectTarget("", 62206, "c2hhcmVkLWtleQ==")
	if err == nil {
		t.Fatal("expected empty hostname to return error")
	}
}

// TestUdpServer_DrainARD_EmptyResolverResult verifies that a resolver that
// returns an empty slice with no error is still treated as a failure.
func TestUdpServer_DrainARD_EmptyResolverResult(t *testing.T) {
	prevLookup := hostLookup
	t.Cleanup(func() { hostLookup = prevLookup })
	hostLookup = func(host string) ([]string, error) {
		return []string{}, nil
	}

	_, err := buildDrainRedirectTarget("nlb.example.com", 62206, "c2hhcmVkLWtleQ==")
	if err == nil {
		t.Fatal("expected empty resolver result to return error")
	}
}

// TestDrainACConnections_NoHostname verifies that drainACConnections returns
// early when no Hostname is configured (e.g., local development).
func TestDrainACConnections_NoHostname(t *testing.T) {
	s, sendCh := newTestServerForBroadcast(t)
	s.config = &Config{
		Hostname:   "", // no NLB hostname
		ListenPort: 62206,
	}

	// Add an AC so we can verify it's NOT drained
	ac1 := newTestACConn(t, "10.0.0.1", 47051, "ac-1")
	s.acConnectionMap["ac-1"] = []*ACConn{ac1}

	done := make(chan struct{})
	go func() {
		s.drainACConnections()
		close(done)
	}()

	select {
	case <-done:
		// good — returned quickly
	case <-time.After(1 * time.Second):
		t.Fatal("drainACConnections should return immediately without Hostname")
	}

	// Verify nothing was sent despite having an AC
	select {
	case md := <-sendCh:
		t.Fatalf("unexpected message sent: %+v", md)
	default:
		// good
	}
}

// TestHandleACOnline_MalformedBodyEmitsFailureMetric verifies that the
// JSON-unmarshal failure path in HandleACOnline emits MetricACRegistrationFailure
// and does NOT emit MetricACRegistrationSuccess. This is a regression test for
// the server-side AC registration metrics added in #870; the alarm
// `registration_stale` requires that any failure path observably increments
// the failure counter.
func TestHandleACOnline_MalformedBodyEmitsFailureMetric(t *testing.T) {
	publisher := metrics.NewPublisherForTest(t)
	s := &UdpServer{metrics: publisher}

	ppd := &core.PacketParserData{
		SenderTrxId: 42,
		HeaderType:  core.NHP_AOL,
		BodyMessage: []byte("not-valid-json"),
		ConnData: &core.ConnectionData{
			RemoteAddr: &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 4567},
		},
	}

	if err := s.HandleACOnline(ppd); err == nil {
		t.Fatal("HandleACOnline should return error on malformed body")
	}

	counters, _ := publisher.CountersForTest(t)
	if got := counters[MetricACRegistrationFailure]; got != 1 {
		t.Errorf("MetricACRegistrationFailure = %v, want 1", got)
	}
	if got := counters[MetricACRegistrationSuccess]; got != 0 {
		t.Errorf("MetricACRegistrationSuccess = %v, want 0 on failure path", got)
	}
}

// TestHandleACOnline_EmptyACIDRejectsBeforeRegistration keeps malformed AC
// online messages out of acConnectionMap. The revocation proof engine treats an
// already-enqueued live conn without ACId as RevocationUntrackable, so the
// registration path must reject empty ACId before such a conn can become live.
func TestHandleACOnline_EmptyACIDRejectsBeforeRegistration(t *testing.T) {
	publisher := metrics.NewPublisherForTest(t)
	s := &UdpServer{
		metrics:         publisher,
		acPeerMap:       map[string]*core.UdpPeer{},
		acConnectionMap: map[string][]*ACConn{},
	}
	body, err := json.Marshal(common.ACOnlineMsg{ACId: "   "})
	if err != nil {
		t.Fatalf("marshal ACOnlineMsg: %v", err)
	}
	ppd := &core.PacketParserData{
		SenderTrxId:  43,
		HeaderType:   core.NHP_AOL,
		BodyMessage:  body,
		RemotePubKey: testPubkey(7),
		ConnData: &core.ConnectionData{
			RemoteAddr:           &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 4567},
			RemoteTransactionMap: make(map[uint64]*core.RemoteTransaction),
		},
	}

	err = s.HandleACOnline(ppd)
	if !errors.Is(err, common.ErrServerACOpsFailed) {
		t.Fatalf("HandleACOnline empty ACId err=%v, want ErrServerACOpsFailed", err)
	}
	counters, _ := publisher.CountersForTest(t)
	if got := counters[MetricACRegistrationFailure]; got != 1 {
		t.Fatalf("%s = %v, want 1", MetricACRegistrationFailure, got)
	}
	if got := counters[MetricACRegistrationSuccess]; got != 0 {
		t.Fatalf("%s = %v, want 0", MetricACRegistrationSuccess, got)
	}
	if got := len(s.acConnectionMap); got != 0 {
		t.Fatalf("acConnectionMap len = %d, want 0", got)
	}
	if got := len(s.acPeerMap); got != 0 {
		t.Fatalf("acPeerMap len = %d, want 0", got)
	}
}

// ---------------------------------------------------------------------------
// BlockAddr: IsBlockAddr / isBlockedIP / AddBlockAddr / RefreshBlockAddr
// ---------------------------------------------------------------------------

// newBlockAddrTestServer returns a minimally-initialized UdpServer suitable
// for exercising the block-address map in isolation (no network, no routines).
// Only blockAddrMap is initialized — other maps (remoteConnectionMap,
// authServiceMap, …) are nil and will panic if touched, so this helper is
// scoped to block-address tests only.
func newBlockAddrTestServer() *UdpServer {
	return &UdpServer{
		blockAddrMap: make(map[string]*BlockAddr),
	}
}

func mustResolveUDP(t *testing.T, hostport string) *net.UDPAddr {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp", hostport)
	if err != nil {
		t.Fatalf("ResolveUDPAddr(%q): %v", hostport, err)
	}
	return addr
}

func TestIsBlockAddr_Empty(t *testing.T) {
	t.Parallel()
	s := newBlockAddrTestServer()
	addr := mustResolveUDP(t, "203.0.113.1:62206")
	if s.IsBlockAddr(addr) {
		t.Fatal("expected empty map to report address not blocked")
	}
	if s.isBlockedIP(addr.IP.String()) {
		t.Fatal("isBlockedIP should agree with IsBlockAddr on empty map")
	}
}

func TestAddBlockAddr_ThenIsBlockAddr(t *testing.T) {
	t.Parallel()
	s := newBlockAddrTestServer()
	addr := mustResolveUDP(t, "203.0.113.2:62206")

	s.AddBlockAddr(addr)

	if !s.IsBlockAddr(addr) {
		t.Fatal("IsBlockAddr should return true after AddBlockAddr")
	}
	if !s.isBlockedIP(addr.IP.String()) {
		t.Fatal("isBlockedIP should return true after AddBlockAddr")
	}

	other := mustResolveUDP(t, "203.0.113.3:62206")
	if s.IsBlockAddr(other) {
		t.Fatal("unrelated address should not be reported as blocked")
	}
}

// TestBlockAddr_PortRotationStaysBlocked is the regression fence for
// #1160 T3-12: a blocked source must remain blocked even when it
// rotates source ports. Old IP:port keying allowed an attacker to
// dodge the block by switching ports.
func TestBlockAddr_PortRotationStaysBlocked(t *testing.T) {
	t.Parallel()
	s := newBlockAddrTestServer()

	// Block the source on port 1000.
	blocked := mustResolveUDP(t, "203.0.113.10:1000")
	s.AddBlockAddr(blocked)

	// Different ports on the same IP must also be flagged as blocked.
	for _, port := range []int{1, 2, 1000, 32767, 65535} {
		probe := &net.UDPAddr{IP: blocked.IP, Port: port}
		if !s.IsBlockAddr(probe) {
			t.Errorf("port %d on blocked source IP must remain blocked (#1160 T3-12)", port)
		}
	}

	// A different IP must NOT be blocked.
	other := mustResolveUDP(t, "203.0.113.11:1000")
	if s.IsBlockAddr(other) {
		t.Fatal("unrelated IP must not be blocked")
	}
}

func TestIsBlockedIP_MatchesIsBlockAddr(t *testing.T) {
	t.Parallel()
	// Guards the invariant the refactor relies on: the public and private
	// forms must agree on blocked/unblocked for any given address.
	s := newBlockAddrTestServer()
	blocked := mustResolveUDP(t, "203.0.113.4:62206")
	unblocked := mustResolveUDP(t, "203.0.113.5:62206")

	s.AddBlockAddr(blocked)

	for _, addr := range []*net.UDPAddr{blocked, unblocked} {
		if got, want := s.isBlockedIP(addr.IP.String()), s.IsBlockAddr(addr); got != want {
			t.Fatalf("isBlockedIP(%s)=%v IsBlockAddr(%s)=%v — must agree",
				addr.IP, got, addr, want)
		}
	}
}

func TestRefreshBlockAddr_RemovesExpiredOnly(t *testing.T) {
	t.Parallel()
	s := newBlockAddrTestServer()

	fresh := mustResolveUDP(t, "203.0.113.6:62206")
	stale := mustResolveUDP(t, "203.0.113.7:62206")

	// Seed directly to control expireTime — AddBlockAddr uses the real clock.
	now := time.Now()
	s.blockAddrMap[fresh.IP.String()] = &BlockAddr{expireTime: now.Add(time.Hour)}
	s.blockAddrMap[stale.IP.String()] = &BlockAddr{expireTime: now.Add(-time.Hour)}

	s.RefreshBlockAddr()

	if !s.IsBlockAddr(fresh) {
		t.Fatal("fresh entry should survive RefreshBlockAddr")
	}
	if s.IsBlockAddr(stale) {
		t.Fatal("expired entry should be purged by RefreshBlockAddr")
	}
}

// TestIsBlockedIP_ConcurrentReaders exercises the sync.RWMutex change:
// many readers must proceed concurrently without deadlock or data race.
// Run with `go test -race` to catch locking regressions.
func TestIsBlockedIP_ConcurrentReaders(t *testing.T) {
	s := newBlockAddrTestServer()
	addr := mustResolveUDP(t, "203.0.113.8:62206")
	s.AddBlockAddr(addr)
	ip := addr.IP.String()

	const readers = 32
	const itersPerReader = 1000

	var wg sync.WaitGroup
	wg.Add(readers)
	for i := 0; i < readers; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < itersPerReader; j++ {
				if !s.isBlockedIP(ip) {
					t.Errorf("concurrent read saw address as not blocked")
					return
				}
			}
		}()
	}
	wg.Wait()
}

// TestBlockAddr_ConcurrentReadWrite exercises reads interleaved with writes —
// the scenario the RWMutex upgrade actually unlocks. A misuse of RLock where
// Lock is required (or vice versa) would surface as a race under -race here,
// where the reader-only test cannot catch it.
//
// The writer continuously re-seeds already-expired entries under the write
// lock so RefreshBlockAddr has something to delete on every iteration,
// exercising the delete-while-read path (not just lock contention).
//
// Assertions: this test has no explicit value checks — correctness is
// validated by the -race detector flagging unsynchronised access. Run with
// `go test -race` or a regression will pass silently.
func TestBlockAddr_ConcurrentReadWrite(t *testing.T) {
	s := newBlockAddrTestServer()
	probe := mustResolveUDP(t, "203.0.113.9:62206")
	probeIP := probe.IP.String()

	const iters = 500

	var wg sync.WaitGroup
	wg.Add(3)

	// Re-seeder: plants stale entries under Lock for Refresh to reap.
	// Takes the raw mutex directly because AddBlockAddr uses time.Now() and
	// so can't produce pre-expired entries via the public API.
	go func() {
		defer wg.Done()
		stalePast := time.Now().Add(-time.Hour)
		for i := 0; i < iters; i++ {
			// Spread across the full TEST-NET-3 /24 (203.0.113.0/24)
			// so the loop pressures the map's growth path with up to
			// 256 distinct keys, not the same 16 keys overwritten
			// 31× — the IP-only block-map keying made the prior
			// (i%16) loop a no-op past the first 16 iterations.
			staleIP := net.IPv4(203, 0, 113, byte(i%256)).String()
			s.blockAddrMapMutex.Lock()
			s.blockAddrMap[staleIP] = &BlockAddr{expireTime: stalePast}
			s.blockAddrMapMutex.Unlock()
		}
	}()
	// Refresher: deletes expired entries (write path).
	go func() {
		defer wg.Done()
		for i := 0; i < iters; i++ {
			s.RefreshBlockAddr()
		}
	}()
	// Reader: hot-path check must not race with either writer.
	go func() {
		defer wg.Done()
		for i := 0; i < iters; i++ {
			_ = s.isBlockedIP(probeIP)
		}
	}()

	wg.Wait()
}

// TestRecordServerStartup verifies that recordServerStartup emits
// both EMF counter events (per-instance + fleet-wide) when the instance
// ID and the metrics publisher are available, and no-ops in the expected
// edge cases (empty instance ID, nil metrics).
//
// Fences the regression class of "unexpected process restarts go
// undetected" by confirming EMF emission of both the per-instance
// series (used by dashboards) and the fleet-wide series (drives the
// server_instance_restart alarm after #1109).
func TestRecordServerStartup(t *testing.T) {
	t.Run("emits per-instance and fleet-wide EMF events", func(t *testing.T) {
		mp, buf := metrics.NewPublisherForTestWithEMFBuffer(t)
		// Mirror the production publisher's base dims so the fleet-wide
		// assertion (Environment + Cell must be present) exercises the
		// real emission shape, not an empty-dim test stub.
		mp.SetBaseDimsForTest(t, []types.Dimension{
			{Name: aws.String("Environment"), Value: aws.String("sandbox")},
			{Name: aws.String("Cell"), Value: aws.String("cell0")},
		})
		s := &UdpServer{
			instanceID: "i-0abc123def456",
			metrics:    mp,
		}

		s.recordServerStartup()

		// Two EMF events expected: per-instance (with InstanceId) and
		// fleet-wide (no InstanceId).
		events := metrics.ParseEMFLinesForTest(t, buf.Bytes())
		if len(events) != 2 {
			t.Fatalf("expected exactly 2 EMF events (per-instance + fleet-wide), got %d: %s", len(events), buf.String())
		}
		var perInstance, fleetWide map[string]any
		for _, ev := range events {
			if _, hasID := ev["InstanceId"]; hasID {
				perInstance = ev
			} else {
				fleetWide = ev
			}
		}
		if perInstance == nil {
			t.Fatalf("no per-instance EMF event (carrying InstanceId) in buffer: %s", buf.String())
		}
		if fleetWide == nil {
			t.Fatalf("no fleet-wide EMF event (no InstanceId) in buffer: %s", buf.String())
		}
		// Assert structural invariants against the per-instance event;
		// the fleet-wide event is a strict subset of its dim sets and
		// gets its own narrower checks further down.
		event := perInstance
		// Dimension value + metric value must both be present and correct.
		if got := event["InstanceId"]; got != "i-0abc123def456" {
			t.Errorf("InstanceId = %v, want i-0abc123def456", got)
		}
		if got := event[MetricServerStartupEvent]; got != float64(1) {
			t.Errorf("%s = %v, want 1", MetricServerStartupEvent, got)
		}
		// Fleet-wide event must also carry the metric (drives the
		// server_instance_restart alarm).
		if got := fleetWide[MetricServerStartupEvent]; got != float64(1) {
			t.Errorf("fleet-wide %s = %v, want 1", MetricServerStartupEvent, got)
		}
		// Structural invariants on the _aws envelope: CloudWatch will
		// silently fail to extract the metric if any of these are wrong.
		awsBlock, ok := event["_aws"].(map[string]any)
		if !ok {
			t.Fatalf("missing _aws CloudWatchMetrics block in EMF event: %v", event)
		}
		// Scan CloudWatchMetrics for the expected directive rather
		// than pinning list lengths -- if AWS adds optional EMF fields
		// or we later emit a second Metrics entry in the same event,
		// the load-bearing assertions still pass.
		cwm, ok := awsBlock["CloudWatchMetrics"].([]any)
		if !ok || len(cwm) == 0 {
			t.Fatalf("_aws.CloudWatchMetrics missing or empty: %v", awsBlock["CloudWatchMetrics"])
		}
		var foundMetric, foundInstanceId, namespaceOK bool
		for _, dirAny := range cwm {
			directive, ok := dirAny.(map[string]any)
			if !ok {
				continue
			}
			if directive["Namespace"] == "LayerV/NHP" {
				namespaceOK = true
			}
			metrics, _ := directive["Metrics"].([]any)
			for _, mAny := range metrics {
				m, ok := mAny.(map[string]any)
				if !ok {
					continue
				}
				if m["Name"] == MetricServerStartupEvent && m["Unit"] == "Count" {
					foundMetric = true
				}
			}
			dimSets, _ := directive["Dimensions"].([]any)
			for _, set := range dimSets {
				names, ok := set.([]any)
				if !ok {
					continue
				}
				for _, n := range names {
					if n == "InstanceId" {
						foundInstanceId = true
					}
				}
			}
		}
		if !namespaceOK {
			t.Errorf("no CloudWatchMetrics directive with Namespace=LayerV/NHP in %v", cwm)
		}
		if !foundMetric {
			t.Errorf("no Metrics entry with Name=%s, Unit=Count in %v", MetricServerStartupEvent, cwm)
		}
		if !foundInstanceId {
			t.Errorf("InstanceId not in any Dimensions list in %v", cwm)
		}

		// The fleet-wide event is what the server_instance_restart
		// alarm consumes. It must (a) carry the Namespace CloudWatch
		// expects and (b) EXCLUDE InstanceId from its dim sets -- a
		// stray InstanceId here would route the series to a
		// different metric identity and break the alarm silently.
		fleetAWS, ok := fleetWide["_aws"].(map[string]any)
		if !ok {
			t.Fatalf("fleet-wide event missing _aws block: %v", fleetWide)
		}
		fleetCwm, ok := fleetAWS["CloudWatchMetrics"].([]any)
		if !ok || len(fleetCwm) == 0 {
			t.Fatalf("fleet-wide _aws.CloudWatchMetrics missing or empty: %v", fleetAWS)
		}
		var fleetNamespaceOK, fleetMetricOK bool
		for _, dirAny := range fleetCwm {
			directive, ok := dirAny.(map[string]any)
			if !ok {
				continue
			}
			if directive["Namespace"] == "LayerV/NHP" {
				fleetNamespaceOK = true
			}
			fleetMetrics, _ := directive["Metrics"].([]any)
			for _, mAny := range fleetMetrics {
				m, ok := mAny.(map[string]any)
				if !ok {
					continue
				}
				if m["Name"] == MetricServerStartupEvent && m["Unit"] == "Count" {
					fleetMetricOK = true
				}
			}
			dimSets, _ := directive["Dimensions"].([]any)
			for _, set := range dimSets {
				names, ok := set.([]any)
				if !ok {
					continue
				}
				var hasEnv, hasCell bool
				for _, n := range names {
					switch n {
					case "InstanceId":
						t.Errorf("fleet-wide event unexpectedly declares InstanceId in Dimensions: %v", names)
					case "Environment":
						hasEnv = true
					case "Cell":
						hasCell = true
					}
				}
				// The server_instance_restart alarm queries with
				// dimensions = { Environment, Cell }. If either
				// goes missing from the EMF event's dim set, the
				// alarm's metric lookup silently misses and it
				// stops firing on crash loops.
				if !hasEnv || !hasCell {
					t.Errorf("fleet-wide event Dimensions must include Environment + Cell so the server_instance_restart alarm resolves; got %v", names)
				}
			}
		}
		if !fleetNamespaceOK {
			t.Errorf("fleet-wide event missing Namespace=LayerV/NHP: %v", fleetCwm)
		}
		if !fleetMetricOK {
			t.Errorf("fleet-wide event missing Metrics entry Name=%s, Unit=Count: %v", MetricServerStartupEvent, fleetCwm)
		}
	})

	t.Run("no-op when instanceID empty", func(t *testing.T) {
		mp, buf := metrics.NewPublisherForTestWithEMFBuffer(t)
		s := &UdpServer{instanceID: "", metrics: mp}

		s.recordServerStartup()

		if buf.Len() != 0 {
			t.Errorf("expected no EMF emission when instanceID is empty; got %q", buf.String())
		}
	})

	t.Run("no-op when metrics nil", func(t *testing.T) {
		s := &UdpServer{instanceID: "i-test", metrics: nil}

		// Must not panic.
		s.recordServerStartup()
	})
}

// TestAwaitTransactionDrain_ImmediateReturnOnEmpty pins the no-wait
// path: shutdown with zero in-flight transactions returns instantly
// (no poll iteration, no metric increment).
func TestAwaitTransactionDrain_ImmediateReturnOnEmpty(t *testing.T) {
	mp := metrics.NewPublisherForTest(t)
	device := core.NewDevice(core.NHP_SERVER, testPrivateKey(), nil)
	if device == nil {
		t.Fatal("NewDevice returned nil")
	}
	defer device.Stop()
	s := &UdpServer{metrics: mp, device: device}

	start := time.Now()
	s.awaitTransactionDrain(5 * time.Second)
	if elapsed := time.Since(start); elapsed > 50*time.Millisecond {
		t.Errorf("awaitTransactionDrain blocked %v on empty map; expected immediate return", elapsed)
	}
	counters, _ := mp.CountersForTest(t)
	if counters[MetricShutdownTransactionDrainTimeout] != 0 {
		t.Errorf("MetricShutdownTransactionDrainTimeout = %v, want 0 (empty drain is not a timeout)", counters[MetricShutdownTransactionDrainTimeout])
	}
}

// TestAwaitTransactionDrain_WaitsForCountToReachZero pins the
// drain-then-return path: a transaction outstanding at shutdown time
// must let the wait block until it's removed, then return cleanly
// (no metric increment).
func TestAwaitTransactionDrain_WaitsForCountToReachZero(t *testing.T) {
	mp := metrics.NewPublisherForTest(t)
	device := core.NewDevice(core.NHP_SERVER, testPrivateKey(), nil)
	if device == nil {
		t.Fatal("NewDevice returned nil")
	}
	defer device.Stop()
	s := &UdpServer{metrics: mp, device: device}

	// Seed one transaction directly into the map to simulate an in-flight
	// knock; bypass AddLocalTransaction so we don't have to spin up the
	// transaction's goroutine.
	core.SeedLocalTransactionForTest(device, 42)

	if got := device.LocalTransactionCount(); got != 1 {
		t.Fatalf("setup: count = %d, want 1", got)
	}

	// Remove the transaction after a short delay; the drain must wait for it.
	const removeAfter = 300 * time.Millisecond
	go func() {
		time.Sleep(removeAfter)
		core.RemoveLocalTransactionForTest(device, 42)
	}()

	start := time.Now()
	s.awaitTransactionDrain(5 * time.Second)
	elapsed := time.Since(start)
	if elapsed < removeAfter {
		t.Errorf("awaitTransactionDrain returned in %v, expected >= %v (must wait for transaction to clear)", elapsed, removeAfter)
	}
	if elapsed > 2*time.Second {
		t.Errorf("awaitTransactionDrain blocked %v after transaction cleared; expected return within ~1 poll interval", elapsed)
	}
	counters, _ := mp.CountersForTest(t)
	if counters[MetricShutdownTransactionDrainTimeout] != 0 {
		t.Errorf("MetricShutdownTransactionDrainTimeout = %v, want 0 (drain reached zero before deadline)", counters[MetricShutdownTransactionDrainTimeout])
	}
}

// TestAwaitTransactionDrain_TimeoutFires pins the budget-exhausted
// path: when a transaction never clears, the wait must give up at
// the deadline and increment MetricShutdownTransactionDrainTimeout so the
// shutdown sequence can continue (with the understanding that the
// outstanding transaction will see closed-connection on its caller).
func TestAwaitTransactionDrain_TimeoutFires(t *testing.T) {
	mp := metrics.NewPublisherForTest(t)
	device := core.NewDevice(core.NHP_SERVER, testPrivateKey(), nil)
	if device == nil {
		t.Fatal("NewDevice returned nil")
	}
	defer device.Stop()
	s := &UdpServer{metrics: mp, device: device}

	core.SeedLocalTransactionForTest(device, 99)
	defer core.RemoveLocalTransactionForTest(device, 99)

	const budget = 300 * time.Millisecond
	start := time.Now()
	s.awaitTransactionDrain(budget)
	elapsed := time.Since(start)
	if elapsed < budget {
		t.Errorf("awaitTransactionDrain returned in %v, expected >= budget %v", elapsed, budget)
	}
	if elapsed > budget+500*time.Millisecond {
		t.Errorf("awaitTransactionDrain blocked %v, expected close to budget %v", elapsed, budget)
	}
	counters, _ := mp.CountersForTest(t)
	if counters[MetricShutdownTransactionDrainTimeout] != 1 {
		t.Errorf("MetricShutdownTransactionDrainTimeout = %v, want 1 (transaction never cleared)", counters[MetricShutdownTransactionDrainTimeout])
	}
}

// TestAwaitTransactionDrain_NilDevice covers the defensive no-op
// when device is nil. The Stop() sequence guards against panics on
// partially-initialized servers; this fences that the drain helper
// doesn't add a new panic surface.
func TestAwaitTransactionDrain_NilDevice(t *testing.T) {
	s := &UdpServer{}
	s.awaitTransactionDrain(5 * time.Second) // must not panic
}

// TestAwaitTransactionDrain_MultipleStaggered pins the loop's
// monotonic-decrement assumption: with N=10 transactions cleared at
// staggered intervals, the wait must return only after the LAST one
// is gone — not after the first count change.
func TestAwaitTransactionDrain_MultipleStaggered(t *testing.T) {
	mp := metrics.NewPublisherForTest(t)
	device := core.NewDevice(core.NHP_SERVER, testPrivateKey(), nil)
	if device == nil {
		t.Fatal("NewDevice returned nil")
	}
	defer device.Stop()
	s := &UdpServer{metrics: mp, device: device}

	const n = 10
	for i := uint64(1); i <= n; i++ {
		core.SeedLocalTransactionForTest(device, i)
	}

	const interval = 50 * time.Millisecond
	for i := uint64(1); i <= n; i++ {
		go func(id uint64) {
			time.Sleep(time.Duration(id) * interval)
			core.RemoveLocalTransactionForTest(device, id)
		}(i)
	}

	start := time.Now()
	s.awaitTransactionDrain(5 * time.Second)
	elapsed := time.Since(start)
	minExpected := time.Duration(n) * interval
	if elapsed < minExpected {
		t.Errorf("awaitTransactionDrain returned in %v, expected >= %v (must wait for all %d txs to clear)", elapsed, minExpected, n)
	}
	if got := device.LocalTransactionCount(); got != 0 {
		t.Errorf("count = %d after drain, want 0", got)
	}
	counters, _ := mp.CountersForTest(t)
	if counters[MetricShutdownTransactionDrainTimeout] != 0 {
		t.Errorf("MetricShutdownTransactionDrainTimeout = %v, want 0 (staggered drain reached zero before deadline)", counters[MetricShutdownTransactionDrainTimeout])
	}
}

// TestAwaitTransactionDrain_BudgetSmallerThanPollInterval pins the
// edge case where the deadline expires before the first time.Sleep
// returns. The loop's deadline check on iteration entry must still
// catch this and increment the timeout metric — otherwise a very
// small budget could spin indefinitely.
func TestAwaitTransactionDrain_BudgetSmallerThanPollInterval(t *testing.T) {
	mp := metrics.NewPublisherForTest(t)
	device := core.NewDevice(core.NHP_SERVER, testPrivateKey(), nil)
	if device == nil {
		t.Fatal("NewDevice returned nil")
	}
	defer device.Stop()
	s := &UdpServer{metrics: mp, device: device}

	core.SeedLocalTransactionForTest(device, 7)
	defer core.RemoveLocalTransactionForTest(device, 7)

	// Budget < shutdownTransactionDrainPollInterval (100ms).
	const budget = 10 * time.Millisecond
	start := time.Now()
	s.awaitTransactionDrain(budget)
	elapsed := time.Since(start)
	// Bound at 250ms: poll interval is 100ms, so the deadline check on
	// iteration 2 fires at ~100ms. 250ms leaves margin for CI jitter
	// while still catching a one-line ordering bug (e.g. deadline check
	// moved below time.Sleep, which would block at least one poll).
	if elapsed > 250*time.Millisecond {
		t.Errorf("awaitTransactionDrain blocked %v with budget=%v; should return within ~1 poll interval", elapsed, budget)
	}
	counters, _ := mp.CountersForTest(t)
	if counters[MetricShutdownTransactionDrainTimeout] != 1 {
		t.Errorf("MetricShutdownTransactionDrainTimeout = %v, want 1 (sub-poll-interval budget must still register a timeout)", counters[MetricShutdownTransactionDrainTimeout])
	}
}

// TestAwaitTransactionDrain_NilMetrics is symmetric with the
// nil-device guard: when s.metrics is nil, the timeout path must
// not panic on the IncrCounter call. Covers the partial-init Stop()
// path where metrics may not have been wired before shutdown.
func TestAwaitTransactionDrain_NilMetrics(t *testing.T) {
	device := core.NewDevice(core.NHP_SERVER, testPrivateKey(), nil)
	if device == nil {
		t.Fatal("NewDevice returned nil")
	}
	defer device.Stop()
	s := &UdpServer{device: device} // no metrics

	core.SeedLocalTransactionForTest(device, 13)
	defer core.RemoveLocalTransactionForTest(device, 13)

	// Must not panic on the timeout path's IncrCounter call.
	s.awaitTransactionDrain(50 * time.Millisecond)
}
