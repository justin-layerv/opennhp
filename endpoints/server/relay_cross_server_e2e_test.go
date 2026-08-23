package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/OpenNHP/opennhp/endpoints/metrics"
	"github.com/OpenNHP/opennhp/endpoints/server/internal/qurlplacement"
	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
	"github.com/OpenNHP/opennhp/nhp/plugins"
)

// ============================================================================
// Cross-server relayed-knock e2e (#2546): relay -> server A -> NHP_FWD ->
// server B (mock AC) -> NHP_FRT -> server A -> ack delivered through the relay.
// ============================================================================
//
// Each leg is fenced in isolation already:
//
//   - HandleRelayForward decrypt + reply-through-relay: relay_test.go's
//     TestHandleRelayForward_RoundTripDeliversAgentAckToRelay (which rejects at
//     the header-type gate, so it never reaches AuthWithNHP / forwarding) +
//     relay_ack_roundtrip_spike_test.go.
//   - NHP_FWD receiver decrypts + processes with the forwarded srcAddr:
//     forward_e2e_test.go's TestE2E_HandleForwardRequest_FullACFlow.
//
// What no test exercised before this one is the COMPOSED path: a relayed knock
// landing on server A whose target AC is connected to a DIFFERENT server B, so
// buildKnockAck's AuthWithNHP triggers a real server-to-server NHP_FWD, and the
// agent-decryptable ack returns to the originating client THROUGH the relay.
// Single-cell deployments with a local AC never hit it; the #2208 multi-instance
// (ASG + DynamoDB) topology can. This is the gap #2546 calls out as the test
// coverage that de-risks the browser relay's private cell hop (#8 / #2628).
//
// The two load-bearing assertions:
//
//  1. The relay-reported CLIENT ip propagates intact through NHP_FWD to server
//     B and lands in the AOP that opens the AC pinhole — never the relay's ip,
//     server A's, or server B's. (relayClientAddr below is distinct from every
//     other address in the topology so any leak is visible.)
//  2. The final ack is delivered to the RELAY's address (not the client's) and
//     is decryptable by the agent's original knock transaction.
//
// Determinism: every node is in-process on localhost (the forward_e2e_test.go
// E2ETestNode harness — real UDP sockets, real Noise crypto, no etcd/DDB). The
// only network hop that actually crosses a socket is the real NHP_FWD/NHP_FRT
// between server A and server B; everything else is a direct call into the
// production handler.

// relayClientAddr is the real browser-client ip:port the relay observes at its
// TLS edge and reports as RelayForwardMsg.SourceAddr. It is deliberately
// distinct from server A, server B, the mock AC, and the relay's own address so
// a leak of any wrong address into the AC pinhole (server B's AOP) or the
// returned ack is caught by a literal-string mismatch.
var relayClientAddr = &net.UDPAddr{IP: net.IPv4(203, 0, 113, 7), Port: 44444}

// TestE2E_RelayCrossServer_KnockForwardedToRemoteAC_AckReturnsViaRelay drives
// the full composed relay -> NHP_FWD -> ack-via-relay path with a remote AC.
//
// This is the end-to-end fence for the cross-server-forward crypto fix (#2651):
// buildKnockAck must forward the ORIGINAL ciphertext so the assigned server can
// re-decrypt the inner knock. The minimal, network-free proof of that crypto
// bug is TestForwardOriginalPacket_ReDecryptableAfterDecrypt. The test-harness
// bugs that also blocked this composed path — #2654 (server B deps never
// transmit NHP_FRT), #2655 (NHP_FWD handled on the recv loop -> NHP_ART timeout
// + pool-release race), #2656 (mock-AC id != resource ACId) — were fixed in
// #2650 (#2653 was investigated and closed as not-a-bug). See #2546 for the
// coverage rationale (de-risks the browser relay's private cell hop, #2208).
func TestE2E_RelayCrossServer_KnockForwardedToRemoteAC_AckReturnsViaRelay(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping cross-server relay e2e test in short mode")
	}

	const (
		aspID         = "agent" // the umbrella agent-knock aspId (served here by relayCrossServerPlugin)
		acID          = "ac-on-server-b"
		serverBID     = "server-b"
		innerKnockTrx = uint64(7654321)
		runID         = "0123456789abcdef"
	)

	// ------------------------------------------------------------------ nodes
	// Both servers run cloud-mode (DisableAgentPeerValidation=true), the posture
	// the #2208 relay/forward path requires: server A synthetically decrypts the
	// relayed inner agent knock and server B decrypts the NHP_FWD-forwarded inner
	// knock, both onto the agent's learned pubkey without a pre-registered agent
	// peer. A legacy (validation-on) server fails these decrypts closed by design
	// (see relay.go's header) — that's not the path under test.
	cloudMode := &core.DeviceOptions{DisableAgentPeerValidation: true}

	// Server A and server B SHARE one registration keypair — the production
	// multi-instance posture (docs/design/PER_INSTANCE_SERVER_KEYS.md §1): every
	// server behind the NLB decrypts agent traffic with the same shared key. This
	// is what makes the forward path work: the agent encrypts its inner knock to
	// the shared key, server A decrypts it on the relay path, and server B
	// re-decrypts the SAME forwarded bytes (decryptForwardedKnock) with the same
	// shared key. Distinct per-node keys (the default) would make server B's
	// re-decrypt fail with an AEAD authentication error.
	sharedRegKey := make([]byte, 32)
	for i := range sharedRegKey {
		sharedRegKey[i] = byte(i) + 0x42
	}

	// Server A: the instance the relay forwards to. Built on the E2E node for
	// its real socket + recv/decrypt/dispatch loops; a hand-constructed
	// UdpServer (below) shares its device + socket and runs the production
	// relay + knock + forward pipeline.
	serverANode := newE2ETestNodeFull(t, "server-a", core.NHP_SERVER, sharedRegKey, cloudMode)
	serverANode.Start()
	defer serverANode.Stop()

	// Server B: the instance the target AC is connected to. Runs the real
	// ServerForwarder.HandleForwardRequest against a mock AC. Same shared key.
	serverBNode := newE2ETestNodeFull(t, serverBID, core.NHP_SERVER, sharedRegKey, cloudMode)
	serverBNode.Start()
	defer serverBNode.Stop()

	// Mock AC connected to server B. NHP_AC device type so it can receive AOP.
	// Its node id MUST be acID: server B resolves the forwarded knock to a
	// ResourceData whose ACId is acID, and mockACForwarderDeps.FindACConnections
	// ForResource gates on resData.ACId == mockACNode.id (so the e2e fails if AC
	// dispatch and ACK ResourceHost ever drift apart). A mismatch here makes
	// server B find no AC connection and the NHP_FWD path never reaches the AOP.
	mockAC := newE2ETestNodeWithType(t, acID, core.NHP_AC)
	mockAC.Start()
	defer mockAC.Stop()

	// Agent: a bare started device (the relay_test.go pattern), NOT an E2E node.
	// The agent never owns a socket here — it encrypts the inner knock onto a
	// send-loop-free capture connection (so drainEncryptedPacket can pull the
	// bytes and nothing transmits them), and later decrypts the relay-delivered
	// ack via its original local transaction (routeResponseToTransaction). Using
	// a started E2E node instead would spin a connectionSendLoop that races the
	// sender-owned packet and would transmit the knock over the
	// wire to server A (which has no agent peer and fails the decrypt).
	agentDev := newSpikeDevice(t, core.NHP_AGENT, 0x11, nil)

	// Both servers share the same durable session authority, just as production
	// instances in one cell share the dedicated session-control table. Server A
	// reserves the exact tuple before forwarding; server B must strong-verify
	// that same tuple before catalog, placement, or AC work. Leaving either side
	// on the old synthetic verifier would let this E2E fabricate a receipt that
	// the strict registered-agent ACK encoder correctly refuses.
	durableStore := newAdmissionSessionControlStore(time.Now())
	durableVerifier := &UdpServer{
		sessionControlCellID: testSessionControlCellID,
		sessionControlStore:  durableStore,
	}
	verifiedReceiptCh := make(chan common.AgentSessionReceipt, 1)

	// The relay stand-in: a plain UDP socket. server A's buildRelayInnerReply +
	// sendRelayReturn path writes the final ack here; the test reads it back and
	// feeds it to the agent.
	relayListen := mustUDPListener(t)
	relayAddr := relayListen.LocalAddr().(*net.UDPAddr)

	// ----------------------------------------------------------------- peering
	// Agent must hold server A's static key to encrypt the inner knock to it and
	// to decrypt the ack's response leg (validatePeer looks the responder's
	// static key up in the agent's pool).
	agentDev.AddPeer(&core.UdpPeer{
		PubKeyBase64: serverANode.publicKey,
		Ip:           serverANode.addr.IP.String(),
		Port:         serverANode.addr.Port,
		Type:         core.NHP_SERVER,
	})

	// Server B <-> mock AC for the AOP/ART exchange.
	serverBNode.AddPeer(mockAC)
	mockAC.AddPeer(serverBNode)

	// Server B must hold server A's key to decrypt the inbound NHP_FWD's outer
	// envelope. (Server A learns server B as a peer lazily via the forwarder's
	// getOrCreateServerPeer, so we do NOT pre-add B on A — a duplicate peer with
	// the same pubkey would confuse session state, mirroring the note in
	// forward_e2e_test.go's TestE2E_ForwarderIntegration.)
	serverBNode.AddPeer(serverANode)

	time.Sleep(200 * time.Millisecond)

	// --------------------------------------------------- server B forward wiring
	// Capture the AOP the mock AC receives so we can assert the pinhole opens for
	// the relay-reported client ip after the srcAddr crossed NHP_FWD.
	acReceivedOp := make(chan *common.ServerACOpsMsg, 1)
	mockAC.SetMessageHandler(func(msg *ReceivedMsg) {
		if msg.HeaderType != core.NHP_AOP {
			return
		}
		var aopMsg common.ServerACOpsMsg
		if err := json.Unmarshal(msg.Data, &aopMsg); err != nil {
			t.Errorf("mock AC: failed to parse AOP: %v", err)
			return
		}
		select {
		case acReceivedOp <- &aopMsg:
		default:
		}
		// Grant the pinhole.
		artBytes, _ := json.Marshal(&common.ACOpsResultMsg{
			ErrCode:  common.ErrSuccess.ErrorCode(),
			OpenTime: 30,
			ACToken:  "relay-cross-server-token",
		})
		if msg.PPD != nil {
			if err := mockAC.SendMessage(serverBNode, core.NHP_ART, msg.PPD.SenderTrxId, artBytes, msg.PPD); err != nil {
				t.Errorf("mock AC: failed to send NHP_ART: %v", err)
			}
		}
	})

	// Server B's forwarder: real ServerForwarder.HandleForwardRequest, with the
	// mock-AC deps from forward_e2e_test.go so the AOP/ART round-trip is real,
	// wrapped (relayServerBForwarderDeps) so SendMessage TRANSMITS the NHP_FRT
	// back to server A over server B's socket. The bare
	// mockACForwarderDeps.SendMessage only captures the result (for the direct
	// FullACFlow test); on this composed path that would strand server A waiting
	// for an NHP_FRT that never arrives (#2654).
	serverBDeps := &relayServerBForwarderDeps{
		mockACForwarderDeps: &mockACForwarderDeps{
			hostname:        serverBID,
			device:          serverBNode.device,
			serverNode:      serverBNode,
			mockACNode:      mockAC,
			t:               t,
			aspData:         newForwardE2EQURLTunnelASP(aspID, acID),
			durableVerifier: durableVerifier,
		},
		verifiedReceiptCh: verifiedReceiptCh,
	}
	serverBForwarder := NewServerForwarder(serverBDeps)
	serverBForwarder.Start()
	defer serverBForwarder.Stop()

	// Route inbound NHP_FWD on server B to its forwarder.
	serverBNode.SetMessageHandler(func(msg *ReceivedMsg) {
		if msg.HeaderType != core.NHP_FWD {
			return
		}
		var fwdMsg common.ServerForwardMsg
		if err := json.Unmarshal(msg.Data, &fwdMsg); err != nil {
			t.Errorf("server B: failed to parse NHP_FWD: %v", err)
			return
		}
		// Dispatch off server B's recv-loop goroutine: HandleForwardRequest blocks
		// in ProcessACOperation waiting for the AC's NHP_ART, and that NHP_ART can
		// only be routed back to its transaction by THIS recv loop (#2655). Running
		// it inline deadlocks the loop against itself -> ProcessACOperation timeout.
		// msg.PPD is safe off-loop: sendForwardResult re-derives the NHP_FRT from
		// ppd's ConnData/RemotePubKey/cipher fields (all retained after Destroy via
		// deriveMsgAssemblerData), never the released base packet.
		go serverBForwarder.HandleForwardRequest(msg.PPD, &fwdMsg)
	})

	// --------------------------------------------------- server A forward wiring
	// Server A's forwarder transmits NHP_FWD to server B over a real socket and
	// receives NHP_FRT back. Its deps bridge SendMessage to server A's E2E node
	// (encrypt via server A's device + WriteToUDP), mirroring e2eForwarderDeps.
	serverAFwdDeps := &crossServerForwarderDeps{node: serverANode}
	serverAForwarder := NewServerForwarder(serverAFwdDeps)
	serverAForwarder.Start()
	defer serverAForwarder.Stop()

	// Route inbound NHP_FRT on server A to its forwarder so ForwardKnock's
	// pending wait completes. This is exactly the dispatch the production
	// UdpServer.connectionRoutine performs (NHP_FRT decrypts via the NHP_FWD
	// local transaction's PrevAssemblerData, lands on DecryptedMsgQueue, and
	// dispatchReceivedMessage routes it to HandleForwardResult).
	serverANode.SetMessageHandler(func(msg *ReceivedMsg) {
		if msg.HeaderType != core.NHP_FRT {
			return
		}
		var resultMsg common.ServerForwardResultMsg
		if err := json.Unmarshal(msg.Data, &resultMsg); err != nil {
			t.Errorf("server A: failed to parse NHP_FRT: %v", err)
			return
		}
		serverAForwarder.HandleForwardResult(msg.PPD, &resultMsg)
	})

	// --------------------------------------------------- server A UdpServer
	// MemoryStorage holds the AC assignment so handleNhpOpenResource's forward
	// gate resolves acID -> server B (the AC is NOT connected to server A, so
	// hasLiveACConn is false and the knock forwards).
	storage := NewMemoryStorage()
	storage.PutACAssignment(&ACAssignment{
		ACID:       acID,
		CustomerID: "cust-relay-cross-server",
		AssignedServers: []ServerInfo{
			{
				ID: serverBID,
				// InternalIP+Port is what the forwarder dials for NHP_FWD.
				IP:         serverBNode.addr.IP.String(),
				InternalIP: serverBNode.addr.IP.String(),
				Port:       serverBNode.addr.Port,
				PubKey:     serverBNode.publicKey,
			},
		},
		Version: 1,
	})

	mp := metrics.NewPublisherForTest(t)

	serverA := &UdpServer{
		device:               serverANode.device,
		metrics:              mp,
		relayPeerMap:         make(map[string]*core.UdpPeer),
		sessionControlCellID: testSessionControlCellID,
		sessionControlStore:  durableStore,
		// A local plugin handler that mirrors the production agent plugin's core
		// (resolve the qURL tunnel resource off helper.AspData via the real
		// qurlplacement.ResolveResource, then dispatch through
		// helper.AuthWithNhpCallbackFunc -> handleNhpOpenResource, which is where
		// the cross-server forward happens). Kept local rather than importing
		// staticplugins/agent because that package's init() registers "agent" in
		// the GLOBAL plugin registry, which perturbs unrelated tests
		// (TestUdpServer_ResolveAuthSvcProvider builds a logger-less UdpServer and
		// would then try to Init the now-registered plugin and nil-deref s.log).
		pluginHandlerMap: map[string]plugins.PluginHandler{aspID: &relayCrossServerPlugin{}},
		// In-memory ASP catalog so buildKnockAck's FindAuthSvcProvider resolves
		// without DDB.
		authServiceMap: common.AuthSvcProviderMap{
			aspID: newForwardE2EQURLTunnelASP(aspID, acID),
		},
		storage:   storage,
		forwarder: serverAForwarder,
		// agentPeerLookup stays nil: the DDB-backed agent resolution block in
		// buildKnockAck is skipped (legacy/non-cloud path). The inner knock's
		// RemotePubKey is populated by the synthetic decrypt under
		// DisableAgentPeerValidation, which is all AuthWithNHP needs.
		// listenConn is server A's real socket — sendRelayReturn writes the
		// wrapped ack to the relay through it.
		listenConn: serverANode.udpConn,
	}

	// ----------------------------------------------- build the relayed knock
	// The agent encrypts a real NHP_KNK transaction to server A; the captured
	// bytes are what the relay forwards as RelayForwardMsg.InnerPacket. Sent as a
	// real transaction (ResponseMsgCh) so the agent can decrypt the returned ack.
	respCh := make(chan *core.PacketParserData, 1)
	agentToServerAConn := newSpikeConn(agentDev, serverANode.addr)
	knockBody, err := json.Marshal(&common.AgentKnockMsg{
		HeaderType:    core.NHP_KNK,
		UserId:        "relay-cross-server-user",
		AuthServiceId: aspID,
		ResourceId:    qurlplacement.TunnelServerResourceID,
		RunID:         runID,
		RunAttempt:    1,
	})
	if err != nil {
		t.Fatalf("marshal knock body: %v", err)
	}
	agentDev.SendMsgToPacket(&core.MsgData{
		ConnData:      agentToServerAConn,
		PeerPk:        serverANode.PublicKeyBytes(),
		HeaderType:    core.NHP_KNK,
		TransactionId: innerKnockTrx,
		Message:       knockBody,
		ResponseMsgCh: respCh,
	})
	innerKnock := drainEncryptedPacket(t, agentToServerAConn)

	// Wrap it as the relay would and hand it to the production NHP_RLY handler.
	rlyBytes, err := json.Marshal(&common.RelayForwardMsg{
		SourceAddr:  &common.NetAddress{Ip: relayClientAddr.IP.String(), Port: relayClientAddr.Port},
		InnerPacket: base64.StdEncoding.EncodeToString(innerKnock),
		RequestID:   testRelayRequestID,
	})
	if err != nil {
		t.Fatalf("marshal RelayForwardMsg: %v", err)
	}
	outerPpd, relayDev, relayConn := realOuterRelayRequest(t, serverANode.device, serverANode.addr, relayAddr, rlyBytes)
	relayPubB64 := base64.StdEncoding.EncodeToString(outerPpd.RemotePubKey)
	serverA.relayPeerMap[relayPubB64] = &core.UdpPeer{PubKeyBase64: relayPubB64, Type: core.NHP_RELAY}

	// ------------------------------------------------------------- drive it
	// HandleRelayForward blocks through buildKnockAck -> AuthWithNHP ->
	// handleNhpOpenResource -> ForwardKnock (the real NHP_FWD round-trip) ->
	// buildRelayInnerReply -> sendRelayReturn, so run it in a goroutine and assert
	// on the observable side effects (the AOP at the AC, the ack at the relay).
	go serverA.HandleRelayForward(outerPpd)

	// The remote server's production verifier must recover the exact receipt
	// from the shared durable reservation. This is the authority later encoded
	// into the forwarded registered-agent ACK; no forwarding field or test echo
	// is allowed to mint it.
	var verifiedReceipt common.AgentSessionReceipt
	select {
	case verifiedReceipt = <-verifiedReceiptCh:
		if err := common.ValidateAgentSessionReceipt(verifiedReceipt); err != nil {
			t.Fatalf("server B durable receipt = %+v: %v", verifiedReceipt, err)
		}
		if verifiedReceipt.CellID != testSessionControlCellID || verifiedReceipt.RunID != runID ||
			verifiedReceipt.RunAttempt != 1 {
			t.Fatalf("server B durable receipt = %+v, want cell=%q run=(%q,1)",
				verifiedReceipt, testSessionControlCellID, runID)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("server B never strong-verified server A's durable session reservation")
	}

	// ---- Assertion 1 (the heart of #2546): the relay-reported CLIENT ip
	// crossed NHP_FWD and opened the AC pinhole on server B — not the relay, not
	// server A, not server B.
	select {
	case aopMsg := <-acReceivedOp:
		if aopMsg.SessionId != verifiedReceipt.SessionID ||
			aopMsg.SessionIssuedAtMillis != verifiedReceipt.SessionIssuedAtMillis ||
			aopMsg.RunID != verifiedReceipt.RunID || aopMsg.RunAttempt != verifiedReceipt.RunAttempt {
			t.Fatalf("AOP exact session = (%d,%d,%q,%d), want durable receipt (%d,%d,%q,%d)",
				aopMsg.SessionId, aopMsg.SessionIssuedAtMillis, aopMsg.RunID, aopMsg.RunAttempt,
				verifiedReceipt.SessionID, verifiedReceipt.SessionIssuedAtMillis,
				verifiedReceipt.RunID, verifiedReceipt.RunAttempt)
		}
		if len(aopMsg.SourceAddrs) == 0 || aopMsg.SourceAddrs[0] == nil {
			t.Fatalf("AOP carried no source address; want relay-reported client %s", relayClientAddr.IP)
		}
		gotIP := aopMsg.SourceAddrs[0].Ip
		if gotIP != relayClientAddr.IP.String() {
			t.Errorf("AC pinhole opened for source ip %q, want relay-reported client %q (srcAddr must propagate relay -> server A -> NHP_FWD -> server B intact, never the relay/server addresses)",
				gotIP, relayClientAddr.IP.String())
		}
		// Belt-and-suspenders: prove it is none of the topology's other addresses.
		for name, addr := range map[string]string{
			"relay":    relayAddr.IP.String(),
			"server-a": serverANode.addr.IP.String(),
			"server-b": serverBNode.addr.IP.String(),
			acID:       mockAC.addr.IP.String(),
		} {
			if gotIP == addr && addr != relayClientAddr.IP.String() {
				t.Errorf("AC pinhole opened for the %s address %q; the relay-reported client ip must be used instead", name, gotIP)
			}
		}
	case <-time.After(10 * time.Second):
		t.Fatal("mock AC on server B never received the forwarded AOP (NHP_FWD path did not complete)")
	}

	// ---- Assertion 2: the ack is delivered to the RELAY's address (not the
	// client) and is decryptable by the agent's original knock transaction.
	outerReturnBytes := readUDPWithTimeout(t, relayListen, 10*time.Second)
	returned := decryptRelayReturnForTest(t, relayDev, relayConn, outerReturnBytes)
	if returned.RequestID != testRelayRequestID {
		t.Fatalf("return request ID = %q, want %q", returned.RequestID, testRelayRequestID)
	}
	ackBytes, err := base64.StdEncoding.DecodeString(returned.InnerPacket)
	if err != nil {
		t.Fatalf("decode returned inner ACK: %v", err)
	}

	routeResponseToTransaction(t, agentDev, ackBytes)
	select {
	case agentPpd := <-respCh:
		if agentPpd.Error != nil {
			t.Fatalf("agent failed to decrypt relayed cross-server ack: %v", agentPpd.Error)
		}
		if agentPpd.HeaderType != core.NHP_ACK {
			t.Fatalf("agent decrypted header = %d, want NHP_ACK", agentPpd.HeaderType)
		}
		if agentPpd.SenderTrxId != innerKnockTrx {
			t.Errorf("ack counter = %d, want inner knock counter %d", agentPpd.SenderTrxId, innerKnockTrx)
		}
		var ack common.ServerKnockAckMsg
		if err := common.DecodeRegisteredAgentKnockAckMsg(agentPpd.BodyMessage, &ack,
			runID, 1, qurlplacement.TunnelServerResourceID); err != nil {
			t.Fatalf("strict-decode decrypted registered-agent ack: %v", err)
		}
		if ack.ErrCode != common.ErrSuccess.ErrorCode() {
			t.Errorf("ack.ErrCode = %q, want success %q (ErrMsg=%q); the forwarded knock should have been granted by the remote AC",
				ack.ErrCode, common.ErrSuccess.ErrorCode(), ack.ErrMsg)
		}
		// AgentAddr is echoed from the inner knock's ConnData.RemoteAddr, which
		// HandleRelayForward stamped with the relay-reported client — same field
		// threaded into the AC pinhole source. Asserting it is the client (not
		// the relay) is the agent-visible half of the srcAddr-propagation proof.
		if ack.AgentAddr != relayClientAddr.String() {
			t.Errorf("ack.AgentAddr = %q, want relay-reported client %q (the ack must reflect the real client, never the relay)",
				ack.AgentAddr, relayClientAddr.String())
		}
		if ack.CellId != verifiedReceipt.CellID || ack.SessionId != verifiedReceipt.SessionID ||
			ack.SessionIssuedAtMillis != verifiedReceipt.SessionIssuedAtMillis ||
			ack.RunID != verifiedReceipt.RunID || ack.RunAttempt != verifiedReceipt.RunAttempt {
			t.Errorf("ACK exact receipt = (%q,%d,%d,%q,%d), want verified durable receipt %+v",
				ack.CellId, ack.SessionId, ack.SessionIssuedAtMillis, ack.RunID, ack.RunAttempt, verifiedReceipt)
		}
		// The forwarded ack carries the remote AC's grant for the resolved qURL
		// tunnel resource — proves the success rode all the way back from server
		// B through NHP_FRT and into the relay-delivered ack.
		if _, ok := ack.ResourceHost[qurlplacement.TunnelServerResourceID]; !ok {
			t.Errorf("ack.ResourceHost missing %q; want the remote AC's granted resource host echoed back through the forward (ResourceHost=%v)",
				qurlplacement.TunnelServerResourceID, ack.ResourceHost)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("agent never received the decrypted relayed cross-server ack")
	}

	// ---- Assertion 3: metrics. One relay forward, zero rejects (an AC grant is
	// delivered as an ack, never a pre-auth drop).
	counters, _ := mp.CountersForTest(t)
	if got := counters[MetricRelayForward]; got != 1 {
		t.Errorf("MetricRelayForward = %v, want 1", got)
	}
	if got := counters[MetricRelayForwardReject]; got != 0 {
		t.Errorf("MetricRelayForwardReject = %v, want 0 (the cross-server forward succeeded; no pre-auth drop)", got)
	}
}

// relayCrossServerPlugin is a minimal plugins.PluginHandler standing in for the
// production agent plugin (staticplugins/agent) on the knock path. AuthWithNHP
// mirrors that plugin's load-bearing core: resolve the requested qURL tunnel
// resource off helper.AspData via the real qurlplacement.ResolveResource, then
// dispatch through helper.AuthWithNhpCallbackFunc (= handleNhpOpenResource,
// where the cross-server NHP_FWD happens). It is registered ONLY in the test's
// own pluginHandlerMap, so — unlike importing staticplugins/agent — it adds no
// entry to the global plugin registry and cannot perturb other tests. Every
// other PluginHandler method is inert: the relay knock path only calls
// AuthWithNHP.
type relayCrossServerPlugin struct{}

func (p *relayCrossServerPlugin) Version() string                        { return "test" }
func (p *relayCrossServerPlugin) Signature() string                      { return "" }
func (p *relayCrossServerPlugin) ExportedData() *plugins.PluginParamsOut { return nil }
func (p *relayCrossServerPlugin) Init(*plugins.PluginParamsIn) error     { return nil }
func (p *relayCrossServerPlugin) Close() error                           { return nil }

func (p *relayCrossServerPlugin) RequestOTP(*common.NhpOTPRequest, *plugins.NhpServerPluginHelper) error {
	return plugins.ErrPluginNotRegistered
}

func (p *relayCrossServerPlugin) RegisterAgent(*common.NhpRegisterRequest, *plugins.NhpServerPluginHelper) (*common.ServerRegisterAckMsg, error) {
	return nil, plugins.ErrPluginNotRegistered
}

func (p *relayCrossServerPlugin) ListService(*common.NhpListRequest, *plugins.NhpServerPluginHelper) (*common.ServerListResultMsg, error) {
	return nil, plugins.ErrPluginNotRegistered
}

func (p *relayCrossServerPlugin) AuthWithHttp(*gin.Context, *common.HttpKnockRequest, *plugins.HttpServerPluginHelper) (*common.ServerKnockAckMsg, error) {
	return nil, plugins.ErrPluginNotRegistered
}

func (p *relayCrossServerPlugin) AuthWithNHP(req *common.NhpAuthRequest, helper *plugins.NhpServerPluginHelper) (*common.ServerKnockAckMsg, error) {
	ackMsg := req.Ack
	if helper == nil || helper.AspData == nil || helper.AuthWithNhpCallbackFunc == nil {
		ackMsg.ErrCode = common.ErrInvalidInput.ErrorCode()
		ackMsg.ErrMsg = "relayCrossServerPlugin: helper/AspData/callback not wired"
		return ackMsg, common.ErrInvalidInput
	}
	res := qurlplacement.ResolveResource(req.Msg.ResourceId, qurlplacement.Identity{
		PublicKey: req.PublicKey,
		UserID:    req.Msg.UserId,
	}, helper.AspData)
	if res == nil {
		ackMsg.ErrCode = common.ErrResourceNotFound.ErrorCode()
		ackMsg.ErrMsg = common.ErrResourceNotFound.Error()
		return ackMsg, common.ErrResourceNotFound
	}
	ackMsg.OpenTime = res.OpenTime
	return helper.AuthWithNhpCallbackFunc(req, res)
}

// relayServerBForwarderDeps is server B's ForwarderDeps in the cross-server
// relay e2e. It reuses mockACForwarderDeps for the AC-side behavior
// (ProcessACOperation against the mock AC over the socket, resource/ASP
// resolution) but overrides SendMessage to TRANSMIT the NHP_FRT result back to
// server A. mockACForwarderDeps.SendMessage only captures the result for the
// direct FullACFlow test (#2654); on the composed path server A must actually
// receive the NHP_FRT to complete its ForwardKnock.
type relayServerBForwarderDeps struct {
	*mockACForwarderDeps
	verifiedReceiptCh chan<- common.AgentSessionReceipt
}

func (d *relayServerBForwarderDeps) VerifyForwardedDurableNHPSession(ctx context.Context,
	knkMsg *common.AgentKnockMsg,
) (common.AgentSessionReceipt, error) {
	receipt, err := d.mockACForwarderDeps.VerifyForwardedDurableNHPSession(ctx, knkMsg)
	if err == nil && d.verifiedReceiptCh != nil {
		select {
		case d.verifiedReceiptCh <- receipt:
		default:
		}
	}
	return receipt, err
}

func (d *relayServerBForwarderDeps) SendMessage(md *core.MsgData) error {
	// sendForwardResult sets md.PrevParserData = the NHP_FWD ppd, which overrides
	// ConnData/RemoteAddr/PeerPk/CipherScheme/TransactionId (see initiator.go), so
	// the NHP_FRT routes back to server A over the connection server B accepted the
	// NHP_FWD on. The response is re-derived from the ppd's retained fields, so it
	// is valid even though PacketToMsg already Destroyed the ppd's base packet.
	d.serverNode.device.SendMsgToPacket(md)
	return nil
}

// crossServerForwarderDeps is the ForwarderDeps for server A's ServerForwarder
// in the cross-server relay e2e. It only needs to (a) expose server A's device
// and hostname and (b) transmit the NHP_FWD over server A's real socket — the
// getOrCreateServerPeer / pending-transaction machinery in ServerForwarder does
// the rest, and the NHP_FRT comes back through server A's E2E recv loop. The AC
// / ASP / token methods are never reached on the forwarding (originating) side,
// so they are inert. Mirrors e2eForwarderDeps.SendMessage.
type crossServerForwarderDeps struct {
	testForwardedSessionDeps
	node *E2ETestNode
}

func (d *crossServerForwarderDeps) GetHostname() string     { return d.node.id }
func (d *crossServerForwarderDeps) GetDevice() *core.Device { return d.node.device }

func (d *crossServerForwarderDeps) SendMessage(md *core.MsgData) error {
	// This E2E transport double writes packets directly, so it mirrors
	// production UdpServer.connDataForOutboundAddr by creating the test socket
	// connection before the encrypted NHP_FWD leaves server A.
	if md.ConnData == nil && md.RemoteAddr != nil {
		md.ConnData = d.node.GetOrCreateConnection(md.RemoteAddr)
	}
	d.node.device.SendMsgToPacket(md)
	return nil
}

func (d *crossServerForwarderDeps) IncrForwarderMetric(string) {}

func (d *crossServerForwarderDeps) FindACConnectionsForResource(*common.AgentKnockMsg, *common.ResourceData) []*ACConn {
	return nil
}

func (d *crossServerForwarderDeps) FindAuthSvcProvider(string) *common.AuthServiceProviderData {
	return nil
}

func (d *crossServerForwarderDeps) ResolveAuthSvcProvider(context.Context, string, string) *common.AuthServiceProviderData {
	return nil
}

func (d *crossServerForwarderDeps) LifecycleCtx() context.Context { return context.Background() }

func (d *crossServerForwarderDeps) ProcessACOperation(*common.AgentKnockMsg, *ACConn, *common.NetAddress, []*common.NetAddress, uint32, *common.ResourceData) (*common.ACOpsResultMsg, error) {
	return nil, nil
}

func (d *crossServerForwarderDeps) ProcessACOperationBroadcast(context.Context, *common.AgentKnockMsg, []*ACConn, *common.NetAddress, []*common.NetAddress, uint32, *common.ResourceData) (*common.ACOpsResultMsg, error) {
	return nil, nil
}

func (d *crossServerForwarderDeps) PublishACKTokens(context.Context, *common.AgentKnockMsg, *common.ServerKnockAckMsg, string, int, string) error {
	return nil
}

func (d *crossServerForwarderDeps) ResolveOwnerIDByPubKey(context.Context, string) string { return "" }
