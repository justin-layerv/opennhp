package server

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
)

// TestCoverageGap948_AdmissionReachesOnlyLocallyConnectedACs is an EMPIRICAL
// reproduction of the qurl-service #948 firewall-coverage gap, exercising the
// real production code paths (snapshotLiveACConns + processACOperationBroadcast)
// with no behavioral mocks.
//
// Production topology (sandbox): the qurl.site AC fleet is N instances, all
// sharing one acId ("${env}-ac" — terraform modules/ac/main.tf), behind an AC
// NLB with cross-zone balancing and NO stickiness. A viewer's GET 5-tuple-hashes
// across the WHOLE fleet. But a knock handled by one nhp-server opens pinholes
// only on the ACs in THAT server's per-server acConnectionMap; there is no
// server-to-server AOP fan-out (only NHP_REV revocation fans out cell-wide via
// snapshotAllACConnections). So an AC that is a healthy NLB target — but is
// connected to a different server, or is mid-re-registration during a deploy
// roll — never receives the admission AOP and has no pinhole. The viewer GET
// the NLB hashes to it is silently dropped: the 30s "awaiting headers" timeout
// observed in CI run 28457942476 (GET1 -> 200 on a covered AC, GET2 -> 30s hang
// on an uncovered AC, both inside the same still-open 60s L3 window).
//
// This test pins that mechanism — it shows the handler's local AC-selection call
// (snapshotLiveACConns + processACOperationBroadcast) structurally cannot see an
// AC on another server, so the local broadcast alone writes a pinhole on every
// locally-connected AC EXCEPT that one. That local-only scope is exactly why the
// handlers add a cross-server fan-out under Config.EnableKnockACFanout (proven by
// TestFanoutHttpKnock_* / TestFanoutKnock_*). The target-set characterization is
// independent of that flag.
func TestCoverageGap948_AdmissionReachesOnlyLocallyConnectedACs(t *testing.T) {
	s, sendCh := newTestServerForBroadcast(t)
	// Enable only the local wait-for-all timing so PROOF 2 can assert after
	// every local AC reports. This direct broadcast call does not exercise the
	// cross-server fan-out half of the flag; gamma remains absent from this
	// server's map either way.
	s.config = &Config{EnableKnockACFanout: true}

	const acId = "sandbox-ac" // all qurl.site AC instances share one acId

	// Three AC instances in the qurl.site NLB target group, all sharing acId.
	// alpha + beta are connected to THIS knock-handling server; gamma is a
	// healthy NLB target connected to a DIFFERENT server (or mid-re-register),
	// so it is absent from this server's per-server connection map.
	const alphaAddr, betaAddr, gammaAddr = "10.0.0.1:62206", "10.0.0.2:62206", "10.0.0.3:62206"
	acAlpha := newTestACConn(t, "10.0.0.1", 62206, acId)
	acBeta := newTestACConn(t, "10.0.0.2", 62206, acId)
	_ = newTestACConn(t, "10.0.0.3", 62206, acId) // gamma exists in the fleet; NOT registered here

	// Mark alpha + beta as freshly keepalived so they survive the
	// staleness filter in snapshotLiveACConns (gamma is simply absent from
	// this server's map — it is connected to a different server).
	now := time.Now().UnixNano()
	atomic.StoreInt64(&acAlpha.ConnData.LastLocalRecvTime, now)
	atomic.StoreInt64(&acBeta.ConnData.LastLocalRecvTime, now)

	s.acConnectionMap[acId] = []*ACConn{acAlpha, acBeta}

	// Record which AC each NHP_AOP is addressed to, keyed by the AC's recv addr.
	var mu sync.Mutex
	var bothObserved sync.Once
	bothLocalAOPs := make(chan struct{})
	gotAOP := make(map[string]bool)
	go func() {
		for md := range sendCh {
			addr := md.ConnData.RemoteAddr.String()
			mu.Lock()
			gotAOP[addr] = true
			if gotAOP[alphaAddr] && gotAOP[betaAddr] {
				bothObserved.Do(func() { close(bothLocalAOPs) })
			}
			mu.Unlock()
			art := &common.ACOpsResultMsg{ErrCode: common.ErrSuccess.ErrorCode()}
			body, _ := json.Marshal(art)
			md.ResponseMsgCh <- &core.PacketParserData{HeaderType: core.NHP_ART, BodyMessage: body}
		}
	}()

	// The exact call the knock handler makes to choose AOP targets
	// (httpserver.go handleHttpOpenResource / udpserver.go handleNhpOpenResource).
	conns, _ := s.snapshotLiveACConns(acId)

	// PROOF 1 — the per-server snapshot structurally cannot see gamma. The
	// handler has no cross-server view, so it will never address an AOP to it.
	if len(conns) != 2 {
		t.Fatalf("snapshotLiveACConns(%q) = %d conns, want 2: the per-server map cannot see an AC connected to another server", acId, len(conns))
	}

	// Drive the real broadcast the knock path uses (viewer src, qURL 0.0.0.0
	// destination sentinel that each AC localizes to its own IP, 60s openTime).
	knk := &common.AgentKnockMsg{UserId: "viewer", ResourceId: "r_wge3dw4z_t4"}
	srcAddr := &common.NetAddress{Ip: "20.169.72.19", Port: 443}
	dstAddrs := []*common.NetAddress{{Ip: "0.0.0.0", Port: 443}}
	if _, err := s.processACOperationBroadcast(context.Background(), knk, conns, srcAddr, dstAddrs, 60, nil); err != nil {
		t.Fatalf("broadcast returned error: %v", err)
	}
	// processACOperationBroadcast has returned, so its target loop has enqueued
	// any AOPs it will send; wait for the collector goroutine to catch up before
	// asserting the negative gamma case.
	select {
	case <-bothLocalAOPs:
	case <-time.After(2 * time.Second):
		mu.Lock()
		t.Logf("timed out waiting for both local AOP collector observations; continuing to existing assertions with gotAOP=%v", gotAOP)
		mu.Unlock()
	}

	waitForAOPs := func(addrs ...string) map[string]bool {
		t.Helper()

		deadline := time.Now().Add(500 * time.Millisecond)
		for {
			mu.Lock()
			snapshot := make(map[string]bool, len(gotAOP))
			for addr, seen := range gotAOP {
				snapshot[addr] = seen
			}
			mu.Unlock()

			allSeen := true
			for _, addr := range addrs {
				if !snapshot[addr] {
					allSeen = false
					break
				}
			}
			if allSeen || time.Now().After(deadline) {
				return snapshot
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	got := waitForAOPs(alphaAddr, betaAddr)

	// PROOF 2 — the two locally-connected ACs got the pinhole AOP (GET1's AC).
	if !got[alphaAddr] || !got[betaAddr] {
		t.Fatalf("expected pinhole AOP on both locally-connected ACs; got %v", got)
	}

	// PROOF 3 — gamma, a healthy AC NLB target the viewer GET can be hashed to,
	// received NO admission AOP and therefore has no pinhole. The GET the NLB
	// routes to gamma is dropped for the full client timeout. This is the #948
	// coverage gap, reproduced against real server code.
	if got[gammaAddr] {
		t.Fatalf("gamma unexpectedly received an AOP — the coverage gap did not reproduce")
	}
	t.Logf("COVERAGE GAP REPRODUCED: knock opened pinholes on %d/3 fleet ACs (alpha,beta); "+
		"gamma is an NLB-routable AC with NO pinhole -> viewer GET hashed to gamma drops (qurl-service #948)", len(conns))
}

// TestKnockACFanout_BroadcastWaitsForAllLocalACs proves the LOCAL half of the
// #948 fix: with EnableKnockACFanout the broadcast must not ack until every
// locally-connected AC has written its pinhole (so the ack → 302 → GET cannot
// race a still-in-flight sibling AC), whereas the legacy path acks on the first
// success. A deliberately slow third AC makes the difference deterministic.
func TestKnockACFanout_BroadcastWaitsForAllLocalACs(t *testing.T) {
	for _, tc := range []struct {
		name          string
		flagOn        bool
		wantSlowByAck bool // must the slow AC's pinhole be written by the time the ack returns?
	}{
		{"flag_off_returns_on_first_success", false, false},
		{"flag_on_waits_for_all_acs", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, sendCh := newTestServerForBroadcast(t)
			if tc.flagOn {
				s.config = &Config{EnableKnockACFanout: true}
			}

			const slowAddr = "10.0.0.3:62206"
			var slowWritten atomic.Bool
			var allDone sync.WaitGroup
			allDone.Add(3)
			go func() {
				for md := range sendCh {
					go func(md *core.MsgData) {
						defer allDone.Done()
						if md.ConnData.RemoteAddr.String() == slowAddr {
							time.Sleep(80 * time.Millisecond) // slow AC: pinhole written late
							slowWritten.Store(true)
						}
						art := &common.ACOpsResultMsg{ErrCode: common.ErrSuccess.ErrorCode()}
						body, _ := json.Marshal(art)
						md.ResponseMsgCh <- &core.PacketParserData{HeaderType: core.NHP_ART, BodyMessage: body}
					}(md)
				}
			}()

			conns := []*ACConn{
				newTestACConn(t, "10.0.0.1", 62206, "sandbox-ac"),
				newTestACConn(t, "10.0.0.2", 62206, "sandbox-ac"),
				newTestACConn(t, "10.0.0.3", 62206, "sandbox-ac"),
			}
			knk := &common.AgentKnockMsg{UserId: "viewer"}
			srcAddr := &common.NetAddress{Ip: "20.169.72.19", Port: 443}
			dstAddrs := []*common.NetAddress{{Ip: "0.0.0.0", Port: 443}}

			artMsg, err := s.processACOperationBroadcast(context.Background(), knk, conns, srcAddr, dstAddrs, 60, nil)
			gotSlowByAck := slowWritten.Load()

			if err != nil {
				t.Fatalf("expected success, got %v", err)
			}
			if artMsg == nil || artMsg.ErrCode != common.ErrSuccess.ErrorCode() {
				t.Fatalf("expected success artMsg, got %+v", artMsg)
			}
			if gotSlowByAck != tc.wantSlowByAck {
				t.Fatalf("slow AC pinhole-written-by-ack = %v, want %v (EnableKnockACFanout=%v): "+
					"flag ON must wait for every local AC before acking; flag OFF returns on first success",
					gotSlowByAck, tc.wantSlowByAck, tc.flagOn)
			}
			allDone.Wait() // no goroutine/channel leak in either mode
		})
	}
}

// TestFanoutHttpKnock_ReachesEveryAssignedPeer proves the cross-server half of
// the #948 fix on the HTTP qURL path: FanoutHttpKnock forwards to EVERY healthy
// assigned peer (self excluded), versus the legacy ForwardHttpKnock which stops
// at the first success. Each forward targets InternalIP:httpPort, so one
// httptest peer on that port counts the fan-out.
func TestFanoutHttpKnock_ReachesEveryAssignedPeer(t *testing.T) {
	var hits atomic.Int32
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_ = json.NewEncoder(w).Encode(HttpKnockForwardResponse{
			AckMsg: &common.ServerKnockAckMsg{ErrCode: common.ErrSuccess.ErrorCode()},
		})
	}))
	defer peer.Close()
	_, portStr, _ := net.SplitHostPort(peer.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)

	storage := newMockStorageBackend()
	storage.assignments["sandbox-ac"] = &ACAssignment{
		ACID: "sandbox-ac",
		AssignedServers: []ServerInfo{
			{ID: "self", InternalIP: "10.0.0.9", Port: port},    // self — must be excluded
			{ID: "peer-1", InternalIP: "127.0.0.1", Port: port}, // → the httptest peer
			{ID: "peer-2", InternalIP: "127.0.0.1", Port: port},
			{ID: "peer-3", InternalIP: "127.0.0.1", Port: port},
		},
	}
	newF := func() *HttpKnockForwarder {
		return &HttpKnockForwarder{
			storage:       storage,
			localIP:       "10.0.0.9", // self
			httpPort:      port,
			httpClient:    &http.Client{Timeout: 2 * time.Second},
			failedServers: make(map[string]time.Time),
		}
	}

	// Legacy first-success forward hits exactly ONE peer.
	hits.Store(0)
	if _, _, err := newF().ForwardHttpKnock(context.Background(), "sandbox-ac", &common.HttpKnockRequest{}, &common.ResourceData{}); err != nil {
		t.Fatalf("ForwardHttpKnock error: %v", err)
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("legacy forward must hit exactly one peer (first-success), hit %d", got)
	}

	// Cell-wide fan-out hits EVERY assigned peer (self excluded).
	hits.Store(0)
	accepted, err := newF().FanoutHttpKnock(context.Background(), "sandbox-ac",
		&common.HttpKnockRequest{Forwarded: true}, &common.ResourceData{})
	if err != nil {
		t.Fatalf("FanoutHttpKnock error: %v", err)
	}
	if got := hits.Load(); got != 3 {
		t.Fatalf("fan-out must reach all 3 assigned peers (self excluded), hit %d", got)
	}
	if accepted != 3 {
		t.Fatalf("FanoutHttpKnock peersAccepted = %d, want 3", accepted)
	}
}

// TestFanoutKnock_ReachesEveryNonSelfHealthyPeer proves the cross-server half of
// the #948 fix on the native/relay NHP_FWD path: FanoutKnock sends an NHP_FWD to
// every healthy assigned peer, excluding self and recently-failed peers. Each
// forwardToServer records its NHP_FWD send via the mock before blocking on the
// (absent) NHP_FRT, so a short deadline keeps the test fast; the send count is
// the coverage proof.
func TestFanoutKnock_ReachesEveryNonSelfHealthyPeer(t *testing.T) {
	device := core.NewDevice(core.NHP_SERVER, testPrivateKey(), nil)
	if device == nil {
		t.Fatal("failed to create device")
	}
	defer device.Stop()

	deps := NewMockForwarderDeps()
	deps.SetDevice(device)
	deps.sendCh = make(chan *core.MsgData, 16)
	f := NewServerForwarder(deps)

	pub := device.PublicKeyBase64()
	assignment := &ACAssignment{
		ACID: "sandbox-ac",
		AssignedServers: []ServerInfo{
			{ID: "self", InternalIP: "10.0.0.9", Port: common.DefaultNHPPort, PubKey: pub},      // self — excluded
			{ID: "peer-1", InternalIP: "10.0.0.1", Port: common.DefaultNHPPort, PubKey: pub},    // healthy
			{ID: "peer-2", InternalIP: "10.0.0.2", Port: common.DefaultNHPPort, PubKey: pub},    // healthy
			{ID: "peer-dead", InternalIP: "10.0.0.3", Port: common.DefaultNHPPort, PubKey: pub}, // unhealthy — skipped
		},
	}
	f.health.RecordFailure("peer-dead")

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	_ = f.FanoutKnock(ctx, assignment, "10.0.0.9", []byte("knock"),
		&net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 54321}, nil)

	// FanoutKnock waited for all forwardToServer goroutines, so every send is
	// recorded by now. Count the NHP_FWD sends.
	close(deps.sendCh)
	sent := 0
	for md := range deps.sendCh {
		if md.HeaderType == core.NHP_FWD {
			sent++
		}
	}
	if sent != 2 {
		t.Fatalf("fan-out sent %d NHP_FWD messages, want 2 (self excluded, unhealthy peer skipped)", sent)
	}
}

// TestHandleHttpOpenResource_FanoutFiresAlongsideLocalBroadcast is the handler-
// level integration test for the #948 fix on the qURL path: with
// EnableKnockACFanout on, an origin knock both runs its local broadcast AND fans
// the knock out to the assigned peer servers, and the handler blocks on the
// fan-out (defer fanoutWg.Wait) before acking. Runs under -race to fence the
// concurrent fan-out + broadcast goroutines on the hot path.
func TestHandleHttpOpenResource_FanoutFiresAlongsideLocalBroadcast(t *testing.T) {
	const acId, resName = "sandbox-ac", "r_fanout"

	var fanoutHits atomic.Int32
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fanoutHits.Add(1)
		_ = json.NewEncoder(w).Encode(HttpKnockForwardResponse{
			AckMsg: &common.ServerKnockAckMsg{ErrCode: common.ErrSuccess.ErrorCode()},
		})
	}))
	defer peer.Close()
	_, portStr, _ := net.SplitHostPort(peer.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)

	storage := newMockStorageBackend()
	storage.assignments[acId] = &ACAssignment{
		ACID: acId,
		AssignedServers: []ServerInfo{
			{ID: "self", InternalIP: "10.0.0.99", Port: port}, // self — excluded
			{ID: "peer-1", InternalIP: "127.0.0.1", Port: port},
		},
	}

	var localBroadcast atomic.Bool
	us := &UdpServer{
		tokenStore: common.NewTokenStore[*ACTokenEntry](),
		config:     &Config{EnableKnockACFanout: true},
		storage:    storage,
		acConnectionMap: map[string][]*ACConn{
			acId: {newACConnWithLastRecv(time.Now().UnixNano())},
		},
		processACOperationBroadcastFn: func(_ context.Context, _ *common.AgentKnockMsg, _ []*ACConn, _ *common.NetAddress, _ []*common.NetAddress, openTime uint32, _ *common.ResourceData) (*common.ACOpsResultMsg, error) {
			localBroadcast.Store(true)
			return &common.ACOpsResultMsg{ErrCode: common.ErrSuccess.ErrorCode(), ACToken: "tok", OpenTime: openTime}, nil
		},
	}
	hs := &HttpServer{
		udpServer: us,
		httpForwarder: &HttpKnockForwarder{
			storage:       storage,
			localIP:       "10.0.0.99", // self — distinct from the 127.0.0.1 peer
			httpPort:      port,
			httpClient:    &http.Client{Timeout: 2 * time.Second},
			failedServers: make(map[string]time.Time),
		},
	}

	req := &common.HttpKnockRequest{
		UserId: "u", DeviceId: "d", AuthServiceId: "asp", ResourceId: resName,
		SrcIp: "203.0.113.77", Ctx: context.Background(),
	}
	res := &common.ResourceData{
		ResourceGroup: common.ResourceGroup{
			ResourceId: resName,
			OpenTime:   60,
			Resources: map[string]*common.ResourceInfo{
				resName: {ACId: acId, Addr: &common.NetAddress{Ip: "10.0.0.7", Port: 443}},
			},
		},
	}

	ack, err := hs.handleHttpOpenResource(req, res)
	if err != nil {
		t.Fatalf("handleHttpOpenResource error: %v", err)
	}
	if ack.ErrCode != common.ErrSuccess.ErrorCode() {
		t.Fatalf("ack ErrCode = %q, want success", ack.ErrCode)
	}
	if !localBroadcast.Load() {
		t.Error("local broadcast did not fire (the origin must still open its own ACs)")
	}
	// The handler must have blocked on the fan-out before returning, so the peer
	// forward is already counted (self excluded).
	if got := fanoutHits.Load(); got != 1 {
		t.Fatalf("fan-out forward to peer = %d, want 1 (handler must fan out to peers AND wait before acking)", got)
	}
}
