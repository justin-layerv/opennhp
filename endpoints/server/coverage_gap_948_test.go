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

// TestKnockACFanout_BroadcastWaitsForAllLocalACs proves the local half of the
// #948 fix: with EnableKnockACFanout the broadcast must not ack until every
// selected local AC has written its pinhole (so the ack -> 302 -> GET cannot
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

// TestFanoutHttpKnock_ReachesOnePeerPerNonLocalAZ proves the cross-server half
// of the #948 fix on the HTTP qURL path: FanoutHttpKnock forwards to one healthy
// assigned peer per non-local AZ, versus the legacy ForwardHttpKnock which stops
// at the first success. Each forward targets InternalIP:httpPort, so one
// httptest peer on that port counts the bounded fan-out.
func TestFanoutHttpKnock_ReachesOnePeerPerNonLocalAZ(t *testing.T) {
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
			{ID: "self", InternalIP: "10.0.0.9", AZ: "us-east-2a", Port: port},
			{ID: "peer-same-az", InternalIP: "127.0.0.1", AZ: "us-east-2a", Port: port},
			{ID: "peer-b-1", InternalIP: "127.0.0.1", AZ: "us-east-2b", Port: port},
			{ID: "peer-b-2", InternalIP: "127.0.0.1", AZ: "us-east-2b", Port: port},
			{ID: "peer-c", InternalIP: "127.0.0.1", AZ: "us-east-2c", Port: port},
		},
	}
	newF := func() *HttpKnockForwarder {
		return &HttpKnockForwarder{
			storage:       storage,
			localIP:       "10.0.0.9",
			httpPort:      port,
			httpClient:    &http.Client{Timeout: 2 * time.Second},
			failedServers: make(map[string]time.Time),
		}
	}

	hits.Store(0)
	if _, _, err := newF().ForwardHttpKnock(context.Background(), "sandbox-ac", &common.HttpKnockRequest{}, &common.ResourceData{}); err != nil {
		t.Fatalf("ForwardHttpKnock error: %v", err)
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("legacy forward must hit exactly one peer (first-success), hit %d", got)
	}

	hits.Store(0)
	accepted, err := newF().FanoutHttpKnock(context.Background(), "sandbox-ac",
		&common.HttpKnockRequest{Forwarded: true}, &common.ResourceData{})
	if err != nil {
		t.Fatalf("FanoutHttpKnock error: %v", err)
	}
	if got := hits.Load(); got != 2 {
		t.Fatalf("fan-out hit %d peers, want 2 (one per non-local AZ)", got)
	}
	if accepted != 2 {
		t.Fatalf("FanoutHttpKnock peersAccepted = %d, want 2", accepted)
	}
}

func TestFilterFanoutTargets_SelectsOnePeerPerAZAndIgnoresRecentlyFailedPeers(t *testing.T) {
	metrics := make(map[string]int)
	f := NewHttpKnockForwarder(newMockStorageBackend(), nil, "10.0.0.1", 8888, func(name string) {
		metrics[name]++
	}, nil)
	f.markFailed("10.0.0.2")

	servers := []ServerInfo{
		{ID: "self", InternalIP: "10.0.0.1", AZ: "us-east-2a"},
		{ID: "peer-same-az", InternalIP: "10.0.0.9", AZ: "us-east-2a"},
		{ID: "peer-stale-failed", InternalIP: "10.0.0.2", AZ: "us-east-2b"},
		{ID: "peer-b-duplicate", InternalIP: "10.0.0.4", AZ: "us-east-2b"},
		{ID: "peer-fresh", InternalIP: "10.0.0.3", AZ: "us-east-2c"},
		{ID: "peer-unknown-1", InternalIP: "10.0.0.5"},
		{ID: "peer-unknown-2", InternalIP: "10.0.0.6"},
	}

	result := f.filterFanoutTargets(context.Background(), servers)
	if len(result) != 3 {
		t.Fatalf("fanout targets = %d, want 3 (AZ b, AZ c, one unknown-AZ bucket)", len(result))
	}
	got := map[string]bool{}
	for _, srv := range result {
		got[srv.ID] = true
	}
	if !got["peer-stale-failed"] || !got["peer-fresh"] || !got["peer-unknown-1"] {
		t.Fatalf("fanout targets omitted expected AZ bucket after stale failure cache: got %v", got)
	}
	if got["peer-same-az"] || got["peer-b-duplicate"] || got["peer-unknown-2"] {
		t.Fatalf("fanout targets were not bounded to one per non-local AZ: got %v", got)
	}
	if metrics[MetricKnockFanoutDuplicateAZCandidate] != 2 {
		t.Fatalf("%s metric = %d, want 2 duplicate non-local AZ buckets", MetricKnockFanoutDuplicateAZCandidate, metrics[MetricKnockFanoutDuplicateAZCandidate])
	}
}

func TestSelectAssignedFanoutTargetsByAZ_BoundedUnderLargeAssignments(t *testing.T) {
	servers := make([]ServerInfo, 0, 10001)
	servers = append(servers, ServerInfo{ID: "self", InternalIP: "10.0.0.1", AZ: "us-east-2a"})
	for i := 0; i < 10000; i++ {
		az := "us-east-2b"
		if i%3 == 1 {
			az = "us-east-2c"
		} else if i%3 == 2 {
			az = ""
		}
		servers = append(servers, ServerInfo{
			ID:         "peer-" + strconv.Itoa(i),
			InternalIP: "10.1.0." + strconv.Itoa(i%250+1),
			AZ:         az,
		})
	}

	targets := selectAssignedFanoutTargetsByAZ(servers, "10.0.0.1")
	if len(targets) != 3 {
		t.Fatalf("selected %d fanout targets from 10k peers, want 3 bounded AZ buckets", len(targets))
	}
	if targets[0].AZ != "us-east-2b" || targets[1].AZ != "us-east-2c" || targets[2].AZ != "" {
		t.Fatalf("fanout targets = %+v, want first peer in AZ b, AZ c, and one unknown-AZ bucket", targets)
	}
}

func TestSelectAssignedFanoutTargetsByAZWithHealth_PrefersNonFailedPeerWithinAZ(t *testing.T) {
	servers := []ServerInfo{
		{ID: "self", InternalIP: "10.0.0.1", AZ: "us-east-2a"},
		{ID: "peer-b-failed", InternalIP: "10.0.1.1", AZ: "us-east-2b"},
		{ID: "peer-b-healthy", InternalIP: "10.0.1.2", AZ: "us-east-2b"},
		{ID: "peer-c-failed", InternalIP: "10.0.2.1", AZ: "us-east-2c"},
		{ID: "peer-unknown-failed", InternalIP: "10.0.3.1"},
		{ID: "peer-unknown-healthy", InternalIP: "10.0.3.2"},
	}
	failed := map[string]bool{
		"peer-b-failed":       true,
		"peer-c-failed":       true,
		"peer-unknown-failed": true,
	}

	targets := selectAssignedFanoutTargetsByAZWithHealth(servers, "10.0.0.1", func(id string) bool {
		return failed[id]
	})

	gotIDs := make([]string, 0, len(targets))
	for _, target := range targets {
		gotIDs = append(gotIDs, target.ID)
	}
	wantIDs := []string{"peer-b-healthy", "peer-c-failed", "peer-unknown-healthy"}
	if len(gotIDs) != len(wantIDs) {
		t.Fatalf("selected targets = %v, want %v", gotIDs, wantIDs)
	}
	for i := range wantIDs {
		if gotIDs[i] != wantIDs[i] {
			t.Fatalf("selected targets = %v, want %v", gotIDs, wantIDs)
		}
	}
}

// TestFanoutKnock_ReachesOnePeerPerNonLocalAZ proves the cross-server half of
// the #948 fix on the native/relay NHP_FWD path: FanoutKnock sends NHP_FWD to
// one assigned peer per non-local AZ, excluding self and same-AZ peers but not
// suppressing an AZ when its only candidate was recently failed. Each
// forwardToServer records its NHP_FWD send via the mock before blocking on the
// absent NHP_FRT, so a short deadline keeps the test fast; the send count is
// the coverage proof.
func TestFanoutKnock_ReachesOnePeerPerNonLocalAZ(t *testing.T) {
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
			{ID: "self", InternalIP: "10.0.0.9", AZ: "us-east-2a", Port: common.DefaultNHPPort, PubKey: pub},
			{ID: "peer-same-az", InternalIP: "10.0.0.8", AZ: "us-east-2a", Port: common.DefaultNHPPort, PubKey: pub},
			{ID: "peer-b", InternalIP: "10.0.0.1", AZ: "us-east-2b", Port: common.DefaultNHPPort, PubKey: pub},
			{ID: "peer-b-duplicate", InternalIP: "10.0.0.2", AZ: "us-east-2b", Port: common.DefaultNHPPort, PubKey: pub},
			{ID: "peer-dead", InternalIP: "10.0.0.3", AZ: "us-east-2c", Port: common.DefaultNHPPort, PubKey: pub},
		},
	}
	f.health.RecordFailure("peer-dead")

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	_ = f.FanoutKnock(ctx, assignment, "10.0.0.9", []byte("knock"),
		&net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 54321}, nil)
	if got := deps.MetricCount(MetricKnockFanoutDuplicateAZCandidate); got != 1 {
		t.Fatalf("%s metric = %d, want 1 duplicate non-local AZ bucket", MetricKnockFanoutDuplicateAZCandidate, got)
	}

	close(deps.sendCh)
	sent := 0
	for md := range deps.sendCh {
		if md.HeaderType == core.NHP_FWD {
			sent++
		}
	}
	if sent != 2 {
		t.Fatalf("fan-out sent %d NHP_FWD messages, want 2 (one per non-local AZ, stale failure cache ignored)", sent)
	}
}

// TestHandleHttpOpenResource_FanoutFiresAlongsideLocalBroadcast is the handler-
// level integration test for the #948 fix on the qURL path: with
// EnableKnockACFanout on, an origin knock both runs its local broadcast AND fans
// the knock out to one assigned peer server per non-local AZ, and the handler
// blocks on the fan-out (defer fanoutWg.Wait) before acking. Runs under -race to
// fence the concurrent fan-out + broadcast goroutines on the hot path.
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
			{ID: "self", InternalIP: "10.0.0.99", AZ: "us-east-2a", Port: port},
			{ID: "peer-same-az", InternalIP: "127.0.0.1", AZ: "us-east-2a", Port: port},
			{ID: "peer-b", InternalIP: "127.0.0.1", AZ: "us-east-2b", Port: port},
			{ID: "peer-b-duplicate", InternalIP: "127.0.0.1", AZ: "us-east-2b", Port: port},
			{ID: "peer-c", InternalIP: "127.0.0.1", AZ: "us-east-2c", Port: port},
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
	// The handler must have blocked on the fan-out before returning, so the
	// bounded peer forwards are already counted.
	if got := fanoutHits.Load(); got != 2 {
		t.Fatalf("fan-out forwards = %d, want 2 (one peer per non-local AZ before ack)", got)
	}
}
