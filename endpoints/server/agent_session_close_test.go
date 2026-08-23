package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/endpoints/metrics"
	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
)

func activateTestAgentSession(t *testing.T, s *UdpServer, agentKey []byte, sessionID uint64, issuedAt, expiresAt time.Time, acID string) {
	t.Helper()
	registry := s.sessionRegistry()
	if err := registry.reserveExact(agentKey, sessionID, issuedAt, expiresAt); err != nil {
		t.Fatalf("reserve session %d: %v", sessionID, err)
	}
	if err := registry.beginOpen(sessionID, issuedAt); err != nil {
		t.Fatalf("begin session %d: %v", sessionID, err)
	}
	if err := registry.finishOpen(sessionID, issuedAt, expiresAt, expiresAt.Add(time.Duration(ACOpenCompensationTime)*time.Second), acID, true); err != nil {
		t.Fatalf("activate session %d: %v", sessionID, err)
	}
}

func addLiveTestAC(t *testing.T, s *UdpServer, acID, ip string, port int) *ACConn {
	t.Helper()
	conn := newTestACConn(t, ip, port, acID, s.device)
	atomic.StoreInt64(&conn.ConnData.LastLocalRecvTime, time.Now().UnixNano())
	s.acConnectionMap[acID] = []*ACConn{conn}
	return conn
}

func testRegistryHasSession(registry *liveNHPSessionRegistry, sessionID uint64) bool {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	_, ok := registry.sessions[sessionID]
	return ok
}

func TestAgentSessionExit_BodylessRequiresNegotiatedAuthenticatedHeaderProfile(t *testing.T) {
	s, sendCh := newTestServerForBroadcast(t)
	agentKey := bytes.Repeat([]byte{0x41}, core.PublicKeySize)
	issuedAt := time.Now().Add(-time.Second)
	activateTestAgentSession(t, s, agentKey, 101, issuedAt, time.Now().Add(time.Minute), "ac-a")
	addLiveTestAC(t, s, "ac-a", "10.0.0.1", 62206)

	var closeCalls atomic.Int32
	s.processACSessionCloseFn = func(_ context.Context, sessionID uint64, conn *ACConn) error {
		closeCalls.Add(1)
		if sessionID != 101 || conn.ACId != "ac-a" {
			t.Errorf("close target = session %d AC %q, want session 101 AC ac-a", sessionID, conn.ACId)
		}
		return nil
	}

	if err := s.HandleAgentSessionExit(&core.PacketParserData{
		HeaderType:   core.NHP_EXT,
		RemotePubKey: agentKey,
	}); err == nil {
		t.Fatal("bodyless agent-global EXT was accepted on the unkeyed 1.1 envelope")
	}
	if got := closeCalls.Load(); got != 0 {
		t.Fatalf("rejected bodyless EXT changed close calls to %d", got)
	}
	if !testRegistryHasSession(s.sessionRegistry(), 101) {
		t.Fatal("rejected bodyless EXT removed the live session")
	}
	select {
	case md := <-sendCh:
		t.Fatalf("direct bodyless handler emitted a response: header=%s", core.HeaderTypeToString(md.HeaderType))
	default:
	}
}

func TestAgentSessionExit_LocalCloseRetriesWithoutDiscardingState(t *testing.T) {
	s, _ := newTestServerForBroadcast(t)
	s.metrics = metrics.NewPublisherForTest(t)
	agentKey := bytes.Repeat([]byte{0x42}, core.PublicKeySize)
	issuedAt := time.Now().Add(-time.Second)
	activateTestAgentSession(t, s, agentKey, 202, issuedAt, time.Now().Add(time.Minute), "ac-retry")
	addLiveTestAC(t, s, "ac-retry", "10.0.0.2", 62206)

	var attempts atomic.Int32
	s.processACSessionCloseFn = func(context.Context, uint64, *ACConn) error {
		if attempts.Add(1) == 1 {
			return errors.New("transient AC close failure")
		}
		return nil
	}
	s.closeAgentSessionsLocal(context.Background(), agentKey, time.Now())
	if got := attempts.Load(); got != 2 {
		t.Fatalf("close attempts = %d, want 2", got)
	}
	if testRegistryHasSession(s.sessionRegistry(), 202) {
		t.Fatal("session remained after retry succeeded")
	}
	counters, _ := s.metrics.CountersForTest(t)
	if counters[MetricAgentSessionCloseLocalRetry] != 1 || counters[MetricAgentSessionCloseLocalSuccess] != 1 {
		t.Fatalf("retry/success metrics = %v/%v, want 1/1", counters[MetricAgentSessionCloseLocalRetry], counters[MetricAgentSessionCloseLocalSuccess])
	}

	issuedAt = time.Now().Add(agentSessionCloseFutureSkew)
	activateTestAgentSession(t, s, agentKey, 203, issuedAt, time.Now().Add(time.Minute), "ac-retry")
	attempts.Store(0)
	s.processACSessionCloseFn = func(context.Context, uint64, *ACConn) error {
		attempts.Add(1)
		return errors.New("persistent AC close failure")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 260*time.Millisecond)
	s.closeAgentSessionsLocal(ctx, agentKey, time.Now())
	cancel()
	if got := attempts.Load(); got < 2 {
		t.Fatalf("bounded close attempts = %d, want at least 2 before deadline", got)
	}
	if !testRegistryHasSession(s.sessionRegistry(), 203) {
		t.Fatal("failed close discarded retryable session state")
	}

	s.processACSessionCloseFn = func(context.Context, uint64, *ACConn) error { return nil }
	s.closeAgentSessionsLocal(context.Background(), agentKey, time.Now())
	if testRegistryHasSession(s.sessionRegistry(), 203) {
		t.Fatal("retained session did not close on a later retry")
	}
}

func TestAgentSessionExit_OneRequestWaitsForDelayedInFlightOpen(t *testing.T) {
	s, _ := newTestServerForBroadcast(t)
	agentKey := bytes.Repeat([]byte{0x62}, core.PublicKeySize)
	issuedAt := time.Now()
	sessionExpiresAt := issuedAt.Add(time.Minute)
	registry := s.sessionRegistry()
	if err := registry.reserveExact(agentKey, 205, issuedAt, sessionExpiresAt); err != nil {
		t.Fatal(err)
	}
	if err := registry.beginOpen(205, issuedAt); err != nil {
		t.Fatal(err)
	}
	addLiveTestAC(t, s, "ac-delayed", "10.0.0.5", 62206)
	var closeCalls atomic.Int32
	s.processACSessionCloseFn = func(_ context.Context, sessionID uint64, conn *ACConn) error {
		if sessionID != 205 || conn.ACId != "ac-delayed" {
			t.Errorf("close target = %d/%q, want 205/ac-delayed", sessionID, conn.ACId)
		}
		closeCalls.Add(1)
		return nil
	}

	done := make(chan struct{})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go func() {
		s.closeAgentSessionsLocal(ctx, agentKey, issuedAt.Add(time.Second))
		close(done)
	}()
	time.Sleep(250 * time.Millisecond)
	retainUntil := time.Now().Add(time.Minute + time.Duration(ACOpenCompensationTime)*time.Second)
	if err := registry.finishOpen(205, issuedAt, sessionExpiresAt, retainUntil, "ac-delayed", true); err == nil {
		t.Fatal("successful ART racing EXT unexpectedly remained admitted")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("single EXT request did not retry after delayed in-flight AOP completed")
	}
	if closeCalls.Load() != 1 || testRegistryHasSession(registry, 205) {
		t.Fatalf("close calls/session retained = %d/%v, want 1/false", closeCalls.Load(), testRegistryHasSession(registry, 205))
	}
}

func TestAgentSessionCloseWork_MissingFanoutIdentityStillClosesLocalSession(t *testing.T) {
	s, _ := newTestServerForBroadcast(t)
	s.config = nil
	s.metrics = metrics.NewPublisherForTest(t)
	agentKey := bytes.Repeat([]byte{0x45}, core.PublicKeySize)
	issuedAt := time.Now().Add(-time.Second)
	activateTestAgentSession(t, s, agentKey, 204, issuedAt, time.Now().Add(time.Minute), "ac-local")
	addLiveTestAC(t, s, "ac-local", "10.0.0.4", 62206)

	var closeCalls atomic.Int32
	s.processACSessionCloseFn = func(context.Context, uint64, *ACConn) error {
		closeCalls.Add(1)
		return nil
	}
	work, leader := s.beginAgentSessionCloseWork(agentKey, time.Now(), time.Now().Add(agentSessionCloseEventTTL), true)
	if !leader || !s.startAgentSessionCloseWorker(work) {
		t.Fatal("start internal agent-session close work")
	}
	waitFor(t, time.Second, "local close without fanout", func() bool { return closeCalls.Load() == 1 })
	if closeCalls.Load() != 1 || testRegistryHasSession(s.sessionRegistry(), 204) {
		t.Fatalf("local close calls/session retained = %d/%v, want 1/false", closeCalls.Load(), testRegistryHasSession(s.sessionRegistry(), 204))
	}
	counters, _ := s.metrics.CountersForTest(t)
	if counters[MetricAgentSessionCloseFanoutFailure] != 1 || counters[MetricAgentSessionCloseLocalSuccess] != 1 {
		t.Fatalf("fanout-failure/local-success metrics = %v/%v, want 1/1", counters[MetricAgentSessionCloseFanoutFailure], counters[MetricAgentSessionCloseLocalSuccess])
	}
}

func TestAgentSessionCloseWork_DuplicateCoalescesOneACLoop(t *testing.T) {
	s, _ := newTestServerForBroadcast(t)
	s.config = nil
	s.metrics = metrics.NewPublisherForTest(t)
	agentKey := bytes.Repeat([]byte{0x46}, core.PublicKeySize)
	now := time.Now()
	activateTestAgentSession(t, s, agentKey, 206, now.Add(-time.Second), now.Add(time.Minute), "ac-coalesced")
	addLiveTestAC(t, s, "ac-coalesced", "10.0.0.6", 62206)

	started := make(chan struct{})
	release := make(chan struct{})
	var closeCalls atomic.Int32
	s.processACSessionCloseFn = func(context.Context, uint64, *ACConn) error {
		if closeCalls.Add(1) == 1 {
			close(started)
		}
		<-release
		return nil
	}
	work, leader := s.beginAgentSessionCloseWork(agentKey, now, now.Add(agentSessionCloseEventTTL), true)
	if !leader || !s.startAgentSessionCloseWorker(work) {
		t.Fatal("start first internal agent-session close work")
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("first EXT did not enter the AC close loop")
	}

	duplicateStarted := time.Now()
	if _, follower := s.beginAgentSessionCloseWork(agentKey, time.Now(), time.Now().Add(agentSessionCloseEventTTL), true); follower {
		t.Fatal("duplicate internal close elected a second leader")
	}
	if elapsed := time.Since(duplicateStarted); elapsed > 100*time.Millisecond {
		t.Fatalf("duplicate direct EXT occupied another close loop for %s", elapsed)
	}
	close(release)
	waitFor(t, time.Second, "coalesced direct EXT cleanup", func() bool {
		s.agentSessionCloseWorkMu.Lock()
		defer s.agentSessionCloseWorkMu.Unlock()
		return len(s.agentSessionCloseWork) == 0 && !testRegistryHasSession(s.sessionRegistry(), 206)
	})
	if got := closeCalls.Load(); got != 1 {
		t.Fatalf("direct duplicate AC close calls = %d, want one leader loop", got)
	}
	if testRegistryHasSession(s.sessionRegistry(), 206) {
		t.Fatal("coalesced direct EXT retained the closed session")
	}
	counters, _ := s.metrics.CountersForTest(t)
	if got := counters[MetricAgentSessionCloseCoalesced]; got != 1 {
		t.Fatalf("coalesced metric = %v, want 1", got)
	}
}

func TestAgentSessionCloseWork_FleetFollowerCoalescesWithLeader(t *testing.T) {
	s, _ := newTestServerForBroadcast(t)
	s.config = nil
	s.metrics = metrics.NewPublisherForTest(t)
	agentKey := bytes.Repeat([]byte{0x47}, core.PublicKeySize)
	now := time.Now()
	activateTestAgentSession(t, s, agentKey, 207, now.Add(-time.Second), now.Add(time.Minute), "ac-fleet-coalesced")
	addLiveTestAC(t, s, "ac-fleet-coalesced", "10.0.0.7", 62206)

	started := make(chan struct{})
	release := make(chan struct{})
	var closeCalls atomic.Int32
	s.processACSessionCloseFn = func(context.Context, uint64, *ACConn) error {
		if closeCalls.Add(1) == 1 {
			close(started)
		}
		<-release
		return nil
	}
	work, leader := s.beginAgentSessionCloseWork(agentKey, now, now.Add(agentSessionCloseEventTTL), true)
	if !leader || !s.startAgentSessionCloseWorker(work) {
		t.Fatal("start internal agent-session close leader")
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("direct EXT did not enter the AC close loop")
	}

	issuedThrough := time.Now()
	forwardedStarted := time.Now()
	if _, leader := s.beginAgentSessionCloseWork(agentKey, issuedThrough, issuedThrough.Add(agentSessionCloseEventTTL), false); leader {
		t.Fatal("fleet follower started a second leader")
	}
	if elapsed := time.Since(forwardedStarted); elapsed > 100*time.Millisecond {
		t.Fatalf("forwarded EXT occupied a duplicate close loop for %s", elapsed)
	}
	close(release)
	waitFor(t, time.Second, "direct/fleet coalesced leader", func() bool {
		s.agentSessionCloseWorkMu.Lock()
		defer s.agentSessionCloseWorkMu.Unlock()
		return len(s.agentSessionCloseWork) == 0
	})
	if got := closeCalls.Load(); got != 1 {
		t.Fatalf("direct/fleet AC close calls = %d, want one leader loop", got)
	}
	counters, _ := s.metrics.CountersForTest(t)
	if got := counters[MetricAgentSessionCloseCoalesced]; got != 1 {
		t.Fatalf("direct/fleet coalesced metric = %v, want 1", got)
	}
}

func TestAgentSessionCloseWork_ShutdownCancelsBlockedFanoutLeader(t *testing.T) {
	s, _ := newTestServerForBroadcast(t)
	s.config = &Config{Hostname: "server-a"}
	s.instanceID = "i-server-a"
	s.localIp = "10.0.0.10"
	lifecycleCtx, cancelLifecycle := context.WithCancel(context.Background())
	s.lifecycleCtx = lifecycleCtx
	agentKey := bytes.Repeat([]byte{0x48}, core.PublicKeySize)

	started := make(chan struct{})
	canceled := make(chan struct{})
	s.broadcastAgentSessionCloseFn = func(ctx context.Context, _ *agentSessionCloseFleetEvent) {
		close(started)
		<-ctx.Done()
		close(canceled)
	}
	work, leader := s.beginAgentSessionCloseWork(agentKey, time.Now(), time.Now().Add(agentSessionCloseEventTTL), true)
	if !leader || !s.startAgentSessionCloseWorker(work) {
		t.Fatal("start internal agent-session close work")
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("EXT leader did not enter fan-out")
	}
	cancelLifecycle()
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("server shutdown did not cancel blocked fan-out")
	}
	// Wait for the worker-owned postcondition instead of racing its deferred map
	// cleanup after the fan-out hook observes lifecycle cancellation.
	waitFor(t, time.Second, "shutdown close-work cleanup", func() bool {
		s.agentSessionCloseWorkMu.Lock()
		defer s.agentSessionCloseWorkMu.Unlock()
		return len(s.agentSessionCloseWork) == 0
	})
}

func TestFleetCloseSourceIsHealthyRequiresExactInstanceAndIP(t *testing.T) {
	servers := []ServerInfo{{ID: "i-origin", InternalIP: "10.0.1.10", HTTPPort: 8888}}
	if !fleetCloseSourceIsHealthy(servers, "i-origin", "10.0.1.10", "10.0.1.10") {
		t.Fatal("exact healthy Cloud Map instance was rejected")
	}
	for name, args := range map[string][3]string{
		"hostname is not instance id": {"server-friendly-name", "10.0.1.10", "10.0.1.10"},
		"body ip mismatch":            {"i-origin", "10.0.1.11", "10.0.1.10"},
		"socket ip mismatch":          {"i-origin", "10.0.1.10", "10.0.1.11"},
	} {
		t.Run(name, func(t *testing.T) {
			if fleetCloseSourceIsHealthy(servers, args[0], args[1], args[2]) {
				t.Fatal("mismatched fleet source was accepted")
			}
		})
	}
}

func TestDecodeAgentSessionCloseFleetEvent_StrictShape(t *testing.T) {
	now := time.Now()
	event := &agentSessionCloseFleetEvent{
		EventID:            "00112233445566778899aabbccddeeff",
		AgentPublicKey:     base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x41}, core.PublicKeySize)),
		IssuedThroughNanos: now.UnixNano(),
		ExpiresAt:          now.Add(agentSessionCloseEventTTL).Unix(),
		OriginServer:       "i-origin",
		OriginIP:           "10.0.1.10",
	}
	valid, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	decoded, agentKey, _, _, err := decodeAgentSessionCloseFleetEvent(valid, now)
	if err != nil || decoded.OriginServer != "i-origin" || len(agentKey) != core.PublicKeySize {
		t.Fatalf("valid fleet event = %#v key=%d err=%v", decoded, len(agentKey), err)
	}
	for name, raw := range map[string][]byte{
		"unknown":             append(bytes.TrimSuffix(valid, []byte("}")), []byte(`,"unknown":1}`)...),
		"duplicate event id":  []byte(strings.Replace(string(valid), `"event_id":"00112233445566778899aabbccddeeff"`, `"event_id":"00112233445566778899aabbccddeeff","event_id":"00112233445566778899aabbccddeeff"`, 1)),
		"missing origin":      []byte(strings.Replace(string(valid), `,"origin_server":"i-origin"`, "", 1)),
		"noncanonical issued": []byte(strings.Replace(string(valid), fmt.Sprintf(`"issued_through_nanos":%d`, event.IssuedThroughNanos), `"issued_through_nanos":1e9`, 1)),
		"trailing":            append(append([]byte(nil), valid...), []byte(`{}`)...),
	} {
		t.Run(name, func(t *testing.T) {
			if got, _, _, _, err := decodeAgentSessionCloseFleetEvent(raw, now); err == nil {
				t.Fatalf("malformed fleet event decoded: %#v", got)
			}
		})
	}
}

func TestAgentSessionCloseCutoffSaturationEmitsOnlyFirstTransition(t *testing.T) {
	s, _ := newTestServerForBroadcast(t)
	s.metrics = metrics.NewPublisherForTest(t)
	registry := s.sessionRegistry()
	registry.maxCloseCutoffs = 1
	now := time.Now()

	s.closeAgentSessionsLocal(context.Background(), bytes.Repeat([]byte{0x61}, core.PublicKeySize), now)
	s.closeAgentSessionsLocal(context.Background(), bytes.Repeat([]byte{0x62}, core.PublicKeySize), now)
	s.closeAgentSessionsLocal(context.Background(), bytes.Repeat([]byte{0x63}, core.PublicKeySize), now)

	counters, _ := s.metrics.CountersForTest(t)
	if got := counters[MetricAgentSessionCloseCutoffSaturated]; got != 1 {
		t.Fatalf("cutoff saturation metric = %v, want first transition only", got)
	}
}

func TestFleetCloseReplaySaturationStillCloses(t *testing.T) {
	s, _ := newTestServerForBroadcast(t)
	s.metrics = metrics.NewPublisherForTest(t)
	registry := s.sessionRegistry()
	registry.maxCloseSeen = 1
	now := time.Now()
	if got := registry.admitCloseEvent("occupied", now.Add(agentSessionCloseEventTTL)); got != closeEventNew {
		t.Fatalf("seed replay admission = %v, want new", got)
	}
	if got := registry.admitCloseEvent("new-event", now.Add(agentSessionCloseEventTTL)); got != closeEventSaturated {
		t.Fatalf("saturated replay admission = %v, want saturated", got)
	}
	agentKey := bytes.Repeat([]byte{0x64}, core.PublicKeySize)
	activateTestAgentSession(t, s, agentKey, 601, now.Add(-time.Second), now.Add(time.Minute), "ac-replay-cap")
	addLiveTestAC(t, s, "ac-replay-cap", "10.0.4.1", 62206)
	s.processACSessionCloseFn = func(context.Context, uint64, *ACConn) error { return nil }
	work, leader := s.beginAgentSessionCloseWork(agentKey, now, now.Add(time.Second), false)
	if !leader || !s.startAgentSessionCloseWorker(work) {
		t.Fatal("saturated replay close work was not scheduled")
	}
	waitFor(t, time.Second, "replay-saturated close", func() bool { return !testRegistryHasSession(registry, 601) })
}

func TestAgentSessionExit_FutureSkewBoundaryRetainsAndClosesAdmittedAC(t *testing.T) {
	s, _ := newTestServerForBroadcast(t)
	registry := newLiveNHPSessionRegistry()
	localNow := time.Unix(1_800_000_000, 0)
	registry.now = func() time.Time { return localNow }
	s.agentSessions = registry
	agentKey := bytes.Repeat([]byte{0x66}, core.PublicKeySize)
	issuedAt := localNow.Add(agentSessionCloseFutureSkew)
	sessionExpiresAt := issuedAt.Add(time.Minute)
	if err := registry.reserveExact(agentKey, 602, issuedAt, sessionExpiresAt); err != nil {
		t.Fatalf("reserve at future-skew boundary: %v", err)
	}
	if err := registry.beginOpen(602, issuedAt); err != nil {
		t.Fatalf("begin open at future-skew boundary: %v", err)
	}
	// At the accepted clock-skew boundary, the server's compensated AC deadline
	// can equal the origin-derived session deadline exactly. Equality still
	// retains the admitted AC identity for bodyless EXT teardown.
	if err := registry.finishOpen(602, issuedAt, sessionExpiresAt, sessionExpiresAt, "ac-skew-boundary", true); err != nil {
		t.Fatalf("finish equal compensated/session deadline: %v", err)
	}
	addLiveTestAC(t, s, "ac-skew-boundary", "10.0.4.2", 62206)
	var closeCalls atomic.Int32
	s.processACSessionCloseFn = func(context.Context, uint64, *ACConn) error {
		closeCalls.Add(1)
		return nil
	}
	s.closeAgentSessionsLocal(context.Background(), agentKey, issuedAt)
	if closeCalls.Load() != 1 || testRegistryHasSession(registry, 602) {
		t.Fatalf("future-skew boundary close calls/session retained = %d/%v, want 1/false", closeCalls.Load(), testRegistryHasSession(registry, 602))
	}
}

func TestProcessACSessionClose_SendsExactZeroOpenAOP(t *testing.T) {
	s, sendCh := newTestServerForBroadcast(t)
	conn := newTestACConn(t, "10.0.3.1", 62206, "ac-close", s.device)
	observed := make(chan common.ServerACOpsMsg, 1)
	go func() {
		md := <-sendCh
		var aop common.ServerACOpsMsg
		if err := json.Unmarshal(md.Message, &aop); err != nil {
			md.ResponseMsgCh <- &core.PacketParserData{Error: err}
			return
		}
		observed <- aop
		body, _ := json.Marshal(&common.ACOpsResultMsg{SessionOwnerId: aop.SessionOwnerId, SessionId: aop.SessionId, ErrCode: common.ErrSuccess.ErrorCode()})
		md.ResponseMsgCh <- &core.PacketParserData{HeaderType: core.NHP_ART, BodyMessage: body}
	}()

	if err := s.processACSessionClose(context.Background(), bytes.Repeat([]byte{0x51}, core.PublicKeySize), nhpSessionCloseSnapshot{SessionID: 501, IssuedAt: time.Unix(1700000000, 0)}, conn); err != nil {
		t.Fatalf("process AC session close: %v", err)
	}
	got := <-observed
	if got.SessionId != 501 || got.OpenTime != 0 {
		t.Fatalf("close AOP session/openTime = %d/%d, want 501/0", got.SessionId, got.OpenTime)
	}
}

func TestProcessACSessionClose_SaturatedQueueHonorsContextAndRetainsSession(t *testing.T) {
	s, sendCh := newTestServerForBroadcast(t)
	s.signals.stop = make(chan struct{})
	for len(sendCh) < cap(sendCh) {
		sendCh <- &core.MsgData{}
	}
	conn := newTestACConn(t, "10.0.3.2", 62206, "ac-close-full", s.device)
	s.acConnectionMap[conn.ACId] = []*ACConn{conn}
	agentKey := bytes.Repeat([]byte{0x52}, core.PublicKeySize)
	now := time.Now()
	activateTestAgentSession(t, s, agentKey, 502, now.Add(-time.Second), now.Add(time.Minute), conn.ACId)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	started := time.Now()
	s.closeAgentSessionsLocal(ctx, agentKey, now)
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("saturated close returned after %s, want bounded context return", elapsed)
	}
	if !testRegistryHasSession(s.sessionRegistry(), 502) {
		t.Fatal("saturated close discarded retryable session state")
	}
}

func TestProcessACSessionClose_ShutdownUnblocksSaturatedQueue(t *testing.T) {
	s, sendCh := newTestServerForBroadcast(t)
	s.signals.stop = make(chan struct{})
	for len(sendCh) < cap(sendCh) {
		sendCh <- &core.MsgData{}
	}
	conn := newTestACConn(t, "10.0.3.3", 62206, "ac-close-stop", s.device)
	done := make(chan error, 1)
	go func() {
		done <- s.processACSessionClose(context.Background(), bytes.Repeat([]byte{0x53}, core.PublicKeySize), nhpSessionCloseSnapshot{SessionID: 503, IssuedAt: time.Unix(1700000000, 0)}, conn)
	}()
	close(s.signals.stop)
	select {
	case err := <-done:
		if !errors.Is(err, common.ErrPacketToMessageRoutineStopped) {
			t.Fatalf("shutdown close error = %v, want routine stopped", err)
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown did not unblock saturated EXT close enqueue")
	}
}

func TestAgentSessionExit_LateFollowerExtendsExpiredLeaderIteration(t *testing.T) {
	s, _ := newTestServerForBroadcast(t)
	s.config = &Config{Hostname: "server-a"}
	s.instanceID = "i-server-a"
	s.localIp = "10.0.0.10"
	agentKey := bytes.Repeat([]byte{0x49}, core.PublicKeySize)
	now := time.Now()
	firstIssued := now.Add(-10 * time.Second)
	secondIssued := now
	activateTestAgentSession(t, s, agentKey, 508, firstIssued.Add(-time.Millisecond), now.Add(time.Minute), "ac-late")
	addLiveTestAC(t, s, "ac-late", "10.0.0.8", 62206)

	firstBroadcastStarted := make(chan struct{})
	var broadcastCalls atomic.Int32
	var lastBroadcastNanos atomic.Int64
	s.broadcastAgentSessionCloseFn = func(ctx context.Context, event *agentSessionCloseFleetEvent) {
		lastBroadcastNanos.Store(event.IssuedThroughNanos)
		if broadcastCalls.Add(1) == 1 {
			close(firstBroadcastStarted)
			<-ctx.Done()
		}
	}
	closed := make(chan uint64, 2)
	s.processACSessionCloseFn = func(_ context.Context, sessionID uint64, _ *ACConn) error {
		closed <- sessionID
		return nil
	}

	work, leader := s.beginAgentSessionCloseWork(agentKey, firstIssued, now.Add(80*time.Millisecond), true)
	if !leader {
		t.Fatal("first close work was not elected leader")
	}
	done := make(chan struct{})
	go func() {
		s.runAgentSessionCloseWork(work)
		close(done)
	}()
	select {
	case <-firstBroadcastStarted:
	case <-time.After(time.Second):
		t.Fatal("first close iteration did not start fan-out")
	}

	activateTestAgentSession(t, s, agentKey, 509, secondIssued, now.Add(time.Minute), "ac-late")
	if got, follower := s.beginAgentSessionCloseWork(agentKey, secondIssued, now.Add(time.Second), true); follower || got != work {
		t.Fatalf("late close work = %p leader %t, want existing %p follower", got, follower, work)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("extended close-work leader did not finish")
	}

	close(closed)
	seen := map[uint64]bool{}
	for sessionID := range closed {
		seen[sessionID] = true
	}
	if !seen[508] || !seen[509] {
		t.Fatalf("closed sessions = %v, want both pre- and late-follower sessions", seen)
	}
	if got := broadcastCalls.Load(); got < 2 {
		t.Fatalf("fan-out iterations = %d, want old-deadline attempt plus advanced cutoff", got)
	}
	if got := lastBroadcastNanos.Load(); got != secondIssued.UnixNano() {
		t.Fatalf("last fleet cutoff = %d, want late follower %d", got, secondIssued.UnixNano())
	}
}
