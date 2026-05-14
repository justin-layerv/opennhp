package server

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	// smithy-go is held as a DIRECT dependency for
	// TestResolveAgentPeerForKnock_ShutdownCanceledSuppressesSDKWrapped
	// below: that test wraps context.Canceled in
	// smithy.OperationError to fence against an aws-sdk-go-v2
	// upgrade that breaks the Unwrap chain. If a future cleanup
	// flags this import as "unused" or "only one test uses it,"
	// keep it — the test is intentionally scoped narrow and the
	// import documents the SDK error-shape contract.
	smithy "github.com/aws/smithy-go"

	"github.com/OpenNHP/opennhp/endpoints/metrics"
	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
)

// TestResolveAgentPeerForKnock_HappyPath asserts that on a fresh
// knock from a registered agent, resolveAgentPeerForKnock:
//   - looks up the pubkey in DDB,
//   - constructs a *UdpPeer,
//   - inserts into agentPeerMap (so subsequent knocks short-circuit),
//   - initializes recvAddr from the current packet (so downstream code
//     reading peer.RecvAddr() doesn't see nil).
//
// Regression fence for the cloud-mode agent registry contract: the
// nhp-server must be able to discover a registered agent on first
// knock without preemptive "load all from etcd" — DDB+LRU is the
// only source.
func TestResolveAgentPeerForKnock_HappyPath(t *testing.T) {
	pk := pubkeyB64(0x21)
	q := newFakeAgentKeysQuerier()
	q.put(pk, "owner-21", "agent-21")

	lookup := newTestLookup(t, q)
	s := &UdpServer{
		metrics:         metrics.NewPublisherForTest(t),
		agentPeerMap:    map[string]*core.UdpPeer{},
		agentPeerLookup: lookup,
		device:          newTestDeviceForAgentLookup(t),
	}

	rawPubkey := decodeB64(t, pk)
	ppd := &core.PacketParserData{
		HeaderType:    core.NHP_KNK,
		SenderTrxId:   1,
		RemotePubKey:  rawPubkey,
		LocalInitTime: 1234567890,
		ConnData: &core.ConnectionData{
			RemoteAddr: &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 12345},
		},
	}
	knkMsg := &common.AgentKnockMsg{UserId: "user-1"}
	ackMsg := &common.ServerKnockAckMsg{}

	if err := s.resolveAgentPeerForKnock(ppd, knkMsg, ackMsg, 1, "203.0.113.10:12345"); err != nil {
		t.Fatalf("resolveAgentPeerForKnock: %v", err)
	}

	// Peer present in agentPeerMap.
	s.agentPeerMapMutex.Lock()
	peer, ok := s.agentPeerMap[pk]
	s.agentPeerMapMutex.Unlock()
	if !ok {
		t.Fatal("agentPeerMap does not contain resolved peer")
	}
	if peer.PublicKeyBase64() != pk {
		t.Errorf("peer pubkey=%q want %q", peer.PublicKeyBase64(), pk)
	}
	// recvAddr initialized AND matches the packet's RemoteAddr.
	// Asserting equality (not just non-nil) fences a future
	// regression that swaps the UpdateRecv args; plugin handlers
	// read peer.RecvAddr() expecting the source of the knock.
	recvAddr := peer.RecvAddr()
	if recvAddr == nil {
		t.Fatal("peer.RecvAddr() is nil; recvAddr was not initialized from packet")
	}
	if recvAddr.String() != ppd.ConnData.RemoteAddr.String() {
		t.Errorf("peer.RecvAddr()=%v want %v (must equal packet RemoteAddr)", recvAddr, ppd.ConnData.RemoteAddr)
	}
	// Ack untouched (success → no error fields set on ackMsg).
	if ackMsg.ErrCode != "" {
		t.Errorf("ackMsg.ErrCode=%q want empty (success)", ackMsg.ErrCode)
	}
	// Success-path counter fires once.
	counters, _ := s.metrics.CountersForTest(t)
	if c := counters[MetricAgentFirstResolve]; c != 1 {
		t.Errorf("MetricAgentFirstResolve counter=%v want 1", c)
	}
	if c := counters[MetricAuthFailure]; c != 0 {
		t.Errorf("MetricAuthFailure counter=%v want 0 on resolve success", c)
	}
}

// TestResolveAgentPeerForKnock_CacheWarmShortCircuits asserts that
// when agentPeerMap already contains the pubkey, the resolver is a
// no-op (no DDB Query). Steady-state knock path optimization.
func TestResolveAgentPeerForKnock_CacheWarmShortCircuits(t *testing.T) {
	pk := pubkeyB64(0x22)
	q := newFakeAgentKeysQuerier()
	// Intentionally do NOT put the row — if the resolver calls DDB,
	// we'd see ErrAgentUnknownPubkey and the test would fail.

	lookup := newTestLookup(t, q)
	s := &UdpServer{
		metrics: metrics.NewPublisherForTest(t),
		agentPeerMap: map[string]*core.UdpPeer{
			pk: {PubKeyBase64: pk, Type: core.NHP_AGENT},
		},
		agentPeerLookup: lookup,
	}

	rawPubkey := decodeB64(t, pk)
	ppd := &core.PacketParserData{
		HeaderType:   core.NHP_KNK,
		RemotePubKey: rawPubkey,
		ConnData: &core.ConnectionData{
			RemoteAddr: &net.UDPAddr{IP: net.ParseIP("203.0.113.20"), Port: 5555},
		},
	}
	knkMsg := &common.AgentKnockMsg{UserId: "user-2"}
	ackMsg := &common.ServerKnockAckMsg{}

	if err := s.resolveAgentPeerForKnock(ppd, knkMsg, ackMsg, 2, "203.0.113.20:5555"); err != nil {
		t.Fatalf("resolveAgentPeerForKnock: %v", err)
	}
	if q.callCount() != 0 {
		t.Errorf("DDB calls=%d want 0 (agentPeerMap warm should short-circuit)", q.callCount())
	}
}

// TestResolveAgentPeerForKnock_CacheWarmDoesNotUpdateRecvAddr fences
// the deliberate divergence from HandleACOnline's re-registration
// pattern (msghandler.go:879-894): when the pubkey is already in
// agentPeerMap, the resolver short-circuits WITHOUT calling
// UpdateRecv. This is safe today because no downstream code reads
// agentPeer.RecvAddr() — the auth flow uses ppd.ConnData.RemoteAddr
// directly. If a future change adds an agent-peer RecvAddr() reader
// (server-initiated outbound, broadcast, plugin handlers), this test
// will fail and force the author to either:
//   - Move UpdateRecv above the alreadyKnown short-circuit (matches
//     the AC pattern exactly), or
//   - Have the new reader source RemoteAddr from the live ppd at call
//     time rather than from the cached peer.
//
// The expectation is intentionally inverted vs. the happy-path test:
// the cache-warm peer's RecvAddr stays at the value it was given when
// inserted, NOT what arrived on the second knock.
func TestResolveAgentPeerForKnock_CacheWarmDoesNotUpdateRecvAddr(t *testing.T) {
	pk := pubkeyB64(0x27)
	q := newFakeAgentKeysQuerier()
	// Intentionally do NOT put the row — first-knock path would fail.

	// Pre-seed the peer with a stale RecvAddr representing the
	// agent's previous NAT source port.
	stalePeer := &core.UdpPeer{PubKeyBase64: pk, Type: core.NHP_AGENT}
	staleAddr := &net.UDPAddr{IP: net.ParseIP("203.0.113.70"), Port: 11111}
	stalePeer.UpdateRecv(1000, staleAddr)

	lookup := newTestLookup(t, q)
	s := &UdpServer{
		metrics: metrics.NewPublisherForTest(t),
		agentPeerMap: map[string]*core.UdpPeer{
			pk: stalePeer,
		},
		agentPeerLookup: lookup,
	}

	rawPubkey := decodeB64(t, pk)
	// Second knock arrives from a different (rebound) source port.
	newAddr := &net.UDPAddr{IP: net.ParseIP("203.0.113.70"), Port: 22222}
	ppd := &core.PacketParserData{
		HeaderType:    core.NHP_KNK,
		RemotePubKey:  rawPubkey,
		LocalInitTime: 2000,
		ConnData:      &core.ConnectionData{RemoteAddr: newAddr},
	}
	knkMsg := &common.AgentKnockMsg{UserId: "user-7"}
	ackMsg := &common.ServerKnockAckMsg{}

	if err := s.resolveAgentPeerForKnock(ppd, knkMsg, ackMsg, 7, newAddr.String()); err != nil {
		t.Fatalf("resolveAgentPeerForKnock: %v", err)
	}

	// RecvAddr MUST still be the stale one — the cache-warm short-
	// circuit deliberately does not refresh it.
	got := stalePeer.RecvAddr()
	if got == nil {
		t.Fatal("stale peer RecvAddr was wiped to nil; cache-warm path must not touch RecvAddr")
	}
	if got.String() != staleAddr.String() {
		t.Errorf("peer.RecvAddr()=%v want %v (cache-warm path must NOT call UpdateRecv; "+
			"if you intentionally changed this, also flip the comment in resolveAgentPeerForKnock "+
			"and confirm no downstream consumer relies on the previous behavior)",
			got, staleAddr)
	}
}

// TestResolveAgentPeerForKnock_UnknownPubkeyRejects asserts an
// unregistered agent's knock is rejected with the generic
// ErrKnockServerNotFound (51002) and no peer is added.
//
// Wire-level invariant: the agent sees the same error whether its
// pubkey was never registered OR DDB read failed (don't leak the
// distinction; the structured log is the only place the difference
// is visible).
func TestResolveAgentPeerForKnock_UnknownPubkeyRejects(t *testing.T) {
	pk := pubkeyB64(0x23)
	q := newFakeAgentKeysQuerier()
	// Do NOT put pk; lookup returns ErrAgentUnknownPubkey.

	lookup := newTestLookup(t, q)
	s := &UdpServer{
		metrics:         metrics.NewPublisherForTest(t),
		agentPeerMap:    map[string]*core.UdpPeer{},
		agentPeerLookup: lookup,
	}

	rawPubkey := decodeB64(t, pk)
	ppd := &core.PacketParserData{
		HeaderType:   core.NHP_KNK,
		RemotePubKey: rawPubkey,
		ConnData: &core.ConnectionData{
			RemoteAddr: &net.UDPAddr{IP: net.ParseIP("203.0.113.30"), Port: 5555},
		},
	}
	knkMsg := &common.AgentKnockMsg{UserId: "user-3"}
	ackMsg := &common.ServerKnockAckMsg{}

	err := s.resolveAgentPeerForKnock(ppd, knkMsg, ackMsg, 3, "203.0.113.30:5555")
	if !errors.Is(err, common.ErrKnockServerNotFound) {
		t.Fatalf("err=%v want ErrKnockServerNotFound", err)
	}

	if ackMsg.ErrCode != common.ErrKnockServerNotFound.ErrorCode() {
		t.Errorf("ackMsg.ErrCode=%q want %q", ackMsg.ErrCode, common.ErrKnockServerNotFound.ErrorCode())
	}

	// Peer NOT added.
	s.agentPeerMapMutex.Lock()
	_, present := s.agentPeerMap[pk]
	s.agentPeerMapMutex.Unlock()
	if present {
		t.Error("agentPeerMap contains unresolved peer; reject should not add to peer map")
	}

	// Auth-failure metric incremented (so ops can alert).
	counters, _ := s.metrics.CountersForTest(t)
	if c := counters[MetricAuthFailure]; c != 1 {
		t.Errorf("MetricAuthFailure counter=%v want 1", c)
	}
}

// TestResolveAgentPeerForKnock_DDBErrorRejects asserts a transient
// DDB error rejects the knock the same way as unknown — same wire
// error, different structured log (covered by event= tag in source).
func TestResolveAgentPeerForKnock_DDBErrorRejects(t *testing.T) {
	pk := pubkeyB64(0x24)
	q := newFakeAgentKeysQuerier()
	q.err = &types.ProvisionedThroughputExceededException{}

	lookup := newTestLookup(t, q)
	s := &UdpServer{
		metrics:         metrics.NewPublisherForTest(t),
		agentPeerMap:    map[string]*core.UdpPeer{},
		agentPeerLookup: lookup,
	}

	rawPubkey := decodeB64(t, pk)
	ppd := &core.PacketParserData{
		HeaderType:   core.NHP_KNK,
		RemotePubKey: rawPubkey,
		ConnData: &core.ConnectionData{
			RemoteAddr: &net.UDPAddr{IP: net.ParseIP("203.0.113.40"), Port: 5555},
		},
	}
	knkMsg := &common.AgentKnockMsg{UserId: "user-4"}
	ackMsg := &common.ServerKnockAckMsg{}

	err := s.resolveAgentPeerForKnock(ppd, knkMsg, ackMsg, 4, "203.0.113.40:5555")
	if !errors.Is(err, common.ErrKnockServerNotFound) {
		t.Fatalf("err=%v want ErrKnockServerNotFound", err)
	}
	if ackMsg.ErrCode != common.ErrKnockServerNotFound.ErrorCode() {
		t.Errorf("ackMsg.ErrCode=%q want %q", ackMsg.ErrCode, common.ErrKnockServerNotFound.ErrorCode())
	}

	// DDB-error metric incremented; AuthFailure NOT incremented.
	// The auth-failures CloudWatch alarm pages on AuthFailure, so a
	// DDB hiccup must not look like an auth-policy event.
	counters, _ := s.metrics.CountersForTest(t)
	if c := counters[MetricAgentLookupDDBError]; c != 1 {
		t.Errorf("MetricAgentLookupDDBError counter=%v want 1 on ddb error", c)
	}
	if c := counters[MetricAuthFailure]; c != 0 {
		t.Errorf("MetricAuthFailure counter=%v want 0 on ddb error (split to MetricAgentLookupDDBError)", c)
	}
}

// TestResolveAgentPeerForKnock_ShutdownCanceledSuppressesDDBErrorMetric
// fences the shutdown-suppression branch: when lifecycleCtx is
// canceled (Stop() in flight), in-flight LookupAgentByPubKey calls
// return wrapped ctx.Canceled errors. Those must NOT increment
// MetricAgentLookupDDBError — otherwise a normal server shutdown
// would page the DDB-error alarm. The knock still rejects (wire
// behavior unchanged); only the metric/log severity is adjusted.
func TestResolveAgentPeerForKnock_ShutdownCanceledSuppressesDDBErrorMetric(t *testing.T) {
	pk := pubkeyB64(0x25)
	q := newFakeAgentKeysQuerier()
	q.err = context.Canceled // simulate DDB SDK returning ctx.Canceled

	lookup := newTestLookup(t, q)
	cancelCtx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel: this is the lifecycleCtx state during Stop()

	s := &UdpServer{
		metrics:         metrics.NewPublisherForTest(t),
		agentPeerMap:    map[string]*core.UdpPeer{},
		agentPeerLookup: lookup,
		lifecycleCtx:    cancelCtx,
	}

	rawPubkey := decodeB64(t, pk)
	ppd := &core.PacketParserData{
		HeaderType:   core.NHP_KNK,
		RemotePubKey: rawPubkey,
		ConnData: &core.ConnectionData{
			RemoteAddr: &net.UDPAddr{IP: net.ParseIP("203.0.113.60"), Port: 5555},
		},
	}
	knkMsg := &common.AgentKnockMsg{UserId: "user-shutdown"}
	ackMsg := &common.ServerKnockAckMsg{}

	err := s.resolveAgentPeerForKnock(ppd, knkMsg, ackMsg, 6, "203.0.113.60:5555")
	if !errors.Is(err, common.ErrKnockServerNotFound) {
		t.Fatalf("err=%v want ErrKnockServerNotFound", err)
	}

	// Neither error counter should fire on shutdown-canceled.
	counters, _ := s.metrics.CountersForTest(t)
	if c := counters[MetricAgentLookupDDBError]; c != 0 {
		t.Errorf("MetricAgentLookupDDBError counter=%v want 0 on shutdown (must not look like DDB outage)", c)
	}
	if c := counters[MetricAuthFailure]; c != 0 {
		t.Errorf("MetricAuthFailure counter=%v want 0 on shutdown", c)
	}
}

// TestResolveAgentPeerForKnock_ShutdownCanceledSuppressesSDKWrapped
// fences the shutdown-suppression branch against the real-world
// case where aws-sdk-go-v2 wraps the cancellation in
// smithy.OperationError before returning it. The previous test
// (ShutdownCanceledSuppressesDDBErrorMetric) injects context.Canceled
// directly; this one matches the production error chain shape.
//
// errors.Is(opError, context.Canceled) MUST unwrap through
// smithy.OperationError; if a future aws-sdk-go-v2 upgrade changes
// the wrapper to break the Unwrap() chain, the shutdown branch in
// resolveAgentPeerForKnock would silently misclassify shutdown as
// a DDB outage. This test fences that.
func TestResolveAgentPeerForKnock_ShutdownCanceledSuppressesSDKWrapped(t *testing.T) {
	pk := pubkeyB64(0x26)
	q := newFakeAgentKeysQuerier()
	// Wrap context.Canceled in a smithy.OperationError shape — the
	// same envelope aws-sdk-go-v2 produces when a DDB call sees its
	// ctx canceled mid-flight.
	q.err = &smithy.OperationError{
		ServiceID:     "DynamoDB",
		OperationName: "Query",
		Err:           context.Canceled,
	}

	lookup := newTestLookup(t, q)
	cancelCtx, cancel := context.WithCancel(context.Background())
	cancel()

	s := &UdpServer{
		metrics:         metrics.NewPublisherForTest(t),
		agentPeerMap:    map[string]*core.UdpPeer{},
		agentPeerLookup: lookup,
		lifecycleCtx:    cancelCtx,
	}

	rawPubkey := decodeB64(t, pk)
	ppd := &core.PacketParserData{
		HeaderType:   core.NHP_KNK,
		RemotePubKey: rawPubkey,
		ConnData: &core.ConnectionData{
			RemoteAddr: &net.UDPAddr{IP: net.ParseIP("203.0.113.61"), Port: 5555},
		},
	}
	knkMsg := &common.AgentKnockMsg{UserId: "user-shutdown-sdkwrap"}
	ackMsg := &common.ServerKnockAckMsg{}

	if err := s.resolveAgentPeerForKnock(ppd, knkMsg, ackMsg, 7, "203.0.113.61:5555"); !errors.Is(err, common.ErrKnockServerNotFound) {
		t.Fatalf("err=%v want ErrKnockServerNotFound", err)
	}

	counters, _ := s.metrics.CountersForTest(t)
	if c := counters[MetricAgentLookupDDBError]; c != 0 {
		t.Errorf("MetricAgentLookupDDBError counter=%v want 0 on shutdown wrapped via smithy.OperationError "+
			"(an SDK upgrade that breaks the Unwrap chain would surface here as a failed assertion — "+
			"check that errors.Is(err, context.Canceled) still resolves through the SDK error envelope)", c)
	}
	if c := counters[MetricAuthFailure]; c != 0 {
		t.Errorf("MetricAuthFailure counter=%v want 0 on SDK-wrapped shutdown", c)
	}
}

// TestResolveAgentPeerForKnock_EmptyPubkeyRejects asserts the
// upstream-invariant fence: a knock with an empty RemotePubKey is
// rejected without hitting DDB. This protects against a future
// noise-responder regression that fails to populate
// ppd.RemotePubKey on the agent path.
func TestResolveAgentPeerForKnock_EmptyPubkeyRejects(t *testing.T) {
	q := newFakeAgentKeysQuerier()
	lookup := newTestLookup(t, q)
	s := &UdpServer{
		metrics:         metrics.NewPublisherForTest(t),
		agentPeerMap:    map[string]*core.UdpPeer{},
		agentPeerLookup: lookup,
	}

	ppd := &core.PacketParserData{
		HeaderType:   core.NHP_KNK,
		RemotePubKey: nil,
		ConnData: &core.ConnectionData{
			RemoteAddr: &net.UDPAddr{IP: net.ParseIP("203.0.113.50"), Port: 5555},
		},
	}
	knkMsg := &common.AgentKnockMsg{UserId: "user-5"}
	ackMsg := &common.ServerKnockAckMsg{}

	err := s.resolveAgentPeerForKnock(ppd, knkMsg, ackMsg, 5, "203.0.113.50:5555")
	if !errors.Is(err, common.ErrKnockServerNotFound) {
		t.Fatalf("err=%v want ErrKnockServerNotFound", err)
	}
	if q.callCount() != 0 {
		t.Errorf("DDB calls=%d want 0 (empty pubkey should not query)", q.callCount())
	}
	// Empty-pubkey is an auth-policy outcome; the auth-failures
	// alarm needs visibility, so counted as AuthFailure.
	counters, _ := s.metrics.CountersForTest(t)
	if c := counters[MetricAuthFailure]; c != 1 {
		t.Errorf("MetricAuthFailure counter=%v want 1 on empty pubkey", c)
	}
}

// TestResolveAgentPeerForKnock_AddsToCoreDevice asserts that the
// resolved peer is registered with core.Device's peer map (via
// AddAgentPeer), so subsequent packets that go through the noise
// responder's DisableAgentPeerValidation=false path (e.g., NHP_LST
// register/list operations from the same agent) would also resolve.
//
// Without this, a hypothetical change that re-enables responder peer
// validation would silently break the agent path; this test fences
// the end-to-end "AddAgentPeer was actually called" invariant.
func TestResolveAgentPeerForKnock_AddsToCoreDevice(t *testing.T) {
	// Distinct filler from
	// TestResolveAgentPeerForKnock_ShutdownCanceledSuppressesDDBErrorMetric
	// (0x25) so a `go test -run` failure points at exactly one test.
	pk := pubkeyB64(0x26)
	q := newFakeAgentKeysQuerier()
	q.put(pk, "owner-26", "agent-26")

	lookup := newTestLookup(t, q)
	device := newTestDeviceForAgentLookup(t)
	s := &UdpServer{
		metrics:         metrics.NewPublisherForTest(t),
		agentPeerMap:    map[string]*core.UdpPeer{},
		agentPeerLookup: lookup,
		device:          device,
	}

	rawPubkey := decodeB64(t, pk)
	ppd := &core.PacketParserData{
		HeaderType:    core.NHP_KNK,
		RemotePubKey:  rawPubkey,
		LocalInitTime: 99,
		ConnData: &core.ConnectionData{
			RemoteAddr: &net.UDPAddr{IP: net.ParseIP("203.0.113.60"), Port: 5555},
		},
	}
	knkMsg := &common.AgentKnockMsg{UserId: "user-6"}
	ackMsg := &common.ServerKnockAckMsg{}

	if err := s.resolveAgentPeerForKnock(ppd, knkMsg, ackMsg, 6, "203.0.113.60:5555"); err != nil {
		t.Fatalf("resolveAgentPeerForKnock: %v", err)
	}

	// LookupPeer takes raw pubkey bytes.
	if got := device.LookupPeer(rawPubkey); got == nil {
		t.Error("core.Device.LookupPeer returned nil after resolve; AddAgentPeer was not called")
	}
}

// TestResolveAgentPeerForKnock_ResolveCounterSingleCountsUnderPiggyback
// fences the single-counting fix for MetricAgentFirstResolve under
// singleflight piggyback. N concurrent first-knocks for the same
// fresh pubkey all dedupe through AgentPeerLookup.sfGroup and reach
// AddAgentPeer; only the winner of the agentPeerMap insertion races
// is supposed to increment the counter.
//
// The test uses a blockingAgentKeysQuerier + the onSingleflightEnter
// hook to GUARANTEE all N goroutines are committed to the same
// singleflight slot before the winner completes Query. Without that
// barrier, a fast first-winner could populate the cache before
// stragglers entered sfGroup.Do and the assertion would pass via
// the cache-warm short-circuit path (which separately satisfies the
// single-count invariant) rather than via the piggyback path the
// test name claims to exercise.
//
// Regression fence: without the bool-return gate on AddAgentPeer +
// the conditional s.metrics.IncrCounter call in
// resolveAgentPeerForKnock, this test sees N counter increments
// for one logical resolve and fails. The number used here (8) is
// arbitrary; any N > 1 catches the regression.
func TestResolveAgentPeerForKnock_ResolveCounterSingleCountsUnderPiggyback(t *testing.T) {
	const concurrency = 8

	pk := pubkeyB64(0x33)
	inner := newFakeAgentKeysQuerier()
	inner.put(pk, "owner-33", "agent-33")
	q := &blockingAgentKeysQuerier{
		inner:   inner,
		release: make(chan struct{}),
		entered: make(chan struct{}, concurrency),
	}
	lookup := newTestLookup(t, q)
	device := newTestDeviceForAgentLookup(t)

	// onSingleflightEnter barrier: each caller signals exactly once
	// when it commits to sfGroup.Do. The releaser below waits for
	// all N signals before releasing the winner's blocked Query,
	// guaranteeing every goroutine is piggybacking on the same
	// singleflight slot rather than taking a cache-warm fast path.
	enterCh := make(chan struct{}, concurrency)
	lookup.onSingleflightEnter = func(string) {
		enterCh <- struct{}{}
	}
	s := &UdpServer{
		metrics:         metrics.NewPublisherForTest(t),
		agentPeerMap:    map[string]*core.UdpPeer{},
		agentPeerLookup: lookup,
		device:          device,
	}

	go func() {
		for i := 0; i < concurrency; i++ {
			<-enterCh
		}
		// Winner is in (or imminently in) Query at b.release.
		<-q.entered
		close(q.release)
	}()

	rawPubkey := decodeB64(t, pk)
	var wg sync.WaitGroup
	wg.Add(concurrency)
	for i := 0; i < concurrency; i++ {
		go func(idx int) {
			defer wg.Done()
			ppd := &core.PacketParserData{
				HeaderType:    core.NHP_KNK,
				RemotePubKey:  rawPubkey,
				LocalInitTime: int64(1000 + idx),
				ConnData: &core.ConnectionData{
					// Distinct source ports so a future regression that
					// doubled the counter under "different addr" wouldn't
					// accidentally pass.
					RemoteAddr: &net.UDPAddr{IP: net.ParseIP("203.0.113.99"), Port: 10000 + idx},
				},
			}
			knkMsg := &common.AgentKnockMsg{UserId: "user-piggyback"}
			ackMsg := &common.ServerKnockAckMsg{}
			if err := s.resolveAgentPeerForKnock(ppd, knkMsg, ackMsg, uint64(idx), "203.0.113.99"); err != nil {
				t.Errorf("call %d: resolveAgentPeerForKnock: %v", idx, err)
			}
		}(i)
	}
	wg.Wait()

	counters, _ := s.metrics.CountersForTest(t)
	got := counters[MetricAgentFirstResolve]
	if got != 1 {
		t.Errorf("%s counter=%v want 1 (singleflight piggyback over-count regression — see "+
			"AddAgentPeer godoc + the gating in resolveAgentPeerForKnock)",
			MetricAgentFirstResolve, got)
	}

	// Sanity: agentPeerMap has exactly one entry for the pubkey.
	s.agentPeerMapMutex.Lock()
	mapLen := len(s.agentPeerMap)
	cachedPeer := s.agentPeerMap[pk]
	s.agentPeerMapMutex.Unlock()
	if mapLen != 1 {
		t.Errorf("agentPeerMap len=%d want 1 (piggyback should NOT duplicate the entry)", mapLen)
	}

	// device.peerMap must hold the SAME peer pointer as agentPeerMap —
	// fences a regression that moves device.AddPeer outside the
	// existed-check (or outside the locked region) so that N piggy-
	// backers each write to device.peerMap. The current implementation
	// holds agentPeerMapMutex across device.AddPeer and gates the call
	// on existed=false, so only the first inserter touches device.
	devicePeer := device.LookupPeer(rawPubkey)
	if devicePeer == nil {
		t.Error("device.LookupPeer returned nil after piggyback resolve; AddAgentPeer must invoke device.AddPeer for the first inserter")
	} else if udpDevicePeer, ok := devicePeer.(*core.UdpPeer); !ok {
		t.Errorf("device.LookupPeer returned %T after piggyback; want *core.UdpPeer (a *core.PeerGroup here would indicate device.AddPeer ran more than once with non-matching addresses)", devicePeer)
	} else if udpDevicePeer != cachedPeer {
		t.Errorf("device.peerMap pointer %p != agentPeerMap pointer %p (piggyback must not write distinct peers into the two maps)", udpDevicePeer, cachedPeer)
	}

	// RecvAddr post-piggyback assertion: peer.UpdateRecv is gated on
	// AddAgentPeer's `added=true` return, so only the first inserter
	// writes RecvAddr on the shared cache pointer. The final value
	// must be non-nil and must equal exactly the first inserter's
	// RemoteAddr — which is non-deterministic across goroutines, so
	// the assertion is "one of the N distinct source ports threaded
	// in." A future regression that either (a) skips UpdateRecv
	// entirely on the first inserter, or (b) re-enables UpdateRecv
	// for piggybackers, surfaces here.
	if cachedPeer == nil {
		t.Fatalf("agentPeerMap[%s] is nil after piggyback resolve", pk)
	}
	recv := cachedPeer.RecvAddr()
	if recv == nil {
		t.Errorf("peer.RecvAddr()=nil after piggyback; want the first inserter's RemoteAddr (UpdateRecv gate may have regressed to skip the first inserter)")
	} else {
		udp, ok := recv.(*net.UDPAddr)
		if !ok {
			t.Errorf("peer.RecvAddr() type=%T want *net.UDPAddr", recv)
		} else if udp.Port < 10000 || udp.Port >= 10000+concurrency || !udp.IP.Equal(net.ParseIP("203.0.113.99")) {
			t.Errorf("peer.RecvAddr()=%v not one of the goroutines' RemoteAddr (expected 203.0.113.99:[10000..%d))",
				udp, 10000+concurrency)
		}
	}
}

// helpers ----------------------------------------------------------

// newTestDeviceForAgentLookup constructs a minimal core.Device for
// tests that need device.AddPeer / device.LookupPeer to round-trip.
// Provides a deterministic 32-byte server private key (irrelevant
// to the lookup test surface) and lets the device populate its peer
// map normally.
func newTestDeviceForAgentLookup(t *testing.T) *core.Device {
	t.Helper()
	priv := make([]byte, 32)
	for i := range priv {
		priv[i] = byte(i + 1)
	}
	dev := core.NewDevice(core.NHP_SERVER, priv, &core.DeviceOptions{
		DisableAgentPeerValidation: true,
	})
	if dev == nil {
		t.Fatalf("core.NewDevice returned nil")
	}
	t.Cleanup(func() {
		dev.Stop()
	})
	return dev
}

// decodeB64 decodes a standard padded base64 string to raw bytes;
// fails the test on error. Centralizes the import so individual
// tests don't pull encoding/base64 directly.
func decodeB64(t *testing.T, b64 string) []byte {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("decodeB64(%q): %v", b64, err)
	}
	return raw
}
