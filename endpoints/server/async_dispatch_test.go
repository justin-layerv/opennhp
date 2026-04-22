package server

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/endpoints/metrics"
	"github.com/OpenNHP/opennhp/nhp/core"
)

// Regression fence for PR fixing #1163 — NHP_AOL and NHP_DOL used to
// be dispatched synchronously on recvMessageRoutine's single goroutine.
// A slow handler (bcrypt + DynamoDB + CloudMap in cloud mode, ~100ms+)
// would saturate recvMsgCh and cause packetToMsgRoutine to silently
// drop validated knocks. The fix: every switch arm in
// dispatchReceivedMessage fires its handler in a goroutine.
//
// The property fenced: dispatchReceivedMessage returns before the
// handler body completes. Tests hold a mutex the handler needs at
// entry and never release it — a synchronous dispatch would block.
// Handler goroutines park on the mutex for the test binary's
// lifetime; this is an intentional leak that keeps the handler
// from racing past the lock and panicking on unset UdpServer
// fields (s.device, s.listenAddr). The leak is bounded per test
// function, not per iteration under -count=N: each iteration
// owns a fresh server, but parked goroutines outlive the
// iteration and scale linearly with -count (single-AOL tests
// leak 1 goroutine per iteration; ManyConcurrentAOLs leaks 20
// per iteration). All goroutines die with the test binary.

// dispatchAssertDeadline is generous enough to absorb slow CI but
// tight enough that a synchronous regression (which would never
// return) trips cleanly.
const dispatchAssertDeadline = 500 * time.Millisecond

// newTestServerForDispatch wires a minimal UdpServer sufficient for
// HandleACOnline / HandleDBOnline to enter and block on the first
// map mutex. No listener, no device, no storage — tests only need
// to observe that dispatch returns before the handler completes.
func newTestServerForDispatch(t *testing.T) *UdpServer {
	t.Helper()
	return &UdpServer{
		metrics:             metrics.NewPublisherForTest(t),
		acPeerMap:           map[string]*core.UdpPeer{},
		acConnectionMap:     map[string][]*ACConn{},
		remoteConnectionMap: map[string]*UdpConn{},
		dbPeerMap:           map[string]*core.UdpPeer{},
		dbConnectionMap:     map[string]*DBConn{},
	}
}

// newDispatchPPD builds a PacketParserData sufficient to drive
// HandleACOnline / HandleDBOnline into their first mutex acquisition.
// BodyMessage is valid JSON so json.Unmarshal succeeds; ConnData has
// a RemoteAddr so the String() call at handler entry doesn't panic.
func newDispatchPPD(headerType int, body string) *core.PacketParserData {
	return &core.PacketParserData{
		HeaderType:   headerType,
		BodyMessage:  []byte(body),
		SenderTrxId:  1,
		RemotePubKey: []byte{},
		ConnData: &core.ConnectionData{
			RemoteAddr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
		},
	}
}

// assertDispatchReturnsPromptly fails the test if dispatchReceivedMessage
// takes longer than deadline — the failure mode #1163 fences. The outer
// goroutine below exists only so the test gets deadline semantics on
// dispatchReceivedMessage's return; the goroutine that
// dispatchReceivedMessage itself spawns for the handler body is the
// one whose prompt return we're measuring.
func assertDispatchReturnsPromptly(t *testing.T, s *UdpServer, ppd *core.PacketParserData, deadline time.Duration) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		s.dispatchReceivedMessage(ppd)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(deadline):
		t.Fatalf("dispatchReceivedMessage(%d) blocked >%s — dispatch is synchronous (#1163 regression)", ppd.HeaderType, deadline)
	}
}

// TestDispatchReceivedMessage_AOLIsAsync fences that NHP_AOL dispatch
// returns before HandleACOnline's body finishes. acPeerMapMutex is
// HandleACOnline's first shared-state acquisition, held by the test
// for the test's lifetime so a synchronous dispatch would stall there.
func TestDispatchReceivedMessage_AOLIsAsync(t *testing.T) {
	s := newTestServerForDispatch(t)
	s.acPeerMapMutex.Lock()
	// Intentionally not unlocked — keeps the spawned handler goroutine
	// parked on the mutex so it can't race past and panic on unset
	// UdpServer fields. Goroutine dies with the test binary.

	ppd := newDispatchPPD(core.NHP_AOL, `{"acId":"test-ac"}`)
	assertDispatchReturnsPromptly(t, s, ppd, dispatchAssertDeadline)
}

// TestDispatchReceivedMessage_DOLIsAsync fences the same property
// for NHP_DOL. HandleDBOnline's first shared-state acquisition is
// dbPeerMapMutex — held here to force the handler to park at entry.
func TestDispatchReceivedMessage_DOLIsAsync(t *testing.T) {
	s := newTestServerForDispatch(t)
	s.dbPeerMapMutex.Lock()

	ppd := newDispatchPPD(core.NHP_DOL, `{"dbId":"test-db"}`)
	assertDispatchReturnsPromptly(t, s, ppd, dispatchAssertDeadline)
}

// TestDispatchReceivedMessage_SlowAOLDoesNotBlockSubsequent fences
// the head-of-line-blocking behavior directly: even while one AOL
// handler is parked on a mutex, additional dispatch calls still
// return immediately. This is the property that prevents recvMsgCh
// saturation — without it, packetToMsgRoutine silently drops knocks.
func TestDispatchReceivedMessage_SlowAOLDoesNotBlockSubsequent(t *testing.T) {
	s := newTestServerForDispatch(t)
	s.acPeerMapMutex.Lock()

	// First dispatch parks its handler on the held mutex. Use the
	// deadline-wrapped helper here too so a sync regression trips the
	// 500ms fail path instead of hanging until go test's timeout.
	first := newDispatchPPD(core.NHP_AOL, `{"acId":"first-ac"}`)
	assertDispatchReturnsPromptly(t, s, first, dispatchAssertDeadline)

	// Subsequent dispatches must still return promptly — each arm
	// spawns its own goroutine, so the parked handler can't block
	// the dispatch loop.
	second := newDispatchPPD(core.NHP_AOL, `{"acId":"second-ac"}`)
	assertDispatchReturnsPromptly(t, s, second, dispatchAssertDeadline)
}

// TestDispatchReceivedMessage_ManyConcurrentAOLsDoNotSerialize fences
// that dispatching many AOLs back-to-back also doesn't serialize on
// the first one's handler. Under a sync regression each goroutine
// would block forever on the held mutex and wg.Wait would never
// return — the test hangs until `go test`'s default timeout rather
// than tripping the 500ms deadline. Either way it correctly fences
// async-vs-sync.
func TestDispatchReceivedMessage_ManyConcurrentAOLsDoNotSerialize(t *testing.T) {
	s := newTestServerForDispatch(t)
	s.acPeerMapMutex.Lock()

	const n = 20
	var wg sync.WaitGroup
	wg.Add(n)
	start := time.Now()
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			s.dispatchReceivedMessage(newDispatchPPD(core.NHP_AOL, `{"acId":"flood-ac"}`))
		}()
	}

	// Wrap wg.Wait in a deadline-select so a sync regression trips
	// the dispatchAssertDeadline fail path instead of hanging the
	// whole test binary until go test's 10-minute default timeout.
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(dispatchAssertDeadline):
		t.Fatalf("dispatch of %d AOLs did not all return within %s while handler was parked — dispatch is serializing (#1163 regression)", n, dispatchAssertDeadline)
	}
	// Secondary check: the select above fences wg.Wait alone; this
	// catches the case where the dispatch loop itself takes ≥deadline
	// to spawn its goroutines (e.g., a future refactor adds blocking
	// work to the dispatcher). Different failure mode from the
	// select, not redundant.
	if elapsed := time.Since(start); elapsed > dispatchAssertDeadline {
		t.Fatalf("dispatch of %d AOLs took %s while handler was parked — dispatch is serializing (#1163 regression)", n, elapsed)
	}
}
