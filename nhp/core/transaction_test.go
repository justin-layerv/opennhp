package core

import (
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	common "github.com/OpenNHP/opennhp/nhp/common"
)

// TestRemoteTransaction_SendMessage_Delivers verifies the happy path:
// SendMessage on an active transaction delivers to NextMsgCh.
func TestRemoteTransaction_SendMessage_Delivers(t *testing.T) {
	ch := make(chan *MsgData, 1)
	tx := NewRemoteTransactionForTest(1, ch)
	// Close the done channel on teardown so the lifecycle matches the
	// real Run() defer (delete-then-close under the mutex). Keeps the
	// test transaction from looking "forever alive" if later edits
	// introduce assertions that care about the terminated state.
	t.Cleanup(tx.CloseForTest)

	md := &MsgData{}
	if err := tx.SendMessage(md); err != nil {
		t.Fatalf("SendMessage failed on active transaction: %v", err)
	}

	select {
	case got := <-ch:
		if got != md {
			t.Errorf("received wrong pointer: got %p, want %p", got, md)
		}
	default:
		t.Errorf("SendMessage returned nil but NextMsgCh is empty")
	}
}

// TestRemoteTransaction_SendMessage_AfterDone fences the
// "panic: send on closed channel" regression: SendMessage on a
// transaction whose done is closed must return ErrTransactionClosed,
// never panic.
func TestRemoteTransaction_SendMessage_AfterDone(t *testing.T) {
	tx := NewRemoteTransactionForTest(1, make(chan *MsgData))
	tx.CloseForTest()

	err := tx.SendMessage(&MsgData{})
	if !errors.Is(err, common.ErrTransactionClosed) {
		t.Errorf("SendMessage after done: got %v, want ErrTransactionClosed", err)
	}
}

// TestRemoteTransaction_SendRacesClose stress-tests the exact race that
// caused the production crash: many goroutines concurrently call
// SendMessage while another goroutine signals the transaction as closed.
// Every send must return cleanly — no panic, no deadlock, no leaked
// sender goroutine. Counters must account for every sender.
//
// Run with -race to catch any residual unsynchronized access.
func TestRemoteTransaction_SendRacesClose(t *testing.T) {
	const senders = 64
	const iterations = 50

	for i := 0; i < iterations; i++ {
		// Unbuffered channel + active drainer mirrors the production
		// configuration (Device.go creates NextMsgCh unbuffered). Every
		// delivered message is a synchronous rendezvous, so delivered ==
		// drained holds exactly — sends that race the close either
		// complete the rendezvous or return via the done case.
		ch := make(chan *MsgData)
		tx := NewRemoteTransactionForTest(uint64(i), ch)

		var drained atomic.Int64
		var drainerWG sync.WaitGroup
		drainerWG.Add(1)
		go func() {
			defer drainerWG.Done()
			for {
				select {
				case <-ch:
					drained.Add(1)
				case <-tx.Done():
					return
				}
			}
		}()

		var wg sync.WaitGroup
		var delivered, closed atomic.Int64
		var firstPanic atomic.Value

		for j := 0; j < senders; j++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() {
					if r := recover(); r != nil {
						firstPanic.CompareAndSwap(nil, r)
					}
				}()
				err := tx.SendMessage(&MsgData{})
				switch {
				case err == nil:
					delivered.Add(1)
				case errors.Is(err, common.ErrTransactionClosed):
					closed.Add(1)
				default:
					firstPanic.CompareAndSwap(nil, err)
				}
			}()
		}

		// Close the transaction after some senders have had a chance to
		// enter their select. runtime.Gosched nudges the scheduler
		// without enforcing a specific ordering, preserving the race.
		go func() {
			runtime.Gosched()
			tx.CloseForTest()
		}()

		wg.Wait()
		drainerWG.Wait()

		if p := firstPanic.Load(); p != nil {
			t.Fatalf("iteration %d: sender panicked (regression of \"send on closed channel\"): %v", i, p)
		}
		if got, want := delivered.Load()+closed.Load(), int64(senders); got != want {
			t.Errorf("iteration %d: delivered(%d)+closed(%d) = %d, want %d (sender leaked)",
				i, delivered.Load(), closed.Load(), got, want)
		}
		if delivered.Load() != drained.Load() {
			t.Errorf("iteration %d: delivered=%d but drained=%d (message lost or double-counted)",
				i, delivered.Load(), drained.Load())
		}
	}
}

// TestRemoteTransaction_SendRacesCloseNoReader is a second stress variant:
// no drainer at all, so sends that find NextMsgCh blocked must all take
// the done path after CloseForTest fires. A successful completion means
// no sender was left blocked on NextMsgCh.
func TestRemoteTransaction_SendRacesCloseNoReader(t *testing.T) {
	const senders = 32

	ch := make(chan *MsgData) // unbuffered, no reader
	tx := NewRemoteTransactionForTest(1, ch)

	var wg sync.WaitGroup
	var closed atomic.Int64
	var entered atomic.Int64
	var firstErr atomic.Value

	for j := 0; j < senders; j++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			entered.Add(1)
			err := tx.SendMessage(&MsgData{})
			if errors.Is(err, common.ErrTransactionClosed) {
				closed.Add(1)
				return
			}
			firstErr.CompareAndSwap(nil, err)
		}()
	}

	// Barrier: wait until every goroutine has been scheduled and is
	// about to enter SendMessage's select, then yield once more to
	// maximize the chance they're blocked on NextMsgCh before close.
	// Correctness does not depend on precise timing — any sender that
	// enters select after close still takes the done path — but this
	// gives deterministic race pressure across slow CI runners.
	for entered.Load() < senders {
		runtime.Gosched()
	}
	runtime.Gosched()
	tx.CloseForTest()

	// Guard against a regressed leak: if a sender were stuck on
	// NextMsgCh without the done case, wg.Wait would hang forever.
	doneWG := make(chan struct{})
	go func() {
		wg.Wait()
		close(doneWG)
	}()
	select {
	case <-doneWG:
	case <-time.After(5 * time.Second):
		t.Fatal("senders leaked: wg.Wait did not return within 5s after CloseForTest")
	}

	if e := firstErr.Load(); e != nil {
		t.Fatalf("unexpected sender error: %v", e)
	}
	if closed.Load() != senders {
		t.Errorf("closed=%d, want %d (sender returned without closed error)", closed.Load(), senders)
	}
}

// TestLocalTransaction_SendAfterDone covers the mirror surface for
// LocalTransaction's two send channels.
func TestLocalTransaction_SendAfterDone(t *testing.T) {
	tx := &LocalTransaction{
		transactionId: 1,
		NextPacketCh:  make(chan *Packet),
		ExternalMsgCh: make(chan *PacketParserData),
		done:          make(chan struct{}),
	}
	close(tx.done)

	if err := tx.SendPacket(&Packet{}); !errors.Is(err, common.ErrTransactionClosed) {
		t.Errorf("SendPacket: got %v, want ErrTransactionClosed", err)
	}
	if err := tx.SendExternalMsg(&PacketParserData{}); !errors.Is(err, common.ErrTransactionClosed) {
		t.Errorf("SendExternalMsg: got %v, want ErrTransactionClosed", err)
	}
}

// TestLocalTransaction_SendRacesClose exercises the same race shape as
// TestRemoteTransaction_SendRacesClose but for LocalTransaction's two
// send surfaces simultaneously. Both channels share the same done
// channel, so both Send* methods must fail closed together.
func TestLocalTransaction_SendRacesClose(t *testing.T) {
	const sendersPerChannel = 32
	const iterations = 30

	for i := 0; i < iterations; i++ {
		// Unbuffered mirrors production: nhp/core/device.go creates both
		// LocalTransaction channels unbuffered. A buffered channel lets
		// sends complete immediately into the buffer without entering
		// the select's race path, weakening this test's race pressure.
		tx := &LocalTransaction{
			transactionId: uint64(i),
			NextPacketCh:  make(chan *Packet),
			ExternalMsgCh: make(chan *PacketParserData),
			done:          make(chan struct{}),
		}

		var drainerWG sync.WaitGroup
		drainerWG.Add(2)
		go func() {
			defer drainerWG.Done()
			for {
				select {
				case <-tx.NextPacketCh:
				case <-tx.done:
					return
				}
			}
		}()
		go func() {
			defer drainerWG.Done()
			for {
				select {
				case <-tx.ExternalMsgCh:
				case <-tx.done:
					return
				}
			}
		}()

		var wg sync.WaitGroup
		var firstPanic atomic.Value

		for j := 0; j < sendersPerChannel; j++ {
			wg.Add(2)
			go func() {
				defer wg.Done()
				defer func() {
					if r := recover(); r != nil {
						firstPanic.CompareAndSwap(nil, r)
					}
				}()
				_ = tx.SendPacket(&Packet{})
			}()
			go func() {
				defer wg.Done()
				defer func() {
					if r := recover(); r != nil {
						firstPanic.CompareAndSwap(nil, r)
					}
				}()
				_ = tx.SendExternalMsg(&PacketParserData{})
			}()
		}

		go func() {
			runtime.Gosched()
			close(tx.done)
		}()

		wg.Wait()
		drainerWG.Wait()

		if p := firstPanic.Load(); p != nil {
			t.Fatalf("iteration %d: sender panicked (local tx race regression): %v", i, p)
		}
	}
}

// TestRemoteTransaction_CloseForTest_Idempotent ensures CloseForTest
// can be called multiple times (e.g. from the test body AND a
// t.Cleanup) without double-closing done.
func TestRemoteTransaction_CloseForTest_Idempotent(t *testing.T) {
	tx := NewRemoteTransactionForTest(1, make(chan *MsgData))

	tx.CloseForTest()
	tx.CloseForTest() // second call must not panic
	tx.CloseForTest() // third call must not panic

	select {
	case <-tx.Done():
		// ok
	default:
		t.Errorf("done channel is not closed after CloseForTest")
	}
}

// TestDevice_LocalTransactionCount pins the contract surfaced by
// graceful-shutdown's awaitTransactionDrain wait loop: the count must
// reflect Add/Remove events under the same mutex protecting the map,
// so a polling loop sees zero exactly when the map is empty.
func TestDevice_LocalTransactionCount(t *testing.T) {
	d := &Device{localTransactionMap: make(map[uint64]*LocalTransaction)}

	if got := d.LocalTransactionCount(); got != 0 {
		t.Fatalf("empty map: count = %d, want 0", got)
	}

	d.localTransactionMutex.Lock()
	d.localTransactionMap[1] = &LocalTransaction{transactionId: 1}
	d.localTransactionMap[2] = &LocalTransaction{transactionId: 2}
	d.localTransactionMutex.Unlock()

	if got := d.LocalTransactionCount(); got != 2 {
		t.Errorf("after two adds: count = %d, want 2", got)
	}

	d.localTransactionMutex.Lock()
	delete(d.localTransactionMap, 1)
	d.localTransactionMutex.Unlock()

	if got := d.LocalTransactionCount(); got != 1 {
		t.Errorf("after one delete: count = %d, want 1", got)
	}
}

// TestRemoteTransaction_FindAfterRunCleanup verifies the ordering
// invariant that made the fix correct: once a transaction's Run() has
// released the RemoteTransactionMutex, Find must return nil. Any caller
// that still holds a pre-cleanup pointer reaches SendMessage, which
// returns ErrTransactionClosed via the done channel.
//
// Simulates the cleanup sequence without a full Run() to keep the test
// dependency-free — the real Run defer is reviewed in transaction.go.
func TestRemoteTransaction_FindAfterRunCleanup(t *testing.T) {
	conn := &ConnectionData{
		RemoteTransactionMap: make(map[uint64]*RemoteTransaction),
	}
	tx := &RemoteTransaction{
		transactionId: 42,
		NextMsgCh:     make(chan *MsgData),
		done:          make(chan struct{}),
	}
	conn.RemoteTransactionMap[tx.transactionId] = tx

	// Caller captures a pointer BEFORE cleanup.
	captured := conn.FindRemoteTransaction(42)
	if captured != tx {
		t.Fatalf("pre-cleanup Find returned wrong transaction")
	}

	// Simulate Run()'s cleanup defer: delete and close under the mutex.
	conn.RemoteTransactionMutex.Lock()
	delete(conn.RemoteTransactionMap, tx.transactionId)
	close(tx.done)
	conn.RemoteTransactionMutex.Unlock()

	// A fresh Find must return nil.
	if post := conn.FindRemoteTransaction(42); post != nil {
		t.Errorf("Find after cleanup returned non-nil, want nil")
	}

	// The caller with a stale pointer must see ErrTransactionClosed
	// rather than panicking.
	if err := captured.SendMessage(&MsgData{}); !errors.Is(err, common.ErrTransactionClosed) {
		t.Errorf("stale-pointer SendMessage: got %v, want ErrTransactionClosed", err)
	}
}

// TestLocalTransactionTimeout_AOPDecoupledFromSharedServerTimeout fences the #3046
// blast-radius fix: the server->AC AC-open (NHP_AOP) gets the aggressive DNS-fast 1.5s
// timeout, while EVERY OTHER server-initiated transaction (DB key-wrap NHP_DWR,
// forwarded knock NHP_FWD, ...) keeps the conservative shared timeout. A regression
// that dropped the shared constant to speed the knock, or routed the DB/forward paths
// through the 1.5s AOP timeout, could fail a cold-TEE DB wrap with no retry to absorb it
// -- this turns that into a red build instead of a silent prod degradation.
func TestLocalTransactionTimeout_AOPDecoupledFromSharedServerTimeout(t *testing.T) {
	server := &Device{deviceType: NHP_SERVER}

	if got := server.LocalTransactionTimeout(NHP_AOP); got != ServerACOpenTransactionResponseTimeoutMs {
		t.Errorf("server NHP_AOP timeout = %d, want ServerACOpenTransactionResponseTimeoutMs (%d)",
			got, ServerACOpenTransactionResponseTimeoutMs)
	}
	for _, mt := range []int{NHP_DWR, NHP_FWD} {
		if got := server.LocalTransactionTimeout(mt); got != ServerLocalTransactionResponseTimeoutMs {
			t.Errorf("server msgType %d timeout = %d, want the shared ServerLocalTransactionResponseTimeoutMs (%d) -- only NHP_AOP is decoupled",
				mt, got, ServerLocalTransactionResponseTimeoutMs)
		}
	}
	// The decoupling only means something if the AOP timeout is actually tighter.
	if ServerACOpenTransactionResponseTimeoutMs >= ServerLocalTransactionResponseTimeoutMs {
		t.Fatalf("AOP timeout (%d) must be < the shared server timeout (%d)",
			ServerACOpenTransactionResponseTimeoutMs, ServerLocalTransactionResponseTimeoutMs)
	}
	// Other device types are unaffected by the msgType arg.
	if got := (&Device{deviceType: NHP_AGENT}).LocalTransactionTimeout(NHP_AOP); got != AgentLocalTransactionResponseTimeoutMs {
		t.Errorf("agent timeout = %d, want AgentLocalTransactionResponseTimeoutMs (%d)", got, AgentLocalTransactionResponseTimeoutMs)
	}
}
