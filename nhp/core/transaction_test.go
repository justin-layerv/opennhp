package core

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	common "github.com/OpenNHP/opennhp/nhp/common"
)

func TestLocalTransactionPreservesResponseReceiptTime(t *testing.T) {
	device := &Device{packetToMsgQueue: make(chan *PacketData, 1)}
	mad := &MsgAssemblerData{device: device}
	transaction := newLocalTransaction(1, &ConnectionData{StopSignal: make(chan struct{})}, mad, 5000)
	device.wg.Add(1)
	go transaction.Run()

	const receivedAtNanos = int64(123456789)
	packet := &Packet{ReceivedAtNanos: receivedAtNanos}
	if err := transaction.SendPacket(packet); err != nil {
		t.Fatalf("SendPacket: %v", err)
	}
	select {
	case pd := <-device.packetToMsgQueue:
		if pd.InitTime != receivedAtNanos {
			t.Fatalf("transaction response InitTime = %d, want receipt %d", pd.InitTime, receivedAtNanos)
		}
	case <-time.After(time.Second):
		t.Fatal("transaction response was not handed to the decrypt queue")
	}
	select {
	case <-transaction.Done():
	case <-time.After(time.Second):
		t.Fatal("local transaction did not complete")
	}
}

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

func TestRemoteTransactionSendMessageContextDeadlineHasNoLateDelivery(t *testing.T) {
	ch := make(chan *MsgData)
	tx := NewRemoteTransactionForTest(1, ch)
	t.Cleanup(tx.CloseForTest)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	message := &MsgData{}
	started := time.Now()
	if err := tx.SendMessageContext(ctx, message); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("SendMessageContext error = %v, want deadline exceeded", err)
	}
	if elapsed := time.Since(started); elapsed < 10*time.Millisecond || elapsed > time.Second {
		t.Fatalf("deadline handoff elapsed %s", elapsed)
	}

	// A goroutine-based timeout wrapper could leave a blocked sender behind and
	// deliver after returning. Making a receiver available now must observe no
	// stale message from the completed call.
	select {
	case got := <-ch:
		t.Fatalf("late message delivered after deadline: %p", got)
	case <-time.After(20 * time.Millisecond):
	}
}

func TestRemoteTransactionSendMessageContextPreCanceledNeverDelivers(t *testing.T) {
	const iterations = 1000
	for i := 0; i < iterations; i++ {
		// A buffered channel makes the send case immediately ready. The explicit
		// context fence before the select must still make a pre-canceled request
		// deterministic rather than letting select choose the ready send.
		ch := make(chan *MsgData, 1)
		tx := NewRemoteTransactionForTest(uint64(i), ch)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		if err := tx.SendMessageContext(ctx, &MsgData{}); !errors.Is(err, context.Canceled) {
			tx.CloseForTest()
			t.Fatalf("iteration %d: SendMessageContext error = %v, want context canceled", i, err)
		}
		if len(ch) != 0 {
			tx.CloseForTest()
			t.Fatalf("iteration %d: pre-canceled message was delivered", i)
		}
		tx.CloseForTest()
	}
}

func TestRemoteTransactionCompleteContextDelivers(t *testing.T) {
	tx := NewRemoteTransactionForTest(1, make(chan *MsgData))
	t.Cleanup(tx.CloseForTest)
	received := make(chan struct{})
	go func() {
		<-tx.complete
		close(received)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := tx.CompleteContext(ctx); err != nil {
		t.Fatalf("CompleteContext: %v", err)
	}
	select {
	case <-received:
	case <-time.After(time.Second):
		t.Fatal("completion receiver did not observe rendezvous")
	}
}

func TestRemoteTransactionCompleteContextDeadlineHasNoLateDelivery(t *testing.T) {
	tx := NewRemoteTransactionForTest(1, make(chan *MsgData))
	t.Cleanup(tx.CloseForTest)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := tx.CompleteContext(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("CompleteContext error = %v, want deadline exceeded", err)
	}

	// A timed-out goroutine sender could finish the transaction after its caller
	// had already classified the response as censored. Making the receiver ready
	// after the deadline must not observe a stale completion.
	select {
	case <-tx.complete:
		t.Fatal("late completion delivered after deadline")
	case <-time.After(20 * time.Millisecond):
	}
}

func TestRemoteTransactionCompleteContextPreCanceledNeverDelivers(t *testing.T) {
	tx := NewRemoteTransactionForTest(1, make(chan *MsgData))
	t.Cleanup(tx.CloseForTest)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := tx.CompleteContext(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("CompleteContext error = %v, want context canceled", err)
	}
	select {
	case <-tx.complete:
		t.Fatal("pre-canceled completion was delivered")
	default:
	}
}

func TestRemoteTransactionCompleteContextAfterClose(t *testing.T) {
	tx := NewRemoteTransactionForTest(1, make(chan *MsgData))
	tx.CloseForTest()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := tx.CompleteContext(ctx); !errors.Is(err, common.ErrTransactionClosed) {
		t.Fatalf("CompleteContext error = %v, want ErrTransactionClosed", err)
	}
}

func TestRemoteTransactionCompleteContextRejectsIncompleteTransaction(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, tx := range []*RemoteTransaction{
		nil,
		{done: make(chan struct{})},
		{complete: make(chan struct{})},
	} {
		if err := tx.CompleteContext(ctx); !errors.Is(err, common.ErrTransactionClosed) {
			t.Fatalf("CompleteContext error = %v, want ErrTransactionClosed", err)
		}
	}
}

func TestRemoteTransactionCompleteContextCloseRace(t *testing.T) {
	tx := NewRemoteTransactionForTest(1, make(chan *MsgData))

	const callers = 32
	results := make(chan error, callers)
	for range callers {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			results <- tx.CompleteContext(ctx)
		}()
	}
	tx.CloseForTest()

	for range callers {
		select {
		case err := <-results:
			if !errors.Is(err, common.ErrTransactionClosed) {
				t.Fatalf("CompleteContext error = %v, want ErrTransactionClosed", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("CompleteContext remained blocked after transaction close")
		}
	}
}

func TestRemoteTransactionCleanupPreservesSameIDReplacement(t *testing.T) {
	conn := &ConnectionData{
		RemoteTransactionMap: make(map[uint64]*RemoteTransaction),
		StopSignal:           make(chan struct{}),
	}
	firstParser := &PacketParserData{
		device:      &Device{},
		ConnData:    conn,
		SenderTrxId: 77,
	}
	first := StartRemoteTransactionForTest(firstParser, time.Second)
	if first == nil || firstParser.OwningRemoteTransaction() != first {
		t.Fatal("first parser did not carry its owning transaction")
	}
	secondParser := &PacketParserData{
		device:      &Device{},
		ConnData:    conn,
		SenderTrxId: 77,
	}
	second := StartRemoteTransactionForTest(secondParser, time.Second)
	if second == nil || secondParser.OwningRemoteTransaction() != second {
		t.Fatal("second parser did not carry its owning transaction")
	}
	if got := conn.FindRemoteTransaction(77); got != second {
		t.Fatalf("same-id replacement = %p, want second owner %p", got, second)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := first.CompleteContext(ctx); err != nil {
		t.Fatalf("complete first owner: %v", err)
	}
	select {
	case <-first.Done():
	case <-time.After(time.Second):
		t.Fatal("first owner did not finish")
	}
	if got := conn.FindRemoteTransaction(77); got != second {
		t.Fatalf("first cleanup removed replacement: got %p, want %p", got, second)
	}

	if err := second.CompleteContext(ctx); err != nil {
		t.Fatalf("complete second owner: %v", err)
	}
	select {
	case <-second.Done():
	case <-time.After(time.Second):
		t.Fatal("second owner did not finish")
	}
	if got := conn.FindRemoteTransaction(77); got != nil {
		t.Fatalf("second cleanup retained map entry %p", got)
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

func TestLocalTransactionTimeout_ACRegistrationOutlivesServerCatchUp(t *testing.T) {
	ac := &Device{deviceType: NHP_AC}
	if got := ac.LocalTransactionTimeout(NHP_AOL); got != ACRegistrationTransactionResponseTimeoutMs {
		t.Fatalf("AC NHP_AOL timeout = %d, want %d", got, ACRegistrationTransactionResponseTimeoutMs)
	}
	if ACRegistrationTransactionResponseTimeoutMs <= RemoteTransactionProcessTimeoutMs {
		t.Fatalf("AC NHP_AOL timeout %d must exceed server remote transaction budget %d",
			ACRegistrationTransactionResponseTimeoutMs, RemoteTransactionProcessTimeoutMs)
	}
	if got := ac.LocalTransactionTimeout(NHP_AOP); got != ACLocalTransactionResponseTimeoutMs {
		t.Fatalf("non-AOL AC timeout = %d, want %d", got, ACLocalTransactionResponseTimeoutMs)
	}
}
