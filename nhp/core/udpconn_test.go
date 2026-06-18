package core

import (
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewStoppedTimer_NotRunning(t *testing.T) {
	timer := NewStoppedTimer()
	defer timer.Stop()

	select {
	case <-timer.C:
		t.Fatal("timer fired without Reset")
	case <-time.After(50 * time.Millisecond):
		// expected
	}

	timer.Reset(20 * time.Millisecond)

	select {
	case <-timer.C:
		// expected
	case <-time.After(200 * time.Millisecond):
		t.Fatal("timer did not fire within 200ms after Reset(20ms)")
	}
}

func TestSetTimeout_StoresAtomicValue(t *testing.T) {
	cd := &ConnectionData{
		SetTimeoutSignal: make(chan struct{}, 1),
		StopSignal:       make(chan struct{}),
	}
	cd.InitTimeoutMs(100)

	cd.SetTimeout(250)

	if got := cd.TimeoutMs(); got != 250 {
		t.Errorf("TimeoutMs after SetTimeout: got %d, want 250", got)
	}

	select {
	case <-cd.SetTimeoutSignal:
		// expected
	default:
		t.Error("SetTimeout did not signal SetTimeoutSignal")
	}
}

func TestSetTimeout_NoReceiverDoesNotBlock(t *testing.T) {
	silenceGlobalLogger(t)

	cd := newCloseRaceConnectionData()

	for i := 0; i < 2; i++ {
		done := make(chan struct{})
		go func(ms int) {
			cd.SetTimeout(ms)
			close(done)
		}(300 + i)

		select {
		case <-done:
		case <-time.After(200 * time.Millisecond):
			t.Fatal("SetTimeout blocked without a receiver")
		}
	}

	if got := cd.TimeoutMs(); got != 301 {
		t.Errorf("TimeoutMs after coalesced SetTimeout: got %d, want 301", got)
	}
}

func TestSetTimeout_AfterCloseDoesNotPanic(t *testing.T) {
	silenceGlobalLogger(t)

	cd := newCloseRaceConnectionData()
	cd.InitTimeoutMs(100)
	cd.Close()

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("SetTimeout after Close panicked: %v", r)
		}
	}()
	cd.SetTimeout(250)
	if got := cd.TimeoutMs(); got != 100 {
		t.Fatalf("SetTimeout after Close mutated TimeoutMs: got %d, want 100", got)
	}
}

func TestSetTimeout_WithReceiverDeliversLatestValue(t *testing.T) {
	silenceGlobalLogger(t)

	cd := newCloseRaceConnectionData()

	got := make(chan int, 1)
	go func() {
		<-cd.SetTimeoutSignal
		got <- cd.TimeoutMs()
	}()

	cd.SetTimeout(450)

	select {
	case ms := <-got:
		if ms != 450 {
			t.Fatalf("receiver saw TimeoutMs %d, want 450", ms)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("timed out waiting for SetTimeoutSignal receiver")
	}
}

func TestConnectionDataCloseConcurrentIsIdempotent(t *testing.T) {
	cd := &ConnectionData{
		StopSignal:       make(chan struct{}),
		SendQueue:        make(chan *Packet, 1),
		RecvQueue:        make(chan *Packet, 1),
		BlockSignal:      make(chan struct{}),
		SetTimeoutSignal: make(chan struct{}, 1),
	}

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cd.Close()
		}()
	}
	wg.Wait()

	if !cd.IsClosed() {
		t.Fatal("Close did not mark connection closed")
	}
	select {
	case <-cd.StopSignal:
		// expected
	default:
		t.Fatal("Close did not close StopSignal")
	}
	assertClosedChannel(t, "SendQueue", cd.SendQueue)
	assertClosedChannel(t, "RecvQueue", cd.RecvQueue)
	assertClosedChannel(t, "BlockSignal", cd.BlockSignal)
	assertClosedChannel(t, "SetTimeoutSignal", cd.SetTimeoutSignal)

	cd.Close()
}

func assertClosedChannel[T any](t *testing.T, name string, ch <-chan T) {
	t.Helper()
	if ch == nil {
		t.Fatalf("%s is nil after Close", name)
	}
	select {
	case _, ok := <-ch:
		if ok {
			t.Fatalf("%s remained open after Close", name)
		}
	default:
		t.Fatalf("%s did not close", name)
	}
}

func TestConnectionDataForwardOutboundPacketEnqueuesWhenOpen(t *testing.T) {
	silenceGlobalLogger(t)

	cd := newCloseRaceConnectionData()
	cd.SendQueue = make(chan *Packet, 1)
	pkt := &Packet{Content: []byte{1}}

	cd.ForwardOutboundPacket(pkt)

	select {
	case got := <-cd.SendQueue:
		if got != pkt {
			t.Fatalf("ForwardOutboundPacket enqueued %p, want %p", got, pkt)
		}
	default:
		t.Fatal("ForwardOutboundPacket did not enqueue packet on open connection")
	}

	cd.Close()
}

func TestConnectionDataChannelSendsRaceClose(t *testing.T) {
	silenceGlobalLogger(t)

	tests := []struct {
		name string
		op   func(*ConnectionData)
	}{
		{
			name: "outbound",
			op: func(cd *ConnectionData) {
				cd.ForwardOutboundPacket(&Packet{Content: []byte{1}})
			},
		},
		{
			name: "inbound",
			op: func(cd *ConnectionData) {
				cd.ForwardInboundPacket(&Packet{Content: []byte{1}})
			},
		},
		{
			name: "block",
			op: func(cd *ConnectionData) {
				cd.SendBlockSignal()
			},
		},
		{
			name: "timeout",
			op: func(cd *ConnectionData) {
				cd.SetTimeout(25)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			exerciseConnectionDataCloseRace(t, tc.op)
		})
	}
}

func exerciseConnectionDataCloseRace(t *testing.T, op func(*ConnectionData)) {
	t.Helper()

	const senders = 64

	cd := newCloseRaceConnectionData()

	var launched atomic.Int32
	var wg sync.WaitGroup
	var panicOnce sync.Once
	var firstPanic any

	for i := 0; i < senders; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					panicOnce.Do(func() {
						firstPanic = r
					})
				}
			}()
			launched.Add(1)
			op(cd)
		}()
	}

	deadline := time.Now().Add(time.Second)
	for launched.Load() < senders {
		if time.Now().After(deadline) {
			t.Fatalf("only %d/%d senders launched before deadline", launched.Load(), senders)
		}
		runtime.Gosched()
	}
	// The barrier above proves goroutines are launched; the unbuffered queues
	// and scheduler yield below provide the close-race pressure.
	runtime.Gosched()

	done := make(chan struct{})
	go func() {
		cd.Close()
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Close or channel senders deadlocked")
	}

	if firstPanic != nil {
		t.Fatalf("channel send raced Close and panicked: %v", firstPanic)
	}
	if !cd.IsClosed() {
		t.Fatal("Close did not mark connection closed")
	}
}

func newCloseRaceConnectionData() *ConnectionData {
	return &ConnectionData{
		Device:               &Device{},
		LocalAddr:            &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 2000},
		RemoteAddr:           &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 2001},
		CookieStore:          &CookieStore{},
		SendQueue:            make(chan *Packet),
		RecvQueue:            make(chan *Packet),
		BlockSignal:          make(chan struct{}),
		SetTimeoutSignal:     make(chan struct{}, 1),
		StopSignal:           make(chan struct{}),
		RemoteTransactionMap: make(map[uint64]*RemoteTransaction),
	}
}
