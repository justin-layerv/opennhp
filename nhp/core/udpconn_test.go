package core

import (
	"sync"
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
		SetTimeoutSignal: make(chan struct{}, 1), // buffered so this unit test can SetTimeout without a real receiving routine; production uses unbuffered.
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

	cd.Close()
}
