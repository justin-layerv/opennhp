package core

import (
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
