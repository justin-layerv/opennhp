package server

import (
	"strconv"
	"sync"
	"testing"
)

// Regression fence for #1525: globalCapAdmits must reject at the
// global cap. The pre-fix inline check let len > Overload (16384)
// short-circuit, leaving the rejection branch unreachable.

// fillRemoteConnectionMap inserts n nil-valued sentinel entries: the
// cap predicate only inspects map size, so no UdpConn allocation is
// needed. Keys are the loop index — the predicate never reads them
// and the test stays correct if MaxConcurrentConnection ever grows.
func fillRemoteConnectionMap(s *UdpServer, n int) {
	for i := 0; i < n; i++ {
		s.remoteConnectionMap[strconv.Itoa(i)] = nil
	}
}

func TestGlobalCapAdmits_EmptyMapAdmitsNoOverload(t *testing.T) {
	s := newTestUdpServer(t)
	s.device.SetOverload(false)

	if !s.globalCapAdmits() {
		t.Fatalf("globalCapAdmits at len=0: got rejected, want admitted")
	}
	if s.device.IsOverload() {
		t.Errorf("overload mode flipped on at len=0, want off")
	}
}

// At len == OverloadConnectionThreshold the threshold check is `n > T`,
// not `n >= T`, so the helper must not flip overload on. This test
// fences against a future `>` → `>=` typo that would prematurely
// signal overload one connection too early.
func TestGlobalCapAdmits_AtOverloadBoundaryAdmitsNoOverload(t *testing.T) {
	s := newTestUdpServer(t)
	s.device.SetOverload(false)
	fillRemoteConnectionMap(s, OverloadConnectionThreshold)

	if !s.globalCapAdmits() {
		t.Fatalf("globalCapAdmits at len=%d: got rejected, want admitted", OverloadConnectionThreshold)
	}
	if s.device.IsOverload() {
		t.Errorf("overload mode flipped on at len=%d (== threshold), want off", OverloadConnectionThreshold)
	}
}

func TestGlobalCapAdmits_AboveOverloadAdmitsAndFlipsOverload(t *testing.T) {
	s := newTestUdpServer(t)
	s.device.SetOverload(false)
	fillRemoteConnectionMap(s, OverloadConnectionThreshold+1)

	if !s.globalCapAdmits() {
		t.Fatalf("globalCapAdmits at len=%d: got rejected, want admitted", OverloadConnectionThreshold+1)
	}
	if !s.device.IsOverload() {
		t.Errorf("overload mode at len=%d: got off, want on", OverloadConnectionThreshold+1)
	}
}

func TestGlobalCapAdmits_JustBelowCapAdmits(t *testing.T) {
	s := newTestUdpServer(t)
	s.device.SetOverload(false)
	fillRemoteConnectionMap(s, MaxConcurrentConnection-1)

	if !s.globalCapAdmits() {
		t.Fatalf("globalCapAdmits at len=%d: got rejected, want admitted", MaxConcurrentConnection-1)
	}
	if !s.device.IsOverload() {
		t.Errorf("overload mode at len=%d: got off, want on", MaxConcurrentConnection-1)
	}
}

// At the cap globalCapAdmits rejects AND flips overload — even on
// the rejection path, the overload flag must reflect map size so a
// rejected recv packet doesn't leave the device under-reporting
// load.
func TestGlobalCapAdmits_AtCapRejectsAndFlipsOverload(t *testing.T) {
	s := newTestUdpServer(t)
	s.device.SetOverload(false)
	fillRemoteConnectionMap(s, MaxConcurrentConnection)

	if s.globalCapAdmits() {
		t.Fatalf("globalCapAdmits at len=%d: got admitted, want rejected (#1525 regression)", MaxConcurrentConnection)
	}
	if !s.device.IsOverload() {
		t.Errorf("overload mode at len=%d: got off, want on", MaxConcurrentConnection)
	}
}

// Defense-in-depth: above-cap state is reachable today via webrtc's
// pre-existing bypass; the predicate must still reject and the
// overload flag must still reflect the (above-threshold) map size.
func TestGlobalCapAdmits_AboveCapRejectsAndFlipsOverload(t *testing.T) {
	s := newTestUdpServer(t)
	s.device.SetOverload(false)
	fillRemoteConnectionMap(s, MaxConcurrentConnection+1)

	if s.globalCapAdmits() {
		t.Fatalf("globalCapAdmits at len=%d: got admitted, want rejected", MaxConcurrentConnection+1)
	}
	if !s.device.IsOverload() {
		t.Errorf("overload mode at len=%d: got off, want on", MaxConcurrentConnection+1)
	}
}

// The reject path must meter MetricGlobalCapRejections so operators get
// a numeric tripwire, not just a greppable log line (#1570). Steady
// state is zero (MaxConcurrentConnection sits far above legitimate
// load), so any non-zero value flags attack-shaped or misbehaved load.
func TestGlobalCapAdmits_EmitsRejectionMetricOnReject(t *testing.T) {
	s := newTestUdpServer(t)
	fillRemoteConnectionMap(s, MaxConcurrentConnection)

	if s.globalCapAdmits() {
		t.Fatalf("globalCapAdmits at len=%d: got admitted, want rejected", MaxConcurrentConnection)
	}

	counters, _ := s.metrics.CountersForTest(t)
	if got := counters[MetricGlobalCapRejections]; got != 1 {
		t.Errorf("MetricGlobalCapRejections after one reject: got %v, want 1", got)
	}
}

// The admit path must NOT meter the reject counter — a false increment
// on every healthy knock would turn the operator tripwire into noise.
func TestGlobalCapAdmits_NoRejectionMetricOnAdmit(t *testing.T) {
	s := newTestUdpServer(t)
	fillRemoteConnectionMap(s, MaxConcurrentConnection-1)

	if !s.globalCapAdmits() {
		t.Fatalf("globalCapAdmits at len=%d: got rejected, want admitted", MaxConcurrentConnection-1)
	}

	counters, _ := s.metrics.CountersForTest(t)
	if got := counters[MetricGlobalCapRejections]; got != 0 {
		t.Errorf("MetricGlobalCapRejections after one admit: got %v, want 0", got)
	}
}

// recvPacketRoutine is single-threaded today, so globalCapAdmits is
// only called from one goroutine. This test pins the helper's lock
// discipline against a future inlining mistake or a second admit
// path that calls it concurrently: every caller must observe a
// consistent (admit, overload) pair under the mutex.
func TestGlobalCapAdmits_ConcurrentCallsAreConsistent(t *testing.T) {
	s := newTestUdpServer(t)
	s.device.SetOverload(false)
	fillRemoteConnectionMap(s, MaxConcurrentConnection)

	const goroutines = 32
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			if s.globalCapAdmits() {
				t.Errorf("concurrent globalCapAdmits at len=%d: got admitted, want rejected", MaxConcurrentConnection)
			}
		}()
	}
	wg.Wait()
	if !s.device.IsOverload() {
		t.Errorf("overload mode after concurrent calls at len=%d: got off, want on", MaxConcurrentConnection)
	}
}
