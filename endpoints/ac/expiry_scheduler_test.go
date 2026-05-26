package ac

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ============================================================================
// FlowKey construction + parsing
// ============================================================================

func TestMakeFlowKey_HappyPath(t *testing.T) {
	cases := []struct {
		name, src, dst string
		port           int
		proto          FlowProto
	}{
		{"v4-tcp", "192.0.2.1", "192.0.2.2", 443, FlowProtoTCP},
		{"v4-udp", "10.0.0.1", "10.0.0.2", 53, FlowProtoUDP},
		{"v6-tcp", "2001:db8::1", "2001:db8::2", 443, FlowProtoTCP},
		{"v4-mapped-v6", "::ffff:192.0.2.1", "::ffff:192.0.2.2", 443, FlowProtoTCP},
		{"port-wildcard", "192.0.2.1", "192.0.2.2", 0, FlowProtoAny},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			k, err := MakeFlowKey(c.src, c.dst, c.port, c.proto)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if k.DstPort != uint16(c.port) {
				t.Errorf("port: got %d want %d", k.DstPort, c.port)
			}
			if k.Protocol != c.proto {
				t.Errorf("proto: got %s want %s", k.Protocol, c.proto)
			}
		})
	}
}

func TestMakeFlowKey_RejectsUnspecifiedIPs(t *testing.T) {
	// 0.0.0.0 / :: would let a single flush wipe AC-wide kernel
	// state if accidentally written to ipset; reject at boundary.
	if _, err := MakeFlowKey("0.0.0.0", "192.0.2.1", 443, FlowProtoTCP); err == nil {
		t.Error("expected error on src=0.0.0.0")
	}
	if _, err := MakeFlowKey("192.0.2.1", "0.0.0.0", 443, FlowProtoTCP); err == nil {
		t.Error("expected error on dst=0.0.0.0")
	}
	if _, err := MakeFlowKey("::", "2001:db8::1", 443, FlowProtoTCP); err == nil {
		t.Error("expected error on src=::")
	}
	if _, err := MakeFlowKey("2001:db8::1", "::", 443, FlowProtoTCP); err == nil {
		t.Error("expected error on dst=::")
	}
}

func TestMakeFlowKey_RejectsInvalidPort(t *testing.T) {
	if _, err := MakeFlowKey("192.0.2.1", "192.0.2.2", -1, FlowProtoTCP); err == nil {
		t.Error("expected error on port=-1")
	}
	if _, err := MakeFlowKey("192.0.2.1", "192.0.2.2", 65536, FlowProtoTCP); err == nil {
		t.Error("expected error on port=65536")
	}
}

func TestMakeFlowKey_RejectsBadIP(t *testing.T) {
	if _, err := MakeFlowKey("not-an-ip", "192.0.2.2", 443, FlowProtoTCP); err == nil {
		t.Error("expected error on malformed src IP")
	}
}

// TestScheduler_Schedule_RejectsWallClockDeadline fences the
// Schedule-boundary check that round 3 finding 5 moved up from
// monoNsAt. A wall-clock-only deadline (no monotonic reading,
// e.g. time.Unix(...)) would silently drift with NTP step and
// produce wrong bucket math. Schedule logs a Warning and no-ops
// rather than crash deep in the scheduler.
func TestScheduler_Schedule_RejectsWallClockDeadline(t *testing.T) {
	f := newRecordingFlusher()
	s := NewScheduler(f, WithTickInterval(5*time.Millisecond), WithWheelSize(100))
	s.Start()
	defer shutdownOrFail(t, s)

	k := mustKey(t, "192.0.2.1", "192.0.2.2", 443, FlowProtoTCP)
	// time.Unix() carries no monotonic reading; deadline far in
	// future so even on a wrong-bucket-math regression we don't
	// false-pass the assertion below.
	s.Schedule(k, time.Unix(time.Now().Unix()+3600, 0))

	if got := s.EntryCount(); got != 0 {
		t.Errorf("Schedule with wall-clock deadline should no-op; got %d entries", got)
	}
}

// TestMonoNsAt_AcceptsMonotonicTime fences the happy path: a
// standard time.Now()-derived time.Time produces a positive offset.
func TestMonoNsAt_AcceptsMonotonicTime(t *testing.T) {
	// time.Now() + Add preserves the monotonic reading.
	got := monoNsAt(time.Now().Add(5 * time.Second))
	if got == 0 {
		t.Errorf("monoNsAt should produce a positive nanosecond offset for a future time; got 0")
	}
}

func TestFlowKey_IPv4MappedRoundtrip(t *testing.T) {
	// IPv4 string in, [16]byte v4-mapped storage, IPv4 string out.
	k, err := MakeFlowKey("192.0.2.1", "192.0.2.2", 443, FlowProtoTCP)
	if err != nil {
		t.Fatal(err)
	}
	if got := k.SrcIPString(); got != "192.0.2.1" {
		t.Errorf("SrcIPString roundtrip: got %q want 192.0.2.1", got)
	}
	if got := k.DstIPString(); got != "192.0.2.2" {
		t.Errorf("DstIPString roundtrip: got %q want 192.0.2.2", got)
	}
	// Confirm storage is in IPv4-mapped form (last 4 bytes hold v4).
	want := net.ParseIP("192.0.2.1").To4()
	if !net.IP(k.SrcIP[12:]).Equal(want) {
		t.Errorf("v4-mapped storage: tail bytes = %v want %v", k.SrcIP[12:], want)
	}
	if k.SrcIP[10] != 0xff || k.SrcIP[11] != 0xff {
		t.Errorf("v4-mapped storage: missing 0xffff prefix, got %v", k.SrcIP[8:12])
	}
}

func TestFlowKey_ShardDistribution(t *testing.T) {
	// Confirm distribution isn't pathological — N keys should spread
	// across at least N/16 shards.
	const n = 4096
	counts := make(map[uint32]int)
	for i := 0; i < n; i++ {
		k, _ := MakeFlowKey(
			randIPv4(),
			randIPv4(),
			1024+i%50000,
			FlowProtoTCP,
		)
		counts[k.shard()]++
	}
	if len(counts) < schedulerShardCount/4 {
		t.Errorf("shard distribution too narrow: %d unique shards for %d keys (want >= %d)",
			len(counts), n, schedulerShardCount/4)
	}
}

func TestFlowProto_String(t *testing.T) {
	if FlowProtoTCP.String() != "tcp" || FlowProtoUDP.String() != "udp" ||
		FlowProtoICMP.String() != "icmp" || FlowProtoAny.String() != "any" {
		t.Error("FlowProto.String mismatch")
	}
}

// ============================================================================
// NoOpFlusher
// ============================================================================

func TestNoOpFlusher_CallCount(t *testing.T) {
	f := &NoOpFlusher{}
	if got := f.CallCount(); got != 0 {
		t.Errorf("initial count: got %d want 0", got)
	}
	for i := 0; i < 10; i++ {
		if err := f.Flush(context.Background(), FlowKey{}); err != nil {
			t.Fatalf("flush err: %v", err)
		}
	}
	if got := f.CallCount(); got != 10 {
		t.Errorf("after 10 calls: got %d want 10", got)
	}
}

// ============================================================================
// Scheduler — basic Schedule / Cancel / fire semantics
// ============================================================================

func TestScheduler_Schedule_Fires(t *testing.T) {
	f := newRecordingFlusher()
	s := NewScheduler(f, WithTickInterval(5*time.Millisecond), WithWheelSize(100))
	s.Start()
	defer shutdownOrFail(t, s)

	k := mustKey(t, "192.0.2.1", "192.0.2.2", 443, FlowProtoTCP)
	s.Schedule(k, time.Now().Add(20*time.Millisecond))

	if !f.waitFor(1, 500*time.Millisecond) {
		t.Fatalf("expected 1 flush; got %d (metrics: %+v)", f.count(), s.Metrics())
	}
	if got := f.lastKey(); got != k {
		t.Errorf("flushed key: got %+v want %+v", got, k)
	}
}

func TestScheduler_Cancel_BeforeFire(t *testing.T) {
	f := newRecordingFlusher()
	s := NewScheduler(f, WithTickInterval(5*time.Millisecond), WithWheelSize(100))
	s.Start()
	defer shutdownOrFail(t, s)

	k := mustKey(t, "192.0.2.1", "192.0.2.2", 443, FlowProtoTCP)
	s.Schedule(k, time.Now().Add(100*time.Millisecond))
	s.Cancel(k)

	time.Sleep(200 * time.Millisecond)
	if got := f.count(); got != 0 {
		t.Errorf("expected 0 flushes after Cancel; got %d", got)
	}
	if got := s.EntryCount(); got != 0 {
		t.Errorf("expected 0 entries after Cancel; got %d", got)
	}
}

func TestScheduler_Cancel_Unknown_IsNoOp(t *testing.T) {
	f := newRecordingFlusher()
	s := NewScheduler(f, WithTickInterval(5*time.Millisecond), WithWheelSize(100))
	s.Start()
	defer shutdownOrFail(t, s)

	k := mustKey(t, "192.0.2.1", "192.0.2.2", 443, FlowProtoTCP)
	s.Cancel(k) // never scheduled — must not panic, must not decrement counter
	if got := s.EntryCount(); got != 0 {
		t.Errorf("EntryCount drift on no-op Cancel: %d", got)
	}
}

func TestScheduler_LongestWins_LaterScheduleReplaces(t *testing.T) {
	f := newRecordingFlusher()
	s := NewScheduler(f, WithTickInterval(5*time.Millisecond), WithWheelSize(200))
	s.Start()
	defer shutdownOrFail(t, s)

	k := mustKey(t, "192.0.2.1", "192.0.2.2", 443, FlowProtoTCP)
	start := time.Now()
	s.Schedule(k, start.Add(30*time.Millisecond))
	s.Schedule(k, start.Add(150*time.Millisecond)) // later — wins

	// Wait past the EARLIER deadline; assert nothing fired yet.
	time.Sleep(80 * time.Millisecond)
	if got := f.count(); got != 0 {
		t.Errorf("flushed before later deadline: got %d flushes", got)
	}
	// Wait past the LATER deadline; assert exactly one flush.
	if !f.waitFor(1, 250*time.Millisecond) {
		t.Fatalf("expected flush by later deadline; got %d (metrics: %+v)", f.count(), s.Metrics())
	}
}

func TestScheduler_LongestWins_EarlierScheduleNoOp(t *testing.T) {
	f := newRecordingFlusher()
	s := NewScheduler(f, WithTickInterval(5*time.Millisecond), WithWheelSize(200))
	s.Start()
	defer shutdownOrFail(t, s)

	k := mustKey(t, "192.0.2.1", "192.0.2.2", 443, FlowProtoTCP)
	start := time.Now()
	s.Schedule(k, start.Add(200*time.Millisecond)) // later first
	s.Schedule(k, start.Add(50*time.Millisecond))  // earlier — no-op

	// If earlier had replaced later, flush would fire around t=50ms.
	time.Sleep(120 * time.Millisecond)
	if got := f.count(); got != 0 {
		t.Errorf("earlier Schedule replaced later: got %d flushes pre-later-deadline", got)
	}
}

// ============================================================================
// Bug-fix fences — these would FAIL on the pre-fix code
// ============================================================================

// TestScheduler_PastTheHand_FiresImmediately fences bug #4 from the
// advisor pass: with delta-based bucket math, a deadline that maps
// to a bucket the hand already drained this frame would sit idle
// for ~1 full frame (6s) before firing. Absolute-tick math forces
// it into the current bucket → fires next tick.
//
// Setup: tick=10ms, wheel=100 (1s frame). Start scheduler, let the
// hand advance for ~500ms (= 50 ticks). Then Schedule a key with
// deadline 5ms ahead — this maps to a bucket low in the wheel
// (bucket 0 absolute-tick math), which is BEHIND the current hand.
// Must fire within ~30ms, NOT after a full wheel rotation.
func TestScheduler_PastTheHand_FiresImmediately(t *testing.T) {
	f := newRecordingFlusher()
	s := NewScheduler(f, WithTickInterval(10*time.Millisecond), WithWheelSize(100))
	s.Start()
	defer shutdownOrFail(t, s)

	// Let the hand advance ~halfway through the frame.
	time.Sleep(500 * time.Millisecond)

	k := mustKey(t, "192.0.2.10", "192.0.2.20", 443, FlowProtoTCP)
	s.Schedule(k, time.Now().Add(5*time.Millisecond))

	if !f.waitFor(1, 100*time.Millisecond) {
		t.Fatalf("past-the-hand deadline late-fired: got %d flushes within 100ms (metrics: %+v)",
			f.count(), s.Metrics())
	}
}

// TestScheduler_RescheduleAfterDrain_StaleEntryDoesNotFlush fences
// bug #2: an entry that was drained and queued, then superseded by
// a Reschedule with a later deadline, must NOT flush — the new
// entry is in the wheel waiting for its later deadline; flushing
// the stale one would tear down kernel state the live entry plans
// to manage.
func TestScheduler_RescheduleAfterDrain_StaleEntryDoesNotFlush(t *testing.T) {
	// Uses real sleeps (30ms + 100ms + 800ms). Skip under -short so
	// contended CI runners don't flake
	if testing.Short() {
		t.Skip("real-sleep test; skipped under -short")
	}
	f := newBlockingFlusher()
	s := NewScheduler(f, WithTickInterval(5*time.Millisecond), WithWheelSize(100), WithWorkerCount(1))
	s.Start()
	defer shutdownOrFail(t, s)

	k := mustKey(t, "192.0.2.1", "192.0.2.2", 443, FlowProtoTCP)

	// Park a no-op entry to occupy the only worker so the next
	// queued entry stays in the queue (not yet flushing).
	parkKey := mustKey(t, "192.0.2.99", "192.0.2.99", 443, FlowProtoTCP)
	s.Schedule(parkKey, time.Now().Add(10*time.Millisecond))
	f.waitForFlushBlocked(1, time.Second)

	// Schedule k with near-immediate deadline; it'll drain and queue
	// behind the parked entry.
	s.Schedule(k, time.Now().Add(10*time.Millisecond))
	time.Sleep(30 * time.Millisecond) // give the tick time to drain + queue

	// While the parked worker is still blocked, Reschedule k with a
	// LATER deadline. The stale already-queued entry should be
	// recognized as superseded when the worker eventually pulls it.
	s.Schedule(k, time.Now().Add(500*time.Millisecond))

	// Release the worker; it processes the parked entry, then the
	// stale k entry (which must no-op).
	f.releaseAll()

	// Within enough time to flush the parked entry but not enough to
	// reach the new k deadline, only the parked entry should have
	// flushed.
	time.Sleep(100 * time.Millisecond)
	flushed := f.allKeys()
	stale := 0
	for _, fk := range flushed {
		if fk == k {
			stale++
		}
	}
	if stale != 0 {
		t.Errorf("stale Reschedule remnant flushed %d times before its new deadline (all=%v)", stale, flushed)
	}

	// Now wait past the new deadline; the live k entry should fire.
	if !f.waitForKey(k, 800*time.Millisecond) {
		t.Errorf("live entry never fired after Reschedule (flushed keys: %v)", f.allKeys())
	}
}

// TestScheduler_ConcurrentScheduleSameKey_FinalStateIsMax fences
// bug #1: 1000 goroutines Schedule the same key with random
// deadlines; the final scheduled state must be the maximum deadline.
// The lock-unlock-relock pattern in the original code lost
// longest-wins under contention.
func TestScheduler_ConcurrentScheduleSameKey_FinalStateIsMax(t *testing.T) {
	f := newRecordingFlusher()
	// Wheel set large enough that the max deadline (base + 2s) fits in
	// the wheel — we want the final deadline preserved in the index
	// long enough to inspect, not promoted/fired during the test.
	s := NewScheduler(f, WithTickInterval(5*time.Millisecond), WithWheelSize(2000))
	s.Start()
	defer shutdownOrFail(t, s)

	k := mustKey(t, "192.0.2.1", "192.0.2.2", 443, FlowProtoTCP)
	const n = 1000
	// Far-future base so the final entry can't fire before we inspect.
	base := time.Now().Add(60 * time.Second)
	var (
		wg            sync.WaitGroup
		maxMu         sync.Mutex
		maxDeadlineNs uint64
	)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			offset := time.Duration(rand.IntN(2000)) * time.Millisecond
			deadline := base.Add(offset)
			s.Schedule(k, deadline)
			dNs := monoNsAt(deadline)
			maxMu.Lock()
			if dNs > maxDeadlineNs {
				maxDeadlineNs = dNs
			}
			maxMu.Unlock()
		}()
	}
	wg.Wait()

	if got := s.EntryCount(); got != 1 {
		t.Fatalf("expected 1 live entry after concurrent same-key Schedule; got %d", got)
	}

	// Strong assertion: the final-state deadline must equal the
	// maximum deadline submitted by any goroutine. The previous
	// weaker assertion (deadline >= base) passed even on partial-loss
	// bugs that landed on the second-highest deadline
	shard := s.shards[k.shard()]
	shard.mu.Lock()
	entry, ok := shard.entries[k]
	shard.mu.Unlock()
	if !ok {
		t.Fatalf("expected entry still in index 60s before its earliest possible fire; got none")
	}
	if entry.deadlineNs != maxDeadlineNs {
		t.Errorf("final-state deadlineNs=%d does not equal max(submitted)=%d — longest-wins broken (could indicate lock-unlock-relock regression)",
			entry.deadlineNs, maxDeadlineNs)
	}
}

// ============================================================================
// Race fence — must run clean under -race
// ============================================================================

// TestScheduler_RaceDetector_MixedOps spins many goroutines doing
// concurrent Schedule, Cancel, Reschedule, and Metrics reads.
// Provides coverage for go test -race. Run for 200ms.
func TestScheduler_RaceDetector_MixedOps(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping race-stress in -short mode")
	}
	f := &NoOpFlusher{}
	s := NewScheduler(f, WithTickInterval(2*time.Millisecond), WithWheelSize(500),
		WithWorkerCount(16), WithFlushQueueCap(8192))
	s.Start()
	defer shutdownOrFail(t, s)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	const workers = 32
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for ctx.Err() == nil {
				k, _ := MakeFlowKey(randIPv4(), randIPv4(),
					1024+rand.IntN(1024), FlowProtoTCP)
				op := rand.IntN(4)
				switch op {
				case 0:
					s.Schedule(k, time.Now().Add(time.Duration(rand.IntN(50))*time.Millisecond))
				case 1:
					s.Cancel(k)
				case 2:
					// Reschedule — same key, different deadline.
					s.Schedule(k, time.Now().Add(time.Duration(rand.IntN(200))*time.Millisecond))
				case 3:
					_ = s.Metrics()
				}
			}
		}(i)
	}
	wg.Wait()
}

// ============================================================================
// Backpressure + breaker
// ============================================================================

// TestScheduler_BreakerOpensOnSustainedErrors confirms the
// rate-based breaker trips after threshold errors in the window.
func TestScheduler_BreakerOpensOnSustainedErrors(t *testing.T) {
	f := &erroringFlusher{}
	s := NewScheduler(f,
		WithTickInterval(2*time.Millisecond),
		WithWheelSize(100),
		WithBreakerThreshold(5),
		WithBreakerWindow(time.Second),
	)
	s.Start()
	defer shutdownOrFail(t, s)

	for i := 0; i < 10; i++ {
		k, _ := MakeFlowKey(randIPv4(), randIPv4(), 443, FlowProtoTCP)
		s.Schedule(k, time.Now().Add(5*time.Millisecond))
	}
	// Give errors time to accumulate.
	if !waitUntil(func() bool { return s.IsBreakerOpen() }, time.Second) {
		t.Errorf("breaker did not open after sustained errors (metrics: %+v)", s.Metrics())
	}
}

// TestScheduler_BreakerOpensImmediatelyOnFirstDrop fences the
// drop-fail-closed contract: a drop is a correctness violation under
// L3-only enforcement, so the breaker opens on the FIRST drop —
// independent of the error-rate threshold.
func TestScheduler_BreakerOpensImmediatelyOnFirstDrop(t *testing.T) {
	// Saturate the queue: 1 worker, queue cap 1, blocking flusher.
	f := newBlockingFlusher()
	s := NewScheduler(f,
		WithTickInterval(2*time.Millisecond),
		WithWheelSize(50),
		WithWorkerCount(1),
		WithFlushQueueCap(1),
	)
	s.Start()
	defer shutdownOrFail(t, s)

	// Schedule enough entries that the queue fills, then keeps
	// re-bucketing until maxConsecutiveDefers.
	for i := 0; i < 50; i++ {
		k, _ := MakeFlowKey(randIPv4(), randIPv4(),
			1024+i, FlowProtoTCP)
		s.Schedule(k, time.Now().Add(5*time.Millisecond))
	}

	// Wait long enough for max defers to occur.
	if !waitUntil(func() bool { return s.Metrics().FlushDropped > 0 }, 2*time.Second) {
		t.Fatalf("no drop observed within 2s; metrics: %+v", s.Metrics())
	}
	if !s.IsBreakerOpen() {
		t.Errorf("breaker did not open on first drop; metrics: %+v", s.Metrics())
	}
	// Cr fence: round 5 boundary check — `maxConsecutiveDefers` is
	// `> N` not `>= N`, so a single entry survives N defers and
	// drops on the (N+1)th. With maxConsecutiveDefers=5 (the
	// current value), an entry's deferCount AT the moment of drop
	// is 6 (incremented before the > check). FlushDeferred therefore
	// includes the drop-precursor defer; FlushDeferred >=
	// FlushDropped × (maxConsecutiveDefers+1).
	m := s.Metrics()
	minExpected := m.FlushDropped * uint64(maxConsecutiveDefers+1)
	if m.FlushDeferred < minExpected {
		t.Errorf("metric semantics: FlushDeferred=%d should be >= FlushDropped(%d) × (maxConsecutiveDefers(%d)+1) = %d",
			m.FlushDeferred, m.FlushDropped, maxConsecutiveDefers, minExpected)
	}
	f.releaseAll()
}

func TestScheduler_ResetBreaker(t *testing.T) {
	f := &erroringFlusher{}
	s := NewScheduler(f,
		WithTickInterval(2*time.Millisecond),
		WithWheelSize(50),
		WithBreakerThreshold(3),
		WithBreakerWindow(time.Second),
	)
	s.Start()
	defer shutdownOrFail(t, s)

	for i := 0; i < 10; i++ {
		k, _ := MakeFlowKey(randIPv4(), randIPv4(), 443, FlowProtoTCP)
		s.Schedule(k, time.Now().Add(5*time.Millisecond))
	}
	if !waitUntil(func() bool { return s.IsBreakerOpen() }, time.Second) {
		t.Fatal("breaker did not open")
	}
	s.ResetBreaker()
	if s.IsBreakerOpen() {
		t.Error("breaker still open after ResetBreaker")
	}
}

// ============================================================================
// Dry-run + overflow
// ============================================================================

func TestScheduler_DryRun_DoesNotInvokeFlusher(t *testing.T) {
	f := newRecordingFlusher()
	s := NewScheduler(f, WithTickInterval(5*time.Millisecond),
		WithWheelSize(100), WithDryRun(true))
	s.Start()
	defer shutdownOrFail(t, s)

	for i := 0; i < 20; i++ {
		k, _ := MakeFlowKey(randIPv4(), randIPv4(),
			1024+i, FlowProtoTCP)
		s.Schedule(k, time.Now().Add(10*time.Millisecond))
	}
	time.Sleep(100 * time.Millisecond)
	if got := f.count(); got != 0 {
		t.Errorf("dry-run invoked flusher %d times", got)
	}
	if got := s.Metrics().FlushDryRun; got == 0 {
		t.Errorf("dry-run counter not incremented; metrics: %+v", s.Metrics())
	}
}

// TestScheduler_Overflow_Promotion confirms entries with deadlines
// beyond wheel coverage land in overflow and get promoted on the
// next wheel wrap → eventually fire.
func TestScheduler_Overflow_Promotion(t *testing.T) {
	f := newRecordingFlusher()
	// tick=10ms × wheel=10 = 100ms coverage. Schedule for 250ms out
	// → overflow → promoted on first wrap → fires.
	s := NewScheduler(f, WithTickInterval(10*time.Millisecond), WithWheelSize(10))
	s.Start()
	defer shutdownOrFail(t, s)

	k := mustKey(t, "192.0.2.1", "192.0.2.2", 443, FlowProtoTCP)
	s.Schedule(k, time.Now().Add(250*time.Millisecond))

	if !f.waitFor(1, 600*time.Millisecond) {
		t.Errorf("overflow entry did not fire; metrics: %+v", s.Metrics())
	}
}

// ============================================================================
// Shutdown
// ============================================================================

// TestScheduler_Shutdown_FlushesScheduledBeforeShutdown fences
// the contract that entries already drained from the wheel onto
// the flush queue BEFORE Shutdown fires complete their Flush call.
// What's NOT tested here (and what cr round 3 finding 1 clarified):
// entries that are still queued WHEN Shutdown fires get pulled and
// discarded — processEntry bails on s.ctx.Err(). The recovery for
// those is boot enumeration on the next AC process.
//
// This test passes because the wheel tick + flush dispatch
// completes within the 30ms warm-up so the entries are already
// flushed by Shutdown time. If a future change made flushers
// slow enough to be still in-flight, this test would correctly
// observe a count <10 — and that observation is the actual fence.
func TestScheduler_Shutdown_FlushesScheduledBeforeShutdown(t *testing.T) {
	f := newRecordingFlusher()
	s := NewScheduler(f, WithTickInterval(5*time.Millisecond), WithWheelSize(100))
	s.Start()

	for i := 0; i < 10; i++ {
		k, _ := MakeFlowKey(randIPv4(), randIPv4(), 1024+i, FlowProtoTCP)
		s.Schedule(k, time.Now().Add(5*time.Millisecond))
	}
	// Wait until the tick has drained the bucket onto the queue AND
	// workers have processed it. With a fast flusher this completes
	// well before Shutdown.
	time.Sleep(30 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := s.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown error: %v", err)
	}
	if got := f.count(); got < 10 {
		t.Errorf("entries scheduled and given time to flush before Shutdown should all have fired: got %d want 10 (metrics: %+v)",
			got, s.Metrics())
	}
}

func TestScheduler_Shutdown_Idempotent(t *testing.T) {
	s := NewScheduler(&NoOpFlusher{}, WithTickInterval(10*time.Millisecond))
	s.Start()
	ctx := context.Background()
	if err := s.Shutdown(ctx); err != nil {
		t.Fatalf("first shutdown: %v", err)
	}
	// Second shutdown must not panic or block.
	if err := s.Shutdown(ctx); err != nil {
		t.Errorf("second shutdown: %v", err)
	}
}

func TestScheduler_ScheduleAfterShutdown_IsNoOp(t *testing.T) {
	f := newRecordingFlusher()
	s := NewScheduler(f, WithTickInterval(5*time.Millisecond))
	s.Start()
	_ = s.Shutdown(context.Background())

	k := mustKey(t, "192.0.2.1", "192.0.2.2", 443, FlowProtoTCP)
	s.Schedule(k, time.Now().Add(10*time.Millisecond))
	time.Sleep(50 * time.Millisecond)
	if got := f.count(); got != 0 {
		t.Errorf("schedule-after-shutdown fired %d flushes", got)
	}
	if got := s.EntryCount(); got != 0 {
		t.Errorf("schedule-after-shutdown EntryCount: %d", got)
	}
}

// ============================================================================
// Test helpers
// ============================================================================

func mustKey(t *testing.T, src, dst string, port int, proto FlowProto) FlowKey {
	t.Helper()
	k, err := MakeFlowKey(src, dst, port, proto)
	if err != nil {
		t.Fatalf("MakeFlowKey(%s,%s,%d,%s): %v", src, dst, port, proto, err)
	}
	return k
}

func shutdownOrFail(t *testing.T, s *Scheduler) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := s.Shutdown(ctx); err != nil {
		t.Errorf("shutdown: %v", err)
	}
}

func waitUntil(pred func() bool, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if pred() {
			return true
		}
		time.Sleep(2 * time.Millisecond)
	}
	return pred()
}

func randIPv4() string {
	return (&net.IPAddr{IP: net.IPv4(
		byte(rand.IntN(254)+1),
		byte(rand.IntN(254)),
		byte(rand.IntN(254)),
		byte(rand.IntN(254)+1),
	)}).IP.String()
}

// --- flushers --------------------------------------------------------

type recordingFlusher struct {
	mu       sync.Mutex
	keys     []FlowKey
	flushedC chan struct{}
}

func newRecordingFlusher() *recordingFlusher {
	return &recordingFlusher{flushedC: make(chan struct{}, 1024)}
}

func (r *recordingFlusher) Flush(_ context.Context, k FlowKey) error {
	r.mu.Lock()
	r.keys = append(r.keys, k)
	r.mu.Unlock()
	select {
	case r.flushedC <- struct{}{}:
	default:
	}
	return nil
}

func (r *recordingFlusher) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.keys)
}

func (r *recordingFlusher) lastKey() FlowKey {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.keys) == 0 {
		return FlowKey{}
	}
	return r.keys[len(r.keys)-1]
}

func (r *recordingFlusher) waitFor(n int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if r.count() >= n {
			return true
		}
		select {
		case <-r.flushedC:
		case <-time.After(2 * time.Millisecond):
		}
	}
	return r.count() >= n
}

// blockingFlusher holds Flush calls until releaseAll() is called.
// Used to test stale-Reschedule and drop-on-saturation paths.
type blockingFlusher struct {
	mu       sync.Mutex
	keys     []FlowKey
	blocking atomic.Int64
	gate     chan struct{}
	once     sync.Once
}

func newBlockingFlusher() *blockingFlusher {
	return &blockingFlusher{gate: make(chan struct{})}
}

func (b *blockingFlusher) Flush(_ context.Context, k FlowKey) error {
	b.mu.Lock()
	b.keys = append(b.keys, k)
	b.mu.Unlock()
	b.blocking.Add(1)
	<-b.gate
	b.blocking.Add(-1)
	return nil
}

func (b *blockingFlusher) releaseAll() {
	b.once.Do(func() { close(b.gate) })
}

func (b *blockingFlusher) waitForFlushBlocked(n int64, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if b.blocking.Load() >= n {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func (b *blockingFlusher) allKeys() []FlowKey {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]FlowKey, len(b.keys))
	copy(out, b.keys)
	return out
}

func (b *blockingFlusher) waitForKey(k FlowKey, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		b.mu.Lock()
		for _, kk := range b.keys {
			if kk == k {
				b.mu.Unlock()
				return true
			}
		}
		b.mu.Unlock()
		time.Sleep(5 * time.Millisecond)
	}
	return false
}

// erroringFlusher always returns an error. Used to drive breaker tests.
type erroringFlusher struct{}

func (e *erroringFlusher) Flush(_ context.Context, _ FlowKey) error {
	return errors.New("simulated flush failure")
}

// panickingFlusher panics on every Flush call. Used to fence the
// defer-recover safety in processEntry (cr round 11 finding 🔴).
type panickingFlusher struct {
	panics atomic.Uint64
}

func (p *panickingFlusher) Flush(_ context.Context, k FlowKey) error {
	p.panics.Add(1)
	panic(fmt.Sprintf("simulated flusher panic on %s", k))
}

// TestScheduler_FlusherPanic_DoesNotCrashAC fences the panic-safety
// contract: a flusher that panics must NOT crash the AC process.
// The recover wrapper in processEntry routes the failure through
// the breaker (FlushErr++ + recordBreakerErr). At 5 panics with
// threshold=3, the breaker should open and admission should fail
// closed instead of the AC exiting
func TestScheduler_FlusherPanic_DoesNotCrashAC(t *testing.T) {
	f := &panickingFlusher{}
	s := NewScheduler(f,
		WithTickInterval(2*time.Millisecond),
		WithWheelSize(50),
		WithWorkerCount(1),
		WithBreakerThreshold(3),
		WithBreakerWindow(time.Second),
	)
	s.Start()
	defer shutdownOrFail(t, s)

	for i := 0; i < 5; i++ {
		k, _ := MakeFlowKey(randIPv4(), randIPv4(), 1024+i, FlowProtoTCP)
		s.Schedule(k, time.Now().Add(5*time.Millisecond))
	}
	if !waitUntil(func() bool { return s.IsBreakerOpen() }, 2*time.Second) {
		t.Fatalf("breaker did not open after 5 flusher panics within 2s; metrics=%+v panics=%d",
			s.Metrics(), f.panics.Load())
	}
	if got := s.Metrics().FlushErr; got == 0 {
		t.Errorf("FlushErr should be > 0 (panic routed through breaker counter); got %d", got)
	}
}

// TestCancel_StillUnusedByProduction_Sentinel fences the contract
// that Scheduler.Cancel currently has NO production caller. The
// package godoc claims this and #2172 tracks the wiring work; when
// that issue closes, this sentinel must be deliberately removed
// rather than silently letting production paths light up untested
//
// Greps the production .go files under endpoints/ac/ for
// `expirySched.Cancel(`. Test files are excluded — Cancel is heavily
// unit-tested in this file.
func TestCancel_StillUnusedByProduction_Sentinel(t *testing.T) {
	prodFiles, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	var callers []string
	for _, f := range prodFiles {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		if strings.Contains(string(data), "expirySched.Cancel(") {
			callers = append(callers, f)
		}
	}
	if len(callers) > 0 {
		t.Fatalf("Scheduler.Cancel now has production caller(s) in %v — remove this sentinel test and update the package godoc + #2172 (Cancel was deferred and is being tracked there; once wired, this fence becomes the regression risk it was guarding against)", callers)
	}
}

// TestScheduler_Shutdown_RestoresGoroutineCount fences the
// scheduler cleanup path: Start launches a ticker goroutine and 64
// workers; Shutdown must reap all of them. A regression that leaks
// a worker or the ticker would silently grow process goroutine
// count across AC reload cycles and (more importantly) across the
// fail-closed-boot path that constructs+Shutdowns the scheduler
// after a synchronous enum failure.
func TestScheduler_Shutdown_RestoresGoroutineCount(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping goroutine-leak test in -short mode (NumGoroutine fence is intrinsically timing-sensitive)")
	}
	runtime.GC()
	time.Sleep(20 * time.Millisecond)
	before := runtime.NumGoroutine()

	s := NewScheduler(&NoOpFlusher{}, WithWorkerCount(64))
	s.Start()
	mid := runtime.NumGoroutine()
	if mid-before < 32 {
		t.Logf("expected ≥32 new goroutines from Start; got delta %d", mid-before)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := s.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	runtime.GC()
	time.Sleep(50 * time.Millisecond)
	after := runtime.NumGoroutine()

	// Allow tolerance for runtime noise (finalizers, scavenger). A
	// leaked worker pool is ≥64 goroutines; threshold 8 catches real
	// leaks while ignoring runtime churn.
	if after-before > 8 {
		t.Errorf("Shutdown leaked goroutines: before=%d mid=%d after=%d (drift=%d)", before, mid, after, after-before)
	}
}

// TestScheduler_SetBreakerParams_RejectsZero ensures the live-reload
// path keeps the previous good values when a typo or zeroed-out
// TOML field would otherwise corrupt the breaker state. The
// implementation drops the update with a Warning rather than
// proceeding with the bad input.
func TestScheduler_SetBreakerParams_RejectsZero(t *testing.T) {
	t.Parallel()
	s := NewScheduler(&NoOpFlusher{},
		WithBreakerThreshold(7),
		WithBreakerWindow(45*time.Second),
	)
	cases := []struct {
		name      string
		threshold int
		window    time.Duration
	}{
		{"zero-threshold", 0, 30 * time.Second},
		{"negative-threshold", -1, 30 * time.Second},
		{"zero-window", 5, 0},
		{"negative-window", 5, -time.Second},
		{"both-zero", 0, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s.SetBreakerParams(tc.threshold, tc.window)
			s.breakerErrMu.Lock()
			gotT, gotW := s.breakerThreshold, s.breakerWindow
			s.breakerErrMu.Unlock()
			if gotT != 7 || gotW != 45*time.Second {
				t.Errorf("SetBreakerParams(%d, %s) corrupted prior values: got threshold=%d window=%s want 7 / 45s",
					tc.threshold, tc.window, gotT, gotW)
			}
		})
	}
}
