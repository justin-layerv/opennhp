package server

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/nhp/core"
)

// newACConnWithLastRecv builds an *ACConn whose underlying ConnectionData
// has LastLocalRecvTime set to the given nano-timestamp. Used to exercise
// filterLiveACConns without standing up a full UDP server.
//
// We initialize the channels ConnectionData.Close() touches so closed-path
// tests can call Close() without panicking (see newClosedACConn). This
// mirrors newTestACConn in udpserver_test.go; kept local to avoid taking
// a dependency on that helper's unrelated peer-construction side-effects.
func newACConnWithLastRecv(lastRecvNano int64) *ACConn {
	return &ACConn{ConnData: &core.ConnectionData{
		LastLocalRecvTime: lastRecvNano,
		StopSignal:        make(chan struct{}),
		SendQueue:         make(chan *core.Packet, 1),
		RecvQueue:         make(chan *core.Packet, 1),
		BlockSignal:       make(chan struct{}, 1),
		SetTimeoutSignal:  make(chan struct{}, 1),
	}}
}

// newClosedACConn returns an ACConn whose ConnectionData reports IsClosed()=true.
// filterLiveACConns must drop these regardless of LastLocalRecvTime: a closed
// connection can never ACK an NHP-AOP.
func newClosedACConn(lastRecvNano int64) *ACConn {
	c := newACConnWithLastRecv(lastRecvNano)
	c.ConnData.Close()
	return c
}

func TestFilterLiveACConns(t *testing.T) {
	// Anchor synthetic LastLocalRecvTime values around the test's start time.
	// filterLiveACConns reads time.Now() internally, so these timestamps must
	// be sufficiently far inside / outside the threshold to tolerate the
	// microseconds of clock drift between this anchor and the filter's call.
	now := time.Now()
	threshold := 30 * time.Second
	fresh := now.Add(-5 * time.Second).UnixNano()
	borderline := now.Add(-29 * time.Second).UnixNano() // within threshold
	justOverThreshold := now.Add(-31 * time.Second).UnixNano()
	veryStale := now.Add(-5 * time.Minute).UnixNano()

	cases := []struct {
		name        string
		input       []*ACConn
		wantKept    int
		wantDropped int
	}{
		{
			name:        "nil slice",
			input:       nil,
			wantKept:    0,
			wantDropped: 0,
		},
		{
			name:        "empty slice",
			input:       []*ACConn{},
			wantKept:    0,
			wantDropped: 0,
		},
		{
			name: "all fresh",
			input: []*ACConn{
				newACConnWithLastRecv(fresh),
				newACConnWithLastRecv(borderline),
				newACConnWithLastRecv(fresh),
			},
			wantKept:    3,
			wantDropped: 0,
		},
		{
			name: "all stale",
			input: []*ACConn{
				newACConnWithLastRecv(justOverThreshold),
				newACConnWithLastRecv(veryStale),
			},
			wantKept:    0,
			wantDropped: 2,
		},
		{
			name: "mixed fresh and stale (the flake shape)",
			input: []*ACConn{
				newACConnWithLastRecv(fresh),
				newACConnWithLastRecv(veryStale),
				newACConnWithLastRecv(borderline),
				newACConnWithLastRecv(justOverThreshold),
			},
			wantKept:    2,
			wantDropped: 2,
		},
		{
			name: "closed connection is dropped regardless of recency",
			input: []*ACConn{
				newACConnWithLastRecv(fresh),
				newClosedACConn(fresh), // fresh but closed
			},
			wantKept:    1,
			wantDropped: 1,
		},
		{
			name: "zero LastLocalRecvTime is treated as stale",
			input: []*ACConn{
				newACConnWithLastRecv(0),
				newACConnWithLastRecv(fresh),
			},
			wantKept:    1,
			wantDropped: 1,
		},
		{
			name:        "nil conn pointer is dropped, not panicked on",
			input:       []*ACConn{nil, newACConnWithLastRecv(fresh)},
			wantKept:    1,
			wantDropped: 1,
		},
		{
			name:        "nil ConnData is dropped, not panicked on",
			input:       []*ACConn{{}, newACConnWithLastRecv(fresh)},
			wantKept:    1,
			wantDropped: 1,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kept, dropped := filterLiveACConns(tc.input, threshold)

			if len(kept) != tc.wantKept {
				t.Errorf("kept=%d, want %d", len(kept), tc.wantKept)
			}
			if dropped != tc.wantDropped {
				t.Errorf("dropped=%d, want %d", dropped, tc.wantDropped)
			}
			// Every input must land in exactly one of kept or dropped (no losses, no double-count).
			if len(kept)+dropped != len(tc.input) {
				t.Errorf("kept(%d)+dropped(%d) != len(input)(%d)",
					len(kept), dropped, len(tc.input))
			}
			for i, c := range kept {
				if c == nil {
					t.Errorf("kept[%d] is nil", i)
				}
			}
		})
	}
}

// TestFilterLiveACConns_AtomicRead confirms that filterLiveACConns reads
// LastLocalRecvTime atomically — if a parallel goroutine updates it via
// atomic.StoreInt64 while the filter is walking, the race detector must
// not trip. Covers the realistic call pattern: recvPacketRoutine updating
// LastLocalRecvTime concurrently with broadcasts.
//
// Also asserts the partition invariant (kept+dropped == len(input)) on
// every iteration, so a future regression that double-counts or drops
// entries under contention fails this test even without -race.
func TestFilterLiveACConns_AtomicRead(t *testing.T) {
	c := newACConnWithLastRecv(time.Now().UnixNano())
	input := []*ACConn{c}

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
				atomic.StoreInt64(&c.ConnData.LastLocalRecvTime, time.Now().UnixNano())
			}
		}
	}()

	for i := 0; i < 1000; i++ {
		kept, dropped := filterLiveACConns(input, 30*time.Second)
		// Partition invariant: every input lands in exactly one bucket.
		if len(kept)+dropped != len(input) {
			t.Fatalf("iter %d: kept(%d)+dropped(%d) != len(input)(%d)",
				i, len(kept), dropped, len(input))
		}
		// Per-element invariant: a single input cannot produce >1 kept or >1 dropped.
		if len(kept) > 1 || dropped > 1 {
			t.Fatalf("iter %d: kept=%d dropped=%d (each must be <=1 for single input)",
				i, len(kept), dropped)
		}
	}
	close(stop)
	<-done
}

// TestStaleACConnThresholdResolution covers the Config override + floor
// clamp logic. Production tuning happens here; if a misconfiguration
// could collapse the threshold below MinStaleACConnThreshold, every
// broadcast would filter every connection.
func TestStaleACConnThresholdResolution(t *testing.T) {
	cases := []struct {
		name     string
		override int
		want     time.Duration
	}{
		{"zero override → default", 0, DefaultStaleACConnThreshold},
		{"negative override → default", -10, DefaultStaleACConnThreshold},
		{"override below floor → floor", 1, MinStaleACConnThreshold},
		{"override at floor → floor", int(MinStaleACConnThreshold / time.Second), MinStaleACConnThreshold},
		{"override above floor → override", 60, 60 * time.Second},
		{"override well above default → override", 300, 300 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &UdpServer{config: &Config{StaleACConnThresholdSeconds: tc.override}}
			if got := s.staleACConnThreshold(); got != tc.want {
				t.Errorf("override=%d: got %v, want %v", tc.override, got, tc.want)
			}
		})
	}

	t.Run("nil config → default", func(t *testing.T) {
		s := &UdpServer{}
		if got := s.staleACConnThreshold(); got != DefaultStaleACConnThreshold {
			t.Errorf("nil config: got %v, want %v", got, DefaultStaleACConnThreshold)
		}
	})
}

// TestSnapshotLiveACConns_FiltersStaleEntries exercises the wired call site
// behavior: build an acConnectionMap with mixed fresh/stale/closed ACConns,
// invoke snapshotLiveACConns, and assert (a) only fresh conns are returned
// and (b) the dropped count matches the stale + closed inputs. This is the
// integration test that fences the broadcast-targeting contract — unit
// tests on filterLiveACConns alone don't catch a regression in the lock /
// snapshot wiring.
func TestSnapshotLiveACConns_FiltersStaleEntries(t *testing.T) {
	const acId = "ac-test"
	now := time.Now().UnixNano()
	stale := time.Now().Add(-2 * time.Minute).UnixNano()
	freshA := newACConnWithLastRecv(now)
	freshB := newACConnWithLastRecv(now)
	staleC := newACConnWithLastRecv(stale)
	staleD := newACConnWithLastRecv(stale)
	closedE := newClosedACConn(now) // fresh time, but closed → drop

	s := &UdpServer{
		acConnectionMap: map[string][]*ACConn{
			acId: {freshA, staleC, freshB, staleD, closedE},
		},
	}

	kept, dropped := s.snapshotLiveACConns(acId)
	if dropped != 3 {
		t.Errorf("dropped=%d, want 3 (2 stale + 1 closed)", dropped)
	}
	if len(kept) != 2 {
		t.Fatalf("kept=%d, want 2 (the two fresh conns)", len(kept))
	}
	// Identity check: kept must contain freshA and freshB, not stale/closed.
	keptSet := map[*ACConn]struct{}{kept[0]: {}, kept[1]: {}}
	if _, ok := keptSet[freshA]; !ok {
		t.Error("freshA missing from kept")
	}
	if _, ok := keptSet[freshB]; !ok {
		t.Error("freshB missing from kept")
	}
	for _, bad := range []*ACConn{staleC, staleD, closedE} {
		if _, ok := keptSet[bad]; ok {
			t.Errorf("stale/closed conn leaked into kept: %p", bad)
		}
	}
}

// TestHasLiveACConn covers the cheap predicate used by the UDP-knock
// forwarding gate. The gate must return true if any conn would survive
// the broadcast filter — short-circuiting on the first match — and false
// when every entry is closed or silent past the threshold.
func TestHasLiveACConn(t *testing.T) {
	const acId = "ac-test"
	fresh := newACConnWithLastRecv(time.Now().UnixNano())
	stale := newACConnWithLastRecv(time.Now().Add(-2 * time.Minute).UnixNano())
	closed := newClosedACConn(time.Now().UnixNano())

	cases := []struct {
		name  string
		conns []*ACConn
		want  bool
	}{
		{"empty map entry", nil, false},
		{"only fresh", []*ACConn{fresh}, true},
		{"only stale", []*ACConn{stale}, false},
		{"only closed (fresh time)", []*ACConn{closed}, false},
		{"stale before fresh — must scan past", []*ACConn{stale, fresh}, true},
		{"closed before fresh", []*ACConn{closed, fresh}, true},
		{"all dead variants", []*ACConn{stale, closed, stale}, false},
		{"unknown acId", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &UdpServer{acConnectionMap: map[string][]*ACConn{}}
			if tc.conns != nil {
				s.acConnectionMap[acId] = tc.conns
			}
			got := s.hasLiveACConn(acId)
			if got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}
