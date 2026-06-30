//go:build linux

package ac

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	conntrack "github.com/florianl/go-conntrack"
	"golang.org/x/sys/unix"
)

// These two tests cover the pure helpers of the netlink datapath and need
// NO netlink socket, so they run on ordinary Linux CI (not just a sandbox
// AC). They fence the deadline-derivation and transient-error
// classification that bound the syscall (the cr's item #1/#3).

func TestNetlinkOpDeadline(t *testing.T) {
	t.Run("no-ctx-deadline-uses-backstop", func(t *testing.T) {
		got := netlinkOpDeadline(context.Background())
		lo := time.Now().Add(defaultNetlinkOpTimeout - time.Second)
		hi := time.Now().Add(defaultNetlinkOpTimeout + time.Second)
		if got.Before(lo) || got.After(hi) {
			t.Errorf("backstop deadline %v not within [%v,%v]", got, lo, hi)
		}
	})
	t.Run("ctx-deadline-wins-when-sooner", func(t *testing.T) {
		want := time.Now().Add(100 * time.Millisecond)
		ctx, cancel := context.WithDeadline(context.Background(), want)
		defer cancel()
		got := netlinkOpDeadline(ctx)
		if !got.Equal(want) {
			t.Errorf("got %v, want the sooner ctx deadline %v", got, want)
		}
	})
	t.Run("backstop-wins-when-ctx-deadline-far", func(t *testing.T) {
		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(time.Hour))
		defer cancel()
		got := netlinkOpDeadline(ctx)
		if got.After(time.Now().Add(defaultNetlinkOpTimeout + time.Second)) {
			t.Errorf("got %v, expected the nearer backstop (~%s), not the far ctx deadline", got, defaultNetlinkOpTimeout)
		}
	})
}

func TestPositiveNetlinkOpTimeout(t *testing.T) {
	if got := positiveNetlinkOpTimeout(defaultNetlinkOpTimeout); got != defaultNetlinkOpTimeout {
		t.Fatalf("positiveNetlinkOpTimeout(default) = %s, want %s", got, defaultNetlinkOpTimeout)
	}
	if got := positiveNetlinkOpTimeout(-time.Second); got != minNetlinkOpTimeout {
		t.Fatalf("positiveNetlinkOpTimeout(negative) = %s, want %s", got, minNetlinkOpTimeout)
	}
	if got := positiveNetlinkOpTimeout(0); got != minNetlinkOpTimeout {
		t.Fatalf("positiveNetlinkOpTimeout(0) = %s, want %s", got, minNetlinkOpTimeout)
	}
}

func TestIsTransientNetlinkErr(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"enobufs", unix.ENOBUFS, true},
		{"eintr", unix.EINTR, true},
		{"wrapped-enobufs", fmt.Errorf("dump: %w", unix.ENOBUFS), true},
		{"enoent-not-transient", unix.ENOENT, false},
		{"timeout-not-transient", unix.ETIMEDOUT, false},
		{"generic-not-transient", errors.New("boom"), false},
		{"nil-not-transient", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isTransientNetlinkErr(tt.err); got != tt.want {
				t.Errorf("isTransientNetlinkErr(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestConntrackDeleteResult(t *testing.T) {
	boom := errors.New("boom")
	tests := []struct {
		name string
		err  error
		want error
	}{
		{"nil-success", nil, nil},
		{"plain-enoent-is-idempotent", unix.ENOENT, nil},
		{"wrapped-enoent-is-idempotent", fmt.Errorf("delete: %w", unix.ENOENT), nil},
		{"joined-enoent-is-idempotent", errors.Join(errors.New("netlink delete"), unix.ENOENT), nil},
		{"real-error-spends-breaker-budget", boom, boom},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := conntrackDeleteResult(tt.err)
			if tt.want == nil {
				if got != nil {
					t.Fatalf("conntrackDeleteResult(%v) = %v, want nil", tt.err, got)
				}
				return
			}
			if !errors.Is(got, tt.want) {
				t.Fatalf("conntrackDeleteResult(%v) = %v, want errors.Is(..., %v)", tt.err, got, tt.want)
			}
		})
	}
}

type fakeCtNetlinkOps struct {
	dumpFn   func(*ctConn, conntrack.Family, time.Time) ([]conntrack.Con, error)
	deleteFn func(*ctConn, conntrack.Family, *conntrack.IPTuple, time.Time) error
}

func (f fakeCtNetlinkOps) dump(c *ctConn, family conntrack.Family, deadline time.Time) ([]conntrack.Con, error) {
	if f.dumpFn == nil {
		return nil, errors.New("unexpected dump")
	}
	return f.dumpFn(c, family, deadline)
}

func (f fakeCtNetlinkOps) deleteOrigin(c *ctConn, family conntrack.Family, origin *conntrack.IPTuple, deadline time.Time) error {
	if f.deleteFn == nil {
		return errors.New("unexpected delete")
	}
	return f.deleteFn(c, family, origin, deadline)
}

func testConntrackCon(t *testing.T, src, dst string, sport, dport uint16, proto uint8) conntrack.Con {
	t.Helper()
	u8 := func(v uint8) *uint8 { return &v }
	u16 := func(v uint16) *uint16 { return &v }
	ip := func(s string) *net.IP {
		parsed := net.ParseIP(s)
		if parsed == nil {
			t.Fatalf("net.ParseIP(%q) returned nil", s)
		}
		return &parsed
	}
	return conntrack.Con{Origin: &conntrack.IPTuple{
		Src: ip(src),
		Dst: ip(dst),
		Proto: &conntrack.ProtoTuple{
			Number:  u8(proto),
			SrcPort: u16(sport),
			DstPort: u16(dport),
		},
	}}
}

func testPartialTCPCon(t *testing.T, src, dst string) conntrack.Con {
	t.Helper()
	u8 := func(v uint8) *uint8 { return &v }
	ip := func(s string) *net.IP {
		parsed := net.ParseIP(s)
		if parsed == nil {
			t.Fatalf("net.ParseIP(%q) returned nil", s)
		}
		return &parsed
	}
	return conntrack.Con{Origin: &conntrack.IPTuple{
		Src: ip(src),
		Dst: ip(dst),
		Proto: &conntrack.ProtoTuple{
			Number: u8(unix.IPPROTO_TCP),
		},
	}}
}

func testCtNetlinkPool(conns ...*ctConn) *ctNetlinkPool {
	p := &ctNetlinkPool{conns: conns, free: make(chan *ctConn, len(conns))}
	for _, c := range conns {
		c.poolClosed = &p.closed
		p.free <- c
	}
	return p
}

func TestCtNetlinkPoolAcquireUsesOnlyFreeSockets(t *testing.T) {
	busy := &ctConn{}
	idle := &ctConn{}
	p := testCtNetlinkPool(busy, idle)
	deadline := time.Now().Add(time.Second)

	first, err := p.acquire(context.Background(), deadline)
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	if first != busy {
		t.Fatalf("first acquire = %p, want busy %p", first, busy)
	}
	second, err := p.acquire(context.Background(), deadline)
	if err != nil {
		t.Fatalf("second acquire: %v", err)
	}
	if second != idle {
		t.Fatalf("second acquire = %p, want idle %p", second, idle)
	}
	p.release(second)
	p.release(first)
}

func TestCtNetlinkPoolAcquireDeadline(t *testing.T) {
	p := &ctNetlinkPool{conns: []*ctConn{{}}, free: make(chan *ctConn, 1)}
	_, err := p.acquire(context.Background(), time.Now().Add(10*time.Millisecond))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("acquire error = %v, want context.DeadlineExceeded", err)
	}
}

func TestCtNetlinkPoolAcquireAfterClose(t *testing.T) {
	p := testCtNetlinkPool(&ctConn{})
	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	p.release(&ctConn{})

	_, err := p.acquire(context.Background(), time.Now().Add(time.Second))
	if !errors.Is(err, errCtNetlinkPoolClosed) {
		t.Fatalf("acquire error = %v, want %v", err, errCtNetlinkPoolClosed)
	}
}

func TestCtNetlinkConnEnsureOpenAfterPoolClose(t *testing.T) {
	c := &ctConn{}
	p := testCtNetlinkPool(c)
	held, err := p.acquire(context.Background(), time.Now().Add(time.Second))
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if held != c {
		t.Fatalf("acquired conn = %p, want %p", held, c)
	}
	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	c.mu.Lock()
	err = c.ensureOpen()
	c.mu.Unlock()
	if !errors.Is(err, errCtNetlinkPoolClosed) {
		t.Fatalf("ensureOpen after pool Close = %v, want %v", err, errCtNetlinkPoolClosed)
	}
}

func TestFlushNetlinkFakeOpsDeletesMatchingAndCounts(t *testing.T) {
	key := mustFlowKey(t, "192.0.2.10", "198.51.100.20", 443, FlowProtoTCP)
	var dumpCalls atomic.Int32
	var deleteSrcPorts []uint16
	f := &ConntrackFlusher{
		backend: BackendNetlink,
		pool:    testCtNetlinkPool(&ctConn{}),
		ctOps: fakeCtNetlinkOps{
			dumpFn: func(_ *ctConn, family conntrack.Family, _ time.Time) ([]conntrack.Con, error) {
				dumpCalls.Add(1)
				if family != conntrack.IPv4 {
					t.Fatalf("dump family = %v, want IPv4", family)
				}
				time.Sleep(netlinkSlowDumpThreshold + time.Millisecond)
				return []conntrack.Con{
					testConntrackCon(t, "192.0.2.10", "198.51.100.20", 51000, 443, unix.IPPROTO_TCP),
					testConntrackCon(t, "192.0.2.10", "198.51.100.20", 51001, 8443, unix.IPPROTO_TCP),
					testPartialTCPCon(t, "192.0.2.10", "198.51.100.20"),
					testConntrackCon(t, "192.0.2.10", "198.51.100.20", 51002, 443, unix.IPPROTO_TCP),
				}, nil
			},
			deleteFn: func(_ *ctConn, family conntrack.Family, origin *conntrack.IPTuple, _ time.Time) error {
				if family != conntrack.IPv4 {
					t.Fatalf("delete family = %v, want IPv4", family)
				}
				if origin == nil || origin.Proto == nil || origin.Proto.SrcPort == nil {
					t.Fatalf("delete origin missing source port: %+v", origin)
				}
				deleteSrcPorts = append(deleteSrcPorts, *origin.Proto.SrcPort)
				return nil
			},
		},
	}

	if err := f.Flush(context.Background(), key); err != nil {
		t.Fatalf("Flush returned error: %v", err)
	}
	if got := dumpCalls.Load(); got != 1 {
		t.Fatalf("dump calls = %d, want 1", got)
	}
	if got, want := fmt.Sprint(deleteSrcPorts), "[51000 51002]"; got != want {
		t.Fatalf("deleted source ports = %s, want %s", got, want)
	}
	if got := f.NetlinkDeletedCount(); got != 2 {
		t.Fatalf("NetlinkDeletedCount = %d, want 2", got)
	}
	if got := f.NetlinkSlowDumpCount(); got != 1 {
		t.Fatalf("NetlinkSlowDumpCount = %d, want 1", got)
	}
}

func TestFlushNetlinkFakeOpsDumpTimeoutReturnsErrorWithoutRetry(t *testing.T) {
	key := mustFlowKey(t, "192.0.2.10", "198.51.100.20", 443, FlowProtoTCP)
	dumpCalls := 0
	deleteCalls := 0
	f := &ConntrackFlusher{
		backend: BackendNetlink,
		pool:    testCtNetlinkPool(&ctConn{}),
		ctOps: fakeCtNetlinkOps{
			dumpFn: func(_ *ctConn, _ conntrack.Family, _ time.Time) ([]conntrack.Con, error) {
				dumpCalls++
				return nil, context.DeadlineExceeded
			},
			deleteFn: func(_ *ctConn, _ conntrack.Family, _ *conntrack.IPTuple, _ time.Time) error {
				deleteCalls++
				return nil
			},
		},
	}

	err := f.Flush(context.Background(), key)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Flush error = %v, want context.DeadlineExceeded", err)
	}
	if dumpCalls != 1 {
		t.Fatalf("dump calls = %d, want 1", dumpCalls)
	}
	if deleteCalls != 0 {
		t.Fatalf("delete calls = %d, want 0", deleteCalls)
	}
	if got := f.NetlinkDeletedCount(); got != 0 {
		t.Fatalf("NetlinkDeletedCount = %d, want 0", got)
	}
}

func TestFlushNetlinkFakeOpsMixedFamilySkipsDump(t *testing.T) {
	key := mustFlowKey(t, "192.0.2.10", "198.51.100.20", 443, FlowProtoTCP)
	v6 := mustFlowKey(t, "2001:db8::10", "2001:db8::20", 443, FlowProtoTCP)
	key.DstIP = v6.DstIP
	dumpCalls := 0
	f := &ConntrackFlusher{
		backend: BackendNetlink,
		pool:    testCtNetlinkPool(&ctConn{}),
		ctOps: fakeCtNetlinkOps{
			dumpFn: func(_ *ctConn, _ conntrack.Family, _ time.Time) ([]conntrack.Con, error) {
				dumpCalls++
				return nil, nil
			},
		},
	}

	if err := f.Flush(context.Background(), key); err != nil {
		t.Fatalf("Flush returned error: %v", err)
	}
	if dumpCalls != 0 {
		t.Fatalf("dump calls = %d, want 0 for mixed-family key", dumpCalls)
	}
	if got := f.SkippedCount(); got != 1 {
		t.Fatalf("SkippedCount after mixed-family key = %d, want 1", got)
	}
}

func TestL3FlushConntrackSkippedGauge(t *testing.T) {
	cf := &ConntrackFlusher{}
	cf.metricSkipped.Store(2)
	ac := &UdpAC{config: &Config{ACId: "test-ac"}}
	ac.conntrackFlusher.Store(cf)
	reg := &ACRegistration{ac: ac}

	if got := reg.l3FlushConntrackSkippedGauge(); got != 2 {
		t.Fatalf("l3FlushConntrackSkippedGauge = %v, want 2", got)
	}
}

func TestFlushNetlinkFakeOpsIPv6ICMPFamily(t *testing.T) {
	key := mustFlowKey(t, "2001:db8::10", "2001:db8::20", 0, FlowProtoICMP)
	deleteCalls := 0
	f := &ConntrackFlusher{
		backend: BackendNetlink,
		pool:    testCtNetlinkPool(&ctConn{}),
		ctOps: fakeCtNetlinkOps{
			dumpFn: func(_ *ctConn, family conntrack.Family, _ time.Time) ([]conntrack.Con, error) {
				if family != conntrack.IPv6 {
					t.Fatalf("dump family = %v, want IPv6", family)
				}
				return []conntrack.Con{
					testConntrackCon(t, "2001:db8::10", "2001:db8::20", 0, 0, 58),
					testConntrackCon(t, "2001:db8::11", "2001:db8::20", 0, 0, 58),
					testConntrackCon(t, "2001:db8::10", "2001:db8::20", 0, 0, unix.IPPROTO_TCP),
				}, nil
			},
			deleteFn: func(_ *ctConn, family conntrack.Family, origin *conntrack.IPTuple, _ time.Time) error {
				if family != conntrack.IPv6 {
					t.Fatalf("delete family = %v, want IPv6", family)
				}
				if origin == nil || origin.Src == nil || origin.Dst == nil || origin.Proto == nil || origin.Proto.Number == nil {
					t.Fatalf("delete origin incomplete: %+v", origin)
				}
				if got := *origin.Proto.Number; got != 58 {
					t.Fatalf("delete proto = %d, want ICMPv6 proto 58", got)
				}
				if got := (*origin.Src).String(); got != "2001:db8::10" {
					t.Fatalf("delete src = %s, want 2001:db8::10", got)
				}
				if got := (*origin.Dst).String(); got != "2001:db8::20" {
					t.Fatalf("delete dst = %s, want 2001:db8::20", got)
				}
				deleteCalls++
				return nil
			},
		},
	}

	if err := f.Flush(context.Background(), key); err != nil {
		t.Fatalf("Flush returned error: %v", err)
	}
	if deleteCalls != 1 {
		t.Fatalf("delete calls = %d, want 1", deleteCalls)
	}
	if got := f.NetlinkDeletedCount(); got != 1 {
		t.Fatalf("NetlinkDeletedCount = %d, want 1", got)
	}
}

func TestFlushNetlinkFakeOpsContinuesAfterSingleDeleteErrorBeforeDeadline(t *testing.T) {
	key := mustFlowKey(t, "192.0.2.10", "198.51.100.20", 443, FlowProtoTCP)
	boom := errors.New("boom")
	deleteCalls := 0
	f := &ConntrackFlusher{
		backend: BackendNetlink,
		pool:    testCtNetlinkPool(&ctConn{}),
		ctOps: fakeCtNetlinkOps{
			dumpFn: func(_ *ctConn, _ conntrack.Family, _ time.Time) ([]conntrack.Con, error) {
				return []conntrack.Con{
					testConntrackCon(t, "192.0.2.10", "198.51.100.20", 51000, 443, unix.IPPROTO_TCP),
					testConntrackCon(t, "192.0.2.10", "198.51.100.20", 51001, 443, unix.IPPROTO_TCP),
					testConntrackCon(t, "192.0.2.10", "198.51.100.20", 51002, 443, unix.IPPROTO_TCP),
				}, nil
			},
			deleteFn: func(_ *ctConn, _ conntrack.Family, _ *conntrack.IPTuple, _ time.Time) error {
				deleteCalls++
				if deleteCalls == 2 {
					return boom
				}
				return nil
			},
		},
	}

	err := f.Flush(context.Background(), key)
	if !errors.Is(err, boom) {
		t.Fatalf("Flush error = %v, want errors.Is(..., boom)", err)
	}
	if !strings.Contains(err.Error(), "deleted 2/3 matched") {
		t.Fatalf("Flush error = %q, want partial delete count", err)
	}
	if deleteCalls != 3 {
		t.Fatalf("delete calls = %d, want 3", deleteCalls)
	}
	if got := f.NetlinkDeletedCount(); got != 2 {
		t.Fatalf("NetlinkDeletedCount = %d, want 2", got)
	}
}

func TestFlushNetlinkFakeOpsStopsOnConsecutiveDeleteErrorsBeforeDeadline(t *testing.T) {
	key := mustFlowKey(t, "192.0.2.10", "198.51.100.20", 443, FlowProtoTCP)
	boom := errors.New("boom")
	deleteCalls := 0
	origins := []conntrack.Con{
		testConntrackCon(t, "192.0.2.10", "198.51.100.20", 51000, 443, unix.IPPROTO_TCP),
		testConntrackCon(t, "192.0.2.10", "198.51.100.20", 51001, 443, unix.IPPROTO_TCP),
		testConntrackCon(t, "192.0.2.10", "198.51.100.20", 51002, 443, unix.IPPROTO_TCP),
		testConntrackCon(t, "192.0.2.10", "198.51.100.20", 51003, 443, unix.IPPROTO_TCP),
		testConntrackCon(t, "192.0.2.10", "198.51.100.20", 51004, 443, unix.IPPROTO_TCP),
	}
	f := &ConntrackFlusher{
		backend: BackendNetlink,
		pool:    testCtNetlinkPool(&ctConn{}),
		ctOps: fakeCtNetlinkOps{
			dumpFn: func(_ *ctConn, _ conntrack.Family, _ time.Time) ([]conntrack.Con, error) {
				return origins, nil
			},
			deleteFn: func(_ *ctConn, _ conntrack.Family, _ *conntrack.IPTuple, _ time.Time) error {
				deleteCalls++
				return boom
			},
		},
	}

	err := f.Flush(context.Background(), key)
	if !errors.Is(err, boom) {
		t.Fatalf("Flush error = %v, want errors.Is(..., boom)", err)
	}
	if !strings.Contains(err.Error(), "deleted 0/5 matched") {
		t.Fatalf("Flush error = %q, want matched count", err)
	}
	if deleteCalls != maxConsecutiveNetlinkDeleteErrors {
		t.Fatalf("delete calls = %d, want %d", deleteCalls, maxConsecutiveNetlinkDeleteErrors)
	}
	if got := f.NetlinkDeletedCount(); got != 0 {
		t.Fatalf("NetlinkDeletedCount = %d, want 0", got)
	}
}

func TestFlushNetlinkFakeOpsStopsOnPersistentDeleteErrorAfterDeadline(t *testing.T) {
	key := mustFlowKey(t, "192.0.2.10", "198.51.100.20", 443, FlowProtoTCP)
	boom := errors.New("boom")
	deleteCalls := 0
	f := &ConntrackFlusher{
		backend: BackendNetlink,
		pool:    testCtNetlinkPool(&ctConn{}),
		ctOps: fakeCtNetlinkOps{
			dumpFn: func(_ *ctConn, _ conntrack.Family, _ time.Time) ([]conntrack.Con, error) {
				return []conntrack.Con{
					testConntrackCon(t, "192.0.2.10", "198.51.100.20", 51000, 443, unix.IPPROTO_TCP),
					testConntrackCon(t, "192.0.2.10", "198.51.100.20", 51001, 443, unix.IPPROTO_TCP),
				}, nil
			},
			deleteFn: func(_ *ctConn, _ conntrack.Family, _ *conntrack.IPTuple, deadline time.Time) error {
				deleteCalls++
				if sleep := time.Until(deadline) + time.Millisecond; sleep > 0 {
					time.Sleep(sleep)
				}
				return boom
			},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	err := f.Flush(ctx, key)
	if !errors.Is(err, boom) {
		t.Fatalf("Flush error = %v, want errors.Is(..., boom)", err)
	}
	if !strings.Contains(err.Error(), "deleted 0/2 matched") {
		t.Fatalf("Flush error = %q, want deadline-break delete count", err)
	}
	if deleteCalls != 1 {
		t.Fatalf("delete calls = %d, want 1", deleteCalls)
	}
	if got := f.NetlinkDeletedCount(); got != 0 {
		t.Fatalf("NetlinkDeletedCount = %d, want 0", got)
	}
}

func TestFlushNetlinkCtxCanceledWhileWaitingForFreeSocket(t *testing.T) {
	key := mustFlowKey(t, "192.0.2.10", "198.51.100.20", 443, FlowProtoTCP)
	var dumpCalls atomic.Int32
	f := &ConntrackFlusher{
		backend: BackendNetlink,
		pool:    &ctNetlinkPool{conns: []*ctConn{{}}, free: make(chan *ctConn, 1)},
		ctOps: fakeCtNetlinkOps{dumpFn: func(*ctConn, conntrack.Family, time.Time) ([]conntrack.Con, error) {
			dumpCalls.Add(1)
			return nil, nil
		}},
	}
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- f.Flush(ctx, key)
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()

	err := <-errCh
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Flush error = %v, want context.Canceled", err)
	}
	if got := dumpCalls.Load(); got != 0 {
		t.Fatalf("dump calls after canceled pool acquire = %d, want 0", got)
	}
}

func TestDumpWithRetry(t *testing.T) {
	t.Run("transient-error-retries-on-fresh-socket", func(t *testing.T) {
		calls := 0
		f := &ConntrackFlusher{ctOps: fakeCtNetlinkOps{dumpFn: func(*ctConn, conntrack.Family, time.Time) ([]conntrack.Con, error) {
			calls++
			if calls == 1 {
				return nil, unix.ENOBUFS
			}
			return []conntrack.Con{{}}, nil
		}}}

		cons, _, err := f.dumpWithRetry(&ctConn{}, conntrack.IPv4, time.Now().Add(time.Minute))
		if err != nil {
			t.Fatalf("dumpWithRetry returned error: %v", err)
		}
		if calls != 2 {
			t.Fatalf("dump calls = %d, want 2", calls)
		}
		if len(cons) != 1 {
			t.Fatalf("dump result len = %d, want 1", len(cons))
		}
	})

	t.Run("expired-deadline-does-not-retry-transient-error", func(t *testing.T) {
		calls := 0
		f := &ConntrackFlusher{ctOps: fakeCtNetlinkOps{dumpFn: func(*ctConn, conntrack.Family, time.Time) ([]conntrack.Con, error) {
			calls++
			return nil, unix.EINTR
		}}}

		_, _, err := f.dumpWithRetry(&ctConn{}, conntrack.IPv4, time.Now().Add(-time.Millisecond))
		if !errors.Is(err, unix.EINTR) {
			t.Fatalf("dumpWithRetry error = %v, want EINTR", err)
		}
		if calls != 1 {
			t.Fatalf("dump calls = %d, want 1", calls)
		}
	})
}

func TestDeleteOriginWithRetry(t *testing.T) {
	origin := &conntrack.IPTuple{}

	t.Run("transient-error-retries-on-fresh-socket", func(t *testing.T) {
		calls := 0
		f := &ConntrackFlusher{ctOps: fakeCtNetlinkOps{deleteFn: func(*ctConn, conntrack.Family, *conntrack.IPTuple, time.Time) error {
			calls++
			if calls == 1 {
				return unix.EINTR
			}
			return nil
		}}}

		if err := f.deleteOriginWithRetry(&ctConn{}, conntrack.IPv4, origin, time.Now().Add(time.Minute)); err != nil {
			t.Fatalf("deleteOriginWithRetry returned error: %v", err)
		}
		if calls != 2 {
			t.Fatalf("delete calls = %d, want 2", calls)
		}
	})

	t.Run("expired-deadline-does-not-retry-transient-error", func(t *testing.T) {
		calls := 0
		f := &ConntrackFlusher{ctOps: fakeCtNetlinkOps{deleteFn: func(*ctConn, conntrack.Family, *conntrack.IPTuple, time.Time) error {
			calls++
			return unix.ENOBUFS
		}}}

		err := f.deleteOriginWithRetry(&ctConn{}, conntrack.IPv4, origin, time.Now().Add(-time.Millisecond))
		if !errors.Is(err, unix.ENOBUFS) {
			t.Fatalf("deleteOriginWithRetry error = %v, want ENOBUFS", err)
		}
		if calls != 1 {
			t.Fatalf("delete calls = %d, want 1", calls)
		}
	})
}

func TestConToTuple(t *testing.T) {
	u8 := func(v uint8) *uint8 { return &v }
	u16 := func(v uint16) *uint16 { return &v }
	ip := func(s string) *net.IP {
		parsed := net.ParseIP(s)
		if parsed == nil {
			t.Fatalf("net.ParseIP(%q) returned nil", s)
		}
		return &parsed
	}

	tests := []struct {
		name string
		con  *conntrack.Con
		want ctTuple
		ok   bool
	}{
		{
			name: "tcp-v4-full-tuple",
			con: &conntrack.Con{Origin: &conntrack.IPTuple{
				Src: ip("192.0.2.10"),
				Dst: ip("198.51.100.20"),
				Proto: &conntrack.ProtoTuple{
					Number:  u8(unix.IPPROTO_TCP),
					SrcPort: u16(54321),
					DstPort: u16(443),
				},
			}},
			want: mustCtTuple(t, "192.0.2.10", "198.51.100.20", 54321, 443, unix.IPPROTO_TCP),
			ok:   true,
		},
		{
			name: "icmpv6-no-ports",
			con: &conntrack.Con{Origin: &conntrack.IPTuple{
				Src: ip("2001:db8::1"),
				Dst: ip("2001:db8::2"),
				Proto: &conntrack.ProtoTuple{
					Number: u8(58),
				},
			}},
			want: mustCtTuple(t, "2001:db8::1", "2001:db8::2", 0, 0, 58),
			ok:   true,
		},
		{
			name: "tcp-missing-dst-port-is-partial",
			con: &conntrack.Con{Origin: &conntrack.IPTuple{
				Src: ip("192.0.2.10"),
				Dst: ip("198.51.100.20"),
				Proto: &conntrack.ProtoTuple{
					Number:  u8(unix.IPPROTO_TCP),
					SrcPort: u16(54321),
				},
			}},
			ok: false,
		},
		{
			name: "missing-proto-number-is-partial",
			con: &conntrack.Con{Origin: &conntrack.IPTuple{
				Src:   ip("192.0.2.10"),
				Dst:   ip("198.51.100.20"),
				Proto: &conntrack.ProtoTuple{},
			}},
			ok: false,
		},
		{
			name: "nil-origin-is-partial",
			con:  &conntrack.Con{},
			ok:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := conToTuple(tt.con)
			if ok != tt.ok {
				t.Fatalf("conToTuple ok = %v, want %v", ok, tt.ok)
			}
			if ok && got != tt.want {
				t.Errorf("conToTuple = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// requireConntrackNetlink skips the caller when this environment can't
// open a conntrack netlink socket (needs CAP_NET_ADMIN + the
// nf_conntrack_netlink module). CI runners and dev laptops usually
// can't, so the netlink datapath tests skip there and exercise on a
// sandbox AC, where the #2165 acceptance soak runs.
func requireConntrackNetlink(tb testing.TB) {
	tb.Helper()
	c, err := conntrack.Open(&conntrack.Config{})
	if err != nil {
		tb.Skipf("conntrack netlink unavailable (need CAP_NET_ADMIN + nf_conntrack_netlink): %v", err)
	}
	_ = c.Close()
}

// TestConntrackFlusherNetlink_Idempotent fences the FlowFlusher
// idempotency contract on the netlink backend: a Flush against a tuple
// with no matching kernel entry MUST return nil so the scheduler's
// breaker is not pinged (the #2168 schedule-then-write reorder relies on
// it). Uses documentation-range addresses (RFC 5737 / RFC 3849) that
// won't have live flows. Also asserts the v4 + v6 + "any" paths all
// no-op cleanly — the v6 path is the capability the exec backend lacks.
func TestConntrackFlusherNetlink_Idempotent(t *testing.T) {
	requireConntrackNetlink(t)
	f, err := NewConntrackFlusher(WithBackend(BackendNetlink), WithNetlinkPoolSize(2))
	if err != nil {
		t.Fatalf("NewConntrackFlusher(netlink): %v", err)
	}
	defer func() { _ = f.Close() }()
	if !f.HandlesIPv6() {
		t.Error("netlink backend must report HandlesIPv6() == true")
	}
	if !f.IsNetlinkBackend() {
		t.Error("netlink backend must report IsNetlinkBackend() == true")
	}

	cases := []struct {
		name  string
		src   string
		dst   string
		port  int
		proto FlowProto
	}{
		{"v4-tcp", "192.0.2.10", "198.51.100.20", 443, FlowProtoTCP},
		{"v4-udp-wildcard-port", "192.0.2.11", "198.51.100.21", 0, FlowProtoUDP},
		{"v4-any", "192.0.2.12", "198.51.100.22", 0, FlowProtoAny},
		{"v6-tcp", "2001:db8::10", "2001:db8::20", 443, FlowProtoTCP},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key := mustFlowKey(t, tc.src, tc.dst, tc.port, tc.proto)
			if err := f.Flush(context.Background(), key); err != nil {
				t.Errorf("Flush(%s) on no-match must be nil (idempotent), got: %v", key, err)
			}
		})
	}
}

// TestConntrackFlusherNetlink_CtxCanceled fences ctx-at-entry honoring:
// a Flush whose context is already canceled returns the context error
// without touching the kernel (mirrors BpfFlusher.Flush).
func TestConntrackFlusherNetlink_CtxCanceled(t *testing.T) {
	requireConntrackNetlink(t)
	f, err := NewConntrackFlusher(WithBackend(BackendNetlink), WithNetlinkPoolSize(1))
	if err != nil {
		t.Fatalf("NewConntrackFlusher(netlink): %v", err)
	}
	defer func() { _ = f.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	key := mustFlowKey(t, "192.0.2.10", "198.51.100.20", 443, FlowProtoTCP)
	if err := f.Flush(ctx, key); err == nil {
		t.Error("Flush with a canceled ctx should return the context error")
	}
}

// BenchmarkConntrackFlusher_Netlink is the #2165 small-table acceptance
// gate: ≤200µs/op steady-state on a fresh/small sandbox AC. It measures Flush
// against the AMBIENT conntrack table with a no-match key, which isolates the
// dominant per-expiry cost — the netlink dump — without the noise of live
// deletes. Set NHP_CONNTRACK_NETLINK_BENCH_GATE=1 to make the acceptance fence
// fail via b.Errorf when per-op time exceeds the budget; without it, the bench
// logs the miss so ad hoc/CI -bench invocations against a populated table don't
// fail for the expected table-size-knee signal (#2908). The rollout ledger's
// populated-table characterization is the separate throughput gate.
//
// Acceptance run:
//
//	NHP_CONNTRACK_NETLINK_BENCH_GATE=1 go test \
//	  -bench=BenchmarkConntrackFlusher_Netlink -benchtime=2s ./endpoints/ac/
func BenchmarkConntrackFlusher_Netlink(b *testing.B) {
	requireConntrackNetlink(b)
	f, err := NewConntrackFlusher(WithBackend(BackendNetlink), WithNetlinkPoolSize(defaultConntrackNetlinkPoolSize))
	if err != nil {
		b.Fatalf("NewConntrackFlusher(netlink): %v", err)
	}
	defer func() { _ = f.Close() }()

	key, err := MakeFlowKey("192.0.2.10", "198.51.100.20", 443, FlowProtoTCP)
	if err != nil {
		b.Fatalf("MakeFlowKey: %v", err)
	}
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if ferr := f.Flush(ctx, key); ferr != nil {
			b.Fatalf("Flush: %v", ferr)
		}
	}
	b.StopTimer()

	const budgetNsPerOp = 200_000.0 // 200µs — the #2165 acceptance gate
	if nsPerOp := float64(b.Elapsed().Nanoseconds()) / float64(b.N); nsPerOp > budgetNsPerOp {
		if os.Getenv("NHP_CONNTRACK_NETLINK_BENCH_GATE") == "1" {
			b.Errorf("netlink Flush %.0f ns/op exceeds the #2165 ≤200µs/op gate — conntrack table likely large; the per-key dump has hit the table-size knee (#2908)", nsPerOp)
		} else {
			b.Logf("netlink Flush %.0f ns/op exceeds the #2165 ≤200µs/op gate; set NHP_CONNTRACK_NETLINK_BENCH_GATE=1 when running the sandbox acceptance gate", nsPerOp)
		}
	}
}

// BenchmarkConntrackFlusher_Netlink_Parallel exercises the socket POOL
// under concurrency — the regime the serial benchmark can't surface (the
// review flagged that the ≤200µs gate is otherwise only measured single-
// threaded, which won't show the concurrent-burst regime the throughput
// follow-up worries about). Each goroutine flushes a distinct no-match key
// so the availability-aware free-list pool + per-socket locking is what's under
// test. No fixed ns/op fence here (contention makes that noisy); this is for
// spotting pool-contention pathology and for -race coverage of the pooled
// sockets, with the serial benchmark owning the acceptance gate.
//
// Run: go test -bench=BenchmarkConntrackFlusher_Netlink_Parallel -benchtime=2s ./endpoints/ac/
func BenchmarkConntrackFlusher_Netlink_Parallel(b *testing.B) {
	requireConntrackNetlink(b)
	f, err := NewConntrackFlusher(WithBackend(BackendNetlink), WithNetlinkPoolSize(defaultConntrackNetlinkPoolSize))
	if err != nil {
		b.Fatalf("NewConntrackFlusher(netlink): %v", err)
	}
	defer func() { _ = f.Close() }()
	ctx := context.Background()

	var counter atomic.Uint32
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			// Distinct dst per call so concurrent goroutines aren't hitting the
			// same (empty) match set in lockstep.
			n := counter.Add(1)
			key, kerr := MakeFlowKey("192.0.2.10", fmt.Sprintf("198.51.100.%d", n%250+1), 443, FlowProtoTCP)
			if kerr != nil {
				b.Fatalf("MakeFlowKey: %v", kerr)
			}
			if ferr := f.Flush(ctx, key); ferr != nil {
				b.Fatalf("Flush: %v", ferr)
			}
		}
	})
}
