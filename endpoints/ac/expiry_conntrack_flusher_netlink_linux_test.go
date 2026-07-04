//go:build linux

package ac

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
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
	dumpFn   func(_ context.Context, _ *ctConn, _ conntrack.Family, _ time.Time, _ bool) ([]conntrack.Con, error)
	deleteFn func(context.Context, *ctConn, conntrack.Family, *conntrack.IPTuple, time.Time) error
}

func (f fakeCtNetlinkOps) dump(ctx context.Context, c *ctConn, family conntrack.Family, deadline time.Time, interruptOnCancel bool) ([]conntrack.Con, error) {
	if f.dumpFn == nil {
		return nil, errors.New("unexpected dump")
	}
	return f.dumpFn(ctx, c, family, deadline, interruptOnCancel)
}

func (f fakeCtNetlinkOps) deleteOrigin(ctx context.Context, c *ctConn, family conntrack.Family, origin *conntrack.IPTuple, deadline time.Time) error {
	if f.deleteFn == nil {
		return errors.New("unexpected delete")
	}
	return f.deleteFn(ctx, c, family, origin, deadline)
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

func testIPLen(ip *net.IP) int {
	if ip == nil {
		return 0
	}
	return len(*ip)
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
			dumpFn: func(_ context.Context, _ *ctConn, family conntrack.Family, _ time.Time, _ bool) ([]conntrack.Con, error) {
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
			deleteFn: func(_ context.Context, _ *ctConn, family conntrack.Family, origin *conntrack.IPTuple, _ time.Time) error {
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

func TestConntrackEventIndexQueriesAndDestroy(t *testing.T) {
	idx := &ctEventIndex{
		byQuery:  make(map[ctIndexQueryKey]map[ctOriginKey]struct{}),
		byOrigin: make(map[ctOriginKey]struct{}),
	}
	con := testConntrackCon(t, "192.0.2.10", "198.51.100.20", 51000, 443, unix.IPPROTO_TCP)
	if got := idx.rebuild([]conntrack.Con{con}); got != 1 {
		t.Fatalf("rebuild indexed %d origins, want 1", got)
	}

	exact := mustFlowKey(t, "192.0.2.10", "198.51.100.20", 443, FlowProtoTCP)
	wildcardPort := mustFlowKey(t, "192.0.2.10", "198.51.100.20", 0, FlowProtoTCP)
	anyProto := mustFlowKey(t, "192.0.2.10", "198.51.100.20", 0, FlowProtoAny)
	wrongPort := mustFlowKey(t, "192.0.2.10", "198.51.100.20", 8443, FlowProtoTCP)

	for _, key := range []FlowKey{exact, wildcardPort, anyProto} {
		origins, ok := idx.originsForKey(key)
		if !ok {
			t.Fatalf("originsForKey(%s) reported unhealthy index", key)
		}
		if len(origins) != 1 {
			t.Fatalf("originsForKey(%s) len = %d, want 1", key, len(origins))
		}
	}
	origins, ok := idx.originsForKey(wrongPort)
	if !ok {
		t.Fatal("originsForKey(wrongPort) reported unhealthy index")
	}
	if len(origins) != 0 {
		t.Fatalf("originsForKey(wrongPort) len = %d, want 0", len(origins))
	}

	con.Info = &conntrack.InfoSource{NetlinkGroup: conntrack.NetlinkCtDestroy}
	idx.handleEvent(con)
	origins, ok = idx.originsForKey(exact)
	if !ok {
		t.Fatal("originsForKey(exact after destroy) reported unhealthy index")
	}
	if len(origins) != 0 {
		t.Fatalf("originsForKey(exact after destroy) len = %d, want 0", len(origins))
	}
}

func TestConntrackEventIndexCanonicalizesDontCareFields(t *testing.T) {
	idx := &ctEventIndex{
		byQuery:  make(map[ctIndexQueryKey]map[ctOriginKey]struct{}),
		byOrigin: make(map[ctOriginKey]struct{}),
	}
	idx.rebuild([]conntrack.Con{
		testConntrackCon(t, "192.0.2.10", "198.51.100.20", 51000, 443, unix.IPPROTO_TCP),
		testConntrackCon(t, "192.0.2.10", "198.51.100.20", 51001, 53, unix.IPPROTO_UDP),
		testConntrackCon(t, "192.0.2.10", "198.51.100.20", 0, 0, unix.IPPROTO_ICMP),
	})

	anyWithIgnoredPort := mustFlowKey(t, "192.0.2.10", "198.51.100.20", 443, FlowProtoAny)
	origins, ok := idx.originsForKey(anyWithIgnoredPort)
	if !ok {
		t.Fatal("originsForKey(anyWithIgnoredPort) reported unhealthy index")
	}
	if len(origins) != 3 {
		t.Fatalf("originsForKey(anyWithIgnoredPort) len = %d, want 3", len(origins))
	}

	icmpWithIgnoredPort := mustFlowKey(t, "192.0.2.10", "198.51.100.20", 443, FlowProtoICMP)
	origins, ok = idx.originsForKey(icmpWithIgnoredPort)
	if !ok {
		t.Fatal("originsForKey(icmpWithIgnoredPort) reported unhealthy index")
	}
	if len(origins) != 1 {
		t.Fatalf("originsForKey(icmpWithIgnoredPort) len = %d, want 1", len(origins))
	}
	if origins[0].Proto == nil || origins[0].Proto.Number == nil || *origins[0].Proto.Number != unix.IPPROTO_ICMP {
		t.Fatalf("originsForKey(icmpWithIgnoredPort) origin proto = %+v, want ICMP", origins[0].Proto)
	}
}

func TestConntrackEventIndexReconstructsDeleteTupleFromCompactKey(t *testing.T) {
	ip := func(s string) *net.IP {
		parsed := net.ParseIP(s)
		if parsed == nil {
			t.Fatalf("net.ParseIP(%q) returned nil", s)
		}
		return &parsed
	}

	t.Run("icmp_v4_preserves_presence_and_zero_values", func(t *testing.T) {
		zone := uint16(12)
		original := conntrack.Con{Origin: &conntrack.IPTuple{
			Src:  ip("192.0.2.10"),
			Dst:  ip("198.51.100.20"),
			Zone: &zone,
			Proto: &conntrack.ProtoTuple{
				Number:   ptrTo(uint8(unix.IPPROTO_ICMP)),
				IcmpID:   ptrTo(uint16(7)),
				IcmpType: ptrTo(uint8(8)),
				IcmpCode: ptrTo(uint8(0)),
			},
		}}
		idx := &ctEventIndex{
			byQuery:  make(map[ctIndexQueryKey]map[ctOriginKey]struct{}),
			byOrigin: make(map[ctOriginKey]struct{}),
		}
		idx.rebuild([]conntrack.Con{original})

		key := mustFlowKey(t, "192.0.2.10", "198.51.100.20", 443, FlowProtoICMP)
		origins, ok := idx.originsForKey(key)
		if !ok {
			t.Fatal("originsForKey(ICMP) reported unhealthy index")
		}
		if len(origins) != 1 {
			t.Fatalf("originsForKey(ICMP) len = %d, want 1", len(origins))
		}
		got := origins[0]
		if got.Src == nil || got.Src.String() != "192.0.2.10" || len(*got.Src) != net.IPv4len {
			t.Fatalf("reconstructed ICMP src = %v len=%d, want 192.0.2.10 len=%d", got.Src, testIPLen(got.Src), net.IPv4len)
		}
		if got.Dst == nil || got.Dst.String() != "198.51.100.20" || len(*got.Dst) != net.IPv4len {
			t.Fatalf("reconstructed ICMP dst = %v len=%d, want 198.51.100.20 len=%d", got.Dst, testIPLen(got.Dst), net.IPv4len)
		}
		if got.Zone == nil || *got.Zone != zone {
			t.Fatalf("reconstructed zone = %v, want %d", got.Zone, zone)
		}
		if got.Proto == nil || got.Proto.Number == nil || *got.Proto.Number != unix.IPPROTO_ICMP {
			t.Fatalf("reconstructed ICMP proto = %+v", got.Proto)
		}
		if got.Proto.SrcPort != nil || got.Proto.DstPort != nil {
			t.Fatalf("reconstructed ICMP tuple gained port filters: %+v", got.Proto)
		}
		if got.Proto.IcmpID == nil || *got.Proto.IcmpID != 7 ||
			got.Proto.IcmpType == nil || *got.Proto.IcmpType != 8 ||
			got.Proto.IcmpCode == nil || *got.Proto.IcmpCode != 0 {
			t.Fatalf("reconstructed ICMP fields = %+v, want id=7 type=8 code=0", got.Proto)
		}
	})

	t.Run("icmp_v6_preserves_v6_fields_without_v4_icmp_filters", func(t *testing.T) {
		original := conntrack.Con{Origin: &conntrack.IPTuple{
			Src: ip("2001:db8::10"),
			Dst: ip("2001:db8::20"),
			Proto: &conntrack.ProtoTuple{
				Number:     ptrTo(uint8(unix.IPPROTO_ICMPV6)),
				Icmpv6ID:   ptrTo(uint16(9)),
				Icmpv6Type: ptrTo(uint8(128)),
				Icmpv6Code: ptrTo(uint8(0)),
			},
		}}
		idx := &ctEventIndex{
			byQuery:  make(map[ctIndexQueryKey]map[ctOriginKey]struct{}),
			byOrigin: make(map[ctOriginKey]struct{}),
		}
		idx.rebuild([]conntrack.Con{original})

		key := mustFlowKey(t, "2001:db8::10", "2001:db8::20", 0, FlowProtoICMP)
		origins, ok := idx.originsForKey(key)
		if !ok {
			t.Fatal("originsForKey(ICMPv6) reported unhealthy index")
		}
		if len(origins) != 1 {
			t.Fatalf("originsForKey(ICMPv6) len = %d, want 1", len(origins))
		}
		got := origins[0]
		if got.Src == nil || got.Src.String() != "2001:db8::10" || len(*got.Src) != net.IPv6len {
			t.Fatalf("reconstructed ICMPv6 src = %v len=%d, want 2001:db8::10 len=%d", got.Src, testIPLen(got.Src), net.IPv6len)
		}
		if got.Dst == nil || got.Dst.String() != "2001:db8::20" || len(*got.Dst) != net.IPv6len {
			t.Fatalf("reconstructed ICMPv6 dst = %v len=%d, want 2001:db8::20 len=%d", got.Dst, testIPLen(got.Dst), net.IPv6len)
		}
		if got.Proto == nil || got.Proto.Number == nil || *got.Proto.Number != unix.IPPROTO_ICMPV6 {
			t.Fatalf("reconstructed ICMPv6 proto = %+v", got.Proto)
		}
		if got.Proto.IcmpID != nil || got.Proto.IcmpType != nil || got.Proto.IcmpCode != nil {
			t.Fatalf("reconstructed ICMPv6 tuple gained v4 ICMP filters: %+v", got.Proto)
		}
		if got.Proto.Icmpv6ID == nil || *got.Proto.Icmpv6ID != 9 ||
			got.Proto.Icmpv6Type == nil || *got.Proto.Icmpv6Type != 128 ||
			got.Proto.Icmpv6Code == nil || *got.Proto.Icmpv6Code != 0 {
			t.Fatalf("reconstructed ICMPv6 fields = %+v, want id=9 type=128 code=0", got.Proto)
		}
	})
}

func TestConntrackOriginKeyRoundTripsThroughReconstructedTuple(t *testing.T) {
	ip := func(s string) *net.IP {
		parsed := net.ParseIP(s)
		if parsed == nil {
			t.Fatalf("net.ParseIP(%q) returned nil", s)
		}
		return &parsed
	}
	zone := uint16(0)

	tests := []struct {
		name          string
		origin        *conntrack.IPTuple
		wantSrcPort   *uint16
		wantDstPort   *uint16
		wantICMPCode  *uint8
		wantICMPv6ID  *uint16
		wantZone      *uint16
		wantSourceLen int
	}{
		{
			name: "tcp_v4_ports",
			origin: &conntrack.IPTuple{
				Src: ip("192.0.2.10"),
				Dst: ip("198.51.100.20"),
				Proto: &conntrack.ProtoTuple{
					Number:  ptrTo(uint8(unix.IPPROTO_TCP)),
					SrcPort: ptrTo(uint16(51000)),
					DstPort: ptrTo(uint16(443)),
				},
			},
			wantSrcPort:   ptrTo(uint16(51000)),
			wantDstPort:   ptrTo(uint16(443)),
			wantSourceLen: net.IPv4len,
		},
		{
			name: "udp_v4_ports",
			origin: &conntrack.IPTuple{
				Src: ip("192.0.2.30"),
				Dst: ip("198.51.100.40"),
				Proto: &conntrack.ProtoTuple{
					Number:  ptrTo(uint8(unix.IPPROTO_UDP)),
					SrcPort: ptrTo(uint16(53000)),
					DstPort: ptrTo(uint16(53)),
				},
			},
			wantSrcPort:   ptrTo(uint16(53000)),
			wantDstPort:   ptrTo(uint16(53)),
			wantSourceLen: net.IPv4len,
		},
		{
			name: "icmp_v4_zero_code",
			origin: &conntrack.IPTuple{
				Src: ip("192.0.2.50"),
				Dst: ip("198.51.100.60"),
				Proto: &conntrack.ProtoTuple{
					Number:   ptrTo(uint8(unix.IPPROTO_ICMP)),
					IcmpID:   ptrTo(uint16(7)),
					IcmpType: ptrTo(uint8(8)),
					IcmpCode: ptrTo(uint8(0)),
				},
			},
			wantICMPCode:  ptrTo(uint8(0)),
			wantSourceLen: net.IPv4len,
		},
		{
			name: "icmpv6_v6_zero_code",
			origin: &conntrack.IPTuple{
				Src: ip("2001:db8::10"),
				Dst: ip("2001:db8::20"),
				Proto: &conntrack.ProtoTuple{
					Number:     ptrTo(uint8(unix.IPPROTO_ICMPV6)),
					Icmpv6ID:   ptrTo(uint16(9)),
					Icmpv6Type: ptrTo(uint8(128)),
					Icmpv6Code: ptrTo(uint8(0)),
				},
			},
			wantICMPv6ID:  ptrTo(uint16(9)),
			wantSourceLen: net.IPv6len,
		},
		{
			name: "tcp_v6_zone_zero",
			origin: &conntrack.IPTuple{
				Src:  ip("2001:db8::30"),
				Dst:  ip("2001:db8::40"),
				Zone: &zone,
				Proto: &conntrack.ProtoTuple{
					Number:  ptrTo(uint8(unix.IPPROTO_TCP)),
					SrcPort: ptrTo(uint16(61000)),
					DstPort: ptrTo(uint16(8443)),
				},
			},
			wantSrcPort:   ptrTo(uint16(61000)),
			wantDstPort:   ptrTo(uint16(8443)),
			wantZone:      &zone,
			wantSourceLen: net.IPv6len,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, ok := originKeyFromIPTuple(tt.origin)
			if !ok {
				t.Fatal("originKeyFromIPTuple(original) returned false")
			}

			reconstructed := originTupleFromKey(key)
			roundTripped, ok := originKeyFromIPTuple(reconstructed)
			if !ok {
				t.Fatal("originKeyFromIPTuple(reconstructed) returned false")
			}
			if roundTripped != key {
				t.Fatalf("round-tripped origin key = %+v, want %+v", roundTripped, key)
			}
			if reconstructed.Src == nil || len(*reconstructed.Src) != tt.wantSourceLen {
				t.Fatalf("reconstructed src len = %d, want %d", testIPLen(reconstructed.Src), tt.wantSourceLen)
			}
			if tt.wantSrcPort != nil && (reconstructed.Proto == nil || reconstructed.Proto.SrcPort == nil || *reconstructed.Proto.SrcPort != *tt.wantSrcPort) {
				t.Fatalf("reconstructed source port = %+v, want %d", reconstructed.Proto, *tt.wantSrcPort)
			}
			if tt.wantDstPort != nil && (reconstructed.Proto == nil || reconstructed.Proto.DstPort == nil || *reconstructed.Proto.DstPort != *tt.wantDstPort) {
				t.Fatalf("reconstructed destination port = %+v, want %d", reconstructed.Proto, *tt.wantDstPort)
			}
			if tt.wantICMPCode != nil && (reconstructed.Proto == nil || reconstructed.Proto.IcmpCode == nil || *reconstructed.Proto.IcmpCode != *tt.wantICMPCode) {
				t.Fatalf("reconstructed ICMP code = %+v, want %d", reconstructed.Proto, *tt.wantICMPCode)
			}
			if tt.wantICMPv6ID != nil && (reconstructed.Proto == nil || reconstructed.Proto.Icmpv6ID == nil || *reconstructed.Proto.Icmpv6ID != *tt.wantICMPv6ID) {
				t.Fatalf("reconstructed ICMPv6 id = %+v, want %d", reconstructed.Proto, *tt.wantICMPv6ID)
			}
			if tt.wantZone != nil && (reconstructed.Zone == nil || *reconstructed.Zone != *tt.wantZone) {
				t.Fatalf("reconstructed zone = %v, want %d", reconstructed.Zone, *tt.wantZone)
			}
		})
	}
}

func TestConntrackOriginTupleFromKeyPreservesIndependentProtoPresence(t *testing.T) {
	tcpFlow := mustFlowKey(t, "192.0.2.70", "198.51.100.80", 443, FlowProtoTCP)
	icmpFlow := mustFlowKey(t, "192.0.2.90", "198.51.100.100", 0, FlowProtoICMP)

	tests := []struct {
		name  string
		key   ctOriginKey
		check func(*conntrack.IPTuple, ctOriginKey)
	}{
		{
			name: "tcp_source_port_without_destination_port",
			key: ctOriginKey{
				family:      conntrack.IPv4,
				srcIP:       tcpFlow.SrcIP,
				dstIP:       tcpFlow.DstIP,
				proto:       unix.IPPROTO_TCP,
				srcPort:     51000,
				protoFields: ctOriginHasSrcPort,
			},
			check: func(got *conntrack.IPTuple, _ ctOriginKey) {
				if got.Proto == nil || got.Proto.SrcPort == nil || *got.Proto.SrcPort != 51000 {
					t.Fatalf("reconstructed TCP source port = %+v, want only src=51000", got.Proto)
				}
				if got.Proto.DstPort != nil {
					t.Fatalf("reconstructed TCP tuple gained destination port: %+v", got.Proto)
				}
			},
		},
		{
			name: "icmp_id_without_type_or_code",
			key: ctOriginKey{
				family:      conntrack.IPv4,
				srcIP:       icmpFlow.SrcIP,
				dstIP:       icmpFlow.DstIP,
				proto:       unix.IPPROTO_ICMP,
				icmpID:      7,
				protoFields: ctOriginHasIcmpID,
			},
			check: func(got *conntrack.IPTuple, want ctOriginKey) {
				if got.Proto == nil || got.Proto.IcmpID == nil || *got.Proto.IcmpID != 7 {
					t.Fatalf("reconstructed ICMP id = %+v, want only id=7", got.Proto)
				}
				if got.Proto.IcmpType != nil || got.Proto.IcmpCode != nil {
					t.Fatalf("reconstructed ICMP tuple gained type/code filters: %+v", got.Proto)
				}
				roundTripped, ok := originKeyFromIPTuple(got)
				if !ok {
					t.Fatal("originKeyFromIPTuple(ICMP id-only reconstructed tuple) returned false")
				}
				if roundTripped != want {
					t.Fatalf("round-tripped ICMP id-only key = %+v, want %+v", roundTripped, want)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.check(originTupleFromKey(tt.key), tt.key)
		})
	}
}

func TestConntrackEventIndexReplaysEventsAfterBackfill(t *testing.T) {
	idx := &ctEventIndex{
		byQuery:     make(map[ctIndexQueryKey]map[ctOriginKey]struct{}),
		byOrigin:    make(map[ctOriginKey]struct{}),
		backfilling: true,
	}
	destroyedDuringBackfill := testConntrackCon(t, "192.0.2.10", "198.51.100.20", 51000, 443, unix.IPPROTO_TCP)
	destroyedDuringBackfill.Info = &conntrack.InfoSource{NetlinkGroup: conntrack.NetlinkCtDestroy}
	createdDuringBackfill := testConntrackCon(t, "192.0.2.10", "198.51.100.20", 51001, 443, unix.IPPROTO_TCP)
	createdDuringBackfill.Info = &conntrack.InfoSource{NetlinkGroup: conntrack.NetlinkCtNew}

	idx.handleEvent(destroyedDuringBackfill)
	idx.handleEvent(createdDuringBackfill)
	if got := idx.EventCount(); got != 2 {
		t.Fatalf("EventCount before rebuild = %d, want 2", got)
	}

	// The snapshot still contains the destroyed entry. Replaying pending events
	// after installing the snapshot must remove it and retain the new entry.
	snapshot := []conntrack.Con{
		testConntrackCon(t, "192.0.2.10", "198.51.100.20", 51000, 443, unix.IPPROTO_TCP),
	}
	if got := idx.rebuild(snapshot); got != 1 {
		t.Fatalf("rebuild indexed %d snapshot origins, want 1", got)
	}

	key := mustFlowKey(t, "192.0.2.10", "198.51.100.20", 443, FlowProtoTCP)
	origins, ok := idx.originsForKey(key)
	if !ok {
		t.Fatal("originsForKey reported unhealthy index after rebuild")
	}
	if len(origins) != 1 {
		t.Fatalf("indexed origins after replay = %d, want 1", len(origins))
	}
	if origins[0].Proto == nil || origins[0].Proto.SrcPort == nil || *origins[0].Proto.SrcPort != 51001 {
		t.Fatalf("indexed origin source port = %+v, want only 51001", origins[0].Proto)
	}
}

func TestConntrackEventIndexPendingReplayOwnsCallbackTuple(t *testing.T) {
	mutateTuple := func(con conntrack.Con) {
		src := net.ParseIP("203.0.113.10")
		dst := net.ParseIP("203.0.113.20")
		*con.Origin.Src = src
		*con.Origin.Dst = dst
		*con.Origin.Proto.SrcPort = 62000
		*con.Origin.Proto.DstPort = 8443
	}

	t.Run("new", func(t *testing.T) {
		idx := &ctEventIndex{
			byQuery:     make(map[ctIndexQueryKey]map[ctOriginKey]struct{}),
			byOrigin:    make(map[ctOriginKey]struct{}),
			backfilling: true,
		}
		createdDuringBackfill := testConntrackCon(t, "192.0.2.10", "198.51.100.20", 51001, 443, unix.IPPROTO_TCP)
		createdDuringBackfill.Info = &conntrack.InfoSource{NetlinkGroup: conntrack.NetlinkCtNew}

		idx.handleEvent(createdDuringBackfill)
		mutateTuple(createdDuringBackfill)
		idx.rebuild(nil)

		originalKey := mustFlowKey(t, "192.0.2.10", "198.51.100.20", 443, FlowProtoTCP)
		origins, ok := idx.originsForKey(originalKey)
		if !ok {
			t.Fatal("originsForKey(originalKey) reported unhealthy index")
		}
		if len(origins) != 1 {
			t.Fatalf("originsForKey(originalKey) len = %d, want cloned pending origin", len(origins))
		}

		mutatedKey := mustFlowKey(t, "203.0.113.10", "203.0.113.20", 8443, FlowProtoTCP)
		origins, ok = idx.originsForKey(mutatedKey)
		if !ok {
			t.Fatal("originsForKey(mutatedKey) reported unhealthy index")
		}
		if len(origins) != 0 {
			t.Fatalf("originsForKey(mutatedKey) len = %d, want callback mutation ignored", len(origins))
		}
	})

	t.Run("destroy", func(t *testing.T) {
		idx := &ctEventIndex{
			byQuery:     make(map[ctIndexQueryKey]map[ctOriginKey]struct{}),
			byOrigin:    make(map[ctOriginKey]struct{}),
			backfilling: true,
		}
		destroyedDuringBackfill := testConntrackCon(t, "192.0.2.10", "198.51.100.20", 51000, 443, unix.IPPROTO_TCP)
		destroyedDuringBackfill.Info = &conntrack.InfoSource{NetlinkGroup: conntrack.NetlinkCtDestroy}

		idx.handleEvent(destroyedDuringBackfill)
		mutateTuple(destroyedDuringBackfill)
		idx.rebuild([]conntrack.Con{
			testConntrackCon(t, "192.0.2.10", "198.51.100.20", 51000, 443, unix.IPPROTO_TCP),
		})

		originalKey := mustFlowKey(t, "192.0.2.10", "198.51.100.20", 443, FlowProtoTCP)
		origins, ok := idx.originsForKey(originalKey)
		if !ok {
			t.Fatal("originsForKey(originalKey) reported unhealthy index")
		}
		if len(origins) != 0 {
			t.Fatalf("originsForKey(originalKey) len = %d, want cloned destroy to prune snapshot origin", len(origins))
		}
	})
}

func TestConntrackEventIndexBackfillDoesNotReviveErroredStream(t *testing.T) {
	idx := &ctEventIndex{
		byQuery:     make(map[ctIndexQueryKey]map[ctOriginKey]struct{}),
		byOrigin:    make(map[ctOriginKey]struct{}),
		backfilling: true,
	}
	idx.markUnhealthy(errors.New("event stream failed during backfill"))
	idx.rebuild([]conntrack.Con{
		testConntrackCon(t, "192.0.2.10", "198.51.100.20", 51000, 443, unix.IPPROTO_TCP),
	})

	key := mustFlowKey(t, "192.0.2.10", "198.51.100.20", 443, FlowProtoTCP)
	if _, ok := idx.originsForKey(key); ok {
		t.Fatal("originsForKey reported healthy index after an event stream error during backfill")
	}
	if got := idx.OriginCount(); got != 0 {
		t.Fatalf("OriginCount after errored backfill = %d, want reclaimed 0", got)
	}
}

func TestConntrackEventIndexConcurrentBackfillErrorLeavesUnhealthy(t *testing.T) {
	for i := 0; i < 200; i++ {
		idx := &ctEventIndex{
			byQuery:     make(map[ctIndexQueryKey]map[ctOriginKey]struct{}),
			byOrigin:    make(map[ctOriginKey]struct{}),
			backfilling: true,
		}
		snapshot := []conntrack.Con{
			testConntrackCon(t, "192.0.2.10", "198.51.100.20", 51000, 443, unix.IPPROTO_TCP),
		}
		start := make(chan struct{})
		done := make(chan struct{}, 2)
		go func() {
			<-start
			idx.rebuild(snapshot)
			done <- struct{}{}
		}()
		go func() {
			<-start
			idx.markUnhealthy(errors.New("event stream failed during backfill"))
			done <- struct{}{}
		}()
		close(start)
		<-done
		<-done
		if idx.ErrorCount() == 0 {
			t.Fatal("ErrorCount = 0, want concurrent event stream error recorded")
		}
		if idx.healthy.Load() {
			t.Fatal("healthy = true after concurrent rebuild/error race")
		}
	}
}

func TestConntrackEventIndexBackfillPendingOverflowDisablesIndex(t *testing.T) {
	idx := &ctEventIndex{
		byQuery:     make(map[ctIndexQueryKey]map[ctOriginKey]struct{}),
		byOrigin:    make(map[ctOriginKey]struct{}),
		backfilling: true,
		pending:     make([]ctPendingEvent, defaultConntrackEventPendingLimit),
	}
	overflow := testConntrackCon(t, "192.0.2.10", "198.51.100.20", 51000, 443, unix.IPPROTO_TCP)
	overflow.Info = &conntrack.InfoSource{NetlinkGroup: conntrack.NetlinkCtNew}

	idx.handleEvent(overflow)
	if got := idx.ErrorCount(); got != 1 {
		t.Fatalf("ErrorCount after pending overflow = %d, want 1", got)
	}
	if got := idx.PendingOverflowCount(); got != 1 {
		t.Fatalf("PendingOverflowCount after pending overflow = %d, want 1", got)
	}
	if got := idx.EventCount(); got != 0 {
		t.Fatalf("EventCount after pending overflow = %d, want overflow-triggering event not counted", got)
	}
	if got := len(idx.pending); got != 0 {
		t.Fatalf("pending len after pending overflow = %d, want 0", got)
	}
	idx.rebuild([]conntrack.Con{
		testConntrackCon(t, "192.0.2.10", "198.51.100.20", 51000, 443, unix.IPPROTO_TCP),
	})
	key := mustFlowKey(t, "192.0.2.10", "198.51.100.20", 443, FlowProtoTCP)
	if _, ok := idx.originsForKey(key); ok {
		t.Fatal("originsForKey reported healthy index after pending overflow")
	}
	if got := idx.OriginCount(); got != 0 {
		t.Fatalf("OriginCount after pending overflow rebuild = %d, want reclaimed 0", got)
	}
}

func TestRebuildEventIndexDoesNotServeSnapshotAfterBackfillOverflow(t *testing.T) {
	key := mustFlowKey(t, "192.0.2.10", "198.51.100.20", 443, FlowProtoTCP)
	idx := &ctEventIndex{
		byQuery:     make(map[ctIndexQueryKey]map[ctOriginKey]struct{}),
		byOrigin:    make(map[ctOriginKey]struct{}),
		backfilling: true,
		pending:     make([]ctPendingEvent, defaultConntrackEventPendingLimit),
	}
	overflow := testConntrackCon(t, "192.0.2.10", "198.51.100.20", 51000, 443, unix.IPPROTO_TCP)
	overflow.Info = &conntrack.InfoSource{NetlinkGroup: conntrack.NetlinkCtNew}
	idx.handleEvent(overflow)

	f := &ConntrackFlusher{
		backend: BackendNetlink,
		pool:    testCtNetlinkPool(&ctConn{}),
		ctOps: fakeCtNetlinkOps{
			dumpFn: func(_ context.Context, _ *ctConn, family conntrack.Family, _ time.Time, _ bool) ([]conntrack.Con, error) {
				if family == conntrack.IPv6 {
					return nil, nil
				}
				return []conntrack.Con{
					testConntrackCon(t, "192.0.2.10", "198.51.100.20", 51000, 443, unix.IPPROTO_TCP),
				}, nil
			},
		},
	}
	f.storeEventIndex(idx)

	indexed, err := f.rebuildEventIndex(context.Background(), idx, time.Now().Add(time.Second))
	if err != nil {
		t.Fatalf("rebuildEventIndex returned error: %v", err)
	}
	if indexed != 1 {
		t.Fatalf("rebuildEventIndex indexed origins = %d, want snapshot count 1", indexed)
	}
	if got := idx.OriginCount(); got != 0 {
		t.Fatalf("OriginCount after disabled rebuild = %d, want 0", got)
	}
	if _, ok := idx.originsForKey(key); ok {
		t.Fatal("originsForKey reported healthy index after backfill overflow")
	}
}

func TestConntrackEventIndexSkipsMapMutationAfterUnhealthy(t *testing.T) {
	idx := &ctEventIndex{
		byQuery:  make(map[ctIndexQueryKey]map[ctOriginKey]struct{}),
		byOrigin: make(map[ctOriginKey]struct{}),
	}
	idx.rebuild([]conntrack.Con{
		testConntrackCon(t, "192.0.2.10", "198.51.100.20", 51000, 443, unix.IPPROTO_TCP),
	})
	if got := idx.OriginCount(); got != 1 {
		t.Fatalf("OriginCount after rebuild = %d, want 1", got)
	}

	idx.markUnhealthy(errors.New("event stream failed"))
	idx.markUnhealthy(errors.New("another event stream failure"))
	if got := idx.ErrorCount(); got != 2 {
		t.Fatalf("ErrorCount after repeated stream errors = %d, want 2", got)
	}
	newAfterUnhealthy := testConntrackCon(t, "192.0.2.10", "198.51.100.20", 51001, 443, unix.IPPROTO_TCP)
	newAfterUnhealthy.Info = &conntrack.InfoSource{NetlinkGroup: conntrack.NetlinkCtNew}

	idx.mu.Lock()
	done := make(chan struct{})
	go func() {
		idx.handleEvent(newAfterUnhealthy)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		idx.mu.Unlock()
		t.Fatal("handleEvent blocked on idx.mu after the index was already disabled")
	}
	idx.mu.Unlock()

	if got := idx.OriginCount(); got != 0 {
		t.Fatalf("OriginCount after unhealthy event = %d, want reclaimed 0", got)
	}
	if got := idx.EventCount(); got != 1 {
		t.Fatalf("EventCount after unhealthy event = %d, want liveness counter to advance", got)
	}

	expectedGroupAfterUnhealthy := testConntrackCon(t, "192.0.2.10", "198.51.100.20", 51002, 443, unix.IPPROTO_TCP)
	expectedGroupAfterUnhealthy.Info = &conntrack.InfoSource{NetlinkGroup: conntrack.NetlinkCtExpectedNew}
	idx.handleEvent(expectedGroupAfterUnhealthy)
	malformedAfterUnhealthy := testConntrackCon(t, "192.0.2.10", "198.51.100.20", 51003, 443, unix.IPPROTO_TCP)
	idx.handleEvent(malformedAfterUnhealthy)

	if got := idx.EventCount(); got != 1 {
		t.Fatalf("EventCount after invalid unhealthy callbacks = %d, want only valid groups counted", got)
	}
	if got := idx.ErrorCount(); got != 4 {
		t.Fatalf("ErrorCount after invalid unhealthy callbacks = %d, want 4", got)
	}
}

func TestConntrackEventIndexUpdateForExistingOriginKeepsCount(t *testing.T) {
	idx := &ctEventIndex{
		byQuery:  make(map[ctIndexQueryKey]map[ctOriginKey]struct{}),
		byOrigin: make(map[ctOriginKey]struct{}),
	}
	con := testConntrackCon(t, "192.0.2.10", "198.51.100.20", 51000, 443, unix.IPPROTO_TCP)
	idx.rebuild([]conntrack.Con{con})
	key, ok := originKeyFromIPTuple(con.Origin)
	if !ok {
		t.Fatal("originKeyFromIPTuple returned false")
	}

	con.Info = &conntrack.InfoSource{NetlinkGroup: conntrack.NetlinkCtUpdate}
	idx.handleEvent(con)

	if got := idx.OriginCount(); got != 1 {
		t.Fatalf("OriginCount after duplicate UPDATE = %d, want 1", got)
	}
	if _, ok := idx.byOrigin[key]; !ok {
		t.Fatal("duplicate UPDATE dropped indexed origin")
	}
	if got := idx.EventCount(); got != 1 {
		t.Fatalf("EventCount after duplicate UPDATE = %d, want 1", got)
	}
}

func TestConntrackEventIndexOriginCountTracksMutations(t *testing.T) {
	idx := &ctEventIndex{
		byQuery:  make(map[ctIndexQueryKey]map[ctOriginKey]struct{}),
		byOrigin: make(map[ctOriginKey]struct{}),
	}
	assertCount := func(want int) {
		t.Helper()
		if got := len(idx.byOrigin); got != want {
			t.Fatalf("len(byOrigin) = %d, want %d", got, want)
		}
		if got := idx.OriginCount(); got != uint64(want) {
			t.Fatalf("OriginCount = %d, want %d", got, want)
		}
	}

	first := testConntrackCon(t, "192.0.2.10", "198.51.100.20", 51000, 443, unix.IPPROTO_TCP)
	second := testConntrackCon(t, "192.0.2.10", "198.51.100.20", 51001, 443, unix.IPPROTO_TCP)
	idx.rebuild([]conntrack.Con{first, second})
	assertCount(2)

	first.Info = &conntrack.InfoSource{NetlinkGroup: conntrack.NetlinkCtUpdate}
	idx.handleEvent(first)
	assertCount(2)

	third := testConntrackCon(t, "192.0.2.10", "198.51.100.20", 51002, 443, unix.IPPROTO_TCP)
	third.Info = &conntrack.InfoSource{NetlinkGroup: conntrack.NetlinkCtNew}
	idx.handleEvent(third)
	assertCount(3)

	second.Info = &conntrack.InfoSource{NetlinkGroup: conntrack.NetlinkCtDestroy}
	idx.handleEvent(second)
	assertCount(2)

	idx.removeOrigins([]*conntrack.IPTuple{first.Origin})
	assertCount(1)

	idx.markUnhealthy(errors.New("event stream failed"))
	assertCount(0)
}

func TestConntrackEventIndexWatchErrorsStopsOnCancel(t *testing.T) {
	idx := &ctEventIndex{}
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error)
	done := make(chan struct{})
	go func() {
		idx.watchErrors(ctx, errCh)
		close(done)
	}()

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("watchErrors did not exit after context cancellation")
	}
}

func TestFlushNetlinkIndexedUsesIndexWithoutDump(t *testing.T) {
	key := mustFlowKey(t, "192.0.2.10", "198.51.100.20", 443, FlowProtoTCP)
	idx := &ctEventIndex{
		byQuery:  make(map[ctIndexQueryKey]map[ctOriginKey]struct{}),
		byOrigin: make(map[ctOriginKey]struct{}),
	}
	idx.rebuild([]conntrack.Con{
		testConntrackCon(t, "192.0.2.10", "198.51.100.20", 51000, 443, unix.IPPROTO_TCP),
	})

	var dumpCalls atomic.Int32
	var deleteSrcPorts []uint16
	f := &ConntrackFlusher{
		backend: BackendNetlink,
		pool:    testCtNetlinkPool(&ctConn{}),
		ctOps: fakeCtNetlinkOps{
			dumpFn: func(_ context.Context, _ *ctConn, _ conntrack.Family, _ time.Time, _ bool) ([]conntrack.Con, error) {
				dumpCalls.Add(1)
				return nil, errors.New("indexed Flush must not dump")
			},
			deleteFn: func(_ context.Context, _ *ctConn, family conntrack.Family, origin *conntrack.IPTuple, _ time.Time) error {
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
	f.storeEventIndex(idx)

	if err := f.Flush(context.Background(), key); err != nil {
		t.Fatalf("Flush returned error: %v", err)
	}
	if got := dumpCalls.Load(); got != 0 {
		t.Fatalf("dump calls = %d, want 0 on indexed fast path", got)
	}
	if got, want := fmt.Sprint(deleteSrcPorts), "[51000]"; got != want {
		t.Fatalf("deleted source ports = %s, want %s", got, want)
	}
	if got := f.NetlinkIndexedFlushCount(); got != 1 {
		t.Fatalf("NetlinkIndexedFlushCount = %d, want 1", got)
	}
	if got := f.NetlinkIndexFallbackDumpCount(); got != 0 {
		t.Fatalf("NetlinkIndexFallbackDumpCount = %d, want 0", got)
	}
	if got := f.NetlinkDeletedCount(); got != 1 {
		t.Fatalf("NetlinkDeletedCount = %d, want 1", got)
	}
	origins, ok := idx.originsForKey(key)
	if !ok {
		t.Fatal("event index became unhealthy after indexed delete")
	}
	if len(origins) != 0 {
		t.Fatalf("indexed origins after delete = %d, want 0", len(origins))
	}
}

func TestFlushNetlinkAuthoritativeContextBypassesHealthyIndex(t *testing.T) {
	key := mustFlowKey(t, "192.0.2.10", "198.51.100.20", 443, FlowProtoTCP)
	idx := &ctEventIndex{
		byQuery:  make(map[ctIndexQueryKey]map[ctOriginKey]struct{}),
		byOrigin: make(map[ctOriginKey]struct{}),
	}
	idx.rebuild([]conntrack.Con{
		testConntrackCon(t, "192.0.2.10", "198.51.100.20", 51000, 443, unix.IPPROTO_TCP),
	})

	var dumpCalls atomic.Int32
	var deleteSrcPorts []uint16
	f := &ConntrackFlusher{
		backend: BackendNetlink,
		pool:    testCtNetlinkPool(&ctConn{}),
		ctOps: fakeCtNetlinkOps{
			dumpFn: func(_ context.Context, _ *ctConn, family conntrack.Family, _ time.Time, _ bool) ([]conntrack.Con, error) {
				dumpCalls.Add(1)
				if family != conntrack.IPv4 {
					t.Fatalf("dump family = %v, want IPv4", family)
				}
				return []conntrack.Con{
					testConntrackCon(t, "192.0.2.10", "198.51.100.20", 51000, 443, unix.IPPROTO_TCP),
					testConntrackCon(t, "192.0.2.10", "198.51.100.20", 51001, 443, unix.IPPROTO_TCP),
				}, nil
			},
			deleteFn: func(_ context.Context, _ *ctConn, family conntrack.Family, origin *conntrack.IPTuple, _ time.Time) error {
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
	f.storeEventIndex(idx)

	if err := f.Flush(withAuthoritativeFlush(context.Background()), key); err != nil {
		t.Fatalf("Flush returned error: %v", err)
	}
	if got := dumpCalls.Load(); got != 1 {
		t.Fatalf("dump calls = %d, want 1 authoritative dump", got)
	}
	if got, want := fmt.Sprint(deleteSrcPorts), "[51000 51001]"; got != want {
		t.Fatalf("deleted source ports = %s, want %s", got, want)
	}
	if got := f.NetlinkIndexedFlushCount(); got != 0 {
		t.Fatalf("NetlinkIndexedFlushCount = %d, want 0", got)
	}
	if got := f.NetlinkIndexFallbackDumpCount(); got != 0 {
		t.Fatalf("NetlinkIndexFallbackDumpCount = %d, want 0 for intentional authoritative dump", got)
	}
	if got := f.NetlinkIndexAuthoritativeDumpCount(); got != 1 {
		t.Fatalf("NetlinkIndexAuthoritativeDumpCount = %d, want 1", got)
	}
	if got := f.NetlinkDeletedCount(); got != 2 {
		t.Fatalf("NetlinkDeletedCount = %d, want 2", got)
	}
}

func TestFlushNetlinkFallsBackToDumpWhenIndexUnhealthy(t *testing.T) {
	key := mustFlowKey(t, "192.0.2.10", "198.51.100.20", 443, FlowProtoTCP)
	idx := &ctEventIndex{
		byQuery:  make(map[ctIndexQueryKey]map[ctOriginKey]struct{}),
		byOrigin: make(map[ctOriginKey]struct{}),
	}
	idx.rebuild(nil)
	idx.markUnhealthy(errors.New("event stream lost"))

	dumpCalls := 0
	deleteCalls := 0
	f := &ConntrackFlusher{
		backend: BackendNetlink,
		pool:    testCtNetlinkPool(&ctConn{}),
		ctOps: fakeCtNetlinkOps{
			dumpFn: func(_ context.Context, _ *ctConn, family conntrack.Family, _ time.Time, _ bool) ([]conntrack.Con, error) {
				dumpCalls++
				if family != conntrack.IPv4 {
					t.Fatalf("dump family = %v, want IPv4", family)
				}
				return []conntrack.Con{
					testConntrackCon(t, "192.0.2.10", "198.51.100.20", 51000, 443, unix.IPPROTO_TCP),
				}, nil
			},
			deleteFn: func(_ context.Context, _ *ctConn, _ conntrack.Family, _ *conntrack.IPTuple, _ time.Time) error {
				deleteCalls++
				return nil
			},
		},
	}
	f.storeEventIndex(idx)

	if err := f.Flush(context.Background(), key); err != nil {
		t.Fatalf("Flush returned error: %v", err)
	}
	if dumpCalls != 1 {
		t.Fatalf("dump calls = %d, want 1 fallback dump", dumpCalls)
	}
	if deleteCalls != 1 {
		t.Fatalf("delete calls = %d, want 1", deleteCalls)
	}
	if got := f.NetlinkIndexedFlushCount(); got != 0 {
		t.Fatalf("NetlinkIndexedFlushCount = %d, want 0", got)
	}
	if got := f.NetlinkIndexFallbackDumpCount(); got != 1 {
		t.Fatalf("NetlinkIndexFallbackDumpCount = %d, want 1", got)
	}
	if got := f.NetlinkIndexAuthoritativeDumpCount(); got != 0 {
		t.Fatalf("NetlinkIndexAuthoritativeDumpCount = %d, want 0", got)
	}
	if got := f.NetlinkIndexEventErrorCount(); got != 1 {
		t.Fatalf("NetlinkIndexEventErrorCount = %d, want 1", got)
	}
}

func TestConntrackEventIndexResyncRestoresIndexedFlush(t *testing.T) {
	key := mustFlowKey(t, "192.0.2.10", "198.51.100.20", 443, FlowProtoTCP)
	oldIdx := &ctEventIndex{
		byQuery:  make(map[ctIndexQueryKey]map[ctOriginKey]struct{}),
		byOrigin: make(map[ctOriginKey]struct{}),
	}
	oldIdx.rebuild([]conntrack.Con{
		testConntrackCon(t, "192.0.2.10", "198.51.100.20", 51999, 443, unix.IPPROTO_TCP),
	})
	oldIdx.markUnhealthy(unix.ENOBUFS)

	var candidate *ctEventIndex
	var dumpCalls atomic.Int32
	var deleteSrcPorts []uint16
	injectedPendingEvent := false
	f := &ConntrackFlusher{
		backend: BackendNetlink,
		pool:    testCtNetlinkPool(&ctConn{}),
		newEventIndex: func() (*ctEventIndex, error) {
			candidate = &ctEventIndex{
				byQuery:     make(map[ctIndexQueryKey]map[ctOriginKey]struct{}),
				byOrigin:    make(map[ctOriginKey]struct{}),
				backfilling: true,
			}
			return candidate, nil
		},
		ctOps: fakeCtNetlinkOps{
			dumpFn: func(_ context.Context, _ *ctConn, family conntrack.Family, _ time.Time, _ bool) ([]conntrack.Con, error) {
				dumpCalls.Add(1)
				switch family {
				case conntrack.IPv4:
					if !injectedPendingEvent {
						injectedPendingEvent = true
						createdDuringResync := testConntrackCon(t, "192.0.2.10", "198.51.100.20", 51001, 443, unix.IPPROTO_TCP)
						createdDuringResync.Info = &conntrack.InfoSource{NetlinkGroup: conntrack.NetlinkCtNew}
						candidate.handleEvent(createdDuringResync)
					}
					return []conntrack.Con{
						testConntrackCon(t, "192.0.2.10", "198.51.100.20", 51000, 443, unix.IPPROTO_TCP),
					}, nil
				case conntrack.IPv6:
					return nil, nil
				default:
					t.Fatalf("unexpected dump family %v", family)
					return nil, nil
				}
			},
			deleteFn: func(_ context.Context, _ *ctConn, family conntrack.Family, origin *conntrack.IPTuple, _ time.Time) error {
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
	f.storeEventIndex(oldIdx)

	indexed, err := f.resyncEventIndex(context.Background(), time.Now().Add(time.Second))
	if err != nil {
		t.Fatalf("resyncEventIndex returned error: %v", err)
	}
	if indexed != 1 {
		t.Fatalf("resync indexed snapshot origins = %d, want 1", indexed)
	}
	if got := f.NetlinkIndexOriginCount(); got != 2 {
		t.Fatalf("NetlinkIndexOriginCount after resync = %d, want 2 (snapshot + buffered NEW)", got)
	}
	if got := f.NetlinkIndexEventErrorCount(); got != 1 {
		t.Fatalf("NetlinkIndexEventErrorCount after resync = %d, want archived overrun 1", got)
	}
	if got := f.NetlinkIndexEventCount(); got != 1 {
		t.Fatalf("NetlinkIndexEventCount after resync = %d, want buffered event 1", got)
	}
	if got := f.NetlinkIndexResyncAttemptCount(); got != 1 {
		t.Fatalf("NetlinkIndexResyncAttemptCount = %d, want 1", got)
	}
	if got := f.NetlinkIndexResyncSuccessCount(); got != 1 {
		t.Fatalf("NetlinkIndexResyncSuccessCount = %d, want 1", got)
	}
	if got := f.NetlinkIndexResyncFailureCount(); got != 0 {
		t.Fatalf("NetlinkIndexResyncFailureCount = %d, want 0", got)
	}

	if err := f.Flush(context.Background(), key); err != nil {
		t.Fatalf("Flush after resync returned error: %v", err)
	}
	if got := dumpCalls.Load(); got != 2 {
		t.Fatalf("dump calls after indexed Flush = %d, want only the two resync backfill dumps", got)
	}
	sort.Slice(deleteSrcPorts, func(i, j int) bool { return deleteSrcPorts[i] < deleteSrcPorts[j] })
	if got, want := fmt.Sprint(deleteSrcPorts), "[51000 51001]"; got != want {
		t.Fatalf("deleted source ports after resync = %s, want %s", got, want)
	}
	if got := f.NetlinkIndexedFlushCount(); got != 1 {
		t.Fatalf("NetlinkIndexedFlushCount after resync Flush = %d, want 1", got)
	}
	if got := f.NetlinkIndexFallbackDumpCount(); got != 0 {
		t.Fatalf("NetlinkIndexFallbackDumpCount after resync Flush = %d, want 0", got)
	}
}

func TestConntrackEventIndexResyncFailureLeavesFallbackVisible(t *testing.T) {
	key := mustFlowKey(t, "192.0.2.10", "198.51.100.20", 443, FlowProtoTCP)
	oldIdx := &ctEventIndex{
		byQuery:  make(map[ctIndexQueryKey]map[ctOriginKey]struct{}),
		byOrigin: make(map[ctOriginKey]struct{}),
	}
	oldIdx.rebuild(nil)
	oldIdx.markUnhealthy(unix.ENOBUFS)
	boom := errors.New("backfill failed")
	f := &ConntrackFlusher{
		backend: BackendNetlink,
		pool:    testCtNetlinkPool(&ctConn{}),
		newEventIndex: func() (*ctEventIndex, error) {
			return &ctEventIndex{
				byQuery:     make(map[ctIndexQueryKey]map[ctOriginKey]struct{}),
				byOrigin:    make(map[ctOriginKey]struct{}),
				backfilling: true,
			}, nil
		},
		ctOps: fakeCtNetlinkOps{
			dumpFn: func(_ context.Context, _ *ctConn, _ conntrack.Family, _ time.Time, _ bool) ([]conntrack.Con, error) {
				return nil, boom
			},
		},
	}
	f.storeEventIndex(oldIdx)

	if _, err := f.resyncEventIndex(context.Background(), time.Now().Add(time.Second)); !errors.Is(err, boom) {
		t.Fatalf("resyncEventIndex error = %v, want errors.Is(..., boom)", err)
	}
	if got := f.NetlinkIndexResyncAttemptCount(); got != 1 {
		t.Fatalf("NetlinkIndexResyncAttemptCount = %d, want 1", got)
	}
	if got := f.NetlinkIndexResyncSuccessCount(); got != 0 {
		t.Fatalf("NetlinkIndexResyncSuccessCount = %d, want 0", got)
	}
	if got := f.NetlinkIndexResyncFailureCount(); got != 1 {
		t.Fatalf("NetlinkIndexResyncFailureCount = %d, want 1", got)
	}

	dumpCalls := 0
	deleteCalls := 0
	f.newEventIndex = nil // keep this assertion synchronous; production resync is callback-driven.
	f.ctOps = fakeCtNetlinkOps{
		dumpFn: func(_ context.Context, _ *ctConn, family conntrack.Family, _ time.Time, _ bool) ([]conntrack.Con, error) {
			dumpCalls++
			if family != conntrack.IPv4 {
				t.Fatalf("dump family = %v, want IPv4", family)
			}
			return []conntrack.Con{
				testConntrackCon(t, "192.0.2.10", "198.51.100.20", 51000, 443, unix.IPPROTO_TCP),
			}, nil
		},
		deleteFn: func(_ context.Context, _ *ctConn, _ conntrack.Family, _ *conntrack.IPTuple, _ time.Time) error {
			deleteCalls++
			return nil
		},
	}

	if err := f.Flush(context.Background(), key); err != nil {
		t.Fatalf("Flush after failed resync returned error: %v", err)
	}
	if dumpCalls != 1 {
		t.Fatalf("dump calls after failed resync Flush = %d, want fallback dump 1", dumpCalls)
	}
	if deleteCalls != 1 {
		t.Fatalf("delete calls after failed resync Flush = %d, want 1", deleteCalls)
	}
	if got := f.NetlinkIndexFallbackDumpCount(); got != 1 {
		t.Fatalf("NetlinkIndexFallbackDumpCount after failed resync Flush = %d, want 1", got)
	}
	if got := f.NetlinkIndexedFlushCount(); got != 0 {
		t.Fatalf("NetlinkIndexedFlushCount after failed resync Flush = %d, want 0", got)
	}
}

func TestConntrackEventIndexResyncUnhealthyDuringBackfillCountsFailure(t *testing.T) {
	var candidate *ctEventIndex
	f := &ConntrackFlusher{
		backend: BackendNetlink,
		pool:    testCtNetlinkPool(&ctConn{}),
		newEventIndex: func() (*ctEventIndex, error) {
			candidate = &ctEventIndex{
				byQuery:     make(map[ctIndexQueryKey]map[ctOriginKey]struct{}),
				byOrigin:    make(map[ctOriginKey]struct{}),
				backfilling: true,
			}
			return candidate, nil
		},
		ctOps: fakeCtNetlinkOps{
			dumpFn: func(_ context.Context, _ *ctConn, family conntrack.Family, _ time.Time, _ bool) ([]conntrack.Con, error) {
				if family == conntrack.IPv4 {
					candidate.markUnhealthy(unix.ENOBUFS)
					return []conntrack.Con{
						testConntrackCon(t, "192.0.2.10", "198.51.100.20", 51000, 443, unix.IPPROTO_TCP),
					}, nil
				}
				return nil, nil
			},
		},
	}

	_, err := f.resyncEventIndex(context.Background(), time.Now().Add(time.Second))
	if err == nil || !strings.Contains(err.Error(), "became unhealthy during backfill") {
		t.Fatalf("resyncEventIndex error = %v, want unhealthy-during-backfill failure", err)
	}
	if got := f.NetlinkIndexResyncAttemptCount(); got != 1 {
		t.Fatalf("NetlinkIndexResyncAttemptCount = %d, want 1", got)
	}
	if got := f.NetlinkIndexResyncSuccessCount(); got != 0 {
		t.Fatalf("NetlinkIndexResyncSuccessCount = %d, want 0", got)
	}
	if got := f.NetlinkIndexResyncFailureCount(); got != 1 {
		t.Fatalf("NetlinkIndexResyncFailureCount = %d, want 1", got)
	}
	if got := f.NetlinkIndexEventErrorCount(); got != 1 {
		t.Fatalf("NetlinkIndexEventErrorCount = %d, want archived candidate error", got)
	}
	if got := f.NetlinkIndexOriginCount(); got != 0 {
		t.Fatalf("NetlinkIndexOriginCount = %d, want discarded unhealthy candidate", got)
	}
}

func TestConntrackEventIndexResyncBackoffRemaining(t *testing.T) {
	now := time.Unix(123, 456)
	f := &ConntrackFlusher{}
	if got := f.eventIndexResyncBackoffRemaining(now); got != 0 {
		t.Fatalf("backoff with no prior resync = %s, want 0", got)
	}

	f.netlinkIndexLastResyncNanos.Store(now.Add(-defaultNetlinkIndexResyncMinInterval / 2).UnixNano())
	if got, want := f.eventIndexResyncBackoffRemaining(now), defaultNetlinkIndexResyncMinInterval/2; got != want {
		t.Fatalf("backoff halfway through interval = %s, want %s", got, want)
	}

	f.netlinkIndexLastResyncNanos.Store(now.Add(-defaultNetlinkIndexResyncMinInterval).UnixNano())
	if got := f.eventIndexResyncBackoffRemaining(now); got != 0 {
		t.Fatalf("backoff after interval elapsed = %s, want 0", got)
	}
}

func TestConntrackEventIndexScheduleResyncHonorsBackoff(t *testing.T) {
	var opened atomic.Int32
	f := &ConntrackFlusher{
		backend: BackendNetlink,
		pool:    testCtNetlinkPool(&ctConn{}),
		newEventIndex: func() (*ctEventIndex, error) {
			opened.Add(1)
			return &ctEventIndex{
				byQuery:     make(map[ctIndexQueryKey]map[ctOriginKey]struct{}),
				byOrigin:    make(map[ctOriginKey]struct{}),
				backfilling: true,
			}, nil
		},
		ctOps: fakeCtNetlinkOps{
			dumpFn: func(_ context.Context, _ *ctConn, _ conntrack.Family, _ time.Time, _ bool) ([]conntrack.Con, error) {
				return nil, nil
			},
		},
	}
	f.netlinkIndexLastResyncNanos.Store(time.Now().UnixNano())

	f.scheduleEventIndexResync("flush fallback", errCtEventIndexUnavailable)
	time.Sleep(50 * time.Millisecond)

	if got := opened.Load(); got != 0 {
		t.Fatalf("newEventIndex calls during backoff = %d, want 0", got)
	}
	if got := f.NetlinkIndexResyncAttemptCount(); got != 0 {
		t.Fatalf("NetlinkIndexResyncAttemptCount during backoff = %d, want 0", got)
	}
	if f.netlinkIndexResyncInFlight.Load() {
		t.Fatal("resyncInFlight set during backoff")
	}
}

func TestConntrackEventIndexFallbackFlushSchedulesResync(t *testing.T) {
	key := mustFlowKey(t, "192.0.2.10", "198.51.100.20", 443, FlowProtoTCP)
	matchingCon := testConntrackCon(t, "192.0.2.10", "198.51.100.20", 51000, 443, unix.IPPROTO_TCP)
	idx := &ctEventIndex{
		byQuery:  make(map[ctIndexQueryKey]map[ctOriginKey]struct{}),
		byOrigin: make(map[ctOriginKey]struct{}),
	}
	idx.rebuild(nil)
	idx.markUnhealthy(unix.ENOBUFS)

	var dumpCalls atomic.Int32
	var deleteCalls atomic.Int32
	f := &ConntrackFlusher{
		backend: BackendNetlink,
		pool:    testCtNetlinkPool(&ctConn{}, &ctConn{}),
		newEventIndex: func() (*ctEventIndex, error) {
			return &ctEventIndex{
				byQuery:     make(map[ctIndexQueryKey]map[ctOriginKey]struct{}),
				byOrigin:    make(map[ctOriginKey]struct{}),
				backfilling: true,
			}, nil
		},
		ctOps: fakeCtNetlinkOps{
			dumpFn: func(_ context.Context, _ *ctConn, family conntrack.Family, _ time.Time, _ bool) ([]conntrack.Con, error) {
				dumpCalls.Add(1)
				if family == conntrack.IPv4 {
					return []conntrack.Con{matchingCon}, nil
				}
				return nil, nil
			},
			deleteFn: func(_ context.Context, _ *ctConn, _ conntrack.Family, _ *conntrack.IPTuple, _ time.Time) error {
				deleteCalls.Add(1)
				return nil
			},
		},
	}
	f.storeEventIndex(idx)

	if err := f.Flush(context.Background(), key); err != nil {
		t.Fatalf("Flush returned error: %v", err)
	}
	if got := f.NetlinkIndexFallbackDumpCount(); got != 1 {
		t.Fatalf("NetlinkIndexFallbackDumpCount = %d, want 1", got)
	}
	if got := deleteCalls.Load(); got != 1 {
		t.Fatalf("delete calls = %d, want 1 fallback delete", got)
	}

	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	timeout := time.After(time.Second)
	for f.NetlinkIndexResyncSuccessCount() == 0 {
		select {
		case <-ticker.C:
		case <-timeout:
			t.Fatalf("fallback Flush did not schedule a successful resync; attempts=%d failures=%d dumpCalls=%d", f.NetlinkIndexResyncAttemptCount(), f.NetlinkIndexResyncFailureCount(), dumpCalls.Load())
		}
	}
	if got := f.NetlinkIndexResyncAttemptCount(); got != 1 {
		t.Fatalf("NetlinkIndexResyncAttemptCount = %d, want 1", got)
	}
	if got := f.NetlinkIndexResyncFailureCount(); got != 0 {
		t.Fatalf("NetlinkIndexResyncFailureCount = %d, want 0", got)
	}
	if got := f.currentEventIndex(); got == nil || got == idx {
		t.Fatalf("currentEventIndex after fallback-triggered resync = %p, want fresh generation", got)
	}
}

func TestFlushNetlinkHealthyEmptyIndexDoesNotScheduleResync(t *testing.T) {
	key := mustFlowKey(t, "192.0.2.10", "198.51.100.20", 443, FlowProtoTCP)
	idx := &ctEventIndex{
		byQuery:  make(map[ctIndexQueryKey]map[ctOriginKey]struct{}),
		byOrigin: make(map[ctOriginKey]struct{}),
	}
	idx.rebuild(nil)

	var dumpCalls atomic.Int32
	resyncStarted := make(chan struct{})
	resyncRelease := make(chan struct{})
	var releaseOnce sync.Once
	releaseResync := func() { releaseOnce.Do(func() { close(resyncRelease) }) }
	defer releaseResync()

	f := &ConntrackFlusher{
		backend: BackendNetlink,
		pool:    testCtNetlinkPool(&ctConn{}),
		newEventIndex: func() (*ctEventIndex, error) {
			close(resyncStarted)
			<-resyncRelease
			return &ctEventIndex{
				byQuery:     make(map[ctIndexQueryKey]map[ctOriginKey]struct{}),
				byOrigin:    make(map[ctOriginKey]struct{}),
				backfilling: true,
			}, nil
		},
		ctOps: fakeCtNetlinkOps{
			dumpFn: func(_ context.Context, _ *ctConn, _ conntrack.Family, _ time.Time, _ bool) ([]conntrack.Con, error) {
				dumpCalls.Add(1)
				return nil, nil
			},
		},
	}
	f.storeEventIndex(idx)

	if err := f.Flush(context.Background(), key); err != nil {
		t.Fatalf("Flush returned error: %v", err)
	}
	if got := f.NetlinkIndexedFlushCount(); got != 1 {
		t.Fatalf("NetlinkIndexedFlushCount = %d, want healthy empty indexed Flush", got)
	}
	if got := f.NetlinkIndexFallbackDumpCount(); got != 0 {
		t.Fatalf("NetlinkIndexFallbackDumpCount = %d, want 0", got)
	}
	if got := dumpCalls.Load(); got != 0 {
		t.Fatalf("dump calls = %d, want 0 for healthy empty index", got)
	}

	select {
	case <-resyncStarted:
		releaseResync()
		t.Fatal("healthy empty index scheduled resync")
	case <-time.After(50 * time.Millisecond):
	}
	if got := f.NetlinkIndexResyncAttemptCount(); got != 0 {
		t.Fatalf("NetlinkIndexResyncAttemptCount = %d, want 0", got)
	}
	if f.netlinkIndexResyncInFlight.Load() {
		t.Fatal("resyncInFlight set for healthy empty index")
	}
}

func TestConntrackEventIndexResyncClosedFlusherRejected(t *testing.T) {
	f := &ConntrackFlusher{backend: BackendNetlink}
	f.closed.Store(true)
	if _, err := f.resyncEventIndex(context.Background(), time.Now().Add(time.Second)); !errors.Is(err, errCtNetlinkPoolClosed) {
		t.Fatalf("resyncEventIndex on closed flusher = %v, want %v", err, errCtNetlinkPoolClosed)
	}
	if got := f.NetlinkIndexResyncAttemptCount(); got != 0 {
		t.Fatalf("NetlinkIndexResyncAttemptCount on closed flusher = %d, want 0", got)
	}
}

func TestConntrackEventIndexUnhealthyCallbackSchedulesResync(t *testing.T) {
	oldIdx := &ctEventIndex{
		byQuery:     make(map[ctIndexQueryKey]map[ctOriginKey]struct{}),
		byOrigin:    make(map[ctOriginKey]struct{}),
		backfilling: true,
	}
	oldIdx.rebuild(nil)
	var dumpCalls atomic.Int32
	f := &ConntrackFlusher{
		backend: BackendNetlink,
		pool:    testCtNetlinkPool(&ctConn{}),
		newEventIndex: func() (*ctEventIndex, error) {
			return &ctEventIndex{
				byQuery:     make(map[ctIndexQueryKey]map[ctOriginKey]struct{}),
				byOrigin:    make(map[ctOriginKey]struct{}),
				backfilling: true,
			}, nil
		},
		ctOps: fakeCtNetlinkOps{
			dumpFn: func(_ context.Context, _ *ctConn, _ conntrack.Family, _ time.Time, _ bool) ([]conntrack.Con, error) {
				dumpCalls.Add(1)
				return nil, nil
			},
		},
	}
	if healthy := f.installStartupEventIndex(oldIdx); !healthy {
		t.Fatal("installStartupEventIndex reported unhealthy for clean index")
	}

	oldIdx.markUnhealthy(unix.ENOBUFS)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	timeout := time.After(time.Second)
	for f.NetlinkIndexResyncSuccessCount() == 0 {
		select {
		case <-ticker.C:
		case <-timeout:
			t.Fatal("unhealthy callback did not schedule a successful resync")
		}
	}
	if got := f.NetlinkIndexResyncAttemptCount(); got != 1 {
		t.Fatalf("NetlinkIndexResyncAttemptCount = %d, want 1", got)
	}
	if got := f.NetlinkIndexResyncFailureCount(); got != 0 {
		t.Fatalf("NetlinkIndexResyncFailureCount = %d, want 0", got)
	}
	if got := dumpCalls.Load(); got != 2 {
		t.Fatalf("resync dump calls = %d, want IPv4+IPv6 backfill", got)
	}
	if got := f.currentEventIndex(); got == nil || got == oldIdx {
		t.Fatalf("currentEventIndex after callback resync = %p, want fresh generation", got)
	}
	if got := f.NetlinkIndexEventErrorCount(); got != 1 {
		t.Fatalf("NetlinkIndexEventErrorCount = %d, want archived callback trigger", got)
	}
}

func TestConntrackStartupUnhealthyIndexFallsBackInsteadOfFailing(t *testing.T) {
	key := mustFlowKey(t, "192.0.2.10", "198.51.100.20", 443, FlowProtoTCP)
	idx := &ctEventIndex{
		byQuery:     make(map[ctIndexQueryKey]map[ctOriginKey]struct{}),
		byOrigin:    make(map[ctOriginKey]struct{}),
		backfilling: true,
	}
	idx.markUnhealthy(unix.ENOBUFS)
	if indexed := idx.rebuild([]conntrack.Con{
		testConntrackCon(t, "192.0.2.10", "198.51.100.20", 51000, 443, unix.IPPROTO_TCP),
	}); indexed != 1 {
		t.Fatalf("startup rebuild indexed = %d, want 1 before unhealthy reclaim", indexed)
	}

	f := &ConntrackFlusher{backend: BackendNetlink}
	if healthy := f.installStartupEventIndex(idx); healthy {
		t.Fatal("installStartupEventIndex reported healthy, want fallback startup")
	}
	if got := f.currentEventIndex(); got != idx {
		t.Fatalf("currentEventIndex = %p, want startup index %p", got, idx)
	}
	if got := f.NetlinkIndexEventErrorCount(); got != 1 {
		t.Fatalf("NetlinkIndexEventErrorCount = %d, want startup event error visible", got)
	}
	if got := f.NetlinkIndexOriginCount(); got != 0 {
		t.Fatalf("NetlinkIndexOriginCount = %d, want reclaimed unhealthy startup mirror", got)
	}
	if _, ok := idx.originsForKey(key); ok {
		t.Fatal("unhealthy startup index served indexed origins; want fallback path")
	}
}

func TestConntrackEventIndexCloseCancelsInFlightResync(t *testing.T) {
	dumpStarted := make(chan struct{})
	resyncDone := make(chan error, 1)
	closeDone := make(chan error, 1)
	var dumpCalls atomic.Int32

	f := &ConntrackFlusher{
		backend: BackendNetlink,
		pool:    testCtNetlinkPool(&ctConn{}),
		newEventIndex: func() (*ctEventIndex, error) {
			return &ctEventIndex{
				byQuery:     make(map[ctIndexQueryKey]map[ctOriginKey]struct{}),
				byOrigin:    make(map[ctOriginKey]struct{}),
				backfilling: true,
			}, nil
		},
		ctOps: fakeCtNetlinkOps{
			dumpFn: func(ctx context.Context, _ *ctConn, _ conntrack.Family, _ time.Time, _ bool) ([]conntrack.Con, error) {
				if dumpCalls.Add(1) == 1 {
					close(dumpStarted)
					<-ctx.Done()
					return nil, ctx.Err()
				}
				return nil, nil
			},
		},
	}

	go func() {
		_, err := f.resyncEventIndex(context.Background(), time.Now().Add(time.Second))
		resyncDone <- err
	}()
	select {
	case <-dumpStarted:
	case <-time.After(time.Second):
		t.Fatal("resync did not reach backfill dump")
	}

	go func() {
		closeDone <- f.Close()
	}()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("Close returned error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not cancel in-flight resync")
	}
	select {
	case err := <-resyncDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("resyncEventIndex during Close = %v, want %v", err, context.Canceled)
		}
	case <-time.After(time.Second):
		t.Fatal("resync did not finish after Close cancellation")
	}
	if got := f.currentEventIndex(); got != nil {
		t.Fatalf("currentEventIndex after Close = %p, want nil", got)
	}
	if got := f.NetlinkIndexResyncAttemptCount(); got != 1 {
		t.Fatalf("NetlinkIndexResyncAttemptCount = %d, want 1", got)
	}
	if got := f.NetlinkIndexResyncSuccessCount(); got != 0 {
		t.Fatalf("NetlinkIndexResyncSuccessCount = %d, want 0", got)
	}
	if got := f.NetlinkIndexResyncFailureCount(); got != 1 {
		t.Fatalf("NetlinkIndexResyncFailureCount = %d, want 1", got)
	}
}

func TestConntrackEventIndexCloseDoesNotDeadlockWithQueuedResync(t *testing.T) {
	beforeLock := make(chan struct{})
	releaseBeforeLock := make(chan struct{})
	closeDone := make(chan error, 1)
	var hookEntered atomic.Bool
	var newEventIndexCalls atomic.Int32

	f := &ConntrackFlusher{
		backend: BackendNetlink,
		pool:    testCtNetlinkPool(&ctConn{}),
		newEventIndex: func() (*ctEventIndex, error) {
			newEventIndexCalls.Add(1)
			return &ctEventIndex{
				byQuery:  make(map[ctIndexQueryKey]map[ctOriginKey]struct{}),
				byOrigin: make(map[ctOriginKey]struct{}),
			}, nil
		},
		netlinkIndexBeforeResyncLock: func() {
			if hookEntered.CompareAndSwap(false, true) {
				close(beforeLock)
			}
			<-releaseBeforeLock
		},
	}

	f.scheduleEventIndexResync("test", errors.New("stream loss"))
	select {
	case <-beforeLock:
	case <-time.After(time.Second):
		t.Fatal("scheduled resync did not reach pre-lock hook")
	}
	f.netlinkIndexResyncMu.Lock()
	go func() {
		closeDone <- f.Close()
	}()
	deadline := time.Now().Add(time.Second)
	for !f.closed.Load() {
		if time.Now().After(deadline) {
			t.Fatal("Close did not mark flusher closed")
		}
		time.Sleep(time.Millisecond)
	}
	close(releaseBeforeLock)
	f.netlinkIndexResyncMu.Unlock()

	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("Close returned error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close deadlocked behind queued resync")
	}
	if got := newEventIndexCalls.Load(); got != 0 {
		t.Fatalf("new event index calls after queued resync observed Close = %d, want 0", got)
	}
	if got := f.NetlinkIndexResyncAttemptCount(); got != 0 {
		t.Fatalf("NetlinkIndexResyncAttemptCount after queued Close = %d, want 0", got)
	}
	if f.netlinkIndexResyncInFlight.Load() {
		t.Fatal("netlinkIndexResyncInFlight remained true after queued Close")
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
			dumpFn: func(_ context.Context, _ *ctConn, _ conntrack.Family, _ time.Time, _ bool) ([]conntrack.Con, error) {
				dumpCalls++
				return nil, context.DeadlineExceeded
			},
			deleteFn: func(_ context.Context, _ *ctConn, _ conntrack.Family, _ *conntrack.IPTuple, _ time.Time) error {
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
			dumpFn: func(_ context.Context, _ *ctConn, _ conntrack.Family, _ time.Time, _ bool) ([]conntrack.Con, error) {
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

func TestL3FlushConntrackIndexGauges(t *testing.T) {
	idx := &ctEventIndex{
		byQuery: make(map[ctIndexQueryKey]map[ctOriginKey]struct{}),
		byOrigin: map[ctOriginKey]struct{}{
			{srcPort: 101}: {},
			{srcPort: 102}: {},
			{srcPort: 103}: {},
			{srcPort: 104}: {},
			{srcPort: 105}: {},
			{srcPort: 106}: {},
			{srcPort: 107}: {},
		},
	}
	cf := &ConntrackFlusher{
		backend: BackendNetlink,
	}
	cf.storeEventIndex(idx)
	cf.netlinkIndexedFlushes.Store(3)
	cf.netlinkIndexFallbackDumps.Store(4)
	cf.netlinkIndexAuthoritativeDumps.Store(9)
	cf.netlinkIndexResyncAttempts.Store(9)
	cf.netlinkIndexResyncSuccesses.Store(8)
	cf.netlinkIndexResyncFailures.Store(1)
	idx.errors.Store(5)
	idx.events.Store(6)
	idx.originCount.Store(7)
	idx.pendingOverflows.Store(8)
	ac := &UdpAC{config: &Config{ACId: "test-ac"}}
	ac.conntrackFlusher.Store(cf)
	reg := &ACRegistration{ac: ac}

	if got := reg.l3FlushConntrackIndexedFlushesGauge(); got != 3 {
		t.Fatalf("l3FlushConntrackIndexedFlushesGauge = %v, want 3", got)
	}
	if got := reg.l3FlushConntrackIndexFallbackDumpsGauge(); got != 4 {
		t.Fatalf("l3FlushConntrackIndexFallbackDumpsGauge = %v, want 4", got)
	}
	if got := reg.l3FlushConntrackIndexAuthoritativeDumpsGauge(); got != 9 {
		t.Fatalf("l3FlushConntrackIndexAuthoritativeDumpsGauge = %v, want 9", got)
	}
	if got := reg.l3FlushConntrackIndexEventErrorsGauge(); got != 5 {
		t.Fatalf("l3FlushConntrackIndexEventErrorsGauge = %v, want 5", got)
	}
	if got := reg.l3FlushConntrackIndexPendingOverflowsGauge(); got != 8 {
		t.Fatalf("l3FlushConntrackIndexPendingOverflowsGauge = %v, want 8", got)
	}
	if got := reg.l3FlushConntrackIndexEventsGauge(); got != 6 {
		t.Fatalf("l3FlushConntrackIndexEventsGauge = %v, want 6", got)
	}
	if got := reg.l3FlushConntrackIndexOriginsGauge(); got != 7 {
		t.Fatalf("l3FlushConntrackIndexOriginsGauge = %v, want 7", got)
	}
	if got := reg.l3FlushConntrackIndexResyncAttemptsGauge(); got != 9 {
		t.Fatalf("l3FlushConntrackIndexResyncAttemptsGauge = %v, want 9", got)
	}
	if got := reg.l3FlushConntrackIndexResyncSuccessesGauge(); got != 8 {
		t.Fatalf("l3FlushConntrackIndexResyncSuccessesGauge = %v, want 8", got)
	}
	if got := reg.l3FlushConntrackIndexResyncFailuresGauge(); got != 1 {
		t.Fatalf("l3FlushConntrackIndexResyncFailuresGauge = %v, want 1", got)
	}
}

func TestFlushNetlinkFakeOpsIPv6ICMPFamily(t *testing.T) {
	key := mustFlowKey(t, "2001:db8::10", "2001:db8::20", 0, FlowProtoICMP)
	deleteCalls := 0
	f := &ConntrackFlusher{
		backend: BackendNetlink,
		pool:    testCtNetlinkPool(&ctConn{}),
		ctOps: fakeCtNetlinkOps{
			dumpFn: func(_ context.Context, _ *ctConn, family conntrack.Family, _ time.Time, _ bool) ([]conntrack.Con, error) {
				if family != conntrack.IPv6 {
					t.Fatalf("dump family = %v, want IPv6", family)
				}
				return []conntrack.Con{
					testConntrackCon(t, "2001:db8::10", "2001:db8::20", 0, 0, 58),
					testConntrackCon(t, "2001:db8::11", "2001:db8::20", 0, 0, 58),
					testConntrackCon(t, "2001:db8::10", "2001:db8::20", 0, 0, unix.IPPROTO_TCP),
				}, nil
			},
			deleteFn: func(_ context.Context, _ *ctConn, family conntrack.Family, origin *conntrack.IPTuple, _ time.Time) error {
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
			dumpFn: func(_ context.Context, _ *ctConn, _ conntrack.Family, _ time.Time, _ bool) ([]conntrack.Con, error) {
				return []conntrack.Con{
					testConntrackCon(t, "192.0.2.10", "198.51.100.20", 51000, 443, unix.IPPROTO_TCP),
					testConntrackCon(t, "192.0.2.10", "198.51.100.20", 51001, 443, unix.IPPROTO_TCP),
					testConntrackCon(t, "192.0.2.10", "198.51.100.20", 51002, 443, unix.IPPROTO_TCP),
				}, nil
			},
			deleteFn: func(_ context.Context, _ *ctConn, _ conntrack.Family, _ *conntrack.IPTuple, _ time.Time) error {
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
			dumpFn: func(_ context.Context, _ *ctConn, _ conntrack.Family, _ time.Time, _ bool) ([]conntrack.Con, error) {
				return origins, nil
			},
			deleteFn: func(_ context.Context, _ *ctConn, _ conntrack.Family, _ *conntrack.IPTuple, _ time.Time) error {
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
			dumpFn: func(_ context.Context, _ *ctConn, _ conntrack.Family, _ time.Time, _ bool) ([]conntrack.Con, error) {
				return []conntrack.Con{
					testConntrackCon(t, "192.0.2.10", "198.51.100.20", 51000, 443, unix.IPPROTO_TCP),
					testConntrackCon(t, "192.0.2.10", "198.51.100.20", 51001, 443, unix.IPPROTO_TCP),
				}, nil
			},
			deleteFn: func(_ context.Context, _ *ctConn, _ conntrack.Family, _ *conntrack.IPTuple, deadline time.Time) error {
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
	if !errors.Is(err, boom) && !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Flush error = %v, want delete error or deadline exceeded", err)
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

func TestFlushNetlinkIndexedStopsAfterDeadlineBetweenSuccessfulDeletes(t *testing.T) {
	key := mustFlowKey(t, "192.0.2.10", "198.51.100.20", 443, FlowProtoTCP)
	idx := &ctEventIndex{
		byQuery:  make(map[ctIndexQueryKey]map[ctOriginKey]struct{}),
		byOrigin: make(map[ctOriginKey]struct{}),
	}
	idx.rebuild([]conntrack.Con{
		testConntrackCon(t, "192.0.2.10", "198.51.100.20", 51000, 443, unix.IPPROTO_TCP),
		testConntrackCon(t, "192.0.2.10", "198.51.100.20", 51001, 443, unix.IPPROTO_TCP),
	})

	deleteCalls := 0
	f := &ConntrackFlusher{
		backend: BackendNetlink,
		pool:    testCtNetlinkPool(&ctConn{}),
		ctOps: fakeCtNetlinkOps{
			dumpFn: func(_ context.Context, _ *ctConn, _ conntrack.Family, _ time.Time, _ bool) ([]conntrack.Con, error) {
				return nil, errors.New("indexed Flush must not dump")
			},
			deleteFn: func(_ context.Context, _ *ctConn, _ conntrack.Family, _ *conntrack.IPTuple, deadline time.Time) error {
				deleteCalls++
				if sleep := time.Until(deadline) + time.Millisecond; sleep > 0 {
					time.Sleep(sleep)
				}
				return nil
			},
		},
	}
	f.storeEventIndex(idx)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	err := f.Flush(ctx, key)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Flush error = %v, want errors.Is(..., context deadline exceeded)", err)
	}
	if !strings.Contains(err.Error(), "deleted 1/2 indexed") {
		t.Fatalf("Flush error = %q, want deadline-break indexed count", err)
	}
	if deleteCalls != 1 {
		t.Fatalf("delete calls = %d, want 1", deleteCalls)
	}
	if got := f.NetlinkDeletedCount(); got != 1 {
		t.Fatalf("NetlinkDeletedCount = %d, want 1", got)
	}
}

func TestFlushNetlinkCtxCanceledWhileWaitingForFreeSocket(t *testing.T) {
	key := mustFlowKey(t, "192.0.2.10", "198.51.100.20", 443, FlowProtoTCP)
	var dumpCalls atomic.Int32
	f := &ConntrackFlusher{
		backend: BackendNetlink,
		pool:    &ctNetlinkPool{conns: []*ctConn{{}}, free: make(chan *ctConn, 1)},
		ctOps: fakeCtNetlinkOps{dumpFn: func(_ context.Context, _ *ctConn, _ conntrack.Family, _ time.Time, _ bool) ([]conntrack.Con, error) {
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
		f := &ConntrackFlusher{ctOps: fakeCtNetlinkOps{dumpFn: func(_ context.Context, _ *ctConn, _ conntrack.Family, _ time.Time, _ bool) ([]conntrack.Con, error) {
			calls++
			if calls == 1 {
				return nil, unix.ENOBUFS
			}
			return []conntrack.Con{{}}, nil
		}}}

		cons, _, err := f.dumpWithRetry(context.Background(), &ctConn{}, conntrack.IPv4, time.Now().Add(time.Minute), false)
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
		f := &ConntrackFlusher{ctOps: fakeCtNetlinkOps{dumpFn: func(_ context.Context, _ *ctConn, _ conntrack.Family, _ time.Time, _ bool) ([]conntrack.Con, error) {
			calls++
			return nil, unix.EINTR
		}}}

		_, _, err := f.dumpWithRetry(context.Background(), &ctConn{}, conntrack.IPv4, time.Now().Add(-time.Millisecond), false)
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
		f := &ConntrackFlusher{ctOps: fakeCtNetlinkOps{deleteFn: func(context.Context, *ctConn, conntrack.Family, *conntrack.IPTuple, time.Time) error {
			calls++
			if calls == 1 {
				return unix.EINTR
			}
			return nil
		}}}

		if err := f.deleteOriginWithRetry(context.Background(), &ctConn{}, conntrack.IPv4, origin, time.Now().Add(time.Minute)); err != nil {
			t.Fatalf("deleteOriginWithRetry returned error: %v", err)
		}
		if calls != 2 {
			t.Fatalf("delete calls = %d, want 2", calls)
		}
	})

	t.Run("expired-deadline-does-not-retry-transient-error", func(t *testing.T) {
		calls := 0
		f := &ConntrackFlusher{ctOps: fakeCtNetlinkOps{deleteFn: func(context.Context, *ctConn, conntrack.Family, *conntrack.IPTuple, time.Time) error {
			calls++
			return unix.ENOBUFS
		}}}

		err := f.deleteOriginWithRetry(context.Background(), &ctConn{}, conntrack.IPv4, origin, time.Now().Add(-time.Millisecond))
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

	monitor, err := conntrack.Open(&conntrack.Config{AddConntrackInformation: true})
	if err != nil {
		tb.Skipf("conntrack event netlink unavailable: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	groups := conntrack.NetlinkCtNew | conntrack.NetlinkCtUpdate | conntrack.NetlinkCtDestroy
	if err := monitor.Register(ctx, conntrack.Conntrack, groups, func(conntrack.Con) int { return 0 }); err != nil {
		cancel()
		_ = monitor.Close()
		tb.Skipf("conntrack event subscription unavailable: %v", err)
	}
	cancel()
	_ = monitor.Close()
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

// BenchmarkConntrackFlusher_Netlink is the #2165/#2908 steady-state acceptance
// gate: ≤200µs/op on a sandbox AC with the event index healthy. It measures an
// indexed no-match Flush after startup backfill, so the ambient conntrack table
// size should not affect per-op cost unless the event stream is unavailable and
// the flusher is forced onto the safe dump fallback. Set
// NHP_CONNTRACK_NETLINK_BENCH_GATE=1 to make the acceptance fence fail via
// b.Errorf when per-op time exceeds the budget; without it, the bench logs the
// miss so ad hoc/CI -bench invocations on an unready AC don't fail noisily. The
// rollout ledger's populated-table characterization remains the operational
// throughput gate.
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
			b.Errorf("netlink Flush %.0f ns/op exceeds the ≤200µs/op gate — event index may be unavailable or delete path is over budget", nsPerOp)
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
