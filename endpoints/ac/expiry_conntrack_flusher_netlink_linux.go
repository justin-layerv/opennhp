//go:build linux

package ac

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	conntrack "github.com/florianl/go-conntrack"
	"golang.org/x/sys/unix"

	"github.com/OpenNHP/opennhp/nhp/log"
)

// BackendNetlink datapath for ConntrackFlusher (#2165).
//
// # What this replaces
//
// The exec backend forks `conntrack -D <partial tuple>` per Flush; the
// fork+exec dominates at ~5-10 ms/call, capping the worker pool well
// below the L3-only million-session burst target (1M expiries / 10 s ≈
// 100k flushes/sec — see the capacity audit #2163). This path issues
// the same teardown over a pre-warmed netlink socket: no fork, no
// userspace-tool dependency, no locale-fragile stderr scrape, and —
// unlike `conntrack -D` without `-f ipv6` — IPv6-capable.
//
// # How a partial-tuple flush works on the kernel
//
// The kernel conntrack table is hashed on the FULL 5-tuple (incl. source
// port); there is no partial-tuple index. A single allow-rule FlowKey
// {src,dst,dport,proto} fans out to every established flow on that tuple
// regardless of the client's ephemeral source port. So a partial-tuple
// flush is fundamentally: enumerate the matching flows (a dump), then
// delete each by its full tuple. flushNetlink does exactly that — it is
// the iptables/conntrack analog of the eBPF enumerate-then-FlushConn-each
// surgical path (EnumerateConnTrackSrcPorts + BpfFlusher.FlushConn), with
// each per-flow delete the conntrack single-flow-delete primitive.
//
// For EXPIRY (this Flush) we delete ALL matching flows — the allow-rule
// is gone, so every flow on its tuple must die; there is no sibling to
// preserve (sibling-preservation matters only for a surgical REVOKE of
// one admission among several behind a NAT, which the coarse path does
// not do — see the #2784 follow-up note in udpac.go).
//
// # Bounding the syscall (fail loud, not silent stall)
//
// florianl's Dump/Delete take no context, and its Config.ReadTimeout is
// deprecated (no effect on Dump/Delete). A wedged kernel reply would
// otherwise park a worker INSIDE the syscall while it holds the pooled
// socket's mutex — eventually exhausting the pool and stalling the L3
// datapath silently. We therefore set read and write deadlines on the socket
// before every dump/delete, using one absolute whole-Flush deadline derived
// from the scheduler's ctx deadline (flushCallTimeout) and capped at
// defaultNetlinkOpTimeout. A timed-out op returns an error the breaker records
// — fail loud, exactly the posture the rest of the L3 design relies on. A
// socket that errors is reopened before reuse (a timed-out dump can leave
// unread kernel messages that would desync the next op), and a transient dump
// error (ENOBUFS/EINTR) is retried once before giving up to the breaker.
//
// # Cost / the remaining throughput follow-up
//
// The per-Flush dump is O(conntrack-table-size). On a small/medium table
// (the common case, and any sandbox AC) the dump is sub-millisecond and
// the win is the eliminated fork+exec — this is what the
// BenchmarkConntrackFlusher_Netlink ≤200µs/op gate measures. At a
// pathological million-entry table a per-key dump does not by itself
// reach the 100k/sec headroom; closing that asymptotic gap needs either
// a kernel-side CTA_FILTER mass-delete (one message, no userspace
// transfer) or an AC-side source-port index fed by conntrack NEW/DESTROY
// events. Both require on-kernel validation and are tracked in #2908;
// this backend is the correct, soak-ready datapath they build on, and
// the L3FlushConntrackSlowDumps metric is the early-warning signal for
// the knee.

// defaultNetlinkOpTimeout is the hard ceiling for one netlink Flush when the
// caller supplies no sooner ctx deadline. It caps socket acquisition, the dump,
// and every delete in the Flush; a larger caller deadline is still clamped here.
// Derived one second under the scheduler's defaultFlushCallTimeout so a wedged
// op fails the breaker before the scheduler's own per-call ctx would have. If
// that scheduler default is ever lowered below the one-second offset, the
// positiveNetlinkOpTimeout floor keeps the backstop in the future.
const defaultNetlinkOpTimeout = defaultFlushCallTimeout - time.Second

// minNetlinkOpTimeout is a defensive floor for netlinkOpDeadline if
// defaultFlushCallTimeout is ever lowered below the one-second offset above.
const minNetlinkOpTimeout = time.Millisecond

// netlinkSlowDumpThreshold is the per-Flush dump latency above which a
// Flush is counted on netlinkSlowDumps. Set well above the ≤200µs/op
// acceptance gate (so normal small-table dumps don't trip it) but low
// enough that a table-size-knee regression shows up as a rising counter
// during the soak.
const netlinkSlowDumpThreshold = 1 * time.Millisecond

// maxConsecutiveNetlinkDeleteErrors bounds the reopen-on-error path inside one
// Flush. A post-retry delete error marks the socket bad; if a kernel-side hard
// failure is systemic (for example EPERM), continuing through a large matched
// set would otherwise reopen once per origin until the deadline expires.
const maxConsecutiveNetlinkDeleteErrors = 3

// ctConn wraps one pre-warmed netlink socket with a mutex. A netlink
// socket multiplexes request→response by sequence number and is NOT safe
// for concurrent Dump/Delete from multiple goroutines; each socket is
// therefore used by exactly one flush at a time. Concurrency comes from
// the pool holding several sockets, not from sharing one.
type ctConn struct {
	mu   sync.Mutex
	nfct *conntrack.Nfct // nil after markBad until ensureOpen reopens
	// Same flag acquire/release use. This also fences already-acquired sockets
	// that markBad then ensureOpen after Close; acquire/release cannot see that edge.
	poolClosed *atomic.Bool
}

type ctNetlinkOps interface {
	dump(c *ctConn, family conntrack.Family, deadline time.Time) ([]conntrack.Con, error)
	deleteOrigin(c *ctConn, family conntrack.Family, origin *conntrack.IPTuple, deadline time.Time) error
}

type realCtNetlinkOps struct{}

func (realCtNetlinkOps) dump(c *ctConn, family conntrack.Family, deadline time.Time) ([]conntrack.Con, error) {
	return c.dump(family, deadline)
}

func (realCtNetlinkOps) deleteOrigin(c *ctConn, family conntrack.Family, origin *conntrack.IPTuple, deadline time.Time) error {
	return c.deleteOrigin(family, origin, deadline)
}

func (f *ConntrackFlusher) ctNetlinkOps() ctNetlinkOps {
	if f.ctOps != nil {
		return f.ctOps
	}
	return realCtNetlinkOps{}
}

// ensureOpen (re)opens the socket if a prior op left it bad. Caller holds mu.
func (c *ctConn) ensureOpen() error {
	if c.nfct != nil {
		return nil
	}
	if c.poolClosed != nil && c.poolClosed.Load() {
		return errCtNetlinkPoolClosed
	}
	// Keep the Config per-open, not pool-shared mutable state. Today it is
	// empty; if future go-conntrack options are added, each socket/reopen
	// still gets an independent config boundary.
	nfct, err := conntrack.Open(&conntrack.Config{})
	if err != nil {
		return err
	}
	c.nfct = nfct
	return nil
}

// markBad closes and drops the socket so the next ensureOpen reopens a
// fresh one. Called after ANY op error: a timed-out or errored netlink
// socket may have unread kernel messages (a partial dump) that would
// desync the next operation, so we never reuse it. Caller holds mu.
func (c *ctConn) markBad() {
	if c.nfct != nil {
		_ = c.nfct.Close()
		c.nfct = nil
	}
}

// setDeadline bounds both sides of the next netlink request. Caller holds mu.
func (c *ctConn) setDeadline(deadline time.Time) error {
	if err := c.nfct.Con.SetReadDeadline(deadline); err != nil {
		return err
	}
	return c.nfct.Con.SetWriteDeadline(deadline)
}

// dump returns the family's conntrack table with the whole-Flush socket
// deadline applied to bound the syscall. Caller holds mu.
func (c *ctConn) dump(family conntrack.Family, deadline time.Time) ([]conntrack.Con, error) {
	if err := c.ensureOpen(); err != nil {
		return nil, err
	}
	if err := c.setDeadline(deadline); err != nil {
		return nil, err
	}
	return c.nfct.Dump(conntrack.Conntrack, family)
}

// deleteOrigin deletes the single conntrack entry identified by origin,
// with the whole-Flush socket deadline applied. ENOENT (entry already gone —
// kernel GC raced us, or it was never written per #2168) maps to success to
// satisfy the FlowFlusher idempotency contract; any other error is returned
// for the breaker. Caller holds mu.
func (c *ctConn) deleteOrigin(family conntrack.Family, origin *conntrack.IPTuple, deadline time.Time) error {
	if origin == nil {
		return nil
	}
	if err := c.ensureOpen(); err != nil {
		return err
	}
	if err := c.setDeadline(deadline); err != nil {
		return err
	}
	return conntrackDeleteResult(c.nfct.Delete(conntrack.Conntrack, family, conntrack.Con{Origin: origin}))
}

// ctNetlinkPool is a fixed pool of pre-warmed netlink sockets. Idle sockets live
// in free; an acquired socket is absent until release, so a Flush never queues
// behind a busy socket while another socket is idle. Sized per the #2165 sketch
// (one socket per ~4 flush workers); see defaultConntrackNetlinkPoolSize and the
// L3FlushConntrackPoolSize config override.
type ctNetlinkPool struct {
	conns  []*ctConn
	free   chan *ctConn
	closed atomic.Bool
}

var errCtNetlinkPoolClosed = errors.New("conntrack netlink pool closed")

// newCtNetlinkPool opens n conntrack netlink sockets. On any open failure it
// closes the sockets already opened and returns the error, so construction is
// all-or-nothing (no half-open pool leaks fds). Deadlines are applied per
// dump/delete from the scheduler's whole-Flush budget instead of Config
// timeouts, whose write side would otherwise overwrite that shorter ctx budget.
func newCtNetlinkPool(n int) (*ctNetlinkPool, error) {
	if n < 1 {
		n = 1
	}
	p := &ctNetlinkPool{conns: make([]*ctConn, 0, n), free: make(chan *ctConn, n)}
	for i := 0; i < n; i++ {
		nfct, err := conntrack.Open(&conntrack.Config{})
		if err != nil {
			_ = p.Close() // best-effort cleanup of the ones already opened
			return nil, fmt.Errorf("open conntrack netlink socket %d/%d: %w", i+1, n, err)
		}
		c := &ctConn{nfct: nfct, poolClosed: &p.closed}
		p.conns = append(p.conns, c)
		p.free <- c
	}
	return p, nil
}

// acquire waits for an idle socket, bounded by the caller's whole-Flush
// deadline. This is deliberately availability-aware instead of round-robin:
// busy sockets are not in p.free, so a worker cannot block behind one while
// another pooled socket is idle.
func (p *ctNetlinkPool) acquire(ctx context.Context, deadline time.Time) (*ctConn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if p.isClosed() {
		return nil, errCtNetlinkPoolClosed
	}
	wait := time.Until(deadline)
	if wait <= 0 {
		return nil, context.DeadlineExceeded
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()

	select {
	case c := <-p.free:
		if p.isClosed() {
			return nil, errCtNetlinkPoolClosed
		}
		return c, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
		return nil, context.DeadlineExceeded
	}
}

func (p *ctNetlinkPool) release(c *ctConn) {
	if c != nil && !p.isClosed() {
		p.free <- c
	}
}

func (p *ctNetlinkPool) isClosed() bool {
	return p.closed.Load()
}

// Close closes every pooled socket, returning the first error. Safe on a
// partially-filled pool (used by newCtNetlinkPool's cleanup path) and on a
// socket already markBad'd (nil nfct).
func (p *ctNetlinkPool) Close() error {
	if !p.closed.CompareAndSwap(false, true) {
		return nil
	}

	var firstErr error
	for _, c := range p.conns {
		if c == nil {
			continue
		}
		c.mu.Lock()
		nfct := c.nfct
		c.nfct = nil
		c.mu.Unlock()
		if nfct == nil {
			continue
		}
		if err := nfct.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// flushNetlink is the BackendNetlink implementation of Flush: dump the
// FlowKey's address family, keep the flows whose origin tuple matches the
// allow-rule, and delete each. Honors the FlowFlusher idempotency
// contract — a zero-match dump and an ENOENT delete both return nil so
// the scheduler's breaker is not pinged.
//
// The socket deadline is derived from ctx (the scheduler's flushCallTimeout) so
// a wedged kernel reply fails loud within that whole-Flush budget rather than
// parking the worker indefinitely — addressing the "ctx honored at entry only"
// limitation by giving ctx real teeth on the syscall.
func (f *ConntrackFlusher) flushNetlink(ctx context.Context, key FlowKey) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if isMixedFamilyKey(key) {
		f.metricSkipped.Add(1)
		log.Warning("[ConntrackFlusher] mixed-family FlowKey %s reached netlink flusher — upstream FlowKey construction regression? No-op'd; key cannot match one conntrack address family; tracked in metricSkipped", key)
		return nil
	}
	family := familyForKey(key)
	isV6 := family == conntrack.IPv6
	deadline := netlinkOpDeadline(ctx)

	c, err := f.pool.acquire(ctx, deadline)
	if err != nil {
		return err
	}
	defer f.pool.release(c)
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := ctx.Err(); err != nil {
		// Keep cancellation clean if the caller's ctx flips after acquisition
		// but before the first syscall.
		return err
	}

	cons, dumpDuration, err := f.dumpWithRetry(c, family, deadline)
	if err != nil {
		return fmt.Errorf("conntrack netlink dump for %s: %w", key, err)
	}
	if dumpDuration > netlinkSlowDumpThreshold {
		f.netlinkSlowDumps.Add(1)
	}

	// Resolve the match spec ONCE — it depends only on key + family, both
	// fixed for this Flush, so recomputing it per dumped entry would be pure
	// repeated work in the O(table) loop.
	wantProto, filterProto, filterPort := conntrackMatchSpec(key, isV6)
	var firstErr error
	var matchedOrigins []*conntrack.IPTuple
	for i := range cons {
		t, ok := conToTuple(&cons[i])
		if !ok {
			continue
		}
		if !t.matchesSpec(key, wantProto, filterProto, filterPort) {
			continue
		}
		matchedOrigins = append(matchedOrigins, cons[i].Origin)
	}

	deleted := 0
	consecutiveDeleteErrors := 0
	for _, origin := range matchedOrigins {
		// Reuse the kernel's own reported origin tuple verbatim for the
		// delete — it carries the full 5-tuple (incl. source port, and for
		// ICMP the id/type/code) the kernel needs to find the exact entry.
		if derr := f.deleteOriginWithRetry(c, family, origin, deadline); derr != nil {
			consecutiveDeleteErrors++
			if firstErr == nil {
				firstErr = derr
			}
			// Stop once the shared whole-Flush deadline is exhausted.
			// processEntry deliberately does not re-fire expired keys; the
			// returned error spends breaker budget so admission fails closed if
			// this repeats, while any sibling the kernel still has ages out by
			// normal conntrack TTL. Transient delete errors get one fresh-socket
			// retry in deleteOriginWithRetry before we reach this branch. If the
			// deadline still has room and the error is not sustained, keep
			// deleting later matched siblings so a one-off per-entry kernel error
			// does not strand the tail. Bound consecutive post-retry errors so a
			// systemic hard error cannot reopen one socket per matched origin.
			if !time.Now().Before(deadline) || consecutiveDeleteErrors >= maxConsecutiveNetlinkDeleteErrors {
				break
			}
			continue
		}
		consecutiveDeleteErrors = 0
		deleted++
	}

	if deleted > 0 {
		f.netlinkDeleted.Add(uint64(deleted))
	}
	if firstErr != nil {
		return fmt.Errorf("conntrack netlink delete for %s (deleted %d/%d matched): %w", key, deleted, len(matchedOrigins), firstErr)
	}
	if len(matchedOrigins) == 0 {
		log.Debug("[ConntrackFlusher] no matching netlink entries for %s (idempotent)", key)
	}
	return nil
}

// deleteOriginWithRetry retries one transient delete failure on a freshly
// opened socket. A failed delete can leave unread netlink messages behind; the
// markBad before retry keeps the retry's request/response stream clean without
// making scheduler-level retries part of the expiry contract.
func (f *ConntrackFlusher) deleteOriginWithRetry(c *ctConn, family conntrack.Family, origin *conntrack.IPTuple, deadline time.Time) error {
	ops := f.ctNetlinkOps()
	err := ops.deleteOrigin(c, family, origin, deadline)
	if err == nil {
		return nil
	}
	c.markBad()
	if !isTransientNetlinkErr(err) || !time.Now().Before(deadline) {
		return err
	}
	log.Debug("[ConntrackFlusher] transient netlink delete error, retrying once: %v", err)
	if rerr := ops.deleteOrigin(c, family, origin, deadline); rerr != nil {
		c.markBad()
		// Join so both the original transient error and the retry failure
		// stay in the chain for errors.Is.
		return fmt.Errorf("conntrack netlink delete failed after one retry: %w", errors.Join(err, rerr))
	}
	return nil
}

// dumpWithRetry dumps the family's conntrack table, retrying ONCE on a
// transient netlink error (ENOBUFS/EINTR — a buffer overrun mid-dump or an
// interrupted syscall, both of which a fresh socket usually clears) before
// giving up to the breaker. The socket is reopened between attempts. The
// returned duration is the successful dump attempt only, so retry/reopen
// overhead does not muddy L3FlushConntrackSlowDumps' table-size signal. A
// timeout (the wedged-kernel case) is NOT transient — it is returned
// immediately, and a transient error after the deadline has passed does not
// spend the retry. A persistent error after the retry still fails loud.
func (f *ConntrackFlusher) dumpWithRetry(c *ctConn, family conntrack.Family, deadline time.Time) ([]conntrack.Con, time.Duration, error) {
	ops := f.ctNetlinkOps()
	dumpStart := time.Now()
	cons, err := ops.dump(c, family, deadline)
	duration := time.Since(dumpStart)
	if err == nil {
		return cons, duration, nil
	}
	c.markBad()
	if !isTransientNetlinkErr(err) || !time.Now().Before(deadline) {
		return nil, duration, err
	}
	log.Debug("[ConntrackFlusher] transient netlink dump error, retrying once: %v", err)
	dumpStart = time.Now()
	cons, rerr := ops.dump(c, family, deadline)
	duration = time.Since(dumpStart)
	if rerr != nil {
		c.markBad()
		// Join so both the original transient error and the retry failure
		// stay in the chain for errors.Is.
		return nil, duration, fmt.Errorf("conntrack netlink dump failed after one retry: %w", errors.Join(err, rerr))
	}
	return cons, duration, nil
}

// netlinkOpDeadline picks the socket deadline for one Flush: the
// scheduler's ctx deadline (flushCallTimeout) when present, capped at
// defaultNetlinkOpTimeout as a backstop for a ctx with no deadline. The
// returned absolute deadline is for the whole enumerate-then-delete Flush:
// socket-pool wait, dump, and every per-flow delete share the same budget.
func netlinkOpDeadline(ctx context.Context) time.Time {
	deadline := time.Now().Add(positiveNetlinkOpTimeout(defaultNetlinkOpTimeout))
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	return deadline
}

func positiveNetlinkOpTimeout(d time.Duration) time.Duration {
	if d >= minNetlinkOpTimeout {
		return d
	}
	return minNetlinkOpTimeout
}

// isTransientNetlinkErr reports whether a netlink error is a transient
// condition worth one retry (vs a hard failure or a timeout). ENOBUFS is a
// dump-buffer overrun under memory pressure; EINTR is an interrupted
// syscall. Both typically clear on a fresh socket.
func isTransientNetlinkErr(err error) bool {
	return errors.Is(err, unix.ENOBUFS) || errors.Is(err, unix.EINTR)
}

func isMixedFamilyKey(key FlowKey) bool {
	return isIPv4Mapped(key.SrcIP) != isIPv4Mapped(key.DstIP)
}

// familyForKey selects the netlink address family for a FlowKey. FlowKey
// stores IPv4 in IPv4-mapped form, so isIPv4Mapped on either endpoint
// distinguishes the families. Callers guard mixed-family keys first; MakeFlowKey
// only ever produces all-v4 or all-v6 keys.
func familyForKey(key FlowKey) conntrack.Family {
	if isIPv4Mapped(key.SrcIP) && isIPv4Mapped(key.DstIP) {
		return conntrack.IPv4
	}
	return conntrack.IPv6
}

// conToTuple decodes a dumped conntrack entry's ORIGINAL-direction tuple
// into the portable ctTuple used for matching. Returns ok=false (skip)
// when any required field is absent — a conntrack entry can legitimately
// lack ports (e.g. an in-progress entry), and a partially-populated Con
// must never be force-matched. That means a port-less TCP/UDP entry is
// skipped here even though the exec backend's kernel-side match might delete
// it; confirmed TCP/UDP conntrack entries carry ports, so the defensive skip is
// expected to affect only incomplete/unreachable entries.
func conToTuple(con *conntrack.Con) (ctTuple, bool) {
	if con == nil || con.Origin == nil {
		return ctTuple{}, false
	}
	o := con.Origin
	if o.Src == nil || o.Dst == nil || o.Proto == nil || o.Proto.Number == nil {
		return ctTuple{}, false
	}
	src := (*o.Src).To16()
	dst := (*o.Dst).To16()
	if src == nil || dst == nil {
		return ctTuple{}, false
	}
	if (*o.Proto.Number == unix.IPPROTO_TCP || *o.Proto.Number == unix.IPPROTO_UDP) &&
		(o.Proto.SrcPort == nil || o.Proto.DstPort == nil) {
		return ctTuple{}, false
	}
	var t ctTuple
	copy(t.srcIP[:], src)
	copy(t.dstIP[:], dst)
	t.proto = *o.Proto.Number
	if o.Proto.SrcPort != nil {
		t.srcPort = *o.Proto.SrcPort
	}
	if o.Proto.DstPort != nil {
		t.dstPort = *o.Proto.DstPort
	}
	return t, true
}

// isConntrackENOENT reports whether a netlink error is the kernel's
// "no such conntrack entry" — the idempotent no-op case. The errno is
// surfaced by mdlayher/netlink through the error chain, so errors.Is
// against unix.ENOENT matches regardless of the wrapping layer.
func isConntrackENOENT(err error) bool {
	return errors.Is(err, unix.ENOENT)
}

// conntrackDeleteResult maps the delete-side idempotency case to success:
// a dumped entry can be GC'd before Delete races it, and that ENOENT must not
// spend breaker budget. Kept pure so CI can fence wrapped ENOENT behavior
// without CAP_NET_ADMIN or a live conntrack socket.
func conntrackDeleteResult(err error) error {
	if err == nil || isConntrackENOENT(err) {
		return nil
	}
	return err
}
