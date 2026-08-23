// Package ac — L3 flush-on-expiry scheduler.
//
// When EnableL3FlushOnExpiry is true, the AC actively tears down
// kernel flow state (conntrack entries in iptables mode, conn_track
// + allow-rule BPF maps in eBPF/XDP mode) at the moment an ipset /
// BPF allow-entry expires. This guarantees existing TCP connections
// terminate at session end — without this scheduler, established
// connections survive entry expiry because both filter modes have an
// ESTABLISHED bypass (iptables: `-m state --state ESTABLISHED -j
// ACCEPT` before the ipset match; eBPF: XDP checks conn_track FIRST
// and returns XDP_PASS without re-checking allow-rules).
//
// # Design — hashed timer wheel
//
// At the million-session scale target (#2163), time.AfterFunc breaks
// down past ~100k concurrent timers (Go runtime timer-heap
// overhead). Instead this file implements a hashed timer wheel
// (Kafka / Netty pattern):
//
//	tick interval     10 ms
//	wheel size        60000 buckets (10 min coverage)
//	overflow          single linked list for deadlines beyond wheel
//	insert            O(1) — bucket math + linked-list prepend
//	cancel            O(1) — intrusive list unlink via entry pointer
//	tick              O(K) — K = entries in current bucket
//	memory            ~80 B/entry + ~64 B/index slot = ~150 MB at 1M
//	                  (see docs/design/SCHEDULER_SCALING.md for math
//	                  + capacity ceilings; ~1.5 GB at 10M)
//
// A 256-shard index (sharded mutex over map[FlowKey]*entry) backs
// Cancel and longest-wins reschedule lookups. Tick advances the
// wheel hand and drains the current bucket onto a bounded flush
// queue; a pool of N worker goroutines pulls from the queue and
// calls FlowFlusher.Flush.
//
// # Backpressure — fail-closed, no silent drops
//
// Under the design contract for L3-only enforcement (no L7
// backstop), late or missed flushes equal unauthorized data flow
// past session end. The scheduler therefore does NOT defer to the
// next tick on a full queue. Instead it pages on the FIRST
// near-cap event via the Deferred metric, and a sustained error
// rate trips the circuit breaker — which UdpAC reads via
// IsBreakerOpen to fail closed at NHP-AOP admission.
//
// # Flush is one-shot, not retried
//
// processEntry does not retry on Flush error. Each error pings
// the breaker; the breaker is the recovery mechanism, not per-call
// retry. A naive retry loop here would (a) compound the breaker
// math (one logical failure → N counted errors), and (b) defeat
// the intent of fail-closed admission (caller retries lose meaning
// when the SAME flusher errors are silently retried internally).
// If a future operator-facing knob wants per-call retries, that
// belongs in a separate retry layer with its own error budget, not
// in processEntry.
//
// # Schedule/Flush serialization via inFlight marker (#2168)
//
// processEntry releases shard.mu BEFORE calling Flush so the wheel
// + index aren't held across a syscall. Without further coordination
// a concurrent HandleAccessControl re-admitting the same FlowKey
// could write a new kernel allow-rule that this in-flight Flush
// then tears down. The scheduler closes that window with an
// `inFlight chan struct{}` on each expiryEntry: processEntry sets
// it under shard.mu before releasing, then closes it in a deferred
// cleanup after Flush returns (success / error / panic). Schedule
// waits on a non-nil-and-open inFlight for the bounded
// flushCallTimeout + 100ms slop, re-acquires shard.mu, then
// inserts the new entry. Cancel is a no-op while inFlight is open
// — the in-flight Flush already IS the cancellation.
//
// Caller order also changed: msghandler.go now schedules BEFORE
// writing the kernel allow-rule (scheduleThenWrite helper). With
// schedule-then-write, the brief no-rule window between Flush
// teardown and the new rule write is the only remaining seam;
// packets in that microwindow drop in BPF mode (vs the prior
// behavior of silent-deny for the entire new session) and self-
// heal at next packet in conntrack mode.
//
// # Out of scope here (lives in callers)
//
//   - Per-mode flusher impls (iptables / eBPF) — see
//     expiry_conntrack_flusher_linux.go and ebpf/bpf_flusher_linux.go.
//   - Schedule wiring at HandleAccessControl call sites — see
//     msghandler.go (13 admission-path + temp-handler Schedule
//     sites; every kernel allow-rule write is paired with a
//     scheduleFlushIfEnabled call immediately after the write).
//   - Boot-time enumeration of kernel state — see udpac.go startup.
//
// # Cancel wiring
//
// Two production sites invoke Scheduler.Cancel via
// UdpAC.cancelAllScheduledFlows — see that function's godoc for
// the over-broad fan-out semantics and known gaps:
//   - httpac.go /refresh handler — when the firewall deadline
//     has already passed, drops scheduler entries before
//     processEntry fires a pointless Flush.
//   - tokenstore.go TokenStore.OnExpire hook (wired in
//     (*UdpAC).Start) — fires per entry CleanExpired removes.
//
// /refresh that EXTENDS the deadline does not need explicit
// Cancel — Schedule's longest-wins semantics absorb the new
// (later) deadline directly.
package ac

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"github.com/OpenNHP/opennhp/nhp/log"
)

// FlowProto identifies the L4 protocol of a FlowKey. uint8 keeps
// FlowKey at a fixed 36 bytes (vs ~90 B with a string field).
type FlowProto uint8

const (
	// FlowProtoAny matches the FilterMode_IPTABLES "no protocol
	// specified" branch in HandleAccessControl (msghandler.go) and the
	// FilterMode_EBPFXDP mapType=2 (src+dst, no port) shape.
	FlowProtoAny  FlowProto = 0
	FlowProtoTCP  FlowProto = 1
	FlowProtoUDP  FlowProto = 2
	FlowProtoICMP FlowProto = 3
)

// String renders a FlowProto in log-friendly form.
func (p FlowProto) String() string {
	switch p {
	case FlowProtoTCP:
		return "tcp"
	case FlowProtoUDP:
		return "udp"
	case FlowProtoICMP:
		return "icmp"
	case FlowProtoAny:
		return "any"
	default:
		return fmt.Sprintf("unknown(%d)", uint8(p))
	}
}

// ianaL4Proto maps the AC's FlowProto enum to the IANA L4 protocol number
// the eBPF map keys use (TCP=6, UDP=17), returning ok=false for protocols
// that have no L4 number in that sense (ICMP, "any"). Single source of the
// TCP/UDP→IANA mapping: both the allow-rule flusher (BpfFlusher.Flush) and
// the surgical conntrack flusher (BpfFlusher.FlushConn) need it, and a
// divergent second copy could silently encode the wrong protocol byte.
func (p FlowProto) ianaL4Proto() (uint8, bool) {
	switch p {
	case FlowProtoTCP:
		return 6, true
	case FlowProtoUDP:
		return 17, true
	default:
		return 0, false
	}
}

// FlowKey identifies a single allow-rule flow at the AC. Both IPv4
// and IPv6 are stored in 16-byte form: IPv4 addresses are stored in
// IPv4-mapped IPv6 form (::ffff:a.b.c.d), matching the kernel
// netlink representation conntrack expects when issuing a delete.
//
// Size: 36 bytes (16 + 16 + 2 + 1 + 1 padding), comparable, suitable
// as a Go map key. Full per-entry cost (FlowKey + expiryEntry +
// sharded-map slot overhead) totals ~150 B; see
// docs/design/SCHEDULER_SCALING.md for the breakdown and
// instance-budget numbers (~150 MB at 1M, ~1.5 GB at 10M).
type FlowKey struct {
	SrcIP    [16]byte
	DstIP    [16]byte
	DstPort  uint16
	Protocol FlowProto
	_        uint8
}

// MakeFlowKey constructs a FlowKey from string IPs, a destination
// port (0..65535; 0 = port-wildcard), and a protocol. Returns an
// error if either IP cannot be parsed or the port is out of range.
func MakeFlowKey(srcIP, dstIP string, dstPort int, proto FlowProto) (FlowKey, error) {
	src, err := parseIPTo16(srcIP)
	if err != nil {
		return FlowKey{}, fmt.Errorf("invalid src IP %q: %w", srcIP, err)
	}
	dst, err := parseIPTo16(dstIP)
	if err != nil {
		return FlowKey{}, fmt.Errorf("invalid dst IP %q: %w", dstIP, err)
	}
	if dstPort < 0 || dstPort > 65535 {
		return FlowKey{}, fmt.Errorf("dst port %d out of range [0,65535]", dstPort)
	}
	return FlowKey{
		SrcIP:    src,
		DstIP:    dst,
		DstPort:  uint16(dstPort),
		Protocol: proto,
	}, nil
}

func parseIPTo16(s string) ([16]byte, error) {
	var out [16]byte
	ip := net.ParseIP(s)
	if ip == nil {
		return out, errors.New("not a valid IP address")
	}
	if ip.IsUnspecified() {
		// 0.0.0.0 / :: are never valid flow tuples — reject at the
		// boundary so a wildcard accidentally written to ipset
		// can't be scheduled for flush against the AC's whole
		// kernel state.
		return out, errors.New("unspecified IP (0.0.0.0 or ::) is not a valid flow tuple")
	}
	// net.ParseIP returns 16-byte IPv4-mapped form for IPv4 inputs
	// already (`::ffff:a.b.c.d`), so a single ip.To16() handles
	// both families uniformly. The kernel conntrack netlink API
	// accepts either form; the mapped form keeps the flusher
	// symmetric across families.
	copy(out[:], ip.To16())
	return out, nil
}

// SrcIPString renders the FlowKey's SrcIP back to its conventional
// string form (IPv4 if it was originally IPv4, else IPv6).
func (k FlowKey) SrcIPString() string { return netIPFrom16(k.SrcIP).String() }

// DstIPString — mirror of SrcIPString for the destination IP.
func (k FlowKey) DstIPString() string { return netIPFrom16(k.DstIP).String() }

func netIPFrom16(b [16]byte) net.IP {
	ip := net.IP(b[:])
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return ip
}

// String renders a FlowKey in `src→dst:port/proto` form for logging.
func (k FlowKey) String() string {
	return fmt.Sprintf("%s→%s:%d/%s", k.SrcIPString(), k.DstIPString(), k.DstPort, k.Protocol)
}

// ConnFlowKey identifies a single ESTABLISHED flow — the allow-rule
// FlowKey plus the per-flow source port. The source port is the
// kernel-visible "per-admission discriminator" (P4c): the allow-rule
// FlowKey alone cannot distinguish two admissions that share one
// {src,dst,dport,proto} network tuple (NAT'd clients behind one IP),
// because they collapse to a single allow-rule map entry — but the
// kernel's conntrack map keys on the full 5-tuple incl. source port, and
// two concurrent flows behind one NAT to the same destination always have
// distinct source ports. So this is the granularity at which a revoke can
// surgically kill EXACTLY one admission's established flow while leaving a
// same-tuple sibling (different source port) alive.
//
// SrcPort is host byte order (0..65535); the eBPF helper converts it to
// the on-wire network order the kernel conntrack key uses.
//
// Why this is a parallel key and NOT a widening of FlowKey: FlowKey has a
// documented per-entry memory budget (SCHEDULER_SCALING.md) and is used as
// the timer-wheel map key across the whole scheduler; adding a source-port
// dimension there would inflate every scheduled allow-rule entry and is
// pointless for scheduled expiry (the allow-rule maps have no source-port
// slot). ConnFlowKey is confined to the surgical-teardown path, which P4e
// wires to the revocation index. The normal scheduled-expiry FlowFlusher
// contract (Flush(ctx, FlowKey)) is untouched.
type ConnFlowKey struct {
	Flow    FlowKey
	SrcPort uint16
}

// String renders a ConnFlowKey in `src:sport→dst:dport/proto` form.
func (c ConnFlowKey) String() string {
	return fmt.Sprintf("%s:%d→%s:%d/%s",
		c.Flow.SrcIPString(), c.SrcPort, c.Flow.DstIPString(), c.Flow.DstPort, c.Flow.Protocol)
}

// shard returns the shard index for this key. Inlines FNV-1a over
// the packed key bytes — the previous `fnv.New32a()` allocated a
// hasher per call, which at the design target of 100k Schedule/sec
// is meaningful GC pressure on the hot path. Inlined form is zero-
// alloc and roughly the same line count
//
// `& (schedulerShardCount-1)` instead of `% schedulerShardCount` —
// 256 is a power of two so the mask is faster than div/mod, and
// self-documents the power-of-two requirement
func (k FlowKey) shard() uint32 {
	const (
		fnvOffset = 2166136261
		fnvPrime  = 16777619
	)
	h := uint32(fnvOffset)
	for _, b := range k.SrcIP {
		h ^= uint32(b)
		h *= fnvPrime
	}
	for _, b := range k.DstIP {
		h ^= uint32(b)
		h *= fnvPrime
	}
	h ^= uint32(byte(k.DstPort >> 8))
	h *= fnvPrime
	h ^= uint32(byte(k.DstPort))
	h *= fnvPrime
	h ^= uint32(byte(k.Protocol))
	h *= fnvPrime
	return h & (schedulerShardCount - 1)
}

type authoritativeFlushContextKey struct{}

func withAuthoritativeFlush(ctx context.Context) context.Context {
	return context.WithValue(ctx, authoritativeFlushContextKey{}, true)
}

func wantsAuthoritativeFlush(ctx context.Context) bool {
	v, _ := ctx.Value(authoritativeFlushContextKey{}).(bool)
	return v
}

// FlowFlusher tears down kernel flow state for a given FlowKey.
//
// CONTRACT: implementations MUST be safe for concurrent use from
// many goroutines and MUST be idempotent on missing flow state —
// return nil when the kernel reports ENOENT / no-such-entry.
// msghandler.go's schedule-then-write reorder for #2168 relies on
// this: a scheduled flush against a never-written kernel entry
// (when the upstream ipset.Add / EbpfRuleAdd subsequently failed)
// MUST NOT bump FlushErr or trip the breaker. The kernel GC also
// can have removed the entry before the scheduler fires; same
// idempotency rule applies. See per-flusher CONTRACT blocks on
// ConntrackFlusher.Flush and BpfFlusher.Flush for implementation
// details (single-source-of-truth is here at the interface).
type FlowFlusher interface {
	Flush(ctx context.Context, key FlowKey) error
}

// NoOpFlusher is a non-Linux-safe placeholder used by tests and by
// the disabled-feature path. Records call counts so callers can
// detect mis-wiring without touching kernel state.
type NoOpFlusher struct{ calls atomic.Uint64 }

// Flush implements FlowFlusher; always returns nil.
func (n *NoOpFlusher) Flush(_ context.Context, _ FlowKey) error {
	n.calls.Add(1)
	return nil
}

// CallCount returns the number of Flush invocations seen.
func (n *NoOpFlusher) CallCount() uint64 { return n.calls.Load() }

const (
	// schedulerShardCount is the shard count for the entry index.
	// 256 gives ~4k entries per shard at 1M total, ~40k at 10M —
	// keeps per-shard map operations cheap and contention rare.
	// MUST be a power of two: FlowKey.shard() uses `& (n-1)`
	// instead of `% n`, which mis-shards silently if n is not a
	// power of two. The compile-time fence below catches a future
	// tuning bump like 250.
	schedulerShardCount = 256

	// defaultWheelSize × defaultTickInterval = wheel coverage window.
	// 60000 × 10ms = 10min. Deadlines beyond 10min land in the
	// overflow list and are promoted as the wheel advances.
	//
	// Sized for production: qURL session_duration distribution
	// (min 60s, default ~300s, p99 ~1800s) lands the vast majority
	// of entries in-wheel rather than in overflow. Overflow
	// promotion is O(N) under wheelMu on every wrap; an undersized
	// wheel turns this into the dominant cost at fleet scale.
	// Wheel memory at this size is 60000 × 8B = 480KB — trivial.
	//
	// Long-tail sessions (>10min) still work correctly; they just
	// pay the overflow-promotion cost once per wrap. See
	// SCHEDULER_SCALING.md "wheel sizing" for the operator tuning
	// guidance if the session-duration distribution shifts.
	defaultWheelSize    = 60000
	defaultTickInterval = 10 * time.Millisecond

	// defaultWorkerCount + defaultFlushQueueCap size the dispatch
	// path. 64 workers × ~1ms per netlink syscall ≈ 64k flushes/sec
	// steady-state ceiling; queue cap 32k buys ~500ms of headroom at
	// that rate before backpressure shows up in metrics.
	defaultWorkerCount   = 64
	defaultFlushQueueCap = 32768
	// defaultBreakerErrLog is the MINIMUM size of the error-
	// timestamp ring. NewScheduler grows the ring to
	// max(defaultBreakerErrLog, breakerThreshold) at construction
	// so an operator-set threshold above this default can still
	// trip the breaker
	defaultBreakerErrLog = 128

	// defaultFlushCallTimeout caps each per-call FlowFlusher.Flush
	// in processEntry. Tight enough that a hung conntrack-tools
	// invocation burns breaker budget (one tripped per N stalls)
	// instead of stalling the worker indefinitely; loose enough that
	// a healthy netlink delete completes well under it. Tune down
	// when #2165's netlink swap lands (sub-ms typical) — until then
	// the conntrack-tools-fork-exec ceiling sets the floor.
	defaultFlushCallTimeout = 5 * time.Second

	// scheduleWaitSlop is the upper bound on bookkeeping time between
	// flusher.Flush returning and inFlight being closed (re-acquire
	// shard.mu, delete from index, decrement metric, close chan).
	// Used by Schedule's wait on a non-nil inFlight: any sane
	// in-flight Flush must have closed inFlight within
	// flushCallTimeout + scheduleWaitSlop; exceeding that means the
	// flusher itself is stuck past its own per-call ctx, which the
	// breaker catches independently.
	//
	// Operator runbook: if ScheduleWaitTimeout ticks WITHOUT a
	// concurrent FlushErr or BreakerOpen signal, the slop is too
	// tight (likely cause: GC stop-the-world tail under hot AC
	// load). Widening to 250ms is the first response before
	// suspecting a real stuck flusher. Auto-adaptive sizing is
	// tracked in #2189.
	scheduleWaitSlop = 100 * time.Millisecond
)

// overflowBucketIdx is the sentinel "bucket index" stored on entries
// that live in the overflow list (not in any wheel slot). Picked to
// be ≥ any real wheel index; the unlink path uses it to dispatch
// between wheel and overflow removal.
const overflowBucketIdx uint32 = 0xFFFFFFFF

// expiryEntry is the per-flow record. Intrusive doubly-linked list
// pointers (next/prev) keep it in exactly one of: a wheel bucket,
// the overflow list, or nowhere (in-flight to a worker).
//
// gen is atomic so Cancel can mark the entry dead (gen=0) without
// holding any per-entry lock; the worker re-reads it under
// shard.mu before flushing.
//
// deferCount caps how many times an entry may be re-bucketed under
// queue backpressure. When deferCount exceeds maxConsecutiveDefers
// the entry is dropped and the breaker opens — silent loss is a
// correctness violation under the L3-only contract, so we trade
// data loss for an explicit fail-closed signal.
//
// Memory: FlowKey (36) + deadlineNs (8) + gen (8 atomic) + bucket
// (4) + deferCount/authoritativeFlush (2) + 2B padding + next/prev (16) + inFlight
// chan header (8, nil until processEntry) ≈ 88 B.
type expiryEntry struct {
	FlowKey
	deadlineNs uint64
	gen        atomic.Uint64
	bucket     uint32
	// authoritativeFlush is set by RescheduleEarlier's immediate-revocation
	// path. Backends that maintain an async fast-path mirror can read the
	// context flag processEntry derives from this and choose fresh kernel
	// ground truth for revoke-triggered coarse flushes.
	authoritativeFlush bool
	// deferCount: single-writer (tick goroutine via dispatch ONLY).
	// Today only one tick loop exists; the per-shard-ticker work in
	// SCHEDULER_SCALING.md's roadmap (tracked in #2169) would change
	// that — multiple goroutines could call dispatch() on the same
	// entry. THIS FIELD MUST become atomic (or the dispatch path must
	// hold a per-shard lock) if that roadmap lands, otherwise the
	// backpressure-drop semantics race silently
	deferCount uint8
	_          [2]byte
	next       *expiryEntry
	prev       *expiryEntry
	// inFlight is non-nil iff a worker has begun Flush for this entry.
	// processEntry allocates the chan under shard.mu after the
	// liveness checks pass and closes it in the deferred cleanup
	// once Flush has returned (any outcome — success / error /
	// panic). Schedule blocks on a non-nil inFlight before
	// proceeding so a re-admission for the same FlowKey cannot
	// write a kernel allow-rule that the in-flight Flush then tears
	// down. See #2168 + package godoc.
	inFlight chan struct{}
}

// maxConsecutiveDefers bounds the re-bucket loop on a sustained
// queue-full condition. The drop fires when deferCount exceeds this
// value (i.e., on the 6th defer attempt), at which point the entry
// is dropped and the breaker is forced open — UdpAC must then refuse
// new NHP-AOPs at admission until the breaker recovers.
const maxConsecutiveDefers = 5

// Compile-time fence: expiryEntry.deferCount is uint8, so bumping
// maxConsecutiveDefers above 255 would silently wrap in the
// increment at dispatch(). If you raise the constant, widen the
// field first The conversion below
// fails at compile time if maxConsecutiveDefers overflows uint8.
const _ = uint8(maxConsecutiveDefers)

// Compile-time fence: schedulerShardCount MUST be a power of two
// because FlowKey.shard() uses `& (schedulerShardCount-1)` instead
// of `% schedulerShardCount`. The expression below evaluates to 0
// for any power of two (x & (x-1) == 0) and to a non-zero positive
// value otherwise — but we want a compile error, so we negate via
// `uint(0) - non-zero` which overflows uint at compile time only
// for non-power-of-two values. A tuning bump from 256 to 250 would
// fail to compile here.
const _ = uint(0) - uint(schedulerShardCount&(schedulerShardCount-1))

type schedulerShard struct {
	mu      sync.Mutex
	entries map[FlowKey]*expiryEntry
}

// SchedulerOption tunes a Scheduler at construction. Tests use these
// to dial down timing and worker counts.
type SchedulerOption func(*Scheduler)

// WithTickInterval overrides the wheel tick interval. Default 10ms.
// Smaller = tighter fire-latency but higher CPU at idle.
func WithTickInterval(d time.Duration) SchedulerOption {
	return func(s *Scheduler) { s.tickInterval = d }
}

// WithWheelSize overrides the wheel bucket count. Wheel coverage =
// size × tick interval. Default 60000 buckets × 10ms = 10min.
func WithWheelSize(n int) SchedulerOption {
	return func(s *Scheduler) { s.wheelSize = n }
}

// WithWorkerCount sets the flush worker pool size. Default 64.
func WithWorkerCount(n int) SchedulerOption {
	return func(s *Scheduler) { s.workerCount = n }
}

// WithFlushCallTimeout overrides the per-Flush() ctx timeout.
// Default 5s (defaultFlushCallTimeout) — sized for ConntrackFlusher's
// fork+exec ceiling. After #2165's netlink swap (sub-ms typical),
// operators should tighten this in lockstep without an AC build
// Rejects ≤0 with Warning + keeps
// default, mirroring WithBreakerThreshold's input-validation pattern.
func WithFlushCallTimeout(d time.Duration) SchedulerOption {
	return func(s *Scheduler) {
		if d <= 0 {
			log.Warning("[ExpirySched] WithFlushCallTimeout(%s) rejected (must be > 0); keeping default %s", d, s.flushCallTimeout)
			return
		}
		s.flushCallTimeout = d
	}
}

// WithFlushQueueCap sets the flush dispatch queue capacity.
// Default 32768.
func WithFlushQueueCap(n int) SchedulerOption {
	return func(s *Scheduler) { s.flushQueueCap = n }
}

// WithDryRun puts the scheduler into log-only mode. Workers log
// intended flushes but skip the FlowFlusher call. Used for the
// safety-default flip described in config.go's EnableL3FlushOnExpiry
// godoc.
func WithDryRun(dry bool) SchedulerOption {
	return func(s *Scheduler) { s.dryRun.Store(dry) }
}

// WithBreakerThreshold + WithBreakerWindow tune the circuit breaker.
// Breaker opens when the count of flush errors in the trailing
// window exceeds threshold. Defaults: 10 errors / 60s window.
//
// Both options reject zero / negative inputs with a Warning and
// keep the constructor default — a caller that passes
// WithBreakerThreshold(0) (e.g., from a TOML field that operator
// forgot to set) would otherwise make `count >= 0` true on the
// first flush error and trip the breaker immediately. Mirror of
// the Schedule wall-clock soft-fail
func WithBreakerThreshold(n int) SchedulerOption {
	return func(s *Scheduler) {
		if n <= 0 {
			log.Warning("[ExpirySched] WithBreakerThreshold(%d) rejected (must be > 0); keeping default %d", n, s.breakerThreshold)
			return
		}
		s.breakerThreshold = n
	}
}

func WithBreakerWindow(d time.Duration) SchedulerOption {
	return func(s *Scheduler) {
		if d <= 0 {
			log.Warning("[ExpirySched] WithBreakerWindow(%s) rejected (must be > 0); keeping default %s", d, s.breakerWindow)
			return
		}
		s.breakerWindow = d
	}
}

// Scheduler is the hashed-wheel L3 flush scheduler. Construct with
// NewScheduler; call Start before scheduling entries; call Shutdown
// to drain. Schedule, Cancel, and IsBreakerOpen are safe for
// concurrent use. Start and Shutdown are each idempotent via
// sync.Once — concurrent invocations are safe but only the first
// wins; the rest are no-ops. Interleaving Start and Shutdown (e.g.,
// re-Start after Shutdown) is unsupported.
type Scheduler struct {
	// Configuration (set at construction, immutable thereafter).
	flusher          FlowFlusher
	tickInterval     time.Duration
	wheelSize        int
	workerCount      int
	flushQueueCap    int
	flushCallTimeout time.Duration
	// dryRun is read by every processEntry on the hot path; atomic so
	// SetDryRun can propagate a config-reload flip without taking a
	// per-call lock
	dryRun atomic.Bool
	// breakerThreshold/breakerWindow are read inside recordBreakerErr
	// under breakerErrMu — SetBreakerParams writes them under the
	// same mutex.
	breakerThreshold int
	breakerWindow    time.Duration

	// Shard index for Cancel / longest-wins reschedule lookups.
	shards [schedulerShardCount]*schedulerShard

	// Timer wheel. wheelMu protects buckets, overflow, and hand.
	// Single mutex is fine because the tick goroutine is the only
	// frequent writer; Schedule/Cancel briefly take it to link /
	// unlink entries.
	wheelMu   sync.Mutex
	wheel     []*expiryEntry // bucket heads; len == wheelSize
	overflow  *expiryEntry   // overflow list head (deadlines beyond wheel coverage)
	wheelHand uint32         // next bucket the tick will drain

	// Flush dispatch.
	flushQueue chan *expiryEntry

	// Generation counter for TOCTOU defense on Cancel-vs-fire races.
	genCounter atomic.Uint64

	// Circuit breaker state.
	breakerErrs  []time.Time // ring buffer of recent error timestamps
	breakerHead  int         // write head into breakerErrs
	breakerCount int         // valid entries in breakerErrs
	breakerErrMu sync.Mutex
	breakerOpen  atomic.Bool
	// lastBreakerClampWarnedThreshold dedups the "threshold exceeds
	// ring size" Warning across repeated SetBreakerParams calls with
	// the same too-large value. 0 = not currently clamped; nonzero =
	// last warned threshold. SetBreakerParams flips it back to 0 on
	// first call where threshold ≤ ring and emits a single INFO
	// "protection restored" line.
	// 0 sentinel is safe because SetBreakerParams rejects
	// threshold ≤ 0 at the input gate before reaching this
	// dedup state machine (see the `threshold <= 0` reject
	// branch at the top of SetBreakerParams).
	lastBreakerClampWarnedThreshold int // guarded by breakerErrMu

	// Metrics.
	metricEntries       atomic.Int64
	metricFlushTotal    atomic.Uint64
	metricFlushErr      atomic.Uint64
	metricFlushDryRun   atomic.Uint64
	metricFlushDeferred atomic.Uint64
	metricFlushDropped  atomic.Uint64
	// metricBucketMaxDepth uses a CAS-update loop in tickOnce
	// (see the inline rationale there). The loop is correct under
	// either a single ticker or a future per-shard ticker
	// (SCHEDULER_SCALING.md roadmap), so this field stays
	// scheduler-global rather than per-shard — if a per-shard
	// ticker is added, the loop semantics still hold; only the
	// contention envelope changes
	metricBucketMaxDepth   atomic.Int64
	metricScheduleRejected atomic.Uint64 // wall-clock-deadline rejections at Schedule boundary
	// metricScheduleAfterShutdown counts Schedule() calls that
	// observed `started.Load() == false` and no-op'd. The
	// post-Shutdown contract is that boot enumeration on the next
	// AC process recovers any in-flight admission state; this
	// metric surfaces how often that recovery is exercised. Under
	// normal operation it should be zero; non-zero means there's
	// an admission path racing Shutdown.
	metricScheduleAfterShutdown atomic.Uint64
	// metricScheduleWaitTimeout counts Schedule() calls where the
	// in-flight Flush did not close its inFlight chan within
	// flushCallTimeout + scheduleWaitSlop. Non-zero means the
	// flusher is stuck past its own per-call deadline — Schedule
	// proceeds anyway (kernel state may briefly flap) and the
	// breaker will eventually catch a chronically stuck flusher.
	// See #2168 + package godoc.
	metricScheduleWaitTimeout atomic.Uint64

	// Lifecycle.
	ctx       context.Context
	cancel    context.CancelFunc
	workerWg  sync.WaitGroup
	tickerWg  sync.WaitGroup
	startOnce sync.Once
	stopOnce  sync.Once
	started   atomic.Bool
}

// NewScheduler constructs a Scheduler with the given flusher and
// options. The returned scheduler is not running; call Start.
func NewScheduler(flusher FlowFlusher, opts ...SchedulerOption) *Scheduler {
	if flusher == nil {
		flusher = &NoOpFlusher{}
	}
	s := &Scheduler{
		flusher:          flusher,
		tickInterval:     defaultTickInterval,
		wheelSize:        defaultWheelSize,
		workerCount:      defaultWorkerCount,
		flushQueueCap:    defaultFlushQueueCap,
		flushCallTimeout: defaultFlushCallTimeout,
		breakerThreshold: DefaultL3FlushErrorThreshold,
		breakerWindow:    time.Duration(DefaultL3FlushErrorWindowSec) * time.Second,
	}
	for _, opt := range opts {
		opt(s)
	}
	for i := range s.shards {
		s.shards[i] = &schedulerShard{entries: make(map[FlowKey]*expiryEntry)}
	}
	s.wheel = make([]*expiryEntry, s.wheelSize)
	s.flushQueue = make(chan *expiryEntry, s.flushQueueCap)
	// Ring sized to hold at least breakerThreshold timestamps; the
	// in-window count loop iterates breakerCount which saturates at
	// the ring's length. If the operator-tunable threshold exceeded
	// defaultBreakerErrLog, the breaker would never trip — count
	// can never reach threshold
	ringSize := defaultBreakerErrLog
	if s.breakerThreshold > ringSize {
		ringSize = s.breakerThreshold
	}
	s.breakerErrs = make([]time.Time, ringSize)
	// gosec G118 false positive: golangci-lint's bundled gosec
	// dataflow doesn't follow tuple-assignment → struct field →
	// method call. Shutdown invokes s.cancel(). Standalone gosec
	// finds 0 issues; same shape as endpoints/server/udpserver.go.
	//nolint:gosec // G118: tuple-assigned cancel is invoked from Shutdown
	s.ctx, s.cancel = context.WithCancel(context.Background())
	return s
}

// Start launches the tick goroutine and worker pool. Safe to call
// once; subsequent calls are no-ops.
func (s *Scheduler) Start() {
	s.startOnce.Do(func() {
		s.tickerWg.Add(1)
		go s.tickLoop()
		for i := 0; i < s.workerCount; i++ {
			s.workerWg.Add(1)
			go s.workerLoop()
		}
		s.started.Store(true)
	})
}

// Shutdown stops the tick goroutine and waits for the worker pool
// to exit. Subsequent Schedule / Cancel calls are no-ops after
// Shutdown.
//
// Pending entries in the flush queue are NOT flushed before return —
// processEntry bails on s.ctx.Err() (cr task #54: skip Flush calls
// that would only fail with context.Canceled and noisily trip the
// breaker). The cross-process recovery for those abandoned entries
// is boot enumeration on the next AC process: enumerateAndSchedule
// Flushes walks live kernel allow-rules and schedules each at its
// remaining timeout
//
// started is flipped false BEFORE cancel/drain so any concurrent
// Schedule racing with Shutdown becomes a no-op immediately,
// preventing entries from being inserted into a wheel whose tick
// loop is exiting.
func (s *Scheduler) Shutdown(ctx context.Context) error {
	var err error
	s.stopOnce.Do(func() {
		// Flip started=false BEFORE cancel/drain so any concurrent
		// Schedule racing Shutdown becomes a no-op immediately,
		// preventing entries from being inserted into a wheel whose
		// tick loop is exiting
		s.started.Store(false)
		s.cancel()
		s.tickerWg.Wait()
		close(s.flushQueue)
		done := make(chan struct{})
		go func() {
			s.workerWg.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-ctx.Done():
			err = ctx.Err()
		}
	})
	return err
}

// Schedule inserts or updates the flush deadline for key. Semantics
// are longest-wins: if key is already scheduled with a later
// deadline, the existing entry stays and Schedule is a no-op.
// Otherwise the entry is (re)inserted at the new deadline.
//
// # Caller contract — Schedule BEFORE writing the kernel allow-rule
//
// Callers MUST call Schedule BEFORE writing the kernel allow-rule
// (`ipset.Add` / `EbpfRuleAdd`). Schedule blocks on any in-flight
// Flush for the same FlowKey (see inFlight on expiryEntry), so the
// caller is guaranteed that any prior Flush has completed before
// the kernel rule write proceeds. msghandler.go's admission paths
// follow this order at every call site (the package-level comment
// in msghandler.go's HandleAccessControl spells out the contract
// alongside the calls). See #2168 + package godoc for the race
// this closes.
//
// # Wait-timeout fallback
//
// If the in-flight Flush exceeds flushCallTimeout +
// scheduleWaitSlop without closing inFlight (chronically stuck
// flusher), Schedule bumps ScheduleWaitTimeout, logs a Warning,
// and proceeds — bypassing the normal longest-wins early-return.
// Bypass rationale: the in-flight entry's kernel rule is in an
// indeterminate post-timeout state, so honoring its stored
// deadline as "still scheduled" would orphan the caller's new
// kernel rule of any flush hook. A non-zero ScheduleWaitTimeout
// is a chronically-stuck-flusher signal the breaker catches
// independently.
//
// # Worst-case blocking budget on the admission hot path
//
// Schedule blocks for up to flushCallTimeout + scheduleWaitSlop
// (5.1s at defaults) PER LOOP ITERATION when a Flush is in flight
// for the same FlowKey. Per-key only — unrelated keys never block
// (different shard mutexes; even same-shard different-keys don't
// block because Phase 1's lock drop is per-call). Under sustained
// healthy-flusher admission churn against a single hot FlowKey,
// the Phase 1 loop can iterate before draining (each loop's
// existing.inFlight check sees a fresh worker that picked up the
// next entry). Total blocking is bounded by the breaker:
// the FIRST stuck Flush eventually returns with an error (its
// own ctx times out), recordBreakerErr counts toward the
// threshold, and UdpAC's HandleAccessControl admission gate
// fails closed at the next NHP-AOP. The pile-up window is
// therefore (recovery_time + 5.1s) at worst under a stuck
// flusher; under a healthy-flusher storm, breaker-trip latency
// is a function of churn rate, not the 5.1s per-iteration bound.
// Operators tuning flushCallTimeout downward (e.g., after #2165's
// netlink swap) tighten this proportionally without an AC build.
// #2189 tracks a loop-iteration metric / cap for additional
// observability.
//
// # Lock order
//
// shard.mu is held across the entire shard-index + wheel-mutation
// sequence. Releasing shard.mu mid-sequence opens a window where
// a concurrent Schedule with an even-later deadline can win and
// then be overwritten by this slower call — silently violating
// longest-wins. Holding wheelMu inside shard.mu is the stable
// lock order observed by Cancel and tickOnce-driven retries.
//
// Phase 1's inFlight wait drops shard.mu BEFORE the
// shard-index + wheel-mutation sequence above begins (lock
// blocking unrelated keys in the same shard is the trade we
// avoid). The lock-order invariant applies to the
// index-mutation portion only — the wait is a separate phase.
//
// # Deadline semantics
//
// deadline is interpreted via its monotonic reading; wall-clock
// skew (NTP step) cannot move it. A deadline already in the past
// lands in the current bucket and fires on the next tick.
//
// Schedule validates that deadline carries a monotonic reading
// (t.Round(0) != t) at the boundary — a wall-clock-only deadline
// would silently drift with NTP step and produce wrong bucket math.
// A bad input here is a programmer bug (callers always derive
// deadlines via time.Now().Add(...) or time.Until-style arithmetic);
// log a Warning and no-op the schedule rather than panic deep in
// the scheduler. This soft-fail surfaces a missed schedule + a log
// line, not a crash that takes down the AC.
func (s *Scheduler) Schedule(key FlowKey, deadline time.Time) {
	s.scheduleEntry(key, deadline, false)
}

// RescheduleEarlier is the deliberate INVERSE of Schedule's longest-wins
// absorb: it moves an existing entry's deadline EARLIER (or inserts it if
// absent), and is a no-op only when the existing deadline is already at or
// before the requested one. It exists so qURL v2 immediate revocation
// (flushEntryNow in revocation_index.go) can force a flow that is already
// scheduled at its normal future firewall deadline to fire NOW — Schedule
// alone cannot, because longest-wins makes Schedule(key, now) a no-op against
// any later-scheduled key (which is every live admitted flow).
//
// It is NOT a substitute for Cancel-then-Schedule: it preserves Schedule's
// Phase 1 in-flight barrier. A worker already tearing the kernel rule down is
// waited out (the in-flight Flush already IS the immediate teardown); the body
// then inserts a fresh entry at the new deadline once the cleanup defer has
// removed the drained one, scheduling a second flush that is an idempotent
// ENOENT no-op against the already-torn-down rule. A not-yet-fired entry is
// simply pulled earlier. Reusing Schedule's body keeps the subtle inFlight-wait
// / wheel-relink / metric accounting in one place — the only behavioral delta
// is the comparison direction.
//
// Shared-FlowKey caveat: pulling a shared tuple's entry earlier fires the
// flush for every session on that FlowKey, including non-revoked siblings.
// That coarse over-flush is the accepted interim for the revocation slice
// (P4b); the kernel-visible per-session discriminator that makes revoke
// surgical is P4c. Non-revocation callers must keep using Schedule.
func (s *Scheduler) RescheduleEarlier(key FlowKey, deadline time.Time) {
	s.scheduleEntry(key, deadline, true)
}

// FlushNowAndWait takes authoritative per-key ownership through the same
// inFlight barrier used by Schedule and the natural-expiry worker. A caller may
// supply a preFlush hook for established-flow teardown; the hook and coarse
// flusher both run while new scheduling for this key is blocked. On failure the
// key is reinserted at its prior deadline (or the next tick when no prior entry
// existed), preserving retry work instead of converting a failed close into an
// empty-index success on the next control event.
func (s *Scheduler) FlushNowAndWait(ctx context.Context, key FlowKey, preFlush func(context.Context, FlowKey) error) (err error) {
	if s == nil || !s.started.Load() {
		return errors.New("expiry scheduler is not running")
	}
	if s.dryRun.Load() {
		return errors.New("authoritative flush cannot run in dry-run mode")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	shard := s.shards[key.shard()]
	for {
		shard.mu.Lock()
		current := shard.entries[key]
		if current == nil || current.inFlight == nil {
			originalDeadline := nowMonoNs()
			if current != nil {
				originalDeadline = current.deadlineNs
				current.gen.Store(0)
				s.wheelMu.Lock()
				s.unlinkLocked(current)
				s.wheelMu.Unlock()
			}
			owned := &expiryEntry{FlowKey: key, deadlineNs: originalDeadline, authoritativeFlush: true, inFlight: make(chan struct{})}
			owned.gen.Store(s.genCounter.Add(1))
			shard.entries[key] = owned
			if current == nil {
				s.metricEntries.Add(1)
			}
			shard.mu.Unlock()

			flushCtx, cancel := context.WithTimeout(ctx, s.flushCallTimeout)
			func() {
				defer func() {
					if recovered := recover(); recovered != nil {
						err = fmt.Errorf("authoritative flush panic: %v", recovered)
					}
				}()
				if preFlush != nil {
					if hookErr := preFlush(flushCtx, key); hookErr != nil {
						err = hookErr
						return
					}
				}
				if flushErr := s.flusher.Flush(withAuthoritativeFlush(flushCtx), key); flushErr != nil {
					err = flushErr
				}
			}()
			cancel()

			shard.mu.Lock()
			done := owned.inFlight
			if shard.entries[key] == owned {
				if err == nil {
					delete(shard.entries, key)
					owned.gen.Store(0)
					s.metricEntries.Add(-1)
				} else {
					if owned.deadlineNs < nowMonoNs() {
						owned.deadlineNs = nowMonoNs()
					}
					s.wheelMu.Lock()
					s.insertLocked(owned)
					s.wheelMu.Unlock()
				}
			}
			// Close the barrier while shard.mu is still held, then clear it on
			// the retained-error entry before publishing the unlocked state.
			// Schedule wakes only after this unlock and can never observe a nil
			// barrier before the authoritative work is complete.
			close(done)
			if err != nil && shard.entries[key] == owned {
				owned.inFlight = nil
			}
			shard.mu.Unlock()

			if errors.Is(err, context.Canceled) && s.ctx.Err() != nil {
				return err
			}
			s.metricFlushTotal.Add(1)
			if err != nil {
				s.metricFlushErr.Add(1)
				s.recordBreakerErr()
			}
			return err
		}
		wait := current.inFlight
		shard.mu.Unlock()
		select {
		case <-wait:
			continue
		case <-ctx.Done():
			return ctx.Err()
		case <-s.ctx.Done():
			return s.ctx.Err()
		}
	}
}

// reanchor replaces key's scheduled deadline without flushing its kernel
// state. Verified session cleanup uses this when the AccessEntry being removed
// shares key with another live entry: the shared rule must survive, but its
// scheduler ownership must move to the surviving entry's latest deadline
// rather than retaining a later deadline owned only by the removed entry.
//
// An in-flight flush has already begun tearing the shared rule down, so it
// cannot be converted into a preservation operation. Return an error instead
// of acknowledging session cleanup with a scheduler state that no longer
// describes the kernel rule. Lock order remains shard.mu before wheelMu.
func (s *Scheduler) reanchor(key FlowKey, deadline time.Time) error {
	if s == nil || !s.started.Load() {
		return errors.New("expiry scheduler is not running")
	}
	if deadline.Round(0) == deadline {
		return errors.New("reanchor deadline has no monotonic reading")
	}

	deadlineNs := monoNsAt(deadline)
	shard := s.shards[key.shard()]
	shard.mu.Lock()
	defer shard.mu.Unlock()

	existing := shard.entries[key]
	if existing != nil && existing.inFlight != nil {
		return errors.New("cannot preserve FlowKey while its flush is in flight")
	}
	if existing != nil && existing.deadlineNs == deadlineNs {
		return nil
	}

	entry := &expiryEntry{FlowKey: key, deadlineNs: deadlineNs}
	entry.gen.Store(s.genCounter.Add(1))

	s.wheelMu.Lock()
	if existing != nil {
		existing.gen.Store(0)
		s.unlinkLocked(existing)
	}
	s.insertLocked(entry)
	s.wheelMu.Unlock()

	shard.entries[key] = entry
	if existing == nil {
		s.metricEntries.Add(1)
	}
	return nil
}

// scheduleEntry is the shared body of Schedule and RescheduleEarlier. When
// pullEarlier is false (Schedule) it skips on existing.deadlineNs >=
// deadlineNs (longest-wins). When true (RescheduleEarlier) it skips only on
// existing.deadlineNs <= deadlineNs, i.e. it inserts whenever the requested
// deadline is strictly earlier than what is scheduled. The wait-timeout
// force-insert path is identical for both — a stuck in-flight entry's stored
// deadline is never honored.
func (s *Scheduler) scheduleEntry(key FlowKey, deadline time.Time, pullEarlier bool) {
	if !s.started.Load() {
		// Schedule lost the race against Shutdown — boot enumeration
		// on the next AC process recovers any state we couldn't
		// admit here. Surface the frequency so a dashboard can catch
		// a regression where this fires under steady-state instead
		// of only at shutdown.
		s.metricScheduleAfterShutdown.Add(1)
		return
	}
	if deadline.Round(0) == deadline {
		// Wall-clock-only deadline — programmer bug upstream.
		// Under L3-only, a no-op'd schedule is unauthorized data
		// past session end. Bump a counter so dashboards catch a
		// regression in caller-side time arithmetic without
		// needing log search
		s.metricScheduleRejected.Add(1)
		log.Warning("[ExpirySched] Schedule(%s): deadline has no monotonic reading (likely time.Unix() or Round(0) result); skipping. Callers must derive deadlines from time.Now()-based arithmetic.", key)
		return
	}
	deadlineNs := monoNsAt(deadline)
	shard := s.shards[key.shard()]

	// Phase 1: if the existing entry has an open inFlight chan, a
	// worker is mid-Flush (kernel allow-rule is being or has been
	// torn down). Wait for the in-flight Flush to complete before
	// proceeding so the caller's subsequent kernel-rule write
	// doesn't race the teardown. Drop shard.mu across the wait —
	// holding it would serialize unrelated keys in the same shard.
	// Re-acquire and re-fetch existing after the wait; the
	// in-flight entry will have been deleted from the index by
	// processEntry's cleanup defer (clean release) or is still
	// present with inFlight set (wait timeout).
	timedOutOnInFlight := false
	shard.mu.Lock()
	// Loop the wait so a re-admission burst that drains AND
	// dispatches a fresh entry to a worker between our wake-up
	// and lock re-acquisition is also serialized. Single-shot
	// semantics would leave a narrow race: Schedule_A waits on X
	// → cleanup closes X → Schedule_B inserts Y → tickOnce
	// drains Y → workerLoop allocates Y.inFlight → Schedule_A
	// wakes, sees Y.inFlight≠nil but doesn't wait → caller's
	// kernel-write races Y's Flush. Loop closes that seam at
	// zero cost in the common case (one iteration). Bound is
	// implicit: each iteration consumes flushCallTimeout +
	// scheduleWaitSlop and bumps ScheduleWaitTimeout on stuck
	// flushers, so a chronically-degraded path trips the breaker
	// independently. See #2168 + cr round 3 item 1.
	for {
		existing, ok := shard.entries[key]
		if !ok || existing.inFlight == nil {
			break
		}
		inFlight := existing.inFlight
		shard.mu.Unlock()
		waitTimeout := s.flushCallTimeout + scheduleWaitSlop
		// time.NewTimer + Stop on the clean-release path returns
		// the timer to the pool earlier than natural fire. Go 1.23+
		// runtimes auto-reclaim unreferenced timers; the explicit
		// Stop is a belt for older toolchains and clearer intent.
		timer := time.NewTimer(waitTimeout)
		select {
		case <-inFlight:
			timer.Stop()
		case <-timer.C:
			s.metricScheduleWaitTimeout.Add(1)
			timedOutOnInFlight = true
			log.Warning("[ExpirySched] Schedule(%s): in-flight Flush exceeded %s; proceeding (kernel state may briefly flap)", key, waitTimeout)
		}
		shard.mu.Lock()
		if timedOutOnInFlight {
			// Past the timeout we bypass the longest-wins check
			// downstream regardless of what we find; no need to
			// re-loop on a fresh inFlight (the breaker handles
			// chronically stuck flushers). NOTE: if the timeout
			// fired on a transient GC-tail stall AND a fresh
			// entry+inFlight materialized in the wake/re-acquire
			// seam, we accept a residual single-occurrence
			// #2168 race window here in exchange for bounded
			// admission blocking. The breaker covers stuck
			// flushers; this seam is the explicit trade. cr
			// round 8 finding 1.
			break
		}
	}
	// Invariant: shard.mu is held here. Every break path of the
	// Phase 1 loop above re-acquires shard.mu before exiting (the
	// no-wait break is reached under the initial Lock; the
	// inFlight-close break re-acquires before the loop test; the
	// timeout break re-acquires before its early exit). A future
	// refactor that adds an early-return inside the loop without
	// re-acquiring would break this defer.
	defer shard.mu.Unlock()

	existing, ok := shard.entries[key]
	// Longest-wins skip when we did NOT just wait out a stuck
	// in-flight entry. On wait-timeout the existing entry's kernel
	// rule has either been torn down (Flush eventually returns
	// past timeout) or is in an indeterminate state; honoring its
	// stored deadline as "still scheduled" would leave the caller's
	// new kernel rule with no flush hook once the cleanup defer
	// finally removes the index entry. Force-insert to keep the
	// new write under a fresh schedule.
	if ok && !timedOutOnInFlight {
		// Longest-wins (Schedule) leaves an at-least-as-late existing
		// entry alone; shortest-wins (RescheduleEarlier) leaves an
		// at-least-as-early one alone. In both directions the existing
		// schedule already satisfies the caller's intent, so skip the
		// re-insert. The in-flight case is handled in Phase 1 above and
		// the wait-timeout force-insert below bypasses this entirely.
		if !pullEarlier && existing.deadlineNs >= deadlineNs {
			return
		}
		if pullEarlier && existing.deadlineNs <= deadlineNs {
			existing.authoritativeFlush = true
			return
		}
	}

	// TODO(scaling): per-call alloc on every Schedule. At the 15M
	// ops/sec insert target a sync.Pool of expiryEntry would
	// eliminate this GC pressure. Tracked in docs/design/
	// SCHEDULER_SCALING.md's "allocation-free hot path" roadmap
	//
	entry := &expiryEntry{
		FlowKey:            key,
		deadlineNs:         deadlineNs,
		authoritativeFlush: pullEarlier,
	}
	entry.gen.Store(s.genCounter.Add(1))

	s.wheelMu.Lock()
	if existing != nil {
		// On inFlight != nil, the worker already passed the
		// `entry.gen.Load() == 0` early-return in processEntry
		// BEFORE allocating inFlight (under shard.mu, line ~1530),
		// so the store here would have no effect on the worker's
		// liveness decision. AND skip unlinkLocked: tickOnce
		// drained the entry from the wheel (snapping next/prev to
		// nil under wheelMu) before dispatch, so the call would
		// be a no-op AND a defense-in-depth fragility (future
		// tickOnce refactor that left next/prev populated could
		// corrupt the bucket list). Both writes are no-op'd
		// together — inFlight ⇒ drained + worker-past-gen-check
		// ⇒ both mutations are wasted work. See cr rounds 3 + 6.
		if existing.inFlight == nil {
			// Mark dead BEFORE unlinking so a worker that already
			// pulled the entry from the queue no-ops at the
			// gen-check (see processEntry).
			existing.gen.Store(0)
			s.unlinkLocked(existing)
		}
	}
	s.insertLocked(entry)
	s.wheelMu.Unlock()

	shard.entries[key] = entry
	// metricEntries invariant under timedOutOnInFlight: the stuck
	// in-flight entry's cleanup defer will eventually run and see
	// `cur != entry` (cur is our new entry), so it skips its own
	// Add(-1). Skipping the +1 here keeps the metric consistent
	// across the overlap — one slot net change, not two — at the
	// cost of a transient single-count metric-fidelity gap during
	// the very rare wait-timeout overlap window.
	if existing == nil {
		s.metricEntries.Add(1)
	}
}

// Cancel removes any scheduled flush for key. Safe to call for keys
// that aren't scheduled (no-op).
//
// If an entry is mid-Flush (inFlight chan is set), Cancel is a
// no-op — the in-flight Flush already IS the cancellation: the
// kernel allow-rule is being torn down right now, and processEntry's
// cleanup defer will remove the index entry once Flush returns.
//
// Reschedule must use Schedule (which handles the in-flight case in
// Phase 1), NOT Cancel-then-Schedule. The latter is a no-op during
// in-flight + a re-insert, reopening the re-admission race window.
// Production callers (UdpAC.cancelAllScheduledFlows) are
// terminal-remove sites that never
// re-schedule the same key.
//
// Lock order matches Schedule: shard.mu before wheelMu.
func (s *Scheduler) Cancel(key FlowKey) {
	if !s.started.Load() {
		return
	}
	shard := s.shards[key.shard()]
	shard.mu.Lock()
	defer shard.mu.Unlock()

	entry, ok := shard.entries[key]
	if !ok {
		return
	}
	if entry.inFlight != nil {
		// In-flight Flush is already the cancellation; let
		// processEntry's cleanup defer finish the index removal.
		return
	}
	delete(shard.entries, key)
	// Mark dead before unlinking — a worker that already pulled the
	// entry from the queue checks gen.Load() before flushing and
	// will no-op.
	entry.gen.Store(0)
	s.wheelMu.Lock()
	s.unlinkLocked(entry)
	s.wheelMu.Unlock()
	s.metricEntries.Add(-1)
}

// IsBreakerOpen reports whether the circuit breaker has tripped.
// UdpAC reads this at NHP-AOP admission to fail closed when the
// scheduler is no longer reliably flushing.
func (s *Scheduler) IsBreakerOpen() bool { return s.breakerOpen.Load() }

// EntryCount returns the number of currently scheduled entries.
// Useful for the scheduler_entries_total gauge.
func (s *Scheduler) EntryCount() int64 { return s.metricEntries.Load() }

// SnapshotKeys returns the live scheduled FlowKeys without changing their
// deadlines. Boot recovery uses this immediately after kernel enumeration to
// synchronously tear down inherited rules before the AC reports ready.
func (s *Scheduler) SnapshotKeys() []FlowKey {
	if s == nil {
		return nil
	}
	keys := make([]FlowKey, 0, max(0, int(s.metricEntries.Load())))
	for _, shard := range s.shards {
		shard.mu.Lock()
		for key, entry := range shard.entries {
			if entry != nil && entry.gen.Load() != 0 {
				keys = append(keys, key)
			}
		}
		shard.mu.Unlock()
	}
	return keys
}

// FlushMetrics snapshots the dispatch counters.
// FlushMetrics is the operator-facing snapshot of scheduler state.
//
// Counter semantics:
//   - FlushTotal — Flush calls that ran to a real outcome
//     (success OR non-canceled failure). Shutdown-canceled flushes
//     (context.Canceled while drain is in progress) are NOT counted;
//     under the L3-only contract those represent abandoned work the
//     next-process boot enumeration will recover.
//   - FlushErr — subset of FlushTotal that returned a non-canceled
//     error. Each contributes to breaker bookkeeping.
//   - FlushDryRun — entries logged-only because dryRun was true at
//     processEntry time. Counted instead of FlushTotal (they never
//     reach the flusher).
//   - FlushDeferred — every queue-full event seen, including the
//     final defer that immediately precedes a drop (see dispatch
//     comment).
//   - FlushDropped — entries the bounded backpressure dropped after
//     exhausting maxConsecutiveDefers. Each drop also forces the
//     breaker open.
//   - Entries — current live shard-index entries (sum across
//     shards).
//   - BucketMaxDepth — high-water mark of drained-bucket size; if
//     this approaches wheelSize the wheel is undersized for the
//     deadline distribution.
//   - BreakerOpen — current breaker state. Read by UdpAC's
//     admission gate to fail-closed.
//   - ScheduleRejected — Schedule calls rejected at the boundary
//     for a wall-clock-only deadline (no monotonic reading).
//     Non-zero means an upstream caller's time arithmetic
//     regressed — surface on dashboards
//   - ScheduleAfterShutdown — Schedule calls that arrived after
//     `started.Store(false)` flipped and were no-op'd. Boot enum on
//     the next process recovers any in-flight admission; this
//     counter surfaces frequency. Should be zero under steady
//     state; non-zero means an admission path is racing Shutdown.
//   - ScheduleWaitTimeout — Schedule calls where the existing
//     entry's in-flight Flush did not close inFlight within
//     flushCallTimeout + scheduleWaitSlop. Non-zero means the
//     flusher is stuck past its own per-call ctx; Schedule
//     proceeds anyway and the breaker will catch a chronically
//     stuck flusher independently. See #2168 + package godoc.
type FlushMetrics struct {
	Entries               int64
	FlushTotal            uint64
	FlushErr              uint64
	FlushDryRun           uint64
	FlushDeferred         uint64
	FlushDropped          uint64
	BucketMaxDepth        int64
	BreakerOpen           bool
	ScheduleRejected      uint64
	ScheduleAfterShutdown uint64
	ScheduleWaitTimeout   uint64
}

// Metrics returns a point-in-time snapshot of counters and gauges.
func (s *Scheduler) Metrics() FlushMetrics {
	return FlushMetrics{
		Entries:               s.metricEntries.Load(),
		FlushTotal:            s.metricFlushTotal.Load(),
		FlushErr:              s.metricFlushErr.Load(),
		FlushDryRun:           s.metricFlushDryRun.Load(),
		FlushDeferred:         s.metricFlushDeferred.Load(),
		FlushDropped:          s.metricFlushDropped.Load(),
		BucketMaxDepth:        s.metricBucketMaxDepth.Load(),
		BreakerOpen:           s.breakerOpen.Load(),
		ScheduleRejected:      s.metricScheduleRejected.Load(),
		ScheduleAfterShutdown: s.metricScheduleAfterShutdown.Load(),
		ScheduleWaitTimeout:   s.metricScheduleWaitTimeout.Load(),
	}
}

// ResetBreaker manually clears the open state. Reserved for test
// harnesses and the future operator runbook for "we fixed the
// flusher fault — resume normal admission." Production should NOT
// auto-recover the breaker; an opened breaker indicates a
// security-relevant flusher failure and operator review is required.
func (s *Scheduler) ResetBreaker() {
	s.breakerErrMu.Lock()
	s.breakerHead = 0
	s.breakerCount = 0
	for i := range s.breakerErrs {
		s.breakerErrs[i] = time.Time{}
	}
	s.breakerErrMu.Unlock()
	s.breakerOpen.Store(false)
}

// SetDryRun flips the live scheduler's dry-run mode at runtime.
// Used by updateBaseConfig so an operator who reloads config.toml
// with a new L3FlushDryRun value sees the change applied without
// an AC restart
func (s *Scheduler) SetDryRun(dry bool) {
	s.dryRun.Store(dry)
}

// SetBreakerParams updates the live circuit-breaker tunables.
// Threshold/window are read inside recordBreakerErr under
// breakerErrMu, so this writes them under the same mutex.
//
// NOTE: the breakerErrs ring is sized at construction from
// max(defaultBreakerErrLog, breakerThreshold); growing the
// threshold past the original size at runtime would silently cap
// the in-window count back to the ring size. Caller is responsible
// for restarting the AC if a threshold above the constructed ring
// is required — log a Warning at the call site rather than silently
// truncating.
func (s *Scheduler) SetBreakerParams(threshold int, window time.Duration) {
	// Reject zero / negative. Skipping the update keeps the
	// previously-good values rather than corrupting the live
	// scheduler with a typo'd TOML reload.
	if threshold <= 0 || window <= 0 {
		log.Warning("[ExpirySched] SetBreakerParams(threshold=%d, window=%s) rejected (both must be > 0); keeping prior values", threshold, window)
		return
	}
	// Defense-in-depth against silent loss of breaker protection:
	// the in-window count saturates at the ring size, so a
	// threshold above ring size means the breaker can never trip.
	// Clamp rather than store the unprotectable value — an
	// operator restart is the only way to grow the ring, and a
	// stored-but-unreachable threshold is an operator footgun.
	//
	// Warn-once dedup: operators reloading config.toml in a loop
	// with the same too-large threshold would otherwise flood logs
	// with identical warnings. Track the last-warned threshold under
	// breakerErrMu and emit only on change. When the threshold drops
	// back at-or-below ring size, emit a single INFO "protection
	// restored" line so operators get a clean recovery signal.
	//
	// Decide-under-lock, emit-after pattern: the lock-held section
	// only reads and writes scheduler state; the log calls happen
	// AFTER Unlock so a slow stderr / log-file rotation can't stall
	// the breaker's recordBreakerErr read path on the schedule loop.
	//
	// breakerErrs slice header is allocated once in NewScheduler
	// and never resliced, so reading len() lock-free here is safe.
	ringSize := len(s.breakerErrs)
	var (
		emitClampWarn    bool
		emitRestoreInfo  bool
		clampedThreshold = threshold
	)
	s.breakerErrMu.Lock()
	if threshold > ringSize {
		if s.lastBreakerClampWarnedThreshold != threshold {
			emitClampWarn = true
			s.lastBreakerClampWarnedThreshold = threshold
		}
		clampedThreshold = ringSize
	} else if s.lastBreakerClampWarnedThreshold != 0 {
		emitRestoreInfo = true
		s.lastBreakerClampWarnedThreshold = 0
	}
	s.breakerThreshold = clampedThreshold
	s.breakerWindow = window
	s.breakerErrMu.Unlock()

	if emitClampWarn {
		log.Warning("[ExpirySched] SetBreakerParams(threshold=%d) exceeds construct-time ring size %d; clamping to %d — restart the AC to grow the ring above this", threshold, ringSize, ringSize)
	} else if emitRestoreInfo {
		log.Info("[ExpirySched] SetBreakerParams(threshold=%d) is at-or-below ring size %d; clamp protection restored", threshold, ringSize)
	}
}

// BreakerRingSize returns the constructed-time size of the
// breaker's error-timestamp ring. SetBreakerParams callers can
// compare against this to detect threshold-exceeds-ring drift and
// log a restart-required warning.
func (s *Scheduler) BreakerRingSize() int {
	return len(s.breakerErrs)
}

// --- wheel internals (all callers MUST hold wheelMu) -----------------

// insertLocked places entry into the wheel bucket implied by its
// deadlineNs, or onto the overflow list if the deadline is beyond
// wheel coverage.
//
// Bucket math is **relative-to-now**: ticksFromNow = ceil((deadline
// - now) / tickInterval), bucket = (wheelHand + ticksFromNow) %
// wheelSize. This is the only formulation that doesn't require a
// wheelHand alignment invariant — past-or-now deadlines fall into
// bucket (wheelHand + 1) and fire on the next tick; in-frame
// deadlines land in their offset bucket relative to the current
// hand; deadlines past wheelSize ticks go to overflow.
//
// (An earlier absolute-tick formulation looked tempting but
// required `wheelHand == (wheelEpoch/tickNs) % wheelSize` at all
// times — a fragile invariant the wrap path complicates. The
// relative-tick formulation has no such invariant.)
func (s *Scheduler) insertLocked(entry *expiryEntry) {
	// Defensive: entry becomes the new head of whichever list it
	// lands on, so prev MUST be nil. Every current caller clears
	// this before calling, but a future call site that reuses an
	// entry without clearing prev would corrupt the list on the
	// next unlinkLocked (a stale prev pointer into a drained
	// bucket).
	entry.prev = nil
	tickNs := uint64(s.tickInterval.Nanoseconds())
	wheelSize := uint64(s.wheelSize)
	nowNs := nowMonoNs()

	var ticksFromNow uint64
	if entry.deadlineNs <= nowNs {
		// Past-or-now — fire on the next tick.
		ticksFromNow = 1
	} else {
		delta := entry.deadlineNs - nowNs
		// Ceiling division so a deadline 0.5 ticks in the future
		// lands 1 tick out, not 0 ticks. Floor-divide would put it
		// in the current bucket, racing the active tickOnce drain.
		ticksFromNow = (delta + tickNs - 1) / tickNs
		if ticksFromNow == 0 {
			ticksFromNow = 1
		}
	}

	if ticksFromNow >= wheelSize {
		entry.bucket = overflowBucketIdx
		entry.next = s.overflow
		if s.overflow != nil {
			s.overflow.prev = entry
		}
		s.overflow = entry
		return
	}

	entry.bucket = (s.wheelHand + uint32(ticksFromNow)) % uint32(wheelSize)
	head := s.wheel[entry.bucket]
	entry.next = head
	if head != nil {
		head.prev = entry
	}
	s.wheel[entry.bucket] = entry
}

// unlinkLocked removes entry from whichever list it lives on (wheel
// bucket or overflow). Safe to call on an already-unlinked entry.
func (s *Scheduler) unlinkLocked(entry *expiryEntry) {
	if entry.prev != nil {
		entry.prev.next = entry.next
	} else if entry.bucket == overflowBucketIdx {
		if s.overflow == entry {
			s.overflow = entry.next
		}
	} else if int(entry.bucket) < len(s.wheel) {
		if s.wheel[entry.bucket] == entry {
			s.wheel[entry.bucket] = entry.next
		}
	}
	if entry.next != nil {
		entry.next.prev = entry.prev
	}
	entry.next = nil
	entry.prev = nil
}

// --- tick loop -------------------------------------------------------

func (s *Scheduler) tickLoop() {
	defer s.tickerWg.Done()
	// A panic inside tickOnce would otherwise terminate this
	// goroutine permanently: the wheel hand freezes, every
	// scheduled entry leaks, and the only operator-visible signal
	// is eventual flush-queue saturation. Recover, route the
	// failure through the breaker (fail-closed admission), and
	// continue ticking — boot enumeration on restart will recover
	// from any state we couldn't reach.
	defer func() {
		if r := recover(); r != nil {
			s.metricFlushErr.Add(1)
			log.Error("[ExpirySched] tickLoop panic: %v\n%s", r, debug.Stack())
			s.recordBreakerErr()
		}
	}()
	ticker := time.NewTicker(s.tickInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.safeTickOnce()
		}
	}
}

// safeTickOnce wraps tickOnce with per-iteration panic recovery.
// Wrapping the outer tickLoop alone is insufficient — a single panic
// would kill the goroutine; wrapping each iteration keeps the ticker
// alive across transient bugs (e.g., a corrupt entry pointer in a
// single bucket) while still surfacing the failure through the
// breaker.
func (s *Scheduler) safeTickOnce() {
	defer func() {
		if r := recover(); r != nil {
			s.metricFlushErr.Add(1)
			log.Error("[ExpirySched] tickOnce panic: %v\n%s", r, debug.Stack())
			s.recordBreakerErr()
		}
	}()
	s.tickOnce()
}

// tickOnce advances the wheel hand by one bucket and dispatches
// that bucket's entries. Two-phase: (1) under wheelMu, splice the
// bucket out and null the per-entry next/prev pointers so a
// concurrent Cancel → unlinkLocked is a no-op on the drained
// entries; (2) outside the lock, push each to the bounded flush
// queue.
//
// **Overflow promotion** is performed on wheel-hand wrap (every
// wheelSize ticks; 6s at defaults). This is O(overflow_size) per
// wrap and is the dominant cost knob at fleet scale — see
// SCHEDULER_SCALING.md "wheel sizing" for the operator guidance on
// keeping most entries in-wheel rather than in overflow
//
// Backpressure semantics under the L3-only contract (no L7
// backstop): if the flush queue is full, re-bucket the entry for
// the next tick and increment metricFlushDeferred. After
// maxConsecutiveDefers re-bucket cycles, drop the entry, increment
// metricFlushDropped, and force the breaker open — silently late
// flushes are themselves a contract violation past that bound.
func (s *Scheduler) tickOnce() {
	s.wheelMu.Lock()

	bucketIdx := s.wheelHand
	bucketHead := s.wheel[bucketIdx]
	s.wheel[bucketIdx] = nil

	// Walk the drained chain under the lock, snapping next/prev to
	// nil so concurrent Cancel.unlinkLocked sees no list membership
	// and no-ops. Collect into a local slice for out-of-lock dispatch.
	//
	// TODO(scaling): per-tick slice alloc (1 per 10ms). A
	// Scheduler-resident reusable drain buffer (drainBuf[:0] at top
	// of tickOnce) would eliminate this alloc. Tracked in
	// SCHEDULER_SCALING.md's "allocation-free hot path" roadmap
	//
	var drained []*expiryEntry
	var depth int64
	for entry := bucketHead; entry != nil; {
		next := entry.next
		entry.next = nil
		entry.prev = nil
		drained = append(drained, entry)
		depth++
		entry = next
	}

	s.wheelHand = (s.wheelHand + 1) % uint32(s.wheelSize)

	// On wrap, walk the overflow list and re-insert each entry —
	// insertLocked recomputes ticksFromNow and either lands the
	// entry in a wheel bucket (if it now fits) or re-enqueues it
	// in overflow. O(overflow_size) per wrap; at 1M+ entries the
	// operator should size wheelSize so most entries land in-wheel
	// (see SCHEDULER_SCALING.md).
	if s.wheelHand == 0 && s.overflow != nil {
		overflow := s.overflow
		s.overflow = nil
		for entry := overflow; entry != nil; {
			next := entry.next
			entry.next = nil
			entry.prev = nil
			s.insertLocked(entry)
			entry = next
		}
	}

	s.wheelMu.Unlock()

	// CAS-loop the max-depth update so a future per-shard ticker
	// (SCHEDULER_SCALING.md roadmap item) can't lose updates against
	// a concurrent tick. Single-writer today; the loop costs one
	// extra Load on contention which is zero now
	for {
		cur := s.metricBucketMaxDepth.Load()
		if depth <= cur || s.metricBucketMaxDepth.CompareAndSwap(cur, depth) {
			break
		}
	}

	// Dispatch — outside wheelMu so a blocked channel send doesn't
	// stall Schedule/Cancel.
	for _, entry := range drained {
		s.dispatch(entry)
	}
}

// dispatch pushes one entry to the flush queue or, if the queue is
// full, re-buckets it for next tick. Bounded by
// maxConsecutiveDefers after which the entry is dropped and the
// breaker is forced open.
//
// Lock discipline: the two backpressure
// paths are mutually exclusive. The DROP path takes shard.mu (and
// never wheelMu) to remove the index entry. The RE-BUCKET path
// takes wheelMu (and never shard.mu) via insertLocked. No call
// site of dispatch ever holds either lock, so neither path inverts
// the documented shard.mu → wheelMu order.
//
// Shutdown-race acceptable: dispatch does
// NOT check `s.started.Load()` or `s.ctx.Err()`. If Shutdown's
// cancel() fires while a tick is mid-flight, dispatch can re-bucket
// entries that then sit in the wheel forever — boot enumeration on
// the next AC process recovers them at remaining-timeout, so the
// invariant holds without a started/ctx check here. (Adding a
// check would race against the cancel call without closing the
// underlying gap; recovery via boot-enum is the chosen approach.)
func (s *Scheduler) dispatch(entry *expiryEntry) {
	defer func() {
		if r := recover(); r != nil {
			s.metricFlushErr.Add(1)
			log.Error("[ExpirySched] dispatch panic on %s: %v\n%s", entry.FlowKey, r, debug.Stack())
			s.recordBreakerErr()
			// Symmetric with the explicit-drop path below: a panic
			// that prevents the index entry from being cleaned up
			// otherwise drifts metricEntries under sustained
			// breaker tripping — exactly when dashboards need to
			// be trustworthy. Best-effort cleanup; mirrors the
			// explicit-drop block at the end of dispatch.
			shard := s.shards[entry.FlowKey.shard()]
			shard.mu.Lock()
			if cur, ok := shard.entries[entry.FlowKey]; ok && cur == entry {
				delete(shard.entries, entry.FlowKey)
				s.metricEntries.Add(-1)
			}
			shard.mu.Unlock()
		}
	}()
	if entry.gen.Load() == 0 {
		// Cancel/Reschedule marked it dead between drain and dispatch.
		return
	}
	select {
	case s.flushQueue <- entry:
		return
	default:
	}

	// TODO(per-shard-tick): under the single-ticker model today,
	// dispatch is called from exactly one goroutine and deferCount
	// is a plain uint8. If SCHEDULER_SCALING.md's per-shard-ticker
	// roadmap lands, this becomes a multi-writer field — swap to
	// `atomic.Uint8` (and update the struct definition) at the same
	// time
	entry.deferCount++
	// metricFlushDeferred counts EVERY queue-full event for this
	// entry — including the final defer that immediately precedes
	// the drop. An eventually-dropped entry therefore contributes
	// (maxConsecutiveDefers+1) to Deferred and 1 to Dropped. Sum
	// is "queue-full events seen"; Dropped is "queue-full events
	// that won"
	s.metricFlushDeferred.Add(1)
	if entry.deferCount > maxConsecutiveDefers {
		s.metricFlushDropped.Add(1)
		// Drop. Force the breaker open — under L3-only the dropped
		// flush is unauthorized data past session end; UdpAC reads
		// IsBreakerOpen and refuses new NHP-AOPs.
		// Log entry.deferCount (the actual observed count) rather
		// than maxConsecutiveDefers (the threshold). With the
		// strictly-greater check above, a drop fires at
		// (maxConsecutiveDefers+1) deferrals; logging the threshold
		// is forensics-misleading.
		if s.breakerOpen.CompareAndSwap(false, true) {
			log.Error("[ExpirySched] circuit breaker OPEN: flush dropped after %d deferrals (%s); UdpAC must fail closed at admission",
				entry.deferCount, entry.FlowKey)
		} else {
			log.Error("[ExpirySched] flush dropped after %d deferrals: %s", entry.deferCount, entry.FlowKey)
		}
		// Best-effort: also drop the shard index entry so EntryCount
		// stays honest.
		shard := s.shards[entry.FlowKey.shard()]
		shard.mu.Lock()
		if cur, ok := shard.entries[entry.FlowKey]; ok && cur == entry {
			delete(shard.entries, entry.FlowKey)
			s.metricEntries.Add(-1)
		}
		shard.mu.Unlock()
		return
	}
	log.Warning("[ExpirySched] flush queue full (cap=%d); deferring %s (defer=%d/%d)",
		s.flushQueueCap, entry.FlowKey, entry.deferCount, maxConsecutiveDefers)
	// Re-bucket reuses the SAME *expiryEntry that was popped from
	// the prior bucket. shard.entries[key] still points to this
	// entry — no shard-index update needed, no memory growth.
	// metricEntries tracks shard-index size, which is unchanged.
	//
	// Intentionally NOT re-checking entry.gen.Load() after taking
	// wheelMu. A Cancel racing between the top-of-dispatch gen
	// check and insertLocked here would re-bucket a dead entry —
	// but the next tick's processEntry re-checks gen under
	// shard.mu and no-ops on gen==0, so the phantom is harmless
	// wasted work, not a leak. Widening lock scope to close this
	// window would invert the documented shard.mu → wheelMu order
	// (Cancel takes shard.mu then wheelMu); a re-check here would
	// NOT prevent the same race anyway since gen could flip after
	// the re-check too.
	s.wheelMu.Lock()
	s.insertLocked(entry)
	s.wheelMu.Unlock()
}

// --- worker pool -----------------------------------------------------

func (s *Scheduler) workerLoop() {
	defer s.workerWg.Done()
	// Defense-in-depth around processEntry's own deferred recover.
	// If recover() itself panics (extremely rare — typically a
	// runtime.Throw from the recover path under mutex contention),
	// the worker would otherwise die silently. A per-iteration
	// outer recover keeps the worker alive across the pathological
	// edge; one bad entry shouldn't halve the worker pool until AC
	// restart.
	for entry := range s.flushQueue {
		s.safeProcessEntry(entry)
	}
}

// safeProcessEntry wraps processEntry with an outer panic recovery
// so a panic inside processEntry's own deferred recover cannot kill
// the worker. Mirrors the safeTickOnce pattern at the ticker.
func (s *Scheduler) safeProcessEntry(entry *expiryEntry) {
	defer func() {
		if r := recover(); r != nil {
			s.metricFlushErr.Add(1)
			log.Error("[ExpirySched] workerLoop panic on %s: %v\n%s", entry.FlowKey, r, debug.Stack())
			s.recordBreakerErr()
		}
	}()
	s.processEntry(entry)
}

func (s *Scheduler) processEntry(entry *expiryEntry) {
	// Panic safety: a flusher-side nil-deref or other panic must NOT
	// crash the AC process. Matches the recoverUDPHandler discipline
	// used everywhere else on the AC's per-packet goroutines. Route
	// the failure through the breaker (same as a regular Flush error)
	// so the breaker's fail-closed-at-admission contract still
	// catches a flusher whose impl repeatedly panics — operator sees
	// a tripped breaker rather than a silently-restarted-by-systemd
	// AC
	defer func() {
		if r := recover(); r != nil {
			// Bump FlushTotal AND FlushErr to keep the FlushMetrics
			// godoc's "calls that ran to a real outcome" framing
			// consistent — a panic is a real outcome. Without
			// FlushTotal++, sustained-panic metrics dashboard would
			// show `FlushErr > FlushTotal`
			s.metricFlushTotal.Add(1)
			s.metricFlushErr.Add(1)
			log.Error("[ExpirySched] flusher panic on %s: %v\n%s", entry.FlowKey, r, debug.Stack())
			s.recordBreakerErr()
		}
	}()
	// TOCTOU: a concurrent Cancel/Reschedule may have set gen=0
	// between drain and now. Re-check under the shard lock so the
	// liveness decision is serialized against Schedule's index
	// update.
	//
	// Schedule/Flush race (#2168) is closed by inFlight: we allocate
	// the chan under shard.mu before releasing, leave the entry in
	// the index across Flush, and the deferred cleanup below
	// removes the index entry + closes inFlight after Flush returns.
	// Schedule waits on the open inFlight before inserting a new
	// entry for the same key, so a concurrent admission's kernel
	// allow-rule write cannot race the teardown.
	shard := s.shards[entry.FlowKey.shard()]
	shard.mu.Lock()
	if entry.gen.Load() == 0 {
		shard.mu.Unlock()
		return
	}
	// If the index now points at a DIFFERENT entry for this key,
	// this entry is a stale Reschedule remnant — the new entry is
	// in the wheel waiting for its later deadline. Flushing now
	// would tear down kernel state that the live entry will need
	// to flush itself, but never re-set. Skip.
	if cur, ok := shard.entries[entry.FlowKey]; !ok || cur != entry {
		shard.mu.Unlock()
		return
	}
	// Mark in-flight under shard.mu so a concurrent Schedule
	// observing this entry sees the non-nil chan and waits.
	// Allocated lazily here (not at Schedule time) so the
	// happy-path allocation cost lives on the flush hot path,
	// not on every admission.
	entry.inFlight = make(chan struct{})
	shard.mu.Unlock()

	// Cleanup: remove the index entry and close inFlight regardless
	// of what happens in Flush below (success / error / panic).
	// LIFO ordering puts this BEFORE the top-of-func recover defer
	// so the recover sees a fully cleaned-up scheduler state. The
	// secondary benefit: if cleanup itself panics (e.g., a future
	// regression that double-closes inFlight), the recover defer
	// is the last line of defense and the worker survives.
	defer func() {
		shard.mu.Lock()
		if cur, ok := shard.entries[entry.FlowKey]; ok && cur == entry {
			delete(shard.entries, entry.FlowKey)
			s.metricEntries.Add(-1)
		}
		shard.mu.Unlock()
		// close inFlight OUTSIDE the shard lock so a Schedule
		// goroutine woken by the close (Phase 1 wait) can
		// re-acquire shard.mu without contending against the
		// cleanup defer's own hold. Happens-before is established
		// by the chan close itself; the lock was only needed for
		// the index mutation above.
		close(entry.inFlight)
	}()

	if s.dryRun.Load() {
		s.metricFlushDryRun.Add(1)
		log.Info("[ExpirySched] dry-run flush: %s", entry.FlowKey)
		return
	}

	// Bail early if Shutdown has fired — Flush will fail with
	// context.Canceled and the resulting recordBreakerErr would
	// open the breaker on a clean shutdown
	if s.ctx.Err() != nil {
		return
	}

	ctx, cancel := context.WithTimeout(s.ctx, s.flushCallTimeout)
	// Safe without holding shard.mu: scheduleEntry can only set this bit while
	// entry.inFlight is nil; setting inFlight under shard.mu above makes later
	// RescheduleEarlier callers wait instead of writing this entry concurrently.
	if entry.authoritativeFlush {
		ctx = withAuthoritativeFlush(ctx)
	}
	err := s.flusher.Flush(ctx, entry.FlowKey)
	cancel()
	// context.Canceled means the scheduler's lifecycle ctx was
	// canceled mid-Flush — Shutdown is in progress; don't count this
	// against FlushTotal (which we want to read as "real flush
	// outcomes" for SLO math), don't bump FlushErr, and don't trip
	// the breaker on shutdown noise
	if errors.Is(err, context.Canceled) {
		return
	}
	s.metricFlushTotal.Add(1)
	if err != nil {
		s.metricFlushErr.Add(1)
		log.Error("[ExpirySched] flush %s: %v", entry.FlowKey, err)
		s.recordBreakerErr()
	}
}

// --- circuit breaker -------------------------------------------------

// recordBreakerErr stamps the current time into the error ring and
// counts in-window errors to decide whether to trip the breaker.
//
// Complexity note: the in-window
// count is O(breakerCount) which saturates at len(breakerErrs) =
// max(default, threshold). For a large operator-set threshold the
// per-error scan is O(threshold) under breakerErrMu. Tolerable in
// practice — by the time breakerCount approaches threshold the
// breaker is about to trip and admission fails closed, so error
// arrival rate drops sharply. A maintained running count with
// cursor-based expiry could amortize to O(1) if the breaker ever
// becomes a hot path under chaos; premature for the current target.
//
// Clock note: the breaker window is
// anchored on wall-clock time.Now(), NOT monotonic. This is by
// design — operators reason about breaker windows in wall-clock
// seconds (the L3FlushErrorWindowSec config field), and a window
// that stretches/compresses with NTP step is acceptable for the
// trip decision (a few ms of drift doesn't change the operational
// semantic). The scheduler's wheel + deadline math is monotonic
// because allow-rule expiry is a kernel-time concept; the breaker
// is an operator-time concept.
func (s *Scheduler) recordBreakerErr() {
	now := time.Now()
	s.breakerErrMu.Lock()
	s.breakerErrs[s.breakerHead] = now
	s.breakerHead = (s.breakerHead + 1) % len(s.breakerErrs)
	if s.breakerCount < len(s.breakerErrs) {
		s.breakerCount++
	}
	// Count errors within the window.
	cutoff := now.Add(-s.breakerWindow)
	count := 0
	for i := 0; i < s.breakerCount; i++ {
		if s.breakerErrs[i].After(cutoff) {
			count++
		}
	}
	// Capture threshold + window under the same lock that
	// SetBreakerParams writes them. Reading either outside the lock
	// would race against a concurrent live-reload — the trip decision
	// must be atomic with respect to the tunables it depends on
	//
	threshold := s.breakerThreshold
	window := s.breakerWindow
	s.breakerErrMu.Unlock()
	if count >= threshold && s.breakerOpen.CompareAndSwap(false, true) {
		log.Error("[ExpirySched] circuit breaker OPEN: %d errors within %s — UdpAC must fail closed at admission", count, window)
	}
}

// --- monotonic-clock helpers -----------------------------------------

// nowMonoNs returns the monotonic-clock reading in nanoseconds.
// Anchored against time.Now() so future-time arithmetic stays
// monotonic-safe (Add/Sub on a time.Time carries the monotonic
// reading).
func nowMonoNs() uint64 {
	return uint64(time.Since(zeroTime).Nanoseconds())
}

// monoNsAt converts a future time.Time into a monotonic-ns count
// from zeroTime. Requires t carry a monotonic reading — which it
// does when produced by time.Now() / Add / Sub (not Round(0) /
// time.Unix() / Unix-epoch reconstructions). Callers that pass a
// wall-clock-only time would get a value that drifts with NTP.
//
// The boundary check lives in Schedule, not here: a panic this
// deep in scheduler internals would DoS the AC on a programmer
// bug, where Schedule's no-op + Warning surfaces the bug as a
// missed schedule. Tests can call monoNsAt directly on
// wall-clock-only times and get a deterministic (if drifty) result
// rather than a panic.
func monoNsAt(t time.Time) uint64 {
	d := t.Sub(zeroTime)
	if d < 0 {
		return 0
	}
	return uint64(d.Nanoseconds())
}

// zeroTime is the package-load timestamp; serves as the monotonic
// epoch for nowMonoNs / monoNsAt. Initialized at init() with
// time.Now() which carries a monotonic reading — that monotonic
// anchor is required by every Sub against zeroTime below; do NOT
// "fix" this to time.Unix(0, 0) (which has no monotonic part).
var zeroTime time.Time

func init() {
	zeroTime = time.Now()
}
