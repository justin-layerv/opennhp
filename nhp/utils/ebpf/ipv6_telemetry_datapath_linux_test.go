//go:build linux

package ebpf

// This file is the E3 IPv6 (+ residual IPv4) FILTER-DECISION TELEMETRY proof. It
// is the in-kernel companion to the E2 verdict proofs in
// ipv6_admission_datapath_linux_test.go: those assert the XDP *verdict*
// (PASS/DROP); these assert that the program also EMITS the right perf EVENT,
// carrying the right addresses, for the eBPF observability path.
//
// WHY THIS EXISTS (the regression E3 closes): before E3 the v6 datapath emitted
// ACCEPT events with src/dst = 0 (struct event_t is IPv4-shaped) and emitted
// NOTHING on a v6 DROP (silent). iptables mode (prod today) logs v6 fully via
// [NHP-ACCEPT6]/[NHP-DENY6] LOG rules with full v6 addresses, so flipping
// FilterMode to eBPF (E5) would blind v6 filter logging. E3 adds a parallel v6
// event variant (struct event_t_v6 / events_v6 map / submit_event_v6) that
// carries the full 128-bit addresses, and adds DENY events at the v6 fail-closed
// + early-drop sites and the residual v4 early-DENY sites.
//
// WHAT IS PROVEN HERE (in-kernel, BPF_PROG_TEST_RUN — same harness contract as
// the E2 datapath proofs; LOUD-SKIP guard via skipOrFatal):
//
//	v6 ACCEPT — a v6 packet matching a seeded sdwhitelist_v6 rule is admitted AND
//	            emits an events_v6 ACCEPT event whose src/dst are the packet's
//	            REAL (non-zero) v6 addresses (not the pre-E3 zeros).
//	v6 DENY   — a v6 packet with no matching rule falls through to the v6
//	            fail-closed site and emits an events_v6 DENY event with the
//	            packet's real v6 addresses (pre-E3 this DROP was silent).
//	v4 DENY   — a v4 TCP packet truncated right after the IPv4 header hits the v4
//	            early-DENY (truncated-TCP) site and emits an `events` DENY event
//	            with the packet's real v4 addresses (residual v4 parity).
//
// The events_v6 / events maps are perf PERF_EVENT_ARRAYs; the reader is opened
// BEFORE prog.Run (so the sample the run produces is captured) and given a read
// deadline AFTER the run (so a MISSING event fails cleanly instead of hanging
// CI). bpf_perf_event_output(..., BPF_F_CURRENT_CPU, ...) writes to the CPU the
// TEST_RUN executes on; perf.Reader reads from all CPUs, so the event is found.

import (
	"bytes"
	"errors"
	"net"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"golang.org/x/sys/unix"
)

const (
	// eventsV6MapName / eventsMapName are the SEC(".maps") perf-array symbols in
	// nhp_ebpf_xdp.c (`} events_v6 SEC(".maps");` / `} events SEC(".maps");`). A
	// rename makes requireMap/Maps[...] return nil -> hard Fatal, the desired
	// fail-loud rather than a silent pass.
	eventsV6MapName = "events_v6"
	eventsMapName   = "events"

	// #2849 rate-limiter maps (mirror the SEC(".maps") symbols added in
	// nhp_ebpf_xdp.c): deny_rl_config (regular ARRAY holding {capacity,
	// refill_per_sec} the test seeds) and deny_suppressed (PERCPU_ARRAY counter
	// the test sums across CPUs).
	denyRlConfigMapName   = "deny_rl_config"
	denySuppressedMapName = "deny_suppressed"

	// Wire sizes of the perf event records, mirrored from the C structs (and the
	// Go EventV6/Event structs). event_t_v6 is __packed at 48 bytes
	// (_Static_assert in nhp_ebpf_xdp.c); event_t is __packed at 24 bytes.
	eventV6WireSize = 48
	eventV4WireSize = 24

	// Field offsets inside a packed event_t_v6 record (mirror the C struct and
	// endpoints/ac/ebpf/event_format.go). Used to read back the action + the
	// 16-byte addresses the datapath emitted.
	ev6OffAction = 8  // __u8 action
	ev6OffSrcIP  = 9  // struct in6_addr src_ip (16 bytes, network order)
	ev6OffDstIP  = 25 // struct in6_addr dst_ip (16 bytes, network order)

	// Field offsets inside a packed event_t (v4). action @8, src @9, dst @13
	// (__be32 each). Mirrors the production v4 reader's offset parse.
	ev4OffAction = 8
	ev4OffSrcIP  = 9
	ev4OffDstIP  = 13

	// Event action byte values (0 = DENY, 1 = ACCEPT), matching submit_event*.
	evActionDeny   = 0
	evActionAccept = 1

	// perfReadTimeout bounds the post-run perf read so a MISSING event fails the
	// test cleanly (deadline -> os.ErrDeadlineExceeded) instead of blocking CI on
	// a hung Read. Generous vs the in-process kernel write that just happened.
	perfReadTimeout = 2 * time.Second
)

// openPerfReader opens a perf.Reader on the named perf-array map BEFORE the
// program runs, so the sample produced by prog.Run is captured. Any open error
// folds into the LOUD-SKIP guard (a perf-buffer open failure is an environment
// problem on a locked-down kernel, like the load failures). The caller defers
// the returned close.
func openPerfReader(t *testing.T, m *ebpf.Map) (*perf.Reader, func()) {
	t.Helper()
	rd, err := perf.NewReader(m, 4096)
	if err != nil {
		skipOrFatal(t, "perf.NewReader (open perf buffer for the telemetry read): %v", err)
		return nil, func() {}
	}
	return rd, func() { _ = rd.Close() }
}

// readOneEvent reads exactly one perf sample with a deadline. It returns the raw
// sample bytes. A deadline timeout means the datapath did NOT emit the expected
// event — a real test failure (the whole point of E3), so it is a hard Fatal
// with a descriptive message, NOT folded into the skip guard. LostSamples on
// this tiny single-event run would indicate a buffer/CPU problem, also fatal.
func readOneEvent(t *testing.T, rd *perf.Reader, wantSize int, ctx string) []byte {
	t.Helper()
	rd.SetDeadline(time.Now().Add(perfReadTimeout))
	rec, err := rd.Read()
	if err != nil {
		if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, unix.EAGAIN) {
			t.Fatalf("%s: no perf event within %s — the datapath did NOT emit the expected event (E3 regression: the emission is missing or went to the wrong map)", ctx, perfReadTimeout)
		}
		t.Fatalf("%s: perf read failed: %v", ctx, err)
	}
	if rec.LostSamples > 0 {
		t.Fatalf("%s: perf buffer reported %d lost samples on a single-event run (CPU/buffer problem)", ctx, rec.LostSamples)
	}
	if len(rec.RawSample) < wantSize {
		t.Fatalf("%s: perf sample too short: got %d bytes, want >= %d (event struct size drift?)", ctx, len(rec.RawSample), wantSize)
	}
	return rec.RawSample
}

// assertNoMoreEvents asserts the reader has no further buffered sample within a
// short deadline — i.e. the datapath emitted EXACTLY ONE event for the packet,
// not a duplicate. A second event would mean a double-emit (e.g. an ACCEPT and a
// stray DENY), which would corrupt the log stream.
func assertNoMoreEvents(t *testing.T, rd *perf.Reader, ctx string) {
	t.Helper()
	rd.SetDeadline(time.Now().Add(250 * time.Millisecond))
	rec, err := rd.Read()
	if err == nil {
		t.Fatalf("%s: unexpected SECOND perf event (action=%d) — the datapath emitted more than one event for a single packet", ctx, rec.RawSample[ev6OffAction])
	}
	if !errors.Is(err, os.ErrDeadlineExceeded) && !errors.Is(err, unix.EAGAIN) {
		t.Fatalf("%s: unexpected error draining perf buffer: %v", ctx, err)
	}
}

// TestIPv6TelemetryAcceptCarriesAddrs is the E3 v6-ACCEPT proof: a v6 packet
// matching a seeded sdwhitelist_v6 rule is admitted (XDP_PASS) AND emits an
// events_v6 ACCEPT event whose src/dst are the packet's REAL v6 addresses — the
// exact regression E3 fixes (pre-E3 the v6 ACCEPT carried src/dst = 0).
func TestIPv6TelemetryAcceptCarriesAddrs(t *testing.T) {
	prog, coll, cleanup := loadXDPCollectionV6(t)
	if cleanup != nil {
		defer cleanup()
	}
	sdMap := requireMap(t, coll, sdWhitelistV6MapName)
	eventsV6 := requireMap(t, coll, eventsV6MapName)

	allowedSrc, dstIP, _ := v6TestAddrs(t)
	const (
		srcPort uint16 = 51000
		dstPort uint16 = 443
	)

	// Seed sdwhitelist_v6[src=allowedSrc, dst=dstIP] = {allowed:1, never-expire}.
	sdKey := (&srcDestKeyV6{SrcIP: allowedSrc, DstIP: dstIP}).ToSdKeyV6()
	sdVal := seedWhitelistValue(t, sdMap.ValueSize())
	if err := sdMap.Put(sdKey, sdVal); err != nil {
		t.Fatalf("seed sdwhitelist_v6[allow]: %v", err)
	}

	allowPkt := craftTCPv6Packet(t, allowedSrc, dstIP, srcPort, dstPort)

	rd, closeRd := openPerfReader(t, eventsV6)
	defer closeRd()

	// Verdict first (PASS), then read the event the run produced.
	if got := runVerdict(t, prog, allowPkt); got != xdpPass {
		t.Fatalf("v6 ACCEPT telemetry: verdict = %d (%s), want XDP_PASS(%d) — the sdwhitelist_v6 rule must admit before we can assert the ACCEPT event",
			got, xdpName(got), xdpPass)
	}

	raw := readOneEvent(t, rd, eventV6WireSize, "v6 ACCEPT telemetry")
	if action := raw[ev6OffAction]; action != evActionAccept {
		t.Fatalf("v6 ACCEPT telemetry: event action = %d, want ACCEPT(%d)", action, evActionAccept)
	}
	gotSrc := raw[ev6OffSrcIP : ev6OffSrcIP+16]
	gotDst := raw[ev6OffDstIP : ev6OffDstIP+16]

	// The load-bearing assertion: addresses are the packet's REAL v6 addresses,
	// NOT zero. A zeroed src/dst here is precisely the pre-E3 regression.
	if isAllZero(gotSrc) || isAllZero(gotDst) {
		t.Fatalf("v6 ACCEPT telemetry: event carries ZEROED addresses (src=% x dst=% x) — this is the pre-E3 regression (v6 ACCEPT events lost their addresses); submit_event_v6 must pass ip6h->saddr/daddr", gotSrc, gotDst)
	}
	if !bytes.Equal(gotSrc, allowedSrc[:]) {
		t.Fatalf("v6 ACCEPT telemetry: event src = % x, want % x (the packet's source address)", gotSrc, allowedSrc[:])
	}
	if !bytes.Equal(gotDst, dstIP[:]) {
		t.Fatalf("v6 ACCEPT telemetry: event dst = % x, want % x (the packet's dest address)", gotDst, dstIP[:])
	}
	t.Logf("v6 ACCEPT event OK: src=%s dst=%s (non-zero, matches packet)", net.IP(gotSrc).String(), net.IP(gotDst).String())

	assertNoMoreEvents(t, rd, "v6 ACCEPT telemetry")
}

// TestIPv6TelemetryDenyEmitsEvent is the E3 v6-DENY proof: a v6 packet with NO
// matching allow-rule falls through to the v6 fail-closed site, is DROPped, AND
// emits an events_v6 DENY event with the packet's real v6 addresses — pre-E3
// this DROP was SILENT (no v6 DENY event existed at all).
func TestIPv6TelemetryDenyEmitsEvent(t *testing.T) {
	prog, coll, cleanup := loadXDPCollectionV6(t)
	if cleanup != nil {
		defer cleanup()
	}
	eventsV6 := requireMap(t, coll, eventsV6MapName)

	// No rule seeded -> the packet misses the whole cascade and hits the v6
	// fail-closed submit_event_v6(0, ...). Use the "denied" source for clarity.
	_, dstIP, deniedSrc := v6TestAddrs(t)
	const (
		srcPort uint16 = 51000
		dstPort uint16 = 443
	)
	denyPkt := craftTCPv6Packet(t, deniedSrc, dstIP, srcPort, dstPort)

	rd, closeRd := openPerfReader(t, eventsV6)
	defer closeRd()

	if got := runVerdict(t, prog, denyPkt); got != xdpDrop {
		t.Fatalf("v6 DENY telemetry: verdict = %d (%s), want XDP_DROP(%d) — an unmatched v6 packet must fail closed before we can assert the DENY event",
			got, xdpName(got), xdpDrop)
	}

	raw := readOneEvent(t, rd, eventV6WireSize, "v6 DENY telemetry")
	if action := raw[ev6OffAction]; action != evActionDeny {
		t.Fatalf("v6 DENY telemetry: event action = %d, want DENY(%d)", action, evActionDeny)
	}
	gotSrc := raw[ev6OffSrcIP : ev6OffSrcIP+16]
	gotDst := raw[ev6OffDstIP : ev6OffDstIP+16]
	if isAllZero(gotSrc) || isAllZero(gotDst) {
		t.Fatalf("v6 DENY telemetry: event carries ZEROED addresses (src=% x dst=% x) — the fail-closed DENY must carry the packet's real addresses", gotSrc, gotDst)
	}
	if !bytes.Equal(gotSrc, deniedSrc[:]) {
		t.Fatalf("v6 DENY telemetry: event src = % x, want % x (the packet's source address)", gotSrc, deniedSrc[:])
	}
	if !bytes.Equal(gotDst, dstIP[:]) {
		t.Fatalf("v6 DENY telemetry: event dst = % x, want % x (the packet's dest address)", gotDst, dstIP[:])
	}
	t.Logf("v6 DENY event OK: src=%s dst=%s (non-zero, matches packet)", net.IP(gotSrc).String(), net.IP(gotDst).String())

	assertNoMoreEvents(t, rd, "v6 DENY telemetry")
}

// TestIPv4TelemetryEarlyDenyEmitsEvent is the E3 residual-v4 proof: a v4 TCP
// packet truncated right after the IPv4 header (no room for the TCP header) hits
// the v4 early-DENY (truncated-TCP) site, is DROPped, AND emits an `events` DENY
// event with the packet's real v4 addresses. Pre-E3 that early drop was silent.
//
// The packet is eth(14) + IPv4(20, ihl=5, proto=TCP) with NO TCP bytes, so
// `(void *)(tcp + 1) > data_end` fires at the FIRST v4 TCP bounds check
// (nhp_ebpf_xdp.c), which now emits submit_event(0, iph->saddr, iph->daddr, ...)
// before XDP_DROP. Addresses are real; ports are 0 (not parsed at that point).
func TestIPv4TelemetryEarlyDenyEmitsEvent(t *testing.T) {
	// loadXDPCollectionV6 loads the SAME object/program as loadXDPCollection and
	// returns the whole collection, so we can fetch the v4 `events` map from it.
	// requireMap is a generic "named map or hard-Fatal" helper (not v6-specific).
	prog, coll, cleanup := loadXDPCollectionV6(t)
	if cleanup != nil {
		defer cleanup()
	}
	eventsV4 := requireMap(t, coll, eventsMapName)

	srcIP := net.ParseIP("10.1.2.3")
	dstIP := net.ParseIP("10.9.8.7")
	truncPkt := craftTruncatedTCPv4Packet(t, srcIP, dstIP)

	rd, closeRd := openPerfReader(t, eventsV4)
	defer closeRd()

	if got := runVerdict(t, prog, truncPkt); got != xdpDrop {
		t.Fatalf("v4 early-DENY telemetry: verdict = %d (%s), want XDP_DROP(%d) — a TCP packet truncated after the IPv4 header must DROP at the v4 truncated-TCP site",
			got, xdpName(got), xdpDrop)
	}

	raw := readOneEvent(t, rd, eventV4WireSize, "v4 early-DENY telemetry")
	if action := raw[ev4OffAction]; action != evActionDeny {
		t.Fatalf("v4 early-DENY telemetry: event action = %d, want DENY(%d)", action, evActionDeny)
	}
	// v4 addresses are __be32 (network order); the packet's src/dst are the wire
	// bytes, so compare the 4-byte fields directly against To4().
	gotSrc := raw[ev4OffSrcIP : ev4OffSrcIP+4]
	gotDst := raw[ev4OffDstIP : ev4OffDstIP+4]
	if isAllZero(gotSrc) || isAllZero(gotDst) {
		t.Fatalf("v4 early-DENY telemetry: event carries ZEROED addresses (src=% x dst=% x) — the truncated-TCP DENY must carry the recoverable v4 addresses", gotSrc, gotDst)
	}
	if !bytes.Equal(gotSrc, srcIP.To4()) {
		t.Fatalf("v4 early-DENY telemetry: event src = % x, want % x", gotSrc, srcIP.To4())
	}
	if !bytes.Equal(gotDst, dstIP.To4()) {
		t.Fatalf("v4 early-DENY telemetry: event dst = % x, want % x", gotDst, dstIP.To4())
	}
	t.Logf("v4 early-DENY event OK: src=%s dst=%s (non-zero, matches packet)", net.IP(gotSrc).String(), net.IP(gotDst).String())
}

// craftTruncatedTCPv4Packet builds eth(14) + IPv4(20, ihl=5, proto=TCP) with NO
// TCP header bytes, so the XDP program's first v4 TCP bounds check
// (`(void *)(tcp + 1) > data_end`) fires and takes the E3 early-DENY path. The
// IPv4 header itself is well-formed (ihl=5, addresses present) so the addresses
// are recoverable for the emitted event.
func craftTruncatedTCPv4Packet(t *testing.T, srcIP, dstIP net.IP) []byte {
	t.Helper()
	src4 := srcIP.To4()
	dst4 := dstIP.To4()
	if src4 == nil || dst4 == nil {
		t.Fatalf("craftTruncatedTCPv4Packet: non-IPv4 address (src=%v dst=%v)", srcIP, dstIP)
	}
	pkt := make([]byte, 0, 34)
	// Ethernet (14): EtherType IPv4.
	pkt = append(pkt,
		0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x02, 0x00, 0x00, 0x00, 0x00, 0x02,
		0x08, 0x00,
	)
	// IPv4 header (20, ihl=5, proto=TCP) — deliberately the LAST bytes of the
	// frame, so there is no room for a TCP header after it.
	ip := make([]byte, 20)
	ip[0] = 0x45 // version 4, ihl 5
	ip[9] = 6    // protocol TCP
	copy(ip[12:16], src4)
	copy(ip[16:20], dst4)
	pkt = append(pkt, ip...)
	return pkt
}

// isAllZero reports whether every byte in b is zero (used to detect the pre-E3
// zeroed-address regression).
func isAllZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

// --- #2849 DENY-telemetry rate-limiter proof ---
//
// These assert the per-CPU token bucket gating the malformed/early-drop DENY
// sites: under a flood of gated DENYs it emits at most `capacity` events and
// COUNTS the rest in deny_suppressed (never silently drops). The proof is
// DETERMINISTIC by construction — the config is seeded with refill_per_sec=0, so
// the bucket starts full and NEVER refills, making the emit/suppress split a pure
// function of (capacity, packet-count) with ZERO dependence on wall-clock /
// bpf_ktime (a refill-rate-based test would be flaky: ktime advances by real time
// between TEST_RUN calls). The test pins to one CPU so the per-CPU bucket is the
// same across every BPF_PROG_TEST_RUN — otherwise runs spread across CPUs, each
// CPU's bucket independently allows `capacity`, and the count is nondeterministic.

// denyRlConfigValue mirrors `struct deny_rl_config_t` (two __u64, native order)
// in nhp_ebpf_xdp.c — the value the test writes into deny_rl_config[0] to drive
// the bucket. (The production AC has its own copy in endpoints/ac/ebpf; this is
// the nhp-module test's local mirror.)
type denyRlConfigValue struct {
	Capacity     uint64
	RefillPerSec uint64
}

// pinToCPU0 pins the calling goroutine to a single CPU for the rest of the test,
// so the per-CPU deny_rl_state bucket is consistent across every BPF_PROG_TEST_RUN
// (bpf_ktime + per-CPU state mean a migrating run would hit a different, full
// bucket). A SchedSetaffinity failure is an environment problem → LOUD-SKIP guard
// (hard-fails under NHP_REQUIRE_BPF_TESTS=1).
func pinToCPU0(t *testing.T) {
	t.Helper()
	runtime.LockOSThread()
	t.Cleanup(runtime.UnlockOSThread)
	var set unix.CPUSet
	set.Set(0)
	if err := unix.SchedSetaffinity(0, &set); err != nil {
		skipOrFatal(t, "SchedSetaffinity to CPU 0 (pin the per-CPU token bucket so the count is deterministic): %v", err)
	}
}

// drainCountEvents reads every buffered perf sample (>= wantSize bytes) until the
// reader times out, returning the count. Used to count how many DENY events the
// rate limiter let through. A LostSamples on this small run means the buffer was
// too small or a CPU problem — fatal, not a silent undercount.
func drainCountEvents(t *testing.T, rd *perf.Reader, wantSize int) int {
	t.Helper()
	count := 0
	for {
		rd.SetDeadline(time.Now().Add(perfReadTimeout))
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, unix.EAGAIN) {
				return count // no more buffered events
			}
			t.Fatalf("drain perf buffer: %v", err)
		}
		if rec.LostSamples > 0 {
			t.Fatalf("drain: perf buffer reported %d lost samples (buffer too small / CPU problem) — count would be unreliable", rec.LostSamples)
		}
		if len(rec.RawSample) >= wantSize {
			count++
		}
	}
}

// setupRateLimiterTest loads a fresh collection (fresh, zero-valued maps), pins to
// one CPU (so the per-CPU token bucket is consistent across BPF_PROG_TEST_RUN
// calls), resolves the rate-limiter maps, and opens a perf reader on `events`
// BEFORE any run. Cleanups are test-scoped. Shared by the rate-limiter scenarios.
func setupRateLimiterTest(t *testing.T) (prog *ebpf.Program, cfgMap, suppressedMap *ebpf.Map, rd *perf.Reader) {
	t.Helper()
	pinToCPU0(t)
	prog, coll, cleanup := loadXDPCollectionV6(t)
	if cleanup != nil {
		t.Cleanup(cleanup)
	}
	eventsV4 := requireMap(t, coll, eventsMapName)
	cfgMap = requireMap(t, coll, denyRlConfigMapName)
	suppressedMap = requireMap(t, coll, denySuppressedMapName)
	rd, closeRd := openPerfReader(t, eventsV4)
	t.Cleanup(closeRd)
	return prog, cfgMap, suppressedMap, rd
}

// fireGatedDENYPackets runs n truncated-TCP v4 packets through the program; each
// must DROP at a #2849-gated early-DENY site (craftTruncatedTCPv4Packet). Shared
// by the rate-limiter tests.
func fireGatedDENYPackets(t *testing.T, prog *ebpf.Program, pkt []byte, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if got := runVerdict(t, prog, pkt); got != xdpDrop {
			t.Fatalf("run %d: verdict = %d (%s), want XDP_DROP at the gated early-DENY site", i, got, xdpName(got))
		}
	}
}

// sumSuppressed reads the per-CPU deny_suppressed counter (key 0) and sums it
// across CPUs — the cumulative count of DENY events the limiter has shed.
func sumSuppressed(t *testing.T, suppressedMap *ebpf.Map) uint64 {
	t.Helper()
	var perCPU []uint64
	if err := suppressedMap.Lookup(uint32(0), &perCPU); err != nil {
		t.Fatalf("read deny_suppressed (per-CPU): %v", err)
	}
	var total uint64
	for _, v := range perCPU {
		total += v
	}
	return total
}

// runRateLimitScenario seeds deny_rl_config={capacity, refill_per_sec:0} (full
// bucket, never refills ⇒ deterministic), fires `total` gated DENY packets, and
// returns how many DENY events reached `events` and the summed deny_suppressed
// counter.
func runRateLimitScenario(t *testing.T, capacity uint64, total int) (emitted int, suppressed uint64) {
	t.Helper()
	prog, cfgMap, suppressedMap, rd := setupRateLimiterTest(t)

	if err := cfgMap.Put(uint32(0), &denyRlConfigValue{Capacity: capacity, RefillPerSec: 0}); err != nil {
		t.Fatalf("seed deny_rl_config{capacity:%d, refill:0}: %v", capacity, err)
	}
	pkt := craftTruncatedTCPv4Packet(t, net.ParseIP("10.1.2.3"), net.ParseIP("10.9.8.7"))
	fireGatedDENYPackets(t, prog, pkt, total)

	return drainCountEvents(t, rd, eventV4WireSize), sumSuppressed(t, suppressedMap)
}

// TestDenyTelemetryRateLimiterShedsAndCounts is the load-bearing #2849 proof:
// with capacity=N and N+M gated DENY packets, EXACTLY N events are emitted and the
// other M are counted in deny_suppressed — the limiter caps the flood without
// silently losing telemetry.
func TestDenyTelemetryRateLimiterShedsAndCounts(t *testing.T) {
	const capacity uint64 = 3
	const total = 5 // capacity (3) emitted + 2 suppressed
	emitted, suppressed := runRateLimitScenario(t, capacity, total)

	if emitted != int(capacity) {
		t.Fatalf("emitted %d DENY events for %d gated packets, want EXACTLY %d (capacity) — the token bucket must emit N then shed the rest", emitted, total, capacity)
	}
	if want := uint64(total) - capacity; suppressed != want {
		t.Fatalf("deny_suppressed = %d, want %d (the packets beyond capacity) — the limiter must COUNT what it sheds, never silently drop", suppressed, want)
	}
	t.Logf("rate-limiter OK: %d gated packets -> %d emitted + %d suppressed (capacity=%d, refill=0, deterministic)", total, emitted, suppressed, capacity)
}

// TestDenyTelemetryRateLimiterGenerousCapacityEmitsAll proves the limiter does NOT
// over-suppress: with capacity far above the packet count, every gated DENY has a
// token, so all emit and deny_suppressed stays 0. A limiter that just dropped
// everything (or mis-computed the bucket) would fail here.
func TestDenyTelemetryRateLimiterGenerousCapacityEmitsAll(t *testing.T) {
	const total = 5
	const capacity uint64 = 100
	emitted, suppressed := runRateLimitScenario(t, capacity, total)

	if emitted != total {
		t.Fatalf("emitted %d of %d gated DENYs under generous capacity %d, want all %d — the limiter must not shed below capacity", emitted, total, capacity, total)
	}
	if suppressed != 0 {
		t.Fatalf("deny_suppressed = %d under generous capacity, want 0 — nothing should be shed when under the cap", suppressed)
	}
}

// TestDenyTelemetryRateLimiterRetuneDownClampsImmediately proves the runtime
// downward-retune path (cr #1): lowering deny_rl_config.capacity while the bucket
// holds MORE tokens than the new cap takes effect on the NEXT decision (the
// unconditional clamp in should_emit_deny_event), not after a refill tick.
// refill_per_sec=0 throughout, so the ONLY thing that can lower the live token
// count is the clamp — a clean proof of the clamp itself, not of refill timing.
// Without the clamp, phase 2 would drain from the old (higher) level and emit 5;
// with it, exactly 2 emit then the rest are shed.
func TestDenyTelemetryRateLimiterRetuneDownClampsImmediately(t *testing.T) {
	prog, cfgMap, suppressedMap, rd := setupRateLimiterTest(t)
	pkt := craftTruncatedTCPv4Packet(t, net.ParseIP("10.1.2.3"), net.ParseIP("10.9.8.7"))

	// Phase 1: high cap, fire 3 → all emit (bucket 10 -> 7, refill=0 so no refill).
	if err := cfgMap.Put(uint32(0), &denyRlConfigValue{Capacity: 10, RefillPerSec: 0}); err != nil {
		t.Fatalf("seed cap=10: %v", err)
	}
	fireGatedDENYPackets(t, prog, pkt, 3)
	if got := drainCountEvents(t, rd, eventV4WireSize); got != 3 {
		t.Fatalf("phase 1: emitted %d of 3 under cap=10, want 3", got)
	}

	// Phase 2: retune DOWN to 2 with ~7 tokens still live. The clamp lowers the
	// bucket to 2 on the next decision → exactly 2 more emit, then shed.
	if err := cfgMap.Put(uint32(0), &denyRlConfigValue{Capacity: 2, RefillPerSec: 0}); err != nil {
		t.Fatalf("retune cap=2: %v", err)
	}
	fireGatedDENYPackets(t, prog, pkt, 5) // expect 2 emit (clamped) + 3 suppressed
	if got := drainCountEvents(t, rd, eventV4WireSize); got != 2 {
		t.Fatalf("phase 2: emitted %d after retune-down to cap=2, want EXACTLY 2 — the downward retune must clamp the live bucket immediately (cr #1); without the clamp the bucket would drain from the old level", got)
	}
	if got := sumSuppressed(t, suppressedMap); got != 3 {
		t.Fatalf("deny_suppressed = %d after retune-down, want 3 (the packets beyond the new cap)", got)
	}
	t.Logf("retune-down OK: cap 10->2 mid-flight -> 2 emitted + 3 suppressed (clamp took effect immediately)")
}
