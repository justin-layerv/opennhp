//go:build linux

package ebpf

// This file is the #2779 surgical-kill DATAPATH proof. It closes the
// "DEEPEST PROOF GAP" called out in conntrack_delete_linux_test.go:
//
//	deleting the conntrack entry actually drops the next REAL packet
//	through the XDP program while the sibling keeps passing.
//
// The map-op tests in conntrack_delete_linux_test.go prove the delete
// targets exactly one 5-tuple. They do NOT exercise the XDP datapath's
// established-flow short-circuit (the `bpf_map_lookup_elem(&conn_track)`
// -> XDP_PASS path in nhp_ebpf_xdp.c). This test does: it loads the REAL
// compiled XDP object, drives SYNTHETIC packets through it via the kernel
// BPF_PROG_TEST_RUN syscall (cilium/ebpf Program.Run), and asserts the
// verdict flips PASS -> DROP for the target after its conntrack entry is
// surgically deleted, while a same-allow-rule sibling (distinct source
// port) keeps PASSing.
//
// WHY conn_track-only (no whitelist seed): the surgical kill models an
// already-established, already-admitted flow whose admission has been
// revoked. The conntrack entry is what keeps an in-flight connection
// alive across packets (the XDP established-flow short-circuit). If we
// also seeded the `spp` allow-rule, deleting conntrack would let the next
// packet be RE-ADMITTED by the whitelist and a fresh conntrack entry
// created -> XDP_PASS, defeating the proof. Seeding conn_track ONLY is the
// faithful model: PASS while the conntrack entry exists, DROP once it is
// flushed and no allow-rule re-admits. This mirrors P4c's map-op test,
// which also seeds conn_track only.
//
// EXECUTION / CI: needs CAP_BPF (or CAP_SYS_ADMIN) + a kernel that loads
// XDP + the compiled object at the path resolved by NHP_EBPF_XDP_OBJECT.
// Run via `make test-ebpf`. LOUD-SKIP guard (memory:
// feedback_silent_failure_patterns.md): with NHP_REQUIRE_BPF_TESTS=1 any
// missing capability / kernel support / missing object is a hard t.Fatal,
// never a silent skip-pass.
//
// NOTE on the skip path: `make test-ebpf` exports NHP_REQUIRE_BPF_TESTS=1
// (Makefile `:-1` default), so running it on a laptop without CAP_BPF /
// kernel XDP support HARD-FAILS by design — the graceful t.Skip only
// applies when you invoke the package directly with the var unset, e.g.
// `go test ./utils/ebpf/...`. (NHP_REQUIRE_BPF_TESTS=0 also skips — the
// guard is "required" only when the value is exactly "1", matching the
// sibling conntrack tests.)
//
// REAL-KERNEL ONLY: BPF_PROG_TEST_RUN executes the verifier-accepted
// bytecode in-kernel, exactly the instructions a live NIC's XDP hook runs.
// It is NOT a userspace re-implementation. The one thing it does not cover
// vs a live NIC is driver-mode XDP (native/offload) packet ingress framing;
// the verdict logic exercised here (header parse + conntrack short-circuit
// + allow-rule fallthrough) is identical on both paths. See the caveat note
// at the bottom of TestSurgicalKillDatapath.

import (
	"encoding/binary"
	"errors"
	"net"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

const (
	// XDP verdict return codes (uapi/linux/bpf.h). Program.Run returns the
	// XDP action the program returned for the synthetic packet.
	xdpAborted uint32 = 0
	xdpDrop    uint32 = 1
	xdpPass    uint32 = 2

	// xdpProgName / connTrack*MapName are the SEC-declared symbol names in
	// nhp_ebpf_xdp.c: `SEC("xdp")` on `xdp_white_prog`, and the conntrack BPF
	// maps. A rename in the C source breaks the lookup loudly (nil program /
	// nil map -> guard Fatal/Skip), which is the desired fail-loud, not a silent
	// pass.
	xdpProgName        = "xdp_white_prog"
	connTrackMapName   = "conn_track"
	connTrackV6MapName = "conn_track_v6"

	// requireBPFEnv gates skip-vs-fatal. Set in CI (make test-ebpf defaults
	// it to 1) so a host that cannot load the object FAILS instead of
	// skip-passing. Unset on dev laptops -> loud t.Skip.
	requireBPFEnv = "NHP_REQUIRE_BPF_TESTS"
	// objectPathEnv is set by `make test-ebpf` to the abspath of the
	// compiled nhp_ebpf_xdp.o.
	objectPathEnv = "NHP_EBPF_XDP_OBJECT"
)

// connValTimestampOff and connValTTLOff are the byte offsets within
// `struct conn_value` that the XDP expiry check reads (check_conn_expiry:
// `now > timestamp + ttl_ns`). conn_value is NOT __packed, so it carries
// natural alignment;
// timestamp and ttl_ns are the first and third __u64 members, at fixed
// offsets 0 and 16 regardless of the trailing fields' padding. We only
// seed these two; state/flags/rx/tx do not affect the PASS verdict. The
// full value buffer is sized to the map's actual ValueSize so the verifier
// gets a correctly-sized value.
const (
	connValTimestampOff = 0  // __u64 timestamp
	connValTTLOff       = 16 // __u64 ttl_ns (after timestamp + last_timestamp)
)

// seedConnValue builds a conn_value byte buffer of the map's exact value
// size that is GUARANTEED not-expired: timestamp=0, ttl_ns=1<<62. The
// kernel expiry test is `bpf_ktime_get_ns() > timestamp + ttl_ns`; with
// ttl_ns=2^62 and timestamp=0 the sum dwarfs any plausible monotonic
// clock, so the entry never reads as expired and the established-flow
// short-circuit returns XDP_PASS.
//
// Fields are written little-endian (host order on the x86_64 CI runners), so
// the bytes land in the same order the kernel reads them — consistent with
// ToCtKey's LE handling of the IP fields. A big-endian host would need
// native-endian encoding here; the eBPF datapath only runs on LE platforms
// in this project, so LE is assumed.
func seedConnValue(t *testing.T, valueSize uint32) []byte {
	t.Helper()
	// We write a uint64 at connValTTLOff, so the buffer must reach
	// connValTTLOff+8. The real conn_value is ~40 bytes, so this only trips
	// if the kernel struct shrinks below 24 — fail loud with the sizes rather
	// than panic with an opaque slice-bounds error.
	if valueSize < connValTTLOff+8 {
		t.Fatalf("conn_value size %d too small: need >= %d to seed timestamp@%d + ttl_ns@%d (conn_value struct shrank?)",
			valueSize, connValTTLOff+8, connValTimestampOff, connValTTLOff)
	}
	buf := make([]byte, valueSize)
	binary.LittleEndian.PutUint64(buf[connValTimestampOff:connValTimestampOff+8], 0)
	binary.LittleEndian.PutUint64(buf[connValTTLOff:connValTTLOff+8], uint64(1)<<62)
	return buf
}

// craftTCPv4Packet builds a minimal Ethernet+IPv4+TCP frame for
// BPF_PROG_TEST_RUN. The XDP program parses Ethernet (EtherType 0x0800),
// IPv4 (ihl=5, protocol=6/TCP), then the TCP header for sport/dport. MAC
// addresses are arbitrary. srcIP/dstIP are net-order; dstPort is 443 (NOT
// 22 — the program unconditionally PASSes SSH before the conntrack check).
// TARGET vs SIBLING differ ONLY in srcPort. Takes *testing.T only to fail
// loud on a non-IPv4 input (To4() == nil would otherwise silently produce an
// all-zero IP that surfaces much later as a mysterious DROP).
func craftTCPv4Packet(t *testing.T, srcIP, dstIP net.IP, srcPort, dstPort uint16) []byte {
	t.Helper()
	srcIP4 := srcIP.To4()
	dstIP4 := dstIP.To4()
	if srcIP4 == nil || dstIP4 == nil {
		t.Fatalf("craftTCPv4Packet: non-IPv4 address (src=%v dst=%v) — To4() nil would zero the packet IPs", srcIP, dstIP)
	}

	pkt := make([]byte, 0, 54)

	// Ethernet header (14 bytes): dst MAC, src MAC, EtherType 0x0800.
	pkt = append(pkt,
		0x02, 0x00, 0x00, 0x00, 0x00, 0x01, // dst MAC
		0x02, 0x00, 0x00, 0x00, 0x00, 0x02, // src MAC
		0x08, 0x00, // EtherType IPv4
	)

	// IPv4 header (20 bytes, ihl=5).
	ipHdr := make([]byte, 20)
	ipHdr[0] = 0x45                            // version=4, ihl=5
	ipHdr[1] = 0x00                            // DSCP/ECN
	binary.BigEndian.PutUint16(ipHdr[2:4], 40) // total length = 20 IP + 20 TCP
	binary.BigEndian.PutUint16(ipHdr[4:6], 0)  // identification
	binary.BigEndian.PutUint16(ipHdr[6:8], 0)  // flags/frag
	ipHdr[8] = 64                              // TTL
	ipHdr[9] = 6                               // protocol = TCP
	// checksum left 0 — XDP program does not verify the IP checksum on this path.
	copy(ipHdr[12:16], srcIP4)
	copy(ipHdr[16:20], dstIP4)
	pkt = append(pkt, ipHdr...)

	// TCP header (20 bytes, data offset=5).
	tcpHdr := make([]byte, 20)
	binary.BigEndian.PutUint16(tcpHdr[0:2], srcPort)
	binary.BigEndian.PutUint16(tcpHdr[2:4], dstPort)
	tcpHdr[12] = 0x50 // data offset = 5 (<<4)
	tcpHdr[13] = 0x02 // SYN
	pkt = append(pkt, tcpHdr...)

	return pkt
}

// loadXDPCollectionInner loads the compiled XDP object into the kernel and
// returns the program + the whole collection + a cleanup that closes it. It is
// the single home for the environment-failure folding that loadXDPCollection
// (returns the conn_track map) and loadXDPCollectionV6 (returns the whole
// collection) share: every missing prerequisite — no object / unreadable
// object / memlock / unsupported kernel / missing CAP_BPF — is folded into the
// LOUD-SKIP guard (a hard t.Fatal when NHP_REQUIRE_BPF_TESTS is set, a LOUD
// t.Skip otherwise). A nil program is NOT an environment problem (a renamed C
// symbol), so it is a hard t.Fatal regardless of the guard. On any skip/fatal
// the returned triple is nil — skipOrFatal stops the goroutine before the
// caller resumes, so the nil return only keeps the static control flow honest.
//
// PINNING: conn_track is declared LIBBPF_PIN_BY_NAME in the C source. With the
// default NewCollection options and no bpffs PinPath, the loader errors
// ("pinning requested but no path given") before our test runs. This is a
// BPF_PROG_TEST_RUN harness — we never want the maps pinned to /sys/fs/bpf — so
// we strip the Pinning flag from EVERY map spec before NewCollection (the
// object carries several PIN_BY_NAME maps; loading is whole-object).
func loadXDPCollectionInner(t *testing.T) (*ebpf.Program, *ebpf.Collection, func()) {
	t.Helper()
	return loadXDPCollectionInnerWithSpecMutator(t, nil)
}

// loadXDPCollectionInnerWithSpecMutator is loadXDPCollectionInner plus a narrow
// test-only hook that can edit the CollectionSpec after pinning is stripped and
// before the object is loaded. The production source is still the compiled XDP
// object; callers use this only to shrink a map's MaxEntries for deterministic
// capacity tests that would otherwise need to fill a million entries.
func loadXDPCollectionInnerWithSpecMutator(t *testing.T, mutate func(*ebpf.CollectionSpec)) (*ebpf.Program, *ebpf.Collection, func()) {
	t.Helper()

	objPath := os.Getenv(objectPathEnv)
	if objPath == "" {
		skipOrFatal(t, "no XDP object: %s is empty (run via `make test-ebpf`)", objectPathEnv)
		return nil, nil, nil
	}
	if _, err := os.Stat(objPath); err != nil {
		skipOrFatal(t, "XDP object %q not readable: %v (build it: `make test-ebpf`-style target compiles nhp_ebpf_xdp.o)", objPath, err)
		return nil, nil, nil
	}

	// Raise RLIMIT_MEMLOCK before loading, matching production
	// (endpoints/ac/ebpf/ebpfegine.go). The object declares several large
	// preallocated maps; on pre-5.11 kernels (no memcg BPF accounting)
	// NewCollection can otherwise fail on the memlock limit — an EPERM/ENOMEM
	// unrelated to the proof that NHP_REQUIRE_BPF_TESTS=1 would turn into a
	// spurious hard failure. Fold any error into the guard.
	if err := rlimit.RemoveMemlock(); err != nil {
		skipOrFatal(t, "rlimit.RemoveMemlock (needed to load the BPF maps; CAP_SYS_RESOURCE / CAP_BPF): %v", err)
		return nil, nil, nil
	}

	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		skipOrFatal(t, "LoadCollectionSpec(%q): %v", objPath, err)
		return nil, nil, nil
	}

	// Strip PIN_BY_NAME from all maps — BPF_PROG_TEST_RUN needs no bpffs.
	for _, m := range spec.Maps {
		m.Pinning = ebpf.PinNone
	}
	if mutate != nil {
		mutate(spec)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		// EPERM/ENOSYS here = no CAP_BPF / kernel can't load XDP. That is
		// precisely the "missing capability / kernel support" the guard
		// turns into Fatal-when-required, Skip-otherwise.
		skipOrFatal(t, "NewCollection (load XDP object into kernel): %v", err)
		return nil, nil, nil
	}

	prog := coll.Programs[xdpProgName]
	if prog == nil {
		coll.Close()
		// A nil program is NOT an environment problem — it means the C
		// symbol was renamed. Always fail loud regardless of the guard.
		t.Fatalf("program %q not found in %s (symbol renamed in nhp_ebpf_xdp.c?)", xdpProgName, objPath)
		return nil, nil, nil
	}

	return prog, coll, coll.Close
}

// loadXDPCollection loads the compiled XDP object and returns the program +
// conn_track map. It wraps loadXDPCollectionInner — which folds every
// environment failure into the LOUD-SKIP guard (Fatal when NHP_REQUIRE_BPF_TESTS
// is set, LOUD Skip otherwise) and whose returned cleanup closes the collection
// — and adds the conn_track lookup the surgical-kill datapath proof needs. A
// missing conn_track map is a renamed-C-symbol bug, not an environment problem,
// so it is a hard t.Fatal regardless of the guard.
func loadXDPCollection(t *testing.T) (*ebpf.Program, *ebpf.Map, func()) {
	t.Helper()

	prog, coll, cleanup := loadXDPCollectionInner(t)

	ctMap := coll.Maps[connTrackMapName]
	if ctMap == nil {
		coll.Close()
		// Re-read the object path (unchanged for the lifetime of a test run)
		// so this renamed-symbol message names the object, symmetric with the
		// program-not-found Fatal in loadXDPCollectionInner.
		t.Fatalf("map %q not found in %s (symbol renamed in nhp_ebpf_xdp.c?)", connTrackMapName, os.Getenv(objectPathEnv))
		return nil, nil, nil
	}

	return prog, ctMap, cleanup
}

// skipOrFatal is the loud-skip guard. NHP_REQUIRE_BPF_TESTS set (CI) ->
// t.Fatalf (a missing capability must not skip-pass the gate). Unset (dev)
// -> t.Skipf, but LOUD: the message names exactly what was missing so a
// silent green is impossible to mistake for a real pass.
func skipOrFatal(t *testing.T, format string, args ...interface{}) {
	t.Helper()
	// Match the sibling eBPF tests' convention exactly (conntrack_delete_linux_test.go
	// newTestConnTrackMap): the flag is "on" only when set to "1", so
	// NHP_REQUIRE_BPF_TESTS=0 stays a graceful skip, not a hard failure.
	if os.Getenv(requireBPFEnv) == "1" {
		t.Fatalf("[eBPF datapath proof REQUIRED] "+format, args...)
	}
	t.Logf("[eBPF datapath proof SKIPPED — set %s=1 to make this a hard failure] "+format,
		append([]interface{}{requireBPFEnv}, args...)...)
	t.Skipf("skipping eBPF datapath proof (%s unset); see log above for the missing prerequisite", requireBPFEnv)
}

// runVerdict drives one synthetic packet through the XDP program via
// BPF_PROG_TEST_RUN and returns the XDP verdict. A run error (e.g.
// EPERM on a locked-down kernel) is folded into the guard.
func runVerdict(t *testing.T, prog *ebpf.Program, pkt []byte) uint32 {
	t.Helper()
	ret, err := prog.Run(&ebpf.RunOptions{Data: pkt})
	if err != nil {
		// Fold ONLY unambiguous environment-prerequisite errors into the
		// guard (Fatal when required, Skip otherwise): EPERM = no CAP_BPF;
		// EOPNOTSUPP = a kernel that loads XDP but does not support
		// BPF_PROG_TEST_RUN for it. EINVAL is deliberately NOT in this set:
		// while a very old kernel can return EINVAL for unsupported
		// TEST_RUN, EINVAL much more commonly means a genuinely malformed /
		// wrong-size synthetic packet — a real test bug. Treating it as a
		// skip would let that bug skip-pass on a dev laptop (var unset).
		// Making it fatal fails loud everywhere; the message names both
		// causes so an ancient-kernel false-positive is still diagnosable.
		// Any other error (program loaded, TEST_RUN ran, then failed) is
		// always a genuine failure.
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EOPNOTSUPP) {
			skipOrFatal(t, "BPF_PROG_TEST_RUN: %v (CAP_BPF + kernel BPF_PROG_TEST_RUN support for XDP required)", err)
		}
		if errors.Is(err, unix.EINVAL) {
			t.Fatalf("BPF_PROG_TEST_RUN returned EINVAL: %v — almost always a malformed/wrong-size synthetic packet (a real test bug); only on a very old kernel does it mean TEST_RUN is unsupported for XDP", err)
		}
		t.Fatalf("BPF_PROG_TEST_RUN failed: %v", err)
	}
	return ret
}

// TestSurgicalKillDatapath is the #2779 real-datapath proof. It seeds two
// conntrack flows (TARGET + SIBLING) that share the allow-tuple and differ
// only in source port, asserts both PASS while their conntrack entries
// exist, then deletes ONLY the target's entry and asserts the verdict
// flips PASS -> DROP for the target while the sibling keeps PASSing.
func TestSurgicalKillDatapath(t *testing.T) {
	prog, ctMap, cleanup := loadXDPCollection(t)
	if cleanup != nil {
		defer cleanup()
	}

	// Flow tuples. Packet src -> dst maps onto ct_key saddr/daddr; the C
	// sets ct_key.saddr = iph->saddr (packet source) and ct_key.daddr =
	// iph->daddr (packet dest), flags = CT_DIR_INGRESS. So the seeded key's
	// SrcIP must equal the packet's source IP and DstIP the packet's dest.
	clientIP := net.ParseIP("10.1.2.3")
	resourceIP := net.ParseIP("10.9.8.7")
	const dstPort uint16 = 443
	const targetSrcPort uint16 = 51000
	const siblingSrcPort uint16 = 51001

	srcU32, err := parseIP(clientIP.String())
	if err != nil {
		t.Fatalf("parseIP(client): %v", err)
	}
	dstU32, err := parseIP(resourceIP.String())
	if err != nil {
		t.Fatalf("parseIP(resource): %v", err)
	}

	targetKey := &connTrackKey{DstIP: dstU32, SrcIP: srcU32, DstPort: dstPort, SrcPort: targetSrcPort, NextHdr: 6 /*TCP*/, Flags: ctDirIngress}
	siblingKey := &connTrackKey{DstIP: dstU32, SrcIP: srcU32, DstPort: dstPort, SrcPort: siblingSrcPort, NextHdr: 6 /*TCP*/, Flags: ctDirIngress}

	val := seedConnValue(t, ctMap.ValueSize())
	if err := ctMap.Put(targetKey.ToCtKey(), val); err != nil {
		t.Fatalf("seed conn_track[target]: %v", err)
	}
	if err := ctMap.Put(siblingKey.ToCtKey(), val); err != nil {
		t.Fatalf("seed conn_track[sibling]: %v", err)
	}

	targetPkt := craftTCPv4Packet(t, clientIP, resourceIP, targetSrcPort, dstPort)
	siblingPkt := craftTCPv4Packet(t, clientIP, resourceIP, siblingSrcPort, dstPort)

	// Step 4: admitted TARGET (conntrack hit, unexpired) -> XDP_PASS.
	if got := runVerdict(t, prog, targetPkt); got != xdpPass {
		t.Fatalf("before delete: target verdict = %d (%s), want XDP_PASS(%d) — established conntrack flow must short-circuit to PASS",
			got, xdpName(got), xdpPass)
	}
	// Sanity: the sibling also PASSes before the kill. If it did not, the
	// post-kill "sibling survives" assert would be vacuously true (it would
	// have failed here for an unrelated reason), so check it up front.
	if got := runVerdict(t, prog, siblingPkt); got != xdpPass {
		t.Fatalf("before delete: sibling verdict = %d (%s), want XDP_PASS(%d) — sibling conntrack flow must also short-circuit to PASS",
			got, xdpName(got), xdpPass)
	}

	// Step 5: surgically delete ONLY the target's conntrack entry, through
	// the PRODUCTION kill path delEbpfConnTrackOnMap (string IPs -> parseIP
	// -> key build -> Delete with ENOENT handling) — the exact function under
	// proof, map-injectable and the same one conntrack_delete_linux_test.go
	// exercises at the map-op layer. This makes the datapath proof also cover
	// the real revoke code, not just a raw map Delete.
	if err := delEbpfConnTrackOnMap(ctMap, clientIP.String(), resourceIP.String(), 6 /*TCP*/, targetSrcPort, dstPort); err != nil {
		t.Fatalf("delEbpfConnTrackOnMap(target): %v", err)
	}

	// Step 6: the load-bearing flip. With the target's conntrack entry gone
	// and NO allow-rule seeded to re-admit it, the next target packet misses
	// every map and falls through to XDP_DROP. PASS (step 4) -> DROP here is
	// the datapath proof that the surgical kill actually tears down the
	// in-flight flow, not just a map row.
	if got := runVerdict(t, prog, targetPkt); got != xdpDrop {
		t.Fatalf("after delete: target verdict = %d (%s), want XDP_DROP(%d) — surgically-killed flow must DROP (no conntrack entry, no allow-rule re-admit). If this is PASS, the delete did not affect the datapath; if ABORTED, the program faulted",
			got, xdpName(got), xdpDrop)
	}

	// Step 7: the surgical guarantee. The sibling shares the allow-tuple and
	// differs only in source port; its conntrack entry was untouched, so it
	// must still PASS. DROP here would mean the kill was coarse (over-flush),
	// the precise failure mode this whole P4 series exists to prevent.
	if got := runVerdict(t, prog, siblingPkt); got != xdpPass {
		t.Fatalf("after delete: sibling verdict = %d (%s), want XDP_PASS(%d) — sibling flow (distinct source port) must survive the surgical kill of the target",
			got, xdpName(got), xdpPass)
	}

	// CAVEAT (real-kernel scope): BPF_PROG_TEST_RUN runs the
	// verifier-accepted bytecode in-kernel — identical instructions to a
	// live NIC's XDP hook — so the verdict logic proven here (header parse,
	// conntrack short-circuit, allow-rule fallthrough) is exactly what the
	// NIC would execute. It does NOT exercise driver-mode (native/offload)
	// XDP ingress framing or real device redirect; those are out of scope
	// for a datapath-verdict proof and orthogonal to the surgical-kill
	// guarantee.
}

// The full-cache helpers below are address-family-agnostic: conntrack keys are
// opaque byte slices by the time they reach the map, and the verdict proof only
// needs a loaded program plus allow/deny packets.
func requireConnTrackHashAndShrinkToOne(t *testing.T, spec *ebpf.CollectionSpec, mapName string) {
	t.Helper()
	m := spec.Maps[mapName]
	if m == nil {
		t.Fatalf("map %q not found in XDP object (symbol renamed in nhp_ebpf_xdp.c?)", mapName)
	}
	if m.Type != ebpf.Hash {
		t.Fatalf("map %q type = %v, want HASH (#2814); LRU would silently evict a spared sibling under pressure", mapName, m.Type)
	}
	m.MaxEntries = 1
}

func seedFullConnTrackAndAssertRejectsOverflow(t *testing.T, ctMap *ebpf.Map, fillerKey, overflowKey, absentKey []byte) {
	t.Helper()
	connVal := seedConnValue(t, ctMap.ValueSize())
	if err := ctMap.Put(fillerKey, connVal); err != nil {
		t.Fatalf("seed conntrack filler entry: %v", err)
	}
	if err := ctMap.Put(overflowKey, connVal); err == nil {
		t.Fatal("second distinct conntrack insert succeeded even though MaxEntries=1; want E2BIG from a full HASH map. If this is LRU, the test would silently evict the filler entry.")
	} else if !IsMapFull(err) {
		t.Fatalf("second distinct conntrack insert returned %v; want map-full E2BIG", err)
	}

	out := make([]byte, ctMap.ValueSize())
	if err := ctMap.Lookup(fillerKey, &out); err != nil {
		t.Fatalf("filler conntrack entry missing after rejected full-map insert: %v — HASH must preserve existing established entries", err)
	}
	if err := ctMap.Lookup(absentKey, &out); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("precondition: admitted flow conntrack lookup err = %v, want ErrKeyNotExist before the allow-rule slow-path packet", err)
	}
}

func assertFullCacheDegradesToSlowPath(t *testing.T, prog *ebpf.Program, ctMap *ebpf.Map, allowedCtKey, fillerKey, allowPkt, denyPkt []byte) {
	t.Helper()
	out := make([]byte, ctMap.ValueSize())
	if got := runVerdict(t, prog, allowPkt); got != xdpPass {
		t.Fatalf("full conntrack HASH + matching allow-rule: verdict = %d (%s), want XDP_PASS(%d) — cache insert failure must degrade to slow path, not DROP",
			got, xdpName(got), xdpPass)
	}
	if err := ctMap.Lookup(allowedCtKey, &out); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("allowed flow became cached despite full HASH conntrack: lookup err = %v, want ErrKeyNotExist. The packet should pass via allow-rule slow path until a slot is made available.", err)
	}
	if err := ctMap.Lookup(fillerKey, &out); err != nil {
		t.Fatalf("filler conntrack entry was evicted/replaced after allowed packet: %v — HASH must not collateral-kill existing established flows", err)
	}
	if got := runVerdict(t, prog, allowPkt); got != xdpPass {
		t.Fatalf("second full-cache slow-path packet: verdict = %d (%s), want XDP_PASS(%d) — uncached admitted flows must keep passing via allow-rule re-check",
			got, xdpName(got), xdpPass)
	}
	if got := runVerdict(t, prog, denyPkt); got != xdpDrop {
		t.Fatalf("full conntrack HASH + no allow-rule: verdict = %d (%s), want XDP_DROP(%d) — full cache must not fail open for unmatched packets",
			got, xdpName(got), xdpDrop)
	}
}

// TestConnTrackFullHashCacheMissFallsBackToAllowRule is the #2814 option-1
// datapath proof: when conn_track is a full HASH map, a new flow's cache insert
// fails with E2BIG, but the XDP verdict remains correct. A packet with a valid
// allow-rule still XDP_PASSes via the slow path, remains uncached, and does NOT
// evict an existing established-flow entry; an unmatched packet still XDP_DROPs.
func TestConnTrackFullHashCacheMissFallsBackToAllowRule(t *testing.T) {
	prog, coll, cleanup := loadXDPCollectionInnerWithSpecMutator(t, func(spec *ebpf.CollectionSpec) {
		requireConnTrackHashAndShrinkToOne(t, spec, connTrackMapName)
	})
	if cleanup != nil {
		defer cleanup()
	}

	ctMap := requireMap(t, coll, connTrackMapName)
	sppMap := requireMap(t, coll, sppV4MapName)

	allowedSrc, dstIP, deniedSrc := v4TestAddrs(t)
	const (
		srcPort uint16 = 51000
		dstPort uint16 = 443
	)

	srcU32 := mustParseIP4(t, allowedSrc)
	dstU32 := mustParseIP4(t, dstIP)
	allowedCtKey := (&connTrackKey{
		DstIP: dstU32, SrcIP: srcU32, DstPort: dstPort, SrcPort: srcPort,
		NextHdr: ipprotoTCPv4, Flags: ctDirIngress,
	}).ToCtKey()

	fillerSrc, err := parseIP("192.0.2.10")
	if err != nil {
		t.Fatalf("parseIP(filler src): %v", err)
	}
	fillerDst, err := parseIP("192.0.2.20")
	if err != nil {
		t.Fatalf("parseIP(filler dst): %v", err)
	}
	fillerKey := (&connTrackKey{
		DstIP: fillerDst, SrcIP: fillerSrc, DstPort: 8443, SrcPort: 40000,
		NextHdr: ipprotoTCPv4, Flags: ctDirIngress,
	}).ToCtKey()
	overflowKey := (&connTrackKey{
		DstIP: fillerDst, SrcIP: fillerSrc, DstPort: 8443, SrcPort: 40001,
		NextHdr: ipprotoTCPv4, Flags: ctDirIngress,
	}).ToCtKey()

	seedFullConnTrackAndAssertRejectsOverflow(t, ctMap, fillerKey, overflowKey, allowedCtKey)

	wlKey := (&whitelistKey{
		SrcIP: srcU32, DstIP: dstU32, DstPort: dstPort, Protocol: ipprotoTCPv4,
	}).ToWlKey()
	if err := sppMap.Put(wlKey, seedWhitelistValue(t, sppMap.ValueSize())); err != nil {
		t.Fatalf("seed spp allow-rule: %v", err)
	}

	allowPkt := craftTCPv4Packet(t, allowedSrc, dstIP, srcPort, dstPort)
	denyPkt := craftTCPv4Packet(t, deniedSrc, dstIP, srcPort, dstPort)
	assertV4PacketsDifferOnlyIn(t, allowPkt, denyPkt, v4SrcAddrRange)

	assertFullCacheDegradesToSlowPath(t, prog, ctMap, allowedCtKey, fillerKey, allowPkt, denyPkt)
}

// TestConnTrackV6FullHashCacheMissFallsBackToAllowRule is the IPv6 twin of the
// v4 #2814 proof above. It uses UDP so the test exercises conn_track_v6's
// TCP/UDP fast path and the spp_v6 allow-rule cascade.
func TestConnTrackV6FullHashCacheMissFallsBackToAllowRule(t *testing.T) {
	prog, coll, cleanup := loadXDPCollectionInnerWithSpecMutator(t, func(spec *ebpf.CollectionSpec) {
		requireConnTrackHashAndShrinkToOne(t, spec, connTrackV6MapName)
	})
	if cleanup != nil {
		defer cleanup()
	}

	ctMap := requireMap(t, coll, connTrackV6MapName)
	sppMap := requireMap(t, coll, sppV6MapName)

	allowedSrc, dstIP, deniedSrc := v6TestAddrs(t)
	const (
		srcPort uint16 = 51000
		dstPort uint16 = 53
	)

	allowedCtKey := (&connTrackKeyV6{
		DstIP: dstIP, SrcIP: allowedSrc, DstPort: dstPort, SrcPort: srcPort,
		NextHdr: ipprotoUDP, Flags: ctDirIngress,
	}).ToCtKeyV6()

	fillerSrc := mustParseIP6(t, "2001:db8::f10")
	fillerDst := mustParseIP6(t, "2001:db8::f20")
	fillerKey := (&connTrackKeyV6{
		DstIP: fillerDst, SrcIP: fillerSrc, DstPort: 8443, SrcPort: 40000,
		NextHdr: ipprotoUDP, Flags: ctDirIngress,
	}).ToCtKeyV6()
	overflowKey := (&connTrackKeyV6{
		DstIP: fillerDst, SrcIP: fillerSrc, DstPort: 8443, SrcPort: 40001,
		NextHdr: ipprotoUDP, Flags: ctDirIngress,
	}).ToCtKeyV6()

	seedFullConnTrackAndAssertRejectsOverflow(t, ctMap, fillerKey, overflowKey, allowedCtKey)

	wlKey := (&whitelistKeyV6{
		SrcIP: allowedSrc, DstIP: dstIP, DstPort: dstPort, Protocol: ipprotoUDP,
	}).ToWlKeyV6()
	if err := sppMap.Put(wlKey, seedWhitelistValue(t, sppMap.ValueSize())); err != nil {
		t.Fatalf("seed spp_v6 allow-rule: %v", err)
	}

	allowPkt := craftUDPv6Packet(t, allowedSrc, dstIP, srcPort, dstPort)
	denyPkt := craftUDPv6Packet(t, deniedSrc, dstIP, srcPort, dstPort)
	assertDifferOnlyInV6SrcAddr(t, allowPkt, denyPkt)

	assertFullCacheDegradesToSlowPath(t, prog, ctMap, allowedCtKey, fillerKey, allowPkt, denyPkt)
}

// xdpName renders an XDP verdict code for readable assertion failures.
func xdpName(v uint32) string {
	switch v {
	case xdpAborted:
		return "XDP_ABORTED"
	case xdpDrop:
		return "XDP_DROP"
	case xdpPass:
		return "XDP_PASS"
	default:
		return "XDP_?"
	}
}
