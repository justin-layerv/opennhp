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

	// xdpProgName / connTrackMapName are the SEC-declared symbol names in
	// nhp_ebpf_xdp.c: `SEC("xdp")` on `xdp_white_prog`, and the
	// `conn_track` BPF_MAP_TYPE_LRU_HASH. A rename in the C source breaks
	// the lookup loudly (nil program / nil map -> guard Fatal/Skip), which
	// is the desired fail-loud, not a silent pass.
	xdpProgName      = "xdp_white_prog"
	connTrackMapName = "conn_track"

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

// loadXDPCollection loads the compiled XDP object and returns the program +
// conn_track map. It folds every failure into the LOUD-SKIP guard: with
// NHP_REQUIRE_BPF_TESTS set, any missing object / unsupported kernel /
// missing capability is a hard t.Fatal; unset, it is a LOUD t.Skip. The
// returned cleanup closes the collection.
//
// PINNING: conn_track is declared LIBBPF_PIN_BY_NAME in the C source. With
// the default NewCollection options and no bpffs PinPath, the loader errors
// ("pinning requested but no path given") before our test runs. This is a
// BPF_PROG_TEST_RUN harness — we never want the maps pinned to /sys/fs/bpf
// — so we strip the Pinning flag from EVERY map spec before NewCollection
// (the object carries several PIN_BY_NAME maps; loading is whole-object).
func loadXDPCollection(t *testing.T) (*ebpf.Program, *ebpf.Map, func()) {
	t.Helper()

	objPath := os.Getenv(objectPathEnv)
	if objPath == "" {
		skipOrFatal(t, "no XDP object: %s is empty (run via `make test-ebpf`)", objectPathEnv)
		return nil, nil, nil
	}
	if _, err := os.Stat(objPath); err != nil {
		skipOrFatal(t, "XDP object %q not readable: %v (build it: `make %s`-style target compiles nhp_ebpf_xdp.o)", objPath, err, "test-ebpf")
		return nil, nil, nil
	}

	// Raise RLIMIT_MEMLOCK before loading, matching production
	// (endpoints/ac/ebpf/ebpfegine.go). The object declares six LRU_HASH maps
	// at max_entries=1_000_000; on pre-5.11 kernels (no memcg BPF accounting)
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
	ctMap := coll.Maps[connTrackMapName]
	if ctMap == nil {
		coll.Close()
		t.Fatalf("map %q not found in %s (symbol renamed in nhp_ebpf_xdp.c?)", connTrackMapName, objPath)
		return nil, nil, nil
	}

	return prog, ctMap, coll.Close
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
