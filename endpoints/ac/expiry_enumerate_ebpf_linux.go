//go:build linux

package ac

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/OpenNHP/opennhp/nhp/log"
	utilebpf "github.com/OpenNHP/opennhp/nhp/utils/ebpf"
)

// errBpfMapNotPinned is returned by enumerateBpfMap when the
// pinned-map path doesn't exist on the filesystem — the expected
// case when the XDP program isn't attached at this path (feature
// inert). Distinct from real load errors (permission denied, schema
// mismatch) which the caller must fail loud on
var errBpfMapNotPinned = errors.New("bpf map not pinned")

// enumerateBpfAllowRules walks the session-tied BPF allow-rule
// maps (/sys/fs/bpf/spp, /sys/fs/bpf/sdwhitelist,
// /sys/fs/bpf/icmpwhitelist) and Schedules a flush for each entry
// at its kernel-side `ExpireTime`.
//
// **Map scope:** session-tied only. The src_port, port_list, and
// protocol_port maps (mapTypes 4-6) carry auxiliary tempset
// entries not bound to a session; the scheduler's per-session
// scope means we deliberately skip them here (matches the
// HandleAccessControl hook scope).
//
// **Stale-entry handling:** entries whose `ExpireTime` is already
// past `now_boot_ns` are skipped — kernel-side LRU will reclaim
// them on next packet or XDP_DROP path.
//
// Returns the number of entries scheduled and any error. A
// single-map failure (e.g., spp map not loaded because the XDP
// program isn't attached) logs a warning and continues to the
// next map; only an unrecoverable error stops enumeration.
func (a *UdpAC) enumerateBpfAllowRules() (int, error) {
	nowBootNs, err := bootTimeNs()
	if err != nil {
		return 0, fmt.Errorf("clock_gettime(BOOTTIME): %w", err)
	}
	nowWall := time.Now()
	total := 0

	// Per-map errors are now classified, mirroring the iptables-side
	// errIpsetSetNotFound discipline (previously every per-map error
	// was log.Warning + continue, which contradicted the wrapper's
	// "fail closed on enumeration error" contract documented in
	// expiry_enumerate.go).
	//
	// Single shared deadline across all three maps Previously each enumerateBpfMap took its own
	// 60s deadline, making the worst-case 3 × 60s = 180s — and the
	// 0.8 × wrapper-warning would fire spuriously when any single
	// map approached its budget. Shared deadline ensures the
	// wrapper's "completed near deadline" signal actually anchors
	// on the aggregate enumeration time.
	deadline := time.Now().Add(bootEnumerationDeadline)

	for _, mp := range []struct {
		pinPath string
		keySize int
		decode  func([]byte) (FlowKey, error)
	}{
		{utilebpf.PinPathWhitelist, 11, decodeWhitelistKey}, // TCP/UDP per-port
		{utilebpf.PinPathSdWhitelist, 8, decodeSdKey},       // any-proto src+dst
		{utilebpf.PinPathIcmpWhitelist, 8, decodeIcmpKey},   // ICMP
	} {
		// Per-map elapsed surfaces in the AC log so the wrapper's
		// "completed near the deadline" Warning is actionable
		// without needing extra instrumentation — operators can
		// grep "[L3FlushSched] enumerate" to see which map was the
		// slow one across the shared aggregate deadline
		mapStart := time.Now()
		n, err := a.enumerateBpfMap(mp.pinPath, mp.keySize, mp.decode, nowBootNs, nowWall, deadline)
		total += n
		mapElapsed := time.Since(mapStart)
		if err == nil {
			log.Info("[L3FlushSched] enumerate %s: %d entries in %s", mp.pinPath, n, mapElapsed)
			continue
		}
		if errors.Is(err, errBpfMapNotPinned) {
			// Expected: feature inert because the XDP program isn't
			// attached at this pin path. Log and continue rather than
			// fail boot — the L3 flush feature is FilterMode-dispatched
			// and an absent map means there's nothing to enumerate.
			log.Info("[L3FlushSched] %s not pinned (XDP program inactive); skipping enumeration", mp.pinPath)
			continue
		}
		// Real load error (permission denied, schema mismatch, decode
		// failure mid-iteration). Fail loud — boot must not proceed
		// with a stale scheduler for that map's flows.
		return total, fmt.Errorf("enumerate %s: %w", mp.pinPath, err)
	}

	return total, nil
}

// enumerateBpfMap opens a pinned map, iterates all entries, and
// Schedules a flush for each one whose ExpireTime is in the
// future. The keyDecoder converts the raw key bytes to a
// FlowKey for the scheduler.
func (a *UdpAC) enumerateBpfMap(
	pinPath string,
	keySize int,
	keyDecoder func([]byte) (FlowKey, error),
	nowBootNs uint64,
	nowWall time.Time,
	deadline time.Time,
) (int, error) {
	m, err := ebpf.LoadPinnedMap(pinPath, nil)
	if err != nil {
		// Distinguish "pin path doesn't exist" (the expected case when
		// the XDP program isn't attached at this path — feature inert)
		// from other load errors (permission, schema). Caller
		// errors.Is(err, errBpfMapNotPinned) to decide whether to fail
		// loud or continue
		if errors.Is(err, fs.ErrNotExist) {
			// %w wraps errBpfMapNotPinned so callers can errors.Is for
			// the sentinel; the underlying fs.ErrNotExist text is in
			// err.Error() (rendered via %s) for diagnostic context —
			// errorlint flags %v on an error so we use %s on the
			// already-formatted err text instead.
			return 0, fmt.Errorf("%w: %s: %s", errBpfMapNotPinned, pinPath, err.Error())
		}
		return 0, fmt.Errorf("load %s: %w", pinPath, err)
	}
	defer func() { _ = m.Close() }()

	// Sanity-check the loaded map's dimensions against this caller's
	// expected key/value sizes. A kernel struct layout change (or
	// the wrong map pinned at this path) would silently corrupt
	// every decoded FlowKey otherwise — fail loud rather than
	// schedule garbage flushes expectedValueSize
	// is exported from nhp/utils/ebpf via unsafe.Sizeof so a struct-
	// layout change in the producer becomes a compile error at this
	// consumer
	info, err := m.Info()
	if err != nil {
		return 0, fmt.Errorf("map %s: info: %w", pinPath, err)
	}
	// Single-dimension helpers (not a bundled wrapper) so each
	// call only takes the two ints for its own axis — no risk of
	// accidentally swapping a key arg into the value position.
	if err := validateMapKeySize(pinPath, int(info.KeySize), keySize); err != nil {
		return 0, err
	}
	if err := validateMapValueSize(pinPath, int(info.ValueSize), utilebpf.WhitelistValueSize); err != nil {
		return 0, err
	}

	keyBytes := make([]byte, keySize)
	valBytes := make([]byte, utilebpf.WhitelistValueSize)
	count := 0
	skipCount := 0
	// Shared aggregate deadline across all maps in this enum cycle
	// (passed in from enumerateBpfAllowRules). cilium/ebpf's
	// Iterator doesn't accept a context; a hung iterator (kernel
	// state inconsistency, EAGAIN loop) would otherwise extend AC
	// boot indefinitely. Check the elapsed time every 4096
	// iterations to amortize the time.Now() cost over the hot
	// path.
	iter := m.Iterate()
	for iter.Next(&keyBytes, &valBytes) {
		if count&0xFFF == 0 && time.Now().After(deadline) {
			return count, fmt.Errorf("iterate %s: bootEnumerationDeadline exceeded at %d entries", pinPath, count)
		}
		// Field offset via unsafe.Offsetof in nhp/utils/ebpf so a
		// struct-layout change becomes a compile error here rather
		// than a silent decode of the wrong 8 bytes
		expireNs := binary.LittleEndian.Uint64(valBytes[utilebpf.ExpireTimeOffset : utilebpf.ExpireTimeOffset+8])
		if expireNs <= nowBootNs {
			// Already expired by kernel clock — let LRU GC handle.
			continue
		}
		remainingNs := expireNs - nowBootNs
		// Skip very-long-TTL entries (>infrastructureTTLSkipNs). The
		// AC writes 1-year-TTL infrastructure routes to sdwhitelist
		// at startup (udpac.go server-peer bootstrap); those are NOT
		// session-tied and must not be flushed. The session-tied
		// HandleAccessControl entries are sub-hour, so a >1d
		// remaining TTL discriminates infrastructure from session
		// entries without needing a distinct pinned map. Symmetric
		// with the iptables-side tempset skip in
		// expiry_enumerate_iptables_linux.go.
		if remainingNs > infrastructureTTLSkipNs {
			continue
		}
		deadlineWall := nowWall.Add(time.Duration(remainingNs))

		key, err := keyDecoder(keyBytes)
		if err != nil {
			// Skip count surfaces in the return error if it exceeds
			// the threshold below; an unmanaged kernel entry means
			// flow state we won't tear down. Warning + accumulate so
			// boot fails closed on systemic corruption rather than
			// silently ship with a partial scheduler.
			skipCount++
			log.Warning("[L3FlushSched] skipping undecodable %s key (%d so far): %v", pinPath, skipCount, err)
			continue
		}
		a.expirySched.Schedule(key, deadlineWall)
		count++
	}
	if err := iter.Err(); err != nil {
		return count, fmt.Errorf("iterate %s: %w", pinPath, err)
	}
	if skipCount > maxBpfDecodeSkipBeforeFailClosed {
		return count, fmt.Errorf("iterate %s: %d undecodable entries exceeds threshold %d — systemic corruption, refusing partial scheduler", pinPath, skipCount, maxBpfDecodeSkipBeforeFailClosed)
	}
	return count, nil
}

// maxBpfDecodeSkipBeforeFailClosed caps how many consecutive
// per-entry decode failures enumerateBpfMap will tolerate before
// failing the whole map. A single corrupt entry can happen
// (kernel-side write torn by a concurrent program); a sustained
// run of failures means either the schema drifted or the map
// type is wrong — under the fail-closed contract that's a boot
// blocker, not a silent skip.
const maxBpfDecodeSkipBeforeFailClosed = 10

// MaxExpectedSessionTTL is the upper bound on any legitimate
// session-tied entry's remaining TTL. Today qURL session_duration
// p99 is ~1800s (30 min); the bound is set well above to absorb
// any near-term growth without changing the discriminator. If a
// future product change raises session_duration past this bound,
// boot enumeration would silently skip legitimate sessions —
// `TestInfrastructureTTLSkip_HasHeadroomOverMaxSession` (see
// expiry_enumerate_test.go) is the regression fence.
const MaxExpectedSessionTTL = 6 * time.Hour

// infrastructureTTLSkipNs is the threshold above which a BPF
// map entry is treated as infrastructure (not session-tied) and
// skipped from boot enumeration. Session entries are sub-hour
// (see MaxExpectedSessionTTL); infrastructure entries (AC↔server
// peer routes) are 1-year TTL. 24h is comfortably above any
// session_duration and well below the 1-year infrastructure TTL.
const infrastructureTTLSkipNs uint64 = uint64(24 * time.Hour)

// decodeWhitelistKey parses an 11-byte whitelistKey:
//
//	src_ip  (4 LE) | dst_ip (4 LE) | dst_port (2 BE) | protocol (1)
//
// Note: byte-order matches nhp/utils/ebpf.whitelistKey.ToWlKey,
// which is the producer.
func decodeWhitelistKey(b []byte) (FlowKey, error) {
	if len(b) != 11 {
		return FlowKey{}, fmt.Errorf("expected 11 bytes, got %d", len(b))
	}
	srcIP := ipv4FromUint32LE(binary.LittleEndian.Uint32(b[0:4]))
	dstIP := ipv4FromUint32LE(binary.LittleEndian.Uint32(b[4:8]))
	dstPort := binary.BigEndian.Uint16(b[8:10])
	protoByte := b[10]
	var proto FlowProto
	switch protoByte {
	case 6:
		proto = FlowProtoTCP
	case 17:
		proto = FlowProtoUDP
	default:
		proto = FlowProtoAny
	}
	return MakeFlowKey(srcIP.String(), dstIP.String(), int(dstPort), proto)
}

// decodeSdKey parses an 8-byte srcDestKey:
//
//	src_ip (4 LE) | dst_ip (4 LE)
//
// Maps to FlowProtoAny (no port / proto in key).
func decodeSdKey(b []byte) (FlowKey, error) {
	if len(b) != 8 {
		return FlowKey{}, fmt.Errorf("expected 8 bytes, got %d", len(b))
	}
	srcIP := ipv4FromUint32LE(binary.LittleEndian.Uint32(b[0:4]))
	dstIP := ipv4FromUint32LE(binary.LittleEndian.Uint32(b[4:8]))
	return MakeFlowKey(srcIP.String(), dstIP.String(), 0, FlowProtoAny)
}

// decodeIcmpKey — same shape as srcDestKey but tagged ICMP.
func decodeIcmpKey(b []byte) (FlowKey, error) {
	if len(b) != 8 {
		return FlowKey{}, fmt.Errorf("expected 8 bytes, got %d", len(b))
	}
	srcIP := ipv4FromUint32LE(binary.LittleEndian.Uint32(b[0:4]))
	dstIP := ipv4FromUint32LE(binary.LittleEndian.Uint32(b[4:8]))
	return MakeFlowKey(srcIP.String(), dstIP.String(), 0, FlowProtoICMP)
}

// ipv4FromUint32LE reconstructs the IPv4 address from the
// little-endian-encoded uint32 form used by
// nhp/utils/ebpf.parseIP (which does binary.LittleEndian.Uint32
// on ip.To4()).
func ipv4FromUint32LE(u uint32) net.IP {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], u)
	return net.IPv4(b[0], b[1], b[2], b[3])
}

// bootTimeNs returns the current CLOCK_BOOTTIME reading in
// nanoseconds. Matches the clock the XDP program uses (and the
// nhp/utils/ebpf.getBootTimeNanos producer of `ExpireTime`).
func bootTimeNs() (uint64, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		return 0, err
	}
	return uint64(ts.Sec)*1_000_000_000 + uint64(ts.Nsec), nil
}
