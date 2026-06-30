//go:build linux

package ebpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"

	"github.com/cilium/ebpf"
)

const connTrackExpiredDeleteBudget = 100_000

// ConnTrackMapStats is a point-in-time sample of one eBPF conntrack map.
// Entries is the number of elements observed before any expired-key deletions
// from this sample. OldestAgeNanos is idle age since last packet among
// surviving entries. ExpiredDeleted is cumulative for the sample only and is
// capped by connTrackExpiredDeleteBudget. PartialSample means concurrent HASH
// churn aborted the walk before a complete pass; Entries may undercount and
// deletes are skipped for that sample.
type ConnTrackMapStats struct {
	Entries          uint64
	MaxEntries       uint64
	OldestAgeNanos   uint64
	ExpiredDeleted   uint64
	DeleteErrorCount uint64
	PartialSample    bool
	SampleError      bool
	MapNotPinned     bool
}

// ConnTrackStats samples and reaps both established-flow conntrack maps.
type ConnTrackStats struct {
	V4 ConnTrackMapStats
	V6 ConnTrackMapStats
}

type connTrackFamily int

const (
	connTrackFamilyV4 connTrackFamily = iota
	connTrackFamilyV6
)

// SampleAndReapConnTrack maps the XDP datapath's packet-triggered
// check_conn_expiry predicate into userspace: entries whose timestamp+ttl_ns is
// already behind the current kernel-time reading are deleted even if the flow
// has gone quiet and will never send the next packet that would trigger
// datapath GC. getBootTimeNanos owns the CLOCK_BOOTTIME-vs-bpf_ktime_get_ns
// host invariant used by the existing eBPF helpers; if it ever skewed ahead,
// the worst case here is premature cache reaping and allow-rule slow-path
// repopulation, never fail-open or silent eviction.
func SampleAndReapConnTrack() (ConnTrackStats, error) {
	now, err := getBootTimeNanos()
	if err != nil {
		return ConnTrackStats{}, err
	}

	v4, v4err := sampleAndReapConnTrackPinned(PinPathConnTrack, connTrackFamilyV4, now)
	v6, v6err := sampleAndReapConnTrackPinned(PinPathConnTrackV6, connTrackFamilyV6, now)

	return ConnTrackStats{V4: v4, V6: v6}, errors.Join(v4err, v6err)
}

func sampleAndReapConnTrackPinned(pinPath string, family connTrackFamily, nowNanos uint64) (ConnTrackMapStats, error) {
	m, err := ebpf.LoadPinnedMap(pinPath, nil)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return ConnTrackMapStats{MapNotPinned: true, SampleError: true}, fmt.Errorf("%w: %s: %s", ErrConnTrackMapNotPinned, pinPath, err.Error())
		}
		return ConnTrackMapStats{SampleError: true}, fmt.Errorf("load pinned conntrack map %s: %w", pinPath, err)
	}
	defer func() { _ = m.Close() }()
	return sampleAndReapConnTrackOnMap(m, family, nowNanos)
}

func sampleAndReapConnTrackOnMap(m *ebpf.Map, family connTrackFamily, nowNanos uint64) (ConnTrackMapStats, error) {
	return sampleAndReapConnTrackOnMapWithBudget(m, family, nowNanos, connTrackExpiredDeleteBudget)
}

func sampleAndReapConnTrackOnMapWithBudget(m *ebpf.Map, family connTrackFamily, nowNanos uint64, deleteBudget int) (ConnTrackMapStats, error) {
	info, err := m.Info()
	if err != nil {
		return ConnTrackMapStats{SampleError: true}, fmt.Errorf("conntrack map info: %w", err)
	}
	wantKeySize := connTrackKeySize
	mapName := PinPathConnTrack
	if family == connTrackFamilyV6 {
		wantKeySize = connTrackKeyV6Size
		mapName = PinPathConnTrackV6
	}
	if int(info.KeySize) != wantKeySize {
		return ConnTrackMapStats{SampleError: true, MaxEntries: uint64(info.MaxEntries)}, fmt.Errorf("conntrack map key size %d, want %d — wrong map pinned at %s?", info.KeySize, wantKeySize, mapName)
	}
	if info.ValueSize < connTrackValueMinSize || int(info.ValueSize) > connTrackValueSizeMax {
		return ConnTrackMapStats{SampleError: true, MaxEntries: uint64(info.MaxEntries)}, fmt.Errorf("conntrack map value size %d out of range (%d..%d) — wrong map pinned at %s?", info.ValueSize, connTrackValueMinSize, connTrackValueSizeMax, mapName)
	}

	stats := ConnTrackMapStats{MaxEntries: uint64(info.MaxEntries)}
	keyBytes := make([]byte, info.KeySize)
	valBytes := make([]byte, info.ValueSize)
	var expiredKeys [][]byte

	iter := m.Iterate()
	for iter.Next(&keyBytes, &valBytes) {
		stats.Entries++
		expiresAt, lastSeen, derr := connTrackValueTimes(valBytes)
		if derr != nil {
			return ConnTrackMapStats{SampleError: true, MaxEntries: uint64(info.MaxEntries)}, derr
		}
		expired := nowNanos > expiresAt
		if !expired && lastSeen <= nowNanos {
			if age := nowNanos - lastSeen; age > stats.OldestAgeNanos {
				stats.OldestAgeNanos = age
			}
		}
		if expired && deleteBudget > 0 && len(expiredKeys) < deleteBudget {
			keyCopy := make([]byte, len(keyBytes))
			copy(keyCopy, keyBytes)
			expiredKeys = append(expiredKeys, keyCopy)
		}
	}
	if err := iter.Err(); err != nil {
		if errors.Is(err, ebpf.ErrIterationAborted) {
			// Healthy datapath churn can make a HASH iteration revisit keys until
			// cilium/ebpf aborts. Keep the partial occupancy sample, skip deletes
			// from an incomplete walk, and let AC emit a partial-sample counter.
			// Unlike surgical enumeration, stats callers do not need a complete
			// key set for correctness; the counter keeps undercounted occupancy
			// visible instead of turning churn into a corrupt-map sample error.
			stats.PartialSample = true
			return stats, nil
		}
		return ConnTrackMapStats{SampleError: true, MaxEntries: uint64(info.MaxEntries)}, fmt.Errorf("iterate conntrack map: %w", err)
	}

	for _, key := range expiredKeys {
		// A same-5-tuple recreate between sample and delete only loses the
		// fast-path cache for that flow. The next packet pays the allow-rule
		// slow path and repopulates if the admission is still valid; it never
		// creates a fail-open or silent-eviction condition.
		if err := m.Delete(key); err != nil {
			if !isEbpfNoEntry(err) {
				stats.DeleteErrorCount++
			}
			// Only successful deletes reduce post-reap occupancy. Failed deletes
			// remain counted so usage alarms err on the conservative side.
			continue
		}
		stats.ExpiredDeleted++
	}
	if stats.DeleteErrorCount > 0 {
		stats.SampleError = true
		return stats, fmt.Errorf("delete expired conntrack entries: %d error(s)", stats.DeleteErrorCount)
	}
	return stats, nil
}

func connTrackValueTimes(buf []byte) (expiresAt uint64, lastSeen uint64, err error) {
	if len(buf) < connTrackValueMinSize {
		return 0, 0, fmt.Errorf("conntrack value length %d, want at least %d", len(buf), connTrackValueMinSize)
	}
	timestamp := binary.LittleEndian.Uint64(buf[connTrackValueTimestampOff : connTrackValueTimestampOff+8])
	lastSeen = binary.LittleEndian.Uint64(buf[connTrackValueLastTimestampOff : connTrackValueLastTimestampOff+8])
	ttl := binary.LittleEndian.Uint64(buf[connTrackValueTTLOff : connTrackValueTTLOff+8])
	expiresAt = timestamp + ttl
	if expiresAt < timestamp {
		expiresAt = ^uint64(0)
	}
	return expiresAt, lastSeen, nil
}
