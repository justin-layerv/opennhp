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

var ErrFragStateMapNotPinned = errors.New("frag_state_v6 bpf map not pinned")

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

// ConnTrackStats samples and reaps established-flow conntrack maps plus IPv6
// fragment-admission state.
type ConnTrackStats struct {
	V4     ConnTrackMapStats
	V6     ConnTrackMapStats
	FragV6 ConnTrackMapStats
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
	fragV6, fragV6err := sampleAndReapFragStatePinned(PinPathFragStateV6, now)

	return ConnTrackStats{V4: v4, V6: v6, FragV6: fragV6}, errors.Join(v4err, v6err, fragV6err)
}

func sampleAndReapConnTrackPinned(pinPath string, family connTrackFamily, nowNanos uint64) (ConnTrackMapStats, error) {
	return sampleAndReapPinnedMap(pinPath, "conntrack", ErrConnTrackMapNotPinned, func(m *ebpf.Map) (ConnTrackMapStats, error) {
		return sampleAndReapConnTrackOnMap(m, family, nowNanos)
	})
}

func sampleAndReapPinnedMap(pinPath string, label string, notPinnedErr error, reap func(*ebpf.Map) (ConnTrackMapStats, error)) (ConnTrackMapStats, error) {
	m, err := ebpf.LoadPinnedMap(pinPath, nil)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return ConnTrackMapStats{MapNotPinned: true, SampleError: true}, fmt.Errorf("%w: %s: %s", notPinnedErr, pinPath, err.Error())
		}
		return ConnTrackMapStats{SampleError: true}, fmt.Errorf("load pinned %s map %s: %w", label, pinPath, err)
	}
	defer func() { _ = m.Close() }()
	return reap(m)
}

func sampleAndReapConnTrackOnMap(m *ebpf.Map, family connTrackFamily, nowNanos uint64) (ConnTrackMapStats, error) {
	return sampleAndReapConnTrackOnMapWithBudget(m, family, nowNanos, connTrackExpiredDeleteBudget)
}

func sampleAndReapConnTrackOnMapWithBudget(m *ebpf.Map, family connTrackFamily, nowNanos uint64, deleteBudget int) (ConnTrackMapStats, error) {
	wantKeySize := connTrackKeySize
	mapName := PinPathConnTrack
	if family == connTrackFamilyV6 {
		wantKeySize = connTrackKeyV6Size
		mapName = PinPathConnTrackV6
	}
	return sampleAndReapMapWithBudget(m, nowNanos, deleteBudget, reapSpec{
		label: "conntrack",
		validate: func(info *ebpf.MapInfo) error {
			if int(info.KeySize) != wantKeySize {
				return fmt.Errorf("conntrack map key size %d, want %d — wrong map pinned at %s?", info.KeySize, wantKeySize, mapName)
			}
			if info.ValueSize < connTrackValueMinSize || int(info.ValueSize) > connTrackValueSizeMax {
				return fmt.Errorf("conntrack map value size %d out of range (%d..%d) — wrong map pinned at %s?", info.ValueSize, connTrackValueMinSize, connTrackValueSizeMax, mapName)
			}
			return nil
		},
		decode:   connTrackValueTimes,
		trackAge: true,
	})
}

func sampleAndReapFragStatePinned(pinPath string, nowNanos uint64) (ConnTrackMapStats, error) {
	// Unlike revocation's mixed-rollout best-effort purge, the sampler treats a
	// missing frag_state_v6 pin as a load/staleness error: after the EBPFXDP flip,
	// the XDP object must pin conntrack and fragment-state maps together.
	return sampleAndReapPinnedMap(pinPath, "fragment-state", ErrFragStateMapNotPinned, func(m *ebpf.Map) (ConnTrackMapStats, error) {
		return sampleAndReapFragStateOnMap(m, nowNanos)
	})
}

func sampleAndReapFragStateOnMap(m *ebpf.Map, nowNanos uint64) (ConnTrackMapStats, error) {
	return sampleAndReapFragStateOnMapWithBudget(m, nowNanos, connTrackExpiredDeleteBudget)
}

func sampleAndReapFragStateOnMapWithBudget(m *ebpf.Map, nowNanos uint64, deleteBudget int) (ConnTrackMapStats, error) {
	return sampleAndReapMapWithBudget(m, nowNanos, deleteBudget, reapSpec{
		label: "fragment-state",
		validate: func(info *ebpf.MapInfo) error {
			if int(info.KeySize) != ipv6FragKeySize {
				return fmt.Errorf("frag_state_v6 map key size %d, want %d — wrong map pinned at %s?", info.KeySize, ipv6FragKeySize, PinPathFragStateV6)
			}
			if int(info.ValueSize) != ipv6FragValueSize {
				return fmt.Errorf("frag_state_v6 map value size %d, want %d — wrong map pinned at %s?", info.ValueSize, ipv6FragValueSize, PinPathFragStateV6)
			}
			return nil
		},
		decode: func(valBytes []byte) (expiresAt uint64, lastSeen uint64, err error) {
			val, derr := ipv6FragValueFromBytes(valBytes)
			if derr != nil {
				return 0, 0, derr
			}
			return val.ExpireTime, 0, nil
		},
	})
}

type reapSpec struct {
	label    string
	validate func(info *ebpf.MapInfo) error
	decode   func(valBytes []byte) (expiresAt uint64, lastSeen uint64, err error)
	trackAge bool
}

func sampleAndReapMapWithBudget(m *ebpf.Map, nowNanos uint64, deleteBudget int, spec reapSpec) (ConnTrackMapStats, error) {
	info, err := m.Info()
	if err != nil {
		return ConnTrackMapStats{SampleError: true}, fmt.Errorf("%s map info: %w", spec.label, err)
	}
	if err := spec.validate(info); err != nil {
		return ConnTrackMapStats{SampleError: true, MaxEntries: uint64(info.MaxEntries)}, err
	}

	stats := ConnTrackMapStats{MaxEntries: uint64(info.MaxEntries)}
	keyBytes := make([]byte, info.KeySize)
	valBytes := make([]byte, info.ValueSize)
	var expiredKeys [][]byte

	iter := m.Iterate()
	for iter.Next(&keyBytes, &valBytes) {
		stats.Entries++
		expiresAt, lastSeen, derr := spec.decode(valBytes)
		if derr != nil {
			return ConnTrackMapStats{SampleError: true, MaxEntries: uint64(info.MaxEntries)}, derr
		}
		expired := nowNanos > expiresAt
		if spec.trackAge && !expired && lastSeen <= nowNanos {
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
		return ConnTrackMapStats{SampleError: true, MaxEntries: uint64(info.MaxEntries)}, fmt.Errorf("iterate %s map: %w", spec.label, err)
	}

	for _, key := range expiredKeys {
		// A same-key recreate between sample and delete is safe for every caller of
		// this shared loop: it only drops that one key's entry, and the next packet
		// re-enters datapath policy instead of bypassing it — never a fail-open or
		// silent eviction. The two callers differ in what the dropped entry was:
		// conn_track loses cached tracking state (re-tracked on the next packet);
		// the spp allow-rule reaper (utilebpf.ReapExpiredWhitelist) drops the
		// admission itself, so the next packet fail-closes to a re-knock. Both are
		// fail-closed, and this loop only ever deletes already-expired keys.
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
		return stats, fmt.Errorf("delete expired %s entries: %d error(s)", spec.label, stats.DeleteErrorCount)
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
