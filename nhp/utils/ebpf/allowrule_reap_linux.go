//go:build linux

package ebpf

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
)

// ErrWhitelistMapNotPinned is returned (wrapped) by ReapExpiredWhitelist when
// a registered allow-rule map pin is absent - the expected case when the XDP
// program isn't attached (EBPFXDP feature inert).
var ErrWhitelistMapNotPinned = errors.New("registered allow-rule bpf map not pinned")

// ReapExpiredWhitelist deletes expired entries from registered pinned
// allow-rule maps and returns how many it deleted.
//
// Why this exists: the tc-egress datapath (tc_egress.c) writes reverse-path
// pinholes into the SHARED `spp` map on every egress packet. Unlike
// admission-created allow-rules (which the L3 expiry scheduler flushes at their
// deadline) and conn_track (which this same lifecycle reaper sweeps), those
// datapath entries have no scheduled GC: since #2163 made `spp` a HASH map they
// are no longer LRU-evicted, and the XDP read path only deletes them lazily when
// a return packet looks them up. A flow whose return traffic never arrives would
// otherwise linger until `spp` fills and fail-closes new admissions (-E2BIG).
// This periodic sweep bounds that.
//
// Safety: it only ever *targets* entries whose ExpireTime is already past —
// entries the XDP datapath treats as absent and deletes on the next lookup. The
// sampled key is deleted in a later pass, so a same-key re-admission (or a fresh
// egress pinhole) in that window is removed despite now carrying a future
// ExpireTime; the cost is at most a re-knock on the next packet, never a
// fail-open (identical to the conn_track reaper's accepted recreate semantics —
// see sampleAndReapMapWithBudget). It reuses the same walk / delete-budget /
// partial-sample machinery as the conn_track reaper and reads ExpireTime with
// getBootTimeNanos (CLOCK_BOOTTIME) — the same clock-domain reconciliation the
// conn_track reaper relies on. The datapath stamps ExpireTime from
// bpf_ktime_get_ns (CLOCK_MONOTONIC), which equals CLOCK_BOOTTIME except across
// host suspend; the target EC2 hosts don't suspend, and if the reading ever
// skewed ahead the worst case is a slightly-early reap → re-knock, never a
// fail-open (see the CLOCK_BOOTTIME-vs-bpf_ktime_get_ns note on
// SampleAndReapConnTrack). Tracks the datapath-fill vector documented in
// docs/design/SESSION_ENFORCEMENT_ARCHITECTURE.md.
//
// Scope: the registry currently sweeps only `spp` (the v4 allow-rule map).
// `spp_v6` is already HASH but has no tc-egress writer today, so it has no
// datapath-fill vector and needs no sweep yet; extend this when the IPv6
// tc-egress datapath lands (layervai/nhp#3022).
func ReapExpiredWhitelist() (WhitelistReapStats, error) {
	nowNanos, err := getBootTimeNanos()
	if err != nil {
		return WhitelistReapStats{}, fmt.Errorf("clock_gettime(BOOTTIME): %w", err)
	}

	var total WhitelistReapStats
	var errs []error
	for _, target := range whitelistReapTargets {
		stats, err := sampleAndReapPinnedMap(
			target.pinPath, target.label, ErrWhitelistMapNotPinned,
			func(m *ebpf.Map) (ConnTrackMapStats, error) {
				return reapExpiredWhitelistTargetOnMap(m, nowNanos, target)
			})
		if errors.Is(err, ErrWhitelistMapNotPinned) {
			// XDP program not attached at this pin path (EBPFXDP feature inert) -
			// nothing to reap. Expected, not an error for the periodic caller.
			continue
		}
		// Live occupancy after this pass's reap = observed entries minus the ones
		// just deleted. ExpiredDeleted only counts successful deletes so it can't
		// exceed Entries, but guard underflow defensively (else the gauge leaves it
		// 0). Return the count/partial/occupancy even on other errors: partial
		// progress still reclaimed those slots, and the caller meters the error
		// separately.
		var liveEntries uint64
		if stats.ExpiredDeleted <= stats.Entries {
			liveEntries = stats.Entries - stats.ExpiredDeleted
		}
		total.Reaped += stats.ExpiredDeleted
		total.Partial = total.Partial || stats.PartialSample
		// TODO(#3043): split occupancy/error reporting before adding a second
		// target; the source guard enforces one target until that lands.
		total.Entries += liveEntries
		total.MaxEntries += stats.MaxEntries
		if err != nil {
			errs = append(errs, err)
		}
	}
	switch len(errs) {
	case 0:
		return total, nil
	case 1:
		return total, errs[0]
	default:
		return total, errors.Join(errs...)
	}
}

func whitelistReapTargetByName(name string) (whitelistReapTarget, bool) {
	for _, target := range whitelistReapTargets {
		if target.mapName == name {
			return target, true
		}
	}
	return whitelistReapTarget{}, false
}

// reapExpiredWhitelistOnMap runs the expired-entry sweep against an already-open
// whitelist (`spp`) map. Split out so a unit test can exercise it against a
// test-created map without pinning at the real /sys/fs/bpf path.
func reapExpiredWhitelistOnMap(m *ebpf.Map, nowNanos uint64) (ConnTrackMapStats, error) {
	target, ok := whitelistReapTargetByName("spp")
	if !ok {
		return ConnTrackMapStats{SampleError: true}, errors.New("missing spp whitelist reaper target")
	}
	return reapExpiredWhitelistTargetOnMap(m, nowNanos, target)
}

func reapExpiredWhitelistTargetOnMap(m *ebpf.Map, nowNanos uint64, target whitelistReapTarget) (ConnTrackMapStats, error) {
	return sampleAndReapMapWithBudget(m, nowNanos, connTrackExpiredDeleteBudget, reapSpec{
		label: target.label,
		validate: func(info *ebpf.MapInfo) error {
			if int(info.KeySize) != target.keySize {
				return fmt.Errorf("%s map key size %d, want %d — wrong map pinned at %s?", target.mapName, info.KeySize, target.keySize, target.pinPath)
			}
			if int(info.ValueSize) != target.valueSize {
				return fmt.Errorf("%s map value size %d, want %d — wrong map pinned at %s?", target.mapName, info.ValueSize, target.valueSize, target.pinPath)
			}
			return nil
		},
		// Allow-rule values carry only {allowed, ExpireTime} — no last-seen, so
		// trackAge stays false and lastSeen is 0.
		decode: func(valBytes []byte) (expiresAt uint64, lastSeen uint64, derr error) {
			if len(valBytes) < target.expireTimeOffset+8 {
				return 0, 0, fmt.Errorf("%s value too short: %d bytes", target.mapName, len(valBytes))
			}
			return binary.LittleEndian.Uint64(valBytes[target.expireTimeOffset : target.expireTimeOffset+8]), 0, nil
		},
	})
}
