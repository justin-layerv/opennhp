//go:build linux

package ebpf

import (
	"encoding/binary"
	"errors"
	"testing"

	cebpf "github.com/cilium/ebpf"
)

func TestConnTrackValueTimes(t *testing.T) {
	buf := make([]byte, ctValueSize)
	binary.LittleEndian.PutUint64(buf[connTrackValueTimestampOff:connTrackValueTimestampOff+8], 100)
	binary.LittleEndian.PutUint64(buf[connTrackValueLastTimestampOff:connTrackValueLastTimestampOff+8], 125)
	binary.LittleEndian.PutUint64(buf[connTrackValueTTLOff:connTrackValueTTLOff+8], 50)

	expiresAt, lastSeen, err := connTrackValueTimes(buf)
	if err != nil {
		t.Fatalf("connTrackValueTimes: %v", err)
	}
	if expiresAt != 150 {
		t.Fatalf("expiresAt = %d, want 150", expiresAt)
	}
	if lastSeen != 125 {
		t.Fatalf("lastSeen = %d, want 125", lastSeen)
	}

	binary.LittleEndian.PutUint64(buf[connTrackValueTimestampOff:connTrackValueTimestampOff+8], ^uint64(0)-10)
	binary.LittleEndian.PutUint64(buf[connTrackValueLastTimestampOff:connTrackValueLastTimestampOff+8], ^uint64(0)-5)
	binary.LittleEndian.PutUint64(buf[connTrackValueTTLOff:connTrackValueTTLOff+8], 20)
	expiresAt, lastSeen, err = connTrackValueTimes(buf)
	if err != nil {
		t.Fatalf("connTrackValueTimes(overflow): %v", err)
	}
	if expiresAt != ^uint64(0) {
		t.Fatalf("overflow expiresAt = %d, want max uint64 saturation", expiresAt)
	}
	if lastSeen != ^uint64(0)-5 {
		t.Fatalf("overflow lastSeen = %d, want preserved last_timestamp", lastSeen)
	}

	if _, _, err := connTrackValueTimes(make([]byte, connTrackValueMinSize-1)); err == nil {
		t.Fatal("connTrackValueTimes(short) = nil error, want loud layout failure")
	}
}

func TestSampleAndReapConnTrackOnMap_DeletesExpiredQuietEntries(t *testing.T) {
	m, ok := newTestConnTrackMap(t)
	if !ok {
		return
	}
	defer func() { _ = m.Close() }()

	src, err := parseIP("198.51.100.7")
	if err != nil {
		t.Fatalf("parseIP(src): %v", err)
	}
	dst, err := parseIP("203.0.113.10")
	if err != nil {
		t.Fatalf("parseIP(dst): %v", err)
	}
	expired := &connTrackKey{DstIP: dst, SrcIP: src, DstPort: 443, SrcPort: 43210, NextHdr: 6, Flags: ctDirIngress}
	live := &connTrackKey{DstIP: dst, SrcIP: src, DstPort: 443, SrcPort: 43211, NextHdr: 6, Flags: ctDirIngress}

	expiredVal := make([]byte, ctValueSize)
	binary.LittleEndian.PutUint64(expiredVal[connTrackValueTimestampOff:connTrackValueTimestampOff+8], 100)
	binary.LittleEndian.PutUint64(expiredVal[connTrackValueLastTimestampOff:connTrackValueLastTimestampOff+8], 120)
	binary.LittleEndian.PutUint64(expiredVal[connTrackValueTTLOff:connTrackValueTTLOff+8], 10)
	liveVal := make([]byte, ctValueSize)
	binary.LittleEndian.PutUint64(liveVal[connTrackValueTimestampOff:connTrackValueTimestampOff+8], 100)
	binary.LittleEndian.PutUint64(liveVal[connTrackValueLastTimestampOff:connTrackValueLastTimestampOff+8], 130)
	binary.LittleEndian.PutUint64(liveVal[connTrackValueTTLOff:connTrackValueTTLOff+8], 500)

	if err := m.Put(expired.ToCtKey(), expiredVal); err != nil {
		t.Fatalf("put expired: %v", err)
	}
	if err := m.Put(live.ToCtKey(), liveVal); err != nil {
		t.Fatalf("put live: %v", err)
	}

	stats, err := sampleAndReapConnTrackOnMap(m, connTrackFamilyV4, 200)
	if err != nil {
		t.Fatalf("sampleAndReapConnTrackOnMap: %v", err)
	}
	if stats.Entries != 2 {
		t.Fatalf("Entries = %d, want 2 (pre-reap sample should count both entries)", stats.Entries)
	}
	if stats.MaxEntries != 16 {
		t.Fatalf("MaxEntries = %d, want 16", stats.MaxEntries)
	}
	if stats.ExpiredDeleted != 1 {
		t.Fatalf("ExpiredDeleted = %d, want 1", stats.ExpiredDeleted)
	}
	if stats.OldestAgeNanos != 70 {
		t.Fatalf("OldestAgeNanos = %d, want 70 (oldest surviving entry after quiet reaper)", stats.OldestAgeNanos)
	}

	out := make([]byte, ctValueSize)
	if err := m.Lookup(expired.ToCtKey(), &out); !isEbpfNoEntry(err) {
		t.Fatalf("expired conntrack lookup err = %v, want no-entry after quiet reaper", err)
	}
	out = make([]byte, ctValueSize)
	if err := m.Lookup(live.ToCtKey(), &out); err != nil {
		t.Fatalf("live conntrack lookup err = %v, want survivor untouched", err)
	}
}

func TestSampleAndReapConnTrackOnMapV6_DeletesExpiredQuietEntries(t *testing.T) {
	m, ok := newTestConnTrackMapV6(t)
	if !ok {
		return
	}
	defer func() { _ = m.Close() }()

	src, err := parseIP6("2001:db8::7")
	if err != nil {
		t.Fatalf("parseIP6(src): %v", err)
	}
	dst, err := parseIP6("2001:db8::10")
	if err != nil {
		t.Fatalf("parseIP6(dst): %v", err)
	}
	expired := &connTrackKeyV6{DstIP: dst, SrcIP: src, DstPort: 443, SrcPort: 43210, NextHdr: 6, Flags: ctDirIngress}
	live := &connTrackKeyV6{DstIP: dst, SrcIP: src, DstPort: 443, SrcPort: 43211, NextHdr: 6, Flags: ctDirIngress}

	expiredVal := make([]byte, ctValueSize)
	binary.LittleEndian.PutUint64(expiredVal[connTrackValueTimestampOff:connTrackValueTimestampOff+8], 100)
	binary.LittleEndian.PutUint64(expiredVal[connTrackValueLastTimestampOff:connTrackValueLastTimestampOff+8], 120)
	binary.LittleEndian.PutUint64(expiredVal[connTrackValueTTLOff:connTrackValueTTLOff+8], 10)
	liveVal := make([]byte, ctValueSize)
	binary.LittleEndian.PutUint64(liveVal[connTrackValueTimestampOff:connTrackValueTimestampOff+8], 100)
	binary.LittleEndian.PutUint64(liveVal[connTrackValueLastTimestampOff:connTrackValueLastTimestampOff+8], 130)
	binary.LittleEndian.PutUint64(liveVal[connTrackValueTTLOff:connTrackValueTTLOff+8], 500)

	if err := m.Put(expired.ToCtKeyV6(), expiredVal); err != nil {
		t.Fatalf("put expired v6: %v", err)
	}
	if err := m.Put(live.ToCtKeyV6(), liveVal); err != nil {
		t.Fatalf("put live v6: %v", err)
	}

	stats, err := sampleAndReapConnTrackOnMap(m, connTrackFamilyV6, 200)
	if err != nil {
		t.Fatalf("sampleAndReapConnTrackOnMap(v6): %v", err)
	}
	if stats.Entries != 2 {
		t.Fatalf("V6 Entries = %d, want 2 (pre-reap sample should count both entries)", stats.Entries)
	}
	if stats.MaxEntries != 16 {
		t.Fatalf("V6 MaxEntries = %d, want 16", stats.MaxEntries)
	}
	if stats.ExpiredDeleted != 1 {
		t.Fatalf("V6 ExpiredDeleted = %d, want 1", stats.ExpiredDeleted)
	}
	if stats.OldestAgeNanos != 70 {
		t.Fatalf("V6 OldestAgeNanos = %d, want 70 (oldest surviving entry after quiet reaper)", stats.OldestAgeNanos)
	}

	out := make([]byte, ctValueSize)
	if err := m.Lookup(expired.ToCtKeyV6(), &out); !isEbpfNoEntry(err) {
		t.Fatalf("expired v6 conntrack lookup err = %v, want no-entry after quiet reaper", err)
	}
	out = make([]byte, ctValueSize)
	if err := m.Lookup(live.ToCtKeyV6(), &out); err != nil {
		t.Fatalf("live v6 conntrack lookup err = %v, want survivor untouched", err)
	}
}

func TestSampleAndReapConnTrackOnMap_RespectsDeleteBudget(t *testing.T) {
	m, ok := newTestConnTrackMap(t)
	if !ok {
		return
	}
	defer func() { _ = m.Close() }()

	src, err := parseIP("198.51.100.7")
	if err != nil {
		t.Fatalf("parseIP(src): %v", err)
	}
	dst, err := parseIP("203.0.113.10")
	if err != nil {
		t.Fatalf("parseIP(dst): %v", err)
	}
	expiredVal := make([]byte, ctValueSize)
	binary.LittleEndian.PutUint64(expiredVal[connTrackValueTimestampOff:connTrackValueTimestampOff+8], 100)
	binary.LittleEndian.PutUint64(expiredVal[connTrackValueLastTimestampOff:connTrackValueLastTimestampOff+8], 120)
	binary.LittleEndian.PutUint64(expiredVal[connTrackValueTTLOff:connTrackValueTTLOff+8], 10)

	for i := uint16(0); i < 2; i++ {
		key := &connTrackKey{DstIP: dst, SrcIP: src, DstPort: 443, SrcPort: 43210 + i, NextHdr: 6, Flags: ctDirIngress}
		if err := m.Put(key.ToCtKey(), expiredVal); err != nil {
			t.Fatalf("put expired %d: %v", i, err)
		}
	}

	stats, err := sampleAndReapConnTrackOnMapWithBudget(m, connTrackFamilyV4, 200, 1)
	if err != nil {
		t.Fatalf("sampleAndReapConnTrackOnMapWithBudget: %v", err)
	}
	if stats.Entries != 2 {
		t.Fatalf("Entries = %d, want 2", stats.Entries)
	}
	if stats.ExpiredDeleted != 1 {
		t.Fatalf("ExpiredDeleted = %d, want delete budget 1", stats.ExpiredDeleted)
	}

	if got := connTrackEntryCount(t, m); got != 1 {
		t.Fatalf("remaining entries after budgeted reap = %d, want 1", got)
	}
}

func connTrackEntryCount(t *testing.T, m *cebpf.Map) int {
	t.Helper()

	info, err := m.Info()
	if err != nil {
		t.Fatalf("conntrack map info: %v", err)
	}
	keyBytes := make([]byte, info.KeySize)
	valBytes := make([]byte, info.ValueSize)
	n := 0
	iter := m.Iterate()
	for iter.Next(&keyBytes, &valBytes) {
		n++
	}
	if err := iter.Err(); err != nil {
		t.Fatalf("iterate conntrack map entries: %v", err)
	}
	return n
}

func TestSampleAndReapConnTrackPinned_MissingMapIsSampleError(t *testing.T) {
	stats, err := sampleAndReapConnTrackPinned("/sys/fs/bpf/nhp-test-missing-conn-track", connTrackFamilyV4, 200)
	if !errors.Is(err, ErrConnTrackMapNotPinned) {
		t.Fatalf("sample missing pinned map err = %v, want ErrConnTrackMapNotPinned", err)
	}
	if !stats.MapNotPinned {
		t.Fatal("MapNotPinned = false, want true")
	}
	if !stats.SampleError {
		t.Fatal("SampleError = false, want true so AC emits MetricEbpfConntrackSampleErrors")
	}
}
