package ac

// BpfConntrackStats is the build-tag-free AC view of the eBPF conntrack and
// IPv6 fragment-state maps. The Linux BpfFlusher fills it from nhp/utils/ebpf;
// non-Linux and non-EBPFXDP paths return the zero value so registration.go can
// publish gauges without taking a build-tag dependency.
//
// UdpAC also consumes the cumulative counter watermarks while metrics gauge
// callbacks run serially. A future concurrent/direct reader must make the
// watermark publish/commit path stronger before consuming those deltas.
type BpfConntrackStats struct {
	V4Entries          uint64
	V4MaxEntries       uint64
	V4UsagePercent     float64
	V4OldestAgeSeconds float64
	// V4ExpiredReaped is BpfFlusher's cumulative v4 quiet-expired delete
	// watermark. UdpAC converts unseen deltas into reset-per-flush
	// MetricEbpfConntrackV4ExpiredReaped counter events; registration.go does
	// not publish this value as a gauge.
	V4ExpiredReaped    uint64
	V6Entries          uint64
	V6MaxEntries       uint64
	V6UsagePercent     float64
	V6OldestAgeSeconds float64
	// V6ExpiredReaped is the v6 twin of V4ExpiredReaped.
	V6ExpiredReaped uint64
	// V6Frag* tracks the IPv6 later-fragment admission-state map separately
	// from established-flow conn_track_v6 so fragment churn cannot hide inside
	// ordinary conntrack occupancy.
	V6FragEntries       uint64
	V6FragMaxEntries    uint64
	V6FragUsagePercent  float64
	V6FragExpiredReaped uint64
	// SppExpiredReaped is BpfFlusher's cumulative count of expired entries
	// deleted from the shared `spp` allow-rule map — the GC for tc-egress
	// datapath-written return-path pinholes, which have no scheduled flush (spp
	// is HASH since #2163, so no LRU eviction). UdpAC converts unseen deltas into
	// reset-per-flush MetricEbpfSppExpiredReaped counter events; not a gauge.
	SppExpiredReaped uint64
	// SppReapPartialSamples / SppReapErrors are the spp sweep's own health
	// watermarks, kept separate from the conntrack ones so an spp-specific
	// aborted-walk or failure stays distinguishable in dashboards. A chronically
	// non-zero SppReapPartialSamples means the fill defense isn't engaging under
	// churn. Reset-per-flush MetricEbpfSppReapPartialSamples / MetricEbpfSppReapErrors.
	SppReapPartialSamples uint64
	SppReapErrors         uint64
	// SppEntries / SppMaxEntries / SppUsagePercent are the point-in-time occupancy
	// of the shared `spp` allow-rule map (post-reap live entries, capacity, and
	// percent), published as gauges. This is the direct prod-flip burst-fill signal
	// the reaper's counters can't give: a burst of >max_entries distinct egress
	// reverse-tuples inside the 180s TTL fills `spp` before any entry is
	// reap-eligible → new admissions get -E2BIG, and that shows up here as
	// occupancy near max_entries, NOT as a slow walk or a partial-sample tick. The
	// reaper computes Entries/MaxEntries on every walk anyway, so this is free.
	SppEntries      uint64
	SppMaxEntries   uint64
	SppUsagePercent float64
	// SampleDurationSeconds is the wall-clock duration of the most recent
	// sample/reap attempt — covering BOTH full-map walks the lifecycle sampler
	// runs per pass: the conn_track sample/reap and the spp allow-rule sweep. It
	// is a gauge so flip validation can see full-map walk latency in CloudWatch
	// instead of relying only on AC logs.
	SampleDurationSeconds float64
	// SampleErrors is BpfFlusher's cumulative sample/reaper failure watermark.
	// UdpAC converts unseen deltas into reset-per-flush
	// MetricEbpfConntrackSampleErrors counter events; registration.go does not
	// publish this value as a gauge.
	SampleErrors uint64
	// PartialSamples is BpfFlusher's cumulative count of conntrack map samples
	// where concurrent HASH churn aborted iteration before a complete pass.
	// UdpAC converts unseen deltas into reset-per-flush
	// MetricEbpfConntrackPartialSamples counter events.
	PartialSamples uint64
}
