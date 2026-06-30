package ac

// BpfConntrackStats is the build-tag-free AC view of the eBPF established-flow
// conntrack maps. The Linux BpfFlusher fills it from nhp/utils/ebpf; non-Linux
// and non-EBPFXDP paths return the zero value so registration.go can publish
// gauges without taking a build-tag dependency.
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
	// SampleDurationSeconds is the wall-clock duration of the most recent
	// sample/reap attempt. It is a gauge so flip validation can see full-map
	// walk latency in CloudWatch instead of relying only on AC logs.
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
