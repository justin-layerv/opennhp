package ebpf

// WhitelistReapStats is the cross-platform result of ReapExpiredWhitelist so the
// caller can surface the reap's health distinctly from conn_track. Zero value off
// Linux / when the map isn't pinned.
type WhitelistReapStats struct {
	// Reaped is the number of expired `spp` entries deleted this pass.
	Reaped uint64
	// Partial is true when the HASH walk aborted under concurrent churn
	// (ebpf.ErrIterationAborted) before a complete pass — deletes are skipped for
	// that pass, so expired pinholes may accumulate until a later complete sweep.
	// High egress churn is exactly what both fills `spp` and aborts the walk, so a
	// chronically-partial reap is the signal the fill defense isn't engaging.
	Partial bool
	// Entries is the live `spp` occupancy after this pass's reap (observed entries
	// minus the ones just deleted); MaxEntries is the map capacity. Surfaced as an
	// occupancy gauge so the prod-flip burst-fill watch (occupancy → max_entries →
	// -E2BIG on new admissions) is visible directly — that mode fills within the
	// TTL and does NOT show up as a slow walk. Undercounts when Partial is set.
	Entries    uint64
	MaxEntries uint64
}
