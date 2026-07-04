package ebpf

type whitelistReapTarget struct {
	mapName          string
	pinPath          string
	label            string
	keySize          int
	valueSize        int
	expireTimeOffset int
}

// whitelistReapTargets is the registry of tc-egress-written allow-rule maps
// that have no scheduler-owned expiry path and therefore must be swept by
// ReapExpiredWhitelist. Keep this in lockstep with tc_egress.c map writes; the
// source-level guard in maptype_test.go fails if a future tc-egress writer, such
// as spp_v6, lands without a matching target here. It intentionally lives in the
// build-tag-free file so that source guard can run outside GOOS=linux too.
var whitelistReapTargets = []whitelistReapTarget{
	{
		mapName:   "spp",
		pinPath:   PinPathWhitelist,
		label:     "spp allow-rule",
		keySize:   whitelistKeySize,
		valueSize: WhitelistValueSize,
		// This target's value is whitelistValue. A future target with a different
		// value layout must set its own decode offset here, not rely on the v4
		// whitelistValue offset by accident.
		expireTimeOffset: ExpireTimeOffset,
	},
}

// WhitelistReapStats is the cross-platform result of ReapExpiredWhitelist so the
// caller can surface the reap's health distinctly from conn_track. Zero value off
// Linux / when the map isn't pinned.
type WhitelistReapStats struct {
	// Reaped is the number of expired registered allow-rule entries deleted this
	// pass. Today the only registered target is `spp`.
	Reaped uint64
	// Partial is true when the HASH walk aborted under concurrent churn
	// (ebpf.ErrIterationAborted) before a complete pass — deletes are skipped for
	// that pass, so expired pinholes may accumulate until a later complete sweep.
	// High egress churn is exactly what both fills `spp` and aborts the walk, so a
	// chronically-partial reap is the signal the fill defense isn't engaging.
	Partial bool
	// Entries is the live registered allow-rule occupancy after this pass's reap
	// (observed entries minus the ones just deleted); MaxEntries is the combined
	// map capacity. Surfaced as an occupancy gauge so the prod-flip burst-fill
	// watch (occupancy -> max_entries -> -E2BIG on new admissions) is visible
	// directly; that mode fills within the TTL and does NOT show up as a slow
	// walk. Undercounts when Partial is set.
	Entries    uint64
	MaxEntries uint64
}
