//go:build !linux

package ebpf

// ReapExpiredWhitelist is a no-op off Linux: the pinned `spp` allow-rule map and
// the eBPF datapath that fills it only exist under FilterMode=EBPFXDP on Linux.
// Mirrors the Linux signature so the cross-platform caller needs no build tags.
func ReapExpiredWhitelist() (WhitelistReapStats, error) { return WhitelistReapStats{}, nil }
