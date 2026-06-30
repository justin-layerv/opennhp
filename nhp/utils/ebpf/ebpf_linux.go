//go:build linux

package ebpf

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// getBootTimeNanos is the package-wide userspace clock for values compared to
// eBPF timestamps. It intentionally follows the existing BOOTTIME convention:
// AC hosts are assumed not to suspend, so BOOTTIME stays equivalent to XDP's
// bpf_ktime_get_ns MONOTONIC domain. If that host invariant ever changes,
// call sites must re-check whether premature expiry is still harmless.
func getBootTimeNanos() (uint64, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		return 0, fmt.Errorf("clock_gettime failed: %w", err)
	}
	return uint64(ts.Sec)*1_000_000_000 + uint64(ts.Nsec), nil
}
