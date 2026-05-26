//go:build linux

package ebpf

import (
	"fmt"

	"golang.org/x/sys/unix"
)

func getBootTimeNanos() (uint64, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		return 0, fmt.Errorf("clock_gettime failed: %w", err)
	}
	return uint64(ts.Sec)*1_000_000_000 + uint64(ts.Nsec), nil
}
