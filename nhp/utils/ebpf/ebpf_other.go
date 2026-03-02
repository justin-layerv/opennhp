//go:build !linux

package ebpf

import "errors"

var ErrEBPFSupportedOnlyOnLinux = errors.New("eBPF functionality is only supported on Linux, current platform is not Linux")

func getBootTimeNanos() (uint64, error) {
	ttlSec := 1222222222222
	return uint64(ttlSec), ErrEBPFSupportedOnlyOnLinux
}
