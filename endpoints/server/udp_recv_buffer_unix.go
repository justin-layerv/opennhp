//go:build linux || darwin

package server

import (
	"syscall"
)

// getsockoptIntRcvBuf reads the effective SO_RCVBUF value from the
// kernel after SetReadBuffer + any kernel clamping has happened.
// Split into a build-tagged file so the verify path compiles on
// both Linux (production) and Darwin (developer laptops); other
// platforms fall back to the no-verify stub.
func getsockoptIntRcvBuf(fd uintptr) (int, error) {
	return syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF)
}
