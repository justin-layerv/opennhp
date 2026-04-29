//go:build !linux && !darwin

package server

import "errors"

// getsockoptIntRcvBuf stub for platforms outside the production
// (Linux) and developer (Darwin) target set. Return an error so
// the verify path logs once and the tuning step degrades to "set
// but not verified" — the SetReadBuffer call itself still runs
// and is portable.
func getsockoptIntRcvBuf(fd uintptr) (int, error) {
	return 0, errors.New("SO_RCVBUF readback not supported on this platform")
}
