//go:build !linux

package ac

import (
	"context"
	"errors"
)

// ConntrackFlusher is the non-Linux build stub. The real
// implementation lives in expiry_conntrack_flusher_linux.go and
// shells out to the Linux `conntrack` userspace tool.
//
// Existence of this stub keeps `go build ./endpoints/ac/...` green
// on darwin / windows developer machines; it never runs in
// production (AC always builds for Linux).
type ConntrackFlusher struct{}

// NewConntrackFlusher returns an error on non-Linux platforms.
// AC initialization in udpac.go uses this to refuse construction
// outside Linux — preventing accidental dry-run testing on macOS
// that would silently no-op.
func NewConntrackFlusher() (*ConntrackFlusher, error) {
	return nil, errors.New("ConntrackFlusher requires Linux")
}

// Flush implements FlowFlusher on non-Linux as a hard error.
func (f *ConntrackFlusher) Flush(_ context.Context, _ FlowKey) error {
	return errors.New("ConntrackFlusher: not supported on this platform")
}
