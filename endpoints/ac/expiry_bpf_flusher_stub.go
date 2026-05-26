//go:build !linux

package ac

import (
	"context"
	"errors"
)

// BpfFlusher is the non-Linux build stub. The real implementation
// lives in expiry_bpf_flusher_linux.go and reads/writes the pinned
// BPF maps under /sys/fs/bpf/.
//
// Existence of this stub keeps `go build ./endpoints/ac/...` green
// on darwin / windows developer machines; it never runs in
// production (AC always builds for Linux).
type BpfFlusher struct{}

// NewBpfFlusher returns an error on non-Linux platforms.
// AC initialization in udpac.go uses this to refuse construction
// outside Linux — preventing accidental dry-run testing on macOS
// that would silently no-op.
func NewBpfFlusher() (*BpfFlusher, error) {
	return nil, errors.New("BpfFlusher requires Linux")
}

// Flush implements FlowFlusher on non-Linux as a hard error.
func (f *BpfFlusher) Flush(_ context.Context, _ FlowKey) error {
	return errors.New("BpfFlusher: not supported on this platform")
}

// SkippedCount is the cross-platform symmetry stub for the Linux
// implementation's non-IPv4 skip counter. Returns 0 on non-Linux —
// the production AC never executes this path; the stub exists so
// the metrics-publishing code (registration.go) can compile across
// platforms without build-tagging the gauge.
func (f *BpfFlusher) SkippedCount() uint64 { return 0 }
