//go:build !linux

package ac

import (
	"context"
	"errors"
)

// ConntrackFlusher is the non-Linux build stub. The real implementation
// lives in expiry_conntrack_flusher_linux.go (exec backend) +
// expiry_conntrack_flusher_netlink_linux.go (netlink backend).
//
// Existence of this stub keeps `go build ./endpoints/ac/...` green on
// darwin / windows developer machines; it never runs in production (AC
// always builds for Linux).
type ConntrackFlusher struct{}

// NewConntrackFlusher returns an error on non-Linux platforms. AC
// initialization in udpac.go uses this to refuse construction outside
// Linux — preventing accidental dry-run testing on macOS that would
// silently no-op. The variadic options match the Linux signature so the
// WithBackend toggle compiles cross-platform.
func NewConntrackFlusher(_ ...ConntrackFlusherOption) (*ConntrackFlusher, error) {
	return nil, errors.New("ConntrackFlusher requires Linux")
}

// Flush implements FlowFlusher on non-Linux as a hard error.
func (f *ConntrackFlusher) Flush(_ context.Context, _ FlowKey) error {
	return errors.New("ConntrackFlusher: not supported on this platform")
}

// HandlesIPv6 is false on non-Linux (no flusher is constructed here).
// Present so udpac.go's cross-platform Start can call it on the typed
// value without a build tag.
func (f *ConntrackFlusher) HandlesIPv6() bool { return false }

// IsNetlinkBackend is false on non-Linux (no flusher is constructed here).
// Present for netlink-specific metric gating in cross-platform code.
func (f *ConntrackFlusher) IsNetlinkBackend() bool { return false }

// Close is a no-op on non-Linux. Present for the same cross-platform
// reason as HandlesIPv6 (udpac.go Stop calls it).
func (f *ConntrackFlusher) Close() error { return nil }

// NetlinkDeletedCount is 0 on non-Linux (no netlink backend). Present so
// the cross-platform metrics gauge can read it without a build tag.
func (f *ConntrackFlusher) NetlinkDeletedCount() uint64 { return 0 }

// NetlinkSlowDumpCount is 0 on non-Linux. Present for the same
// cross-platform metrics-gauge reason as NetlinkDeletedCount.
func (f *ConntrackFlusher) NetlinkSlowDumpCount() uint64 { return 0 }

// NetlinkIndexedFlushCount is 0 on non-Linux. Present for the same
// cross-platform metrics-gauge reason as NetlinkDeletedCount.
func (f *ConntrackFlusher) NetlinkIndexedFlushCount() uint64 { return 0 }

// NetlinkIndexFallbackDumpCount is 0 on non-Linux. Present for the same
// cross-platform metrics-gauge reason as NetlinkDeletedCount.
func (f *ConntrackFlusher) NetlinkIndexFallbackDumpCount() uint64 { return 0 }

// NetlinkIndexAuthoritativeDumpCount is 0 on non-Linux. Present for the same
// cross-platform metrics-gauge reason as NetlinkDeletedCount.
func (f *ConntrackFlusher) NetlinkIndexAuthoritativeDumpCount() uint64 { return 0 }

// NetlinkIndexEventErrorCount is 0 on non-Linux. Present for the same
// cross-platform metrics-gauge reason as NetlinkDeletedCount.
func (f *ConntrackFlusher) NetlinkIndexEventErrorCount() uint64 { return 0 }

// NetlinkIndexPendingOverflowCount is 0 on non-Linux. Present for the same
// cross-platform metrics-gauge reason as NetlinkDeletedCount.
func (f *ConntrackFlusher) NetlinkIndexPendingOverflowCount() uint64 { return 0 }

// NetlinkIndexEventCount is 0 on non-Linux. Present for the same
// cross-platform metrics-gauge reason as NetlinkDeletedCount.
func (f *ConntrackFlusher) NetlinkIndexEventCount() uint64 { return 0 }

// NetlinkIndexOriginCount is 0 on non-Linux. Present for the same
// cross-platform metrics-gauge reason as NetlinkDeletedCount.
func (f *ConntrackFlusher) NetlinkIndexOriginCount() uint64 { return 0 }

// NetlinkIndexResyncAttemptCount is 0 on non-Linux. Present for the same
// cross-platform metrics-gauge reason as NetlinkDeletedCount.
func (f *ConntrackFlusher) NetlinkIndexResyncAttemptCount() uint64 { return 0 }

// NetlinkIndexResyncSuccessCount is 0 on non-Linux. Present for the same
// cross-platform metrics-gauge reason as NetlinkDeletedCount.
func (f *ConntrackFlusher) NetlinkIndexResyncSuccessCount() uint64 { return 0 }

// NetlinkIndexResyncFailureCount is 0 on non-Linux. Present for the same
// cross-platform metrics-gauge reason as NetlinkDeletedCount.
func (f *ConntrackFlusher) NetlinkIndexResyncFailureCount() uint64 { return 0 }

// SkippedCount is 0 on non-Linux. It is not currently read cross-platform for
// ConntrackFlusher, but keeping the stub method symmetric with Linux prevents
// future metric plumbing from needing another build-tag split.
func (f *ConntrackFlusher) SkippedCount() uint64 { return 0 }
