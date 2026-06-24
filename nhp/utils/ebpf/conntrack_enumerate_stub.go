//go:build !linux

package ebpf

import "errors"

// ErrConnTrackMapNotPinned mirrors the Linux sentinel so cross-platform
// callers in endpoints/ac can errors.Is against it without build-tagging.
// On non-Linux the conntrack enumeration is never reached (the EBPFXDP
// BpfFlusher cannot be constructed off Linux — NewBpfFlusher errors), so this
// is symmetry-only.
var ErrConnTrackMapNotPinned = errors.New("conn_track bpf map not pinned")

// EnumerateConnTrackSrcPorts is the non-Linux build stub for the conntrack
// source-port enumeration primitive (P4e slice 5). Hard error, symmetric to
// BpfFlusher.FlushConn's stub — the production AC always builds for Linux;
// this keeps `go build` green on darwin / windows developer machines.
func EnumerateConnTrackSrcPorts(_, _ string, _ uint8, _ uint16) ([]uint16, error) {
	return nil, errors.New("EnumerateConnTrackSrcPorts: conntrack enumeration requires Linux")
}
