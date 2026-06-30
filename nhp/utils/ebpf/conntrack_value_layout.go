package ebpf

const (
	connTrackValueTimestampOff     = 0
	connTrackValueLastTimestampOff = 8
	connTrackValueTTLOff           = 16
	connTrackValueMinSize          = connTrackValueTTLOff + 8
)
