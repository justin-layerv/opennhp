//go:build linux

package ac

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"

	conntrack "github.com/florianl/go-conntrack"
	"golang.org/x/sys/unix"

	"github.com/OpenNHP/opennhp/nhp/log"
)

// ctEventIndex is the #2908 steady-state accelerator for the netlink
// ConntrackFlusher. It subscribes to conntrack NEW/UPDATE/DESTROY events and
// maintains a userspace source-port/full-origin index keyed by the same
// partial tuple a FlowKey can express. A healthy index lets Flush skip the
// O(table) family dump and delete exactly the currently-known origins for the
// key. If the multicast stream errors, the index is marked unhealthy and Flush
// falls back to the old dump-and-filter path rather than silently missing flows.
type ctEventIndex struct {
	mu       sync.RWMutex
	byQuery  map[ctIndexQueryKey]map[ctOriginKey]struct{}
	byOrigin map[ctOriginKey]*conntrack.IPTuple
	// backfilling is true from subscription start until the initial table dump
	// is installed. Events received in that window are buffered and replayed
	// after the snapshot so a DESTROY that races the dump cannot be overwritten
	// back into the index, and a NEW after the dump cannot be lost.
	backfilling bool
	pending     []ctPendingEvent

	healthy          atomic.Bool
	events           atomic.Uint64
	errors           atomic.Uint64
	pendingOverflows atomic.Uint64
	// originCount mirrors len(byOrigin) so the IndexOrigins gauge does not
	// contend with hot event application. Keep every byOrigin mutation paired:
	// rebuild Store(len), upsert +1, remove/removeOrigins -1, reclaim Store(0).
	// TestConntrackEventIndexOriginCountTracksMutations fences the invariant.
	originCount atomic.Int64
	closed      atomic.Bool

	monitor *conntrack.Nfct
	cancel  context.CancelFunc
}

type ctIndexQueryKey struct {
	family                conntrack.Family
	srcIP, dstIP          [16]byte
	proto                 uint8
	dstPort               uint16
	filterProto           bool
	filterDestinationPort bool
}

type ctOriginKey struct {
	family       conntrack.Family
	srcIP, dstIP [16]byte
	proto        uint8
	srcPort      uint16
	dstPort      uint16
	icmpID       uint16
	icmpType     uint8
	icmpCode     uint8
	icmpv6ID     uint16
	icmpv6Type   uint8
	icmpv6Code   uint8
	zone         uint16
	hasZone      bool
}

type ctPendingEvent struct {
	group  conntrack.NetlinkGroup
	origin *conntrack.IPTuple
}

// defaultConntrackEventReadBuffer gives the monitor socket more burst headroom
// than the OS default. Do NOT set NETLINK_NO_ENOBUFS: ENOBUFS on this socket is
// the load-bearing signal that multicast events may have been dropped, so the
// index must go unhealthy and Flush must fall back to dump-and-filter.
const defaultConntrackEventReadBuffer = 4 << 20

// defaultConntrackEventPendingLimit bounds startup replay memory while the
// initial dump is in flight. Overflow disables the hot-path index and keeps the
// safe dump fallback rather than risking startup OOM on a high-churn table.
const defaultConntrackEventPendingLimit = 1 << 18

func newCtEventIndex() (*ctEventIndex, error) {
	idx := &ctEventIndex{
		byQuery:     make(map[ctIndexQueryKey]map[ctOriginKey]struct{}),
		byOrigin:    make(map[ctOriginKey]*conntrack.IPTuple),
		backfilling: true,
	}

	nfct, err := conntrack.Open(&conntrack.Config{AddConntrackInformation: true})
	if err != nil {
		return nil, err
	}
	// mdlayher/netlink delegates to mdlayher/socket here; on Linux that tries
	// SO_RCVBUFFORCE before falling back to SO_RCVBUF, so CAP_NET_ADMIN ACs
	// avoid the usual net.core.rmem_max clamp while unprivileged runs stay safe.
	if err := nfct.Con.SetReadBuffer(defaultConntrackEventReadBuffer); err != nil {
		log.Warning("[ConntrackFlusher] conntrack event index could not raise netlink receive buffer to %d bytes: %v", defaultConntrackEventReadBuffer, err)
	}
	errCh := nfct.AttachErrChan()
	ctx, cancel := context.WithCancel(context.Background())
	idx.monitor = nfct
	idx.cancel = cancel

	groups := conntrack.NetlinkCtNew | conntrack.NetlinkCtUpdate | conntrack.NetlinkCtDestroy
	if err := nfct.Register(ctx, conntrack.Conntrack, groups, idx.handleEvent); err != nil {
		cancel()
		_ = nfct.Close()
		return nil, err
	}
	go idx.watchErrors(ctx, errCh)

	return idx, nil
}

func (idx *ctEventIndex) Close() error {
	if idx == nil || idx.monitor == nil {
		return nil
	}
	if !idx.closed.CompareAndSwap(false, true) {
		return nil
	}
	if idx.cancel != nil {
		idx.cancel()
	}
	return idx.monitor.Close()
}

func (idx *ctEventIndex) watchErrors(ctx context.Context, errCh <-chan error) {
	for {
		select {
		case err, ok := <-errCh:
			if !ok {
				return
			}
			if err == nil {
				continue
			}
			idx.markUnhealthy(err)
		case <-ctx.Done():
			return
		}
	}
}

func (idx *ctEventIndex) markUnhealthy(err error) {
	idx.mu.Lock()
	shouldLog := idx.markUnhealthyLocked()
	idx.mu.Unlock()
	if shouldLog {
		logConntrackEventIndexUnhealthy(err)
	}
}

func (idx *ctEventIndex) markUnhealthyLocked() bool {
	shouldLog := idx.errors.Add(1) == 1
	idx.healthy.Store(false)
	idx.reclaimMirrorLocked()
	if idx.backfilling {
		idx.pending = nil
	}
	return shouldLog
}

// reclaimMirrorLocked drops the userspace origin mirror. Once the index is
// disabled it is never read again (Flush falls back to dump/filter until AC
// restart, #2946), so releasing both maps returns the dead RSS at million-entry
// scale and drives OriginCount/IndexOrigins to 0 as the disabled-state signal.
// Already-empty maps are left in place so repeated stream errors do not churn
// fresh allocations after the first disable.
func (idx *ctEventIndex) reclaimMirrorLocked() {
	if len(idx.byQuery) == 0 && len(idx.byOrigin) == 0 {
		idx.originCount.Store(0)
		return
	}
	idx.byQuery = make(map[ctIndexQueryKey]map[ctOriginKey]struct{})
	idx.byOrigin = make(map[ctOriginKey]*conntrack.IPTuple)
	idx.originCount.Store(0)
}

func logConntrackEventIndexUnhealthy(err error) {
	log.Warning("[ConntrackFlusher] conntrack event index disabled; falling back to per-Flush dumps until AC restart: %v", err)
}

func (idx *ctEventIndex) handleEvent(con conntrack.Con) int {
	if idx == nil {
		return 0
	}
	if con.Info == nil {
		// AddConntrackInformation should populate NetlinkGroup for every event;
		// without it we cannot distinguish create/update from destroy, so fail
		// closed to dump/filter instead of trusting an ambiguous stream.
		idx.markUnhealthy(fmt.Errorf("conntrack event missing InfoSource"))
		return 0
	}
	switch con.Info.NetlinkGroup {
	case conntrack.NetlinkCtDestroy, conntrack.NetlinkCtNew, conntrack.NetlinkCtUpdate:
		if idx.errors.Load() > 0 {
			// Once a stream error permanently disables the index, valid-group events
			// are only useful as a liveness signal. Avoid taking idx.mu on the
			// fallback-only path; #2946 owns any future runtime re-arm.
			idx.events.Add(1)
			return 0
		}
		var unhealthyErr error
		countEvent := true
		idx.mu.Lock()
		if idx.backfilling {
			switch {
			case idx.errors.Load() > 0:
				// Raced-disable re-check: markUnhealthy may have landed after the
				// top-of-function fast path. Do not retain replay events that cannot
				// make the index healthy after the startup dump.
				idx.pending = nil
			case len(idx.pending) >= defaultConntrackEventPendingLimit:
				unhealthyErr = fmt.Errorf("conntrack event pending buffer exceeded %d during backfill", defaultConntrackEventPendingLimit)
				idx.pendingOverflows.Add(1)
				countEvent = false
				if !idx.markUnhealthyLocked() {
					unhealthyErr = nil
				}
			default:
				// Pending owns the minimal event data needed for startup
				// replay, so replay does not depend on go-conntrack callback
				// buffer lifetime or retain unused reply/status fields.
				idx.pending = append(idx.pending, pendingEventFromCon(con))
			}
		} else if idx.healthy.Load() {
			idx.applyEventLocked(con)
		}
		idx.mu.Unlock()
		if unhealthyErr != nil {
			logConntrackEventIndexUnhealthy(unhealthyErr)
		}
		if !countEvent {
			return 0
		}
	default:
		// The subscription only asks for the three groups above. Treat a new
		// value as stream skew and fall back to dumps before trusting the index.
		idx.markUnhealthy(fmt.Errorf("unexpected conntrack netlink group %d", con.Info.NetlinkGroup))
		return 0
	}
	idx.events.Add(1)
	return 0
}

func (idx *ctEventIndex) rebuild(cons []conntrack.Con) int {
	nextByQuery := make(map[ctIndexQueryKey]map[ctOriginKey]struct{})
	nextByOrigin := make(map[ctOriginKey]*conntrack.IPTuple)
	indexed := 0
	for i := range cons {
		key, origin, ok := indexedOriginFromCon(&cons[i])
		if !ok {
			continue
		}
		addIndexedOrigin(nextByQuery, nextByOrigin, key, origin)
		indexed++
	}

	idx.mu.Lock()
	idx.byQuery = nextByQuery
	idx.byOrigin = nextByOrigin
	idx.originCount.Store(int64(len(nextByOrigin)))
	pending := idx.pending
	idx.pending = nil
	idx.backfilling = false
	for _, event := range pending {
		idx.applyPendingEventLocked(event)
	}
	if idx.errors.Load() == 0 {
		idx.healthy.Store(true)
	} else {
		// A stream error landed during backfill: discard the snapshot we just
		// installed (markUnhealthyLocked already ran, but before the maps were
		// populated) and stay disabled rather than trust a partial mirror.
		idx.reclaimMirrorLocked()
		idx.healthy.Store(false)
	}
	idx.mu.Unlock()
	return indexed
}

func (idx *ctEventIndex) upsertOriginLocked(origin *conntrack.IPTuple, clone bool) {
	key, ok := originKeyFromIPTuple(origin)
	if !ok {
		return
	}
	if _, exists := idx.byOrigin[key]; exists {
		return
	}
	if clone {
		origin = cloneIPTuple(origin)
		if origin == nil {
			return
		}
	}
	addIndexedOrigin(idx.byQuery, idx.byOrigin, key, origin)
	idx.originCount.Add(1)
}

func (idx *ctEventIndex) removeOriginLocked(origin *conntrack.IPTuple) {
	key, ok := originKeyFromIPTuple(origin)
	if !ok {
		return
	}
	if removeIndexedOrigin(idx.byQuery, idx.byOrigin, key) {
		idx.originCount.Add(-1)
	}
}

func pendingEventFromCon(con conntrack.Con) ctPendingEvent {
	return ctPendingEvent{
		group:  con.Info.NetlinkGroup,
		origin: cloneIPTuple(con.Origin),
	}
}

func (idx *ctEventIndex) applyEventLocked(con conntrack.Con) {
	idx.applyGroupOriginLocked(con.Info.NetlinkGroup, con.Origin, true)
}

func (idx *ctEventIndex) applyPendingEventLocked(event ctPendingEvent) {
	idx.applyGroupOriginLocked(event.group, event.origin, false)
}

func (idx *ctEventIndex) applyGroupOriginLocked(group conntrack.NetlinkGroup, origin *conntrack.IPTuple, clone bool) {
	switch group {
	case conntrack.NetlinkCtDestroy:
		idx.removeOriginLocked(origin)
	case conntrack.NetlinkCtNew, conntrack.NetlinkCtUpdate:
		idx.upsertOriginLocked(origin, clone)
	}
}

func (idx *ctEventIndex) removeOrigins(origins []*conntrack.IPTuple) {
	if idx == nil || len(origins) == 0 {
		return
	}
	keys := make([]ctOriginKey, 0, len(origins))
	for _, origin := range origins {
		key, ok := originKeyFromIPTuple(origin)
		if ok {
			keys = append(keys, key)
		}
	}
	if len(keys) == 0 {
		return
	}
	idx.mu.Lock()
	for _, key := range keys {
		if removeIndexedOrigin(idx.byQuery, idx.byOrigin, key) {
			idx.originCount.Add(-1)
		}
	}
	idx.mu.Unlock()
}

func (idx *ctEventIndex) originsForKey(key FlowKey) ([]*conntrack.IPTuple, bool) {
	if idx == nil {
		return nil, false
	}
	query := indexQueryForFlowKey(key)

	idx.mu.RLock()
	if !idx.healthy.Load() {
		idx.mu.RUnlock()
		return nil, false
	}
	originKeys := idx.byQuery[query]
	if len(originKeys) == 0 {
		idx.mu.RUnlock()
		return nil, true
	}
	origins := make([]*conntrack.IPTuple, 0, len(originKeys))
	for originKey := range originKeys {
		origin, ok := idx.byOrigin[originKey]
		if !ok {
			continue
		}
		origins = append(origins, cloneIPTuple(origin))
	}
	idx.mu.RUnlock()
	return origins, true
}

func (idx *ctEventIndex) EventCount() uint64 {
	if idx == nil {
		return 0
	}
	return idx.events.Load()
}

func (idx *ctEventIndex) OriginCount() uint64 {
	if idx == nil {
		return 0
	}
	count := idx.originCount.Load()
	if count < 0 {
		return 0
	}
	return uint64(count)
}

func (idx *ctEventIndex) ErrorCount() uint64 {
	if idx == nil {
		return 0
	}
	return idx.errors.Load()
}

func (idx *ctEventIndex) PendingOverflowCount() uint64 {
	if idx == nil {
		return 0
	}
	return idx.pendingOverflows.Load()
}

func addIndexedOrigin(byQuery map[ctIndexQueryKey]map[ctOriginKey]struct{}, byOrigin map[ctOriginKey]*conntrack.IPTuple, key ctOriginKey, origin *conntrack.IPTuple) {
	byOrigin[key] = origin
	queries, n := indexQueriesForOriginKey(key)
	for i := 0; i < n; i++ {
		query := queries[i]
		origins := byQuery[query]
		if origins == nil {
			origins = make(map[ctOriginKey]struct{})
			byQuery[query] = origins
		}
		origins[key] = struct{}{}
	}
}

func removeIndexedOrigin(byQuery map[ctIndexQueryKey]map[ctOriginKey]struct{}, byOrigin map[ctOriginKey]*conntrack.IPTuple, key ctOriginKey) bool {
	if _, ok := byOrigin[key]; !ok {
		return false
	}
	queries, n := indexQueriesForOriginKey(key)
	for i := 0; i < n; i++ {
		query := queries[i]
		origins := byQuery[query]
		if len(origins) == 0 {
			continue
		}
		delete(origins, key)
		if len(origins) == 0 {
			delete(byQuery, query)
		}
	}
	delete(byOrigin, key)
	return true
}

func indexedOriginFromCon(con *conntrack.Con) (ctOriginKey, *conntrack.IPTuple, bool) {
	if con == nil {
		return ctOriginKey{}, nil, false
	}
	key, ok := originKeyFromIPTuple(con.Origin)
	if !ok {
		return ctOriginKey{}, nil, false
	}
	origin := cloneIPTuple(con.Origin)
	if origin == nil {
		return ctOriginKey{}, nil, false
	}
	return key, origin, true
}

func indexQueryForFlowKey(key FlowKey) ctIndexQueryKey {
	family := familyForKey(key)
	wantProto, filterProto, filterPort := conntrackMatchSpec(key, family == conntrack.IPv6)
	dstPort := key.DstPort
	if !filterProto {
		wantProto = 0
	}
	if !filterPort {
		dstPort = 0
	}
	return ctIndexQueryKey{
		family:                family,
		srcIP:                 key.SrcIP,
		dstIP:                 key.DstIP,
		proto:                 wantProto,
		dstPort:               dstPort,
		filterProto:           filterProto,
		filterDestinationPort: filterPort,
	}
}

func indexQueriesForTuple(t ctTuple, family conntrack.Family) ([3]ctIndexQueryKey, int) {
	queries := [3]ctIndexQueryKey{
		{
			family: family,
			srcIP:  t.srcIP,
			dstIP:  t.dstIP,
			// FlowProtoAny equivalent: src/dst only.
			filterProto: false,
		},
		{
			family:      family,
			srcIP:       t.srcIP,
			dstIP:       t.dstIP,
			proto:       t.proto,
			filterProto: true,
		},
	}
	n := 2
	if (t.proto == unix.IPPROTO_TCP || t.proto == unix.IPPROTO_UDP) && t.dstPort != 0 {
		queries[n] = ctIndexQueryKey{
			family:                family,
			srcIP:                 t.srcIP,
			dstIP:                 t.dstIP,
			proto:                 t.proto,
			dstPort:               t.dstPort,
			filterProto:           true,
			filterDestinationPort: true,
		}
		n++
	}
	return queries, n
}

func indexQueriesForOriginKey(key ctOriginKey) ([3]ctIndexQueryKey, int) {
	return indexQueriesForTuple(ctTuple{
		srcIP:   key.srcIP,
		dstIP:   key.dstIP,
		proto:   key.proto,
		dstPort: key.dstPort,
	}, key.family)
}

func originKeyFromIPTuple(origin *conntrack.IPTuple) (ctOriginKey, bool) {
	con := conntrack.Con{Origin: origin}
	t, ok := conToTuple(&con)
	if !ok {
		return ctOriginKey{}, false
	}
	return originKeyFromTuple(t, origin)
}

func originKeyFromTuple(t ctTuple, origin *conntrack.IPTuple) (ctOriginKey, bool) {
	key := ctOriginKey{
		family:  familyForIPs(t.srcIP, t.dstIP),
		srcIP:   t.srcIP,
		dstIP:   t.dstIP,
		proto:   t.proto,
		srcPort: t.srcPort,
		dstPort: t.dstPort,
	}
	if origin == nil {
		return key, false
	}
	if origin.Zone != nil {
		key.zone = *origin.Zone
		key.hasZone = true
	}
	if origin.Proto != nil {
		p := origin.Proto
		if p.IcmpID != nil {
			key.icmpID = *p.IcmpID
		}
		if p.IcmpType != nil {
			key.icmpType = *p.IcmpType
		}
		if p.IcmpCode != nil {
			key.icmpCode = *p.IcmpCode
		}
		if p.Icmpv6ID != nil {
			key.icmpv6ID = *p.Icmpv6ID
		}
		if p.Icmpv6Type != nil {
			key.icmpv6Type = *p.Icmpv6Type
		}
		if p.Icmpv6Code != nil {
			key.icmpv6Code = *p.Icmpv6Code
		}
	}
	return key, true
}

func cloneIPTuple(in *conntrack.IPTuple) *conntrack.IPTuple {
	if in == nil {
		return nil
	}
	out := &conntrack.IPTuple{}
	if in.Src != nil {
		src := append(net.IP(nil), (*in.Src)...)
		out.Src = &src
	}
	if in.Dst != nil {
		dst := append(net.IP(nil), (*in.Dst)...)
		out.Dst = &dst
	}
	if in.Zone != nil {
		zone := *in.Zone
		out.Zone = &zone
	}
	if in.Proto != nil {
		out.Proto = cloneProtoTuple(in.Proto)
	}
	return out
}

func cloneProtoTuple(in *conntrack.ProtoTuple) *conntrack.ProtoTuple {
	if in == nil {
		return nil
	}
	out := &conntrack.ProtoTuple{}
	if in.Number != nil {
		v := *in.Number
		out.Number = &v
	}
	if in.SrcPort != nil {
		v := *in.SrcPort
		out.SrcPort = &v
	}
	if in.DstPort != nil {
		v := *in.DstPort
		out.DstPort = &v
	}
	if in.IcmpID != nil {
		v := *in.IcmpID
		out.IcmpID = &v
	}
	if in.IcmpType != nil {
		v := *in.IcmpType
		out.IcmpType = &v
	}
	if in.IcmpCode != nil {
		v := *in.IcmpCode
		out.IcmpCode = &v
	}
	if in.Icmpv6ID != nil {
		v := *in.Icmpv6ID
		out.Icmpv6ID = &v
	}
	if in.Icmpv6Type != nil {
		v := *in.Icmpv6Type
		out.Icmpv6Type = &v
	}
	if in.Icmpv6Code != nil {
		v := *in.Icmpv6Code
		out.Icmpv6Code = &v
	}
	return out
}
