package server

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/OpenNHP/opennhp/nhp/core"
	"github.com/OpenNHP/opennhp/nhp/log"
)

const (
	// ACPubkeyRevokeSweepIntervalEnvVar configures the strict-mode
	// mid-session drop sweep for #1535. Values are whole seconds;
	// unset defaults to 60s and 0 disables the background sweep.
	ACPubkeyRevokeSweepIntervalEnvVar = "NHP_AC_PUBKEY_REVOKE_SWEEP_INTERVAL_SECONDS"

	defaultACPubkeyRevokeSweepInterval = 60 * time.Second
	minACPubkeyRevokeSweepInterval     = 5 * time.Second

	acPubkeyRevokedConnDropSourceSweep    = "sweep"
	acPubkeyRevokedConnDropSourceOnDemand = "on-demand"
)

type acPubkeyRevokedConnDropStats struct {
	CheckedACIDs  int  `json:"checked_ac_ids"`
	AffectedACIDs int  `json:"affected_ac_ids"`
	DroppedConns  int  `json:"dropped_conns"`
	LookupErrors  int  `json:"lookup_errors"`
	Skipped       bool `json:"skipped,omitempty"`
	Truncated     bool `json:"truncated,omitempty"`
}

type acPubkeyRevokedConnDrop struct {
	connData *core.ConnectionData
	pubkey   string
	addr     string
}

func parseACPubkeyRevokeSweepInterval(raw string) (time.Duration, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return defaultACPubkeyRevokeSweepInterval, nil
	}
	seconds, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("must be an integer number of seconds")
	}
	if seconds < 0 {
		return 0, fmt.Errorf("must be non-negative seconds")
	}
	if seconds == 0 {
		return 0, nil
	}
	d := time.Duration(seconds) * time.Second
	if d < minACPubkeyRevokeSweepInterval {
		return 0, fmt.Errorf("must be 0 or at least %s", minACPubkeyRevokeSweepInterval)
	}
	return d, nil
}

func (s *UdpServer) acPubkeyRevokeDropEnabled() bool {
	return s != nil &&
		s.acPubkeyRevokeVerifyRequire &&
		s.storage != nil &&
		s.storageConfig != nil &&
		s.storageConfig.Backend == StorageBackendDynamoDB
}

func (s *UdpServer) activeACIDsSnapshot() []string {
	s.acConnectionMapMutex.RLock()
	defer s.acConnectionMapMutex.RUnlock()

	acIDs := make([]string, 0, len(s.acConnectionMap))
	for acID := range s.acConnectionMap {
		acIDs = append(acIDs, acID)
	}
	sort.Strings(acIDs)
	return acIDs
}

func (s *UdpServer) sweepRevokedACPubkeyConnections(ctx context.Context, acIDs []string, source string) acPubkeyRevokedConnDropStats {
	stats := acPubkeyRevokedConnDropStats{}
	if !s.acPubkeyRevokeDropEnabled() {
		stats.Skipped = true
		return stats
	}
	if len(acIDs) == 0 {
		acIDs = s.activeACIDsSnapshot()
	}

	for _, acID := range acIDs {
		if ctx.Err() != nil {
			log.Info("server-ac(%s)[ACPubkeyRevokedDrop] sweep context ended before assignment lookup: %v (source=%s)",
				acID, ctx.Err(), source)
			stats.Truncated = true
			return stats
		}

		lookupCtx, cancel := context.WithTimeout(ctx, DefaultStorageTimeout)
		assignment, err := s.storage.GetACAssignment(lookupCtx, acID)
		cancel()
		stats.CheckedACIDs++
		if err != nil {
			if IsNotFoundError(err) {
				continue
			}
			if ctx.Err() != nil && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
				log.Info("server-ac(%s)[ACPubkeyRevokedDrop] sweep context ended during assignment lookup: %v (source=%s)",
					acID, ctx.Err(), source)
				stats.Truncated = true
				return stats
			}
			stats.LookupErrors++
			if s.metrics != nil {
				s.metrics.IncrCounter(MetricACPubkeyRevokedLookupErr)
			}
			log.Warning("server-ac(%s)[ACPubkeyRevokedDrop] ACAssignment lookup failed: %v (source=%s; fired %s)",
				acID, err, source, MetricACPubkeyRevokedLookupErr)
			continue
		}
		if assignment == nil {
			continue
		}
		dropped := s.dropRevokedACPubkeyConnections(acID, assignment.RevokedPubKeys, source)
		if dropped > 0 {
			stats.AffectedACIDs++
			stats.DroppedConns += dropped
		}
	}
	return stats
}

func (s *UdpServer) dropRevokedACPubkeyConnections(acID string, revokedPubkeys []string, source string) int {
	if len(revokedPubkeys) == 0 {
		return 0
	}

	drops := s.removeRevokedACConnsFromMap(acID, revokedPubkeys)
	for _, drop := range drops {
		udpConnClosed := false
		if drop.addr != "" && drop.connData != nil {
			udpConn := s.lookupRemoteConnForDrop(drop.addr, drop.connData)
			if udpConn != nil {
				s.removeConnection(udpConn, drop.addr)
				go udpConn.Close()
				udpConnClosed = true
			}
		}
		s.removeACPeerIfNoLiveConn(drop.pubkey)
		if s.metrics != nil {
			// Counts revoked ACConn state removed from live maps. When
			// udp_conn_closed=false in the paired log line, the UDP map
			// entry was already gone or replaced and no socket was closed
			// by this pass.
			s.metrics.IncrCounter(MetricACPubkeyRevokedConnDropped)
		}
		log.Warning("server-ac(%s@%s)[ACPubkeyRevokedDrop] removed revoked ACConn entry: pubkey=%s... source=%s udp_conn_closed=%t (fired %s)",
			acID, drop.addr, pubkeyLogPrefix(drop.pubkey), source, udpConnClosed, MetricACPubkeyRevokedConnDropped)
	}
	return len(drops)
}

func (s *UdpServer) removeRevokedACConnsFromMap(acID string, revokedPubkeys []string) []acPubkeyRevokedConnDrop {
	s.acConnectionMapMutex.Lock()
	defer s.acConnectionMapMutex.Unlock()

	conns := s.acConnectionMap[acID]
	if len(conns) == 0 {
		return nil
	}

	kept := make([]*ACConn, 0, len(conns))
	drops := make([]acPubkeyRevokedConnDrop, 0, len(conns))
	for _, conn := range conns {
		pubkey, ok := acConnPubkey(conn)
		if !ok || verifyACPubkeyRevoked(pubkey, revokedPubkeys) != verdictACPubkeyRevokeRevoked {
			kept = append(kept, conn)
			continue
		}
		addr := ""
		if conn.ConnData != nil && conn.ConnData.RemoteAddr != nil {
			addr = conn.ConnData.RemoteAddr.String()
		}
		drops = append(drops, acPubkeyRevokedConnDrop{
			connData: conn.ConnData,
			pubkey:   pubkey,
			addr:     addr,
		})
	}
	if len(drops) == 0 {
		return nil
	}
	if len(kept) == 0 {
		delete(s.acConnectionMap, acID)
	} else {
		s.acConnectionMap[acID] = kept
	}
	return drops
}

func acConnPubkey(conn *ACConn) (string, bool) {
	if conn == nil || conn.ACPeer == nil || conn.ACPeer.PubKeyBase64 == "" {
		return "", false
	}
	return conn.ACPeer.PubKeyBase64, true
}

func (s *UdpServer) lookupRemoteConnForDrop(addr string, connData *core.ConnectionData) *UdpConn {
	if addr == "" || connData == nil {
		return nil
	}
	s.remoteConnectionMapMutex.Lock()
	defer s.remoteConnectionMapMutex.Unlock()

	udpConn := s.remoteConnectionMap[addr]
	if udpConn == nil || udpConn.ConnData != connData {
		return nil
	}
	return udpConn
}

func (s *UdpServer) removeACPeerIfNoLiveConn(pubkey string) {
	if pubkey == "" {
		return
	}

	s.acConnectionMapMutex.RLock()
	defer s.acConnectionMapMutex.RUnlock()
	for _, conns := range s.acConnectionMap {
		for _, conn := range conns {
			if got, ok := acConnPubkey(conn); ok && got == pubkey {
				return
			}
		}
	}

	// O(total live conns) per drop is intentional for the incident-
	// response path: operator workflow is one pubkey at a time, and
	// runaway revoke lists are already surfaced by
	// MetricACPubkeyRevokeListOversize. If bulk revoke becomes a
	// normal workflow, replace this scan with a pubkey refcount.
	// This caller runs only after the strict F5 gate has found the
	// pubkey in this server's storage view. That relies on the drop
	// path and HandleACOnline F5 gate reading the same CachedStorage
	// snapshot; revisit this scan-then-remove gap if those views ever
	// diverge.
	// Keep acConnectionMapMutex.RLock through removeACPeer so the
	// decision is serialized with ACConn appends. HandleACOnline
	// publishes/re-publishes cloud AC peers only after its ACConn append
	// while holding the same RLock, so if cleanup wins before the
	// append the registration restores the peer after the conn is live;
	// if the append wins first, this scan observes it and keeps the
	// peer.
	s.removeACPeer(pubkey)
}

func (s *UdpServer) ensureACPeerForLiveConn(acID string, acConn *ACConn) bool {
	if acConn == nil || acConn.ACPeer == nil {
		return false
	}

	s.acConnectionMapMutex.RLock()
	defer s.acConnectionMapMutex.RUnlock()

	for _, conn := range s.acConnectionMap[acID] {
		if conn == acConn {
			s.AddACPeer(acConn.ACPeer)
			return true
		}
	}
	return false
}

func (s *UdpServer) acPubkeyRevokeSweepRoutine() {
	defer s.wg.Done()

	sweepCtx, cancelSweep := context.WithCancel(context.Background())
	defer cancelSweep()
	stopWatcherDone := make(chan struct{})
	defer close(stopWatcherDone)
	go func() {
		// The main loop's stop case exits between ticks. This watcher
		// cancels a storage lookup already blocked inside the current
		// sweep so Stop() is not delayed by DefaultStorageTimeout.
		select {
		case <-s.signals.stop:
			cancelSweep()
		case <-stopWatcherDone:
		}
	}()

	ticker := time.NewTicker(s.acPubkeyRevokeSweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.signals.stop:
			cancelSweep()
			return
		case <-ticker.C:
			stats := s.sweepRevokedACPubkeyConnections(sweepCtx, nil, acPubkeyRevokedConnDropSourceSweep)
			if stats.DroppedConns > 0 {
				log.Warning("[ACPubkeyRevokedDrop] periodic sweep dropped %d live AC connection(s) across %d affected acId(s) (%d checked)",
					stats.DroppedConns, stats.AffectedACIDs, stats.CheckedACIDs)
			}
			if stats.LookupErrors > 0 {
				log.Warning("[ACPubkeyRevokedDrop] periodic sweep saw %d assignment lookup error(s) across %d acId(s)",
					stats.LookupErrors, stats.CheckedACIDs)
			}
		}
	}
}
