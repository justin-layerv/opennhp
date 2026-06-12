package server

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/OpenNHP/opennhp/nhp/core"
	"github.com/OpenNHP/opennhp/nhp/log"
)

// ACPubkeyRevokeSweepIntervalEnvVar controls the strict-mode sweep
// that severs already-connected ACs whose pubkey has since been added
// to ACAssignment.RevokedPubKeys. Registration-time rejection lives in
// ac_pubkey_revoke_gate.go; this closes the parent #1157 F5
// mid-session gap.
const ACPubkeyRevokeSweepIntervalEnvVar = "NHP_AC_PUBKEY_REVOKE_SWEEP_INTERVAL_SECONDS"

const defaultACPubkeyRevokeSweepInterval = 60 * time.Second

// MetricACPubkeyRevokedConnDropped fires once per live AC connection
// severed because its pubkey appears in ACAssignment.RevokedPubKeys.
const MetricACPubkeyRevokedConnDropped = "ACPubkeyRevokedConnDropped"

type revokedACConnDrop struct {
	acId       string
	pubkey     string
	addrStr    string
	connData   *core.ConnectionData
	removePeer bool
}

func parseACPubkeyRevokeSweepInterval(raw string) (time.Duration, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return defaultACPubkeyRevokeSweepInterval, nil
	}
	seconds, err := strconv.Atoi(raw)
	if err != nil {
		return 0, err
	}
	if seconds <= 0 {
		return 0, fmt.Errorf("must be > 0 seconds, got %d", seconds)
	}
	return time.Duration(seconds) * time.Second, nil
}

func (s *UdpServer) acPubkeyRevokeSweepRoutine(interval time.Duration) {
	defer s.wg.Done()
	defer log.Info("AC pubkey revocation sweep stopped")

	log.Info("AC pubkey revocation sweep started (interval=%v)", interval)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-s.signals.stop:
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), interval)
			dropped, err := s.dropRevokedACPubkeyConnections(ctx, "sweep")
			cancel()
			if err != nil {
				log.Warning("AC pubkey revocation sweep failed after dropping %d connection(s): %v", dropped, err)
				continue
			}
			if dropped > 0 {
				log.Warning("AC pubkey revocation sweep dropped %d revoked connection(s)", dropped)
			}
		}
	}
}

// dropRevokedACPubkeyConnections walks the current AC connection table,
// reloads each acId's assignment, and severs any connection whose
// pubkey appears in that acId's RevokedPubKeys set.
//
// Locking: this snapshots acConnectionMap keys, performs storage I/O
// without holding server locks, then mutates acConnectionMap and the
// remote connection map in separate phases. Do not nest those mutexes;
// endpoints/server/CLAUDE.md documents the lifecycle lock order.
func (s *UdpServer) dropRevokedACPubkeyConnections(ctx context.Context, source string) (int, error) {
	if s.storage == nil {
		return 0, nil
	}

	s.acConnectionMapMutex.RLock()
	acIDs := make([]string, 0, len(s.acConnectionMap))
	for acId := range s.acConnectionMap {
		acIDs = append(acIDs, acId)
	}
	s.acConnectionMapMutex.RUnlock()

	dropped := 0
	for _, acId := range acIDs {
		if err := ctx.Err(); err != nil {
			return dropped, err
		}
		assignment, err := s.storage.GetACAssignment(ctx, acId)
		if err != nil {
			if IsNotFoundError(err) {
				continue
			}
			s.metrics.IncrCounter(MetricACPubkeyRevokedLookupErr)
			log.Warning("server-ac(%s)[ACPubkeyRevokedDrop] assignment lookup failed: %v (source=%s; skipping acId)",
				acId, err, source)
			continue
		}
		if assignment == nil || len(assignment.RevokedPubKeys) == 0 {
			continue
		}
		dropped += s.dropRevokedACPubkeyConnectionsForAC(acId, assignment.RevokedPubKeys, source)
	}
	return dropped, nil
}

func (s *UdpServer) dropRevokedACPubkeyConnectionsForAC(acId string, revokedPubkeys []string, source string) int {
	var drops []revokedACConnDrop
	removedPubkeys := map[string]bool{}

	s.acConnectionMapMutex.Lock()
	existing := s.acConnectionMap[acId]
	if len(existing) == 0 {
		s.acConnectionMapMutex.Unlock()
		return 0
	}

	kept := make([]*ACConn, 0, len(existing))
	for _, acConn := range existing {
		if acConn == nil || acConn.ACPeer == nil || acConn.ConnData == nil || acConn.ConnData.RemoteAddr == nil {
			kept = append(kept, acConn)
			continue
		}
		pubkey := acConn.ACPeer.PubKeyBase64
		if verifyACPubkeyRevoked(pubkey, revokedPubkeys) != verdictACPubkeyRevokeRevoked {
			kept = append(kept, acConn)
			continue
		}
		drops = append(drops, revokedACConnDrop{
			acId:     acId,
			pubkey:   pubkey,
			addrStr:  acConn.ConnData.RemoteAddr.String(),
			connData: acConn.ConnData,
		})
		removedPubkeys[pubkey] = true
	}

	if len(drops) == 0 {
		s.acConnectionMapMutex.Unlock()
		return 0
	}
	if len(kept) == 0 {
		delete(s.acConnectionMap, acId)
	} else {
		s.acConnectionMap[acId] = kept
	}
	for pubkey := range removedPubkeys {
		if s.hasACConnWithPubkeyLocked(pubkey) {
			continue
		}
		for i := range drops {
			if drops[i].pubkey == pubkey {
				drops[i].removePeer = true
				break
			}
		}
	}
	s.acConnectionMapMutex.Unlock()

	for _, drop := range drops {
		closed := s.closeRemoteConnectionForConnData(drop.connData)
		if drop.removePeer {
			s.removeACPeer(drop.pubkey)
		}
		s.metrics.IncrCounter(MetricACPubkeyRevokedConnDropped)
		log.Warning("server-ac(%s@%s)[ACPubkeyRevokedDrop] dropped revoked AC connection: pubkey=%s... source=%s closed=%t",
			drop.acId, drop.addrStr, pubkeyLogPrefix(drop.pubkey), source, closed)
	}
	return len(drops)
}

// hasACConnWithPubkeyLocked reports whether any remaining ACConn still
// uses pubkey. Caller must hold s.acConnectionMapMutex.
func (s *UdpServer) hasACConnWithPubkeyLocked(pubkey string) bool {
	for _, conns := range s.acConnectionMap {
		for _, acConn := range conns {
			if acConn != nil && acConn.ACPeer != nil && acConn.ACPeer.PubKeyBase64 == pubkey {
				return true
			}
		}
	}
	return false
}

func (s *UdpServer) closeRemoteConnectionForConnData(connData *core.ConnectionData) bool {
	if connData == nil || connData.RemoteAddr == nil {
		return false
	}

	addrStr := connData.RemoteAddr.String()
	var conn *UdpConn
	s.remoteConnectionMapMutex.Lock()
	if existing := s.remoteConnectionMap[addrStr]; existing != nil && existing.ConnData != nil && existing.ConnData.Equal(connData) {
		conn = existing
	}
	s.remoteConnectionMapMutex.Unlock()

	if conn == nil {
		return false
	}
	s.removeConnection(conn, addrStr)
	go conn.Close()
	return true
}
