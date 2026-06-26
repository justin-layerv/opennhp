package server

import (
	"encoding/base64"
	"encoding/json"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
	"github.com/OpenNHP/opennhp/nhp/log"
)

// HandleRevocationAck processes a single NHP_RACK packet: an AC's
// proof-of-delivery acknowledgement of an NHP_REV the server fanned out (P4e
// Slice 3, #2793). It unmarshals the ACRevocationAckMsg, resolves the acking
// AC's identity from the cryptographically-authenticated connection pubkey (NOT
// a body field), and clears that AC's pending-revoke tracker for the acked
// (scope, scope_key) at or below the acked epoch — which stops the
// retry-until-ack-or-age-out loop for that AC.
//
// Identity attribution (load-bearing security property): the acId is resolved
// from ppd.RemotePubKey (set by the responder only after validatePeer
// authenticates it) against the live AC connection registry. The ack message
// deliberately carries NO acId field; trusting a body-supplied id would let any
// authenticated AC clear another AC's pending revoke (a fail-open: the server
// would stop retrying a revoke that never reached its true target). See the
// ServerACAckMsg/HandleACOnline precedent (msghandler.go) for the same
// pubkey→acId resolution from ppd.RemotePubKey.
//
// Acknowledgement semantics mirror the AC side (common.ACRevocationAckMsg): the
// ack is a CONVERGENCE claim, so a matched ack clears the pending tracker
// regardless of whether the AC flushed any live flow. scope_key is matched
// VERBATIM against what the server sent into the NHP_REV (the scope-prefixed
// form) — the server does NOT strip/normalize it on the ack path, mirroring the
// AC's verbatim echo, to avoid the fail-open-on-key-mismatch trap.
//
// Synchronous — the caller (dispatchReceivedMessage's NHP_RACK arm) owns the
// goroutine, mirroring the other AC→server receive handlers. Returns an error
// for the direct test callers; the dispatch arm logs it.
//
// The clear is a no-op when the retry engine is disabled (the default;
// s.revocationRetry is nil): the ack is still validated, attributed, and counted
// (proof-of-delivery metric), but there is no pending tracker to clear. The
// engine is armed by NHP_REVOCATION_RETRY_ENABLED — see revocation_retry.go.
func (s *UdpServer) HandleRevocationAck(ppd *core.PacketParserData) error {
	ackMsg := &common.ACRevocationAckMsg{}
	if err := json.Unmarshal(ppd.BodyMessage, ackMsg); err != nil {
		log.Error("[Server][HandleRevocationAck] failed to parse NHP_RACK message: %v", err)
		return err
	}

	acId, ok := s.resolveACIdFromPubkey(ppd.RemotePubKey)
	if !ok {
		// The authenticated pubkey matched no live AC connection. The conn may
		// have dropped/reconnected between the NHP_REV and this ack; ignore the
		// ack (the pending tracker is keyed by resolved acId) and surface the
		// unresolved case so a drop/reconnect race is observable rather than
		// silent.
		if s.metrics != nil {
			s.metrics.IncrCounter(MetricRevocationAckUnresolved)
		}
		log.Warning("[Server][HandleRevocationAck] could not attribute NHP_RACK to a live AC connection (scope=%q key=%q epoch=%d eventId=%q); fired %s",
			ackMsg.Scope, ackMsg.ScopeKey, ackMsg.RevocationEpoch, ackMsg.EventId, MetricRevocationAckUnresolved)
		return nil
	}

	if s.metrics != nil {
		s.metrics.IncrCounter(MetricRevocationAckReceived)
	}
	log.Info("server-ac(%s)[HandleRevocationAck] received NHP_RACK scope=%q key=%q epoch=%d eventId=%q",
		acId, ackMsg.Scope, ackMsg.ScopeKey, ackMsg.RevocationEpoch, ackMsg.EventId)

	// Clear the per-AC pending-revoke tracker for (acId, scope, scope_key) at or
	// below the acked epoch — this stops the retry loop for that AC (#2793).
	// scope_key is matched VERBATIM against the wire form the server sent (no
	// strip/normalize). No-op when the engine is disabled (tracker nil).
	s.clearPendingRevocationAck(acId, ackMsg.Scope, ackMsg.ScopeKey, ackMsg.RevocationEpoch)

	return nil
}

// resolveACIdFromPubkey maps an authenticated connection pubkey (raw bytes from
// ppd.RemotePubKey) to the configured acId of the AC that owns a live connection
// with that pubkey, or ("", false) if no live ACConn matches. It is the ack
// path's identity attribution: the acId comes from the crypto-authenticated
// pubkey, never a spoofable message field.
//
// The scan is O(total live AC conns), acceptable because NHP_RACK volume is
// bounded by revoke volume (a security-event rate, not a steady-state rate) and
// the live-conn set is small (a cell's ACs × blue/green slots). If revoke
// volume ever rises to where this matters, add a pubkey→acId index alongside
// acConnectionMap — but that is premature today. Mirrors the existing
// acConnPubkey-based scan in ac_pubkey_revoke_drop.go.
func (s *UdpServer) resolveACIdFromPubkey(pubkey []byte) (string, bool) {
	if len(pubkey) != core.PublicKeySize {
		return "", false
	}
	want := base64.StdEncoding.EncodeToString(pubkey)

	s.acConnectionMapMutex.RLock()
	defer s.acConnectionMapMutex.RUnlock()
	for acId, conns := range s.acConnectionMap {
		for _, conn := range conns {
			if got, ok := acConnPubkey(conn); ok && got == want {
				return acId, true
			}
		}
	}
	return "", false
}
