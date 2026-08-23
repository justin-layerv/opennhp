package server

import (
	"encoding/base64"
	"encoding/json"
	"strings"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
	"github.com/OpenNHP/opennhp/nhp/log"
)

// HandleRevocationAck processes a single NHP_RVA packet. A body carrying the
// session-close kind is first routed through the strict pre-publication AOL
// waiter: that path binds the authenticated key, exact ConnData, durable event
// selector, boot, and flush generation without consulting acConnectionMap.
// NHP_REV/NHP_RVA is a push/ack protocol, not a core LocalTransaction.
// Kind absence enters the generic qURL proof-of-delivery path below. It
// unmarshals the ACRevocationAckMsg, resolves the acking
// AC slot identity from the cryptographically-authenticated connection pubkey
// (NOT a body field), and clears that slot's pending-revoke tracker for the
// acked (scope, scope_key) at or below the acked epoch — which stops the
// retry-until-ack-or-age-out loop for that exact live slot.
//
// Identity attribution (load-bearing security property): acId + AC pubkey are
// resolved from ppd.RemotePubKey — the sender's AEAD-authenticated static key (the
// responder opens the handshake only if the sender actually holds that private
// key) — against the live AC connection registry (acConnectionMap). The
// authorization that this pubkey belongs to a real AC is the registry match in
// resolveACIdentityFromPubkey, NOT validatePeer: in cloud (DynamoDB) mode the
// server runs with DisableACPeerValidation=true, so validatePeer does not
// pool-check the AC pubkey — the acConnectionMap membership check is the gate. Do
// NOT "tighten" attribution by trusting validatePeer alone, and do not loosen the
// registry check. The ack message deliberately carries NO acId/pubkey field;
// trusting a body-supplied id would let any authenticated AC clear another AC's
// pending revoke (a fail-open: the server would stop retrying a revoke that never
// reached its true target). The pubkey is part of the pending key because
// acConnectionMap supports multiple blue/green slots under one acId, and one
// sibling's ack must not prove another sibling's delivery.
//
// Acknowledgement semantics mirror the AC side (common.ACRevocationAckMsg): the
// ack is a CONVERGENCE claim, so a matched ack clears the pending tracker
// regardless of whether the AC flushed any live flow. scope_key is matched
// VERBATIM against what the server sent into the NHP_REV (the scope-prefixed
// form) — the server does NOT strip/normalize it on the ack path, mirroring the
// AC's verbatim echo, to avoid the fail-open-on-key-mismatch trap.
//
// Dispatched asynchronously: the NHP_RVA arm of dispatchReceivedMessage spawns
// this in its own goroutine (NOT joined to s.wg), mirroring the other AC→server
// receive handlers, so a slow ack cannot head-of-line-block the receive queue. It
// is shutdown-safe despite not being wg-tracked because it only touches the
// leaf-most tracker mutex and the nil-safe metrics publisher — it never sends on
// s.sendMsgCh — so it cannot race Stop()'s close(s.sendMsgCh). Returns an error
// for the direct test callers; the dispatch arm logs it.
//
// The clear is a no-op when the retry engine is disabled (the default;
// s.revocationRetry is nil): the ack is still validated, attributed, and counted
// (proof-of-delivery metric), but there is no pending tracker to clear. The
// engine is armed by NHP_REVOCATION_RETRY_ENABLED — see revocation_retry.go.
func (s *UdpServer) HandleRevocationAck(ppd *core.PacketParserData) error {
	if handled, err := s.handleACSessionControlFenceAck(ppd); handled || err != nil {
		return err
	}
	ackMsg := &common.ACRevocationAckMsg{}
	if err := json.Unmarshal(ppd.BodyMessage, ackMsg); err != nil {
		log.Error("[Server][HandleRevocationAck] failed to parse NHP_RVA message: %v", err)
		return err
	}

	acId, acPubkey, ok := s.resolveACIdentityFromPubkey(ppd.RemotePubKey)
	if !ok {
		// The authenticated pubkey matched no live AC connection. The conn may
		// have dropped/reconnected between the NHP_REV and this ack; ignore the
		// ack (the pending tracker is keyed by resolved acId) and surface the
		// unresolved case so a drop/reconnect race is observable rather than
		// silent. If the send-side live conn was malformed, trackFanout already
		// fires RevocationUntrackable; the receive-side signal remains
		// RevocationAckUnresolved because no safe clear key can be reconstructed.
		if s.metrics != nil {
			s.metrics.IncrCounter(MetricRevocationAckUnresolved)
		}
		log.Warning("[Server][HandleRevocationAck] could not attribute NHP_RVA to a live AC connection (scope=%q key=%q epoch=%d eventId=%q); fired %s",
			ackMsg.Scope, ackMsg.ScopeKey, ackMsg.RevocationEpoch, ackMsg.EventId, MetricRevocationAckUnresolved)
		return nil
	}

	if s.metrics != nil {
		s.metrics.IncrCounter(MetricRevocationAckReceived)
	}
	log.Info("server-ac(%s)[HandleRevocationAck] received NHP_RVA scope=%q key=%q epoch=%d eventId=%q",
		acId, ackMsg.Scope, ackMsg.ScopeKey, ackMsg.RevocationEpoch, ackMsg.EventId)

	// Clear the per-slot pending-revoke tracker for
	// (acId, acPubkey, scope, scope_key) at or below the acked epoch — this stops
	// the retry loop for that exact AC slot (#2793). scope_key is matched
	// VERBATIM against the wire form the server sent (no strip/normalize). No-op
	// when the engine is disabled (tracker nil).
	s.clearPendingRevocationAck(acId, acPubkey, ackMsg.Scope, ackMsg.ScopeKey, ackMsg.RevocationEpoch)

	return nil
}

// resolveACIdentityFromPubkey maps an authenticated connection pubkey (raw bytes
// from ppd.RemotePubKey) to the configured acId and stable AC slot pubkey
// (ACPeer.PubKeyBase64) of the AC that owns a live connection with that pubkey,
// or ("", "", false) if no live ACConn matches. It is the ack path's identity
// attribution: both values come from the crypto-authenticated pubkey and the
// live connection registry, never a spoofable message field.
//
// The scan is O(total live AC conns), acceptable because NHP_RVA volume is
// bounded by revoke volume (a security-event rate, not a steady-state rate) and
// the live-conn set is small (a cell's ACs × blue/green slots). If revoke
// volume ever rises to where this matters, add a pubkey→identity index alongside
// acConnectionMap — but that is premature today. Mirrors the existing
// acConnPubkey-based scan in ac_pubkey_revoke_drop.go.
func (s *UdpServer) resolveACIdentityFromPubkey(pubkey []byte) (string, string, bool) {
	if len(pubkey) != core.PublicKeySize {
		return "", "", false
	}
	want := base64.StdEncoding.EncodeToString(pubkey)

	s.acConnectionMapMutex.RLock()
	defer s.acConnectionMapMutex.RUnlock()
	for mapACId, conns := range s.acConnectionMap {
		for _, conn := range conns {
			if got, ok := acConnPubkey(conn); ok && got == want {
				acId := conn.ACId
				if strings.TrimSpace(acId) == "" {
					// Match trackFanout's empty-ACId refusal: no pending entry can
					// exist for this malformed live conn, so treat the ack as
					// unresolved instead of reconstructing a fallback clear key. A
					// duplicate same-pubkey entry with a valid ACId can still resolve.
					log.Warning("[Server][resolveACIdentityFromPubkey] live ACConn for map acId %q has empty ACId; treating NHP_RVA as unresolved", mapACId)
					continue
				}
				// Return the same ACPeer.PubKeyBase64 form trackFanout keyed on,
				// so the ack clear key matches the pending entry representation.
				return acId, got, true
			}
		}
	}
	return "", "", false
}
