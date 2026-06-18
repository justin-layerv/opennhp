package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
	"github.com/OpenNHP/opennhp/nhp/log"
)

// HandleKnockRequest
// Server will respond with success or error with NHP_ACK message
func (s *UdpServer) HandleKnockRequest(ppd *core.PacketParserData) error {
	s.wg.Add(1)
	defer s.wg.Done()

	ackBytes, userId, err := s.buildKnockAck(ppd)
	if err != nil {
		// Only a marshal failure reaches here; the ack cannot be sent.
		// An auth REJECT is not this error — it rides inside ackBytes
		// (ackMsg.ErrCode) and is still delivered below, matching the
		// pre-extraction behavior where the closure's error was overwritten
		// by the send result.
		return err
	}

	ackMd := makeMsgData(ppd, core.NHP_ACK, ackBytes)
	return s.forwardToTransaction(ppd.ConnData, ppd.SenderTrxId, ackMd, "server-agent", "HandleKnockRequest", userId, ppd.ConnData.RemoteAddr.String())
}

// buildKnockAck runs the knock authorization pipeline for ppd and returns the
// marshaled ACK bytes (NHP_ACK, or the DHP ack for DHP_KNK), the agent user id
// (for the caller's send-path log tag), and a non-nil error ONLY when the ack
// itself cannot be marshaled. An auth REJECT is not such an error: the verdict
// is encoded in the returned bytes (ackMsg.ErrCode) and the caller still sends
// it so the agent sees the reject.
//
// The source address used for the AC pinhole, the echoed AgentAddr, and the log
// tags is ppd.ConnData.RemoteAddr. The NHP_RLY relay path (#2208) decrypts the
// forwarded inner knock onto a synthetic ppd whose ConnData.RemoteAddr is the
// relay-reported client IP, so this pipeline needs no source-address parameter
// to serve both the direct and the relayed knock paths.
//
// Extracted from HandleKnockRequest so the relay handler can reuse the exact
// knock pipeline while replying through the relay (EncryptedPktCh + WriteToUDP)
// instead of forwardToTransaction.
func (s *UdpServer) buildKnockAck(ppd *core.PacketParserData) ([]byte, string, error) {
	knockStart := time.Now()
	s.metrics.IncrCounter(MetricKnockRequest)

	transactionId := ppd.SenderTrxId
	addrStr := ppd.ConnData.RemoteAddr.String()
	knkMsg := &common.AgentKnockMsg{}
	dhpKnkMsg := &common.DHPKnockMsg{}
	ackMsg := &common.ServerKnockAckMsg{
		// AgentAddr is set BEFORE pubkey resolution / auth and so
		// is echoed on EVERY reject path (unknown pubkey, DDB
		// error, header-type mismatch, etc.) in addition to the
		// success path. NOT an information disclosure: the ACK is
		// AEAD-encrypted to the claimed agent pubkey, so only the
		// holder of the matching private key can decrypt and read
		// it. A probing attacker who guesses a pubkey can't read
		// back the field; a legitimate agent reading it sees its
		// own apparent outwards IP for self-diagnosis.
		AgentAddr: addrStr,
	}
	dhpAckMsg := &common.ServerDHPKnockAckMsg{
		OpenTime: 30, // currently, use fixed value, unit is seconds.
	}

	// closureErr is the closure's internal control-flow signal ONLY — it is
	// deliberately a local, NOT a named return. An auth reject rides in
	// ackMsg.ErrCode and must still be delivered, so buildKnockAck returns an
	// explicit nil error on the success-marshal path; only a marshal failure
	// returns non-nil. Keeping this a local makes a stray bare `return` a
	// compile error rather than a silent ack-suppression regression.
	var closureErr error

	func() {
		// parse knockMsg
		if ppd.HeaderType == core.DHP_KNK { // dhp knock
			closureErr = json.Unmarshal(ppd.BodyMessage, dhpKnkMsg)
		} else {
			closureErr = json.Unmarshal(ppd.BodyMessage, knkMsg)
		}

		if closureErr != nil {
			log.Error("server-agent(#%d@%s)[HandleKnockRequest] failed to parse %s message: %v", transactionId, addrStr, core.HeaderTypeToString(ppd.HeaderType), closureErr)
			ackMsg.ErrCode = common.ErrJsonParseFailed.ErrorCode()
			ackMsg.ErrMsg = closureErr.Error()
			return
		}

		// dhp knock
		if ppd.HeaderType == core.DHP_KNK {
			log.Info("server-agent(%s#%d@%s)[HandleKnockRequest] start to verify evidence for dhp knock", knkMsg.UserId, transactionId, addrStr)
			if s.AppraiseEvidence(dhpKnkMsg.Evidence) {
				dhpAckMsg.ErrCode = common.ErrSuccess.ErrorCode()
			} else {
				dhpAckMsg.ErrCode = common.ErrEvidenceAppraisalFailed.ErrorCode()
			}
			return
		}

		// Determine knock type. Compare the AEAD-authenticated
		// body.HeaderType against the (unauthenticated) wire
		// ppd.HeaderType. A mismatch is the #1154 attack signature —
		// MitM flipped the wire type byte and recomputed the unkeyed
		// "HMAC". See knock_headertype_gate.go for policy details.
		//
		// Expected wire types at this point are the knock family:
		// NHP_KNK, NHP_RKN, NHP_EXT (DHP_KNK was carved off at the
		// early branch above). If a future refactor routes additional
		// wire types through this handler, the gate's body==wire
		// comparison stays correct as long as agents populate
		// body.HeaderType for those new types — agent-side
		// KnockRequest/ExitKnockRequest are the two places to update.
		useType, verdict := verifyKnockHeaderType(knkMsg.HeaderType, ppd.HeaderType, s.knockHeaderTypeVerifyRequire)
		proceed, rejectErr := s.applyKnockHeaderTypeVerdict(verdict, knkMsg.HeaderType, ppd.HeaderType, transactionId, addrStr)
		if !proceed {
			// applyKnockHeaderTypeVerdict is the single source of
			// truth for both "proceed?" and "which error to ack":
			// verdictLegacy→52010, verdictMismatch→52009, and
			// (unreachable today but fail-closed) unknown-verdict
			// →52011. Centralizing the error in the side-effect
			// wrapper means the caller can't get the mapping
			// wrong on a future refactor.
			closureErr = rejectErr
			ackMsg.ErrCode = rejectErr.ErrorCode()
			ackMsg.ErrMsg = closureErr.Error()
			// Closure return: the outer HandleKnockRequest flow still
			// marshals ackMsg and forwards NHP_ACK via the normal ack
			// path. A legitimate agent sees 52009/52010/52011 and
			// self-diagnoses; a MitM sees an AEAD-encrypted ACK it
			// can't read. The ack carries the AgentAddr field pre-
			// populated at HandleKnockRequest entry (the agent's
			// own peer address), which is not an info disclosure
			// because the AEAD envelope to the initiator's static
			// pubkey is what makes the ack readable only by that
			// agent. If a future refactor collapses this closure,
			// the ack-still-flows property must be preserved.
			return
		}
		knkMsg.HeaderType = useType

		// Cloud mode agent peer resolution: with
		// DisableAgentPeerValidation=true the noise responder skipped
		// the peer-pool check, so an unknown-but-registered agent's
		// knock reaches us and must be resolved against the
		// qurl-agent-keys DDB table. Nil lookup = DDB-backed agent
		// path disabled (legacy etcd / file deployments); fall
		// through to the auth handler unchanged.
		if s.agentPeerLookup != nil && !isQurlRelayBootstrapKnock(ppd, knkMsg) {
			if resolveErr := s.resolveAgentPeerForKnock(ppd, knkMsg, ackMsg, transactionId, addrStr); resolveErr != nil {
				// resolveAgentPeerForKnock has already populated ackMsg.ErrCode/
				// ErrMsg; the reject rides in the ack, so just stop the pipeline.
				return
			}
		} else if s.agentPeerLookup != nil {
			// qurl.link's first browser knock presents a freshly generated
			// JS-agent pubkey that qurl-service cannot have registered yet.
			// The encrypted qURL access token is the bootstrap credential; the
			// qURL plugin validates it and binds ppd.RemotePubKey through the
			// internal browser-relay resolve endpoint before opening access.
			log.Info("server-agent(%s#%d@%s)[HandleKnockRequest] event=\"qurl_bootstrap_unknown_pubkey_allowed\" pubkey_b64_prefix=%q",
				knkMsg.UserId, transactionId, addrStr,
				pubkeyLogPrefix(base64.StdEncoding.EncodeToString(ppd.RemotePubKey)))
		}

		// find out auth service provider. Try the in-memory map first
		// (hot path, no allocation). Only fall through to
		// ResolveAuthSvcProvider (which formats the log prefix and
		// consults DDB) on a cache miss.
		aspData := s.FindAuthSvcProvider(knkMsg.AuthServiceId)
		if aspData == nil {
			aspData = s.ResolveAuthSvcProvider(s.LifecycleCtx(), knkMsg.AuthServiceId,
				fmt.Sprintf("HandleKnockRequest-Auth agent=%s tx=%d remote=%s", knkMsg.UserId, transactionId, addrStr))
		}
		if aspData == nil {
			closureErr = common.ErrAuthServiceProviderNotFound
			ackMsg.ErrCode = common.ErrAuthServiceProviderNotFound.ErrorCode()
			ackMsg.ErrMsg = closureErr.Error()
			// MetricAuthFailure attribution is owned by
			// ResolveAuthSvcProvider: it fires on auth-policy-outcome
			// branches (unknown aspId, no resource lookup wired AND no
			// in-memory entry) and suppresses on DDB-error / graceful-
			// shutdown branches. The caller MUST NOT add its own
			// counter here or the MetricResourceLookupDDBError vs
			// MetricAuthFailure split collapses.
			return
		}

		// find out auth plugin handler
		handler := s.FindPluginHandler(knkMsg.AuthServiceId)
		if handler == nil {
			log.Error("server-agent(%s#%d@%s)[HandleKnockRequest-Auth] failed to find service provider with %s", knkMsg.UserId, transactionId, addrStr, knkMsg.AuthServiceId)
			closureErr = common.ErrAuthServiceProviderNotFound
			ackMsg.ErrCode = common.ErrAuthServiceProviderNotFound.ErrorCode()
			ackMsg.ErrMsg = closureErr.Error()
			return
		}

		authReq := &common.NhpAuthRequest{
			Msg:       knkMsg,
			Ack:       ackMsg,
			PublicKey: base64.StdEncoding.EncodeToString(ppd.RemotePubKey),
			SrcAddr: &common.NetAddress{
				Ip:   ppd.ConnData.RemoteAddr.IP.String(),
				Port: ppd.ConnData.RemoteAddr.Port,
			},
			OriginalPacket: ppd.BasePacketContent(), // For server-to-server forwarding
		}

		// perform knock auth and open ip rule from the agent src address and resource dst address
		ackMsg, closureErr = handler.AuthWithNHP(authReq, s.NewNhpServerHelper(ppd, aspData))
		if closureErr != nil {
			log.Info("server-agent(%s#%d@%s)[HandleKnockRequest] failed: %+v", knkMsg.UserId, transactionId, addrStr, closureErr)
			s.metrics.IncrCounter(MetricAuthFailure)
			return
		}

		// Do not add %+v ackMsg here — ackMsg carries ACTokens (token leak).
		log.Info("server-agent(%s#%d@%s)[HandleKnockRequest] succeed", knkMsg.UserId, transactionId, addrStr)
		s.metrics.IncrCounter(MetricAuthSuccess)
	}()

	// Record knock processing latency
	s.metrics.RecordLatency(MetricKnockLatency, float64(time.Since(knockStart).Milliseconds()))

	// marshal the knock ack response; the caller sends it
	ackBytes, marshalErr := json.Marshal(ackMsg)
	if marshalErr != nil {
		log.Error("server-agent(%s#%d@%s)[HandleKnockRequest] failed to marshal ack message: %v", knkMsg.UserId, transactionId, addrStr, marshalErr)
		return nil, knkMsg.UserId, marshalErr
	}

	// DHP knock
	if ppd.HeaderType == core.DHP_KNK {
		ackBytes, marshalErr = json.Marshal(dhpAckMsg)
		if marshalErr != nil {
			log.Error("server-agent(%s#%d@%s)[HandleKnockRequest] failed to marshal DHP ack message: %v", knkMsg.UserId, transactionId, addrStr, marshalErr)
			return nil, knkMsg.UserId, marshalErr
		}
	}

	return ackBytes, knkMsg.UserId, nil
}

const (
	qurlRelayBootstrapAuthServiceID = "qurl"
	qurlRelayBootstrapResourceID    = "qurl-bootstrap"
	qurlAccessTokenUserDataKey      = "qurl_access_token"
)

func isQurlRelayBootstrapKnock(ppd *core.PacketParserData, knkMsg *common.AgentKnockMsg) bool {
	if ppd == nil || knkMsg == nil {
		return false
	}
	if ppd.HeaderType != core.NHP_KNK {
		return false
	}
	if knkMsg.AuthServiceId != qurlRelayBootstrapAuthServiceID {
		return false
	}
	if knkMsg.ResourceId != qurlRelayBootstrapResourceID {
		return false
	}
	if len(ppd.RemotePubKey) == 0 {
		return false
	}
	raw, ok := knkMsg.UserData[qurlAccessTokenUserDataKey]
	if !ok {
		return false
	}
	token, ok := raw.(string)
	if !ok {
		return false
	}
	return looksLikeQurlAccessTokenForBootstrap(strings.TrimSpace(token))
}

func looksLikeQurlAccessTokenForBootstrap(token string) bool {
	if !strings.HasPrefix(token, "at_") || len(token) < 8 || len(token) > 512 {
		return false
	}
	for _, c := range token {
		if !(unicode.IsLetter(c) || unicode.IsDigit(c) || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

// resolveAgentPeerForKnock looks the presented agent pubkey up
// in the qurl-agent-keys DDB table (LRU-cached) and registers
// the resulting peer with the live agentPeerMap on first hit.
// Returns nil on success, an error pre-populated with the right
// ackMsg fields on reject.
//
// agentPeerMap is the steady-state authority: once AddAgentPeer
// has run, every subsequent knock from this agent short-circuits
// before LookupAgentByPubKey is called. A 60s TTL cache miss in
// the lookup does NOT evict from agentPeerMap.
func (s *UdpServer) resolveAgentPeerForKnock(
	ppd *core.PacketParserData,
	knkMsg *common.AgentKnockMsg,
	ackMsg *common.ServerKnockAckMsg,
	transactionId uint64,
	addrStr string,
) error {
	// Empty/nil RemotePubKey check up front. base64.StdEncoding of nil
	// or zero-length input is "", but check the raw bytes instead of
	// the encoded form so the intent ("did the responder actually
	// give us a pubkey?") is explicit at the read site rather than
	// implicit in base64 round-trip behavior.
	if len(ppd.RemotePubKey) == 0 {
		// Distinct event from "agent_unknown_pubkey" so dashboard
		// slicing separates responder-regression (empty key reached
		// the handler) from missing-registration (key reached the
		// handler but no DDB row exists). Same MetricAuthFailure
		// counter — alarm cardinality stays flat.
		//
		// pubkey_b64_prefix="<empty>" keeps the field present on
		// the line so grep-based dashboards parsing
		// `pubkey_b64_prefix=` against the other reject branches
		// see a consistent schema.
		log.Error("server-agent(%s#%d@%s)[HandleKnockRequest] event=\"agent_empty_pubkey\" pubkey_b64_prefix=%q",
			knkMsg.UserId, transactionId, addrStr, pubkeyLogPrefix(""))
		err := common.ErrKnockServerNotFound
		ackMsg.ErrCode = err.ErrorCode()
		ackMsg.ErrMsg = err.Error()
		// Empty pubkey is an auth-policy outcome (responder failed
		// to populate ppd.RemotePubKey, or the agent presented none);
		// counted as AuthFailure so the existing auth-failures alarm
		// catches it. Matches the unknown-pubkey branch below for
		// alarm symmetry.
		s.metrics.IncrCounter(MetricAuthFailure)
		return err
	}
	pubKeyB64 := base64.StdEncoding.EncodeToString(ppd.RemotePubKey)

	// alreadyKnown pre-check: hold agentPeerMapMutex only to read
	// the map, then release before LookupAgentByPubKey runs. The
	// Unlock-before-Lookup pattern is intentional: holding the
	// mutex across the DDB call would serialize ALL agent knocks
	// process-wide on whoever is currently waiting for DDB,
	// turning a single tail-latency event into a fleet-wide pause.
	// The downside — two concurrent callers can both miss the warm
	// path and both hit LookupAgentByPubKey — is bounded by
	// AgentPeerLookup.sfGroup (singleflight dedupes the DDB query)
	// and AddAgentPeer's `added` bool return (gates the metric/log
	// single-fire). See agent_peer_lookup.go::AgentPeerLookup
	// godoc for the singleflight contract this depends on.
	s.agentPeerMapMutex.Lock()
	_, alreadyKnown := s.agentPeerMap[pubKeyB64]
	s.agentPeerMapMutex.Unlock()
	if alreadyKnown {
		// Deliberate divergence from the AC re-registration pattern in
		// HandleACOnline (msghandler.go:879-894), which calls UpdateRecv
		// on every knock to track source-port rebinds. We do NOT call
		// UpdateRecv here: no downstream code today reads
		// agentPeer.RecvAddr() (the auth flow uses
		// ppd.ConnData.RemoteAddr directly for SrcAddr; the AC RecvAddr
		// consumers in udpserver.go are scoped to ACPeer/DBPeer). The
		// cache-warm path is therefore a pure no-op on intent.
		//
		// Trade-off: an agent behind a NAT that rebinds its source port
		// between knocks keeps a stale RecvAddr on its in-process peer
		// entry until the nhp-server process restarts. If a future
		// change adds a consumer that reads agentPeer.RecvAddr() (e.g.
		// server-initiated outbound, broadcast, plugin handlers), this
		// short-circuit must move below UpdateRecv to match the AC
		// pattern — or each new consumer must source RemoteAddr from
		// the live ppd at call time.
		//
		// TestResolveAgentPeerForKnock_CacheWarmDoesNotUpdateRecvAddr
		// fences this divergence; flip its expectation along with the
		// behavior change if/when this turns into a problem.
		return nil
	}

	// Use the server-lifecycle context so a Stop() during a stuck
	// DDB call cancels promptly rather than waiting out
	// DynamoDBOperationTimeout per in-flight knock. Falls back to
	// context.Background() pre-Start (tests construct UdpServer
	// without calling Start).
	//
	// IMPORTANT: this MUST stay a process-shared context, NOT a
	// per-knock derived one. AgentPeerLookup wraps the call in a
	// singleflight gate that captures the first caller's ctx; if a
	// future change threads (say) a per-knock WithTimeout here, the
	// first caller's cancellation would propagate to all N
	// piggybackers. Re-read the godoc on LookupAgentByPubKey before
	// changing this.
	lookupCtx := s.lifecycleCtx
	if lookupCtx == nil {
		lookupCtx = context.Background()
	}
	peer, lookupErr := s.agentPeerLookup.LookupAgentByPubKey(lookupCtx, pubKeyB64)
	if lookupErr == nil {
		// AddAgentPeer reports whether THIS call performed the first
		// insertion for the pubkey. Gating the entire post-resolve
		// side-effect block (UpdateRecv + log + counter) on the
		// returned bool keeps three invariants single-fired under
		// singleflight piggyback:
		//
		//   - MetricAgentFirstResolve counts one logical resolve per
		//     pubkey-window. Without this gate, N concurrent
		//     first-knocks all reach the same sfGroup slot and each
		//     increment the counter (N for one resolve), distorting
		//     the writer-side-liveness signal the metric provides.
		//   - The agent_resolved structured log fires once. N copies
		//     of the same line under bursty load would obscure the
		//     resolve cardinality.
		//   - peer.UpdateRecv is called exactly once on the cached
		//     pointer. Piggybackers' source addresses are no longer
		//     written; the cached RecvAddr stays at the first
		//     inserter's value, matching the cache-warm short-circuit
		//     behavior documented at the alreadyKnown branch above.
		//     This is deterministic — no last-writer-wins race on
		//     the shared cache pointer — and the only case where
		//     multiple piggybackers present DISTINCT source addresses
		//     is the cross-tenant pubkey-squat posture
		//     (qurl-service #488 tracks the hard uniqueness fix).
		//
		// Mirrors the cloud-mode AC pattern in HandleACOnline
		// (UpdateRecv runs only on the first registration in a
		// connection lifecycle, not on every re-registration).
		if s.AddAgentPeer(peer) {
			peer.UpdateRecv(ppd.LocalInitTime, ppd.ConnData.RemoteAddr)
			// pubkey_b64_prefix=%q (NOT pubkey_b64=%q) for schema
			// consistency with the reject branches below. Every
			// agent-event log line uses the same field name so
			// dashboards/grep patterns built against
			// `pubkey_b64_prefix=` capture both success and reject
			// signals uniformly. The truncated form (12 chars via
			// pubkeyLogPrefix) is uniquely identifying in practice;
			// the full key is recoverable from cache-state dumps if
			// ever needed for triage.
			//
			// owner_id is read from the lookup cache (populated by
			// queryAndCache via the KEYS_ONLY GSI projection — free
			// alongside public_key). Empty when the row was older
			// than the writer-side owner_id rollout or the cache
			// evicted between the resolve and the log; in that case
			// the field is just empty in the log line.
			log.Info("server-agent(%s#%d@%s)[HandleKnockRequest] event=\"agent_resolved\" pubkey_b64_prefix=%q owner_id=%q",
				knkMsg.UserId, transactionId, addrStr, pubkeyLogPrefix(pubKeyB64),
				s.agentPeerLookup.CachedOwnerID(pubKeyB64))
			s.metrics.IncrCounter(MetricAgentFirstResolve)
		}
		return nil
	}

	// Reject path: identical wire error for unknown vs DDB
	// failure; only the structured log and the metric differ.
	// Unknown is an auth-policy outcome (counted as AuthFailure so
	// existing alarms catch it); DDB-error is an infra outcome
	// (counted separately so the auth-failures alarm doesn't page
	// on a DDB hiccup). Shutdown-canceled is neither — surface as
	// info, don't pollute either counter.
	//
	// Log the truncated pubkey prefix on the reject paths via the
	// shared pubkeyLogPrefix helper (license_pubkey_gate.go) —
	// returns at most 12 chars, matching the convention already in
	// use on the AC pubkey gates so dashboards stay homogeneous.
	// At normal volume the saving over the full 44-byte b64 is
	// negligible, but a scan/fuzz storm where unknown-pubkey
	// rejects dominate is the worst case for CloudWatch cost — the
	// prefix is still greppable and uniquely identifies the agent
	// in practice. The success path keeps the full key (low
	// frequency, useful for triage).
	pubKeyPrefix := pubkeyLogPrefix(pubKeyB64)
	switch {
	case errors.Is(lookupErr, ErrAgentUnknownPubkey):
		log.Warning("server-agent(%s#%d@%s)[HandleKnockRequest] event=\"agent_unknown_pubkey\" pubkey_b64_prefix=%q",
			knkMsg.UserId, transactionId, addrStr, pubKeyPrefix)
		s.metrics.IncrCounter(MetricAuthFailure)
	case errors.Is(lookupErr, context.Canceled) && lookupCtx.Err() != nil:
		// Server is shutting down (lifecycleCtx canceled). The
		// errors.Is(context.Canceled) match is load-bearing: a
		// DDB call that exceeds DynamoDBOperationTimeout returns
		// DeadlineExceeded (wrapped through %w), which we DO
		// want to fall through into the default DDB-error branch
		// — otherwise a healthy server doing slow DDB calls
		// would silently swallow infra signals. Pairing with the
		// lookupCtx.Err() != nil guard avoids matching a
		// hypothetical future caller-side cancellation that
		// doesn't reflect server shutdown.
		//
		// Without the shutdown-suppression branch, a normal
		// Stop() during in-flight knock lookups would look like
		// a DDB outage on dashboards because every queued lookup
		// returns an error wrapping ctx.Canceled.
		//
		// Assumption: lookupCtx is UdpServer.lifecycleCtx (or
		// context.Background pre-Start in tests). This is the
		// same process-shared-ctx requirement the godoc on
		// LookupAgentByPubKey warns about for singleflight ctx
		// capture — both branches share the invariant. If a
		// future change threads a per-call WithTimeout here, the
		// errors.Is(context.Canceled) match still does the right
		// thing for actual cancellations; only re-classifying
		// caller-side deadlines as shutdown would need attention.
		log.Info("server-agent(%s#%d@%s)[HandleKnockRequest] event=\"agent_lookup_shutdown\" pubkey_b64_prefix=%q err=%v",
			knkMsg.UserId, transactionId, addrStr, pubKeyPrefix, lookupErr)
	case errors.Is(lookupErr, ErrAgentLookupMalformedRow):
		// Writer-side schema regression: DDB returned a row whose
		// shape attributevalue.UnmarshalMap could not parse. Same
		// counter as a transient DDB error (a third metric would
		// inflate alarm cardinality for an exceedingly rare case)
		// but a distinct event= tag so triage sees the schema-
		// regression theory immediately rather than grepping the
		// err string. ErrAgentLookupMalformedRow wraps
		// ErrAgentLookupRetryAfter (see the sentinel godoc in
		// agent_peer_lookup.go), so this case must come before the
		// default arm — otherwise the generic ddb_error branch
		// would swallow it.
		log.Error("server-agent(%s#%d@%s)[HandleKnockRequest] event=\"agent_lookup_row_unmarshal_error\" pubkey_b64_prefix=%q err=%v",
			knkMsg.UserId, transactionId, addrStr, pubKeyPrefix, lookupErr)
		s.metrics.IncrCounter(MetricAgentLookupDDBError)
	case errors.Is(lookupErr, ErrAgentLookupInternal):
		// Code-regression branch (e.g., singleflight closure
		// returning a non-*core.UdpPeer despite the contract).
		// Structurally impossible today; the distinct event= tag
		// routes triage to the dev on-call instead of misleading
		// the SRE on-call to a DDB-outage theory.
		// ErrAgentLookupInternal wraps ErrAgentLookupRetryAfter
		// so this case must precede the default arm.
		log.Error("server-agent(%s#%d@%s)[HandleKnockRequest] event=\"agent_lookup_internal_bug\" pubkey_b64_prefix=%q err=%v",
			knkMsg.UserId, transactionId, addrStr, pubKeyPrefix, lookupErr)
		s.metrics.IncrCounter(MetricAgentLookupDDBError)
	default:
		// ErrAgentLookupRetryAfter and any future error variant.
		log.Error("server-agent(%s#%d@%s)[HandleKnockRequest] event=\"agent_lookup_ddb_error\" pubkey_b64_prefix=%q err=%v",
			knkMsg.UserId, transactionId, addrStr, pubKeyPrefix, lookupErr)
		s.metrics.IncrCounter(MetricAgentLookupDDBError)
	}

	rejectErr := common.ErrKnockServerNotFound
	ackMsg.ErrCode = rejectErr.ErrorCode()
	ackMsg.ErrMsg = rejectErr.Error()
	return rejectErr
}
