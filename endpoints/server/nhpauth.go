package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"
	"unicode"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
	"github.com/OpenNHP/opennhp/nhp/log"
	"github.com/OpenNHP/opennhp/nhp/plugins"
)

func bindServerSessionAuthorityForPluginCallback(callbackReq *common.NhpAuthRequest,
	sessionID uint64, issuedAt time.Time, authority common.AgentKnockMsg,
) (*common.NhpAuthRequest, error) {
	if callbackReq == nil || callbackReq.Msg == nil || sessionID == 0 || issuedAt.IsZero() ||
		!common.ValidNHPAgentPublicKey(authority.NHPAgentPublicKey) {
		return nil, common.ErrInvalidInput
	}
	requestCopy := *callbackReq
	messageCopy := *callbackReq.Msg
	requestCopy.SessionId = sessionID
	requestCopy.SessionIssuedAt = issuedAt
	requestCopy.PublicKey = authority.NHPAgentPublicKey
	messageCopy.NHPSessionId = sessionID
	messageCopy.NHPSessionIssuedAt = issuedAt
	messageCopy.NHPAgentPublicKey = authority.NHPAgentPublicKey
	messageCopy.NHPAgentOwnerID = authority.NHPAgentOwnerID
	messageCopy.RunID = authority.RunID
	messageCopy.RunAttempt = authority.RunAttempt
	messageCopy.NativeSessionOperationID = authority.NativeSessionOperationID
	messageCopy.NativeSessionOperationBinding = authority.NativeSessionOperationBinding
	messageCopy.NativeSessionOperationOwnerID = authority.NativeSessionOperationOwnerID
	messageCopy.NativeSessionOperationPrepared = authority.NativeSessionOperationPrepared
	messageCopy.NativeSessionOperationExpiresAt = authority.NativeSessionOperationExpiresAt
	requestCopy.Msg = &messageCopy
	return &requestCopy, nil
}

// HandleKnockRequest
// Server will respond with success or error with NHP_ACK message
func (s *UdpServer) HandleKnockRequest(ppd *core.PacketParserData) error {
	s.wg.Add(1)
	defer s.wg.Done()

	ackBytes, userId, admission, err := s.buildKnockAckWithAdmission(ppd)
	if err != nil {
		// Only a marshal failure reaches here; the ack cannot be sent.
		// An auth REJECT is not this error — it rides inside ackBytes
		// (ackMsg.ErrCode) and is still delivered below, matching the
		// pre-extraction behavior where the closure's error was overwritten
		// by the send result.
		return err
	}

	ackMd := makeMsgData(ppd, core.NHP_ACK, ackBytes)
	sendErr := s.forwardToTransaction(ppd.ConnData, ppd.SenderTrxId, ackMd, "server-agent", "HandleKnockRequest", userId, ppd.ConnData.RemoteAddr.String())
	if sendErr != nil {
		s.compensateSuccessfulACKBytes(ppd.RemotePubKey, ackBytes)
		return errors.Join(sendErr, s.compensateDurableAdmission(admission))
	}
	if admission != nil {
		markCtx, markCancel := udpCorrelationCtx(DefaultStorageTimeout, userId, ppd.SenderTrxId)
		markErr := s.markDurableSessionAckEnqueued(markCtx, admission.Candidate)
		markCancel()
		if markErr != nil {
			s.compensateSuccessfulACKBytes(ppd.RemotePubKey, ackBytes)
			closeErr := s.compensateDurableAdmission(admission)
			return errors.Join(fmt.Errorf("mark durable NHP ACK boundary: %w", markErr), closeErr)
		}
	}
	return nil
}

// compensateSuccessfulACKBytes closes only a successfully admitted session
// whose serialized ACK could not be delivered by an observable transport
// operation. Denials and DHP replies carry no base session and are no-ops.
func (s *UdpServer) compensateSuccessfulACKBytes(agentPubKey, ackBytes []byte) {
	var closeAck common.ServerExactSessionCloseAckMsg
	if json.Unmarshal(ackBytes, &closeAck) == nil && closeAck.CloseEventID != "" {
		// Exact-retirement success is already durable before its ACK is built.
		// An ACK transport failure is recovered by the caller replaying the same
		// receipt and must not schedule a second process-local compensation path.
		return
	}
	var ack common.ServerKnockAckMsg
	if json.Unmarshal(ackBytes, &ack) != nil || !common.IsSuccessErrCode(ack.ErrCode) || ack.SessionId == 0 {
		return
	}
	s.compensateFailedNHPSessionFleet(agentPubKey, ack.SessionId, time.Time{}, ack.OpenTime)
}

func (s *UdpServer) compensateDurableAdmission(admission *sessionControlAdmissionReceipt) error {
	if admission == nil {
		return nil
	}
	retainUntilMillis := admission.Candidate.ReservationDeadlineMillis
	if admission.OpenTime > 0 {
		lifetimeSeconds := uint64(admission.OpenTime) + uint64(ACOpenCompensationTime)
		if lifetimeSeconds > uint64(math.MaxInt64/time.Second.Milliseconds()) {
			return errors.New("durable exact-session compensation lifetime overflow")
		}
		lifetimeMillis := int64(lifetimeSeconds) * time.Second.Milliseconds()
		nowMillis := time.Now().UnixMilli()
		if nowMillis > math.MaxInt64-lifetimeMillis {
			return errors.New("durable exact-session compensation retention overflow")
		}
		if derived := nowMillis + lifetimeMillis; derived > retainUntilMillis {
			retainUntilMillis = derived
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), DefaultStorageTimeout)
	defer cancel()
	if err := s.ensureDurableExactSessionClose(ctx, admission.Candidate, retainUntilMillis); err != nil {
		return fmt.Errorf("prepare durable exact-session compensation: %w", err)
	}
	return nil
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
	ack, userID, _, err := s.buildKnockAckWithAdmission(ppd)
	return ack, userID, err
}

func (s *UdpServer) buildKnockAckWithAdmission(ppd *core.PacketParserData) ([]byte, string, *sessionControlAdmissionReceipt, error) {
	if ppd == nil {
		return nil, "", nil, errors.New("nil knock packet")
	}
	if ppd.HeaderType == core.NHP_EXT && len(ppd.BodyMessage) == 0 {
		return nil, "", nil, errors.New("bodyless NHP_EXT is not authenticated authority on the current envelope")
	}
	if ppd.HeaderType == core.NHP_EXT {
		var recovery common.AgentNativeSessionOperationRecoveryMsg
		if err := common.DecodeAgentNativeSessionOperationRecoveryMsg(ppd.BodyMessage, &recovery); err == nil {
			ack, userID, recoveryErr := s.buildAgentNativeSessionOperationRecoveryAck(ppd, recovery)
			return ack, userID, nil, recoveryErr
		}
		ack, userID, err := s.buildAgentExactSessionCloseAck(ppd)
		return ack, userID, nil, err
	}
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
	var sessionReserved bool
	var durableCandidate *sessionControlSessionCandidate
	var nativeOperation *sessionControlNativeOperation
	var durableCompensationErr error
	var reservedSessionID uint64
	var reservedSessionIssuedAt time.Time

	func() {
		// parse knockMsg
		if ppd.HeaderType == core.DHP_KNK { // dhp knock
			closureErr = json.Unmarshal(ppd.BodyMessage, dhpKnkMsg)
		} else {
			closureErr = json.Unmarshal(ppd.BodyMessage, knkMsg)
		}

		if closureErr != nil {
			// Canonical-value failures wrap ErrInvalidAgentKnockRunID and map to
			// public RunID error 52025. Duplicate/alias/type abuses remain JSON
			// shape errors by design: conformance requires body-shape rejection to
			// precede auth-service RunID policy.
			if errors.Is(closureErr, common.ErrInvalidAgentKnockRunID) {
				closureErr = common.ErrKnockRunIDInvalid
				ackMsg.ErrCode = common.ErrKnockRunIDInvalid.ErrorCode()
				ackMsg.ErrMsg = closureErr.Error()
				log.Warning("server-agent(#%d@%s)[HandleKnockRequest] rejected knock with malformed runId", transactionId, addrStr)
				return
			}
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
		// NHP_KNK, NHP_RKN, and NHP_EXT (DHP_KNK was carved off at the
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

		// The registered-agent native UDP path is the qURL Connector retry
		// binding boundary. Reject omission before peer lookup, catalog reads, or
		// AC work. Malformed nonempty values were already rejected by the strict
		// application-body decoder above.
		if bindingErr := validateRegisteredAgentKnockRunID(knkMsg); bindingErr != nil {
			publicErr := common.ErrKnockRunIDInvalid
			if errors.Is(bindingErr, common.ErrKnockRunAttemptInvalid) {
				publicErr = common.ErrKnockRunAttemptInvalid
			}
			closureErr = publicErr
			ackMsg.ErrCode = publicErr.ErrorCode()
			ackMsg.ErrMsg = publicErr.Error()
			log.Warning("server-agent(%s#%d@%s)[HandleKnockRequest] rejected registered-agent knock with missing or invalid retry binding",
				knkMsg.UserId, transactionId, addrStr)
			return
		}
		if len(ppd.RemotePubKey) != core.PublicKeySize {
			closureErr = common.ErrInvalidInput
			ackMsg.ErrCode = common.ErrServerACOpsFailed.ErrorCode()
			ackMsg.ErrMsg = common.ErrServerACOpsFailed.Error()
			return
		}
		knkMsg.NHPAgentPublicKey = base64.StdEncoding.EncodeToString(ppd.RemotePubKey)
		operationPresent := common.NativeSessionOperationPresent(*knkMsg)
		if operationPresent || (s.nativeSessionOperationEnabled() && knkMsg.AuthServiceId == common.RegisteredAgentAuthServiceID) {
			if !operationPresent || !s.nativeSessionOperationEnabled() {
				closureErr = common.ErrInvalidInput
				ackMsg.ErrCode = common.ErrServerACOpsFailed.ErrorCode()
				ackMsg.ErrMsg = common.ErrServerACOpsFailed.Error()
				return
			}
			serverBinding, bindingErr := s.nativeSessionOperationServerBinding()
			if bindingErr == nil {
				bindingErr = common.ValidateNativeSessionOperation(*knkMsg, knkMsg.NHPAgentPublicKey, serverBinding, time.Now())
			}
			var operation sessionControlNativeOperation
			if bindingErr == nil {
				operation, bindingErr = sessionControlNativeOperationForKnock(knkMsg, knkMsg.NHPAgentPublicKey, serverBinding)
			}
			if bindingErr != nil {
				closureErr = common.ErrInvalidInput
				ackMsg.ErrCode = common.ErrServerACOpsFailed.ErrorCode()
				ackMsg.ErrMsg = common.ErrServerACOpsFailed.Error()
				return
			}
			nativeOperation = &operation
		}

		// Cloud mode agent peer resolution: with
		// DisableAgentPeerValidation=true the noise responder skipped
		// the peer-pool check, so an unknown-but-registered agent's
		// knock reaches us and must be resolved against the
		// qurl-agent-keys DDB table. Nil lookup = DDB-backed agent
		// path disabled (legacy etcd / file deployments); fall
		// through to the auth handler unchanged.
		if nativeOperation == nil && s.agentPeerLookup != nil && !isQurlRelaySelfAuthKnock(ppd, knkMsg) {
			if resolveErr := s.resolveAgentPeerForKnock(ppd, knkMsg, ackMsg, transactionId, addrStr); resolveErr != nil {
				// resolveAgentPeerForKnock has already populated ackMsg.ErrCode/
				// ErrMsg; the reject rides in the ack, so just stop the pipeline.
				return
			}
		} else if s.agentPeerLookup != nil {
			// qurl.link's first browser knock presents a freshly generated
			// JS-agent / per-qURL pubkey that qurl-service cannot have registered
			// as an agent row. For qv1 the encrypted qURL access token is the
			// bootstrap credential; for qv2 the encrypted signed claims plus
			// proof-of-possession are. Either way the qURL plugin validates the
			// credential and binds ppd.RemotePubKey before opening access, so the
			// DDB agent-key resolution above is skipped.
			log.Info("server-agent(%s#%d@%s)[HandleKnockRequest] event=\"qurl_bootstrap_unknown_pubkey_allowed\" pubkey_b64_prefix=%q",
				knkMsg.UserId, transactionId, addrStr,
				pubkeyLogPrefix(base64.StdEncoding.EncodeToString(ppd.RemotePubKey)))
		}

		// find out auth service provider. Try the in-memory map first
		// (hot path, no allocation). Only fall through to
		// ResolveAuthSvcProvider (which formats the log prefix and
		// consults DDB) on a cache miss.
		var aspData *common.AuthServiceProviderData
		var handler plugins.PluginHandler
		if nativeOperation == nil {
			aspData = s.FindAuthSvcProvider(knkMsg.AuthServiceId)
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
			handler = s.FindPluginHandler(knkMsg.AuthServiceId)
			if handler == nil {
				log.Error("server-agent(%s#%d@%s)[HandleKnockRequest-Auth] failed to find service provider with %s", knkMsg.UserId, transactionId, addrStr, knkMsg.AuthServiceId)
				closureErr = common.ErrAuthServiceProviderNotFound
				ackMsg.ErrCode = common.ErrAuthServiceProviderNotFound.ErrorCode()
				ackMsg.ErrMsg = closureErr.Error()
				return
			}
		}

		// The NHP-Server assigns one non-zero 8-byte session identifier for
		// this access request before any AOP is emitted. The same value is
		// carried through AOP, required back on ART, and returned on the ACK;
		// neither the agent nor an auth plugin may choose or rewrite it.
		reservedSessionIssuedAt = time.Now()
		for range sessionControlRuntimeSessionIDAttempts {
			reservedSessionID, closureErr = s.sessionRegistry().reserveNew(ppd.RemotePubKey, reservedSessionIssuedAt)
			if closureErr != nil {
				break
			}
			knkMsg.NHPSessionId = reservedSessionID
			knkMsg.NHPSessionIssuedAt = reservedSessionIssuedAt
			if !s.sessionControlAuthorityRequired() {
				break
			}

			candidate, candidateErr := sessionControlCandidateForKnock(s.sessionControlCellID, knkMsg)
			if candidateErr == nil {
				reserveBudget := DefaultStorageTimeout
				if nativeOperation != nil {
					candidate.NativeOperation = nativeOperation.Binding
					reserveBudget = sessionControlNativeOperationWriteTimeout + sessionControlNativeOperationReadTimeout
				}
				reserveCtx, reserveCancel := udpCorrelationCtx(reserveBudget, knkMsg.UserId, transactionId)
				if nativeOperation != nil {
					candidateErr = s.reserveNativeDurableSession(reserveCtx, candidate, *nativeOperation, reservedSessionIssuedAt)
				} else {
					candidateErr = s.reserveDurableSession(reserveCtx, candidate)
				}
				reserveCancel()
			}
			if candidateErr == nil {
				durableCandidate = &candidate
				break
			}
			s.sessionRegistry().release(ppd.RemotePubKey, reservedSessionID, reservedSessionIssuedAt)
			reservedSessionID = 0
			if errors.Is(candidateErr, errSessionControlSessionCollision) {
				continue
			}
			closureErr = candidateErr
			break
		}
		if closureErr != nil || reservedSessionID == 0 ||
			(s.sessionControlAuthorityRequired() && durableCandidate == nil) {
			log.Error("server-agent(%s#%d@%s)[HandleKnockRequest] failed to reserve NHP session authority: %v",
				knkMsg.UserId, transactionId, addrStr, closureErr)
			if errors.Is(closureErr, common.ErrNativeSessionOperationRecoveryRequired) {
				closureErr = common.ErrNativeSessionOperationRecoveryRequired
				ackMsg.ErrCode = common.ErrNativeSessionOperationRecoveryRequired.ErrorCode()
				ackMsg.ErrMsg = closureErr.Error()
			} else {
				closureErr = common.ErrServerACOpsFailed
				ackMsg.ErrCode = common.ErrServerACOpsFailed.ErrorCode()
				ackMsg.ErrMsg = closureErr.Error()
			}
			return
		}
		if nativeOperation != nil {
			knkMsg.NHPAgentOwnerID = nativeOperation.OwnerID
			peer := &core.UdpPeer{PubKeyBase64: knkMsg.NHPAgentPublicKey, Type: core.NHP_AGENT}
			s.AddAgentPeer(peer)
		}
		// Everything after the plugin boundary uses this immutable server-owned
		// tuple. A plugin may mutate req.Msg for resource resolution, but it must
		// never be able to rewrite the AOP/ART/ACK identity or strand the original
		// local and durable reservation during compensation.
		sessionReserved = true
		ackMsg.SessionId = reservedSessionID
		// The durable OP transaction is the first external authority on this
		// path. Only after it commits may the server consult ASP/plugin catalog
		// state or invoke plugin/AOP work. A missing in-memory contract is then a
		// normal compensated admission failure, never a pre-transaction bypass.
		if nativeOperation != nil {
			aspData = s.FindAuthSvcProvider(knkMsg.AuthServiceId)
			handler = s.FindPluginHandler(knkMsg.AuthServiceId)
			if aspData == nil || handler == nil {
				closureErr = common.ErrAuthServiceProviderNotFound
				ackMsg.ErrCode = common.ErrAuthServiceProviderNotFound.ErrorCode()
				ackMsg.ErrMsg = closureErr.Error()
				return
			}
		}

		authReq := &common.NhpAuthRequest{
			Msg:            knkMsg,
			Ack:            ackMsg,
			PublicKey:      base64.StdEncoding.EncodeToString(ppd.RemotePubKey),
			WireHeaderType: ppd.HeaderType,
			SrcAddr: &common.NetAddress{
				Ip:   ppd.ConnData.RemoteAddr.IP.String(),
				Port: ppd.ConnData.RemoteAddr.Port,
			},
			OriginalPacket:  ppd.BasePacketContent(), // For server-to-server forwarding
			SessionId:       reservedSessionID,
			SessionIssuedAt: reservedSessionIssuedAt,
		}
		immutableSessionAuthority := *knkMsg
		helper := s.NewNhpServerHelper(ppd, aspData)
		helper.AuthWithNhpCallbackFunc = func(callbackReq *common.NhpAuthRequest,
			res *common.ResourceData,
		) (*common.ServerKnockAckMsg, error) {
			// A plugin may normalize resource fields before dispatch, but it may
			// not rewrite or cross-swap the authenticated session authority.
			requestCopy, bindErr := bindServerSessionAuthorityForPluginCallback(callbackReq,
				reservedSessionID, reservedSessionIssuedAt, immutableSessionAuthority)
			if bindErr != nil {
				return nil, bindErr
			}
			return s.handleNhpOpenResource(requestCopy, res)
		}

		// perform knock auth and open ip rule from the agent src address and resource dst address
		ackMsg, closureErr = handler.AuthWithNHP(authReq, helper)
		if ackMsg == nil {
			// Plugin implementations are outside the server's trust boundary. A
			// nil ACK must not panic this recovered handler or strand the reserved
			// numeric session; convert both (nil,nil) and (nil,error) into the
			// canonical denial envelope and let the final boundary release it.
			ackMsg = &common.ServerKnockAckMsg{
				ErrCode:   common.ErrServerACOpsFailed.ErrorCode(),
				ErrMsg:    common.ErrServerACOpsFailed.Error(),
				AgentAddr: addrStr,
			}
			if closureErr == nil {
				closureErr = common.ErrServerACOpsFailed
			}
		}
		if closureErr != nil {
			log.Info("server-agent(%s#%d@%s)[HandleKnockRequest] failed: %+v", knkMsg.UserId, transactionId, addrStr, closureErr)
			s.metrics.IncrCounter(MetricAuthFailure)
			return
		}

		// Do not add %+v ackMsg here — ackMsg carries ACTokens (token leak).
		log.Info("server-agent(%s#%d@%s)[HandleKnockRequest] succeed", knkMsg.UserId, transactionId, addrStr)
		s.metrics.IncrCounter(MetricAuthSuccess)
	}()
	if closureErr != nil || (ppd.HeaderType != core.DHP_KNK && !common.IsSuccessErrCode(ackMsg.ErrCode)) {
		failedOpenTime := ackMsg.OpenTime
		if closureErr != nil && common.IsSuccessErrCode(ackMsg.ErrCode) {
			// An auth plugin may return a partially populated success ACK together
			// with an error. The error is authoritative: never serialize a success
			// code after the final boundary has removed its session and lifetime.
			ackMsg.ErrCode = common.ErrServerACOpsFailed.ErrorCode()
			ackMsg.ErrMsg = common.ErrServerACOpsFailed.Error()
		}
		// Rejected access requests do not establish an NHP session. Keep the
		// identifier absent rather than exposing a value that no AC admitted.
		// NHP ACK denials also carry the required typed opnTime field with the
		// canonical value zero; a plugin may have stamped a positive lifetime
		// before a later AC/token failure, so normalize it at this final wire
		// boundary rather than relying on every producer branch to unwind it.
		ackMsg.SessionId = 0
		ackMsg.CellId = ""
		ackMsg.SessionIssuedAtMillis = 0
		ackMsg.RunID = ""
		ackMsg.RunAttempt = 0
		ackMsg.OpenTime = 0
		if sessionReserved {
			s.compensateFailedNHPSessionFleet(ppd.RemotePubKey, reservedSessionID, reservedSessionIssuedAt, failedOpenTime)
			s.sessionRegistry().release(ppd.RemotePubKey, reservedSessionID, reservedSessionIssuedAt)
			if durableCandidate != nil {
				durableCompensationErr = errors.Join(durableCompensationErr, s.compensateDurableAdmission(&sessionControlAdmissionReceipt{
					Candidate: *durableCandidate, SessionID: reservedSessionID,
					SessionIssuedAt: reservedSessionIssuedAt, OpenTime: failedOpenTime,
				}))
			}
		}
	} else if ppd.HeaderType != core.DHP_KNK {
		if ackMsg.OpenTime == 0 {
			// A successful NHP ACK must describe a live, bounded session. Do not
			// serialize a success that consumers cannot schedule or expire.
			ackMsg.ErrCode = common.ErrServerACOpsFailed.ErrorCode()
			ackMsg.ErrMsg = common.ErrServerACOpsFailed.Error()
			ackMsg.SessionId = 0
			ackMsg.CellId = ""
			ackMsg.SessionIssuedAtMillis = 0
			ackMsg.RunID = ""
			ackMsg.RunAttempt = 0
			if sessionReserved {
				s.compensateFailedNHPSessionFleet(ppd.RemotePubKey, reservedSessionID, reservedSessionIssuedAt, 0)
				s.sessionRegistry().release(ppd.RemotePubKey, reservedSessionID, reservedSessionIssuedAt)
				if durableCandidate != nil {
					durableCompensationErr = errors.Join(durableCompensationErr, s.compensateDurableAdmission(&sessionControlAdmissionReceipt{
						Candidate: *durableCandidate, SessionID: reservedSessionID, SessionIssuedAt: reservedSessionIssuedAt,
					}))
				}
			}
		} else {
			// Auth plugins may mutate or replace the ACK object, but session
			// assignment remains server-owned. Stamp the authoritative value after
			// plugin return so a replacement cannot omit or rewrite it.
			ackMsg.SessionId = reservedSessionID
			if durableCandidate != nil {
				ackMsg.CellId = durableCandidate.CellID
				ackMsg.SessionIssuedAtMillis = durableCandidate.IssuedAtMillis
				ackMsg.RunID = durableCandidate.RunID
				ackMsg.RunAttempt = durableCandidate.RunAttempt
			} else {
				ackMsg.CellId = ""
				ackMsg.SessionIssuedAtMillis = 0
				ackMsg.RunID = ""
				ackMsg.RunAttempt = 0
			}
		}
	}

	// Record knock processing latency
	s.metrics.RecordLatency(MetricKnockLatency, float64(time.Since(knockStart).Milliseconds()))

	// Marshal the knock ACK response; the caller sends it. Registered-agent
	// replies use their strict receipt union, while every generic knock keeps
	// the legacy envelope unchanged. AuthServiceId comes from the authenticated
	// body and is sufficient to select the denial arm even when run validation
	// rejected the request before a durable candidate was reserved.
	var ackBytes []byte
	var marshalErr error
	if ppd.HeaderType != core.DHP_KNK && knkMsg.AuthServiceId == common.RegisteredAgentAuthServiceID {
		ackBytes, marshalErr = common.MarshalRegisteredAgentKnockAckMsg(
			ackMsg, knkMsg.RunID, knkMsg.RunAttempt, knkMsg.ResourceId,
		)
	} else {
		ackBytes, marshalErr = json.Marshal(ackMsg)
	}
	if marshalErr != nil {
		log.Error("server-agent(%s#%d@%s)[HandleKnockRequest] failed to marshal ack message: %v", knkMsg.UserId, transactionId, addrStr, marshalErr)
		if sessionReserved {
			s.compensateFailedNHPSessionFleet(ppd.RemotePubKey, reservedSessionID, reservedSessionIssuedAt, ackMsg.OpenTime)
			if durableCandidate != nil {
				durableCompensationErr = errors.Join(durableCompensationErr, s.compensateDurableAdmission(&sessionControlAdmissionReceipt{
					Candidate: *durableCandidate, SessionID: reservedSessionID,
					SessionIssuedAt: reservedSessionIssuedAt, OpenTime: ackMsg.OpenTime,
				}))
			}
		}
		return nil, knkMsg.UserId, nil, errors.Join(marshalErr, durableCompensationErr)
	}

	// DHP knock
	if ppd.HeaderType == core.DHP_KNK {
		ackBytes, marshalErr = json.Marshal(dhpAckMsg)
		if marshalErr != nil {
			log.Error("server-agent(%s#%d@%s)[HandleKnockRequest] failed to marshal DHP ack message: %v", knkMsg.UserId, transactionId, addrStr, marshalErr)
			return nil, knkMsg.UserId, nil, marshalErr
		}
	}
	var admission *sessionControlAdmissionReceipt
	if durableCandidate != nil && ppd.HeaderType != core.DHP_KNK && common.IsSuccessErrCode(ackMsg.ErrCode) &&
		ackMsg.SessionId == durableCandidate.SessionID && ackMsg.OpenTime > 0 {
		admission = &sessionControlAdmissionReceipt{
			Candidate: *durableCandidate, SessionID: reservedSessionID,
			SessionIssuedAt: reservedSessionIssuedAt, OpenTime: ackMsg.OpenTime,
		}
	}
	if durableCompensationErr != nil {
		return nil, knkMsg.UserId, nil, durableCompensationErr
	}
	return ackBytes, knkMsg.UserId, admission, nil
}

const (
	qurlRelayBootstrapAuthServiceID = "qurl"
	qurlRelayBootstrapResourceID    = "qurl-bootstrap"
	qurlAccessTokenUserDataKey      = "qurl_access_token"
)

// qURL v2 signed-claims knock carries the issuer-signed claims (Part 1) and the
// issuer signature (Part 3) in two separate encrypted-UserData blobs — NO
// unsigned secret part (the per-qURL private key never leaves the client;
// possession is proven by completing the Noise IK handshake). The field names
// match the NHP Server Contract's prepare request blobs verbatim
// (docs/design/QURL_V2_KEYED_IDENTITY.md → "NHP Server Contract").
//
// Exported because the qURL plugin (which imports this package) keys its qv2
// dispatch on the same UserData blobs; sharing the constant keeps the
// HandleKnockRequest skip-DDB predicate and the plugin dispatch from drifting.
const (
	QurlV2ClaimsUserDataKey    = "qurl_claims_b64"
	QurlV2IssuerSigUserDataKey = "qurl_issuer_sig_b64"
)

// isQurlRelaySelfAuthKnock reports whether a knock is a qURL knock that the
// browser/headless client self-authenticates (qURL access token or qv2 signed
// claims) rather than one whose agent key is pre-registered in the
// qurl-agent-keys DDB table. Both qURL flows present a freshly generated
// per-qURL/JS-agent pubkey that qurl-service cannot have registered as an agent
// row, so HandleKnockRequest skips the DDB agent-key resolution for them; the
// qURL plugin establishes identity from the bootstrap credential (qv1 token) or
// from the signed claims + proof-of-possession (qv2) instead. (Per-qURL key
// authorization model: identity is NOT a catalog row.)
func isQurlRelaySelfAuthKnock(ppd *core.PacketParserData, knkMsg *common.AgentKnockMsg) bool {
	return isQurlRelayBootstrapKnock(ppd, knkMsg) || isQurlV2ClaimsKnock(ppd, knkMsg)
}

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

// isQurlV2ClaimsKnock reports whether a knock is a qURL v2 signed-claims knock.
// It is recognized DISTINCTLY from the qv1 access-token bootstrap: a qv2 knock
// carries the signed claims + issuer signature blobs in encrypted UserData and
// its ResourceId is the protected-resource public key (gospel step 5), NOT the
// "qurl-bootstrap" sentinel. So this predicate keys on the qv2 UserData blobs
// being present and non-empty strings — it deliberately does NOT check
// ResourceId against a sentinel (there is none) and does NOT verify the
// signature here. This is only the cheap "should HandleKnockRequest skip DDB
// agent-key registration?" gate; the qURL plugin's authWithNHPClaims performs
// the authoritative independent signature/binding/liveness verification before
// any AC is opened. A knock that trips this predicate but fails verification is
// rejected there, having merely skipped a DDB lookup it would have missed anyway
// (the per-qURL key is never an agent-keys row).
//
// This predicate is intentionally INDEPENDENT of the qURL v2 admission feature
// flag (which lives in the qURL plugin package and is not readable here). That is
// safe because the plugin's AuthWithNHP decides a qv2-shaped knock either way: it
// runs the full verify when the flag is on and FAILS CLOSED (denies) when the
// flag is off. A qv2-shaped knock never reaches the steady-state path, so the DDB
// lookup this predicate skips can never gate anything — skipping it with the flag
// off changes no outcome.
func isQurlV2ClaimsKnock(ppd *core.PacketParserData, knkMsg *common.AgentKnockMsg) bool {
	if ppd == nil || knkMsg == nil {
		return false
	}
	if ppd.HeaderType != core.NHP_KNK {
		return false
	}
	if knkMsg.AuthServiceId != qurlRelayBootstrapAuthServiceID {
		return false
	}
	if len(ppd.RemotePubKey) == 0 {
		return false
	}
	_, claimsOK := TrimmedStringUserData(knkMsg.UserData, QurlV2ClaimsUserDataKey)
	_, sigOK := TrimmedStringUserData(knkMsg.UserData, QurlV2IssuerSigUserDataKey)
	return claimsOK && sigOK
}

// TrimmedStringUserData returns userData[key] with surrounding whitespace
// trimmed, and ok=true only if it is present, a string, and non-empty after
// trimming. Exported so the qURL plugin's qv2 dispatch reads the same UserData
// blobs the HandleKnockRequest skip-DDB predicate (isQurlV2ClaimsKnock) keys on,
// from a single definition — the predicate and the dispatch must agree on what a
// present, usable qv2 blob is.
func TrimmedStringUserData(userData map[string]any, key string) (string, bool) {
	raw, ok := userData[key]
	if !ok {
		return "", false
	}
	s, ok := raw.(string)
	if !ok {
		return "", false
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return "", false
	}
	return s, true
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
		//     multiple piggybackers present DISTINCT source addresses,
		//     where first-writer-wins is the same posture the cache-warm
		//     branch uses for the pubkey identity.
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
	case errors.Is(lookupErr, ErrAgentLookupSchemaMismatch):
		// Schema/collision/overflow counters are owned by queryAndCache at
		// the exact fail-closed decision point; these arms add log events only.
		log.Error("server-agent(%s#%d@%s)[HandleKnockRequest] event=\"agent_lookup_schema_mismatch\" pubkey_b64_prefix=%q err=%v",
			knkMsg.UserId, transactionId, addrStr, pubKeyPrefix, lookupErr)
	case errors.Is(lookupErr, ErrAgentLookupPubkeyCollision):
		log.Error("server-agent(%s#%d@%s)[HandleKnockRequest] event=\"agent_lookup_pubkey_collision\" pubkey_b64_prefix=%q err=%v",
			knkMsg.UserId, transactionId, addrStr, pubKeyPrefix, lookupErr)
	case errors.Is(lookupErr, ErrAgentLookupPubkeyCandidateOverflow):
		log.Error("server-agent(%s#%d@%s)[HandleKnockRequest] event=\"agent_lookup_pubkey_candidate_overflow\" pubkey_b64_prefix=%q err=%v",
			knkMsg.UserId, transactionId, addrStr, pubKeyPrefix, lookupErr)
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
