package agent

import (
	"encoding/json"
	"net"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
	"github.com/OpenNHP/opennhp/nhp/log"
)

// note: code in request.go is for nhp-agent to send request to nhp-server.

// resolveServerAddr validates the server peer and returns its UDP send address.
func resolveServerAddr(peer *core.UdpPeer, userId, funcName string) (*net.UDPAddr, error) {
	// #3108: these are operator-actionable misconfigurations returned as a
	// (retriable) error to a retry loop — knockResourceRoutine retries per
	// interval — not unrecoverable process-integrity events, so Error, not
	// Critical (which would spam per-retry under a persistently misconfigured peer).
	if peer == nil {
		log.Error("agent(%s)[%s] server is not assigned", userId, funcName)
		return nil, common.ErrKnockServerNotFound
	}
	sendAddr := peer.SendAddr()
	if sendAddr == nil {
		log.Error("agent(%s)[%s] server IP cannot be parsed", userId, funcName)
		return nil, common.ErrKnockServerNotFound
	}
	udpAddr, ok := sendAddr.(*net.UDPAddr)
	if !ok {
		log.Error("agent(%s)[%s] unexpected address type %T", userId, funcName, sendAddr)
		return nil, common.ErrKnockServerNotFound
	}
	return udpAddr, nil
}

// newMsgData creates a MsgData with common agent fields pre-populated.
// Callers should set ResponseMsgCh or EncryptedPktCh as needed.
func (a *UdpAgent) newMsgData(addr *net.UDPAddr, headerType int, msg []byte, peerPk []byte) *core.MsgData {
	return &core.MsgData{
		RemoteAddr:    addr,
		HeaderType:    headerType,
		CipherScheme:  a.config.DefaultCipherScheme,
		TransactionId: a.device.NextCounterIndex(),
		Compress:      true,
		Message:       msg,
		PeerPk:        peerPk,
	}
}

// sendOrStop enqueues md on sendMsgCh, bailing out if the agent is being torn
// down. It returns true if the message was enqueued, or false if signals.stop
// closed first; the caller logs and returns its own stopped-error shape on false.
//
// This is the send-side sibling of awaitTransactionResponse and guards every
// send to sendMsgCh. sendMsgCh is never closed (see Stop()), so the raw send
// can't panic — but an IsRunning() check alone can't make it safe: not all
// callers are wg-tracked, so a bare blocking send on a full buffer after
// sendMessageRoutine has exited would hang (leaking an untracked caller, or
// deadlocking Stop()'s wg.Wait() for a wg-tracked knock caller). Selecting on
// signals.stop makes the send either complete while the routine is alive or bail
// cleanly; with signals.stop open it's identical to a bare send.
//
// Callers gate this behind IsRunning(): on a never-Start()ed agent both
// a.sendMsgCh and a.signals.stop are nil, so both select cases would block
// forever (Start() assigns them before flipping running=true). The nil-sendMsgCh
// guard below backstops that convention, so a future caller that forgets the gate
// bails cleanly instead of hanging rather than relying on the caller inventory
// staying complete.
//
// Deliberately asymmetric with awaitTransactionResponse: that biases toward an
// already-delivered response, whereas dropping a not-yet-sent message on teardown
// has no server-side effect, so the send side doesn't bother. Full rationale +
// caller inventory: docs/design/AGENT_LIFECYCLE_TEARDOWN.md invariant #2.
func (a *UdpAgent) sendOrStop(md *core.MsgData) bool {
	// Snapshot both channels under lifecycleMu.RLock so a concurrent Start()
	// reassignment can't data-race these reads (#3103); the blocking select then
	// runs on the locals, never holding the lock (which would deadlock Stop()).
	a.lifecycleMu.RLock()
	sendCh, stopCh := a.sendMsgCh, a.signals.stop
	a.lifecycleMu.RUnlock()
	if sendCh == nil {
		return false // never-Start()ed; both channels nil, so the select would hang
	}
	select {
	case sendCh <- md:
		return true
	case <-stopCh:
		return false
	}
}

// awaitOrDeadline receives one value from ch, bailing out cleanly if stop closes
// or deadline fires first. It returns (v, true) once a value arrives, or
// (zero, false) on a stop/deadline bail. A nil deadline channel never fires, so
// awaitOrStop (which passes nil) has no deadline. Callers: awaitTransactionResponse
// (ResponseMsgCh, no deadline — the transaction layer carries its own) and
// preAccessRequest (EncryptedPktCh, with an encrypt deadline — #3112).
//
// ch MUST be buffered (size 1) and single-writer: the producer writes with a
// BLOCKING send from a device.wg-tracked goroutine, so if this caller bails
// without receiving, the buffer must absorb that late write or the writer
// deadlocks device.Stop()'s wg.Wait(). On the receive path ch is closed
// DELIBERATELY, so a future second writer fails loud with a send-on-closed panic
// (caught under -race) rather than silently breaking the single-writer contract;
// don't drop it. On the bail path ch is left open so the late write lands in the
// buffer and ch is GC'd.
//
// The leading non-blocking receive prefers an already-delivered value over the
// stop/deadline bail, so a raced Stop() (or a deadline firing the same instant
// the packet lands) can't discard a result that actually arrived. Full rationale:
// docs/design/AGENT_LIFECYCLE_TEARDOWN.md invariant #3.
func awaitOrDeadline[T any](ch chan T, stop <-chan struct{}, deadline <-chan time.Time) (T, bool) {
	if ch == nil {
		// Defensive: a nil channel never delivers, so without this the select
		// could hang if a future caller passes one (callers always make ch today).
		var zero T
		return zero, false
	}
	select {
	case v := <-ch:
		close(ch)
		return v, true
	default:
	}
	select {
	case v := <-ch:
		close(ch)
		return v, true
	case <-stop:
		var zero T
		return zero, false
	case <-deadline:
		var zero T
		return zero, false
	}
}

// awaitOrStop is awaitOrDeadline with no deadline — the teardown-only variant for
// the transaction ResponseMsgCh path (whose deadline lives at the transaction
// layer, AgentLocalTransactionResponseTimeoutMs).
func awaitOrStop[T any](ch chan T, stop <-chan struct{}) (T, bool) {
	return awaitOrDeadline(ch, stop, nil)
}

// awaitTransactionResponse waits for the single transaction response on ch,
// bailing on Stop(). Returns (ppd, true) on a response or (nil, false) on stop; a
// (nil, false) is surfaced by callers as ErrPacketToMessageRoutineStopped, which
// is retriable, not terminal — the request may already have taken effect
// server-side (advisory for EXTERNAL consumers; the in-tree knock loops retry).
// ch's buffering/close contract is documented on awaitOrStop; the single-writer
// property it relies on is fenced in nhp/core (see the back-reference comments +
// TestResponseMsgChWrittenExactlyOnce, executable-fence follow-up in #3104).
func (a *UdpAgent) awaitTransactionResponse(ch chan *core.PacketParserData) (*core.PacketParserData, bool) {
	// stopSignal() snapshots a.signals.stop under RLock so this can't race a
	// concurrent Start() reassignment (#3103).
	return awaitOrStop(ch, a.stopSignal())
}

func (a *UdpAgent) RequestOtp(target *KnockTarget) error {
	state := a.snapshotKnockUserState()
	otpMsg := &common.AgentOTPMsg{
		UserId:         state.user.UserId,
		DeviceId:       state.deviceID,
		OrganizationId: state.user.OrganizationId,
		AuthServiceId:  target.AuthServiceId,
		UserData:       state.user.UserData,
	}
	// G117 (secret-in-json): AgentOTPMsg's struct type carries a
	// Passcode field ("pass" on the wire) that has its own struct-tag
	// `//nolint:gosec // G117` at nhp/common/nhpmsg.go:38. Newer
	// gosec versions flag the Marshal callsite via taint analysis
	// even when the field carries its own suppression, so the
	// callsite needs its own nolint for the scan to pass. Same
	// shape of suppression as the ResolveRequest Marshal in
	// endpoints/server/staticplugins/qurl/resolver.go:174.
	//
	// In THIS RequestOtp path Passcode is deliberately not populated
	// (the literal above omits it) — the OTP is being *requested*,
	// not presented — so the taint flag is type-based on the struct,
	// not evidence of a secret in this particular marshal.
	//
	// Asymmetry note: the sibling RegisterPublicKey below marshals
	// AgentRegisterMsg, which carries an OTP field that IS populated on
	// the wire. gosec v2.11.4's G117 pattern matches "pass"/"passcode"
	// but not "otp", so that callsite isn't flagged today and carries no
	// nolint — see the note there for why a pre-emptive one is deliberately
	// omitted.
	otpBytes, marshalErr := json.Marshal(otpMsg) //nolint:gosec // G117
	if marshalErr != nil {
		log.Error("agent(%s)[RequestOtp] failed to marshal OTP message: %v", otpMsg.UserId, marshalErr)
		return marshalErr
	}

	serverPeer := target.GetServerPeer()
	addr, err := resolveServerAddr(serverPeer, otpMsg.UserId, "RequestOtp")
	if err != nil {
		return err
	}

	otpMd := a.newMsgData(addr, core.NHP_OTP, otpBytes, serverPeer.PublicKey())

	if !a.IsRunning() {
		log.Error("agent(%s#%d)[RequestOtp] MsgData channel closed or being closed, skip sending", otpMsg.UserId, otpMd.TransactionId)
		return common.ErrPacketToMessageRoutineStopped
	}

	// Guarded send (see sendOrStop): bail cleanly if a concurrent Stop() is
	// tearing the agent down.
	if !a.sendOrStop(otpMd) {
		log.Error("agent(%s#%d)[RequestOtp] message routine stopped, skip sending", otpMsg.UserId, otpMd.TransactionId)
		return common.ErrPacketToMessageRoutineStopped
	}

	log.Info("agent(%s#%d)[RequestOtp] sending otp request", otpMsg.UserId, otpMd.TransactionId)
	return nil
}

func (a *UdpAgent) RegisterPublicKey(otp string, target *KnockTarget) (rakMsg *common.ServerRegisterAckMsg, err error) {
	state := a.snapshotKnockUserState()
	regMsg := &common.AgentRegisterMsg{
		UserId:         state.user.UserId,
		DeviceId:       state.deviceID,
		OrganizationId: state.user.OrganizationId,
		AuthServiceId:  target.AuthServiceId,
		OTP:            otp,
		UserData:       state.user.UserData,
	}
	// G117 (secret-in-json): deliberately NOT suppressed here. gosec
	// v2.11.4's pattern matches "pass"/"passcode" but not "otp", so
	// marshaling AgentRegisterMsg.OTP (necessarily on the wire — REG
	// carries the OTP from the prior OTP request) isn't flagged today. A
	// pre-emptive //nolint would silently mask the FIRST real G117 this
	// line ever draws — the event that would add one is the same event you'd
	// want to see. If a future gosec tightens the pattern and fires here,
	// evaluate it then and add the suppression with that finding; contrast
	// the RequestOtp callsite above, which needs its nolint today.
	regBytes, marshalErr := json.Marshal(regMsg)
	if marshalErr != nil {
		log.Error("agent(%s)[RegisterPublicKey] failed to marshal REG message: %v", regMsg.UserId, marshalErr)
		return nil, marshalErr
	}

	serverPeer := target.GetServerPeer()
	addr, err := resolveServerAddr(serverPeer, regMsg.UserId, "RegisterPublicKey")
	if err != nil {
		return nil, err
	}
	addrStr := addr.String()

	regMd := a.newMsgData(addr, core.NHP_REG, regBytes, serverPeer.PublicKey())
	regMd.ResponseMsgCh = make(chan *core.PacketParserData, 1) // buffered: see awaitTransactionResponse

	if !a.IsRunning() {
		log.Error("agent(%s#%d)[RegisterPublicKey] MsgData channel closed or being closed, skip sending", regMsg.UserId, regMd.TransactionId)
		return nil, common.ErrPacketToMessageRoutineStopped
	}

	// Guarded send (see sendOrStop).
	if !a.sendOrStop(regMd) {
		log.Error("agent(%s#%d)[RegisterPublicKey] message routine stopped, skip sending", regMsg.UserId, regMd.TransactionId)
		return nil, common.ErrPacketToMessageRoutineStopped
	}

	// Block for the transaction response, bailing out if a concurrent Stop()
	// tears the agent down first (this method isn't wg-tracked; see
	// awaitTransactionResponse).
	serverPpd, ok := a.awaitTransactionResponse(regMd.ResponseMsgCh)
	if !ok {
		log.Error("agent(%s#%d)[RegisterPublicKey] message routine stopped, skip waiting for response", regMsg.UserId, regMd.TransactionId)
		return nil, common.ErrPacketToMessageRoutineStopped
	}

	if serverPpd.Error != nil {
		log.Error("agent(%s#%d)[RegisterPublicKey] failed to receive response from server %s: %v", regMsg.UserId, regMd.TransactionId, addrStr, serverPpd.Error)
		err = serverPpd.Error
		return nil, err
	}

	if serverPpd.HeaderType != core.NHP_RAK {
		log.Error("agent(%s#%d)[RegisterPublicKey] response has wrong type: %s", regMsg.UserId, regMd.TransactionId, core.HeaderTypeToString(serverPpd.HeaderType))
		err = common.ErrTransactionRepliedWithWrongType
		return nil, err
	}

	rakMsg = &common.ServerRegisterAckMsg{}
	err = json.Unmarshal(serverPpd.BodyMessage, rakMsg)
	if err != nil {
		log.Error("agent(%s#%d)[RegisterPublicKey] failed to parse %s message: %v", regMsg.UserId, regMd.TransactionId, core.HeaderTypeToString(serverPpd.HeaderType), err)
		return nil, err
	}

	if rakMsg.ErrCode != common.ErrSuccess.ErrorCode() {
		log.Error("agent(%s#%d)[RegisterPublicKey] response error: %s", regMsg.UserId, regMd.TransactionId, rakMsg.ErrMsg)
		err = common.ErrorCodeToError(rakMsg.ErrCode)
		return rakMsg, err
	}

	log.Info("agent(%s#%d)[RegisterPublicKey] succeed", regMsg.UserId, regMd.TransactionId)
	return rakMsg, nil
}

func (a *UdpAgent) ListResource(target *KnockTarget) (lrtMsg *common.ServerListResultMsg, err error) {
	state := a.snapshotKnockUserState()
	lstMsg := &common.AgentListMsg{
		UserId:         state.user.UserId,
		DeviceId:       state.deviceID,
		OrganizationId: state.user.OrganizationId,
		AuthServiceId:  target.AuthServiceId,
		UserData:       state.user.UserData,
	}
	lstBytes, marshalErr := json.Marshal(lstMsg)
	if marshalErr != nil {
		log.Error("agent(%s)[ListResource] failed to marshal LST message: %v", lstMsg.UserId, marshalErr)
		return nil, marshalErr
	}

	serverPeer := target.GetServerPeer()
	addr, err := resolveServerAddr(serverPeer, lstMsg.UserId, "ListResource")
	if err != nil {
		return nil, err
	}
	addrStr := addr.String()

	lstMd := a.newMsgData(addr, core.NHP_LST, lstBytes, serverPeer.PublicKey())
	lstMd.ResponseMsgCh = make(chan *core.PacketParserData, 1) // buffered: see awaitTransactionResponse

	if !a.IsRunning() {
		log.Error("agent(%s#%d)[ListResource] MsgData channel closed or being closed, skip sending", lstMsg.UserId, lstMd.TransactionId)
		return nil, common.ErrPacketToMessageRoutineStopped
	}

	// Guarded send (see sendOrStop).
	if !a.sendOrStop(lstMd) {
		log.Error("agent(%s#%d)[ListResource] message routine stopped, skip sending", lstMsg.UserId, lstMd.TransactionId)
		return nil, common.ErrPacketToMessageRoutineStopped
	}

	// Block for the transaction response, bailing out on Stop(); see
	// RegisterPublicKey / awaitTransactionResponse.
	serverPpd, ok := a.awaitTransactionResponse(lstMd.ResponseMsgCh)
	if !ok {
		log.Error("agent(%s#%d)[ListResource] message routine stopped, skip waiting for response", lstMsg.UserId, lstMd.TransactionId)
		return nil, common.ErrPacketToMessageRoutineStopped
	}

	if serverPpd.Error != nil {
		log.Error("agent(%s#%d)[ListResource] failed to receive response from server %s: %v", lstMsg.UserId, lstMd.TransactionId, addrStr, serverPpd.Error)
		err = serverPpd.Error
		return nil, err
	}

	if serverPpd.HeaderType != core.NHP_LRT {
		log.Error("agent(%s#%d)[ListResource] response has wrong type: %s", lstMsg.UserId, lstMd.TransactionId, core.HeaderTypeToString(serverPpd.HeaderType))
		err = common.ErrTransactionRepliedWithWrongType
		return nil, err
	}

	lrtMsg = &common.ServerListResultMsg{}
	err = json.Unmarshal(serverPpd.BodyMessage, lrtMsg)
	if err != nil {
		log.Error("agent(%s#%d)[ListResource] failed to parse %s message: %v", lstMsg.UserId, lstMd.TransactionId, core.HeaderTypeToString(serverPpd.HeaderType), err)
		return nil, err
	}

	if lrtMsg.ErrCode != common.ErrSuccess.ErrorCode() {
		log.Error("agent(%s#%d)[ListResource] list response error: %s", lstMsg.UserId, lstMd.TransactionId, lrtMsg.ErrMsg)
		err = common.ErrorCodeToError(lrtMsg.ErrCode)
		return lrtMsg, err
	}

	log.Info("agent(%s#%d)[ListResource] succeed", lstMsg.UserId, lstMd.TransactionId)
	return lrtMsg, nil
}
