package agent

import (
	"encoding/json"
	"errors"
	"net"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
	wasmEngine "github.com/OpenNHP/opennhp/nhp/core/wasm/engine"
	"github.com/OpenNHP/opennhp/nhp/log"
)

func (a *UdpAgent) Knock(res *KnockTarget) (ackMsg *common.ServerKnockAckMsg, err error) {
	// Register against teardown before doing any work: beginTrackedOp does the
	// running check + a.wg.Add(1) under lifecycleMu.RLock, so a DIRECT SDK Knock
	// (sdk.KnockResource, no parent wg token) racing a Stop() already at
	// wg.Wait()==0 can't trip the "WaitGroup reused before Wait returned" panic
	// (#3103). If the agent isn't running, synthesize a stopped ack — the SDK
	// export reads ackMsg (not err), and knockResourceRoutine retries then bails
	// on knockTargetStop.
	if !a.beginTrackedOp() {
		return &common.ServerKnockAckMsg{
			ErrCode: common.ErrPacketToMessageRoutineStopped.ErrorCode(),
			ErrMsg:  common.ErrPacketToMessageRoutineStopped.Error(),
		}, common.ErrPacketToMessageRoutineStopped
	}
	defer a.wg.Done()

	errWaitTime := (core.AgentLocalTransactionResponseTimeoutMs - 100) * time.Millisecond
	startTime := time.Now()

	ackMsg, err = a.knockRequest(res, false)
	if errors.Is(err, common.ErrKnockTerminatedByCookie) {
		// if cookie is required by server, use cookie to knock
		// Note: don't use recursive calling method, it may get too deep if cookie message is kept sending
		// use flat calling
		ackMsg, err = a.knockRequest(res, true)
	}
	// knockRequest returns (nil, err) on its early-error paths: resolveServerAddr
	// failing (nil peer, or a DNS-unresolvable / unparseable server address,
	// nhp/core/peer.go SendAddr()), and — practically unreachable — a json.Marshal
	// failure on the knock message. Synthesize an ackMsg from err so the
	// ackMsg.ErrCode read below — and every later Knock caller, the live
	// knockResourceRoutine (udpagent.go) and the SDK KnockResource export
	// (sdk/ops.go) — can't dereference nil and crash.
	//
	// Adapted from upstream c6f9c769: the fork has no common.ErrorToErrorCode, so
	// recover the wire code by unwrapping the *common.Error (resolveServerAddr
	// returns common.ErrKnockServerNotFound), falling back to its code for any
	// non-*common.Error (e.g. the marshal path). err.Error() is always carried in
	// ErrMsg, so that fallback code is only a best-effort label for the rare
	// non-*common.Error case.
	if ackMsg == nil {
		if err == nil {
			err = common.ErrKnockServerNotFound
		}
		code := common.ErrKnockServerNotFound.ErrorCode()
		var cerr *common.Error
		if errors.As(err, &cerr) {
			code = cerr.ErrorCode()
		}
		ackMsg = &common.ServerKnockAckMsg{
			ErrCode: code,
			ErrMsg:  err.Error(),
		}
	}
	if ackMsg.ErrCode == common.ErrPacketEncryptionFailed.ErrorCode() {
		// local failure, packet not sent
		return ackMsg, err
	}
	if err != nil {
		// If a local error happens, wait some time before returning so the
		// caller (knockResourceRoutine) backs off between retries — but bail
		// immediately on Stop(). Knock is a.wg-tracked and Stop() runs
		// a.wg.Wait() before device.Stop(), so an unconditional sleep here would
		// delay a whole teardown by up to ~errWaitTime (~4.9s) per active knock
		// target, defeating the fast bail-on-signals.stop this PR is built around.
		// (a.signals.stop is nil only for a never-Start()ed agent, e.g. the
		// nil-guard unit test, where the nil case is simply never ready.)
		elapsedTime := time.Since(startTime)
		if elapsedTime < errWaitTime {
			select {
			case <-time.After(errWaitTime - elapsedTime):
			case <-a.signals.stop:
			}
		}
		return ackMsg, err
	}

	// deal with ac PASS_ACCESS_IP mode
	if len(ackMsg.PreAccessActions) > 0 {
		if preErr := a.preAccessRequest(ackMsg); preErr != nil {
			log.Error("agent(%s)[KnockRequest] pre-access request failed: %v", a.knockUser.UserId, preErr)
		}
	}
	res.LastKnockSuccessTime = time.Now()

	log.Info("agent(%s)[KnockRequest] knock for %s:%s success, duration %d seconds", a.knockUser.UserId, res.AuthServiceId, res.ResourceId, ackMsg.OpenTime)
	return ackMsg, err
}

func (a *UdpAgent) knockRequest(res *KnockTarget, useCookie bool) (ackMsg *common.ServerKnockAckMsg, err error) {
	serverPeer := res.GetServerPeer()
	addr, err := resolveServerAddr(serverPeer, a.knockUser.UserId, "KnockRequest")
	if err != nil {
		return nil, err
	}
	addrStr := addr.String()

	// #1154 invariant: body.HeaderType MUST equal the wire
	// HeaderType passed to newMsgData below. Keeping both uses of
	// `headerType` from this single local variable is the
	// mechanical enforcement — a future refactor that reassigns
	// one but not the other will silently break all knocks under
	// strict mode (agent body says KNK, wire says RKN, server
	// rejects). If you split the two sites, add an explicit
	// `require.Equal(body.HeaderType, wireHeaderType)` pin.
	headerType := core.NHP_KNK
	if useCookie {
		headerType = core.NHP_RKN
	}

	a.knockUserMutex.RLock()
	knkMsg := &common.AgentKnockMsg{
		HeaderType:     headerType, // #1154 invariant: must equal newMsgData wire arg below
		UserId:         a.knockUser.UserId,
		DeviceId:       a.deviceId,
		OrganizationId: a.knockUser.OrganizationId,
		AuthServiceId:  res.AuthServiceId,
		ResourceId:     res.ResourceId,
		CheckResults:   a.checkResults,
		UserData:       a.knockUser.UserData,
	}
	a.knockUserMutex.RUnlock()

	knkBytes, marshalErr := json.Marshal(knkMsg)
	if marshalErr != nil {
		log.Error("agent(%s)[Knock] failed to marshal KNK message: %v", knkMsg.UserId, marshalErr)
		return nil, marshalErr
	}
	// #1154 invariant: wire arg here MUST equal knkMsg.HeaderType above.
	knkMd := a.newMsgData(addr, headerType, knkBytes, serverPeer.PublicKey())
	knkMd.ResponseMsgCh = make(chan *core.PacketParserData, 1) // buffered: see awaitTransactionResponse

	ackMsg = &common.ServerKnockAckMsg{}
	if !a.IsRunning() {
		// Not-running only happens during/after Stop(): expected teardown, not an
		// error — log at Debug so routine restarts don't trip error-log alerting.
		log.Debug("agent(%s#%d)[KnockRequest] MsgData channel closed or being closed, skip sending", knkMsg.UserId, knkMd.TransactionId)
		err = common.ErrPacketToMessageRoutineStopped
		ackMsg.ErrCode = common.ErrPacketToMessageRoutineStopped.ErrorCode()
		ackMsg.ErrMsg = err.Error()
		return ackMsg, err
	}

	// Guarded send (see sendOrStop). knockRequest is wg-tracked (via Knock), so
	// bailing here keeps a full-buffer block from deadlocking Stop()'s wg.Wait().
	if !a.sendOrStop(knkMd) {
		log.Error("agent(%s#%d)[KnockRequest] message routine stopped, skip sending", knkMsg.UserId, knkMd.TransactionId)
		err = common.ErrPacketToMessageRoutineStopped
		ackMsg.ErrCode = common.ErrPacketToMessageRoutineStopped.ErrorCode()
		ackMsg.ErrMsg = err.Error()
		return ackMsg, err
	}

	// Block for the transaction response, bailing out on Stop(). knockRequest is
	// wg-tracked (via Knock), so a hang here would deadlock Stop()'s wg.Wait();
	// see awaitTransactionResponse.
	serverPpd, ok := a.awaitTransactionResponse(knkMd.ResponseMsgCh)
	if !ok {
		log.Error("agent(%s#%d)[KnockRequest] message routine stopped, skip waiting for response", knkMsg.UserId, knkMd.TransactionId)
		err = common.ErrPacketToMessageRoutineStopped
		ackMsg.ErrCode = common.ErrPacketToMessageRoutineStopped.ErrorCode()
		ackMsg.ErrMsg = err.Error()
		return ackMsg, err
	}

	if serverPpd.Error != nil {
		log.Error("agent(%s#%d)[KnockRequest] failed to receive response from server %s: %v", knkMsg.UserId, knkMd.TransactionId, addrStr, serverPpd.Error)
		err = serverPpd.Error
		ackMsg.ErrCode = common.ErrPacketEncryptionFailed.ErrorCode()
		ackMsg.ErrMsg = serverPpd.Error.Error()
		return ackMsg, err
	}

	if serverPpd.HeaderType == core.NHP_COK {
		log.Error("agent(%s#%d)[KnockRequest] terminated by server's cookie message", knkMsg.UserId, knkMd.TransactionId)
		err = common.ErrKnockTerminatedByCookie
		ackMsg.ErrCode = common.ErrKnockTerminatedByCookie.ErrorCode()
		ackMsg.ErrMsg = err.Error()
		return ackMsg, err
	}

	if serverPpd.HeaderType != core.NHP_ACK {
		log.Error("agent(%s#%d)[KnockRequest] response has wrong type: %s", knkMsg.UserId, knkMd.TransactionId, core.HeaderTypeToString(serverPpd.HeaderType))
		err = common.ErrTransactionRepliedWithWrongType
		ackMsg.ErrCode = common.ErrTransactionRepliedWithWrongType.ErrorCode()
		ackMsg.ErrMsg = err.Error()
		return ackMsg, err
	}

	err = json.Unmarshal(serverPpd.BodyMessage, ackMsg)
	if err != nil {
		log.Error("agent(%s#%d)[KnockRequest] failed to parse %s message: %v", knkMsg.UserId, knkMd.TransactionId, core.HeaderTypeToString(serverPpd.HeaderType), err)
		ackMsg.ErrCode = common.ErrJsonParseFailed.ErrorCode()
		ackMsg.ErrMsg = err.Error()
		return ackMsg, err
	}

	if ackMsg.ErrCode != common.ErrSuccess.ErrorCode() {
		log.Error("agent(%s#%d)[KnockRequest] response error: %s", knkMsg.UserId, knkMd.TransactionId, ackMsg.ErrMsg)
		err = common.ErrorCodeToError(ackMsg.ErrCode)
		return ackMsg, err
	}

	log.Info("agent(%s#%d)[KnockRequest] succeed", knkMsg.UserId, knkMd.TransactionId)
	return ackMsg, nil
}

func (a *UdpAgent) ExitKnockRequest(res *KnockTarget) (ackMsg *common.ServerKnockAckMsg, err error) {
	serverPeer := res.GetServerPeer()
	addr, err := resolveServerAddr(serverPeer, a.knockUser.UserId, "ExitKnockRequest")
	if err != nil {
		return nil, err
	}
	addrStr := addr.String()

	// #1154 invariant: a single local variable drives BOTH the
	// body.HeaderType and the wire HeaderType passed to
	// newMsgData, so the two can't drift. See knockRequest above
	// for the same pattern — both call sites enforce the
	// invariant structurally (variable reuse) rather than by
	// review-time comment on literal constants.
	headerType := core.NHP_EXT

	a.knockUserMutex.RLock()
	knkMsg := &common.AgentKnockMsg{
		HeaderType:     headerType, // #1154 invariant: must equal newMsgData wire arg below
		UserId:         a.knockUser.UserId,
		DeviceId:       a.deviceId,
		OrganizationId: a.knockUser.OrganizationId,
		AuthServiceId:  res.AuthServiceId,
		ResourceId:     res.ResourceId,
		CheckResults:   a.checkResults,
		UserData:       a.knockUser.UserData,
	}
	a.knockUserMutex.RUnlock()

	knkBytes, marshalErr := json.Marshal(knkMsg)
	if marshalErr != nil {
		log.Error("agent(%s)[ExitKnockRequest] failed to marshal EXT message: %v", knkMsg.UserId, marshalErr)
		return nil, marshalErr
	}
	// #1154 invariant: wire arg here MUST equal knkMsg.HeaderType above.
	knkMd := a.newMsgData(addr, headerType, knkBytes, serverPeer.PublicKey())
	knkMd.ResponseMsgCh = make(chan *core.PacketParserData, 1) // buffered: see awaitTransactionResponse

	ackMsg = &common.ServerKnockAckMsg{}
	if !a.IsRunning() {
		// Not-running only happens during/after Stop(): expected teardown (this
		// runs from the knock sub-routine's defer on every restart), not an error.
		log.Debug("agent(%s#%d)[ExitKnockRequest] MsgData channel closed or being closed, skip sending", knkMsg.UserId, knkMd.TransactionId)
		err = common.ErrPacketToMessageRoutineStopped
		ackMsg.ErrCode = common.ErrPacketToMessageRoutineStopped.ErrorCode()
		ackMsg.ErrMsg = err.Error()
		return ackMsg, err
	}

	// Guarded send (see sendOrStop). ExitKnockRequest is reachable directly from
	// the unsynchronized SDK export (NhpAgentExitResource -> sdk.ExitResource)
	// and is not wg-tracked.
	if !a.sendOrStop(knkMd) {
		log.Error("agent(%s#%d)[ExitKnockRequest] message routine stopped, skip sending", knkMsg.UserId, knkMd.TransactionId)
		err = common.ErrPacketToMessageRoutineStopped
		ackMsg.ErrCode = common.ErrPacketToMessageRoutineStopped.ErrorCode()
		ackMsg.ErrMsg = err.Error()
		return ackMsg, err
	}

	// Block for the transaction response, bailing out on Stop(); see
	// awaitTransactionResponse.
	serverPpd, ok := a.awaitTransactionResponse(knkMd.ResponseMsgCh)
	if !ok {
		log.Error("agent(%s#%d)[ExitKnockRequest] message routine stopped, skip waiting for response", knkMsg.UserId, knkMd.TransactionId)
		err = common.ErrPacketToMessageRoutineStopped
		ackMsg.ErrCode = common.ErrPacketToMessageRoutineStopped.ErrorCode()
		ackMsg.ErrMsg = err.Error()
		return ackMsg, err
	}

	if serverPpd.Error != nil {
		log.Error("agent(%s#%d)[ExitKnockRequest] failed to receive response from server %s: %v", knkMsg.UserId, knkMd.TransactionId, addrStr, serverPpd.Error)
		err = serverPpd.Error
		ackMsg.ErrCode = common.ErrTransactionFailedByTimeout.ErrorCode()
		ackMsg.ErrMsg = serverPpd.Error.Error()
		return ackMsg, err
	}

	if serverPpd.HeaderType == core.NHP_COK {
		log.Error("agent(%s#%d)[ExitKnockRequest] terminated by server's cookie message", knkMsg.UserId, knkMd.TransactionId)
		err = common.ErrKnockTerminatedByCookie
		ackMsg.ErrCode = common.ErrKnockTerminatedByCookie.ErrorCode()
		ackMsg.ErrMsg = err.Error()
		return ackMsg, err
	}

	if serverPpd.HeaderType != core.NHP_ACK {
		log.Error("agent(%s#%d)[ExitKnockRequest] response has wrong type: %s", knkMsg.UserId, knkMd.TransactionId, core.HeaderTypeToString(serverPpd.HeaderType))
		err = common.ErrTransactionRepliedWithWrongType
		ackMsg.ErrCode = common.ErrTransactionRepliedWithWrongType.ErrorCode()
		ackMsg.ErrMsg = err.Error()
		return ackMsg, err
	}

	err = json.Unmarshal(serverPpd.BodyMessage, ackMsg)
	if err != nil {
		log.Error("agent(%s#%d)[ExitKnockRequest] failed to parse %s message: %v", knkMsg.UserId, knkMd.TransactionId, core.HeaderTypeToString(serverPpd.HeaderType), err)
		ackMsg.ErrCode = common.ErrJsonParseFailed.ErrorCode()
		ackMsg.ErrMsg = err.Error()
		return ackMsg, err
	}

	if ackMsg.ErrCode != common.ErrSuccess.ErrorCode() {
		log.Error("agent(%s#%d)[ExitKnockRequest] response error: %s", knkMsg.UserId, knkMd.TransactionId, ackMsg.ErrMsg)
		err = common.ErrorCodeToError(ackMsg.ErrCode)
		return ackMsg, err
	}

	log.Info("agent(%s#%d)[ExitKnockRequest] succeed", knkMsg.UserId, knkMd.TransactionId)
	return ackMsg, nil
}

// agent -> ac, pre-access
func (a *UdpAgent) preAccessRequest(ackMsg *common.ServerKnockAckMsg) (err error) {
	a.knockUserMutex.RLock()
	if len(a.knockUser.UserId) == 0 {
		a.knockUserMutex.RUnlock()
		return common.ErrKnockUserNotSpecified
	}
	a.knockUserMutex.RUnlock()

	var acWg sync.WaitGroup
	for _, action := range ackMsg.PreAccessActions {
		acWg.Add(1)
		go func(info *common.PreAccessInfo) {
			defer acWg.Done()
			if info != nil {
				if err := a.processPreAccessAction(info); err != nil {
					log.Error("agent[preAccessRequest] processPreAccessAction failed: %v", err)
				}
			}
		}(action)
	}
	acWg.Wait()

	return nil
}

func (a *UdpAgent) processPreAccessAction(info *common.PreAccessInfo) error {
	acIp := net.ParseIP(info.AccessIp)
	if acIp == nil {
		return common.ErrInvalidIpAddress
	}

	acPort, _ := strconv.Atoi(info.AccessPort)
	if acPort <= 0 {
		return common.ErrInvalidIpAddress
	}

	udpACAddr := &net.UDPAddr{
		IP:   acIp,
		Port: acPort,
	}
	tcpACAddr := &net.TCPAddr{
		IP:   acIp,
		Port: acPort,
	}
	acPeer := &core.UdpPeer{
		PubKeyBase64: info.ACPubKey,
		Ip:           info.AccessIp,
		Port:         acPort,
	}
	acPk := acPeer.PublicKey()
	a.device.AddPeer(acPeer)

	a.knockUserMutex.RLock()
	accMsg := &common.AgentAccessMsg{
		UserId:         a.knockUser.UserId,
		DeviceId:       a.deviceId,
		OrganizationId: a.knockUser.OrganizationId,
		ACToken:        info.ACToken,
		UserData:       a.knockUser.UserData,
	}
	a.knockUserMutex.RUnlock()
	accBytes, marshalErr := json.Marshal(accMsg)
	if marshalErr != nil {
		log.Error("agent(%s)[PreAccessRequest] failed to marshal ACC message: %v", accMsg.UserId, marshalErr)
		return marshalErr
	}

	accMd := a.newMsgData(udpACAddr, core.NHP_ACC, accBytes, acPk)
	accMd.EncryptedPktCh = make(chan *core.MsgAssemblerData, 1) // buffered size-1: see awaitOrStop

	if !a.IsRunning() {
		log.Error("agent(%s)[PreAccessRequest] MsgData channel closed or being closed, skip sending", accMsg.UserId)
		return common.ErrPacketToMessageRoutineStopped
	}

	// start message encryption
	a.device.SendMsgToPacket(accMd)

	// Wait for the encrypted packet, bailing on Stop() OR the encrypt deadline.
	// preAccessRequest is reachable synchronously from the a.wg-tracked Knock and
	// Stop() runs a.wg.Wait() before device.Stop(), so a bare <-EncryptedPktCh
	// would strand that Wait if the packet was discarded (SendMsgToPacket is
	// non-blocking) or the device is mid-teardown. The deadline additionally bounds
	// the discard-while-running case — this direct encrypt-await, unlike the
	// transaction paths, has no transaction-layer timeout of its own. See
	// docs/design/AGENT_LIFECYCLE_TEARDOWN.md invariant #3 for the buffered-size-1 /
	// close-on-receive / leave-open-on-bail contract and the pool-reclaim tradeoff.
	stopCh := a.stopSignal() // snapshot under RLock (#3103); reused by the bail classify below
	encryptTimer := time.NewTimer(core.AgentLocalTransactionResponseTimeoutMs * time.Millisecond)
	defer encryptTimer.Stop()
	accMad, ok := awaitOrDeadline(accMd.EncryptedPktCh, stopCh, encryptTimer.C)
	if !ok {
		// Classify stop vs deadline for the log + error (best-effort — a
		// simultaneous stop+deadline reports stop). The knock already succeeded;
		// the caller only logs this, so pre-access is genuinely best-effort.
		select {
		case <-stopCh:
			log.Debug("agent(%s)[PreAccessRequest] message routine stopped, skip pre-access", accMsg.UserId)
			return common.ErrPacketToMessageRoutineStopped
		default:
			log.Error("agent(%s)[PreAccessRequest] timed out waiting for access-packet encryption (msgToPacketQueue overloaded?), skip pre-access", accMsg.UserId)
			return common.ErrTransactionFailedByTimeout
		}
	}

	if accMad.Error != nil {
		log.Error("agent(%s)[PreAccessRequest] failed to encrypt access message: %v", accMsg.UserId, accMad.Error)
		return accMad.Error
	}

	// copy the packet for GC recycling and release the original packet buffer
	packetBytes := slices.Clone(accMad.BasePacket.Content)
	accMad.Destroy()

	// open new routine(s) to send access packet to ac's temporary port
	go func(packet []byte, tcpAddr *net.TCPAddr) {
		// dial tcp connection and send accMad packet
		conn, err := net.DialTCP("tcp", nil, tcpAddr)
		if err != nil {
			log.Error("agent(%s)[PreAccessRequest] failed to connect to temporary tcp access port: %v", accMsg.UserId, err)
			return
		}
		defer func() { _ = conn.Close() }()

		_, err = conn.Write(packet)
		if err != nil {
			log.Error("agent(%s)[PreAccessRequest] failed to send tcp access packet: %v", accMsg.UserId, err)
		} else {
			log.Info("agent(%s)[PreAccessRequest] send tcp access message succeed", accMsg.UserId)
		}

	}(packetBytes, tcpACAddr)

	go func(packet []byte, udpAddr *net.UDPAddr) {
		// dial udp connection and send accMad packet
		conn, err := net.DialUDP("udp", nil, udpAddr)
		if err != nil {
			log.Error("agent(%s)[PreAccessRequest] failed to connect to temporary udp access port: %v", accMsg.UserId, err)
			return
		}
		defer func() { _ = conn.Close() }()

		_, err = conn.Write(packet)
		if err != nil {
			log.Error("agent(%s)[PreAccessRequest] failed to send udp access packet: %v", accMsg.UserId, err)
		} else {
			log.Info("agent(%s)[PreAccessRequest] send udp access message succeed", accMsg.UserId)
		}

	}(packetBytes, udpACAddr)

	return nil
}

func (a *UdpAgent) KnockDHP() (ackMsg *common.ServerDHPKnockAckMsg, err error) {
	serverPeer := a.GetFirstServerPeer()
	addr, err := resolveServerAddr(serverPeer, a.knockUser.UserId, "KnockDHP")
	if err != nil {
		return nil, err
	}
	addrStr := addr.String()

	evidence, err := wasmEngine.GetEvidence()
	if err != nil {
		log.Error("agent(%s)[KnockDHP] cannot get evidence: %s", a.knockUser.UserId, err)
		return nil, common.ErrEvidenceGetFailed
	}

	a.knockUserMutex.RLock()
	knkMsg := &common.DHPKnockMsg{
		UserId:         a.knockUser.UserId,
		DeviceId:       a.deviceId,
		OrganizationId: a.knockUser.OrganizationId,
		UserData:       a.knockUser.UserData,
		Evidence:       evidence,
	}
	a.knockUserMutex.RUnlock()

	knkBytes, marshalErr := json.Marshal(knkMsg)
	if marshalErr != nil {
		log.Error("agent(%s)[KnockDHP] failed to marshal DHP_KNK message: %v", knkMsg.UserId, marshalErr)
		return nil, marshalErr
	}
	knkMd := a.newMsgData(addr, core.DHP_KNK, knkBytes, serverPeer.PublicKey())
	knkMd.ResponseMsgCh = make(chan *core.PacketParserData, 1) // buffered: see awaitTransactionResponse

	ackMsg = &common.ServerDHPKnockAckMsg{}
	if !a.IsRunning() {
		// Not-running only happens during/after Stop(): expected teardown, not an error.
		log.Debug("agent(%s#%d)[KnockDHP] MsgData channel closed or being closed, skip sending", knkMsg.UserId, knkMd.TransactionId)
		err = common.ErrPacketToMessageRoutineStopped
		ackMsg.ErrCode = common.ErrPacketToMessageRoutineStopped.ErrorCode()
		ackMsg.ErrMsg = err.Error()
		return ackMsg, err
	}

	// Guarded send (see sendOrStop). KnockDHP is wg-tracked (via
	// dhpKnockResourceRoutine), so bailing here keeps a full-buffer block from
	// deadlocking Stop()'s wg.Wait().
	if !a.sendOrStop(knkMd) {
		log.Error("agent(%s#%d)[KnockDHP] message routine stopped, skip sending", knkMsg.UserId, knkMd.TransactionId)
		err = common.ErrPacketToMessageRoutineStopped
		ackMsg.ErrCode = common.ErrPacketToMessageRoutineStopped.ErrorCode()
		ackMsg.ErrMsg = err.Error()
		return ackMsg, err
	}

	// Block for the transaction response, bailing out on Stop(). KnockDHP is
	// wg-tracked (via dhpKnockResourceRoutine), so a hang here would deadlock
	// Stop()'s wg.Wait(); see awaitTransactionResponse.
	serverPpd, ok := a.awaitTransactionResponse(knkMd.ResponseMsgCh)
	if !ok {
		log.Error("agent(%s#%d)[KnockDHP] message routine stopped, skip waiting for response", knkMsg.UserId, knkMd.TransactionId)
		err = common.ErrPacketToMessageRoutineStopped
		ackMsg.ErrCode = common.ErrPacketToMessageRoutineStopped.ErrorCode()
		ackMsg.ErrMsg = err.Error()
		return ackMsg, err
	}

	if serverPpd.Error != nil {
		log.Error("agent(%s#%d)[KnockDHP] failed to receive response from server %s: %v", knkMsg.UserId, knkMd.TransactionId, addrStr, serverPpd.Error)
		a.trustedByNHPServer.Store(false) // in this case, need to check local server configuration and remote agent public key configuration
		err = serverPpd.Error
		ackMsg.ErrCode = common.ErrPacketEncryptionFailed.ErrorCode()
		ackMsg.ErrMsg = serverPpd.Error.Error()
		return ackMsg, err
	} else { // In case that peer validation is enabled, agent public key has been configured correctly in server
		a.trustedByNHPServer.Store(true)
	}

	if serverPpd.HeaderType != core.NHP_ACK {
		log.Error("agent(%s#%d)[KnockDHP] response has wrong type: %s", knkMsg.UserId, knkMd.TransactionId, core.HeaderTypeToString(serverPpd.HeaderType))
		err = common.ErrTransactionRepliedWithWrongType
		ackMsg.ErrCode = common.ErrTransactionRepliedWithWrongType.ErrorCode()
		ackMsg.ErrMsg = err.Error()
		return ackMsg, err
	}

	err = json.Unmarshal(serverPpd.BodyMessage, ackMsg)
	if err != nil {
		log.Error("agent(%s#%d)[KnockDHP] failed to parse %s message: %v", knkMsg.UserId, knkMd.TransactionId, core.HeaderTypeToString(serverPpd.HeaderType), err)
		ackMsg.ErrCode = common.ErrJsonParseFailed.ErrorCode()
		ackMsg.ErrMsg = err.Error()
		return ackMsg, err
	}

	if ackMsg.ErrCode != common.ErrSuccess.ErrorCode() {
		log.Error("agent(%s#%d)[KnockDHP] response error: %s", knkMsg.UserId, knkMd.TransactionId, ackMsg.ErrMsg)
		err = common.ErrorCodeToError(ackMsg.ErrCode)
		return ackMsg, err
	}

	log.Info("agent(%s#%d)[KnockDHP] succeed", knkMsg.UserId, knkMd.TransactionId)
	return ackMsg, nil
}
