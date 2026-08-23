package server

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/layervai/nhp/internalauth"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
	"github.com/OpenNHP/opennhp/nhp/log"
)

const (
	agentSessionCloseEventTTL        = 30 * time.Second
	agentSessionCloseFutureSkew      = 5 * time.Second
	agentSessionCloseRetryBackoff    = 100 * time.Millisecond
	agentSessionCloseRetryBackoffMax = time.Second
	failedSessionCompensationTimeout = 3 * time.Second
	maxAgentSessionCloseFanoutPeers  = 1_000
	maxAgentSessionCloseFleetBody    = 1_024
	maxAgentSessionCloseWorkers      = 64
	maxAgentSessionClosePriorityWork = maxLiveNHPSessions
	maxAgentSessionCloseRegularWork  = maxLiveNHPSessions
	agentSessionCloseFleetPath       = "/nhp/internal/agent-sessions/close"
	exactSessionCloseFleetPath       = "/nhp/internal/agent-sessions/close-exact"
)

const (
	MetricAgentSessionCloseRequest         = "AgentSessionCloseRequest"
	MetricAgentSessionCloseInvalid         = "AgentSessionCloseInvalid"
	MetricAgentSessionCloseReplay          = "AgentSessionCloseReplay"
	MetricAgentSessionCloseReplaySaturated = "AgentSessionCloseReplaySaturated"
	MetricAgentSessionCloseCoalesced       = "AgentSessionCloseCoalesced"
	MetricAgentSessionCloseCutoffSaturated = "AgentSessionCloseCutoffSaturated"
	MetricAgentSessionCloseLocalSuccess    = "AgentSessionCloseLocalSuccess"
	MetricAgentSessionCloseLocalRetry      = "AgentSessionCloseLocalRetry"
	MetricAgentSessionCloseLocalFailure    = "AgentSessionCloseLocalFailure"
	MetricAgentSessionCloseFanoutQueued    = "AgentSessionCloseFanoutQueued"
	MetricAgentSessionCloseFanoutFailure   = "AgentSessionCloseFanoutFailure"
	MetricAgentSessionCloseWorkerSaturated = "AgentSessionCloseWorkerSaturated"
)

func (s *UdpServer) incrAgentSessionCloseMetric(name string) {
	if s != nil && s.metrics != nil {
		s.metrics.IncrCounter(name)
	}
}

func newAgentSessionCloseEventID() (string, error) {
	var raw [16]byte
	if _, err := cryptorand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

func validAgentSessionCloseEventID(eventID string) bool {
	if len(eventID) != 32 {
		return false
	}
	decoded, err := hex.DecodeString(eventID)
	return err == nil && len(decoded) == 16 && hex.EncodeToString(decoded) == eventID
}

type agentSessionCloseWork struct {
	agentPubKey    []byte
	issuedThrough  time.Time
	deadline       time.Time
	broadcastUntil time.Time
}

// agentSessionCloseFleetEvent is an internal implementation detail of the
// external bodyless NHP_EXT contract. It is never serialized as an NHP message.
// The shared-cell HMAC authenticates fleet membership; OriginServer/OriginIP
// are additionally bound to the request's private source IP and current
// healthy Cloud Map snapshot, but are not cryptographic instance attribution.
type agentSessionCloseFleetEvent struct {
	EventID            string `json:"event_id"`
	AgentPublicKey     string `json:"agent_public_key"`
	IssuedThroughNanos int64  `json:"issued_through_nanos"`
	ExpiresAt          int64  `json:"expires_at"`
	OriginServer       string `json:"origin_server"`
	OriginIP           string `json:"origin_ip"`
}

// exactSessionCloseFleetEvent compensates one logical NHP session across the
// fleet after an ACK/token failure. Agent key + numeric ID + issuance identify
// the shared logical session; every receiving process uses its own authenticated
// sessOwnerId when closing its local AC index.
type exactSessionCloseFleetEvent struct {
	EventID              string `json:"event_id"`
	AgentPublicKey       string `json:"agent_public_key"`
	SessionID            uint64 `json:"session_id"`
	SessionIssuedAtNanos int64  `json:"session_issued_at_nanos"`
	ExpiresAt            int64  `json:"expires_at"`
	OriginServer         string `json:"origin_server"`
	OriginIP             string `json:"origin_ip"`
}

// beginAgentSessionCloseWork records the admission cutoff for every accepted
// event, then elects at most one close-work leader per authenticated agent.
// Followers advance the leader's cutoff/deadline and return immediately.
func (s *UdpServer) beginAgentSessionCloseWork(agentPubKey []byte, issuedThrough, deadline time.Time, broadcast bool) (*agentSessionCloseWork, bool) {
	if s.sessionRegistry().recordAgentSessionCloseCutoff(agentPubKey, issuedThrough) {
		s.incrAgentSessionCloseMetric(MetricAgentSessionCloseCutoffSaturated)
		log.Warning("NHP_EXT agent cutoff registry saturated; owned session admission is temporarily fail-closed")
	}
	key := string(agentPubKey)
	s.agentSessionCloseWorkMu.Lock()
	defer s.agentSessionCloseWorkMu.Unlock()
	if existing := s.agentSessionCloseWork[key]; existing != nil {
		if issuedThrough.After(existing.issuedThrough) {
			existing.issuedThrough = issuedThrough
		}
		if deadline.After(existing.deadline) {
			existing.deadline = deadline
		}
		if broadcast && issuedThrough.After(existing.broadcastUntil) {
			existing.broadcastUntil = issuedThrough
		}
		s.incrAgentSessionCloseMetric(MetricAgentSessionCloseCoalesced)
		return existing, false
	}
	if s.agentSessionCloseWork == nil {
		s.agentSessionCloseWork = make(map[string]*agentSessionCloseWork)
	}
	work := &agentSessionCloseWork{
		agentPubKey:   bytes.Clone(agentPubKey),
		issuedThrough: issuedThrough,
		deadline:      deadline,
	}
	if broadcast {
		work.broadcastUntil = issuedThrough
	}
	s.agentSessionCloseWork[key] = work
	return work, true
}

func (s *UdpServer) finishAgentSessionCloseWork(work *agentSessionCloseWork) {
	if work == nil {
		return
	}
	key := string(work.agentPubKey)
	s.agentSessionCloseWorkMu.Lock()
	if s.agentSessionCloseWork[key] == work {
		delete(s.agentSessionCloseWork, key)
	}
	s.agentSessionCloseWorkMu.Unlock()
}

// startAgentSessionCloseWorker admits background close work under a dedicated
// shutdown barrier. Both direct NHP_EXT and internal HTTP replication return as
// soon as this tracked worker is accepted; Stop prevents new Add calls before
// waiting, cancels the lifecycle context, and joins every accepted worker.
func (s *UdpServer) startAgentSessionCloseWorker(work *agentSessionCloseWork) bool {
	if s == nil || work == nil {
		return false
	}
	return s.startAgentSessionCloseTaskWithPriority(func() { s.runAgentSessionCloseWork(work) }, true)
}

func (s *UdpServer) startAgentSessionCloseTask(run func()) bool {
	return s.startAgentSessionCloseTaskWithPriority(run, false)
}

// startAgentSessionCloseTaskWithPriority admits close work into a bounded,
// lifecycle-tracked scheduler. Agent-global EXT work has a dedicated reserve;
// exact internal work is rejected with 503 when its own bound is exhausted so
// the authenticated origin can retry instead of receiving a false 204.
func (s *UdpServer) startAgentSessionCloseTaskWithPriority(run func(), priority bool) bool {
	if s == nil || run == nil {
		return false
	}
	s.agentSessionCloseWorkerMu.Lock()
	defer s.agentSessionCloseWorkerMu.Unlock()
	if s.agentSessionCloseWorkersStopping || !s.IsRunning() {
		return false
	}
	if priority {
		if s.agentSessionClosePriorityOutstanding >= maxAgentSessionClosePriorityWork {
			s.incrAgentSessionCloseMetric(MetricAgentSessionCloseWorkerSaturated)
			return false
		}
		s.agentSessionClosePriorityOutstanding++
		s.agentSessionClosePriorityQueue = append(s.agentSessionClosePriorityQueue, run)
	} else {
		if s.agentSessionCloseRegularOutstanding >= maxAgentSessionCloseRegularWork {
			s.incrAgentSessionCloseMetric(MetricAgentSessionCloseWorkerSaturated)
			return false
		}
		s.agentSessionCloseRegularOutstanding++
		s.agentSessionCloseRegularQueue = append(s.agentSessionCloseRegularQueue, run)
	}
	s.agentSessionCloseWorkerWG.Add(1)
	s.launchAgentSessionCloseTasksLocked()
	return true
}

func popAgentSessionCloseTask(queue *[]func()) func() {
	if len(*queue) == 0 {
		return nil
	}
	run := (*queue)[0]
	(*queue)[0] = nil
	*queue = (*queue)[1:]
	return run
}

// launchAgentSessionCloseTasksLocked starts at most the fixed worker bound.
// Queued work was already counted in the shutdown WaitGroup, so Stop can set
// the admission fence and wait while completion drains the retained queue.
func (s *UdpServer) launchAgentSessionCloseTasksLocked() {
	for s.agentSessionCloseWorkerActive < maxAgentSessionCloseWorkers {
		priority := len(s.agentSessionClosePriorityQueue) != 0
		var run func()
		if priority {
			run = popAgentSessionCloseTask(&s.agentSessionClosePriorityQueue)
		} else {
			run = popAgentSessionCloseTask(&s.agentSessionCloseRegularQueue)
		}
		if run == nil {
			return
		}
		s.agentSessionCloseWorkerActive++
		go func(run func(), priority bool) {
			defer s.agentSessionCloseWorkerWG.Done()
			run()
			s.agentSessionCloseWorkerMu.Lock()
			s.agentSessionCloseWorkerActive--
			if priority {
				s.agentSessionClosePriorityOutstanding--
			} else {
				s.agentSessionCloseRegularOutstanding--
			}
			s.launchAgentSessionCloseTasksLocked()
			s.agentSessionCloseWorkerMu.Unlock()
		}(run, priority)
	}
}

// runAgentSessionCloseWork owns local retry and optional origin fan-out for one
// agent. If followers advance the target while an iteration is running, the
// same leader performs another iteration before releasing the map entry.
func (s *UdpServer) runAgentSessionCloseWork(work *agentSessionCloseWork) {
	if work == nil {
		return
	}
	var locallyClosedThrough, broadcastThrough time.Time
	for {
		s.agentSessionCloseWorkMu.Lock()
		issuedThrough := work.issuedThrough
		deadline := work.deadline
		broadcastUntil := work.broadcastUntil
		s.agentSessionCloseWorkMu.Unlock()
		if !deadline.After(time.Now()) {
			s.agentSessionCloseWorkMu.Lock()
			if work.deadline.After(deadline) && work.deadline.After(time.Now()) {
				s.agentSessionCloseWorkMu.Unlock()
				continue
			}
			if s.agentSessionCloseWork[string(work.agentPubKey)] == work {
				delete(s.agentSessionCloseWork, string(work.agentPubKey))
			}
			s.agentSessionCloseWorkMu.Unlock()
			return
		}

		ctx, cancel := context.WithDeadline(s.LifecycleCtx(), deadline)
		var iteration sync.WaitGroup
		if issuedThrough.After(locallyClosedThrough) {
			iteration.Add(1)
			go func() {
				defer iteration.Done()
				s.closeAgentSessionsLocal(ctx, work.agentPubKey, issuedThrough)
			}()
		}
		if broadcastUntil.After(broadcastThrough) {
			iteration.Add(1)
			go func() {
				defer iteration.Done()
				s.broadcastAgentSessionCloseFromOrigin(ctx, work.agentPubKey, broadcastUntil, deadline)
			}()
		}
		iteration.Wait()
		iterationErr := ctx.Err()
		cancel()
		if iterationErr != nil {
			if lifecycleCtx := s.LifecycleCtx(); lifecycleCtx != nil && lifecycleCtx.Err() != nil {
				s.finishAgentSessionCloseWork(work)
				return
			}
			// A follower can advance this work while the previous iteration is
			// expiring. Continue under the follower's deadline instead of dropping
			// its newer local and fleet cutoff with the old context.
			s.agentSessionCloseWorkMu.Lock()
			advanced := work.deadline.After(deadline) && work.deadline.After(time.Now()) &&
				(work.issuedThrough.After(locallyClosedThrough) || work.broadcastUntil.After(broadcastThrough))
			if !advanced && s.agentSessionCloseWork[string(work.agentPubKey)] == work {
				delete(s.agentSessionCloseWork, string(work.agentPubKey))
			}
			s.agentSessionCloseWorkMu.Unlock()
			if advanced {
				continue
			}
			return
		}
		if issuedThrough.After(locallyClosedThrough) {
			locallyClosedThrough = issuedThrough
		}
		if broadcastUntil.After(broadcastThrough) {
			broadcastThrough = broadcastUntil
		}

		if s.agentSessionCloseBeforeFinalizeFn != nil {
			s.agentSessionCloseBeforeFinalizeFn()
		}
		s.agentSessionCloseWorkMu.Lock()
		caughtUp := !work.issuedThrough.After(locallyClosedThrough) && !work.broadcastUntil.After(broadcastThrough)
		expired := !work.deadline.After(time.Now())
		if (caughtUp || expired) && s.agentSessionCloseWork[string(work.agentPubKey)] == work {
			delete(s.agentSessionCloseWork, string(work.agentPubKey))
		}
		s.agentSessionCloseWorkMu.Unlock()
		if caughtUp || expired {
			return
		}
	}
}

func (s *UdpServer) broadcastAgentSessionCloseFromOrigin(ctx context.Context, agentPubKey []byte, issuedThrough, deadline time.Time) {
	// Fleet delivery is deliberately not a prerequisite for local teardown. A
	// missing server identity or event-randomness failure is observable, while
	// the authenticated agent's local sessions still close independently.
	originServer := s.InstanceID()
	if s.device == nil || originServer == "" || net.ParseIP(s.localIp) == nil {
		s.incrAgentSessionCloseMetric(MetricAgentSessionCloseFanoutFailure)
		log.Warning("NHP_EXT fleet fan-out identity unavailable; local close remains independent")
		return
	}
	eventID, err := newAgentSessionCloseEventID()
	if err != nil {
		s.incrAgentSessionCloseMetric(MetricAgentSessionCloseFanoutFailure)
		log.Warning("NHP_EXT fleet fan-out event id generation failed: %v", err)
		return
	}
	event := &agentSessionCloseFleetEvent{
		EventID:            eventID,
		AgentPublicKey:     base64.StdEncoding.EncodeToString(agentPubKey),
		IssuedThroughNanos: issuedThrough.UnixNano(),
		ExpiresAt:          deadline.Unix(),
		OriginServer:       originServer,
		OriginIP:           s.localIp,
	}
	if s.broadcastAgentSessionCloseFn != nil {
		s.broadcastAgentSessionCloseFn(ctx, event)
		return
	}
	s.broadcastAgentSessionClose(ctx, event)
}

// HandleAgentSessionExit is deliberately unavailable on the current NHP 1.1
// envelope. Its clear HeaderType is protected only by a publicly recomputable
// digest, so a bodyless agent-global close would not be authenticated authority.
// EXT is dispatched through HandleKnockRequest instead, where the encrypted
// body carries the strict HeaderType mirror and preserves the existing ACK path.
func (s *UdpServer) HandleAgentSessionExit(ppd *core.PacketParserData) error {
	if s != nil {
		s.incrAgentSessionCloseMetric(MetricAgentSessionCloseInvalid)
	}
	return errors.New("bodyless agent-global NHP_EXT requires a negotiated authenticated-header profile")
}

func (s *UdpServer) processACSessionCloseResolved(ctx context.Context, agentPubKey []byte, snapshot nhpSessionCloseSnapshot, conn *ACConn) error {
	if s.processACSessionCloseFn != nil {
		return s.processACSessionCloseFn(ctx, snapshot.SessionID, conn)
	}
	return s.processACSessionClose(ctx, agentPubKey, snapshot, conn)
}

func (s *UdpServer) processACSessionClose(ctx context.Context, agentPubKey []byte, snapshot nhpSessionCloseSnapshot, conn *ACConn) error {
	if s == nil || len(agentPubKey) != core.PublicKeySize || snapshot.SessionID == 0 || snapshot.IssuedAt.IsZero() ||
		conn == nil || conn.ConnData == nil || conn.ACPeer == nil {
		return common.ErrInvalidInput
	}
	sessionOwnerID, err := s.sessionOwnerID()
	if err != nil {
		return err
	}
	aopBytes, err := json.Marshal(&common.ServerACOpsMsg{
		SessionId:             snapshot.SessionID,
		SessionOwnerId:        sessionOwnerID,
		AgentPublicKey:        base64.StdEncoding.EncodeToString(agentPubKey),
		SessionIssuedAtMillis: snapshot.IssuedAt.UnixMilli(),
		OpenTime:              0,
	})
	if err != nil {
		return err
	}
	aopMd := &core.MsgData{
		ConnData:      conn.ConnData,
		HeaderType:    core.NHP_AOP,
		CipherScheme:  conn.ACCipherScheme,
		TransactionId: s.device.NextCounterIndex(),
		Compress:      true,
		PeerPk:        conn.ACPeer.PublicKey(),
		Message:       aopBytes,
		// Buffer one result so a canceled close attempt never needs a drain
		// goroutine that can outlive the bounded EXT worker indefinitely.
		ResponseMsgCh: make(chan *core.PacketParserData, 1),
	}
	if !s.IsRunning() {
		return common.ErrPacketToMessageRoutineStopped
	}
	select {
	case s.sendMsgCh <- aopMd:
	case <-ctx.Done():
		return ctx.Err()
	case <-s.signals.stop:
		return common.ErrPacketToMessageRoutineStopped
	}
	var acPpd *core.PacketParserData
	select {
	case acPpd = <-aopMd.ResponseMsgCh:
	case <-ctx.Done():
		return ctx.Err()
	case <-s.signals.stop:
		return common.ErrPacketToMessageRoutineStopped
	}
	if acPpd == nil || acPpd.Error != nil {
		if acPpd != nil {
			return acPpd.Error
		}
		return common.ErrServerACOpsFailed
	}
	if acPpd.HeaderType != core.NHP_ART {
		return common.ErrTransactionRepliedWithWrongType
	}
	var art common.ACOpsResultMsg
	if err := common.DecodeACOpsResultMsg(acPpd.BodyMessage, &art); err != nil {
		return err
	}
	if art.SessionId != snapshot.SessionID || art.SessionOwnerId != sessionOwnerID || !common.IsSuccessErrCode(art.ErrCode) {
		return common.ErrACOperationFailed
	}
	return nil
}

func (s *UdpServer) closeAgentSessionsLocal(ctx context.Context, agentPubKey []byte, issuedThrough time.Time) {
	if ctx == nil {
		ctx = context.Background()
	}
	if _, bounded := ctx.Deadline(); !bounded {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, agentSessionCloseEventTTL)
		defer cancel()
	}
	backoff := agentSessionCloseRetryBackoff
	for {
		select {
		case <-ctx.Done():
			s.incrAgentSessionCloseMetric(MetricAgentSessionCloseLocalFailure)
			log.Warning("NHP_EXT local close retained retryable session state at deadline")
			return
		case <-s.signals.stop:
			s.incrAgentSessionCloseMetric(MetricAgentSessionCloseLocalFailure)
			return
		default:
		}
		snapshots, cutoffSaturated := s.sessionRegistry().snapshotAgentSessionsWithStatus(agentPubKey, issuedThrough)
		if cutoffSaturated {
			s.incrAgentSessionCloseMetric(MetricAgentSessionCloseCutoffSaturated)
			log.Warning("NHP_EXT agent cutoff registry saturated; owned session admission is temporarily fail-closed")
		}
		if len(snapshots) == 0 {
			return
		}
		remaining := 0
		for _, snapshot := range snapshots {
			if s.closeNHPSessionSnapshotOnce(ctx, agentPubKey, snapshot) {
				s.incrAgentSessionCloseMetric(MetricAgentSessionCloseLocalSuccess)
				continue
			}
			remaining++
		}
		if remaining == 0 {
			return
		}
		s.incrAgentSessionCloseMetric(MetricAgentSessionCloseLocalRetry)
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			s.incrAgentSessionCloseMetric(MetricAgentSessionCloseLocalFailure)
			log.Warning("NHP_EXT local close retained retryable session state at deadline")
			return
		case <-s.signals.stop:
			timer.Stop()
			s.incrAgentSessionCloseMetric(MetricAgentSessionCloseLocalFailure)
			return
		case <-timer.C:
		}
		if backoff < agentSessionCloseRetryBackoffMax {
			backoff *= 2
			if backoff > agentSessionCloseRetryBackoffMax {
				backoff = agentSessionCloseRetryBackoffMax
			}
		}
	}
}

// closeNHPSessionSnapshotOnce attempts one close against every live connection
// for every AC that admitted the exact session. It removes registry state only
// after all closes succeed, leaving failed work retryable until retention ends.
// agentPubKey is nil only for the isolated legacy internal-HTTP open path.
func (s *UdpServer) closeNHPSessionSnapshotOnce(ctx context.Context, agentPubKey []byte, snapshot nhpSessionCloseSnapshot) bool {
	if snapshot.InFlight != 0 {
		return false
	}
	allClosed := true
	for _, acID := range snapshot.ACIDs {
		conns, _ := s.snapshotLiveACConns(acID)
		if len(conns) == 0 {
			allClosed = false
			continue
		}
		var closeWg sync.WaitGroup
		failures := make(chan struct{}, len(conns))
		for _, conn := range conns {
			closeWg.Add(1)
			go func(conn *ACConn) {
				defer closeWg.Done()
				closeCtx, cancel := context.WithTimeout(ctx, DefaultBroadcastTimeout)
				defer cancel()
				if err := s.processACSessionCloseResolved(closeCtx, agentPubKey, snapshot, conn); err != nil {
					failures <- struct{}{}
				}
			}(conn)
		}
		closeWg.Wait()
		if len(failures) != 0 {
			allClosed = false
		}
	}
	return allClosed && s.sessionRegistry().completeExactSessionClose(agentPubKey, snapshot)
}

// compensateFailedNHPSession synchronously closes one admitted session when a
// post-AC token/ACK failure means the client cannot safely use or later tear
// down it. The cleanup is exact-session scoped, bounded, and retains failed
// work for natural expiry rather than deleting evidence before an AC close.
func (s *UdpServer) compensateFailedNHPSession(agentPubKey []byte, sessionID uint64, issuedAt time.Time) bool {
	if s == nil || sessionID == 0 {
		return true
	}
	ctx, cancel := context.WithTimeout(s.LifecycleCtx(), failedSessionCompensationTimeout)
	defer cancel()
	closed := s.compensateFailedNHPSessionUntil(ctx, agentPubKey, sessionID, issuedAt)
	if closed {
		return true
	}
	retainUntil, ok := s.sessionRegistry().exactSessionRetainUntil(agentPubKey, sessionID, issuedAt)
	if !ok || !retainUntil.After(time.Now()) {
		return false
	}
	if !s.startAgentSessionCloseTask(func() {
		workerCtx, workerCancel := context.WithDeadline(s.LifecycleCtx(), retainUntil)
		defer workerCancel()
		s.compensateFailedNHPSessionUntil(workerCtx, agentPubKey, sessionID, issuedAt)
	}) {
		log.Error("post-admission compensation for exact NHP session %d could not enter bounded retry scheduler", sessionID)
	}
	return false
}

// compensateFailedNHPSessionUntil retries one exact close through the caller's
// authenticated event deadline. The short local-origin wrapper above remains a
// bounded best effort; an internal fleet receiver uses the full event lifetime
// and reports completion to the origin only after the exact session disappears.
func (s *UdpServer) compensateFailedNHPSessionUntil(ctx context.Context, agentPubKey []byte, sessionID uint64, issuedAt time.Time) bool {
	if s == nil || sessionID == 0 {
		return true
	}
	if ctx == nil {
		ctx = s.LifecycleCtx()
	}
	backoff := agentSessionCloseRetryBackoff
	for {
		snapshot, ok := s.sessionRegistry().snapshotExactSessionForCompensation(agentPubKey, sessionID, issuedAt)
		if !ok {
			return true
		}
		if s.closeNHPSessionSnapshotOnce(ctx, agentPubKey, snapshot) {
			return true
		}
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			log.Warning("post-admission compensation retained exact NHP session %d until bounded expiry", sessionID)
			return false
		case <-s.signals.stop:
			timer.Stop()
			return false
		case <-timer.C:
		}
		if backoff < agentSessionCloseRetryBackoffMax {
			backoff *= 2
			if backoff > agentSessionCloseRetryBackoffMax {
				backoff = agentSessionCloseRetryBackoffMax
			}
		}
	}
}

// compensateFailedNHPSessionFleet performs the exact local cleanup first, then
// schedules authenticated best-effort delivery to every currently healthy
// server because forwarding/fan-out may have admitted the same logical session
// elsewhere. The cross-fleet identity is agent key + session ID + issuance;
// each receiver uses its own process sessOwnerId to close its local AC rows.
func (s *UdpServer) compensateFailedNHPSessionFleet(agentPubKey []byte, sessionID uint64, issuedAt time.Time, openTime uint32) bool {
	if len(agentPubKey) != core.PublicKeySize || sessionID == 0 {
		return false
	}
	if issuedAt.IsZero() {
		var found bool
		issuedAt, found = s.sessionRegistry().exactSessionIssuedAt(agentPubKey, sessionID)
		if !found {
			return false
		}
	}
	retainUntil, _ := s.sessionRegistry().exactSessionRetainUntil(agentPubKey, sessionID, issuedAt)
	if openTime != 0 {
		derived := issuedAt.Add(time.Duration(openTime)*time.Second + time.Duration(ACOpenCompensationTime)*time.Second)
		if derived.After(retainUntil) {
			retainUntil = derived
		}
	}
	if !retainUntil.After(time.Now()) {
		return false
	}
	localClosed := s.compensateFailedNHPSession(agentPubKey, sessionID, issuedAt)
	eventID, err := newAgentSessionCloseEventID()
	if err != nil {
		return false
	}
	originServer := s.InstanceID()
	if originServer == "" || !isPrivateIP(s.localIp) {
		log.Warning("exact NHP session compensation fleet fan-out unavailable: missing registered instance identity")
		return localClosed
	}
	// Round upward because the wire uses Unix seconds while registry retention
	// is nanosecond precise. A close worker must never stop before the AC/session
	// retention boundary it is compensating.
	eventExpiresAt := retainUntil.Truncate(time.Second)
	if eventExpiresAt.Before(retainUntil) {
		eventExpiresAt = eventExpiresAt.Add(time.Second)
	}
	event := &exactSessionCloseFleetEvent{
		EventID:              eventID,
		AgentPublicKey:       base64.StdEncoding.EncodeToString(agentPubKey),
		SessionID:            sessionID,
		SessionIssuedAtNanos: issuedAt.UnixNano(),
		ExpiresAt:            eventExpiresAt.Unix(),
		OriginServer:         originServer,
		OriginIP:             s.localIp,
	}
	if !s.startAgentSessionCloseTask(func() {
		ctx, cancel := context.WithDeadline(s.LifecycleCtx(), eventExpiresAt)
		defer cancel()
		s.broadcastExactSessionClose(ctx, event)
	}) {
		log.Warning("exact NHP session compensation fleet fan-out could not enter shutdown-tracked worker set")
		return false
	}
	return localClosed
}

func (s *UdpServer) broadcastAgentSessionClose(ctx context.Context, event *agentSessionCloseFleetEvent) {
	if s == nil || event == nil || s.cloudMap == nil || s.fleetCloseSigner == nil || s.fleetCloseHTTPClient == nil {
		s.incrAgentSessionCloseMetric(MetricAgentSessionCloseFanoutFailure)
		log.Warning("NHP_EXT fleet HTTP fan-out unavailable; local close remains independent")
		return
	}
	body, err := json.Marshal(event)
	if err != nil {
		s.incrAgentSessionCloseMetric(MetricAgentSessionCloseFanoutFailure)
		return
	}
	s.broadcastFleetSessionClose(ctx, event.OriginServer, time.Unix(event.ExpiresAt, 0), agentSessionCloseFleetPath, body)
}

func (s *UdpServer) broadcastExactSessionClose(ctx context.Context, event *exactSessionCloseFleetEvent) {
	if s == nil || event == nil || s.cloudMap == nil || s.fleetCloseSigner == nil || s.fleetCloseHTTPClient == nil {
		s.incrAgentSessionCloseMetric(MetricAgentSessionCloseFanoutFailure)
		log.Warning("exact NHP session compensation fleet HTTP fan-out unavailable; local close remains independent")
		return
	}
	body, err := json.Marshal(event)
	if err != nil {
		s.incrAgentSessionCloseMetric(MetricAgentSessionCloseFanoutFailure)
		return
	}
	s.broadcastFleetSessionClose(ctx, event.OriginServer, time.Unix(event.ExpiresAt, 0), exactSessionCloseFleetPath, body)
}

func (s *UdpServer) broadcastFleetSessionClose(ctx context.Context, originServer string, deadline time.Time, path string, body []byte) {
	if !deadline.After(time.Now()) {
		s.incrAgentSessionCloseMetric(MetricAgentSessionCloseFanoutFailure)
		return
	}
	delivered := make(map[string]bool)
	requiredTargets := make(map[string]ServerInfo)
	hadAuthoritativeSnapshot := false
	backoff := agentSessionCloseRetryBackoff
	for {
		if ctx.Err() != nil || !deadline.After(time.Now()) {
			break
		}
		discoverCtx, cancel := context.WithTimeout(ctx, DefaultStorageTimeout)
		var targets []ServerInfo
		var discoverErr error
		// Every fleet-close attempt uses an authoritative snapshot. The ordinary
		// cache TTL is as long as the complete event lifetime, so accepting a
		// cached first pass could report success while omitting a newly healthy
		// session-owning server for the entire close window.
		targets, discoverErr = s.cloudMap.DiscoverServerInstancesFresh(discoverCtx)
		cancel()
		if discoverErr == nil {
			sort.Slice(targets, func(i, j int) bool { return targets[i].ID < targets[j].ID })
			if !s.fleetCloseOriginPresent(targets, originServer) {
				discoverErr = errors.New("authoritative fleet snapshot omitted or mismatched the origin instance")
			} else {
				hadAuthoritativeSnapshot = true
				for _, target := range targets {
					if target.ID == originServer {
						continue
					}
					if previous, exists := requiredTargets[target.ID]; exists && previous != target {
						// A changed direct address is a new delivery target. A prior 204
						// covered the old process/address, not this replacement row.
						delivered[target.ID] = false
					}
					requiredTargets[target.ID] = target
				}
			}
			if len(requiredTargets) > maxAgentSessionCloseFanoutPeers {
				discoverErr = fmt.Errorf("observed fleet target count %d exceeds bound %d", len(requiredTargets), maxAgentSessionCloseFanoutPeers)
			}
		}
		if discoverErr == nil {
			type sendResult struct {
				id  string
				err error
			}
			results := make(chan sendResult, len(requiredTargets))
			started := 0
			for _, target := range requiredTargets {
				if delivered[target.ID] || started >= maxAgentSessionCloseFanoutPeers {
					continue
				}
				started++
				go func(target ServerInfo) {
					results <- sendResult{id: target.ID, err: s.sendAgentSessionCloseHTTP(ctx, target, path, body)}
				}(target)
			}
			for i := 0; i < started; i++ {
				result := <-results
				if result.err != nil {
					log.Warning("NHP_EXT fleet HTTP fan-out to server %s will retry: %v", result.id, result.err)
					continue
				}
				if !delivered[result.id] {
					delivered[result.id] = true
					s.incrAgentSessionCloseMetric(MetricAgentSessionCloseFanoutQueued)
				}
			}
			allDelivered := true
			for id := range requiredTargets {
				if !delivered[id] {
					allDelivered = false
					break
				}
			}
			if allDelivered {
				return
			}
		} else {
			log.Warning("NHP_EXT fleet discovery will retry: %v", discoverErr)
		}
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
		case <-timer.C:
		}
		if ctx.Err() != nil {
			break
		}
		if backoff < agentSessionCloseRetryBackoffMax {
			backoff *= 2
			if backoff > agentSessionCloseRetryBackoffMax {
				backoff = agentSessionCloseRetryBackoffMax
			}
		}
	}
	failed := 0
	for id := range requiredTargets {
		if !delivered[id] {
			failed++
			s.incrAgentSessionCloseMetric(MetricAgentSessionCloseFanoutFailure)
			log.Warning("NHP_EXT fleet HTTP fan-out deadline expired for healthy server %s", id)
		}
	}
	if failed == 0 && (!hadAuthoritativeSnapshot || len(requiredTargets) == 0) {
		s.incrAgentSessionCloseMetric(MetricAgentSessionCloseFanoutFailure)
		log.Warning("NHP_EXT fleet HTTP fan-out ended without a healthy discovery snapshot")
	}
}

func (s *UdpServer) fleetCloseHTTPPortAllowed(port int) bool {
	if s != nil && s.fleetCloseHTTPPortAllowedFn != nil {
		return s.fleetCloseHTTPPortAllowedFn(port)
	}
	return fleetCloseHTTPPortIsVPCAdmitted(port)
}

func (s *UdpServer) fleetCloseOriginPresent(targets []ServerInfo, originServer string) bool {
	if s == nil || originServer == "" || s.localIp == "" || s.httpServer == nil || !s.httpServer.IsRunning() || s.httpServer.listenAddr == nil || s.httpServer.tlsEnabled {
		return false
	}
	wantPort := s.httpServer.listenAddr.Port
	if !s.fleetCloseHTTPPortAllowed(wantPort) {
		return false
	}
	for _, target := range targets {
		if target.ID != originServer {
			continue
		}
		parsed := net.ParseIP(target.InternalIP)
		return parsed != nil && parsed.String() == target.InternalIP && target.InternalIP == s.localIp && target.HTTPPort == wantPort
	}
	return false
}

func (s *UdpServer) sendAgentSessionCloseHTTP(ctx context.Context, target ServerInfo, path string, body []byte) error {
	parsedIP := net.ParseIP(target.InternalIP)
	if target.ID == "" || parsedIP == nil || parsedIP.String() != target.InternalIP || !isPrivateIP(target.InternalIP) || !s.fleetCloseHTTPPortAllowed(target.HTTPPort) {
		return errors.New("target is missing a canonical private IP or HTTP_PORT")
	}
	if path != agentSessionCloseFleetPath && path != exactSessionCloseFleetPath {
		return errors.New("unsupported fleet close path")
	}
	url := "http://" + net.JoinHostPort(target.InternalIP, strconv.Itoa(target.HTTPPort)) + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(internalauth.Header, s.fleetCloseSigner.Sign(http.MethodPost, path, body))
	resp, err := s.fleetCloseHTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	responseBody, readErr := io.ReadAll(io.LimitReader(resp.Body, 2))
	if readErr != nil {
		return readErr
	}
	if resp.StatusCode != http.StatusNoContent || len(responseBody) != 0 {
		return fmt.Errorf("unexpected fleet close response status/body: %d/%d", resp.StatusCode, len(responseBody))
	}
	return nil
}

func decodeExactJSONObject(raw []byte, allowed ...string) (map[string]json.RawMessage, error) {
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, key := range allowed {
		allowedSet[key] = struct{}{}
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	start, err := dec.Token()
	if err != nil || start != json.Delim('{') {
		return nil, errors.New("expected one JSON object")
	}
	object := make(map[string]json.RawMessage, len(allowed))
	for dec.More() {
		token, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := token.(string)
		if !ok {
			return nil, errors.New("expected JSON object key")
		}
		if _, ok := allowedSet[key]; !ok {
			return nil, fmt.Errorf("unknown field %q", key)
		}
		if _, duplicate := object[key]; duplicate {
			return nil, fmt.Errorf("duplicate field %q", key)
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, err
		}
		object[key] = value
	}
	end, err := dec.Token()
	if err != nil || end != json.Delim('}') {
		return nil, errors.New("unterminated JSON object")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing JSON value")
	}
	return object, nil
}

func strictJSONInt64(raw json.RawMessage) (int64, error) {
	var value int64
	if len(raw) == 0 || json.Unmarshal(raw, &value) != nil || !bytes.Equal(bytes.TrimSpace(raw), []byte(strconv.FormatInt(value, 10))) {
		return 0, errors.New("expected canonical int64")
	}
	return value, nil
}

func strictJSONUint64(raw json.RawMessage) (uint64, error) {
	var value uint64
	if len(raw) == 0 || json.Unmarshal(raw, &value) != nil || !bytes.Equal(bytes.TrimSpace(raw), []byte(strconv.FormatUint(value, 10))) {
		return 0, errors.New("expected canonical uint64")
	}
	return value, nil
}

func strictJSONString(raw json.RawMessage) (string, error) {
	var value string
	if len(raw) == 0 || json.Unmarshal(raw, &value) != nil {
		return "", errors.New("expected JSON string")
	}
	return value, nil
}

func decodeAgentSessionCloseFleetEvent(raw []byte, now time.Time) (*agentSessionCloseFleetEvent, []byte, time.Time, time.Time, error) {
	object, err := decodeExactJSONObject(raw, "event_id", "agent_public_key", "issued_through_nanos", "expires_at", "origin_server", "origin_ip")
	if err != nil || len(object) != 6 {
		return nil, nil, time.Time{}, time.Time{}, errors.New("fleet close event must have the exact shape")
	}
	eventID, err := strictJSONString(object["event_id"])
	if err != nil || !validAgentSessionCloseEventID(eventID) {
		return nil, nil, time.Time{}, time.Time{}, errors.New("invalid fleet close event id")
	}
	agentPublicKey, err := strictJSONString(object["agent_public_key"])
	if err != nil {
		return nil, nil, time.Time{}, time.Time{}, err
	}
	agentKey, err := decodeAgentPublicKey(agentPublicKey)
	if err != nil {
		return nil, nil, time.Time{}, time.Time{}, errors.New("invalid fleet close agent key")
	}
	issuedNanos, err := strictJSONInt64(object["issued_through_nanos"])
	if err != nil || issuedNanos <= 0 {
		return nil, nil, time.Time{}, time.Time{}, errors.New("invalid fleet close issuance")
	}
	expiresUnix, err := strictJSONInt64(object["expires_at"])
	if err != nil {
		return nil, nil, time.Time{}, time.Time{}, errors.New("invalid fleet close expiry")
	}
	originServer, err := strictJSONString(object["origin_server"])
	if err != nil || originServer == "" || len(originServer) > 256 || originServer != strings.TrimSpace(originServer) {
		return nil, nil, time.Time{}, time.Time{}, errors.New("invalid fleet close origin server")
	}
	originIP, err := strictJSONString(object["origin_ip"])
	parsedOriginIP := net.ParseIP(originIP)
	if err != nil || parsedOriginIP == nil || parsedOriginIP.String() != originIP || !isPrivateIP(originIP) {
		return nil, nil, time.Time{}, time.Time{}, errors.New("invalid fleet close origin IP")
	}
	issuedThrough := time.Unix(0, issuedNanos)
	expiresAt := time.Unix(expiresUnix, 0)
	if issuedThrough.After(now.Add(agentSessionCloseFutureSkew)) || !expiresAt.After(now) || expiresAt.After(now.Add(agentSessionCloseEventTTL+agentSessionCloseFutureSkew)) || !expiresAt.After(issuedThrough.Add(-agentSessionCloseFutureSkew)) {
		return nil, nil, time.Time{}, time.Time{}, errors.New("invalid fleet close lifetime")
	}
	return &agentSessionCloseFleetEvent{
		EventID: eventID, AgentPublicKey: agentPublicKey, IssuedThroughNanos: issuedNanos,
		ExpiresAt: expiresUnix, OriginServer: originServer, OriginIP: originIP,
	}, agentKey, issuedThrough, expiresAt, nil
}

func decodeExactSessionCloseFleetEvent(raw []byte, now time.Time) (*exactSessionCloseFleetEvent, []byte, time.Time, time.Time, error) {
	object, err := decodeExactJSONObject(raw, "event_id", "agent_public_key", "session_id", "session_issued_at_nanos", "expires_at", "origin_server", "origin_ip")
	if err != nil || len(object) != 7 {
		return nil, nil, time.Time{}, time.Time{}, errors.New("exact session close event must have the exact shape")
	}
	eventID, err := strictJSONString(object["event_id"])
	if err != nil || !validAgentSessionCloseEventID(eventID) {
		return nil, nil, time.Time{}, time.Time{}, errors.New("invalid exact session close event id")
	}
	agentPublicKey, err := strictJSONString(object["agent_public_key"])
	if err != nil {
		return nil, nil, time.Time{}, time.Time{}, err
	}
	agentKey, err := decodeAgentPublicKey(agentPublicKey)
	if err != nil {
		return nil, nil, time.Time{}, time.Time{}, errors.New("invalid exact session close agent key")
	}
	sessionID, err := strictJSONUint64(object["session_id"])
	if err != nil || sessionID == 0 {
		return nil, nil, time.Time{}, time.Time{}, errors.New("invalid exact session id")
	}
	issuedNanos, err := strictJSONInt64(object["session_issued_at_nanos"])
	if err != nil || issuedNanos <= 0 {
		return nil, nil, time.Time{}, time.Time{}, errors.New("invalid exact session issuance")
	}
	expiresUnix, err := strictJSONInt64(object["expires_at"])
	if err != nil {
		return nil, nil, time.Time{}, time.Time{}, errors.New("invalid exact session close expiry")
	}
	originServer, err := strictJSONString(object["origin_server"])
	if err != nil || originServer == "" || len(originServer) > 256 || originServer != strings.TrimSpace(originServer) {
		return nil, nil, time.Time{}, time.Time{}, errors.New("invalid exact session close origin server")
	}
	originIP, err := strictJSONString(object["origin_ip"])
	parsedOriginIP := net.ParseIP(originIP)
	if err != nil || parsedOriginIP == nil || parsedOriginIP.String() != originIP || !isPrivateIP(originIP) {
		return nil, nil, time.Time{}, time.Time{}, errors.New("invalid exact session close origin IP")
	}
	issuedAt := time.Unix(0, issuedNanos)
	expiresAt := time.Unix(expiresUnix, 0)
	maxLifetime := time.Duration(^uint32(0))*time.Second + time.Duration(ACOpenCompensationTime)*time.Second + agentSessionCloseFutureSkew
	if issuedAt.After(now.Add(agentSessionCloseFutureSkew)) || !expiresAt.After(now) || expiresAt.After(issuedAt.Add(maxLifetime)) {
		return nil, nil, time.Time{}, time.Time{}, errors.New("invalid exact session close lifetime")
	}
	return &exactSessionCloseFleetEvent{
		EventID: eventID, AgentPublicKey: agentPublicKey, SessionID: sessionID,
		SessionIssuedAtNanos: issuedNanos, ExpiresAt: expiresUnix,
		OriginServer: originServer, OriginIP: originIP,
	}, agentKey, issuedAt, expiresAt, nil
}

func (hs *HttpServer) handleInternalAgentSessionClose(ctx *gin.Context) {
	if hs == nil || hs.udpServer == nil || hs.udpServer.fleetCloseSigner == nil || hs.udpServer.cloudMap == nil {
		ctx.Status(http.StatusServiceUnavailable)
		return
	}
	if ctx.Request.URL.RawQuery != "" || ctx.Request.URL.Fragment != "" {
		ctx.Status(http.StatusBadRequest)
		return
	}
	host, _, err := net.SplitHostPort(ctx.Request.RemoteAddr)
	if err != nil || !isPrivateIP(host) {
		ctx.Status(http.StatusForbidden)
		return
	}
	originalBody := ctx.Request.Body
	defer originalBody.Close()
	body, err := io.ReadAll(io.LimitReader(originalBody, maxAgentSessionCloseFleetBody+1))
	if err != nil {
		ctx.Status(http.StatusBadRequest)
		return
	}
	if len(body) > maxAgentSessionCloseFleetBody {
		ctx.Status(http.StatusRequestEntityTooLarge)
		return
	}
	if err := hs.udpServer.fleetCloseSigner.Verify(ctx.GetHeader(internalauth.Header), http.MethodPost, agentSessionCloseFleetPath, body, agentSessionCloseEventTTL+agentSessionCloseFutureSkew); err != nil {
		hs.udpServer.incrAgentSessionCloseMetric(MetricAgentSessionCloseInvalid)
		ctx.Status(http.StatusUnauthorized)
		return
	}
	now := time.Now()
	event, agentKey, issuedThrough, expiresAt, err := decodeAgentSessionCloseFleetEvent(body, now)
	if err != nil {
		hs.udpServer.incrAgentSessionCloseMetric(MetricAgentSessionCloseInvalid)
		ctx.Status(http.StatusBadRequest)
		return
	}
	discoverCtx, cancel := context.WithTimeout(ctx.Request.Context(), DefaultStorageTimeout)
	servers, err := hs.udpServer.cloudMap.DiscoverServerInstances(discoverCtx)
	cancel()
	if err != nil || !fleetCloseSourceIsHealthy(servers, event.OriginServer, event.OriginIP, host) {
		freshCtx, freshCancel := context.WithTimeout(ctx.Request.Context(), DefaultStorageTimeout)
		servers, err = hs.udpServer.cloudMap.DiscoverServerInstancesFresh(freshCtx)
		freshCancel()
	}
	if err != nil || !fleetCloseSourceIsHealthy(servers, event.OriginServer, event.OriginIP, host) {
		hs.udpServer.incrAgentSessionCloseMetric(MetricAgentSessionCloseInvalid)
		ctx.Status(http.StatusForbidden)
		return
	}
	replayKey := event.OriginServer + "/" + event.EventID
	admission := hs.udpServer.sessionRegistry().admitCloseEvent(replayKey, expiresAt)
	switch admission {
	case closeEventReplay:
		hs.udpServer.incrAgentSessionCloseMetric(MetricAgentSessionCloseReplay)
		ctx.Status(http.StatusNoContent)
		return
	case closeEventSaturated:
		hs.udpServer.incrAgentSessionCloseMetric(MetricAgentSessionCloseReplaySaturated)
	case closeEventNew:
	case closeEventRejected:
		hs.udpServer.incrAgentSessionCloseMetric(MetricAgentSessionCloseInvalid)
		ctx.Status(http.StatusBadRequest)
		return
	}
	work, leader := hs.udpServer.beginAgentSessionCloseWork(agentKey, issuedThrough, expiresAt, false)
	if leader && !hs.udpServer.startAgentSessionCloseWorker(work) {
		hs.udpServer.finishAgentSessionCloseWork(work)
		if admission == closeEventNew {
			hs.udpServer.sessionRegistry().rollbackCloseEventAdmission(replayKey, expiresAt)
		}
		ctx.Status(http.StatusServiceUnavailable)
		return
	}
	ctx.Status(http.StatusNoContent)
}

func (hs *HttpServer) handleInternalExactSessionClose(ctx *gin.Context) {
	if hs == nil || hs.udpServer == nil || hs.udpServer.fleetCloseSigner == nil || hs.udpServer.cloudMap == nil {
		ctx.Status(http.StatusServiceUnavailable)
		return
	}
	if ctx.Request.URL.RawQuery != "" || ctx.Request.URL.Fragment != "" {
		ctx.Status(http.StatusBadRequest)
		return
	}
	host, _, err := net.SplitHostPort(ctx.Request.RemoteAddr)
	if err != nil || !isPrivateIP(host) {
		ctx.Status(http.StatusForbidden)
		return
	}
	originalBody := ctx.Request.Body
	defer originalBody.Close()
	body, err := io.ReadAll(io.LimitReader(originalBody, maxAgentSessionCloseFleetBody+1))
	if err != nil {
		ctx.Status(http.StatusBadRequest)
		return
	}
	if len(body) > maxAgentSessionCloseFleetBody {
		ctx.Status(http.StatusRequestEntityTooLarge)
		return
	}
	if err := hs.udpServer.fleetCloseSigner.Verify(ctx.GetHeader(internalauth.Header), http.MethodPost, exactSessionCloseFleetPath, body, agentSessionCloseEventTTL+agentSessionCloseFutureSkew); err != nil {
		hs.udpServer.incrAgentSessionCloseMetric(MetricAgentSessionCloseInvalid)
		ctx.Status(http.StatusUnauthorized)
		return
	}
	now := time.Now()
	event, agentKey, issuedAt, expiresAt, err := decodeExactSessionCloseFleetEvent(body, now)
	if err != nil {
		hs.udpServer.incrAgentSessionCloseMetric(MetricAgentSessionCloseInvalid)
		ctx.Status(http.StatusBadRequest)
		return
	}
	discoverCtx, cancel := context.WithTimeout(ctx.Request.Context(), DefaultStorageTimeout)
	servers, err := hs.udpServer.cloudMap.DiscoverServerInstances(discoverCtx)
	cancel()
	if err != nil || !fleetCloseSourceIsHealthy(servers, event.OriginServer, event.OriginIP, host) {
		freshCtx, freshCancel := context.WithTimeout(ctx.Request.Context(), DefaultStorageTimeout)
		servers, err = hs.udpServer.cloudMap.DiscoverServerInstancesFresh(freshCtx)
		freshCancel()
	}
	if err != nil || !fleetCloseSourceIsHealthy(servers, event.OriginServer, event.OriginIP, host) {
		hs.udpServer.incrAgentSessionCloseMetric(MetricAgentSessionCloseInvalid)
		ctx.Status(http.StatusForbidden)
		return
	}
	replayKey := "exact/" + event.OriginServer + "/" + event.EventID
	admission := hs.udpServer.sessionRegistry().admitCloseEvent(replayKey, expiresAt)
	switch admission {
	case closeEventReplay:
		hs.udpServer.incrAgentSessionCloseMetric(MetricAgentSessionCloseReplay)
		if hs.udpServer.sessionRegistry().hasExactSession(agentKey, event.SessionID, issuedAt) {
			ctx.Status(http.StatusAccepted)
		} else {
			ctx.Status(http.StatusNoContent)
		}
		return
	case closeEventSaturated:
		hs.udpServer.incrAgentSessionCloseMetric(MetricAgentSessionCloseReplaySaturated)
	case closeEventNew:
	case closeEventRejected:
		hs.udpServer.incrAgentSessionCloseMetric(MetricAgentSessionCloseInvalid)
		ctx.Status(http.StatusBadRequest)
		return
	}
	if saturated, cutoffErr := hs.udpServer.sessionRegistry().recordExactSessionCloseCutoff(agentKey, event.SessionID, issuedAt, expiresAt); cutoffErr != nil {
		if admission == closeEventNew {
			hs.udpServer.sessionRegistry().rollbackCloseEventAdmission(replayKey, expiresAt)
		}
		hs.udpServer.incrAgentSessionCloseMetric(MetricAgentSessionCloseInvalid)
		ctx.Status(http.StatusBadRequest)
		return
	} else if saturated {
		hs.udpServer.incrAgentSessionCloseMetric(MetricAgentSessionCloseCutoffSaturated)
		log.Warning("exact NHP session close cutoff registry saturated; forwarded admission is temporarily fail-closed")
	}
	if !hs.udpServer.sessionRegistry().hasExactSession(agentKey, event.SessionID, issuedAt) {
		ctx.Status(http.StatusNoContent)
		return
	}
	if !hs.udpServer.startAgentSessionCloseTask(func() {
		workerCtx, cancel := context.WithDeadline(hs.udpServer.LifecycleCtx(), expiresAt)
		defer cancel()
		hs.udpServer.compensateFailedNHPSessionUntil(workerCtx, agentKey, event.SessionID, issuedAt)
	}) {
		if admission == closeEventNew {
			hs.udpServer.sessionRegistry().rollbackCloseEventAdmission(replayKey, expiresAt)
		}
		ctx.Status(http.StatusServiceUnavailable)
		return
	}
	ctx.Status(http.StatusAccepted)
}

func fleetCloseSourceIsHealthy(servers []ServerInfo, originServer, originIP, sourceIP string) bool {
	source := net.ParseIP(sourceIP)
	origin := net.ParseIP(originIP)
	if source == nil || origin == nil || !source.Equal(origin) {
		return false
	}
	for _, server := range servers {
		if server.ID == originServer {
			registered := net.ParseIP(server.InternalIP)
			return registered != nil && registered.Equal(source)
		}
	}
	return false
}
