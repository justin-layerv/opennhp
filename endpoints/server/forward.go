package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/OpenNHP/opennhp/endpoints/server/internal/qurlplacement"
	"github.com/OpenNHP/opennhp/endpoints/server/internal/qurlv2"
	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
	"github.com/OpenNHP/opennhp/nhp/log"
)

// ============================================================================
// Server-to-Server Forwarding
// See docs/design/PLUGGABLE_STORAGE_BACKEND.md sections 6.3-6.5 for details.
//
// When a knock arrives at a server that doesn't have a connection to the
// target AC, ForwardKnock races the AC's healthy assigned servers via NHP_FWD
// and returns the first successful NHP_FRT result. FanoutKnock is coverage-only
// and sends one NHP_FWD per non-local AZ.
//
// Key design decisions:
// - Uses Noise K pattern for forward secrecy (per-server keypairs)
// - Health tracking skips recently failed peers without poisoning on local pressure
//   unless skipping would leave a retry-less admission with zero attempts
// - Bounded first-success fan-out for retry-less forwarded admission
// - 30-second health decay for automatic recovery
// - 2-second timeout for the forwarded admission budget
// ============================================================================

const (
	// ForwardTimeout is the maximum time to wait for a forward response.
	ForwardTimeout = 2 * time.Second

	// HealthDecayDuration is how long to consider a server unhealthy after failure.
	HealthDecayDuration = 30 * time.Second

	// MaxTimestampAge is the maximum age of an NHP_FWD timestamp (replay protection).
	MaxTimestampAge = 30 * time.Second

	// MaxPendingForwards is the maximum number of concurrent pending forwards.
	// ForwardKnock can schedule up to MaxServersPerAssignment per user knock, so
	// keep this at 3x the old single-peer cap to preserve effective headroom
	// while still preventing unbounded growth under DDoS or slow downstream.
	MaxPendingForwards = 30000

	// ForwardNoResponseFailureThreshold is the number of consecutive full-budget
	// no-response outcomes required before a peer is marked unhealthy. A single
	// shared budget expiry must not poison every assigned owner; if all owners
	// are cached unhealthy, ForwardKnock still falls back to attempting the
	// bounded assignment row so a retry-less admission never turns into zero
	// forward attempts.
	ForwardNoResponseFailureThreshold = 2
)

type localForwardSendError struct {
	err error
}

var (
	errAllAssignedServersUnhealthy = errors.New("all assigned servers unreachable or unhealthy")
	errForwardTimeout              = errors.New("forward timeout")
)

func (e *localForwardSendError) Error() string {
	return e.err.Error()
}

func (e *localForwardSendError) Unwrap() error {
	return e.err
}

func isLocalForwardSendError(err error) bool {
	var localErr *localForwardSendError
	return errors.As(err, &localErr)
}

func shouldRecordForwardFailure(err error) bool {
	return err != nil &&
		!isLocalForwardSendError(err) &&
		!errors.Is(err, context.Canceled) &&
		!errors.Is(err, context.DeadlineExceeded) &&
		// handleNhpOpenResource gives ForwardKnock the same ForwardTimeout as
		// each peer attempt, so errForwardTimeout is shared-budget exhaustion in
		// this path rather than proof that one peer should be marked unhealthy.
		!errors.Is(err, errForwardTimeout)
}

func shouldRecordForwardNoResponse(err error) bool {
	return errors.Is(err, errForwardTimeout) || errors.Is(err, context.DeadlineExceeded)
}

// recordForwardPeerFailure applies the shared peer-health policy for a failed
// forward attempt: real peer failures poison health immediately, while local
// pressure, cancellation, and single shared-budget expiries are ignored, and a
// persistent full-budget no-response only marks the peer unhealthy after the
// consecutive threshold. op labels the calling path for the threshold warning.
func (f *ServerForwarder) recordForwardPeerFailure(op, serverID, acID string, err error) {
	if shouldRecordForwardFailure(err) {
		f.health.RecordFailure(serverID)
		return
	}
	if shouldRecordForwardNoResponse(err) && f.health.RecordNoResponse(serverID) {
		log.Warning("%s to server %s for AC %s hit %d consecutive full-budget no-response outcomes; marking peer unhealthy",
			op, serverID, acID, ForwardNoResponseFailureThreshold)
	}
}

// ServerForwarder handles server-to-server knock forwarding.
type ServerForwarder struct {
	deps         ForwarderDeps
	health       *ServerHealthTracker
	pendingFwds  map[uint64]*PendingForward // Transaction ID -> pending forward
	pendingMutex sync.RWMutex
	serverPeers  map[string]*core.UdpPeer // Server ID -> peer
	peerMutex    sync.RWMutex
	nextTxID     uint64
	txIDMutex    sync.Mutex
	stopCh       chan struct{}
	wg           sync.WaitGroup
}

// PendingForward tracks a pending forward request.
type PendingForward struct {
	TransactionID uint64
	UserAddr      *net.UDPAddr
	ResponseCh    chan *common.ServerForwardResultMsg
	CreatedAt     time.Time
}

// ServerHealthTracker tracks server health for smart forwarding.
type ServerHealthTracker struct {
	failures    map[string]time.Time // Server ID -> last failure time
	noResponses map[string]int       // Server ID -> consecutive full-budget no-response count
	mu          sync.RWMutex
}

// NewServerForwarder creates a new server forwarder.
func NewServerForwarder(deps ForwarderDeps) *ServerForwarder {
	// Initialize transaction ID with entropy to prevent collisions after restart
	// and to make IDs unpredictable (security hardening)
	initialTxID := uint64(time.Now().UnixNano()) ^ uint64(rand.Int64())

	return &ServerForwarder{
		deps:        deps,
		health:      NewServerHealthTracker(),
		pendingFwds: make(map[uint64]*PendingForward),
		serverPeers: make(map[string]*core.UdpPeer),
		nextTxID:    initialTxID,
		stopCh:      make(chan struct{}),
	}
}

// NewServerHealthTracker creates a new health tracker.
func NewServerHealthTracker() *ServerHealthTracker {
	return &ServerHealthTracker{
		failures:    make(map[string]time.Time),
		noResponses: make(map[string]int),
	}
}

// IsUnhealthy returns true if the server is considered unhealthy.
func (h *ServerHealthTracker) IsUnhealthy(serverID string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	lastFail, exists := h.failures[serverID]
	return exists && time.Since(lastFail) < HealthDecayDuration
}

// RecordFailure records a server failure.
func (h *ServerHealthTracker) RecordFailure(serverID string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.failures[serverID] = time.Now()
	delete(h.noResponses, serverID)
}

// RecordNoResponse records a full-budget no-response outcome. It returns true
// when the peer crossed the consecutive threshold and was marked unhealthy.
func (h *ServerHealthTracker) RecordNoResponse(serverID string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.noResponses[serverID]++
	if h.noResponses[serverID] < ForwardNoResponseFailureThreshold {
		return false
	}

	h.failures[serverID] = time.Now()
	delete(h.noResponses, serverID)
	return true
}

// ClearNoResponse clears only the soft consecutive no-response debt. It does
// not clear a real failure/unhealthy mark.
func (h *ServerHealthTracker) ClearNoResponse(serverID string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.noResponses, serverID)
}

// RecordSuccess records a successful communication (clears failure).
func (h *ServerHealthTracker) RecordSuccess(serverID string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.failures, serverID)
	delete(h.noResponses, serverID)
}

// ForwardKnock forwards a knock to the AC's healthy assigned servers and
// returns the first successful ACK data to send to the user.
//
// Unlike FanoutKnock -- which bounds to one peer per non-local AZ purely for
// pinhole coverage -- ForwardKnock deliberately races every healthy assigned
// server. The customer's single admission attempt gets no second chance, so it
// spends the redundant assigned owners already in the placement row rather than
// letting one slow or non-owner peer consume the whole timeout. Do not AZ-bound
// this path. This applies to every native no-local-AC forward, not just qURL v2
// admission; receivers may all open valid pinholes, so rollout validation should
// watch MetricKnockForwardPeerAttempt alongside AC operation volume. Native
// receiver-side plugin work must be idempotent enough for that bounded
// duplicate processing. For qURL v2, qurl-service prepare/commit already ran
// once on the origin before this call; forwarded receivers only open AC pinholes
// with the committed admission metadata sidecar, so fan-out does not multiply
// one-time-use or session-count commits.
func (f *ServerForwarder) ForwardKnock(
	ctx context.Context,
	assignment *ACAssignment,
	knockData []byte,
	userAddr *net.UDPAddr,
	admissionResource *common.ResourceData,
) (*common.ServerForwardResultMsg, error) {
	if len(assignment.AssignedServers) == 0 {
		return nil, errors.New("no assigned servers for AC")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Placement should keep assigned server IDs unique; enforce that locally so
	// topology drift cannot double-send, double-open AC pinholes, or double-write
	// health for the same peer in one user knock.
	servers := make([]ServerInfo, 0, len(assignment.AssignedServers))
	seenServerIDs := make(map[string]struct{}, len(assignment.AssignedServers))
	for _, server := range assignment.AssignedServers {
		if _, ok := seenServerIDs[server.ID]; ok {
			log.Warning("Skipping duplicate assigned server %s for AC %s in forward fan-out", server.ID, assignment.ACID)
			continue
		}
		seenServerIDs[server.ID] = struct{}{}
		servers = append(servers, server)
	}

	// Shuffle goroutine launch order so equal-latency responses are not always
	// biased by assignment ordering. All healthy targets are still contacted.
	rand.Shuffle(len(servers), func(i, j int) {
		servers[i], servers[j] = servers[j], servers[i]
	})

	targets := make([]ServerInfo, 0, len(servers))
	for _, target := range servers {
		if f.health.IsUnhealthy(target.ID) {
			log.Debug("Skipping unhealthy server %s for AC %s", target.ID, assignment.ACID)
			continue
		}
		targets = append(targets, target)
	}
	if len(targets) == 0 {
		// Do not let the local health cache convert a retry-less forwarded
		// admission into an immediate zero-attempt denial. If every assigned
		// owner is cached unhealthy, spend the bounded unique assignment row and
		// let the current attempt prove whether any owner has recovered.
		log.Warning("All %d assigned servers for AC %s are cached unhealthy; attempting all unique owners for retry-less forwarded admission",
			len(servers), assignment.ACID)
		targets = append(targets, servers...)
	}

	type forwardOutcome struct {
		target ServerInfo
		result *common.ServerForwardResultMsg
		err    error
	}

	attemptCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// The buffer size is load-bearing: ForwardKnock returns on first success,
	// so losing goroutines must be able to report their outcome without blocking
	// even when this caller stops ranging the channel.
	outcomes := make(chan forwardOutcome, len(targets))
	var wg sync.WaitGroup
	for _, target := range targets {
		if f.deps != nil {
			f.deps.IncrForwarderMetric(MetricKnockForwardPeerAttempt)
		}
		wg.Add(1)
		go func(target ServerInfo) {
			defer wg.Done()
			result, err := f.forwardToServer(attemptCtx, target, assignment.ACID, knockData, userAddr, admissionResource)
			outcomes <- forwardOutcome{target: target, result: result, err: err}
		}(target)
	}
	go func() {
		wg.Wait()
		close(outcomes)
	}()

	var lastErr error
	for outcome := range outcomes {
		if outcome.err != nil {
			log.Warning("Forward to server %s failed for AC %s: %v", outcome.target.ID, assignment.ACID, outcome.err)
			f.recordForwardPeerFailure("Forward", outcome.target.ID, assignment.ACID, outcome.err)
			lastErr = outcome.err
			continue
		}

		// Reachability health is separate from AC ownership. A non-success
		// response can still prove the peer answered, while other owners race.
		f.health.RecordSuccess(outcome.target.ID)
		if outcome.result != nil && outcome.result.Success {
			for _, target := range targets {
				if target.ID != outcome.target.ID {
					f.health.ClearNoResponse(target.ID)
				}
			}
			cancel()
			return outcome.result, nil
		}

		lastErr = forwardUnsuccessfulResultError(outcome.target, assignment.ACID, outcome.result)
		log.Warning("Forward to server %s returned unsuccessful result for AC %s: %v", outcome.target.ID, assignment.ACID, lastErr)
	}

	if lastErr != nil {
		return nil, lastErr
	}
	// Defensive safety net: targets is non-empty, and every non-success outcome
	// above sets lastErr. Keep a deterministic error if that invariant changes.
	return nil, errAllAssignedServersUnhealthy
}

func forwardUnsuccessfulResultError(target ServerInfo, acID string, result *common.ServerForwardResultMsg) error {
	prefix := fmt.Sprintf("forward to server %s for AC %s", target.ID, acID)
	switch {
	case result == nil:
		return fmt.Errorf("%s returned nil result", prefix)
	case result.ErrCode == "" && result.ErrMsg == "":
		return fmt.Errorf("%s returned unsuccessful result", prefix)
	case result.ErrCode == "":
		return fmt.Errorf("%s rejected: %s", prefix, result.ErrMsg)
	case result.ErrMsg == "":
		return fmt.Errorf("%s rejected with %s", prefix, result.ErrCode)
	default:
		return fmt.Errorf("%s rejected with %s: %s", prefix, result.ErrCode, result.ErrMsg)
	}
}

// FanoutKnock sends the knock to one assigned peer server per non-local AZ in
// parallel -- not first-success -- purely so each AZ opens its local AC pinhole.
// This is the NHP_FWD (native/relay knock path) half of the qurl-service#948
// fix: the origin server already opened its own local ACs, and the assignment
// row is the bounded routing table for the AZs that still need an NHP_FWD.
//
// selfInternalIP is this server's VPC IP; a target matching it is skipped (the
// origin already opened its local ACs). The receiver runs HandleForwardRequest →
// handleDecryptedForwardedKnock, which opens local ACs and never re-forwards, so
// depth is bounded to one hop without needing a Forwarded flag.
//
// The return is coverage observability only — peersAccepted is how many peers
// reported a successful open; the caller owns the knock ack from its local
// broadcast. Individual peer failures are logged, never surfaced: a single down
// peer must not fail an otherwise-good knock.
func (f *ServerForwarder) FanoutKnock(
	ctx context.Context,
	assignment *ACAssignment,
	selfInternalIP string,
	knockData []byte,
	userAddr *net.UDPAddr,
	admissionResource *common.ResourceData,
) (peersAccepted int) {
	if assignment == nil || len(assignment.AssignedServers) == 0 {
		return 0
	}

	// Native fanout counts duplicate AZ candidates on the raw assignment. This
	// is a topology-drift signal; the local failure cache below is stale by
	// design and must not hide a duplicate-AZ assignment from rollout validation.
	if duplicateAZBuckets := countDuplicateFanoutAZBuckets(assignment.AssignedServers, selfInternalIP); duplicateAZBuckets > 0 && f.deps != nil {
		// Forwarder metrics are exposed as increment-only callbacks, so emit one
		// sample per duplicate AZ bucket.
		for i := 0; i < duplicateAZBuckets; i++ {
			f.deps.IncrForwarderMetric(MetricKnockFanoutDuplicateAZCandidate)
		}
		log.Warning("Knock fan-out for AC %s saw %d non-local AZ bucket(s) with multiple assigned peer candidates; still selecting one peer per AZ", assignment.ACID, duplicateAZBuckets)
	}
	targets := selectAssignedFanoutTargetsByAZWithHealth(assignment.AssignedServers, selfInternalIP, f.health.IsUnhealthy)
	var wg sync.WaitGroup
	var accepted atomic.Int32
	for _, target := range targets {
		// Unlike first-success ForwardKnock, coverage fanout never skips an AZ
		// only because its selected peer is in the stale local failure cache.
		// The selector prefers a non-failed peer within the AZ when one exists,
		// but falls back to the failed peer if it is the AZ's only candidate.
		wg.Add(1)
		go func(target ServerInfo) {
			defer wg.Done()
			result, ferr := f.forwardToServer(ctx, target, assignment.ACID, knockData, userAddr, admissionResource)
			if ferr != nil {
				f.recordForwardPeerFailure("Knock fan-out", target.ID, assignment.ACID, ferr)
				log.Warning("Knock fan-out to server %s failed for AC %s: %v", target.ID, assignment.ACID, ferr)
				return
			}
			f.health.RecordSuccess(target.ID)
			if result != nil && result.Success {
				accepted.Add(1)
			}
		}(target)
	}
	wg.Wait()
	return int(accepted.Load())
}

const unknownFanoutAZ = "<unknown>"

// selectAssignedFanoutTargetsByAZ returns the bounded coverage target set for
// an origin knock: skip the origin server, skip the origin AZ when it is known,
// then keep at most one assigned server for each remaining AZ. Missing AZ
// metadata is collapsed to one bucket so a metadata regression cannot turn
// fan-out into an unbounded parallel blast.
func selectAssignedFanoutTargetsByAZ(servers []ServerInfo, selfInternalIP string) []ServerInfo {
	return selectAssignedFanoutTargetsByAZWithHealth(servers, selfInternalIP, nil)
}

// selectAssignedFanoutTargetsByAZWithHealth keeps fan-out bounded by AZ while
// preferring a peer not currently in the caller's local failure cache. A stale
// failure must not suppress an entire AZ's pinhole attempt, so the first peer in
// an AZ remains the fallback when every candidate for that AZ is marked failed.
func selectAssignedFanoutTargetsByAZWithHealth(servers []ServerInfo, selfInternalIP string, isUnhealthy func(string) bool) []ServerInfo {
	selfAZ := fanoutSelfAZ(servers, selfInternalIP)

	type candidate struct {
		server    ServerInfo
		unhealthy bool
	}

	selected := make(map[string]candidate, len(servers))
	order := make([]string, 0, len(servers))
	for _, srv := range servers {
		if skipFanoutCandidate(srv, selfInternalIP, selfAZ) {
			continue
		}

		key := fanoutAZKey(srv)

		unhealthy := false
		if isUnhealthy != nil {
			unhealthy = isUnhealthy(srv.ID)
		}
		current, ok := selected[key]
		if !ok {
			selected[key] = candidate{server: srv, unhealthy: unhealthy}
			order = append(order, key)
			continue
		}
		if current.unhealthy && !unhealthy {
			selected[key] = candidate{server: srv, unhealthy: unhealthy}
		}
	}

	targets := make([]ServerInfo, 0, len(order))
	for _, key := range order {
		targets = append(targets, selected[key].server)
	}
	return targets
}

func countDuplicateFanoutAZBuckets(servers []ServerInfo, selfInternalIP string) int {
	selfAZ := fanoutSelfAZ(servers, selfInternalIP)
	counts := make(map[string]int, len(servers))
	for _, srv := range servers {
		if skipFanoutCandidate(srv, selfInternalIP, selfAZ) {
			continue
		}
		counts[fanoutAZKey(srv)]++
	}

	duplicates := 0
	for _, count := range counts {
		if count > 1 {
			duplicates++
		}
	}
	return duplicates
}

func fanoutSelfAZ(servers []ServerInfo, selfInternalIP string) string {
	if selfInternalIP == "" {
		return ""
	}
	for _, srv := range servers {
		if srv.InternalIP == selfInternalIP {
			return srv.AZ
		}
	}
	return ""
}

func skipFanoutCandidate(srv ServerInfo, selfInternalIP, selfAZ string) bool {
	if selfInternalIP != "" && srv.InternalIP == selfInternalIP {
		return true
	}
	// If selfAZ is missing, same-AZ exclusion is unknowable. Keep fan-out
	// bounded by letting unknown-AZ peers collapse into the single unknown bucket.
	return selfAZ != "" && srv.AZ == selfAZ
}

func fanoutAZKey(srv ServerInfo) string {
	if srv.AZ == "" {
		return unknownFanoutAZ
	}
	return srv.AZ
}

// forwardToServer sends an NHP_FWD message to a specific server.
func (f *ServerForwarder) forwardToServer(
	ctx context.Context,
	target ServerInfo,
	acID string,
	knockData []byte,
	userAddr *net.UDPAddr,
	admissionResource *common.ResourceData,
) (*common.ServerForwardResultMsg, error) {
	// Get or create peer for target server
	peer, err := f.getOrCreateServerPeer(target)
	if err != nil {
		return nil, err
	}

	// Generate transaction ID
	txID := f.nextTransactionID()

	// Create forward message
	fwdMsg := &common.ServerForwardMsg{
		KnockData:               knockData,
		SourceServer:            f.deps.GetHostname(),
		UserAddr:                userAddr.String(),
		TransactionId:           txID,
		Timestamp:               time.Now().Unix(),
		SessionId:               admissionResourceSessionID(admissionResource),
		SessionIssuedAtNanos:    admissionResourceSessionIssuedAtNanos(admissionResource),
		AdmissionRevocationData: nativeForwardAdmissionRevocationData(admissionResource),
		ResolvedResourceData:    nativeForwardResolvedResourceData(admissionResource),
	}

	msgBytes, err := json.Marshal(fwdMsg)
	if err != nil {
		return nil, err
	}

	// Create pending forward
	responseCh := make(chan *common.ServerForwardResultMsg, 1)
	pending := &PendingForward{
		TransactionID: txID,
		UserAddr:      userAddr,
		ResponseCh:    responseCh,
		CreatedAt:     time.Now(),
	}

	f.pendingMutex.Lock()
	if len(f.pendingFwds) >= MaxPendingForwards {
		f.pendingMutex.Unlock()
		return nil, &localForwardSendError{
			err: errors.New("too many pending forwards"),
		}
	}
	f.pendingFwds[txID] = pending
	f.pendingMutex.Unlock()

	defer func() {
		f.pendingMutex.Lock()
		delete(f.pendingFwds, txID)
		f.pendingMutex.Unlock()
	}()

	// Create and send message via device
	md := &core.MsgData{
		HeaderType:     core.NHP_FWD,
		TransactionId:  txID,
		Compress:       false,
		PrevParserData: nil,
		Message:        msgBytes,
	}

	// Set peer for encryption - require valid UDP address
	sendAddr := peer.SendAddr()
	if sendAddr == nil {
		return nil, fmt.Errorf("server peer %s has no send address", target.ID)
	}
	udpAddr, ok := sendAddr.(*net.UDPAddr)
	if !ok {
		return nil, fmt.Errorf("server peer %s has non-UDP address type: %T", target.ID, sendAddr)
	}
	md.RemoteAddr = udpAddr
	md.PeerPk = peer.PublicKey()

	// Send message
	if err := f.deps.SendMessage(md); err != nil {
		// SendMessage failures are local/prequeue outcomes: backpressure,
		// shutdown, or assignment/peer-map drift before a packet reaches the
		// target. Do not mark the remote server unhealthy; persistent target
		// drift is surfaced by ServerForwardTargetDrop.
		return nil, &localForwardSendError{
			err: fmt.Errorf("forward send failed: %w", err),
		}
	}

	// Wait for response with timeout
	select {
	case result := <-responseCh:
		return result, nil
	case <-time.After(ForwardTimeout):
		return nil, errForwardTimeout
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func admissionResourceSessionID(res *common.ResourceData) uint64 {
	if res == nil {
		return 0
	}
	return res.NHPSessionId
}

func admissionResourceSessionIssuedAtNanos(res *common.ResourceData) int64 {
	if res == nil || res.NHPSessionIssuedAt.IsZero() {
		return 0
	}
	return res.NHPSessionIssuedAt.UnixNano()
}

// Keep the copy, presence check, and overlay below in lockstep with
// common.ForwardAdmissionRevocationData and stampQurlV2RevocationMetadata.
func nativeForwardAdmissionRevocationData(res *common.ResourceData) *common.ForwardAdmissionRevocationData {
	if res == nil {
		return nil
	}
	data := &common.ForwardAdmissionRevocationData{
		QurlUserPublicKeyHash: res.QurlUserPublicKeyHash,
		ResourcePublicKeyHash: res.ResourcePublicKeyHash,
		QurlSessionId:         res.QurlSessionId,
		AdmissionId:           res.AdmissionId,
		Deadline:              res.Deadline,
	}
	if !hasForwardAdmissionRevocationData(data) {
		return nil
	}
	return data
}

func hasForwardAdmissionRevocationData(data *common.ForwardAdmissionRevocationData) bool {
	// ResourcePublicKeyHash is copied when a genuine v2 sidecar is already
	// present, but a hash by itself is catalog metadata. Do not emit or accept a
	// hash-only sidecar; the receiver's local catalog hash remains authoritative.
	return data != nil && (data.QurlUserPublicKeyHash != "" ||
		data.QurlSessionId != "" ||
		data.AdmissionId != "" ||
		data.Deadline != 0)
}

type forwardedAdmissionResourceHashMismatchDecision struct {
	mismatch      bool
	catalogHash   string
	admissionHash string
}

func forwardedACOperationResourceData(catalog *common.ResourceData, admission *common.ForwardAdmissionRevocationData) (*common.ResourceData, forwardedAdmissionResourceHashMismatchDecision) {
	if catalog == nil {
		return nil, forwardedAdmissionResourceHashMismatchDecision{}
	}
	if !hasForwardAdmissionRevocationData(admission) {
		// Legacy/empty-sidecar path intentionally aliases the receiver catalog;
		// downstream AOP stamping treats ResourceData as read-only.
		return catalog, forwardedAdmissionResourceHashMismatchDecision{}
	}
	resourceHashMismatch := forwardedAdmissionResourceHashMismatch(catalog, admission)
	res := cloneResourceData(catalog)
	if admission.QurlUserPublicKeyHash != "" {
		res.QurlUserPublicKeyHash = admission.QurlUserPublicKeyHash
	}
	// Keep the receiver's catalog resource hash authoritative when present. The
	// origin sidecar only fills older/missing catalog rows so revocation coverage
	// does not regress during metadata rollout.
	if res.ResourcePublicKeyHash == "" && admission.ResourcePublicKeyHash != "" {
		res.ResourcePublicKeyHash = admission.ResourcePublicKeyHash
	}
	if admission.QurlSessionId != "" {
		res.QurlSessionId = admission.QurlSessionId
	}
	if admission.AdmissionId != "" {
		res.AdmissionId = admission.AdmissionId
	}
	if admission.Deadline != 0 {
		res.Deadline = admission.Deadline
	}
	return res, resourceHashMismatch
}

func forwardedAdmissionResourceHashMismatch(catalog *common.ResourceData, admission *common.ForwardAdmissionRevocationData) forwardedAdmissionResourceHashMismatchDecision {
	// Called only after hasForwardAdmissionRevocationData accepts the sidecar;
	// hash-only catalog metadata must not reach this mismatch check.
	var decision forwardedAdmissionResourceHashMismatchDecision
	if catalog != nil {
		decision.catalogHash = catalog.ResourcePublicKeyHash
	}
	if admission != nil {
		decision.admissionHash = admission.ResourcePublicKeyHash
	}
	decision.mismatch = decision.catalogHash != "" &&
		decision.admissionHash != "" &&
		decision.catalogHash != decision.admissionHash
	return decision
}

func nativeForwardResolvedResourceData(res *common.ResourceData) *common.ForwardResolvedResourceData {
	if res == nil || res.AuthServiceId == "" || res.ResourceId == "" || len(res.Resources) == 0 {
		return nil
	}
	return &common.ForwardResolvedResourceData{
		AuthServiceId:         res.AuthServiceId,
		ResourceId:            res.ResourceId,
		OpenTime:              res.OpenTime,
		Resources:             cloneResourceInfoMap(res.Resources),
		ResourcePublicKeyB64:  res.ResourcePublicKeyB64,
		ResourcePublicKeyHash: res.ResourcePublicKeyHash,
	}
}

func forwardedResolvedResourceData(
	route *common.ForwardResolvedResourceData,
	admission *common.ForwardAdmissionRevocationData,
	knkMsg *common.AgentKnockMsg,
) (*common.ResourceData, error) {
	if route == nil {
		return nil, errors.New("missing origin resolved resource data")
	}
	if knkMsg == nil {
		return nil, errors.New("missing forwarded knock message")
	}
	if route.AuthServiceId == "" || route.AuthServiceId != knkMsg.AuthServiceId {
		return nil, fmt.Errorf("origin resolved resource aspId %q does not match knock aspId %q",
			route.AuthServiceId, knkMsg.AuthServiceId)
	}
	if route.ResourceId == "" {
		return nil, errors.New("origin resolved resource id is empty")
	}
	if len(route.Resources) != 1 {
		return nil, fmt.Errorf("origin resolved resource has %d resource entries, want exactly 1", len(route.Resources))
	}
	res := &common.ResourceData{
		ResourceGroup: common.ResourceGroup{
			AuthServiceId: route.AuthServiceId,
			ResourceId:    route.ResourceId,
			OpenTime:      route.OpenTime,
			Resources:     cloneResourceInfoMap(route.Resources),
		},
		ResourcePublicKeyB64:  route.ResourcePublicKeyB64,
		ResourcePublicKeyHash: route.ResourcePublicKeyHash,
	}
	info := qurlplacement.OnlyResourceInfo(res)
	if info == nil || info.ACId == "" || info.Addr == nil {
		return nil, errors.New("origin resolved resource routing is incomplete")
	}
	if err := bindForwardedResolvedResourceIdentity(res, admission, knkMsg); err != nil {
		return nil, err
	}
	return res, nil
}

func bindForwardedResolvedResourceIdentity(
	res *common.ResourceData,
	admission *common.ForwardAdmissionRevocationData,
	knkMsg *common.AgentKnockMsg,
) error {
	if res == nil || knkMsg == nil {
		return errors.New("missing resource identity inputs")
	}
	if res.ResourceId == knkMsg.ResourceId {
		return nil
	}
	resourceHash := res.ResourcePublicKeyHash
	if resourceHash == "" && admission != nil {
		resourceHash = admission.ResourcePublicKeyHash
	}
	if resourceHash == "" {
		return fmt.Errorf("origin resolved resource id %q differs from knock resource id %q without a resource public-key hash",
			res.ResourceId, knkMsg.ResourceId)
	}
	knockHash, err := qurlv2.PublicKeyHashFromB64(knkMsg.ResourceId)
	if err != nil {
		return fmt.Errorf("knock resource id %q is not a qURL v2 public key: %w", knkMsg.ResourceId, err)
	}
	if knockHash != resourceHash {
		return fmt.Errorf("origin resolved resource hash %q does not match knock resource hash %q", resourceHash, knockHash)
	}
	if res.ResourcePublicKeyHash == "" {
		res.ResourcePublicKeyHash = resourceHash
	}
	return nil
}

// HandleForwardRequest processes an incoming NHP_FWD message.
// This is called on the ASSIGNED server when another server forwards a knock.
func (f *ServerForwarder) HandleForwardRequest(
	ppd *core.PacketParserData,
	fwdMsg *common.ServerForwardMsg,
) {
	// Replay protection: Check timestamp (both stale and future)
	msgTime := time.Unix(fwdMsg.Timestamp, 0)
	timeDiff := time.Since(msgTime)
	if timeDiff > MaxTimestampAge {
		log.Warning("Rejecting stale NHP_FWD from %s (timestamp %v, age %v)", fwdMsg.SourceServer, msgTime, timeDiff)
		f.sendForwardFailure(ppd, fwdMsg.TransactionId, "STALE_TIMESTAMP", "Message too old")
		return
	}
	// Reject messages with future timestamps (clock skew tolerance: 5 seconds)
	const maxFutureSkew = 5 * time.Second
	if timeDiff < -maxFutureSkew {
		log.Warning("Rejecting future NHP_FWD from %s (timestamp %v, skew %v)", fwdMsg.SourceServer, msgTime, -timeDiff)
		f.sendForwardFailure(ppd, fwdMsg.TransactionId, "FUTURE_TIMESTAMP", "Message timestamp in future")
		return
	}

	// Parse user address
	userAddr, err := net.ResolveUDPAddr("udp", fwdMsg.UserAddr)
	if err != nil {
		log.Error("Invalid user address in NHP_FWD: %s", fwdMsg.UserAddr)
		f.sendForwardFailure(ppd, fwdMsg.TransactionId, "INVALID_USER_ADDR", err.Error())
		return
	}

	log.Info("Processing NHP_FWD from %s for user %s (txID=%d)", fwdMsg.SourceServer, userAddr, fwdMsg.TransactionId)

	// Step 1: Decrypt the forwarded knock packet
	// All servers share the registration keypair, so we can decrypt any knock
	knockPpd, err := f.decryptForwardedKnock(fwdMsg.KnockData, userAddr)
	if err != nil {
		log.Error("Failed to decrypt forwarded knock from %s: %v", fwdMsg.SourceServer, err)
		f.sendForwardFailure(ppd, fwdMsg.TransactionId, "DECRYPT_FAILED", err.Error())
		return
	}

	f.handleDecryptedForwardedKnock(ppd, fwdMsg, userAddr, knockPpd)
}

func (f *ServerForwarder) handleDecryptedForwardedKnock(
	ppd *core.PacketParserData,
	fwdMsg *common.ServerForwardMsg,
	userAddr *net.UDPAddr,
	knockPpd *core.PacketParserData,
) {
	// Step 2: Parse the knock message
	knkMsg := &common.AgentKnockMsg{}
	if err := json.Unmarshal(knockPpd.BodyMessage, knkMsg); err != nil {
		// Keep the direct-path classification contract: canonical-value errors
		// are INVALID_RUN_ID, while duplicate/alias/type abuses are body-shape
		// parse failures before auth-service policy.
		if errors.Is(err, common.ErrInvalidAgentKnockRunID) {
			log.Warning("Rejected forwarded knock with malformed runId: tx=%d", fwdMsg.TransactionId)
			f.sendForwardFailure(ppd, fwdMsg.TransactionId, "INVALID_RUN_ID", common.ErrKnockRunIDInvalid.Error())
			return
		}
		log.Error("Failed to parse forwarded knock message: %v", err)
		f.sendForwardFailure(ppd, fwdMsg.TransactionId, "PARSE_FAILED", err.Error())
		return
	}
	// The forwarding server is authenticated by NHP_FWD; the inner agent KNK
	// cannot supply this value because the NHP-Server assigns it. Reuse the
	// origin's session across every peer AOP rather than allocating divergent
	// per-AZ sessions for one access request.
	knkMsg.NHPSessionId = fwdMsg.SessionId
	if knkMsg.NHPSessionId == 0 {
		log.Warning("Rejected forwarded knock with missing NHP session id: tx=%d", fwdMsg.TransactionId)
		f.sendForwardFailure(ppd, fwdMsg.TransactionId, "INVALID_SESSION_ID", common.ErrACOperationFailed.Error())
		return
	}
	if fwdMsg.SessionIssuedAtNanos <= 0 {
		log.Warning("Rejected forwarded knock with missing NHP session issuance time: tx=%d", fwdMsg.TransactionId)
		f.sendForwardFailure(ppd, fwdMsg.TransactionId, "INVALID_SESSION_ISSUED_AT", common.ErrACOperationFailed.Error())
		return
	}
	knkMsg.NHPSessionIssuedAt = time.Unix(0, fwdMsg.SessionIssuedAtNanos)
	// Mirror buildKnockAck's native registered-agent boundary on the server
	// that decrypts and executes a forwarded UDP knock. This must precede
	// authenticated-pubkey, ASP/catalog, placement, and AC work; otherwise the
	// forwarded path could mint an empty stored binding while the local path
	// rejects the same packet.
	if err := validateRegisteredAgentKnockRunID(knkMsg); err != nil {
		resultCode := "INVALID_RUN_ID"
		resultErr := common.ErrKnockRunIDInvalid
		if errors.Is(err, common.ErrKnockRunAttemptInvalid) {
			resultCode = "INVALID_RUN_ATTEMPT"
			resultErr = common.ErrKnockRunAttemptInvalid
		}
		log.Warning("Rejected forwarded registered-agent knock with missing or invalid retry binding: tx=%d resource=%s",
			fwdMsg.TransactionId, knkMsg.ResourceId)
		f.sendForwardFailure(ppd, fwdMsg.TransactionId, resultCode, resultErr.Error())
		return
	}

	agentPubKey, ok := forwardedAgentPubKey(knockPpd)
	if !ok {
		// The forward receiver should only reach this point after the inner
		// knock decrypts through Noise IK, which authenticates and populates
		// RemotePubKey. Fail closed if that upstream invariant ever regresses
		// rather than letting user-controlled knkMsg.UserId steer qURL tunnel
		// placement.
		log.Error("Forwarded knock missing authenticated RemotePubKey: tx=%d resource=%s authSvc=%s",
			fwdMsg.TransactionId, knkMsg.ResourceId, knkMsg.AuthServiceId)
		f.sendForwardFailure(ppd, fwdMsg.TransactionId, "INVALID_AGENT_PUBKEY", "Forwarded knock missing authenticated agent public key")
		return
	}
	knkMsg.NHPAgentPublicKey = agentPubKey
	sessionDeps, ok := f.deps.(forwardedNHPSessionDeps)
	if !ok {
		log.Error("Forwarded knock receiver has no NHP session reservation authority: tx=%d", fwdMsg.TransactionId)
		f.sendForwardFailure(ppd, fwdMsg.TransactionId, "SESSION_REGISTRY_UNAVAILABLE", common.ErrACOperationFailed.Error())
		return
	}
	// Verify the origin's durable reservation immediately after reconstructing
	// the authenticated session tuple. Rejection must precede catalog, placement,
	// protected-resource, local-registry, and AC work.
	verifyBudget := DefaultStorageTimeout
	if common.NativeSessionOperationPresent(*knkMsg) {
		verifyBudget = sessionControlNativeOperationReadTimeout
	}
	verifyCtx, verifyCancel := context.WithTimeout(f.deps.LifecycleCtx(), verifyBudget)
	verifiedReceipt, verifyErr := sessionDeps.VerifyForwardedDurableNHPSession(verifyCtx, knkMsg)
	verifyCancel()
	if verifyErr != nil {
		log.Warning("Rejected forwarded knock without durable NHP session authority: tx=%d session=%d err=%v",
			fwdMsg.TransactionId, knkMsg.NHPSessionId, verifyErr)
		f.sendForwardFailure(ppd, fwdMsg.TransactionId, "INVALID_SESSION_AUTHORITY", common.ErrACOperationFailed.Error())
		return
	}
	placementIdentity := qurlplacement.Identity{
		PublicKey: agentPubKey,
		UserID:    knkMsg.UserId,
	}

	// Resolve the auth service provider before qURL placement so the placement
	// step receives the DDB-backed ASP catalog for this authSvcId. The resolved
	// ResourceData then feeds both FindACConnectionsForResource and ACK
	// construction. Pubkey validation stays above this lookup so malformed
	// forwarded knocks fail closed without burning a catalog/DDB read. The
	// resolver must still run before AC lookup: it installs DDB-only aspIds
	// into the in-memory map that some AC selection paths read.
	aspData := f.deps.ResolveAuthSvcProvider(f.deps.LifecycleCtx(), knkMsg.AuthServiceId,
		fmt.Sprintf("forward-receiver tx=%d resource=%s authSvc=%s", fwdMsg.TransactionId, knkMsg.ResourceId, knkMsg.AuthServiceId))
	if aspData == nil {
		log.Error("Auth service provider not found for forwarded knock: %s", knkMsg.AuthServiceId)
		f.sendForwardFailure(ppd, fwdMsg.TransactionId, "ASP_NOT_FOUND", "Auth service provider not found")
		return
	}

	// Resolve qURL placement exactly once. The same ResourceData feeds both AC
	// selection and ACK ResourceHost construction so future health-aware
	// placement cannot pick AZ A for the AC operation while ACK'ing AZ B.
	resData := qurlplacement.ResolveResource(knkMsg.ResourceId, placementIdentity, aspData)
	if resData == nil {
		var routeErr error
		resData, routeErr = forwardedResolvedResourceData(fwdMsg.ResolvedResourceData, fwdMsg.AdmissionRevocationData, knkMsg)
		if routeErr != nil {
			log.Error("Resource not found for forwarded knock: %s (origin routing unusable: %v)", knkMsg.ResourceId, routeErr)
			f.sendForwardFailure(ppd, fwdMsg.TransactionId, "RESOURCE_NOT_FOUND", "Resource not found")
			return
		}
		f.deps.IncrForwarderMetric(MetricForwardResolvedResourceFallback)
		log.Info("Using origin-resolved resource routing for forwarded knock resource=%s resolvedResource=%s txID=%d",
			knkMsg.ResourceId, resData.ResourceId, fwdMsg.TransactionId)
	}

	resInfo := qurlplacement.OnlyResourceInfo(resData)
	if resInfo == nil || resInfo.Addr == nil {
		log.Error("Resource info not found for forwarded knock: %s", knkMsg.ResourceId)
		f.sendForwardFailure(ppd, fwdMsg.TransactionId, "RESOURCE_INFO_NOT_FOUND", "Resource info not found")
		return
	}
	resourceHost := resInfo.DestHost()
	if resourceHost == "" {
		log.Error("Resource info incomplete for forwarded knock: %s", knkMsg.ResourceId)
		f.sendForwardFailure(ppd, fwdMsg.TransactionId, "RESOURCE_INFO_INCOMPLETE", "Resource info missing usable destination host")
		return
	}
	if bindErr := bindRegisteredAgentProtectedResource(knkMsg, resData); bindErr != nil {
		log.Warning("Rejected forwarded protected resource binding: tx=%d resource=%s err=%v", fwdMsg.TransactionId, knkMsg.ResourceId, bindErr)
		f.sendForwardFailure(ppd, fwdMsg.TransactionId, "INVALID_PROTECTED_RESOURCE", common.ErrResourceNotFound.Error())
		return
	}

	// Find all AC connections for this already-resolved resource. Reads the
	// resource's AC ID, then looks up currently live AC connections.
	acConns := f.deps.FindACConnectionsForResource(knkMsg, resData)
	if acConns == nil || len(acConns) == 0 {
		log.Warning("No AC connection found for forwarded knock (resource=%s, authSvc=%s)",
			knkMsg.ResourceId, knkMsg.AuthServiceId)
		f.sendForwardFailure(ppd, fwdMsg.TransactionId, "AC_NOT_CONNECTED", "AC not connected to this server")
		return
	}

	// Process the knock - send AOP to AC and wait for ART.
	srcAddr := &common.NetAddress{
		Ip:   userAddr.IP.String(),
		Port: userAddr.Port,
	}

	// Build destination addresses
	dstAddrs := []*common.NetAddress{
		{
			Ip:   resInfo.DstIp(),
			Port: resInfo.Addr.Port,
		},
	}

	// #1154 invariant: the forward receiver sources openTime from
	// resData ONLY — never from knkMsg.HeaderType or the inner
	// knockPpd wire HeaderType. This is what makes it safe to skip
	// the Knock HeaderType gate here (see knock_headertype_gate.go
	// scope section). If you ever add a branch that consults
	// HeaderType to alter openTime,
	// you MUST re-apply verifyKnockHeaderType +
	// applyKnockHeaderTypeVerdict against
	// (knockPpd.HeaderType, knkMsg.HeaderType) —
	// otherwise the forward path re-opens the #1154 attack.
	openTime := resData.OpenTime
	if openTime == 0 {
		openTime = 60 // Default open time
	}
	sessionExpiresAt := knkMsg.NHPSessionIssuedAt.Add(time.Duration(openTime) * time.Second)
	if reserveErr := sessionDeps.ReserveForwardedNHPSession(agentPubKey, knkMsg.NHPSessionId, knkMsg.NHPSessionIssuedAt, sessionExpiresAt); reserveErr != nil {
		log.Warning("Rejected forwarded knock NHP session reservation: tx=%d session=%d err=%v", fwdMsg.TransactionId, knkMsg.NHPSessionId, reserveErr)
		f.sendForwardFailure(ppd, fwdMsg.TransactionId, "INVALID_SESSION_RESERVATION", common.ErrACOperationFailed.Error())
		return
	}
	sessionOpened := false
	defer func() {
		if !sessionOpened {
			sessionDeps.ReleaseForwardedNHPSession(agentPubKey, knkMsg.NHPSessionId, knkMsg.NHPSessionIssuedAt)
		}
	}()
	acOperationResData, resourceHashMismatch := forwardedACOperationResourceData(resData, fwdMsg.AdmissionRevocationData)
	if resourceHashMismatch.mismatch {
		f.deps.IncrForwarderMetric(MetricForwardAdmissionResourceHashMismatch)
		log.Debug("forwarded qURL v2 admission resource hash differs from receiver catalog; keeping catalog hash catalog=%s admission=%s",
			resourceHashMismatch.catalogHash, resourceHashMismatch.admissionHash)
	}

	// Step 5: Broadcast AOP to all ACs (supports blue/green with same AC ID).
	// HandleForwardRequest is invoked by the UDP server-to-server path, which
	// does not have an HTTP request context, so use the server's lifecycle
	// context — symmetric with the ResolveOwnerIDByPubKey call below and
	// with the resolver's `f.deps.LifecycleCtx()` plumbing in
	// `ResolveAuthSvcProvider`. The broadcast itself discards parent
	// cancellation regardless (so shutdown won't actually preempt the AC
	// dispatch today), but threading lifecycle ctx keeps log correlation
	// and any future cancellation-respecting code path consistent across
	// the forward-receiver call sites.
	//
	// acOperationResData keeps receiver-local catalog placement authoritative
	// while overlaying the origin admission's qURL v2 revocation metadata when a
	// newer sender carried it on NHP_FWD. The receiver trusts the per-admission
	// fields from an authenticated forwarding cell member over NHP_FWD, the same
	// trust boundary as the forwarded AOP; it does not recompute or revalidate
	// the deadline/user/admission tuple. The receiver's catalog resource hash
	// stays authoritative when present. Legacy senders omit the sidecar and
	// retain the previous catalog-only behavior.
	//
	// DELIBERATELY the bare broadcast, NOT broadcastACOpenWithReknock: this is the
	// UDP server-to-server forward RECEIVER, whose caller is a forwarding server
	// bounded by the 2s ForwardTimeout. A reknock
	// retry adds ~one AC-open transaction timeout + backoff (~1.8s) on top of the
	// first, so its ~3.3s worst case lands well after the forwarder has already
	// given up at 2s — there is no in-flight forwarded transaction left to rescue.
	// The client recovers via its next re-knock against the by-then-settled topology (the first AOP already
	// wrote the pinhole idempotently if the AC applied it); wrapping here would only
	// burn a held goroutine per forwarded timeout during exactly the broad-flip window
	// forwarding peaks in. If ForwardTimeout is ever raised past the reknock worst
	// case, revisit this.
	artMsg, err := f.deps.ProcessACOperationBroadcast(f.deps.LifecycleCtx(), knkMsg, acConns, srcAddr, dstAddrs, openTime, acOperationResData)
	if err != nil {
		log.Error("AC operation failed for forwarded knock: %v", err)
		errCode := "AC_OP_FAILED"
		errMsg := err.Error()
		if artMsg != nil && artMsg.ErrCode != "" {
			errCode = artMsg.ErrCode
			errMsg = artMsg.ErrMsg
		}
		f.sendForwardFailure(ppd, fwdMsg.TransactionId, errCode, errMsg)
		return
	}

	// Check if AC returned an error in the result message (even if no Go error)
	if artMsg != nil && !common.IsSuccessErrCode(artMsg.ErrCode) {
		log.Warning("AC returned error for forwarded knock: %s - %s", artMsg.ErrCode, artMsg.ErrMsg)
		f.sendForwardFailure(ppd, fwdMsg.TransactionId, artMsg.ErrCode, artMsg.ErrMsg)
		return
	}
	// The AC admitted the exact session. Retain it even if token publication or
	// ACK serialization later fails so a concurrent/global EXT can still close
	// the pinhole; natural expiry remains the final bound.
	sessionOpened = true

	// Step 6: Build ACK message to return to user
	ackMsg := &common.ServerKnockAckMsg{
		SessionId:        fwdMsg.SessionId,
		ErrCode:          common.ErrSuccess.ErrorCode(),
		AgentAddr:        userAddr.String(),
		OpenTime:         openTime,
		ResourceHost:     make(map[string]string),
		ACTokens:         make(map[string]string),
		PreAccessActions: make(map[string]*common.PreAccessInfo),
	}
	ackMsg.ResourceHost[knkMsg.ResourceId] = resourceHost
	if artMsg != nil {
		ackMsg.ACTokens[knkMsg.ResourceId] = artMsg.ACToken
		if artMsg.PreAccessAction != nil {
			ackMsg.PreAccessActions[knkMsg.ResourceId] = artMsg.PreAccessAction
		}
		// PR-2a: persist the AC-issued token so PR-2b's
		// /nhp/internal/token/validate can resolve it. Route through
		// PublishACKTokens so the empty-token guard, maps.Clone
		// isolation, and the storeACToken chokepoint apply
		// identically to the native UDP knock path.
		//
		// Resolve owner_id locally from the agent's pubkey (decrypted
		// out of the inner knock packet by decryptForwardedKnock).
		// Without local resolution, the forward-receiver would always
		// stamp "" while the originating server stamps the resolved
		// owner_id — downstream consumers
		// (qurl-reverse-tunnel-server's tunnel-auth plugin) hitting
		// /nhp/internal/token/validate on different NLB-hashed
		// instances would see inconsistent OwnerId for the same
		// logical agent, breaking the consistency contract.
		//
		// ResolveOwnerIDByPubKey hits DDB on cold-cache (one Query
		// per cold pubkey per receiver), then populates the local
		// LRU so subsequent forwarded knocks for the same agent are
		// cache hits. Fail-safe: any lookup failure (unknown pubkey,
		// DDB outage, non-cloud-mode) returns "" — the path falls
		// back to the historical empty-OwnerId behavior, never blocks
		// the forward.
		ownerId := knkMsg.NHPAgentOwnerID
		if ownerId == "" {
			ownerId = f.deps.ResolveOwnerIDByPubKey(
				f.deps.LifecycleCtx(),
				agentPubKey,
			)
		}
		if publishErr := f.deps.PublishACKTokens(f.deps.LifecycleCtx(), knkMsg, ackMsg, srcAddr.Ip, int(openTime), ownerId); publishErr != nil {
			log.Error("Failed to persist ACK token metadata for forwarded knock: %v", publishErr)
			sessionDeps.CompensateForwardedNHPSession(agentPubKey, knkMsg.NHPSessionId, knkMsg.NHPSessionIssuedAt)
			f.sendForwardFailure(ppd, fwdMsg.TransactionId, common.ErrServerTokenPersistFailed.ErrorCode(), common.ErrServerTokenPersistFailed.Error())
			return
		}
	}

	// Serialize the ACK. The registered-agent receipt comes exclusively from
	// the receiver's strong durable verification above; no NHP_FWD field or
	// inner body can choose the cell. Generic knocks keep their legacy shape.
	var ackData []byte
	var marshalErr error
	if knkMsg.AuthServiceId == common.RegisteredAgentAuthServiceID {
		ackMsg.CellId = verifiedReceipt.CellID
		ackMsg.SessionId = verifiedReceipt.SessionID
		ackMsg.SessionIssuedAtMillis = verifiedReceipt.SessionIssuedAtMillis
		ackMsg.RunID = verifiedReceipt.RunID
		ackMsg.RunAttempt = verifiedReceipt.RunAttempt
		ackData, marshalErr = common.MarshalRegisteredAgentKnockAckMsg(
			ackMsg, knkMsg.RunID, knkMsg.RunAttempt, knkMsg.ResourceId,
		)
	} else {
		ackData, marshalErr = json.Marshal(ackMsg)
	}
	if marshalErr != nil {
		log.Error("Failed to marshal ACK for forwarded knock: %v", marshalErr)
		sessionDeps.CompensateForwardedNHPSession(agentPubKey, knkMsg.NHPSessionId, knkMsg.NHPSessionIssuedAt)
		f.sendForwardFailure(ppd, fwdMsg.TransactionId, "MARSHAL_FAILED", marshalErr.Error())
		return
	}

	// Step 7: Send success result with ACK data. A synchronous enqueue error is
	// authoritative: the origin cannot receive a usable ACK, so close this exact
	// local admission. Loss after a successful enqueue is not observable here and
	// remains bounded by the retained session lifetime or a later global EXT.
	log.Info("Successfully processed forwarded knock for user %s (resource=%s)", userAddr, knkMsg.ResourceId)
	if sendErr := f.sendForwardResult(ppd, fwdMsg.TransactionId, true, ackData, "", ""); sendErr != nil {
		log.Warning("failed to enqueue successful NHP_FRT for txID %d; compensating exact session: %v", fwdMsg.TransactionId, sendErr)
		sessionDeps.CompensateForwardedNHPSession(agentPubKey, knkMsg.NHPSessionId, knkMsg.NHPSessionIssuedAt)
	}
}

// decryptForwardedKnock decrypts a knock packet that was forwarded from another server.
// All servers share the same registration keypair, so any server can decrypt knocks.
func (f *ServerForwarder) decryptForwardedKnock(knockData []byte, userAddr *net.UDPAddr) (*core.PacketParserData, error) {
	if len(knockData) == 0 {
		return nil, errors.New("empty knock data")
	}

	// NHP packets require at least a common header (24 bytes minimum)
	// A valid NHP_KNK packet is much larger due to crypto overhead
	const minPacketSize = 24
	if len(knockData) < minPacketSize {
		return nil, fmt.Errorf("packet too short: %d bytes (minimum %d)", len(knockData), minPacketSize)
	}

	// Create a Packet from the raw bytes
	pkt := &core.Packet{
		Content: knockData,
	}

	// Create minimal ConnectionData for decryption
	// The device's registration key is used for decryption
	connData := &core.ConnectionData{
		Device:     f.deps.GetDevice(),
		RemoteAddr: userAddr,
		InitTime:   time.Now().UnixNano(),
	}

	// Create PacketData for decryption
	pd := &core.PacketData{
		BasePacket: pkt,
		ConnData:   connData,
		InitTime:   time.Now().UnixNano(),
	}

	// Decrypt using the device's PacketToMsg
	knockPpd, err := f.deps.GetDevice().PacketToMsg(pd)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}
	if knockPpd == nil {
		return nil, errors.New("decryption failed: no parsed packet returned")
	}

	return knockPpd, nil
}

func forwardedAgentPubKey(knockPpd *core.PacketParserData) (string, bool) {
	if knockPpd == nil || len(knockPpd.RemotePubKey) != 32 {
		return "", false
	}
	return base64.StdEncoding.EncodeToString(knockPpd.RemotePubKey), true
}

// HandleForwardResult processes an incoming NHP_FRT message.
func (f *ServerForwarder) HandleForwardResult(
	ppd *core.PacketParserData,
	resultMsg *common.ServerForwardResultMsg,
) {
	f.pendingMutex.RLock()
	pending, ok := f.pendingFwds[resultMsg.TransactionId]
	f.pendingMutex.RUnlock()

	if !ok {
		if f.deps != nil {
			f.deps.IncrForwarderMetric(MetricServerForwardUnknownResult)
		}
		log.Debug("Received NHP_FRT for unknown transaction %d; expected when a first-success forward already returned", resultMsg.TransactionId)
		return
	}

	// Send result to waiting goroutine
	select {
	case pending.ResponseCh <- resultMsg:
	default:
		log.Warning("NHP_FRT response channel full for txID %d", resultMsg.TransactionId)
	}
}

// sendForwardResult marshals and synchronously enqueues an NHP_FRT response.
// A nil return means only that the server transport accepted the message; it
// does not claim that the datagram reached the forwarding origin.
func (f *ServerForwarder) sendForwardResult(
	ppd *core.PacketParserData,
	txID uint64,
	success bool,
	ackData []byte,
	errCode string,
	errMsg string,
) error {
	resultMsg := &common.ServerForwardResultMsg{
		TransactionId: txID,
		Success:       success,
		ACKData:       ackData,
		ErrCode:       errCode,
		ErrMsg:        errMsg,
	}

	msgBytes, err := json.Marshal(resultMsg)
	if err != nil {
		log.Error("Failed to marshal NHP_FRT: %v", err)
		return err
	}

	md := &core.MsgData{
		HeaderType:     core.NHP_FRT,
		TransactionId:  txID,
		Compress:       false,
		PrevParserData: ppd,
		Message:        msgBytes,
	}

	if err := f.deps.SendMessage(md); err != nil {
		log.Warning("failed to send NHP_FRT for txID %d: %v", txID, err)
		return err
	}
	return nil
}

// sendForwardFailure best-effort reports a forwarded-knock rejection. There is
// no second transport available on this terminal error path, but send failures
// remain operationally visible instead of being silently discarded.
func (f *ServerForwarder) sendForwardFailure(
	ppd *core.PacketParserData,
	txID uint64,
	errCode string,
	errMsg string,
) {
	if err := f.sendForwardResult(ppd, txID, false, nil, errCode, errMsg); err != nil {
		log.Warning("failed to enqueue NHP_FRT failure for txID %d code=%s: %v", txID, errCode, err)
	}
}

// getOrCreateServerPeer gets or creates a peer for a target server.
func (f *ServerForwarder) getOrCreateServerPeer(target ServerInfo) (*core.UdpPeer, error) {
	f.peerMutex.RLock()
	peer, ok := f.serverPeers[target.ID]
	f.peerMutex.RUnlock()

	if ok {
		return peer, nil
	}

	// Create new peer
	f.peerMutex.Lock()
	defer f.peerMutex.Unlock()

	// Double-check after acquiring write lock
	if peer, ok = f.serverPeers[target.ID]; ok {
		return peer, nil
	}

	// Create peer with target server's public key.
	// Hostname is intentionally left empty so ResolveHost() uses the static Ip
	// field directly. target.ID is an identifier, not a DNS-resolvable hostname.
	peer = &core.UdpPeer{
		Ip:           target.InternalIP, // Use internal IP for server-to-server
		Port:         target.Port,
		PubKeyBase64: target.PubKey,
		ExpireTime:   0, // No expiration for server peers
		Type:         core.NHP_SERVER,
	}

	// Add peer to device
	f.deps.GetDevice().AddPeer(peer)
	f.serverPeers[target.ID] = peer

	log.Info("Created server peer for %s (%s:%d)", target.ID, target.InternalIP, target.Port)
	return peer, nil
}

// nextTransactionID generates a unique transaction ID.
func (f *ServerForwarder) nextTransactionID() uint64 {
	f.txIDMutex.Lock()
	defer f.txIDMutex.Unlock()
	f.nextTxID++
	return f.nextTxID
}

// Start begins the forwarder's background routines.
func (f *ServerForwarder) Start() {
	f.wg.Add(1)
	go f.cleanupRoutine()
	log.Info("ServerForwarder started with cleanup routine")
}

// Stop stops the forwarder's background routines.
func (f *ServerForwarder) Stop() {
	close(f.stopCh)
	f.wg.Wait()
	log.Info("ServerForwarder stopped")
}

// cleanupRoutine periodically removes expired pending forwards.
func (f *ServerForwarder) cleanupRoutine() {
	defer f.wg.Done()
	ticker := time.NewTicker(ForwardTimeout * 2)
	defer ticker.Stop()

	for {
		select {
		case <-f.stopCh:
			return
		case <-ticker.C:
			f.CleanupPendingForwards()
		}
	}
}

// CleanupPendingForwards removes expired pending forwards.
func (f *ServerForwarder) CleanupPendingForwards() {
	f.pendingMutex.Lock()
	defer f.pendingMutex.Unlock()

	now := time.Now()
	cleaned := 0
	for txID, pending := range f.pendingFwds {
		if now.Sub(pending.CreatedAt) > ForwardTimeout*2 {
			delete(f.pendingFwds, txID)
			cleaned++
		}
	}
	if cleaned > 0 {
		log.Debug("Cleaned up %d expired pending forwards", cleaned)
	}
}
