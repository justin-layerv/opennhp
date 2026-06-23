package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/OpenNHP/opennhp/endpoints/server/internal/qurlplacement"
	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
	"github.com/OpenNHP/opennhp/nhp/log"
)

// ============================================================================
// Server-to-Server Forwarding
// See docs/design/PLUGGABLE_STORAGE_BACKEND.md sections 6.3-6.5 for details.
//
// When a knock arrives at a server that doesn't have a connection to the
// target AC, the knock is forwarded to one of the AC's assigned servers
// via NHP_FWD. The assigned server handles the knock and returns the
// result via NHP_FRT.
//
// Key design decisions:
// - Uses Noise K pattern for forward secrecy (per-server keypairs)
// - Random shuffle + health tracking for load distribution
// - 30-second health decay for automatic recovery
// - 2-second timeout per forward attempt
// ============================================================================

const (
	// ForwardTimeout is the maximum time to wait for a forward response.
	ForwardTimeout = 2 * time.Second

	// HealthDecayDuration is how long to consider a server unhealthy after failure.
	HealthDecayDuration = 30 * time.Second

	// MaxTimestampAge is the maximum age of an NHP_FWD timestamp (replay protection).
	MaxTimestampAge = 30 * time.Second

	// MaxPendingForwards is the maximum number of concurrent pending forwards.
	// This prevents unbounded memory growth under DDoS or slow downstream.
	MaxPendingForwards = 10000
)

type localForwardSendError struct {
	err error
}

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
	failures map[string]time.Time // Server ID -> last failure time
	mu       sync.RWMutex
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
		failures: make(map[string]time.Time),
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
}

// RecordSuccess records a successful communication (clears failure).
func (h *ServerHealthTracker) RecordSuccess(serverID string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.failures, serverID)
}

// ForwardKnock forwards a knock to one of the AC's assigned servers.
// Returns the ACK data to send to the user, or an error if all servers failed.
func (f *ServerForwarder) ForwardKnock(
	ctx context.Context,
	assignment *ACAssignment,
	knockData []byte,
	userAddr *net.UDPAddr,
) (*common.ServerForwardResultMsg, error) {
	if len(assignment.AssignedServers) == 0 {
		return nil, errors.New("no assigned servers for AC")
	}

	// Copy and shuffle servers for load distribution
	servers := slices.Clone(assignment.AssignedServers)
	rand.Shuffle(len(servers), func(i, j int) {
		servers[i], servers[j] = servers[j], servers[i]
	})

	// Try each server in order, skipping unhealthy ones
	var lastErr error
	for _, target := range servers {
		// Skip servers we've recently seen fail
		if f.health.IsUnhealthy(target.ID) {
			log.Debug("Skipping unhealthy server %s for AC %s", target.ID, assignment.ACID)
			continue
		}

		result, err := f.forwardToServer(ctx, target, assignment.ACID, knockData, userAddr)
		if err != nil {
			log.Warning("Forward to server %s failed for AC %s: %v", target.ID, assignment.ACID, err)
			if !isLocalForwardSendError(err) {
				f.health.RecordFailure(target.ID)
			}
			lastErr = err
			continue
		}

		// Success
		f.health.RecordSuccess(target.ID)
		return result, nil
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, errors.New("all assigned servers unreachable or unhealthy")
}

// forwardToServer sends an NHP_FWD message to a specific server.
func (f *ServerForwarder) forwardToServer(
	ctx context.Context,
	target ServerInfo,
	acID string,
	knockData []byte,
	userAddr *net.UDPAddr,
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
		KnockData:     knockData,
		SourceServer:  f.deps.GetHostname(),
		UserAddr:      userAddr.String(),
		TransactionId: txID,
		Timestamp:     time.Now().Unix(),
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
		return nil, errors.New("too many pending forwards")
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
		return nil, errors.New("forward timeout")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
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
		f.sendForwardResult(ppd, fwdMsg.TransactionId, false, nil, "STALE_TIMESTAMP", "Message too old")
		return
	}
	// Reject messages with future timestamps (clock skew tolerance: 5 seconds)
	const maxFutureSkew = 5 * time.Second
	if timeDiff < -maxFutureSkew {
		log.Warning("Rejecting future NHP_FWD from %s (timestamp %v, skew %v)", fwdMsg.SourceServer, msgTime, -timeDiff)
		f.sendForwardResult(ppd, fwdMsg.TransactionId, false, nil, "FUTURE_TIMESTAMP", "Message timestamp in future")
		return
	}

	// Parse user address
	userAddr, err := net.ResolveUDPAddr("udp", fwdMsg.UserAddr)
	if err != nil {
		log.Error("Invalid user address in NHP_FWD: %s", fwdMsg.UserAddr)
		f.sendForwardResult(ppd, fwdMsg.TransactionId, false, nil, "INVALID_USER_ADDR", err.Error())
		return
	}

	log.Info("Processing NHP_FWD from %s for user %s (txID=%d)", fwdMsg.SourceServer, userAddr, fwdMsg.TransactionId)

	// Step 1: Decrypt the forwarded knock packet
	// All servers share the registration keypair, so we can decrypt any knock
	knockPpd, err := f.decryptForwardedKnock(fwdMsg.KnockData, userAddr)
	if err != nil {
		log.Error("Failed to decrypt forwarded knock from %s: %v", fwdMsg.SourceServer, err)
		f.sendForwardResult(ppd, fwdMsg.TransactionId, false, nil, "DECRYPT_FAILED", err.Error())
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
		log.Error("Failed to parse forwarded knock message: %v", err)
		f.sendForwardResult(ppd, fwdMsg.TransactionId, false, nil, "PARSE_FAILED", err.Error())
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
		f.sendForwardResult(ppd, fwdMsg.TransactionId, false, nil, "INVALID_AGENT_PUBKEY", "Forwarded knock missing authenticated agent public key")
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
		f.sendForwardResult(ppd, fwdMsg.TransactionId, false, nil, "ASP_NOT_FOUND", "Auth service provider not found")
		return
	}

	// Resolve qURL placement exactly once. The same ResourceData feeds both AC
	// selection and ACK ResourceHost construction so future health-aware
	// placement cannot pick AZ A for the AC operation while ACK'ing AZ B.
	resData := qurlplacement.ResolveResource(knkMsg.ResourceId, placementIdentity, aspData)
	if resData == nil {
		log.Error("Resource not found for forwarded knock: %s", knkMsg.ResourceId)
		f.sendForwardResult(ppd, fwdMsg.TransactionId, false, nil, "RESOURCE_NOT_FOUND", "Resource not found")
		return
	}

	resInfo := qurlplacement.OnlyResourceInfo(resData)
	if resInfo == nil || resInfo.Addr == nil {
		log.Error("Resource info not found for forwarded knock: %s", knkMsg.ResourceId)
		f.sendForwardResult(ppd, fwdMsg.TransactionId, false, nil, "RESOURCE_INFO_NOT_FOUND", "Resource info not found")
		return
	}
	resourceHost := resInfo.DestHost()
	if resourceHost == "" {
		log.Error("Resource info incomplete for forwarded knock: %s", knkMsg.ResourceId)
		f.sendForwardResult(ppd, fwdMsg.TransactionId, false, nil, "RESOURCE_INFO_INCOMPLETE", "Resource info missing usable destination host")
		return
	}

	// Find all AC connections for this already-resolved resource. Reads the
	// resource's AC ID, then looks up currently live AC connections.
	acConns := f.deps.FindACConnectionsForResource(knkMsg, resData)
	if acConns == nil || len(acConns) == 0 {
		log.Warning("No AC connection found for forwarded knock (resource=%s, authSvc=%s)",
			knkMsg.ResourceId, knkMsg.AuthServiceId)
		f.sendForwardResult(ppd, fwdMsg.TransactionId, false, nil, "AC_NOT_CONNECTED", "AC not connected to this server")
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
	// HeaderType to alter openTime (e.g., porting the
	// "NHP_EXT ⇒ openTime=1" short-circuit from the local path),
	// you MUST re-apply verifyKnockHeaderType +
	// applyKnockHeaderTypeVerdict against
	// (knockPpd.HeaderType, knkMsg.HeaderType) —
	// otherwise the forward path re-opens the #1154 attack.
	openTime := resData.OpenTime
	if openTime == 0 {
		openTime = 60 // Default open time
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
	// resData here is the catalog ResourceData from ResolveResource (not a v2
	// admission decision), so it carries ResourcePublicKeyHash but not the
	// per-admission revocation fields. Passing it lets the resource hash reach
	// the AOP on the forward path; the rest stay omitted (see deps interface).
	artMsg, err := f.deps.ProcessACOperationBroadcast(f.deps.LifecycleCtx(), knkMsg, acConns, srcAddr, dstAddrs, openTime, resData)
	if err != nil {
		log.Error("AC operation failed for forwarded knock: %v", err)
		errCode := "AC_OP_FAILED"
		errMsg := err.Error()
		if artMsg != nil && artMsg.ErrCode != "" {
			errCode = artMsg.ErrCode
			errMsg = artMsg.ErrMsg
		}
		f.sendForwardResult(ppd, fwdMsg.TransactionId, false, nil, errCode, errMsg)
		return
	}

	// Check if AC returned an error in the result message (even if no Go error)
	if artMsg != nil && !common.IsSuccessErrCode(artMsg.ErrCode) {
		log.Warning("AC returned error for forwarded knock: %s - %s", artMsg.ErrCode, artMsg.ErrMsg)
		f.sendForwardResult(ppd, fwdMsg.TransactionId, false, nil, artMsg.ErrCode, artMsg.ErrMsg)
		return
	}

	// Step 6: Build ACK message to return to user
	ackMsg := &common.ServerKnockAckMsg{
		ErrCode:          common.ErrSuccess.ErrorCode(),
		AgentAddr:        userAddr.String(),
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
		// identically to the local UDP/HTTP knock paths.
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
		ownerId := f.deps.ResolveOwnerIDByPubKey(
			f.deps.LifecycleCtx(),
			agentPubKey,
		)
		if publishErr := f.deps.PublishACKTokens(f.deps.LifecycleCtx(), knkMsg, ackMsg, srcAddr.Ip, int(openTime), ownerId); publishErr != nil {
			log.Error("Failed to persist ACK token metadata for forwarded knock: %v", publishErr)
			f.sendForwardResult(ppd, fwdMsg.TransactionId, false, nil, common.ErrServerTokenPersistFailed.ErrorCode(), common.ErrServerTokenPersistFailed.Error())
			return
		}
	}

	// Serialize ACK message
	ackData, err := json.Marshal(ackMsg)
	if err != nil {
		log.Error("Failed to marshal ACK for forwarded knock: %v", err)
		f.sendForwardResult(ppd, fwdMsg.TransactionId, false, nil, "MARSHAL_FAILED", err.Error())
		return
	}

	// Step 7: Send success result with ACK data
	log.Info("Successfully processed forwarded knock for user %s (resource=%s)", userAddr, knkMsg.ResourceId)
	f.sendForwardResult(ppd, fwdMsg.TransactionId, true, ackData, "", "")
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
		log.Warning("Received NHP_FRT for unknown transaction %d", resultMsg.TransactionId)
		return
	}

	// Send result to waiting goroutine
	select {
	case pending.ResponseCh <- resultMsg:
	default:
		log.Warning("NHP_FRT response channel full for txID %d", resultMsg.TransactionId)
	}
}

// sendForwardResult sends an NHP_FRT response.
func (f *ServerForwarder) sendForwardResult(
	ppd *core.PacketParserData,
	txID uint64,
	success bool,
	ackData []byte,
	errCode string,
	errMsg string,
) {
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
		return
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
