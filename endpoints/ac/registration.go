package ac

import (
	"encoding/json"
	"errors"
	"math/rand"
	"sync"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
	"github.com/OpenNHP/opennhp/nhp/log"
)

// ============================================================================
// Multi-Server Connection Management (Phase 2)
// See docs/design/PLUGGABLE_STORAGE_BACKEND.md section 6.2 for details.
//
// In Phase 2, each AC connects to 3 assigned servers (in different AZs).
// When AC starts, it:
// 1. Connects to FQDN (via NLB, hits any server)
// 2. Sends NHP_AOL with credentials
// 3. Server responds NHP_ARD with assigned servers
// 4. AC terminates initial connection
// 5. AC connects to all 3 assigned servers
// 6. Maintains keepalives to all 3 servers
// ============================================================================

const (
	// RegistrationTimeout is the timeout for initial registration.
	RegistrationTimeout = 30 * time.Second

	// KeepaliveInterval is how often to send keepalives to each server.
	KeepaliveInterval = 10 * time.Second

	// KeepaliveTimeout is the timeout for keepalive response.
	KeepaliveTimeout = 3 * time.Second

	// KeepaliveMaxRetries is the max retries before considering server down.
	KeepaliveMaxRetries = 3

	// ReregistrationJitter is random jitter before re-registration (0-5s).
	ReregistrationJitter = 5 * time.Second

	// OldServerKeepDuration is how long to keep old connections during reassignment.
	OldServerKeepDuration = 2 * time.Minute
)

// AssignedServer represents a server assigned to this AC.
type AssignedServer struct {
	Target      common.RedirectTarget
	Peer        *core.UdpPeer
	Connected   bool
	LastSeen    time.Time
	FailCount   int
}

// ACRegistration manages AC registration with NHP servers.
type ACRegistration struct {
	ac              *UdpAC
	assignedServers []*AssignedServer
	// oldServerSets tracks multiple sets of old servers during overlapping reassignments.
	// Key is a unique cleanup ID (timestamp-based), value is the servers to clean up.
	// This prevents a race condition where rapid reassignments could cause the wrong
	// servers to be cleaned up. See cleanupOldServers for details.
	oldServerSets map[string][]*AssignedServer
	mu            sync.RWMutex
	stopCh        chan struct{}
	wg            sync.WaitGroup
}

// NewACRegistration creates a new AC registration manager.
func NewACRegistration(ac *UdpAC) *ACRegistration {
	return &ACRegistration{
		ac:              ac,
		assignedServers: make([]*AssignedServer, 0),
		oldServerSets:   make(map[string][]*AssignedServer),
		stopCh:          make(chan struct{}),
	}
}

// Start begins the registration process and keepalive loop.
func (r *ACRegistration) Start() error {
	// If we have assigned servers configured, use those
	// Otherwise, we need to register via FQDN to get assignment
	if r.ac.config.ResourceFQDN != "" && r.ac.config.CustomerId != "" {
		log.Info("Phase 2 mode: will register with FQDN %s", r.ac.config.ResourceFQDN)
		// Start registration in background
		go r.registrationLoop()
	} else {
		log.Info("Phase 1 mode: using static server configuration")
	}

	return nil
}

// Stop stops the registration manager.
func (r *ACRegistration) Stop() {
	close(r.stopCh)
	r.wg.Wait()
}

// GetAssignedServers returns the current assigned servers.
func (r *ACRegistration) GetAssignedServers() []*AssignedServer {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.assignedServers
}

// HasAssignedServers returns true if AC has assigned servers.
func (r *ACRegistration) HasAssignedServers() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.assignedServers) > 0
}

// registrationLoop attempts registration and maintains connections.
func (r *ACRegistration) registrationLoop() {
	r.wg.Add(1)
	defer r.wg.Done()

	// Initial registration with exponential backoff and jitter
	backoff := time.Second
	for {
		select {
		case <-r.stopCh:
			return
		default:
		}

		err := r.register()
		if err == nil {
			break
		}

		// Add ±20% jitter to prevent thundering herd
		jitter := time.Duration(float64(backoff) * (0.8 + 0.4*rand.Float64()))
		log.Warning("Registration failed: %v, retrying in %v (with jitter)", err, jitter)
		select {
		case <-r.stopCh:
			return
		case <-time.After(jitter):
			backoff *= 2
			if backoff > 30*time.Second {
				backoff = 30 * time.Second
			}
		}
	}

	// Start keepalive loop
	r.keepaliveLoop()
}

// register performs initial registration via FQDN.
func (r *ACRegistration) register() error {
	// Create AOL message with Phase 2 credentials
	aolMsg := &common.ACOnlineMsg{
		ACId:          r.ac.config.ACId,
		AuthServiceId: r.ac.config.AuthServiceId,
		ResourceIds:   r.ac.config.ResourceIds,
		CustomerId:    r.ac.config.CustomerId,
		LicenseKey:    r.ac.config.LicenseKey,
		ResourceFQDN:  r.ac.config.ResourceFQDN,
		ACVersion:     r.ac.config.ACVersion,
	}

	log.Info("Registering AC %s with resource FQDN %s", aolMsg.ACId, aolMsg.ResourceFQDN)

	// TODO: Send NHP_AOL to FQDN and handle NHP_ARD response
	// For now, return nil to indicate success (will be implemented with server integration)
	_ = aolMsg

	return nil
}

// HandleRedispatch processes an NHP_ARD message and connects to assigned servers.
func (r *ACRegistration) HandleRedispatch(ardMsg *common.ACRedispatchMsg) error {
	if ardMsg.ErrCode != "" && ardMsg.ErrCode != "SUCCESS" {
		return errors.New("redispatch failed: " + ardMsg.ErrMsg)
	}

	if len(ardMsg.Targets) == 0 {
		return errors.New("no targets in redispatch message")
	}

	log.Info("Received NHP_ARD with %d assigned servers", len(ardMsg.Targets))

	r.mu.Lock()
	// Move current servers to old servers map for graceful transition.
	// Using a unique key ensures each cleanup goroutine only cleans up its own set,
	// preventing a race condition with rapid reassignments.
	var cleanupKey string
	hasOldServers := len(r.assignedServers) > 0
	if hasOldServers {
		cleanupKey = time.Now().Format(time.RFC3339Nano)
		r.oldServerSets[cleanupKey] = r.assignedServers
	}
	r.assignedServers = make([]*AssignedServer, len(ardMsg.Targets))

	for i, target := range ardMsg.Targets {
		r.assignedServers[i] = &AssignedServer{
			Target:    target,
			Connected: false,
		}
		log.Info("Assigned server %d: %s:%d (AZ=%s)", i, target.IP, target.Port, target.AZ)
	}
	// Capture slice reference before unlocking. This is safe because:
	// 1. Each HandleRedispatch creates NEW *AssignedServer structs (not shared)
	// 2. connectToServer modifies only these new structs (Connected, Peer, LastSeen)
	// 3. cleanupOldServers sleeps 2min before accessing old servers - by then
	//    connectToServer (non-blocking channel send) has long finished
	// 4. Concurrent HandleRedispatch calls get their own independent structs
	serversToConnect := r.assignedServers
	r.mu.Unlock()

	successCount := 0
	for _, server := range serversToConnect {
		if err := r.connectToServer(server); err != nil {
			log.Warning("Failed to connect to assigned server %s: %v", server.Target.IP, err)
		} else {
			successCount++
		}
	}

	// Fail if no connections succeeded - AC would be unreachable
	if successCount == 0 {
		return errors.New("failed to connect to any assigned servers")
	}

	// Warn if partial failure (some but not all servers connected)
	if successCount < len(serversToConnect) {
		log.Warning("Partial connection success: %d/%d assigned servers connected", successCount, len(serversToConnect))
	} else {
		log.Info("Successfully connected to all %d assigned servers", successCount)
	}

	// Schedule old server cleanup (only if we had old servers to clean up)
	if hasOldServers {
		go r.cleanupOldServers(cleanupKey)
	}

	return nil
}

// connectToServer establishes connection to an assigned server.
func (r *ACRegistration) connectToServer(server *AssignedServer) error {
	// Create peer for this server
	peer := &core.UdpPeer{
		Hostname:     server.Target.ServerID,
		Ip:           server.Target.IP,
		Port:         server.Target.Port,
		PubKeyBase64: server.Target.PubKeyBase64,
		ExpireTime:   0,
		Type:         core.NHP_SERVER,
	}

	// Add peer to device
	r.ac.device.AddPeer(peer)
	server.Peer = peer

	// Send NHP_AOL to register with this server
	aolMsg := &common.ACOnlineMsg{
		ACId:          r.ac.config.ACId,
		AuthServiceId: r.ac.config.AuthServiceId,
		ResourceIds:   r.ac.config.ResourceIds,
		CustomerId:    r.ac.config.CustomerId,
		LicenseKey:    r.ac.config.LicenseKey,
		ResourceFQDN:  r.ac.config.ResourceFQDN,
		ACVersion:     r.ac.config.ACVersion,
	}

	msgBytes, err := json.Marshal(aolMsg)
	if err != nil {
		return err
	}

	md := &core.MsgData{
		HeaderType:     core.NHP_AOL,
		TransactionId:  uint64(time.Now().UnixNano()),
		Compress:       false,
		PrevParserData: nil,
		Message:        msgBytes,
		PeerPk:         peer.PublicKey(),
	}

	r.ac.sendMsgCh <- md

	server.Connected = true
	server.LastSeen = time.Now()
	log.Info("Connected to assigned server %s:%d", server.Target.IP, server.Target.Port)

	return nil
}

// keepaliveLoop sends keepalives to all assigned servers.
func (r *ACRegistration) keepaliveLoop() {
	ticker := time.NewTicker(KeepaliveInterval)
	defer ticker.Stop()

	for {
		select {
		case <-r.stopCh:
			return
		case <-ticker.C:
			r.sendKeepalives()
		}
	}
}

// sendKeepalives sends keepalive to each assigned server.
func (r *ACRegistration) sendKeepalives() {
	r.mu.RLock()
	servers := r.assignedServers
	r.mu.RUnlock()

	for _, server := range servers {
		if server.Peer == nil {
			continue
		}

		// TODO: Send NHP_KPL (keepalive) to server
		// For now, just update last seen
		server.LastSeen = time.Now()
	}
}

// checkServerHealth checks if any server is down and triggers re-registration.
func (r *ACRegistration) checkServerHealth() {
	r.mu.RLock()
	servers := r.assignedServers
	r.mu.RUnlock()

	for _, server := range servers {
		if time.Since(server.LastSeen) > KeepaliveInterval*KeepaliveMaxRetries {
			log.Warning("Server %s appears down, triggering re-registration", server.Target.IP)
			go r.handleServerDown(server)
			return // Re-register once, not for each down server
		}
	}
}

// handleServerDown handles when a server is detected as down.
// Per design doc: AC re-registers via FQDN on ANY server failure.
func (r *ACRegistration) handleServerDown(deadServer *AssignedServer) {
	// Add jitter to prevent thundering herd
	jitter := time.Duration(rand.Intn(int(ReregistrationJitter.Milliseconds()))) * time.Millisecond
	time.Sleep(jitter)

	log.Info("Re-registering due to server %s failure", deadServer.Target.IP)

	// Exponential backoff for re-registration attempts
	for attempt := 1; attempt <= 5; attempt++ {
		select {
		case <-r.stopCh:
			return
		default:
		}

		err := r.register()
		if err == nil {
			return
		}

		backoff := time.Duration(attempt*attempt) * time.Second
		log.Warning("Re-registration attempt %d failed: %v, retrying in %v", attempt, err, backoff)
		time.Sleep(backoff + jitter)
	}

	log.Error("Re-registration failed after 5 attempts, continuing with remaining servers")
}

// cleanupOldServers removes old server connections after grace period.
// Each cleanup goroutine receives a unique key to identify which set of servers
// to clean up, preventing race conditions with overlapping reassignments.
func (r *ACRegistration) cleanupOldServers(cleanupKey string) {
	time.Sleep(OldServerKeepDuration)

	r.mu.Lock()
	oldServers := r.oldServerSets[cleanupKey]
	delete(r.oldServerSets, cleanupKey)
	r.mu.Unlock()

	for _, server := range oldServers {
		if server.Peer != nil {
			r.ac.device.RemovePeer(server.Peer.PublicKeyBase64())
			log.Info("Cleaned up old server connection to %s", server.Target.IP)
		}
	}
}
