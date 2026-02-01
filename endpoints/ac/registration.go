package ac

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
	"github.com/OpenNHP/opennhp/nhp/log"
)

// ============================================================================
// Multi-Server Connection Management
// See docs/design/PLUGGABLE_STORAGE_BACKEND.md section 6.2 for details.
//
// Each AC connects to 3 assigned servers (in different AZs).
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

	// MaxReregistrationAttempts is the max attempts for re-registration after server failure.
	MaxReregistrationAttempts = 5
)

// AssignedServer represents a server assigned to this AC.
type AssignedServer struct {
	mu        sync.RWMutex // Protects mutable fields below
	Target    common.RedirectTarget
	Peer      *core.UdpPeer
	Connected bool
	LastSeen  time.Time
	FailCount int
}

// SetConnected safely sets the Connected field.
func (s *AssignedServer) SetConnected(connected bool) {
	s.mu.Lock()
	s.Connected = connected
	s.mu.Unlock()
}

// IsConnected safely gets the Connected field.
func (s *AssignedServer) IsConnected() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Connected
}

// UpdateLastSeen safely updates the LastSeen time and resets FailCount.
func (s *AssignedServer) UpdateLastSeen() {
	s.mu.Lock()
	s.LastSeen = time.Now()
	s.FailCount = 0
	s.mu.Unlock()
}

// GetLastSeen safely gets the LastSeen time.
func (s *AssignedServer) GetLastSeen() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.LastSeen
}

// IncrementFailCount safely increments the FailCount.
func (s *AssignedServer) IncrementFailCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.FailCount++
	return s.FailCount
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

	// reregistering prevents concurrent re-registration attempts
	reregistering atomic.Bool

	// stopped prevents double Stop() calls from panicking (closing stopCh twice)
	stopped atomic.Bool

	// registrationPeer tracks the peer from NHP_AAK response (the server that is
	// assigned to us and will send NHP_AOP packets). This is separate from
	// connectedServers because the registration server responds with NHP_AAK
	// directly, not NHP_ARD. We need to track it for cleanup when AC stops
	// or re-registers to a different server.
	registrationPeer *core.UdpPeer
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
	// Validate required config
	if r.ac.config.ServerEndpoint == "" {
		return errors.New("ServerEndpoint is required")
	}

	log.Info("Starting AC registration with endpoint %s", r.ac.config.ServerEndpoint)

	// Add to wait group BEFORE starting goroutine to prevent race with Stop()
	r.wg.Add(1)
	go r.registrationLoop()

	return nil
}

// Stop stops the registration manager. Safe to call multiple times.
func (r *ACRegistration) Stop() {
	// Prevent double Stop() from panicking (closing stopCh twice)
	if r.stopped.Swap(true) {
		return
	}

	log.Info("Stopping AC registration manager")
	close(r.stopCh)
	r.wg.Wait()

	// Clean up all peers
	r.mu.Lock()
	// Clean up registration peer (from NHP_AAK response)
	if r.registrationPeer != nil {
		r.ac.device.RemovePeer(r.registrationPeer.PublicKeyBase64())
		r.registrationPeer = nil
	}
	// Clean up connected server peers
	for _, server := range r.assignedServers {
		if server.Peer != nil {
			r.ac.device.RemovePeer(server.Peer.PublicKeyBase64())
			server.Peer = nil
		}
	}
	r.assignedServers = nil
	// Clean up any pending old server sets (from overlapping reassignments)
	for cleanupKey, oldServers := range r.oldServerSets {
		for _, server := range oldServers {
			if server.Peer != nil {
				r.ac.device.RemovePeer(server.Peer.PublicKeyBase64())
				server.Peer = nil
			}
		}
		delete(r.oldServerSets, cleanupKey)
	}
	r.mu.Unlock()

	log.Debug("AC registration manager stopped")
}

// GetAssignedServers returns a copy of the current assigned servers slice.
func (r *ACRegistration) GetAssignedServers() []*AssignedServer {
	r.mu.RLock()
	defer r.mu.RUnlock()
	servers := make([]*AssignedServer, len(r.assignedServers))
	copy(servers, r.assignedServers)
	return servers
}

// HasAssignedServers returns true if AC has assigned servers.
func (r *ACRegistration) HasAssignedServers() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.assignedServers) > 0
}

// UpdateServerLastSeen updates the LastSeen time for a server based on its public key.
// This should be called when any message is received from a server (NHP_AOP, NHP_AAK, etc.).
func (r *ACRegistration) UpdateServerLastSeen(pubKeyBase64 string) {
	r.mu.RLock()
	servers := make([]*AssignedServer, len(r.assignedServers))
	copy(servers, r.assignedServers)
	r.mu.RUnlock()

	for _, server := range servers {
		if server.Target.PubKeyBase64 == pubKeyBase64 {
			server.UpdateLastSeen()
			log.Debug("Updated LastSeen for server %s", server.Target.IP)
			return
		}
	}
}

// UpdateServerLastSeenByAddr updates the LastSeen time for a server based on its address.
// This is useful when we receive a message but don't have the public key readily available.
func (r *ACRegistration) UpdateServerLastSeenByAddr(addr string) {
	r.mu.RLock()
	servers := make([]*AssignedServer, len(r.assignedServers))
	copy(servers, r.assignedServers)
	r.mu.RUnlock()

	for _, server := range servers {
		serverAddr := fmt.Sprintf("%s:%d", server.Target.IP, server.Target.Port)
		if serverAddr == addr {
			server.UpdateLastSeen()
			log.Debug("Updated LastSeen for server at %s", addr)
			return
		}
	}
}

// registrationLoop attempts registration and maintains connections.
func (r *ACRegistration) registrationLoop() {
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

// DefaultServerPort is the default NHP server port.
const DefaultServerPort = 62206

// register performs initial registration via ServerEndpoint.
// It sends NHP_AOL to the ServerEndpoint and handles NHP_ARD (redispatch) or NHP_AAK response.
func (r *ACRegistration) register() error {
	// Validate config (ServerEndpoint already validated in Start())
	if r.ac.config.ServerPubKeyBase64 == "" {
		return errors.New("ServerPubKeyBase64 is required")
	}

	// Determine server port (default 62206)
	serverPort := r.ac.config.ServerPort
	if serverPort == 0 {
		serverPort = DefaultServerPort
	}

	// Create temporary peer for endpoint registration
	// This uses the shared registration public key (all servers share this for NLB)
	registrationPeer := &core.UdpPeer{
		Hostname:     r.ac.config.ServerEndpoint,
		Port:         serverPort,
		PubKeyBase64: r.ac.config.ServerPubKeyBase64,
		Type:         core.NHP_SERVER,
	}

	// Resolve endpoint to address
	sendAddr := registrationPeer.SendAddr()
	if sendAddr == nil {
		return fmt.Errorf("cannot resolve endpoint %s", r.ac.config.ServerEndpoint)
	}

	log.Info("Registering AC %s via endpoint %s (resolved to %s)", r.ac.config.ACId, r.ac.config.ServerEndpoint, sendAddr.String())

	// Create AOL message with registration credentials
	aolMsg := &common.ACOnlineMsg{
		ACId:          r.ac.config.ACId,
		AuthServiceId: r.ac.config.AuthServiceId,
		ResourceIds:   r.ac.config.ResourceIds,
		LicenseKey:    r.ac.config.LicenseKey,
		ACVersion:     r.ac.config.ACVersion,
	}

	aolBytes, err := json.Marshal(aolMsg)
	if err != nil {
		return fmt.Errorf("failed to marshal NHP_AOL: %w", err)
	}

	// Add peer to device for encryption
	// The peer will be kept if NHP_AAK is received (this server is assigned to us)
	// The peer will be removed if NHP_ARD is received (we'll connect to different servers)
	r.ac.device.AddPeer(registrationPeer)

	// Create message data for sending
	// Use buffered channel (size 1) to prevent sender from blocking if we exit early
	md := &core.MsgData{
		RemoteAddr:    sendAddr.(*net.UDPAddr),
		HeaderType:    core.NHP_AOL,
		TransactionId: r.ac.device.NextCounterIndex(),
		Compress:      true,
		PeerPk:        registrationPeer.PublicKey(),
		Message:       aolBytes,
		ResponseMsgCh: make(chan *core.PacketParserData, 1),
	}

	// Send NHP_AOL
	if !r.ac.IsRunning() {
		r.ac.device.RemovePeer(registrationPeer.PublicKeyBase64())
		return errors.New("AC not running")
	}
	r.ac.sendMsgCh <- md

	// Wait for response with timeout
	// Note: We don't close ResponseMsgCh here because the sender (in another goroutine)
	// may write to it after we exit. The buffered channel (size 1) prevents blocking,
	// and the channel will be garbage collected when no longer referenced.
	select {
	case <-r.stopCh:
		r.ac.device.RemovePeer(registrationPeer.PublicKeyBase64())
		return errors.New("registration cancelled")
	case <-time.After(RegistrationTimeout):
		r.ac.device.RemovePeer(registrationPeer.PublicKeyBase64())
		return errors.New("registration timeout")
	case ppd := <-md.ResponseMsgCh:
		return r.handleRegistrationResponse(ppd, registrationPeer)
	}
}

// handleRegistrationResponse processes the server's response to NHP_AOL.
// The response can be:
// - NHP_ARD: Server is not assigned to this AC, contains list of assigned servers
// - NHP_AAK: Server is assigned to this AC
//
// The registrationPeer is removed if NHP_ARD is received (we'll connect to different servers),
// but kept if NHP_AAK is received (this server will send us NHP_AOP packets).
func (r *ACRegistration) handleRegistrationResponse(ppd *core.PacketParserData, registrationPeer *core.UdpPeer) error {
	if ppd.Error != nil {
		r.ac.device.RemovePeer(registrationPeer.PublicKeyBase64())
		return fmt.Errorf("registration failed: %w", ppd.Error)
	}

	switch ppd.HeaderType {
	case core.NHP_ARD:
		// Server is not assigned to this AC - parse redispatch message
		// Remove the registration peer since we'll connect to different servers
		r.ac.device.RemovePeer(registrationPeer.PublicKeyBase64())

		var ardMsg common.ACRedispatchMsg
		if err := json.Unmarshal(ppd.BodyMessage, &ardMsg); err != nil {
			return fmt.Errorf("failed to parse NHP_ARD: %w", err)
		}

		log.Info("Received NHP_ARD with %d assigned servers", len(ardMsg.Targets))

		// Connect to all assigned servers
		if err := r.HandleRedispatch(&ardMsg); err != nil {
			return fmt.Errorf("failed to handle redispatch: %w", err)
		}

		log.Info("Successfully connected to assigned servers")
		return nil

	case core.NHP_AAK:
		// Server responded with ACK - this server is assigned to us
		// Keep the registration peer because this server will send us NHP_AOP packets
		var aakMsg common.ServerACAckMsg
		if err := json.Unmarshal(ppd.BodyMessage, &aakMsg); err != nil {
			r.ac.device.RemovePeer(registrationPeer.PublicKeyBase64())
			return fmt.Errorf("failed to parse NHP_AAK: %w", err)
		}

		if !common.IsSuccessErrCode(aakMsg.ErrCode) {
			r.ac.device.RemovePeer(registrationPeer.PublicKeyBase64())
			return fmt.Errorf("registration rejected: %s - %s", aakMsg.ErrCode, aakMsg.ErrMsg)
		}

		if !aakMsg.Registered {
			r.ac.device.RemovePeer(registrationPeer.PublicKeyBase64())
			return errors.New("server returned NHP_AAK with Registered=false")
		}

		// Track the registration peer for cleanup when AC stops or re-registers.
		// NOTE: The peer is intentionally tracked in TWO places:
		//   - registrationPeer: for cleanup on re-registration (RemovePeer above)
		//   - assignedServers: for keepalive management (sendKeepalives iterates this)
		// This dual-tracking is necessary because registrationPeer cleanup happens
		// before we add the new server to assignedServers.
		r.mu.Lock()
		// Clean up old registration peer if exists (re-registration case)
		if r.registrationPeer != nil {
			r.ac.device.RemovePeer(r.registrationPeer.PublicKeyBase64())
		}
		r.registrationPeer = registrationPeer

		// Replace assignedServers with the registration server for keepalive management.
		// When NHP_AAK is received directly (no NHP_ARD redispatch), the registration
		// server IS our assigned server. Without this, keepaliveLoop() has no servers
		// to send keepalives to, causing the connection to timeout after 5 minutes.
		// We replace (not append) to avoid duplicate entries on re-registration.
		sendAddr := registrationPeer.SendAddr()
		if sendAddr != nil {
			udpAddr := sendAddr.(*net.UDPAddr)
			assignedServer := &AssignedServer{
				Target: common.RedirectTarget{
					IP:           udpAddr.IP.String(),
					Port:         udpAddr.Port,
					PubKeyBase64: registrationPeer.PublicKeyBase64(),
				},
				Peer:      registrationPeer,
				Connected: true,
				LastSeen:  time.Now(),
			}
			r.assignedServers = []*AssignedServer{assignedServer}
			log.Info("Set registration server as assignedServer for keepalive: %s:%d", udpAddr.IP.String(), udpAddr.Port)
		} else {
			log.Warning("Registration peer has nil SendAddr, cannot add to assignedServers for keepalive")
		}
		r.mu.Unlock()

		log.Info("Received NHP_AAK: ACAddr=%s, Registered=%v (peer kept for NHP_AOP)", aakMsg.ACAddr, aakMsg.Registered)
		return nil

	default:
		r.ac.device.RemovePeer(registrationPeer.PublicKeyBase64())
		return fmt.Errorf("unexpected response type: %s", core.HeaderTypeToString(ppd.HeaderType))
	}
}

// HandleRedispatch processes an NHP_ARD message and connects to assigned servers.
func (r *ACRegistration) HandleRedispatch(ardMsg *common.ACRedispatchMsg) error {
	if !common.IsSuccessErrCode(ardMsg.ErrCode) {
		return errors.New("redispatch failed: " + ardMsg.ErrMsg)
	}

	if len(ardMsg.Targets) == 0 {
		return errors.New("no targets in redispatch message")
	}

	// Validate all targets before proceeding
	for i, target := range ardMsg.Targets {
		if target.IP == "" {
			return fmt.Errorf("target %d has empty IP", i)
		}
		if target.Port == 0 {
			return fmt.Errorf("target %d has invalid port", i)
		}
		if target.PubKeyBase64 == "" {
			return fmt.Errorf("target %d has empty public key", i)
		}
		// Validate IP address format
		if ip := net.ParseIP(target.IP); ip == nil {
			return fmt.Errorf("target %d has invalid IP address: %s", i, target.IP)
		}
	}

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

// ConnectionTimeout is the timeout for connecting to an assigned server.
const ConnectionTimeout = 10 * time.Second

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

	// Resolve server address
	sendAddr := peer.SendAddr()
	if sendAddr == nil {
		return fmt.Errorf("cannot resolve address for server %s", server.Target.IP)
	}

	// Add peer to device
	r.ac.device.AddPeer(peer)
	server.Peer = peer

	// Send NHP_AOL to register with this server
	aolMsg := &common.ACOnlineMsg{
		ACId:          r.ac.config.ACId,
		AuthServiceId: r.ac.config.AuthServiceId,
		ResourceIds:   r.ac.config.ResourceIds,
		LicenseKey:    r.ac.config.LicenseKey,
		ACVersion:     r.ac.config.ACVersion,
	}

	msgBytes, err := json.Marshal(aolMsg)
	if err != nil {
		return err
	}

	// Use buffered channel (size 1) to prevent sender from blocking if we exit early
	md := &core.MsgData{
		RemoteAddr:    sendAddr.(*net.UDPAddr),
		HeaderType:    core.NHP_AOL,
		TransactionId: r.ac.device.NextCounterIndex(),
		Compress:      true,
		PeerPk:        peer.PublicKey(),
		Message:       msgBytes,
		ResponseMsgCh: make(chan *core.PacketParserData, 1),
	}

	if !r.ac.IsRunning() {
		return errors.New("AC not running")
	}
	r.ac.sendMsgCh <- md

	// Wait for NHP_AAK response with timeout
	// Note: We don't close ResponseMsgCh here because the sender (in another goroutine)
	// may write to it after we exit. The buffered channel (size 1) prevents blocking,
	// and the channel will be garbage collected when no longer referenced.
	select {
	case <-r.stopCh:
		r.ac.device.RemovePeer(peer.PublicKeyBase64())
		server.Peer = nil
		return errors.New("connection cancelled")
	case <-time.After(ConnectionTimeout):
		r.ac.device.RemovePeer(peer.PublicKeyBase64())
		server.Peer = nil
		return fmt.Errorf("connection to %s timed out", server.Target.IP)
	case ppd := <-md.ResponseMsgCh:
		if ppd.Error != nil {
			r.ac.device.RemovePeer(peer.PublicKeyBase64())
			server.Peer = nil
			return fmt.Errorf("connection failed: %w", ppd.Error)
		}
		if ppd.HeaderType != core.NHP_AAK {
			r.ac.device.RemovePeer(peer.PublicKeyBase64())
			server.Peer = nil
			return fmt.Errorf("unexpected response type: %s", core.HeaderTypeToString(ppd.HeaderType))
		}

		var aakMsg common.ServerACAckMsg
		if err := json.Unmarshal(ppd.BodyMessage, &aakMsg); err != nil {
			r.ac.device.RemovePeer(peer.PublicKeyBase64())
			server.Peer = nil
			return fmt.Errorf("failed to parse NHP_AAK: %w", err)
		}

		if !common.IsSuccessErrCode(aakMsg.ErrCode) {
			r.ac.device.RemovePeer(peer.PublicKeyBase64())
			server.Peer = nil
			return fmt.Errorf("server rejected: %s - %s", aakMsg.ErrCode, aakMsg.ErrMsg)
		}

		server.SetConnected(true)
		server.UpdateLastSeen()
		log.Info("Connected to assigned server %s:%d (ACAddr=%s)", server.Target.IP, server.Target.Port, aakMsg.ACAddr)
		return nil
	}
}

// keepaliveLoop sends keepalives to all assigned servers and monitors their health.
func (r *ACRegistration) keepaliveLoop() {
	ticker := time.NewTicker(KeepaliveInterval)
	defer ticker.Stop()

	for {
		select {
		case <-r.stopCh:
			return
		case <-ticker.C:
			r.sendKeepalives()
			r.checkServerHealth()
		}
	}
}

// sendKeepalives sends keepalive to each assigned server.
func (r *ACRegistration) sendKeepalives() {
	r.mu.RLock()
	servers := make([]*AssignedServer, len(r.assignedServers))
	copy(servers, r.assignedServers)
	r.mu.RUnlock()

	for _, server := range servers {
		if server.Peer == nil || !server.IsConnected() {
			continue
		}

		// Get server's send address
		sendAddr := server.Peer.SendAddr()
		if sendAddr == nil {
			log.Warning("Cannot resolve address for server %s", server.Target.IP)
			continue
		}

		// Create and send NHP_KPL message
		md := &core.MsgData{
			RemoteAddr:    sendAddr.(*net.UDPAddr),
			HeaderType:    core.NHP_KPL,
			CipherScheme:  r.ac.config.DefaultCipherScheme,
			TransactionId: r.ac.device.NextCounterIndex(),
		}

		if r.ac.IsRunning() {
			r.ac.sendMsgCh <- md
			log.Debug("Sent NHP_KPL to assigned server %s:%d", server.Target.IP, server.Target.Port)
		}
	}
}

// checkServerHealth checks if any server is down and triggers re-registration.
func (r *ACRegistration) checkServerHealth() {
	r.mu.RLock()
	servers := make([]*AssignedServer, len(r.assignedServers))
	copy(servers, r.assignedServers)
	r.mu.RUnlock()

	for _, server := range servers {
		// Skip servers that were never connected - they have zero LastSeen
		// which would always trigger false positives.
		if !server.IsConnected() {
			log.Debug("Health check: skipping server %s (never connected)", server.Target.IP)
			continue
		}

		if time.Since(server.GetLastSeen()) > KeepaliveInterval*KeepaliveMaxRetries {
			// Check if already re-registering to prevent concurrent attempts
			if r.reregistering.CompareAndSwap(false, true) {
				log.Warning("Server %s appears down, triggering re-registration", server.Target.IP)
				go r.handleServerDown(server)
			} else {
				log.Debug("Server %s appears down but re-registration already in progress", server.Target.IP)
			}
			return // Re-register once, not for each down server
		}
	}
}

// handleServerDown handles when a server is detected as down.
// Per design doc: AC re-registers via FQDN on ANY server failure.
func (r *ACRegistration) handleServerDown(deadServer *AssignedServer) {
	// Always reset reregistering flag when done
	defer r.reregistering.Store(false)

	// Add jitter to prevent thundering herd
	jitter := time.Duration(rand.Intn(int(ReregistrationJitter.Milliseconds()))) * time.Millisecond
	select {
	case <-r.stopCh:
		return
	case <-time.After(jitter):
	}

	log.Info("Re-registering due to server %s failure", deadServer.Target.IP)

	// Exponential backoff for re-registration attempts
	for attempt := 1; attempt <= MaxReregistrationAttempts; attempt++ {
		select {
		case <-r.stopCh:
			return
		default:
		}

		err := r.register()
		if err == nil {
			log.Info("Re-registration successful after %d attempt(s)", attempt)
			return
		}

		backoff := time.Duration(attempt*attempt) * time.Second
		log.Warning("Re-registration attempt %d failed: %v, retrying in %v", attempt, err, backoff)

		// Interruptible sleep
		select {
		case <-r.stopCh:
			return
		case <-time.After(backoff + jitter):
		}
	}

	log.Error("Re-registration failed after %d attempts, continuing with remaining servers", MaxReregistrationAttempts)
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
