package ac

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/OpenNHP/opennhp/endpoints/metrics"
	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
	"github.com/OpenNHP/opennhp/nhp/log"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
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

	// RegistrationRefreshInterval is how often to re-send NHP_AOL to assigned servers
	// to refresh server peer state. This handles server restarts where the server loses
	// peer state but the AC continues sending keep-alives.
	// Set to 6 * KeepaliveInterval = 60 seconds.
	RegistrationRefreshInterval = 6
)

// CloudWatch metric names for AC registration lifecycle.
const (
	MetricRegistrationAttempts    = "RegistrationAttempts"
	MetricRegistrationSuccess     = "RegistrationSuccess"
	MetricRegistrationFailure     = "RegistrationFailure"
	MetricRegistrationLatency     = "RegistrationLatency"
	MetricServerConnections       = "ServerConnections"
	MetricServerConnectionFailure = "ServerConnectionFailure"
	MetricServerHealthFailures    = "ServerHealthFailures"
	MetricReregistrationTriggers  = "ReregistrationTriggers"
)

// Re-registration reason constants. These are the only values that
// classifyReason passes through; all others map to "other".
const (
	ReasonRefreshRedirect         = "refresh_redirect"
	ReasonServerConnectionTimeout = "server_connection_timeout"
	ReasonConnectionTimeout       = "connection_timeout"
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

// Pre-allocated dimension name strings to avoid per-call heap allocations.
var (
	dimNameACId             = aws.String("ACId")
	dimNameErrorCode        = aws.String("ErrorCode")
	dimNameRegistrationType = aws.String("RegistrationType")
	dimNameConnectionType   = aws.String("ConnectionType")
	dimNameReason           = aws.String("Reason")
)

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

	// CloudWatch metrics publisher (batched, shared package)
	metrics *metrics.Publisher

	// cachedACIdDim is the pre-built ACId dimension. ACId is immutable after
	// startup, so we build once and reuse to avoid per-call aws.String allocations.
	cachedACIdDim types.Dimension

	// cachedAOLBytes is the pre-marshaled ACOnlineMsg. Config is immutable after
	// startup, so we marshal once and reuse across register/connect/refresh calls.
	cachedAOLBytes []byte
}

// NewACRegistration creates a new AC registration manager.
// Returns an error if the ACOnlineMsg cannot be marshaled (indicates a
// programmer error in the Config struct — json.Marshal should never fail
// on these simple fields).
func NewACRegistration(ac *UdpAC) (*ACRegistration, error) {
	env := ac.config.Environment
	if env == "" {
		env = "unknown"
	}

	// Marshal ACOnlineMsg once — config is immutable after startup.
	aolMsg := &common.ACOnlineMsg{
		ACId:          ac.config.ACId,
		AuthServiceId: ac.config.AuthServiceId,
		ResourceIds:   ac.config.ResourceIds,
		LicenseKey:    ac.config.LicenseKey,
		ACVersion:     ac.config.ACVersion,
	}
	aolBytes, err := json.Marshal(aolMsg)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ACOnlineMsg: %w", err)
	}

	// Build shared dimensions for all metrics.
	// ACId is included as an extra dimension on failure/debug metrics only.
	dims := []types.Dimension{
		{Name: aws.String("Environment"), Value: aws.String(env)},
		{Name: aws.String("Component"), Value: aws.String("AC")},
	}
	// Include Region when available (set by AWS SDK or user data scripts).
	// Enables querying metrics across regions in multi-region deployments.
	if region := os.Getenv("AWS_REGION"); region != "" {
		dims = append(dims, types.Dimension{Name: aws.String("Region"), Value: aws.String(region)})
	}

	return &ACRegistration{
		ac:              ac,
		assignedServers: make([]*AssignedServer, 0),
		oldServerSets:   make(map[string][]*AssignedServer),
		stopCh:          make(chan struct{}),
		cachedAOLBytes:  aolBytes,
		cachedACIdDim:   types.Dimension{Name: dimNameACId, Value: aws.String(ac.config.ACId)},
		metrics: metrics.NewPublisher(metrics.Config{
			Namespace:  "LayerV/NHP",
			Dimensions: dims,
		}),
	}, nil
}

// acIdDimension returns the cached CloudWatch dimension for this AC's ID.
// The dimension is built once at startup since ACId is immutable.
func (r *ACRegistration) acIdDimension() types.Dimension {
	return r.cachedACIdDim
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

	// Flush remaining CloudWatch metrics
	r.metrics.Stop()

	log.Debug("AC registration manager stopped")
}

// GetAssignedServers returns a copy of the current assigned servers slice.
func (r *ACRegistration) GetAssignedServers() []*AssignedServer {
	r.mu.RLock()
	defer r.mu.RUnlock()
	servers := slices.Clone(r.assignedServers)
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
	servers := slices.Clone(r.assignedServers)
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
	servers := slices.Clone(r.assignedServers)
	r.mu.RUnlock()

	for _, server := range servers {
		serverAddr := net.JoinHostPort(server.Target.IP, strconv.Itoa(server.Target.Port))
		if serverAddr == addr {
			server.UpdateLastSeen()
			log.Debug("Updated LastSeen for server at %s", addr)
			return
		}
	}
	// No matching server found - expected during NLB registration before server assignment
	log.Debug("No assigned server matches address %s (have %d servers)", addr, len(servers))
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
			// Registration successful - reset iptables to restore port hiding.
			// This is critical: the server discovery loop in maintainServerConnectionRoutine
			// may have opened the firewall (AcceptAllInput) if serverPeerMap was empty.
			// Now that cloud-mode registration succeeded, we must close it.
			r.resetIptables()
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
const DefaultServerPort = common.DefaultNHPPort

// register performs initial registration via ServerEndpoint.
// It sends NHP_AOL to the ServerEndpoint and handles NHP_ARD (redispatch) or NHP_AAK response.
func (r *ACRegistration) register() error {
	// Validate config (ServerEndpoint already validated in Start())
	if r.ac.config.ServerPubKeyBase64 == "" {
		return errors.New("ServerPubKeyBase64 is required")
	}

	// Track attempt after validation so RegistrationAttempts == RegistrationSuccess + RegistrationFailure.
	r.metrics.IncrCounter(MetricRegistrationAttempts)
	startTime := time.Now()

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

	// Use pre-marshaled AOL bytes (config is immutable after startup).
	// cachedAOLBytes is set by NewACRegistration, which returns an error on
	// marshal failure. A nil value here means a bug in the construction path.
	// Intentional panic: this is a programming error, not a runtime condition.
	if r.cachedAOLBytes == nil {
		panic("BUG: cachedAOLBytes is nil — NewACRegistration should have returned an error")
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
		Message:       r.cachedAOLBytes,
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
	// Use time.NewTimer instead of time.After to avoid leaking the timer
	// goroutine when stopCh fires or a response arrives before timeout.
	regTimer := time.NewTimer(RegistrationTimeout)
	defer regTimer.Stop()

	select {
	case <-r.stopCh:
		r.ac.device.RemovePeer(registrationPeer.PublicKeyBase64())
		r.metrics.IncrCounterWithDims(MetricRegistrationFailure, []types.Dimension{
			r.acIdDimension(),
			{Name: dimNameErrorCode, Value: aws.String("canceled")},
		})
		return errors.New("registration canceled")
	case <-regTimer.C:
		r.ac.device.RemovePeer(registrationPeer.PublicKeyBase64())
		r.metrics.IncrCounterWithDims(MetricRegistrationFailure, []types.Dimension{
			r.acIdDimension(),
			{Name: dimNameErrorCode, Value: aws.String("timeout")},
		})
		return errors.New("registration timeout")
	case ppd := <-md.ResponseMsgCh:
		err := r.handleRegistrationResponse(ppd, registrationPeer)
		if err == nil {
			r.metrics.RecordLatency(MetricRegistrationLatency, float64(time.Since(startTime).Milliseconds()))
		}
		return err
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

		// Send registration failure metric with error category (not raw message)
		// to keep dimension cardinality bounded.
		r.metrics.IncrCounterWithDims(MetricRegistrationFailure, []types.Dimension{
			r.acIdDimension(),
			{Name: dimNameErrorCode, Value: aws.String(classifyError(ppd.Error))},
		})

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

		// Send registration success metric
		r.metrics.IncrCounterWithDims(MetricRegistrationSuccess, []types.Dimension{
			{Name: dimNameRegistrationType, Value: aws.String("Redispatch")},
		})

		return nil

	case core.NHP_AAK:
		// Server responded with ACK - this server is assigned to us
		var aakMsg common.ServerACAckMsg
		if err := json.Unmarshal(ppd.BodyMessage, &aakMsg); err != nil {
			r.ac.device.RemovePeer(registrationPeer.PublicKeyBase64())
			return fmt.Errorf("failed to parse NHP_AAK: %w", err)
		}

		if !common.IsSuccessErrCode(aakMsg.ErrCode) {
			r.ac.device.RemovePeer(registrationPeer.PublicKeyBase64())

			// Send registration failure metric with server's error code (bounded cardinality).
			errCode := aakMsg.ErrCode
			if errCode == "" {
				errCode = "unknown"
			}
			r.metrics.IncrCounterWithDims(MetricRegistrationFailure, []types.Dimension{
				r.acIdDimension(),
				{Name: dimNameErrorCode, Value: aws.String(errCode)},
			})

			return fmt.Errorf("registration rejected: %s - %s", aakMsg.ErrCode, aakMsg.ErrMsg)
		}

		if !aakMsg.Registered {
			r.ac.device.RemovePeer(registrationPeer.PublicKeyBase64())

			// Send registration failure metric for server-side rejection.
			r.metrics.IncrCounterWithDims(MetricRegistrationFailure, []types.Dimension{
				r.acIdDimension(),
				{Name: dimNameErrorCode, Value: aws.String("registered_false")},
			})

			return errors.New("server returned NHP_AAK with Registered=false")
		}

		// Determine which peer to use for ongoing communication.
		// If server provides its direct address (ServerAddr), create a new peer for direct
		// communication. This is necessary when AC connects through NLB - the AC's connected
		// UDP socket only accepts packets from the NLB IP, but the server sends responses
		// directly from its own IP. By creating a new connection to the server's direct
		// address, we ensure bidirectional communication works.
		var serverPeer *core.UdpPeer

		if aakMsg.ServerAddr != "" && aakMsg.ServerPubKey != "" {
			// Parse server's direct address
			host, portStr, parseErr := net.SplitHostPort(aakMsg.ServerAddr)
			if parseErr != nil {
				log.Warning("Failed to parse ServerAddr %s: %v, falling back to registration peer", aakMsg.ServerAddr, parseErr)
				serverPeer = registrationPeer
			} else {
				port, portErr := strconv.Atoi(portStr)
				if portErr != nil || port < 1 || port > 65535 {
					log.Warning("Invalid port in ServerAddr %s, falling back to registration peer", aakMsg.ServerAddr)
					serverPeer = registrationPeer
				} else {
					// Check if the server's direct IP is routable from this AC.
					// Non-routable IPs should not be used for direct connection when
					// the AC is outside the VPC (e.g., connected via NLB from internet).
					// Note: If host is a hostname (not IP), ParseIP returns nil and we
					// proceed to create a direct connection. This is intentional because
					// hostnames may resolve differently in different network contexts.
					serverIP := net.ParseIP(host)
					if serverIP != nil && isNonRoutableIP(serverIP) {
						log.Info("Server direct address %s is non-routable, staying on NLB connection", aakMsg.ServerAddr)
						// Keep using NLB address but update peer's public key to server's key.
						// Must remove and re-add because device's peer map is keyed by public key.
						oldPubKey := registrationPeer.PublicKeyBase64()
						r.ac.device.RemovePeer(oldPubKey)
						registrationPeer.PubKeyBase64 = aakMsg.ServerPubKey
						r.ac.device.AddPeer(registrationPeer)
						serverPeer = registrationPeer
					} else {
						// Create new peer with server's direct address
						serverPeer = &core.UdpPeer{
							Ip:           host,
							Port:         port,
							PubKeyBase64: aakMsg.ServerPubKey,
							Type:         core.NHP_SERVER,
						}

						// Verify the new peer can resolve its address
						if serverPeer.SendAddr() == nil {
							log.Warning("Cannot resolve server direct address %s, falling back to registration peer", aakMsg.ServerAddr)
							serverPeer = registrationPeer
						} else {
							// Add the new direct peer to the device
							r.ac.device.AddPeer(serverPeer)
							// Remove the old registration peer (connected to NLB)
							r.ac.device.RemovePeer(registrationPeer.PublicKeyBase64())
							log.Info("Switched from NLB %s:%d to server direct address %s", registrationPeer.Ip, registrationPeer.Port, aakMsg.ServerAddr)
						}
					}
				}
			}
		} else {
			// No direct address provided, use registration peer (legacy behavior)
			serverPeer = registrationPeer
			// Log partial field cases to help diagnose misconfiguration
			if aakMsg.ServerAddr != "" {
				log.Debug("ServerAddr provided without ServerPubKey, using registration peer")
			} else if aakMsg.ServerPubKey != "" {
				log.Debug("ServerPubKey provided without ServerAddr, using registration peer")
			}
		}

		// Get the server address for assignedServers
		sendAddr := serverPeer.SendAddr()
		if sendAddr == nil {
			// Edge case: peer address cannot be resolved (e.g., DNS failure after initial check).
			// We keep the peer for potential future use but skip adding to assignedServers,
			// meaning no keepalives will be sent. The connection may timeout, but this is
			// preferable to failing registration entirely for a transient DNS issue.
			log.Warning("Server peer has nil SendAddr, cannot add to assignedServers for keepalive")
			r.mu.Lock()
			if r.registrationPeer != nil {
				r.ac.device.RemovePeer(r.registrationPeer.PublicKeyBase64())
			}
			r.registrationPeer = serverPeer
			r.mu.Unlock()
			log.Info("Received NHP_AAK: ACAddr=%s, Registered=%v (peer kept but no keepalive)", aakMsg.ACAddr, aakMsg.Registered)

			// Send registration success metric
			r.metrics.IncrCounterWithDims(MetricRegistrationSuccess, []types.Dimension{
				{Name: dimNameRegistrationType, Value: aws.String("Direct")},
			})

			return nil
		}

		udpAddr := sendAddr.(*net.UDPAddr)

		r.mu.Lock()
		// Clean up old registration peer if exists (re-registration case)
		if r.registrationPeer != nil && r.registrationPeer.PublicKeyBase64() != serverPeer.PublicKeyBase64() {
			r.ac.device.RemovePeer(r.registrationPeer.PublicKeyBase64())
		}
		r.registrationPeer = serverPeer

		// Replace assignedServers with the server for keepalive management.
		// We replace (not append) to avoid duplicate entries on re-registration.
		assignedServer := &AssignedServer{
			Target: common.RedirectTarget{
				IP:           udpAddr.IP.String(),
				Port:         udpAddr.Port,
				PubKeyBase64: serverPeer.PublicKeyBase64(),
			},
			Peer:      serverPeer,
			Connected: true,
			LastSeen:  time.Now(),
		}
		r.assignedServers = []*AssignedServer{assignedServer}
		r.mu.Unlock()

		log.Info("Set server as assignedServer for keepalive: %s:%d", udpAddr.IP.String(), udpAddr.Port)
		if serverPeer == registrationPeer {
			log.Info("Received NHP_AAK: ACAddr=%s, Registered=%v (using registration peer)", aakMsg.ACAddr, aakMsg.Registered)
		} else {
			log.Info("Received NHP_AAK: ACAddr=%s, Registered=%v, ServerAddr=%s (using direct connection)", aakMsg.ACAddr, aakMsg.Registered, aakMsg.ServerAddr)
		}

		// Send registration success metric
		r.metrics.IncrCounterWithDims(MetricRegistrationSuccess, []types.Dimension{
			{Name: dimNameRegistrationType, Value: aws.String("Direct")},
		})

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

	// Connect to all assigned servers concurrently. Each connection has its own
	// ConnectionTimeout (10s), so sequential attempts could take 30s+ total.
	var connectWg sync.WaitGroup
	var successCount int32
	for _, server := range serversToConnect {
		connectWg.Add(1)
		go func(s *AssignedServer) {
			defer connectWg.Done()
			if err := r.connectToServer(s); err != nil {
				log.Warning("Failed to connect to assigned server %s: %v", s.Target.IP, err)

				// Track individual connection failures for alerting on partial connectivity.
				r.metrics.IncrCounterWithDims(MetricServerConnectionFailure, []types.Dimension{
					r.acIdDimension(),
					{Name: dimNameErrorCode, Value: aws.String(classifyError(err))},
				})
			} else {
				atomic.AddInt32(&successCount, 1)
			}
		}(server)
	}
	connectWg.Wait()

	// Fail if no connections succeeded - AC would be unreachable
	if successCount == 0 {
		return errors.New("failed to connect to any assigned servers")
	}

	// Warn if partial failure (some but not all servers connected)
	if int(successCount) < len(serversToConnect) {
		log.Warning("Partial connection success: %d/%d assigned servers connected", successCount, len(serversToConnect))
	} else {
		log.Info("Successfully connected to all %d assigned servers", successCount)
	}

	// Schedule old server cleanup (only if we had old servers to clean up)
	if hasOldServers {
		go r.cleanupOldServers(cleanupKey)
	}

	// Send server connections metric
	r.metrics.AddCounterWithDims(MetricServerConnections, float64(successCount), []types.Dimension{
		{Name: dimNameConnectionType, Value: aws.String("Redispatch")},
	})

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

	// Send NHP_AOL to register with this server (use cached bytes)
	// Use buffered channel (size 1) to prevent sender from blocking if we exit early
	md := &core.MsgData{
		RemoteAddr:    sendAddr.(*net.UDPAddr),
		HeaderType:    core.NHP_AOL,
		TransactionId: r.ac.device.NextCounterIndex(),
		Compress:      true,
		PeerPk:        peer.PublicKey(),
		Message:       r.cachedAOLBytes,
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
		return errors.New("connection canceled")
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
// Every RegistrationRefreshInterval ticks, it also sends NHP_AOL to refresh server
// peer state (handles server restarts without AC knowing).
func (r *ACRegistration) keepaliveLoop() {
	ticker := time.NewTicker(KeepaliveInterval)
	defer ticker.Stop()

	tickCount := 0
	for {
		select {
		case <-r.stopCh:
			return
		case <-ticker.C:
			tickCount++
			r.sendKeepalives()
			r.checkServerHealth()

			// Periodically refresh registration to handle server restarts.
			// The server may have restarted and lost peer state, but the AC
			// continues sending keep-alives successfully (UDP works).
			// By re-sending NHP_AOL periodically, we ensure the server always
			// has our peer state.
			// Note: tickCount is incremented before the check, so first refresh happens after 6 ticks (60s).
			if tickCount >= RegistrationRefreshInterval {
				tickCount = 0
				r.refreshAssignedServerRegistrations()
			}
		}
	}
}

// sendKeepalives sends keepalive to each assigned server.
func (r *ACRegistration) sendKeepalives() {
	r.mu.RLock()
	servers := slices.Clone(r.assignedServers)
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
			// Update LastSeen when we send a keepalive, not when receiving a response.
			// NHP_KPL is unidirectional - the server receives but doesn't respond.
			// This keeps the connection "alive" from the AC's perspective as long as
			// we can queue sends. If the server is truly unreachable, registration
			// will fail when we eventually try to re-register.
			server.UpdateLastSeen()
			log.Debug("Sent NHP_KPL to assigned server %s:%d", server.Target.IP, server.Target.Port)
		}
	}
}

// refreshAssignedServerRegistrations sends NHP_AOL to each assigned server to
// refresh its peer state. This handles server restarts where the server loses
// peer state but the AC continues sending successful keep-alives (UDP works).
//
// Unlike full re-registration through the NLB, this sends directly to assigned
// servers. The server will either:
// - NHP_AAK: Acknowledge and refresh/create peer state
// - NHP_ARD: Redirect to different servers (triggers full re-registration)
// - Timeout: Server unreachable, triggers health check failure
func (r *ACRegistration) refreshAssignedServerRegistrations() {
	r.mu.RLock()
	servers := slices.Clone(r.assignedServers)
	r.mu.RUnlock()

	if len(servers) == 0 {
		log.Debug("No assigned servers to refresh")
		return
	}

	log.Debug("Refreshing registration with %d assigned servers", len(servers))

	for _, server := range servers {
		if server.Peer == nil || !server.IsConnected() {
			log.Debug("Skipping refresh for unconnected server %s", server.Target.IP)
			continue
		}

		// Get server's send address
		sendAddr := server.Peer.SendAddr()
		if sendAddr == nil {
			log.Warning("Cannot resolve address for server %s during refresh", server.Target.IP)
			continue
		}

		// Send refresh in a goroutine to avoid blocking keepalive loop
		go r.refreshSingleServer(server, sendAddr.(*net.UDPAddr))
	}
}

// refreshSingleServer sends NHP_AOL to a single assigned server to refresh registration.
func (r *ACRegistration) refreshSingleServer(server *AssignedServer, sendAddr *net.UDPAddr) {
	// Create message data for sending (use cached AOL bytes)
	// Use buffered channel to prevent sender from blocking if we timeout
	md := &core.MsgData{
		RemoteAddr:    sendAddr,
		HeaderType:    core.NHP_AOL,
		CipherScheme:  r.ac.config.DefaultCipherScheme,
		TransactionId: r.ac.device.NextCounterIndex(),
		Compress:      true,
		PeerPk:        server.Peer.PublicKey(),
		Message:       r.cachedAOLBytes,
		ResponseMsgCh: make(chan *core.PacketParserData, 1),
	}

	// Send NHP_AOL
	if !r.ac.IsRunning() {
		return
	}
	r.ac.sendMsgCh <- md

	// Wait for response with short timeout (don't block keepalive loop).
	// Use time.NewTimer instead of time.After to avoid leaking the timer
	// goroutine when stopCh fires or a response arrives before timeout.
	timer := time.NewTimer(KeepaliveTimeout)
	defer timer.Stop()

	select {
	case <-r.stopCh:
		return
	case <-timer.C:
		// Timeout is OK - server may be slow or unreachable
		// Health check will eventually detect and trigger re-registration
		log.Debug("Refresh NHP_AOL to %s timed out", sendAddr.String())
		return
	case ppd := <-md.ResponseMsgCh:
		r.handleRefreshResponse(ppd, server, sendAddr)
	}
}

// handleRefreshResponse handles the server's response to refresh NHP_AOL.
func (r *ACRegistration) handleRefreshResponse(ppd *core.PacketParserData, server *AssignedServer, sendAddr *net.UDPAddr) {
	if ppd.Error != nil {
		log.Warning("Refresh NHP_AOL to %s failed: %v", sendAddr.String(), ppd.Error)
		return
	}

	switch ppd.HeaderType {
	case core.NHP_AAK:
		// Server acknowledged - peer state refreshed
		var aakMsg common.ServerACAckMsg
		if err := json.Unmarshal(ppd.BodyMessage, &aakMsg); err != nil {
			log.Warning("Failed to parse refresh NHP_AAK from %s: %v", sendAddr.String(), err)
			return
		}

		if common.IsSuccessErrCode(aakMsg.ErrCode) {
			server.UpdateLastSeen()
			log.Debug("Refreshed registration with server %s", sendAddr.String())
		} else {
			log.Warning("Refresh rejected by %s: %s - %s", sendAddr.String(), aakMsg.ErrCode, aakMsg.ErrMsg)
		}

	case core.NHP_ARD:
		// Server wants us to connect to different servers
		// This shouldn't happen during refresh, but handle it gracefully
		log.Info("Server %s responded with NHP_ARD during refresh, triggering full re-registration", sendAddr.String())
		r.TriggerReregistration(ReasonRefreshRedirect)

	default:
		log.Warning("Unexpected response type %d from %s during refresh", ppd.HeaderType, sendAddr.String())
	}
}

// checkServerHealth checks if any server is down and triggers re-registration.
func (r *ACRegistration) checkServerHealth() {
	r.mu.RLock()
	servers := slices.Clone(r.assignedServers)
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

				// Send server health failure metric.
				// Only ACId as extra dimension — no ServerIP to keep cardinality bounded
				// (server IPs change on every ASG launch).
				r.metrics.IncrCounterWithDims(MetricServerHealthFailures, []types.Dimension{
					r.acIdDimension(),
				})

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
			// Reset iptables to restore port hiding after successful re-registration
			r.resetIptables()
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

// IsServerAddress checks if the given address belongs to an assigned server.
// This is used to determine if a connection closure should trigger re-registration.
func (r *ACRegistration) IsServerAddress(addr string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, server := range r.assignedServers {
		// Use net.JoinHostPort for correct IPv6 formatting (adds brackets)
		// e.g., "::1" + 62206 -> "[::1]:62206" to match net.UDPAddr.String()
		serverAddr := net.JoinHostPort(server.Target.IP, strconv.Itoa(server.Target.Port))
		if serverAddr == addr {
			return true
		}
	}

	// Also check the registration peer (for single-server cloud mode)
	if r.registrationPeer != nil {
		peerAddr := r.registrationPeer.SendAddr()
		if peerAddr != nil && peerAddr.String() == addr {
			return true
		}
	}

	return false
}

// TriggerReregistration triggers re-registration due to a connection event.
// This should be called when a server connection closes unexpectedly (e.g., socket
// timeout/recreation) to ensure the server has our current address.
// The reason parameter is logged for debugging.
func (r *ACRegistration) TriggerReregistration(reason string) {
	// Use atomic flag to prevent concurrent re-registration attempts
	if !r.reregistering.CompareAndSwap(false, true) {
		log.Debug("Re-registration already in progress, skipping trigger for: %s", reason)
		return
	}

	log.Info("Triggering re-registration due to: %s", reason)

	// Send reregistration trigger metric with bounded reason category.
	r.metrics.IncrCounterWithDims(MetricReregistrationTriggers, []types.Dimension{
		r.acIdDimension(),
		{Name: dimNameReason, Value: aws.String(classifyReason(reason))},
	})

	go func() {
		// Always reset reregistering flag when done
		defer r.reregistering.Store(false)

		// Small jitter to avoid thundering herd if multiple connections close.
		// Use half of ReregistrationJitter (0-2.5s) for connection-triggered re-registration
		// since these are more time-sensitive than server-down scenarios (which use 0-5s).
		jitter := time.Duration(rand.Intn(int(ReregistrationJitter.Milliseconds()/2))) * time.Millisecond
		select {
		case <-r.stopCh:
			return
		case <-time.After(jitter):
		}

		// Attempt re-registration with backoff
		for attempt := 1; attempt <= MaxReregistrationAttempts; attempt++ {
			select {
			case <-r.stopCh:
				return
			default:
			}

			err := r.register()
			if err == nil {
				log.Info("Re-registration successful after %d attempt(s) (triggered by: %s)", attempt, reason)
				r.resetIptables()
				return
			}

			backoff := time.Duration(attempt*attempt) * time.Second
			log.Warning("Re-registration attempt %d failed: %v, retrying in %v", attempt, err, backoff)

			select {
			case <-r.stopCh:
				return
			case <-time.After(backoff + jitter):
			}
		}

		log.Error("Re-registration failed after %d attempts (triggered by: %s)", MaxReregistrationAttempts, reason)
	}()
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

// CGNAT is the Carrier-Grade NAT range (100.64.0.0/10) used by some cloud providers.
// This is not covered by net.IP.IsPrivate().
var cgnatBlock = &net.IPNet{
	IP:   net.IPv4(100, 64, 0, 0),
	Mask: net.CIDRMask(10, 32),
}

// isNonRoutableIP checks if an IP address is non-routable from the public internet.
// This includes:
//   - RFC 1918 private IPs (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
//   - Loopback (127.0.0.0/8, ::1)
//   - Link-local (169.254.0.0/16, fe80::/10)
//   - CGNAT/Carrier-Grade NAT (100.64.0.0/10)
//   - IPv6 private (fc00::/7)
func isNonRoutableIP(ip net.IP) bool {
	if ip == nil {
		return true // Treat nil as non-routable for safety
	}

	// Check standard non-routable ranges
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}

	// Check CGNAT range (100.64.0.0/10) - not covered by IsPrivate()
	if ip4 := ip.To4(); ip4 != nil && cgnatBlock.Contains(ip4) {
		return true
	}

	return false
}

// resetIptables resets iptables rules to restore NHP port hiding.
// This should be called when cloud-mode registration succeeds to close the firewall
// that may have been opened by AcceptAllInput() during server discovery.
func (r *ACRegistration) resetIptables() {
	if r.ac.config.FilterMode == FilterMode_IPTABLES && r.ac.iptables != nil {
		log.Info("Resetting iptables after successful registration for AC %s", r.ac.config.ACId)
		r.ac.iptables.ResetAllInput()
	}
}

// classifyError maps an error to a bounded category string for use as a
// CloudWatch dimension value. Using raw error messages would create unbounded
// cardinality; this function ensures a finite set of dimension values.
//
// Priority order (first match wins):
//  1. Typed *common.Error — returns the NHP error code (e.g., "ErrTransactionFailedByTimeout")
//  2. net.Error with Timeout() — returns "timeout"
//  3. String matching — categorizes by message content (timeout, connection_error, crypto_error, dns_error)
//  4. Fallback — returns "other"
//
// NHP error codes are checked first because a *common.Error may also satisfy
// net.Error (via wrapping), and the specific NHP code is more useful than
// the generic "timeout" category.
func classifyError(err error) string {
	if err == nil {
		return "none"
	}

	// Check for typed NHP errors, unwrapping if needed.
	var nhpErr *common.Error
	if errors.As(err, &nhpErr) {
		if code := nhpErr.ErrorCode(); code != "" {
			return code
		}
	}

	// Check for net.Error timeout via interface (handles wrapped net errors).
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "timeout"
	}

	// Fall back to string matching for errors without typed wrappers.
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "timeout") || strings.Contains(msg, "timed out") || strings.Contains(msg, "deadline exceeded"):
		return "timeout"
	case strings.Contains(msg, "connection refused") || strings.Contains(msg, "connection reset"):
		return "connection_error"
	case strings.Contains(msg, "ecdh") || strings.Contains(msg, "decrypt") || strings.Contains(msg, "encrypt"):
		return "crypto_error"
	case strings.Contains(msg, "resolve") || strings.Contains(msg, "no such host") ||
		strings.Contains(msg, "dns") || strings.Contains(msg, "name resolution"):
		return "dns_error"
	default:
		return "other"
	}
}

// classifyReason maps a re-registration reason string to a bounded category
// for use as a CloudWatch dimension value. This prevents unbounded cardinality
// from free-form caller-supplied reason strings.
func classifyReason(reason string) string {
	switch reason {
	case ReasonRefreshRedirect,
		ReasonServerConnectionTimeout,
		ReasonConnectionTimeout:
		return reason
	default:
		return "other"
	}
}
