package ac

import (
	"crypto/sha256"
	"encoding/binary"
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

	// cleanupChBufferSize is the buffer capacity for the cleanup worker channel.
	// Accommodates bursts of rapid reassignments without blocking HandleRedispatch.
	cleanupChBufferSize = 10

	// MaxReregistrationAttempts is the max attempts for re-registration after server failure.
	MaxReregistrationAttempts = 5

	// RegistrationRefreshInterval is how often to re-send NHP_AOL to assigned servers
	// to refresh server peer state and validate server health. This is the primary
	// mechanism for confirming server liveness — NHP_KPL is unidirectional and cannot
	// confirm receipt. Only validated NHP_AOL responses update LastSeen.
	// Set to 2 * KeepaliveInterval = 20 seconds.
	RegistrationRefreshInterval = 2

	// MaxServerDownReregBackoff caps circuit-breaker backoff when server-down
	// re-registration keeps failing.
	MaxServerDownReregBackoff = 5 * time.Minute

	// DefaultNLBReregistrationInterval is the default cadence for the
	// periodic NLB re-registration safety net. It is intentionally long
	// (every 30 minutes) because it is a defense-in-depth check for silent
	// failures, not a primary recovery path. Operators can override this
	// per-AC via Config.NLBReregistrationIntervalSeconds.
	DefaultNLBReregistrationInterval = 30 * time.Minute

	// MinNLBReregistrationInterval is the lower bound for the periodic NLB
	// re-registration safety net. Going below this would defeat the
	// "rate-limited safety net" intent and risks DoS-ing the registration
	// fleet during a network blip. Any configured value below this is
	// clamped up to it.
	MinNLBReregistrationInterval = 5 * time.Minute

	// DefaultAllUnconnectedThreshold is the default number of consecutive
	// keepalive ticks during which ALL assigned servers must remain in
	// "never connected" state before the all-unconnected detector triggers
	// a re-registration. With KeepaliveInterval = 10s, the default of 3
	// ticks gives a recovery latency of ~30s while requiring sustained
	// failure to fire. Operators can override via Config.AllUnconnectedThresholdTicks.
	DefaultAllUnconnectedThreshold = 3

	// MinAllUnconnectedThreshold is the lower bound for the all-unconnected
	// detector. We never accept zero/negative values: a single tick of
	// allUnconnected would over-react to brief transient blips.
	MinAllUnconnectedThreshold = 2

	// NLBReregistrationJitterFraction is the maximum fractional jitter
	// applied to NLBReregistrationInterval (and AllUnconnectedThreshold,
	// when expressed as a duration via KeepaliveInterval). Each AC picks
	// a deterministic offset within ±NLBReregistrationJitterFraction of
	// the configured interval, derived from the AC public key hash, so
	// many ACs booted at the same time do not all attempt re-registration
	// in lock-step after a network blip ("thundering herd").
	NLBReregistrationJitterFraction = 0.25
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

	// MetricAllUnconnectedDetected is incremented once per "all assigned
	// servers are unconnected" incident (on the 0->1 tick transition only)
	// so each incident counts once. It provides early visibility into a
	// degraded AC before the threshold actually triggers re-registration.
	MetricAllUnconnectedDetected = "AllUnconnectedDetected"
)

// Re-registration reason constants. These are the only values that
// classifyReason passes through; all others map to "other".
const (
	ReasonRefreshRedirect         = "refresh_redirect"
	ReasonServerConnectionTimeout = "server_connection_timeout"
	ReasonConnectionTimeout       = "connection_timeout"

	// ReasonAllServersUnconnected is emitted when checkAllUnconnected has
	// observed every assigned server in "never connected" state for the
	// configured number of consecutive ticks and trips a re-registration.
	// This catches the case where all keepalive paths are silently dead
	// (e.g. NAT rebinding broke every UDP flow simultaneously, or a
	// transient registration response misconfigured the assigned slice).
	ReasonAllServersUnconnected = "all_servers_unconnected"

	// ReasonPeriodicNLBRefresh is emitted by checkPeriodicNLBReregistration
	// every NLBReregistrationInterval as a defense-in-depth safety net
	// independent of any per-server health signal.
	ReasonPeriodicNLBRefresh = "periodic_nlb_refresh"
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

// Pre-allocated dimension name/value strings to avoid per-call heap allocations.
var (
	dimNameACId             = aws.String("ACId")
	dimNameErrorCode        = aws.String("ErrorCode")
	dimNameRegistrationType = aws.String("RegistrationType")
	dimNameConnectionType   = aws.String("ConnectionType")
	dimNameReason           = aws.String("Reason")

	dimValDirect         = aws.String("Direct")
	dimValRedispatch     = aws.String("Redispatch")
	dimValPeerRedispatch = aws.String("PeerRedispatch")
)

// recordRegistrationSuccess emits a MetricRegistrationSuccess counter with the
// given registration type dimension (dimValDirect, dimValRedispatch, or dimValPeerRedispatch).
func (r *ACRegistration) recordRegistrationSuccess(regType *string) {
	r.metrics.IncrCounterWithDims(MetricRegistrationSuccess, []types.Dimension{
		{Name: dimNameRegistrationType, Value: regType},
	})
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

	// serverDownReregFailures tracks consecutive failures of server-down triggered
	// re-registration attempts (used for circuit-breaker backoff).
	serverDownReregFailures atomic.Int32

	// serverDownReregCooldownUntil is a unix nano timestamp. While now < cooldown,
	// health-check-triggered re-registration is suppressed to avoid tight loops.
	serverDownReregCooldownUntil atomic.Int64

	// registrationPeer tracks the peer from NHP_AAK response (the server that is
	// assigned to us and will send NHP_AOP packets). This is separate from
	// connectedServers because the registration server responds with NHP_AAK
	// directly, not NHP_ARD. We need to track it for cleanup when AC stops
	// or re-registers to a different server.
	registrationPeer *core.UdpPeer

	// cleanupCh feeds old-server cleanup keys to a single worker goroutine,
	// replacing the previous pattern of spawning an unbounded goroutine per
	// HandleRedispatch call. See cleanupChBufferSize.
	cleanupCh chan string

	// CloudWatch metrics publisher (batched, shared package)
	metrics *metrics.Publisher

	// cachedACIdDim is the pre-built ACId dimension. ACId is immutable after
	// startup, so we build once and reuse to avoid per-call aws.String allocations.
	cachedACIdDim types.Dimension

	// cachedAOLBytes is the pre-marshaled ACOnlineMsg. Config is immutable after
	// startup, so we marshal once and reuse across register/connect/refresh calls.
	cachedAOLBytes []byte

	// lastNLBRegistrationNano is a monotonic-ish (UnixNano) timestamp of
	// the last successful registration through the NLB endpoint. It is the
	// reference time for the periodic NLB re-registration safety net
	// (see checkPeriodicNLBReregistration). Stored as an atomic Int64
	// because it is written from multiple goroutines (registrationLoop,
	// handleServerDown, TriggerReregistration's go func) and read from
	// keepaliveLoop — a plain time.Time read/write would race.
	lastNLBRegistrationNano atomic.Int64

	// allUnconnectedTicks counts consecutive keepalive ticks during which
	// every assigned server is in "never connected" state (Connected=false).
	// When the count reaches the effective threshold (default + jitter),
	// the AC triggers a re-registration via the control plane and resets
	// the counter. Atomic because keepaliveLoop increments/reads it while
	// re-registration goroutines reset it.
	allUnconnectedTicks atomic.Uint32

	// nlbReregistrationInterval is the effective (config + per-AC jitter)
	// interval for the periodic NLB re-registration safety net. Computed
	// once at construction so the jitter is stable across the AC's
	// lifetime — a stable jitter is what de-correlates a fleet, not a
	// fresh random value every tick.
	nlbReregistrationInterval time.Duration

	// allUnconnectedThreshold is the effective (config + per-AC jitter)
	// number of consecutive keepalive ticks the all-unconnected detector
	// requires before tripping a re-registration. Computed once at
	// construction for the same fleet-jitter reason as
	// nlbReregistrationInterval.
	allUnconnectedThreshold uint32
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

	// Derive a per-AC jitter factor from the immutable config so that two
	// ACs booted at the same second pick different (but stable) intervals
	// for the safety-net mechanisms below. Stability across restarts is
	// important: the jitter offsets exist to de-correlate the fleet, not
	// to randomize each tick. ACId + PrivateKeyBase64 are both immutable
	// and uniquely identify a particular AC instance.
	jitterFactor := resilienceJitterFactor(ac.config.ACId, ac.config.PrivateKeyBase64)
	nlbInterval := computeNLBReregistrationInterval(ac.config.NLBReregistrationIntervalSeconds, jitterFactor)
	allUnconnected := computeAllUnconnectedThreshold(ac.config.AllUnconnectedThresholdTicks, jitterFactor)

	return &ACRegistration{
		ac:                        ac,
		assignedServers:           make([]*AssignedServer, 0),
		oldServerSets:             make(map[string][]*AssignedServer),
		stopCh:                    make(chan struct{}),
		cleanupCh:                 make(chan string, cleanupChBufferSize),
		cachedAOLBytes:            aolBytes,
		cachedACIdDim:             types.Dimension{Name: dimNameACId, Value: aws.String(ac.config.ACId)},
		nlbReregistrationInterval: nlbInterval,
		allUnconnectedThreshold:   allUnconnected,
		metrics: metrics.NewPublisher(metrics.Config{
			Namespace:  "LayerV/NHP",
			Dimensions: dims,
		}),
	}, nil
}

// resilienceJitterFactor returns a deterministic value in the inclusive
// range [-1.0, +1.0] derived from the SHA-256 of the AC's identity. The
// per-AC mechanisms (periodic NLB re-registration, all-unconnected
// detector) multiply this factor by NLBReregistrationJitterFraction and
// scale the resulting offset against the configured interval, so each AC
// in the fleet picks a stable interval that is uniformly spread across
// the configured baseline ± NLBReregistrationJitterFraction.
//
// The factor is stable across restarts of the same AC because both inputs
// (ACId and PrivateKeyBase64) are immutable for an AC instance — this is
// the property that prevents a thundering-herd retry every time the AC
// process restarts.
//
// This function never returns a math/rand value; it is intentionally
// deterministic per AC.
func resilienceJitterFactor(acID, privateKeyBase64 string) float64 {
	h := sha256.New()
	h.Write([]byte(acID))
	// Domain-separator so a future identifier change cannot accidentally
	// produce a colliding factor with an empty ACId.
	h.Write([]byte{0})
	h.Write([]byte(privateKeyBase64))
	sum := h.Sum(nil)

	// Take the first 8 bytes as a uint64, then map to [-1.0, +1.0].
	u := binary.BigEndian.Uint64(sum[:8])
	// Mantissa precision: 53 bits is the max integer that survives
	// float64 conversion exactly. Mask down before dividing.
	const mantissaMask uint64 = (1 << 53) - 1
	frac := float64(u&mantissaMask) / float64(mantissaMask) // [0, 1]
	return frac*2.0 - 1.0                                   // [-1, +1]
}

// computeNLBReregistrationInterval returns the effective NLB
// re-registration interval after applying configured override and
// per-AC jitter. The minimum lower bound is enforced after jitter so
// the jittered interval can never collapse to something pathologically
// small.
func computeNLBReregistrationInterval(configSeconds int, jitterFactor float64) time.Duration {
	base := DefaultNLBReregistrationInterval
	if configSeconds > 0 {
		base = time.Duration(configSeconds) * time.Second
	}
	if base < MinNLBReregistrationInterval {
		base = MinNLBReregistrationInterval
	}

	// jitterFactor is in [-1, +1]; scale by NLBReregistrationJitterFraction
	// so the actual offset is in ±NLBReregistrationJitterFraction*base.
	offset := time.Duration(float64(base) * NLBReregistrationJitterFraction * jitterFactor)
	jittered := base + offset

	// Hard floor: never go below MinNLBReregistrationInterval even after
	// a worst-case negative jitter. This protects the registration fleet
	// from a deterministically-low jitter pinning a particular AC into
	// re-registering every couple of minutes.
	if jittered < MinNLBReregistrationInterval {
		jittered = MinNLBReregistrationInterval
	}
	return jittered
}

// computeAllUnconnectedThreshold returns the effective all-unconnected
// detector threshold (in keepalive ticks) after applying configured
// override and per-AC jitter. Like the NLB interval, the minimum bound
// is enforced after jitter so a short jitter cannot make the detector
// trigger on a single transient blip.
//
// All arithmetic is performed on positive values inside the bounded
// range [MinAllUnconnectedThreshold, configTicks*(1+jitterFraction)],
// so the final uint32 conversion is safe by construction.
func computeAllUnconnectedThreshold(configTicks int, jitterFactor float64) uint32 {
	base := DefaultAllUnconnectedThreshold
	if configTicks > 0 {
		base = configTicks
	}
	if base < MinAllUnconnectedThreshold {
		base = MinAllUnconnectedThreshold
	}

	// Apply ±NLBReregistrationJitterFraction jitter, rounded away from
	// zero so the threshold bias is symmetric across the fleet rather
	// than systematically biased downward.
	offset := float64(base) * NLBReregistrationJitterFraction * jitterFactor
	rounded := int(offset + 0.5*signOf(offset))
	jittered := base + rounded

	if jittered < MinAllUnconnectedThreshold {
		jittered = MinAllUnconnectedThreshold
	}
	// jittered is now guaranteed >= MinAllUnconnectedThreshold (>= 2),
	// so the conversion to uint32 cannot wrap.
	return uint32(jittered)
}

// signOf returns -1 for negative x, +1 for non-negative x. Used by the
// rounding helper above so the threshold rounds away from zero rather
// than truncating, which would systematically bias jittered thresholds
// downward.
func signOf(x float64) float64 {
	if x < 0 {
		return -1
	}
	return 1
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

	// Add to wait group BEFORE starting goroutines to prevent race with Stop()
	r.wg.Add(2)
	go r.registrationLoop()
	go r.cleanupWorker()

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
		r.ac.device.RemovePeerByAddress(r.registrationPeer.PublicKeyBase64(), r.registrationPeer.Host())
		r.registrationPeer = nil
	}
	// Clean up connected server peers
	for _, server := range r.assignedServers {
		if server.Peer != nil {
			r.ac.device.RemovePeerByAddress(server.Peer.PublicKeyBase64(), server.Peer.Host())
			server.Peer = nil
		}
	}
	r.assignedServers = nil
	// Clean up any pending old server sets (from overlapping reassignments)
	for cleanupKey, oldServers := range r.oldServerSets {
		for _, server := range oldServers {
			if server.Peer != nil {
				r.ac.device.RemovePeerByAddress(server.Peer.PublicKeyBase64(), server.Peer.Host())
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
			r.lastNLBRegistrationNano.Store(time.Now().UnixNano())
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
	udpAddr, ok := sendAddr.(*net.UDPAddr)
	if !ok {
		r.ac.device.RemovePeerByAddress(registrationPeer.PublicKeyBase64(), registrationPeer.Host())
		return fmt.Errorf("unexpected address type %T for registration peer", sendAddr)
	}
	md := &core.MsgData{
		RemoteAddr:    udpAddr,
		HeaderType:    core.NHP_AOL,
		TransactionId: r.ac.device.NextCounterIndex(),
		Compress:      true,
		PeerPk:        registrationPeer.PublicKey(),
		Message:       r.cachedAOLBytes,
		ResponseMsgCh: make(chan *core.PacketParserData, 1),
	}

	// Send NHP_AOL
	if !r.ac.IsRunning() {
		r.ac.device.RemovePeerByAddress(registrationPeer.PublicKeyBase64(), registrationPeer.Host())
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
		r.ac.device.RemovePeerByAddress(registrationPeer.PublicKeyBase64(), registrationPeer.Host())
		r.metrics.IncrCounterWithDims(MetricRegistrationFailure, []types.Dimension{
			r.acIdDimension(),
			{Name: dimNameErrorCode, Value: aws.String("canceled")},
		})
		return errors.New("registration canceled")
	case <-regTimer.C:
		r.ac.device.RemovePeerByAddress(registrationPeer.PublicKeyBase64(), registrationPeer.Host())
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
		r.ac.device.RemovePeerByAddress(registrationPeer.PublicKeyBase64(), registrationPeer.Host())

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
		r.ac.device.RemovePeerByAddress(registrationPeer.PublicKeyBase64(), registrationPeer.Host())

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
		r.recordRegistrationSuccess(dimValRedispatch)

		return nil

	case core.NHP_AAK:
		// Server responded with ACK - this server is assigned to us
		var aakMsg common.ServerACAckMsg
		if err := json.Unmarshal(ppd.BodyMessage, &aakMsg); err != nil {
			r.ac.device.RemovePeerByAddress(registrationPeer.PublicKeyBase64(), registrationPeer.Host())
			return fmt.Errorf("failed to parse NHP_AAK: %w", err)
		}

		if !common.IsSuccessErrCode(aakMsg.ErrCode) {
			r.ac.device.RemovePeerByAddress(registrationPeer.PublicKeyBase64(), registrationPeer.Host())

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
			r.ac.device.RemovePeerByAddress(registrationPeer.PublicKeyBase64(), registrationPeer.Host())

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
						r.ac.device.RemovePeerByAddress(oldPubKey, registrationPeer.Host())
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
							r.ac.device.RemovePeerByAddress(registrationPeer.PublicKeyBase64(), registrationPeer.Host())
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
				r.ac.device.RemovePeerByAddress(r.registrationPeer.PublicKeyBase64(), r.registrationPeer.Host())
			}
			r.registrationPeer = serverPeer
			r.mu.Unlock()
			log.Info("Received NHP_AAK: ACAddr=%s, Registered=%v (peer kept but no keepalive)", aakMsg.ACAddr, aakMsg.Registered)

			// Send registration success metric
			r.recordRegistrationSuccess(dimValDirect)

			return nil
		}

		udpAddr, ok := sendAddr.(*net.UDPAddr)
		if !ok {
			r.ac.device.RemovePeerByAddress(registrationPeer.PublicKeyBase64(), registrationPeer.Host())
			return fmt.Errorf("unexpected address type %T for server peer", sendAddr)
		}

		// If the server included a full peer list (all assigned servers), use it
		// to connect to every server. This ensures every AC reaches all servers
		// so knock fan-out can open ipset pinholes across all AZs.
		if len(aakMsg.Peers) > 0 {
			log.Info("Received NHP_AAK with %d peers, connecting to all assigned servers", len(aakMsg.Peers))

			ardMsg := &common.ACRedispatchMsg{
				Targets: aakMsg.Peers,
				ErrCode: common.ErrSuccess.ErrorCode(),
			}
			if err := r.HandleRedispatch(ardMsg); err != nil {
				// HandleRedispatch only errors when zero connections succeeded.
				// The AC still has its NLB registration peer, so it remains
				// operational — log a warning and continue rather than failing
				// the entire registration.
				log.Warning("Failed to connect to assigned peers (%v), keeping NLB peer", err)
				r.recordRegistrationSuccess(dimValDirect)
				return nil
			}

			// Remove the NLB registration peer only after HandleRedispatch
			// succeeds — otherwise a failure would leave the AC with no connections.
			r.ac.device.RemovePeerByAddress(registrationPeer.PublicKeyBase64(), registrationPeer.Host())

			r.recordRegistrationSuccess(dimValPeerRedispatch)
			return nil
		}

		r.mu.Lock()
		// Clean up old registration peer if exists (re-registration case)
		if r.registrationPeer != nil && r.registrationPeer.PublicKeyBase64() != serverPeer.PublicKeyBase64() {
			r.ac.device.RemovePeerByAddress(r.registrationPeer.PublicKeyBase64(), r.registrationPeer.Host())
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
		r.recordRegistrationSuccess(dimValDirect)

		return nil

	default:
		r.ac.device.RemovePeerByAddress(registrationPeer.PublicKeyBase64(), registrationPeer.Host())
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

	// Filter targets through RedirectTarget.Validate(). Invalid targets are
	// skipped with a warning so a single malformed upstream entry cannot
	// poison the whole redispatch, but if no valid targets remain we fail
	// the redispatch rather than corrupting r.assignedServers with an
	// unusable slice. See #832: hostname-only targets used to pass the old
	// "IP == '' && Hostname == ''" check and then broke every downstream
	// consumer that keyed on Target.IP.
	validTargets := make([]common.RedirectTarget, 0, len(ardMsg.Targets))
	for i, target := range ardMsg.Targets {
		if err := target.Validate(); err != nil {
			log.Warning("Skipping invalid redispatch target %d: %v", i, err)
			continue
		}
		validTargets = append(validTargets, target)
	}
	if len(validTargets) == 0 {
		return errors.New("no valid targets in redispatch message after filtering")
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
	r.assignedServers = make([]*AssignedServer, len(validTargets))

	for i, target := range validTargets {
		r.assignedServers[i] = &AssignedServer{
			Target:    target,
			Connected: false,
		}
		log.Info("Assigned server %d: %s:%d (AZ=%s)", i, target.Address(), target.Port, target.AZ)
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
				log.Warning("Failed to connect to assigned server %s: %v", s.Target.Address(), err)

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

	// Schedule old server cleanup (only if we had old servers to clean up).
	// Send to the cleanup worker channel instead of spawning a goroutine.
	if hasOldServers {
		select {
		case r.cleanupCh <- cleanupKey:
			log.Debug("Queued old server cleanup key %s", cleanupKey)
		default:
			log.Warning("Cleanup channel full, dropping cleanup key %s; old servers will be cleaned up on shutdown", cleanupKey)
		}
	}

	// Send server connections metric
	r.metrics.AddCounterWithDims(MetricServerConnections, float64(successCount), []types.Dimension{
		{Name: dimNameConnectionType, Value: dimValRedispatch},
	})

	return nil
}

// ConnectionTimeout is the timeout for connecting to an assigned server.
const ConnectionTimeout = 10 * time.Second

// connectToServer establishes connection to an assigned server.
func (r *ACRegistration) connectToServer(server *AssignedServer) error {
	// Create peer for this server.
	// Hostname is set from RedirectTarget.Hostname (for NLB drain redirects).
	// For direct IP connections, Hostname is empty — UdpPeer.ResolveHost()
	// correctly uses Ip when Hostname is empty.
	peer := &core.UdpPeer{
		Hostname:     server.Target.Hostname,
		Ip:           server.Target.IP,
		Port:         server.Target.Port,
		PubKeyBase64: server.Target.PubKeyBase64,
		ExpireTime:   0,
		Type:         core.NHP_SERVER,
	}

	// Resolve server address
	sendAddr := peer.SendAddr()
	if sendAddr == nil {
		return fmt.Errorf("cannot resolve address for server %s", server.Target.Address())
	}

	// Add peer to device
	r.ac.device.AddPeer(peer)
	server.Peer = peer

	// Send NHP_AOL to register with this server (use cached bytes)
	// Use buffered channel (size 1) to prevent sender from blocking if we exit early
	udpAddr, ok := sendAddr.(*net.UDPAddr)
	if !ok {
		r.ac.device.RemovePeerByAddress(peer.PublicKeyBase64(), peer.Host())
		return fmt.Errorf("unexpected address type %T for server %s", sendAddr, server.Target.Address())
	}
	md := &core.MsgData{
		RemoteAddr:    udpAddr,
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
		r.ac.device.RemovePeerByAddress(peer.PublicKeyBase64(), peer.Host())
		server.Peer = nil
		return errors.New("connection canceled")
	case <-time.After(ConnectionTimeout):
		r.ac.device.RemovePeerByAddress(peer.PublicKeyBase64(), peer.Host())
		server.Peer = nil
		return fmt.Errorf("connection to %s timed out", server.Target.Address())
	case ppd := <-md.ResponseMsgCh:
		if ppd.Error != nil {
			r.ac.device.RemovePeerByAddress(peer.PublicKeyBase64(), peer.Host())
			server.Peer = nil
			return fmt.Errorf("connection failed: %w", ppd.Error)
		}
		if ppd.HeaderType != core.NHP_AAK {
			r.ac.device.RemovePeerByAddress(peer.PublicKeyBase64(), peer.Host())
			server.Peer = nil
			return fmt.Errorf("unexpected response type: %s", core.HeaderTypeToString(ppd.HeaderType))
		}

		var aakMsg common.ServerACAckMsg
		if err := json.Unmarshal(ppd.BodyMessage, &aakMsg); err != nil {
			r.ac.device.RemovePeerByAddress(peer.PublicKeyBase64(), peer.Host())
			server.Peer = nil
			return fmt.Errorf("failed to parse NHP_AAK: %w", err)
		}

		if !common.IsSuccessErrCode(aakMsg.ErrCode) {
			r.ac.device.RemovePeerByAddress(peer.PublicKeyBase64(), peer.Host())
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
//
// Each tick also runs two complementary resilience checks that are layered
// underneath the existing health-check path:
//
//  1. checkAllUnconnected — fast detection (~30s) for the case where every
//     assigned server is in "never connected" state. The existing
//     checkServerHealth path explicitly skips servers with Connected=false,
//     so without this hook there is no signal to recover from when ALL
//     of them are still in the never-connected state (silent NAT rebind,
//     a transient network blip during the AC's bootstrap window, or a
//     bug in the registration response that handed back targets the AC
//     could never establish a flow with).
//
//  2. checkPeriodicNLBReregistration — slow defense-in-depth (~30min) that
//     fires regardless of per-server health. checkServerHealth needs at
//     least one previously-connected server to detect a problem; if every
//     UDP path is silently dead but no health signal has flipped, this
//     periodic refresh is the catch-all.
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

			// Resilience layer (see docstring above for what each one
			// catches and why they don't overlap with checkServerHealth).
			r.checkAllUnconnected()

			// Skip the periodic NLB safety net when checkAllUnconnected
			// already kicked off a re-registration this tick. The
			// CompareAndSwap inside TriggerReregistration would make a
			// duplicate call a no-op, but short-circuiting here avoids
			// the redundant log line and the duplicate metric increment.
			if !r.reregistering.Load() {
				r.checkPeriodicNLBReregistration()
			}
		}
	}
}

// sendKeepalives sends NHP_KPL to each assigned server to keep the UDP path active.
// NHP_KPL is unidirectional (fire-and-forget) — it does NOT update LastSeen.
// Server health is validated via periodic NHP_AOL refreshes (see refreshAssignedServerRegistrations).
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
		udpAddr, ok := sendAddr.(*net.UDPAddr)
		if !ok {
			log.Warning("Unexpected address type %T for server %s, skipping keepalive", sendAddr, server.Target.IP)
			continue
		}
		md := &core.MsgData{
			RemoteAddr:    udpAddr,
			HeaderType:    core.NHP_KPL,
			CipherScheme:  r.ac.config.DefaultCipherScheme,
			TransactionId: r.ac.device.NextCounterIndex(),
		}

		if r.ac.IsRunning() {
			r.ac.sendMsgCh <- md
			// NHP_KPL is unidirectional — the server receives but doesn't respond.
			// Do NOT update LastSeen here: we have no confirmation the server received
			// the keepalive. LastSeen is only updated when we receive a validated
			// NHP_AAK response to a periodic NHP_AOL refresh (see handleRefreshResponse).
			// This prevents spoofed or unrelated packets from masking server failures.
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
		udpAddr, ok := sendAddr.(*net.UDPAddr)
		if !ok {
			log.Warning("Unexpected address type %T for server %s during refresh, skipping", sendAddr, server.Target.IP)
			continue
		}
		go r.refreshSingleServer(server, udpAddr)
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
			log.Warning("Refresh rejected by server %s at %s: %s - %s", server.Target.IP, sendAddr.String(), aakMsg.ErrCode, aakMsg.ErrMsg)
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

// checkServerHealth checks assigned-server health and triggers re-registration
// only when all connected assigned servers appear unhealthy.
func (r *ACRegistration) checkServerHealth() {
	r.mu.RLock()
	servers := slices.Clone(r.assignedServers)
	r.mu.RUnlock()

	connectedCount := 0
	downConnectedCount := 0
	var firstDownServer *AssignedServer

	for _, server := range servers {
		// Skip servers that were never connected - they have zero LastSeen
		// which would always trigger false positives.
		if !server.IsConnected() {
			log.Debug("Health check: skipping server %s (never connected)", server.Target.IP)
			continue
		}

		connectedCount++

		if time.Since(server.GetLastSeen()) > KeepaliveInterval*KeepaliveMaxRetries {
			downConnectedCount++
			if firstDownServer == nil {
				firstDownServer = server
			}
		}
	}

	// No connected servers means no reliable health signal from keepalive path.
	if connectedCount == 0 {
		log.Debug("Health check: no connected servers to monitor")
		return
	}

	// Trigger re-registration only when all connected assigned servers are unhealthy.
	// This avoids churn when only part of the assigned server set is degraded.
	if downConnectedCount != connectedCount {
		return
	}

	if cooldownUntil := time.Unix(0, r.serverDownReregCooldownUntil.Load()); time.Now().Before(cooldownUntil) {
		log.Warning("All %d connected servers appear down, but re-registration is in backoff until %s", connectedCount, cooldownUntil.Format(time.RFC3339))
		return
	}

	// Check if already re-registering to prevent concurrent attempts
	if r.reregistering.CompareAndSwap(false, true) {
		log.Warning("All %d connected servers appear down, triggering re-registration", connectedCount)

		// Send server health failure metric.
		// Only ACId as extra dimension — no ServerIP to keep cardinality bounded
		// (server IPs change on every ASG launch).
		r.metrics.IncrCounterWithDims(MetricServerHealthFailures, []types.Dimension{
			r.acIdDimension(),
		})

		go r.handleServerDown(firstDownServer)
	} else if firstDownServer != nil {
		log.Debug("Server %s appears down but re-registration already in progress", firstDownServer.Target.IP)
	}
}

// handleServerDown handles when assigned-server health degrades enough to
// trigger a full re-registration attempt.
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
			r.serverDownReregFailures.Store(0)
			r.serverDownReregCooldownUntil.Store(0)
			r.lastNLBRegistrationNano.Store(time.Now().UnixNano())
			r.allUnconnectedTicks.Store(0)
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

	failures := r.serverDownReregFailures.Add(1)
	cooldown := KeepaliveInterval * time.Duration(1<<min(failures-1, 5))
	if cooldown > MaxServerDownReregBackoff {
		cooldown = MaxServerDownReregBackoff
	}
	until := time.Now().Add(cooldown)
	r.serverDownReregCooldownUntil.Store(until.UnixNano())

	log.Error("Re-registration failed after %d attempts, continuing with remaining servers", MaxReregistrationAttempts)
	log.Warning("Entering server-down re-registration backoff for %v after %d consecutive failure(s) (until %s)", cooldown, failures, until.Format(time.RFC3339))
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
				// A successful re-registration from any trigger should clear server-down
				// circuit-breaker state so future genuine outages are not suppressed.
				r.serverDownReregFailures.Store(0)
				r.serverDownReregCooldownUntil.Store(0)
				r.lastNLBRegistrationNano.Store(time.Now().UnixNano())
				r.allUnconnectedTicks.Store(0)
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

		// NOTE: We intentionally do NOT increment serverDownReregFailures here.
		// Connection-triggered re-registration has different semantics from the
		// health-check path — it fires once per disconnect event, not on a timer,
		// so applying circuit-breaker backoff would suppress legitimate retries.
		log.Error("Re-registration failed after %d attempts (triggered by: %s)", MaxReregistrationAttempts, reason)
	}()
}

// checkAllUnconnected catches the silent-failure mode where every assigned
// server is in the "never connected" state for several consecutive keepalive
// ticks. The existing checkServerHealth function explicitly skips servers
// with Connected=false (their LastSeen is zero, which would otherwise look
// like a stale connection), so when *every* assigned server is in that
// state checkServerHealth has nothing to act on and the AC will sit
// indefinitely with a fully-populated assigned-server slice but no
// functioning UDP path.
//
// Concretely this catches:
//   - Assigned servers that came back from registration but the AC's
//     initial NHP_AOL never reached them (port unreachable swallowed
//     somewhere upstream of the AC's socket).
//   - All UDP flows torn down simultaneously by a NAT rebinding event,
//     before any individual flow had a chance to trip the per-server
//     keepalive failure path.
//   - A future bug in the registration response that hands the AC
//     targets it cannot establish a flow with — having a generic
//     "we're stuck, ask the control plane again" mechanism is cheap
//     insurance against the long tail of new failure modes.
//
// It does NOT clear r.assignedServers itself: the recovery path is
// "trigger a fresh registration", and HandleRedispatch /
// handleRegistrationResponse atomically replace the slice when the
// response arrives, migrating the previous entries into oldServerSets
// for cleanup. Clearing the slice from this goroutine would race with a
// concurrent HandleRedispatch that might have just installed a fresh
// set of valid servers and silently drop those legitimate assignments.
func (r *ACRegistration) checkAllUnconnected() {
	r.mu.RLock()
	servers := slices.Clone(r.assignedServers)
	r.mu.RUnlock()

	if len(servers) == 0 {
		// Initial registration hasn't completed yet (or we just stopped).
		// Reset the counter so a brand-new bootstrap doesn't immediately
		// trip the threshold based on stale state.
		r.allUnconnectedTicks.Store(0)
		return
	}

	for _, server := range servers {
		if server.IsConnected() {
			r.allUnconnectedTicks.Store(0)
			return
		}
	}

	newTicks := r.allUnconnectedTicks.Add(1)

	// Emit the detection metric only on the 0->1 transition so each
	// incident counts once instead of inflating the counter by up to
	// allUnconnectedThreshold per occurrence. ACId dimension matches the
	// convention used by MetricServerHealthFailures so operators can pivot
	// on which AC is degraded.
	if newTicks == 1 {
		r.metrics.IncrCounterWithDims(MetricAllUnconnectedDetected, []types.Dimension{
			r.acIdDimension(),
		})
		log.Warning("AC %s: all %d assigned servers are unconnected (tick %d/%d)",
			r.ac.config.ACId, len(servers), newTicks, r.allUnconnectedThreshold)
	} else {
		// Continued detection: log at debug to avoid spamming production
		// logs every keepalive tick while the condition persists.
		log.Debug("AC %s: all %d assigned servers still unconnected (tick %d/%d)",
			r.ac.config.ACId, len(servers), newTicks, r.allUnconnectedThreshold)
	}

	if newTicks < r.allUnconnectedThreshold {
		return
	}

	// Threshold reached — trip a re-registration through the control
	// plane. Reset the tick counter immediately so we don't re-fire on
	// the next tick while the in-flight TriggerReregistration is still
	// running. Note we do NOT touch r.assignedServers here; see the
	// docstring above for why.
	log.Warning("AC %s: all assigned servers unconnected for %d consecutive ticks, triggering NLB re-registration",
		r.ac.config.ACId, newTicks)
	r.allUnconnectedTicks.Store(0)
	r.TriggerReregistration(ReasonAllServersUnconnected)
}

// timeSinceLastNLBRegistration returns the duration since the most recent
// successful NLB re-registration. Reads the atomic timestamp once so the
// caller sees a consistent value across the elapsed/threshold comparison.
func (r *ACRegistration) timeSinceLastNLBRegistration() time.Duration {
	return time.Since(time.Unix(0, r.lastNLBRegistrationNano.Load()))
}

// checkPeriodicNLBReregistration is the slow defense-in-depth safety net
// that fires every nlbReregistrationInterval regardless of any per-server
// health signal. It exists for the failure modes the per-server
// keepalive path simply cannot see:
//
//   - The AC believes it has live connections (LastSeen recent because
//     the NHP_AOL refresh path completed) but the underlying UDP flow
//     was silently rebound somewhere in the network and the server is
//     no longer receiving packets. The next NHP_AOP we'd send to that
//     AC would silently fail.
//   - A subset of servers in the assigned slice were quietly replaced
//     between health checks: re-registering through the NLB pulls the
//     authoritative current set without waiting for a per-server
//     keepalive to flip Connected=false.
//   - Any future failure mode where "the AC silently stops getting
//     server updates" is the symptom — having a bounded recovery window
//     prevents an indefinite paging incident.
//
// This is intentionally distinct from checkAllUnconnected:
// checkAllUnconnected fires within ~30 seconds when the failure is
// observable through Connected=false; this one fires once every
// ~30 minutes regardless and is the catch-all for "looks fine, isn't".
// Without both layers a bug whose symptom is "AC works for the first
// minute then silently goes deaf" could page on-call instead of
// self-healing.
func (r *ACRegistration) checkPeriodicNLBReregistration() {
	if r.timeSinceLastNLBRegistration() < r.nlbReregistrationInterval {
		return
	}

	// Only trigger if we already have assigned servers — otherwise the
	// initial registration loop is still running and we'd be racing with
	// it for no good reason.
	r.mu.RLock()
	hasServers := len(r.assignedServers) > 0
	r.mu.RUnlock()
	if !hasServers {
		return
	}

	log.Info("AC %s: periodic NLB re-registration triggered (last registration: %s ago, interval: %s)",
		r.ac.config.ACId,
		r.timeSinceLastNLBRegistration().Truncate(time.Second),
		r.nlbReregistrationInterval)

	r.TriggerReregistration(ReasonPeriodicNLBRefresh)
}

// cleanupWorker is a single long-lived goroutine that processes old-server
// cleanup requests from cleanupCh. It replaces the previous pattern of
// spawning an unbounded goroutine per HandleRedispatch call, which could
// accumulate many sleeping goroutines during rapid reassignments.
func (r *ACRegistration) cleanupWorker() {
	defer r.wg.Done()
	for {
		select {
		case cleanupKey, ok := <-r.cleanupCh:
			if !ok {
				return
			}
			// Wait the grace period before cleaning up, but exit early on stop.
			// Use time.NewTimer instead of time.After to avoid leaking the timer
			// goroutine when stopCh fires before the grace period elapses.
			timer := time.NewTimer(OldServerKeepDuration)
			select {
			case <-timer.C:
				r.cleanupOldServers(cleanupKey)
			case <-r.stopCh:
				timer.Stop()
				return
			}
		case <-r.stopCh:
			return
		}
	}
}

// cleanupOldServers removes old server connections for the given cleanup key.
// Called by the cleanupWorker after the grace period has elapsed.
func (r *ACRegistration) cleanupOldServers(cleanupKey string) {
	r.mu.Lock()
	oldServers := r.oldServerSets[cleanupKey]
	delete(r.oldServerSets, cleanupKey)
	r.mu.Unlock()

	for _, server := range oldServers {
		if server.Peer != nil {
			r.ac.device.RemovePeerByAddress(server.Peer.PublicKeyBase64(), server.Peer.Host())
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
		ReasonConnectionTimeout,
		ReasonAllServersUnconnected,
		ReasonPeriodicNLBRefresh:
		return reason
	default:
		return "other"
	}
}
