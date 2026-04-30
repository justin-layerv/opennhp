package server

import (
	"container/list"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/OpenNHP/opennhp/nhp/etcd"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/pion/webrtc/v4"

	"github.com/OpenNHP/opennhp/endpoints/metrics"
	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
	"github.com/OpenNHP/opennhp/nhp/log"
	"github.com/OpenNHP/opennhp/nhp/plugins"
	"github.com/OpenNHP/opennhp/nhp/utils"
	"github.com/OpenNHP/opennhp/nhp/version"
)

var (
	ExeDirPath string
)

// dimNameInstanceId is the canonical CloudWatch dimension name for
// per-instance metrics. Single source of truth so a typo (e.g.,
// "InstanceID") can't silently split the time series across two
// dimension values.
var dimNameInstanceId = aws.String("InstanceId")

// buildServerMetricDimensions returns the CloudWatch dimensions derived from environment
// variables. Dimensions: [Environment, Cell]. CloudWatch alarms and Grafana dashboard
// panels match on this exact set. Adding or removing dimensions creates a separate
// metric time series that existing alarms/panels won't find.
func buildServerMetricDimensions() []types.Dimension {
	environment := os.Getenv("NHP_ENVIRONMENT")
	if environment == "" {
		environment = "unknown"
	}
	cellID := os.Getenv("NHP_CELL_ID")
	if cellID == "" {
		cellID = "cell0"
	}

	return []types.Dimension{
		{Name: aws.String("Environment"), Value: aws.String(environment)},
		{Name: aws.String("Cell"), Value: aws.String(cellID)},
	}
}

type UdpServer struct {
	stats struct {
		totalRecvBytes uint64
		totalSendBytes uint64
	}

	config     *Config
	httpConfig *HttpConfig
	log        *log.Logger
	listenAddr *net.UDPAddr
	listenConn *net.UDPConn
	localIp    string
	localMac   string

	device       *core.Device
	httpServer   *HttpServer
	webrtcServer *WebRTCServer
	wg           sync.WaitGroup
	running      atomic.Bool

	// knockHeaderTypeVerifyRequire gates strict-mode rejection of
	// knocks whose AEAD-authenticated body.HeaderType disagrees with
	// the wire HeaderType (or is the zero-value NHP_KPL sentinel for
	// legacy agents). Read once at Start from
	// KnockHeaderTypeVerifyEnvVar — see knock_headertype_gate.go for
	// the gate policy and #1154 for the threat model.
	//
	// Concurrency: written once in Start before any UDP packet
	// dispatch, read lock-free from HandleKnockRequest's hot path.
	// Safe today because Start's env parse happens-before the
	// listener starts. A future refactor that allows live reconfig
	// (e.g., SIGHUP to re-read env) MUST promote this to
	// atomic.Bool or protect it behind a mutex; a bare read against
	// a concurrent write would be a Go memory-model violation even
	// if it happens to work on most architectures.
	knockHeaderTypeVerifyRequire bool

	// licensePubkeyVerifyRequire gates strict-mode rejection of AC
	// registrations whose presented static pubkey is not in the
	// License.BoundPubKeys allowlist (or whose license has no
	// allowlist). Read once at Start from LicensePubkeyVerifyEnvVar
	// — see license_pubkey_gate.go for the gate policy and #1155
	// for the threat model.
	//
	// Concurrency: same contract as knockHeaderTypeVerifyRequire —
	// written once in Start before any UDP packet dispatch, read
	// lock-free from validateACLicense's hot path. A future refactor
	// that allows live reconfig MUST promote this to atomic.Bool
	// or protect it behind a mutex.
	licensePubkeyVerifyRequire bool

	// acPubkeyCapVerifyRequire gates strict-mode rejection of AC
	// registrations whose presented static pubkey would push the
	// distinct-pubkey count for the claimed acId above
	// MaxACConnsPerID. Read once at Start from
	// ACPubkeyCapVerifyEnvVar — see ac_pubkey_cap_gate.go for the
	// gate policy and #1157 F3 for the threat model.
	//
	// Concurrency: same contract as licensePubkeyVerifyRequire.
	acPubkeyCapVerifyRequire bool

	// licenseACIDCustomerVerifyRequire gates strict-mode rejection of
	// AC registrations whose license CustomerID disagrees with the
	// ACAssignment-recorded CustomerID for the claimed acId. Read
	// once at Start from LicenseACIDCustomerVerifyEnvVar — see
	// license_customer_gate.go for the gate policy and #1157 F4 for
	// the threat model.
	//
	// Concurrency: same contract as licensePubkeyVerifyRequire.
	licenseACIDCustomerVerifyRequire bool

	// connection and remote transaction management

	remoteConnectionMapMutex sync.Mutex
	remoteConnectionMap      map[string]*UdpConn   // indexed by remote UDP address
	connectionsByIP          map[string]*list.List // per-IP FIFO of agent *UdpConn for MaxAgentConnsPerIP eviction; AC/DB excluded

	agentPeerMapMutex sync.Mutex
	agentPeerMap      map[string]*core.UdpPeer // indexed by peer's public key base64 string

	acConnectionMapMutex sync.RWMutex
	acConnectionMap      map[string][]*ACConn // ac connections indexed by AC ID, multiple per ID for blue/green

	acPeerMapMutex sync.Mutex
	acPeerMap      map[string]*core.UdpPeer // indexed by peer's public key base64 string

	dbConnectionMapMutex sync.Mutex
	dbConnectionMap      map[string]*DBConn // ac connection is indexed by remote IP address

	tokenStore *common.TokenStore[*ACTokenEntry]

	// block address management.
	// RWMutex so per-packet reads don't serialize with concurrent readers.
	// Keyed by remote IP only (not IP:port) — an attacker rotating source
	// ports cannot bypass a block by switching ports (#1160 T3-12). The
	// BlockSignal hot path passes the originating *net.UDPAddr; helpers
	// extract IP for keying.
	blockAddrMapMutex sync.RWMutex
	blockAddrMap      map[string]*BlockAddr // indexed by remote IP

	// address association map
	srcIpAssociatedAddrMapMutex sync.Mutex
	srcIpAssociatedAddrMap      map[string][]*common.NetAddress // indexed by source ip

	// preset asp-resource-address map
	authServiceMapMutex sync.RWMutex
	authServiceMap      common.AuthSvcProviderMap // indexed by asp id and then resource id

	// plugin handlers
	pluginHandlerMapMutex sync.RWMutex
	pluginHandlerMap      map[string]plugins.PluginHandler

	// signals
	signals struct {
		stop chan struct{}
	}

	recvMsgCh <-chan *core.PacketParserData
	sendMsgCh chan *core.MsgData

	//NHP-DB
	dbPeerMapMutex sync.Mutex
	dbPeerMap      map[string]*core.UdpPeer // indexed by peer's public key base64 string

	teeMapMutex sync.Mutex
	teeMap      map[string]*TeeAttestationReport // indexed by tee's measure

	// etcd client
	etcdConn                *etcd.EtcdConn
	remoteConfigUpdateMutex sync.Mutex

	// Pluggable storage backend (DynamoDB for cloud, etcd for on-prem)
	// See docs/design/PLUGGABLE_STORAGE_BACKEND.md for architecture details.
	storage       StorageBackend // DynamoDB (cloud) or etcd (on-prem)
	storageConfig *StorageConfig
	forwarder     *ServerForwarder // Server-to-server knock forwarding

	// Cloud Map client for server health discovery.
	// Used to filter stale AC assignments pointing to terminated servers.
	cloudMap *CloudMapClient

	// EC2 instance identity (populated from IMDS in cloud mode)
	instanceID string // EC2 instance ID (e.g., "i-0abc123")
	instanceAZ string // Availability zone (e.g., "us-east-2a")
	asgName    string // ASG name from IMDS Name tag (blue/green filtering)

	// TTL refresh throttle: tracks last refresh time per AC ID to prevent
	// excessive DynamoDB writes from frequent AC re-registrations.
	ttlRefreshTimes sync.Map // acID -> time.Time

	// CloudWatch metrics publisher for NHP operational metrics.
	metrics *metrics.Publisher

	// Per-source-IP rate limiter for UDP knock packets.
	// Drops packets that exceed the configured rate to mitigate DoS attacks
	// before any cryptographic processing occurs.
	rateLimiter    *IPRateLimiter
	rateLimitDrops atomic.Int64 // total dropped packets, for sampled logging

	// Per-IP agent-conn eviction warning counter, for sampled logging.
	// MetricAgentConnPerIPEvictions is the source of truth; this counter
	// just throttles the warn-log to 1 + every 1000th eviction.
	perIPEvictionWarns atomic.Int64

	// Rate limiter for license validation (brute-force prevention).
	licenseRateLimiter *LicenseRateLimiter
}

type BlockAddr struct {
	expireTime time.Time
}

type UdpConn struct {
	ConnData       *core.ConnectionData
	isACConnection bool // Immutable. Don't change it after creation. Conn object is also stored in acConnectionMap which is indexed by ACId
	isDBConnection bool // Immutable. Don't change it after creation. Conn object is also stored in dbConnectionMap which is indexed by DBId
	isWebRTC       bool
	dc             *webrtc.DataChannel

	// perIPElem is the conn's slot in connectionsByIP[ip]; nil for AC/DB.
	// Cleared on eviction so the cleanup defer doesn't double-pop.
	perIPElem *list.Element

	// evictSignal contract:
	//   - MUST be non-nil for any UdpConn passed to connectionRoutine
	//     or admitNewConnection. admitNewConnection panics on nil.
	//   - Closed exactly once by admitNewConnection on per-IP cap
	//     eviction; never closed by any other path.
	//   - For AC/DB conns and WebRTC conns, the channel is allocated
	//     for select-shape consistency but never closed (those paths
	//     bypass the per-IP cap).
	// Dedicated channel (rather than reusing SetTimeoutSignal) so the
	// receive loop doesn't hold the map mutex across a connection
	// routine that may be mid-WriteToUDP.
	evictSignal chan struct{}
}

type ACConn struct {
	ConnData       *core.ConnectionData
	ACPeer         *core.UdpPeer
	ACCipherScheme int
	ACId           string
	ServiceId      string
	Apps           []string
}

type DBConn struct {
	ConnData       *core.ConnectionData
	DBPeer         *core.UdpPeer
	DBCipherScheme int
	DBId           string
}

type TeeAttestationReport struct {
	Measure      string `json:"measure"`
	SerialNumber string `json:"serialNumber"`
	Verified     bool   `json:"verified"`
}

type TeeAttestationReports struct {
	TEEs []*TeeAttestationReport `json:"tees"`
}

func (c *UdpConn) Close() {
	c.ConnData.Close()
}

/*
dirPath: the path of app or shared library entry point
logLevel: 0: silent, 1: error, 2: info, 3: debug, 4: verbose
*/
// UDP server never actively sends first packet outwards. It only reacts to received packet then sends response.
func (s *UdpServer) Start(dirPath string, logLevel int) (err error) {
	plugins.ExeDirPath = dirPath
	ExeDirPath = dirPath

	// init logger
	s.log = log.NewLogger("NHP-Server", logLevel, filepath.Join(ExeDirPath, "logs"), "server")
	log.SetGlobalLogger(s.log)

	log.Info("=========================================================")
	log.Info("=== NHP-Server %s started              ===", version.Version)
	log.Info("=== REVISION %s ===", version.CommitId)
	log.Info("=== RELEASE %s                       ===", version.BuildTime)
	log.Info("=========================================================")

	// Initialize etcd connection for AC registry discovery (if configured)
	// This does NOT affect base config loading - private key always comes from local config.toml
	err = s.initRemoteConn()
	if err != nil {
		// Log warning but continue - etcd is optional for config, required only for AC discovery
		log.Warning("initRemoteConn failed: %v (AC registry discovery disabled)", err)
	}

	// Always load base config from local config.toml first
	// The private key is per-server and stored in Secrets Manager, not shared etcd
	err = s.loadBaseConfig()
	if err != nil {
		return err
	}

	// Parse NHP_KNOCK_HEADERTYPE_VERIFY (#1154). Fail Start on an
	// unrecognized token so an operator typo cannot silently leave
	// the gate in permit mode. See knock_headertype_gate.go.
	s.knockHeaderTypeVerifyRequire, err = parseKnockHeaderTypeVerify(os.Getenv(KnockHeaderTypeVerifyEnvVar))
	if err != nil {
		return fmt.Errorf("%s: %w", KnockHeaderTypeVerifyEnvVar, err)
	}
	if s.knockHeaderTypeVerifyRequire {
		log.Info("Knock HeaderType verify gate: strict mode (#1154); mismatches reject with 52009, legacy agents with 52010")
	} else {
		// Echo the dashboard keys an operator should alarm on before
		// flipping strict. The rollout playbook is "watch legacy
		// drain to zero, then watch mismatch stay at zero in burn-in,
		// then flip NHP_KNOCK_HEADERTYPE_VERIFY=true."
		log.Info("Knock HeaderType verify gate: permit mode (#1154); watch %s (rollout) and %s (attack) before flipping NHP_KNOCK_HEADERTYPE_VERIFY=true",
			MetricKnockHeaderTypeLegacy, MetricKnockHeaderTypeMismatch)
	}

	// Parse NHP_LICENSE_PUBKEY_VERIFY (#1155). Fail Start on an
	// unrecognized token so an operator typo cannot silently leave
	// the gate in permit mode. See license_pubkey_gate.go.
	s.licensePubkeyVerifyRequire, err = parseLicensePubkeyVerify(os.Getenv(LicensePubkeyVerifyEnvVar))
	if err != nil {
		return fmt.Errorf("%s: %w", LicensePubkeyVerifyEnvVar, err)
	}
	if s.licensePubkeyVerifyRequire {
		log.Info("License pubkey verify gate: strict mode (#1155); pubkey mismatch rejects with 52012, unbound license with 52013")
	} else {
		log.Info("License pubkey verify gate: permit mode (#1155); watch %s (rollout) and %s (attack) before flipping NHP_LICENSE_PUBKEY_VERIFY=true",
			MetricLicensePubkeyUnbound, MetricLicensePubkeyMismatch)
	}

	// Parse NHP_AC_PUBKEY_CAP_VERIFY (#1157 F3). Fail Start on an
	// unrecognized token so an operator typo cannot silently leave
	// the gate in permit mode. See ac_pubkey_cap_gate.go.
	s.acPubkeyCapVerifyRequire, err = parseACPubkeyCapVerify(os.Getenv(ACPubkeyCapVerifyEnvVar))
	if err != nil {
		return fmt.Errorf("%s: %w", ACPubkeyCapVerifyEnvVar, err)
	}
	if s.acPubkeyCapVerifyRequire {
		log.Info("AC pubkey-cap gate: strict mode (#1157 F3); distinct-pubkey cap exceeded rejects with 52015")
	} else {
		log.Info("AC pubkey-cap gate: permit mode (#1157 F3); watch %s before flipping NHP_AC_PUBKEY_CAP_VERIFY=true",
			MetricACPubkeyCapExceeded)
	}

	// Parse NHP_LICENSE_ACID_CUSTOMER_VERIFY (#1157 F4). Fail Start
	// on an unrecognized token so an operator typo cannot silently
	// leave the gate in permit mode. See license_customer_gate.go.
	s.licenseACIDCustomerVerifyRequire, err = parseLicenseACIDCustomerVerify(os.Getenv(LicenseACIDCustomerVerifyEnvVar))
	if err != nil {
		return fmt.Errorf("%s: %w", LicenseACIDCustomerVerifyEnvVar, err)
	}
	if s.licenseACIDCustomerVerifyRequire {
		log.Info("License-customer cross-check gate: strict mode (#1157 F4); customer mismatch rejects with 52017")
	} else {
		log.Info("License-customer cross-check gate: permit mode (#1157 F4); watch %s (attack) and %s (storage flap) before flipping NHP_LICENSE_ACID_CUSTOMER_VERIFY=true",
			MetricLicenseCustomerMismatch, MetricLicenseCustomerLookupErr)
	}

	// Initialize pluggable storage backend (DynamoDB or etcd)
	// See docs/design/PLUGGABLE_STORAGE_BACKEND.md for architecture details.
	s.storageConfig, err = s.loadStorageConfig()
	if err != nil {
		log.Warning("Failed to load storage config, storage backend disabled: %v", err)
		// Continue without storage - fall back to etcd/local config for AC discovery
	} else if s.storageConfig != nil && s.storageConfig.Backend != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		s.storage, err = CreateStorageBackend(ctx, *s.storageConfig)
		if err != nil {
			log.Warning("Failed to create storage backend (%s): %v", s.storageConfig.Backend, err)
			// Continue without storage - fall back to etcd/local config
		} else {
			log.Info("Storage backend initialized: %s", s.storage.Name())
		}
	}

	// Initialize license rate limiter for brute-force prevention.
	// Defaults are applied in loadStorageConfig() if not configured.
	if s.storageConfig != nil {
		rlConfig := s.storageConfig.RateLimit
		s.licenseRateLimiter = NewLicenseRateLimiter(rlConfig)
		log.Info("License rate limiter initialized (enabled=%t, ip_limit=%d/%ds, ac_limit=%d/%ds)",
			rlConfig.Enabled, rlConfig.MaxFailuresPerIP, rlConfig.WindowSeconds,
			rlConfig.MaxFailuresPerACID, rlConfig.WindowSeconds)
	}

	// Initialize Cloud Map client for server health discovery (if configured).
	// This is used to filter stale AC assignments pointing to terminated servers.
	if s.storageConfig != nil && s.storageConfig.CloudMap.Enabled {
		cloudMapCtx, cloudMapCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cloudMapCancel()

		var cloudMapErr error
		s.cloudMap, cloudMapErr = NewCloudMapClient(cloudMapCtx, s.storageConfig.CloudMap)
		if cloudMapErr != nil {
			// Fail-fast: if CloudMap is explicitly enabled, it must work.
			// A silent failure here would cause nil pointer panics later when
			// processing AC registrations (in handleACServerAssignment).
			log.Error("Failed to initialize Cloud Map client: %v", cloudMapErr)
			return fmt.Errorf("cloudmap client initialization failed (cloudmap.enabled=true): %w", cloudMapErr)
		}
		log.Info("Cloud Map client initialized for server health filtering")
	}

	// Initialize CloudWatch metrics publisher (non-fatal if unavailable)
	s.metrics = metrics.NewPublisher(metrics.Config{
		Namespace:  "LayerV/NHP",
		Dimensions: buildServerMetricDimensions(),
	})

	// Initialize per-source-IP rate limiter for UDP knock packets.
	// Defense-in-depth alongside iptables rate limiting (see user_data.sh.tpl).
	// Drops packets before cryptographic processing to reduce CPU cost of DoS.
	rlCfg := DefaultRateLimiterConfig()
	s.rateLimiter = NewIPRateLimiter(rlCfg)
	log.Info("UDP rate limiter initialized: %.0f pps sustained, %d burst per source IP",
		rlCfg.Rate, rlCfg.Burst)

	// Initialize server-to-server forwarder
	s.forwarder = NewServerForwarder(s)
	s.forwarder.Start()

	if s.config.WebRTC.Enable {
		s.webrtcServer = NewWebRTCServer(s, &s.config.WebRTC)
		if err := s.webrtcServer.Start(); err != nil {
			log.Error("[Server] failed to start WebRTC server: %v", err)
		}
	}

	var netIP net.IP
	if len(s.config.ListenIp) > 0 {
		netIP = net.ParseIP(s.config.ListenIp)
		if netIP == nil {
			log.Error("[Server] UDP listen IP address is incorrect")
			return errors.New("udp listen ip address is incorrect")
		}
	} else {
		netIP = net.IPv4zero // will both listen on ipv4 0.0.0.0:port and ipv6 [::]:port
	}

	s.listenConn, err = net.ListenUDP("udp", &net.UDPAddr{
		IP:   netIP,
		Port: s.config.ListenPort,
	})
	if err != nil {
		log.Error("[Server] listen error on %s: %v", s.listenAddr.String(), err)
		return fmt.Errorf("listen error: %w", err)
	}

	// SO_RCVBUF tuning. Rationale + sysctl coupling live in
	// udp_recv_buffer.go; failures here are non-fatal so a misconfigured
	// sysctl can't keep the server out of rotation.
	rcvBufTarget, err := parseUDPRecvBufferSize(os.Getenv(UDPRecvBufferEnvVar))
	if err != nil {
		// listenConn was created above; close it before returning so
		// the OS doesn't carry the FD past Start() failure.
		_ = s.listenConn.Close()
		return err
	}
	tuneUDPRecvBuffer(s.listenConn, rcvBufTarget)

	// retrieve local port
	laddr := s.listenConn.LocalAddr()
	s.listenAddr, err = net.ResolveUDPAddr(laddr.Network(), laddr.String())
	if err != nil {
		log.Error("[Server] failed to resolve local UDPAddr: %v", err)
		return fmt.Errorf("resolve UDPAddr error: %w", err)
	}

	prk, err := base64.StdEncoding.DecodeString(s.config.PrivateKeyBase64)
	if err != nil {
		log.Error("[Server] private key parse error: %v", err)
		return fmt.Errorf("private key parse error: %w", err)
	}

	// In cloud mode (storage_backend = "dynamodb"), disable AC peer pre-validation.
	// AC authentication will be done via license validation in HandleACOnline
	// instead of requiring pre-registered public keys from etcd.
	// See docs/design/PLUGGABLE_STORAGE_BACKEND.md Section 6.2 for details.
	cloudMode := s.storageConfig != nil && s.storageConfig.Backend == StorageBackendDynamoDB
	if cloudMode {
		log.Info("Cloud mode (storage_backend=dynamodb): AC peer pre-validation disabled, will validate via DynamoDB")
	}

	option := &core.DeviceOptions{
		DisableAgentPeerValidation: s.config.DisableAgentValidation,
		DisableACPeerValidation:    cloudMode,
	}
	s.device = core.NewDevice(core.NHP_SERVER, prk, option)
	if s.device == nil {
		log.Critical("failed to create device")
		return errors.New("failed to create device")
	}

	// retrieve local ip and mac
	localAddr := utils.GetLocalOutboundAddress()
	if localAddr != nil {
		s.localIp = localAddr.String()
	}
	s.localMac = utils.GetMacAddress(s.localIp)

	// In cloud mode, fetch instance identity from IMDS and register public key with Cloud Map
	if cloudMode && s.cloudMap != nil {
		s.registerWithCloudMap()
	}

	s.recordServerStartup()

	// load asp resources and plugins
	s.pluginHandlerMap = make(map[string]plugins.PluginHandler)
	if s.etcdConn != nil {
		// Try to load additional config from etcd (optional)
		// This loads HTTP config, agent peers, resources, etc. from /nhp/config key
		// Note: The key may not exist if etcd is used only for AC registry
		if err := s.loadRemoteConfig(); err != nil {
			log.Info("Remote config not loaded from etcd (key may not exist): %v", err)
			// Fall back to local config files for HTTP, peers, resources
			if loadErr := s.loadPeers(); loadErr != nil {
				log.Error("[Server] failed to load peers: %v", loadErr)
			}
			if loadErr := s.loadHttpConfig(); loadErr != nil {
				log.Error("[Server] failed to load HTTP config: %v", loadErr)
			}
			if loadErr := s.loadSourceIps(); loadErr != nil {
				log.Error("[Server] failed to load source IPs: %v", loadErr)
			}
			if loadErr := s.loadResources(); loadErr != nil {
				log.Error("[Server] failed to load resources: %v", loadErr)
			}
		}

		// Load AC registry - per-instance AC keys registered dynamically
		// This watches /nhp/ac-registry/ prefix for AC registrations
		// ACs register themselves with their public keys on startup
		if err := s.loadACRegistry(); err != nil {
			log.Error("Failed to load AC registry: %v", err)
			// Continue anyway - will use ACs from local ac.toml if present
		}
	} else {
		// load peers
		if err := s.loadPeers(); err != nil {
			log.Error("[Server] failed to load peers: %v", err)
		}

		// load http config and turn on http server if needed
		if err := s.loadHttpConfig(); err != nil {
			log.Error("[Server] failed to load HTTP config: %v", err)
		}

		// load ip associated addresses
		if err := s.loadSourceIps(); err != nil {
			log.Error("[Server] failed to load source IPs: %v", err)
		}

		if err := s.loadResources(); err != nil {
			log.Error("[Server] failed to load resources: %v", err)
		}
	}

	s.remoteConnectionMap = make(map[string]*UdpConn)
	s.connectionsByIP = make(map[string]*list.List)
	s.acConnectionMap = make(map[string][]*ACConn)
	s.dbConnectionMap = make(map[string]*DBConn)
	s.tokenStore = common.NewTokenStore[*ACTokenEntry]()
	s.blockAddrMap = make(map[string]*BlockAddr)
	s.signals.stop = make(chan struct{})

	s.recvMsgCh = s.device.DecryptedMsgQueue
	s.sendMsgCh = make(chan *core.MsgData, core.SendQueueSize)

	// start device routines
	s.device.Start()

	// start server routines
	s.wg.Add(5)
	go s.tokenStore.RunRefreshRoutine(&s.wg, s.signals.stop, TokenStoreRefreshInterval)
	go s.BlockAddrRefreshRoutine()
	go s.recvPacketRoutine()
	go s.sendMessageRoutine()
	go s.recvMessageRoutine()

	s.running.Store(true)
	return nil
}

func (s *UdpServer) Stop() {
	if !s.running.Load() {
		// already stopped, do nothing
		return
	}
	s.running.Store(false)
	// stop http server first
	if s.httpServer != nil {
		s.httpServer.Stop()
	}
	if s.etcdConn != nil {
		s.etcdConn.Close()
	}
	if s.webrtcServer != nil {
		s.webrtcServer.Stop()
	}
	// Best-effort cleanup: remove this server from AC assignments
	s.cleanupOwnedAssignments()
	// Best-effort cleanup: deregister from Cloud Map so peers stop forwarding to us
	if s.cloudMap != nil && s.instanceID != "" {
		drCtx, drCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer drCancel()
		if err := s.cloudMap.DeregisterInstance(drCtx, s.instanceID); err != nil {
			log.Warning("Failed to deregister instance %s from Cloud Map: %v", s.instanceID, err)
			if s.metrics != nil {
				s.metrics.IncrCounter(MetricCloudMapDeregisterFailure)
			}
		}
	}
	// Drain AC connections: send NHP_ARD redirecting ACs to NLB for immediate reconnect.
	// Must run before close(s.signals.stop) because drain sends via s.sendMsgCh.
	s.drainACConnections()
	// Stop forwarder cleanup routine
	if s.forwarder != nil {
		s.forwarder.Stop()
	}
	// Stop license rate limiter cleanup goroutine
	if s.licenseRateLimiter != nil {
		s.licenseRateLimiter.Stop()
	}
	// Flush remaining CloudWatch metrics
	if s.metrics != nil {
		s.metrics.Stop()
	}
	close(s.signals.stop)
	_ = s.listenConn.Close()
	s.device.Stop()
	s.StopConfigWatch()
	s.wg.Wait()
	// Close storage backend AFTER wg.Wait() so in-flight goroutines
	// (e.g., refreshAssignmentTTL) finish their storage operations first.
	if s.storage != nil {
		_ = s.storage.Close()
	}
	close(s.sendMsgCh)
	s.ClosePlugins()

	log.Info("==========================")
	log.Info("=== NHP-Server stopped ===")
	log.Info("==========================")
	s.log.Close()
}

// ACPeerCount returns the number of unique AC peers with active connections.
// This counts distinct AC IDs (not total connections per AC, which may be >1
// during blue/green deployments). For health checking, at least one AC peer
// means knock traffic can be processed.
// Implements health.ACPeerCounter for the AC-aware health check.
func (s *UdpServer) ACPeerCount() int {
	s.acConnectionMapMutex.RLock()
	defer s.acConnectionMapMutex.RUnlock()
	return len(s.acConnectionMap)
}

// MaxACConnsForAnyID returns the maximum number of connections held by any
// single AC ID. During blue/green deployments this is typically 2 (one per
// color). A sustained value at MaxACConnsPerID indicates eviction pressure.
func (s *UdpServer) MaxACConnsForAnyID() int {
	s.acConnectionMapMutex.RLock()
	defer s.acConnectionMapMutex.RUnlock()
	maxConns := 0
	for _, conns := range s.acConnectionMap {
		if len(conns) > maxConns {
			maxConns = len(conns)
		}
	}
	return maxConns
}

// TotalACConns returns the total number of AC connections across all AC IDs.
func (s *UdpServer) TotalACConns() int {
	s.acConnectionMapMutex.RLock()
	defer s.acConnectionMapMutex.RUnlock()
	total := 0
	for _, conns := range s.acConnectionMap {
		total += len(conns)
	}
	return total
}

// cleanupOwnedAssignments is called during shutdown to best-effort remove this
// server from AC assignments it's part of. This helps reduce stale forwarding
// attempts while the 30-minute TTL and Cloud Map health checks provide the
// primary staleness protection.
func (s *UdpServer) cleanupOwnedAssignments() {
	if s.storage == nil {
		return
	}

	selfID := s.getServerID()
	if selfID == "" {
		return
	}

	// Collect AC IDs from current connections (read-only snapshot)
	s.acConnectionMapMutex.RLock()
	acIDs := make([]string, 0, len(s.acConnectionMap))
	for acID := range s.acConnectionMap {
		acIDs = append(acIDs, acID)
	}
	s.acConnectionMapMutex.RUnlock()

	if len(acIDs) == 0 {
		return
	}

	log.Info("Shutdown: cleaning up %d AC assignments", len(acIDs))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for _, acID := range acIDs {
		assignment, err := s.storage.GetACAssignment(ctx, acID)
		if err != nil {
			continue
		}

		// Remove self from assigned servers
		updated := make([]ServerInfo, 0, len(assignment.AssignedServers))
		for _, srv := range assignment.AssignedServers {
			if srv.ID != selfID {
				updated = append(updated, srv)
			}
		}

		if len(updated) == len(assignment.AssignedServers) {
			continue // This server wasn't in the assignment
		}

		// Clone to avoid mutating cached pointer
		newAssignment := assignment.Clone()
		newAssignment.AssignedServers = updated
		newAssignment.Version = assignment.Version + 1

		if saveErr := s.storage.SaveACAssignment(ctx, newAssignment); saveErr != nil {
			if IsVersionConflictError(saveErr) {
				log.Debug("Shutdown: version conflict for AC %s (concurrent update), skipping", acID)
				continue
			}
			log.Debug("Shutdown: failed to update assignment for AC %s: %v", acID, saveErr)
		} else {
			log.Debug("Shutdown: removed self from AC %s assignment (%d servers remaining)", acID, len(updated))
		}
	}

	// Clear TTL refresh throttle map to release memory
	s.ttlRefreshTimes.Range(func(key, _ any) bool {
		s.ttlRefreshTimes.Delete(key)
		return true
	})
}

// drainFlushDelay is how long to wait after queuing drain messages for the
// encrypt→send pipeline to flush packets onto the wire. NHP_ARD is small
// (~200 bytes) and the pipeline is non-blocking after enqueueing.
const drainFlushDelay = 100 * time.Millisecond

// hostLookup is the default DNS resolver used by buildDrainRedirectTarget.
// It is a package-level variable so tests can inject a deterministic resolver
// without touching the system resolver.
var hostLookup = net.LookupHost

// buildDrainRedirectTarget resolves the NLB hostname and constructs a
// RedirectTarget suitable for an NHP_ARD drain message.
//
// The RedirectTarget contract requires IP to be populated (see #832). The
// server's graceful-drain code previously emitted a hostname-only target,
// which the AC accepted but downstream consumer code (refreshAssigned-
// ServerRegistrations, IsServerAddress, logging) could not use because
// Target.IP was empty. The returned target is guaranteed to pass
// RedirectTarget.Validate() — callers should treat a non-nil error as
// "skip the drain entirely" rather than attempting to fall back to a
// hostname-only target.
func buildDrainRedirectTarget(hostname string, port int, pubKey string) (common.RedirectTarget, error) {
	if hostname == "" {
		return common.RedirectTarget{}, errors.New("hostname is empty")
	}
	addrs, err := hostLookup(hostname)
	if err != nil {
		return common.RedirectTarget{}, fmt.Errorf("resolving %q: %w", hostname, err)
	}
	if len(addrs) == 0 {
		return common.RedirectTarget{}, fmt.Errorf("resolver returned no addresses for %q", hostname)
	}
	target := common.RedirectTarget{
		IP:           addrs[0],
		Hostname:     hostname,
		Port:         port,
		PubKeyBase64: pubKey,
	}
	if err := target.Validate(); err != nil {
		return common.RedirectTarget{}, fmt.Errorf("built invalid drain target: %w", err)
	}
	return target, nil
}

// drainACConnections sends NHP_ARD to all connected ACs, redirecting them
// to the NLB so they reconnect to surviving servers immediately.
// Called during shutdown, before sendMessageRoutine is stopped.
func (s *UdpServer) drainACConnections() {
	if s.config.Hostname == "" {
		log.Warning("Shutdown: cannot drain without Hostname configured")
		return
	}

	// Snapshot connections under read lock — check before doing any work
	s.acConnectionMapMutex.RLock()
	totalConns := 0
	for _, acConns := range s.acConnectionMap {
		totalConns += len(acConns)
	}
	conns := make([]*ACConn, 0, totalConns)
	for _, acConns := range s.acConnectionMap {
		conns = append(conns, acConns...)
	}
	s.acConnectionMapMutex.RUnlock()

	if len(conns) == 0 {
		return
	}

	// Resolve NLB hostname at construction time so Target.IP is populated.
	// RedirectTarget.IP is required by the contract (#832): downstream
	// consumer code (refreshAssignedServerRegistrations, IsServerAddress)
	// uses Target.IP as a stable identifier. A hostname-only target would
	// silently corrupt the AC's assignedServers slice. If resolution fails,
	// skip the drain entirely — ACs will reconnect via NLB on the next
	// keepalive failure.
	nlbTarget, err := buildDrainRedirectTarget(s.config.Hostname, s.config.ListenPort, s.device.PublicKeyBase64())
	if err != nil {
		log.Warning("Shutdown: skipping drain ARD (ACs will reconnect via NLB on next keepalive failure): %v", err)
		return
	}
	ardMsg := &common.ACRedispatchMsg{
		Targets: []common.RedirectTarget{nlbTarget},
		ErrCode: common.ErrSuccess.ErrorCode(),
	}
	ardBytes, err := json.Marshal(ardMsg)
	if err != nil {
		log.Error("Shutdown: failed to marshal drain ARD: %v", err)
		return
	}

	log.Info("Shutdown: draining %d AC connections to NLB", len(conns))

	sent := 0
	for _, conn := range conns {
		md := &core.MsgData{
			ConnData:      conn.ConnData,
			HeaderType:    core.NHP_ARD,
			CipherScheme:  conn.ACCipherScheme,
			TransactionId: s.device.NextCounterIndex(),
			Compress:      true,
			PeerPk:        conn.ACPeer.PublicKey(),
			Message:       ardBytes,
			// No ResponseMsgCh — fire-and-forget
		}
		select {
		case s.sendMsgCh <- md:
			sent++
		default:
			log.Warning("Shutdown: sendMsgCh full, skipped drain for 1 AC")
		}
	}

	time.Sleep(drainFlushDelay)

	log.Info("Shutdown: drained %d/%d AC connections", sent, len(conns))
}

// registerWithCloudMap fetches EC2 instance identity from IMDS and registers
// this server's public key with Cloud Map. This enables DiscoverServerInstances
// to return full ServerInfo including the public key for NHP_ARD.
func (s *UdpServer) registerWithCloudMap() {
	imdsClient := &http.Client{Timeout: 2 * time.Second}

	// Obtain a single IMDS token and reuse it for all metadata fetches
	// (avoids 3 separate token PUT requests).
	token, err := imdsV2Token(imdsClient)
	if err != nil {
		log.Error("Failed to get IMDS token: %v (Cloud Map registration skipped, auto-assignment will use hostname fallback)", err)
		return
	}

	// Fetch instance ID
	instanceID, err := imdsV2GetWithToken(imdsClient, token, "http://169.254.169.254/latest/meta-data/instance-id")
	if err != nil {
		log.Error("Failed to get instance ID from IMDS: %v (Cloud Map registration skipped, auto-assignment will use hostname fallback)", err)
		return
	}
	s.instanceID = strings.TrimSpace(instanceID)

	// Fetch AZ
	az, err := imdsV2GetWithToken(imdsClient, token, "http://169.254.169.254/latest/meta-data/placement/availability-zone")
	if err != nil {
		log.Warning("Failed to get AZ from IMDS: %v", err)
		az = "unknown"
	}
	s.instanceAZ = strings.TrimSpace(az)

	// Fetch ASG name from IMDS Name tag for blue/green filtering.
	// The Name tag matches the ASG name (e.g., "layerv-nhp-sandbox-server" vs
	// "layerv-nhp-sandbox-server-green"). AWS-prefixed tags like
	// aws:autoscaling:groupName are NOT accessible via IMDS.
	// COUPLING: Requires ASG tag propagation to set Name = ASG name
	// (configured via propagate_at_launch in terraform/modules/compute/main.tf
	// and terraform/modules/ac/main.tf). If the Name tag diverges from the
	// ASG name, filtering silently degrades to fail-open (no outage, but no
	// blue/green protection). Escape hatch: ec2:DescribeTags API has the
	// authoritative aws:autoscaling:groupName but requires IAM permissions.
	asgName, err := imdsV2GetWithToken(imdsClient, token, "http://169.254.169.254/latest/meta-data/tags/instance/Name")
	if err != nil {
		log.Warning("Failed to get Name tag from IMDS: %v (blue/green filtering disabled)", err)
	} else if trimmed := strings.TrimSpace(asgName); trimmed == "" {
		log.Warning("IMDS Name tag is empty/whitespace (blue/green filtering disabled)")
	} else {
		s.asgName = trimmed
	}

	// Register with Cloud Map including PUBLIC_KEY
	// IMPORTANT: RegisterInstance REPLACES all attributes. Must re-include IP, AZ, port.
	attrs := map[string]string{
		CloudMapAttrIPv4: s.localIp,
		CloudMapAttrAZ:   s.instanceAZ,
		CloudMapAttrPort: strconv.Itoa(s.config.ListenPort),
		CloudMapAttrKey:  s.device.PublicKeyBase64(),
	}
	if s.asgName != "" {
		attrs[CloudMapAttrASG] = s.asgName
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := s.cloudMap.RegisterInstanceAttributes(ctx, s.instanceID, attrs); err != nil {
		log.Error("Failed to register public key with Cloud Map: %v (auto-assignment may not include this server's key)", err)
		return
	}

	log.Info("Registered with Cloud Map: instance=%s, az=%s, asg=%s, pubkey=%s...",
		s.instanceID, s.instanceAZ, s.asgName, s.device.PublicKeyBase64()[:12])
}

// imdsV2Token obtains an IMDSv2 session token via PUT.
// The token can be reused across multiple imdsV2GetWithToken calls to avoid
// redundant token requests (each PUT is an HTTP round-trip to the link-local address).
func imdsV2Token(client *http.Client) (string, error) {
	tokenReq, err := http.NewRequest(http.MethodPut, "http://169.254.169.254/latest/api/token", nil)
	if err != nil {
		return "", fmt.Errorf("create token request: %w", err)
	}
	tokenReq.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "21600")

	tokenResp, err := client.Do(tokenReq) //nolint:gosec // hardcoded IMDS link-local address
	if err != nil {
		return "", fmt.Errorf("IMDS token request failed: %w", err)
	}
	defer tokenResp.Body.Close()
	if tokenResp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("IMDS token request returned status %d", tokenResp.StatusCode)
	}
	tokenBody, err := io.ReadAll(tokenResp.Body)
	if err != nil {
		return "", fmt.Errorf("read IMDS token: %w", err)
	}
	return string(tokenBody), nil
}

// imdsV2GetWithToken fetches a metadata value using a pre-obtained IMDSv2 token.
// The metadataURL must be a hardcoded IMDS link-local address (169.254.169.254).
func imdsV2GetWithToken(client *http.Client, token, metadataURL string) (string, error) {
	metaReq, err := http.NewRequest(http.MethodGet, metadataURL, nil)
	if err != nil {
		return "", fmt.Errorf("create metadata request: %w", err)
	}
	metaReq.Header.Set("X-aws-ec2-metadata-token", token)

	metaResp, err := client.Do(metaReq) //nolint:gosec // hardcoded IMDS link-local address
	if err != nil {
		return "", fmt.Errorf("IMDS metadata request failed: %w", err)
	}
	defer metaResp.Body.Close()
	if metaResp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("IMDS returned status %d for %s", metaResp.StatusCode, metadataURL)
	}
	body, err := io.ReadAll(metaResp.Body)
	if err != nil {
		return "", fmt.Errorf("read IMDS metadata: %w", err)
	}
	return string(body), nil
}

// GetListenPort returns the UDP listening port of the server
func (s *UdpServer) GetListenPort() int {
	if s.listenAddr != nil {
		return s.listenAddr.Port
	}
	if s.config != nil {
		return s.config.ListenPort
	}
	return 0
}

// GetHttpPort returns the HTTP listening port and whether HTTP is enabled
func (s *UdpServer) GetHttpPort() (int, bool) {
	if s.httpConfig == nil || !s.httpConfig.EnableHttp {
		return 0, false
	}
	port := s.httpConfig.HttpListenPort
	if port == 0 {
		port = s.GetListenPort() // falls back to UDP port
	}
	return port, true
}

// GetHttpTLSStatus returns TLS status as a string
func (s *UdpServer) GetHttpTLSStatus() string {
	if s.httpConfig != nil && s.httpConfig.EnableTLS {
		return "enabled"
	}
	return "disabled"
}

// EtcdPinger is the interface for health checking etcd connectivity.
type EtcdPinger interface {
	Ping(ctx context.Context) error
}

// DynamoDBPinger is the interface for health checking DynamoDB connectivity.
type DynamoDBPinger interface {
	Ping(ctx context.Context) error
}

// unwrapStorageBackend returns the underlying storage backend, unwrapping
// CachedStorage if present. Returns nil if no storage is configured.
func (s *UdpServer) unwrapStorageBackend() StorageBackend {
	if s.storage == nil {
		return nil
	}
	if cached, ok := s.storage.(*CachedStorage); ok {
		return cached.Backend()
	}
	return s.storage
}

// GetEtcdPinger returns an EtcdPinger if the storage backend supports it.
// Returns nil if no etcd-based health check is available.
func (s *UdpServer) GetEtcdPinger() EtcdPinger {
	if pinger, ok := s.unwrapStorageBackend().(EtcdPinger); ok {
		return pinger
	}
	return nil
}

// GetDynamoDBPinger returns a DynamoDBPinger if the storage backend supports it.
// Returns nil if no DynamoDB-based health check is available.
func (s *UdpServer) GetDynamoDBPinger() DynamoDBPinger {
	if pinger, ok := s.unwrapStorageBackend().(DynamoDBPinger); ok {
		return pinger
	}
	return nil
}

// GetStorageBackendName returns the name of the current storage backend.
func (s *UdpServer) GetStorageBackendName() string {
	if s.storage == nil {
		return "none"
	}
	return s.storage.Name()
}

func (s *UdpServer) IsRunning() bool {
	return s.running.Load()
}

func (s *UdpServer) SendPacket(pkt *core.Packet, conn *UdpConn) (n int, err error) {
	defer func() {
		atomic.AddUint64(&s.stats.totalSendBytes, uint64(n))
		atomic.StoreInt64(&conn.ConnData.LastLocalSendTime, time.Now().UnixNano())

		if !pkt.KeepAfterSend {
			s.device.ReleasePoolPacket(pkt)
		}
	}()

	pktType := core.HeaderTypeToString(pkt.HeaderType)
	log.Info("Send [%s] packet (%s -> %s), %d bytes", pktType, s.listenAddr.String(), conn.ConnData.RemoteAddr.String(), len(pkt.Content))
	log.Evaluate("Send [%s] packet (%s -> %s), %d bytes", pktType, s.listenAddr.String(), conn.ConnData.RemoteAddr.String(), len(pkt.Content))

	if conn.isWebRTC && conn.dc != nil {
		err = conn.dc.Send(pkt.Content)
		return len(pkt.Content), err
	}

	return s.listenConn.WriteToUDP(pkt.Content, conn.ConnData.RemoteAddr)
}

func (s *UdpServer) recvPacketRoutine() {
	defer s.wg.Done()
	defer log.Debug("recvPacketRoutine stopped")

	log.Debug("recvPacketRoutine started")

	// IP-keyed, size-capped, TTL-expiring counter of RecvPrecheck
	// failures. Replaces a previously unbounded map[IP:port]int32 that
	// an IP-spoofing flood could grow without limit (#1158). See
	// precheck_threat_cache.go for keying + sizing rationale.
	preCheckThreats := newPreCheckThreatCache(
		PreCheckThreatCacheSize,
		PreCheckThreatCacheTTL,
		func() { s.metrics.IncrCounter(MetricPreCheckThreatEviction) },
	)

	for {
		select {
		case <-s.signals.stop:
			return

		default:
		}

		// allocate a new packet buffer for every read
		pkt := s.device.AllocatePoolPacket()

		// udp recv, blocking until packet arrives or conn.Close()
		n, remoteAddr, err := s.listenConn.ReadFromUDP(pkt.Buf[:])
		if err != nil {
			s.device.ReleasePoolPacket(pkt)
			log.Error("[Server] ReadFromUDP on %s failed: %v", s.listenAddr.String(), err)
			if n == 0 {
				// listenConn closed
				return
			}
			continue
		}
		addrStr := remoteAddr.String()
		// IP-only key for blockAddrMap (#1160 T3-12), rate limiter, and
		// preCheckThreats — computed once per packet so the hot path
		// doesn't re-stringify on every consumer.
		ipStr := remoteAddr.IP.String()

		// add total recv bytes
		atomic.AddUint64(&s.stats.totalRecvBytes, uint64(n))

		// Snapshot MinimalLength() before ReleasePoolPacket: the release
		// nils pkt.Content, so a post-release call panics via unsafe.Pointer
		// deref. Fenced by TestPacketMinimalLengthPanicsAfterRelease.
		minLen := pkt.MinimalLength()
		if n < minLen {
			s.device.ReleasePoolPacket(pkt)
			log.Error("[Server] received UDP packet from %s is too short (%d bytes, min %d), discarding", addrStr, n, minLen)
			continue
		}

		if s.isBlockedIP(ipStr) {
			s.device.ReleasePoolPacket(pkt)
			log.Critical("Remote address %s is being blocked at the moment, discard.", addrStr)
			continue
		}

		// Per-source-IP rate limiting: drop packets exceeding the configured
		// rate before any cryptographic processing (HMAC, ECDH). This is the
		// application-level defense-in-depth layer; iptables provides the
		// kernel-level first line of defense.
		if s.rateLimiter != nil && !s.rateLimiter.Allow(ipStr) {
			s.device.ReleasePoolPacket(pkt)
			drops := s.rateLimitDrops.Add(1)
			if drops == 1 || drops%1000 == 0 {
				log.Warning("[Server] rate limited UDP packet from %s (total drops: %d)", addrStr, drops)
			}
			continue
		}

		recvTime := time.Now().UnixNano()
		pkt.Content = pkt.Buf[:n]
		//log.Trace("receive udp packet (%s -> %s): %+v", addrStr, s.listenAddr.String(), pkt.Content)

		typ, _, err := s.device.RecvPrecheck(pkt) // this check also records packet header type
		msgType := core.HeaderTypeToString(typ)
		log.Info("Receive [%s] packet (%s -> %s), %d bytes", msgType, addrStr, s.listenAddr.String(), n)
		log.Evaluate("Receive [%s] packet (%s -> %s), %d bytes", msgType, addrStr, s.listenAddr.String(), n)
		if err != nil {
			s.recordPreCheckThreat(preCheckThreats, ipStr)
			s.device.ReleasePoolPacket(pkt)
			log.Warning("Receive [%s] packet (%s -> %s), precheck error: %v", msgType, addrStr, s.listenAddr.String(), err)
			log.Evaluate("Receive [%s] packet (%s -> %s) precheck error: %v", msgType, addrStr, s.listenAddr.String(), err)
			continue
		}
		// Any successful precheck from this IP clears the IP's counter:
		// if any port from a source looks legitimate, the source isn't
		// a scanner. Semantics change from the old IP:port keying,
		// where one port succeeding didn't affect others.
		preCheckThreats.Clear(ipStr)

		s.remoteConnectionMapMutex.Lock()
		conn, found := s.remoteConnectionMap[addrStr]
		s.remoteConnectionMapMutex.Unlock()

		if found {
			// existing connection
			atomic.StoreInt64(&conn.ConnData.LastLocalRecvTime, recvTime)
			conn.ConnData.ForwardInboundPacket(pkt)

		} else {
			// create new connection if there is room
			s.remoteConnectionMapMutex.Lock()
			if len(s.remoteConnectionMap) > OverloadConnectionThreshold {
				s.device.SetOverload(true)
			} else if len(s.remoteConnectionMap) >= MaxConcurrentConnection {
				s.remoteConnectionMapMutex.Unlock()
				log.Critical("Reached maximum concurrent connection. Discard new packet from addr: %s", addrStr)
				s.device.ReleasePoolPacket(pkt)
				continue
			}
			s.remoteConnectionMapMutex.Unlock()

			// Classify only on header type AND source-IP match against a
			// configured peer. RecvPrecheck only validates header bytes,
			// so an attacker can set NHP_AOL/NHP_DOL on rotated-port
			// packets — without the IP gate they would bypass the per-IP
			// cap and inherit the AC/DB 300s idle timeout. The crypto
			// identity check (HMAC/ECDH) runs later in HandleACOnline /
			// HandleDBOnline, after this Conn is already allocated, so
			// the gate has to live here at admit. See #1504.
			isACConn := pkt.HeaderType == core.NHP_AOL && s.isKnownACPeerIP(ipStr)
			isDBConn := pkt.HeaderType == core.NHP_DOL && s.isKnownDBPeerIP(ipStr)
			conn = &UdpConn{
				isACConnection: isACConn,
				isDBConnection: isDBConn,
				evictSignal:    make(chan struct{}),
			}
			// setup new routine for connection
			conn.ConnData = &core.ConnectionData{
				InitTime:             recvTime,
				LastLocalRecvTime:    recvTime, // not in multithreaded yet, directly assign value
				Device:               s.device,
				LocalAddr:            s.listenAddr,
				RemoteAddr:           remoteAddr,
				CookieStore:          &core.CookieStore{},
				RemoteTransactionMap: make(map[uint64]*core.RemoteTransaction),
				TimeoutMs:            DefaultAgentConnectionTimeoutMs,
				SendQueue:            make(chan *core.Packet, PacketQueueSizePerConnection),
				RecvQueue:            make(chan *core.Packet, PacketQueueSizePerConnection),
				BlockSignal:          make(chan struct{}),
				SetTimeoutSignal:     make(chan struct{}),
				StopSignal:           make(chan struct{}),
			}

			if conn.isACConnection {
				conn.ConnData.TimeoutMs = DefaultACConnectionTimeoutMs
				log.Debug("Received new ac connection from %s", addrStr)
			}
			if conn.isDBConnection {
				conn.ConnData.TimeoutMs = DefaultDBConnectionTimeoutMs
				log.Debug("Received new db connection from %s", addrStr)
			}
			s.admitNewConnection(conn, addrStr)

			conn.ConnData.RecvQueue <- pkt

			log.Info("Accept new UDP connection from %s to %s", addrStr, s.listenAddr.String())

			// launch connection routine
			s.wg.Add(1)
			go s.connectionRoutine(conn)
		}
	}
}

// isKnownACPeerIP reports whether ipStr matches the configured IP,
// last resolved IP, or last recv IP of any peer in acPeerMap. Used at
// admit time to gate the per-IP cap bypass for NHP_AOL header types
// so an attacker can't claim AC status from a random source IP.
//
// The s.acPeerMap field is read inside the lock — config.go's
// updatePeers reassigns the field (`*peerMap = newMap`) under the
// same mutex on reload, so reading the field before acquiring the
// mutex would race. This is why the helper takes no map argument
// and reads the field directly.
//
// Lock order: acPeerMapMutex first, then peer.Lock() inside MatchesIP.
// O(n_peers) scan is fine today (n < 50 in prod) but consider an
// IP-keyed sibling map if the peer count grows — see #1529.
func (s *UdpServer) isKnownACPeerIP(ipStr string) bool {
	s.acPeerMapMutex.Lock()
	defer s.acPeerMapMutex.Unlock()
	for _, peer := range s.acPeerMap {
		if peer.MatchesIP(ipStr) {
			return true
		}
	}
	return false
}

// isKnownDBPeerIP is the DB equivalent of isKnownACPeerIP. Same race
// considerations apply to s.dbPeerMap.
func (s *UdpServer) isKnownDBPeerIP(ipStr string) bool {
	s.dbPeerMapMutex.Lock()
	defer s.dbPeerMapMutex.Unlock()
	for _, peer := range s.dbPeerMap {
		if peer.MatchesIP(ipStr) {
			return true
		}
	}
	return false
}

// admitNewConnection registers conn in remoteConnectionMap. For agent
// conns it also enforces MaxAgentConnsPerIP via a FIFO list per source
// IP, closing the oldest entry's evictSignal when the bucket is full.
// AC and DB conns bypass the per-IP cap because (a) they pass an
// identity gate before being trusted and (b) capping them would risk
// evicting the live AC during blue/green NAT churn from one source IP.
// The caller is responsible for the global MaxConcurrentConnection
// check upstream.
//
// Eviction is asynchronous: closing evictSignal wakes the evictee's
// routine, which removes the global-map entry on its defer. Until that
// runs, packets arriving at the evictee's addrStr still resolve to the
// evictee and land in its (no-longer-drained) RecvQueue, where they're
// released by Close()'s flush. This is intentional — a synchronous
// delete here would race the evictee mid-WriteToUDP, which is exactly
// the case the dedicated channel was chosen to avoid. Steady-state
// per-IP live agent conns are bounded by MaxAgentConnsPerIP; transient
// in-flight cleanup may briefly add to global-map size by an amount
// bounded by goroutine scheduling latency plus Go's pseudo-random
// select bias when multiple cases are ready (RecvQueue plus
// evictSignal both fire under sustained traffic to the evicted addr,
// so the routine may drain a few packets before the evictSignal case
// wins).
//
// Eviction policy is FIFO (oldest-by-admit-time) rather than LRU. A
// legit client that connected first behind a NAT shared with an
// attacker will be evicted before the attacker's later conns. The
// trade-off was made explicitly in #1504 — LRU-on-last-recv is a
// follow-up if the eviction-of-legit-clients pattern shows up in
// MetricAgentConnPerIPEvictions correlated with a known-NAT'd IP.
//
// Cloud-mode dynamic AC registration corner: a brand-new AC whose IP
// isn't yet in acPeerMap (no static config, no prior recv, no resolved
// hostname) misclassifies as agent on its first NHP_AOL packet. Under
// concurrent same-IP attack it can be FIFO-evicted before
// HandleACOnline registers it. The AC retries; once registered, the
// IP gate succeeds. Watch MetricAgentConnPerIPEvictions correlated
// with AC IPs after rollout — sustained eviction of cloud-mode ACs
// would argue for a registration-bootstrap exception.
func (s *UdpServer) admitNewConnection(conn *UdpConn, addrStr string) {
	if conn.evictSignal == nil {
		// Defense in depth: a nil evictSignal would silently disable
		// eviction (select on nil never fires), so a future UdpConn
		// literal that forgets the field would leak conns out of the
		// per-IP cap. Panic at admit so the bug surfaces immediately
		// instead of as a slow conn leak under attack.
		panic("admitNewConnection: conn.evictSignal must be initialized")
	}
	var evictedAddr string
	s.remoteConnectionMapMutex.Lock()
	s.remoteConnectionMap[addrStr] = conn
	if !conn.isACConnection && !conn.isDBConnection {
		ipStr := conn.ConnData.RemoteAddr.IP.String()
		bucket, ok := s.connectionsByIP[ipStr]
		if !ok {
			bucket = list.New()
			s.connectionsByIP[ipStr] = bucket
		}
		if bucket.Len() >= MaxAgentConnsPerIP {
			// MaxAgentConnsPerIP ≥ 1 is enforced at compile time
			// (constants.go) so Front is always non-nil here.
			front := bucket.Front()
			evicted := front.Value.(*UdpConn)
			bucket.Remove(front)
			evicted.perIPElem = nil
			evictedAddr = evicted.ConnData.RemoteAddr.String()
			close(evicted.evictSignal)
		}
		conn.perIPElem = bucket.PushBack(conn)
	}
	s.remoteConnectionMapMutex.Unlock()

	if evictedAddr != "" {
		// evictedAddr is set only when the lock-held branch popped a
		// front entry from a full bucket — i.e. an eviction occurred.
		// Sample the log: under sustained port-rotation an attacker
		// can drive evictions at the rate-limit ceiling (~25/s/IP);
		// MetricAgentConnPerIPEvictions is the source of truth, the
		// log just gives operators an entry point. Same shape as
		// rateLimitDrops.
		evictions := s.perIPEvictionWarns.Add(1)
		if evictions == 1 || evictions%1000 == 0 {
			log.Warning("Per-IP agent connection cap (%d) reached, evicting oldest %s (total: %d)",
				MaxAgentConnsPerIP, evictedAddr, evictions)
		}
		s.metrics.IncrCounter(MetricAgentConnPerIPEvictions)
	}
}

// removeConnection drops conn from remoteConnectionMap and (if it's an
// agent conn that wasn't already evicted) from connectionsByIP. Called
// only from the connection routine's defer. The map delete is gated on
// pointer equality: between eviction-close and this defer, a new conn
// can be admitted at the same addrStr (NAT/CGNAT rebinding to the same
// (srcIP, srcPort) tuple after the evictee's perceived flow ends, or
// any path that allocates a fresh tuple at the same key). Without the
// guard the evictee's defer would orphan the new conn from the lookup
// map.
func (s *UdpServer) removeConnection(conn *UdpConn, addrStr string) {
	s.remoteConnectionMapMutex.Lock()
	defer s.remoteConnectionMapMutex.Unlock()

	if existing, ok := s.remoteConnectionMap[addrStr]; ok && existing == conn {
		delete(s.remoteConnectionMap, addrStr)
	}
	if conn.perIPElem != nil {
		ipKey := conn.ConnData.RemoteAddr.IP.String()
		if bucket := s.connectionsByIP[ipKey]; bucket != nil {
			bucket.Remove(conn.perIPElem)
			if bucket.Len() == 0 {
				delete(s.connectionsByIP, ipKey)
			}
		}
		conn.perIPElem = nil
	}
	if len(s.remoteConnectionMap) <= OverloadConnectionThreshold {
		s.device.SetOverload(false)
	}
}

func (s *UdpServer) connectionRoutine(conn *UdpConn) {
	if conn.evictSignal == nil {
		// Defense in depth: if a future code path constructs a UdpConn
		// and starts a routine without going through admitNewConnection
		// (which has its own nil-check), a nil evictSignal would silently
		// disable the eviction case in the select below — select on nil
		// channel never fires. See evictSignal contract on UdpConn.
		panic("connectionRoutine: conn.evictSignal must be initialized")
	}

	addrStr := conn.ConnData.RemoteAddr.String()

	defer s.wg.Done()
	defer log.Debug("Connection routine: %s stopped", addrStr)

	log.Debug("Connection routine: %s started", addrStr)

	// stop receiving packets and clean up
	defer func() {
		// Remove old ac connection record
		// Note on server side, before an old ac connection times out, the very ac can send new connections (due to restart or deemed connection failure)
		// and it may come with the same remote ip but a different remote port
		// so make sure the timeout removal here does not delete newer ac connections
		if conn.isACConnection {
			s.acConnectionMapMutex.Lock()
			s.removeACConnectionRecord(conn)
			s.acConnectionMapMutex.Unlock()
		}

		if conn.isDBConnection {
			var dbToDelete string
			s.dbConnectionMapMutex.Lock()
			for dbId, dbConn := range s.dbConnectionMap {
				if dbConn.ConnData.Equal(conn.ConnData) {
					dbToDelete = dbId
					break
				}
			}
			delete(s.dbConnectionMap, dbToDelete)
			s.dbConnectionMapMutex.Unlock()
		}

		s.removeConnection(conn, addrStr)

		conn.Close()
	}()

	for {
		select {
		case <-s.signals.stop:
			return

		case <-conn.evictSignal:
			log.Debug("Connection routine: %s evicted by per-IP cap", addrStr)
			return

		case <-conn.ConnData.SetTimeoutSignal:
			if conn.ConnData.TimeoutMs <= 0 {
				log.Debug("Connection routine closed immediately")
				return
			}

		case <-time.After(time.Duration(conn.ConnData.TimeoutMs) * time.Millisecond):
			// timeout, quit routine
			log.Debug("Connection routine idle timeout")
			return

		case <-conn.ConnData.BlockSignal:
			s.AddBlockAddr(conn.ConnData.RemoteAddr)
			return

		case pkt, ok := <-conn.ConnData.RecvQueue:
			if !ok {
				return
			}
			if pkt == nil {
				continue
			}
			log.Debug("Received udp packet len [%d] from addr: %s", len(pkt.Content), addrStr)

			// process keepalive packet
			if pkt.HeaderType == core.NHP_KPL {
				s.device.ReleasePoolPacket(pkt)
				log.Info("Receive [NHP_KPL] message (%s -> %s)", addrStr, s.listenAddr.String())
				continue
			}

			if s.device.IsTransactionResponse(pkt.HeaderType) {
				// forward to a specific transaction
				transactionId := pkt.Counter()
				transaction := s.device.FindLocalTransaction(transactionId)
				if transaction != nil {
					if err := transaction.SendPacket(pkt); err != nil {
						log.Warning("recvPacketRoutine: local transaction %d closed before forward: %v", transactionId, err)
						s.recordTransactionClosed(err)
					}
					continue
				}
			}

			pd := &core.PacketData{
				BasePacket: pkt,
				ConnData:   conn.ConnData,
				InitTime:   atomic.LoadInt64(&conn.ConnData.LastLocalRecvTime),
			}
			// generic receive
			s.device.RecvPacketToMsg(pd)

		case pkt, ok := <-conn.ConnData.SendQueue:
			if !ok {
				return
			}
			if pkt == nil {
				continue
			}
			if _, sendErr := s.SendPacket(pkt, conn); sendErr != nil {
				log.Error("[Server] failed to send packet to %s: %v", conn.ConnData.RemoteAddr.String(), sendErr)
			}
		}
	}
}

func (s *UdpServer) BlockAddrRefreshRoutine() {
	defer s.wg.Done()
	defer log.Info("BlockedAddrRoutine stopped")

	log.Info("BlockedAddrRoutine started")

	for {
		select {
		case <-s.signals.stop:
			return

		case <-time.After(BlockAddrRefreshRate * time.Second):
			s.RefreshBlockAddr()
		}
	}
}

// IsBlockAddr reports whether the source IP of addr is currently
// blocked. Only addr.IP is consulted — addr.Port is ignored, since
// the block map keys on IP only (#1160 T3-12) so a port-rotating
// attacker cannot bypass an existing block by minting a fresh
// IP:port tuple.
func (s *UdpServer) IsBlockAddr(addr *net.UDPAddr) bool {
	return s.isBlockedIP(addr.IP.String())
}

// isBlockedIP is the IP-keyed lookup used by the hot path. The map keys
// on remote IP only — port rotation from a blocked source must not
// re-admit packets (#1160 T3-12).
func (s *UdpServer) isBlockedIP(ip string) bool {
	s.blockAddrMapMutex.RLock()
	defer s.blockAddrMapMutex.RUnlock()

	_, found := s.blockAddrMap[ip]
	return found
}

// AddBlockAddr blocks the source IP of addr. Only addr.IP is
// recorded — addr.Port is ignored. See IsBlockAddr for the IP-only
// keying rationale (#1160 T3-12).
func (s *UdpServer) AddBlockAddr(addr *net.UDPAddr) {
	s.addBlockedIP(addr.IP.String())
}

// addBlockedIP records a block keyed by remote IP only. See isBlockedIP for
// the IP:port → IP keying rationale.
func (s *UdpServer) addBlockedIP(ip string) {
	s.blockAddrMapMutex.Lock()
	poolFull := len(s.blockAddrMap) >= MaxConcurrentConnection
	if !poolFull {
		s.blockAddrMap[ip] = &BlockAddr{time.Now().Add(BlockAddrExpireTime * time.Second)}
	}
	s.blockAddrMapMutex.Unlock()

	// Log outside the lock so a blocked log I/O (disk pressure, stderr pipe)
	// can't extend the hold time and stall packet readers.
	if poolFull {
		log.Warning("block address pool is full")
	} else {
		log.Critical("add blocking source IP %s", ip)
	}
}

func (s *UdpServer) RefreshBlockAddr() {
	now := time.Now()

	// Phase 1: collect expired keys under RLock so concurrent packet readers
	// (isBlockedIP) proceed in parallel with the scan. Under sustained
	// attack the map can approach MaxConcurrentConnection entries, and the
	// old single-phase exclusive Lock held during the full iteration would
	// stall every reader for the duration of the scan.
	var expired []string
	s.blockAddrMapMutex.RLock()
	for k, v := range s.blockAddrMap {
		if v.expireTime.Before(now) {
			expired = append(expired, k)
		}
	}
	s.blockAddrMapMutex.RUnlock()

	if len(expired) == 0 {
		return
	}

	// Phase 2: delete under exclusive Lock. Re-check expiry in case a key was
	// re-added between the two critical sections — if AddBlockAddr ran with
	// the same addrStr, its fresh expireTime would be in the future and we
	// must not delete it.
	s.blockAddrMapMutex.Lock()
	for _, k := range expired {
		if v, ok := s.blockAddrMap[k]; ok && v.expireTime.Before(now) {
			delete(s.blockAddrMap, k)
		}
	}
	s.blockAddrMapMutex.Unlock()
}

func (s *UdpServer) sendMessageRoutine() {
	defer s.wg.Done()
	defer log.Info("sendMessageRoutine stopped")

	log.Info("sendMessageRoutine started")

	for {
		select {
		case <-s.signals.stop:
			return

		case md, ok := <-s.sendMsgCh:
			if !ok {
				return
			}
			if md.PrevParserData != nil && s.device.IsTransactionResponse(md.HeaderType) {
				// forward to a specific transaction
				transaction := md.ConnData.FindRemoteTransaction(md.PrevParserData.SenderTrxId)
				if transaction != nil {
					if err := transaction.SendMessage(md); err != nil {
						log.Warning("sendMsgRoutine: transaction %d closed before forward: %v", md.PrevParserData.SenderTrxId, err)
						s.recordTransactionClosed(err)
					}
					continue
				}
			}

			// generic send
			s.device.SendMsgToPacket(md)
		}
	}
}

func (s *UdpServer) recvMessageRoutine() {
	defer s.wg.Done()
	defer log.Info("recvMessageRoutine stopped")

	log.Info("recvMessageRoutine started")

	for {
		select {
		case <-s.signals.stop:
			return

		case ppd, ok := <-s.recvMsgCh:
			if !ok {
				return
			}
			if ppd == nil {
				// recvMsgCh is closed
				continue
			}

			s.dispatchReceivedMessage(ppd)
		}
	}
}

// dispatchReceivedMessage routes a decrypted PPD to its handler.
// Every handler arm dispatches asynchronously via a goroutine:
// recvMsgCh feeds packetToMsgRoutine, and a slow handler on this
// goroutine would head-of-line-block the queue and cause
// packetToMsgRoutine to silently drop legitimate knocks (#1163).
// Handlers guard their own shared state with per-map mutexes, so
// concurrent dispatch is safe. The default arm logs without
// spawning — there's no handler to run. The extraction also makes
// the async-dispatch property directly testable without standing
// up a full listener loop.
func (s *UdpServer) dispatchReceivedMessage(ppd *core.PacketParserData) {
	switch ppd.HeaderType {
	case core.NHP_KNK, core.NHP_RKN, core.NHP_EXT, core.DHP_KNK:
		go func() {
			if knockErr := s.HandleKnockRequest(ppd); knockErr != nil {
				log.Error("[Server] HandleKnockRequest failed: %v", knockErr)
			}
		}()

	case core.NHP_AOL:
		go func() {
			if aolErr := s.HandleACOnline(ppd); aolErr != nil {
				log.Error("[Server] HandleACOnline failed: %v", aolErr)
			}
		}()

	case core.NHP_DOL:
		go func() {
			if dolErr := s.HandleDBOnline(ppd); dolErr != nil {
				log.Error("[Server] HandleDBOnline failed: %v", dolErr)
			}
		}()

	case core.NHP_OTP:
		go func() {
			if otpErr := s.HandleOTPRequest(ppd); otpErr != nil {
				log.Error("[Server] HandleOTPRequest failed: %v", otpErr)
			}
		}()

	case core.NHP_REG:
		go func() {
			if regErr := s.HandleRegisterRequest(ppd); regErr != nil {
				log.Error("[Server] HandleRegisterRequest failed: %v", regErr)
			}
		}()

	case core.NHP_LST:
		go func() {
			if listErr := s.HandleListRequest(ppd); listErr != nil {
				log.Error("[Server] HandleListRequest failed: %v", listErr)
			}
		}()
	case core.NHP_DAR:
		go func() {
			if darErr := s.HandleDHPDARMessage(ppd); darErr != nil {
				log.Error("[Server] HandleDHPDARMessage failed: %v", darErr)
			}
		}()
	case core.NHP_DRG:
		go func() {
			if drgErr := s.HandleDHPDRGMessage(ppd); drgErr != nil {
				log.Error("[Server] HandleDHPDRGMessage failed: %v", drgErr)
			}
		}()
	case core.NHP_DAV:
		go func() {
			if davErr := s.HandleDHPDAVMessage(ppd); davErr != nil {
				log.Error("[Server] HandleDHPDAVMessage failed: %v", davErr)
			}
		}()

	// Server-to-server forwarding
	case core.NHP_FWD:
		go s.HandleForwardRequest(ppd)
	case core.NHP_FRT:
		go s.HandleForwardResult(ppd)

	default:
		// An unknown HeaderType reaching here means the upstream
		// parser accepted a type this dispatcher doesn't route —
		// either a protocol-version mismatch or a parser/dispatcher
		// drift. Log so ops can grep for it rather than drop silently.
		log.Warning("[Server] dispatchReceivedMessage: unhandled HeaderType %d", ppd.HeaderType)
	}
}

func (s *UdpServer) AddAgentPeer(agent *core.UdpPeer) {
	if agent.DeviceType() == core.NHP_AGENT {
		s.device.AddPeer(agent)
		s.agentPeerMapMutex.Lock()
		s.agentPeerMap[agent.PublicKeyBase64()] = agent
		s.agentPeerMapMutex.Unlock()
	}
}

func (s *UdpServer) UpdateTeePublicKeyAndConsumerEphemeralPublicKey(teePublicKeyBase64 string, consumerEphemeralPublicKeyBase64 string, agentPulicKey []byte) {
	agentPulicKeyBase64 := base64.StdEncoding.EncodeToString(agentPulicKey)

	if peer, found := s.agentPeerMap[agentPulicKeyBase64]; found {
		peer.SetTeePublicKeyBase64(teePublicKeyBase64)
		peer.SetConsumerEphemeralPublicKeyBase64(consumerEphemeralPublicKeyBase64)
	}
}

func (s *UdpServer) GetTeePublicKeyBase64AndConsumerEphemeralPublicKeyBase64(agentPublicKey []byte) (teePublicKeyBase64 string, consumerEphemeralPublicKeyBase64 string) {
	agentPulicKeyBase64 := base64.StdEncoding.EncodeToString(agentPublicKey)

	if peer, found := s.agentPeerMap[agentPulicKeyBase64]; found {
		return peer.TeePublicKeyBase64(), peer.ConsumerEphemeralPublicKeyBase64()
	}
	return "", ""
}

// removeACConnectionRecord removes the given connection from acConnectionMap.
// Must be called while holding s.acConnectionMapMutex.
func (s *UdpServer) removeACConnectionRecord(conn *UdpConn) {
	for acId, conns := range s.acConnectionMap {
		for i, acConn := range conns {
			if acConn.ConnData.Equal(conn.ConnData) {
				s.acConnectionMap[acId] = append(conns[:i], conns[i+1:]...)
				if len(s.acConnectionMap[acId]) == 0 {
					delete(s.acConnectionMap, acId)
				}
				return
			}
		}
	}
}

func (s *UdpServer) AddACPeer(acPeer *core.UdpPeer) {
	if acPeer.DeviceType() == core.NHP_AC {
		s.device.AddPeer(acPeer)
		s.acPeerMapMutex.Lock()
		// Initialize map if nil (cloud mode without ac.toml doesn't call updateACPeers)
		if s.acPeerMap == nil {
			s.acPeerMap = make(map[string]*core.UdpPeer)
		}
		s.acPeerMap[acPeer.PublicKeyBase64()] = acPeer
		s.acPeerMapMutex.Unlock()
	}
}

// removeACPeer is the symmetric undo of AddACPeer: it removes the
// pubkey from BOTH core.Device's peer table and acPeerMap. Today's
// only caller is HandleACOnline's in-lock TOCTOU cleanup branch
// (#1157 F3) where a peer was just added but the registration is
// being rejected; if a future caller adds another write target to
// AddACPeer, this helper must be widened in lockstep — the matching
// fence is TestRemoveACPeer in handle_ac_online_f3_test.go.
func (s *UdpServer) removeACPeer(acPubkeyBase64 string) {
	s.device.RemovePeer(acPubkeyBase64)
	s.acPeerMapMutex.Lock()
	delete(s.acPeerMap, acPubkeyBase64)
	s.acPeerMapMutex.Unlock()
}

func (s *UdpServer) AddAddressAssociation(srcIp string, addrs []*common.NetAddress) {
	s.srcIpAssociatedAddrMapMutex.Lock()
	s.srcIpAssociatedAddrMap[srcIp] = addrs
	s.srcIpAssociatedAddrMapMutex.Unlock()
}

func (s *UdpServer) RemoveAddressAssociation(srcIp string) {
	s.srcIpAssociatedAddrMapMutex.Lock()
	delete(s.srcIpAssociatedAddrMap, srcIp)
	s.srcIpAssociatedAddrMapMutex.Unlock()
}

func (s *UdpServer) AddAuthService(aspData *common.AuthServiceProviderData) error {
	if len(aspData.AuthSvcId) == 0 {
		return errors.New("aspId is empty")
	}

	s.authServiceMapMutex.Lock()
	s.authServiceMap[aspData.AuthSvcId] = aspData
	s.authServiceMapMutex.Unlock()

	// Try to load plugin from static registry first, then fall back to dynamic loading
	h := plugins.GetPluginHandler(aspData.AuthSvcId, aspData.PluginPath)
	if h != nil {
		err := s.LoadPlugin(aspData.AuthSvcId, h)
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *UdpServer) AddResource(res *common.ResourceData) error {
	if len(res.AuthServiceId) == 0 || len(res.ResourceId) == 0 {
		return errors.New("aspId or resId is empty")
	}

	s.authServiceMapMutex.Lock()
	aspData, found := s.authServiceMap[res.AuthServiceId]
	if !found {
		s.authServiceMapMutex.Unlock()
		return errors.New("aspId not found")
	}
	aspData.ResourceGroups[res.ResourceId] = res
	s.authServiceMapMutex.Unlock()

	return nil
}

func (s *UdpServer) ValidatePlugin(h plugins.PluginHandler) bool {
	return true
}

func (s *UdpServer) LoadPlugin(pluginId string, h plugins.PluginHandler) error {
	if !s.ValidatePlugin(h) {
		log.Error("[Server] plugin %s validation failed", pluginId)
		return errors.New("plugin validation failed")
	}

	s.pluginHandlerMapMutex.RLock()
	oldHandler, found := s.pluginHandlerMap[pluginId]
	s.pluginHandlerMapMutex.RUnlock()
	if found {
		if closeErr := oldHandler.Close(); closeErr != nil {
			log.Error("[Server] failed to close old plugin handler %s: %v", pluginId, closeErr)
		}
	}

	pluginDirPath := filepath.Join(ExeDirPath, "plugins", pluginId)
	err := h.Init(&plugins.PluginParamsIn{
		PluginDirPath: &pluginDirPath,
		Log:           s.log.NewSubLogger("Plugin["+pluginId+"]", log.LogLevelDebug),
		Hostname:      &s.config.Hostname,
		LocalIp:       &s.localIp,
		LocalMac:      &s.localMac,
	})
	if err != nil {
		log.Error("[Server] plugin %s initialization failed: %v", pluginId, err)
		return err
	}

	ver := h.Version()

	s.pluginHandlerMapMutex.Lock()
	s.pluginHandlerMap[pluginId] = h
	s.pluginHandlerMapMutex.Unlock()

	log.Info("plugin %s loaded successfully to %s", ver, pluginId)
	return nil
}

func (s *UdpServer) ClosePlugins() {
	s.pluginHandlerMapMutex.Lock()
	defer s.pluginHandlerMapMutex.Unlock()

	for id, handler := range s.pluginHandlerMap {
		log.Info("closing plugin: %s", id)
		if closeErr := handler.Close(); closeErr != nil {
			log.Error("[Server] failed to close plugin %s: %v", id, closeErr)
		}
	}
}

func (s *UdpServer) FindAuthSvcProvider(aspId string) *common.AuthServiceProviderData {
	s.authServiceMapMutex.RLock()
	defer s.authServiceMapMutex.RUnlock()

	aspData, found := s.authServiceMap[aspId]
	if found {
		return aspData
	}

	return nil
}

func (s *UdpServer) processACOperation(ctx context.Context, knkMsg *common.AgentKnockMsg, conn *ACConn, srcAddr *common.NetAddress, dstAddrs []*common.NetAddress, openTime uint32) (artMsg *common.ACOpsResultMsg, err error) {
	// should not happen
	if knkMsg == nil || conn == nil {
		log.Critical("processACOperation with nil input argument")
		err = common.ErrInvalidInput
		return
	}

	artMsg = &common.ACOpsResultMsg{}
	if srcAddr == nil || len(dstAddrs) == 0 {
		log.Error("[processACOperation] no address specified")
		err = common.ErrACEmptyPassAddress
		artMsg.ErrCode = common.ErrACEmptyPassAddress.ErrorCode()
		artMsg.ErrMsg = err.Error()
		return
	}

	srcAddrs := []*common.NetAddress{srcAddr}
	// check source ip associated address
	s.srcIpAssociatedAddrMapMutex.Lock()
	asscAddrs, found := s.srcIpAssociatedAddrMap[srcAddr.Ip]
	s.srcIpAssociatedAddrMapMutex.Unlock()
	if found {
		srcAddrs = append(srcAddrs, asscAddrs...)
	}

	acAddrStr := conn.ACPeer.RecvAddr().String()
	if acAddrStr == "<nil>" {
		log.Error("[processACOperation] AC peer %s has nil recvAddr - peer may not be properly initialized", conn.ACId)
		err = common.ErrACEmptyPassAddress
		artMsg.ErrCode = common.ErrACEmptyPassAddress.ErrorCode()
		artMsg.ErrMsg = "AC peer address not initialized"
		return
	}
	if openTime == 0 {
		openTime = DefaultIpOpenTime
	}

	aopMsg := &common.ServerACOpsMsg{
		UserId:           knkMsg.UserId,
		DeviceId:         knkMsg.DeviceId,
		OrganizationId:   knkMsg.OrganizationId,
		AuthServiceId:    knkMsg.AuthServiceId,
		ResourceId:       knkMsg.ResourceId,
		SourceAddrs:      srcAddrs,
		DestinationAddrs: dstAddrs,
		OpenTime:         openTime + ACOpenCompensationTime, // compensate ac open time
	}
	aopBytes, marshalErr := json.Marshal(aopMsg)
	if marshalErr != nil {
		log.Error("server-agent(%s@%s)[processACOperation] failed to marshal AOP message: %v", knkMsg.UserId, srcAddr.String(), marshalErr)
		return nil, marshalErr
	}

	aopMd := &core.MsgData{
		ConnData:      conn.ConnData,
		HeaderType:    core.NHP_AOP,
		CipherScheme:  conn.ACCipherScheme,
		TransactionId: s.device.NextCounterIndex(),
		Compress:      true,
		PeerPk:        conn.ACPeer.PublicKey(),
		Message:       aopBytes,
		ResponseMsgCh: make(chan *core.PacketParserData),
	}

	if !s.IsRunning() {
		log.Error("server-agent(%s@%s)-ac(%s#%d@%s)[processACOperation] MsgData channel closed or being closed, skip sending", knkMsg.UserId, srcAddr.String(), conn.ACId, aopMd.TransactionId, acAddrStr)
		err = common.ErrPacketToMessageRoutineStopped
		artMsg.ErrCode = common.ErrPacketToMessageRoutineStopped.ErrorCode()
		artMsg.ErrMsg = err.Error()
		return
	}

	s.sendMsgCh <- aopMd

	// wait for ac sending back operation result
	// block until transaction completes or context is canceled
	var acPpd *core.PacketParserData
	select {
	case acPpd = <-aopMd.ResponseMsgCh:
		close(aopMd.ResponseMsgCh)
	case <-ctx.Done():
		log.Debug("server-agent(%s@%s)-ac(%s#%d@%s)[processACOperation] canceled by context: %v",
			knkMsg.UserId, srcAddr.String(), conn.ACId, aopMd.TransactionId, acAddrStr, ctx.Err())
		// Drain the response channel in a background goroutine to prevent
		// the transaction from leaking. The channel will eventually receive
		// a response (or timeout) from the core layer.
		go func() {
			<-aopMd.ResponseMsgCh
			close(aopMd.ResponseMsgCh)
		}()
		artMsg = &common.ACOpsResultMsg{}
		err = ctx.Err()
		artMsg.ErrCode = common.ErrServerACOpsFailed.ErrorCode()
		artMsg.ErrMsg = err.Error()
		return
	}

	if acPpd.Error != nil {
		log.Error("server-agent(%s@%s)-ac(%s#%d@%s)[processACOperation] failed to receive response from ac: %v", knkMsg.UserId, srcAddr.String(), conn.ACId, aopMd.TransactionId, acAddrStr, acPpd.Error)
		err = acPpd.Error
		artMsg.ErrCode = common.ErrServerACOpsFailed.ErrorCode()
		artMsg.ErrMsg = err.Error()
		// If the transaction timed out, the connection is likely unhealthy
		// (e.g., AC unreachable, network path broken). Close it so that
		// retry attempts filter it out via IsClosed() instead of sending
		// to the same dead connection again.
		if errors.Is(acPpd.Error, common.ErrTransactionFailedByTimeout) {
			log.Warning("server-agent(%s@%s)-ac(%s#%d@%s)[processACOperation] closing timed-out connection", knkMsg.UserId, srcAddr.String(), conn.ACId, aopMd.TransactionId, acAddrStr)
			conn.ConnData.Close()
		}
		return
	}

	if acPpd.HeaderType != core.NHP_ART {
		log.Error("server-agent(%s@%s)-ac(%s#%d@%s)[processACOperation] response has wrong type: %s", knkMsg.UserId, srcAddr.String(), conn.ACId, aopMd.TransactionId, acAddrStr, core.HeaderTypeToString(acPpd.HeaderType))
		err = common.ErrTransactionRepliedWithWrongType
		artMsg.ErrCode = common.ErrTransactionRepliedWithWrongType.ErrorCode()
		artMsg.ErrMsg = err.Error()
		return
	}

	err = json.Unmarshal(acPpd.BodyMessage, artMsg)
	if err != nil {
		log.Error("server-agent(%s@%s)-ac(%s#%d@%s)[processACOperation] failed to parse %s message: %v", knkMsg.UserId, srcAddr.String(), conn.ACId, aopMd.TransactionId, acAddrStr, core.HeaderTypeToString(acPpd.HeaderType), err)
		artMsg.ErrCode = common.ErrJsonParseFailed.ErrorCode()
		artMsg.ErrMsg = err.Error()
		return
	}

	if artMsg.ErrCode != common.ErrSuccess.ErrorCode() {
		log.Error("server-agent(%s@%s)-ac(%s#%d@%s)[processACOperation] response error: %+v", knkMsg.UserId, srcAddr.String(), conn.ACId, aopMd.TransactionId, acAddrStr, artMsg)
		err = common.ErrACOperationFailed
		return
	}

	return artMsg, nil
}

// processACOperationBroadcast sends NHP-AOP to ALL AC connections in parallel.
// Each AC in a different AZ must receive the knock so its ipset pinhole is
// opened for the client IP — the AC NLB round-robins the client's subsequent
// HTTPS request, so every AC needs the entry.
//
// Returns the first successful result immediately to minimize client-facing
// latency. Unlike the pre-fix version, remaining goroutines are NOT canceled
// — they continue in the background so all ACs still get the pinhole.
// A background goroutine drains and logs the remaining results.
func (s *UdpServer) processACOperationBroadcast(
	parentCtx context.Context,
	knkMsg *common.AgentKnockMsg,
	conns []*ACConn,
	srcAddr *common.NetAddress,
	dstAddrs []*common.NetAddress,
	openTime uint32,
) (*common.ACOpsResultMsg, error) {
	s.metrics.IncrCounter(MetricBroadcastTotal)

	// Inherit context values (request ID) without inheriting cancellation —
	// broadcast goroutines must run independently to open pinholes on all ACs.
	// Callers MUST pass a non-nil parentCtx (context.Background() if they
	// have nothing else); WithoutCancel handles Background fine.
	baseCtx := context.WithoutCancel(parentCtx)

	if len(conns) == 1 {
		start := time.Now()
		ctx, cancel := context.WithTimeout(baseCtx, DefaultBroadcastTimeout)
		defer cancel()
		artMsg, err := s.processACOperation(ctx, knkMsg, conns[0], srcAddr, dstAddrs, openTime)
		elapsed := float64(time.Since(start).Milliseconds())
		s.metrics.RecordLatency(MetricBroadcastDurationMs, elapsed)
		s.metrics.RecordLatency(MetricBroadcastACLatencyMs, elapsed)
		if err == nil {
			s.metrics.IncrCounter(MetricBroadcastSuccess)
		} else {
			s.metrics.IncrCounter(MetricBroadcastAllFail)
		}
		return artMsg, err
	}

	userId := knkMsg.UserId
	addrStr := srcAddr.String()
	total := len(conns)
	broadcastStart := time.Now()
	log.Info("server-agent(%s@%s)[processACOperationBroadcast] broadcasting to %d ACs", userId, addrStr, total)

	// Each goroutine gets its own timeout context — NOT a shared cancellable
	// context. When we return on first success, remaining goroutines must keep
	// running so all ACs get the pinhole. The per-goroutine timeout ensures
	// they don't leak if an AC is unreachable.
	type broadcastResult struct {
		artMsg *common.ACOpsResultMsg
		err    error
		acAddr string
	}
	results := make(chan broadcastResult, total)
	for _, conn := range conns {
		go func(c *ACConn) {
			acStart := time.Now()
			ctx, cancel := context.WithTimeout(baseCtx, DefaultBroadcastTimeout)
			defer cancel()
			artMsg, err := s.processACOperation(ctx, knkMsg, c, srcAddr, dstAddrs, openTime)
			s.metrics.RecordLatency(MetricBroadcastACLatencyMs, float64(time.Since(acStart).Milliseconds()))
			results <- broadcastResult{artMsg, err, c.ACPeer.RecvAddr().String()}
		}(conn)
	}

	// Wait for results. Return on first success to unblock the client, but
	// let remaining goroutines finish in the background (fire-and-forget AOP).
	// If all fail, return the last error.
	var lastErr error
	var lastArtMsg *common.ACOpsResultMsg
	var failCount int
	for i := 0; i < total; i++ {
		r := <-results
		if r.err == nil {
			log.Info("server-agent(%s@%s)[processACOperationBroadcast] AC at %s succeeded (1/%d), returning to caller",
				userId, addrStr, r.acAddr, total)
			// Drain remaining results in background — single summary log, emit metrics
			remaining := total - i - 1
			if remaining > 0 {
				go func() {
					var bgSuccess, bgFail int
					var failedAddrs []string
					for j := 0; j < remaining; j++ {
						bgr := <-results
						if bgr.err == nil {
							bgSuccess++
						} else {
							bgFail++
							failedAddrs = append(failedAddrs, bgr.acAddr)
						}
					}
					elapsed := time.Since(broadcastStart)
					s.metrics.RecordLatency(MetricBroadcastDurationMs, float64(elapsed.Milliseconds()))
					if bgFail > 0 {
						s.metrics.IncrCounter(MetricBroadcastPartialFail)
						log.Warning("server-agent(%s@%s)[processACOperationBroadcast] broadcast done in %v: %d/%d ACs succeeded, failed: %v",
							userId, addrStr, elapsed, bgSuccess+1, total, failedAddrs)
					} else {
						log.Info("server-agent(%s@%s)[processACOperationBroadcast] broadcast done in %v: %d/%d ACs succeeded",
							userId, addrStr, elapsed, bgSuccess+1, total)
					}
				}()
			} else {
				elapsed := time.Since(broadcastStart)
				s.metrics.RecordLatency(MetricBroadcastDurationMs, float64(elapsed.Milliseconds()))
			}
			s.metrics.IncrCounter(MetricBroadcastSuccess)
			return r.artMsg, nil
		}
		failCount++
		log.Warning("server-agent(%s@%s)[processACOperationBroadcast] AC at %s failed: %v (%d/%d)",
			userId, addrStr, r.acAddr, r.err, failCount, total)
		lastErr = r.err
		lastArtMsg = r.artMsg
	}

	elapsed := time.Since(broadcastStart)
	s.metrics.RecordLatency(MetricBroadcastDurationMs, float64(elapsed.Milliseconds()))
	s.metrics.IncrCounter(MetricBroadcastAllFail)
	log.Warning("server-agent(%s@%s)[processACOperationBroadcast] all %d ACs failed in %v", userId, addrStr, total, elapsed)
	return lastArtMsg, lastErr
}

func (s *UdpServer) handleNhpOpenResource(req *common.NhpAuthRequest, res *common.ResourceData) (ackMsg *common.ServerKnockAckMsg, err error) {
	knkMsg := req.Msg
	srcAddr := req.SrcAddr
	addrStr := srcAddr.String()
	ackMsg = req.Ack

	acDstIpMap := make(map[string][]*common.NetAddress)
	for resName, info := range res.Resources {
		addrs, exist := acDstIpMap[resName]
		if exist {
			addrs = append(addrs, info.Addr)
			acDstIpMap[resName] = addrs
		} else {
			acDstIpMap[resName] = []*common.NetAddress{info.Addr}
		}
	}

	// Check if we need to forward this knock to another server.
	// If the AC for this resource isn't connected to us, we look up DynamoDB
	// to find which servers the AC IS connected to, then forward the knock.
	needsForwarding := false
	var forwardACId string
	for _, resInfo := range res.Resources {
		if resInfo == nil {
			continue
		}
		// Cheap predicate; the broadcast loop below snapshots and emits
		// MetricACConnStaleFiltered for the same acId. Calling
		// snapshotLiveACConns here would double-count.
		if !s.hasLiveACConn(resInfo.ACId) {
			needsForwarding = true
			forwardACId = resInfo.ACId
			break
		}
	}

	// Try forwarding if: AC not connected, storage available, original packet available
	if needsForwarding && s.storage != nil && s.forwarder != nil && len(req.OriginalPacket) > 0 {
		log.Info("server-agent(%s@%s)[handleNhpOpenResource] AC %s not connected, attempting forward",
			knkMsg.UserId, addrStr, forwardACId)

		// Look up AC assignment from storage
		ctx, cancel := context.WithTimeout(context.Background(), DefaultStorageTimeout)
		defer cancel()

		assignment, lookupErr := s.storage.GetACAssignment(ctx, forwardACId)
		if lookupErr == nil && assignment != nil && len(assignment.AssignedServers) > 0 {
			// Parse user address for forwarding
			userAddr, parseErr := net.ResolveUDPAddr("udp", addrStr)
			if parseErr == nil {
				// Forward the knock to assigned servers
				fwdCtx, fwdCancel := context.WithTimeout(context.Background(), ForwardTimeout)
				defer fwdCancel()

				result, fwdErr := s.forwarder.ForwardKnock(fwdCtx, assignment, req.OriginalPacket, userAddr)
				if fwdErr == nil && result != nil && result.Success {
					// Forward succeeded - parse and return the ACK from the assigned server
					var forwardedAck common.ServerKnockAckMsg
					if json.Unmarshal(result.ACKData, &forwardedAck) == nil {
						log.Info("server-agent(%s@%s)[handleNhpOpenResource] forward succeeded via assigned server",
							knkMsg.UserId, addrStr)
						return &forwardedAck, nil
					}
				} else if fwdErr != nil {
					log.Warning("server-agent(%s@%s)[handleNhpOpenResource] forward failed: %v",
						knkMsg.UserId, addrStr, fwdErr)
				}
			}
		} else if lookupErr != nil && !IsNotFoundError(lookupErr) {
			log.Warning("server-agent(%s@%s)[handleNhpOpenResource] storage lookup failed: %v",
				knkMsg.UserId, addrStr, lookupErr)
		}
		// Fall through to local processing if forwarding failed
	}

	// PART III: request ac operation for each resource and block for response
	var acWg sync.WaitGroup
	var artMsgsMutex sync.Mutex
	artMsgs := make(map[string]*common.ACOpsResultMsg)
	ackMsg.ResourceHost = make(map[string]string)
	ackMsg.ACTokens = make(map[string]string)
	ackMsg.PreAccessActions = make(map[string]*common.PreAccessInfo)

	knockHadNoAC := false

	for resName, addrs := range acDstIpMap {
		resInfo := res.Resources[resName]
		if resInfo == nil {
			continue
		}
		acId := resInfo.ACId
		connsCopy, droppedStale := s.snapshotLiveACConns(acId)
		if droppedStale > 0 {
			log.Warning("server-agent(%s@%s)-ac(%s)[handleNhpOpenResource] filtered %d stale/closed AC connection(s) (threshold=%v)",
				knkMsg.UserId, addrStr, acId, droppedStale, s.staleACConnThreshold())
		}
		if len(connsCopy) == 0 {
			knockHadNoAC = true
			log.Warning("server-agent(%s@%s)-ac(%s)[handleNhpOpenResource] no ac connection is available", knkMsg.UserId, addrStr, acId)
			artMsg := &common.ACOpsResultMsg{}
			err = common.ErrACConnectionNotFound
			artMsg.ErrCode = common.ErrACConnectionNotFound.ErrorCode()
			artMsg.ErrMsg = err.Error()
			artMsgsMutex.Lock()
			artMsgs[resName] = artMsg
			artMsgsMutex.Unlock()
			continue
		}

		acWg.Add(1)
		go func(name string, info *common.ResourceInfo, dstAddrs []*common.NetAddress) {
			defer acWg.Done()

			// openTime=1 here is the attack payoff a MitM
			// type-flip (#1154) would exploit. The knock HeaderType
			// gate in nhpauth.go (verifyKnockHeaderType — upstream
			// of this call site) ensures knkMsg.HeaderType was
			// body-authenticated before we reach this branch. In
			// strict mode a mismatch is rejected entirely; in
			// permit mode the pre-fix behavior is preserved (wire
			// value used). See knock_headertype_gate.go for the
			// full policy.
			openTime := res.OpenTime
			if knkMsg.HeaderType == core.NHP_EXT {
				openTime = 1 // timeout in 1 second
			}
			// UDP knock path: no request-scoped context exists, so pass Background.
			// processACOperationBroadcast discards parent cancellation regardless.
			artMsg, err := s.processACOperationBroadcast(context.Background(), knkMsg, connsCopy, srcAddr, dstAddrs, openTime)
			artMsgsMutex.Lock()
			artMsgs[name] = artMsg
			if err == nil {
				ackMsg.ResourceHost[name] = info.DestHost()
				ackMsg.ACTokens[name] = artMsg.ACToken
				ackMsg.PreAccessActions[name] = artMsg.PreAccessAction
			}
			artMsgsMutex.Unlock()
		}(resName, resInfo, addrs)
	}
	acWg.Wait()

	// Increment once per knock request (not per resource) for alarm accuracy
	if knockHadNoAC {
		s.metrics.IncrCounter(MetricKnockNoAC)
	}

	var successCount int
	for _, artMsg := range artMsgs {
		if artMsg.ErrCode == common.ErrSuccess.ErrorCode() {
			successCount++
		}
	}

	if successCount == 0 {
		log.Info("server-agent(%s@%s)[handleNhpOpenResource] failed: %+v", knkMsg.UserId, addrStr, artMsgs)
		err = common.ErrServerACOpsFailed
		ackMsg.ErrCode = common.ErrServerACOpsFailed.ErrorCode()
		ackMsg.ErrMsg = err.Error()
		return
	}

	ackMsg.ErrCode = common.ErrSuccess.ErrorCode()
	ackMsg.ErrMsg = common.ErrSuccess.Error()
	return ackMsg, nil
}

func (us *UdpServer) NewNhpServerHelper(ppd *core.PacketParserData) *plugins.NhpServerPluginHelper {
	h := &plugins.NhpServerPluginHelper{}
	h.StopSignal = ppd.ConnData.StopSignal

	h.AuthWithNhpCallbackFunc = func(req *common.NhpAuthRequest, res *common.ResourceData) (*common.ServerKnockAckMsg, error) {
		return us.handleNhpOpenResource(req, res)
	}

	return h
}

func (us *UdpServer) FindPluginHandler(aspId string) plugins.PluginHandler {
	us.pluginHandlerMapMutex.RLock()
	defer us.pluginHandlerMapMutex.RUnlock()

	handler, found := us.pluginHandlerMap[aspId]
	if !found {
		return nil
	}
	return handler
}

// ============================================================================
// Server-to-Server Forwarding Handlers
// See docs/design/PLUGGABLE_STORAGE_BACKEND.md sections 6.3-6.5 for details.
// ============================================================================

// HandleForwardRequest processes an incoming NHP_FWD message from another server.
func (s *UdpServer) HandleForwardRequest(ppd *core.PacketParserData) {
	var fwdMsg common.ServerForwardMsg
	if err := json.Unmarshal(ppd.BodyMessage, &fwdMsg); err != nil {
		log.Error("Failed to parse NHP_FWD message: %v", err)
		return
	}

	if s.forwarder != nil {
		s.forwarder.HandleForwardRequest(ppd, &fwdMsg)
	} else {
		log.Warning("Received NHP_FWD but forwarder not initialized")
	}
}

// HandleForwardResult processes an incoming NHP_FRT response from another server.
func (s *UdpServer) HandleForwardResult(ppd *core.PacketParserData) {
	var resultMsg common.ServerForwardResultMsg
	if err := json.Unmarshal(ppd.BodyMessage, &resultMsg); err != nil {
		log.Error("Failed to parse NHP_FRT message: %v", err)
		return
	}

	if s.forwarder != nil {
		s.forwarder.HandleForwardResult(ppd, &resultMsg)
	} else {
		log.Warning("Received NHP_FRT but forwarder not initialized")
	}
}

// DHP
func (s *UdpServer) AddDEPeer(device *core.UdpPeer) {
	if device.DeviceType() == core.NHP_DB {
		s.device.AddPeer(device)
		s.dbPeerMapMutex.Lock()
		s.dbPeerMap[device.PublicKeyBase64()] = device
		s.dbPeerMapMutex.Unlock()
	}
}

func (s *UdpServer) ProcessDataPrivateKeyWrapping(dwrMsg *common.DWRMsg, conn *DBConn) (dwaMsg *common.DWAMsg, err error) {
	if dwrMsg == nil || conn == nil {
		log.Critical("processACOperation with nil input argument")
		err = common.ErrInvalidInput
		return
	}

	dbAddrStr := conn.DBPeer.RecvAddr().String()

	dwrBytes, marshalErr := json.Marshal(dwrMsg)
	if marshalErr != nil {
		log.Error("server-db(%s)[ProcessDataPrivateKeyWrapping] failed to marshal DWR message: %v", dbAddrStr, marshalErr)
		return nil, marshalErr
	}

	dwrMd := &core.MsgData{
		ConnData:      conn.ConnData,
		HeaderType:    core.NHP_DWR,
		CipherScheme:  conn.DBCipherScheme,
		TransactionId: s.device.NextCounterIndex(),
		Compress:      true,
		PeerPk:        conn.DBPeer.PublicKey(),
		Message:       dwrBytes,
		ResponseMsgCh: make(chan *core.PacketParserData),
	}

	dwaMsg = &common.DWAMsg{}

	if !s.IsRunning() {
		log.Error("server-db(%s#%d@%s)[ProcessDataPrivateKeyWrapping] MsgData channel closed or being closed, skip sending", conn.DBId, dwrMd.TransactionId, dbAddrStr)
		err = common.ErrPacketToMessageRoutineStopped
		errCode, _ := strconv.Atoi(common.ErrPacketToMessageRoutineStopped.ErrorCode())
		dwaMsg.ErrCode = errCode
		dwaMsg.ErrMsg = err.Error()
		return
	}

	s.sendMsgCh <- dwrMd

	// wait for ac sending back operation result
	// block until transaction completes
	dbPpd := <-dwrMd.ResponseMsgCh
	close(dwrMd.ResponseMsgCh)

	err = json.Unmarshal(dbPpd.BodyMessage, dwaMsg)
	if err != nil {
		log.Error("server-db(%s#%d@%s)[ProcessDataPrivateKeyWrapping] failed to parse %s message: %v", conn.DBId, dwrMd.TransactionId, dbAddrStr, core.HeaderTypeToString(dbPpd.HeaderType), err)
		errCode, _ := strconv.Atoi(common.ErrJsonParseFailed.ErrorCode())
		dwaMsg.ErrCode = errCode
		dwaMsg.ErrMsg = err.Error()
		return
	}

	return dwaMsg, nil
}

// FindACConnectionsForKnock finds all AC connections for a given knock message.
// This looks up the AC ID from the auth service provider's resource info
// and returns all corresponding AC connections if found.
// Multiple connections exist when blue/green ACs register with the same AC ID.
func (s *UdpServer) FindACConnectionsForKnock(knkMsg *common.AgentKnockMsg) []*ACConn {
	// Find the auth service provider
	aspData := s.FindAuthSvcProvider(knkMsg.AuthServiceId)
	if aspData == nil {
		log.Debug("FindACConnectionsForKnock: ASP not found for %s", knkMsg.AuthServiceId)
		return nil
	}

	// Find the resource to get the AC ID
	resInfo := aspData.FindResource(knkMsg.ResourceId)
	if resInfo == nil {
		log.Debug("FindACConnectionsForKnock: Resource %s not found in ASP %s", knkMsg.ResourceId, knkMsg.AuthServiceId)
		return nil
	}

	acId := resInfo.ACId
	if acId == "" {
		log.Debug("FindACConnectionsForKnock: Resource %s has no AC ID", knkMsg.ResourceId)
		return nil
	}

	// Look up all live AC connections. The forwarder consumes this slice
	// for NHP-AOP fan-out, so a stale conn here would drain the forwarded
	// knock's transaction timeout the same way it would drain a local one.
	result, droppedStale := s.snapshotLiveACConns(acId)
	if droppedStale > 0 {
		log.Warning("FindACConnectionsForKnock: AC %s filtered %d stale/closed connection(s) (threshold=%v)",
			acId, droppedStale, s.staleACConnThreshold())
	}

	if len(result) == 0 {
		log.Debug("FindACConnectionsForKnock: AC %s not connected", acId)
		return nil
	}

	return result
}

// ============================================================================
// ForwarderDeps Interface Implementation
// ============================================================================

// GetHostname returns the server's hostname for use in forward messages.
func (s *UdpServer) GetHostname() string {
	return s.config.Hostname
}

// GetDevice returns the core.Device for Noise protocol operations.
func (s *UdpServer) GetDevice() *core.Device {
	return s.device
}

// SendMessage queues a message for sending via the server's send channel.
func (s *UdpServer) SendMessage(md *core.MsgData) {
	s.sendMsgCh <- md
}

// ProcessACOperation wraps the internal processACOperation method.
func (s *UdpServer) ProcessACOperation(
	knkMsg *common.AgentKnockMsg,
	acConn *ACConn,
	srcAddr *common.NetAddress,
	dstAddrs []*common.NetAddress,
	openTime uint32,
) (*common.ACOpsResultMsg, error) {
	return s.processACOperation(context.Background(), knkMsg, acConn, srcAddr, dstAddrs, openTime)
}

// ProcessACOperationBroadcast wraps the internal processACOperationBroadcast method.
func (s *UdpServer) ProcessACOperationBroadcast(
	parentCtx context.Context,
	knkMsg *common.AgentKnockMsg,
	conns []*ACConn,
	srcAddr *common.NetAddress,
	dstAddrs []*common.NetAddress,
	openTime uint32,
) (*common.ACOpsResultMsg, error) {
	return s.processACOperationBroadcast(parentCtx, knkMsg, conns, srcAddr, dstAddrs, openTime)
}
