package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
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

	// connection and remote transaction management

	remoteConnectionMapMutex sync.Mutex
	remoteConnectionMap      map[string]*UdpConn // indexed by remote UDP address

	agentPeerMapMutex sync.Mutex
	agentPeerMap      map[string]*core.UdpPeer // indexed by peer's public key base64 string

	acConnectionMapMutex sync.Mutex
	acConnectionMap      map[string][]*ACConn // ac connections indexed by AC ID, multiple per ID for blue/green

	acPeerMapMutex sync.Mutex
	acPeerMap      map[string]*core.UdpPeer // indexed by peer's public key base64 string

	dbConnectionMapMutex sync.Mutex
	dbConnectionMap      map[string]*DBConn // ac connection is indexed by remote IP address

	tokenStore *common.TokenStore[*ACTokenEntry]

	// block address management
	blockAddrMapMutex sync.Mutex
	blockAddrMap      map[string]*BlockAddr // indexed by remote UDP address, need lock for dynamic change

	// address association map
	srcIpAssociatedAddrMapMutex sync.Mutex
	srcIpAssociatedAddrMap      map[string][]*common.NetAddress // indexed by source ip

	// preset asp-resource-address map
	authServiceMapMutex sync.Mutex
	authServiceMap      common.AuthSvcProviderMap // indexed by asp id and then resource id

	// plugin handlers
	pluginHandlerMapMutex sync.Mutex
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

	// CloudWatch metrics publisher for NHP operational metrics.
	metrics *metrics.Publisher
}

type BlockAddr struct {
	addr       *net.UDPAddr
	expireTime time.Time
}

type UdpConn struct {
	ConnData       *core.ConnectionData
	isACConnection bool // Immutable. Don't change it after creation. Conn object is also stored in acConnectionMap which is indexed by ACId
	isDBConnection bool // Immutable. Don't change it after creation. Conn object is also stored in dbConnectionMap which is indexed by DBId
	isWebRTC       bool
	dc             *webrtc.DataChannel
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

	// Initialize server-to-server forwarder
	s.forwarder = NewServerForwarder(s)
	s.forwarder.Start()

	if s.config.WebRTC.Enable {
		s.webrtcServer = NewWebRTCServer(s, &s.config.WebRTC)
		if err := s.webrtcServer.Start(); err != nil {
			log.Error("failed to start WebRTC server: %v", err)
		}
	}

	var netIP net.IP
	if len(s.config.ListenIp) > 0 {
		netIP = net.ParseIP(s.config.ListenIp)
		if netIP == nil {
			log.Error("udp listen ip address is incorrect!")
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
		log.Error("listen error %v", err)
		return fmt.Errorf("listen error: %w", err)
	}

	// retrieve local port
	laddr := s.listenConn.LocalAddr()
	s.listenAddr, err = net.ResolveUDPAddr(laddr.Network(), laddr.String())
	if err != nil {
		log.Error("resolve local UDPAddr error %v", err)
		return fmt.Errorf("resolve UDPAddr error: %w", err)
	}

	prk, err := base64.StdEncoding.DecodeString(s.config.PrivateKeyBase64)
	if err != nil {
		log.Error("private key parse error %v", err)
		return fmt.Errorf("private key parse error: %w", err)
	}

	// In cloud mode (storage_backend = "dynamodb"), disable AC peer pre-validation.
	// AC authentication will be done via license validation in HandleACOnline
	// instead of requiring pre-registered public keys from etcd.
	// See docs/design/PLUGGABLE_STORAGE_BACKEND.md Section 6.2 for details.
	cloudMode := s.storageConfig != nil && s.storageConfig.Backend == "dynamodb"
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
	s.localIp = utils.GetLocalOutboundAddress().String()
	s.localMac = utils.GetMacAddress(s.localIp)
	// load asp resources and plugins
	s.pluginHandlerMap = make(map[string]plugins.PluginHandler)
	if s.etcdConn != nil {
		// Try to load additional config from etcd (optional)
		// This loads HTTP config, agent peers, resources, etc. from /nhp/config key
		// Note: The key may not exist if etcd is used only for AC registry
		if err := s.loadRemoteConfig(); err != nil {
			log.Info("Remote config not loaded from etcd (key may not exist): %v", err)
			// Fall back to local config files for HTTP, peers, resources
			s.loadPeers()
			s.loadHttpConfig()
			s.loadSourceIps()
			s.loadResources()
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
		s.loadPeers()

		// load http config and turn on http server if needed
		s.loadHttpConfig()

		// load ip associated addresses
		s.loadSourceIps()

		s.loadResources()
	}

	s.remoteConnectionMap = make(map[string]*UdpConn)
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
	// Close storage backend
	if s.storage != nil {
		s.storage.Close()
	}
	// Stop forwarder cleanup routine
	if s.forwarder != nil {
		s.forwarder.Stop()
	}
	// Flush remaining CloudWatch metrics
	if s.metrics != nil {
		s.metrics.Stop()
	}
	close(s.signals.stop)
	s.listenConn.Close()
	s.device.Stop()
	s.StopConfigWatch()
	s.wg.Wait()
	close(s.sendMsgCh)
	s.ClosePlugins()

	log.Info("==========================")
	log.Info("=== NHP-Server stopped ===")
	log.Info("==========================")
	s.log.Close()
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

	preCheckThreats := make(map[string]int32)

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
			log.Error("Read from UDP error: %v", err)
			if n == 0 {
				// listenConn closed
				return
			}
			continue
		}
		addrStr := remoteAddr.String()

		// add total recv bytes
		atomic.AddUint64(&s.stats.totalRecvBytes, uint64(n))

		// check minimal length
		if n < pkt.MinimalLength() {
			s.device.ReleasePoolPacket(pkt)
			log.Error("Received UDP packet from %s is too short, discard", addrStr)
			continue
		}

		// check if it is from blocked address
		if s.IsBlockAddr(remoteAddr) {
			s.device.ReleasePoolPacket(pkt)
			log.Critical("Remote address %s is being blocked at the moment, discard.", addrStr)
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
			// threat plus 1
			preCheckThreats[addrStr]++
			if preCheckThreats[addrStr] > PreCheckThreatCountBeforeBlock {
				s.AddBlockAddr(remoteAddr)
			}
			s.device.ReleasePoolPacket(pkt)
			log.Warning("Receive [%s] packet (%s -> %s), precheck error: %v", msgType, addrStr, s.listenAddr.String(), err)
			log.Evaluate("Receive [%s] packet (%s -> %s) precheck error: %v", msgType, addrStr, s.listenAddr.String(), err)
			continue
		}
		// clear threat
		delete(preCheckThreats, addrStr)

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

			isACConn := pkt.HeaderType == core.NHP_AOL
			isDBConn := pkt.HeaderType == core.NHP_DOL
			conn = &UdpConn{
				isACConnection: isACConn,
				isDBConnection: isDBConn,
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
			s.remoteConnectionMapMutex.Lock()
			s.remoteConnectionMap[addrStr] = conn
			s.remoteConnectionMapMutex.Unlock()

			conn.ConnData.RecvQueue <- pkt

			log.Info("Accept new UDP connection from %s to %s", addrStr, s.listenAddr.String())

			// launch connection routine
			s.wg.Add(1)
			go s.connectionRoutine(conn)
		}
	}
}

func (s *UdpServer) connectionRoutine(conn *UdpConn) {
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

		// remove the udp conn from remoteConnectionMap
		s.remoteConnectionMapMutex.Lock()
		delete(s.remoteConnectionMap, addrStr)
		if len(s.remoteConnectionMap) <= OverloadConnectionThreshold {
			s.device.SetOverload(false)
		}
		s.remoteConnectionMapMutex.Unlock()

		conn.Close()
	}()

	for {
		select {
		case <-s.signals.stop:
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
					transaction.NextPacketCh <- pkt
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
			s.SendPacket(pkt, conn)
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

func (s *UdpServer) IsBlockAddr(addr *net.UDPAddr) bool {
	s.blockAddrMapMutex.Lock()
	defer s.blockAddrMapMutex.Unlock()

	_, found := s.blockAddrMap[addr.String()]
	return found
}

func (s *UdpServer) AddBlockAddr(addr *net.UDPAddr) {
	s.blockAddrMapMutex.Lock()
	defer s.blockAddrMapMutex.Unlock()

	addrStr := addr.String()
	log.Critical("add blocking address %s", addrStr)

	if len(s.blockAddrMap) < MaxConcurrentConnection {
		s.blockAddrMap[addrStr] = &BlockAddr{addr, time.Now().Add(BlockAddrExpireTime * time.Second)}
	} else {
		log.Warning("block address pool is full")
	}
}

func (s *UdpServer) RefreshBlockAddr() {
	s.blockAddrMapMutex.Lock()
	defer s.blockAddrMapMutex.Unlock()

	now := time.Now()
	for k, v := range s.blockAddrMap {
		if v.expireTime.Before(now) {
			delete(s.blockAddrMap, k)
		}
	}
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
					transaction.NextMsgCh <- md
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

			switch ppd.HeaderType {
			case core.NHP_KNK, core.NHP_RKN, core.NHP_EXT, core.DHP_KNK:
				// aynchronously process knock messages with ack response
				go s.HandleKnockRequest(ppd)

			case core.NHP_AOL:
				// synchronously block and deal with NHP_DOL to ensure future ac messages will be correctly processed. Don't use go routine
				s.HandleACOnline(ppd)

			case core.NHP_DOL:
				s.HandleDBOnline(ppd)

			case core.NHP_OTP:
				go s.HandleOTPRequest(ppd)

			case core.NHP_REG:
				go s.HandleRegisterRequest(ppd)

			case core.NHP_LST:
				go s.HandleListRequest(ppd)
			case core.NHP_DAR:
				go s.HandleDHPDARMessage(ppd)
			case core.NHP_DRG:
				go s.HandleDHPDRGMessage(ppd)
			case core.NHP_DAV:
				go s.HandleDHPDAVMessage(ppd)

			// Server-to-server forwarding
			case core.NHP_FWD:
				go s.HandleForwardRequest(ppd)
			case core.NHP_FRT:
				go s.HandleForwardResult(ppd)
			}

		}
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
		log.Error("Plugin: %s validation failed", pluginId)
		return errors.New("plugin validation failed")
	}

	s.pluginHandlerMapMutex.Lock()
	oldHandler, found := s.pluginHandlerMap[pluginId]
	s.pluginHandlerMapMutex.Unlock()
	if found {
		oldHandler.Close()
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
		log.Error("plugin: %s initialization failed, %v", pluginId, err)
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
		handler.Close()
	}
}

func (s *UdpServer) FindAuthSvcProvider(aspId string) *common.AuthServiceProviderData {
	s.authServiceMapMutex.Lock()
	defer s.authServiceMapMutex.Unlock()

	aspData, found := s.authServiceMap[aspId]
	if found {
		return aspData
	}

	return nil
}

func (s *UdpServer) processACOperation(knkMsg *common.AgentKnockMsg, conn *ACConn, srcAddr *common.NetAddress, dstAddrs []*common.NetAddress, openTime uint32) (artMsg *common.ACOpsResultMsg, err error) {
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
	aopBytes, _ := json.Marshal(aopMsg)

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
	// block until transaction completes
	acPpd := <-aopMd.ResponseMsgCh
	close(aopMd.ResponseMsgCh)

	if acPpd.Error != nil {
		log.Error("server-agent(%s@%s)-ac(%s#%d@%s)[processACOperation] failed to receive response from ac: %v", knkMsg.UserId, srcAddr.String(), conn.ACId, aopMd.TransactionId, acAddrStr, acPpd.Error)
		err = acPpd.Error
		artMsg.ErrCode = common.ErrServerACOpsFailed.ErrorCode()
		artMsg.ErrMsg = err.Error()
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

// processACOperationBroadcast sends NHP-AOP to all AC connections in parallel.
// Returns the first successful result. If all fail, returns the last error.
// This supports blue/green deployments where multiple ACs register with the same AC ID.
func (s *UdpServer) processACOperationBroadcast(
	knkMsg *common.AgentKnockMsg,
	conns []*ACConn,
	srcAddr *common.NetAddress,
	dstAddrs []*common.NetAddress,
	openTime uint32,
) (*common.ACOpsResultMsg, error) {
	if len(conns) == 1 {
		return s.processACOperation(knkMsg, conns[0], srcAddr, dstAddrs, openTime)
	}

	log.Info("server-agent(%s@%s)[processACOperationBroadcast] broadcasting to %d ACs", knkMsg.UserId, srcAddr.String(), len(conns))

	type result struct {
		artMsg *common.ACOpsResultMsg
		err    error
		acAddr string
	}
	results := make(chan result, len(conns))
	for _, conn := range conns {
		go func(c *ACConn) {
			artMsg, err := s.processACOperation(knkMsg, c, srcAddr, dstAddrs, openTime)
			results <- result{artMsg, err, c.ACPeer.RecvAddr().String()}
		}(conn)
	}

	var lastErr error
	var lastArtMsg *common.ACOpsResultMsg
	for i := 0; i < len(conns); i++ {
		r := <-results
		if r.err == nil {
			log.Info("server-agent(%s@%s)[processACOperationBroadcast] AC at %s succeeded", knkMsg.UserId, srcAddr.String(), r.acAddr)
			return r.artMsg, nil
		}
		lastErr = r.err
		lastArtMsg = r.artMsg
	}
	log.Warning("server-agent(%s@%s)[processACOperationBroadcast] all %d ACs failed", knkMsg.UserId, srcAddr.String(), len(conns))
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
		s.acConnectionMapMutex.Lock()
		conns, found := s.acConnectionMap[resInfo.ACId]
		s.acConnectionMapMutex.Unlock()
		if !found || len(conns) == 0 {
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
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
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

	for resName, addrs := range acDstIpMap {
		resInfo := res.Resources[resName]
		if resInfo == nil {
			continue
		}
		acId := resInfo.ACId
		s.acConnectionMapMutex.Lock()
		acConns, found := s.acConnectionMap[acId]
		var connsCopy []*ACConn
		if found {
			connsCopy = slices.Clone(acConns)
		}
		s.acConnectionMapMutex.Unlock()
		if !found || len(connsCopy) == 0 {
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

			openTime := res.OpenTime
			if knkMsg.HeaderType == core.NHP_EXT {
				openTime = 1 // timeout in 1 second
			}
			artMsg, err := s.processACOperationBroadcast(knkMsg, connsCopy, srcAddr, dstAddrs, openTime)
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
	us.pluginHandlerMapMutex.Lock()
	defer us.pluginHandlerMapMutex.Unlock()

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

	dwrBytes, _ := json.Marshal(dwrMsg)

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

	// Look up all AC connections
	s.acConnectionMapMutex.Lock()
	conns, found := s.acConnectionMap[acId]
	var result []*ACConn
	if found {
		result = slices.Clone(conns)
	}
	s.acConnectionMapMutex.Unlock()

	if !found || len(result) == 0 {
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
	return s.processACOperation(knkMsg, acConn, srcAddr, dstAddrs, openTime)
}

// ProcessACOperationBroadcast wraps the internal processACOperationBroadcast method.
func (s *UdpServer) ProcessACOperationBroadcast(
	knkMsg *common.AgentKnockMsg,
	conns []*ACConn,
	srcAddr *common.NetAddress,
	dstAddrs []*common.NetAddress,
	openTime uint32,
) (*common.ACOpsResultMsg, error) {
	return s.processACOperationBroadcast(knkMsg, conns, srcAddr, dstAddrs, openTime)
}
