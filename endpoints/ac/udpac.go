package ac

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	ebpflocal "github.com/OpenNHP/opennhp/endpoints/ac/ebpf"
	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
	"github.com/OpenNHP/opennhp/nhp/log"
	"github.com/OpenNHP/opennhp/nhp/utils"
	"github.com/OpenNHP/opennhp/nhp/utils/ebpf"
	"github.com/OpenNHP/opennhp/nhp/version"
)

var (
	ExeDirPath string
)

type UdpAC struct {
	config     *Config
	httpConfig *HttpConfig
	iptables   *utils.IPTables
	ipset      *utils.IPSet

	stats struct {
		totalRecvBytes uint64
		totalSendBytes uint64
	}

	log *log.Logger

	remoteConnectionMutex sync.Mutex
	remoteConnectionMap   map[string]*UdpConn // indexed by remote UDP address

	serverPeerMutex sync.RWMutex
	serverPeerMap   map[string]*core.UdpPeer // indexed by server's public key

	tokenStore *common.TokenStore[*AccessEntry]

	device     *core.Device
	httpServer *HttpAC
	wg         sync.WaitGroup
	running    atomic.Bool

	signals struct {
		stop             chan struct{}
		serverMapUpdated chan struct{}
	}

	recvMsgCh <-chan *core.PacketParserData
	sendMsgCh chan *core.MsgData

	// Multi-server connection management
	// See docs/design/PLUGGABLE_STORAGE_BACKEND.md section 6.2
	registration *ACRegistration

	// dnsRateLimiter prevents reconnection storms when DNS flaps rapidly.
	// See dns_rate_limiter.go for details.
	dnsRateLimiter *DNSChangeRateLimiter
}

type UdpConn struct {
	ConnData     *core.ConnectionData
	netConn      *net.UDPConn
	connected    atomic.Bool
	externalAddr string
}

func (c *UdpConn) Close() {
	if c.netConn != nil {
		_ = c.netConn.Close()
		c.ConnData.Close()
	}
}

/*
dirPath: the path of app or shared library entry point
logLevel: 0: silent, 1: error, 2: info, 3: debug, 4: verbose
*/
func (a *UdpAC) Start(dirPath string, logLevel int) (err error) {
	common.ExeDirPath = dirPath
	ExeDirPath = dirPath
	// init logger
	a.log = log.NewLogger("NHP-AC", logLevel, filepath.Join(ExeDirPath, "logs"), "ac")
	log.SetGlobalLogger(a.log)

	log.Info("=========================================================")
	log.Info("=== NHP-AC %s started                              ===", version.Version)
	log.Info("=== REVISION %s ===", version.CommitId)
	log.Info("=== RELEASE %s                       ===", version.BuildTime)
	log.Info("=========================================================")

	// Load local base config (private key must come from local file)
	err = a.loadBaseConfig()
	if err != nil {
		return err
	}

	switch a.config.FilterMode {
	case FilterMode_IPTABLES:
		a.iptables, err = utils.NewIPTables()
		if err != nil {
			log.Error("iptables command not found")
			return
		}

		a.ipset, err = utils.NewIPSet(false)
		if err != nil {
			log.Error("ipset command not found")
			return
		}
	case FilterMode_EBPFXDP:
		err = ebpflocal.EbpfEngineLoad(dirPath, logLevel, a.config.ACId)
		if err != nil {
			return err
		}
	default:
		log.Error("[HandleAccessControl] unsupported FilterMode: %d (expected 0=IPTABLES or 1=EBPFXDP)", a.config.FilterMode)
		return
	}

	prk, err := base64.StdEncoding.DecodeString(a.config.PrivateKeyBase64)
	if err != nil {
		log.Error("private key parse error %v", err)
		return fmt.Errorf("private key parse error: %w", err)
	}

	a.device = core.NewDevice(core.NHP_AC, prk, nil)
	if a.device == nil {
		log.Critical("failed to create device")
		return errors.New("failed to create device")
	}

	a.remoteConnectionMap = make(map[string]*UdpConn)
	a.serverPeerMap = make(map[string]*core.UdpPeer)
	a.tokenStore = common.NewTokenStore[*AccessEntry]()
	a.dnsRateLimiter = NewDNSChangeRateLimiter()

	// Load http config and turn on http server if needed
	if err := a.loadHttpConfig(); err != nil {
		log.Error("failed to load http config: %v", err)
	}

	// Load server peers from local config
	if err := a.loadPeers(); err != nil {
		log.Error("failed to load server peers: %v", err)
	}

	if a.config.FilterMode == FilterMode_EBPFXDP {
		for _, server := range a.config.Servers {
			ebpfHashStr := ebpf.EbpfRuleParams{
				SrcIP: server.Ip,
				DstIP: a.config.DefaultIp,
			}
			log.Info("server ip is %s", server.Ip)
			err = ebpf.EbpfRuleAdd(2, ebpfHashStr, 31536000)
			if err != nil {
				log.Error("[EbpfRuleAdd] add ebpf src: %s dst: %s, error: %v", ebpfHashStr.SrcIP, ebpfHashStr.DstIP, err)
				continue
			}
		}
	}

	a.signals.stop = make(chan struct{})
	a.signals.serverMapUpdated = make(chan struct{}, 1)

	a.recvMsgCh = a.device.DecryptedMsgQueue
	a.sendMsgCh = make(chan *core.MsgData, core.SendQueueSize)

	// start device routines
	a.device.Start()

	// Initialize multi-server registration manager
	var regErr error
	a.registration, regErr = NewACRegistration(a)
	if regErr != nil {
		return fmt.Errorf("failed to create AC registration manager: %w", regErr)
	}
	if err := a.registration.Start(); err != nil {
		return fmt.Errorf("failed to start AC registration manager: %w", err)
	}

	// start ac routines
	a.wg.Add(4)
	go a.tokenStore.RunRefreshRoutine(&a.wg, a.signals.stop, TokenStoreRefreshInterval)
	go a.sendMessageRoutine()
	go a.recvMessageRoutine()
	go a.maintainServerConnectionRoutine()

	a.running.Store(true)
	return nil
}

func (ac *UdpAC) Stop() {
	ac.running.Store(false)
	close(ac.signals.stop)
	// Stop registration manager
	if ac.registration != nil {
		ac.registration.Stop()
	}
	ac.device.Stop()
	ac.StopConfigWatch()
	if ac.dnsRateLimiter != nil {
		ac.dnsRateLimiter.ResetAll()
	}
	ac.wg.Wait()
	close(ac.sendMsgCh)
	close(ac.signals.serverMapUpdated)

	log.Info("==========================")
	log.Info("=== NHP-AC stopped ===")
	log.Info("==========================")
	ac.log.Close()
	if ebpflocal.DenyLogger != nil {
		ebpflocal.DenyLogger.Close()
	}
	if ebpflocal.AcLogger != nil {
		ebpflocal.AcLogger.Close()
	}
}

func (a *UdpAC) IsRunning() bool {
	return a.running.Load()
}

func (a *UdpAC) newConnection(addr *net.UDPAddr) (conn *UdpConn) {
	conn = &UdpConn{}
	var err error
	// Use ListenUDP instead of DialUDP to create an unconnected socket.
	// Connected sockets (from DialUDP) only accept packets from the dialed address,
	// which breaks when AC connects through NLB but server responds from its direct IP.
	// Unconnected sockets accept packets from any source, allowing the server to
	// respond directly without going through the NLB.
	//
	// Security note: Accepting packets from any source is safe because all NHP
	// packets are cryptographically validated by the device layer. Unauthenticated
	// or forged packets are rejected in device.RecvPrecheck() before processing.
	//
	// Determine the network type based on the remote address to ensure we bind
	// to the correct address family (IPv4 vs IPv6).
	network := "udp4"
	localIP := net.IPv4zero
	if addr.IP.To4() == nil {
		// IPv6 address
		network = "udp6"
		localIP = net.IPv6zero
	}
	conn.netConn, err = net.ListenUDP(network, &net.UDPAddr{IP: localIP, Port: 0})
	if err != nil {
		log.Error("[AC] failed to create UDP socket (%s) for remote addr %s: %v", network, addr.String(), err)
		return nil
	}

	// retrieve local port
	laddr := conn.netConn.LocalAddr()
	localAddr, err := net.ResolveUDPAddr(laddr.Network(), laddr.String())
	if err != nil {
		log.Error("[AC] failed to resolve local UDPAddr %s: %v", laddr.String(), err)
		_ = conn.netConn.Close()
		return nil
	}

	log.Info("Created UDP socket from %s for remote %s", localAddr.String(), addr.String())

	conn.ConnData = &core.ConnectionData{
		Device:               a.device,
		CookieStore:          &core.CookieStore{},
		RemoteTransactionMap: make(map[uint64]*core.RemoteTransaction),
		LocalAddr:            localAddr,
		RemoteAddr:           addr,
		TimeoutMs:            DefaultConnectionTimeoutMs,
		SendQueue:            make(chan *core.Packet, PacketQueueSizePerConnection),
		RecvQueue:            make(chan *core.Packet, PacketQueueSizePerConnection),
		BlockSignal:          make(chan struct{}),
		SetTimeoutSignal:     make(chan struct{}),
		StopSignal:           make(chan struct{}),
	}

	// start connection receive routine
	conn.ConnData.Add(1)
	go a.recvPacketRoutine(conn)

	return conn
}

func (a *UdpAC) sendMessageRoutine() {
	defer a.wg.Done()
	defer log.Info("sendMessageRoutine stopped")

	log.Info("sendMessageRoutine started")

	for {
		select {
		case <-a.signals.stop:
			return

		case md, ok := <-a.sendMsgCh:
			if !ok {
				return
			}
			if md == nil || md.RemoteAddr == nil {
				log.Warning("Invalid initiator session starter")
				continue
			}

			addrStr := md.RemoteAddr.String()

			a.remoteConnectionMutex.Lock()
			conn, found := a.remoteConnectionMap[addrStr]
			a.remoteConnectionMutex.Unlock()

			if found {
				md.ConnData = conn.ConnData
			} else {
				conn = a.newConnection(md.RemoteAddr)
				if conn == nil {
					log.Error("[AC] failed to create connection to remote address %s", addrStr)
					continue
				}

				a.remoteConnectionMutex.Lock()
				a.remoteConnectionMap[addrStr] = conn
				a.remoteConnectionMutex.Unlock()

				md.ConnData = conn.ConnData

				// launch connection routine
				a.wg.Add(1)
				go a.connectionRoutine(conn)
			}

			a.device.SendMsgToPacket(md)
		}
	}
}

func (a *UdpAC) SendPacket(pkt *core.Packet, conn *UdpConn) (n int, err error) {
	defer func() {
		atomic.AddUint64(&a.stats.totalSendBytes, uint64(n))
		atomic.StoreInt64(&conn.ConnData.LastLocalSendTime, time.Now().UnixNano())

		if !pkt.KeepAfterSend {
			a.device.ReleasePoolPacket(pkt)
		}
	}()

	pktType := core.HeaderTypeToString(pkt.HeaderType)
	//log.Debug("Send [%s] packet (%s -> %s): %+v", pktType, conn.ConnData.LocalAddr.String(), conn.ConnData.RemoteAddr.String(), pkt.Content)
	log.Info("Send [%s] packet (%s -> %s), %d bytes", pktType, conn.ConnData.LocalAddr.String(), conn.ConnData.RemoteAddr.String(), len(pkt.Content))
	log.Evaluate("Send [%s] packet (%s -> %s, %d bytes)", pktType, conn.ConnData.LocalAddr.String(), conn.ConnData.RemoteAddr.String(), len(pkt.Content))
	// Use WriteToUDP with explicit destination since we use unconnected sockets
	return conn.netConn.WriteToUDP(pkt.Content, conn.ConnData.RemoteAddr)
}

func (a *UdpAC) recvPacketRoutine(conn *UdpConn) {
	addrStr := conn.ConnData.RemoteAddr.String()

	defer conn.ConnData.Done()
	defer log.Debug("recvPacketRoutine for %s stopped", addrStr)

	log.Debug("recvPacketRoutine for %s started", addrStr)

	for {
		select {
		case <-conn.ConnData.StopSignal:
			return

		default:
		}

		// udp recv, blocking until packet arrives or netConn.Close()
		// Use ReadFromUDP since we use unconnected sockets that accept from any source.
		// This allows the server to respond directly (bypassing NLB) while AC sent via NLB.
		pkt := a.device.AllocatePoolPacket()
		n, fromAddr, err := conn.netConn.ReadFromUDP(pkt.Buf[:])
		if err != nil {
			a.device.ReleasePoolPacket(pkt)
			if n == 0 {
				// udp connection closed, it is not an error
				return
			}
			log.Error("[AC] failed to receive UDP packet from %s: %v", addrStr, err)
			continue
		}
		// Log the actual source address for debugging (may differ from expected remote)
		// This is expected when server responds directly instead of through NLB
		actualSource := fromAddr.String()
		if actualSource != addrStr {
			log.Debug("Received packet from %s (expected %s) - server responding directly", actualSource, addrStr)
		}

		// add total recv bytes
		atomic.AddUint64(&a.stats.totalRecvBytes, uint64(n))

		// check minimal length
		if n < pkt.MinimalLength() {
			a.device.ReleasePoolPacket(pkt)
			log.Error("[AC] received UDP packet from %s is too short (%d bytes, min %d), discarding", actualSource, n, pkt.MinimalLength())
			continue
		}

		pkt.Content = pkt.Buf[:n]
		//log.Trace("receive udp packet (%s -> %s): %+v", conn.ConnData.RemoteAddr.String(), conn.ConnData.LocalAddr.String(), pkt.Content)

		typ, _, err := a.device.RecvPrecheck(pkt)
		msgType := core.HeaderTypeToString(typ)
		log.Info("Receive [%s] packet (%s -> %s), %d bytes", msgType, actualSource, conn.ConnData.LocalAddr.String(), n)
		log.Evaluate("Receive [%s] packet (%s -> %s), %d bytes", msgType, actualSource, conn.ConnData.LocalAddr.String(), n)
		if err != nil {
			a.device.ReleasePoolPacket(pkt)
			log.Warning("Receive [%s] packet (%s -> %s), precheck error: %v", msgType, actualSource, conn.ConnData.LocalAddr.String(), err)
			log.Evaluate("Receive [%s] packet (%s -> %s) precheck error: %v", msgType, actualSource, conn.ConnData.LocalAddr.String(), err)
			continue
		}

		atomic.StoreInt64(&conn.ConnData.LastLocalRecvTime, time.Now().UnixNano())

		// Do NOT update LastSeen on raw packet receipt. Updating on any received packet
		// allows spoofed traffic to mask server failures. LastSeen is only updated when
		// the AC receives a validated NHP_AAK response to a periodic NHP_AOL refresh
		// (see handleRefreshResponse in registration.go). This ensures cryptographic
		// proof that the server is alive and responding correctly.

		conn.ConnData.ForwardInboundPacket(pkt)
	}
}

func (a *UdpAC) connectionRoutine(conn *UdpConn) {
	addrStr := conn.ConnData.RemoteAddr.String()

	defer a.wg.Done()
	defer log.Debug("Connection routine: %s stopped", addrStr)

	log.Debug("Connection routine: %s started", addrStr)

	// stop receiving packets and clean up
	defer func() {
		a.remoteConnectionMutex.Lock()
		delete(a.remoteConnectionMap, addrStr)
		a.remoteConnectionMutex.Unlock()

		conn.Close()
	}()

	for {
		select {
		case <-a.signals.stop:
			return

		case <-conn.ConnData.SetTimeoutSignal:
			if conn.ConnData.TimeoutMs <= 0 {
				log.Debug("Connection routine closed immediately")
				return
			}

		case <-time.After(time.Duration(conn.ConnData.TimeoutMs) * time.Millisecond):
			// timeout, quit routine
			log.Debug("Connection routine idle timeout for %s", addrStr)
			// If this is a server connection in cloud mode, trigger re-registration
			// so the server gets our new address when we reconnect.
			if a.registration != nil && a.registration.IsServerAddress(addrStr) {
				log.Info("Server connection %s timed out, triggering re-registration", addrStr)
				a.registration.TriggerReregistration(ReasonServerConnectionTimeout)
			}
			return

		case pkt, ok := <-conn.ConnData.SendQueue:
			if !ok {
				return
			}
			if pkt == nil {
				continue
			}
			if _, sendErr := a.SendPacket(pkt, conn); sendErr != nil {
				log.Error("failed to send packet to %s: %v", addrStr, sendErr)
			}

		case pkt, ok := <-conn.ConnData.RecvQueue:
			if !ok {
				return
			}
			if pkt == nil {
				continue
			}
			log.Debug("Received udp packet len [%d] from addr: %s", len(pkt.Content), addrStr)

			if pkt.HeaderType == core.NHP_KPL {
				a.device.ReleasePoolPacket(pkt)
				log.Info("Receive [NHP_KPL] message (%s -> %s)", addrStr, conn.ConnData.LocalAddr.String())
				continue
			}

			if a.device.IsTransactionResponse(pkt.HeaderType) {
				// forward to a specific transaction
				transactionId := pkt.Counter()
				transaction := a.device.FindLocalTransaction(transactionId)
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
			a.device.RecvPacketToMsg(pd)

		case <-conn.ConnData.BlockSignal:
			log.Critical("blocking address %s", addrStr)
			return
		}
	}
}

func (a *UdpAC) recvMessageRoutine() {
	defer a.wg.Done()
	defer log.Info("recvMessageRoutine stopped")

	log.Info("recvMessageRoutine started")

	for {
		select {
		case <-a.signals.stop:
			return

		case ppd, ok := <-a.recvMsgCh:
			if !ok {
				return
			}
			if ppd == nil {
				continue
			}

			// Do NOT update LastSeen on every received message. While the pubkey is
			// cryptographically validated, blindly updating on any message type allows
			// unrelated server traffic (e.g., NHP_AOP) to mask keepalive failures.
			// LastSeen is only updated via validated NHP_AAK responses to periodic
			// NHP_AOL refresh requests (see handleRefreshResponse in registration.go).

			switch ppd.HeaderType {
			case core.NHP_AOP:
				// deal with NHP_AOP message
				a.wg.Add(1)
				go func() {
					if err := a.HandleUdpACOperations(ppd); err != nil {
						log.Error("HandleUdpACOperations failed: %v", err)
					}
				}()

			case core.NHP_ARD:
				// Handle AC redispatch to assigned servers
				go a.HandleACRedispatch(ppd)
			}
		}
	}
}

// keep interaction between ac and server in certain time interval to keep outwards ip path active
func (a *UdpAC) maintainServerConnectionRoutine() {
	defer a.wg.Done()
	defer log.Info("maintainServerConnectionRoutine stopped")

	log.Info("maintainServerConnectionRoutine started")

	// reset iptables before exiting
	if a.config.FilterMode == FilterMode_IPTABLES {
		defer a.iptables.ResetAllInput()
	}

	// Check for cloud mode at startup (no static servers configured)
	a.serverPeerMutex.RLock()
	isCloudMode := len(a.serverPeerMap) == 0
	a.serverPeerMutex.RUnlock()
	if isCloudMode {
		log.Info("Cloud mode detected: no static servers configured, AC will use dynamic registration")
	}

	var discoveryRoutineWg sync.WaitGroup
	defer discoveryRoutineWg.Wait()

	for {
		// make a local copy of servers then iterate because next operations are time consuming (too long to use locked iteration)
		a.serverPeerMutex.RLock()
		var serverCount int32 = int32(len(a.serverPeerMap))
		discoveryQuitArr := make([]chan struct{}, 0, serverCount)
		discoveryFailStatusArr := make([]*int32, 0, serverCount)

		for _, server := range a.serverPeerMap {
			// launch discovery routine for each server
			fail := new(int32)
			discoveryFailStatusArr = append(discoveryFailStatusArr, fail)
			quit := make(chan struct{})
			discoveryQuitArr = append(discoveryQuitArr, quit)

			discoveryRoutineWg.Add(1)
			go a.serverDiscovery(server, &discoveryRoutineWg, fail, quit)
		}
		a.serverPeerMutex.RUnlock()

		// check whether all server discovery failed.
		// If so, open all blocked input
		quitCheck := make(chan struct{})
		discoveryQuitArr = append(discoveryQuitArr, quitCheck)
		discoveryRoutineWg.Add(1)
		go func() {
			defer discoveryRoutineWg.Done()

			for {
				select {
				case <-a.signals.stop:
					return
				case <-quitCheck:
					return
				case <-time.After(MinimalServerDiscoveryInterval * time.Second):
					// Skip fail-open logic if no servers configured (cloud mode uses registration, not discovery)
					if len(discoveryFailStatusArr) == 0 {
						log.Debug("Cloud mode: skipping fail-open check (no static servers configured)")
						continue
					}

					var totalFail int32
					for _, status := range discoveryFailStatusArr {
						totalFail += atomic.LoadInt32(status)
					}

					if totalFail < int32(len(discoveryFailStatusArr)) {
						if a.config.FilterMode == FilterMode_IPTABLES {
							a.iptables.ResetAllInput()
						}
					} else {
						if a.config.FilterMode == FilterMode_IPTABLES {
							a.iptables.AcceptAllInput()
						}
					}
				}
			}
		}()

		select {
		case <-a.signals.stop:
			return
		case _, ok := <-a.signals.serverMapUpdated:
			if !ok {
				return
			}
			// stop all current discovery routines
			for _, q := range discoveryQuitArr {
				close(q)
			}
			// continue and restart with new server discovery cycle
		}
	}
}

func (a *UdpAC) serverDiscovery(server *core.UdpPeer, discoveryRoutineWg *sync.WaitGroup, serverFailCount *int32, quit <-chan struct{}) {
	defer discoveryRoutineWg.Done()

	acId := a.config.ACId
	var lastAddrStr string // Track previous address to detect DNS changes

	defer func() {
		if lastAddrStr != "" {
			log.Info("server discovery sub-routine at %s stopped", lastAddrStr)
		}
	}()
	log.Info("server discovery sub-routine started for %s", server.Hostname)

	var failCount int

	for {
		// Re-resolve server address each iteration to pick up DNS changes
		sendAddr := server.SendAddr()
		if sendAddr == nil {
			log.Error("Cannot resolve server address for %s, will retry", server.Hostname)
			select {
			case <-a.signals.stop:
				return
			case <-quit:
				return
			case <-time.After(MinimalServerDiscoveryInterval * time.Second):
				continue
			}
		}
		addrStr := sendAddr.String()

		// If address changed, close old connection and reset fail count.
		// Rate-limit rapid DNS changes to prevent reconnection storms during DNS flapping.
		if lastAddrStr != "" && lastAddrStr != addrStr {
			if a.dnsRateLimiter != nil && !a.dnsRateLimiter.ShouldProcess(server.Hostname, lastAddrStr, addrStr) {
				// DNS change suppressed — keep using the current address
				addrStr = lastAddrStr
			} else {
				log.Info("ac(%s)[ServerDiscovery] Server DNS changed: %s -> %s (hostname: %s). Resetting connection state.",
					acId, lastAddrStr, addrStr, server.Hostname)
				var oldConn *UdpConn
				a.remoteConnectionMutex.Lock()
				if conn, found := a.remoteConnectionMap[lastAddrStr]; found {
					oldConn = conn
					delete(a.remoteConnectionMap, lastAddrStr)
					log.Debug("ac(%s)[ServerDiscovery] Removed old connection entry for %s", acId, lastAddrStr)
				}
				a.remoteConnectionMutex.Unlock()
				// Close outside lock to avoid blocking other operations, but synchronously
				// to ensure cleanup completes before we proceed
				if oldConn != nil {
					oldConn.Close()
					log.Info("ac(%s)[ServerDiscovery] Closed old connection to %s, will establish new connection to %s",
						acId, lastAddrStr, addrStr)
				}
				failCount = 0
				atomic.StoreInt32(serverFailCount, 0)
			}
		}
		lastAddrStr = addrStr
		var lastSendTime int64
		var lastRecvTime int64
		var connected bool

		// find whether connection is already connected
		a.remoteConnectionMutex.Lock()
		conn, found := a.remoteConnectionMap[addrStr]
		a.remoteConnectionMutex.Unlock()

		if found {
			// connection based timing
			lastSendTime = atomic.LoadInt64(&conn.ConnData.LastLocalSendTime)
			lastRecvTime = atomic.LoadInt64(&conn.ConnData.LastLocalRecvTime)
			connected = conn.connected.Load()
		} else {
			// peer based timing
			conn = nil
			lastSendTime = server.LastSendTime()
			lastRecvTime = server.LastRecvTime()
		}

		currTime := time.Now().UnixNano()
		peerPbk := server.PublicKey()
		log.Debug("serverDiscovery: server=%s, peerPbk len=%d, base64=%s",
			server.Hostname, len(peerPbk), server.PublicKeyBase64())

		// when a server is not connected, try to connect in every ACLocalTransactionResponseTimeoutMs
		// when a server is connected when ServerConnectionInterval is reached since last receive, try resend NHP_AOL for maintaining server connection
		if !connected || (currTime-lastRecvTime) > int64(ReportToServerInterval*time.Second) {
			// send NHP_AOL message to server
			aolMsg := &common.ACOnlineMsg{
				ACId:          acId,
				AuthServiceId: a.config.AuthServiceId,
				ResourceIds:   a.config.ResourceIds,
			}
			aolBytes, marshalErr := json.Marshal(aolMsg)
			if marshalErr != nil {
				log.Error("ac(%s)[ACOnline] failed to marshal AOL message: %v", acId, marshalErr)
				return
			}

			udpAddr, ok := sendAddr.(*net.UDPAddr)
			if !ok {
				log.Error("ac(%s)[ACOnline] unexpected address type %T", acId, sendAddr)
				return
			}
			aolMd := &core.MsgData{
				RemoteAddr:    udpAddr,
				HeaderType:    core.NHP_AOL,
				CipherScheme:  a.config.DefaultCipherScheme,
				TransactionId: a.device.NextCounterIndex(),
				Compress:      true,
				PeerPk:        peerPbk,
				Message:       aolBytes,
				ResponseMsgCh: make(chan *core.PacketParserData),
			}

			if !a.IsRunning() {
				log.Error("ac(%s#%d)[ACOnline] MsgData channel closed or being closed, skip sending", acId, aolMd.TransactionId)
				return
			}

			a.sendMsgCh <- aolMd // create new connection
			server.UpdateSend(currTime)

			// block until transaction completes or timeouts
			ppd := <-aolMd.ResponseMsgCh
			close(aolMd.ResponseMsgCh)

			var err error
			func() {
				defer func() {
					if err != nil {
						if conn != nil {
							conn.connected.Store(false)
						}

						failCount += 1
						attemptsUntilInvalidation := ServerDiscoveryRetryBeforeFail - (failCount % ServerDiscoveryRetryBeforeFail)
						if attemptsUntilInvalidation == ServerDiscoveryRetryBeforeFail {
							attemptsUntilInvalidation = 0 // We're at the threshold, invalidation happens now
						}
						log.Debug("ac(%s)[ServerDiscovery] connection to %s failed (attempt %d, %d more until DNS invalidation)",
							acId, addrStr, failCount, attemptsUntilInvalidation)

						if failCount%ServerDiscoveryRetryBeforeFail == 0 {
							atomic.StoreInt32(serverFailCount, 1)
							log.Warning("ac(%s)[ServerDiscovery] %d consecutive failures to %s, invalidating DNS cache",
								acId, ServerDiscoveryRetryBeforeFail, addrStr)

							// remove failed connection
							a.remoteConnectionMutex.Lock()
							conn = a.remoteConnectionMap[addrStr]
							if conn != nil {
								log.Debug("ac(%s)[ServerDiscovery] closing stale connection to %s (local: %s)",
									acId, addrStr, conn.ConnData.LocalAddr.String())
								delete(a.remoteConnectionMap, addrStr)
								conn.Close()
							}
							a.remoteConnectionMutex.Unlock()

							// Invalidate DNS cache to pick up potential IP changes (e.g., after server redeployment).
							// This is rate-limited by ServerDiscoveryRetryBeforeFail (every 3 failures).
							server.InvalidateDNSCache()
						}
						log.Error("ac(%s#%d)[ACOnline] reporting to server %s failed", acId, aolMd.TransactionId, addrStr)
					}

				}()

				if ppd.Error != nil {
					log.Error("ac(%s#%d)[ACOnline] failed to receive response from server %s: %v", acId, aolMd.TransactionId, addrStr, ppd.Error)
					err = ppd.Error
					return
				}

				if ppd.HeaderType != core.NHP_AAK {
					log.Error("ac(%s#%d)[ACOnline] response from server %s has wrong type: %s", acId, aolMd.TransactionId, addrStr, core.HeaderTypeToString(ppd.HeaderType))
					err = common.ErrTransactionRepliedWithWrongType
					return
				}

				aakMsg := &common.ServerACAckMsg{}
				err = json.Unmarshal(ppd.BodyMessage, aakMsg)
				if err != nil {
					log.Error("ac(%s#%d)[HandleACAck] failed to parse %s message: %v", acId, ppd.SenderTrxId, core.HeaderTypeToString(ppd.HeaderType), err)
					return
				}

				// server discovery succeeded
				failCount = 0
				atomic.StoreInt32(serverFailCount, 0)
				a.remoteConnectionMutex.Lock()
				conn = a.remoteConnectionMap[addrStr]
				if conn != nil {
					conn.connected.Store(true)
					conn.externalAddr = aakMsg.ACAddr
				}
				a.remoteConnectionMutex.Unlock()
				if conn == nil {
					log.Error("ac(%s#%d)[ACOnline] connection not found in map after successful handshake", acId, aolMd.TransactionId)
					err = errors.New("connection not found after handshake")
					return
				}
				log.Info("ac(%s#%d)[ACOnline] succeed. ac external address is %s, replied by server %s", acId, aolMd.TransactionId, aakMsg.ACAddr, addrStr)
			}()

		} else if connected {
			if (currTime - lastSendTime) > int64(ServerKeepaliveInterval*time.Second) {
				// send NHP_KPL to server if no send happens within ServerKeepaliveInterval
				kplAddr, ok := sendAddr.(*net.UDPAddr)
				if !ok {
					log.Error("ac(%s)[ACOnline] unexpected address type %T for keepalive", acId, sendAddr)
					continue
				}
				md := &core.MsgData{
					RemoteAddr:   kplAddr,
					HeaderType:   core.NHP_KPL,
					CipherScheme: a.config.DefaultCipherScheme,
					//PeerPk:        peerPbk, // pubkey not needed
					TransactionId: a.device.NextCounterIndex(),
				}

				a.sendMsgCh <- md // send NHP_KPL to server via existing connection
				server.UpdateSend(currTime)
			}
		}

		select {
		case <-a.signals.stop:
			return
		case <-quit:
			return
		case <-time.After(MinimalServerDiscoveryInterval * time.Second):
			// wait for ServerConnectionDiscoveryInterval
		}
	}
}

func (a *UdpAC) AddServerPeer(server *core.UdpPeer) {
	if server.DeviceType() == core.NHP_SERVER {
		a.device.AddPeer(server)

		a.serverPeerMutex.Lock()
		a.serverPeerMap[server.PublicKeyBase64()] = server
		a.serverPeerMutex.Unlock()

		// renew server connection cycle
		if len(a.signals.serverMapUpdated) == 0 {
			a.signals.serverMapUpdated <- struct{}{}
		}
	}
}

func (a *UdpAC) RemoveServerPeer(serverKey string) {
	a.serverPeerMutex.Lock()
	beforeSize := len(a.serverPeerMap)
	delete(a.serverPeerMap, serverKey)
	afterSize := len(a.serverPeerMap)
	a.serverPeerMutex.Unlock()

	if beforeSize != afterSize {
		// renew server connection cycle
		if len(a.signals.serverMapUpdated) == 0 {
			a.signals.serverMapUpdated <- struct{}{}
		}
	}
}

func (a *UdpAC) GetConfig() *Config {
	return a.config // return  config
}

// ============================================================================
// AC Redispatch Handler
// See docs/design/PLUGGABLE_STORAGE_BACKEND.md section 6.2 for details.
// ============================================================================

// HandleACRedispatch processes an NHP_ARD message from the server.
// This redirects the AC to its assigned servers.
func (a *UdpAC) HandleACRedispatch(ppd *core.PacketParserData) {
	var ardMsg common.ACRedispatchMsg
	if err := json.Unmarshal(ppd.BodyMessage, &ardMsg); err != nil {
		log.Error("ac(%s)[HandleACRedispatch] failed to parse NHP_ARD message: %v", a.config.ACId, err)
		return
	}

	log.Info("ac(%s)[HandleACRedispatch] received redispatch with %d targets", a.config.ACId, len(ardMsg.Targets))

	if a.registration != nil {
		if err := a.registration.HandleRedispatch(&ardMsg); err != nil {
			log.Error("ac(%s)[HandleACRedispatch] failed to process redispatch: %v", a.config.ACId, err)
		}
	} else {
		log.Warning("ac(%s)[HandleACRedispatch] registration manager not initialized", a.config.ACId)
	}
}
