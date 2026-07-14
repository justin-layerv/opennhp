package db

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
	ztdolib "github.com/OpenNHP/opennhp/nhp/core/ztdo"
	"github.com/OpenNHP/opennhp/nhp/log"
	"github.com/OpenNHP/opennhp/nhp/version"
)

var (
	ExeDirPath string
)

type KnockUser struct {
	UserId         string
	OrganizationId string
	UserData       map[string]any
}

type KnockResource struct {
	AuthServiceId string `json:"aspId"`
	ResourceId    string `json:"resId"`
	ServerAddr    string `json:"serverAddr"`
}

func (res *KnockResource) Id() string {
	return res.AuthServiceId + "/" + res.ResourceId
}

type KnockTarget struct {
	sync.Mutex
	KnockResource
	ServerPeer           *core.UdpPeer
	LastKnockSuccessTime time.Time
}

func (kt *KnockTarget) SetResource(res *KnockResource) {
	kt.Lock()
	defer kt.Unlock()

	kt.KnockResource = *res
}

func (kt *KnockTarget) SetServer(peer *core.UdpPeer) {
	kt.Lock()
	defer kt.Unlock()

	kt.ServerPeer = peer
}

func (kt *KnockTarget) Server() *core.UdpPeer {
	kt.Lock()
	defer kt.Unlock()

	return kt.ServerPeer
}

type UdpDevice struct {
	stats struct {
		totalRecvBytes uint64
		totalSendBytes uint64
	}

	config *Config
	log    *log.Logger

	remoteConnectionMutex sync.Mutex
	remoteConnectionMap   map[string]*UdpConn // indexed by remote UDP address

	serverPeerMutex sync.Mutex
	serverPeerMap   map[string]*core.UdpPeer // indexed by server's public key

	teeMutex sync.Mutex
	teeMap   map[string]*TEE // indexed by tee's public key

	device  *core.Device
	ownEcdh core.Ecdh // cached at startup, derived from config private key
	wg      sync.WaitGroup
	running atomic.Bool

	signals struct {
		stop             chan struct{}
		serverMapUpdated chan struct{}
	}

	recvMsgCh <-chan *core.PacketParserData
	sendMsgCh chan *core.MsgData

	EnableOnlineReport bool
}

type UdpConn struct {
	ConnData     *core.ConnectionData
	netConn      *net.UDPConn
	connected    atomic.Bool
	externalAddr string
}

func (c *UdpConn) Close() {
	_ = c.netConn.Close()
	c.ConnData.Close()
}

/*
dirPath: the path of app or shared library entry point
logLevel: 0: silent, 1: error, 2: info, 3: debug, 4: verbose
*/
func (a *UdpDevice) Start(dirPath string, logLevel int) (err error) {
	common.ExeDirPath = dirPath
	ExeDirPath = dirPath
	// init logger
	a.log = log.NewLogger("NHP-DB", logLevel, filepath.Join(ExeDirPath, "logs"), "device")
	log.SetGlobalLogger(a.log)

	log.Info("=========================================================")
	log.Info("=== NHP-DB %s started                           ===", version.Version)
	log.Info("=== REVISION %s ===", version.CommitId)
	log.Info("=== RELEASE %s                       ===", version.BuildTime)
	log.Info("=========================================================")

	err = a.loadBaseConfig()
	if err != nil {
		return err
	}

	prk, err := base64.StdEncoding.DecodeString(a.config.PrivateKeyBase64)
	if err != nil {
		log.Error("private key parse error %v", err)
		return fmt.Errorf("private key parse error: %w", err)
	}

	a.device = core.NewDevice(core.NHP_DB, prk, nil)
	if a.device == nil {
		log.Critical("failed to create device")
		return errors.New("failed to create device")
	}

	a.ownEcdh = a.device.GetEcdhByCipherScheme(common.CIPHER_SCHEME_CURVE)

	a.remoteConnectionMap = make(map[string]*UdpConn)
	a.serverPeerMap = make(map[string]*core.UdpPeer)

	// load peers
	if err := a.loadPeers(); err != nil {
		log.Error("[DB] failed to load peers: %v", err)
	}

	// load TEEs
	if err := a.loadTEEs(); err != nil {
		log.Error("[DB] failed to load TEEs: %v", err)
	}

	a.signals.stop = make(chan struct{})
	a.signals.serverMapUpdated = make(chan struct{}, 1)
	a.recvMsgCh = a.device.DecryptedMsgQueue
	a.sendMsgCh = make(chan *core.MsgData, core.SendQueueSize)

	// start device routines
	a.device.Start()

	// start device routines
	a.wg.Add(2)

	go a.sendMessageRoutine()
	go a.recvMessageRoutine()
	if a.EnableOnlineReport {
		a.wg.Add(1)
		go a.maintainServerConnectionRoutine()
	}
	a.running.Store(true)
	return nil
}

// export Stop
func (a *UdpDevice) Stop() {
	a.running.Store(false)
	close(a.signals.stop)
	a.device.Stop()
	a.StopConfigWatch()
	a.wg.Wait()
	close(a.sendMsgCh)
	close(a.signals.serverMapUpdated)

	log.Info("=========================")
	log.Info("=== NHP-Device stopped ===")
	log.Info("=========================")
	a.log.Close()
}

func (a *UdpDevice) IsRunning() bool {
	return a.running.Load()
}

func (a *UdpDevice) newConnection(addr *net.UDPAddr) (conn *UdpConn) {
	conn = &UdpConn{}
	var err error
	// unlike tcp, udp dial is fast (just socket bind), so no need to run in a thread
	conn.netConn, err = net.DialUDP("udp", nil, addr)
	if err != nil {
		log.Error("[DB] failed to dial UDP to remote addr %s: %v", addr.String(), err)
		return nil
	}

	// retrieve local port
	laddr := conn.netConn.LocalAddr()
	localAddr, err := net.ResolveUDPAddr(laddr.Network(), laddr.String())
	if err != nil {
		log.Error("[DB] failed to resolve local UDPAddr %s: %v", laddr.String(), err)
		return nil
	}

	log.Info("Dial up new UDP connection from %s to %s", localAddr.String(), addr.String())

	conn.ConnData = &core.ConnectionData{
		Device:               a.device,
		CookieStore:          &core.CookieStore{},
		RemoteTransactionMap: make(map[uint64]*core.RemoteTransaction),
		LocalAddr:            localAddr,
		RemoteAddr:           addr,
		SendQueue:            make(chan *core.Packet, PacketQueueSizePerConnection),
		RecvQueue:            make(chan *core.Packet, PacketQueueSizePerConnection),
		BlockSignal:          make(chan struct{}),
		SetTimeoutSignal:     make(chan struct{}, 1),
		StopSignal:           make(chan struct{}),
	}
	conn.ConnData.InitTimeoutMs(DefaultConnectionTimeoutMs)

	conn.ConnData.Add(1)
	go a.recvPacketRoutine(conn)

	return conn
}

func (a *UdpDevice) sendMessageRoutine() {
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
					log.Error("[DB] failed to create connection to remote address %s", addrStr)
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

func (a *UdpDevice) SendPacket(pkt *core.Packet, conn *UdpConn) (n int, err error) {
	defer func() {
		atomic.AddUint64(&a.stats.totalSendBytes, uint64(n))
		atomic.StoreInt64(&conn.ConnData.LastLocalSendTime, time.Now().UnixNano())

		if !pkt.KeepAfterSend {
			a.device.ReleasePoolPacket(pkt)
		}
	}()

	pktType := core.HeaderTypeToString(pkt.HeaderType)
	localAddrStr := conn.ConnData.LocalAddr.String()
	remoteAddrStr := conn.ConnData.RemoteAddr.String()
	log.Info("Send [%s] packet (%s -> %s), %d bytes", pktType, localAddrStr, remoteAddrStr, len(pkt.Content))
	log.Evaluate("Send [%s] packet (%s -> %s), %d bytes", pktType, localAddrStr, remoteAddrStr, len(pkt.Content))
	return conn.netConn.Write(pkt.Content)
}

func (a *UdpDevice) recvPacketRoutine(conn *UdpConn) {
	addrStr := conn.ConnData.RemoteAddr.String()
	localAddrStr := conn.ConnData.LocalAddr.String()

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
		pkt := a.device.AllocatePoolPacket()
		n, err := conn.netConn.Read(pkt.Buf[:])
		if err != nil {
			a.device.ReleasePoolPacket(pkt)
			if n == 0 {
				// udp connection closed, it is not an error
				return
			}
			log.Error("[DB] failed to receive UDP packet from %s: %v", addrStr, err)
			continue
		}

		// add total recv bytes
		atomic.AddUint64(&a.stats.totalRecvBytes, uint64(n))

		// Snapshot MinimalLength() before ReleasePoolPacket: the release
		// nils pkt.Content, so a post-release call panics via unsafe.Pointer
		// deref. Fenced by TestPacketMinimalLengthPanicsAfterRelease.
		minLen := pkt.MinimalLength()
		if n < minLen {
			a.device.ReleasePoolPacket(pkt)
			log.Error("[DB] received UDP packet from %s is too short (%d bytes, min %d), discarding", addrStr, n, minLen)
			continue
		}

		pkt.Content = pkt.Buf[:n]
		//log.Trace("receive udp packet (%s -> %s): %+v", conn.ConnData.RemoteAddr.String(), conn.ConnData.LocalAddr.String(), pkt.Content)

		typ, _, err := a.device.RecvPrecheck(pkt)
		msgType := core.HeaderTypeToString(typ)
		log.Info("Receive [%s] packet (%s -> %s), %d bytes", msgType, addrStr, localAddrStr, n)
		log.Evaluate("Receive [%s] packet (%s -> %s), %d bytes", msgType, addrStr, localAddrStr, n)
		if err != nil {
			a.device.ReleasePoolPacket(pkt)
			log.Warning("Receive [%s] packet (%s -> %s), precheck error: %v", msgType, addrStr, localAddrStr, err)
			log.Evaluate("Receive [%s] packet (%s -> %s) precheck error: %v", msgType, addrStr, localAddrStr, err)
			continue
		}

		atomic.StoreInt64(&conn.ConnData.LastLocalRecvTime, time.Now().UnixNano())

		conn.ConnData.ForwardInboundPacket(pkt)
	}
}

func (a *UdpDevice) connectionRoutine(conn *UdpConn) {
	addrStr := conn.ConnData.RemoteAddr.String()
	localAddrStr := conn.ConnData.LocalAddr.String()

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

	// See endpoints/ac/udpac.go::connectionRoutine — canonical placement + fences.
	idleTimeout := time.Duration(conn.ConnData.TimeoutMs()) * time.Millisecond
	idleTimer := time.NewTimer(idleTimeout)
	defer idleTimer.Stop()

	for {
		select {
		case <-a.signals.stop:
			return

		case _, ok := <-conn.ConnData.SetTimeoutSignal:
			if !ok {
				return
			}
			newTimeoutMs := conn.ConnData.TimeoutMs()
			if newTimeoutMs <= 0 {
				log.Debug("Connection routine closed immediately")
				return
			}
			idleTimeout = time.Duration(newTimeoutMs) * time.Millisecond
			idleTimer.Reset(idleTimeout)

		case <-idleTimer.C:
			// timeout, quit routine
			log.Debug("Connection routine idle timeout")
			return

		case pkt, ok := <-conn.ConnData.SendQueue:
			if !ok {
				return
			}
			idleTimer.Reset(idleTimeout)
			if pkt == nil {
				continue
			}
			if _, sendErr := a.SendPacket(pkt, conn); sendErr != nil {
				log.Error("[DB] failed to send packet to %s: %v", addrStr, sendErr)
			}

		case pkt, ok := <-conn.ConnData.RecvQueue:
			if !ok {
				return
			}
			idleTimer.Reset(idleTimeout)
			if pkt == nil {
				continue
			}
			log.Debug("Received udp packet len [%d] from addr: %s", len(pkt.Content), addrStr)
			// process keepalive packet
			if pkt.HeaderType == core.NHP_KPL {
				a.device.ReleasePoolPacket(pkt)
				log.Info("Receive [NHP_KPL] message (%s -> %s)", addrStr, localAddrStr)
				continue
			}
			if a.device.IsTransactionResponse(pkt.HeaderType) {
				// forward to a specific transaction
				transactionId := pkt.Counter()
				transaction := a.device.FindLocalTransaction(transactionId)
				if transaction != nil {
					if err := transaction.SendPacket(pkt); err != nil {
						log.Warning("recvPacketRoutine: local transaction %d closed before forward: %v", transactionId, err)
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
			a.device.RecvPacketToMsg(pd)

		case _, ok := <-conn.ConnData.BlockSignal:
			if !ok {
				return
			}
			log.Critical("blocking address %s", addrStr)
			return
		}
	}
}

func (a *UdpDevice) recvMessageRoutine() {
	defer a.wg.Done()
	defer log.Info("recvMessageRoutine stopped")

	log.Info("recvMessageRoutine started")

	for {
		select {
		case <-a.signals.stop:
			return
		case ppd, ok := <-a.recvMsgCh:
			log.Debug("recvMessageRoutine ppd.HeaderType:%d", ppd.HeaderType)
			if !ok {
				return
			}
			if ppd == nil {
				continue
			}

			switch ppd.HeaderType {
			case core.NHP_DWR:
				// deal with NHP_AOP message
				a.wg.Add(1)
				go func() {
					if opErr := a.HandleUdpDataKeyWrappingOperations(ppd); opErr != nil {
						log.Error("[DB] HandleUdpDataKeyWrappingOperations failed: %v", opErr)
					}
				}()
			}
		}
	}
}

func (a *UdpDevice) maintainServerConnectionRoutine() {
	defer a.wg.Done()
	defer log.Info("maintainServerConnectionRoutine stopped")

	log.Info("maintainServerConnectionRoutine started")

	var discoveryRoutineWg sync.WaitGroup
	defer discoveryRoutineWg.Wait()

	for {
		// make a local copy of servers then iterate because next operations are time consuming (too long to use locked iteration)
		a.serverPeerMutex.Lock()
		var serverCount int32 = int32(len(a.serverPeerMap))
		discoveryQuitArr := make([]chan struct{}, 0, serverCount)

		for _, server := range a.serverPeerMap {
			// launch discovery routine for each server
			fail := new(int32)
			quit := make(chan struct{})
			discoveryQuitArr = append(discoveryQuitArr, quit)

			discoveryRoutineWg.Add(1)
			go a.serverDiscovery(server, &discoveryRoutineWg, fail, quit)
		}
		a.serverPeerMutex.Unlock()

		select {
		case <-a.signals.stop:
			log.Info("maintainServerConnectionRoutine receives stop signal")
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

func (a *UdpDevice) serverDiscovery(server *core.UdpPeer, discoveryRoutineWg *sync.WaitGroup, serverFailCount *int32, quit <-chan struct{}) {
	defer discoveryRoutineWg.Done()

	dbId := a.config.DbId
	var lastAddrStr string // Track previous resolved address to detect DNS changes

	defer func() {
		if lastAddrStr != "" {
			log.Info("server discovery sub-routine at %s stopped", lastAddrStr)
		}
	}()
	log.Info("server discovery sub-routine started for %s", server.Hostname)

	var failCount int

	discoveryTimer := core.NewStoppedTimer()
	defer discoveryTimer.Stop()

	for {
		// Re-resolve server address each iteration to pick up DNS changes (e.g., after server redeployment)
		sendAddr := server.SendAddr()
		if sendAddr == nil {
			log.Error("[DB] cannot resolve server address for %s, will retry", server.Hostname)
			discoveryTimer.Reset(MinimalServerDiscoveryInterval * time.Second)
			select {
			case <-a.signals.stop:
				return
			case <-quit:
				return
			case <-discoveryTimer.C:
				continue
			}
		}
		addrStr := sendAddr.String()

		// If address changed, close old connection and reset fail count
		if lastAddrStr != "" && lastAddrStr != addrStr {
			log.Info("db(%s)[ServerDiscovery] Server DNS changed: %s -> %s (hostname: %s). Resetting connection state.",
				dbId, lastAddrStr, addrStr, server.Hostname)
			var oldConn *UdpConn
			a.remoteConnectionMutex.Lock()
			if conn, found := a.remoteConnectionMap[lastAddrStr]; found {
				oldConn = conn
				delete(a.remoteConnectionMap, lastAddrStr)
				log.Debug("db(%s)[ServerDiscovery] Removed old connection entry for %s", dbId, lastAddrStr)
			}
			a.remoteConnectionMutex.Unlock()
			// Close outside lock to avoid blocking other operations, but synchronously to ensure cleanup completes
			if oldConn != nil {
				oldConn.Close()
				log.Info("db(%s)[ServerDiscovery] Closed old connection to %s, will establish new connection to %s",
					dbId, lastAddrStr, addrStr)
			}
			failCount = 0
			atomic.StoreInt32(serverFailCount, 0)
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

		// when a server is not connected, try to connect in every ACLocalTransactionResponseTimeoutMs
		// when a server is connected when ServerConnectionInterval is reached since last receive, try resend NHP_AOL for maintaining server connection
		if !connected || (currTime-lastRecvTime) > int64(ReportToServerInterval*time.Second) {
			// send NHP_AOL message to server
			aolMsg := &common.DBOnlineMsg{
				DBId: dbId,
			}
			aolBytes, marshalErr := json.Marshal(aolMsg)
			if marshalErr != nil {
				log.Error("db(%s)[DBOnline] failed to marshal DOL message: %v", dbId, marshalErr)
				return
			}

			udpAddr, ok := sendAddr.(*net.UDPAddr)
			if !ok {
				log.Error("db(%s)[DBOnline] unexpected address type %T", dbId, sendAddr)
				return
			}
			aolMd := &core.MsgData{
				RemoteAddr:    udpAddr,
				HeaderType:    core.NHP_DOL,
				CipherScheme:  a.config.DefaultCipherScheme,
				TransactionId: a.device.NextCounterIndex(),
				Compress:      true,
				PeerPk:        peerPbk,
				Message:       aolBytes,
				ResponseMsgCh: make(chan *core.PacketParserData),
			}

			if !a.IsRunning() {
				log.Error("db(%s#%d)[DBOnline] MsgData channel closed or being closed, skip sending", dbId, aolMd.TransactionId)
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

						if failCount%ServerDiscoveryRetryBeforeFail == 0 {
							atomic.StoreInt32(serverFailCount, 1)
							log.Warning("db(%s)[ServerDiscovery] %d consecutive failures to %s, invalidating DNS cache",
								dbId, ServerDiscoveryRetryBeforeFail, addrStr)

							// Remove failed connection
							a.remoteConnectionMutex.Lock()
							conn = a.remoteConnectionMap[addrStr]
							if conn != nil {
								log.Debug("db(%s)[ServerDiscovery] closing stale connection to %s (local: %s)",
									dbId, addrStr, conn.ConnData.LocalAddr.String())
								delete(a.remoteConnectionMap, addrStr)
								conn.Close()
							}
							a.remoteConnectionMutex.Unlock()

							// Invalidate DNS cache to pick up potential IP changes (e.g., after server redeployment).
							// This is rate-limited by ServerDiscoveryRetryBeforeFail (every N consecutive failures).
							server.InvalidateDNSCache()
						}
					}
				}()

				if ppd.Error != nil {
					log.Error("db(%s#%d)[DBOnline] failed to receive response from server %s: %v", dbId, aolMd.TransactionId, addrStr, ppd.Error)
					err = ppd.Error
					return
				}

				if ppd.HeaderType != core.NHP_DBA {
					log.Error("db(%s#%d)[DBOnline] response from server %s has wrong type: %s", dbId, aolMd.TransactionId, addrStr, core.HeaderTypeToString(ppd.HeaderType))
					err = common.ErrTransactionRepliedWithWrongType
					return
				}

				aakMsg := &common.ServerDBAckMsg{}
				err = json.Unmarshal(ppd.BodyMessage, aakMsg)
				if err != nil {
					log.Error("db(%s#%d)[HandleDBAck] failed to parse %s message: %v", dbId, ppd.SenderTrxId, core.HeaderTypeToString(ppd.HeaderType), err)
					return
				}

				// server discovery succeeded
				failCount = 0
				atomic.StoreInt32(serverFailCount, 0)
				a.remoteConnectionMutex.Lock()
				conn = a.remoteConnectionMap[addrStr]
				if conn == nil {
					a.remoteConnectionMutex.Unlock()
					log.Error("db(%s#%d)[DBOnline] connection not found in map after successful handshake", dbId, aolMd.TransactionId)
					err = errors.New("connection not found after handshake")
					return
				}
				conn.connected.Store(true)
				conn.externalAddr = aakMsg.DBAddr
				a.remoteConnectionMutex.Unlock()
				log.Info("db(%s#%d)[DBOnline] succeed. db external address is %s, replied by server %s", dbId, aolMd.TransactionId, aakMsg.DBAddr, addrStr)
			}()

		} else if connected {
			if (currTime - lastSendTime) > int64(ServerKeepaliveInterval*time.Second) {
				// send NHP_KPL to server if no send happens within ServerKeepaliveInterval
				kplAddr, ok := sendAddr.(*net.UDPAddr)
				if !ok {
					log.Error("db(%s)[DBOnline] unexpected address type %T for keepalive", dbId, sendAddr)
					continue
				}
				md := &core.MsgData{
					RemoteAddr:    kplAddr,
					HeaderType:    core.NHP_KPL,
					CipherScheme:  a.config.DefaultCipherScheme,
					TransactionId: a.device.NextCounterIndex(),
				}

				a.sendMsgCh <- md // send NHP_KPL to server via existing connection
				server.UpdateSend(currTime)
			}
		}

		discoveryTimer.Reset(MinimalServerDiscoveryInterval * time.Second)
		select {
		case <-a.signals.stop:
			log.Info("server discovery sub-routine at %s receives stop signal", addrStr)
			return
		case <-quit:
			return
		case <-discoveryTimer.C:
			// wait for ServerConnectionDiscoveryInterval
		}
	}
}

func (a *UdpDevice) AddServer(server *core.UdpPeer) {
	if server.DeviceType() == core.NHP_SERVER {
		a.device.AddPeer(server)
		a.serverPeerMutex.Lock()
		a.serverPeerMap[server.PublicKeyBase64()] = server
		a.serverPeerMutex.Unlock()
	}
}

func (a *UdpDevice) RemoveServer(serverKey string) {
	a.serverPeerMutex.Lock()
	delete(a.serverPeerMap, serverKey)
	a.serverPeerMutex.Unlock()
}

// get first server
func (a *UdpDevice) GetServerPeer() (serverPeer *core.UdpPeer) {
	for _, value := range a.serverPeerMap {
		serverPeer = value
		return serverPeer
	}
	return nil
}
func (a *UdpDevice) SendDHPRegister(msg common.DRGMsg) {
	log.Debug("DHP started")
	serverPeer := a.GetServerPeer()

	log.Debug("serverPeer:%v", serverPeer)
	result := a.SendNHPDRG(serverPeer, msg)
	if result {
		log.Info("successfully registered or updated data object: doId=%s", msg.DoId)
	} else {
		log.Error("failed to register or update data object: doId=%s", msg.DoId)
	}
}

// send NHP_DRG to NHP-Server
func (a *UdpDevice) SendNHPDRG(server *core.UdpPeer, msg common.DRGMsg) bool {
	sendAddr := server.SendAddr()
	if sendAddr == nil {
		log.Critical("device(%v)[SendNHPDRG] register server IP cannot be parsed", a)
		return false
	}
	udpAddr, ok := sendAddr.(*net.UDPAddr)
	if !ok {
		log.Critical("device(%v)[SendNHPDRG] unexpected address type %T", a, sendAddr)
		return false
	}
	drgBytes, marshalErr := json.Marshal(msg)
	if marshalErr != nil {
		log.Error("device[SendNHPDRG] failed to marshal DRG message: %v", marshalErr)
		return false
	}
	drgMd := &core.MsgData{
		RemoteAddr:    udpAddr,
		HeaderType:    core.NHP_DRG,
		CipherScheme:  a.config.DefaultCipherScheme,
		TransactionId: a.device.NextCounterIndex(),
		Compress:      true,
		Message:       drgBytes,
		PeerPk:        server.PublicKey(),
		ResponseMsgCh: make(chan *core.PacketParserData),
	}
	currTime := time.Now().UnixNano()
	if !a.IsRunning() {
		log.Error("[DB] send channel closed or closing, skipping NHP_DRG for doId=%s", msg.DoId)
		return false
	}
	// device will create or find existing connection and sends the MsgAssembler via that connection
	a.sendMsgCh <- drgMd
	server.UpdateSend(currTime)
	// block until transaction completes
	serverPpd := <-drgMd.ResponseMsgCh
	close(drgMd.ResponseMsgCh)

	if serverPpd.Error != nil {
		log.Error("DB(%s#%d)[SendNHPDRG] failed to receive response from server %s: %v", msg.DoId, drgMd.TransactionId, server.Ip, serverPpd.Error)
		return false
	}

	if serverPpd.HeaderType != core.NHP_DAK {
		log.Error("DB(%s#%d)[SendNHPDRG] response from server %s has wrong type: %s", msg.DoId, drgMd.TransactionId, server.Ip, core.HeaderTypeToString(serverPpd.HeaderType))
		return false
	}

	dakMsg := &common.DAKMsg{}
	if err := json.Unmarshal(serverPpd.BodyMessage, dakMsg); err != nil {
		log.Error("DB(%s#%d)[SendNHPDRG] failed to parse %s message: %v", msg.DoId, serverPpd.SenderTrxId, core.HeaderTypeToString(serverPpd.HeaderType), err)
		return false
	}

	if dakMsg.ErrCode != 0 {
		log.Error("[DB] SendNHPDRG failed for doId=%s: errCode=%d, errMsg=%s", msg.DoId, dakMsg.ErrCode, dakMsg.ErrMsg)
		return false
	}

	log.Info("SendNHPDRG sent successfully: doId=%s", msg.DoId)
	return true
}

func (a *UdpDevice) GetCipherSchema() int {
	return a.config.DefaultCipherScheme
}

func (a *UdpDevice) GetSymmetricCipherMode() string {
	return a.config.SymmetricCipherMode
}

func (a *UdpDevice) GetDataBrokerId() string {
	return a.config.DbId
}

func (a *UdpDevice) GetOwnEcdh() core.Ecdh {
	return a.ownEcdh
}

func (a *UdpDevice) isTEEAuthorized(teePbkBase64 string) bool {
	a.teeMutex.Lock()
	defer a.teeMutex.Unlock()
	if tee, found := a.teeMap[teePbkBase64]; found {
		return tee.ExpireTime > 0 && time.Now().UnixMilli() < tee.ExpireTime*1000
	}

	return false
}

func (a *UdpDevice) HandleUdpDataKeyWrappingOperations(ppd *core.PacketParserData) (err error) {
	defer a.wg.Done()

	dbId := a.config.DbId

	dwrMsg := &common.DWRMsg{}
	dwaMsg := &common.DWAMsg{}

	transactionId := ppd.SenderTrxId
	err = json.Unmarshal(ppd.BodyMessage, dwrMsg)
	if err == nil {
		if !a.isTEEAuthorized(dwrMsg.TeePublicKey) {
			errCode, _ := strconv.Atoi(common.ErrTEENotAuthorized.ErrorCode())
			dwaMsg.ErrCode = errCode
			dwaMsg.ErrMsg = common.ErrTEENotAuthorized.Error()
		} else {
			dataPrkStore, err := NewDataPrivateKeyStoreWith(dwrMsg.DoId)
			if err != nil {
				errCode, _ := strconv.Atoi(common.ErrDataPrivateKeyStore.ErrorCode())
				dwaMsg.ErrCode = errCode
				dwaMsg.ErrMsg = common.ErrDataPrivateKeyStore.Error()
			} else {
				dataKeyPairEccMode := ztdolib.CURVE25519

				teePbk, err := base64.StdEncoding.DecodeString(dwrMsg.TeePublicKey)
				if err != nil {
					log.Error("failed to decode TEE public key base64: %v", err)
					errCode, _ := strconv.Atoi(common.ErrDataPrivateKeyStore.ErrorCode())
					dwaMsg.ErrCode = errCode
					dwaMsg.ErrMsg = fmt.Sprintf("failed to decode TEE public key: %v", err)
				} else if consumerEPbk, err := base64.StdEncoding.DecodeString(dwrMsg.ConsumerEphemeralPublicKey); err != nil {
					log.Error("failed to decode consumer ephemeral public key base64: %v", err)
					errCode, _ := strconv.Atoi(common.ErrDataPrivateKeyStore.ErrorCode())
					dwaMsg.ErrCode = errCode
					dwaMsg.ErrMsg = fmt.Sprintf("failed to decode consumer ephemeral public key: %v", err)
				} else {
					sa := ztdolib.NewSymmetricAgreement(dataKeyPairEccMode, true)
					sa.SetMessagePatterns(ztdolib.DataPrivateKeyWrappingPatterns)
					sa.SetPsk([]byte(ztdolib.InitialDHPKeyWrappingString))
					sa.SetStaticKeyPair(a.GetOwnEcdh())
					sa.SetRemoteStaticPublicKey(teePbk)
					sa.SetRemoteEphemeralPublicKey(consumerEPbk)

					gcmKey, ad := sa.AgreeSymmetricKey()

					dataPrkWrapping := ztdolib.NewDataPrivateKeyWrapping(dataPrkStore.ProviderPublicKeyBase64, dataPrkStore.DataPrivateKeyBase64, gcmKey[:], ad)

					dataPrkWrappingJson, marshalErr := json.Marshal(dataPrkWrapping)
					if marshalErr != nil {
						log.Error("db(%s#%d)[HandleUdpDataKeyWrappingOperations] failed to marshal data private key wrapping: %v", dbId, transactionId, marshalErr)
						errCode, _ := strconv.Atoi(common.ErrDataPrivateKeyStore.ErrorCode())
						dwaMsg.ErrCode = errCode
						dwaMsg.ErrMsg = fmt.Sprintf("failed to marshal data private key wrapping: %v", marshalErr)
					} else {
						kao := common.KeyAccessObject{
							WrappedDataKey: string(dataPrkWrappingJson),
						}
						dwaMsg.Kao = &kao
						dwaMsg.DoId = dwrMsg.DoId
					}
				}
			}
		}
	} else {
		log.Error("db(%s#%d)[HandleUdpDataKeyWrappingOperations] failed to parse %s message: %v", dbId, transactionId, core.HeaderTypeToString(ppd.HeaderType), err)
		errCode, _ := strconv.Atoi(common.ErrJsonParseFailed.ErrorCode())
		dwaMsg.ErrCode = errCode
		dwaMsg.ErrMsg = err.Error()
	}

	dwaBytes, marshalErr := json.Marshal(dwaMsg)
	if marshalErr != nil {
		log.Error("db(%s#%d)[HandleUdpDataKeyWrappingOperations] failed to marshal DWA message: %v", dbId, transactionId, marshalErr)
		return marshalErr
	}
	md := &core.MsgData{
		HeaderType:     core.NHP_DWA,
		TransactionId:  transactionId,
		Compress:       true,
		PrevParserData: ppd,
		Message:        dwaBytes,
	}

	// forward to a specific transaction
	transaction := ppd.ConnData.FindRemoteTransaction(transactionId)
	if transaction == nil {
		log.Error("db(%s#%d)[HandleUdpDataKeyWrappingOperations] transaction is not available", dbId, transactionId)
		return common.ErrTransactionIdNotFound
	}

	if sendErr := transaction.SendMessage(md); sendErr != nil {
		log.Error("db(%s#%d)[HandleUdpDataKeyWrappingOperations] transaction closed before forward: %v", dbId, transactionId, sendErr)
		return sendErr
	}

	return nil
}
