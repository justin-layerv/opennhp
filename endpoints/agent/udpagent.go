package agent

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
	wasmEngine "github.com/OpenNHP/opennhp/nhp/core/wasm/engine"
	ztdolib "github.com/OpenNHP/opennhp/nhp/core/ztdo"
	"github.com/OpenNHP/opennhp/nhp/log"
	utils "github.com/OpenNHP/opennhp/nhp/utils"
	"github.com/OpenNHP/opennhp/nhp/version"
)

// ErrRegisteredAgentKnockLoopUnsupported is returned when a caller tries to
// place the registered-agent auth service in the periodic background resource
// loop. Registered-agent callers own an explicit RunID lifecycle and must use
// the one-shot knock and exit APIs.
var ErrRegisteredAgentKnockLoopUnsupported = errors.New("registered-agent background knock loop is unsupported; use the one-shot RunID APIs")

var (
	ExeDirPath                 string
	SmartDataPolicyRefreshTime = 15 * int64(time.Second)
)

type KnockUser struct {
	UserId         string
	OrganizationId string
	UserData       map[string]any
}

type knockUserState struct {
	user         KnockUser
	deviceID     string
	checkResults map[string]any
}

type KnockResource struct {
	AuthServiceId  string `json:"aspId"`
	ResourceId     string `json:"resId"`
	RunID          string `json:"runId,omitempty"`
	RunAttempt     uint64 `json:"runAttempt,omitempty"`
	ServerHostname string `json:"serverHostname"`
	ServerIp       string `json:"serverIp"`
	ServerPort     int    `json:"serverPort"`
}

func (res *KnockResource) Id() string {
	return res.AuthServiceId + "/" + res.ResourceId
}

func (res *KnockResource) ServerHost() string {
	hostAddr := res.ServerIp
	if len(res.ServerHostname) > 0 {
		hostAddr = res.ServerHostname
	}
	if res.ServerPort == 0 {
		return hostAddr
	}
	return fmt.Sprintf("%s:%d", hostAddr, res.ServerPort)
}

type KnockTarget struct {
	sync.Mutex
	KnockResource
	ServerPeer           *core.UdpPeer
	LastKnockSuccessTime time.Time
	sessionReceipt       *agentSessionReceipt
}

// agentSessionReceipt couples the public immutable receipt with the exact
// server peer that issued it. Later assignment changes must not redirect an
// exact retirement to a different cell/key.
type agentSessionReceipt struct {
	common.AgentSessionReceipt
	serverPeer *core.UdpPeer
}

func (kt *KnockTarget) SetResource(res *KnockResource) {
	kt.Lock()
	defer kt.Unlock()

	kt.KnockResource = *res
}

func (kt *KnockTarget) SetServerPeer(peer *core.UdpPeer) {
	kt.Lock()
	defer kt.Unlock()

	kt.ServerPeer = peer
}

func (kt *KnockTarget) GetServerPeer() *core.UdpPeer {
	kt.Lock()
	defer kt.Unlock()

	return kt.ServerPeer
}

func (kt *KnockTarget) setSessionReceipt(receipt common.AgentSessionReceipt, peer *core.UdpPeer) {
	kt.Lock()
	defer kt.Unlock()
	kt.sessionReceipt = &agentSessionReceipt{AgentSessionReceipt: receipt, serverPeer: peer}
}

func (kt *KnockTarget) getSessionReceipt() (*agentSessionReceipt, bool) {
	kt.Lock()
	defer kt.Unlock()
	if kt.sessionReceipt == nil {
		return nil, false
	}
	copy := *kt.sessionReceipt
	return &copy, true
}

// snapshot returns one immutable view of the per-knock resource and server.
// In particular, a cookie retry must reuse the exact caller-owned RunID from
// its initial KNK rather than observing a concurrent resource reload.
func (kt *KnockTarget) snapshot() *KnockTarget {
	kt.Lock()
	defer kt.Unlock()

	var receipt *agentSessionReceipt
	if kt.sessionReceipt != nil {
		copied := *kt.sessionReceipt
		receipt = &copied
	}
	return &KnockTarget{
		KnockResource:  kt.KnockResource,
		ServerPeer:     kt.ServerPeer,
		sessionReceipt: receipt,
	}
}

// NewSessionRetirementTarget constructs a target that can send only the
// receipt-based exact-session EXT. It is used by the exported SDK after the
// caller returns the receipt from the original successful knock ACK.
func NewSessionRetirementTarget(receipt common.AgentSessionReceipt, peer *core.UdpPeer) (*KnockTarget, error) {
	if err := common.ValidateAgentSessionReceipt(receipt); err != nil || peer == nil {
		return nil, common.ErrInvalidInput
	}
	target := &KnockTarget{KnockResource: KnockResource{
		AuthServiceId: common.RegisteredAgentAuthServiceID,
		RunID:         receipt.RunID,
		RunAttempt:    receipt.RunAttempt,
	}, ServerPeer: peer}
	target.setSessionReceipt(receipt, peer)
	return target, nil
}

type UdpAgent struct {
	stats struct {
		totalRecvBytes uint64
		totalSendBytes uint64
	}

	config *Config
	log    *log.Logger

	remoteConnectionMutex sync.Mutex
	remoteConnectionMap   map[string]*UdpConn // indexed by remote UDP address

	knockTargetMapMutex sync.Mutex
	knockTargetMap      map[string]*KnockTarget // indexed by aspId + resId

	serverPeerMutex sync.Mutex
	serverPeerMap   map[string]*core.UdpPeer // indexed by server's public key

	device  *core.Device
	wg      sync.WaitGroup
	running atomic.Bool

	// lifecycleMu serializes Start()/Stop() — which reassign signals.stop /
	// sendMsgCh / knockTargetStopOnce and flip running — against each other and
	// against SDK entry points that snapshot those fields or call a.wg.Add.
	// Start/Stop hold it for writing; SDK ops hold the RLock only long enough to
	// snapshot the channels or register on a.wg, never across a blocking
	// send/receive (that would deadlock a concurrent Stop). Closes the
	// RestartAgent field-reassignment data race and the "WaitGroup is reused
	// before previous Wait has returned" panic (#3103).
	lifecycleMu sync.RWMutex

	signals struct {
		stop                  chan struct{}
		knockTargetStop       chan struct{}
		knockTargetMapUpdated chan struct{}
	}
	// knockTargetStopOnce guards close(knockTargetStop). Both
	// StopKnockLoop() (an exported SDK entry point via sdk.KnockloopStop)
	// and Stop() close this channel; the documented RestartAgent flow
	// calls the former before the latter, so an unguarded close
	// double-closes and panics. Re-armed in Start() (see Start) because a
	// sync.Once is spent after its first Do and RestartAgent reuses the
	// same *UdpAgent.
	knockTargetStopOnce sync.Once

	recvMsgCh <-chan *core.PacketParserData
	sendMsgCh chan *core.MsgData

	// one agent should serve only one specific user at a time
	knockUserMutex sync.RWMutex
	knockUser      *KnockUser
	deviceId       string
	checkResults   map[string]any

	// dhp
	smartPolicyEngine          map[string]*wasmEngine.Engine // index by smart data policy identifier
	decryptedZtdoRecord        map[string]string             // index by data object id
	smartPolicyIdentifier      map[string]string             // index by data object id
	smartDataPolicyRefreshTime map[string]int64              // indexed by data object id, use to record the refresh time of smart data policy, the unit of time is UnixNano
	dataAccessRefreshMutex     sync.Mutex

	safeTee            atomic.Bool
	trustedByNHPServer atomic.Bool
	trustedByNHPDB     atomic.Bool
}

type UdpConn struct {
	ConnData *core.ConnectionData
	netConn  *net.UDPConn
}

func (c *UdpConn) Close() {
	_ = c.netConn.Close()
	c.ConnData.Close()
}

/*
dirPath: the path of app or shared library entry point
logLevel: 0: silent, 1: error, 2: info, 3: debug, 4: verbose
*/
func (a *UdpAgent) Start(dirPath string, logLevel int) (err error) {
	common.ExeDirPath = dirPath
	ExeDirPath = dirPath
	// init logger
	a.log = log.NewLogger("NHP-Agent", logLevel, filepath.Join(ExeDirPath, "logs"), "agent")
	log.SetGlobalLogger(a.log)

	log.Info("=========================================================")
	log.Info("=== NHP-Agent %s started                           ===", version.Version)
	log.Info("=== REVISION %s ===", version.CommitId)
	log.Info("=== RELEASE %s                       ===", version.BuildTime)
	log.Info("=========================================================")
	err = a.loadBaseConfig()
	if err != nil {
		return err
	}
	err = a.loadDHPConfig()
	if err != nil {
		return err
	}

	prk, err := base64.StdEncoding.DecodeString(a.config.PrivateKeyBase64)
	if err != nil {
		log.Error("private key parse error %v", err)
		return fmt.Errorf("private key parse error: %w", err)
	}

	a.device = core.NewDevice(core.NHP_AGENT, prk, nil)
	if a.device == nil {
		log.Critical("failed to create device")
		return errors.New("failed to create device")
	}

	// start device routines
	a.device.Start()

	// load peers
	if err := a.loadPeers(); err != nil {
		log.Error("[Agent] failed to load peers: %v", err)
	}

	a.remoteConnectionMap = make(map[string]*UdpConn)
	// knockTargetMap and serverPeerMap MUST be initialized here,
	// alongside the other per-Start maps. The struct literal
	// (`&UdpAgent{}` in callers like cmd/frpc/run.go in
	// tunnel-client) leaves them nil, and the corresponding
	// AddResource / AddServer writes
	// (`a.knockTargetMap[res.Id()] = ...`,
	// `a.serverPeerMap[server.PublicKeyBase64()] = ...`) panic with
	// "assignment to entry in nil map" the first time a caller
	// registers a target/peer programmatically.
	//
	// updateResources / updateServerPeers (config.go) each do an
	// `os.ReadFile` early-return on a missing `etc/resource.toml`
	// or `etc/server.toml` and only assign the parsed map on
	// success, so callers (tunnel-client, et al.) that don't ship
	// those files and register everything via AddResource /
	// AddServer hit the panic before any later assignment runs.
	// updateResources also has a defensive
	// `if a.knockTargetMap == nil { a.knockTargetMap = targetMap }`
	// fallback, but it lives behind the same early-return so it
	// doesn't cover the missing-file path either.
	// #3103: reassign these maps under their own mutexes (the same ones
	// AddResource/AddServer/RemoveResource and the config.go reload path take), so
	// an unsynchronized SDK AddServer/AddResource racing a RestartAgent Start()
	// can't data-race the map-header write. lifecycleMu (below) covers only the
	// lifecycle channels; these two fields have their own locks.
	a.knockTargetMapMutex.Lock()
	a.knockTargetMap = make(map[string]*KnockTarget)
	a.knockTargetMapMutex.Unlock()
	a.serverPeerMutex.Lock()
	a.serverPeerMap = make(map[string]*core.UdpPeer)
	a.serverPeerMutex.Unlock()

	// #3103: reassign the lifecycle channels (+ the guarding Once) and flip
	// running under lifecycleMu, so a concurrent SDK op that RLocks never reads a
	// half-reassigned field set and its wg.Add can't race this transition.
	a.lifecycleMu.Lock()
	a.signals.stop = make(chan struct{})
	a.signals.knockTargetStop = make(chan struct{})
	// Re-arm the once alongside the channel it guards. RestartAgent reuses
	// the same *UdpAgent (Stop() -> Start()), and a sync.Once is spent
	// after its first Do. Without this reset, every post-restart
	// stopKnockLoop() (from both StopKnockLoop() and Stop()) would no-op,
	// leaving the new knockTargetStop never closed — so knockResourceRoutine
	// (which only selects on knockTargetStop / knockTargetMapUpdated, never
	// signals.stop) never stops and Stop()'s wg.Wait() deadlocks. Assigning
	// a fresh zero Once is the idiomatic re-arm (go vet does not flag it —
	// it isn't a copy of an in-use lock).
	a.knockTargetStopOnce = sync.Once{}
	a.signals.knockTargetMapUpdated = make(chan struct{}, 1)

	// load knock resources
	if err := a.loadResources(); err != nil {
		log.Error("[Agent] failed to load resources: %v", err)
		a.StopConfigWatch()
		a.lifecycleMu.Unlock()
		a.device.Stop()
		a.log.Close()
		return err
	}

	a.recvMsgCh = a.device.DecryptedMsgQueue
	a.sendMsgCh = make(chan *core.MsgData, core.SendQueueSize)

	// initialize dhp related stuff
	a.smartPolicyEngine = make(map[string]*wasmEngine.Engine)
	a.decryptedZtdoRecord = make(map[string]string)
	a.smartDataPolicyRefreshTime = make(map[string]int64)
	a.smartPolicyIdentifier = make(map[string]string)
	a.trustedByNHPServer.Store(false)
	a.trustedByNHPDB.Store(false)

	// start agent routines
	a.wg.Add(2)
	go a.sendMessageRoutine()
	go a.recvMessageRoutine()

	a.running.Store(true)
	a.lifecycleMu.Unlock()

	a.safeTee.Store(false)

	time.Sleep(1000 * time.Millisecond)

	return nil
}

func (a *UdpAgent) RestartAgent() error {
	a.Stop()
	a.config = nil // re-load config
	err := a.Start(common.ExeDirPath, 4)
	if err != nil {
		return err
	}

	a.StartDHPKnockLoop()
	return nil
}

// StartKnockLoop launches the preset-resource knock loop and returns the number
// of knock targets, or -1 if the agent isn't running (e.g. racing a Stop() /
// RestartAgent) so the loop was not started — the same "-1 = can't start"
// sentinel sdk.KnockloopStart already uses for an uninitialized agent. Callers
// treating the result as an unsigned count (incl. the cgo/iOS exports) must
// handle -1.
//
// It must follow a Start() (or RestartAgent()), not a bare
// StopKnockLoop(): knockTargetStop and its guarding knockTargetStopOnce are
// re-armed only in Start(), so a StartKnockLoop() after a StopKnockLoop() with no
// intervening Start() would spawn a knockResourceRoutine that immediately sees
// the already-closed knockTargetStop and exits. StopKnockLoop/StartKnockLoop are
// therefore not a standalone reusable pair.
func (a *UdpAgent) StartKnockLoop() int {
	a.knockTargetMapMutex.Lock()
	size := len(a.knockTargetMap)
	a.knockTargetMapMutex.Unlock()
	// start knock preset resources (guarded wg.Add + launch — see
	// launchTrackedRoutine; #3103)
	if !a.launchTrackedRoutine(a.knockResourceRoutine) {
		return -1 // agent not running (e.g. racing a Stop) — loop not started
	}

	return size
}

func (a *UdpAgent) StartDHPKnockLoop() {
	a.launchTrackedRoutine(a.dhpKnockResourceRoutine)
}

// stopKnockLoop closes knockTargetStop exactly once, so callers may
// invoke it from StopKnockLoop() and Stop() in any order (e.g. the
// RestartAgent flow stops the knock loop before tearing the agent down)
// without risking a double-close panic.
func (a *UdpAgent) stopKnockLoop() {
	a.knockTargetStopOnce.Do(func() {
		close(a.signals.knockTargetStop)
	})
}

func (a *UdpAgent) StopKnockLoop() {
	a.stopKnockLoop()
}

func (a *UdpAgent) SetKnockUser(usrId string, orgId string, userData map[string]any) {
	a.knockUserMutex.Lock()
	if a.knockUser == nil {
		a.knockUser = &KnockUser{}
	}
	a.knockUser.UserId = usrId
	a.knockUser.OrganizationId = orgId
	a.knockUser.UserData = userData
	a.knockUserMutex.Unlock()
}

// snapshotKnockUserState returns one lock-consistent view of the user fields
// and the device/check metadata protected by the same mutex. A zero-value user
// represents the valid "not specified" state of a programmatically constructed
// agent; callers must apply their own operation-specific empty-user policy.
func (a *UdpAgent) snapshotKnockUserState() knockUserState {
	a.knockUserMutex.RLock()
	defer a.knockUserMutex.RUnlock()

	state := knockUserState{
		deviceID:     a.deviceId,
		checkResults: a.checkResults,
	}
	if a.knockUser != nil {
		state.user = *a.knockUser
	}
	return state
}

func (a *UdpAgent) SetDeviceId(devId string) {
	a.knockUserMutex.Lock()
	defer a.knockUserMutex.Unlock()
	a.deviceId = devId
}

func (a *UdpAgent) SetCheckResults(results map[string]any) {
	a.knockUserMutex.Lock()
	defer a.knockUserMutex.Unlock()
	a.checkResults = results
}

// export Stop
func (a *UdpAgent) Stop() {
	// Teardown model + the invariants the inline comments below rest on:
	// docs/design/AGENT_LIFECYCLE_TEARDOWN.md
	//
	// Idempotent, concurrency-safe teardown: only the caller that flips running
	// true->false proceeds. A second or concurrent Stop() — e.g. two web-console
	// RestartAgent requests, or an SDK Close racing RestartAgent — returns early
	// instead of double-closing signals.stop / re-stopping the device (the same
	// double-close panic class this PR guards for knockTargetStop via
	// knockTargetStopOnce). Also makes a pre-Start Stop() a safe no-op, since the
	// signals channels are still nil.
	//
	// lifecycleMu (held for the CAS + stopKnockLoop + close, released before the
	// wg.Wait below) serializes this against Start()'s reassignment and against
	// SDK ops' guarded a.wg.Add: it closes the Stop()-racing-an-in-progress-Start()
	// window (Stop() now blocks on Start()'s Lock and stops the fully-started
	// agent instead of CAS-failing mid-launch) and the "WaitGroup reused before
	// Wait" panic (a beginTrackedOp Add can't interleave past this CAS). #3103.
	a.lifecycleMu.Lock()
	if !a.running.CompareAndSwap(true, false) {
		a.lifecycleMu.Unlock()
		return
	}
	a.stopKnockLoop()
	close(a.signals.stop)
	a.lifecycleMu.Unlock()
	a.StopConfigWatch()
	// Wait for the agent's own routines to exit BEFORE stopping the device:
	// device.Stop() closes msgToPacketQueue, which sendMessageRoutine feeds, so
	// tearing the device down first races that feed into a send-on-closed panic
	// (nhp/core/device.go). wg.Wait() can't hang when run first — every a.wg
	// routine returns on signals.stop (closed above) without needing the device:
	// sendMessageRoutine's device.SendMsgToPacket is a NON-BLOCKING send
	// (discard-on-full — see the breadcrumb there), and the wg-tracked knock
	// paths bail on signals.stop at their blocking receives — the transaction
	// response and preAccessRequest's encrypted-packet receive, both via
	// awaitOrStop — rather than waiting for device.Stop() to unblock them; those
	// receive guards are the load-bearing prerequisite. (device.Stop()'s own
	// termination depends on device-internal routines, but those are device.wg,
	// drained by device.Stop() after this Wait — not a gate on a.wg.Wait().)
	// Full rationale: docs/design/AGENT_LIFECYCLE_TEARDOWN.md ("Stop() ordering").
	a.wg.Wait()
	a.device.Stop()
	// Deliberately do NOT close sendMsgCh or knockTargetMapUpdated. Their
	// consumers already return on signals.stop, so a close is redundant — but
	// not harmless: not every sender is wg-tracked (the other SDK request
	// methods, the DHP DAR/DAV sends, and a resource-config
	// file-watcher's debounced time.AfterFunc callback all run untracked), so
	// wg.Wait() above doesn't fence them. A send case on an already-closed
	// channel is still "ready" in a select and can be chosen (panicking), so the
	// select-on-signals.stop guard every untracked sender uses only narrows the
	// window — not closing is what removes it. (Upstream 8e983f1d did this for
	// knockTargetMapUpdated; extended here to sendMsgCh.)
	// See docs/design/AGENT_LIFECYCLE_TEARDOWN.md invariant #1.

	log.Info("=========================")
	log.Info("=== NHP-Agent stopped ===")
	log.Info("=========================")
	a.log.Close()
}

func (a *UdpAgent) IsRunning() bool {
	return a.running.Load()
}

// beginTrackedOp registers an a.wg-tracked operation against teardown. It returns
// false (the caller MUST abort) if the agent isn't running; on true the caller
// MUST defer a.wg.Done(). The running check + a.wg.Add(1) run under
// lifecycleMu.RLock, so the Add cannot race Stop()'s Lock+CAS+wg.Wait — closing
// the "WaitGroup is reused before previous Wait has returned" panic reachable from
// a direct SDK Knock (#3103). Holding a wg token also pins the lifecycle field
// set: Stop() can't drain wg.Wait and Start() can't reassign signals.stop /
// sendMsgCh until the op calls Done, so the op's later channel snapshots are
// stable. RLock is held only across the check+Add, never a blocking send/receive.
func (a *UdpAgent) beginTrackedOp() bool {
	a.lifecycleMu.RLock()
	defer a.lifecycleMu.RUnlock()
	if !a.running.Load() {
		return false
	}
	a.wg.Add(1)
	return true
}

// launchTrackedRoutine starts fn as an a.wg-tracked goroutine iff the agent is
// running, doing the wg.Add + go under lifecycleMu.RLock so the Add can't race
// Stop()'s wg.Wait (#3103, same class as beginTrackedOp but for the routine
// launchers reachable from the SDK — sdk.KnockloopStart -> StartKnockLoop). fn
// MUST call a.wg.Done() on exit (the knock routines defer it). Returns false if
// the agent isn't running, in which case no routine is started.
func (a *UdpAgent) launchTrackedRoutine(fn func()) bool {
	a.lifecycleMu.RLock()
	defer a.lifecycleMu.RUnlock()
	if !a.running.Load() {
		return false
	}
	a.wg.Add(1)
	go fn()
	return true
}

// stopSignal snapshots a.signals.stop under lifecycleMu.RLock so an SDK-reachable
// reader can't race Start()'s reassignment (#3103). The returned channel is safe
// to select on without the lock: Stop() only ever closes the current stop channel
// (never reassigns a live one), and Start() installs a fresh one only after
// Stop()'s wg.Wait, so a snapshot either fires (teardown) or stays the live one.
func (a *UdpAgent) stopSignal() <-chan struct{} {
	a.lifecycleMu.RLock()
	defer a.lifecycleMu.RUnlock()
	return a.signals.stop
}

// mapUpdatedSignal snapshots a.signals.knockTargetMapUpdated under lifecycleMu.RLock,
// mirroring stopSignal for the one remaining Start()-reassigned channel with
// unsynchronized senders: AddResource/RemoveResource (SDK) and the debounced
// updateResources file-watcher callback. Without it those sends race Start()'s
// reassignment of the field (#3103). Returns the sendable channel; the non-blocking
// send stays outside the lock (knockTargetMapUpdated is never closed, so a snapshot
// of the previous cycle's channel just lands harmlessly in its size-1 buffer).
func (a *UdpAgent) mapUpdatedSignal() chan struct{} {
	a.lifecycleMu.RLock()
	defer a.lifecycleMu.RUnlock()
	return a.signals.knockTargetMapUpdated
}

// deviceKey returns the agent's device public key for log identification, or ""
// if the device isn't initialized. Nil-safe: some log sites (the address-parse
// Criticals in SendDAR/DAVMsgToServer) fire before the IsRunning() gate, so on a
// never-Start()ed agent a.device can be nil — a bare a.device.PublicKeyBase64()
// there would nil-deref.
func (a *UdpAgent) deviceKey() string {
	if a.device == nil {
		return ""
	}
	return a.device.PublicKeyBase64()
}

func (a *UdpAgent) newConnection(addr *net.UDPAddr) (conn *UdpConn) {
	conn = &UdpConn{}
	var err error
	// unlike tcp, udp dial is fast (just socket bind), so no need to run in a thread
	conn.netConn, err = net.DialUDP("udp", nil, addr)
	if err != nil {
		log.Error("[Agent] failed to dial UDP to remote addr %s: %v", addr.String(), err)
		return nil
	}

	// retrieve local port
	laddr := conn.netConn.LocalAddr()
	localAddr, err := net.ResolveUDPAddr(laddr.Network(), laddr.String())
	if err != nil {
		log.Error("[Agent] failed to resolve local UDPAddr %s: %v", laddr.String(), err)
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

func (a *UdpAgent) sendMessageRoutine() {
	defer a.wg.Done()
	defer log.Info("sendMessageRoutine stopped")

	log.Info("sendMessageRoutine started")

	for {
		select {
		case <-a.signals.stop:
			return

		case md, ok := <-a.sendMsgCh:
			// sendMsgCh is intentionally never closed (see Stop()), so this
			// !ok branch is currently unreachable; retained as defensive code
			// so the routine still terminates if that invariant ever changes.
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
					log.Error("[Agent] failed to create connection to remote address %s", addrStr)
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

func (a *UdpAgent) SendPacket(pkt *core.Packet, conn *UdpConn) (n int, err error) {
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

func (a *UdpAgent) recvPacketRoutine(conn *UdpConn) {
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
			log.Error("[Agent] failed to receive UDP packet from %s: %v", addrStr, err)
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
			log.Error("[Agent] received UDP packet from %s is too short (%d bytes, min %d), discarding", addrStr, n, minLen)
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

func (a *UdpAgent) connectionRoutine(conn *UdpConn) {
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
				log.Error("[Agent] failed to send packet to %s: %v", addrStr, sendErr)
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

func (a *UdpAgent) recvMessageRoutine() {
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

			switch ppd.HeaderType {
			case core.NHP_COK:
				// synchronously block and deal with cookie message to ensure future messages will be correctly processed. note cookie is not handled as a transaction, so it arrives in here
				a.HandleCookieMessage(ppd)

			}
		}
	}
}

func (a *UdpAgent) knockResourceRoutine() {
	defer a.wg.Done()
	defer log.Info("knockResourceRoutine stopped")

	log.Info("knockResourceRoutine started")

	var knockRoutineWg sync.WaitGroup
	defer knockRoutineWg.Wait()

	for {
		a.knockTargetMapMutex.Lock()
		targetSize := len(a.knockTargetMap)
		targetQuitArr := make([]chan struct{}, 0, targetSize)

		for k, r := range a.knockTargetMap {
			// launch knock routine for each knock target
			q := make(chan struct{})
			targetQuitArr = append(targetQuitArr, q)

			knockRoutineWg.Add(1)
			go func(knockStr string, res *KnockTarget, quit <-chan struct{}) {
				defer knockRoutineWg.Done()
				defer log.Info("knock %s sub-routine stopped", knockStr)
				defer func() {
					_, exitErr := a.ExitKnockRequest(res)
					switch {
					case exitErr == nil:
					case errors.Is(exitErr, common.ErrPacketToMessageRoutineStopped):
						// This defer runs on every sub-routine exit, including a
						// normal Stop()/RestartAgent where ExitKnockRequest bails on
						// signals.stop and returns the stopped-error for each active
						// target. That's expected teardown, not a failure — log at
						// Debug so routine restarts don't spam Error-level lines.
						log.Debug("[Agent] exit knock request skipped for %s during teardown: %v", knockStr, exitErr)
					default:
						log.Error("[Agent] exit knock request failed for %s: %v", knockStr, exitErr)
					}
				}()

				log.Info("knock %s sub-routine started", knockStr)

				openTimer := core.NewStoppedTimer()
				defer openTimer.Stop()

				for {
					select {
					case <-a.signals.knockTargetStop:
						return
					case <-quit:
						return
					default:
					}

					ackMsg, err := a.Knock(res) // timeout in AgentLocalTransactionTimeoutMs
					if err != nil {
						// if error happens wait some time (total AgentLocalTransactionResponseTimeoutMs) to retry.
						// A knock bailing on signals.stop during teardown is expected,
						// not a failure — log it at Debug so a routine Stop()/restart
						// doesn't emit an Error line per active target.
						if errors.Is(err, common.ErrPacketToMessageRoutineStopped) {
							log.Debug("[Agent] knock for resource %s stopped during teardown: %v", knockStr, err)
						} else {
							log.Error("[Agent] knock failed for resource %s: %v", knockStr, err)
						}
						continue // retry knock
					}

					log.Info("knock %s succeeded, next knock in %d seconds", knockStr, ackMsg.OpenTime)
					openTimer.Reset(time.Second * time.Duration(ackMsg.OpenTime))
					select {
					case <-a.signals.knockTargetStop:
						return
					case <-quit:
						return
					case <-openTimer.C:
						// continue knock
					}
				}
			}(k, r, q)
		}
		a.knockTargetMapMutex.Unlock()

		// block until knockTargetMap is updated
		select {
		case <-a.signals.knockTargetStop:
			return
		case <-a.signals.knockTargetMapUpdated:
			// stop all current knock routines
			for _, q := range targetQuitArr {
				close(q)
			}
			log.Info("restart knock cycle with updated targets")
			// continue and restart with new knock targets
		}
	}
}

func (a *UdpAgent) dhpKnockResourceRoutine() {
	defer a.wg.Done()
	defer log.Info("dhpKnockResourceRoutine stopped")

	log.Info("dhpKnockResourceRoutine started")

	openTimer := core.NewStoppedTimer()
	defer openTimer.Stop()

	for {
		select {
		case <-a.signals.stop:
			return
		default: // don't block for knock failure
		}
		ackMsg, err := a.KnockDHP()

		if err != nil {
			a.safeTee.Store(false)

			// A DHP knock bailing on signals.stop during teardown is expected, not
			// a failure — log at Debug so routine restarts don't emit Error noise.
			if errors.Is(err, common.ErrPacketToMessageRoutineStopped) {
				log.Debug("[Agent] DHP knock stopped during teardown: %v", err)
			} else {
				log.Error("[Agent] DHP knock failed: %v", err)
			}
			// On failure, back off FailureRetryInterval (2s, DNS-fast) before
			// re-knocking. Kept short so a transient failure re-establishes access in
			// a couple of seconds; the server's per-IP rate limiter — not this sleep —
			// is what bounds a knock flood. Interruptible on signals.stop so this
			// wg-tracked routine's backoff can't delay Stop()'s wg.Wait() (same as
			// Knock's error backoff).
			select {
			case <-time.After(core.FailureRetryInterval * time.Second):
			case <-a.signals.stop:
			}
			continue // retry knock (exits at the top select once signals.stop is closed)
		}

		log.Info("knock succeeded, next knock in %d seconds", ackMsg.OpenTime)
		a.safeTee.Store(true)

		openTimer.Reset(time.Second * time.Duration(ackMsg.OpenTime))
		select {
		case <-a.signals.stop:
			return
		case <-openTimer.C:
			// continue knock
		}
	}
}

func (a *UdpAgent) AddServer(server *core.UdpPeer) {
	if server.DeviceType() == core.NHP_SERVER {
		a.device.AddPeer(server)
		a.serverPeerMutex.Lock()
		a.serverPeerMap[server.PublicKeyBase64()] = server
		a.serverPeerMutex.Unlock()
	}
}

func (a *UdpAgent) RemoveServer(serverKey string) {
	a.serverPeerMutex.Lock()
	delete(a.serverPeerMap, serverKey)
	a.serverPeerMutex.Unlock()
}

func (a *UdpAgent) AddResource(res *KnockResource) error {
	if res.AuthServiceId == common.RegisteredAgentAuthServiceID {
		return ErrRegisteredAgentKnockLoopUnsupported
	}
	peer := a.FindServerPeerFromResource(res)
	if peer == nil {
		log.Error("[Agent] no server peer found for resource %s (server=%s)", res.Id(), res.ServerHost())
		return common.ErrKnockServerNotFound
	}

	updated := false
	a.knockTargetMapMutex.Lock()
	target, found := a.knockTargetMap[res.Id()]
	if found {
		target.SetResource(res)
		target.SetServerPeer(peer)
	} else {
		a.knockTargetMap[res.Id()] = &KnockTarget{
			KnockResource: *res,
			ServerPeer:    peer,
		}
		updated = true
	}
	a.knockTargetMapMutex.Unlock()

	if updated {
		// renew knock cycle. Non-blocking send (channel is buffered size
		// 1): coalesces with an already-queued update and, critically,
		// can't block forever or panic if a concurrent Stop() raced us —
		// same pattern as updateResources / RemoveResource.
		// knockTargetMapUpdated is never closed (see Stop()), so a late
		// send lands harmlessly in the buffer.
		mapUpdated := a.mapUpdatedSignal() // snapshot under RLock (#3103)
		select {
		case mapUpdated <- struct{}{}:
		default:
		}
	}

	return nil
}

func (a *UdpAgent) RemoveResource(aspId string, resId string) {
	res := &KnockResource{
		AuthServiceId: aspId,
		ResourceId:    resId,
	}

	a.knockTargetMapMutex.Lock()
	beforeSize := len(a.knockTargetMap)
	delete(a.knockTargetMap, res.Id())
	afterSize := len(a.knockTargetMap)
	a.knockTargetMapMutex.Unlock()

	if beforeSize != afterSize {
		// renew knock cycle. See AddResource: non-blocking send so a
		// concurrent caller or a racing Stop() can't block or panic.
		mapUpdated := a.mapUpdatedSignal() // snapshot under RLock (#3103)
		select {
		case mapUpdated <- struct{}{}:
		default:
		}
	}
}

func (a *UdpAgent) FindServerPeerFromResource(res *KnockResource) *core.UdpPeer {
	a.serverPeerMutex.Lock()
	defer a.serverPeerMutex.Unlock()
	for _, peer := range a.serverPeerMap {
		if peer.Host() == res.ServerHost() {
			return peer
		}
	}

	return nil
}

func (a *UdpAgent) StartConfidentialComputing(ztdoId string, taId string, function string, params map[string]any) (any, error) {
	var err error
	var policyId string

	output, refreshSdp, decrypted := a.PreCheckDataAccess(ztdoId)

	if refreshSdp {
		a.dataAccessRefreshMutex.Lock()
		defer a.dataAccessRefreshMutex.Unlock()

		// secondly check again
		output, refreshSdp, decrypted = a.PreCheckDataAccess(ztdoId)

		if refreshSdp {
			output, err = a.RefreshDataAccess(ztdoId, decrypted, output)
			if err != nil {
				return nil, fmt.Errorf("failed to refresh SDP: %w", err)
			}
		}
	}

	// inject data path to params
	params["path"] = output

	var exist bool
	if policyId, exist = a.smartPolicyIdentifier[ztdoId]; !exist {
		return nil, fmt.Errorf("failed to find policyId for ztdoId %s", ztdoId)
	}

	taRes, err := a.CallTrustedApplication(taId, function, params, policyId)
	if err != nil {
		return nil, fmt.Errorf("failed to call trusted application: %w", err)
	}

	var structResult map[string]any
	if err := json.Unmarshal([]byte(taRes), &structResult); err != nil {
		return nil, fmt.Errorf("failed to unmarshal confidential computing result: %w", err)
	}
	return structResult, nil
}

func (a *UdpAgent) PreCheckDataAccess(ztdoId string) (output string, refreshSdp bool, decrypted bool) {
	output = ""

	// Check whether the smart data policy needs to be refreshed
	if sdpRefreshTime, exist := a.smartDataPolicyRefreshTime[ztdoId]; exist {
		if time.Now().UnixNano()-sdpRefreshTime > SmartDataPolicyRefreshTime {
			refreshSdp = true
		}
	} else {
		refreshSdp = true
	}

	// Check whether the ZTDO has been decrypted
	if plaintextPath, exist := a.decryptedZtdoRecord[ztdoId]; exist {
		output = plaintextPath
		decrypted = true
	} else {
		decrypted = false
		refreshSdp = true
	}

	return output, refreshSdp, decrypted
}

func (a *UdpAgent) RefreshDataAccess(ztdoId string, decrypted bool, decryptedOutput string) (output string, err error) {
	ztdo := ztdolib.NewZtdo()

	consumerEphemeralEcdh, err := core.NewECDH(a.config.GetEccType())
	if err != nil {
		return "", fmt.Errorf("failed to generate ephemeral ECDH: %w", err)
	}
	teeEcdh, err := a.config.GetTeeEcdh()
	if err != nil {
		return "", fmt.Errorf("failed to get TEE ECDH: %w", err)
	}

	darMsg := common.DARMsg{
		DoId:                       ztdoId,
		UserId:                     a.config.UserId,
		TeePublicKey:               teeEcdh.PublicKeyBase64(),
		ConsumerEphemeralPublicKey: consumerEphemeralEcdh.PublicKeyBase64(),
	}
	serverPeer := a.GetFirstServerPeer()
	result, dagMsg := a.SendDARMsgToServer(serverPeer, darMsg)
	if result {
		a.trustedByNHPDB.Store(true) // agent has been trusted by NHP DB

		// update smart data policy refresh time
		a.smartDataPolicyRefreshTime[ztdoId] = time.Now().UnixNano()

		log.Info("[StartConfidentialComputing] Refresh smart data policy for data object which id is %s", ztdoId)

		if !decrypted {
			output, err = utils.GenerateTempFilePath("plaintext-*")
			if err != nil {
				return "", fmt.Errorf("failed to generate temporary file path: %w", err)
			}

			dataPrkWrapping := ztdolib.DataPrivateKeyWrapping{}

			if err := json.Unmarshal([]byte(dagMsg.Kao.WrappedDataKey), &dataPrkWrapping); err != nil {
				log.Error("failed to unmarshal data private key wrapping: %v", err)
				return "", fmt.Errorf("failed to unmarshal data private key wrapping: %w", err)
			}

			providerPbk, err := base64.StdEncoding.DecodeString(dataPrkWrapping.ProviderPublicKeyBase64)
			if err != nil {
				return "", fmt.Errorf("failed to decode provider public key base64: %w", err)
			}

			if dagMsg.AccessUrl == "" {
				log.Error("access url is empty, please check with data provider")
				return "", errors.New("access url is empty, please check with data provider")
			}

			ztdoPath, err := utils.DownloadFileToTemp(dagMsg.AccessUrl, "ztdo-")
			if err != nil {
				log.Error("failed to download ztdo: %v", err)
				return "", fmt.Errorf("failed to download ztdo: %w", err)
			}

			if err := ztdo.ParseHeader(ztdoPath); err != nil {
				log.Error("failed to parse ztdo header: %s", err)
				return "", fmt.Errorf("failed to parse ztdo header: %w", err)
			}

			if ztdoId != ztdo.GetObjectID() {
				log.Error("ztdo id mismatch: expected=%s, got=%s", ztdoId, ztdo.GetObjectID())
				return "", errors.New("ztdo id mismatch, please check with data provider")
			}

			// decrypt data private key
			saDataPrk := ztdolib.NewSymmetricAgreement(ztdo.GetECCMode(), false)
			saDataPrk.SetMessagePatterns(ztdolib.DataPrivateKeyWrappingPatterns)
			saDataPrk.SetPsk([]byte(ztdolib.InitialDHPKeyWrappingString))
			saDataPrk.SetStaticKeyPair(teeEcdh)
			saDataPrk.SetEphemeralKeyPair(consumerEphemeralEcdh)
			saDataPrk.SetRemoteStaticPublicKey(providerPbk)

			gcmKey, ad := saDataPrk.AgreeSymmetricKey()

			dataPrkBase64, err := dataPrkWrapping.Unwrap(gcmKey[:], ad)
			if err != nil {
				return "", fmt.Errorf("failed to unwrap data private key: %w", err)
			}

			if ztdoPath == "" || output == "" {
				return "", errors.New("ztdo path or output is empty")
			}

			// decrypt data
			dataKeyPairEccMode := ztdo.GetECCMode()

			dataMsgPattern := [][]ztdolib.MessagePattern{
				{ztdolib.MessagePatternS, ztdolib.MessagePatternDHSS},
				{ztdolib.MessagePatternRS, ztdolib.MessagePatternDHSS},
			}

			dataPrk, err := base64.StdEncoding.DecodeString(dataPrkBase64)
			if err != nil {
				return "", fmt.Errorf("failed to decode data private key base64: %w", err)
			}
			dataEcdh, err := core.ECDHFromKey(dataKeyPairEccMode.ToEccType(), dataPrk)
			if err != nil {
				return "", fmt.Errorf("failed to create ECDH from data key: %w", err)
			}
			saData := ztdolib.NewSymmetricAgreement(dataKeyPairEccMode, false)
			saData.SetMessagePatterns(dataMsgPattern)
			saData.SetStaticKeyPair(dataEcdh)

			providerPublicKey, err := base64.StdEncoding.DecodeString(dataPrkWrapping.ProviderPublicKeyBase64)
			if err != nil {
				return "", fmt.Errorf("failed to decode provider public key base64: %w", err)
			}
			saData.SetRemoteStaticPublicKey(providerPublicKey)

			gcmKey, ad = saData.AgreeSymmetricKey()

			if err := ztdo.DecryptZtdoFile(ztdoPath, output, gcmKey[:], ad); err != nil {
				return "", fmt.Errorf("failed to decrypt ztdo file: %w", err)
			}
			a.decryptedZtdoRecord[ztdoId] = output
		} else {
			output = decryptedOutput
		}
	} else {
		teeNotAuthorizedCode, _ := strconv.Atoi(common.ErrTEENotAuthorized.ErrorCode())
		if dagMsg.ErrCode == teeNotAuthorizedCode {
			a.trustedByNHPDB.Store(false)
		}

		return "", fmt.Errorf("failed to request ztdo: %s", dagMsg.ErrMsg)
	}
	return output, nil
}

func (a *UdpAgent) GetFirstServerPeer() (serverPeer *core.UdpPeer) {
	for _, value := range a.serverPeerMap {
		serverPeer = value
		return serverPeer
	}
	return nil
}

func (a *UdpAgent) SendDARMsgToServer(server *core.UdpPeer, msg common.DARMsg) (bool, *common.DAGMsg) {
	sendAddr := server.SendAddr()
	if sendAddr == nil {
		log.Critical("device(%s)[SendDARMsgToServer] register server IP cannot be parsed", a.deviceKey())
		return false, nil
	}
	udpAddr, ok := sendAddr.(*net.UDPAddr)
	if !ok {
		log.Critical("device(%s)[SendDARMsgToServer] unexpected address type %T", a.deviceKey(), sendAddr)
		return false, nil
	}
	drgBytes, marshalErr := json.Marshal(msg)
	if marshalErr != nil {
		log.Error("[Agent] SendDARMsgToServer failed to marshal DAR message: %v", marshalErr)
		return false, nil
	}
	drgMd := &core.MsgData{
		RemoteAddr:    udpAddr,
		HeaderType:    core.NHP_DAR,
		TransactionId: a.device.NextCounterIndex(),
		Compress:      true,
		Message:       drgBytes,
		PeerPk:        server.PublicKey(),
		ResponseMsgCh: make(chan *core.PacketParserData, 1), // buffered: see awaitTransactionResponse
	}

	currTime := time.Now().UnixNano()
	if !a.IsRunning() {
		log.Error("[Agent] send channel closed or closing, skipping message send")
		return false, nil
	}
	// Guarded send (see sendOrStop); runs on the untracked DHP web-console
	// goroutine. On success the device creates or finds a connection and sends
	// the MsgAssembler via it.
	if !a.sendOrStop(drgMd) {
		log.Error("device(%s)[SendDARMsgToServer] message routine stopped, skipping message send", a.deviceKey())
		return false, nil
	}
	server.UpdateSend(currTime)
	// Block for the transaction response, bailing out on Stop() (this runs on the
	// untracked DHP web-console goroutine); see awaitTransactionResponse.
	serverPpd, ok := a.awaitTransactionResponse(drgMd.ResponseMsgCh)
	if !ok {
		log.Error("device(%s)[SendDARMsgToServer] message routine stopped, skip waiting for response", a.deviceKey())
		return false, nil
	}

	// Parse DSA response
	dsaMsg := &common.DSAMsg{}
	dagMsg := &common.DAGMsg{}
	if serverPpd.Error != nil {
		log.Error("Agent(%s#%d)[SendDARMsgToServer] failed to receive response from server %s: %v", msg.DoId, drgMd.TransactionId, server.Ip, serverPpd.Error)
		return false, dagMsg
	}

	if serverPpd.HeaderType != core.NHP_DSA {
		log.Error("[Agent] SendDARMsgToServer(%s#%d) response from server %s has wrong type: %s", msg.DoId, drgMd.TransactionId, server.Ip, core.HeaderTypeToString(serverPpd.HeaderType))
		return false, dagMsg
	}

	if err := json.Unmarshal(serverPpd.BodyMessage, dsaMsg); err != nil {
		log.Error("Agent(%s#%d)[SendDARMsgToServer] failed to parse %s message: %v", msg.DoId, serverPpd.SenderTrxId, core.HeaderTypeToString(serverPpd.HeaderType), err)
		return false, dagMsg
	}

	if dsaMsg.ErrCode != 0 {
		log.Error("[Agent] SendDARMsgToServer failed for doId=%s: errCode=%d, errMsg=%s", dsaMsg.DoId, dsaMsg.ErrCode, dsaMsg.ErrMsg)
		dagMsg.DoId = dsaMsg.DoId
		dagMsg.ErrCode = dsaMsg.ErrCode
		dagMsg.ErrMsg = dsaMsg.ErrMsg
		return false, dagMsg
	}

	// Clear related resources when loading new smart data policy
	if spoId, exist := a.smartPolicyIdentifier[dsaMsg.DoId]; exist {
		if _, exist := a.smartPolicyEngine[spoId]; exist {
			a.smartPolicyEngine[spoId].Close()
			delete(a.smartPolicyEngine, spoId)
		}
		delete(a.smartPolicyIdentifier, dsaMsg.DoId)
	}
	a.smartPolicyIdentifier[dsaMsg.DoId] = dsaMsg.Spo.PolicyId

	// Collect attestation proofs with smart policy
	evidence, err := a.onAttestationCollect(dsaMsg.Spo)
	if err != nil {
		return false, &common.DAGMsg{DoId: dsaMsg.DoId, ErrCode: 1, ErrMsg: err.Error()}
	}

	// avoid flood attack from server side
	time.Sleep(core.MinimalRecvIntervalMs * time.Millisecond)

	davMsg := common.DAVMsg{
		DoId:     msg.DoId,
		SpoId:    dsaMsg.SpoId,
		Evidence: evidence,
	}

	return a.SendDAVMsgToServer(server, davMsg)
}

func (a *UdpAgent) SendDAVMsgToServer(server *core.UdpPeer, msg common.DAVMsg) (bool, *common.DAGMsg) {
	sendAddr := server.SendAddr()
	if sendAddr == nil {
		log.Critical("device(%s)[SendDAVMsgToServer] register server IP cannot be parsed", a.deviceKey())
		return false, nil
	}
	udpAddr, ok := sendAddr.(*net.UDPAddr)
	if !ok {
		log.Critical("device(%s)[SendDAVMsgToServer] unexpected address type %T", a.deviceKey(), sendAddr)
		return false, nil
	}
	davBytes, marshalErr := json.Marshal(msg)
	if marshalErr != nil {
		log.Error("[Agent] SendDAVMsgToServer failed to marshal DAV message: %v", marshalErr)
		return false, nil
	}
	davMd := &core.MsgData{
		RemoteAddr:    udpAddr,
		HeaderType:    core.NHP_DAV,
		TransactionId: a.device.NextCounterIndex(),
		Compress:      true,
		Message:       davBytes,
		PeerPk:        server.PublicKey(),
		ResponseMsgCh: make(chan *core.PacketParserData, 1), // buffered: see awaitTransactionResponse
	}

	currTime := time.Now().UnixNano()
	if !a.IsRunning() {
		log.Error("[Agent] send channel closed or closing, skipping message send")
		return false, nil
	}
	// Guarded send (see sendOrStop); untracked DHP web-console goroutine.
	if !a.sendOrStop(davMd) {
		log.Error("device(%s)[SendDAVMsgToServer] message routine stopped, skipping message send", a.deviceKey())
		return false, nil
	}
	server.UpdateSend(currTime)
	// Block for the transaction response, bailing out on Stop() (untracked DHP
	// web-console goroutine); see awaitTransactionResponse.
	serverPpd, ok := a.awaitTransactionResponse(davMd.ResponseMsgCh)
	if !ok {
		log.Error("device(%s)[SendDAVMsgToServer] message routine stopped, skip waiting for response", a.deviceKey())
		return false, nil
	}

	dagMsg := &common.DAGMsg{}
	if serverPpd.Error != nil {
		log.Error("Agent(%s#%d)[SendDAVMsgToServer] failed to receive response from server %s: %v", msg.DoId, davMd.TransactionId, server.Ip, serverPpd.Error)
		return false, dagMsg
	}

	if serverPpd.HeaderType != core.NHP_DAG {
		log.Error("[Agent] SendDAVMsgToServer(%s#%d) response from server %s has wrong type: %s", msg.DoId, davMd.TransactionId, server.Ip, core.HeaderTypeToString(serverPpd.HeaderType))
		return false, dagMsg
	}

	if err := json.Unmarshal(serverPpd.BodyMessage, dagMsg); err != nil {
		log.Error("Agent(%s#%d)[SendDAVMsgToServer] failed to parse %s message: %v", msg.DoId, serverPpd.SenderTrxId, core.HeaderTypeToString(serverPpd.HeaderType), err)
		return false, dagMsg
	}

	if dagMsg.ErrCode != 0 {
		log.Error("[Agent] SendDAVMsgToServer failed for doId=%s: errCode=%d, errMsg=%s", dagMsg.DoId, dagMsg.ErrCode, dagMsg.ErrMsg)
		return false, dagMsg
	}

	return true, dagMsg
}

func (s *UdpAgent) onAttestationCollect(spo *common.SmartPolicy) (string, error) {
	if spo.Policy == "" {
		return "", nil
	}

	wasmBytes, err := spo.GetPolicy()
	if err != nil {
		return "", err
	}

	engine := wasmEngine.NewEngine()
	err = engine.LoadWasm(wasmBytes)
	if err != nil {
		return "", err
	}

	s.smartPolicyEngine[spo.PolicyId] = engine

	attestation := engine.OnAttestationCollect()

	return attestation, nil
}

func (a *UdpAgent) CallTrustedApplication(taId string, function string, params map[string]any, spoId string) (string, error) {
	ta, err := GetTrustedApplication(taId)
	if err != nil {
		return "", err
	}

	taRes, err := ta.CallFunction(function, params)
	if err != nil {
		return "", err
	}

	if spEngine, exist := a.smartPolicyEngine[spoId]; exist {
		return spEngine.OnDataPostprocess(taRes), nil
	}
	return taRes, nil
}
