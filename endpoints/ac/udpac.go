package ac

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"runtime/debug"
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

	// serverPubKeyAllowlist is the NHP_ARD pubkey-allowlist "extras"
	// set (#1156). Protected by serverPeerMutex above so a concurrent
	// config reload cannot rebuild this while an ARD evaluation is in
	// flight. Sourced from Config.ServerPubKeyAllowlist; see
	// ard_allowlist.go for the lookup and rebuild helpers.
	serverPubKeyAllowlist map[string]struct{}

	tokenStore *common.TokenStore[*AccessEntry]

	// revIndex is the qURL v2 secondary revocation index (P4b): reverse
	// lookups from a revocation key (qurl_user_public_key_hash /
	// resource_public_key_hash / session_id / admission_id) to the tokenStore
	// tokens whose AccessEntry carries it, plus the per-(scope,key) applied-
	// epoch watermark for idempotency. Maintained by storeToken/deleteToken and
	// the OnExpire hook so it tracks tokenStore membership; driven by
	// ApplyRevocation. Constructed in Start alongside tokenStore. See
	// revocation_index.go and docs/design/QURL_V2_KEYED_IDENTITY.md.
	revIndex *revocationIndex

	// aopReplay dedupes recently observed NHP_AOP packets by
	// (sender_pubkey, txid, send_time) so a captured-and-replayed
	// packet cannot re-open ipset entries on a fresh connection.
	// Initialized in Start(); tests that construct &UdpAC{} without
	// going through Start MUST wire `aopReplay: newAOPReplayCache()`
	// manually before invoking HandleUdpACOperations, or the call
	// will nil-deref on MarkSeen. See aop_replay_cache.go for the
	// threat model and sizing.
	aopReplay *aopReplayCache

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

	// expirySched is the L3 flush-on-expiry scheduler. nil when
	// Config.EnableL3FlushOnExpiry is false — call-sites guard with
	// `if a.expirySched != nil` before Schedule/Cancel. Constructed
	// in Start() per FilterMode (ConntrackFlusher for IPTABLES,
	// BpfFlusher for EBPFXDP); stopped in Stop() via Shutdown.
	// See expiry_scheduler.go for the wheel design + the
	// fail-closed-at-admission contract IsBreakerOpen feeds.
	expirySched *Scheduler

	// enumerateFn is the boot-enumeration dispatch hook. nil means
	// "use the platform default" (enumerateKernelAllowRules, build-
	// tagged per OS). Tests set this directly to inject success/
	// failure paths without needing kernel-state manipulation, so
	// the synchronous-fail-closed-boot contract can be fenced on
	// every platform CI runs on — not just non-Linux (cr round-2
	// silent-skip self-review).
	enumerateFn func() (int, error)

	// bpfFlusherSkippedCount is the BpfFlusher's non-IPv4 skip
	// counter reader, set when the scheduler is constructed in
	// EBPFXDP mode on Linux. nil otherwise. The cross-platform
	// indirection (rather than a typed *BpfFlusher field) lets the
	// metrics publisher read the counter from registration.go
	// without taking a build-tag dependency
	bpfFlusherSkippedCount func() uint64

	// surgicalConnFlush is the per-flow surgical conntrack-teardown seam
	// used by the revocation apply path (flushEntryNow). Set to
	// BpfFlusher.FlushConn ONLY when the scheduler is constructed in EBPFXDP
	// mode on Linux (same gate as bpfFlusherSkippedCount); nil otherwise —
	// in iptables mode, on non-Linux, or when L3 flush is disabled, where
	// flushEntryNow falls back to the coarse allow-rule reschedule alone.
	// A non-nil value is the signal that the eBPF/XDP+IPv4 surgical path is
	// available: flushEntryNow enumerates each revoked flow's conntrack
	// 5-tuples and calls this to kill EXACTLY the revoked admission's flow,
	// leaving same-allow-tuple siblings (different source port) alive — the
	// surgical precision P4c's primitives enable and #2784 needs. The
	// func-field indirection (rather than a typed *BpfFlusher) keeps
	// revocation_index.go build-tag-free and lets an AC-level test inject a
	// fake to prove the wiring drives surgical-per-v4-key + v6-hard-fail.
	surgicalConnFlush func(context.Context, ConnFlowKey) error

	// enumerateConnSrcPorts recovers the live conn_track source ports on an
	// allow-rule tuple {srcIP,dstIP,proto,dstPort}, feeding the surgical flush
	// above. Bound to utilebpf.EnumerateConnTrackSrcPorts in the same
	// EBPFXDP-on-Linux Start() block as surgicalConnFlush. The func-field seam
	// (rather than calling the package function directly from
	// surgicalFlushFlowKey) lets an AC-level test inject a fake enumerator: the
	// pinned conn_track map is absent in unit tests, so without this seam the
	// surgical FlushConn-per-source-port drive could not be proven off a kernel
	// rig. Only read when surgicalConnFlush != nil.
	enumerateConnSrcPorts func(srcIP, dstIP string, proto uint8, dstPort uint16) ([]uint16, error)

	// surgicalConnFlushV6 / enumerateConnSrcPortsV6 are the IPv6 twins of the
	// two fields above (E2 slice 5). Bound to BpfFlusher.FlushConnV6 and
	// utilebpf.EnumerateConnTrackSrcPortsV6 in the same EBPFXDP-on-Linux Start()
	// block; nil otherwise. When both are non-nil, surgicalFlushFlowKey performs
	// surgical conntrack teardown for v6 flows (closing the #2778 IPv6
	// immediate-revocation gap on the eBPF/XDP path) instead of the v6 hard-fail;
	// when either is nil (iptables mode, non-Linux, L3 disabled) it keeps the
	// hard-fail fallback. Same func-field indirection rationale as the v4 fields:
	// keeps revocation_index.go build-tag-free and lets a test inject fakes (the
	// pinned conn_track_v6 map is absent off a kernel rig).
	surgicalConnFlushV6     func(context.Context, ConnFlowKey) error
	enumerateConnSrcPortsV6 func(srcIP, dstIP string, proto uint8, dstPort uint16) ([]uint16, error)
}

// BpfFlusherSkippedCount returns the BpfFlusher's non-IPv4 skip
// counter and ok=true when the scheduler is wired in EBPFXDP mode;
// 0, false otherwise. Cross-platform via the func-field
// indirection so registration.go's gauge stays build-tag-free.
func (a *UdpAC) BpfFlusherSkippedCount() (uint64, bool) {
	if a.bpfFlusherSkippedCount == nil {
		return 0, false
	}
	return a.bpfFlusherSkippedCount(), true
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
	// serverPubKeyAllowlist is allocated earlier in Start via
	// loadBaseConfig → updateBaseConfig's first-load path;
	// re-initializing here would wipe the operator-supplied
	// ServerPubKeyAllowlist entries and leave source 3 of the
	// allowlist dead until the next config.toml touch (see #1239).
	a.tokenStore = common.NewTokenStore[*AccessEntry]()
	a.revIndex = newRevocationIndex()
	// Registered BEFORE a.expirySched is constructed below. Safe
	// for two reasons: (1) the hook closure captures `a` rather
	// than the scheduler pointer, so it reads a.expirySched at
	// call time and cancelAllScheduledFlows's nil-scheduler
	// guard handles the in-progress window; (2) RunRefreshRoutine
	// is launched at the end of Start, so CleanExpired cannot fire
	// in this window — no tokens can be stored before Start
	// returns. A future Start refactor that violates either
	// invariant must move installExpiryHook accordingly.
	a.installExpiryHook()
	a.dnsRateLimiter = NewDNSChangeRateLimiter()
	a.aopReplay = newAOPReplayCache()

	// Load http config and turn on http server if needed
	if err := a.loadHttpConfig(); err != nil {
		log.Error("failed to load http config: %v", err)
	}

	// Load server peers from local config
	if err := a.loadPeers(); err != nil {
		log.Error("failed to load server peers: %v", err)
	}

	if a.config.FilterMode == FilterMode_EBPFXDP {
		// Long-lived infrastructure routes (1-year TTL) for the AC's
		// own server peers. INTENTIONALLY not wired into the L3 flush
		// scheduler — these aren't session-tied; the scheduler's scope
		// is per-session NHP-AOP entries only. An operator who removes
		// a server from config + restarts AC will leave the stale
		// kernel rule until natural 1-year TTL expiry; the iptables
		// path makes the same trade-off by skipping tempset in boot
		// enumeration
		for _, server := range a.config.Servers {
			ebpfHashStr := ebpf.EbpfRuleParams{
				SrcIP: server.Ip,
				DstIP: a.config.DefaultIp,
			}
			log.Info("server ip is %s", server.Ip)
			err = a.ebpfRuleAddFailClosed(2, ebpfHashStr, 31536000)
			if err != nil {
				log.Error("[EbpfRuleAdd] add ebpf src: %s dst: %s, error: %v", ebpfHashStr.SrcIP, ebpfHashStr.DstIP, err)
				continue
			}
		}
	}

	// Construct the L3 flush-on-expiry scheduler if the feature is
	// enabled. Per-mode flusher selection mirrors the FilterMode
	// dispatch above. Construction failures are fatal — running
	// with EnableL3FlushOnExpiry=true but no flusher would silently
	// late-fire forever (worst-of-both-worlds for an L3-only
	// enforcement contract).
	if a.config.EnableL3FlushOnExpiry {
		flusher, ferr := newFlusherForFilterMode(a.config.FilterMode)
		if ferr != nil {
			return ferr
		}
		// Type-assert AFTER the err check: a future flusher constructor that returns
		// (typed-nil, err) would otherwise silently bind a method
		// on a nil receiver to a.bpfFlusherSkippedCount.
		// Type-asserting through the FlowFlusher interface lets the
		// metrics-publisher path stay cross-platform — the
		// non-Linux stub returns 0 from SkippedCount.
		if bf, ok := flusher.(*BpfFlusher); ok && bf != nil {
			a.bpfFlusherSkippedCount = bf.SkippedCount
			// Bind the surgical conntrack-teardown seam to the same
			// EBPFXDP-on-Linux BpfFlusher. This is what flips
			// flushEntryNow from coarse-only allow-rule reschedule to the
			// surgical FlushConn-per-5-tuple path. iptables mode
			// (ConntrackFlusher) and non-Linux leave it nil → coarse path.
			a.surgicalConnFlush = bf.FlushConn
			// Pair the enumerator that recovers the source ports FlushConn
			// needs. Bound here (not called directly) so a unit test can swap
			// in a fake — the pinned conn_track map is absent off a kernel rig.
			a.enumerateConnSrcPorts = ebpf.EnumerateConnTrackSrcPorts
			// IPv6 twins (E2 slice 5): bind the v6 surgical seam to the same
			// EBPFXDP-on-Linux BpfFlusher so a v6 revoke gets immediate
			// conntrack teardown instead of the #2778 hard-fail. FlushConnV6
			// mirrors FlushConn but targets the conn_track_v6 map.
			a.surgicalConnFlushV6 = bf.FlushConnV6
			a.enumerateConnSrcPortsV6 = ebpf.EnumerateConnTrackSrcPortsV6
		}
		a.expirySched = NewScheduler(flusher,
			WithDryRun(a.config.L3FlushDryRun),
			WithBreakerThreshold(a.config.L3FlushErrorThreshold),
			WithBreakerWindow(time.Duration(a.config.L3FlushErrorWindowSec)*time.Second),
		)
		a.expirySched.Start()
		log.Info("[L3FlushSched] started: filterMode=%d dryRun=%t breakerThresh=%d/%ds",
			a.config.FilterMode, a.config.L3FlushDryRun,
			a.config.L3FlushErrorThreshold, a.config.L3FlushErrorWindowSec)
		// Synchronous boot-time enumeration: walk kernel allow-rules
		// from a previous AC process and Schedule a flush for each
		// at its remaining timeout. MUST complete before the AC
		// begins accepting NHP-AOPs — otherwise an AC restart would
		// leave existing kernel entries unmanaged by the scheduler
		// and their flow-state would survive past session end. See
		// expiry_enumerate.go for the fail-closed-on-error contract.
		//
		// If enumeration fails we must Shutdown the scheduler before
		// returning — Start() already launched the tick + 64 worker
		// goroutines; without explicit teardown they leak (and a
		// caller that doesn't call Stop() on a failed Start() would
		// leak permanently). Nil the pointer so the caller's
		// post-Start cleanup is a no-op
		if err = a.enumerateAndScheduleFlushes(); err != nil {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if shutdownErr := a.expirySched.Shutdown(shutdownCtx); shutdownErr != nil {
				log.Error("[L3FlushSched] cleanup shutdown after boot enum failure timed out: %v", shutdownErr)
			}
			// Safe to nil here (vs Stop()'s explicit don't-nil): we
			// haven't called `a.running.Store(true)` yet, no readers
			// are spawned, no in-flight HandleAccessControl can race
			// the write. Inverse of the Stop()-path invariant (cr
			// fence: round 11 minor — nil-write safety pinned).
			a.expirySched = nil
			a.bpfFlusherSkippedCount = nil
			a.surgicalConnFlush = nil
			a.enumerateConnSrcPorts = nil
			a.surgicalConnFlushV6 = nil
			a.enumerateConnSrcPortsV6 = nil
			return fmt.Errorf("L3 flush boot enumeration: %w", err)
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
	// Stop registration manager.
	//
	// Ordering note: ac.registration.Stop() runs BEFORE ac.wg.Wait()
	// below, so an in-flight NHP_ARD goroutine spawned by
	// recvMessageRoutine can still re-enter the registration manager
	// after its teardown begins. The wg-tracking added in #1655 keeps
	// the goroutine inside ac.wg.Wait(); the use-after-stop window
	// itself is closed by ACRegistration.HandleRedispatch's
	// r.stopped.Load() gate (#1657). The obvious reorder — moving
	// ac.wg.Wait() above this call — introduces a new deadlock
	// surface in serverDiscovery (bare `sendMsgCh <- aolMd` and a
	// bare `<-aolMd.ResponseMsgCh`, neither selecting on
	// signals.stop). Today nhp/core/device.go::(*Device).Stop is
	// what resolves the response wait; reversing the order leaves
	// serverDiscovery blocked with no path to wake. If
	// nhp/core/device.go::(*Device).Stop ever changes its drain
	// semantics, revisit this ordering.
	if ac.registration != nil {
		ac.registration.Stop()
	}
	ac.device.Stop()
	ac.StopConfigWatch()
	if ac.dnsRateLimiter != nil {
		ac.dnsRateLimiter.ResetAll()
	}
	// Drain the L3 flush scheduler before goroutine teardown so any
	// pending flushes complete (or time out cleanly) before the
	// process exits. 5s budget matches the worker-side flush
	// context timeout in processEntry.
	//
	// Do NOT nil ac.expirySched here: in-flight HandleAccessControl
	// goroutines tracked by ac.wg can still read the pointer (admission
	// gate + scheduleFlushIfEnabled). Scheduler.Schedule/Cancel already
	// no-op once Shutdown flips started=false (see expiry_scheduler.go),
	// so a stale pointer is safe; a write race against `ac.expirySched
	// = nil` before ac.wg.Wait() is not
	if ac.expirySched != nil {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		// defer-cancel right after WithTimeout — catches a panic mid-Shutdown without leaking
		// the context's internal goroutine.
		defer cancel()
		if err := ac.expirySched.Shutdown(shutdownCtx); err != nil {
			log.Error("[L3FlushSched] shutdown drain timed out: %v", err)
		}
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

// newFlusherForFilterMode selects the per-mode FlowFlusher impl
// based on FilterMode. Extracted from Start() so the dispatch is
// directly unit-testable — a future FilterMode addition that forgets
// to wire a flusher here is caught by TestNewFlusherForFilterMode
// rather than discovered at AC startup time
func newFlusherForFilterMode(filterMode int) (FlowFlusher, error) {
	switch filterMode {
	case FilterMode_IPTABLES:
		f, err := NewConntrackFlusher()
		if err != nil {
			return nil, fmt.Errorf("L3 flush enabled but ConntrackFlusher failed: %w", err)
		}
		return f, nil
	case FilterMode_EBPFXDP:
		f, err := NewBpfFlusher()
		if err != nil {
			return nil, fmt.Errorf("L3 flush enabled but BpfFlusher failed: %w", err)
		}
		return f, nil
	default:
		return nil, fmt.Errorf("L3 flush enabled but unsupported FilterMode %d", filterMode)
	}
}

// scheduleFlushIfEnabled is the central call-site wrapper for the
// L3 flush-on-expiry scheduler. It's a no-op when the feature is
// disabled (a.expirySched == nil) so call sites in
// HandleAccessControl can sprinkle Schedule calls without per-site
// nil-checks. Returns silently on malformed FlowKey inputs — the
// scheduler is best-effort defense-in-depth, NOT a correctness
// gate; the kernel state has already been written by the caller.
//
// Wildcard ports (port == 0) and "any" protocol map to the FlowKey
// shape the scheduler expects; the per-mode flusher dispatches
// based on FlowKey.Protocol (BpfFlusher uses sdwhitelist for
// FlowProtoAny, spp for tcp/udp, icmpwhitelist for icmp).
//
// When the feature is enabled, entry MUST be non-nil. The key is
// recorded on entry.scheduledKeys BEFORE Scheduler.Schedule
// (record-then-Schedule order — see the inline rationale below) so the
// matching cancelAllScheduledFlows walks exactly what was scheduled
// (#2201, #2205). A nil entry while the scheduler is live would
// schedule without tracking; cancelAllScheduledFlows would later miss
// the key and leave a phantom scheduler entry that fires Flush against
// already-gone kernel state. The non-nil contract is enforced by a
// Critical log + early return rather than panic — the kernel-state side
// may already be settled by the caller, so taking the AC down for a
// single mis-shaped admission is a worse outcome than dropping the
// schedule.
//
// The disabled-scheduler short-circuit comes FIRST, before the nil-entry
// check: with no scheduler there is nothing to Schedule and no phantom
// to create, so a nil entry is harmless. Ordering it first lets callers
// that legitimately have no entry to mint when the feature is off (the
// temp-access path's registerTempAccessFlushEntry returns nil in that
// config to avoid parking a useless tokenStore entry — #2213) pass nil
// without tripping the Critical/metric meant for a genuine
// enabled-scheduler contract violation.
func (a *UdpAC) scheduleFlushIfEnabled(entry *AccessEntry, srcIP, dstIP string, dstPort int, proto FlowProto, deadline time.Time) {
	if a.expirySched == nil {
		return
	}
	if entry == nil {
		log.Critical("[L3FlushSched] scheduleFlushIfEnabled called with nil entry — schedule dropped to avoid phantom scheduler entry (src=%s dst=%s port=%d)",
			srcIP, dstIP, dstPort)
		a.incrMetric(MetricL3FlushScheduleNilEntry)
		return
	}
	key, ok := a.flowKeyForScheduler(srcIP, dstIP, dstPort, proto)
	if !ok {
		return
	}
	// Record-before-Schedule order closes a same-FlowKey race against
	// a concurrent cancelAllScheduledFlows on a peer entry:
	//
	//   T1 expire → drainScheduledKeys(T1) returns {K}
	//   T1 expire → Snapshot tokenStore (sees T2)
	//   T1 expire → holdsScheduledKey(T2, K) — if T2 hasn't recorded
	//               yet this returns false and we Cancel(K), erasing
	//               the scheduler entry T2 just created
	//
	// With record first: even if T2 hasn't reached Scheduler.Schedule
	// yet, T1's cancel observes T2's tracking and re-Schedules K at
	// T2's deadline+margin. T2's subsequent Schedule is then absorbed
	// by longest-wins. A Schedule failure (breaker open, shutdown)
	// after a successful record leaves K in T2's tracked set with no
	// scheduler entry — the next Cancel walks K and Scheduler.Cancel
	// no-ops idempotently. Acceptable degradation; the alternative
	// (rollback the record on Schedule failure) would re-introduce
	// the race window we just closed.
	entry.recordScheduledKey(key)
	a.expirySched.Schedule(key, deadline)
}

// registerTempAccessFlushEntry constructs and stores a long-lived
// AccessEntry that OWNS the L3 flushes scheduled by the NAT'd /
// temp-access path (msghandler.go's tcpTempAccessHandler /
// udpTempAccessHandler). It is the #2213 fix that retires the prior
// orphan-flush path (the removed scheduleFlushOrphan), and it is a
// prerequisite for explicit admin Cancel (#2172) to terminate
// temp-access flows early.
//
// # Why a dedicated entry
//
// The temp handler writes a kernel rule whose lifetime is the long
// outer openTimeSec (often hours). The two AccessEntry pointers that
// already exist at that point don't fit, which is why the orphan path
// recorded the FlowKey on no entry at all:
//
//   - tempEntry (the auth-gate entry minted in HandleAccessControl's
//     PASS_PRE_ACCESS_IP branch) has OpenTime = TempPortOpenTime
//     (30s). Recording the FlowKey on it would let its ~35s tokenStore
//     expiry fire cancelAllScheduledFlows and Cancel the scheduled
//     flush while the kernel rule is still live for the rest of
//     openTimeSec — an ESTABLISHED-bypass under L3-only enforcement.
//   - the outer AOL admission entry's firewallDeadline +
//     accessTokenLatePacketBufferSeconds expires before the temp
//     handler's kernel rule (which can be written up to
//     tempOpenTimeSec=30s after admission), so it Cancels early too.
//
// The lifetime mismatch is structural; no pre-existing AccessEntry
// covers it. This entry closes the gap: its OpenTime is set to
// openTimeSec, so firewallDeadline() == FirstKnockTime + openTimeSec
// ≈ the kernel rule's natural TTL.
//
// # Ownership & cancelability (the point of #2213)
//
// The returned entry is stored in tokenStore via GenerateAccessToken,
// so it appears in tokenStore.Snapshot() and self-cleans via the
// OnExpire hook. The caller records every temp-rule FlowKey on it
// through scheduleFlushIfEnabled. Consequences:
//
//   - Natural expiry: OnExpire fires cancelAllScheduledFlows at
//     FirstKnockTime + openTimeSec + accessTokenLatePacketBufferSeconds,
//     which is AFTER the flush already fired at
//     computeFlushDeadline(openTimeSec) (openTimeSec +
//     flushSafetyMargin). The drain hits an already-fired scheduler
//     entry and Scheduler.Cancel no-ops idempotently — timing is
//     preserved exactly vs the orphan path (the flush still fires at
//     its deadline; only OWNERSHIP changed).
//   - Explicit admin Cancel (#2172): because the FlowKeys are now
//     OWNED, an admin Cancel walking tokenStore entries can call
//     cancelAllScheduledFlows on this entry and terminate the flow's
//     scheduled flush early. The orphan path had no owner to walk to,
//     so its scheduler entry could never be terminated before its
//     deadline.
//
// Failure-cleanup divergence from the admission path: if a per-tuple
// kernel write in the caller's loop fails mid-way, the caller returns
// and the keys already recorded on this entry are drained only at the
// natural OnExpire (openTimeSec later), NOT immediately — the temp
// handler has no equivalent of admission's emitOrCleanupPreMintedToken
// immediate drain. Acceptable and bounded: the entry is in tokenStore
// so OnExpire reaps it, and each orphaned key's own flushDeadline
// (now + openTimeSec + flushSafetyMargin) fires a self-idempotent
// no-op flush around the same moment. This matches the retired orphan
// path's behavior; converging on admission's immediate drain isn't
// worth the temp loop's added complexity for this slice.
//
// The phantom token minted here is never returned to the agent; it
// exists only to anchor the entry in tokenStore for the OnExpire /
// admin-Cancel reachability above. The agent already holds its own
// auth-gate token (tempEntry's), which it used to reach this handler,
// so no second token is exposed. The fresh &AccessEntry{} is stored
// under exactly one token, satisfying the pointer-identity invariant
// documented on the AccessEntry struct (and the nhp_debug Store
// fence): it is never re-keyed.
//
// # Cross-session safety (now that the key is owned)
//
// Recording on a real entry restores the #2201 multi-session
// reschedule path for temp-access keys: if a peer entry holds the same
// FlowKey with a later firewall deadline, cancelAllScheduledFlows
// re-Schedules rather than Cancels. With the prior orphan path this
// peer-aware behavior was impossible (the orphan registered on no
// entry, so latestOtherFirewallDeadline could neither find it as a
// peer nor protect it — the cross-cancel asymmetry the orphan godoc
// documented). Under the current AC-global IpPassMode the same K is
// never scheduled by both the AOL admission path and the temp-handler
// path on one AC, so that asymmetry was unreachable in production;
// this fix removes it structurally regardless of a future
// per-resource PassMode.
//
// SrcAddrs carries the AOL-declared agent address(es) for parity with
// tempEntry and for log/refresh shape; the scheduled FlowKeys use the
// kernel-observed (NAT'd) source IP the caller derives from the live
// connection, exactly as the orphan path did (#2205). The cancel walk
// reads only firewallDeadline + scheduledKeys, never SrcAddrs, so the
// two source views never need to agree. A corollary for the #2172
// admin-Cancel SELECTION surface: it must match these entries by their
// kernel-keyed (NAT'd) FlowKey, not by SrcAddrs — matching the
// AOL-declared IP would miss the NAT'd kernel rule this entry owns.
//
// Occupancy note (scheduler ENABLED only — the disabled config stores
// nothing, see the feature-off short-circuit below): where the orphan
// path stored nothing, every successful PASS_PRE_ACCESS_IP admission now
// parks UP TO TWO long-lived entries (lifetime openTimeSec, often hours)
// in tokenStore until natural expiry — HandleAccessControl opens both a
// TCP and a UDP temp listener on the picked port and spawns both
// tcpTempAccessHandler and udpTempAccessHandler, each of which calls
// this helper once (a TCP-keyed entry and a UDP/ANY/ICMP-keyed entry).
// This raises N for cancelAllScheduledFlows's O(K×N) walk and for each
// CleanExpired scan on a busy temp-access AC, and the #2172 admin-Cancel
// selection surface will see both owning entries per flow. There is no
// dedicated tokenStore-size alarm today; the occupancy is bounded and
// self-cleaning, folded into the same capacity model the
// cancelAllScheduledFlows godoc tracks under #2163 — the right place to
// add a size gauge/alarm if PASS_PRE_ACCESS_IP occupancy becomes
// alarm-relevant under sustained authenticated knock load.
//
// Zero-key parking edge: this entry is registered before the caller's
// FilterMode dispatch + per-tuple loop, so if FilterMode hits the
// validated-unreachable default branch (or the first kernel write
// fails) the entry is parked owning no keys until its OnExpire. Benign
// (FilterMode is validated config; the entry self-cleans), and the same
// shape as the partial-schedule failure-cleanup divergence noted above
// — not worth lazy-registration complexity that would split the
// load-bearing Schedule-then-write (#2168) interleaving.
func (a *UdpAC) registerTempAccessFlushEntry(au *common.AgentUser, srcAddrs, dstAddrs []*common.NetAddress, openTimeSec int) *AccessEntry {
	// Feature-off short-circuit: with no scheduler there is no flush to
	// own and no admin-Cancel target, so minting + storing an entry would
	// be pure tokenStore occupancy with zero benefit — and a divergence
	// from the retired orphan path, which stored nothing in EITHER config.
	// Returning nil is safe: scheduleFlushIfEnabled short-circuits on the
	// nil scheduler before its nil-entry guard, so the caller's schedule
	// calls no-op without tripping the Critical/metric.
	if a.expirySched == nil {
		return nil
	}
	entry := &AccessEntry{
		User:     au,
		SrcAddrs: srcAddrs,
		DstAddrs: dstAddrs,
		OpenTime: openTimeSec,
	}
	// GenerateAccessToken stamps FirstKnockTime/ExpireTime and Stores
	// the entry under a fresh opaque token. The token is intentionally
	// discarded — see godoc (phantom token, never sent to the agent).
	a.GenerateAccessToken(entry)
	return entry
}

// installExpiryHook wires cancelAllScheduledFlows into TokenStore's
// OnExpire callback. Extracted so tests can invoke the same wiring
// (*UdpAC).Start does without bringing up the full UDP/scheduler
// stack. No-op when the scheduler is disabled
// (cancelAllScheduledFlows checks a.expirySched). The hook runs
// outside tokenStore.mu (see SetOnExpire godoc), so scheduler
// shard locks taken inside are never held with tokenStore.mu.
func (a *UdpAC) installExpiryHook() {
	a.tokenStore.SetOnExpire(func(token string, entry *AccessEntry) {
		// Deindex BEFORE the scheduler cancel so a concurrent
		// ApplyRevocation snapshot taken after this point cannot include a
		// token whose entry is already expiring. revIndex.remove is a no-op
		// for legacy entries (no qURL v2 metadata) and nil-safe pre-Start.
		a.revIndex.remove(token, entry)
		a.cancelAllScheduledFlows(entry)
	})
}

// flowKeyForScheduler is the validation preamble for the Schedule
// path: returns (key, true) when the scheduler is enabled and
// MakeFlowKey accepts the inputs, otherwise (zero, false) with
// MetricL3FlushKeyMalformed + a Warning log already emitted. A
// malformed FlowKey here means an upstream regression let a bad IP
// / port through; the breaker is not pinged because the kernel-state
// side is already settled.
//
// Single caller: scheduleFlushIfEnabled. The Cancel path
// (cancelAllScheduledFlows) does not go through this helper —
// it walks per-entry tracked FlowKeys directly (#2201/#2205) so
// there's nothing to validate; the keys are already-validated
// outputs from prior Schedule calls.
//
// The nil-scheduler guard returns (zero, false) silently — no metric
// tick, no log. scheduleFlushIfEnabled also short-circuits on
// a.expirySched == nil upstream (via the entry/scheduler nil-guards
// at the top), so the silent return here is unreachable today. Kept
// as defense-in-depth so a future caller that lands a new path can't
// nil-deref MakeFlowKey via a stale `expirySched` field — better to
// drop the schedule silently than to crash the AC.
func (a *UdpAC) flowKeyForScheduler(srcIP, dstIP string, dstPort int, proto FlowProto) (FlowKey, bool) {
	if a.expirySched == nil {
		return FlowKey{}, false
	}
	key, err := MakeFlowKey(srcIP, dstIP, dstPort, proto)
	if err != nil {
		a.incrMetric(MetricL3FlushKeyMalformed)
		log.Warning("[L3FlushSched] skipping schedule for malformed FlowKey src=%s dst=%s port=%d: %v",
			srcIP, dstIP, dstPort, err)
		return FlowKey{}, false
	}
	return key, true
}

// cancelAllScheduledFlows cancels (or reschedules to next-longest)
// every FlowKey the entry actually scheduled. Called from
// /refresh-shorten in httpac.go and from the TokenStore.OnExpire
// hook wired in (*UdpAC).Start.
//
// Walks entry.scheduledKeys (populated by scheduleFlushIfEnabled at
// Schedule time). Drain-then-walk — never holds entry.mu across a
// Scheduler.Cancel / Schedule call, satisfying the lock order in
// endpoints/ac/CLAUDE.md (entry.mu is leaf-most). Idempotent: a
// second call drains an empty set and returns.
//
// Closes #2205 (NAT'd temp-access where the kernel-observed
// remoteAddr.IP differs from the AOL-declared entry.SrcAddrs): the
// temp handler records FlowKeys with the kernel IP, so this walk
// hits the same FlowKey that was scheduled — Cancel matches the
// kernel state that was written.
//
// Closes #2201 (multi-session shared-FlowKey races) with the
// per-key tokenStore consult described in the plan: for each drained
// key, scan tokenStore for any OTHER live AccessEntry that holds the
// same key. If one exists with a still-future firewall deadline, the
// scheduler entry must survive for that session — re-Schedule to the
// other entry's deadline so longest-wins absorb keeps the entry
// alive. Only when no other live entry covers the key do we Cancel.
//
// Cost model: O(K × N) per cancel where K is the entry's tracked
// keys (typically 1–3) and N is tokenStore size. Acceptable at
// current scale (hundreds of entries). At million-session scale a
// reverse FlowKey → entry index becomes worth adding; tracked in
// the capacity audit (#2163).
//
// Snapshot semantics: Snapshot returns entry pointers under
// tokenStore.mu. If a peer entry T2 is Delete()'d from tokenStore
// (silent — no OnExpire) between Snapshot and the per-key
// holdsScheduledKey(T2, ...) check, the check still returns true:
// the entry pointer is alive in the snapshot slice and its
// scheduledKeys hasn't been drained. This is the desired behavior
// — we preserve scheduler coverage for any AccessEntry with a
// live firewall window, not just live tokenStore presence — but
// it's subtle, so don't re-snapshot per key in a future "fix."
//
// Re-Schedule margin: maxOtherDeadline.Add(flushSafetyMargin)
// APPROXIMATELY matches the peer's original Schedule deadline.
// The peer's scheduleFlushIfEnabled used
// computeFlushDeadline(openTimeSec) = time.Now() + OpenTime +
// flushSafetyMargin; the reschedule reads
// peer.FirstKnockTime + OpenTime + flushSafetyMargin. The
// difference is ε — the drift between GenerateAccessToken
// stamping FirstKnockTime and scheduleFlushIfEnabled running.
// Upper bound on ε is HandleAccessControl's pre-schedule
// preamble: FilterMode dispatch + per-tuple IP validation +
// ipset/BPF setup before the first scheduleFlushIfEnabled call.
// Sub-millisecond in the common case; bounded by single-digit
// milliseconds at the high end under burst-admission load.
// Always small enough that the reschedule deadline lands within
// the same scheduler tick (10ms wheel resolution) as the
// original — the kernel-state-side late-fire window is bounded
// by that tick, not by ε. Scheduler longest-wins absorb handles
// the residual gap: if the original schedule's deadline was
// slightly later, it stays; if the reschedule is later, it wins.
// Boot-enumeration paths in expiry_enumerate_*_linux.go also call
// Scheduler.Schedule directly but do NOT recordScheduledKey on any
// AccessEntry, so they don't appear as candidates in
// latestOtherFirewallDeadline's walk (holdsScheduledKey returns
// false for them). The margin assumption is therefore correct for
// every key that CAN be in candidates. A future Schedule call site
// that DOES record on an AccessEntry with a different deadline
// derivation would silently drift the reschedule logic — route all
// admission/refresh-style Schedule calls through
// scheduleFlushIfEnabled + computeFlushDeadline.
//
// Multi-session protection scope: only fires across DIFFERENT
// cleanup events. If T1 and T2 expire in the SAME CleanExpired
// tick, tokenStore.CleanExpired removes both under ts.mu BEFORE
// firing the OnExpire batch — T1's Snapshot doesn't see T2, so
// the shared key Cancels. This is correct because both firewalls
// closed on the same tick boundary (both already past their
// FirstKnockTime + OpenTime). The protection IS load-bearing
// across:
//   - OnExpire fired on T1 while T2 is still admitting / live
//   - /refresh-shorten on T1 while T2 holds the shared FlowKey
//   - Two separate CleanExpired ticks, one per session
//
// Concurrent call to the same entry (e.g., /refresh-shorten races
// with OnExpire on the same token) is safe: drainScheduledKeys's
// e.mu serializes the drain, so the second caller drains nil and
// walks nothing. /refresh-shorten DOES NOT tokenStore.Delete the
// entry; only CleanExpired does — see httpac.go for that
// asymmetry.
//
// Self-skip in latestOtherFirewallDeadline depends on the pointer-
// identity invariant documented on the AccessEntry struct godoc
// (each *AccessEntry is in tokenStore under exactly one token).
// Both callers of this function (OnExpire and emitOrCleanupPreMintedToken)
// rely on it; #2214 / #2215 file stronger guards before any
// AccessEntry pool/reuse refactor.
func (a *UdpAC) cancelAllScheduledFlows(entry *AccessEntry) {
	if a.expirySched == nil || entry == nil {
		return
	}
	keys := entry.drainScheduledKeys()
	if len(keys) == 0 {
		return
	}
	// Snapshot tokenStore once for all keys — multi-session sharing is
	// uncommon, but when it happens the snapshot is consulted per key.
	// Nil tokenStore is a programmer error in production (Start always
	// constructs it) — log Critical + tick a metric so a future
	// dependency-injection refactor that drops the field is loudly
	// visible rather than silently regressing the #2201 multi-session
	// protection. Test paths that intentionally exercise this branch
	// pass entries with empty scheduledKeys, so the early-return
	// upstream short-circuits before reaching here.
	var candidates []*AccessEntry
	if a.tokenStore != nil {
		candidates = a.tokenStore.Snapshot()
	} else {
		log.Critical("[L3FlushSched] cancelAllScheduledFlows called with nil tokenStore — multi-session protection degraded to lone-entry behavior")
		a.incrMetric(MetricL3FlushCancelNilTokenStore)
	}
	// now captured once and reused across the key loop — matches
	// Snapshot's point-in-time semantic; liveness check is "are any
	// peers live AS OF THIS CANCEL" rather than per-key fresh time.
	// Observable consequence: an entry whose firewall closes during
	// the cancel walk is still treated as live for keys later in the
	// drain. Benign — the re-Schedule deadline is at most sub-second
	// past the actual close moment and the kernel-state side has
	// already self-expired by its TTL, so the late Flush is an ENOENT
	// no-op per the flusher's idempotency contract.
	now := time.Now()
	for _, key := range keys {
		maxOtherDeadline := a.latestOtherFirewallDeadline(candidates, entry, key, now)
		if maxOtherDeadline.IsZero() {
			a.expirySched.Cancel(key)
			continue
		}
		// Another live entry still needs this FlowKey. Re-Schedule
		// at its firewall deadline + the same safety margin
		// scheduleFlushIfEnabled applies, so longest-wins absorb
		// keeps the scheduler entry at the correct moment. Schedule
		// (not Cancel-then-Schedule) so any in-flight Flush barrier
		// inside the scheduler holds — see Scheduler.Schedule godoc
		// in expiry_scheduler.go for the inFlight-marker semantics
		// this preserves (#2168).
		a.expirySched.Schedule(key, maxOtherDeadline.Add(flushSafetyMargin))
		a.incrMetric(MetricL3FlushCancelRescheduledForPeer)
	}
}

// latestOtherFirewallDeadline scans candidates for any AccessEntry
// other than self that holds key in its tracked set AND whose
// firewall deadline (FirstKnockTime + OpenTime) is still in the
// future. Returns the latest such deadline, or the zero time if no
// other live entry needs the key.
//
// The "other live entry" check is what closes #2201 — pre-fix code
// canceled the shared FlowKey unconditionally, orphaning any
// concurrent session that had absorbed into the same scheduler
// entry via longest-wins. Walking tracked sets directly (rather
// than recomputing FlowKey shapes from address fields) means
// candidates that happened to share an IP-tuple but never actually
// scheduled the key don't count as "needs the key."
//
// Self-skip via pointer equality (`other == self`) relies on the
// invariant that each AccessEntry pointer is stored under exactly
// one token in tokenStore. Production preserves this: every
// admission allocates a fresh &AccessEntry{} in HandleUdpACOperations
// and never reuses pointers across tokens. A future refactor that
// pools or reuses entry pointers (e.g., connection-pool style
// optimization) would let self show up multiple times in the
// snapshot, each non-self instance falsely registering as an
// "other holder" and keeping scheduler entries alive past their
// genuine deadlines. Guard that invariant when extending the entry
// lifecycle.
//
// Receiver is *UdpAC even though the function reads no a-state —
// surfaces cleanly in pprof / stack traces as part of UdpAC's
// L3-flush surface rather than as an orphaned free function.
func (a *UdpAC) latestOtherFirewallDeadline(candidates []*AccessEntry, self *AccessEntry, key FlowKey, now time.Time) time.Time {
	var latest time.Time
	for _, other := range candidates {
		if other == nil || other == self {
			continue
		}
		if !other.holdsScheduledKey(key) {
			continue
		}
		firewallEnd := other.firewallDeadline()
		if firewallEnd.After(now) && firewallEnd.After(latest) {
			latest = firewallEnd
		}
	}
	return latest
}

// incrMetric is the centralized increment site for AC counters,
// nil-safe on both a.registration and the publisher (the latter is
// guaranteed by Publisher.IncrCounter's nil-receiver check). Every
// metric-publishing call site in this file should route through
// here so the nil-discipline lives in one place.
func (a *UdpAC) incrMetric(name string) {
	if reg := a.registration; reg != nil {
		reg.metrics.IncrCounter(name)
	}
}

// addMetric adds value to an AC counter in one publish, the batched analog
// of incrMetric. Same nil-discipline (nil registration / nil publisher are
// no-ops). Used by the revocation apply path to report N entries flushed
// without N separate IncrCounter calls.
func (a *UdpAC) addMetric(name string, value uint64) {
	if reg := a.registration; reg != nil {
		reg.metrics.AddCounterWithDims(name, float64(value), nil)
	}
}

// recordTransactionClosed increments MetricTransactionClosed iff err
// is common.ErrTransactionClosed. Nil-safety is delegated to
// incrMetric.
func (a *UdpAC) recordTransactionClosed(err error) {
	if err == nil {
		return
	}
	if errors.Is(err, common.ErrTransactionClosed) {
		a.incrMetric(MetricTransactionClosed)
	}
}

// recoverUDPHandler catches panics on every per-packet goroutine on
// the AC's UDP message-handler path: the recvMessageRoutine entries
// (NHP_AOP, NHP_ARD, NHP_REV) and every goroutine they transitively spawn
// (HandleAccessControl's tcpTempAccessHandler / udpTempAccessHandler
// and the tempConnTerminator nested inside each of those). It logs
// the panic value + stack at Error and increments
// MetricUDPHandlerPanic so the alarm in
// terraform/modules/ac/monitoring.tf fires on the next flush.
//
// Both defers (a.wg.Done and a.recoverUDPHandler) must be at the
// goroutine ENTRY, not nested inside the handler — pushing the
// recover into HandleUdpACOperations would silently swallow panics
// in msghandler_test.go's direct test callers. The relative order
// of the two defers is functionally equivalent (Go runs every
// deferred function in LIFO order even if an earlier defer panicked,
// and a recovered panic does not propagate), so wg.Done is reached
// either way; the convention here is wg.Done first → recover second
// purely for grep-symmetry across spawn sites.
//
// headerType is the NHP message type that triggered the goroutine
// (matches the type of core.PacketParserData.HeaderType used by the
// inner handlers); core.HeaderTypeToString stringifies it for the
// log line. Goroutines spawned downstream (the temp-access handlers)
// re-use NHP_AOP since that's the message type that initiated the
// access-control flow.
func (a *UdpAC) recoverUDPHandler(headerType int) {
	r := recover()
	if r == nil {
		return
	}
	// Read ACId via a local with a nil fallback because this is the
	// one place in the codebase where being more defensive than the
	// surrounding code has asymmetric value: a panic inside this
	// deferred handler is itself unrecovered and would kill the
	// process — exactly what the PR exists to prevent. The rest of
	// udpac.go derefs both a.config and a.registration freely; in
	// practice both are read-once-and-never-reassigned (set during
	// Start() / NewACRegistration() and not mutated thereafter), so
	// the nil-guards here (and the matching `if reg := a.registration`
	// in incrMetric) are defense-in-depth against a hypothetical
	// future hot-reload-style refactor, not against a concurrent
	// nil. If config ever becomes hot-reloadable, the nil-fallback
	// here also fences the racing-mutation case — the field is read
	// once into the local without holding any lock.
	acId := "<nil-config>"
	if a.config != nil {
		acId = a.config.ACId
	}
	log.Error("ac(%s)[%s] panic recovered: %v\n%s",
		acId, core.HeaderTypeToString(headerType), r, string(debug.Stack()))
	a.incrMetric(MetricUDPHandlerPanic)
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
		SendQueue:            make(chan *core.Packet, PacketQueueSizePerConnection),
		RecvQueue:            make(chan *core.Packet, PacketQueueSizePerConnection),
		BlockSignal:          make(chan struct{}),
		SetTimeoutSignal:     make(chan struct{}, 1),
		StopSignal:           make(chan struct{}),
	}
	conn.ConnData.InitTimeoutMs(DefaultConnectionTimeoutMs)

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

		// Snapshot MinimalLength() before ReleasePoolPacket: the release
		// nils pkt.Content, so a post-release call panics via unsafe.Pointer
		// deref. Fenced by TestPacketMinimalLengthPanicsAfterRelease.
		minLen := pkt.MinimalLength()
		if n < minLen {
			a.device.ReleasePoolPacket(pkt)
			log.Error("[AC] received UDP packet from %s is too short (%d bytes, min %d), discarding", actualSource, n, minLen)
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

	// Cached read of TimeoutMs(); refreshed on SetTimeoutSignal.
	// Pre-existing race at the boundary: select is uniformly random when
	// multiple cases ready, so idleTimer.C can win over a ready queue case.
	// Recovery differs per endpoint: AC re-establishes via serverDiscovery
	// (this routine), DB likewise; server/agent rely on the peer reconnecting
	// (agent re-knock; server has no client side, the next AC/DB AOL/DOL
	// builds a fresh conn).
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
			// Reset before any early-`continue` (nil/KPL/matched-tx) so all paths count as activity, deliberately matching pre-PR per-iteration time.After. Fence: udpac_test.go.
			idleTimer.Reset(idleTimeout)
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
			idleTimer.Reset(idleTimeout)
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
					defer a.wg.Done()
					defer a.recoverUDPHandler(core.NHP_AOP)
					// Note: this errors.Is filter is bypassed when
					// HandleUdpACOperations panics — control jumps
					// straight to the deferred recoverUDPHandler.
					// That's the intended behavior; the filter only
					// shapes the *error-returning* path here.
					if err := a.HandleUdpACOperations(ppd); err != nil {
						// HandleUdpACOperations already logs both the
						// duplicate drop (Warning) and the
						// missing-pubkey upstream-invariant violation
						// (Critical) with full context (acId, txid,
						// header type). Re-logging at this seam adds
						// noise without information.
						if errors.Is(err, common.ErrACDuplicateTransaction) ||
							errors.Is(err, common.ErrACMissingPeerPubkey) {
							return
						}
						log.Error("HandleUdpACOperations failed: %v", err)
					}
				}()

			case core.NHP_ARD:
				// Handle AC redispatch to assigned servers. wg-track
				// so Stop()'s wg.Wait() blocks until in-flight
				// redispatches return (#1655); pre-fix the goroutine
				// could outlive Stop() entirely. The use-after-stop
				// window is closed inside ACRegistration.HandleRedispatch
				// via an r.stopped.Load() gate (#1657).
				a.wg.Add(1)
				go func() {
					defer a.wg.Done()
					defer a.recoverUDPHandler(core.NHP_ARD)
					a.HandleACRedispatch(ppd)
				}()

			case core.NHP_REV:
				// Handle a qURL v2 immediate-revocation push from the
				// server (P4e). wg-tracked like NHP_ARD so Stop()'s
				// wg.Wait() blocks until an in-flight revoke apply
				// returns. HandleUdpACRevocation validates the event and
				// calls the P4b ApplyRevocation primitive; it logs every
				// outcome (parse/validation reject AND apply result) with
				// full context itself, so — like the NHP_ARD seam — this
				// dispatch arm does not re-log the returned error (the
				// NHP_AOP seam comment above: re-logging here adds noise
				// without information). The error return exists for the
				// direct test callers. There is no NHP_ART response path,
				// so nothing to forward.
				a.wg.Add(1)
				go func() {
					defer a.wg.Done()
					defer a.recoverUDPHandler(core.NHP_REV)
					_ = a.HandleUdpACRevocation(ppd)
				}()
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

			checkTimer := time.NewTimer(MinimalServerDiscoveryInterval * time.Second)
			defer checkTimer.Stop()
			for {
				select {
				case <-a.signals.stop:
					return
				case <-quitCheck:
					return
				case <-checkTimer.C:
					// Reset before work: cloud-mode `continue` below would skip a reset placed at the bottom.
					// Cycle ≈ interval (vs interval+work_time pre-PR). iptables fork+exec is 10-50ms — well under
					// the 5s interval. If work ever approaches the interval, move Reset to the bottom.
					checkTimer.Reset(MinimalServerDiscoveryInterval * time.Second)
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

	discoveryTimer := core.NewStoppedTimer()
	defer discoveryTimer.Stop()

	for {
		// Re-resolve server address each iteration to pick up DNS changes.
		// Note: ResolveHost() internally caches results for MinimalNSLookupInterval (300s)
		sendAddr := server.SendAddr()
		if sendAddr == nil {
			log.Error("Cannot resolve server address for %s, will retry in %ds", server.Hostname, MinimalServerDiscoveryInterval)
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

		discoveryTimer.Reset(MinimalServerDiscoveryInterval * time.Second)
		select {
		case <-a.signals.stop:
			return
		case <-quit:
			return
		case <-discoveryTimer.C:
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
			// ARDs that arrive during teardown are expected and bounded
			// by the in-flight count at Stop; logging them at Error
			// would noise up alerting during rolling deploys.
			if errors.Is(err, ErrRegistrationStopped) {
				log.Debug("ac(%s)[HandleACRedispatch] dropped post-stop ARD with %d targets", a.config.ACId, len(ardMsg.Targets))
			} else {
				log.Error("ac(%s)[HandleACRedispatch] failed to process redispatch: %v", a.config.ACId, err)
			}
		}
	} else {
		log.Warning("ac(%s)[HandleACRedispatch] registration manager not initialized", a.config.ACId)
	}
}
