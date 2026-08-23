package server

import (
	"container/list"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	runtimemetrics "runtime/metrics"
	"sort"
	"strings"

	"strconv"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/OpenNHP/opennhp/nhp/etcd"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/pion/webrtc/v4"
	"golang.org/x/sync/semaphore"

	"github.com/OpenNHP/opennhp/endpoints/metrics"
	"github.com/OpenNHP/opennhp/endpoints/server/internal/qurlplacement"
	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
	"github.com/OpenNHP/opennhp/nhp/log"
	"github.com/OpenNHP/opennhp/nhp/plugins"
	"github.com/OpenNHP/opennhp/nhp/utils"
	"github.com/OpenNHP/opennhp/nhp/version"
	"github.com/layervai/nhp/internalauth"
)

var (
	ExeDirPath string

	errUnknownServerPeerTarget = errors.New("outbound address is not a known server peer target")
	errServerPeerTupleOwned    = errors.New("outbound server-peer address already owned by non-promotable connection")
	errOutboundServerGlobalCap = errors.New("outbound server-peer global cap reached")
	errOutboundServerStopping  = errors.New("server stopping")
)

// dimNameInstanceId is the canonical CloudWatch dimension name for
// per-instance metrics. Single source of truth so a typo (e.g.,
// "InstanceID") can't silently split the time series across two
// dimension values.
var dimNameInstanceId = aws.String("InstanceId")

// buildServerEnvDimension returns the [Environment]-ONLY CloudWatch dimension set
// (the fleet-wide dim, no Cell). It is the base of buildServerMetricDimensions and
// is also the exact set a fleet-wide alarm must select — e.g. the agent-OTP-shed
// launch-blocking alarm keys on {Environment} only, so OTPRejectRateLimited is
// dual-published at this set (via the publisher's explicit-dims emit) in ADDITION
// to the [Environment, Cell] breakdown. Sourced from the SAME NHP_ENVIRONMENT var
// as the full dim set so the Environment value can never drift between the base
// stream and the breakdown (a drift would land the base metric at a different
// Environment and silently blind the alarm — cf. the relay's buildRelayMetricDimensions
// NB note). Keep NHP_ENVIRONMENT wired in user_data.
func buildServerEnvDimension() []types.Dimension {
	return []types.Dimension{
		{Name: aws.String("Environment"), Value: aws.String(serverEnvironmentValue())},
	}
}

// serverEnvironmentValue is the single source of the Environment dimension value
// (NHP_ENVIRONMENT, "unknown" fallback). Shared by buildServerEnvDimension and
// buildServerMetricDimensions so the Environment value can never drift between the
// [Environment]-only base (used by the OTPRejectRateLimited dual-publish) and the
// full [Environment, Cell] set.
func serverEnvironmentValue() string {
	environment := os.Getenv("NHP_ENVIRONMENT")
	if environment == "" {
		environment = "unknown"
	}
	return environment
}

// buildServerMetricDimensions returns the CloudWatch dimensions derived from environment
// variables. Dimensions: [Environment, Cell]. CloudWatch alarms and Grafana dashboard
// panels match on this exact set. Adding or removing dimensions creates a separate
// metric time series that existing alarms/panels won't find.
func buildServerMetricDimensions() []types.Dimension {
	cellID := os.Getenv("NHP_CELL_ID")
	if cellID == "" {
		cellID = "cell0"
	}

	// [Environment, Cell], listed literally. Environment uses the same package
	// `environment` value as buildServerEnvDimension (the [Environment]-only base the
	// OTPRejectRateLimited dual-publish emits), so the value cannot drift between the
	// two. The names are pinned here directly — not via append(buildServerEnvDimension(),
	// …) — because observability-parity's static fence matches the relay_forward_reject
	// alarm's dimension selectors against this builder's own body.
	return []types.Dimension{
		{Name: aws.String("Environment"), Value: aws.String(serverEnvironmentValue())},
		{Name: aws.String("Cell"), Value: aws.String(cellID)},
	}
}

type UdpServer struct {
	stats struct {
		totalRecvBytes uint64
		totalSendBytes uint64
	}

	config        *Config
	httpConfig    *HttpConfig
	log           *log.Logger
	listenAddr    *net.UDPAddr
	listenAddrStr string
	listenConn    *net.UDPConn
	// SetWriteDeadline is socket-global. The weighted gate admits concurrent
	// ordinary writes but makes deadline mutation exclusive; udpWriteSocket is
	// a private test seam and is nil in production.
	udpWriteGateOnce      sync.Once
	udpWriteGate          *semaphore.Weighted
	udpWriteDeadlineDirty atomic.Bool
	udpWriteSocket        udpWriteSocket
	localIp               string
	localMac              string

	device       *core.Device
	httpServer   *HttpServer
	webrtcServer *WebRTCServer
	wg           sync.WaitGroup
	// cookieSigningKeyClearedWarned suppresses repeated SIGHUP noise after an
	// operator clears CookieSigningKeyBase64. The running key intentionally
	// stays in memory until restart, so the cached config keeps the last known
	// good key and would otherwise look changed forever.
	cookieSigningKeyClearedWarned bool
	// overloadCookieProcessLocalKey tracks whether this process currently uses
	// a random fallback overload-cookie key. It backs the CloudWatch gauge, so
	// reload paths that install a shared key must clear it.
	overloadCookieProcessLocalKey atomic.Bool
	// outboundConnStartMutex serializes connDataForOutboundAddr's late
	// server-peer connectionRoutine wg.Add calls with Stop's transition
	// to wg.Wait. Static Start-time Add calls don't use it.
	outboundConnStartMutex sync.Mutex
	running                atomic.Bool

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

	// acPubkeyRevokeVerifyRequire gates strict-mode rejection of AC
	// registrations whose presented static pubkey appears in
	// ACAssignment.RevokedPubKeys for the claimed acId. Read once at
	// Start from ACPubkeyRevokeVerifyEnvVar — see
	// ac_pubkey_revoke_gate.go for the gate policy and #1507 (parent
	// #1157 F5) for the threat model.
	//
	// Concurrency: same contract as licensePubkeyVerifyRequire.
	acPubkeyRevokeVerifyRequire bool
	// acPubkeyRevokeSweepInterval controls the F5 mid-session drop
	// sweeper. Parsed once at Start from
	// NHP_AC_PUBKEY_REVOKE_SWEEP_INTERVAL_SECONDS; zero disables the
	// background sweep. The sweeper itself only starts when the F5
	// revoke gate is strict and the server is in DynamoDB cloud mode.
	acPubkeyRevokeSweepInterval time.Duration

	// revocationRetry is the qURL v2 NHP_REV retry-until-ack-or-age-out
	// engine (P4e Slice 3, #2793). nil = engine disabled (absent-env binary
	// default for unmanaged/pre-ACK fleets; Terraform-managed fleets set
	// NHP_REVOCATION_RETRY_ENABLED=true). When non-nil, the
	// fanout handler records a pending entry per targeted AC slot
	// (acId + authenticated pubkey), the
	// revocationRetryRoutine retransmits un-acked NHP_REV on a cadence
	// until acked (NHP_RVA clears it) or aged out (RevocationAgedOut),
	// and HandleRevocationAck clears the matching entry. See
	// revocation_retry.go.
	revocationRetry *revocationRetryTracker

	// connection and remote transaction management

	remoteConnectionMapMutex sync.Mutex
	remoteConnectionMap      map[string]*UdpConn   // indexed by remote UDP address
	connectionsByIP          map[string]*list.List // per-IP FIFO of capped agent UDP conns; infra conns excluded

	agentPeerMapMutex sync.Mutex
	agentPeerMap      map[string]*core.UdpPeer // indexed by peer's public key base64 string

	acConnectionMapMutex sync.RWMutex
	// acConnectionMap holds AC connections per acId. Multiple entries
	// per acId support blue/green AC fleets sharing one acId.
	//
	// Identity invariant: each entry's stable identity is the AC's
	// PubKeyBase64, NOT its (IP, port). HandleACOnline matches by
	// pubkey for in-place replacement so a same-pubkey reconnect
	// from a new (IP, port) — NAT rebind, EIP swap, AC daemon
	// restart, server-driven redispatch — replaces its existing
	// slot rather than appending. Pre-#1157 the match was by IP and
	// same-pubkey-new-IP reconnects appended, filling the slice
	// past MaxACConnsPerID and FIFO-evicting a DIFFERENT AC's last
	// slot — a silent de-listing from AOP broadcast while the NLB
	// kept routing client traffic to the evicted AC.
	//
	// Cap: MaxACConnsPerID, enforced as a DISTINCT-PUBKEY cap by
	// the F3 gate (ac_pubkey_cap_gate.go) and as a backstop
	// connection-list cap by HandleACOnline's append branch. With
	// same-pubkey replacement, the backstop fires only on
	// distinct-pubkey overflow.
	acConnectionMap map[string][]*ACConn

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
	// connectorRegistrationHandler is the strict qURL Connector assigned-cell
	// OTP/activation/completion capability. Nil is the dark, absent-config state.
	// It is constructed before the listener binds and intercepts only exact
	// top-level aspId=agent registration intent before generic plugin dispatch.
	connectorRegistrationHandler connectorRegistrationHandler
	// connectorRegistrationTiming is populated atomically with the handler from
	// the same all-or-none startup contract. It has no runtime defaults.
	connectorRegistrationTiming connectorRegistrationTiming
	// observeConnectorRegistrationRejectedBodyCleared is a TEST-ONLY SEAM proving
	// registration secrets rejected on non-direct ingress are cleared before return.
	observeConnectorRegistrationRejectedBodyCleared func([]byte)
	// observeRelayRejectedBodyCleared is a TEST-ONLY SEAM proving generic
	// authenticated-relay rejection clears decrypted bodies. Production leaves nil.
	observeRelayRejectedBodyCleared func([]byte)
	// observePreCheckThreatCache is a TEST-ONLY SEAM that exposes the otherwise
	// receive-routine-local cache so the real UDP path can assert that the
	// unauthenticated KPL exception never clears threat history. Production nil.
	observePreCheckThreatCache func(*preCheckThreatCache)
	// credentialRecoveryHandler is the direct-UDP-only assigned-cell recovery
	// capability. Nil is the dark, absent-configuration state. It is constructed
	// once during Start before the listener binds and is never exposed to relay or
	// generic plugin dispatch.
	credentialRecoveryHandler credentialRecoveryDirectHandler
	// connectorResourceHandler is the strict post-registration resource
	// discovery capability. Exact connector_resource LSTs are claimed even while
	// this is nil so they cannot reach generic ListService dispatch.
	connectorResourceHandler connectorResourceDirectHandler

	// signals
	signals struct {
		stop chan struct{}
	}

	// lifecycleCtx is canceled by Stop() so in-flight, async work
	// dispatched off the receive path (DDB Query inside
	// resolveAgentPeerForKnock today) abandons promptly on shutdown
	// rather than waiting out its per-call timeout. Initialized in
	// Start(), canceled in Stop() alongside close(signals.stop).
	lifecycleCtx    context.Context
	lifecycleCancel context.CancelFunc

	recvMsgCh <-chan *core.PacketParserData
	sendMsgCh chan *core.MsgData

	//NHP-DB
	dbPeerMapMutex sync.Mutex
	dbPeerMap      map[string]*core.UdpPeer // indexed by peer's public key base64 string

	// NHP-RELAY (#2208)
	relayPeerMapMutex sync.Mutex
	relayPeerMap      map[string]*core.UdpPeer // NHP_RELAY peers (relay.toml), indexed by public key base64

	teeMapMutex sync.Mutex
	teeMap      map[string]*TeeAttestationReport // indexed by tee's measure

	// etcd client
	etcdConn                *etcd.EtcdConn
	remoteConfigUpdateMutex sync.Mutex

	// Pluggable storage backend (DynamoDB for cloud, etcd for on-prem)
	// See docs/design/PLUGGABLE_STORAGE_BACKEND.md for architecture details.
	storage       StorageBackend // DynamoDB (cloud) or etcd (on-prem)
	storageConfig *StorageConfig
	// sessionControlStore is separate from StorageBackend because routing
	// assignments expire and may be rewritten, while session authority and
	// pending close work must survive disconnects and process restarts.
	sessionControlStore sessionControlStore
	// sessionControlCellID is the canonical NHP_CELL_ID resolved exactly once
	// during cloud Start before the UDP listener binds. It is immutable after
	// Start and is the cell authority used by AOL fence snapshots/activation.
	sessionControlCellID string
	// acSessionControlAdmission serializes the durable Prepare -> catch-up ->
	// Activate -> publish transition per AC identity. Its bookkeeping mutex is
	// never held while waiting for the keyed mutex and the keyed mutex is never
	// nested with server map locks; store/network work therefore cannot block a
	// global connection-map critical section.
	acSessionControlAdmissionMu sync.Mutex
	acSessionControlAdmissions  map[string]*acSessionControlAdmissionLock
	// acSessionControlAuthorityGates linearize AOP enqueue with AOL authority
	// transitions per exact AC ID/public-key target. AOP holds one read unit from
	// its final readiness check through send enqueue; AOL holds the full weight
	// through Prepare/catch-up/Activate, publication, and AAK enqueue. The map
	// bookkeeping mutex is never held while acquiring or doing store/network work.
	acSessionControlAuthorityGatesMu sync.Mutex
	acSessionControlAuthorityGates   map[acSessionControlAuthorityGateKey]*acSessionControlAuthorityGate
	// sessionControlCellGate closes the same-process interval between durable
	// session admission and exact-close preparation. The global acquisition
	// order is owner gate before cell gate: AOP takes both read sides through its
	// final durable intent/readiness checks and send enqueue; AOL takes owner
	// write then cell read; close preparation takes only cell write. Never retain
	// either read gate while invoking close compensation.
	sessionControlCellGateOnce sync.Once
	sessionControlCellGate     *semaphore.Weighted
	// acSessionControlFenceWaiters correlates the strict, unsolicited NHP_RVA
	// push acknowledgement with the exact pre-publication AC connection and
	// durable fence. NHP_REV is intentionally not a core transaction request,
	// so this registry is independent of Device.LocalTransactionMap. Its mutex
	// is leaf-local and is never held across network or store operations.
	acSessionControlFenceWaitersMu sync.Mutex
	acSessionControlFenceWaiters   map[acSessionControlFenceWaiterKey]*acSessionControlFenceWaiter
	// sendACSessionControlFenceFn is a test-only seam for the synchronous strict
	// REV/RVA catch-up exchange. Production leaves it nil.
	sendACSessionControlFenceFn func(context.Context, *ACConn, sessionControlFenceAuthority) error
	// sendACSessionControlTaskFn is the exact-ACK variant used by durable task
	// delivery. Production leaves it nil; tests can observe the decoded RVA
	// without constructing encrypted UDP packets.
	sendACSessionControlTaskFn func(context.Context, *ACConn, sessionControlExactCloseTaskAuthority) (common.ACSessionCloseAckMsg, error)
	// sessionControlAOLBudget is a test-only seam for deterministically proving
	// that the pre-AAK durable publication proof does not inherit an exhausted
	// catch-up budget.
	// Production leaves it zero and HandleACOnline uses DefaultStorageTimeout.
	sessionControlAOLBudget time.Duration
	sessionControlRecovery  sessionControlRecoveryRuntime
	forwarder               *ServerForwarder // Server-to-server knock forwarding

	// agentSessions is the authoritative process-local base NHP session
	// allocator/close registry. Lazy initialization keeps bare unit-test server
	// literals safe while Start initializes it before the listener accepts work.
	agentSessionsOnce sync.Once
	agentSessions     *liveNHPSessionRegistry
	// acSessionOwnerID is a random per-process boot identity. The fleet shares
	// one Noise server key, so AC session indexes require this additional
	// authenticated AOP/ART scope to isolate same-ID sessions across processes.
	acSessionOwnerOnce sync.Once
	acSessionOwnerID   string
	acSessionOwnerErr  error
	// agentSessionCloseWork coalesces duplicate direct and fleet EXT work by
	// authenticated agent key. One handler remains the leader for local retries
	// and origin fan-out; followers advance its cutoff/deadline and return rather
	// than consuming another handler slot for the same close loop.
	agentSessionCloseWorkMu              sync.Mutex
	agentSessionCloseWork                map[string]*agentSessionCloseWork
	agentSessionCloseWorkerMu            sync.Mutex
	agentSessionCloseWorkerWG            sync.WaitGroup
	agentSessionCloseWorkersStopping     bool
	agentSessionCloseWorkerActive        int
	agentSessionClosePriorityQueue       []func()
	agentSessionCloseRegularQueue        []func()
	agentSessionClosePriorityOutstanding int
	agentSessionCloseRegularOutstanding  int
	// agentSessionCloseBeforeFinalizeFn is a deterministic test barrier for the
	// follower-at-finalization race. Production leaves it nil.
	agentSessionCloseBeforeFinalizeFn func()
	// processACSessionCloseFn is a test seam for the bodyless EXT close worker.
	// Production always leaves it nil and uses processACSessionClose.
	processACSessionCloseFn func(context.Context, uint64, *ACConn) error
	// broadcastAgentSessionCloseFn is a test seam for shutdown/cancellation of
	// the origin fan-out. Production leaves it nil and uses Cloud Map plus direct
	// private HTTP; it never enters the bounded NHP peer-forwarding cache.
	broadcastAgentSessionCloseFn func(context.Context, *agentSessionCloseFleetEvent)
	fleetCloseSigner             *internalauth.Signer
	fleetCloseHTTPClient         *http.Client
	// fleetCloseHTTPPortAllowedFn is a test-only seam for loopback listeners
	// allocated on ephemeral ports. Production leaves it nil and accepts only
	// ports matched by the Terraform VPC ingress contract.
	fleetCloseHTTPPortAllowedFn func(int) bool

	// Cloud Map client for server health discovery.
	// Used to filter stale AC assignments pointing to terminated servers.
	cloudMap *CloudMapClient

	// EC2 instance identity (populated from IMDS in cloud mode).
	// Boot may write a partial set if AZ/Name fetch hiccups; the refresh
	// goroutine re-fetches in that case via fetchInstanceIdentityFromIMDS,
	// so these are NOT effectively-immutable post-Start. Read concurrently
	// by packet-handler goroutines (every NHP_AAK reads instanceAZ and
	// instanceID). Always go through InstanceID()/InstanceAZ()/ASGName() —
	// the bare field is unprotected. Issue #1681 cr round 3.
	instanceIdentityMu sync.RWMutex
	instanceID         string // EC2 instance ID (e.g., "i-0abc123")
	instanceAZ         string // Availability zone (e.g., "us-east-2a")
	asgName            string // ASG name from IMDS Name tag (blue/green filtering)

	// TTL refresh throttle: tracks last refresh time per AC ID to prevent
	// excessive DynamoDB writes from frequent AC re-registrations.
	ttlRefreshTimes sync.Map // acID -> time.Time

	// CloudWatch metrics publisher for NHP operational metrics.
	metrics *metrics.Publisher

	// artReplay dedupes recently observed NHP_ART packets by
	// (sender_pubkey, txid, sendTime) (#1457). Wired into the core
	// Device via SetRecvReplayDedupe(s.dedupeRecvART) in Start, so the
	// check runs at the post-validation chokepoint that sees every ART.
	// See art_replay_cache.go for the threat model. nil until Start
	// constructs it; dedupeRecvART is only reachable via the hook, which
	// Start installs after this is set.
	artReplay *artReplayCache

	// Per-source-IP rate limiter for UDP knock packets.
	// Drops packets that exceed the configured rate to mitigate DoS attacks
	// before any cryptographic processing occurs.
	rateLimiter    *IPRateLimiter
	rateLimitDrops atomic.Int64 // total dropped packets, for sampled logging

	// Pre-plugin OTP rate limiter, keyed by the inner device pubkey (b64), for
	// every native-UDP NHP_OTP and generic non-direct NHP_OTP not claimed as
	// Connector registration. Configured Connector registration on non-direct
	// ingress is rejected before this limiter. Nil means unbounded — a test-only
	// affordance; the constructor initializes it in production. See
	// agent_otp_ratelimit.go.
	otpRateLimiter *OTPRateLimiter

	// handlerSem is the general agent-facing handler partition. The protected
	// partition below is reserved for source-cookie-proven RKNs and configured
	// relay envelopes; together they total MaxConcurrentHandlers.
	// dispatchHandler acquires with a NON-BLOCKING send so recvMessageRoutine never
	// head-of-line-blocks on a full budget (#1163) — excess dispatches
	// are shed and the agent retries. A nil sem means unbounded; that is
	// a test-only affordance (bare &UdpServer{} literals), the
	// constructor always initializes it in production.
	handlerSem chan struct{}
	// protectedHandlerSem cannot be consumed by first-flight KNK or other
	// unproven public work. It preserves progress after handler pressure flips
	// core into overload-cookie mode.
	protectedHandlerSem chan struct{}
	// overloadMu serializes each pressure-source transition with the derived
	// core overload write. The source flags remain atomic because tests and
	// gauges inspect them independently, but neither source may publish from a
	// stale interleaving and handler transitions must re-check live occupancy.
	overloadMu         sync.Mutex
	connectionOverload atomic.Bool
	handlerOverload    atomic.Bool
	// handlerShedCount throttles the shed warn-log to 1 + every 1000th
	// shed — the same lifetime-modulus sampled-log idiom as rateLimitDrops
	// and perIPEvictionWarns. It never resets, so the log is only a
	// sample; MetricHandlerBudgetExhausted is the durable per-incident
	// signal (a later, smaller shed burst may not cross a 1000-boundary
	// and log nothing, but it always ticks the metric).
	handlerShedCount atomic.Int64

	// handlerPanicStackGates rate-limits the debug.Stack() carried by
	// dispatchHandler's panic-recovery line to one per
	// handlerPanicStackInterval PER HEADER TYPE. A remote-reachable handler
	// panic is triggerable at packet rate, and a multi-KB stack per packet would
	// let an attacker turn a correctness bug into unbounded log-ingestion cost.
	// The alarm-bearing line is emitted on EVERY recovery regardless, so
	// ServerHandlerPanic keeps counting them all; only the stack is sampled, and
	// the suppressed count is carried on the next stack-bearing line rather than
	// dropped.
	//
	// Per-type rather than global so a panic on one message type cannot swallow
	// the stack of a different bug on another within the same window. Keys are
	// header types (a small fixed registry), values *handlerPanicStackGate.
	//
	// The suppressed counter lives IN the gate, not beside it: a process-global
	// counter would let one type's stack line report another type's suppressed
	// count, and the "since the previous one" wording claims same-stream
	// accounting. Per-type keeps the annotation true.
	//
	// Zero values are usable: the first recovery of each type emits a stack.
	handlerPanicStackGates sync.Map

	// Per-IP agent-conn eviction warning counter, for sampled logging.
	// MetricAgentConnPerIPEvictions is the source of truth; this counter
	// just throttles the warn-log to 1 + every 1000th eviction.
	perIPEvictionWarns atomic.Int64

	// Rate limiter for license validation (brute-force prevention).
	licenseRateLimiter *LicenseRateLimiter

	// processACOperationBroadcastFn — TEST-ONLY SEAM.
	//
	// Indirection the native UDP knock handler goes through to reach
	// processACOperationBroadcast. Production paths leave it nil; the
	// resolveProcessACOperationBroadcast helper picks the real method
	// when unset. Tests set it on a literal UdpServer to inject a fake
	// AC response (populating artMsg.ACToken without driving real Noise
	// cipher state), which is the only practical way to fence the
	// load-bearing post-Wait PublishACKTokens call from the handler
	// entry point — see udpserver_publish_acktokens_test.go.
	//
	// Not a stable production knob: package-private, no setter, no
	// documented production semantics. If you find yourself wanting to
	// override this from outside a _test.go file, reconsider — there is
	// almost certainly a better extension point.
	processACOperationBroadcastFn func(
		parentCtx context.Context,
		knkMsg *common.AgentKnockMsg,
		conns []*ACConn,
		srcAddr *common.NetAddress,
		dstAddrs []*common.NetAddress,
		openTime uint32,
		res *common.ResourceData,
	) (*common.ACOpsResultMsg, error)

	// reknockRetryBackoff overrides the pause broadcastACOpenWithReknock waits
	// before its single retry (the blue/green reassignment window). The
	// zero value — the production default — resolves to defaultReknockRetryBackoff
	// at use; timeout-path tests set a tiny value via shortenReknockBackoff to run
	// fast. Per-instance (not a package var) so those tests mutate only their own
	// server, which a future t.Parallel() reknock test could not race.
	reknockRetryBackoff time.Duration

	// agentPeerLookup resolves a knock's RemotePubKey to a registered
	// agent peer via the qurl-agent-keys DDB table with a 60s LRU.
	// Populated only in cloud mode when AgentKeysTable is configured;
	// nil = legacy etcd / file-config agent path.
	//
	// Concurrency: written once in Start before any UDP packet
	// dispatch (between storage init and the listener boot), read
	// lock-free from resolveAgentPeerForKnock's hot path and from
	// computeEffectiveDisableAgentValidation (called by both Start
	// and the hot-reload watcher path). Same single-write-then-read
	// posture as knockHeaderTypeVerifyRequire / licensePubkeyVerify-
	// Require / sibling read-once gates above. A future refactor
	// that mutates this after Start MUST promote to atomic.Pointer
	// or protect behind a mutex; a bare write against a concurrent
	// read would be a Go memory-model violation even if it happens
	// to work on most architectures.
	agentPeerLookup *AgentPeerLookup

	// resourceLookup resolves a knock's AuthServiceId to a registered
	// *common.AuthServiceProviderData via the nhp_resources DDB table
	// with a 60s LRU. Populated only in cloud mode when ResourcesTable
	// is configured; nil = legacy TOML-overlay-only path (the
	// agentBootstrap-flow-prereq before #1976 landed).
	//
	// Concurrency: same single-write-then-read posture as
	// agentPeerLookup above (written once in Start before any UDP
	// packet dispatch; read lock-free from HandleKnockRequest's
	// FindAuthSvcProvider miss path). The same atomic-Pointer-or-
	// mutex warning applies to a future refactor that mutates this
	// after Start.
	resourceLookup *ResourceLookup

	// ackTokenStore persists short-lived ACK token metadata in a
	// fleet-visible backing store. Local tokenStore remains the fast
	// path; /nhp/internal/token/validate falls back here on local miss
	// so FRPS does not depend on hitting the same NHP server that
	// processed the knock.
	ackTokenStore ackTokenStore

	// pluginLoadOnce serializes ensurePluginLoaded per aspId so
	// LoadPlugin runs at most once per aspId per process. Without
	// this gate two concurrent first-knocks for the same DDB-only
	// aspId would both pass the alreadyLoaded check, both call
	// LoadPlugin (which always invokes h.Init), and the second
	// writer's pluginHandlerMap insert would silently leak the
	// first handler's Init-acquired resources (the Close path in
	// LoadPlugin only fires when its own RLock check finds an
	// existing entry — both racers would observe "not found").
	// Keyed on aspId (string); values are *sync.Once. Entries are
	// removed on failed load to enable retry (loadPluginOnce's
	// Delete-on-failure path so a transient h.Init flake doesn't
	// permanently reject the aspId — see loadPluginOnce godoc).
	// Bounded in steady state by distinct-aspId count, with brief
	// churn during failed-then-retried loads.
	pluginLoadOnce sync.Map
}

// resolveProcessACOperationBroadcast returns the function the local
// knock handlers should call to drive the AC broadcast. Production
// returns the bound method; tests that set processACOperationBroadcastFn
// directly on the UdpServer literal get their fake. Centralizing the
// fallback here keeps the native handleNhpOpenResource call site testable.
func (s *UdpServer) resolveProcessACOperationBroadcast() func(
	parentCtx context.Context,
	knkMsg *common.AgentKnockMsg,
	conns []*ACConn,
	srcAddr *common.NetAddress,
	dstAddrs []*common.NetAddress,
	openTime uint32,
	res *common.ResourceData,
) (*common.ACOpsResultMsg, error) {
	if s.processACOperationBroadcastFn != nil {
		return s.processACOperationBroadcastFn
	}
	return s.processACOperationBroadcast
}

type BlockAddr struct {
	expireTime time.Time
}

type UdpConn struct {
	ConnData       *core.ConnectionData
	isACConnection bool // Immutable. Don't change it after creation. Conn object is also stored in acConnectionMap which is indexed by ACId
	isDBConnection bool // Immutable. Don't change it after creation. Conn object is also stored in dbConnectionMap which is indexed by DBId
	// isServerPeer marks trusted server-to-server forward traffic. It is set at
	// construction for outbound synthetic conns, or promoted under
	// remoteConnectionMapMutex when a reciprocal forward reuses an inbound
	// generic conn from the same known server peer tuple.
	isServerPeer bool
	isWebRTC     bool
	dc           *webrtc.DataChannel

	// perIPElem is the conn's slot in connectionsByIP[ip]; nil for
	// trusted infra conns (AC/DB/server-peer/WebRTC).
	// Cleared on eviction so the cleanup defer doesn't double-pop.
	perIPElem *list.Element

	// evictSignal contract:
	//   - MUST be non-nil for any UdpConn passed to connectionRoutine
	//     or admitNewConnection. admitNewConnection panics on nil.
	//   - Closed exactly once by admitNewConnection on per-IP cap
	//     eviction; never closed by any other path.
	//   - For infra conns and WebRTC conns, the channel is allocated
	//     for select-shape consistency but never closed (those paths
	//     bypass the per-IP cap).
	// Dedicated channel (rather than reusing SetTimeoutSignal) so the
	// receive loop doesn't hold the map mutex across a connection
	// routine that may be mid-WriteToUDP.
	evictSignal chan struct{}
}

type ACConn struct {
	ConnData        *core.ConnectionData
	ACPeer          *core.UdpPeer
	ACCipherScheme  int
	ACId            string
	ServiceId       string
	Apps            []string
	BootID          string
	FlushGeneration uint64
	// sessionControlAuthorityReady is set only after the durable target has
	// caught up through the exact control-directory version and activated.
	// A counted reconnect clears the old connection's bit before Prepare, so a
	// PREPARING target remains available for control recovery but cannot receive
	// a new AOP.
	sessionControlAuthorityReady atomic.Bool
	// sessionControlTarget is the immutable durable READY authority consumed by
	// PrepareSessionIntentCurrent. It is published before the ready bit and
	// cleared after that bit during replacement, so the local bit remains only
	// a fast-path optimization rather than an authority substitute.
	sessionControlTarget atomic.Pointer[sessionControlTargetAuthority]
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
	if _, err := s.sessionOwnerID(); err != nil {
		return fmt.Errorf("initialize AC session owner identity: %w", err)
	}
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
	if err := s.configureConnectorCellAuthority(
		context.Background(),
		os.LookupEnv,
		loadConnectorCellAuthorityAWSConfig,
	); err != nil {
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
		log.Info("Knock HeaderType verify gate: permit mode (#1154); watch %s (rollout) and %s (producer/parser drift) before flipping NHP_KNOCK_HEADERTYPE_VERIFY=true",
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

	// Parse NHP_AC_PUBKEY_REVOKE_VERIFY (#1507, parent #1157 F5).
	// Fail Start on an unrecognized token so an operator typo cannot
	// silently leave the gate in permit mode. See
	// ac_pubkey_revoke_gate.go.
	s.acPubkeyRevokeVerifyRequire, err = parseACPubkeyRevokeVerify(os.Getenv(ACPubkeyRevokeVerifyEnvVar))
	if err != nil {
		return fmt.Errorf("%s: %w", ACPubkeyRevokeVerifyEnvVar, err)
	}
	if s.acPubkeyRevokeVerifyRequire {
		// Strict-flip prerequisites (see docs/runbooks/f5-revoked-pubkey-paging.md):
		// 1. ACPubkeyRevoked metric stays at zero through a full
		//    permit-mode deploy cycle.
		// 2. CloudWatch alarms (#1543) on ACPubkeyRevoked,
		//    ACPubkeyRevokedLookupErr, ACPubkeyRevokeListOversize,
		//    LicenseValidationRateLimited are provisioned and OK.
		// 3. ACAssignment pre-provisioning (#1262) lands so F4 + F5
		//    strict can flip together without the TOFU race.
		log.Info("AC pubkey revoke gate: strict mode (#1507); revoked pubkey rejects with 52019")
	} else {
		log.Info("AC pubkey revoke gate: permit mode (#1507); watch %s (revoked-pubkey hits) and %s (storage flap) before flipping NHP_AC_PUBKEY_REVOKE_VERIFY=true",
			MetricACPubkeyRevoked, MetricACPubkeyRevokedLookupErr)
	}
	s.acPubkeyRevokeSweepInterval, err = parseACPubkeyRevokeSweepInterval(os.Getenv(ACPubkeyRevokeSweepIntervalEnvVar))
	if err != nil {
		return fmt.Errorf("%s: %w", ACPubkeyRevokeSweepIntervalEnvVar, err)
	}
	if s.acPubkeyRevokeSweepInterval == 0 {
		log.Info("AC pubkey revoke mid-session sweep disabled (%s=0)", ACPubkeyRevokeSweepIntervalEnvVar)
	} else {
		log.Info("AC pubkey revoke mid-session sweep interval: %s (starts only in strict DynamoDB cloud mode)",
			s.acPubkeyRevokeSweepInterval)
	}

	// qURL v2 revocation retry-until-ack-or-age-out engine (#2793). The binary
	// arms only when NHP_REVOCATION_RETRY_ENABLED=true because a pre-ACK AC fleet
	// would otherwise storm the aged-out degraded metric. Terraform-managed fleets
	// now render that env var explicitly; absent env remains the unmanaged
	// compatibility default. Parse fails Start on a typo (see parseRevocationRetryConfig).
	revRetryEnabled, revRetryInterval, revRetryAgeOut, err := parseRevocationRetryConfig()
	if err != nil {
		return err
	}
	if revRetryEnabled {
		s.revocationRetry = newRevocationRetryTracker(revRetryInterval, revRetryAgeOut)
		log.Info("qURL v2 revocation retry engine ENABLED (interval=%s ageOut=%s)", revRetryInterval, revRetryAgeOut)
	} else {
		log.Info("qURL v2 revocation retry engine disabled (%s not true); NHP_REV fanout stays fire-and-forget", RevocationRetryEnabledEnvVar)
	}

	// Initialize pluggable storage backend (DynamoDB or etcd)
	// See docs/design/PLUGGABLE_STORAGE_BACKEND.md for architecture details.
	//
	// agentLookupInitFailed is captured here and emitted to
	// MetricAgentLookupInitFailure AFTER the metrics publisher is
	// constructed below — s.metrics is nil at this point in Start(),
	// so any direct IncrCounter here is a silent no-op.
	agentLookupInitFailed := false
	// resourceLookupInitFailed mirrors agentLookupInitFailed: captured
	// during storage init (when s.metrics is still nil) and emitted to
	// MetricResourceLookupInitFailure after the publisher exists.
	resourceLookupInitFailed := false
	// ackTokenStoreInitFailed mirrors the lookup flags above for the
	// fleet-visible ACK token store. It emits after metrics init so the
	// failure is visible instead of being dropped by a nil publisher.
	ackTokenStoreInitFailed := false
	s.storageConfig, err = s.loadStorageConfig()
	if err != nil {
		return fmt.Errorf("load storage config before session-control authority: %w", err)
	} else if s.storageConfig != nil && s.storageConfig.Backend != "" {
		if s.storageConfig.Backend == StorageBackendDynamoDB && s.storageConfig.DynamoDB.SessionControlTable == "" {
			return errors.New("DynamoDB storage requires SessionControlTable before accepting AOL/knock traffic")
		}
		if s.storageConfig.Backend == StorageBackendDynamoDB {
			// Resolve the durable authority cell once, before any listener can
			// accept AOL/knock traffic. There is deliberately no cell0 fallback:
			// a missing or noncanonical deployment identity must fail closed.
			if err := s.configureCloudSessionControlCellID(); err != nil {
				return err
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		s.storage, err = CreateStorageBackend(ctx, *s.storageConfig)
		if err != nil {
			if s.storageConfig.Backend == StorageBackendDynamoDB {
				return fmt.Errorf("create DynamoDB storage required by session-control authority: %w", err)
			}
			log.Warning("Failed to create storage backend (%s): %v", s.storageConfig.Backend, err)
			// Continue without storage - fall back to etcd/local config
		} else {
			log.Info("Storage backend initialized: %s", s.storage.Name())
		}

		// Agent peer lookup: nil when AgentKeysTable is unset or
		// the backend isn't DynamoDB (legacy etcd / file-config
		// path stays in effect). AC peers remain on etcd — tracked
		// as a follow-up.
		//
		// A real init failure (vs. "disabled by config") in cloud
		// mode is silent at the responder layer — the responder
		// pre-validates against the empty agentPeerMap and rejects
		// every agent knock, with NO MetricAgentLookupDDBError to
		// page on (the lookup never ran). Promote to Error and
		// emit MetricAgentLookupInitFailure (deferred to after the
		// metrics publisher is constructed; see flag above) so the
		// failure surfaces in alarms instead of disappearing into
		// the noise. DynamoDB construction and the dedicated session-control
		// authority fail Start above; only optional lookup construction keeps
		// the existing degraded behavior. On-prem etcd/file-config deployments
		// remain outside that cloud authority requirement.
		if s.storage != nil {
			if s.storageConfig.Backend == StorageBackendDynamoDB {
				sessionStore, sessionStoreErr := NewSessionControlStoreFromStorage(ctx, s.storage)
				if sessionStoreErr != nil {
					return fmt.Errorf("initialize mandatory session-control authority: %w", sessionStoreErr)
				}
				s.sessionControlStore = sessionStore
				if _, ok := sessionStore.(sessionControlRequestStore); !ok {
					return errors.New("initialize mandatory session-control request authority: incomplete store capability")
				}
				if err := s.validateSessionControlExactRetirementCapabilities(); err != nil {
					return fmt.Errorf("initialize mandatory session-control exact retirement authority: %w", err)
				}
				if err := s.validateSessionControlRecoveryCapabilities(); err != nil {
					return fmt.Errorf("initialize mandatory session-control recovery authority: %w", err)
				}
				log.Info("Session-control authority initialized (DDB, strong startup read succeeded)")
			}

			lookup, lookupErr := NewAgentPeerLookupFromStorage(s.storage)
			if lookupErr != nil {
				log.Error("Failed to initialize agent peer lookup: %v", lookupErr)
				agentLookupInitFailed = true
			} else if lookup != nil {
				s.agentPeerLookup = lookup
				log.Info("Agent peer lookup initialized (DDB+LRU, cache_ttl=%s)", agentPeerLookupCacheTTL)
			}

			// Resource lookup: nil when ResourcesTable is unset or
			// the backend isn't DynamoDB (legacy TOML-overlay-only
			// path stays in effect). Symmetric posture to the
			// agent-peer lookup above: a real init failure (vs.
			// "disabled by config") is silent at FindAuthSvcProvider's
			// miss path (the miss falls through to nil aspData and the
			// plugin returns ErrAuthServiceProviderNotFound — same
			// reject shape PR #2091 was added to prevent) with NO
			// MetricResourceLookupDDBError to page on. Capture the
			// failure here and defer the metric emit until after the
			// publisher exists (~30 lines below).
			resourceLookupInst, resourceLookupErr := NewResourceLookupFromStorage(s.storage, s)
			if resourceLookupErr != nil {
				log.Error("Failed to initialize resource lookup: %v", resourceLookupErr)
				resourceLookupInitFailed = true
			} else if resourceLookupInst != nil {
				s.resourceLookup = resourceLookupInst
				log.Info("Resource lookup initialized (DDB+LRU, cache_ttl=%s)", resourceLookupCacheTTL)
			}

			ackStore, ackStoreErr := NewACKTokenStoreFromStorage(s.storage)
			if ackStoreErr != nil {
				log.Error("Failed to initialize ACK token shared store: %v", ackStoreErr)
				if s.storageConfig.DynamoDB.AckTokensTable != "" {
					ackTokenStoreInitFailed = true
					return fmt.Errorf("configured ACK token shared store failed to initialize: %w", ackStoreErr)
				}
			} else if ackStore != nil {
				s.ackTokenStore = ackStore
				log.Info("ACK token shared store initialized (DDB, table configured)")
			} else if s.storageConfig.DynamoDB.AckTokensTable != "" {
				return fmt.Errorf("configured ACK token shared store unavailable for storage backend %q", s.storageConfig.Backend)
			}
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

	// Emit any startup metrics whose triggers fired BEFORE s.metrics
	// existed. agentLookupInitFailed is captured ~80 lines above
	// during storage init; emitting here guarantees the counter
	// actually reaches CloudWatch instead of silently dropping on
	// the nil publisher.
	if agentLookupInitFailed {
		s.metrics.IncrCounter(MetricAgentLookupInitFailure)
	}
	// Thread the publisher into the agent peer lookup so its forensic
	// counters (MetricAgentLookupSchemaMismatch,
	// MetricAgentLookupPubkeyCollision, and
	// MetricAgentLookupPubkeyCandidateOverflow today; future additions
	// here) emit. Same init-order reason as the deferred
	// agentLookupInitFailed emit above: the lookup is constructed
	// ~40 lines before s.metrics exists.
	//
	// SET-ONCE — do NOT call SetMetrics(nil) to "clear" the wiring.
	// AgentPeerLookup's setter refuses nil after a non-nil set (and
	// logs a Warning) so the forensic counters can't be silently
	// disabled by a future partial-reset refactor. See the godoc on
	// AgentPeerLookup.SetMetrics for the contract.
	if s.agentPeerLookup != nil {
		s.agentPeerLookup.SetMetrics(s.metrics)
	}

	// Symmetric to agentLookupInitFailed above: emit the deferred
	// resource-lookup init failure metric now that the publisher
	// exists. resourceLookupInitFailed is captured during storage
	// init (when s.metrics was nil).
	if resourceLookupInitFailed {
		s.metrics.IncrCounter(MetricResourceLookupInitFailure)
	}
	if s.resourceLookup != nil {
		s.resourceLookup.SetMetrics(s.metrics)
	}
	if ackTokenStoreInitFailed {
		s.metrics.IncrCounter(MetricACKTokenSharedStoreInitFailure)
	}

	// Initialize per-source-IP rate limiter for UDP knock packets.
	// Defense-in-depth alongside iptables rate limiting (see user_data.sh.tpl).
	// Drops packets before cryptographic processing to reduce CPU cost of DoS.
	rlCfg := DefaultRateLimiterConfig()
	s.rateLimiter = NewIPRateLimiter(rlCfg)
	log.Info("UDP rate limiter initialized: %.0f pps sustained, %d burst per source IP",
		rlCfg.Rate, rlCfg.Burst)

	// Initialize the pre-plugin OTP rate limiter (keyed by device pubkey). It
	// guards every native-UDP OTP and generic non-direct OTP not claimed as
	// Connector registration; configured Connector registration on non-direct
	// ingress is rejected before the limiter.
	otpCfg := DefaultOTPRateLimiterConfig()
	s.otpRateLimiter = NewOTPRateLimiter(otpCfg)
	log.Info("OTP rate limiter initialized: capacity %d, refill 1 per %s per key, global ~%.1f/min",
		otpCfg.Capacity, otpCfg.RefillInterval, otpCfg.GlobalRate*60)

	// Partition the original aggregate handler ceiling. First-flight public
	// work can fill only the general partition; cookie-proven RKNs and trusted
	// relay envelopes may fall back to the protected reserve. The total bound
	// remains MaxConcurrentHandlers.
	s.handlerSem = make(chan struct{}, HandlerGeneralCapacity)
	s.protectedHandlerSem = make(chan struct{}, HandlerProtectedReserve)
	s.metrics.RegisterGaugeFunc(MetricHandlerInFlight, func() float64 {
		// The two len calls are individually race-safe but not one atomic
		// cross-partition snapshot. The sum is bounded and operational telemetry;
		// admission and overload transitions consult the semaphores directly.
		return float64(len(s.handlerSem) + len(s.protectedHandlerSem))
	})
	s.metrics.RegisterGaugeFunc(MetricHandlerProtectedInFlight, func() float64 {
		return float64(len(s.protectedHandlerSem))
	})
	s.metrics.RegisterGaugeFunc(MetricHandlerPressureOverload, func() float64 {
		if s.handlerOverload.Load() {
			return 1
		}
		return 0
	})
	s.metrics.RegisterGaugeFunc(MetricRuntimeGoroutine, func() float64 {
		return float64(runtime.NumGoroutine())
	})
	s.metrics.RegisterGaugeFunc(MetricRuntimeHeapAllocBytes, func() float64 {
		var samples [1]runtimemetrics.Sample
		samples[0].Name = "/memory/classes/heap/objects:bytes"
		runtimemetrics.Read(samples[:])
		return float64(samples[0].Value.Uint64())
	})
	// Initialize server-to-server forwarder
	s.sessionRegistry()
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
		log.Error("[Server] listen error on %s: %v", s.listenAddrStr, err)
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
	s.listenAddrStr = s.listenAddr.String()

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

	// In cloud mode the agent registry is in DDB, so the responder
	// must skip its peer-pool check for agent packets — otherwise
	// an unknown-but-registered agent's first knock would fail
	// validatePeer before reaching HandleKnockRequest where the
	// DDB lookup runs. Composes with the legacy
	// DisableAgentValidation toggle so on-prem behavior is
	// unchanged.
	//
	// computeEffectiveDisableAgentValidation centralizes the
	// operator-value OR cloud-mode-override resolution so the
	// hot-reload path in updateBaseConfig can apply the same logic
	// — without that, a server.toml edit that touches
	// DisableAgentValidation flips the device option back to the
	// operator literal and the cloud-mode override is silently
	// undone. Boot-time logging stays here (Warning vs Info
	// depending on whether the override changes the operator value).
	operatorDisableAgentValidation := s.config.DisableAgentValidation
	disableAgentValidation := s.computeEffectiveDisableAgentValidation(operatorDisableAgentValidation)
	if cloudMode && s.agentPeerLookup != nil {
		if !operatorDisableAgentValidation {
			// Cloud-mode requires the responder to skip agent
			// pre-validation so first-knock-from-unknown-agent
			// reaches HandleKnockRequest; we're overriding an
			// operator who explicitly set DisableAgentValidation=
			// false (typically a hardening-minded posture). Log at
			// Warning so the override surfaces in alarms/dashboards
			// instead of vanishing into the Info stream — without
			// this, a tightening operator never sees that their
			// config was bypassed. The override itself is
			// non-negotiable in cloud mode (the agent path doesn't
			// work otherwise); the loud log is the compromise that
			// keeps operator intent visible.
			log.Warning("Cloud mode: operator's DisableAgentValidation=false is being overridden to true because the agent peer DDB lookup is wired; pre-validation is now delegated to the DDB lookup on knock")
		} else {
			log.Info("Cloud mode: agent peer pre-validation disabled, will resolve via qurl-agent-keys DDB lookup on knock")
		}
	} else if cloudMode && s.agentPeerLookup == nil && !agentLookupInitFailed {
		// Cloud mode is on but the lookup never wired AND no init
		// error fired earlier — i.e., the (nil, nil) "disabled by
		// config" branch: AgentKeysTable unset in storage.toml,
		// storage backend missing, etc. Sibling of
		// MetricAgentLookupInitFailure (which already fired above
		// for the (nil, error) branch): that metric catches real
		// init failures; this one catches the silently-misconfigured
		// happy path.
		//
		// The !agentLookupInitFailed guard is load-bearing — without
		// it, a wrapper-cycle init failure would double-emit both
		// MetricAgentLookupInitFailure (via the deferred-emit flag)
		// and MetricAgentLookupNotConfigured (this branch), since
		// both branches observe agentPeerLookup == nil. Each metric's
		// alarm posture assumes single-cause attribution; double-emit
		// would inflate the page count and conflate failure modes.
		//
		// The responder will pre-validate against an EMPTY
		// agentPeerMap (no agent.toml exists in cloud mode), so
		// every agent knock rejects at the responder layer with no
		// MetricAgentLookupDDBError to alarm on — the lookup never
		// ran. Warning + MetricAgentLookupNotConfigured surface the
		// misconfig so it's visible on dashboards instead of looking
		// identical to a healthy boot. Not fail-fast: matches the
		// existing Warning-and-continue posture for storage init
		// failures three sections up.
		log.Warning("Cloud mode: agent peer lookup not wired (AgentKeysTable unset or storage init returned nil with no error); every agent knock will reject at the responder layer (no MetricAgentLookupDDBError emitted because the lookup never ran) — agent validation falls back to legacy DisableAgentValidation=%v",
			disableAgentValidation)
		// s.metrics is already initialized at this point (Publisher
		// is constructed ~100 lines above) so emit directly. Unlike
		// MetricAgentLookupInitFailure (whose trigger fires during
		// storage init before the publisher exists and so uses a
		// deferred-emit flag), this branch executes after the
		// publisher is wired. IncrCounter is nil-safe (see
		// endpoints/metrics/publisher.go) so the guard is omitted
		// for consistency with the surrounding emit sites.
		s.metrics.IncrCounter(MetricAgentLookupNotConfigured)
	}

	// Symmetric to the agent-peer NotConfigured emit above: cloud mode
	// on, resource lookup never wired, no init error fired (the
	// (nil, nil) "disabled by config" branch — ResourcesTable unset).
	// Without this, a cloud deployment that forgot to plumb
	// ResourcesTable boots Info-only and looks healthy on dashboards
	// until the first knock for a DDB-only aspId rejects with no
	// MetricResourceLookupDDBError to alarm on (the lookup never ran).
	// Mutually exclusive with MetricResourceLookupInitFailure via the
	// !resourceLookupInitFailed guard — same single-cause-attribution
	// posture as the agent-peer pair.
	if cloudMode && s.resourceLookup == nil && !resourceLookupInitFailed {
		// Info-level, not Warning: with the staged rollout (#1976
		// read path lands first; cutover PR seeds real values and
		// removes the TOML overlay later), this branch is the
		// EXPECTED state through the entire bake window. A Warning
		// here would alarm-spam every nhp-server boot during the
		// staged rollout for a state that's deliberately deferred.
		// Once the cutover lands and ResourcesTable becomes
		// load-bearing, an operator missing the tfvar plumbing will
		// still see the MetricResourceLookupNotConfigured counter
		// climb (the alarm signal) — the log level is just for
		// human eyeballs and shouldn't page during a known-deferred
		// state.
		log.Info("Cloud mode: resource lookup not wired (ResourcesTable unset or storage init returned nil with no error); the DDB-backed authServiceMap bridge is inactive — aspIds not present in resource.toml's overlay will reject with ErrAuthServiceProviderNotFound. This is the expected state during the #1976 staged rollout (read path lands before the cutover seeds real DDB values)")
		s.metrics.IncrCounter(MetricResourceLookupNotConfigured)
	}

	// deviceOptions() is the single source of truth shared with the hot-reload
	// SetOption (it recomputes the same effective agent value logged above and
	// AC=cloudMode, plus the relay option) — so Start and reload never diverge.
	opts := s.deviceOptions(s.config)
	s.device = core.NewDevice(core.NHP_SERVER, prk, &opts)
	if s.device == nil {
		log.Critical("failed to create device")
		return errors.New("failed to create device")
	}
	if err := s.registerReceiveQueueMetrics(); err != nil {
		return err
	}

	if err := s.configureStatelessCookieParams(); err != nil {
		return err
	}

	// NHP_ART replay dedupe (#1457). Construct the cache and install the
	// post-validation dedupe hook BEFORE s.device.Start() spawns the
	// packetToMsgRoutine workers — the `go` in Start establishes the
	// happens-before that lets those workers read recvReplayDedupeFn
	// lock-free (see the field doc on core.Device).
	s.artReplay = newARTReplayCache()
	s.device.SetRecvReplayDedupe(s.dedupeRecvART)
	s.device.SetCookieMintFailureHook(s.recordOverloadCookieMintFailure)

	// retrieve local ip and mac
	localAddr := utils.GetLocalOutboundAddress()
	if localAddr != nil {
		s.localIp = localAddr.String()
	}
	s.localMac = utils.GetMacAddress(s.localIp)

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
				if errors.Is(loadErr, errPeerRegistryConflict) {
					return loadErr
				}
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
			if errors.Is(err, errPeerRegistryConflict) {
				return err
			}
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

	if err := s.configureAgentSessionCloseFleetAuth(); err != nil {
		return err
	}

	// Register only after HTTP configuration is loaded. Fleet-wide EXT close
	// propagation targets each healthy instance's direct private HTTP port; a
	// registration that advertised UDP identity before HTTP_PORT was known would
	// create an avoidable partial-delivery window. Periodic refresh below
	// re-asserts the complete attribute set.
	if cloudMode && s.cloudMap != nil {
		if err := s.registerWithCloudMapWithRetry(); err != nil {
			// loadHttpConfig starts the private HTTP listener before its actual
			// bound port can be advertised. Tear it down on the fail-closed
			// registration exit so a caller that handles Start's error without
			// immediately terminating the process cannot leave a partial server.
			if s.httpServer != nil {
				s.httpServer.Stop()
				s.httpServer = nil
			}
			return err
		}
	}

	s.remoteConnectionMap = make(map[string]*UdpConn)
	s.connectionsByIP = make(map[string]*list.List)
	s.acConnectionMap = make(map[string][]*ACConn)
	s.dbConnectionMap = make(map[string]*DBConn)
	s.tokenStore = common.NewTokenStore[*ACTokenEntry]()
	// Expose tokenStore population as a gauge. RegisterGaugeFunc is
	// nil-safe (see endpoints/metrics/publisher.go); s.metrics may be
	// nil in test fixtures, in which case the registration is a no-op
	// and the gauge simply isn't emitted. The closure samples
	// tokenStore.Size each flush — RLock-only, no contention with
	// Store/Load/CleanExpired beyond the brief read.
	s.metrics.RegisterGaugeFunc(MetricTokenStoreSize, func() float64 {
		return float64(s.tokenStore.Size())
	})
	s.blockAddrMap = make(map[string]*BlockAddr)
	s.signals.stop = make(chan struct{})
	s.lifecycleCtx, s.lifecycleCancel = context.WithCancel(context.Background())

	s.recvMsgCh = s.device.DecryptedMsgQueue
	s.sendMsgCh = make(chan *core.MsgData, core.SendQueueSize)
	// All fallible startup and lifecycle initialization is complete before the
	// durable reconciler owns a goroutine. Its first sweep is ticker-delayed, so
	// the device/send routines and running flag below are visible before work can
	// be dispatched. This also guarantees a failed Start cannot leak a worker
	// rooted in context.Background.
	if err := s.startSessionControlRecovery(); err != nil {
		return fmt.Errorf("start mandatory session-control recovery: %w", err)
	}

	// start device routines
	s.device.Start()

	// start server routines
	s.wg.Add(5)
	go s.tokenStore.RunRefreshRoutine(&s.wg, s.signals.stop, TokenStoreRefreshInterval)
	go s.BlockAddrRefreshRoutine()
	go s.recvPacketRoutine()
	go s.sendMessageRoutine()
	go s.recvMessageRoutine()

	// Cloud Map registration self-healing routine. Started after s.signals.stop
	// is initialized so the select inside the routine isn't reading a nil channel.
	if cloudMode && s.cloudMap != nil {
		s.wg.Add(1)
		go s.cloudMapRegisterRefreshRoutine()
	}
	if s.acPubkeyRevokeDropEnabled() && s.acPubkeyRevokeSweepInterval > 0 {
		s.wg.Add(1)
		go s.acPubkeyRevokeSweepRoutine()
		log.Info("AC pubkey revoke mid-session sweeper started (interval=%s)", s.acPubkeyRevokeSweepInterval)
	} else if s.acPubkeyRevokeSweepInterval > 0 && !s.acPubkeyRevokeVerifyRequire {
		log.Info("AC pubkey revoke mid-session sweeper not started because %s is permit mode",
			ACPubkeyRevokeVerifyEnvVar)
	}
	// qURL v2 revocation retry/age-out routine (#2793). Started only when the
	// engine is armed (tracker non-nil). Joins s.wg + exits on s.signals.stop so
	// it stops sending before Stop() closes s.sendMsgCh (wg.Wait precedes the
	// close).
	if s.revocationRetry != nil {
		s.wg.Add(1)
		go s.revocationRetryRoutine()
	}

	s.running.Store(true)
	return nil
}

// registerReceiveQueueMetrics wires queue telemetry only after the core device
// exists. The metric publisher may collect a gauge as soon as it is registered,
// so registering these closures before NewDevice would introduce a startup race
// in addition to making SetReceiveQueueDropHook dereference a nil device.
func (s *UdpServer) registerReceiveQueueMetrics() error {
	if s.device == nil {
		return errors.New("cannot register receive queue metrics before device initialization")
	}

	s.metrics.RegisterGaugeFunc(MetricPacketDecryptQueueDepth, func() float64 {
		depth, _ := s.device.ReceiveQueueDepths()
		return float64(depth)
	})
	s.metrics.RegisterGaugeFunc(MetricDecryptedMessageQueueDepth, func() float64 {
		_, depth := s.device.ReceiveQueueDepths()
		return float64(depth)
	})
	s.device.SetReceiveQueueDropHook(func(reason core.ReceiveQueueDrop) {
		switch reason {
		case core.ReceiveQueueDropDecrypt:
			s.metrics.IncrCounter(MetricPacketDecryptQueueDrop)
		case core.ReceiveQueueDropDecrypted:
			s.metrics.IncrCounter(MetricDecryptedMessageQueueDrop)
		}
	})
	return nil
}

func (s *UdpServer) configureStatelessCookieParams() error {
	cookieKey, cookieKeyErr := decodeCookieSigningKey(s.config.CookieSigningKeyBase64)
	if cookieKeyErr != nil {
		log.Critical("invalid CookieSigningKeyBase64 in config: %v", cookieKeyErr)
		return fmt.Errorf("invalid CookieSigningKeyBase64: %w", cookieKeyErr)
	}
	defer func() {
		core.SetZero(cookieKey)
	}()

	processLocalCookieKey := false
	if len(cookieKey) == 0 {
		cookieKey = make([]byte, core.SymmetricKeySize)
		if _, err := rand.Read(cookieKey); err != nil {
			log.Critical("failed to generate random cookie signing key: %v", err)
			return fmt.Errorf("failed to generate random cookie signing key: %w", err)
		}
		processLocalCookieKey = true
		log.Warning("CookieSigningKeyBase64 not set; using a random per-process overload-cookie key; cross-instance RKN verification requires a shared configured key")
	} else {
		log.Info("CookieSigningKeyBase64 configured; overload cookies can verify across server instances")
	}
	s.overloadCookieProcessLocalKey.Store(processLocalCookieKey)
	s.metrics.RegisterGaugeFunc(MetricOverloadCookieProcessLocalKey, func() float64 {
		if s.overloadCookieProcessLocalKey.Load() {
			return 1
		}
		return 0
	})

	s.device.SetStatelessCookieParams(cookieKey, effectiveCookieTimeWindow(s.config.CookieTimeWindowSeconds))
	return nil
}

func (s *UdpServer) recordOverloadCookieMintFailure(reason string) {
	if s == nil || s.metrics == nil {
		return
	}
	s.metrics.IncrCounter(MetricOverloadCookieMintFailure)
	s.metrics.IncrCounterWithDims(MetricOverloadCookieMintFailure, []types.Dimension{
		{
			Name:  aws.String("Reason"),
			Value: aws.String(reason),
		},
	})
}

func (s *UdpServer) Stop() {
	if !s.running.Load() {
		// already stopped, do nothing
		return
	}
	s.running.Store(false)
	s.agentSessionCloseWorkerMu.Lock()
	s.agentSessionCloseWorkersStopping = true
	s.agentSessionCloseWorkerMu.Unlock()
	// Stop HTTP ingress first: once recovery cancellation begins, no new request
	// may be accepted that depends on that durable reconciler. Recovery still
	// stops before AC drain, so no new close delivery starts while connection
	// ownership is being torn down.
	s.stopHTTPAndSessionControlRecovery()
	if s.etcdConn != nil {
		s.etcdConn.Close()
	}
	if s.webrtcServer != nil {
		s.webrtcServer.Stop()
	}
	// Best-effort cleanup: remove this server from AC assignments
	s.cleanupOwnedAssignments()
	// Best-effort cleanup: deregister from Cloud Map so peers stop forwarding to us
	if instanceID := s.InstanceID(); s.cloudMap != nil && instanceID != "" {
		drCtx, drCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer drCancel()
		if err := s.cloudMap.DeregisterInstance(drCtx, instanceID); err != nil {
			log.Warning("Failed to deregister instance %s from Cloud Map: %v", instanceID, err)
			if s.metrics != nil {
				s.metrics.IncrCounter(MetricCloudMapDeregisterFailure)
			}
		}
	}
	// Drain AC connections: send NHP_ARD redirecting ACs to NLB for immediate reconnect.
	// Must run before close(s.signals.stop) because drain sends via s.sendMsgCh.
	s.drainACConnections()
	// Stop the cross-server forwarder BEFORE the transaction drain so
	// no new forwarded knocks can spawn fresh local transactions while
	// we're waiting for existing ones to clear. forwarder.Stop() only
	// halts the cleanup routine — it does not drain in-flight forwards
	// — so it's safe to run pre-drain. listenConn is intentionally left
	// open through the drain: closing it pre-drain would cause every
	// in-flight server->AC transaction (waiting for an AC response on
	// listenConn) to time out at ServerACOpenTransactionResponseTimeoutMs
	// instead of completing normally.
	if s.forwarder != nil {
		s.forwarder.Stop()
	}
	// Wait for in-flight local transactions (server->AC knocks, etc.) to
	// complete or time out before closing connection StopSignals. Without
	// this wait, close(s.signals.stop) below tears down every connection's
	// StopSignal mid-flight and any active transaction returns
	// ErrTransactionFailedByClosedConnection — observed as `knock_failed`
	// on qURL plugin responses during canary rolls.
	s.awaitTransactionDrain(shutdownTransactionDrainTimeout)
	// Residual-race check: a UDP packet arriving on listenConn between
	// the drain's last count=0 observation and close(s.signals.stop)
	// below can still spawn a fresh local transaction that gets
	// stranded. The durable fix is the LB-side ASG lifecycle hook
	// (deregister from NLB before SIGTERM) — tracked as a follow-up.
	// In the meantime, surface the residual race in logs so it's
	// triagable when it occurs.
	if s.device != nil {
		if residual := s.device.LocalTransactionCount(); residual > 0 {
			log.Warning("Shutdown: %d local transactions arrived after drain completed (will fail with closed-connection); see ASG-lifecycle-hook follow-up", residual)
		}
	}
	// Stop license rate limiter cleanup goroutine
	if s.licenseRateLimiter != nil {
		s.licenseRateLimiter.Stop()
	}
	// Flush remaining CloudWatch metrics. MUST come AFTER
	// awaitTransactionDrain — the drain calls IncrCounter on the
	// timeout path, and moving metrics.Stop() above the drain would
	// turn that counter into a silent no-op and lose the only
	// observable signal that the budget was exhausted.
	if s.metrics != nil {
		s.metrics.Stop()
	}
	close(s.signals.stop)
	if s.lifecycleCancel != nil {
		s.lifecycleCancel()
	}
	_ = s.listenConn.Close()
	s.device.Stop()
	s.StopConfigWatch()
	// Barrier with startOutboundConnectionRoutine: any outbound launch that
	// passed the pre-stop check finishes its wg.Add before Stop enters wg.Wait.
	s.outboundConnStartMutex.Lock()
	s.outboundConnStartMutex.Unlock()
	s.wg.Wait()
	s.agentSessionCloseWorkerWG.Wait()
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

func (s *UdpServer) stopHTTPAndSessionControlRecovery() {
	if s.httpServer != nil {
		s.httpServer.Stop()
	}
	s.stopSessionControlRecovery()
}

// ACPeerCount returns the number of unique AC IDs with at least one live,
// authority-eligible connection.
// This counts distinct AC IDs (not total connections per AC, which may be >1
// during blue/green deployments). For health checking, at least one AC peer
// means knock traffic can be processed.
// Implements health.ACPeerCounter for the AC-aware health check.
func (s *UdpServer) ACPeerCount() int {
	s.acConnectionMapMutex.RLock()
	defer s.acConnectionMapMutex.RUnlock()
	cutoffNanos := time.Now().Add(-s.staleACConnThreshold()).UnixNano()
	authorityRequired := s.sessionControlAuthorityRequired()
	count := 0
	for _, conns := range s.acConnectionMap {
		for _, conn := range conns {
			if acConnAuthorityEligibleAt(conn, cutoffNanos, authorityRequired) {
				count++
				break
			}
		}
	}
	return count
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

		// assignment is already an owned copy (GetACAssignment clones,
		// #1540); the clone just keeps it pristine as the "before" while
		// newAssignment is the mutated "after" — defensive, not
		// load-bearing for cache safety.
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

// shutdownTransactionDrainTimeout bounds how long Stop() waits for in-flight
// local transactions to complete before closing connection StopSignals.
// Sized at ~3× the SHARED ServerLocalTransactionResponseTimeoutMs (4.7s, per
// nhp/core/constants.go): the LONGEST server-initiated local transaction that can be
// in flight at shutdown is a DB key-wrap (NHP_DWR) or forward (NHP_FWD) on that shared
// timeout, so the drain must cover THAT — not the faster 1s AC-open (NHP_AOP). The
// AC-open path fits comfortably inside this window even with its reknock second
// transaction (~3.3s worst case, ac_open_reknock_retry.go). Each individual
// LocalTransaction self-clears via its own timer branch
// (nhp/core/transaction.go::LocalTransaction.Run), but multiple queued txs can
// serialize within this window. If exceeded, MetricShutdownTransactionDrainTimeout
// fires and outstanding transactions return ErrTransactionFailedByClosedConnection.
const shutdownTransactionDrainTimeout = 15 * time.Second

// shutdownTransactionDrainPollInterval is the polling cadence inside
// awaitTransactionDrain. Tight enough that a fast-clearing drain returns
// quickly; loose enough to avoid a busy loop while waiting on a slow AC.
const shutdownTransactionDrainPollInterval = 100 * time.Millisecond

// awaitTransactionDrain blocks until either the device reports zero
// in-flight local transactions or maxWait elapses. Polls every
// shutdownTransactionDrainPollInterval. Logs and increments
// MetricShutdownTransactionDrainTimeout if the budget is exhausted with
// transactions still outstanding — those transactions will see the
// connection's StopSignal close shortly after this returns and surface
// ErrTransactionFailedByClosedConnection to their callers.
func (s *UdpServer) awaitTransactionDrain(maxWait time.Duration) {
	if s.device == nil {
		return
	}
	start := time.Now()
	deadline := start.Add(maxWait)
	initial := s.device.LocalTransactionCount()
	if initial == 0 {
		// Info level so a healthy clean-drain leaves a per-shutdown
		// log line in CloudWatch — without this, the absence of any
		// drain log can't be distinguished from the drain being
		// silently skipped due to a future bug.
		log.Info("Shutdown: no in-flight local transactions to drain")
		return
	}
	log.Info("Shutdown: waiting for %d in-flight local transactions to drain (max %v)", initial, maxWait)
	for {
		count := s.device.LocalTransactionCount()
		if count == 0 {
			log.Info("Shutdown: transaction drain complete after %v", time.Since(start))
			return
		}
		if time.Now().After(deadline) {
			log.Warning("Shutdown: transaction drain timed out after %v with %d transactions still in-flight (will fail with closed-connection)", maxWait, count)
			if s.metrics != nil {
				s.metrics.IncrCounter(MetricShutdownTransactionDrainTimeout)
			}
			return
		}
		time.Sleep(shutdownTransactionDrainPollInterval)
	}
}

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
	conns := s.snapshotAllACConnections()

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

// Revocation fanout mode wire strings. These mirror qurl-service's
// revocation.FanoutMode constants byte-for-byte (internal/revocation/event.go:
// FanoutTargeted / FanoutCellWide) so the server selects the AC set without a
// translation table. Keep them stable; they are part of the cross-repo wire
// contract.
const (
	// revocationFanoutTargeted delivers only to the ACs whose ACId is in the
	// event's target_ac_ids. Honored ONLY when target_set_complete=true (the
	// handler rejects an incomplete targeted event before reaching fanout).
	revocationFanoutTargeted = "targeted"
	// revocationFanoutCellWide delivers to every connected AC. It is the safe
	// fallback qurl-service emits whenever the admitted-AC set cannot be proven
	// complete (and the only mode qurl-service emits until the P3c admitted-AC
	// wiring lands).
	revocationFanoutCellWide = "cell-wide"
)

// snapshotAllACConnections returns every live AC connection (all acIds, all
// blue/green slots per acId) as a flat slice, taken under acConnectionMapMutex.
// RLock. The returned *ACConn pointers are read lock-free by callers; the slice
// itself is a fresh copy so iterating it never races a concurrent map mutation.
// This is the shared snapshot primitive behind the graceful-drain (NHP_ARD) and
// cell-wide revocation (NHP_REV) fanouts — keep the lock-hold to this pure map
// walk (no I/O, no send) so it never serializes the receive path.
func (s *UdpServer) snapshotAllACConnections() []*ACConn {
	s.acConnectionMapMutex.RLock()
	defer s.acConnectionMapMutex.RUnlock()
	totalConns := 0
	for _, acConns := range s.acConnectionMap {
		totalConns += len(acConns)
	}
	conns := make([]*ACConn, 0, totalConns)
	for _, acConns := range s.acConnectionMap {
		conns = append(conns, acConns...)
	}
	return conns
}

// findACConnectionsForRevocation snapshots the AC connection map and returns
// the ACConn entries an NHP_REV fanout should target, selected purely by
// fanoutMode (orthogonal to the revocation scope — a resource-scoped revoke can
// ship cell-wide):
//
//   - cell-wide: every connected AC connection (all colors / all blue-green
//     slots), via snapshotAllACConnections (the same snapshot the NHP_ARD drain
//     uses).
//   - targeted: only connections whose ACId is in targetACIDs. ACConn.ACId is
//     the AC's configured id string, the identifier space qurl-service is
//     EXPECTED to record in a session's admitted_ac_ids and copy into
//     target_ac_ids — a cross-repo string-equality contract NOT yet proven
//     end-to-end (#2790), which is why the caller emits a zero-match canary. An
//     empty targetACIDs therefore matches nothing.
//
// The returned slice holds *ACConn pointers the caller reads lock-free.
// fanoutMode is assumed pre-validated by the handler (revocationFanoutTargeted /
// revocationFanoutCellWide); any other value selects nothing (defensive — the
// handler rejects unknown modes with 400 before calling this). Metric emission
// still normalizes fanoutMode defensively in recordRevocationFanoutSent so a
// future caller cannot create unbounded CloudWatch FanoutMode values.
//
// An empty result is a legitimate success case (cell-wide with no connected
// ACs, or targeted with no matching ACId on this server): there is simply
// nothing to flush here. The caller treats it as "nothing to do," not an error —
// but for a targeted event the caller (handleInternalRevocation) counts this case
// via MetricRevocationTargetedZeroMatch (#2790) so a zero match is observable
// instead of silent, since that is the shape a cross-repo target_ac_ids↔ACId
// identifier drift would take.
func (s *UdpServer) findACConnectionsForRevocation(fanoutMode string, targetACIDs []string) []*ACConn {
	switch fanoutMode {
	case revocationFanoutCellWide:
		return s.snapshotAllACConnections()
	case revocationFanoutTargeted:
		// Build the targeted-id lookup outside the lock to keep the critical
		// section to a pure map walk; index by ACId so we resolve each wanted
		// id to its connection slice rather than scanning every connection.
		wanted := make(map[string]struct{}, len(targetACIDs))
		for _, id := range targetACIDs {
			wanted[id] = struct{}{}
		}
		s.acConnectionMapMutex.RLock()
		defer s.acConnectionMapMutex.RUnlock()
		conns := make([]*ACConn, 0, len(wanted))
		for id := range wanted {
			conns = append(conns, s.acConnectionMap[id]...)
		}
		return conns
	default:
		return nil
	}
}

// fanoutRevocation pushes an NHP_REV carrying revBytes (a marshaled
// common.ACRevocationMsg) to each AC connection fire-and-forget, mirroring
// drainACConnections' per-connection MsgData construction. revBytes is marshaled
// once by the caller and reused for every AC (the message is identical
// per-connection; only the transport envelope — ConnData, PeerPk, cipher,
// counter — differs).
//
// Backpressure is fail-CLOSED: the send is a non-blocking enqueue onto the
// shared sendMsgCh, and if any AC's enqueue would block (queue full) the method
// stops and returns ok=false so the handler can answer 503 and let
// qurl-service's at-least-once Publisher retry the whole event. This is safe
// despite a possible partial fanout (some ACs already enqueued before the full
// queue) because NHP_REV apply is epoch-idempotent on the AC (Slice 1 watermark:
// a re-delivered event at the same revocation_epoch is a no-op), so the retry
// re-sending to already-served ACs causes no double-teardown. The alternative —
// silently dropping — would lose the revocation with no retry signal (fail-open).
//
// conns may be empty (cell-wide with no connected ACs / targeted with no match
// here); that returns sent=0, ok=true (nothing to do is success, not 503).
func (s *UdpServer) fanoutRevocation(conns []*ACConn, revBytes []byte) (sent int, ok bool) {
	for _, conn := range conns {
		if conn == nil || conn.ACPeer == nil {
			// Defensive: a nil conn or a conn with a nil ACPeer must be skipped, not
			// dereferenced (conn.ACPeer.PublicKey() would panic). This is the minimal
			// "don't panic" guard and is intentionally LOOSER than the proof side:
			// trackFanout keys on acConnPubkey, which rejects BOTH a nil ACPeer and a
			// non-nil ACPeer with an empty PubKeyBase64 (ticking RevocationUntrackable).
			// So for either malformed shape the track side is stricter than the send
			// side, not symmetric: a nil-ACPeer conn is skipped here AND ticks
			// RevocationUntrackable there (counted-but-not-sent), and a non-nil but
			// keyless ACPeer would be SENT an NHP_REV here yet get no pending proof
			// entry. Both surface a malformed-registry invariant break rather than a
			// silent proof gap. Under current invariants findACConnectionsForRevocation
			// never yields any such entry; this is defense-in-depth against a future
			// regression.
			continue
		}
		md := &core.MsgData{
			ConnData:      conn.ConnData,
			HeaderType:    core.NHP_REV,
			CipherScheme:  conn.ACCipherScheme,
			TransactionId: s.device.NextCounterIndex(),
			Compress:      true,
			PeerPk:        conn.ACPeer.PublicKey(),
			Message:       revBytes,
			// No ResponseMsgCh — fire-and-forget (server→AC push, like NHP_ARD).
		}
		select {
		case s.sendMsgCh <- md:
			sent++
		default:
			// Fail closed: report backpressure so the caller returns 503 and
			// the producer retries, rather than dropping this (and any
			// remaining) AC's revocation.
			if s.metrics != nil {
				s.metrics.IncrCounter(MetricRevocationFanoutBackpressure)
			}
			log.Warning("revocation fanout: sendMsgCh full after %d/%d ACs; returning 503 for producer retry", sent, len(conns))
			return sent, false
		}
	}
	return sent, true
}

// Cloud Map registration self-healing tunables (issue #1681). Boot retry +
// periodic refresh together ensure a transient IMDS / Cloud Map failure at
// boot doesn't leave the server permanently absent from auto-assignment.
// Per-call timeout bounds a hung API so the refresh goroutine can't wedge.
// Worst-case boot delay if Cloud Map is fully down: attempts × timeout +
// (attempts-1) × backoff = 3 × 5s + 2 × 2s = 19s.
const (
	cloudMapRegisterInitialAttempts = 3
	cloudMapRegisterInitialBackoff  = 2 * time.Second
	cloudMapRegisterRefreshInterval = 5 * time.Minute
	cloudMapRegisterTimeout         = 5 * time.Second
)

// registerWithCloudMap fetches EC2 instance identity from IMDS (once)
// and asserts this server's public key in Cloud Map. Safe to call
// repeatedly: IMDS values are cached on the receiver after the first
// successful fetch, and RegisterInstance is idempotent under identical
// attributes. Returns nil on success, or the first non-recoverable
// error encountered. The boot-time caller retries on error; the
// refresh routine logs and continues on error.
//
// Re-fetches IMDS when AZ is empty even if instanceID is set: a partial
// IMDS fetch (instance-id succeeded, AZ failed) would otherwise leave
// the server registered with an empty AZ for its lifetime, breaking
// the AZ-distribution heuristic in maybeGrowAssignedServers downstream.
func (s *UdpServer) registerWithCloudMap() error {
	instanceID, instanceAZ, asgName := s.snapshotInstanceIdentity()
	if instanceID == "" || instanceAZ == "" {
		if err := s.fetchInstanceIdentityFromIMDS(); err != nil {
			return err
		}
		instanceID, instanceAZ, asgName = s.snapshotInstanceIdentity()
	}
	httpPort := s.effectiveHTTPPort()
	if httpPort == 0 {
		return errors.New("Cloud Map registration requires a running plaintext VPC-admitted fleet-control HTTP listener")
	}

	// Re-assert with current attributes. RegisterInstance REPLACES all
	// attributes for the instance ID, so we must include IP, AZ, port,
	// pubkey, and the actual bound fleet-control HTTP port on every call.
	attrs := map[string]string{
		CloudMapAttrIPv4:     s.localIp,
		CloudMapAttrAZ:       instanceAZ,
		CloudMapAttrPort:     strconv.Itoa(s.config.ListenPort),
		CloudMapAttrKey:      s.device.PublicKeyBase64(),
		CloudMapAttrHTTPPort: strconv.Itoa(httpPort),
	}
	if asgName != "" {
		attrs[CloudMapAttrASG] = asgName
	}

	ctx, cancel := context.WithTimeout(context.Background(), cloudMapRegisterTimeout)
	defer cancel()

	if err := s.cloudMap.RegisterInstanceAttributes(ctx, instanceID, attrs); err != nil {
		return fmt.Errorf("Cloud Map RegisterInstance: %w", err)
	}
	return nil
}

const agentSessionCloseFleetMACDomain = "opennhp/agent-session-close-fleet/v1\x00"

// configureAgentSessionCloseFleetAuth derives a purpose-specific HTTP HMAC key
// from the deployed NHP server static private key. The key is shared by every
// process in a cell today, so it authenticates fleet membership, not a unique
// instance. Exact source IP + Cloud Map membership provide the instance-target
// binding used by the receiver.
func (s *UdpServer) configureAgentSessionCloseFleetAuth() error {
	if s == nil || s.config == nil {
		return errors.New("missing server config for fleet close authentication")
	}
	privateKey, err := base64.StdEncoding.DecodeString(s.config.PrivateKeyBase64)
	if err != nil || len(privateKey) != core.PrivateKeySize {
		return errors.New("invalid server private key for fleet close authentication")
	}
	defer core.SetZero(privateKey)
	mac := hmac.New(sha256.New, privateKey)
	_, _ = mac.Write([]byte(agentSessionCloseFleetMACDomain))
	derived := mac.Sum(nil)
	defer core.SetZero(derived)
	signer, err := internalauth.New(base64.RawURLEncoding.EncodeToString(derived))
	if err != nil {
		return fmt.Errorf("construct fleet close authenticator: %w", err)
	}
	s.fleetCloseSigner = signer
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = (&net.Dialer{Timeout: 2 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	transport.TLSHandshakeTimeout = 2 * time.Second
	transport.ResponseHeaderTimeout = 3 * time.Second
	transport.IdleConnTimeout = 30 * time.Second
	transport.MaxIdleConns = 32
	transport.MaxIdleConnsPerHost = 2
	s.fleetCloseHTTPClient = &http.Client{
		Transport: transport,
		Timeout:   agentSessionCloseEventTTL,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("fleet close redirects are forbidden")
		},
	}
	return nil
}

func (s *UdpServer) effectiveHTTPPort() int {
	if s == nil || s.httpServer == nil || !s.httpServer.IsRunning() || s.httpServer.listenAddr == nil {
		return 0
	}
	hs := s.httpServer
	if hs.tlsEnabled || !fleetCloseHTTPPortIsVPCAdmitted(hs.listenAddr.Port) {
		return 0
	}
	return hs.listenAddr.Port
}

// fleetCloseHTTPPortIsVPCAdmitted mirrors the two VPC-scoped TCP ingress rules
// in terraform/modules/compute/main.tf. Do not advertise a configured listener
// through Cloud Map unless sibling instances can actually reach it.
func fleetCloseHTTPPortIsVPCAdmitted(port int) bool {
	return port == 62206 || port == 8888
}

// InstanceID returns the EC2 instance ID, or "" if IMDS hasn't completed.
// Safe for concurrent reads alongside refresh-time IMDS re-fetch.
func (s *UdpServer) InstanceID() string {
	s.instanceIdentityMu.RLock()
	defer s.instanceIdentityMu.RUnlock()
	return s.instanceID
}

// InstanceAZ returns the EC2 availability zone, or "" if IMDS hasn't
// completed (or partially completed without AZ — the refresh routine
// re-fetches in that case).
func (s *UdpServer) InstanceAZ() string {
	s.instanceIdentityMu.RLock()
	defer s.instanceIdentityMu.RUnlock()
	return s.instanceAZ
}

// ASGName returns the ASG name from the IMDS Name tag, or "" if IMDS
// hasn't completed or the Name tag was unset. Used by blue/green ASG
// filtering on the auto-assign and refresh-grow paths.
func (s *UdpServer) ASGName() string {
	s.instanceIdentityMu.RLock()
	defer s.instanceIdentityMu.RUnlock()
	return s.asgName
}

// snapshotInstanceIdentity returns all three identity fields under a single
// RLock, so callers that read multiple fields together (e.g.
// registerWithCloudMap) get a consistent snapshot rather than three
// independently-acquired reads that could straddle a writer.
func (s *UdpServer) snapshotInstanceIdentity() (instanceID, instanceAZ, asgName string) {
	s.instanceIdentityMu.RLock()
	defer s.instanceIdentityMu.RUnlock()
	return s.instanceID, s.instanceAZ, s.asgName
}

// fetchInstanceIdentityFromIMDS populates s.instanceID, s.instanceAZ,
// and s.asgName from EC2 IMDSv2. Splits the IMDS reads off of
// registerWithCloudMap so the registration path can re-assert without
// re-polling IMDS once identity is known. Returns an error iff the
// instance ID could not be fetched — without it Cloud Map registration
// cannot proceed. AZ and ASG fall back to defaults on failure (the
// server still registers with reduced metadata).
//
// Holds instanceIdentityMu for the entire IMDS fetch + commit so concurrent
// readers (msghandler.go's NHP_AAK path reads instanceAZ on every knock)
// never observe a torn snapshot mid-fetch. The Lock is held across HTTP
// round-trips to IMDS link-local (169.254.169.254), which the imdsV2*
// helpers cap at the 2s client timeout — bounded, and the alternative
// (pre-fetch under no lock, commit under lock) would still need a Lock
// for the commit and would not measurably help reader contention.
func (s *UdpServer) fetchInstanceIdentityFromIMDS() error {
	s.instanceIdentityMu.Lock()
	defer s.instanceIdentityMu.Unlock()

	imdsClient := &http.Client{Timeout: 2 * time.Second}

	// Obtain a single IMDS token and reuse it for all metadata fetches
	// (avoids 3 separate token PUT requests).
	token, err := imdsV2Token(imdsClient)
	if err != nil {
		return fmt.Errorf("IMDS token: %w", err)
	}

	instanceID, err := imdsV2GetWithToken(imdsClient, token, "http://169.254.169.254/latest/meta-data/instance-id")
	if err != nil {
		return fmt.Errorf("IMDS instance-id: %w", err)
	}
	s.instanceID = strings.TrimSpace(instanceID)

	az, err := imdsV2GetWithToken(imdsClient, token, "http://169.254.169.254/latest/meta-data/placement/availability-zone")
	if err != nil {
		// Leave s.instanceAZ unchanged so the next refresh re-tries the fetch.
		// The registerWithCloudMap gate keys on s.instanceAZ == "" to retry
		// IMDS rather than persisting an "unknown" sentinel for the process
		// lifetime (which would break AZ-distribution downstream).
		log.Warning("Failed to get AZ from IMDS: %v (will retry on next refresh)", err)
	} else if trimmed := strings.TrimSpace(az); trimmed != "" {
		s.instanceAZ = trimmed
	}

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
	return nil
}

// registerWithCloudMapWithRetry calls registerWithCloudMap with bounded
// retries at process start. The retry budget covers a transient IMDS or
// Cloud Map hiccup that would otherwise leave the server permanently
// absent from auto-assignment until the next deploy (issue #1681). After
// exhaustion, Start fails closed: an undiscoverable server cannot safely admit
// sessions whose later fleet-close work depends on reaching every live owner.
func (s *UdpServer) registerWithCloudMapWithRetry() error {
	return s.runRegisterWithRetry(s.registerWithCloudMap, cloudMapRegisterInitialAttempts, cloudMapRegisterInitialBackoff)
}

// runRegisterWithRetry is the parameterized retry loop that
// registerWithCloudMapWithRetry delegates to. Split out so tests can
// drive the loop with a fake register fn and a near-zero backoff
// without paying boot timing in the test path.
func (s *UdpServer) runRegisterWithRetry(register func() error, attempts int, backoff time.Duration) error {
	if register == nil || attempts <= 0 {
		return errors.New("Cloud Map registration retry requires a callback and positive attempt budget")
	}
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		err := register()
		if err == nil {
			instanceID, instanceAZ, asgName := s.snapshotInstanceIdentity()
			// %.12s safely truncates to 12 chars without panicking on a
			// shorter pubkey (a 32-byte key always exceeds 12 base64 chars,
			// but guarded against future encoding changes anyway).
			log.Info("Registered with Cloud Map: instance=%s, az=%s, asg=%s, pubkey=%.12s...",
				instanceID, instanceAZ, asgName, s.device.PublicKeyBase64())
			return nil
		}
		lastErr = err
		if attempt == attempts {
			log.Error("Cloud Map registration failed after %d attempts: %v (server remains unavailable)", attempts, err)
			if s.metrics != nil {
				s.metrics.IncrCounter(MetricCloudMapRegisterFailure)
			}
			break
		}
		log.Warning("Cloud Map registration attempt %d/%d failed: %v (retrying in %s)",
			attempt, attempts, err, backoff)
		time.Sleep(backoff)
	}
	return fmt.Errorf("Cloud Map registration required before accepting traffic: %w", lastErr)
}

// cloudMapRegisterRefreshRoutine periodically re-asserts the Cloud Map
// registration so a one-shot boot failure (or external drift) recovers
// without operator intervention (issue #1681). Cadence is
// cloudMapRegisterRefreshInterval. Exits on s.signals.stop.
func (s *UdpServer) cloudMapRegisterRefreshRoutine() {
	ticker := time.NewTicker(cloudMapRegisterRefreshInterval)
	defer ticker.Stop()
	s.runRefreshLoop(ticker.C, s.registerWithCloudMap)
}

// runRefreshLoop is the parameterized body that cloudMapRegisterRefreshRoutine
// delegates to. Split out so tests can drive ticks via a buffered channel and
// inject a stub register func instead of waiting on a real 5-minute timer and
// hitting the AWS SDK.
func (s *UdpServer) runRefreshLoop(tickCh <-chan time.Time, register func() error) {
	defer s.wg.Done()
	for {
		select {
		case <-s.signals.stop:
			return
		case <-tickCh:
			// Don't re-register after Stop() has begun — Stop() sets
			// s.running=false before calling DeregisterInstance, and
			// drainACConnections holds the close(stop) until the drain
			// completes. A tick landing in that window would silently
			// re-assert the registration after deregister, negating the
			// "deregister before terminating" guarantee.
			if !s.running.Load() {
				return
			}
			if err := register(); err != nil {
				log.Warning("Cloud Map registration refresh failed: %v", err)
				if s.metrics != nil {
					s.metrics.IncrCounter(MetricCloudMapRegisterRefreshFailure)
				}
				continue
			}
			if s.metrics != nil {
				s.metrics.IncrCounter(MetricCloudMapRegisterRefresh)
			}
		}
	}
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
	remoteAddrStr := conn.ConnData.RemoteAddr.String()
	log.Info("Send [%s] packet (%s -> %s), %d bytes", pktType, s.listenAddrStr, remoteAddrStr, len(pkt.Content))
	log.Evaluate("Send [%s] packet (%s -> %s), %d bytes", pktType, s.listenAddrStr, remoteAddrStr, len(pkt.Content))

	if conn.isWebRTC && conn.dc != nil {
		err = conn.dc.Send(pkt.Content)
		return len(pkt.Content), err
	}

	ctx, cancel := context.WithTimeout(s.LifecycleCtx(), ForwardTimeout)
	defer cancel()
	return s.writeUDPDatagram(ctx, pkt.Content, conn.ConnData.RemoteAddr, time.Time{})
}

// packetFromUDPDatagram copies one socket read into its owned Packet storage.
// Standard direct NHP traffic remains hard-capped at PacketBufferSize. Only an
// exact, clear-header NHP_RLY envelope may use the dedicated larger transport
// buffer needed to contain a complete standard inner packet. This pre-auth
// allocation is still bounded: recvPacketRoutine applies the per-source rate
// limiter first, the socket reads at most 6145 bytes, the type and exact length
// are checked before borrowing the separate relay sync.Pool, and the fixed
// receive queue bounds concurrent ownership. The server's UDP 62206 SG admits
// the existing main-VPC sources plus the relay-DMZ /24s; Noise authentication
// and registered-relay-key validation, not the SG alone, authorize NHP_RLY.
// Authenticated returns target the relay's separate private UDP 62207 socket.
// The accepted steady-state cost is one bounded copy (at most 6 KiB) for each
// admitted control datagram. That copy is the ownership boundary that lets the
// single socket reader immediately reuse readBuf; placing it after the block and
// rate-limit gates also avoids pool traffic for rejected floods. Do not restore
// the old read-directly-into-a-pooled-packet path without preserving truncation
// observability and independent ownership across the asynchronous receive queue.
func packetFromUDPDatagram(device *core.Device, raw []byte, receivedAtNanos int64) (*core.Packet, int, error) {
	if receivedAtNanos <= 0 {
		return nil, 0, fmt.Errorf("missing UDP receipt time")
	}
	if len(raw) < core.HeaderCommonSize {
		return nil, 0, fmt.Errorf("packet too short")
	}
	tmp := &core.Packet{Content: raw}
	headerType, payloadSize := tmp.HeaderTypeAndSize()
	if len(raw) > core.RelayPacketBufferSize {
		return nil, headerType, fmt.Errorf("packet exceeds relay transport limit")
	}
	if len(raw) > core.PacketBufferSize {
		if headerType != core.NHP_RLY {
			return nil, headerType, fmt.Errorf("oversized direct packet type %s", core.HeaderTypeToString(headerType))
		}
		if len(raw) != tmp.MinimalLength()+payloadSize {
			return nil, headerType, fmt.Errorf("relay packet total size is incorrect")
		}
		pkt := device.AllocateRelayPacket()
		copy(pkt.Content, raw)
		pkt.Content = pkt.Content[:len(raw)]
		pkt.HeaderType = headerType
		pkt.ReceivedAtNanos = receivedAtNanos
		return pkt, headerType, nil
	}

	// Preserve the standard-packet fast path exactly as it behaved before relay
	// envelopes existed: RecvPrecheck performs structural protocol validation
	// after this copy. Do not mirror the oversized branch's exact
	// clear-header length check here; doing so would silently change admission
	// semantics for every existing <= 4,096-byte direct NHP packet.
	pkt := device.AllocatePoolPacket()
	if pkt == nil {
		return nil, headerType, fmt.Errorf("packet pool exhausted")
	}
	copy(pkt.Content, raw)
	pkt.Content = pkt.Content[:len(raw)]
	pkt.HeaderType = headerType
	pkt.ReceivedAtNanos = receivedAtNanos
	return pkt, headerType, nil
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
	if s.observePreCheckThreatCache != nil {
		s.observePreCheckThreatCache(preCheckThreats)
	}
	// Load-bearing single-reader invariant: this buffer is reused by exactly one
	// recvPacketRoutine goroutine and every admitted datagram is copied before the
	// next read. The extra byte makes a datagram above the authenticated relay
	// envelope ceiling observable instead of accepting a truncated prefix;
	// packetFromUDPDatagram moves admitted bytes into independently owned storage.
	readBuf := make([]byte, core.RelayPacketBufferSize+1)
	minLen := core.RelayPacketMinimalLength

	for {
		select {
		case <-s.signals.stop:
			return

		default:
		}

		// udp recv, blocking until packet arrives or conn.Close()
		n, remoteAddr, err := s.listenConn.ReadFromUDP(readBuf)
		if err != nil {
			log.Error("[Server] ReadFromUDP on %s failed: %v", s.listenAddrStr, err)
			if n == 0 {
				// listenConn closed
				return
			}
			continue
		}
		recvTime := time.Now().UnixNano()
		addrStr := remoteAddr.String()
		// IP-only key for blockAddrMap (#1160 T3-12), rate limiter, and
		// preCheckThreats — computed once per packet so the hot path
		// doesn't re-stringify on every consumer.
		ipStr := remoteAddr.IP.String()

		// add total recv bytes
		atomic.AddUint64(&s.stats.totalRecvBytes, uint64(n))

		if n < minLen {
			log.Error("[Server] received UDP packet from %s is too short (%d bytes, min %d), discarding", addrStr, n, minLen)
			continue
		}

		if s.isBlockedIP(ipStr) {
			log.Critical("Remote address %s is being blocked at the moment, discard.", addrStr)
			continue
		}

		// Per-source-IP rate limiting: drop packets exceeding the configured
		// rate before any cryptographic processing (HMAC, ECDH). This is the
		// application-level defense-in-depth layer; iptables provides the
		// kernel-level first line of defense.
		if s.rateLimiter != nil && !s.rateLimiter.Allow(ipStr) {
			drops := s.rateLimitDrops.Add(1)
			s.metrics.IncrCounter(MetricUDPRateLimitDrop)
			if drops == 1 || drops%1000 == 0 {
				log.Warning("[Server] rate limited UDP packet from %s (total drops: %d)", addrStr, drops)
			}
			continue
		}

		pkt, clearType, packetErr := packetFromUDPDatagram(s.device, readBuf[:n], recvTime)
		if packetErr != nil {
			s.recordPreCheckThreat(preCheckThreats, ipStr)
			msgType := core.HeaderTypeToString(clearType)
			log.Warning("Receive [%s] packet (%s -> %s), outer-size gate error: %v", msgType, addrStr, s.listenAddrStr, packetErr)
			continue
		}
		//log.Trace("receive udp packet (%s -> %s): %+v", addrStr, s.listenAddrStr, pkt.Content)

		typ, _, err := s.device.RecvPrecheck(pkt) // this check also records packet header type
		msgType := core.HeaderTypeToString(typ)
		log.Info("Receive [%s] packet (%s -> %s), %d bytes", msgType, addrStr, s.listenAddrStr, n)
		log.Evaluate("Receive [%s] packet (%s -> %s), %d bytes", msgType, addrStr, s.listenAddrStr, n)
		if err != nil {
			s.recordPreCheckThreat(preCheckThreats, ipStr)
			s.device.ReleasePoolPacket(pkt)
			log.Warning("Receive [%s] packet (%s -> %s), precheck error: %v", msgType, addrStr, s.listenAddrStr, err)
			log.Evaluate("Receive [%s] packet (%s -> %s) precheck error: %v", msgType, addrStr, s.listenAddrStr, err)
			continue
		}
		s.remoteConnectionMapMutex.Lock()
		conn, found := s.remoteConnectionMap[addrStr]
		s.remoteConnectionMapMutex.Unlock()

		// Appendix A2.1 KPL is deliberately unauthenticated and exists only
		// to maintain an already-established UDP tuple. A structurally valid
		// keepalive therefore cannot establish a connection or clear the
		// source-IP precheck threat history. Known tuples still receive it so
		// their connection routine can refresh the idle timer.
		if pkt.HeaderType == core.NHP_KPL && !found {
			s.device.ReleasePoolPacket(pkt)
			log.Info("Discard [NHP_KPL] from unknown UDP tuple (%s -> %s)", addrStr, s.listenAddrStr)
			continue
		}
		// Appendix A2.1 KPL is unauthenticated, so it must never erase
		// structural-failure history. Other structurally valid 1.1 packets keep
		// the existing cache-clear behavior until a separately negotiated keyed
		// header profile exists.
		if pkt.HeaderType != core.NHP_KPL {
			preCheckThreats.Clear(ipStr)
		}

		if found {
			// existing connection
			atomic.StoreInt64(&conn.ConnData.LastLocalRecvTime, recvTime)
			conn.ConnData.ForwardInboundPacket(pkt)

		} else {
			// create new connection if there is room
			if !s.globalCapAdmits() {
				log.Critical("Reached maximum concurrent connection. Discard new packet from addr: %s", addrStr)
				s.device.ReleasePoolPacket(pkt)
				continue
			}

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
			timeoutMs := DefaultAgentConnectionTimeoutMs
			switch {
			case conn.isACConnection:
				timeoutMs = DefaultACConnectionTimeoutMs
				log.Debug("Received new ac connection from %s", addrStr)
			case conn.isDBConnection:
				timeoutMs = DefaultDBConnectionTimeoutMs
				log.Debug("Received new db connection from %s", addrStr)
			}

			// setup new routine for connection
			conn.ConnData = &core.ConnectionData{
				InitTime:             recvTime,
				LastLocalRecvTime:    recvTime, // not in multithreaded yet, directly assign value
				Device:               s.device,
				LocalAddr:            s.listenAddr,
				RemoteAddr:           remoteAddr,
				IngressTransport:     core.IngressTransportDirectUDP,
				CookieStore:          &core.CookieStore{},
				RemoteTransactionMap: make(map[uint64]*core.RemoteTransaction),
				SendQueue:            make(chan *core.Packet, PacketQueueSizePerConnection),
				RecvQueue:            make(chan *core.Packet, PacketQueueSizePerConnection),
				BlockSignal:          make(chan struct{}),
				SetTimeoutSignal:     make(chan struct{}, 1),
				StopSignal:           make(chan struct{}),
			}
			conn.ConnData.InitTimeoutMs(timeoutMs)
			s.admitNewConnection(conn, addrStr)

			conn.ConnData.ForwardInboundPacket(pkt)

			log.Info("Accept new UDP connection from %s to %s", addrStr, s.listenAddrStr)

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

// globalCapAdmits reports whether the global MaxConcurrentConnection
// cap admits a new connection. As side effects it flips overload mode
// on when the map crosses OverloadConnectionThreshold (under the lock)
// and, on the reject path, increments MetricGlobalCapRejections (after
// releasing the lock — see below).
//
// The overload flip and the cap decision are independent reads of the
// same map-size snapshot n; neither gates the other. The pre-fix bug
// (#1525) was `if overload { ... } else if cap { reject }`, which made
// the cap branch unreachable once the map crossed the (lower) overload
// threshold. Keep them independent — do NOT fuse the two back into
// `if/else if`, which re-introduces #1525.
//
// Overload is flipped BEFORE the cap decision so the flag still
// reflects map size on the reject path. recvPacketRoutine alone
// would always set overload on a prior admit before reaching the
// cap; webrtcserver's DataChannel admit (#1569) bypasses this
// helper entirely, so the map can land above OverloadConnectionThreshold
// without recvPacketRoutine ever running. Doing the overload flip
// first means a recv packet that lands the cap-reject path still
// updates the flag honestly. Revisit when #1569 lands and webrtc
// routes through this helper — at that point the rationale weakens.
//
// MetricGlobalCapRejections is incremented AFTER Unlock, not before
// the return, because IncrCounter takes the publisher mutex and
// remoteConnectionMapMutex must not nest the publisher mutex (see
// endpoints/server/CLAUDE.md); its only permitted nested lock is overloadMu.
// This mirrors admitNewConnection's
// eviction counter: mutate-under-lock, unlock, then increment. The
// counter treats every false return as a dropped packet, so callers
// MUST discard on false — do not reuse this as a non-dropping capacity
// probe, or the operator tripwire over-counts. recvPacketRoutine is the
// sole caller today and does exactly that.
//
// The deferred Unlock is dropped (explicit Unlock) so the increment
// lands outside the lock. That is safe only because the remaining
// under-lock work — len() and the bounded overload publication — cannot panic,
// so there is no leaked-mutex path. A future edit that adds
// panic-able work under this lock must restore a defer (or unlock on
// the panic path) before doing so.
//
// "Admits" not "reserves": the function does not insert into the
// map. admitNewConnection re-acquires remoteConnectionMapMutex
// before mutating it; the brief unlocked window between is the same
// TOCTOU window that lived inline in recvPacketRoutine.
func (s *UdpServer) globalCapAdmits() bool {
	s.remoteConnectionMapMutex.Lock()
	admit := s.globalCapAdmitsLocked()
	s.remoteConnectionMapMutex.Unlock()

	if !admit {
		s.metrics.IncrCounter(MetricGlobalCapRejections)
	}
	return admit
}

// globalCapAdmitsLocked applies the global-cap decision while
// remoteConnectionMapMutex is already held. Callers must increment
// MetricGlobalCapRejections after unlocking when this returns false.
func (s *UdpServer) globalCapAdmitsLocked() bool {
	n := len(s.remoteConnectionMap)
	if n > OverloadConnectionThreshold {
		s.setConnectionOverload(true)
	}
	return n < MaxConcurrentConnection
}

func (s *UdpServer) setConnectionOverload(overloaded bool) {
	s.overloadMu.Lock()
	defer s.overloadMu.Unlock()
	s.connectionOverload.Store(overloaded)
	s.publishOverloadLocked()
}

func (s *UdpServer) setHandlerOverload(overloaded bool) {
	s.overloadMu.Lock()
	defer s.overloadMu.Unlock()

	// A dispatch/release decides from an earlier channel snapshot. Re-check
	// while serializing the pressure transition so a shedder that observed a
	// full partition cannot re-enable cookie mode after the final recovery
	// release, and a stale release cannot clear it above the hysteresis floor.
	next := overloaded
	if s.handlerSem != nil {
		next = s.handlerOverload.Load()
		inFlight := int64(len(s.handlerSem))
		if overloaded && inFlight >= int64(cap(s.handlerSem)) {
			next = true
		} else if !overloaded && inFlight <= handlerPressureRecoveryThreshold(cap(s.handlerSem)) {
			next = false
		}
	}
	s.handlerOverload.Store(next)
	s.publishOverloadLocked()
}

// publishOverloadLocked combines independent pressure sources. Neither handler
// recovery nor connection cleanup may clear cookie mode while the other source
// is still above its threshold. The caller holds overloadMu across its source
// update and this derived write.
func (s *UdpServer) publishOverloadLocked() {
	if s.device != nil {
		s.device.SetOverload(s.connectionOverload.Load() || s.handlerOverload.Load())
	}
}

// admitNewConnection registers conn in remoteConnectionMap. For agent
// conns it also enforces MaxAgentConnsPerIP via a FIFO list per source
// IP, closing the oldest entry's evictSignal when the bucket is full.
// Trusted infra conns (AC, DB, synthetic outbound server-peer, and WebRTC)
// bypass the per-IP cap because (a) they pass an identity gate before
// being trusted or are selected from server assignment state, and (b)
// capping them would risk evicting live infra traffic during NAT churn
// or forwarded-knock fan-in from one source IP.
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
	s.remoteConnectionMapMutex.Lock()
	evictedAddr := s.admitNewConnectionLocked(conn, addrStr)
	s.remoteConnectionMapMutex.Unlock()

	s.recordPerIPEviction(evictedAddr)
}

// admitNewConnectionLocked registers conn while remoteConnectionMapMutex
// is held. Use this when the caller needs check-and-insert to be atomic.
func (s *UdpServer) admitNewConnectionLocked(conn *UdpConn, addrStr string) (evictedAddr string) {
	s.remoteConnectionMap[addrStr] = conn
	if conn.isPerIPCapped() {
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
	return evictedAddr
}

func (conn *UdpConn) isPerIPCapped() bool {
	return !conn.isACConnection && !conn.isDBConnection && !conn.isServerPeer && !conn.isWebRTC
}

func (s *UdpServer) recordPerIPEviction(evictedAddr string) {
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
		s.setConnectionOverload(false)
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

	// See endpoints/ac/udpac.go::connectionRoutine — canonical placement + fences.
	idleTimeout := time.Duration(conn.ConnData.TimeoutMs()) * time.Millisecond
	idleTimer := time.NewTimer(idleTimeout)
	defer idleTimer.Stop()

	for {
		select {
		case <-s.signals.stop:
			return

		case <-conn.evictSignal:
			log.Debug("Connection routine: %s evicted by per-IP cap", addrStr)
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

		case _, ok := <-conn.ConnData.BlockSignal:
			if !ok {
				return
			}
			s.AddBlockAddr(conn.ConnData.RemoteAddr)
			return

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
				s.device.ReleasePoolPacket(pkt)
				log.Info("Receive [NHP_KPL] message (%s -> %s)", addrStr, s.listenAddrStr)
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

			pd := packetDataForInbound(conn.ConnData, pkt)
			// generic receive
			s.device.RecvPacketToMsg(pd)

		case pkt, ok := <-conn.ConnData.SendQueue:
			if !ok {
				return
			}
			idleTimer.Reset(idleTimeout)
			if pkt == nil {
				continue
			}
			if _, sendErr := s.SendPacket(pkt, conn); sendErr != nil {
				log.Error("[Server] failed to send packet to %s: %v", conn.ConnData.RemoteAddr.String(), sendErr)
			}
		}
	}
}

func packetDataForInbound(connData *core.ConnectionData, pkt *core.Packet) *core.PacketData {
	// RecvQueue has exactly two production producers: packetFromUDPDatagram and
	// packetFromWebRTCMessage. Both reject a non-positive receipt timestamp, and
	// the asynchronous parser intentionally relies on that stamped invariant.
	return &core.PacketData{
		BasePacket: pkt,
		ConnData:   connData,
		InitTime:   pkt.ReceivedAtNanos,
	}
}

func (s *UdpServer) BlockAddrRefreshRoutine() {
	defer s.wg.Done()
	defer log.Info("BlockedAddrRoutine stopped")

	log.Info("BlockedAddrRoutine started")

	// Armed at construction so the first refresh fires after one interval (matches prior time.After timing).
	refreshTimer := time.NewTimer(BlockAddrRefreshRate * time.Second)
	defer refreshTimer.Stop()
	for {
		select {
		case <-s.signals.stop:
			return

		case <-refreshTimer.C:
			s.RefreshBlockAddr()
			// Reset after work: no early-continue here. If RefreshBlockAddr ever grows an
			// early-return path, move the Reset above it so cycle stays interval+work_time.
			refreshTimer.Reset(BlockAddrRefreshRate * time.Second)
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
			if md == nil {
				// SendMessage rejects nil; this only protects direct channel
				// misuse from taking down the sender goroutine.
				log.Warning("sendMsgRoutine: received nil message")
				continue
			}
			// Some diverted encrypted-packet sends carry PrevParserData without
			// ConnData; those should fall through to the generic packet path
			// rather than panic on a nil transaction lookup.
			if md.PrevParserData != nil && s.device.IsTransactionResponse(md.HeaderType) {
				if md.ConnData == nil {
					log.Debug("sendMsgRoutine: sending %s response for transaction %d via generic packet path without ConnData",
						core.HeaderTypeToString(md.HeaderType), md.PrevParserData.SenderTrxId)
				} else {
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

// dispatchHandler runs fn(ppd) under the partitioned handler budget. Every arm
// first tries the general partition. A cookie-proven RKN or authenticated relay
// envelope may fall back to the protected reserve; first-flight public work
// cannot. Filling the general partition enables overload-cookie mode so later
// direct clients can obtain the source-bound proof needed for that reserve.
// All acquisition remains non-blocking, preserving #1163.
//
// A nil handlerSem means unbounded — a test-only affordance for bare
// &UdpServer{} literals; the constructor always initializes it.
func (s *UdpServer) dispatchHandler(ppd *core.PacketParserData, fn func(*core.PacketParserData) error) {
	bounded := s.handlerSem != nil
	usedGeneral := false
	usedProtected := false
	if bounded {
		select {
		case s.handlerSem <- struct{}{}:
			usedGeneral = true
			// len is an occupancy snapshot: a concurrent release may hide this
			// exact saturating admission, but the next rejected admission catches
			// it and setHandlerOverload re-checks occupancy before transitioning.
			if inFlight := len(s.handlerSem); s.protectedHandlerSem != nil && inFlight >= cap(s.handlerSem) {
				s.setHandlerOverload(true)
			}
		default:
			// The production server has a protected reserve. Small unit-test
			// servers that intentionally construct only a single semaphore do not
			// participate in overload-cookie recovery and must not retain stale
			// pressure state after a rejected dispatch.
			if s.protectedHandlerSem != nil {
				s.setHandlerOverload(true)
			}
			if s.protectedHandlerSem != nil && isProtectedHandlerType(ppd.HeaderType) {
				select {
				case s.protectedHandlerSem <- struct{}{}:
					usedProtected = true
				default:
				}
			}
			if usedProtected {
				break
			}
			s.metrics.IncrCounter(MetricHandlerBudgetExhausted)
			if isProtectedHandlerType(ppd.HeaderType) && s.protectedHandlerSem != nil {
				s.metrics.IncrCounter(MetricHandlerProtectedReserveExhausted)
			}
			if sheds := s.handlerShedCount.Add(1); sheds == 1 || sheds%1000 == 0 {
				log.Warning("[Server] handler budget (general=%d protected=%d) exhausted, shedding %s from %s (total sheds: %d)",
					cap(s.handlerSem), cap(s.protectedHandlerSem), core.HeaderTypeToString(ppd.HeaderType),
					ppd.ConnData.RemoteAddr.String(), sheds)
			}
			return
		}
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		// SCOPE: this recovers panics on THIS goroutine's stack only. A handler
		// that spawns its own `go func()` is not covered — handleNhpOpenResource's
		// AC-open fan-out is the live example, and a panic in one of those inner
		// goroutines still takes the process down. Do not read this guard as
		// "handlers can no longer crash the server". dispatchAsync (NHP_AOL,
		// NHP_FWD, NHP_FRT) has no recover at all, by the same reasoning.
		//
		// CLIENT-VISIBLE EFFECT: the request is dropped with no response
		// synthesized, so the peer waits out its own timeout instead of getting
		// a fast failure. No half-formed ack can escape: a response is built in
		// full and handed to RemoteTransaction.SendMessage as one `NextMsgCh <-
		// md` channel send, so a panic lands strictly before that handoff (peer
		// sees nothing) or strictly after it (peer sees a complete, already-
		// queued message). There is no incremental write to tear.
		defer func() {
			if r := recover(); r != nil {
				// Every deref below is guarded. A panic raised inside this
				// deferred function runs AFTER recover() has already returned,
				// so nothing recovers it — it would crash the process and
				// defeat the hardening this block exists to provide. ConnData
				// is a *ConnectionData, so it needs its own check.
				remote, htype := "<unknown>", "<unknown>"
				// -1 is the gate key for a nil ppd: it cannot collide with a
				// real header type, so an unknown-shape recovery gets its own
				// stack budget instead of borrowing NHP_KPL's.
				panicHeaderType := -1
				if ppd != nil {
					panicHeaderType = ppd.HeaderType
					htype = core.HeaderTypeToString(ppd.HeaderType)
					if ppd.ConnData != nil && ppd.ConnData.RemoteAddr != nil {
						remote = ppd.ConnData.RemoteAddr.String()
					}
				}
				// Recovering here removes the process crash that used to make
				// this class visible to the stderr "panic:" filter
				// (server_panic), so this log line is now the ONLY alarm
				// signal for a handler panic. Keep "dispatchHandler" plus
				// ErrRuntimePanic's message text in it; Terraform's
				// server-handler-panic log filter keys on both.
				//
				// The filter is an AND match over one log event, and both terms
				// land in one because slog's structured handlers escape control
				// characters: debug.Stack()'s newlines become literal
				// backslash-n, so the whole record is a single physical line
				// whatever order the fields render in. THAT is the load-bearing
				// invariant. It is a property of the structured handler, not of
				// JSON specifically — slog.TextHandler escapes too, so a
				// JSON->Text swap is safe; a handler that writes the message RAW
				// is the hazard. TestLoggerEmitsSingleLineRecords (nhp/log) pins
				// it at the source, and TestDispatchHandler_RecoverSurvives
				// AdversarialPanicValue pins it end to end here.
				//
				// Field order is a second-order concern that only bites if the
				// handler ever becomes line-oriented: Error() renders
				// "<msg>: <extra>", keeping ErrRuntimePanic's message ahead of
				// the stack, so even split per-line the first line would carry
				// both terms. Reversing that in WithExtra would push the message
				// past the stack. Under the JSON handler neither matters.
				// (The AC solves the same problem with a direct
				// MetricUDPHandlerPanic counter — see endpoints/ac/udpac.go
				// recoverUDPHandler, nhp#1423. A counter is used there because
				// the log line carries no stack; here the stack is the
				// operator's root-cause handle, so the signal rides the log.)
				// The stack is rate-limited; the alarm-bearing line is NOT. A
				// remote-reachable parser panic is attacker-triggerable at packet
				// rate, and a full debug.Stack() per packet turns a correctness
				// bug into unbounded CloudWatch ingestion — a billing-DoS on the
				// same signal that is supposed to page us. Every recovery still
				// emits both filter terms, so ServerHandlerPanic counts them all;
				// only the multi-KB stack is capped, and the suppressed count
				// rides the next stack-bearing line so nothing is silently lost.
				// The panic VALUE is bounded too, not just the stack. A runtime
				// fault carries short text, but a handler that panics with an
				// attacker-derived string would otherwise render it in full on
				// every recovery — the same amplification the stack cap closes,
				// just through the one field the cap doesn't cover.
				value := truncateForLog(fmt.Sprintf("%v", r), maxHandlerPanicValueLen)
				detail := value
				gate := s.handlerPanicStackGateFor(panicHeaderType)
				if gate.allow() {
					// Swap on the same gate that admitted this stack, so the
					// count describes THIS header type's suppressed stacks.
					if suppressed := gate.suppressed.Swap(0); suppressed > 0 {
						detail = fmt.Sprintf("%s (%d stack traces suppressed for this header type since the previous one)\n%s",
							value, suppressed, debug.Stack())
					} else {
						detail = fmt.Sprintf("%s\n%s", value, debug.Stack())
					}
				} else {
					gate.suppressed.Add(1)
				}
				err := core.ErrRuntimePanic.WithExtra(errors.New(detail))
				log.Critical("dispatchHandler [%s] from %s recovered from panic: %v",
					htype, remote, err)
			}
		}()
		if usedGeneral {
			defer func() {
				<-s.handlerSem
				remaining := int64(len(s.handlerSem))
				recoveryThreshold := handlerPressureRecoveryThreshold(cap(s.handlerSem))
				// remaining is the post-release snapshot; reload occupancy in
				// the condition so a concurrent re-acquire cannot make this
				// goroutine clear pressure from a stale below-threshold value.
				if s.protectedHandlerSem != nil && remaining <= recoveryThreshold && int64(len(s.handlerSem)) <= recoveryThreshold {
					s.setHandlerOverload(false)
				}
			}()
		} else if usedProtected {
			defer func() {
				<-s.protectedHandlerSem
			}()
		}
		if err := fn(ppd); err != nil {
			log.Error("[Server] %s handler failed: %v", core.HeaderTypeToString(ppd.HeaderType), err)
		}
	}()
}

func isProtectedHandlerType(headerType int) bool {
	// Security boundary: this classifier is reached only after core has built a
	// decrypted PacketParserData. For NHP_RKN, parseHeadPacket in
	// nhp/core/responder.go requires the source-bound overload cookie whenever
	// stateless cookie parameters are configured; the end-to-end rejection
	// fences are TestCookieVerifyRejectsBadCookieOnNonOverloadedServer and
	// TestCookieVerifyRejectsWrongRemote. Do not route pre-validation headers
	// here or the protected reserve would become source-spoofable.
	return headerType == core.NHP_RKN || headerType == core.NHP_RLY || headerType == core.NHP_EXT
}

func handlerPressureRecoveryThreshold(generalCapacity int) int64 {
	// General pressure turns on overload-cookie mode at capacity and stays on
	// until occupancy falls to 75%, avoiding mode flaps near the boundary. The
	// threshold derives from the actual channel capacity so production and
	// deliberately small test partitions share one formula.
	return int64(generalCapacity * 3 / 4)
}

// maxHandlerPanicValueLen bounds the recovered panic VALUE rendered into the
// recovery line. Runtime faults carry short text, but a handler that panics
// with an attacker-derived string would otherwise render it in full on every
// recovery — the stack cap alone does not cover that field. 512 bytes keeps
// every realistic runtime message intact (the longest in the tree are well
// under it) while removing the amplification.
const maxHandlerPanicValueLen = 512

// truncateForLog clips s to limit bytes, marking the clip so a truncated value
// is never mistaken for the whole one.
//
// The cut backs off to a rune boundary rather than splitting a multi-byte
// character. Today's sink is the JSON logger, which would escape a partial rune
// to U+FFFD rather than emit invalid output — so this is belt-and-braces for
// that path, and correctness for any future caller with a sink that does not
// sanitize.
//
// The back-off is bounded to UTFMax-1 bytes, which is all a boundary split can
// ever require. An unbounded walk would keep deleting good bytes when the input
// was ALREADY invalid UTF-8 before the limit — in the worst case consuming the
// whole prefix and returning only the truncation marker. In that case the input
// is malformed no matter where it is cut, so clip at the limit and let the sink
// sanitize.
func truncateForLog(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	cut := limit
	for back := 0; back < utf8.UTFMax-1 && cut > 0; back++ {
		if utf8.ValidString(s[:cut]) {
			break
		}
		cut--
	}
	if !utf8.ValidString(s[:cut]) {
		cut = limit
	}
	return s[:cut] + fmt.Sprintf("...[truncated, %d bytes total]", len(s))
}

// handlerPanicStackInterval bounds how often dispatchHandler's recovery line
// carries a full debug.Stack(). One per minute keeps a genuine (zero-baseline)
// panic fully diagnosable on its first occurrence while capping what a
// packet-rate attacker can drive into the log group. It is deliberately far
// shorter than the alarm's 5-minute period, so every alarm window that fires
// still has at least one stack to triage from.
const handlerPanicStackInterval = time.Minute

// handlerPanicStackGate is one header type's stack budget. Both fields belong
// to the same type so the "N suppressed" annotation on a stack-bearing line
// describes that type's own stream and nothing else.
//
// KNOWN PROPERTIES of the suppressed count, both deliberately not fixed. It is
// a triage hint, NOT the source of truth: the alarm-bearing line is emitted on
// every recovery, so ServerHandlerPanic in CloudWatch is the authoritative
// occurrence count and is always exact and complete.
//
//  1. The count rides the NEXT stack-bearing line for its type, so the tail of
//     a final burst is never emitted — if a type stops panicking (bug fixed,
//     traffic shifted), its last N suppressed stacks go unreported. Flushing
//     the tail would need a timer or a drain on Stop(), and Stop() carries six
//     load-bearing ordering invariants (see the shutdown section in
//     endpoints/server/CLAUDE.md).
//  2. Under concurrent same-type panics the Swap(0) here can interleave with an
//     Add(1) on a suppressed goroutine, so a given line's N can be off by one
//     in either direction. Serializing it would mean a lock on the panic path
//     to make a diagnostic annotation exact.
//
// Both are acceptable precisely because of the first paragraph: no count that
// anything depends on is at stake.
type handlerPanicStackGate struct {
	lastNanos  atomic.Int64
	suppressed atomic.Int64
}

// handlerPanicStackGateFor returns the gate for a header type, creating it on
// first use. -1 is the shared key for "no usable header type": a nil ppd, or a
// value outside the registry.
//
// The key domain is bounded HERE rather than relying on callers, so the map can
// never exceed one entry per registered header type plus the -1 bucket (~36).
// dispatchHandler is only reached with validated types today, so the fold is
// unreachable — but this map is keyed by a field that originates in a received
// packet, and "an attacker cannot choose this value" is exactly the kind of
// invariant that quietly stops holding. Folding costs one bounds check and
// removes the unbounded-growth vector by construction.
func (s *UdpServer) handlerPanicStackGateFor(headerType int) *handlerPanicStackGate {
	if core.HeaderTypeToString(headerType) == "UNKNOWN" {
		headerType = -1
	}
	// Load before LoadOrStore: this runs once per recovered panic, which under
	// a remote-triggerable handler panic is once per packet. LoadOrStore would
	// allocate a throwaway gate on every one of those, on the exact path being
	// hardened against amplification. After the first panic of a type the
	// steady state is a lock-free read.
	if gate, ok := s.handlerPanicStackGates.Load(headerType); ok {
		return gate.(*handlerPanicStackGate)
	}
	gate, _ := s.handlerPanicStackGates.LoadOrStore(headerType, &handlerPanicStackGate{})
	return gate.(*handlerPanicStackGate)
}

// allowHandlerPanicStack reports whether this recovery may emit a stack trace,
// admitting at most one per handlerPanicStackInterval PER HEADER TYPE.
//
// Keyed per header type, not globally, because different header types are
// different handlers and therefore different bugs: a global budget lets a
// benign panic on one message type swallow the stack of an unrelated panic on
// another within the same minute — losing distinct diagnostic information at
// exactly the moment two things are failing at once. The bound stays small and
// fixed: at most one stack per minute per header type, over a registry of ~33
// types of which only the dispatched handlers can reach here.
//
// The CompareAndSwap makes concurrent panics on the SAME type elect exactly one
// winner rather than all passing a read-then-write check.
func (g *handlerPanicStackGate) allow() bool {
	now := time.Now().UnixNano()
	for {
		prev := g.lastNanos.Load()
		if prev != 0 && now-prev < int64(handlerPanicStackInterval) {
			return false
		}
		if g.lastNanos.CompareAndSwap(prev, now) {
			return true
		}
	}
}

// dispatchAsync tracks trusted-peer handlers without applying the public
// handlerSem budget. dispatchReceivedMessage is itself called by a wg-tracked
// receive loop, and Add completes synchronously before that loop can finish, so
// Stop cannot reach a zero counter before the handler is registered.
func (s *UdpServer) dispatchAsync(fn func()) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		fn()
	}()
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
//
// Agent-facing handshake-class arms (KNK/RKN/EXT/DHP_KNK, OTP, REG,
// LST, DAR, DRG, DAV, and the relay-forwarded knock RLY) go through
// dispatchHandler, which caps concurrent handlers at
// MaxConcurrentHandlers and sheds when full — these are the
// attacker-influenced, expensive arms (a knock runs buildKnockAck +
// an AC-open round-trip). Infra arms stay unbounded: they arrive from
// IP-gated trusted peers and must not compete with an agent-knock flood
// for slots — shedding a legitimate AC-online behind a flood would be
// worse than the flood itself. AOL/DOL (AC/DB online) and RVA
// (revocation-ack) are also cheap. FWD/FRT (server-to-server) are the
// exception worth naming: a forwarded knock runs the SAME expensive
// buildKnockAck + AC-open pipeline, so leaving it unbounded is
// load-bearing on the peer-server trust boundary. It's safe because
// NHP_FWD is accepted only from source-restricted peer servers (not
// spoofable within the boundary). The transitive bound is PER peer, not a
// global 4096: N peers can drive up to 4096×N expensive FWD handlers
// here, none counted against this server's budget; and it assumes a
// homogeneous fleet — an un-upgraded peer mid-rollout has no handlerSem,
// and a single compromised peer sidesteps the ceiling. Acceptable only
// because that aggregate stays inside the trusted server mesh; #3100
// tracks bounding FWD/FRT per-peer to close the residual.
func (s *UdpServer) dispatchReceivedMessage(ppd *core.PacketParserData) {
	switch ppd.HeaderType {
	// DHP_KNK intentionally enters HandleKnockRequest but returns before the
	// forwardable-knock BasePacketContent path; do not narrow this dispatcher to
	// IsForwardableKnockType.
	case core.NHP_KNK, core.NHP_RKN, core.NHP_EXT, core.DHP_KNK:
		s.dispatchHandler(ppd, s.HandleKnockRequest)

	case core.NHP_AOL:
		// Infra (AC online) — unbounded; see dispatchReceivedMessage doc.
		s.dispatchAsync(func() {
			if aolErr := s.HandleACOnline(ppd); aolErr != nil {
				log.Error("[Server] HandleACOnline failed: %v", aolErr)
			}
		})

	case core.NHP_DOL:
		// Infra (DB online) — unbounded.
		s.dispatchAsync(func() {
			if dolErr := s.HandleDBOnline(ppd); dolErr != nil {
				log.Error("[Server] HandleDBOnline failed: %v", dolErr)
			}
		})

	case core.NHP_OTP:
		s.dispatchHandler(ppd, s.HandleOTPRequest)

	case core.NHP_REG:
		s.dispatchHandler(ppd, s.HandleRegisterRequest)

	case core.NHP_LST:
		s.dispatchHandler(ppd, s.HandleListRequest)

	case core.NHP_DAR:
		s.dispatchHandler(ppd, s.HandleDHPDARMessage)

	case core.NHP_DRG:
		s.dispatchHandler(ppd, s.HandleDHPDRGMessage)

	case core.NHP_DAV:
		s.dispatchHandler(ppd, s.HandleDHPDAVMessage)

	// Server-to-server forwarding — infra, unbounded.
	case core.NHP_FWD:
		s.dispatchAsync(func() { s.HandleForwardRequest(ppd) })
	case core.NHP_FRT:
		s.dispatchAsync(func() { s.HandleForwardResult(ppd) })

	// NHP-Relay forwarded agent knock (#2208). Core dispatches NHP_RLY only
	// after its outer Noise packet decrypts as a configured relay peer; that
	// identity proof is why isProtectedHandlerType may grant reserve capacity.
	// Keep that coupling explicit if relay authentication or routing changes.
	// It runs the same knock pipeline as a direct knock (buildKnockAck + AC-open),
	// so it is bounded with the other agent-facing arms. HandleRelayForward
	// returns no error, so it is wrapped to the dispatchHandler signature.
	case core.NHP_RLY:
		s.dispatchHandler(ppd, func(p *core.PacketParserData) error {
			s.HandleRelayForward(p)
			return nil
		})

	// qURL v2 revocation ack from an AC (P4e Slice 3, #2793). Unsolicited
	// AC→server push acknowledging an NHP_REV; clears the per-AC-slot
	// pending-revoke tracker so the retry-until-ack loop stops. Infra
	// (AC→server), so unbounded like the other trusted-peer arms;
	// dispatched async so a slow handler cannot head-of-line-block the
	// receive queue.
	case core.NHP_RVA:
		s.dispatchAsync(func() {
			if ackErr := s.HandleRevocationAck(ppd); ackErr != nil {
				log.Error("[Server] HandleRevocationAck failed: %v", ackErr)
			}
		})

	default:
		// An unknown HeaderType reaching here means the upstream
		// parser accepted a type this dispatcher doesn't route —
		// either a protocol-version mismatch or a parser/dispatcher
		// drift. Log so ops can grep for it rather than drop silently.
		log.Warning("[Server] dispatchReceivedMessage: unhandled HeaderType %d", ppd.HeaderType)
	}
}

// AddAgentPeer registers an agent peer with both core.Device and the
// in-process agentPeerMap. Returns true when the pubkey was NOT
// already present in agentPeerMap — i.e., this call performed the
// first registration for that pubkey. Returns false when the pubkey
// was already mapped (a piggybacker in a singleflight-deduped
// concurrent resolve, or a redundant register from a different code
// path).
//
// The bool is load-bearing for MetricAgentFirstResolve single-counting
// under singleflight piggyback: without it, N concurrent first-knocks
// for the same fresh pubkey all reach this function via the same
// sfGroup slot and each independently increments the resolve counter
// (N for one resolve). The caller in resolveAgentPeerForKnock gates
// the IncrCounter on the returned bool so the metric semantics
// ("fires once per successful first-knock agent resolve") hold.
//
// Cross-map atomicity: the first inserter writes the pubkey into
// agentPeerMap AND calls device.AddPeer in the SAME critical
// section (agentPeerMapMutex held); a piggybacker that observes
// existed=true returns without invoking device.AddPeer. This
// closes the previous "agentPeerMap has the pubkey but
// device.peerMap doesn't yet" window so a future receive-path
// consumer that gates synchronously on device.peerMap (e.g.
// NHP_LST register/list, plugin handlers) can rely on both maps
// being populated together once agentPeerMap reflects the pubkey.
// Lock-order: agentPeerMapMutex → device.peerMapMutex (acquired
// by AddPeer). No existing code goes the reverse direction, so
// the nested chain is safe; documented in endpoints/server/CLAUDE.md's
// Lock Order section.
//
// No-op when DeviceType != NHP_AGENT — guards against callers
// accidentally adding an AC or DB peer through the agent path.
// Returns false in that case (no insertion occurred).
// computeEffectiveDisableAgentValidation resolves the operator's
// `DisableAgentValidation` setting against the cloud-mode
// override. The override flips false→true when cloud mode is on
// AND the agent peer DDB lookup is wired: the responder MUST skip
// agent pre-validation, otherwise every first knock from an
// unknown-but-registered agent fails at the responder layer
// before HandleKnockRequest can run the DDB lookup. Operator=true
// composes additively (the operator already wants the validation
// off, the override has nothing to do).
//
// Called by Start() at boot AND by updateBaseConfig() on hot-reload
// — without the hot-reload call site using this same helper, a
// server.toml edit that touches DisableAgentValidation flips the
// device option back to the operator literal `false` and the
// cloud-mode override is silently undone (every cloud-mode agent
// first-knock then fails at the responder layer with no metric to
// alarm on, because the lookup is still wired but never reached).
// TestUpdateBaseConfig_DisableAgentValidationHotReloadPreservesCloud-
// ModeOverride fences this.
func (s *UdpServer) computeEffectiveDisableAgentValidation(operatorVal bool) bool {
	cloudMode := s.storageConfig != nil && s.storageConfig.Backend == StorageBackendDynamoDB
	return operatorVal || (cloudMode && s.agentPeerLookup != nil)
}

// deviceOptions computes the complete DeviceOptions for the server device from
// conf + cloud mode. SINGLE SOURCE OF TRUTH: core.Device.SetOption REPLACES the
// whole DeviceOptions struct, so the Start-time NewDevice and the hot-reload
// SetOption (updateBaseConfig) must apply the SAME complete set — an option set
// in one path but omitted in the other silently resets to false on reload (this
// is what previously let a hot-reload reset DisableACPeerValidation). Add any new
// server device option here, not at the call sites.
func (s *UdpServer) deviceOptions(conf *Config) core.DeviceOptions {
	cloudMode := s.storageConfig != nil && s.storageConfig.Backend == StorageBackendDynamoDB
	return core.DeviceOptions{
		DisableAgentPeerValidation: s.computeEffectiveDisableAgentValidation(conf.DisableAgentValidation),
		DisableACPeerValidation:    cloudMode,
		// #2208: skip the relay source-IP pin so the shared-keypair fleet
		// authenticates by pubkey + relay.toml. No cloud-mode override — see the
		// Config.DisableRelayValidation doc.
		DisableRelayPeerValidation: conf.DisableRelayValidation,
	}
}

func (s *UdpServer) AddAgentPeer(agent *core.UdpPeer) (added bool) {
	if agent.DeviceType() != core.NHP_AGENT {
		// Caller-bug guard: a non-AGENT peer reaching the agent path
		// means an AC/DB peer was misrouted (typical cause: a refactor
		// that collapses AddACPeer + AddAgentPeer into a shared
		// dispatcher without preserving the type-check). Loud-log so
		// the regression doesn't masquerade as a piggybacker —
		// returning false here is otherwise indistinguishable from the
		// healthy "this caller wasn't the first inserter" return, and
		// MetricAgentFirstResolve would stay at 0 with no other signal.
		log.Warning("[Server] AddAgentPeer: refusing non-agent peer pubkey_b64_prefix=%q DeviceType=%v — caller bug or unintended cross-path dispatch",
			pubkeyLogPrefix(agent.PublicKeyBase64()), agent.DeviceType())
		return false
	}
	s.agentPeerMapMutex.Lock()
	defer s.agentPeerMapMutex.Unlock()
	// Initialize map if nil. In cloud mode there is no
	// etc/agent.toml, so updateAgentPeers (which constructs the
	// map at boot) never runs and the first knock-driven
	// resolveAgentPeerForKnock would otherwise nil-write-panic
	// here. Mirrors AddACPeer's lazy-init below for the same
	// reason — see TestAddAgentPeer_NilMap in udpserver_test.go.
	if s.agentPeerMap == nil {
		s.agentPeerMap = make(map[string]*core.UdpPeer)
	}
	pk := agent.PublicKeyBase64()
	if _, existed := s.agentPeerMap[pk]; existed {
		// Piggybacker: agentPeerMap already had this pubkey. The
		// device's peerMap has the same pointer (the first inserter
		// put it there in the same critical section below);
		// re-calling device.AddPeer would round-trip
		// device.peerMapMutex and take the udpPeersShareAddress
		// overwrite branch for a functionally identical
		// re-assignment. Skip it. Also leaves the existing peer
		// pointer in place so callers that captured it via
		// lookupAgentPeer keep observing the same identity.
		return false
	}
	s.agentPeerMap[pk] = agent
	// First inserter: also register the peer with core.Device in
	// the SAME critical section. Subsequent packets that go through
	// DisableAgentPeerValidation=false paths (e.g., NHP_LST
	// register/list ops) resolve via the noise responder. Nested
	// lock acquisition is safe — see the lock-order note in the
	// godoc above.
	s.device.AddPeer(agent)
	return true
}

// lookupAgentPeer returns the *core.UdpPeer mapped to pubKeyBase64
// under the agentPeerMapMutex, or nil if absent. Centralizes the
// map read so concurrent writers (AddAgentPeer) and readers
// (UpdateTee* / GetTee*) don't race under -race. The returned
// pointer outlives the lock: peers are never removed today
// (Phase-2 active-knock revocation tracks in #1943), and the peer's
// internally-locked setters/getters (SetTeePublicKeyBase64,
// TeePublicKeyBase64, etc.) are concurrency-safe on their own.
func (s *UdpServer) lookupAgentPeer(pubKeyBase64 string) *core.UdpPeer {
	s.agentPeerMapMutex.Lock()
	defer s.agentPeerMapMutex.Unlock()
	return s.agentPeerMap[pubKeyBase64]
}

func (s *UdpServer) UpdateTeePublicKeyAndConsumerEphemeralPublicKey(teePublicKeyBase64 string, consumerEphemeralPublicKeyBase64 string, agentPulicKey []byte) {
	if peer := s.lookupAgentPeer(base64.StdEncoding.EncodeToString(agentPulicKey)); peer != nil {
		peer.SetTeePublicKeyBase64(teePublicKeyBase64)
		peer.SetConsumerEphemeralPublicKeyBase64(consumerEphemeralPublicKeyBase64)
	}
}

func (s *UdpServer) GetTeePublicKeyBase64AndConsumerEphemeralPublicKeyBase64(agentPublicKey []byte) (teePublicKeyBase64 string, consumerEphemeralPublicKeyBase64 string) {
	if peer := s.lookupAgentPeer(base64.StdEncoding.EncodeToString(agentPublicKey)); peer != nil {
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

// applyAspMapDelta publishes a freshly-resolved *AuthServiceProviderData
// into s.authServiceMap via build-fresh-then-atomic-swap. This method
// allocates a fresh top-level map, copies existing entries, installs the
// new aspId, and swaps the pointer atomically under the write lock.
// Concurrent readers observe either the old or new map snapshot; any
// pointer already handed to a plugin remains valid for that plugin
// invocation.
//
// Fast path: pointer-equal install short-circuits (no fresh
// allocation). The resolver's cache-hit republish drives most calls
// through this path, so steady-state cost on the knock hot path is a
// single pointer-compare under the write lock.
//
// Also calls ensurePluginLoaded on every call — including the
// fast-path branch — so a DDB-only aspId (one never seen by
// updateResources) reaches FindPluginHandler with a populated entry.
// The fast-path-still-loads behavior covers the "second knock after
// restart" case: authServiceMap is rehydrated from the LRU cache hit
// but pluginHandlerMap is still empty for that aspId. The plugin-load
// happens AFTER authServiceMapMutex is released (CLAUDE.md lock-order
// invariant: pluginHandlerMapMutex never held while authServiceMapMutex
// is held) — best-effort, not under critical section. Callers MUST NOT
// rely on "plugin is loaded by the time applyAspMapDelta returns";
// today no caller does, but future code should treat the plugin-load
// as eventually-consistent.
//
// Nil aspId / nil aspData are programmer errors from the caller; we
// no-op rather than install a nil sentinel that would surface as a
// nil-deref in FindAuthSvcProvider readers.
//
// Onboarding-a-new-aspId-via-DDB-only failure mode: ensurePluginLoaded
// routes to loadPluginOnce with pluginPath="", which resolves
// statically-registered plugins only (init() RegisterPlugin calls).
// A future aspId added via DDB write WITHOUT a corresponding code
// change to compile in a `staticplugins/<aspId>/` package will
// resolve aspData here but reject downstream at FindPluginHandler.
// The reject is logged via ensurePluginLoaded's "no static plugin
// registered" Warning, but operators onboarding aspId #2 should
// know the DDB-write-alone is necessary-but-not-sufficient.
func (s *UdpServer) applyAspMapDelta(aspId string, asp *common.AuthServiceProviderData) {
	if aspId == "" || asp == nil {
		return
	}

	// RLock fast-path: the steady-state knock path is a cache-hit
	// republish that finds the same pointer already installed. Doing
	// the pointer-equal check under RLock lets every cache-hit knock
	// run in parallel (FindAuthSvcProvider readers also hold RLock)
	// instead of serializing on a write lock. The RUnlock-then-Lock
	// gap below is benign: a concurrent install of the SAME pointer
	// is a no-op; a concurrent install of a DIFFERENT pointer wins
	// under the subsequent Lock and we still publish correctly.
	s.authServiceMapMutex.RLock()
	existing, ok := s.authServiceMap[aspId]
	s.authServiceMapMutex.RUnlock()
	if ok && existing == asp {
		s.ensurePluginLoaded(aspId)
		return
	}

	// Slow path: mismatch (or no entry). Acquire the write lock and
	// re-check inside the critical section so a concurrent winner
	// doesn't get overwritten by stale data. Shallow copy: the values
	// are *AuthServiceProviderData pointers that callers (plugins)
	// read field-by-field. Allocating a fresh top-level map decouples
	// the swap from any reader that might be iterating the old map
	// (today only FindAuthSvcProvider does point lookups — no
	// iteration — but the safety property is general).
	s.authServiceMapMutex.Lock()
	if existing, ok := s.authServiceMap[aspId]; ok && existing == asp {
		// Lost the race but the winner installed our pointer anyway —
		// no-op, no fresh allocation.
		s.authServiceMapMutex.Unlock()
		s.ensurePluginLoaded(aspId)
		return
	}
	fresh := make(common.AuthSvcProviderMap, len(s.authServiceMap)+1)
	for k, v := range s.authServiceMap {
		fresh[k] = v
	}
	fresh[aspId] = asp
	s.authServiceMap = fresh
	s.authServiceMapMutex.Unlock()

	s.ensurePluginLoaded(aspId)
}

// ensurePluginLoaded loads the static plugin for `aspId` into
// pluginHandlerMap if it isn't already present. Best-effort: a missing
// static registration (no init() call registered "aspId") is logged
// once and tolerated — the eventual `FindPluginHandler` reject still
// fires, but at least the cause is in the logs.
//
// Lock order: authServiceMapMutex is released BEFORE pluginHandlerMap-
// Mutex is taken (CLAUDE.md). Splitting this out of applyAspMapDelta
// preserves that sequencing.
//
// Per-aspId sync.Once serializes concurrent first-knocks so
// LoadPlugin (which is NOT idempotent — h.Init runs every invocation)
// fires at most once per aspId per successful load. On FAILURE (no
// static plugin registered, or h.Init returned an error) the Once
// is removed from pluginLoadOnce so the next knock retries: a
// transient Init failure (file permission, missing plugin dir) or a
// deploy where a plugin's static registration becomes wired between two callers
// shouldn't lock the aspId into permanent reject. Inside the Do
// closure we observe success/failure via the pluginHandlerMap
// itself (LoadPlugin's atomic insert) rather than a closed-over
// flag — a flag would be per-call-site and miss the load-completed
// state for piggybacking callers; reading the live map is the only
// shared-truth signal available.
// ensurePluginLoaded is the DDB-bridge entry point (pluginPath="" →
// statically-registered plugins only). Convenience wrapper around
// loadPluginOnce; the TOML reload path in updateResources calls
// loadPluginOnce directly with a non-empty pluginPath so dynamic .so
// loading still works there.
func (s *UdpServer) ensurePluginLoaded(aspId string) {
	s.loadPluginOnce(aspId, "")
}

// loadPluginOnce loads the plugin for `aspId` exactly once per
// successful load per process. Used by the per-knock DDB-bridge
// path (applyAspMapDelta → ensurePluginLoaded) so concurrent
// first-knocks for the same aspId can't race two h.Init runs.
//
// The boot/reload-time updateResources path intentionally does
// NOT route through here — it force-loads via LoadPlugin directly
// so an operator-driven TOML edit can rely on Init re-running.
// The narrow concurrent-TOML-reload + first-knock race is
// documented at the updateResources call site; the operator
// workflow preservation wins over closing the theoretical race.
//
// Lock order: pluginHandlerMapMutex is taken WITHOUT holding any
// other mutex (CLAUDE.md). updateResources's TOML iteration calls
// here OUTSIDE its authServiceMapMutex critical section;
// applyAspMapDelta releases authServiceMapMutex BEFORE invoking.
//
// Per-aspId sync.Once: serializes loaders so LoadPlugin (NOT
// idempotent — h.Init runs every invocation; only the LAST writer's
// handler stays in pluginHandlerMap and the earlier handler's Init
// resources would leak) fires at most once per aspId per successful
// load. On FAILURE (no plugin registered, or h.Init returned an
// error) the Once is removed from pluginLoadOnce so the next caller
// retries — a transient Init failure or a race-by-deploy where the
// staticplugin compiles in mid-process shouldn't lock the aspId into
// permanent reject. Success/failure is observed via the live
// pluginHandlerMap (LoadPlugin's atomic insert is the only
// shared-truth signal — a closed-over flag would be per-call-site
// and miss the success state for piggybacking callers).
//
// Piggybacker semantics on failure: when N goroutines share a single
// failing Once, all N observe the empty pluginHandlerMap and return
// having "completed" their load attempt. The Delete(aspId) below lets
// the (N+1)th caller create a fresh Once and retry. The original N
// piggybackers do NOT self-retry — for a transient h.Init flake, every
// knock landed in that N-goroutine window rejects (the FindPluginHandler
// reject path that fires downstream). Bounded retry-storm trade-off:
// the alternative would be intra-call retry with backoff, which would
// pin a goroutine per piggybacker.
//
// Race-safety on Delete+LoadOrStore: a concurrent Delete + new
// LoadOrStore can produce a brief window where two goroutines race
// for a fresh Once. Both re-check pluginHandlerMap inside Do(); if
// either succeeded, the alreadyLoaded fast-path catches the other.
// Worst case is one extra failing GetPluginHandler call — bounded
// by the failure rate (zero under normal operation).
func (s *UdpServer) loadPluginOnce(aspId, pluginPath string) {
	if aspId == "" {
		return
	}
	once, _ := s.pluginLoadOnce.LoadOrStore(aspId, &sync.Once{})
	once.(*sync.Once).Do(func() {
		s.pluginHandlerMapMutex.RLock()
		_, alreadyLoaded := s.pluginHandlerMap[aspId]
		s.pluginHandlerMapMutex.RUnlock()
		if alreadyLoaded {
			return
		}

		h := plugins.GetPluginHandler(aspId, pluginPath)
		if h == nil {
			if pluginPath != "" {
				log.Error("loadPluginOnce: failed to load plugin for aspId=%q from path=%q", aspId, pluginPath)
			} else {
				log.Warning("loadPluginOnce: no static plugin registered for aspId=%q; FindPluginHandler will reject knocks for this asp until a plugin is registered", aspId)
			}
			return
		}
		if loadErr := s.LoadPlugin(aspId, h); loadErr != nil {
			log.Error("loadPluginOnce: failed to load plugin for aspId=%q: %v", aspId, loadErr)
		}
	})

	// Verify success via the live pluginHandlerMap. On failure, drop
	// the Once so the next caller retries (see godoc above).
	s.pluginHandlerMapMutex.RLock()
	_, loaded := s.pluginHandlerMap[aspId]
	s.pluginHandlerMapMutex.RUnlock()
	if !loaded {
		s.pluginLoadOnce.Delete(aspId)
	}
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

// LifecycleCtx returns the server's lifecycle context. Canceled by
// Stop() so async work (DDB lookups on the forward path; future
// callers that need shutdown-awareness) abandons promptly. Returns
// context.Background pre-Start (tests construct UdpServer literals
// without calling Start), matching the defensive fallback in
// ResolveAuthSvcProvider.
func (s *UdpServer) LifecycleCtx() context.Context {
	if s.lifecycleCtx == nil {
		return context.Background()
	}
	return s.lifecycleCtx
}

// ResolveOwnerIDByPubKey implements the ForwarderDeps surface for the
// forward-receiver path. Triggers LookupAgentByPubKey to warm the
// LRU on this server (cold receiver hits DDB), then reads owner_id
// from the cache. Fail-safe contract: any failure (unknown pubkey,
// DDB outage, non-cloud-mode where agentPeerLookup is nil, graceful
// shutdown) returns "" so the caller stamps an empty OwnerId on the
// ACK entry — same behavior the path had before this method existed.
//
// Without local resolution, the forward-receiver would always stamp
// "" while the originating server stamps the resolved owner_id —
// downstream consumers hitting /nhp/internal/token/validate on
// different NLB-hashed instances would see inconsistent OwnerId for
// the same logical agent. This method makes the field consistent
// across instances at the cost of one DDB Query per cold-cache
// forwarded knock per receiver.
//
// Also used by the local UDP knock path (handleNhpOpenResource): the
// auth-path LookupAgentByPubKey warmed the cache moments ago, so the
// inner LookupAgentByPubKey here hits the singleflight-deduplicated
// cache fast path. Symmetric across local + forward paths defends
// against the rare-but-possible cache-eviction-between-auth-and-ACK
// case (agentPeerLookupCacheSize=2048; a >2048-distinct-pubkey burst
// could evict between auth and ACK-publish) — the forward path's
// DDB fallback closes that gap, and using the same call shape here
// gives the local path the same defense.
//
// Observability: transient-DDB failures are logged at debug level
// (distinct from legitimate unknown-pubkey returns) so a receiver
// silently degrading to empty-OwnerId on a connectivity outage is
// visible in triage. A metric counter for the same signal is
// tracked in #2148.
func (s *UdpServer) ResolveOwnerIDByPubKey(ctx context.Context, pubKeyB64 string) string {
	if s.agentPeerLookup == nil || pubKeyB64 == "" {
		return ""
	}
	// LookupAgentByPubKey populates the LRU cache on success (cache
	// entry includes owner_id projected from the pubkey-index GSI).
	// We discard the *core.UdpPeer return — the next CachedOwnerID
	// call surfaces the projected owner_id.
	if _, err := s.agentPeerLookup.LookupAgentByPubKey(ctx, pubKeyB64); err != nil {
		// Split the empty-from-error log into two cases:
		//   - ErrAgentLookupRetryAfter: transient DDB outage. Log at
		//     debug level so triage can correlate
		//     receiver-empty-OwnerId rates with DDB connectivity.
		//   - Everything else (ErrAgentUnknownPubkey,
		//     ErrAgentLookupInternal, ctx canceled): silent return.
		//     Unknown-pubkey is a legitimate "no resolved identity
		//     for this agent" — logging would spam on knocks from
		//     pubkeys we don't know about.
		if errors.Is(err, ErrAgentLookupRetryAfter) {
			log.Debug("resolve_owner_id: transient ddb lookup failure, degrading to empty OwnerId: %v", err)
		}
		return ""
	}
	return s.agentPeerLookup.CachedOwnerID(pubKeyB64)
}

// ResolveAuthSvcProvider is the "do-the-right-thing" entry point for
// callers that need the aspData for a knock and are willing to pay a
// DDB roundtrip on first-touch. The in-memory authServiceMap is
// checked first via FindAuthSvcProvider; on miss, if the DDB-backed
// resource lookup is wired (cloud mode + ResourcesTable configured),
// the lookup runs against the system partition, populates
// authServiceMap via applyAspMapDelta, and returns the resolved
// aspData. On any failure returns nil — the caller's reject path
// owns the wire-level error code.
//
// The resolver OWNS the auth-failure / DDB-error / shutdown metric
// attribution so the caller doesn't have to re-derive the
// classification. Mirrors the agent-peer resolver's posture (the
// agent-peer side fires MetricAuthFailure inside itself only on
// ErrAgentUnknownPubkey).
//
// Nil-safety: relies on *metrics.Publisher.IncrCounter being
// nil-safe on a nil receiver (Publisher.IncrCounter checks
// `if mp == nil { return }`). Bare-struct test fixtures construct
// `&UdpServer{}` without going through Start (where s.metrics is
// wired); the publisher's nil-safety carries that through.
//
// Metric attribution:
//
//   - Hit in authServiceMap: NO counter (caller continues into
//     handler.AuthWithNHP which owns its own success/failure
//     counters downstream).
//   - resourceLookup == nil AND no in-memory hit: auth-policy
//     outcome (aspId not registered anywhere on this server).
//     MetricAuthFailure fires.
//   - ErrResourceUnknownASP from DDB lookup: auth-policy outcome.
//     MetricAuthFailure fires.
//   - context.Canceled during a canceled parent ctx: graceful
//     shutdown. Log Info, NO counter — a normal `systemctl stop`
//     during in-flight knocks must not page on-call (DDB-error
//     OR auth-failure alarm).
//   - Other lookup errors (transient DDB throttle/5xx, malformed
//     row, internal type-assert): infrastructure trouble.
//     MetricResourceLookupDDBError fires; MetricAuthFailure does
//     NOT.
//
// `logPrefix` is a short caller-supplied tag (e.g., "HandleKnockRequest-Auth"
// or "forwarder") prepended to structured log lines so triage can
// attribute the failure to the correct call site. `ctx` should be
// the caller's request-bound context (typically UdpServer.lifecycleCtx
// today); nil is tolerated (falls back to context.Background, only
// reachable in bare-struct test paths).
func (s *UdpServer) ResolveAuthSvcProvider(ctx context.Context, aspId, logPrefix string) *common.AuthServiceProviderData {
	aspData, _ := s.resolveAuthSvcProvider(ctx, aspId, logPrefix, MetricAuthFailure)
	return aspData
}

// ResolveInternalKnockAuthSvcProvider mirrors ResolveAuthSvcProvider for
// /nhp/internal/knock, but routes unknown aspId misses to an internal-knock
// catalog metric instead of the UDP knock auth-failure metric. DDB/shutdown
// attribution is intentionally shared with ResolveAuthSvcProvider.
func (s *UdpServer) ResolveInternalKnockAuthSvcProvider(ctx context.Context, aspId, logPrefix string) (*common.AuthServiceProviderData, error) {
	return s.resolveAuthSvcProvider(ctx, aspId, logPrefix, MetricInternalKnockASPNotFound)
}

// ResolveInternalKnockResource performs a direct resource_id lookup for
// qurl-service's dynamic q_ resources. It intentionally bypasses the aspId map
// cache used by ResolveInternalKnockAuthSvcProvider so freshly minted qURLs do
// not wait for ResourceLookup's ASP-level cache TTL before becoming knockable.
func (s *UdpServer) ResolveInternalKnockResource(ctx context.Context, aspId, resourceID, logPrefix string) (*common.ResourceData, error) {
	if s.resourceLookup == nil {
		s.incrCounterIfMetrics(MetricInternalKnockResourceNotFound)
		return nil, common.ErrResourceNotFound
	}
	if ctx == nil {
		ctx = context.Background()
	}
	resolved, lookupErr := s.resourceLookup.LookupResource(ctx, aspId, resourceID)
	if lookupErr == nil {
		return resolved, nil
	}
	switch {
	case errors.Is(lookupErr, context.Canceled) && ctx.Err() != nil:
		log.Info("[%s] event=\"resource_lookup_shutdown\" aspId=%q resourceID=%q (server stopping; no counter increment — suppresses DDB-error metric even for a concurrent throttle)", logPrefix, aspId, resourceID)
		return nil, ctx.Err()
	case errors.Is(lookupErr, ErrResourceUnknownResource):
		s.incrCounterIfMetrics(MetricInternalKnockResourceNotFound)
		return nil, common.ErrResourceNotFound
	default:
		log.Error("[%s] resource lookup ddb error aspId=%q resourceID=%q: %v", logPrefix, aspId, resourceID, lookupErr)
		s.incrCounterIfMetrics(MetricResourceLookupDDBError)
		return nil, fmt.Errorf("resource lookup ddb error: %w", lookupErr)
	}
}

func (s *UdpServer) incrCounterIfMetrics(name string) {
	if s == nil || s.metrics == nil {
		return
	}
	s.metrics.IncrCounter(name)
}

func (s *UdpServer) resolveAuthSvcProvider(ctx context.Context, aspId, logPrefix, unknownASPMetric string) (*common.AuthServiceProviderData, error) {
	if aspData := s.FindAuthSvcProvider(aspId); aspData != nil {
		return aspData, nil
	}
	if s.resourceLookup == nil {
		// Non-cloud / lookup-disabled deployment AND aspId not in the
		// TOML-loaded authServiceMap → genuine auth-policy outcome.
		// Owned here so the attribution stays correct regardless of
		// which code path reaches the nil-aspData reject.
		s.metrics.IncrCounter(unknownASPMetric)
		return nil, common.ErrAuthServiceProviderNotFound
	}
	if ctx == nil {
		ctx = context.Background()
	}
	resolved, lookupErr := s.resourceLookup.LookupAuthServiceProvider(ctx, aspId)
	if lookupErr == nil {
		return resolved, nil
	}
	switch {
	case errors.Is(lookupErr, context.Canceled) && ctx.Err() != nil:
		// Shutdown wins over a concurrent DDB throttle: if a
		// ProvisionedThroughputExceeded happens to land while
		// lifecycleCtx is already canceled, the SDK-wrapped
		// errors.Is(err, context.Canceled) typically matches first
		// and this branch fires. That suppresses
		// MetricResourceLookupDDBError for the in-flight throttle —
		// intentional. Graceful Stop() is a louder signal than a
		// single transient throttle; an isolated throttle that
		// happened to coincide with shutdown is invisible until the
		// next non-shutdown knock surfaces a fresh DDB error. A
		// future operator triaging "why no DDB alarm during
		// shutdown" finds the answer here.
		log.Info("[%s] event=\"resource_lookup_shutdown\" aspId=%q (server stopping; no counter increment — suppresses DDB-error metric even for a concurrent throttle)", logPrefix, aspId)
		return nil, ctx.Err()
	case errors.Is(lookupErr, ErrResourceUnknownASP):
		// Auth-policy outcome: aspId genuinely not registered.
		s.metrics.IncrCounter(unknownASPMetric)
		return nil, common.ErrAuthServiceProviderNotFound
	default:
		log.Error("[%s] resource lookup ddb error aspId=%q: %v", logPrefix, aspId, lookupErr)
		s.metrics.IncrCounter(MetricResourceLookupDDBError)
		return nil, fmt.Errorf("resource lookup ddb error: %w", lookupErr)
	}
}

// dedupeRecvART is the core.Device recvReplayDedupe hook (installed in
// Start, #1457): packetToMsgRoutine calls it after validatePeer, the one
// point where both forks of every NHP_ART reconverge (matched →
// transaction, unmatched → generic queue), so a replay is recognized
// whether or not it matched a transaction. Returning a non-nil error
// drops the packet via the responder's error-delivery path. See the
// recvReplayDedupeFn field doc in nhp/core/device.go for why a RESPONSE
// needs this chokepoint.
//
// No spurious error to a live knock: the error path surfaces on a MATCHED
// transaction's response channel, but a duplicate never reaches one. The
// original consumes the transaction's single (unbuffered) NextPacketCh
// slot and removes the transaction, so a duplicate racing in the in-flight
// window is dropped at recvPacketRoutine's SendPacket via the closed-
// transaction branch BEFORE this hook, and a later duplicate is unmatched
// (FindLocalTransaction nil) and silently destroyed. A duplicate is thus
// always a silent drop, never a spurious ErrServerDuplicateTransaction
// delivered to a waiting knock.
//
// Scope — only NHP_ART is deduped (it is the one AC→server response, and
// the only type whose replay can feed a stale access result into a live
// knock flow — see art_replay_cache.go); every other type returns nil.
//
// Fail-closed on a missing/wrong-length pubkey: validatePeer must have
// populated a core.PublicKeySize-byte ppd.RemotePubKey before this hook,
// so any other length means the upstream invariant broke (parser
// regression, or a harness bypassing validatePeer). The cache cannot
// scope dedupe state without the authenticated key, so the packet is
// refused with a distinct error (ErrServerMissingPeerPubkey) so an
// oncall chasing a duplicate-spike alert is not misled. Mirrors the AC's
// HandleUdpACOperations guard.
func (s *UdpServer) dedupeRecvART(ppd *core.PacketParserData) error {
	if ppd.HeaderType != core.NHP_ART {
		return nil
	}

	if len(ppd.RemotePubKey) != core.PublicKeySize {
		log.Critical("server[dedupeRecvART] missing or wrong-length peer pubkey (len=%d, want %d), drop %s packet (txid=%d)", len(ppd.RemotePubKey), core.PublicKeySize, core.HeaderTypeToString(ppd.HeaderType), ppd.SenderTrxId)
		return common.ErrServerMissingPeerPubkey
	}

	if !s.artReplay.MarkSeen(ppd.RemotePubKey, ppd.SenderTrxId, ppd.RemoteSendTime) {
		// Warning, not Critical: this fires on replay attempts (the
		// security signal) and on benign in-flight ARTs that reach the
		// server twice after an AC failover / NAT-table rebind. The
		// MetricARTReplayDetected counter is the primary alert surface;
		// the log is the breadcrumb (txid, pubkey fingerprint, sendTime)
		// telling the operator which transaction saw it. Drop silently —
		// no NHP reply — so the response side cannot be used as a
		// replay-success oracle.
		s.metrics.IncrCounter(MetricARTReplayDetected)
		log.Warning("server[dedupeRecvART] duplicate transaction id, drop replayed %s packet (txid=%d, pubkey=%s, sendTime=%d)", core.HeaderTypeToString(ppd.HeaderType), ppd.SenderTrxId, pubkeyFingerprint(ppd.RemotePubKey), ppd.RemoteSendTime)
		return common.ErrServerDuplicateTransaction
	}

	return nil
}

// stampQurlV2RevocationMetadata copies the qURL v2 revocation metadata (P4a)
// from res onto the AOP. Pure + nil-safe so the production stamp and the test
// doubles share ONE mapping and cannot drift (mirrors the AC-side
// accessEntryFromAOP extraction). res is nil on the local non-v2 path and may
// be catalog ResourceData on legacy callers. Upgraded native forwards
// merge the origin admission's narrow revocation sidecar into the receiver's
// catalog ResourceData before stamping. All fields are omitempty, so the AOP stays
// additive/wire-compatible (pre-v2 ACs ignore unknown keys).
// Only the v2 admission path (authWithNHPClaims/buildV2ResourceData) sets
// qurl_user hash / admission_id / deadline on a ResourceData;
// resource_public_key_hash can ride a catalog ResourceData for a v2-provisioned
// resource even on a non-v2 knock (it is the resource revocation key).
// session_id is carried only by the steady-state authorize (re-knock) path,
// which is the first place a session id exists (prepare returns none); the
// first-knock path leaves it empty. revocation_epoch is still not carried (no
// admission response returns it) and has no ResourceData field; it awaits a
// later contract + slice.
// Keep this stamped admission-time field set in sync with
// common.ForwardAdmissionRevocationData plus nativeForwardAdmissionRevocationData
// / forwardedACOperationResourceData. Any new qURL v2 revocation key that is
// stamped onto the AOP must also cross native NHP_FWD, or forwarded flows would
// silently regress to catalog-only metadata for that key.
//
// INVARIANT (forward-safety): the per-admission fields (admission_id / deadline /
// qurl_user hash / session_id) must ONLY ever originate from v2 admission, never
// from a catalog/storage producer. Today that holds: buildV2ResourceData and
// buildV2RefreshResourceData (the prepare and authorize paths) are the sole
// writers of those fields onto any ResourceData, and the native forward sender
// carries a narrow revocation sidecar from that admission result. If a future change ever
// persists any of them onto a catalog row, a non-v2 forwarded knock could emit
// stale per-admission metadata; at that point this stamp must gate them on
// v2-admission provenance.
func stampQurlV2RevocationMetadata(aopMsg *common.ServerACOpsMsg, res *common.ResourceData) {
	if aopMsg == nil || res == nil {
		return
	}
	aopMsg.QurlUserPublicKeyHash = res.QurlUserPublicKeyHash
	aopMsg.ResourcePublicKeyHash = res.ResourcePublicKeyHash
	aopMsg.QurlSessionId = res.QurlSessionId
	aopMsg.AdmissionId = res.AdmissionId
	aopMsg.Deadline = res.Deadline
}

// res carries the qURL v2 revocation metadata (P4a) to stamp onto the AOP. It is
// nil on the local admission path for non-qURL-v2 knocks, and may be catalog
// ResourceData on legacy callers. Native forwards merge a narrow
// revocation sidecar from the origin admission before this stamp. The stamped fields are
// all omitempty, so the AOP stays additive and wire-compatible: pre-v2 ACs
// simply ignore keys they don't know. No flag check is needed here — only the v2
// admission path (authWithNHPClaims, gated by v2AdmissionEnabled) sets the
// per-admission fields (qurl_user hash, admission_id, deadline);
// resource_public_key_hash rides the catalog ResourceData for v2-provisioned
// resources (see stampQurlV2RevocationMetadata).
func (s *UdpServer) processACOperation(ctx context.Context, knkMsg *common.AgentKnockMsg, conn *ACConn, srcAddr *common.NetAddress, dstAddrs []*common.NetAddress, openTime uint32, res *common.ResourceData) (artMsg *common.ACOpsResultMsg, err error) {
	// should not happen
	if knkMsg == nil || conn == nil {
		log.Critical("processACOperation with nil input argument")
		err = common.ErrInvalidInput
		return
	}
	if !conn.sessionControlReady(s.sessionControlAuthorityRequired()) {
		log.Warning("processACOperation rejected AC connection without active session-control authority")
		return &common.ACOpsResultMsg{ErrCode: common.ErrACSessionControlNotReady.ErrorCode(), ErrMsg: common.ErrACSessionControlNotReady.Error()}, common.ErrACSessionControlNotReady
	}
	if knkMsg.NHPSessionId == 0 {
		log.Error("processACOperation rejected missing NHP session id")
		return &common.ACOpsResultMsg{ErrCode: common.ErrACOperationFailed.ErrorCode(), ErrMsg: common.ErrACOperationFailed.Error()}, common.ErrACOperationFailed
	}
	if knkMsg.NHPSessionIssuedAt.IsZero() {
		log.Error("processACOperation rejected missing NHP session issuance time")
		return &common.ACOpsResultMsg{ErrCode: common.ErrACOperationFailed.ErrorCode(), ErrMsg: common.ErrACOperationFailed.Error()}, common.ErrACOperationFailed
	}
	if !common.ValidNHPAgentPublicKey(knkMsg.NHPAgentPublicKey) {
		log.Error("processACOperation rejected missing authenticated NHP-Agent public key")
		return &common.ACOpsResultMsg{ErrCode: common.ErrACOperationFailed.ErrorCode(), ErrMsg: common.ErrACOperationFailed.Error()}, common.ErrACOperationFailed
	}
	if knkMsg.AuthServiceId == common.RegisteredAgentAuthServiceID &&
		(common.ValidateAgentKnockRunID(knkMsg.RunID) != nil || knkMsg.RunAttempt == 0) {
		log.Error("processACOperation rejected missing registered-agent retry binding")
		return &common.ACOpsResultMsg{ErrCode: common.ErrACOperationFailed.ErrorCode(), ErrMsg: common.ErrACOperationFailed.Error()}, common.ErrACOperationFailed
	}
	validACID := utf8.ValidString(conn.ACId) && strings.TrimSpace(conn.ACId) != "" && strings.TrimSpace(conn.ACId) == conn.ACId
	for _, r := range conn.ACId {
		if unicode.IsControl(r) {
			validACID = false
			break
		}
	}
	if !validACID {
		log.Error("processACOperation rejected non-canonical AC id")
		return &common.ACOpsResultMsg{ErrCode: common.ErrACOperationFailed.ErrorCode(), ErrMsg: common.ErrACOperationFailed.Error()}, common.ErrACOperationFailed
	}
	sessionOwnerID, ownerErr := s.sessionOwnerID()
	if ownerErr != nil {
		log.Error("processACOperation failed to establish AC session owner identity: %v", ownerErr)
		return &common.ACOpsResultMsg{ErrCode: common.ErrACOperationFailed.ErrorCode(), ErrMsg: common.ErrACOperationFailed.Error()}, common.ErrACOperationFailed
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
	if openTime == 0 || !time.Now().Before(knkMsg.NHPSessionIssuedAt.Add(time.Duration(openTime)*time.Second)) {
		log.Error("processACOperation rejected invalid or expired NHP session lifetime")
		return &common.ACOpsResultMsg{ErrCode: common.ErrACOperationFailed.ErrorCode(), ErrMsg: common.ErrACOperationFailed.Error()}, common.ErrACOperationFailed
	}
	sessionExpiresAt := knkMsg.NHPSessionIssuedAt.Add(time.Duration(openTime) * time.Second)
	aopOpenTime := openTime
	if aopOpenTime > ^uint32(0)-uint32(ACOpenCompensationTime) {
		aopOpenTime = ^uint32(0)
	} else {
		aopOpenTime += uint32(ACOpenCompensationTime)
	}
	if beginErr := s.sessionRegistry().beginOpen(knkMsg.NHPSessionId, knkMsg.NHPSessionIssuedAt); beginErr != nil {
		log.Warning("server-agent(%s@%s)-ac(%s)[processACOperation] NHP session is not openable: %v", knkMsg.UserId, srcAddr.String(), conn.ACId, beginErr)
		return &common.ACOpsResultMsg{ErrCode: common.ErrACOperationFailed.ErrorCode(), ErrMsg: common.ErrACOperationFailed.Error()}, common.ErrACOperationFailed
	}
	acAdmitted := false
	defer func() {
		// AC OpenTime is relative to when the AC receives the AOP, not the
		// session issuance timestamp. Retain exact close work conservatively
		// from ART completion through the full compensated AC lifetime while
		// keeping beginOpen fenced by sessionExpiresAt.
		acRetainUntil := time.Now().Add(time.Duration(aopOpenTime) * time.Second)
		finishErr := s.sessionRegistry().finishOpen(knkMsg.NHPSessionId, knkMsg.NHPSessionIssuedAt, sessionExpiresAt, acRetainUntil, conn.ACId, acAdmitted)
		if finishErr != nil && acAdmitted {
			log.Warning("server-agent(%s@%s)-ac(%s)[processACOperation] NHP session closed while AOP was in flight", knkMsg.UserId, srcAddr.String(), conn.ACId)
			err = common.ErrACOperationFailed
			artMsg = &common.ACOpsResultMsg{
				SessionId:      knkMsg.NHPSessionId,
				SessionOwnerId: sessionOwnerID,
				ErrCode:        common.ErrACOperationFailed.ErrorCode(),
				ErrMsg:         common.ErrACOperationFailed.Error(),
			}
		}
	}()

	var releaseAuthorityRead func()
	var releaseCellRead func()
	var durableIntent *sessionControlSessionIntentPreparation
	if s.sessionControlAuthorityRequired() {
		candidate, candidateErr := sessionControlCandidateForKnock(s.sessionControlCellID, knkMsg)
		if candidateErr != nil {
			return &common.ACOpsResultMsg{ErrCode: common.ErrACOperationFailed.ErrorCode(), ErrMsg: common.ErrACOperationFailed.Error()}, candidateErr
		}
		var gateErr error
		releaseAuthorityRead, gateErr = s.acquireACSessionControlAuthorityRead(ctx, conn)
		if gateErr != nil {
			log.Warning("server-agent(%s@%s)-ac(%s)[processACOperation] authority gate unavailable: %v", knkMsg.UserId, srcAddr.String(), conn.ACId, gateErr)
			return &common.ACOpsResultMsg{ErrCode: common.ErrACSessionControlNotReady.ErrorCode(), ErrMsg: common.ErrACSessionControlNotReady.Error()}, common.ErrACSessionControlNotReady
		}
		defer func() {
			if releaseAuthorityRead != nil {
				releaseAuthorityRead()
			}
		}()
		releaseCellRead, gateErr = s.acquireSessionControlCellRead(ctx)
		if gateErr != nil {
			return &common.ACOpsResultMsg{ErrCode: common.ErrACSessionControlNotReady.ErrorCode(), ErrMsg: common.ErrACSessionControlNotReady.Error()}, common.ErrACSessionControlNotReady
		}
		defer func() {
			if releaseCellRead != nil {
				releaseCellRead()
			}
		}()
		if !conn.sessionControlReady(true) {
			return &common.ACOpsResultMsg{ErrCode: common.ErrACSessionControlNotReady.ErrorCode(), ErrMsg: common.ErrACSessionControlNotReady.Error()}, common.ErrACSessionControlNotReady
		}
		targetPtr := conn.sessionControlTarget.Load()
		if targetPtr == nil {
			return &common.ACOpsResultMsg{ErrCode: common.ErrACSessionControlNotReady.ErrorCode(), ErrMsg: common.ErrACSessionControlNotReady.Error()}, common.ErrACSessionControlNotReady
		}
		target := *targetPtr
		if validateSessionControlTargetAuthority(target) != nil || !target.ready() || target.RetiredAtMillis != 0 ||
			target.ControlCellID != candidate.CellID || target.ACID != conn.ACId || target.PublicKey != conn.ACPeer.PubKeyBase64 ||
			target.BootID != conn.BootID || target.FlushGeneration != conn.FlushGeneration {
			return &common.ACOpsResultMsg{ErrCode: common.ErrACSessionControlNotReady.ErrorCode(), ErrMsg: common.ErrACSessionControlNotReady.Error()}, common.ErrACSessionControlNotReady
		}
		deliveryDeadline := time.Now().Add(DefaultBroadcastTimeout)
		if deadline, ok := ctx.Deadline(); ok {
			deliveryDeadline = deadline
		}
		retainUntilMillis, retainErr := sessionControlRetainUntilMillis(candidate, aopOpenTime, deliveryDeadline)
		if retainErr != nil {
			return &common.ACOpsResultMsg{ErrCode: common.ErrACOperationFailed.ErrorCode(), ErrMsg: common.ErrACOperationFailed.Error()}, retainErr
		}
		durableIntent, gateErr = s.prepareDurableSessionIntent(ctx, candidate, target,
			sessionExpiresAt.UnixMilli(), retainUntilMillis)
		if gateErr != nil {
			log.Warning("server-agent(%s@%s)-ac(%s)[processACOperation] durable intent rejected: %v", knkMsg.UserId, srcAddr.String(), conn.ACId, gateErr)
			return &common.ACOpsResultMsg{ErrCode: common.ErrACSessionControlNotReady.ErrorCode(), ErrMsg: common.ErrACSessionControlNotReady.Error()}, common.ErrACSessionControlNotReady
		}
		currentTarget := conn.sessionControlTarget.Load()
		if currentTarget == nil || *currentTarget != target || !conn.sessionControlReady(true) {
			return &common.ACOpsResultMsg{ErrCode: common.ErrACSessionControlNotReady.ErrorCode(), ErrMsg: common.ErrACSessionControlNotReady.Error()}, common.ErrACSessionControlNotReady
		}
	}

	aopSessionID := knkMsg.NHPSessionId
	aopAgentPublicKey := knkMsg.NHPAgentPublicKey
	aopIssuedAtMillis := knkMsg.NHPSessionIssuedAt.UnixMilli()
	aopRunID := knkMsg.RunID
	aopRunAttempt := knkMsg.RunAttempt
	if durableIntent != nil {
		authority := durableIntent.Intent.Session
		aopSessionID = authority.SessionID
		aopAgentPublicKey = authority.AgentPublicKey
		aopIssuedAtMillis = authority.IssuedAtMillis
		aopRunID = authority.RunID
		aopRunAttempt = authority.RunAttempt
	}

	aopMsg := &common.ServerACOpsMsg{
		SessionId:             aopSessionID,
		SessionOwnerId:        sessionOwnerID,
		AgentPublicKey:        aopAgentPublicKey,
		SessionIssuedAtMillis: aopIssuedAtMillis,
		RunID:                 aopRunID,
		RunAttempt:            aopRunAttempt,
		UserId:                knkMsg.UserId,
		DeviceId:              knkMsg.DeviceId,
		OrganizationId:        knkMsg.OrganizationId,
		AuthServiceId:         knkMsg.AuthServiceId,
		ResourceId:            knkMsg.ResourceId,
		SourceAddrs:           srcAddrs,
		DestinationAddrs:      dstAddrs,
		OpenTime:              aopOpenTime, // compensate AC open time without uint32 wraparound
	}
	// qURL v2 revocation metadata (P4a): stamp from res via the shared pure
	// helper so prod and the test doubles can't diverge (see its godoc).
	stampQurlV2RevocationMetadata(aopMsg, res)
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

	select {
	case s.sendMsgCh <- aopMd:
		if releaseCellRead != nil {
			releaseCellRead()
			releaseCellRead = nil
		}
		if releaseAuthorityRead != nil {
			releaseAuthorityRead()
			releaseAuthorityRead = nil
		}
	case <-ctx.Done():
		artMsg.ErrCode = common.ErrServerACOpsFailed.ErrorCode()
		artMsg.ErrMsg = ctx.Err().Error()
		return artMsg, ctx.Err()
	case <-s.signals.stop:
		err = common.ErrPacketToMessageRoutineStopped
		artMsg.ErrCode = common.ErrPacketToMessageRoutineStopped.ErrorCode()
		artMsg.ErrMsg = err.Error()
		return artMsg, err
	}

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
		// A matched ART dropped by the per-connection replay gate (a
		// timestamp regression, #1457) surfaces here as
		// core.ErrReplayPacketReceived; count it on its own gate-drop
		// counter — see MetricARTReplayGateDrop for why it is kept distinct
		// from the cross-connection cache counter.
		if errors.Is(acPpd.Error, core.ErrReplayPacketReceived) {
			s.metrics.IncrCounter(MetricARTReplayGateDrop)
		}
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

	err = common.DecodeACOpsResultMsg(acPpd.BodyMessage, artMsg)
	if err != nil {
		log.Error("server-agent(%s@%s)-ac(%s#%d@%s)[processACOperation] failed to parse %s message: %v", knkMsg.UserId, srcAddr.String(), conn.ACId, aopMd.TransactionId, acAddrStr, core.HeaderTypeToString(acPpd.HeaderType), err)
		artMsg.ErrCode = common.ErrJsonParseFailed.ErrorCode()
		artMsg.ErrMsg = err.Error()
		return
	}
	if artMsg.SessionId != aopMsg.SessionId || artMsg.SessionOwnerId != aopMsg.SessionOwnerId {
		log.Error("server-agent(%s@%s)-ac(%s#%d@%s)[processACOperation] ART session identity mismatch", knkMsg.UserId, srcAddr.String(), conn.ACId, aopMd.TransactionId, acAddrStr)
		err = common.ErrACOperationFailed
		artMsg = &common.ACOpsResultMsg{
			SessionId:      aopMsg.SessionId,
			SessionOwnerId: aopMsg.SessionOwnerId,
			ErrCode:        common.ErrACOperationFailed.ErrorCode(),
			ErrMsg:         err.Error(),
		}
		return
	}

	if artMsg.ErrCode != common.ErrSuccess.ErrorCode() {
		// ACOpsResultMsg carries ACToken (empty on this error path today —
		// defensive fence). Log only ErrCode/ErrMsg, never %+v the struct;
		// ErrMsg is token-free. See docs/SECURITY_TOKEN_TOUCH_INVENTORY.md.
		log.Error("server-agent(%s@%s)-ac(%s#%d@%s)[processACOperation] response error: errCode=%s errMsg=%s", knkMsg.UserId, srcAddr.String(), conn.ACId, aopMd.TransactionId, acAddrStr, artMsg.ErrCode, artMsg.ErrMsg)
		err = common.ErrACOperationFailed
		return
	}
	acAdmitted = true

	return artMsg, nil
}

// knockACFanoutEnabled reports whether cell-wide knock AC fan-out
// (qurl-service#948, Config.EnableKnockACFanout) is on. Nil-safe so tests that
// construct a bare UdpServer default to the legacy first-success, local-only
// path.
func (s *UdpServer) knockACFanoutEnabled() bool {
	return s.config != nil && s.config.EnableKnockACFanout
}

// processACOperationBroadcast sends NHP-AOP to the live local AC connections
// selected for one acId. That local slice is capped by MaxACConnsPerID; cross-AZ
// coverage is handled by the assignment-scoped server fan-out below, not by
// broadcasting to the full AC fleet from one server.
//
// Return timing depends on Config.EnableKnockACFanout (knockACFanoutEnabled):
//
//   - OFF (legacy): returns the first successful result immediately to minimize
//     client-facing latency; remaining goroutines are NOT canceled — they
//     continue in the background so all ACs still get the pinhole, drained and
//     logged by a background goroutine. The risk this leaves is qurl-service#948:
//     the ack (which unblocks the synchronous knock → 302) can fire before a
//     sibling AC's pinhole write completes, and a viewer GET the NLB hashes to
//     that AC is dropped.
//   - ON: waits for every selected local AC to complete before returning, so the
//     ack means the local slice has the pinhole. Success/failure semantics are
//     unchanged (success with the first successful ART if >=1 AC succeeded; a
//     partial failure does not fail an otherwise-good knock; the last error if
//     every AC failed); only the timing moves from fastest-AC to slowest-AC. The
//     wait is bounded per-AC by the broadcast context + the AC transaction
//     timeout, so a wedged AC delays this knock by at most that budget. This is
//     the local half of the #948 fix; the handler pairs it with a cross-server
//     fan-out so one peer per assigned AZ is covered too.
func (s *UdpServer) processACOperationBroadcast(
	parentCtx context.Context,
	knkMsg *common.AgentKnockMsg,
	conns []*ACConn,
	srcAddr *common.NetAddress,
	dstAddrs []*common.NetAddress,
	openTime uint32,
	res *common.ResourceData,
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
		artMsg, err := s.processACOperation(ctx, knkMsg, conns[0], srcAddr, dstAddrs, openTime, res)
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
			artMsg, err := s.processACOperation(ctx, knkMsg, c, srcAddr, dstAddrs, openTime, res)
			s.metrics.RecordLatency(MetricBroadcastACLatencyMs, float64(time.Since(acStart).Milliseconds()))
			results <- broadcastResult{artMsg, err, c.ACPeer.RecvAddr().String()}
		}(conn)
	}

	// Wait for results. With fan-out OFF (legacy) return on first success to
	// unblock the client, letting remaining goroutines finish in the background
	// (fire-and-forget AOP). With fan-out ON wait for every selected local AC so
	// the ack means the local slice has the pinhole (qurl-service#948). Either
	// way, if all fail, return the last error.
	waitAll := s.knockACFanoutEnabled()
	var lastErr error
	var lastArtMsg *common.ACOpsResultMsg
	var firstSuccessArt *common.ACOpsResultMsg
	var successCount, failCount int
	var failedAddrs []string
	for i := 0; i < total; i++ {
		r := <-results
		if r.err == nil {
			successCount++
			if firstSuccessArt == nil {
				firstSuccessArt = r.artMsg
			}
			if !waitAll {
				log.Info("server-agent(%s@%s)[processACOperationBroadcast] AC at %s succeeded (1/%d), returning to caller",
					userId, addrStr, r.acAddr, total)
				// Drain remaining results in background — single summary log, emit metrics
				remaining := total - i - 1
				if remaining > 0 {
					go func() {
						var bgSuccess, bgFail int
						var bgFailedAddrs []string
						for j := 0; j < remaining; j++ {
							bgr := <-results
							if bgr.err == nil {
								bgSuccess++
							} else {
								bgFail++
								bgFailedAddrs = append(bgFailedAddrs, bgr.acAddr)
							}
						}
						elapsed := time.Since(broadcastStart)
						s.metrics.RecordLatency(MetricBroadcastDurationMs, float64(elapsed.Milliseconds()))
						if bgFail > 0 {
							s.metrics.IncrCounter(MetricBroadcastPartialFail)
							log.Warning("server-agent(%s@%s)[processACOperationBroadcast] broadcast done in %v: %d/%d ACs succeeded, failed: %v",
								userId, addrStr, elapsed, bgSuccess+1, total, bgFailedAddrs)
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
			// waitAll: keep collecting until every AC goroutine has reported.
			continue
		}
		failCount++
		failedAddrs = append(failedAddrs, r.acAddr)
		log.Warning("server-agent(%s@%s)[processACOperationBroadcast] AC at %s failed: %v (%d/%d)",
			userId, addrStr, r.acAddr, r.err, failCount, total)
		lastErr = r.err
		lastArtMsg = r.artMsg
	}

	// Reached when waitAll collected every result, or (in either mode) when
	// every AC failed.
	elapsed := time.Since(broadcastStart)
	s.metrics.RecordLatency(MetricBroadcastDurationMs, float64(elapsed.Milliseconds()))
	if successCount > 0 {
		// waitAll: every AC has now completed and at least one opened its
		// pinhole. Mirror the legacy success/partial-fail metrics + logs.
		if failCount > 0 {
			s.metrics.IncrCounter(MetricBroadcastPartialFail)
			log.Warning("server-agent(%s@%s)[processACOperationBroadcast] broadcast done in %v: %d/%d ACs succeeded, failed: %v",
				userId, addrStr, elapsed, successCount, total, failedAddrs)
		} else {
			log.Info("server-agent(%s@%s)[processACOperationBroadcast] broadcast done in %v: %d/%d ACs succeeded",
				userId, addrStr, elapsed, successCount, total)
		}
		s.metrics.IncrCounter(MetricBroadcastSuccess)
		return firstSuccessArt, nil
	}
	s.metrics.IncrCounter(MetricBroadcastAllFail)
	log.Warning("server-agent(%s@%s)[processACOperationBroadcast] all %d ACs failed in %v", userId, addrStr, total, elapsed)
	return lastArtMsg, lastErr
}

// warnKnockOriginalPacketMissing emits the guard-drift canary (log + metric)
// when a knock needs fan-out or no-local-AC forwarding but BasePacketContent()
// returned nil. Both gates in handleNhpOpenResource share this so the message
// and MetricKnockForwardMissingPacket cannot drift apart.
func (s *UdpServer) warnKnockOriginalPacketMissing(gate, userId, addrStr string, wireHeaderType, bodyHeaderType int) {
	log.Warning("server-agent(%s@%s)[handleNhpOpenResource] knock %s skipped: BasePacketContent() returned nil for wire_header=%s body_header=%s; check IsForwardableKnockType guard in decryptBody",
		userId, addrStr, gate, core.HeaderTypeToString(wireHeaderType), core.HeaderTypeToString(bodyHeaderType))
	s.metrics.IncrCounter(MetricKnockForwardMissingPacket)
}

func (s *UdpServer) handleNhpOpenResource(req *common.NhpAuthRequest, res *common.ResourceData) (ackMsg *common.ServerKnockAckMsg, err error) {
	knkMsg := req.Msg
	srcAddr := req.SrcAddr
	addrStr := srcAddr.String()
	ackMsg = req.Ack
	if bindErr := bindRegisteredAgentProtectedResource(knkMsg, res); bindErr != nil {
		log.Warning("server-agent(%s@%s)[handleNhpOpenResource] rejected protected resource binding: %v", knkMsg.UserId, addrStr, bindErr)
		err = common.ErrResourceNotFound
		ackMsg.ErrCode = common.ErrResourceNotFound.ErrorCode()
		ackMsg.ErrMsg = err.Error()
		return ackMsg, err
	}
	// ResourceData may be a shared catalog pointer. Clone before attaching the
	// transient NHP session used by server-to-server forwarding so concurrent
	// knocks cannot overwrite one another's session identity.
	resWithSession := *res
	resWithSession.NHPSessionId = req.SessionId
	resWithSession.NHPSessionIssuedAt = req.SessionIssuedAt
	res = &resWithSession

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

	// qurl-service#948: AZ-scoped knock AC fan-out (native/relay knock path).
	// handleNhpOpenResource only ever runs for origin knocks: a forwarded knock is
	// processed by ServerForwarder.handleDecryptedForwardedKnock, which never
	// re-forwards, so no Forwarded guard is needed. The per-resource loop below
	// opens pinholes only on THIS server's local AC slice; FanoutKnock uses the
	// assignment row to send NHP_FWD to one peer server per non-local AZ. The
	// defer makes every return path, including the no-local-AC forward early
	// return below, block until peer pinholes are open before we ack.
	// Coverage-only; the ack still comes from the local broadcast / forward.
	fanoutReady := s.knockACFanoutEnabled() && s.storage != nil && s.forwarder != nil
	if fanoutReady && len(req.OriginalPacket) == 0 {
		s.warnKnockOriginalPacketMissing("fan-out", knkMsg.UserId, addrStr, req.WireHeaderType, knkMsg.HeaderType)
	} else if fanoutReady {
		if userAddr, parseErr := net.ResolveUDPAddr("udp", addrStr); parseErr == nil {
			fanoutBase := context.WithoutCancel(context.Background())
			var fanoutWg sync.WaitGroup
			fannedAcIds := make(map[string]bool, len(res.Resources))
			for _, info := range res.Resources {
				if info == nil || info.ACId == "" || fannedAcIds[info.ACId] {
					continue
				}
				fannedAcIds[info.ACId] = true
				fanoutWg.Add(1)
				go func(acId string) {
					defer fanoutWg.Done()
					lctx, lcancel := context.WithTimeout(fanoutBase, DefaultStorageTimeout)
					assignment, lookupErr := s.storage.GetACAssignment(lctx, acId)
					lcancel()
					if lookupErr != nil || assignment == nil || len(assignment.AssignedServers) == 0 {
						if lookupErr != nil && !IsNotFoundError(lookupErr) {
							log.Warning("server-agent(%s@%s)-ac(%s)[handleNhpOpenResource] knock fan-out assignment lookup failed: %v", knkMsg.UserId, addrStr, acId, lookupErr)
						}
						return
					}
					fctx, fcancel := context.WithTimeout(fanoutBase, ForwardTimeout)
					defer fcancel()
					accepted := s.forwarder.FanoutKnock(fctx, assignment, s.localIp, req.OriginalPacket, userAddr, res)
					s.metrics.IncrCounter(MetricKnockFanout)
					log.Info("server-agent(%s@%s)-ac(%s)[handleNhpOpenResource] knock fan-out opened pinholes on %d peer server(s)", knkMsg.UserId, addrStr, acId, accepted)
				}(info.ACId)
			}
			defer fanoutWg.Wait()
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
	forwardReady := needsForwarding && s.storage != nil && s.forwarder != nil
	if forwardReady && len(req.OriginalPacket) == 0 {
		s.warnKnockOriginalPacketMissing("forward", knkMsg.UserId, addrStr, req.WireHeaderType, knkMsg.HeaderType)
	} else if forwardReady {
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
				// Forward the knock to assigned servers. Keep this caller budget
				// equal to forward.go's per-peer ForwardTimeout; a full-budget
				// expiry is shared admission exhaustion, not peer-health proof.
				fwdCtx, fwdCancel := context.WithTimeout(context.Background(), ForwardTimeout)
				defer fwdCancel()

				result, fwdErr := s.forwarder.ForwardKnock(fwdCtx, assignment, req.OriginalPacket, userAddr, res)
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

	// openTime is loop-invariant and comes from the resolved resource. On the
	// current 1.1 envelope, EXT remains a body-bearing, resource-scoped close;
	// the strict encrypted-body HeaderType mirror is checked before this point.
	openTime := res.OpenTime
	if knkMsg.HeaderType == core.NHP_EXT {
		openTime = 1
	}

	// logCtx is the per-knock agent-identity prefix shared by the re-knock
	// retry's logs; loop-invariant, so build it once.
	logCtx := fmt.Sprintf("server-agent(%s@%s)", knkMsg.UserId, addrStr)

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

			// UDP knock path: no request-scoped context exists, so pass the
			// server lifecycle context. processACOperationBroadcast WithoutCancel's
			// it internally, so the AOP send is unaffected by cancellation; the
			// lifecycle ctx is used only by the re-knock retry's backoff select, so
			// a retry pending when Stop() cancels lifecycleCtx abandons promptly
			// instead of firing a fresh server→AC transaction into the drain window.
			// broadcastACOpenWithReknock wraps the broadcast with a single
			// re-snapshot retry on the blue/green reassignment-window timeout
			// (qurl-service#976); it still funnels through
			// resolveProcessACOperationBroadcast, which lets handler-site
			// integration tests inject a fake AC response — see
			// udpserver_publish_acktokens_test.go.
			artMsg, err := s.broadcastACOpenWithReknock(s.LifecycleCtx(), knkMsg, info.ACId, connsCopy, srcAddr, dstAddrs, openTime, res, logCtx)
			if artMsg == nil {
				// Keep the artMsgs map nil-free — the successCount loop and the
				// failure-log loop below deref entries unconditionally (mirrors the
				// ErrACConnectionNotFound synthesis above). Every return path that
				// yields a nil artMsg also sets a non-nil err (none returns
				// (nil, nil)), so the err==nil success branch below never treats a
				// synthesized failure entry as a success.
				artMsg = &common.ACOpsResultMsg{ErrCode: common.ErrACOperationFailed.ErrorCode()}
				if err != nil {
					artMsg.ErrMsg = err.Error()
				}
			}
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

	// PR-2a: persist AC-issued tokens AFTER acWg.Wait so PR-2b's
	// /nhp/internal/token/validate reader doesn't race the AC
	// goroutines still mutating ackMsg.ACTokens. See PublishACKTokens
	// for the contract.
	//
	// ResolveOwnerIDByPubKey symmetric with the forward-receiver path
	// (forward.go's `f.deps.ResolveOwnerIDByPubKey`). The auth-path
	// LookupAgentByPubKey warmed the cache moments ago, so the inner
	// LookupAgentByPubKey hits the singleflight-deduplicated cache
	// fast path; the DDB fallback only fires in the rare-but-possible
	// case where the LRU evicted the entry between auth and ACK-publish
	// (agentPeerLookupCacheSize=2048; a >2048-distinct-pubkey burst
	// could trigger). Per CSA Stealth Mode SDP §"NHP Workflow", the
	// server-side pubkey resolution IS the authoritative identity
	// signal; this propagates it through the ACK-path so application-
	// layer consumers can authorize without re-resolving.
	//
	// Non-cloud-mode: agentPeerLookup is nil (no DDB-backed agent
	// registry wired). ResolveOwnerIDByPubKey returns "" via its
	// receiver nil-guard — the same empty contract as legacy entries.
	// Cache-eviction observability tracked in #2148.
	ownerId := s.ResolveOwnerIDByPubKey(s.LifecycleCtx(), req.PublicKey)
	if publishErr := s.PublishACKTokens(s.LifecycleCtx(), knkMsg, ackMsg, srcAddr.Ip, int(openTime), ownerId); publishErr != nil {
		log.Error("server-agent(%s@%s)[handleNhpOpenResource] failed to persist ACK token metadata: %v", knkMsg.UserId, addrStr, publishErr)
		if agentPubKey, keyErr := decodeAgentPublicKey(req.PublicKey); keyErr == nil {
			s.compensateFailedNHPSession(agentPubKey, knkMsg.NHPSessionId, knkMsg.NHPSessionIssuedAt)
		} else {
			log.Error("server-agent(%s@%s)[handleNhpOpenResource] cannot compensate token-publish failure with invalid authenticated public key", knkMsg.UserId, addrStr)
		}
		err = common.ErrServerTokenPersistFailed
		ackMsg.ErrCode = common.ErrServerTokenPersistFailed.ErrorCode()
		ackMsg.ErrMsg = err.Error()
		return
	}

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
		// Log per-resource ErrCodes (sorted for stable oncall output),
		// never %+v the artMsgs map — each entry carries ACToken (see
		// docs/SECURITY_TOKEN_TOUCH_INVENTORY.md).
		resErrs := make([]string, 0, len(artMsgs))
		for name, m := range artMsgs {
			resErrs = append(resErrs, name+"="+m.ErrCode)
		}
		sort.Strings(resErrs)
		log.Info("server-agent(%s@%s)[handleNhpOpenResource] failed: resErrs=%v", knkMsg.UserId, addrStr, resErrs)
		err = common.ErrServerACOpsFailed
		ackMsg.ErrCode = common.ErrServerACOpsFailed.ErrorCode()
		ackMsg.ErrMsg = err.Error()
		return
	}

	ackMsg.ErrCode = common.ErrSuccess.ErrorCode()
	ackMsg.ErrMsg = common.ErrSuccess.Error()
	return ackMsg, nil
}

// NewNhpServerHelper builds the per-knock plugin helper. aspData is the
// AuthServiceProviderData that matched the knock's AuthServiceId — the
// caller already resolved it via FindAuthSvcProvider, so we plumb it
// through rather than have plugins re-lookup. Plugins without their own
// resource registry (e.g. the agent-bootstrap `layerv` plugin) read
// `helper.AspData.ResourceGroups[resourceId]` to dispatch AC ops on the
// host server's resource.toml-loaded catalog.
//
// Call-site contract: the knock path (`nhpauth.go`) plumbs aspData;
// the OTP/Register/List paths (`msghandler.go`) intentionally pass nil
// because passcode/OIDC carry their own SDK-backed resource registry
// and don't read AspData. A future static plugin needing AspData on
// those flows must update all three msghandler call sites.
func (us *UdpServer) NewNhpServerHelper(ppd *core.PacketParserData, aspData *common.AuthServiceProviderData) *plugins.NhpServerPluginHelper {
	h := &plugins.NhpServerPluginHelper{}
	h.StopSignal = ppd.ConnData.StopSignal
	h.AspData = aspData
	// Expose this server's own static (cell) public key so qURL v2 admission can
	// bind the signed claims' cell_public_key_b64 to THIS cell. Std-base64, the
	// same encoding the authenticated agent key (req.PublicKey) carries.
	h.ServerCellPublicKeyB64 = us.device.PublicKeyBase64()

	h.AuthWithNhpCallbackFunc = func(req *common.NhpAuthRequest, res *common.ResourceData) (*common.ServerKnockAckMsg, error) {
		return us.handleNhpOpenResource(req, res)
	}
	h.ResolveResourceFunc = func(aspId, resId, srcIP string) (*common.ResourceData, error) {
		_ = srcIP // Dynamic qURL rows resolve by exact (aspId, resId).
		return us.ResolveInternalKnockResource(us.LifecycleCtx(), aspId, resId, "HandleKnockRequest-resource")
	}

	// Bind the metric emitter for plugins (mirrors the HTTP helper in
	// httpserver.go; gate on metrics != nil before binding). The knock path
	// — where qURL v2 admission runs (authWithNHPClaims) — uses THIS helper, so
	// without this binding any helper.IncrCounter from the plugin (e.g.
	// MetricQurlV2RevocationHashError) would be a silent no-op on the real v2
	// admission path. The bound method value is also nil-receiver-safe.
	if us.metrics != nil {
		h.IncrCounter = us.metrics.IncrCounter
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

// FindACConnectionsForResource looks up live AC connections using a resource
// resolution that the caller already chose. This is the forwarder-safe helper:
// qURL placement happens once, outside this method, and the same resData is
// reused to build the ACK ResourceHost. Callers that can supply multi-entry
// ResourceData must first resolve or alias it to the single entry they intend
// to authorize; multi-entry data fails closed so AC dispatch and ACK
// construction stay paired.
func (s *UdpServer) FindACConnectionsForResource(knkMsg *common.AgentKnockMsg, resData *common.ResourceData) []*ACConn {
	resInfo := qurlplacement.OnlyResourceInfo(resData)
	if resInfo == nil {
		log.Debug("FindACConnectionsForResource: Resource %s not found in ASP %s", knkMsg.ResourceId, knkMsg.AuthServiceId)
		return nil
	}

	acId := resInfo.ACId
	if acId == "" {
		log.Debug("FindACConnectionsForResource: Resource %s has no AC ID", knkMsg.ResourceId)
		return nil
	}

	// Look up all live AC connections. The forwarder consumes this slice
	// for NHP-AOP fan-out, so a stale conn here would drain the forwarded
	// knock's transaction timeout the same way it would drain a local one.
	result, droppedStale := s.snapshotLiveACConns(acId)
	if droppedStale > 0 {
		log.Warning("FindACConnectionsForResource: AC %s filtered %d stale/closed connection(s) (threshold=%v)",
			acId, droppedStale, s.staleACConnThreshold())
	}

	if len(result) == 0 {
		log.Debug("FindACConnectionsForResource: AC %s not connected", acId)
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

func (s *UdpServer) IncrForwarderMetric(name string) {
	s.metrics.IncrCounter(name)
}

func (s *UdpServer) connDataForOutboundAddr(remoteAddr *net.UDPAddr, peerPk []byte) (*core.ConnectionData, error) {
	if remoteAddr == nil {
		return nil, errors.New("missing remote address")
	}
	addrStr := remoteAddr.String()
	if !s.isKnownServerPeerTarget(remoteAddr, peerPk) {
		return nil, fmt.Errorf("%w: %s", errUnknownServerPeerTarget, addrStr)
	}

	s.remoteConnectionMapMutex.Lock()
	// Server assignment gives us a known server-peer UDP tuple and pubkey.
	// A reciprocal NHP_FWD may have already admitted the same tuple as a
	// generic inbound conn; promote only that trusted tuple so arbitrary live
	// conns are never reused as server peers. Promotion is intentionally
	// tuple+pubkey-gated; NHP encryption still gates real data, and the
	// accounting blast radius is this one tuple leaving per-IP eviction.
	connData, err := s.tryReuseServerPeerConnLocked(addrStr)
	if err != nil || connData != nil {
		s.remoteConnectionMapMutex.Unlock()
		return connData, err
	}
	s.remoteConnectionMapMutex.Unlock()

	recvTime := time.Now().UnixNano()
	conn := &UdpConn{
		isServerPeer: true,
		evictSignal:  make(chan struct{}),
	}
	conn.ConnData = &core.ConnectionData{
		InitTime:             recvTime,
		LastLocalRecvTime:    recvTime,
		Device:               s.device,
		LocalAddr:            s.listenAddr,
		RemoteAddr:           remoteAddr,
		CookieStore:          &core.CookieStore{},
		RemoteTransactionMap: make(map[uint64]*core.RemoteTransaction),
		SendQueue:            make(chan *core.Packet, PacketQueueSizePerConnection),
		RecvQueue:            make(chan *core.Packet, PacketQueueSizePerConnection),
		BlockSignal:          make(chan struct{}),
		SetTimeoutSignal:     make(chan struct{}, 1),
		StopSignal:           make(chan struct{}),
	}
	// Server-peer conns are trusted infra but intentionally keep the
	// short agent idle timeout: ForwardTimeout is 2s, so 30s covers the
	// transaction while letting sparse peer traffic tear down cleanly.
	conn.ConnData.InitTimeoutMs(DefaultAgentConnectionTimeoutMs)

	s.remoteConnectionMapMutex.Lock()
	connData, err = s.tryReuseServerPeerConnLocked(addrStr)
	if err != nil || connData != nil {
		s.remoteConnectionMapMutex.Unlock()
		return connData, err
	}
	if !s.globalCapAdmitsLocked() {
		s.remoteConnectionMapMutex.Unlock()
		s.metrics.IncrCounter(MetricGlobalCapRejections)
		return nil, fmt.Errorf("%w: maximum concurrent connection cap reached for outbound address %s", errOutboundServerGlobalCap, addrStr)
	}
	// Server-peer conns bypass the per-IP cap, so admitting one cannot evict
	// from connectionsByIP.
	s.admitNewConnectionLocked(conn, addrStr)
	s.remoteConnectionMapMutex.Unlock()
	if !s.startOutboundConnectionRoutine(conn) {
		// Shutdown-only race note: another forward can briefly observe this
		// just-admitted conn before this cleanup runs and queue one packet
		// against a conn that is immediately closed while Stop quiesces.
		s.remoteConnectionMapMutex.Lock()
		if s.remoteConnectionMap[addrStr] == conn {
			delete(s.remoteConnectionMap, addrStr)
		}
		s.remoteConnectionMapMutex.Unlock()
		conn.Close()
		return nil, errOutboundServerStopping
	}

	log.Debug("Created outbound UDP connection from %s to %s", s.listenAddrStr, addrStr)
	return conn.ConnData, nil
}

func (s *UdpServer) tryReuseServerPeerConnLocked(addrStr string) (*core.ConnectionData, error) {
	conn, found := s.remoteConnectionMap[addrStr]
	if !found {
		return nil, nil
	}
	connData, err := s.serverPeerConnDataLocked(addrStr, conn)
	if err != nil || connData == nil {
		return connData, err
	}
	// The routine's SendQueue case resets the idle timer for reused
	// server-peer conns; no timestamp poke is needed here.
	return connData, nil
}

func (s *UdpServer) isKnownServerPeerTarget(remoteAddr *net.UDPAddr, peerPk []byte) bool {
	if remoteAddr == nil || len(peerPk) == 0 {
		return false
	}
	peer := s.device.LookupPeer(peerPk)
	if peer == nil || peer.DeviceType() != core.NHP_SERVER {
		return false
	}
	return peerSendAddrMatches(peer, remoteAddr)
}

func peerSendAddrMatches(peer core.Peer, remoteAddr *net.UDPAddr) bool {
	if remoteAddr == nil {
		return false
	}
	if group, ok := peer.(*core.PeerGroup); ok {
		for _, member := range group.Members() {
			if udpPeerSendAddrMatches(member, remoteAddr) {
				return true
			}
		}
		return false
	}
	if udpPeer, ok := peer.(*core.UdpPeer); ok {
		return udpPeerSendAddrMatches(udpPeer, remoteAddr)
	}
	addr, ok := peer.SendAddr().(*net.UDPAddr)
	return ok && udpAddrEqual(addr, remoteAddr)
}

func udpPeerSendAddrMatches(peer *core.UdpPeer, remoteAddr *net.UDPAddr) bool {
	if peer == nil {
		return false
	}
	addr, ok := peer.SendAddr().(*net.UDPAddr)
	return ok && udpAddrEqual(addr, remoteAddr)
}

func udpAddrEqual(a, b *net.UDPAddr) bool {
	if a == nil || b == nil {
		return false
	}
	return a.Port == b.Port && a.Zone == b.Zone && a.IP.Equal(b.IP)
}

func (s *UdpServer) startOutboundConnectionRoutine(conn *UdpConn) bool {
	s.outboundConnStartMutex.Lock()
	defer s.outboundConnStartMutex.Unlock()

	select {
	case <-s.signals.stop:
		return false
	default:
	}

	s.wg.Add(1)
	go s.connectionRoutine(conn)
	return true
}

func (s *UdpServer) serverPeerConnDataLocked(addrStr string, conn *UdpConn) (*core.ConnectionData, error) {
	if conn == nil || conn.ConnData == nil {
		return nil, nil
	}
	if !conn.isServerPeer {
		if conn.isACConnection || conn.isDBConnection || conn.isWebRTC {
			return nil, fmt.Errorf("%w: %s", errServerPeerTupleOwned, addrStr)
		}
		if conn.ConnData.IsClosed() {
			return nil, nil
		}
		s.promoteServerPeerConnLocked(conn)
	}
	if conn.ConnData.IsClosed() {
		return nil, nil
	}
	return conn.ConnData, nil
}

func (s *UdpServer) promoteServerPeerConnLocked(conn *UdpConn) {
	if conn.isServerPeer {
		return
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
	conn.isServerPeer = true
}

// SendMessage prepares and queues a message for sending via the server's send
// channel. For outbound server-to-server forwards, it may synchronously
// synthesize/reuse ConnData before queueing, or drop when the peer/tuple is not
// safe to use. It returns local/prequeue failures only; successful queueing does
// not imply a protocol-level response.
func (s *UdpServer) SendMessage(md *core.MsgData) error {
	if md == nil {
		log.Warning("SendMessage called with nil MsgData")
		return errors.New("nil MsgData")
	}
	// Today RemoteAddr-without-ConnData is only the server-to-server NHP_FWD
	// path. Future callers that set RemoteAddr and omit both ConnData and
	// PrevParserData must target a known NHP_SERVER peer and will get the
	// same synthetic server-peer UDP lifecycle.
	if md.ConnData == nil && md.PrevParserData == nil && md.RemoteAddr != nil {
		connData, err := s.connDataForOutboundAddr(md.RemoteAddr, md.PeerPk)
		if err != nil {
			switch {
			case errors.Is(err, errUnknownServerPeerTarget):
				s.metrics.IncrCounter(MetricServerForwardTargetDrop)
				log.Warning("SendMessage dropping outbound connection to %s: %v", md.RemoteAddr, err)
			case errors.Is(err, errServerPeerTupleOwned):
				s.metrics.IncrCounter(MetricServerForwardTargetDrop)
				log.Error("SendMessage failed to prepare outbound connection to %s: %v", md.RemoteAddr, err)
			case errors.Is(err, errOutboundServerGlobalCap):
				log.Warning("SendMessage dropping outbound connection to %s under global connection cap: %v", md.RemoteAddr, err)
			case errors.Is(err, errOutboundServerStopping):
				log.Debug("SendMessage dropping outbound connection to %s during shutdown: %v", md.RemoteAddr, err)
			default:
				log.Error("SendMessage failed to prepare outbound connection to %s: %v", md.RemoteAddr, err)
			}
			return err
		}
		md.ConnData = connData
	}
	if md.ConnData == nil && md.PrevParserData == nil {
		err := fmt.Errorf("missing connection data for %s outbound packet", core.HeaderTypeToString(md.HeaderType))
		log.Error("SendMessage dropping %s without ConnData or PrevParserData", core.HeaderTypeToString(md.HeaderType))
		return err
	}
	s.sendMsgCh <- md
	return nil
}

// ProcessACOperation wraps the internal processACOperation method. res carries
// qURL v2 revocation metadata (P4a) to stamp onto the AOP, or nil for legacy
// callers.
func (s *UdpServer) ProcessACOperation(
	knkMsg *common.AgentKnockMsg,
	acConn *ACConn,
	srcAddr *common.NetAddress,
	dstAddrs []*common.NetAddress,
	openTime uint32,
	res *common.ResourceData,
) (*common.ACOpsResultMsg, error) {
	ctx, cancel := context.WithTimeout(context.Background(), DefaultBroadcastTimeout)
	defer cancel()
	return s.processACOperation(ctx, knkMsg, acConn, srcAddr, dstAddrs, openTime, res)
}

// ProcessACOperationBroadcast wraps the internal processACOperationBroadcast
// method. res carries qURL v2 revocation metadata (P4a) to stamp onto the AOP,
// or nil for legacy callers.
func (s *UdpServer) ProcessACOperationBroadcast(
	parentCtx context.Context,
	knkMsg *common.AgentKnockMsg,
	conns []*ACConn,
	srcAddr *common.NetAddress,
	dstAddrs []*common.NetAddress,
	openTime uint32,
	res *common.ResourceData,
) (*common.ACOpsResultMsg, error) {
	return s.processACOperationBroadcast(parentCtx, knkMsg, conns, srcAddr, dstAddrs, openTime, res)
}
