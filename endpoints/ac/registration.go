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
	// MinNLBReregistrationInterval (= 3 × this) derives from this value, and
	// DefaultAllUnconnectedThreshold (= 3) is a tick count whose duration is
	// also (3 × this) — keepalive cadence drives both, not the reverse. A
	// bump here proportionally raises both durations, so re-validate the
	// deploy-gate fences (TestNLBReregistration_BoundedByDeployGate) before
	// raising it.
	KeepaliveInterval = 10 * time.Second

	// KeepaliveTimeout is the timeout for keepalive response.
	KeepaliveTimeout = 3 * time.Second

	// KeepaliveMaxRetries is the max retries before considering server down.
	KeepaliveMaxRetries = 3

	// ReregistrationJitter is random jitter before re-registration (0-5s).
	ReregistrationJitter = 5 * time.Second

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
	// periodic NLB re-registration safety net. It must fit within the
	// blue/green deploy gate (post_switch_knock_ready_timeout_minutes
	// in .github/workflows/blue-green-deploy.yml, default 5 min;
	// driven by .github/scripts/verify-knock-ready.sh) so a
	// wrong-color latch caused by NLB UDP listener propagation lag
	// heals before the gate gives up. The worst-case interval
	// (default + max positive jitter) is fenced against the gate by
	// TestNLBReregistration_BoundedByDeployGate.
	//
	// No faster path catches the "AC has at least one connected server,
	// but it's the wrong color" case (checkAllUnconnected requires
	// *all* servers unconnected); the safety net is the primary
	// recovery path for that bug class, not a once-in-a-while hedge.
	//
	// Per cycle each AC sends 1 NLB-routed NHP_AOL plus N direct
	// NHP_AOLs to its assigned servers (HandleRedispatch always
	// re-handshakes; #1727 tracks short-circuiting on stable peer list).
	// At single-digit fleet sizes that's a few handshakes per minute —
	// well below NLB and per-server registration capacity *at single-
	// digit fleet sizes*. Larger fleets scale linearly with N_ac × N_servers
	// per AC; #1727's stable-peer-list short-circuit is the prerequisite
	// for raising fleet count without retuning. Keepalives stay on the
	// direct-IP path (every KeepaliveInterval per assigned server) because
	// routing them via NLB would amplify listener-fanout load without
	// buying additional self-healing.
	//
	// Operators can override per-AC via Config.NLBReregistrationIntervalSeconds.
	DefaultNLBReregistrationInterval = 90 * time.Second

	// periodicNLBRefreshLogSubstring is the load-bearing substring of
	// the log.Info message emitted by checkPeriodicNLBReregistration.
	// Pinned as a package-private constant so:
	//   - the unit fence (TestCheckPeriodicNLBReregistration_LogFormatStable)
	//     anchors directly against this symbol rather than a duplicated
	//     literal;
	//   - a refactor that reformats the log line is forced to either
	//     update this constant (which lights up the unit fence and,
	//     by symmetry, the smoke fence's regex) or live with a stale
	//     reference (which the unit test catches at compile time).
	//
	// The smoke test in tests/smoke/01_ac_nlb_reregistration_cadence_test.go
	// duplicates this literal in its CloudWatch Logs Insights query —
	// a cross-module import would add wiring without buying additional
	// safety because the unit test catches drift here. Replace with
	// #1714's structured tag at the emission site (and DELETE this
	// constant in the same PR) when the tag lands.
	periodicNLBRefreshLogSubstring = "periodic NLB re-registration triggered"

	// MinNLBReregistrationInterval is the lower bound for the periodic NLB
	// re-registration safety net. Going below ~3 × KeepaliveInterval
	// risks dogpiling under network blips even with the single-flight
	// guard in TriggerReregistration. Any configured value below this
	// is clamped up. Defined in terms of KeepaliveInterval so a future
	// retune of the keepalive cadence carries this floor along
	// proportionally rather than silently falling out of sync.
	//
	// Operator-config behavior change (PR #1726): pre-PR the floor was
	// 5 min, so any NLBReregistrationIntervalSeconds value between 60s
	// and 300s was silently clamped up to 300s. Post-PR the floor is
	// 30s, so those configs now take effect verbatim — a 5× nominal
	// rate increase from configs that were previously dead-zoned.
	//
	// This bounds the *steady-state* cadence. Under sustained
	// registration outages the inner retry loop in TriggerReregistration
	// (MaxReregistrationAttempts × n²-second backoff) governs cadence
	// instead — lastNLBRegistrationNano only advances on success, so a
	// failing periodic tick is not "spent" against this floor. The
	// inner exponential backoff is the intentional dogpile guard for
	// the failure path; this floor governs the success path.
	MinNLBReregistrationInterval = 3 * KeepaliveInterval

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
	MetricRegistrationAttempts = "RegistrationAttempts"
	MetricRegistrationSuccess  = "RegistrationSuccess"
	MetricRegistrationFailure  = "RegistrationFailure"
	MetricRegistrationLatency  = "RegistrationLatency"

	// MetricTransactionClosed counts forward-race hits on the AC side
	// (transaction.SendMessage returned common.ErrTransactionClosed).
	// Emitted in the same LayerV/NHP namespace as the server-side
	// counter; separated by AC dimensions so AC and server rates are
	// distinguishable in alarms / dashboards.
	MetricTransactionClosed = "TransactionClosed"
	// MetricAOPReplayDetected counts replay-dedupe drops of already-seen
	// (sender pubkey, transaction id, send time) AOP packets. Any sustained
	// non-zero rate is a security signal or a broken retry/failover path.
	MetricAOPReplayDetected       = "AOPReplayDetected"
	MetricServerConnections       = "ServerConnections"
	MetricServerConnectionFailure = "ServerConnectionFailure"
	MetricServerHealthFailures    = "ServerHealthFailures"
	MetricReregistrationTriggers  = "ReregistrationTriggers"

	// MetricAllUnconnectedDetected is incremented once per "all assigned
	// servers are unconnected" incident (on the 0->1 tick transition only)
	// so each incident counts once. It provides early visibility into a
	// degraded AC before the threshold actually triggers re-registration.
	MetricAllUnconnectedDetected = "AllUnconnectedDetected"

	// MetricReconcileOverlap is incremented when reconcileDevicePeers enters
	// while another reconcile is already in flight — i.e., the orphan-
	// precondition for the synchronous-reconcile model (#1680). Wired into
	// reconcileDevicePeers itself so both call sites (HandleRedispatch and
	// handleRegistrationResponse's direct-AAK branch) feed the same counter
	// and the metric stays a true family-wide signal: HandleRedispatch ↔
	// HandleRedispatch, HandleRedispatch ↔ direct-AAK, and direct-AAK ↔
	// direct-AAK overlaps all bump it.
	//
	// Counting model: emits N-1 events per overlap window of N concurrent
	// entrants — every reconcile past the first entrant bumps the counter
	// once. So 3 simultaneous reconcilers produce 2 metric events, not 1.
	// Alarm thresholds in #1693 should treat this as a rate signal, not as
	// a count of distinct overlap incidents.
	//
	// Each AC publishes its own per-ACId dim-stream, so any individual
	// AC sees per-AC overlap events. Fleet-aggregate views (CloudWatch
	// SUM/COUNT across ACId dims) are the right shape for fleet-wide
	// alarms; per-AC alarms can be tight since the empty-prior early
	// return means an AC's own first redispatch doesn't bump this
	// counter (cr round-38 #2 — the sibling reconcile that DOES have
	// work catches the overlap when it enters). #1693's alarms should
	// pick the appropriate view per use case.
	//
	// A non-zero rate in production is the signal to invest in a stronger
	// mitigation (e.g., serialize reconcile under r.mu, add a periodic
	// device-pool sweep against the live assignedServers, or land the
	// (pubkey, address) tuple-identity refactor in #1682 that structurally
	// eliminates the whole bug family).
	//
	// Coverage limit: this metric surfaces the orphan-precondition (two
	// reconciles in-flight). It does NOT directly surface the data-race
	// family on .Peer field reads under HandleRedispatch overlap (a
	// sibling connectToServer's .Peer write racing a reconcile's .Peer
	// read). The two families share the precondition but a partial
	// pointer read on .Peer doesn't necessarily emit an overlap event for
	// that exact occurrence — the metric covers the orphan family in
	// aggregate, not the data-race family in particular. #1670 is the
	// structural fix for the AssignedServer.Peer field-locking question.
	MetricReconcileOverlap = "ReconcileOverlap"

	// MetricUnaddressedTarget is incremented when targetActiveKey falls
	// through to the <unaddressed> sentinel — i.e., a RedirectTarget with
	// no IP and no Hostname reached reconcileDevicePeers despite
	// RedirectTarget.Validate (#832). Should be flat in steady state; a
	// non-zero rate is a Validate regression. Paired with the per-pass
	// log.Warning emitted from reconcileDevicePeers (deliberately loud —
	// this is a bug-class signal, not a noise source, because Validate is
	// supposed to make the branch unreachable). The metric exists so
	// alarms can surface the regression without log-grep. If this rate
	// ever becomes non-zero in steady state, the Validate fix lands first
	// and only then is rate-limiting on the warning revisited.
	//
	// Counting model: the per-pass aggregation in reconcileDevicePeers
	// sums sentinel observations across both newServers and priorServers
	// loops, so a single broken target that appears in both sides of one
	// reconcile pass produces 2 events. Alarms in #1693 should treat this
	// as "sentinel observations per pass" rather than "distinct broken
	// targets" — the difference doesn't matter for a flat-line steady
	// state, but it does for thresholds expressed in target counts.
	//
	// Log/metric correlation: ONE log.Warning per pass + ONE metric
	// emission per pass that increments by N (where N is the per-pass
	// observation count). An alarm author should NOT pattern-match on
	// "1 log line == 1 metric increment" — those are correlated 1:1 at
	// the event level, but the metric value scales with target count
	// while the log line is a single event. The log line carries
	// "total=N (prior=N1 new=N2)" so log-grepping reproduces the
	// metric breakdown.
	MetricUnaddressedTarget = "UnaddressedTarget"

	// MetricNilNewServersReconcile is incremented when reconcileDevicePeers
	// runs with newServers=nil — i.e., HandleRedispatch's all-fail
	// (successCount == 0) eviction branch — AND actually evicts at least
	// one prior peer. The branch is correct (avoids the orphan leak
	// Stop()'s invariant assumes away) but it widens the address-aliasing
	// race window for sibling redispatches: every prior is eligible for
	// removal, no active-set save can rescue it. Splitting this out from
	// MetricReconcileOverlap lets soak observation answer whether all-fail
	// entries dominate the overlap signal during partial-outage incidents
	// — if they do, the orphan-creation rate from this branch is the
	// load-bearing question rather than the overlap signal itself. Per-AC
	// dim so cross-AC alarms can isolate.
	//
	// Emitted from inside reconcileDevicePeers (not at the call site) so
	// the race-clean post-snapshot .Peer values gate the eviction count
	// (cr round-38 #3 — the previous shape did a duplicate racy scan in
	// the caller). One Incr per all-fail reconcile that did real work,
	// regardless of how many priors were evicted: branch-entry signal,
	// not per-element count.
	MetricNilNewServersReconcile = "NilNewServersReconcile"

	// Gauge metrics for AC-to-Server registration health monitoring (issue #239).
	// Published every flush interval via RegisterGaugeFunc.
	MetricServersConnected = "ServersConnected"
	MetricServersHealthy   = "ServersHealthy"

	// NHP_ARD pubkey-allowlist telemetry (#1156).
	//
	// MetricARDPubkeyPermitUnknown fires once per ARD target whose
	// pubkey is not in the AC's allowlist while the AC is running in
	// permit mode. Operators must verify this counter is flat before
	// flipping RequireServerPubKeyAllowlist=true: a non-zero rate in
	// permit mode would translate directly to a knock-path outage
	// under strict mode.
	//
	// MetricARDPubkeyRejected fires once per ARD target rejected in
	// strict mode. A non-zero rate in strict mode indicates either
	// (a) stale AC config (operator missed a server pubkey rotation)
	// or (b) an active attacker attempting the exfil described in
	// #1156. Either case is a page-worthy alert.
	//
	// Both metrics carry the ACId dimension only — intentional,
	// for CloudWatch cost. Forensic detail (which pubkey prefix
	// triggered the counter) lives in the Warning summary line
	// emitted by filterRedispatchTargets alongside the counter,
	// not in the metric dimension. An alarm triggered on either
	// counter should cross-reference the log stream at the same
	// timestamp to get the sample prefixes.
	MetricARDPubkeyPermitUnknown = "ARDPubkeyPermitUnknown"
	MetricARDPubkeyRejected      = "ARDPubkeyRejected"

	// MetricUDPHandlerPanic counts panics recovered by the top-level
	// guard on the AC's UDP message-handler goroutines (NHP_AOP and
	// NHP_ARD entry points in udpac.go::recvMessageRoutine; see
	// recoverUDPHandler in udpac.go for the increment site). Without
	// the guard a single panic on any per-packet goroutine would
	// crash nhp-acd; with it the panic is contained and surfaced as
	// this counter so the corresponding alarm in
	// terraform/modules/ac/monitoring.tf can page operators on the
	// next flush. Any non-zero value is page-worthy: it indicates a
	// reachable panic site somewhere on the UDP path that needs a
	// root-cause fix, not a tuning change.
	MetricUDPHandlerPanic = "UDPHandlerPanic"

	// MetricL3FlushKeyMalformed is incremented on the Schedule path
	// when scheduleFlushIfEnabled is rejected by MakeFlowKey
	// (malformed IP, unspecified IP, out-of-range port). Non-zero
	// means an upstream regression let a bad value reach the call
	// site; the kernel state is already settled, this is scheduler-
	// side bookkeeping loss.
	//
	// Schedule tick rate per (src, dst) pair: 1 tick per
	// scheduleFlushIfEnabled call reached, so 1–4 ticks per pair
	// on IP-bad depending on FilterMode + Protocol (the Schedule
	// fan-out across TCP / UDP / Any / ICMP).
	MetricL3FlushKeyMalformed = "L3FlushKeyMalformed"

	// MetricL3FlushScheduleNilEntry is incremented when
	// scheduleFlushIfEnabled is called with a nil AccessEntry. This
	// should never happen in production — all admission paths pass
	// the pre-stored tokenStore-bound entry. Non-zero is a regression
	// signal pointing at whichever caller dropped the entry; the
	// schedule is dropped (not Scheduled) to avoid creating a phantom
	// scheduler entry that cancelAllScheduledFlows would later miss.
	MetricL3FlushScheduleNilEntry = "L3FlushScheduleNilEntry"

	// MetricL3FlushCancelRescheduledForPeer is incremented when
	// cancelAllScheduledFlows's multi-session check (#2201) detects a
	// live peer entry that still holds the FlowKey and re-Schedules
	// instead of Cancel. Non-zero is the positive signal that the
	// per-entry tracking architecture is doing its job: peers with
	// overlapping FlowKeys (e.g., same agent IP + dst tuple via
	// longest-wins absorb) survive each other's expiry.
	//
	// Also ticks on the failed-admission cleanup path: if T1's
	// HandleAccessControl writes some Schedules then a downstream
	// kernel-write fails, emitOrCleanupPreMintedToken's drain runs
	// cancelAllScheduledFlows and any peer holding the same FlowKey
	// triggers a reschedule rather than a cancel. Dashboard readers
	// should not be alarmed by ticks correlated with admission
	// failures — that's correct behavior (a failing admission still
	// must not orphan a peer's coverage).
	//
	// Useful for: (a) regression detection — a sudden drop to zero
	// when peer-sharing is expected (multi-tab access to the same
	// resource, /refresh during a long session) signals
	// holdsScheduledKey returning false where it should return true;
	// (b) capacity planning — high tick rate indicates the workload
	// is FlowKey-collision-heavy and the reverse-index optimization
	// (#2163) becomes worth landing sooner.
	//
	// Edge: when the scheduler breaker is open during T2's admission,
	// T2's scheduleFlushIfEnabled still records K on T2.scheduledKeys
	// but its Scheduler.Schedule is a no-op (scheduler entry never
	// created). A subsequent T1 expire walks K, finds T2 via the
	// holdsScheduledKey consult, and ticks this metric on the
	// reschedule — even though the scheduler doesn't actually hold
	// K at that moment. Behaviorally fine (the reschedule then
	// creates the entry; outcome matches the non-breaker path) but
	// the tick momentarily over-reports "real peer-collision."
	// Dashboard readers chasing a spike should correlate against
	// breaker-trip metrics before interpreting as a workload shift.
	MetricL3FlushCancelRescheduledForPeer = "L3FlushCancelRescheduledForPeer"

	// MetricL3FlushAdmissionNilEntry is incremented when
	// HandleAccessControl is invoked with a nil *AccessEntry. This
	// should never happen in production — admitAndIssueToken
	// constructs the entry before the call, and /refresh-extend
	// passes the tokenStore-resident entry. Non-zero signals a
	// future refactor dropped the entry; the gate fails-closed with
	// ErrACNilEntry rather than nil-dereferencing entry.User.
	// Mirrors MetricL3FlushScheduleNilEntry's observability shape
	// so both layers of the nil-entry defense-in-depth surface
	// loudly in dashboards.
	MetricL3FlushAdmissionNilEntry = "L3FlushAdmissionNilEntry"

	// MetricL3FlushCancelNilTokenStore is incremented when
	// cancelAllScheduledFlows is called on a UdpAC with nil
	// tokenStore. This should never happen in production — Start
	// always constructs tokenStore before installExpiryHook fires
	// (and before any admission path can run). Non-zero is a
	// regression signal that a future dependency-injection refactor
	// dropped the field; multi-session protection (#2201) silently
	// degrades to lone-entry behavior when this fires, so the
	// counter MUST be alarmed before that regression reaches prod.
	MetricL3FlushCancelNilTokenStore = "L3FlushCancelNilTokenStore"

	// MetricL3FlushIpsetParseError is incremented per undecodable
	// `add` line during enumerateIpsetSet boot enumeration.
	// Tolerated up to maxCorruptIpsetLinesBeforeFail per call
	// (single-line damage shouldn't fail-close a 1M-entry boot);
	// past that the fail-loud contract trips. Non-zero on a
	// healthy fleet means an `ipset save` format drift or a racing
	// add/flush operation mid-stream — investigate before the next
	// ipset-tools upgrade. Naturally-expiring entries observed at
	// timeout=0 mid-stream are accepted by the parser and dropped
	// silently downstream (do NOT bump this counter).
	MetricL3FlushIpsetParseError = "L3FlushIpsetParseError"

	// L3 flush scheduler gauges Published every 60s via RegisterGaugeFunc; reads
	// are no-ops when the feature is off (UdpAC.expirySched nil).
	// The 4+4-week rollout's "validate then drop dry-run" gate
	// depends on these being visible in CloudWatch — without
	// telemetry, the rollout sequence can't validate against
	// anything.
	//
	//   - Entries        — current shard-index size (load)
	//   - FlushTotal     — Flush calls run to a real outcome
	//   - FlushErr       — non-canceled flusher failures (paging signal)
	//   - FlushDryRun    — dry-run skip count (validates flag wiring)
	//   - Deferred       — queue-full events seen
	//   - Dropped        — bounded-backpressure drops (page-worthy)
	//   - BucketMaxDepth — hot-bucket high-water mark
	//   - BreakerOpen    — 0/1 — fail-closed gauge for admission
	//   - BpfSkipped     — non-IPv4 keys hitting the IPv4-only BPF
	//                      flusher (upstream-regression signal)
	MetricL3FlushEntries               = "L3FlushEntries"
	MetricL3FlushFlushTotal            = "L3FlushTotal"
	MetricL3FlushFlushErr              = "L3FlushErr"
	MetricL3FlushFlushDryRun           = "L3FlushDryRun"
	MetricL3FlushDeferred              = "L3FlushDeferred"
	MetricL3FlushDropped               = "L3FlushDropped"
	MetricL3FlushBucketMaxDepth        = "L3FlushBucketMaxDepth"
	MetricL3FlushBreakerOpen           = "L3FlushBreakerOpen"
	MetricL3FlushBpfSkipped            = "L3FlushBpfSkipped"
	MetricL3FlushScheduleRejected      = "L3FlushScheduleRejected"
	MetricL3FlushScheduleAfterShutdown = "L3FlushScheduleAfterShutdown"
	// MetricL3FlushScheduleWaitTimeout counts Schedule() calls where
	// the in-flight Flush exceeded flushCallTimeout + scheduleWaitSlop
	// before closing its inFlight chan. Non-zero is a chronically-
	// stuck-flusher signal — the breaker catches it independently
	// once the first Flush returns with err, but this metric
	// surfaces the signal before the breaker trips. Must be wired
	// to a dashboard alert before L3FlushDryRun=false rollout
	// (#2189 tracks the terraform side).
	MetricL3FlushScheduleWaitTimeout = "L3FlushScheduleWaitTimeout"

	// qURL v2 immediate-revocation metrics (P4b). The revocation apply
	// primitive (ApplyRevocation) reuses the L3 flush scheduler, so these sit
	// alongside the L3Flush counters.
	//
	//   - MetricRevocationStaleDropped — a revoke event whose epoch was <= the
	//     last applied epoch for its (scope, scope_key); dropped as a stale /
	//     duplicate per the at-least-once + idempotency contract (mirrors P4d).
	//     A nonzero rate is expected and benign under at-least-once delivery;
	//     a SPIKE can indicate event-bus replay or a producer-side epoch bug.
	//   - MetricRevocationEntriesFlushed — count of tokenStore AccessEntries
	//     torn down by revocation (the revocation analog of an admission
	//     count). Drives the revocation-delivery / flush-completion proof the
	//     design requires.
	//   - MetricRevocationFlushScheduled — incremented once per entry whose
	//     tracked FlowKeys were rescheduled to fire now. Distinguishes "entry
	//     had live L3 flows we forced down" from "entry had no scheduled flows"
	//     (e.g. scheduler disabled), which Flushed alone cannot.
	//   - MetricRevocationRejected — incremented once per NHP_REV the AC handler
	//     (HandleUdpACRevocation, P4e) drops at validation BEFORE reaching
	//     ApplyRevocation: malformed body, an unsupported/AC-internal scope, an
	//     empty scope_key, or a negative epoch. NHP_REV is post-handshake
	//     authenticated (the sender is a known server peer), so a spike here is a
	//     producer bug or a malformed/forged event worth alarming on rather than
	//     leaving only in logs — distinct from the benign StaleDropped rate.
	MetricRevocationStaleDropped   = "RevocationStaleDropped"
	MetricRevocationEntriesFlushed = "RevocationEntriesFlushed"
	MetricRevocationFlushScheduled = "RevocationFlushScheduled"
	MetricRevocationRejected       = "RevocationRejected"
)

// Re-registration reason constants. These are the only values that
// classifyReason passes through; all others map to "other".
const (
	ReasonRefreshRedirect         = "refresh_redirect"
	ReasonRefreshPeerChange       = "refresh_peer_change"
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

// IsHealthy reports whether the server is currently connected and has
// been seen within the supplied healthWindow. Both Connected and LastSeen
// are read under a single lock acquisition so the two values are always
// consistent with respect to each other.
func (s *AssignedServer) IsHealthy(healthWindow time.Duration) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Connected && time.Since(s.LastSeen) <= healthWindow
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

// ErrRegistrationStopped is returned by public ACRegistration entry points
// when called after Stop has begun teardown. Callers can discriminate via
// errors.Is to distinguish a torn-down manager from a transient error.
// This sentinel is part of the package's public API surface — external
// callers may errors.Is against it, so renames must update every
// errors.Is site (in this package and any future consumers).
//
// As of #1657 the only entry point that needs this gate is HandleRedispatch.
// The other public mutating paths self-protect: TriggerReregistration's
// spawned goroutine selects on r.stopCh at every blocking step, and the
// register/connectToServer chain checks IsRunning + selects on r.stopCh.
// Start is one-shot — Stop is terminal, not pause/resume; a stopped
// manager cannot be restarted, so Start sits outside this audit.
// Read-only methods (GetAssignedServers, HasAssignedServers,
// IsServerAddress, connectedServerCount, healthyServerCount) do not
// need a gate — they take r.mu.RLock to seal Stop's slice mutation,
// so "no gate" does not mean "lock-free." Internal routines
// (keepaliveLoop, handleServerDown,
// refreshAssignedServerRegistrations, etc.) are
// reachable only via the gated public methods listed above or via
// wg-tracked loops that exit on r.stopCh, so they sit outside this
// audit. New public state-mutating entry points should return
// ErrRegistrationStopped early when r.stopped.Load() is true to keep
// this invariant.
var ErrRegistrationStopped = errors.New("registration manager stopped")

// recordRegistrationSuccess emits a MetricRegistrationSuccess counter with the
// given registration type dimension (dimValDirect, dimValRedispatch, or dimValPeerRedispatch).
//
// It also emits an unbreakdown base counter (no RegistrationType dim) so the
// registration_stale alarm — keyed on the publisher base dimension set
// [Component, Environment, Region] — has a matching metric stream to evaluate.
// The breakdown variant remains queryable for dashboards that want a
// per-RegistrationType view.
//
// This results in two CloudWatch datapoints per successful registration; the
// extra cost is acceptable in exchange for being able to alarm on the absence
// of *any* successful registration.
func (r *ACRegistration) recordRegistrationSuccess(regType *string) {
	r.metrics.IncrCounter(MetricRegistrationSuccess)
	r.metrics.IncrCounterWithDims(MetricRegistrationSuccess, []types.Dimension{
		{Name: dimNameRegistrationType, Value: regType},
	})
}

// recordRegistrationBreakdown emits the per-ErrorCode/ACId breakdown stream for
// MetricRegistrationFailure. This stream carries the extra dims (ACId, ErrorCode)
// and is for dashboards/analysis — it is NOT the stream the registration_failure
// alarm watches (that is the base counter at [Component, Environment, Region]).
// Shared by both recordRegistrationFailure (alarmable) and recordRegistrationDrop
// (non-alarmable); on its own it says nothing about alarmability.
func (r *ACRegistration) recordRegistrationBreakdown(errorCode *string) {
	r.metrics.IncrCounterWithDims(MetricRegistrationFailure, []types.Dimension{
		r.acIdDimension(),
		{Name: dimNameErrorCode, Value: errorCode},
	})
}

// recordRegistrationFailure records a registration failure that SHOULD page —
// a server-side rejection or error on an actual NHP_AOL response (the server
// returned an error response, an NHP_AAK ErrCode, or Registered=false). It
// dual-publishes:
//   - an unbreakdown base counter at the publisher base dim set
//     [Component, Environment, Region] — the stream the registration_failure
//     alarm evaluates, and
//   - the ErrorCode/ACId breakdown counter for dashboards.
//
// CloudWatch alarms select a stream by exact dimension match, so before #968
// (no base counter) the alarm watched a never-published stream and sat in
// permanent OK (treat_missing_data=notBreaching) even while registrations were
// failing. The base counter is what makes the alarm able to fire.
//
// Transport/lifecycle drops (our own shutdown "canceled", a no-response
// "timeout", or "stopped") are recorded via recordRegistrationDrop (breakdown
// only) instead: they are not page-worthy and burst during every instance
// refresh / blue/green flip, which with the alarm's Sum>5-over-one-period config
// would guarantee false pages. A genuine "AC can't reach any server" outage is
// still caught — registration_stale alarms on the ABSENCE of RegistrationSuccess
// and servers_healthy_low on the connected-server count.
func (r *ACRegistration) recordRegistrationFailure(errorCode *string) {
	r.metrics.IncrCounter(MetricRegistrationFailure)
	r.recordRegistrationBreakdown(errorCode)
}

// recordRegistrationDrop records a non-alarmable registration drop: it emits the
// ErrorCode/ACId breakdown stream ONLY (no base counter), so it stays out of the
// registration_failure alarm while remaining queryable for accounting and
// dashboards. Used for lifecycle/transport outcomes (canceled, timeout, stopped)
// that fire in bursts during AC teardown and blue/green flips. See
// recordRegistrationFailure for the alarmable counterpart and why the split
// exists (#968).
func (r *ACRegistration) recordRegistrationDrop(errorCode *string) {
	r.recordRegistrationBreakdown(errorCode)
}

// teardownRegistrationDropCodes is the explicit allow-list of teardown ErrorCode
// values that classifyResponseError can return and that are NOT page-worthy.
// recordRegistrationOutcomeByCode drops any code in this set and routes every
// other code to the alarmable path. That fail-safe default is the point: if a
// future change makes classifyResponseError return a new page-worthy code, it
// stays visible to the registration_failure alarm instead of silently landing
// breakdown-only and re-introducing the #968 non-functional-alarm bug class.
//
// Only "stopped" is here because classifyResponseError is the sole producer
// routed through recordRegistrationOutcomeByCode (it returns "" or "stopped"
// today). The register() select records its statically-known "canceled"/"timeout"
// drops directly via recordRegistrationDrop, and the ppd.Error path is always
// alarmable (a response WAS received) — neither flows through this set.
var teardownRegistrationDropCodes = map[string]struct{}{
	"stopped": {},
}

// recordRegistrationOutcomeByCode routes a classifyResponseError-derived
// ErrorCode to the breakdown-only drop stream (if it is a known teardown code)
// or the alarmable base counter (everything else, including a future code).
// Scoped to classifyResponseError specifically: its output is the only
// classification routed through the teardown-code set. The ppd.Error path uses
// recordResponseError (timeout = drop, real error = alarmable), and server-
// controlled or explicit-failure codes (NHP_AAK ErrCode, "registered_false")
// call recordRegistrationFailure directly so a server value can never masquerade
// as a teardown drop.
func (r *ACRegistration) recordRegistrationOutcomeByCode(code string) {
	if _, isDrop := teardownRegistrationDropCodes[code]; isDrop {
		r.recordRegistrationDrop(aws.String(code))
		return
	}
	r.recordRegistrationFailure(aws.String(code))
}

// recordResponseError records the failure for a non-nil PacketParserData.Error
// on the NHP_AOL response path. It distinguishes the two ways that error arises:
//
//   - A transaction-layer TIMEOUT, where no response was actually received: the
//     transaction's defer fabricates a PPD carrying common.ErrTransactionFailedByTimeout
//     (nhp/core/transaction.go) after the ~4.7s local-transaction timer fires —
//     which beats register()'s 30s RegistrationTimeout select, so this, not the
//     regTimer.C branch, is the path a blue/green-flip / unreachable-server
//     timeout actually takes. It is a transport drop (breakdown only, NOT
//     alarmable) so it can't false-page registration_failure on flips; a true
//     "AC can't reach any server" outage is still caught by registration_stale.
//   - Any OTHER error is a genuine server-returned error response and is
//     alarmable.
//
// Type-checked via errors.Is rather than the classifyError string so a genuine
// server error that merely classifies as "timeout" still pages.
func (r *ACRegistration) recordResponseError(err error) {
	if errors.Is(err, common.ErrTransactionFailedByTimeout) {
		r.recordRegistrationDrop(aws.String("timeout"))
		return
	}
	r.recordRegistrationFailure(aws.String(classifyError(err)))
}

// recordServerConnectionBreakdown emits the per-ErrorCode/ACId breakdown stream
// for MetricServerConnectionFailure (for dashboards/analysis). The counterpart
// of recordRegistrationBreakdown; there is no drop variant because every
// connectToServer failure is alarmable (see recordServerConnectionFailure).
func (r *ACRegistration) recordServerConnectionBreakdown(errorCode *string) {
	r.metrics.IncrCounterWithDims(MetricServerConnectionFailure, []types.Dimension{
		r.acIdDimension(),
		{Name: dimNameErrorCode, Value: errorCode},
	})
}

// recordServerConnectionFailure emits a MetricServerConnectionFailure counter,
// broken down by ErrorCode and ACId, plus an unbreakdown base counter so the
// server_connection_failure alarm (keyed on [Component, Environment, Region])
// has a matching stream. Same rationale as recordRegistrationFailure (#968).
// Unlike registration there is no drop exclusion: every connectToServer failure
// is alarmable, including the in-flight failures during an AC instance refresh,
// which the Sum>10-over-2-periods threshold is meant to ride out.
//
// Concurrency: the per-server connect attempts run on separate goroutines and
// each publisher call takes the publisher mutex, so individual increments are
// race-safe. The base and breakdown writes are two separate increments, not one
// atomic unit — at a flush snapshot the base total and the breakdown sum can
// differ by in-flight increments. That is harmless for alarming and accounting.
func (r *ACRegistration) recordServerConnectionFailure(errorCode *string) {
	r.metrics.IncrCounter(MetricServerConnectionFailure)
	r.recordServerConnectionBreakdown(errorCode)
}

// ACRegistration manages AC registration with NHP servers.
//
// New public state-mutating methods on this type must add an
// r.stopped.Load() gate at entry — see ErrRegistrationStopped's
// audit-invariant comment for the full rule.
type ACRegistration struct {
	ac *UdpAC
	// assignedServers is the current set of servers this AC is connected to.
	// INVARIANT: replace-only (copy-on-write). Never append or mutate in place —
	// always assign a new slice. Readers (peersChanged, checkServerHealth, etc.)
	// snapshot the slice header under RLock and iterate outside the lock, relying
	// on this invariant for safe concurrent access.
	assignedServers []*AssignedServer
	mu              sync.RWMutex
	stopCh          chan struct{}
	wg              sync.WaitGroup

	// reregistering prevents concurrent re-registration attempts
	reregistering atomic.Bool

	// reconcileInFlight counts the number of reconcileDevicePeers calls
	// currently executing. Surfaces the orphan-precondition for
	// MetricReconcileOverlap. Bumped by recordReconcileEntry inside
	// reconcileDevicePeers itself so both reconcile call sites
	// (HandleRedispatch and handleRegistrationResponse's direct-AAK
	// branch) feed the same family-wide signal.
	reconcileInFlight atomic.Int32

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
	//
	// IMMUTABLE after NewACRegistration. checkPeriodicNLBReregistration
	// reads it without a lock, relying on goroutine-start
	// happens-before. A future SIGHUP-style reload path that mutates
	// this field must serialize the read or switch to atomic.
	nlbReregistrationInterval time.Duration

	// allUnconnectedThreshold is the effective (config + per-AC jitter)
	// number of consecutive keepalive ticks the all-unconnected detector
	// requires before tripping a re-registration. Computed once at
	// construction for the same fleet-jitter reason as
	// nlbReregistrationInterval. IMMUTABLE after NewACRegistration on
	// the same terms (see comment above).
	allUnconnectedThreshold uint32
}

// resolveRegion mirrors the AWS SDK's region resolution chain (AWS_REGION
// then AWS_DEFAULT_REGION) so a process configured the CLI-style way still
// passes the AC's startup guard. TrimSpace defends against stray whitespace
// (e.g. `Environment="AWS_REGION= "` or a heredoc-mangled unit file) that
// would otherwise pass the empty-check and fail later inside the AWS SDK
// with a less obvious error.
func resolveRegion() string {
	if r := strings.TrimSpace(os.Getenv("AWS_REGION")); r != "" {
		return r
	}
	return strings.TrimSpace(os.Getenv("AWS_DEFAULT_REGION"))
}

// envFallbackUnknown is the dim value used when ac.config.Environment is
// empty (or whitespace-only). Deployed envs must carry a real value
// (TF user_data writes it); this fallback is for local/dev.
const envFallbackUnknown = "unknown"

// envFallbackWarn emits the startup warning when ac.config.Environment
// is empty or whitespace-only. Indirected through a package var so
// tests can fence the call site without setting up async-log
// capture; production code in NewACRegistration always calls it
// through this binding. Do not call directly from non-startup code.
var envFallbackWarn = func() {
	log.Warning("[AC] config.Environment is empty or whitespace-only (falling back to %q). Region-keyed alarms in monitoring.tf require this dim; in deployed envs this signals a TF user_data regression. See terraform/CLAUDE.md \"Metric / Alarm Dim-Set Rules\".", envFallbackUnknown)
}

// resolveEnvironment returns the publisher's Environment dim value
// (trimmed) plus a flag indicating whether the fallback path was
// taken. Empty or whitespace-only config falls back to "unknown" —
// defensible for local/dev but a regression in deployed envs
// (Region-keyed alarms in monitoring.tf select on this dim; "unknown"
// or whitespace silently breaks every one). TrimSpace parallels
// resolveRegion's defense against `Environment=" prod "` typos in a
// heredoc-mangled config.toml that would otherwise pass the
// empty-check and still produce a dim mismatch.
//
// Returning usedFallback lets callers warn-on-fallback without
// re-trimming the input. Signature differs from resolveRegion
// (which signals absent-config via an empty return); the parallel
// is the TrimSpace + empty-or-whitespace fallback contract, not
// the function shape.
//
// Why this is non-fatal where resolveRegion is fatal: AWS_REGION
// is required for the SDK to construct a CloudWatch client at all
// (no endpoint without a region), so the publisher cannot even
// start. Environment is a dim label — the publisher CAN still
// emit metrics with "unknown" (useful for local dev visibility),
// they just won't match deployed-env alarms. The asymmetry is
// intentional and load-bearing in dev/test workflows.
func resolveEnvironment(configEnv string) (env string, usedFallback bool) {
	trimmed := strings.TrimSpace(configEnv)
	if trimmed == "" {
		return envFallbackUnknown, true
	}
	return trimmed, false
}

// acBaseDims is the shared dim set every AC metric carries. Region is
// load-bearing: alarms in terraform/modules/ac/monitoring.tf select streams
// by exact dimension match, so dropping it would silently lose alerting.
// Order mirrors the alarm dim block in monitoring.tf for cross-file diff.
func acBaseDims(env, region string) []types.Dimension {
	return []types.Dimension{
		{Name: aws.String("Component"), Value: aws.String("AC")},
		{Name: aws.String("Environment"), Value: aws.String(env)},
		{Name: aws.String("Region"), Value: aws.String(region)},
	}
}

// NewACRegistration creates a new AC registration manager. AWS_REGION (or
// AWS_DEFAULT_REGION) must be set; without it the CloudWatch SDK can't
// resolve an endpoint and the publisher's dim set wouldn't match the
// Region-keyed alarms in terraform/modules/ac/monitoring.tf (see #1659).
func NewACRegistration(ac *UdpAC) (*ACRegistration, error) {
	region := resolveRegion()
	if region == "" {
		return nil, errors.New("AWS_REGION (or AWS_DEFAULT_REGION) must be set: required for CloudWatch metric publishing and Region-keyed alarms (e.g. AWS_REGION=us-east-2 or AWS_DEFAULT_REGION=us-east-2; see issue #1659)")
	}

	// Warn-loud at startup so a future TF regression that drops or
	// whitespace-mangles the Environment field surfaces in AC logs
	// instead of in CloudWatch alarm latch-up weeks later. An
	// operator who deliberately configures "unknown" (defensible
	// for a local-only dev box) does NOT trip the warning, because
	// only the empty/whitespace path sets usedFallback=true.
	env, usedFallback := resolveEnvironment(ac.config.Environment)
	if usedFallback {
		envFallbackWarn()
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

	dims := acBaseDims(env, region)

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
		stopCh:                    make(chan struct{}),
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

	// Register gauge functions for AC-to-Server registration health (issue #239).
	// These are evaluated every flush interval (60s) by the metrics publisher.
	r.metrics.RegisterGaugeFunc(MetricServersConnected, r.connectedServerCount)
	r.metrics.RegisterGaugeFunc(MetricServersHealthy, r.healthyServerCount)

	// Register L3 flush scheduler gauges so the rollout's
	// "validate then drop dry-run" gate has visible telemetry
	// Reads are
	// no-ops when the scheduler isn't constructed (feature off);
	// the closure handles the nil-receiver case gracefully.
	r.metrics.RegisterGaugeFunc(MetricL3FlushEntries, r.l3FlushEntriesGauge)
	r.metrics.RegisterGaugeFunc(MetricL3FlushFlushTotal, r.l3FlushFlushTotalGauge)
	r.metrics.RegisterGaugeFunc(MetricL3FlushFlushErr, r.l3FlushFlushErrGauge)
	r.metrics.RegisterGaugeFunc(MetricL3FlushFlushDryRun, r.l3FlushDryRunGauge)
	r.metrics.RegisterGaugeFunc(MetricL3FlushDeferred, r.l3FlushDeferredGauge)
	r.metrics.RegisterGaugeFunc(MetricL3FlushDropped, r.l3FlushDroppedGauge)
	r.metrics.RegisterGaugeFunc(MetricL3FlushBucketMaxDepth, r.l3FlushBucketMaxDepthGauge)
	r.metrics.RegisterGaugeFunc(MetricL3FlushBreakerOpen, r.l3FlushBreakerOpenGauge)
	r.metrics.RegisterGaugeFunc(MetricL3FlushBpfSkipped, r.l3FlushBpfSkippedGauge)
	r.metrics.RegisterGaugeFunc(MetricL3FlushScheduleRejected, r.l3FlushScheduleRejectedGauge)
	r.metrics.RegisterGaugeFunc(MetricL3FlushScheduleAfterShutdown, r.l3FlushScheduleAfterShutdownGauge)
	r.metrics.RegisterGaugeFunc(MetricL3FlushScheduleWaitTimeout, r.l3FlushScheduleWaitTimeoutGauge)

	// Add to wait group BEFORE starting goroutines to prevent race with Stop()
	r.wg.Add(1)
	go r.registrationLoop()

	return nil
}

// Stop stops the registration manager. Safe to call multiple times,
// and safe to call without a prior Start — tests rely on this
// invariant to drive ACRegistration.stopped=true without spinning up
// the real registrationLoop. Adding a started.Load() precondition
// here would silently mask any regression fence keyed on it.
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
	// Clean up connected server peers. HandleRedispatch reconciles the device
	// peer pool synchronously, so the live assignedServers slice is the
	// principal reference path at Stop() time.
	//
	// Concurrency: Stop ↔ in-flight redispatch.
	//
	// Edge case: if a redispatch is between r.mu.Unlock() and connectWg.Wait()
	// when Stop runs, Stop sees the freshly-installed assignedServers (the
	// new ones) and evicts those; the prior set is held only by
	// HandleRedispatch's local priorServers slice, which its in-flight
	// reconcile then evicts. What ensures the device pool ends fully cleared
	// is the prior+new disjointness (no peer pointer is shared between Stop's
	// view and the goroutine's local), not reconcile idempotency on its own
	// — both halves of the cleanup run against disjoint sets and serialize
	// through peerMapMutex.
	//
	// Stop does not block on an in-flight reconcile (HandleRedispatch is
	// not in r.wg). If Stop returns while a redispatch is mid-loop, the
	// AC is shutting down and the device is going with it — residual
	// peer-pool state on a dying device is not observable, so abandoned
	// mid-loop evictions don't leave the system in a bad state.
	//
	// Concurrency: metric drop semantics.
	//
	// An in-flight reconcile that calls IncrCounterWithDims after
	// r.metrics.Stop() (below) bumps an in-memory counter that is never
	// flushed. Best-effort by design — the AC is shutting down,
	// MetricReconcileOverlap is a precondition signal not a correctness
	// signal, and a metric that doesn't make it to CloudWatch on the
	// dying-process path is acceptable. #1693's alarms work on
	// rate-of-arrival and tolerate the rare drop.
	for _, server := range r.assignedServers {
		if server.Peer != nil {
			r.ac.device.RemovePeerByAddress(server.Peer.PublicKeyBase64(), server.Peer.Host())
			server.Peer = nil
		}
	}
	r.assignedServers = nil
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

// connectedServerCount returns the number of assigned servers in Connected state.
// Used as a GaugeFunc for the ServersConnected CloudWatch metric.
func (r *ACRegistration) connectedServerCount() float64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	count := 0
	for _, s := range r.assignedServers {
		if s.IsConnected() {
			count++
		}
	}
	return float64(count)
}

// healthyServerCount returns the number of assigned servers that are both
// connected and have responded within the keepalive health window
// (KeepaliveInterval * KeepaliveMaxRetries = 30s).
// Used as a GaugeFunc for the ServersHealthy CloudWatch metric.
func (r *ACRegistration) healthyServerCount() float64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	count := 0
	healthWindow := KeepaliveInterval * KeepaliveMaxRetries
	for _, s := range r.assignedServers {
		if s.IsHealthy(healthWindow) {
			count++
		}
	}
	return float64(count)
}

// l3FlushSnapshot returns the scheduler's metrics snapshot or the
// zero value if the feature is off (r.ac.expirySched nil). All
// l3Flush*Gauge helpers read through this single accessor so the
// nil-discipline lives in one place.
func (r *ACRegistration) l3FlushSnapshot() FlushMetrics {
	if r.ac == nil || r.ac.expirySched == nil {
		return FlushMetrics{}
	}
	return r.ac.expirySched.Metrics()
}

func (r *ACRegistration) l3FlushEntriesGauge() float64 {
	return float64(r.l3FlushSnapshot().Entries)
}
func (r *ACRegistration) l3FlushFlushTotalGauge() float64 {
	return float64(r.l3FlushSnapshot().FlushTotal)
}
func (r *ACRegistration) l3FlushFlushErrGauge() float64 {
	return float64(r.l3FlushSnapshot().FlushErr)
}
func (r *ACRegistration) l3FlushDryRunGauge() float64 {
	return float64(r.l3FlushSnapshot().FlushDryRun)
}
func (r *ACRegistration) l3FlushDeferredGauge() float64 {
	return float64(r.l3FlushSnapshot().FlushDeferred)
}
func (r *ACRegistration) l3FlushDroppedGauge() float64 {
	return float64(r.l3FlushSnapshot().FlushDropped)
}
func (r *ACRegistration) l3FlushBucketMaxDepthGauge() float64 {
	return float64(r.l3FlushSnapshot().BucketMaxDepth)
}
func (r *ACRegistration) l3FlushScheduleRejectedGauge() float64 {
	return float64(r.l3FlushSnapshot().ScheduleRejected)
}
func (r *ACRegistration) l3FlushScheduleAfterShutdownGauge() float64 {
	return float64(r.l3FlushSnapshot().ScheduleAfterShutdown)
}
func (r *ACRegistration) l3FlushScheduleWaitTimeoutGauge() float64 {
	return float64(r.l3FlushSnapshot().ScheduleWaitTimeout)
}

// l3FlushBreakerOpenGauge emits 1.0 when the breaker is open
// (admission failing closed) and 0.0 otherwise. A non-zero reading
// is page-worthy under the L3-only contract — refused NHP-AOPs
// translate to customer-visible auth failures.
func (r *ACRegistration) l3FlushBreakerOpenGauge() float64 {
	if r.l3FlushSnapshot().BreakerOpen {
		return 1.0
	}
	return 0.0
}

// l3FlushBpfSkippedGauge reads the BpfFlusher's non-IPv4 skip
// counter (when in EBPFXDP mode with BpfFlusher attached). A
// non-zero reading signals an upstream regression scheduling v6
// keys under EBPFXDP — see BpfFlusher.Flush godoc. Returns 0 when
// the feature is off or the flusher isn't a BpfFlusher.
func (r *ACRegistration) l3FlushBpfSkippedGauge() float64 {
	if r.ac == nil {
		return 0
	}
	count, ok := r.ac.BpfFlusherSkippedCount()
	if !ok {
		return 0
	}
	return float64(count)
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

		// Post-stop teardown is the expected exit path here — short-circuit
		// rather than falling through to the jitter select. Falling
		// through is functionally equivalent (the next iteration's
		// <-r.stopCh would exit deterministically since stopCh is
		// already closed), but adds one Warning log line for an
		// expected condition. Debug here keeps alerting noise off
		// rolling deploys.
		if errors.Is(err, ErrRegistrationStopped) {
			log.Debug("AC stopping during registration loop, exiting: %v", err)
			return
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
		// Statically-known lifecycle drop (AC shutting down) — breakdown only.
		r.recordRegistrationDrop(aws.String("canceled"))
		return errors.New("registration canceled")
	case <-regTimer.C:
		r.ac.device.RemovePeerByAddress(registrationPeer.PublicKeyBase64(), registrationPeer.Host())
		// Backstop only: this 30s RegistrationTimeout is almost always beaten by
		// the ~4.7s local-transaction timeout, which arrives on ResponseMsgCh as
		// ErrTransactionFailedByTimeout and is dropped by recordResponseError. This
		// branch covers the rare case the transaction timer didn't fire. Transport
		// drop (no response) — breakdown only; registration_stale covers a true
		// reach-nothing outage.
		r.recordRegistrationDrop(aws.String("timeout"))
		return errors.New("registration timeout")
	case ppd := <-md.ResponseMsgCh:
		err := r.handleRegistrationResponse(ppd, registrationPeer)
		if err == nil {
			r.metrics.RecordLatency(MetricRegistrationLatency, float64(time.Since(startTime).Milliseconds()))
		} else if code := classifyResponseError(err); code != "" {
			// Account for teardown drops in the failure metric so they
			// are not silently absorbed by the attempts counter. Bounded
			// by in-flight count at Stop; the dimension keeps cardinality
			// flat alongside "canceled" / "timeout". Other pre-existing
			// wrap-and-return paths (e.g., NHP_ARD's fmt.Errorf "failed
			// to handle redispatch") still leak attempts; #1672 tracks
			// closing those gaps.
			//
			// Routed by code, not hardcoded: classifyResponseError returns
			// "stopped" (a teardown drop) today, but if it ever returns a
			// page-worthy code, recordRegistrationOutcomeByCode defaults it
			// to alarmable rather than silently dropping it (#968 fail-safe).
			r.recordRegistrationOutcomeByCode(code)
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

		// Record the failure with a bounded error category. A transaction-layer
		// timeout arrives here as ErrTransactionFailedByTimeout (no response was
		// received — the transaction defer fabricated this PPD), which is the
		// dominant flip-time / unreachable-server transient and must NOT page;
		// recordResponseError drops it (breakdown only) and alarms genuine
		// server-returned error responses. See recordResponseError.
		r.recordResponseError(ppd.Error)

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

		// Connect to all assigned servers. Demote post-stop errors to Debug
		// — bounded by in-flight count at Stop and not alert-worthy; the
		// returned error keeps registrationLoop in retry-mode where its
		// stopCh select will exit cleanly.
		if err := r.HandleRedispatch(&ardMsg); err != nil {
			if errors.Is(err, ErrRegistrationStopped) {
				log.Debug("AC stopping during initial-registration NHP_ARD handling, %d targets: %v", len(ardMsg.Targets), err)
				return err
			}
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
			r.recordRegistrationFailure(aws.String(errCode))

			return fmt.Errorf("registration rejected: %s - %s", aakMsg.ErrCode, aakMsg.ErrMsg)
		}

		if !aakMsg.Registered {
			r.ac.device.RemovePeerByAddress(registrationPeer.PublicKeyBase64(), registrationPeer.Host())

			// Send registration failure metric for server-side rejection.
			r.recordRegistrationFailure(aws.String("registered_false"))

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
				// ErrRegistrationStopped means the manager is being torn
				// down — there is no "operational" state to preserve, so
				// don't record success. Mirror the NHP_ARD branch above
				// and propagate the error so registrationLoop's stopCh
				// select exits cleanly.
				//
				// Peer-leak note: registrationPeer (and serverPeer if the
				// direct-address branch ran above) remain in the device
				// peer map on this early-return — Stop's own cleanup
				// loop walks r.assignedServers and r.registrationPeer
				// (the struct field, not yet assigned at this point), so
				// it does not catch them. Bounded by in-flight count at
				// Stop and harmless until process GC since device.Stop
				// halts traffic processing. Tracked as concern 1c on
				// #1670; the structural fence there closes this surface.
				if errors.Is(err, ErrRegistrationStopped) {
					log.Debug("AC stopping during NHP_AAK peer handling, %d peers: %v", len(aakMsg.Peers), err)
					return err
				}
				// Genuine connection failure — HandleRedispatch only errors
				// when zero connections succeeded. The AC still has its NLB
				// registration peer, so it remains operational; log a
				// warning and record a (degraded) success rather than
				// failing the whole registration.
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
		// Snapshot the prior set so the device peer pool gets reconciled
		// consistently with the HandleRedispatch path (#1680).
		priorServers := r.assignedServers
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
		newServers := r.assignedServers

		// Hold r.mu across reconcile. Cost analysis (cr round-38):
		// reconcileDevicePeers does at most len(priorServers) ×
		// RemovePeerByAddress device-pool calls (each O(1) under
		// peerMapMutex), so for typical N≈3 the lock-held window is a
		// few µs of RLock-reader blocking. Releasing the lock here
		// (the previous shape) admitted an "orphan-until-process-restart"
		// hole on a racing HandleRedispatch — strictly worse than
		// blocking three readers for µs.
		//
		// serverPeer was added to the device pool earlier in this
		// response path, so reconcile sees the post-AddPeer state and
		// only evicts addresses that genuinely retired between the prior
		// assignment and the new one.
		//
		// Direct-AAK is authoritative. NHP_AAK from a registration
		// server is the canonical answer to "where is this AC assigned
		// now"; sibling-installed peers from a partial-redispatch
		// in-flight at NHP_AAK arrival time are evicted by design (not
		// merged additively). If a future operator sees
		// MetricReconcileOverlap correlate with multi-target →
		// single-target collapses on the direct-AAK path, that is the
		// expected shape — the multi-target redispatch's peers are
		// retired in favor of the AAK's authoritative single assignment.
		r.reconcileDevicePeers(priorServers, newServers)
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

// filterRedispatchTargets is the single gate that decides which NHP_ARD
// targets become assigned servers. It runs two filters in order:
//
//  1. Shape validation via RedirectTarget.Validate() — drops malformed
//     entries (empty IP, bad port, missing pubkey) so one bad upstream
//     entry cannot poison the whole redispatch. See #832.
//
//  2. Pubkey allowlist check via ardTrustSnapshot.contains — drops
//     (strict mode) or logs+counts (permit mode) entries whose pubkey
//     is not in the AC's trusted server-pubkey set. See #1156.
//
// Extracted from HandleRedispatch so the filter decisions are unit-
// testable without needing a live core.Device. The returned slice is
// always a fresh allocation (caller may retain it for assignedServers
// without aliasing the input).
func (r *ACRegistration) filterRedispatchTargets(targets []common.RedirectTarget) []common.RedirectTarget {
	// Snapshot the trusted-pubkey set + strict flag once per ARD so
	// concurrent config reload cannot flip the mode mid-batch (race
	// fix from PR #1239 review). The snapshot is a fresh map; an
	// ARD has a handful of targets so allocating it is cheaper than
	// re-acquiring the lock per target.
	snap := r.ac.ardTrustSnapshot()

	valid := make([]common.RedirectTarget, 0, len(targets))

	// Summary buffer for the per-batch Warning. Per-target lines
	// live at Debug to cap log-amplification from a large ARD
	// (reviewer concern: a malicious or buggy server shipping many
	// unknown targets could flood Warning otherwise). The first
	// few prefixes stay on the summary line so forensics still
	// see "which pubkeys did the AC reject".
	var unknownCount int
	samplePrefixes := make([]string, 0, maxPubkeyLogSamples)

	for i, target := range targets {
		if err := target.Validate(); err != nil {
			log.Warning("Skipping invalid redispatch target %d: %v", i, err)
			continue
		}
		if !snap.contains(target.PubKeyBase64) {
			unknownCount++
			if len(samplePrefixes) < maxPubkeyLogSamples {
				samplePrefixes = append(samplePrefixes, pubKeyPrefix(target.PubKeyBase64))
			}
			log.Debug("Redispatch target %d (%s:%d) pubkey %s not in allowlist",
				i, target.Address(), target.Port, pubKeyPrefix(target.PubKeyBase64))

			if snap.strict {
				continue
			}
		}
		valid = append(valid, target)
	}

	if unknownCount > 0 {
		// Dedicated counter per mode so CloudWatch alarms can
		// distinguish "config drift" (permit-mode signal — operator
		// should update the allowlist before flipping to strict)
		// from "attack or stale config in prod" (strict-mode signal
		// — page-worthy).
		//
		// Batched AddCounter instead of N IncrCounter calls: a
		// malicious or buggy upstream shipping an ARD with N
		// unknown pubkeys used to emit N metric publishes. Batching
		// is cheap today and cheap-forever even if metrics.Publisher
		// ever gains a sync or network cost.
		action := "allowing (permit mode — flip RequireServerPubKeyAllowlist=true once this signal is flat)"
		metric := MetricARDPubkeyPermitUnknown
		if snap.strict {
			action = "rejecting (strict mode)"
			metric = MetricARDPubkeyRejected
		}
		r.metrics.AddCounterWithDims(metric, float64(unknownCount), []types.Dimension{r.acIdDimension()})
		log.Warning("NHP_ARD: %d target(s) with unknown pubkey, %s; sample prefixes=%v",
			unknownCount, action, samplePrefixes)
	}

	return valid
}

// HandleRedispatch processes an NHP_ARD message and connects to
// assigned servers.
//
// Entry points — every NHP_ARD-shaped message flows through this
// function, making it the single choke point for the #1156
// pubkey-allowlist filter. A future code path that needs to
// provision assigned-server connections from an ARD MUST call
// HandleRedispatch (or filterRedispatchTargets directly) rather
// than bypassing to connectToServer, or the allowlist gate is
// silently lost.
//
//  1. Initial registration NHP_ARD response — startRegistration's
//     handleOnlineResponse branch on NHP_ARD.
//  2. NHP_AAK with an embedded peer list — handleOnlineResponse
//     wraps aakMsg.Peers as a synthetic ACRedispatchMsg and calls
//     HandleRedispatch.
//  3. Out-of-band NHP_ARD from the server — udpac.go's
//     HandleACRedispatch forwards to r.registration.HandleRedispatch.
//
// Refresh-triggered re-registrations route through TriggerReregistration
// → a new startRegistration cycle, which again lands in entry
// point 1 or 2 above — not a distinct path.
//
// Returns ErrRegistrationStopped after Stop has begun teardown (#1657);
// callers should errors.Is(err, ErrRegistrationStopped) to discriminate
// the post-stop case from genuine redispatch errors. See udpac.go::Stop
// for the ordering rationale. The gate fences this function's own
// state mutations and goroutine spawns; callers may have already
// performed side effects (e.g., handleRegistrationResponse's NHP_ARD
// branch removes the registration peer before reaching here) — those
// are the desired teardown behaviors and not gated by
// ErrRegistrationStopped.
//
// A goroutine that reads r.stopped == false just before Stop's Swap
// can still pass the gate. The fallout is bounded: connectToServer's
// downstream goroutines exit on r.stopCh, so no panic; r.assignedServers
// may be repopulated post-Stop and any peers AddPeer'd in that window
// stay in the device peer map until process GC. core.Device.Stop's
// "tolerant of concurrent AddPeer" contract is load-bearing for the
// in-flight wg-tracked goroutines that #1655 introduced; the structural
// fence for the in-flight TOCTOU is tracked in #1670.
func (r *ACRegistration) HandleRedispatch(ardMsg *common.ACRedispatchMsg) error {
	if r.stopped.Load() {
		return ErrRegistrationStopped
	}

	if !common.IsSuccessErrCode(ardMsg.ErrCode) {
		return errors.New("redispatch failed: " + ardMsg.ErrMsg)
	}

	if len(ardMsg.Targets) == 0 {
		return errors.New("no targets in redispatch message")
	}

	// Filter targets through RedirectTarget.Validate() and the pubkey
	// allowlist (#1156). Invalid targets are skipped with a warning so
	// a single malformed upstream entry cannot poison the whole
	// redispatch, but if no valid targets remain we fail the redispatch
	// rather than corrupting r.assignedServers with an unusable slice.
	// See #832: hostname-only targets used to pass the old
	// "IP == '' && Hostname == ''" check and then broke every downstream
	// consumer that keyed on Target.IP.
	validTargets := r.filterRedispatchTargets(ardMsg.Targets)
	if len(validTargets) == 0 {
		return errors.New("no valid targets in redispatch message after filtering")
	}

	r.mu.Lock()
	// Snapshot the previous assignment so we can reconcile the device peer
	// pool after the new connections are established. Each HandleRedispatch
	// creates fresh *AssignedServer structs, so the old slice is independent
	// of the new — connectToServer mutates only the new structs.
	priorServers := r.assignedServers
	r.assignedServers = make([]*AssignedServer, len(validTargets))
	for i, target := range validTargets {
		r.assignedServers[i] = &AssignedServer{
			Target:    target,
			Connected: false,
		}
		log.Info("Assigned server %d: %s:%d (AZ=%s)", i, target.Address(), target.Port, target.AZ)
	}
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
				r.recordServerConnectionFailure(aws.String(classifyError(err)))
			} else {
				atomic.AddInt32(&successCount, 1)
			}
		}(server)
	}
	connectWg.Wait()

	// Fail if no connections succeeded — AC would be unreachable.
	// Evict prior peers anyway: none of the new connects succeeded, so no
	// address overlap can save them, and r.assignedServers has already been
	// replaced with the failed new entries. By the time the next redispatch
	// runs, its priorServers snapshot loops over those failed entries,
	// skips them via srv.Peer == nil, and the genuinely-retired peers
	// would be orphaned in the device pool — unreachable from any code
	// path, not just skipped. Pass nil newServers so the active-set check
	// evicts the whole prior set, restoring the invariant Stop()'s comment
	// relies on (assignedServers is the only place peers are referenced).
	//
	// Overlap-family note: this nil-newServers reconcile makes every prior
	// eligible for removal, which widens the window for the address-aliasing
	// race documented in reconcileDevicePeers' doc comment — a sibling
	// redispatch's just-AddPeer'd shared-pubkey peer at a prior's address
	// can be collateral-evicted (PeerGroup.RemoveMember matches by address;
	// the LookupPeer defense covers only the non-PeerGroup branch). Same
	// MetricReconcileOverlap signal applies; #1682 is the structural fix.
	// Bump MetricNilNewServersReconcile separately so soak observation can
	// answer whether all-fail entries dominate the overlap signal during
	// partial-outage incidents.
	if successCount == 0 {
		// nil newServers → activeKeys is empty → every prior is removal-
		// eligible. The active-set check trivially fails, the LookupPeer
		// defense still runs, and reconcile evicts the whole prior set.
		// MetricNilNewServersReconcile is emitted from reconcileDevicePeers
		// itself when nil newServers actually evicts at least one prior —
		// using the same race-clean .Peer snapshot the loop already takes
		// (cr round-38 #3: avoids a duplicate racy scan here).
		r.reconcileDevicePeers(priorServers, nil)
		return errors.New("failed to connect to any assigned servers")
	}

	// Warn if partial failure (some but not all servers connected)
	if int(successCount) < len(serversToConnect) {
		log.Warning("Partial connection success: %d/%d assigned servers connected", successCount, len(serversToConnect))
	} else {
		log.Info("Successfully connected to all %d assigned servers", successCount)
	}

	// Reconcile the device peer pool: remove any (pubkey, address) entries that
	// were in the prior assignment but are not in the new one. Synchronous and
	// without a grace period — see reconcileDevicePeers and #1680 for why.
	r.reconcileDevicePeers(priorServers, serversToConnect)

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
		// Mirror the cleanup of the other error returns below: the new
		// successCount==0 branch in HandleRedispatch made an IsRunning
		// flap during redispatch leak the just-AddPeer'd peer into the
		// device pool with no live AssignedServer pointing at it (no
		// other reconcile path picks it up because it's on a fresh
		// pubkey not in priorServers). Closes the leak that was
		// pre-existing but reachability-amplified by this PR.
		r.ac.device.RemovePeerByAddress(peer.PublicKeyBase64(), peer.Host())
		server.Peer = nil
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
//  2. checkPeriodicNLBReregistration — bounded NLB re-registration
//     that fires regardless of per-server health. Catches both
//     "every UDP path is silently dead" (the original
//     defense-in-depth motivation) and "AC connected to the
//     wrong-color server after a deploy switch" (the primary recovery
//     path checkAllUnconnected cannot see when at least one server
//     is connected). See DefaultNLBReregistrationInterval.
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
		// LOAD-BEARING WORDING: tests/smoke/09_ac_redispatch_loop_test.go
		// substring-matches /Refresh NHP_AOL to .* failed: peer not found
		// in peer pool/ as the AC-side half of the #1680 regression
		// fence. A wording change here will silently break that fence
		// (no compile-time link). Until #1714 lands a stable structured
		// tag, treat this phrasing as part of the AC log surface contract.
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
			// If the server included an updated peer list, check whether it
			// differs from our current assignedServers. A mismatch means the
			// server reassigned this AC (e.g., after a blue-green switch) and
			// we need to reconnect to the correct set of servers.
			// Check before UpdateLastSeen to avoid a wasted write when
			// re-registration replaces the entire assignedServers slice.
			//
			// Validate peers first to avoid spurious re-registration from
			// malformed entries (same bug class as issue #832).
			validPeers := filterValidPeers(aakMsg.Peers, sendAddr.String())
			if len(validPeers) > 0 {
				if changed, currentAddrs := r.peersChanged(validPeers); changed {
					log.Info("Refresh NHP_AAK from %s: peer list changed, triggering re-registration (current=%s, new=%s)",
						sendAddr.String(), currentAddrs, formatPeerAddrs(validPeers))
					r.TriggerReregistration(ReasonRefreshPeerChange)
					return
				}
			}

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

// peersChanged returns true if the server-provided peer list differs from
// the AC's current assignedServers, plus a formatted string of the current
// addresses for logging (from the same snapshot, avoiding TOCTOU with the
// comparison). Comparison is by IP:Port since public keys can rotate
// independently.
//
// Assumes neither list contains duplicate addresses — the server builds
// peers from DynamoDB assignments which are unique per AC.
func (r *ACRegistration) peersChanged(peers []common.RedirectTarget) (bool, string) {
	r.mu.RLock()
	current := r.assignedServers
	r.mu.RUnlock()

	// Build a set of current server addresses for O(n) comparison.
	// net.JoinHostPort handles IPv6 bracket formatting correctly.
	currentAddrs := make(map[string]struct{}, len(current))
	for _, s := range current {
		currentAddrs[net.JoinHostPort(s.Target.IP, strconv.Itoa(s.Target.Port))] = struct{}{}
	}

	if len(peers) != len(current) {
		return true, formatAssignedAddrs(current)
	}

	for _, p := range peers {
		if _, ok := currentAddrs[net.JoinHostPort(p.IP, strconv.Itoa(p.Port))]; !ok {
			return true, formatAssignedAddrs(current)
		}
	}

	// No change — skip the log-string allocation entirely (99.99% path).
	return false, ""
}

// formatAssignedAddrs builds a human-readable address list from the snapshot
// used by peersChanged. Only called on the change path to avoid allocating
// on every refresh cycle.
func formatAssignedAddrs(servers []*AssignedServer) string {
	addrs := make([]string, len(servers))
	for i, s := range servers {
		addrs[i] = net.JoinHostPort(s.Target.IP, strconv.Itoa(s.Target.Port))
	}
	return "[" + strings.Join(addrs, ", ") + "]"
}

// filterValidPeers returns only peers that pass RedirectTarget.Validate().
// Invalid entries are logged and dropped to prevent malformed peers from
// causing spurious re-registration on every refresh cycle (see issue #832).
func filterValidPeers(peers []common.RedirectTarget, source string) []common.RedirectTarget {
	if len(peers) == 0 {
		return nil
	}
	// First pass: check if all peers are valid (common case — zero alloc).
	allValid := true
	for i := range peers {
		if err := peers[i].Validate(); err != nil {
			log.Warning("Dropping invalid peer from refresh response (source=%s): %v", source, err)
			allValid = false
		}
	}
	if allValid {
		return peers
	}

	// Second pass: build filtered slice (rare — only when server sends bad data).
	valid := make([]common.RedirectTarget, 0, len(peers))
	for i := range peers {
		if peers[i].Validate() == nil {
			valid = append(valid, peers[i])
		}
	}
	return valid
}

// formatPeerAddrs returns a human-readable list of RedirectTarget addresses for logging.
func formatPeerAddrs(peers []common.RedirectTarget) string {
	addrs := make([]string, len(peers))
	for i, p := range peers {
		addrs[i] = net.JoinHostPort(p.IP, strconv.Itoa(p.Port))
	}
	return "[" + strings.Join(addrs, ", ") + "]"
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
		// LOAD-BEARING WORDING: tests/smoke/09_ac_redispatch_loop_test.go
		// substring-matches /servers appear down, triggering
		// re-registration/ as one half of the #1680 regression fence
		// (the other half is in handleRefreshResponse). A wording change
		// here silently breaks that fence — no compile-time link. Until
		// #1714 lands a stable structured tag, treat this phrasing as
		// part of the AC log surface contract.
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

		if errors.Is(err, ErrRegistrationStopped) {
			log.Debug("AC stopping during server-down re-registration, exiting: %v", err)
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

			if errors.Is(err, ErrRegistrationStopped) {
				log.Debug("AC stopping during connection-triggered re-registration, exiting: %v", err)
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
// response arrives, then reconcile the device peer pool synchronously
// (see reconcileDevicePeers). Clearing the slice from this goroutine
// would race with a concurrent HandleRedispatch that might have just
// installed a fresh set of valid servers and silently drop those
// legitimate assignments.
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

// checkPeriodicNLBReregistration is the bounded NLB re-registration
// path that fires every nlbReregistrationInterval regardless of any
// per-server health signal. It exists for the failure modes the
// per-server keepalive path simply cannot see:
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
// Distinct from checkAllUnconnected: that one fires within ~30s
// when *every* server is in Connected=false. This one fires every
// nlbReregistrationInterval regardless. See
// DefaultNLBReregistrationInterval for cadence rationale.
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

	log.Info("AC %s: "+periodicNLBRefreshLogSubstring+" (last registration: %s ago, interval: %s)",
		r.ac.config.ACId,
		r.timeSinceLastNLBRegistration().Truncate(time.Second),
		r.nlbReregistrationInterval)

	r.TriggerReregistration(ReasonPeriodicNLBRefresh)
}

// recordReconcileEntry increments the in-flight counter at the point where
// reconcileDevicePeers begins mutating peer-pool state and returns the
// matching exit hook to defer. inFlight > 1 emits MetricReconcileOverlap —
// the orphan-precondition documented on reconcileDevicePeers.
//
// Called from inside reconcileDevicePeers (not from its callers), so every
// reconcile call site contributes to the same family-wide signal. A future
// third call site that goes through reconcileDevicePeers gets the metric
// for free; a future reconcile bypass that doesn't would silently miss it.
//
// Use as:
//
//	exit := r.recordReconcileEntry()
//	defer exit()
func (r *ACRegistration) recordReconcileEntry() func() {
	// entrants is the count AFTER our increment, including ourselves.
	// We're an overlap-causing entrant when entrants > 1 (i.e., at
	// least one other reconcile was already in flight when we arrived).
	// Off-by-one trap to watch for: a future refactor that switches to
	// CompareAndSwap or pre-increment-compare must keep the
	// "we're the second-or-later entrant" semantic, not "we observed
	// any other entrant at any point."
	if entrants := r.reconcileInFlight.Add(1); entrants > 1 {
		r.metrics.IncrCounterWithDims(MetricReconcileOverlap, []types.Dimension{r.acIdDimension()})
	}
	return func() { r.reconcileInFlight.Add(-1) }
}

// targetActiveKey returns a canonical (pubkey, address) key for active-set
// membership tests, plus a bool flagging the <unaddressed> sentinel branch.
//
// Contract. Keys on RedirectTarget.IP (preferred) or Hostname; both prior
// and new sets are keyed consistently because RedirectTarget.Validate (#832)
// requires one of them. PeerGroup.RemoveMember matches on
// m.Ip == addr || m.Host() == addr; passing peer.Host() at remove time
// (which prefers Hostname when set and includes the port suffix as
// "host:port") resolves the correct member via the m.Host() == addr branch.
// The m.Ip == addr branch does not fire for typical peers because m.Ip is
// the IP without a port and peer.Host() includes one — the load-bearing
// match is m.Host() == addr.
//
// INVARIANT: callers must ensure both prior and new targets have IP
// populated. RedirectTarget.Validate (#832) requires IP specifically and
// explicitly rejects hostname-only targets ("Hostname is not a substitute"
// — see nhp/common/nhpmsg.go). Hostname is optional metadata. The
// Hostname fallback below and the IP→Hostname transition test
// (TestACRegistration_ReconcileDevicePeers_IPToHostnameTransition) are
// defense-in-depth: they exercise paths that bypass Validate (today only
// reachable via direct test invocation), and the <unaddressed> sentinel +
// MetricUnaddressedTarget surface a Validate regression that did let
// such a target through.
//
// DNS-flip semantics. Drain-redirect targets (#1239) are emitted with
// Hostname set on the wire; the AC's pre-Validate adapter must resolve
// Hostname to IP before construction so the produced RedirectTarget
// satisfies Validate. If the resolved IP changes between prior and new
// (NLB address rotation), the keys differ and the prior is evicted —
// correct, because the new peer is at the new resolved address and is
// already in newServers, so the active member is preserved while the
// stale one drops.
//
// Sentinel + reporting. Returns (key, true) when input has neither IP nor
// Hostname — belt-and-suspenders against a regression in
// RedirectTarget.Validate. Callers (reconcileDevicePeers) aggregate the
// bool over a single reconcile pass and emit one log.Warning per pass +
// one MetricUnaddressedTarget bump PER SENTINEL OBSERVATION (the metric
// uses AddCounterWithDims with the per-pass count, so the time-series
// counts observations, not passes). Aggregation is the deliberate rate
// limit on the warning: Validate is supposed to make this branch
// unreachable, so the signal must be loud, but a per-target log.Warning
// would scale with offending target count and reconcile frequency.
// Per-pass log + per-observation metric keeps the loud-on-regression
// signal while bounding log volume.
func targetActiveKey(t common.RedirectTarget) (key string, sentinel bool) {
	addr := t.IP
	if addr == "" {
		addr = t.Hostname
	}
	if addr == "" {
		addr = "<unaddressed>"
		sentinel = true
	}
	// Use \x00 as the field separator. PubKeyBase64 is RFC 4648 base64
	// (alphabet [A-Za-z0-9+/=]) so "|" would also work, but Hostname is
	// not similarly constrained — a future test/regression injecting a
	// hostname containing "|" would ambiguate "k|host|with|pipes:port"
	// vs "k|host:port|with|pipes" (cr round-38 #8). The null-byte
	// separator is unambiguous against any printable input and matches
	// the convention buildDimCounterKey uses in endpoints/metrics.
	key = fmt.Sprintf("%s\x00%s:%d", t.PubKeyBase64, addr, t.Port)
	return key, sentinel
}

// reconcileDevicePeers removes from the device cipher pool the
// (pubkey, address) entries present in priorServers but absent from
// newServers. Called synchronously from HandleRedispatch after the new
// connections have been established.
//
// Behavior. Two invariants keep this safe with the *core.PeerGroup model
// that ASGs with shared keypairs land in (issue #1680):
//
//  1. Set difference. Only addresses that are NOT in newServers are
//     candidates for removal. An address that re-appears in the new
//     assignment is skipped here, preventing the previous async cleanup's
//     self-inflicted eviction loop.
//
//  2. Order. connectToServer (which calls device.AddPeer for each new
//     target) runs BEFORE this function. Addresses removed here are
//     therefore addresses that have NOT been re-AddPeer'd in this
//     redispatch — the *UdpPeer member sitting at that address inside
//     the PeerGroup is still the prior one, so RemovePeerByAddress
//     evicts the correct peer.
//
// Replaces the previous oldServerSets + 2-minute-grace-period cleanupWorker.
// The grace period was non-load-bearing (the only packets that could rely
// on it were leftovers from a server already disowned by this AC, whose
// validation outcome no longer affects the user-facing flow), so deleting
// the async machinery removes a bug surface without changing behavior.
//
// Concurrency: overlap windows.
//
// In the rare case where a second
// redispatch starts and finishes its reconcile while the first redispatch's
// connectToServer is still running, the first's late AddPeer can reintroduce
// a peer at an address the second redispatch had just removed. The resulting
// orphan sits in the device peer pool with no live AssignedServer pointing
// at it; nothing routes traffic to it, and the next non-overlapping
// redispatch evicts it via this function's normal delta path. The symmetric
// failure is also possible: between this function's targetActiveKey
// enumeration and its RemovePeerByAddress call, a sibling redispatch can
// AddPeer at the to-be-removed address — and we then evict that fresh peer.
// connectToServer's own failure path (AddPeer-then-RemovePeerByAddress on
// timeout/error) admits the same family of races against a sibling's fresh
// AddPeer at the same address. All three are the original incident's
// pointer-aliasing failure mode in miniature; fully eliminating them
// requires (pubkey, address) tuple identity in core.Device (tracked in
// #1682), so a non-zero MetricReconcileOverlap rate is the signal for the
// whole family — not just orphans from this function. Acceptable given
// that re-registration is gated by reregistering.CompareAndSwap, so
// HandleRedispatch overlap requires an out-of-band NHP_ARD landing during
// an in-progress register cycle. Direct-AAK ↔ direct-AAK overlap (two
// NHP_AAK responses arriving in quick succession) is gated only by network
// arrival ordering — not by the CAS, which sits on TriggerReregistration
// rather than the response handler. MetricReconcileOverlap covers both.
//
// Concurrency: single-peer branch hazard.
//
// core.Device.RemovePeerByAddress's single-peer (non-PeerGroup)
// branch ignores the addr argument and unconditionally deletes peerMap[K].
// Under the documented overlap precondition, this means a sibling's just-
// AddPeer'd single peer at K can be wholesale evicted when this function
// thinks it's removing the prior K|A — the active-set check above
// prevents the in-set case but cannot rescue the cross-redispatch race.
// Tightening that branch to honor addr is part of #1682's tuple-identity
// surface.
//
// Concurrency: field reads under overlap.
//
// reconcileDevicePeers reads Target on both priorServers and
// newServers (immutable after AssignedServer construction in
// HandleRedispatch), and reads .Peer on priorServers for the
// RemovePeerByAddress call. Under the documented HandleRedispatch overlap
// precondition a sibling redispatch's connectToServer can still be writing
// .Peer on those structs — the read here is intentionally racy in that
// rare case (the AssignedServer.Peer field-locking question is tracked in
// #1670). MetricReconcileOverlap surfaces the precondition; if it fires
// in production, #1670 / #1682 are the structural fixes.
//
// priorServers' .Peer fields are also read after handleRegistrationResponse's
// pre-existing registrationPeer cleanup may have mutated peerMap entries
// under r.mu; the .Peer reads here are of immutable fields on *core.UdpPeer
// (PublicKeyBase64, Host()), not of peerMap state, so the device-side
// cleanup above does not invalidate the captured pointers — the cleanup
// only changes what's *in* the device pool, not what those pointers refer
// to.
//
// Failure shapes: partial-success / address-aliasing.
//
// When HandleRedispatch's
// connectToServer fails on a target whose address aliases a prior server,
// connectToServer's failure path calls RemovePeerByAddress on the new
// peer's pubkey/host — which is the same address as the prior under
// shared pubkey, so the prior is collateral-evicted. Reconcile here then
// sees activeKeys including that address (the new entry is in
// serversToConnect regardless of connect success) and skips the prior,
// so the device pool ends up missing both peers. Bounded by the next
// non-overlapping cycle; same family the overlap doc describes; #1688
// is the right place to track the fix once test-harness work supports
// driving the partial-failure path deterministically.
func (r *ACRegistration) reconcileDevicePeers(priorServers, newServers []*AssignedServer) {
	if len(priorServers) == 0 {
		// Empty priors → nothing to evict. MetricReconcileOverlap is an
		// orphan-precondition signal (concurrent reconciles that *could*
		// evict — i.e., have priors), not a generic data-race detector;
		// a reconcile with no priors cannot be the orphan-creator, so
		// returning here without bumping the counter keeps the metric's
		// semantics tight. cr round-38 #2: the previously-hoisted
		// recordReconcileEntry produced fleet-warmup baseline noise on
		// cold-start ACs without adding coverage (the racing
		// connectToServer-vs-sibling-reconcile case is caught by the
		// SIBLING reconcile's own entry, not by this empty-prior one).
		return
	}

	// Track concurrent reconcile entries — the orphan precondition for the
	// whole bug family this function admits. Wired here (not at the
	// HandleRedispatch / handleRegistrationResponse callers) so every
	// reconcile call site contributes to MetricReconcileOverlap, including
	// the realistic HandleRedispatch ↔ direct-AAK overlap that an
	// out-of-band NHP_ARD landing during a register cycle produces.
	exitReconcile := r.recordReconcileEntry()
	defer exitReconcile()
	var unaddressedNew, unaddressedPrior int
	var anyEvicted bool // tracks whether any prior was actually RemovePeerByAddress'd; gates MetricNilNewServersReconcile
	activeKeys := make(map[string]struct{}, len(newServers))
	for _, srv := range newServers {
		if srv == nil {
			continue
		}
		k, sentinel := targetActiveKey(srv.Target)
		if sentinel {
			unaddressedNew++
		}
		activeKeys[k] = struct{}{}
	}
	for _, srv := range priorServers {
		if srv == nil {
			continue
		}
		// Single-load .Peer into a local. On the direct-AAK reconcile
		// path priorServers shares the same *AssignedServer pool a
		// still-running sibling HandleRedispatch.connectToServer may
		// be writing .Peer into (the failure path nils server.Peer).
		// A nil-check on srv.Peer followed by srv.Peer.PublicKey()
		// would crash on a sibling write of nil between check and
		// dereference. Snapshot the pointer here so the rest of the
		// loop body is consistent regardless of concurrent writes.
		// Structural fix is field-level locking on AssignedServer.Peer
		// via #1715 / #1670; this local-load is the minimum defense
		// for the immediate nil-deref hazard (cr round-31 #3).
		peer := srv.Peer
		if peer == nil {
			continue
		}
		// unaddressedPrior counts only priors that survived the
		// nil-Peer guard above — which is intentional. A prior with
		// .Peer == nil is one this reconcile would skip anyway (no
		// peer-pool work to do), so its sentinel observation isn't
		// telemetry-relevant. Keeps the metric tied to "broken target
		// on a prior we'd touch," not "broken target in any
		// AssignedServer slot."
		k, sentinel := targetActiveKey(srv.Target)
		if sentinel {
			unaddressedPrior++
		}
		if _, active := activeKeys[k]; active {
			continue
		}
		// Defense against core.Device.RemovePeerByAddress's single-peer
		// (non-PeerGroup) branch ignoring addr: if the device's current
		// entry for this pubkey is a *UdpPeer that is NOT the one we
		// captured at snapshot time, a concurrent AddPeer landed in the
		// snapshot-to-reconcile window — wholesale deleting peerMap[K]
		// would wipe that sibling's fresh peer (the original incident's
		// bug class in miniature, but reachable without two overlapping
		// reconciles). Skip the device call in that case.
		//
		// Single-peer branch only. PeerGroup entries pass through (the
		// type assertion fails, so the !ok arm of the if leaves us
		// proceeding to RemoveMember). RemoveMember matches by address,
		// so under shared-pubkey ASGs (the original incident's shape)
		// what saves us is invariant 1 — set difference — not this
		// defense. Single-peer is protected by invariant 1 + this
		// LookupPeer check; PeerGroup is protected by invariant 1 alone
		// in the same-redispatch case. The cross-redispatch case
		// (sibling AddPeer between this enumeration and its
		// RemovePeerByAddress) is genuinely undefended on the PeerGroup
		// branch — invariant 1 only saves you when the sibling's
		// address is in YOUR newServers activeKeys, which it isn't in
		// cross-redispatch. That residual is part of the overlap family
		// surfaced by MetricReconcileOverlap; the symmetric
		// PeerGroup-side LookupMember-style defense is tracked in #1711.
		//
		// TOCTOU residual on the single-peer branch too: LookupPeer
		// releases peerMapMutex before RemovePeerByAddress re-acquires
		// it. A sibling AddPeer landing in that gap can swap peerMap[K]
		// to a fresh peer between our identity check and our remove —
		// and we then evict the fresh peer. The defense closes the
		// "swap already happened before we checked" case but not the
		// "swap happens between check and remove" case. Same overlap
		// family, surfaced by MetricReconcileOverlap; #1682 closes both
		// cases by making the remove tuple-keyed and atomic.
		current := r.ac.device.LookupPeer(peer.PublicKey())
		if current == nil {
			continue
		}
		if udp, ok := current.(*core.UdpPeer); ok && udp != peer {
			log.Debug("Skipping device cleanup for retired server %s: pubkey now references a different peer", srv.Target.Address())
			continue
		}
		r.ac.device.RemovePeerByAddress(peer.PublicKeyBase64(), peer.Host())
		log.Info("Removed device peer for retired server %s", srv.Target.Address())
		anyEvicted = true
	}
	// Emit one log + one metric event per reconcile pass that observed any
	// unaddressed-sentinel target. Aggregating here keeps the signal loud on
	// regression (every reconcile after a Validate break logs once) without
	// scaling log volume by target count or reconcile rate. The prior/new
	// split in the log line lets a 3am operator distinguish "Validate
	// regression in NHP_ARD parsing path" (unaddressedNew > 0) from
	// "leftover broken target in r.assignedServers" (unaddressedPrior > 0).
	unaddressedHits := unaddressedNew + unaddressedPrior
	if unaddressedHits > 0 {
		log.Warning("targetActiveKey fallback to <unaddressed> sentinel: %d total (prior=%d new=%d) in this reconcile pass — RedirectTarget.Validate (#832) regressed?", unaddressedHits, unaddressedPrior, unaddressedNew)
		r.metrics.AddCounterWithDims(MetricUnaddressedTarget, float64(unaddressedHits), []types.Dimension{r.acIdDimension()})
	}

	// MetricNilNewServersReconcile fires when the all-fail eviction
	// branch (HandleRedispatch's successCount == 0 path) actually evicts
	// at least one prior. Detected here, not at the call site, so the
	// race-clean post-snapshot .Peer values are used and the duplicate
	// scan in the caller is eliminated (cr round-38 #3). Branch-entry
	// signal: one event per all-fail reconcile that did real eviction
	// work, regardless of how many priors were evicted.
	if newServers == nil && anyEvicted {
		r.metrics.IncrCounterWithDims(MetricNilNewServersReconcile, []types.Dimension{r.acIdDimension()})
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

// classifyResponseError returns the MetricRegistrationFailure ErrorCode
// dimension for an error surfaced after the response was received in
// register's receive case, or "" if the error doesn't have a known
// post-response attribution at this site (today, only ErrRegistrationStopped).
// Extracted so the dispatch logic is unit-testable without a counter
// reader on metrics.Publisher (see #1672).
//
// Dimension semantics: the "stopped" code (this function) fires when
// ErrRegistrationStopped surfaces after a response was received. The
// pre-existing "canceled" code (in register's select on r.stopCh) fires
// when r.stopCh closes BEFORE a response arrives. Both are teardown-
// bounded drops with the same operational consequence (AC is tearing
// down); they distinguish only when in the AOL→AAK/ARD round-trip the
// teardown landed. Dashboards keying on either should treat them as
// the same alerting class.
func classifyResponseError(err error) string {
	if errors.Is(err, ErrRegistrationStopped) {
		return "stopped"
	}
	return ""
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
		ReasonRefreshPeerChange,
		ReasonServerConnectionTimeout,
		ReasonConnectionTimeout,
		ReasonAllServersUnconnected,
		ReasonPeriodicNLBRefresh:
		return reason
	default:
		return "other"
	}
}
