package ac

import (
	"crypto/sha256"
	"encoding/base64"
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
	// Set to every KeepaliveInterval (10 seconds). A successful authenticated
	// AAK is the control-lease heartbeat; KPL never renews this lease.
	RegistrationRefreshInterval = 1

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

	// Phase 0D (qurl-service#976): all-unconnected episode DURATIONS, so the
	// ~30s outage (link (c)) is measurable, not just counted.
	// MetricAllUnconnectedDurationMs is the first-detected -> threshold-tripped
	// span (detector latency); MetricAllUnconnectedRecoveryMs is the
	// first-detected -> episode-closed span — a time-to-remediation gauge closed
	// by whichever fires first: an observed reconnect (a healthy keepalive tick)
	// OR a successful NLB re-registration (the remediation itself). Read it as
	// MTTR, not strictly "viewer traffic flowing again", and as a LOWER BOUND on
	// the viewer-facing outage: re-registration success closes the episode a beat
	// before the actual UDP re-establishment the next tick would confirm, so a
	// re-reg-won episode stops the clock early. If servers are still down
	// checkAllUnconnected opens a fresh episode. Because a
	// still-down fleet reopens a fresh episode, one real outage can emit several
	// RecoveryMs samples — so a dashboard/alarm must read it as a percentile
	// (p50/p90), never a sum or count, or a flapping outage looks like many short
	// recoveries (dashboard guidance tracked in #3001).
	MetricAllUnconnectedDurationMs = "AllUnconnectedDurationMs"
	MetricAllUnconnectedRecoveryMs = "AllUnconnectedRecoveryMs"

	// MetricReconcileOverlap is incremented if reconcileDevicePeers runs
	// concurrently. Production assignment transitions are serialized by
	// transitionMu, so a non-zero rate means a future or internal call site
	// bypassed that invariant. It emits N-1 events for N concurrent entrants.
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

	// MetricNilNewServersReconcile is incremented when HandleRedispatch's
	// all-fail (successCount == 0) branch actually evicts at least one prior
	// peer, either during the pre-connect authoritative prune or the final
	// nil-newServers cleanup. This is a per-AC branch signal for partial-outage
	// diagnosis, not a count of removed peers.
	//
	// reconcileDevicePeers returns whether its race-clean pass evicted a peer;
	// HandleRedispatch combines both passes and emits one increment per all-fail
	// redispatch that did real work, regardless of how many priors were evicted.
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
	//   - ConntrackSkipped — keys no-op'd by the iptables-mode
	//                        ConntrackFlusher before backend work
	MetricL3FlushEntries        = "L3FlushEntries"
	MetricL3FlushFlushTotal     = "L3FlushTotal"
	MetricL3FlushFlushErr       = "L3FlushErr"
	MetricL3FlushFlushDryRun    = "L3FlushDryRun"
	MetricL3FlushDeferred       = "L3FlushDeferred"
	MetricL3FlushDropped        = "L3FlushDropped"
	MetricL3FlushBucketMaxDepth = "L3FlushBucketMaxDepth"
	MetricL3FlushBreakerOpen    = "L3FlushBreakerOpen"
	MetricL3FlushBpfSkipped     = "L3FlushBpfSkipped"
	// MetricL3FlushConntrackSkipped is the ConntrackFlusher's skip counter:
	// exec backend non-IPv4 expiry skips, plus netlink backend mixed-family
	// FlowKey regressions. 0/absent outside iptables-mode L3 flush.
	MetricL3FlushConntrackSkipped = "L3FlushConntrackSkipped"
	// MetricL3FlushConntrackDeleted is the cumulative count of conntrack
	// entries the netlink ConntrackFlusher backend (#2165) has deleted.
	// Published only when that backend is active (iptables mode + netlink);
	// its rate over the soak confirms the netlink path is tearing flows
	// down and is readable against the throughput target. 0/absent on the
	// exec backend and EBPFXDP.
	MetricL3FlushConntrackDeleted = "L3FlushConntrackDeleted"
	// MetricL3FlushConntrackSlowDumps is the cumulative count of netlink
	// Flush calls whose successful conntrack dump attempt exceeded the
	// slow-dump threshold — now a fallback/backfill signal for the soak (a
	// rising steady-state rate means the event index is unhealthy, immediate
	// revocations are forcing authoritative dumps, or both).
	// Same backend gating as MetricL3FlushConntrackDeleted.
	MetricL3FlushConntrackSlowDumps = "L3FlushConntrackSlowDumps"
	// MetricL3FlushConntrackDumpLatency is the per-Flush netlink conntrack dump
	// duration distribution, published as CloudWatch Values/Counts in
	// milliseconds so percentile gates can be read during the #2165/#2908 soak.
	// It includes fallback and authoritative Flush dumps, not indexed fast-path
	// Flushes or one-time startup/resync backfill dumps. Rollout sign-off must
	// judge backfill wall time separately. Only successful dump attempts produce
	// samples; dump errors and timeouts ride L3FlushFlushErr/breaker metrics.
	MetricL3FlushConntrackDumpLatency = "L3FlushConntrackDumpLatency"
	// MetricL3FlushConntrackDumpLatencyDropped counts dump-latency samples that
	// were dropped because the ConntrackFlusher's local histogram buffer filled
	// before the metrics publisher drained it. Nonzero means the corresponding
	// latency distribution is incomplete for that flush window.
	MetricL3FlushConntrackDumpLatencyDropped = "L3FlushConntrackDumpLatencyDropped"
	// MetricL3FlushConntrackDumpLatencyNegativeDurations counts impossible
	// negative dump-duration measurements ignored before histogram buffering.
	// Nonzero indicates a monotonic-clock or instrumentation anomaly.
	MetricL3FlushConntrackDumpLatencyNegativeDurations = "L3FlushConntrackDumpLatencyNegativeDurations"
	// MetricL3FlushConntrackIndexedFlushes is the cumulative count of netlink
	// Flush calls served from the conntrack event index (#2908), i.e. the
	// O(matches) path that avoids the per-Flush O(table) dump.
	MetricL3FlushConntrackIndexedFlushes = "L3FlushConntrackIndexedFlushes"
	// MetricL3FlushConntrackIndexFallbackDumps is the cumulative count of
	// netlink Flush calls that fell back to the O(table) dump path because the
	// event index was unavailable/unhealthy. Correctness is preserved, but any
	// nonzero rate means the #2908 hot path is not serving all scheduled-expiry
	// Flushes.
	MetricL3FlushConntrackIndexFallbackDumps = "L3FlushConntrackIndexFallbackDumps"
	// MetricL3FlushConntrackIndexAuthoritativeDumps is the cumulative count of
	// netlink Flush calls that intentionally bypassed the event index to use
	// fresh kernel ground truth for immediate revocation.
	MetricL3FlushConntrackIndexAuthoritativeDumps = "L3FlushConntrackIndexAuthoritativeDumps"
	// MetricL3FlushConntrackIndexEventErrors counts conntrack multicast stream
	// errors. Nonzero means the event index has been disabled and Flush is using
	// the safe dump fallback rather than risking a silent enforcement gap. It
	// also includes failed candidate generations so stream-loss during rebuild is
	// visible even when that candidate never served Flush.
	MetricL3FlushConntrackIndexEventErrors = "L3FlushConntrackIndexEventErrors"
	// MetricL3FlushConntrackIndexPendingOverflows counts startup backfill
	// pending-buffer overflows. Nonzero distinguishes startup replay pressure
	// from generic event stream errors during the #2908 soak.
	MetricL3FlushConntrackIndexPendingOverflows = "L3FlushConntrackIndexPendingOverflows"
	// MetricL3FlushConntrackIndexEvents is the cumulative count of valid-group
	// conntrack multicast events observed by the event index. The soak uses its
	// delta as a liveness signal: healthy and zero-error is not enough if no
	// events arrive.
	MetricL3FlushConntrackIndexEvents = "L3FlushConntrackIndexEvents"
	// MetricL3FlushConntrackIndexOrigins is the current number of full-origin
	// conntrack tuples mirrored in userspace by the event index. The soak uses it
	// to bound resident memory at target table cardinality. Interpret 0 only
	// alongside EventErrors/FallbackDumps: it may be a healthy empty table or a
	// disabled/reclaimed index.
	MetricL3FlushConntrackIndexOrigins = "L3FlushConntrackIndexOrigins"
	// MetricL3FlushConntrackIndexResyncAttempts is the cumulative number of
	// runtime event-index resync attempts after stream loss/skew. Startup
	// backfill is intentionally excluded.
	MetricL3FlushConntrackIndexResyncAttempts = "L3FlushConntrackIndexResyncAttempts"
	// MetricL3FlushConntrackIndexResyncSuccesses is the cumulative number of
	// runtime resyncs that installed a rebuilt subscription generation.
	MetricL3FlushConntrackIndexResyncSuccesses = "L3FlushConntrackIndexResyncSuccesses"
	// MetricL3FlushConntrackIndexResyncFailures is the cumulative number of
	// runtime resyncs that failed; while this rises, Flush remains on the safe
	// dump/filter/delete fallback.
	MetricL3FlushConntrackIndexResyncFailures = "L3FlushConntrackIndexResyncFailures"
	MetricL3FlushScheduleRejected             = "L3FlushScheduleRejected"
	MetricL3FlushScheduleAfterShutdown        = "L3FlushScheduleAfterShutdown"
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
	//     tracked FlowKeys were processed by the immediate-revoke path (v4 keys
	//     rescheduled to fire now; v6 keys torn down via the surgical-v6 seam or
	//     surfaced as MetricRevocationIPv6HardFail — the coarse reschedule is
	//     v4-only, #2778 part 2). Distinguishes "entry had scheduled L3 flows we
	//     acted on" from "entry had no scheduled flows" (e.g. scheduler disabled),
	//     which Flushed alone cannot. NOTE since #2778 part 2 this is a per-entry
	//     "processed by revoke" tick, NOT a "a flush fired now" count: a v6-only
	//     entry increments it even though nothing was rescheduled to fire now (its
	//     teardown is surgical-v6 or the hard-fail). So a dashboard must not read it
	//     as "live flows we forced down now" for v6 — that reading holds only for v4.
	//   - MetricRevocationRejected — incremented once per NHP_REV the AC handler
	//     (HandleUdpACRevocation, P4e) drops at validation BEFORE reaching
	//     ApplyRevocation: malformed body, an unsupported/AC-internal scope, an
	//     empty scope_key, or a negative epoch. NHP_REV is post-handshake
	//     authenticated (the sender is a known server peer), so a spike here is a
	//     producer bug or a malformed/forged event worth alarming on rather than
	//     leaving only in logs — distinct from the benign StaleDropped rate.
	//   - MetricRevocationSurgicalFlushed — incremented once per established
	//     IPv4 conntrack flow surgically torn down by FlushConn on the
	//     eBPF/XDP+IPv4 revocation path (P4e slice 5). This is the per-FLOW analog
	//     of the per-ENTRY EntriesFlushed: one revoked AccessEntry can have
	//     multiple live 5-tuples (one per source port / client behind a NAT), each
	//     killed individually so same-allow-tuple siblings survive. A zero count
	//     while EntriesFlushed is nonzero means the revoked entries had no live
	//     established flows (only quiet/new pinholes) — expected, not an error.
	//     IPv6 surgical teardown is counted separately on
	//     MetricRevocationSurgicalFlushedV6 (this counter is IPv4-only).
	//   - MetricRevocationSurgicalFlushedV6 — the IPv6 twin of
	//     MetricRevocationSurgicalFlushed (same per-flow semantics, same
	//     zero-while-EntriesFlushed-nonzero reading): incremented once per
	//     established conn_track_v6 flow surgically torn down by FlushConnV6 on
	//     the eBPF/XDP+IPv6 revocation path (E2 slice 5). Split by address family
	//     rather than folded into the v4 counter because the v6 datapath is the
	//     newly-activated path operators most need to watch during the E5
	//     FilterMode flip, and a shared counter would mask whether v6 surgical
	//     teardown is firing at all. Mirrors the per-family split already used by
	//     MetricRevocationIPv6HardFail.
	//   - MetricRevocationIPv6HardFail — incremented for an IPv6 flow a revoke
	//     could NOT immediately tear down. Under EBPFXDP, when the v6 conntrack
	//     seam is UNWIRED (a v4-only build / non-Linux) the surgical path can't
	//     address the flow (conn_track is IPv4-only, struct ipv4_ct_tuple; #2778);
	//     when the seam IS wired (#2837) v6 is torn down surgically and this does
	//     NOT tick. Under FilterMode_IPTABLES + BackendExec, `conntrack -D` is
	//     IPv4-only (no `-f ipv6`) and the surgical seam is EBPFXDP-only, so this
	//     ticks. Under FilterMode_IPTABLES + BackendNetlink (#2165), v6 is torn
	//     down by the coarse netlink path and this does NOT tick. In the
	//     unaddressable cases the v6 flow survives the revoke until kernel TTL —
	//     a DECLARED out-of-scope gap (see the gospel Filter-mode/IPv6 caveat +
	//     DE Risk #6).
	//
	//     GRANULARITY: ticked once per IPv6 FlowKey when the WHOLE key has no
	//     teardown path (the iptables branch, the eBPF v6-seam-unwired branch, or
	//     a v6 conntrack ENUMERATION error — none of which addresses any flow on
	//     the tuple), AND once per FLOW for a per-port FlushConnV6 that fails on a
	//     wired-but-pinned v6 map (enumeration succeeded but THAT 5-tuple's delete
	//     genuinely failed — symmetric to the per-flow MetricRevocationSurgicalFlushedV6
	//     success counter, since each failed delete is one real leaked flow). A
	//     single revoked entry with N live flows can therefore contribute up to N
	//     here if every per-flow delete fails. Both cases are real
	//     immediate-revocation gaps on the SAME metric by design.
	//
	//     flushEntryNow ticks this directly (eBPF via surgicalFlushFlowKey,
	//     iptables via its explicit FilterMode_IPTABLES branch) so the signal is
	//     revocation-specific and (since #2778 part 2) cleanly SPLIT from the benign
	//     per-flusher skip counters (BpfFlusherSkippedCount / ConntrackFlusher
	//     metricSkipped, which track scheduled-expiry v6 leaks and impossible
	//     mixed-family FlowKey regressions only). For this revocation metric,
	//     ANY nonzero reading is a real immediate-revocation gap worth alarming on. The split's
	//     full rationale — incl. the deferred-tick residual (#2901) — is in the
	//     flushEntryNow godoc / the QURL_V2_KEYED_IDENTITY.md Filter-mode/IPv6 caveat.
	//   - MetricRevocationWatermarks — current count of per-(scope,scope_key)
	//     epoch watermarks retained for stale/duplicate rejection. Expected to
	//     track distinct revoked keys over roughly the last
	//     revocationWatermarkTTL plus currently-live keys, not AC process
	//     lifetime. A monotonic climb without drops means the #2782 sweep is not
	//     running or every retained key is still live.
	//   - MetricRevocationWatermarksPruned — count of inactive epoch watermarks
	//     the #2782 sweep reclaimed after the retention TTL. This is capacity
	//     hygiene only; it is not a revocation-delivery signal.
	MetricRevocationStaleDropped      = "RevocationStaleDropped"
	MetricRevocationEntriesFlushed    = "RevocationEntriesFlushed"
	MetricRevocationFlushScheduled    = "RevocationFlushScheduled"
	MetricRevocationRejected          = "RevocationRejected"
	MetricRevocationSurgicalFlushed   = "RevocationSurgicalFlushed"
	MetricRevocationSurgicalFlushedV6 = "RevocationSurgicalFlushedV6"
	MetricRevocationIPv6HardFail      = "RevocationIPv6HardFail"
	MetricRevocationWatermarks        = "RevocationWatermarks"
	MetricRevocationWatermarksPruned  = "RevocationWatermarksPruned"
	// MetricRevocationAckSent counts NHP_RVA acks the AC enqueued to the server
	// after processing a validated NHP_REV (proof-of-delivery, P4e Slice 3
	// #2793). One per validated NHP_REV regardless of flush count (the ack is a
	// convergence claim, not a work-done claim — see common.ACRevocationAckMsg).
	// A reject path does NOT send an ack, so this counter trails
	// MetricRevocationRejected: (received - rejected) ≈ acks sent. A sustained
	// gap below that line means acks are failing to enqueue (a degraded
	// AC→server path), which the server side surfaces as un-acked → aged-out.
	MetricRevocationAckSent = "RevocationAckSent"
	// MetricRevocationAckSendFailed counts NHP_RVA acks that could not be
	// enqueued to the server (no usable connection on the inbound NHP_REV, or
	// the AC is shutting down). A nonzero value means the AC applied/converged
	// the revoke but could not prove it to the server, so the server will retry
	// the NHP_REV until it acks or ages out — not a silent loss, but a signal
	// the AC→server return path is impaired.
	MetricRevocationAckSendFailed = "RevocationAckSendFailed"

	// MetricEbpfMapFull counts allow-rule eBPF map inserts that failed because
	// the map is at max_entries (kernel -E2BIG). This is the FAIL-CLOSED signal
	// for the eBPF FilterMode: rather than silently evicting an already-admitted
	// session (the LRU_HASH bug fixed in #2163), the AC rejects the NEW
	// admission and bumps this counter. A non-zero rate means the eBPF capacity
	// ceiling has been hit and admissions are being denied. The Terraform alarm
	// is deliberately allow-rule-specific; established-flow conntrack cache
	// saturation uses the EbpfConntrack* gauges below. Inert under
	// FilterMode_IPTABLES (the maps are never loaded), so it cannot fire until
	// the eBPF FilterMode flip.
	MetricEbpfMapFull = "EbpfMapFull"

	// MetricEbpfPerfLostSamples counts perf-buffer samples the kernel dropped
	// before the AC reader could drain them. This should stay flat after #2849's
	// malformed-DENY limiter; any non-zero period means filter-decision telemetry
	// was lost and the E5 FilterMode flip is no longer observably complete.
	MetricEbpfPerfLostSamples = "EbpfPerfLostSamples"

	// MetricEbpfDenyTelemetrySuppressed counts malformed/early-drop DENY events
	// intentionally shed by the #2849 token bucket. A non-zero rate means the
	// limiter is protecting the perf ring under malformed-packet pressure; it is
	// expected during an attack/canary and should be flat under normal load.
	MetricEbpfDenyTelemetrySuppressed = "EbpfDenyTelemetrySuppressed"

	// eBPF established-flow conntrack and IPv6 fragment-state telemetry.
	// Entries/max/usage/age values are gauges produced by
	// BpfFlusher.ConntrackStats when EBPFXDP is wired; the gauge funcs are not
	// registered in iptables mode, avoiding inert pre-flip custom metrics.
	// ExpiredReaped values are emitted as reset-per-flush counters from the same
	// stats snapshot. The split is intentional because allow rules, conntrack,
	// and fragment state have independent max_entries ceilings and E5 needs to
	// distinguish allow-rule admission saturation (MetricEbpfMapFull) from cache
	// or later-fragment-state saturation.
	MetricEbpfConntrackV4Entries          = "EbpfConntrackV4Entries"
	MetricEbpfConntrackV4MaxEntries       = "EbpfConntrackV4MaxEntries"
	MetricEbpfConntrackV4UsagePercent     = "EbpfConntrackV4UsagePercent"
	MetricEbpfConntrackV4OldestAgeSeconds = "EbpfConntrackV4OldestAgeSeconds"
	MetricEbpfConntrackV4ExpiredReaped    = "EbpfConntrackV4ExpiredReaped"
	MetricEbpfConntrackV6Entries          = "EbpfConntrackV6Entries"
	MetricEbpfConntrackV6MaxEntries       = "EbpfConntrackV6MaxEntries"
	MetricEbpfConntrackV6UsagePercent     = "EbpfConntrackV6UsagePercent"
	MetricEbpfConntrackV6OldestAgeSeconds = "EbpfConntrackV6OldestAgeSeconds"
	MetricEbpfConntrackV6ExpiredReaped    = "EbpfConntrackV6ExpiredReaped"
	MetricEbpfFragStateV6Entries          = "EbpfFragStateV6Entries"
	MetricEbpfFragStateV6MaxEntries       = "EbpfFragStateV6MaxEntries"
	MetricEbpfFragStateV6UsagePercent     = "EbpfFragStateV6UsagePercent"
	MetricEbpfFragStateV6ExpiredReaped    = "EbpfFragStateV6ExpiredReaped"
	// MetricEbpfSppExpiredReaped counts expired entries the lifecycle reaper
	// deletes from the shared `spp` allow-rule map — the GC bound on tc-egress
	// datapath-written return-path pinholes (spp is HASH since #2163, no LRU).
	// MetricEbpfSppReapPartialSamples / MetricEbpfSppReapErrors are the sweep's own
	// health signals (HASH walk aborted under churn / reap failed), kept separate
	// from the conntrack ones; sustained SppReapPartialSamples means the fill
	// defense isn't engaging under the churn it defends against.
	MetricEbpfSppExpiredReaped      = "EbpfSppExpiredReaped"
	MetricEbpfSppReapPartialSamples = "EbpfSppReapPartialSamples"
	MetricEbpfSppReapErrors         = "EbpfSppReapErrors"
	// MetricEbpfSpp{Entries,MaxEntries,UsagePercent} are the point-in-time `spp`
	// allow-rule occupancy gauges — the direct burst-fill signal for the prod
	// EBPFXDP flip (occupancy → max_entries → -E2BIG on new admissions), which the
	// reaper's reset-per-flush counters can't show because a within-TTL burst fills
	// faster than entries become reap-eligible.
	MetricEbpfSppEntries             = "EbpfSppEntries"
	MetricEbpfSppMaxEntries          = "EbpfSppMaxEntries"
	MetricEbpfSppUsagePercent        = "EbpfSppUsagePercent"
	MetricEbpfConntrackSampleSeconds = "EbpfConntrackSampleSeconds"

	// MetricEbpfConntrackSampleErrors counts stats/reaper sample failures per
	// publisher interval. It intentionally uses reset-per-flush counter
	// semantics, not a cumulative gauge, so the alarm self-recovers after the
	// pinned-map problem clears.
	MetricEbpfConntrackSampleErrors = "EbpfConntrackSampleErrors"

	// MetricEbpfConntrackPartialSamples counts conntrack and IPv6 fragment-state
	// HASH map iterations that were aborted by concurrent map churn before a
	// complete pass. It is a reset-per-flush counter because the occupancy gauges
	// from that sample may undercount and the quiet reaper skips deletes from
	// incomplete walks.
	MetricEbpfConntrackPartialSamples = "EbpfConntrackPartialSamples"
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
// of recordRegistrationBreakdown. Lifecycle cancellation is suppressed before
// this helper is called; every failure that reaches it is operational and
// alarmable (see recordServerConnectionFailure).
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
// Unlike registration there is no drop stream: handleRedispatchLocked excludes
// ErrRegistrationStopped and post-fence results before calling this helper, and
// every remaining connectToServer failure is alarmable. The
// Sum>10-over-2-periods threshold is meant to ride out bounded operational
// failures during an AC instance refresh.
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
	// transitionMu serializes authoritative assignment transitions across the
	// assignedServers swap, peer-pool reconciliation, network connects, and
	// final cleanup. It is acquired before mu when both are needed; mu is never
	// held across network waits.
	transitionMu sync.Mutex
	stopCh       chan struct{}
	wg           sync.WaitGroup

	// pendingRegistrationPeer is the temporary NLB peer for an in-flight AOL.
	// Protected by mu. Authoritative reconciles retain it until response,
	// timeout, or cancellation cleanup clears it under transitionMu.
	pendingRegistrationPeer *core.UdpPeer

	// assignmentPeers tracks dynamic peers installed by this registration
	// manager, keyed by public key and address. Pointer identity distinguishes
	// them from static/config peers sharing the same key and address.
	assignmentPeersMu sync.Mutex
	assignmentPeers   map[string]*core.UdpPeer

	// afterRedispatchTransitionLock is a deterministic test seam. Production
	// construction leaves it nil.
	afterRedispatchTransitionLock func()
	// afterRegistrationTransitionLock is the corresponding response-handler
	// test seam. Production construction leaves it nil.
	afterRegistrationTransitionLock func()

	// reregistering prevents concurrent re-registration attempts
	reregistering atomic.Bool

	// reconcileInFlight detects any future reconcile call that bypasses the
	// authoritative transition serialization invariant.
	reconcileInFlight atomic.Int32

	// stopped prevents double Stop() calls from panicking (closing stopCh twice)
	stopped atomic.Bool

	// controlLeaseExpired coalesces one fail-closed session flush per episode
	// where every authenticated server control is outside the 30-second lease.
	controlLeaseExpired atomic.Bool

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

	// cachedAOLBytes is retained for construction-time validation and bare unit
	// fixtures. Production sends call currentAOLBytes so a control-gap flush
	// generation change is reflected on the very next authenticated AOL.
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

	// allUnconnectedSinceNano timestamps the first tick of the CURRENT
	// all-unconnected EPISODE (0 = not currently all-unconnected), so the outage
	// can be measured as a DURATION, not just counted (Phase 0D, qurl-service#976
	// link (c) — the fixed ~30s MTTR). Set once per episode (CAS 0->now),
	// emitted+cleared on reconnect. Spans repeated threshold trips within one
	// outage -> RecoveryMs.
	allUnconnectedSinceNano atomic.Int64

	// allUnconnectedWindowStartNano timestamps the start of the current
	// threshold WINDOW (reset every tick-counter 0->1), distinct from the
	// episode start above. DurationMs (detector-trip latency) is measured from
	// this, so a re-trip during a sustained outage reports the window latency,
	// not an ever-growing episode age.
	allUnconnectedWindowStartNano atomic.Int64

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

func (r *ACRegistration) decodeCurrentSessionControlAAK(ppd *core.PacketParserData) (common.ServerACAckMsg, error) {
	var aak common.ServerACAckMsg
	if ppd == nil {
		return aak, errors.New("nil NHP_AAK response")
	}
	if err := common.DecodeServerACAckMsg(ppd.BodyMessage, &aak); err != nil {
		return aak, err
	}
	if common.IsSuccessErrCode(aak.ErrCode) {
		if r == nil || r.ac == nil || !common.ValidNHPACBootID(r.ac.bootID) ||
			aak.BootID != r.ac.bootID || aak.SessionFlushGeneration != r.ac.sessionFlushGeneration.Load() ||
			ppd.SenderTrxId == 0 || aak.AOLTransactionID != ppd.SenderTrxId {
			return aak, errors.New("NHP_AAK does not bind the current AC boot, flush generation, and AOL transaction")
		}
	}
	return aak, nil
}

func (r *ACRegistration) acceptCurrentSessionControlAAK(aak *common.ServerACAckMsg) {
	if r == nil || r.ac == nil || aak == nil {
		return
	}
	r.ac.sessionControlFlushMu.Lock()
	defer r.ac.sessionControlFlushMu.Unlock()
	if !common.IsSuccessErrCode(aak.ErrCode) || !aak.Registered || !r.ac.sessionFlushComplete.Load() ||
		aak.BootID != r.ac.bootID || aak.SessionFlushGeneration != r.ac.sessionFlushGeneration.Load() {
		return
	}
	r.ac.sessionControlLeaseHeld.Store(true)
	r.controlLeaseExpired.Store(false)
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
		ACId:                   ac.config.ACId,
		AuthServiceId:          ac.config.AuthServiceId,
		ResourceIds:            ac.config.ResourceIds,
		LicenseKey:             ac.config.LicenseKey,
		ACVersion:              ac.config.ACVersion,
		BootID:                 ac.bootID,
		SessionFlushGeneration: ac.sessionFlushGeneration.Load(),
		SessionFlushComplete:   ac.sessionFlushComplete.Load(),
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
		assignmentPeers:           make(map[string]*core.UdpPeer),
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

func (r *ACRegistration) currentAOLBytes() ([]byte, error) {
	if r == nil || r.ac == nil || r.ac.config == nil {
		return nil, errors.New("AC registration is not initialized")
	}
	msg := &common.ACOnlineMsg{
		ACId:                   r.ac.config.ACId,
		AuthServiceId:          r.ac.config.AuthServiceId,
		ResourceIds:            r.ac.config.ResourceIds,
		LicenseKey:             r.ac.config.LicenseKey,
		ACVersion:              r.ac.config.ACVersion,
		BootID:                 r.ac.bootID,
		SessionFlushGeneration: r.ac.sessionFlushGeneration.Load(),
		SessionFlushComplete:   r.ac.sessionFlushComplete.Load(),
	}
	if msg.BootID != "" && (!common.ValidNHPACBootID(msg.BootID) ||
		msg.SessionFlushGeneration == 0 || !msg.SessionFlushComplete) {
		return nil, errors.New("AC session-control state is not ready for registration")
	}
	return json.Marshal(msg)
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
	r.metrics.RegisterGaugeFunc(MetricL3FlushConntrackSkipped, r.l3FlushConntrackSkippedGauge)
	r.metrics.RegisterGaugeFunc(MetricL3FlushConntrackDeleted, r.l3FlushConntrackDeletedGauge)
	r.metrics.RegisterGaugeFunc(MetricL3FlushConntrackSlowDumps, r.l3FlushConntrackSlowDumpsGauge)
	// This drain also emits L3FlushConntrackDumpLatencyDropped, so the
	// histogram samples and local drop counter stay tied to one buffer drain.
	r.metrics.RegisterHistogramFunc(MetricL3FlushConntrackDumpLatency, types.StandardUnitMilliseconds, r.l3FlushConntrackDumpLatencyHistogram)
	r.metrics.RegisterGaugeFunc(MetricL3FlushConntrackDumpLatencyNegativeDurations, r.l3FlushConntrackDumpLatencyNegativeDurationsGauge)
	r.metrics.RegisterGaugeFunc(MetricL3FlushConntrackIndexedFlushes, r.l3FlushConntrackIndexedFlushesGauge)
	r.metrics.RegisterGaugeFunc(MetricL3FlushConntrackIndexFallbackDumps, r.l3FlushConntrackIndexFallbackDumpsGauge)
	r.metrics.RegisterGaugeFunc(MetricL3FlushConntrackIndexAuthoritativeDumps, r.l3FlushConntrackIndexAuthoritativeDumpsGauge)
	r.metrics.RegisterGaugeFunc(MetricL3FlushConntrackIndexEventErrors, r.l3FlushConntrackIndexEventErrorsGauge)
	r.metrics.RegisterGaugeFunc(MetricL3FlushConntrackIndexPendingOverflows, r.l3FlushConntrackIndexPendingOverflowsGauge)
	r.metrics.RegisterGaugeFunc(MetricL3FlushConntrackIndexEvents, r.l3FlushConntrackIndexEventsGauge)
	r.metrics.RegisterGaugeFunc(MetricL3FlushConntrackIndexOrigins, r.l3FlushConntrackIndexOriginsGauge)
	r.metrics.RegisterGaugeFunc(MetricL3FlushConntrackIndexResyncAttempts, r.l3FlushConntrackIndexResyncAttemptsGauge)
	r.metrics.RegisterGaugeFunc(MetricL3FlushConntrackIndexResyncSuccesses, r.l3FlushConntrackIndexResyncSuccessesGauge)
	r.metrics.RegisterGaugeFunc(MetricL3FlushConntrackIndexResyncFailures, r.l3FlushConntrackIndexResyncFailuresGauge)
	r.metrics.RegisterGaugeFunc(MetricL3FlushScheduleRejected, r.l3FlushScheduleRejectedGauge)
	r.metrics.RegisterGaugeFunc(MetricL3FlushScheduleAfterShutdown, r.l3FlushScheduleAfterShutdownGauge)
	r.metrics.RegisterGaugeFunc(MetricL3FlushScheduleWaitTimeout, r.l3FlushScheduleWaitTimeoutGauge)
	r.metrics.RegisterGaugeFunc(MetricRevocationWatermarks, r.revocationWatermarksGauge)

	r.registerConntrackGaugeFuncs()

	// Add to wait group BEFORE starting goroutines to prevent race with Stop()
	r.wg.Add(1)
	go r.registrationLoop()

	return nil
}

func (r *ACRegistration) registerConntrackGaugeFuncs() {
	// These conntrack gauges are registered only when the EBPFXDP BpfFlusher
	// stats reader is wired. Quiet-entry reaping is owned by BpfFlusher's
	// lifecycle sampler; gauge collection reads the cached snapshot and converts
	// unseen cumulative sample/partial/expired-reaped watermarks into
	// reset-per-flush counters. The publisher calls each GaugeFunc separately,
	// so these helpers may revisit the same cached snapshot in one collection
	// cycle; the delta watermarks are intentionally idempotent, and only the
	// first gauge read after a sampler advance emits each unseen counter delta.
	// If a sampler pass publishes mid-collection, occupancy gauges in the same
	// publisher flush can straddle two snapshots; this is eventually consistent
	// by design because the destructive map walk is no longer publisher-owned.
	// Before the sampler's async first pass publishes, the zero snapshot emits
	// zero occupancy/age instead of triggering any high-watermark signal.
	if r == nil || r.metrics == nil || r.ac == nil || r.ac.bpfConntrackStats == nil {
		return
	}
	r.metrics.RegisterGaugeFunc(MetricEbpfConntrackV4Entries, r.ebpfConntrackV4EntriesGauge)
	r.metrics.RegisterGaugeFunc(MetricEbpfConntrackV4MaxEntries, r.ebpfConntrackV4MaxEntriesGauge)
	r.metrics.RegisterGaugeFunc(MetricEbpfConntrackV4UsagePercent, r.ebpfConntrackV4UsagePercentGauge)
	r.metrics.RegisterGaugeFunc(MetricEbpfConntrackV4OldestAgeSeconds, r.ebpfConntrackV4OldestAgeSecondsGauge)
	r.metrics.RegisterGaugeFunc(MetricEbpfConntrackV6Entries, r.ebpfConntrackV6EntriesGauge)
	r.metrics.RegisterGaugeFunc(MetricEbpfConntrackV6MaxEntries, r.ebpfConntrackV6MaxEntriesGauge)
	r.metrics.RegisterGaugeFunc(MetricEbpfConntrackV6UsagePercent, r.ebpfConntrackV6UsagePercentGauge)
	r.metrics.RegisterGaugeFunc(MetricEbpfConntrackV6OldestAgeSeconds, r.ebpfConntrackV6OldestAgeSecondsGauge)
	r.metrics.RegisterGaugeFunc(MetricEbpfFragStateV6Entries, r.ebpfFragStateV6EntriesGauge)
	r.metrics.RegisterGaugeFunc(MetricEbpfFragStateV6MaxEntries, r.ebpfFragStateV6MaxEntriesGauge)
	r.metrics.RegisterGaugeFunc(MetricEbpfFragStateV6UsagePercent, r.ebpfFragStateV6UsagePercentGauge)
	r.metrics.RegisterGaugeFunc(MetricEbpfSppEntries, r.ebpfSppEntriesGauge)
	r.metrics.RegisterGaugeFunc(MetricEbpfSppMaxEntries, r.ebpfSppMaxEntriesGauge)
	r.metrics.RegisterGaugeFunc(MetricEbpfSppUsagePercent, r.ebpfSppUsagePercentGauge)
	r.metrics.RegisterGaugeFunc(MetricEbpfConntrackSampleSeconds, r.ebpfConntrackSampleSecondsGauge)
}

// Stop stops the registration manager. Safe to call multiple times,
// and safe to call without a prior Start — tests rely on this
// invariant to drive ACRegistration.stopped=true without spinning up
// the real registrationLoop. Adding a started.Load() precondition
// here would silently mask any regression fence keyed on it.
func (r *ACRegistration) Stop() {
	// Fence new work and close stopCh before waiting for transitionMu. An
	// authoritative redispatch holds transitionMu across its bounded network
	// waits; taking that mutex first would prevent Stop from closing stopCh and
	// therefore prevent those waits from being canceled promptly.
	if r.stopped.Swap(true) {
		return
	}
	close(r.stopCh)

	log.Info("Stopping AC registration manager")
	r.wg.Wait()

	// A pre-fence transition observes stopCh and unwinds; a post-fence transition
	// observes stopped before mutating state. Serialize final cleanup with both
	// cases after lifecycle goroutines have exited.
	r.transitionMu.Lock()
	defer r.transitionMu.Unlock()
	r.mu.Lock()
	// Clean up registration peer (from NHP_AAK response)
	if r.registrationPeer != nil {
		r.removeAssignmentPeer(r.registrationPeer)
		r.registrationPeer = nil
	}
	if r.pendingRegistrationPeer != nil {
		r.removeTransientPeer(r.pendingRegistrationPeer)
		r.pendingRegistrationPeer = nil
	}
	// Clean up connected server peers. HandleRedispatch reconciles the device
	// peer pool synchronously, so the live assignedServers slice is the
	// principal reference path at Stop() time.
	//
	for _, server := range r.assignedServers {
		if server.Peer != nil {
			r.removeAssignmentPeer(server.Peer)
			server.Peer = nil
		}
	}
	r.assignedServers = nil
	r.mu.Unlock()

	for _, peer := range r.assignmentPeersSnapshot() {
		r.removeAssignmentPeer(peer)
	}

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

// hasHealthyServer reports whether this AC currently has any recently
// confirmed assigned NHP server path. The public load balancer readiness
// endpoint uses this as the minimum datapath condition for serving knocked-in
// resource flows.
func (r *ACRegistration) hasHealthyServer() bool {
	if r == nil {
		return false
	}

	r.mu.RLock()
	defer r.mu.RUnlock()
	return healthyAssignedServerCount(r.assignedServers, 1) > 0
}

// healthyServerCount returns the number of assigned servers that are both
// connected and have responded within the keepalive health window
// (KeepaliveInterval * KeepaliveMaxRetries = 30s).
// Used as a GaugeFunc for the ServersHealthy CloudWatch metric.
func (r *ACRegistration) healthyServerCount() float64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return float64(healthyAssignedServerCount(r.assignedServers, 0))
}

// healthyAssignedServerCount counts healthy assigned servers. Callers must hold
// the registration lock that protects assignedServers. limit=0 counts all;
// limit>0 short-circuits once that many healthy servers have been found.
func healthyAssignedServerCount(servers []*AssignedServer, limit int) int {
	count := 0
	healthWindow := KeepaliveInterval * KeepaliveMaxRetries
	for _, s := range servers {
		if s.IsHealthy(healthWindow) {
			count++
			if limit > 0 && count >= limit {
				return count
			}
		}
	}
	return count
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

func (r *ACRegistration) revocationWatermarksGauge() float64 {
	if r.ac == nil || r.ac.revIndex == nil {
		return 0
	}
	return float64(r.ac.revIndex.watermarkCount())
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
// keys under EBPFXDP — see BpfFlusher.Flush godoc. This is the
// EXPIRY-skip signal only: since #2778 part 2 the revoke path's
// coarse reschedule is IPv4-only, so failed v6 revokes are surfaced
// on MetricRevocationIPv6HardFail, not here. Returns 0 when the
// feature is off or the flusher isn't a BpfFlusher.
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

// l3FlushConntrackSkippedGauge reads the iptables-mode ConntrackFlusher's
// skip counter. On exec this is the existing non-IPv4 expiry-skip signal; on
// netlink it also catches impossible mixed-family FlowKey regressions before
// the backend can pick an address family.
func (r *ACRegistration) l3FlushConntrackSkippedGauge() float64 {
	if r.ac == nil {
		return 0
	}
	count, ok := r.ac.ConntrackFlusherSkippedCount()
	if !ok {
		return 0
	}
	return float64(count)
}

// l3FlushConntrackDeletedGauge reads the netlink ConntrackFlusher's
// cumulative deleted-entries counter (#2165), when in iptables mode with
// the netlink backend attached. Returns 0 when the feature is off, the
// backend is exec, or the mode is EBPFXDP — so the published series is
// flat/0 except on an AC actually running the netlink datapath.
func (r *ACRegistration) l3FlushConntrackDeletedGauge() float64 {
	if r.ac == nil {
		return 0
	}
	count, ok := r.ac.ConntrackNetlinkDeletedCount()
	if !ok {
		return 0
	}
	// GaugeFuncs publish float64; this cumulative uint64 stays exactly
	// represented until 2^53, far beyond a single AC process's expected
	// lifetime conntrack-delete count.
	return float64(count)
}

// l3FlushConntrackSlowDumpsGauge reads the netlink ConntrackFlusher's
// slow-dump counter (#2165). Returns 0 unless the netlink datapath is the
// active backend (mirrors l3FlushConntrackDeletedGauge).
func (r *ACRegistration) l3FlushConntrackSlowDumpsGauge() float64 {
	if r.ac == nil {
		return 0
	}
	count, ok := r.ac.ConntrackNetlinkSlowDumpCount()
	if !ok {
		return 0
	}
	// Same float64 gauge boundary as l3FlushConntrackDeletedGauge; the
	// counter remains exact for any realistic AC-process lifetime.
	return float64(count)
}

// l3FlushConntrackDumpLatencyHistogram drains per-Flush netlink dump durations
// from the ConntrackFlusher. Values are milliseconds, so sub-millisecond soak
// gates remain visible in CloudWatch percentile queries. Values are rounded to
// the nearest microsecond and floored at 0.001ms, so use low percentiles as a
// positive-floor view rather than sub-microsecond ground truth. This drain may
// emit the local drop companion counter so both signals share one flush window
// when a metrics publisher is available.
func (r *ACRegistration) l3FlushConntrackDumpLatencyHistogram() []float64 {
	if r == nil || r.ac == nil {
		return nil
	}
	values, dropped, ok := r.ac.DrainConntrackNetlinkDumpLatenciesMillis()
	if !ok {
		return nil
	}
	if dropped > 0 {
		// Production registration wires this drain through a non-nil metrics
		// publisher. Direct tests or defensive calls without one still consume
		// drops so the flusher buffer remains bounded, but have no counter sink.
		if r.metrics != nil {
			// AddCounterWithDims is the public arbitrary-value counter API. This
			// is a per-drain delta tied to the histogram's best-effort flush
			// window; nil extra dims publishes with the shared counter dims.
			r.metrics.AddCounterWithDims(MetricL3FlushConntrackDumpLatencyDropped, float64(dropped), nil)
		}
	}
	return values
}

func (r *ACRegistration) l3FlushConntrackDumpLatencyNegativeDurationsGauge() float64 {
	if r == nil || r.ac == nil {
		return 0
	}
	count, ok := r.ac.ConntrackNetlinkDumpLatencyNegativeDurationCount()
	if !ok {
		return 0
	}
	return float64(count)
}

func (r *ACRegistration) l3FlushConntrackIndexedFlushesGauge() float64 {
	if r.ac == nil {
		return 0
	}
	count, ok := r.ac.ConntrackNetlinkIndexedFlushCount()
	if !ok {
		return 0
	}
	return float64(count)
}

func (r *ACRegistration) l3FlushConntrackIndexFallbackDumpsGauge() float64 {
	if r.ac == nil {
		return 0
	}
	count, ok := r.ac.ConntrackNetlinkIndexFallbackDumpCount()
	if !ok {
		return 0
	}
	return float64(count)
}

func (r *ACRegistration) l3FlushConntrackIndexAuthoritativeDumpsGauge() float64 {
	if r.ac == nil {
		return 0
	}
	count, ok := r.ac.ConntrackNetlinkIndexAuthoritativeDumpCount()
	if !ok {
		return 0
	}
	return float64(count)
}

func (r *ACRegistration) l3FlushConntrackIndexEventErrorsGauge() float64 {
	if r.ac == nil {
		return 0
	}
	count, ok := r.ac.ConntrackNetlinkIndexEventErrorCount()
	if !ok {
		return 0
	}
	return float64(count)
}

func (r *ACRegistration) l3FlushConntrackIndexPendingOverflowsGauge() float64 {
	if r.ac == nil {
		return 0
	}
	count, ok := r.ac.ConntrackNetlinkIndexPendingOverflowCount()
	if !ok {
		return 0
	}
	return float64(count)
}

func (r *ACRegistration) l3FlushConntrackIndexEventsGauge() float64 {
	if r.ac == nil {
		return 0
	}
	count, ok := r.ac.ConntrackNetlinkIndexEventCount()
	if !ok {
		return 0
	}
	return float64(count)
}

func (r *ACRegistration) l3FlushConntrackIndexOriginsGauge() float64 {
	if r.ac == nil {
		return 0
	}
	count, ok := r.ac.ConntrackNetlinkIndexOriginCount()
	if !ok {
		return 0
	}
	return float64(count)
}

func (r *ACRegistration) l3FlushConntrackIndexResyncAttemptsGauge() float64 {
	if r.ac == nil {
		return 0
	}
	count, ok := r.ac.ConntrackNetlinkIndexResyncAttemptCount()
	if !ok {
		return 0
	}
	return float64(count)
}

func (r *ACRegistration) l3FlushConntrackIndexResyncSuccessesGauge() float64 {
	if r.ac == nil {
		return 0
	}
	count, ok := r.ac.ConntrackNetlinkIndexResyncSuccessCount()
	if !ok {
		return 0
	}
	return float64(count)
}

func (r *ACRegistration) l3FlushConntrackIndexResyncFailuresGauge() float64 {
	if r.ac == nil {
		return 0
	}
	count, ok := r.ac.ConntrackNetlinkIndexResyncFailureCount()
	if !ok {
		return 0
	}
	return float64(count)
}

func (r *ACRegistration) ebpfConntrackStatsSnapshot() BpfConntrackStats {
	if r.ac == nil {
		return BpfConntrackStats{}
	}
	stats, ok := r.ac.BpfConntrackStats()
	if !ok {
		return BpfConntrackStats{}
	}
	return stats
}

func (r *ACRegistration) ebpfConntrackV4EntriesGauge() float64 {
	return float64(r.ebpfConntrackStatsSnapshot().V4Entries)
}
func (r *ACRegistration) ebpfConntrackV4MaxEntriesGauge() float64 {
	return float64(r.ebpfConntrackStatsSnapshot().V4MaxEntries)
}
func (r *ACRegistration) ebpfConntrackV4UsagePercentGauge() float64 {
	return r.ebpfConntrackStatsSnapshot().V4UsagePercent
}
func (r *ACRegistration) ebpfConntrackV4OldestAgeSecondsGauge() float64 {
	return r.ebpfConntrackStatsSnapshot().V4OldestAgeSeconds
}
func (r *ACRegistration) ebpfConntrackV6EntriesGauge() float64 {
	return float64(r.ebpfConntrackStatsSnapshot().V6Entries)
}
func (r *ACRegistration) ebpfConntrackV6MaxEntriesGauge() float64 {
	return float64(r.ebpfConntrackStatsSnapshot().V6MaxEntries)
}
func (r *ACRegistration) ebpfConntrackV6UsagePercentGauge() float64 {
	return r.ebpfConntrackStatsSnapshot().V6UsagePercent
}
func (r *ACRegistration) ebpfConntrackV6OldestAgeSecondsGauge() float64 {
	return r.ebpfConntrackStatsSnapshot().V6OldestAgeSeconds
}
func (r *ACRegistration) ebpfFragStateV6EntriesGauge() float64 {
	return float64(r.ebpfConntrackStatsSnapshot().V6FragEntries)
}
func (r *ACRegistration) ebpfFragStateV6MaxEntriesGauge() float64 {
	return float64(r.ebpfConntrackStatsSnapshot().V6FragMaxEntries)
}
func (r *ACRegistration) ebpfFragStateV6UsagePercentGauge() float64 {
	return r.ebpfConntrackStatsSnapshot().V6FragUsagePercent
}
func (r *ACRegistration) ebpfSppEntriesGauge() float64 {
	return float64(r.ebpfConntrackStatsSnapshot().SppEntries)
}
func (r *ACRegistration) ebpfSppMaxEntriesGauge() float64 {
	return float64(r.ebpfConntrackStatsSnapshot().SppMaxEntries)
}
func (r *ACRegistration) ebpfSppUsagePercentGauge() float64 {
	return r.ebpfConntrackStatsSnapshot().SppUsagePercent
}
func (r *ACRegistration) ebpfConntrackSampleSecondsGauge() float64 {
	return r.ebpfConntrackStatsSnapshot().SampleDurationSeconds
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

// DefaultServerPort is the UDP port the AC dials to register with its cell.
// Registration targets the cell's PUBLIC server NLB (`ServerEndpoint` is the
// NLB DNS name), so this is the client-edge port, not the port the server
// process binds. The NLB forwards to common.DefaultNHPPort on its targets.
const DefaultServerPort = common.DefaultNHPClientPort

// beginRegistrationAttempt installs and publishes the temporary NLB peer as
// one atomic assignment transition. A concurrent redispatch that follows sees
// pendingRegistrationPeer and protects it during the actual-group sweep.
func (r *ACRegistration) beginRegistrationAttempt(peer *core.UdpPeer) error {
	r.transitionMu.Lock()
	defer r.transitionMu.Unlock()
	if r.stopped.Load() {
		return ErrRegistrationStopped
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pendingRegistrationPeer != nil && r.pendingRegistrationPeer != peer {
		return errors.New("registration attempt already in flight")
	}
	r.pendingRegistrationPeer = peer
	// A prior rotating assignment may already have filled this key's bounded
	// PeerGroup. Drain stale members only when AddPeer would otherwise refuse the
	// pending NLB peer; normal cold-start membership is left unchanged until the
	// assignment response makes its authoritative set known.
	if group, ok := r.ac.device.LookupPeer(peer.PublicKey()).(*core.PeerGroup); ok && group.Len() >= core.MaxPeerGroupSize {
		r.reconcileDevicePeers(r.assignedServers, r.assignedServers, peer)
	}
	if !r.ac.device.TryAddPeer(peer) {
		r.pendingRegistrationPeer = nil
		return fmt.Errorf("registration peer group at capacity for %s", peer.Host())
	}
	return nil
}

// discardRegistrationAttempt removes a pending temporary peer on a local
// registration failure. If the attempt has already been superseded, leave the
// newer assignment untouched.
func (r *ACRegistration) discardRegistrationAttempt(peer *core.UdpPeer) {
	r.transitionMu.Lock()
	defer r.transitionMu.Unlock()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pendingRegistrationPeer != peer {
		return
	}
	r.removeTransientPeer(peer)
	r.pendingRegistrationPeer = nil
}

// clearRegistrationAttemptLocked clears the in-flight marker after its server
// response has been handled. The caller holds transitionMu.
func (r *ACRegistration) clearRegistrationAttemptLocked(peer *core.UdpPeer) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pendingRegistrationPeer == peer {
		r.pendingRegistrationPeer = nil
	}
}

// register performs initial registration via ServerEndpoint.
// It sends NHP_AOL to the ServerEndpoint and handles NHP_ARD (redispatch) or NHP_AAK response.
func (r *ACRegistration) register() error {
	// Validate config (ServerEndpoint already validated in Start())
	if r.ac.config.ServerPubKeyBase64 == "" {
		return errors.New("ServerPubKeyBase64 is required")
	}
	if r.stopped.Load() {
		return ErrRegistrationStopped
	}

	// Track attempt after validation so RegistrationAttempts == RegistrationSuccess + RegistrationFailure.
	r.metrics.IncrCounter(MetricRegistrationAttempts)
	startTime := time.Now()

	// Determine server port (default: the public NHP client edge port)
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

	aolBytes, err := r.currentAOLBytes()
	if err != nil {
		return err
	}

	// Add peer to device for encryption
	// The peer will be kept if NHP_AAK is received (this server is assigned to us)
	// The peer will be removed if NHP_ARD is received (we'll connect to different servers)
	if err := r.beginRegistrationAttempt(registrationPeer); err != nil {
		return err
	}

	// Create message data for sending
	// Use buffered channel (size 1) to prevent sender from blocking if we exit early
	udpAddr, ok := sendAddr.(*net.UDPAddr)
	if !ok {
		r.discardRegistrationAttempt(registrationPeer)
		return fmt.Errorf("unexpected address type %T for registration peer", sendAddr)
	}
	md := &core.MsgData{
		RemoteAddr:    udpAddr,
		HeaderType:    core.NHP_AOL,
		TransactionId: r.ac.device.NextCounterIndex(),
		Compress:      true,
		PeerPk:        registrationPeer.PublicKey(),
		Message:       aolBytes,
		ResponseMsgCh: make(chan *core.PacketParserData, 1),
	}

	// Send NHP_AOL
	if !r.ac.IsRunning() {
		r.discardRegistrationAttempt(registrationPeer)
		return errors.New("AC not running")
	}
	select {
	case <-r.stopCh:
		r.discardRegistrationAttempt(registrationPeer)
		r.recordRegistrationDrop(aws.String("canceled"))
		return ErrRegistrationStopped
	case r.ac.sendMsgCh <- md:
	}

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
		r.discardRegistrationAttempt(registrationPeer)
		// Statically-known lifecycle drop (AC shutting down) — breakdown only.
		r.recordRegistrationDrop(aws.String("canceled"))
		return ErrRegistrationStopped
	case <-regTimer.C:
		r.discardRegistrationAttempt(registrationPeer)
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
	r.transitionMu.Lock()
	defer r.transitionMu.Unlock()
	if r.afterRegistrationTransitionLock != nil {
		r.afterRegistrationTransitionLock()
	}
	defer r.clearRegistrationAttemptLocked(registrationPeer)
	if r.stopped.Load() {
		r.removeTransientPeer(registrationPeer)
		return ErrRegistrationStopped
	}
	return r.handleRegistrationResponseLocked(ppd, registrationPeer)
}

// handleRegistrationResponseLocked applies one authoritative registration
// response. The caller holds transitionMu.
func (r *ACRegistration) handleRegistrationResponseLocked(ppd *core.PacketParserData, registrationPeer *core.UdpPeer) error {
	if r.stopped.Load() {
		return ErrRegistrationStopped
	}
	if ppd.Error != nil {
		r.removeTransientPeer(registrationPeer)

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
		// The endpoint is not assigned. Retire the temporary peer even when the
		// response body is malformed; the wrapper clears its pending marker.
		r.removeTransientPeer(registrationPeer)
		var ardMsg common.ACRedispatchMsg
		if err := json.Unmarshal(ppd.BodyMessage, &ardMsg); err != nil {
			return fmt.Errorf("failed to parse NHP_ARD: %w", err)
		}

		log.Info("Received NHP_ARD with %d assigned servers", len(ardMsg.Targets))

		// Connect to all assigned servers. Demote post-stop errors to Debug
		// — bounded by in-flight count at Stop and not alert-worthy; the
		// returned error keeps registrationLoop in retry-mode where its
		// stopCh select will exit cleanly.
		if err := r.handleRedispatchLocked(&ardMsg, nil); err != nil {
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
		aakMsg, decodeErr := r.decodeCurrentSessionControlAAK(ppd)
		if decodeErr != nil {
			r.removeTransientPeer(registrationPeer)
			return fmt.Errorf("failed to parse NHP_AAK: %w", decodeErr)
		}

		if !common.IsSuccessErrCode(aakMsg.ErrCode) {
			r.removeTransientPeer(registrationPeer)

			// Send registration failure metric with server's error code (bounded cardinality).
			errCode := aakMsg.ErrCode
			if errCode == "" {
				errCode = "unknown"
			}
			r.recordRegistrationFailure(aws.String(errCode))

			return fmt.Errorf("registration rejected: %s - %s", aakMsg.ErrCode, aakMsg.ErrMsg)
		}

		if !aakMsg.Registered {
			r.removeTransientPeer(registrationPeer)

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
						r.removeTransientPeer(registrationPeer)
						registrationPeer.PubKeyBase64 = aakMsg.ServerPubKey
						// Best-effort offer; the authoritative reconcile and TryAddPeer gate
						// below revalidate capacity before publishing the assignment.
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
							// Best-effort offer; the authoritative reconcile and TryAddPeer gate
							// below revalidate capacity before publishing the assignment.
							r.ac.device.AddPeer(serverPeer)
							// Remove the old registration peer (connected to NLB)
							r.removeTransientPeer(registrationPeer)
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
			if r.registrationPeer != nil && r.registrationPeer != serverPeer {
				r.removeAssignmentPeer(r.registrationPeer)
			}
			// This peer is intentionally retained in Device even though it has
			// no assignedServers entry. Track its ownership so a later
			// same-key authoritative transition can discover and retire it.
			r.trackAssignmentPeer(serverPeer)
			r.registrationPeer = serverPeer
			r.mu.Unlock()
			log.Info("Received NHP_AAK: ACAddr=%s, Registered=%v (peer kept but no keepalive)", aakMsg.ACAddr, aakMsg.Registered)
			r.acceptCurrentSessionControlAAK(&aakMsg)

			// Send registration success metric
			r.recordRegistrationSuccess(dimValDirect)

			return nil
		}

		udpAddr, ok := sendAddr.(*net.UDPAddr)
		if !ok {
			r.removeTransientPeer(registrationPeer)
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
			// Protect the peer that is actually usable after processing ServerAddr.
			// It may be the direct serverPeer rather than the original NLB
			// registrationPeer, which was already exact-removed above.
			if err := r.handleRedispatchLocked(ardMsg, serverPeer); err != nil {
				// ErrRegistrationStopped means the manager is being torn
				// down — there is no "operational" state to preserve, so
				// don't record success. Mirror the NHP_ARD branch above
				// and propagate the error so registrationLoop's stopCh
				// select exits cleanly.
				if errors.Is(err, ErrRegistrationStopped) {
					r.removeAssignmentPeer(serverPeer)
					if serverPeer != registrationPeer {
						r.removeAssignmentPeer(registrationPeer)
					}
					log.Debug("AC stopping during NHP_AAK peer handling, %d peers: %v", len(aakMsg.Peers), err)
					return err
				}
				// Genuine connection failure — HandleRedispatch only errors
				// when zero connections succeeded. Re-add the viable response
				// peer in case a same-address failed attempt replaced it, then
				// publish and track that exact pointer for Stop and future
				// authoritative reconciliation.
				if !r.ac.device.TryAddPeer(serverPeer) {
					return fmt.Errorf("assigned peer connections failed and response peer group remained at capacity: %w", err)
				}
				r.mu.Lock()
				if r.registrationPeer != nil && r.registrationPeer != serverPeer {
					r.removeAssignmentPeer(r.registrationPeer)
				}
				r.trackAssignmentPeer(serverPeer)
				r.registrationPeer = serverPeer
				fallbackIP := serverPeer.Ip
				if fallbackIP == "" {
					fallbackIP = udpAddr.IP.String()
				}
				r.assignedServers = []*AssignedServer{{
					Target: common.RedirectTarget{
						IP:           fallbackIP,
						Hostname:     serverPeer.Hostname,
						Port:         udpAddr.Port,
						PubKeyBase64: serverPeer.PublicKeyBase64(),
					},
					Peer:      serverPeer,
					Connected: true,
					LastSeen:  time.Now(),
				}}
				r.mu.Unlock()
				log.Warning("Failed to connect to assigned peers (%v), keeping response peer %s", err, serverPeer.Host())
				r.recordRegistrationSuccess(dimValDirect)
				r.acceptCurrentSessionControlAAK(&aakMsg)
				return nil
			}

			// The embedded peer list is authoritative after success. Exact-pointer
			// removal retires only the response path; if connectToServer replaced
			// the same key/address with an assigned peer, that new pointer survives.
			r.removeAssignmentPeer(serverPeer)
			if serverPeer != registrationPeer {
				r.removeAssignmentPeer(registrationPeer)
			}

			r.recordRegistrationSuccess(dimValPeerRedispatch)
			r.acceptCurrentSessionControlAAK(&aakMsg)
			return nil
		}

		r.mu.Lock()
		// Clean up old registration peer if exists (re-registration case)
		if r.registrationPeer != nil && r.registrationPeer.PublicKeyBase64() != serverPeer.PublicKeyBase64() {
			r.removeAssignmentPeer(r.registrationPeer)
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

		// Hold r.mu across the bounded in-memory reconcile so Stop and readers
		// cannot observe a half-installed direct assignment. No network wait
		// occurs in this section.
		//
		// serverPeer was offered to the device pool earlier in this
		// response path, so reconcile sees any admitted post-add state and
		// only evicts addresses that genuinely retired between the prior
		// assignment and the new one.
		//
		// Direct-AAK is authoritative. transitionMu ensures any sibling
		// assignment response completes before this single-target replacement
		// starts, so transitions cannot partially overwrite one another.
		r.trackAssignmentPeer(serverPeer)
		r.reconcileDevicePeers(priorServers, newServers)
		// The direct peer was first offered before the authoritative set was
		// known. If stale shared-key members had already filled PeerGroup,
		// that admission was refused. Try again after reconcile drains stale
		// owned members; a group still filled by active/static peers cannot be
		// evicted safely, so fail instead of publishing an unreachable peer.
		if !r.ac.device.TryAddPeer(serverPeer) {
			r.assignedServers = nil
			if r.registrationPeer == serverPeer {
				r.registrationPeer = nil
			}
			r.untrackAssignmentPeer(serverPeer)
			r.mu.Unlock()
			return fmt.Errorf("direct assignment peer group remained at capacity for %s", serverPeer.Host())
		}
		r.mu.Unlock()

		log.Info("Set server as assignedServer for keepalive: %s:%d", udpAddr.IP.String(), udpAddr.Port)
		if serverPeer == registrationPeer {
			log.Info("Received NHP_AAK: ACAddr=%s, Registered=%v (using registration peer)", aakMsg.ACAddr, aakMsg.Registered)
		} else {
			log.Info("Received NHP_AAK: ACAddr=%s, Registered=%v, ServerAddr=%s (using direct connection)", aakMsg.ACAddr, aakMsg.Registered, aakMsg.ServerAddr)
		}

		// Send registration success metric
		r.recordRegistrationSuccess(dimValDirect)
		r.acceptCurrentSessionControlAAK(&aakMsg)

		return nil

	default:
		r.removeTransientPeer(registrationPeer)
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
// Returns ErrRegistrationStopped after Stop has established its atomic stop
// fence. A pre-fence transition observes stopCh and unwinds before Stop's final
// cleanup; a post-fence transition observes stopped after taking transitionMu
// and cannot repopulate assignment or device state.
func (r *ACRegistration) HandleRedispatch(ardMsg *common.ACRedispatchMsg) error {
	return r.handleRedispatch(ardMsg, nil)
}

// handleRedispatch optionally protects the response's registration peer while
// reconciling the assigned server set. handleRedispatchLocked also snapshots
// pendingRegistrationPeer, so ordinary out-of-band NHP_ARD calls cannot evict
// an NLB peer whose AOL response is still pending.
func (r *ACRegistration) handleRedispatch(ardMsg *common.ACRedispatchMsg, registrationPeer *core.UdpPeer) error {
	r.transitionMu.Lock()
	defer r.transitionMu.Unlock()
	if r.afterRedispatchTransitionLock != nil {
		r.afterRedispatchTransitionLock()
	}
	return r.handleRedispatchLocked(ardMsg, registrationPeer)
}

// handleRedispatchLocked applies one authoritative assignment while the caller
// holds transitionMu.
func (r *ACRegistration) handleRedispatchLocked(ardMsg *common.ACRedispatchMsg, registrationPeer *core.UdpPeer) error {
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
	// pool before the new connections are established. Each HandleRedispatch
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
	pendingRegistrationPeer := r.pendingRegistrationPeer
	r.mu.Unlock()

	// Retire peers that are absent from the new authoritative assignment before
	// adding its members. Shared-key server fleets use a bounded PeerGroup; if
	// stale members fill that group, AddPeer refuses the new live members and
	// their replies fail address validation. The active-set check preserves any
	// address that remains assigned, so this ordering frees only retired slots.
	preconnectEvicted := r.reconcileDevicePeers(
		priorServers,
		serversToConnect,
		registrationPeer,
		pendingRegistrationPeer,
	)

	// The new authoritative assignment supersedes any retained direct-AAK
	// response peer that is not the response path currently protected by this
	// transition. Clear it before network waits so an all-failed redispatch does
	// not leave a side reference to a peer the ownership sweep already retired.
	r.mu.Lock()
	if r.registrationPeer != nil && r.registrationPeer != registrationPeer {
		r.removeAssignmentPeer(r.registrationPeer)
		r.registrationPeer = nil
	}
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
				if errors.Is(err, ErrRegistrationStopped) || r.stopped.Load() {
					log.Debug("AC stopping during assigned-server connection to %s: %v", s.Target.Address(), err)
					return
				}
				log.Warning("Failed to connect to assigned server %s: %v", s.Target.Address(), err)

				// Track individual connection failures for alerting on partial connectivity.
				r.recordServerConnectionFailure(aws.String(classifyError(err)))
			} else {
				atomic.AddInt32(&successCount, 1)
			}
		}(server)
	}
	connectWg.Wait()
	// stopCh cancellation and a response can become ready together. Even if the
	// response branch won that select, do not publish connection or registration
	// success after Stop established the lifecycle fence; Stop performs the final
	// peer cleanup after this transition releases transitionMu.
	if r.stopped.Load() {
		return ErrRegistrationStopped
	}

	// Fail if no connections succeeded — AC would be unreachable.
	// Evict prior peers anyway: none of the new connects succeeded, so no
	// address overlap can save them, and r.assignedServers has already been
	// replaced with the failed new entries. By the time the next redispatch
	// runs, its priorServers snapshot loops over those failed entries,
	// skips them via srv.Peer == nil, and the genuinely-retired peers
	// would be orphaned in the device pool — unreachable from any code
	// path, not just skipped. Pass nil newServers so the active-set check
	// evicts the whole prior set; the ownership map provides the final sweep for
	// any dynamic peer that is no longer reachable through assignedServers.
	//
	// transitionMu keeps sibling authoritative responses outside this cleanup.
	// MetricNilNewServersReconcile records that the all-fail branch did work.
	if successCount == 0 {
		// nil newServers → activeKeys is empty → every prior is removal-
		// eligible. The active-set check trivially fails, the LookupPeer
		// defense still runs, and reconcile evicts the whole prior set.
		// Combine the race-clean results from the pre-connect prune and this
		// all-priors cleanup. Emit once when either pass did real work.
		allFailEvicted := r.reconcileDevicePeers(
			priorServers,
			nil,
			registrationPeer,
			pendingRegistrationPeer,
		)
		if preconnectEvicted || allFailEvicted {
			r.metrics.IncrCounterWithDims(MetricNilNewServersReconcile, []types.Dimension{r.acIdDimension()})
		}
		return errors.New("failed to connect to any assigned servers")
	}

	// Warn if partial failure (some but not all servers connected)
	if int(successCount) < len(serversToConnect) {
		log.Warning("Partial connection success: %d/%d assigned servers connected", successCount, len(serversToConnect))
	} else {
		log.Info("Successfully connected to all %d assigned servers", successCount)
	}

	// Send server connections metric
	r.metrics.AddCounterWithDims(MetricServerConnections, float64(successCount), []types.Dimension{
		{Name: dimNameConnectionType, Value: dimValRedispatch},
	})

	// Success also retires the response path protected by an embedded-peers AAK.
	// Its caller exact-removes the same pointer after this returns; this cleanup
	// handles the case where it was already retained in registrationPeer.
	r.mu.Lock()
	if r.registrationPeer != nil {
		r.removeAssignmentPeer(r.registrationPeer)
		r.registrationPeer = nil
	}
	r.mu.Unlock()

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
	if !r.addAssignmentPeer(peer) {
		return fmt.Errorf("peer group at capacity for assigned server %s", server.Target.Address())
	}
	server.Peer = peer

	aolBytes, err := r.currentAOLBytes()
	if err != nil {
		return err
	}
	// Send NHP_AOL to register with this server.
	// Use buffered channel (size 1) to prevent sender from blocking if we exit early
	udpAddr, ok := sendAddr.(*net.UDPAddr)
	if !ok {
		r.removeAssignmentPeer(peer)
		return fmt.Errorf("unexpected address type %T for server %s", sendAddr, server.Target.Address())
	}
	md := &core.MsgData{
		RemoteAddr:    udpAddr,
		HeaderType:    core.NHP_AOL,
		TransactionId: r.ac.device.NextCounterIndex(),
		Compress:      true,
		PeerPk:        peer.PublicKey(),
		Message:       aolBytes,
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
		r.removeAssignmentPeer(peer)
		server.Peer = nil
		return errors.New("AC not running")
	}
	select {
	case <-r.stopCh:
		r.removeAssignmentPeer(peer)
		server.Peer = nil
		return ErrRegistrationStopped
	case r.ac.sendMsgCh <- md:
	}

	// Wait for NHP_AAK response with timeout
	// Note: We don't close ResponseMsgCh here because the sender (in another goroutine)
	// may write to it after we exit. The buffered channel (size 1) prevents blocking,
	// and the channel will be garbage collected when no longer referenced.
	select {
	case <-r.stopCh:
		r.removeAssignmentPeer(peer)
		server.Peer = nil
		return ErrRegistrationStopped
	case <-time.After(ConnectionTimeout):
		r.removeAssignmentPeer(peer)
		server.Peer = nil
		return fmt.Errorf("connection to %s timed out", server.Target.Address())
	case ppd := <-md.ResponseMsgCh:
		if ppd.Error != nil {
			r.removeAssignmentPeer(peer)
			server.Peer = nil
			return fmt.Errorf("connection failed: %w", ppd.Error)
		}
		if ppd.HeaderType != core.NHP_AAK {
			r.removeAssignmentPeer(peer)
			server.Peer = nil
			return fmt.Errorf("unexpected response type: %s", core.HeaderTypeToString(ppd.HeaderType))
		}

		aakMsg, decodeErr := r.decodeCurrentSessionControlAAK(ppd)
		if decodeErr != nil {
			r.removeAssignmentPeer(peer)
			server.Peer = nil
			return fmt.Errorf("failed to parse NHP_AAK: %w", decodeErr)
		}

		if !common.IsSuccessErrCode(aakMsg.ErrCode) {
			r.removeAssignmentPeer(peer)
			server.Peer = nil
			return fmt.Errorf("server rejected: %s - %s", aakMsg.ErrCode, aakMsg.ErrMsg)
		}

		server.SetConnected(true)
		server.UpdateLastSeen()
		r.acceptCurrentSessionControlAAK(&aakMsg)
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
			// tickCount is incremented before the check, so with the current
			// interval the first authenticated refresh happens after 10 seconds.
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
	aolBytes, err := r.currentAOLBytes()
	if err != nil {
		log.Warning("Cannot refresh AC registration before session-control readiness: %v", err)
		return
	}
	// Create message data for sending (use cached AOL bytes)
	// Use buffered channel to prevent sender from blocking if we timeout
	md := &core.MsgData{
		RemoteAddr:    sendAddr,
		HeaderType:    core.NHP_AOL,
		CipherScheme:  r.ac.config.DefaultCipherScheme,
		TransactionId: r.ac.device.NextCounterIndex(),
		Compress:      true,
		PeerPk:        server.Peer.PublicKey(),
		Message:       aolBytes,
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
		aakMsg, decodeErr := r.decodeCurrentSessionControlAAK(ppd)
		if decodeErr != nil {
			log.Warning("Failed to parse refresh NHP_AAK from %s: %v", sendAddr.String(), decodeErr)
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
			r.acceptCurrentSessionControlAAK(&aakMsg)
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
	if err := r.expireSessionControlLease(); err != nil {
		log.Error("All authenticated server controls expired and NHP session cleanup is incomplete: %v", err)
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

func (r *ACRegistration) expireSessionControlLease() error {
	if !r.controlLeaseExpired.CompareAndSwap(false, true) {
		return nil
	}
	if err := r.ac.flushLiveNHPSessionsForControlGap(); err != nil {
		r.controlLeaseExpired.Store(false)
		return err
	}
	return nil
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
			r.markAllUnconnectedRecovered() // Phase 0D: close the episode now, not on the next healthy tick
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
				r.markAllUnconnectedRecovered() // Phase 0D: close the episode now, not on the next healthy tick
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
// markAllUnconnectedRecovered closes an open all-unconnected episode (Phase 0D)
// and emits the recovery latency — the first-detected -> reconnected span, i.e.
// the outage the viewer experiences. Atomically reads+clears the episode timer,
// so it is a no-op when no episode is open and safe to call on every healthy
// tick / from any recovery path.
func (r *ACRegistration) markAllUnconnectedRecovered() {
	// Clear the window timer too, for symmetry — no stale value survives an
	// episode close (it is otherwise only read right after a fresh Store).
	// Best-effort under concurrent recovery: checkAllUnconnected (keepalive
	// goroutine) and the re-reg success paths both touch these atomics, so a rare
	// interleave can drop or slightly skew a single latency sample — acceptable
	// for an observability gauge.
	r.allUnconnectedWindowStartNano.Store(0)
	if since := r.allUnconnectedSinceNano.Swap(0); since != 0 {
		recoveryMs := elapsedSinceNano(since).Milliseconds()
		r.metrics.RecordLatency(MetricAllUnconnectedRecoveryMs, float64(recoveryMs))
		// RecordLatency carries no acId dimension; log it so a long outage can
		// still be attributed to a specific AC (per-AC MTTR via logs).
		log.Info("AC %s: recovered from all-unconnected episode after %dms", r.ac.config.ACId, recoveryMs)
	}
}

func (r *ACRegistration) checkAllUnconnected() {
	r.mu.RLock()
	servers := slices.Clone(r.assignedServers)
	r.mu.RUnlock()

	if len(servers) == 0 {
		// Initial registration hasn't completed yet (or we just stopped).
		// Reset the counter so a brand-new bootstrap doesn't immediately
		// trip the threshold based on stale state. Phase 0D: also drop any open
		// outage timers — an empty set is a teardown/redispatch, not a reconnect,
		// so clear (no RecoveryMs) rather than let a stale episode start leak.
		r.allUnconnectedTicks.Store(0)
		r.allUnconnectedSinceNano.Store(0)
		r.allUnconnectedWindowStartNano.Store(0)
		return
	}

	for _, server := range servers {
		if server.IsConnected() {
			r.allUnconnectedTicks.Store(0)
			r.markAllUnconnectedRecovered() // Phase 0D: close any open outage episode
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
		// Phase 0D: episode timer is idempotent (CAS(0, now) fires only on the
		// 0->episode transition, so a threshold-trip's tick reset doesn't restart
		// it mid-outage); the window timer restarts every window for DurationMs.
		now := time.Now().UnixNano()
		r.allUnconnectedSinceNano.CompareAndSwap(0, now)
		r.allUnconnectedWindowStartNano.Store(now)
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
	if err := r.expireSessionControlLease(); err != nil {
		log.Error("All server controls remain unconnected and NHP session cleanup is incomplete: %v", err)
		return
	}

	// Threshold reached — trip a re-registration through the control
	// plane. Reset the tick counter immediately so we don't re-fire on
	// the next tick while the in-flight TriggerReregistration is still
	// running. Note we do NOT touch r.assignedServers here; see the
	// docstring above for why.
	log.Warning("AC %s: all assigned servers unconnected for %d consecutive ticks, triggering NLB re-registration",
		r.ac.config.ACId, newTicks)
	// Phase 0D: detector-trip latency for THIS window (window-start -> threshold),
	// not the episode age — so a re-trip during a sustained outage reports the
	// window latency. The episode timer stays open for RecoveryMs on reconnect.
	if ws := r.allUnconnectedWindowStartNano.Load(); ws != 0 {
		r.metrics.RecordLatency(MetricAllUnconnectedDurationMs, float64(elapsedSinceNano(ws).Milliseconds()))
	}
	r.allUnconnectedTicks.Store(0)
	r.TriggerReregistration(ReasonAllServersUnconnected)
}

// elapsedSinceNano returns the time elapsed since a unix-nanosecond instant,
// centralizing the time.Since(time.Unix(0, …)) idiom the AC's atomic
// outage/registration timers share. Callers guard nano != 0 before treating the
// result as a real sample (nano == 0 is "no open episode", which would yield a
// meaninglessly large duration).
func elapsedSinceNano(nano int64) time.Duration {
	return time.Since(time.Unix(0, nano))
}

// timeSinceLastNLBRegistration returns the duration since the most recent
// successful NLB re-registration. Reads the atomic timestamp once so the
// caller sees a consistent value across the elapsed/threshold comparison.
func (r *ACRegistration) timeSinceLastNLBRegistration() time.Duration {
	return elapsedSinceNano(r.lastNLBRegistrationNano.Load())
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

// recordReconcileEntry detects violations of the transitionMu serialization
// invariant. It lives inside reconcileDevicePeers so future internal call sites
// cannot silently omit the signal.
//
// Use as:
//
//	exit := r.recordReconcileEntry()
//	defer exit()
func (r *ACRegistration) recordReconcileEntry() func() {
	// entrants includes this call; the second and later concurrent entrants
	// each emit one invariant-violation event.
	if entrants := r.reconcileInFlight.Add(1); entrants > 1 {
		r.metrics.IncrCounterWithDims(MetricReconcileOverlap, []types.Dimension{r.acIdDimension()})
	}
	return func() { r.reconcileInFlight.Add(-1) }
}

// formatActiveKey frames a public key and endpoint without ambiguous field
// boundaries. It uses \x00 as the field separator. PubKeyBase64 is RFC 4648
// base64 (alphabet [A-Za-z0-9+/=]) so "|" would also work, but Hostname is
// not similarly constrained — a future test/regression injecting a hostname
// containing "|" would ambiguate "k|host|with|pipes:port" vs
// "k|host:port|with|pipes". The null-byte separator is unambiguous against
// any printable input and matches the convention buildDimCounterKey uses in
// endpoints/metrics. net.JoinHostPort separately frames address and port,
// including bracketed IPv6 literals.
func formatActiveKey(pubKeyBase64, addr string, port int) string {
	return fmt.Sprintf("%s\x00%s", pubKeyBase64, net.JoinHostPort(addr, strconv.Itoa(port)))
}

// targetActiveKey returns a canonical (pubkey, address) key for active-set
// membership tests, plus a bool flagging the <unaddressed> sentinel branch.
//
// Contract. Keys on RedirectTarget.IP (preferred) or Hostname; both prior
// and new sets are keyed consistently because RedirectTarget.Validate (#832)
// requires one of them. net.JoinHostPort frames the endpoint so IPv6 address
// and port tuples cannot collide. udpPeerActiveKey uses the identical framing
// for actual Device members and assignment-ownership bookkeeping.
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
	key = formatActiveKey(t.PubKeyBase64, addr, t.Port)
	return key, sentinel
}

func udpPeerActiveKey(peer *core.UdpPeer) string {
	addr := peer.Ip
	if addr == "" {
		addr = peer.Hostname
	}
	if addr == "" {
		addr = "<unaddressed>"
	}
	return formatActiveKey(peer.PublicKeyBase64(), addr, peer.Port)
}

func (r *ACRegistration) trackAssignmentPeer(peer *core.UdpPeer) {
	if peer == nil {
		return
	}
	r.assignmentPeersMu.Lock()
	defer r.assignmentPeersMu.Unlock()
	if r.assignmentPeers == nil {
		r.assignmentPeers = make(map[string]*core.UdpPeer)
	}
	r.assignmentPeers[udpPeerActiveKey(peer)] = peer
}

func (r *ACRegistration) untrackAssignmentPeer(peer *core.UdpPeer) {
	if peer == nil {
		return
	}
	r.assignmentPeersMu.Lock()
	defer r.assignmentPeersMu.Unlock()
	key := udpPeerActiveKey(peer)
	if r.assignmentPeers[key] == peer {
		delete(r.assignmentPeers, key)
	}
}

func (r *ACRegistration) assignmentPeersSnapshot() map[string]*core.UdpPeer {
	r.assignmentPeersMu.Lock()
	defer r.assignmentPeersMu.Unlock()
	out := make(map[string]*core.UdpPeer, len(r.assignmentPeers))
	for key, peer := range r.assignmentPeers {
		out[key] = peer
	}
	return out
}

func (r *ACRegistration) staticServerActiveKeys() map[string]struct{} {
	keys := make(map[string]struct{})
	if r.ac == nil {
		return keys
	}
	r.ac.serverPeerMutex.RLock()
	defer r.ac.serverPeerMutex.RUnlock()
	if r.ac.config != nil {
		for _, peer := range r.ac.config.Servers {
			if peer != nil {
				keys[udpPeerActiveKey(peer)] = struct{}{}
			}
		}
	}
	for _, peer := range r.ac.serverPeerMap {
		if peer != nil {
			keys[udpPeerActiveKey(peer)] = struct{}{}
		}
	}
	return keys
}

// staticServerPeerForActiveKeyLocked returns the configured static pointer for
// key. The caller holds serverPeerMutex.
func (r *ACRegistration) staticServerPeerForActiveKeyLocked(key string) *core.UdpPeer {
	if r.ac.config != nil {
		for _, peer := range r.ac.config.Servers {
			if peer != nil && udpPeerActiveKey(peer) == key {
				return peer
			}
		}
	}
	for _, peer := range r.ac.serverPeerMap {
		if peer != nil && udpPeerActiveKey(peer) == key {
			return peer
		}
	}
	return nil
}

// removePeerPreservingStatic exact-removes a dynamic peer and atomically
// restores any currently configured same-key, same-address static pointer.
// Holding serverPeerMutex through the Device operation keeps config reloads
// from changing the chosen pointer, while Device's atomic replacement keeps a
// sibling connection attempt from consuming the freed group slot.
func (r *ACRegistration) removePeerPreservingStatic(peer *core.UdpPeer) bool {
	if peer == nil || r.ac == nil {
		return false
	}
	key := udpPeerActiveKey(peer)
	r.ac.serverPeerMutex.RLock()
	replacement := r.staticServerPeerForActiveKeyLocked(key)
	removed := r.ac.device.RemovePeerInstanceAndRestore(peer, replacement)
	r.ac.serverPeerMutex.RUnlock()
	return removed
}

func (r *ACRegistration) removeTransientPeer(peer *core.UdpPeer) bool {
	return r.removePeerPreservingStatic(peer)
}

func (r *ACRegistration) addAssignmentPeer(peer *core.UdpPeer) bool {
	if !r.ac.device.TryAddPeer(peer) {
		return false
	}
	r.trackAssignmentPeer(peer)
	return true
}

func (r *ACRegistration) removeAssignmentPeer(peer *core.UdpPeer) bool {
	if peer == nil {
		return false
	}
	removed := r.removePeerPreservingStatic(peer)
	r.untrackAssignmentPeer(peer)
	return removed
}

// reconcileDevicePeers converges the device cipher pool to newServers plus any
// explicitly protected in-flight registration peers and statically configured
// server endpoints. For shared-key
// PeerGroups it walks the actual members rather than only priorServers, but it
// removes only exact pointers owned by this registration manager. That closes
// #2123's rotating-subset accumulation without evicting static/config peers
// sharing the key. HandleRedispatch calls this before
// establishing the new connections so retired members cannot consume the
// bounded PeerGroup slots needed by the new assignment. The direct-AAK path
// calls it after installing its single new peer while holding r.mu. It reports
// whether the pass attempted at least one removal from the device pool.
//
// Behavior. Two invariants keep this safe with the *core.PeerGroup model
// that ASGs with shared keypairs land in (issue #1680):
//
//  1. Set difference. Only addresses that are NOT in newServers, are not a
//     protected registration peer, and are not statically configured are
//     candidates for removal. An address that re-appears in the new assignment
//     is skipped here, preventing the previous async cleanup's self-inflicted
//     eviction loop.
//
//  2. Order. HandleRedispatch removes retired addresses BEFORE
//     connectToServer calls device.AddPeer for the new targets. This prevents
//     stale shared-key members from filling PeerGroup to MaxPeerGroupSize and
//     starving live replacements. The active-set check above preserves every
//     address present in the new assignment. The direct-AAK caller adds its
//     single new peer first; the same active-set check preserves that address.
//
// Replaces the previous oldServerSets + 2-minute-grace-period cleanupWorker.
// The grace period was non-load-bearing (the only packets that could rely
// on it were leftovers from a server already disowned by this AC, whose
// validation outcome no longer affects the user-facing flow), so deleting
// the async machinery removes a bug surface without changing behavior.
//
// Concurrency. Every production caller holds transitionMu across the complete
// authoritative transition: assignment swap, reconcile, network connects, and
// final cleanup. That serialization makes the Members snapshot and removals
// atomic with respect to sibling assignment responses without holding r.mu
// across network waits. A non-zero MetricReconcileOverlap means a future or
// internal caller bypassed this contract and is an invariant violation.
//
// RemovePeerInstanceAndRestore performs the pointer check and optional static
// restoration atomically under Device's map lock. A config reload that replaces
// the same key and address between the Members snapshot and removal is therefore
// preserved.
func (r *ACRegistration) reconcileDevicePeers(priorServers, newServers []*AssignedServer, protectedPeers ...*core.UdpPeer) bool {
	ownedPeers := r.assignmentPeersSnapshot()
	if len(priorServers) == 0 && len(newServers) == 0 && len(protectedPeers) == 0 && len(ownedPeers) == 0 {
		// No assignment, protected peer, or retained ownership describes a
		// public key to inspect.
		return false
	}

	// Production call sites are serialized by transitionMu. Keep the detector
	// here so a future internal bypass is observable rather than silently unsafe.
	if len(priorServers) > 0 {
		exitReconcile := r.recordReconcileEntry()
		defer exitReconcile()
	}
	var unaddressedNew, unaddressedPrior int
	var anyEvicted bool
	activeKeys := make(map[string]struct{}, len(newServers)+len(protectedPeers))
	sweepKeys := make(map[string][]byte, len(newServers)+len(priorServers))
	priorPeers := make(map[string]*core.UdpPeer, len(priorServers))
	addSweepKey := func(pubKeyBase64 string) {
		if pubKeyBase64 == "" {
			return
		}
		if _, ok := sweepKeys[pubKeyBase64]; ok {
			return
		}
		pubKey, err := base64.StdEncoding.DecodeString(pubKeyBase64)
		if err != nil {
			log.Debug("Skipping AC peer sweep for invalid public key prefix %s", pubKeyPrefix(pubKeyBase64))
			return
		}
		sweepKeys[pubKeyBase64] = pubKey
	}
	// Ownership, rather than only the current/prior assignment slices, is the
	// complete set of dynamic peers this manager may need to retire. In
	// particular, direct AAK can retain an unaddressed peer outside
	// assignedServers; a later redispatch under a different public key must still
	// sweep it.
	for _, peer := range ownedPeers {
		if peer != nil {
			addSweepKey(peer.PublicKeyBase64())
		}
	}
	for _, srv := range newServers {
		if srv == nil {
			continue
		}
		k, sentinel := targetActiveKey(srv.Target)
		if sentinel {
			unaddressedNew++
		}
		activeKeys[k] = struct{}{}
		addSweepKey(srv.Target.PubKeyBase64)
	}
	for _, peer := range protectedPeers {
		if peer == nil {
			continue
		}
		activeKeys[udpPeerActiveKey(peer)] = struct{}{}
		addSweepKey(peer.PublicKeyBase64())
	}
	for key := range r.staticServerActiveKeys() {
		activeKeys[key] = struct{}{}
	}
	for _, srv := range priorServers {
		if srv == nil {
			continue
		}
		addSweepKey(srv.Target.PubKeyBase64)
		if srv.Peer != nil {
			priorPeers[udpPeerActiveKey(srv.Peer)] = srv.Peer
		}
	}

	// A priorServers delta cannot see members forgotten by earlier rotating
	// assignment epochs. Sweep the actual PeerGroup membership for every key
	// touched by this reconcile before falling back to the single-peer-safe
	// prior loop below. The authoritative active set, not address age, decides
	// retention; holding stale members for MinimalPeerAddressHoldTime would
	// recreate the capacity starvation this path exists to prevent.
	sweptGroups := make(map[string]struct{})
	for pubKeyBase64, pubKey := range sweepKeys {
		group, ok := r.ac.device.LookupPeer(pubKey).(*core.PeerGroup)
		if !ok {
			continue
		}
		sweptGroups[pubKeyBase64] = struct{}{}
		for _, member := range group.Members() {
			key := udpPeerActiveKey(member)
			if owned := ownedPeers[key]; owned != nil && owned != member {
				// An exact-key replacement proves the older owned pointer is no
				// longer in Device; retire its bookkeeping without touching the
				// replacement.
				r.untrackAssignmentPeer(owned)
				delete(ownedPeers, key)
			}
			if _, active := activeKeys[key]; active {
				continue
			}
			// Device also holds static/config peers. Remove only an exact pointer
			// installed by this registration manager (including the captured
			// prior assignment for upgrade/test compatibility). Pointer-aware
			// removal preserves a same-address config-reload replacement.
			if ownedPeers[key] != member && priorPeers[key] != member {
				continue
			}
			if r.removeAssignmentPeer(member) {
				log.Info("Removed unassigned AC-owned peer-group member %s", member.Host())
				anyEvicted = true
			}
			delete(ownedPeers, key)
		}
	}
	for _, srv := range priorServers {
		if srv == nil {
			continue
		}
		// Snapshot once so the nil check and later device operations use the
		// same assignment peer.
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
		if _, swept := sweptGroups[peer.PublicKeyBase64()]; swept {
			continue
		}
		if r.removeAssignmentPeer(peer) {
			log.Info("Removed AC-owned device peer for retired server %s", srv.Target.Address())
			anyEvicted = true
		}
		delete(ownedPeers, udpPeerActiveKey(peer))
	}

	// Retire owned peers that are not reachable from priorServers. This closes
	// the direct-AAK nil-address case and also drains bookkeeping for pointers
	// that a same-address static/config replacement already displaced.
	for key, peer := range ownedPeers {
		if peer == nil {
			continue
		}
		if _, active := activeKeys[key]; active {
			continue
		}
		if r.removeAssignmentPeer(peer) {
			log.Info("Removed stale AC-owned device peer %s", peer.Host())
			anyEvicted = true
		}
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

	return anyEvicted
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
