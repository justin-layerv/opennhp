package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"golang.org/x/crypto/bcrypt"

	"github.com/OpenNHP/opennhp/endpoints/server/internal/connectorcell"
	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
	wasmEngine "github.com/OpenNHP/opennhp/nhp/core/wasm/engine"
	"github.com/OpenNHP/opennhp/nhp/log"
	utils "github.com/OpenNHP/opennhp/nhp/utils"
)

const (
	// MaxServersPerAssignment is the maximum number of servers assigned to a single AC.
	MaxServersPerAssignment = 3

	// AssignmentTTLSeconds is the TTL for AC assignments (30 minutes).
	AssignmentTTLSeconds int64 = 1800

	// DefaultStorageTimeout is the default timeout for storage and Cloud Map operations.
	DefaultStorageTimeout = 5 * time.Second

	// DefaultStaleACConnThreshold is the default duration after which an AC
	// connection is considered dead for broadcast purposes. Set to the same
	// window the AC itself uses to decide a server is down: KeepaliveInterval
	// (10s) × KeepaliveMaxRetries (3) = 30s (see endpoints/ac/registration.go).
	// Past that point the AC will have entered its own re-registration path,
	// so NHP-AOP sent on a connection silent this long will sit until the
	// server-side transaction timeout — wasting the broadcast budget on a
	// peer that will not ACK. recvPacketRoutine updates
	// ConnectionData.LastLocalRecvTime on every inbound packet (including
	// keepalives), so a live connection stays fresh without extra work.
	//
	// Override per-server via Config.StaleACConnThresholdSeconds; the floor
	// MinStaleACConnThreshold (5s) is enforced on the resolved value to
	// prevent a misconfiguration from filtering every connection on every
	// knock.
	DefaultStaleACConnThreshold = 30 * time.Second

	// MinStaleACConnThreshold is the floor enforced when resolving the
	// effective threshold from Config.StaleACConnThresholdSeconds. A value
	// below this would filter out connections that haven't quite finished
	// their first keepalive cycle (KeepaliveInterval = 10s on the AC side).
	MinStaleACConnThreshold = 5 * time.Second

	// TTLRefreshMinInterval is the minimum time between TTL refreshes for the same AC.
	// Prevents excessive DynamoDB writes from frequent AC re-registrations.
	TTLRefreshMinInterval = 5 * time.Minute
)

// Metric counter names for CloudWatch. Using constants prevents typos
// and enables discoverability across the codebase.
const (
	MetricKnockRequest   = "KnockRequest"
	MetricKnockLatency   = "KnockLatency"
	MetricAuthSuccess    = "AuthSuccess"
	MetricAuthFailure    = "AuthFailure"
	MetricAutoAssignment = "AutoAssignment"
	// MetricACAssignmentColorMigration fires once each time an AC that
	// re-registered onto this server is *successfully* migrated wholesale
	// off a stale cross-color (old blue/green) assignment onto this
	// server's own color — it counts durable migrations (a persisted
	// reassignment), not attempts, so an autoAssignAC fall-through (e.g.
	// save conflict-cap exhausted) does NOT tick it. Expected to spike to
	// ~one-per-AC during a blue/green switch and sit at zero in steady
	// state. A SUSTAINED non-zero rate outside a deploy window means ACs
	// keep landing on a color that disagrees with their persisted
	// assignment — i.e., assignments are not converging (investigate
	// Cloud Map staleness or a stuck scale-down). Occasional ISOLATED ticks
	// are benign — e.g. a cache straddle between the FilterHealthyServers
	// read and this check can reassign an already-same-color AC to its own
	// color — so read the rate, not single events. Surfaced today by the
	// manual post-rollout ledger check, not an automated CloudWatch alarm;
	// a bounded-window alarm (spike-then-zero within the switch window) is
	// tracked in issue #2497.
	//
	// Scope: this counts ONLY the post-switch/pre-scale-down graft-avoidance
	// path (handleACServerAssignment's not-assigned branch). The
	// all-assigned-unhealthy reassign (post-scale-down) also re-homes an AC
	// onto the surviving color but is NOT counted here — it is the expected
	// steady-state recovery path, not the convergence signal this counter
	// tracks.
	MetricACAssignmentColorMigration = "ACAssignmentColorMigration"
	// MetricACAssignmentColorMigrationSuppressed fires when the blue/green
	// migration fast-path detects that the current-color Cloud Map view would
	// reduce an AC's dialable assignment coverage. The handler keeps the
	// existing healthy assignment instead of persisting a thinner one.
	MetricACAssignmentColorMigrationSuppressed = "ACAssignmentColorMigrationSuppressed"
	// Knock-path AC-open re-knock retry (blue/green reassignment window,
	// qurl-service#976). A broadcast whose every AC connection hit the transaction
	// timeout re-snapshots the connection map after a short backoff; the three
	// counters map the three outcomes (steady-state all ~0):
	//   - MetricKnockReknockNoFreshConns: the re-snapshot found NO fresh conn, so no
	//     retry was issued; a distinct counter because this case increments NEITHER
	//     Retry counter below (why it gets its own is at the increment site).
	//   - MetricKnockReknockRetry: a retry WAS issued after fresh conns appeared.
	//   - MetricKnockReknockRetrySuccess: the issued retry then succeeded (an
	//     ErrServerACOpsFailed/52005 converted into a success).
	// The on-call decision tree (which combination means absorbed-flip vs ongoing
	// thrash vs escalate-to-ops/forward) lives in the qURL AC-open
	// rollout-ledger entry so it stays single-sourced.
	MetricKnockReknockRetry        = "KnockReknockRetry"
	MetricKnockReknockRetrySuccess = "KnockReknockRetrySuccess"
	MetricKnockReknockNoFreshConns = "KnockReknockNoFreshConns"
	// MetricKnockForwardMissingPacket fires when a knock needs fan-out or
	// no-local-AC forwarding but BasePacketContent() returned nil: a guard-drift
	// canary for the IsForwardableKnockType clone guard in decryptBody. It covers
	// both gates in handleNhpOpenResource, so a single knock can increment it
	// twice; treat any nonzero value as investigate-worthy, not a per-packet count.
	MetricKnockForwardMissingPacket = "KnockForwardMissingPacket"
	// Cell-wide knock AC fan-out (qurl-service#948, Config.EnableKnockACFanout).
	// Unlike the forward counters above (a no-local-AC FAILOVER to one peer),
	// these track the coverage fan-out an origin knock sends to one assigned peer
	// server per non-local AZ so the qurl.site AC AZ set opens the pinhole.
	MetricKnockFanout            = "KnockFanout"            // origin knocks that fanned out (per acId)
	MetricKnockFanoutPeerSuccess = "KnockFanoutPeerSuccess" // peer servers that accepted a fan-out knock
	MetricKnockFanoutPeerFail    = "KnockFanoutPeerFail"    // peer servers a fan-out knock could not reach
	// MetricKnockForwardPeerAttempt counts each scheduled native NHP_FWD peer
	// attempt from the no-local-AC forward path. Local pending-forward
	// backpressure can still abort before a packet is sent. ForwardKnock now
	// races every healthy assigned owner, so this is the graphable multiplier
	// behind AC AOP volume during blue/green and qURL admission burn-in.
	MetricKnockForwardPeerAttempt = "KnockForwardPeerAttempt"
	// MetricServerForwardUnknownResult counts NHP_FRT responses that arrive after
	// the origin has already stopped waiting for that transaction. That is
	// expected for first-success ForwardKnock losers, but the counter keeps the
	// volume visible without warning-level log noise.
	MetricServerForwardUnknownResult = "ServerForwardUnknownResult"
	// MetricKnockFanoutDuplicateAZCandidate flags a topology/precondition drift:
	// a bounded fan-out selector saw more than one eligible assigned peer in at
	// least one non-local AZ bucket. Fan-out still sends one peer per AZ; this
	// metric tells rollout validation that the one-server-per-AZ assumption is no
	// longer true for that AC assignment.
	MetricKnockFanoutDuplicateAZCandidate = "KnockFanoutDuplicateAZCandidate"
	// MetricRelayForward counts every NHP_RLY packet (relay-forwarded agent
	// knock, #2208) RECEIVED past the outer Noise auth. It is incremented at
	// handler entry, BEFORE the relay-peer / source / inner-packet validation,
	// so it includes forwards that are then dropped (MetricRelayForwardReject).
	// processed = RelayForward − RelayForwardReject is the count that REACHED the
	// knock pipeline (buildKnockAck), and only those also tick MetricKnockRequest
	// — so relay traffic stays separable from direct knocks without double-
	// counting. Note: processed means "reached the pipeline", NOT "delivered" —
	// the two rare post-auth internal-failure paths (ack marshal failure,
	// relay-ack send failure) land in processed but deliver no ack. They aren't
	// worth a dedicated counter. (P5/P7 alarm authors: read processed as the
	// difference, and treat it as ~delivered modulo those rare internal failures.)
	MetricRelayForward = "RelayForward"
	// MetricRelayOverloadCookieReturn counts authenticated COK challenges
	// successfully encrypted and written to the relay-return UDP socket
	// while the server is overloaded. During a known overload window, correlate
	// it with MetricOverloadCookieMintFailure and relay-return send-failure logs;
	// a successful socket write does not by itself prove relay receipt.
	MetricRelayOverloadCookieReturn = "RelayOverloadCookieReturn"
	// MetricOverloadCookieProcessLocalKey is 1 while this server is using a
	// random per-process overload-cookie signing key and 0 when a shared key is
	// configured. Process-local mode is valid only for single-instance
	// deployments; any non-zero value in a load-balanced fleet means
	// cross-instance COK->RKN verification can fail.
	MetricOverloadCookieProcessLocalKey = "OverloadCookieProcessLocalKey"
	// MetricOverloadCookieMintFailure counts overload rejects where the server
	// intended to return a COK but could not mint or marshal one. A non-zero
	// rate means agents are receiving ErrServerRejectWithCookie without a usable
	// cookie to re-knock with. The base stream drives the CloudWatch alarm; the
	// Reason breakdown identifies missing source binding, wrong peer-pubkey
	// length, missing legacy CookieStore, or marshal failure.
	MetricOverloadCookieMintFailure = "OverloadCookieMintFailure"
	// MetricRelayForwardReject counts NHP_RLY packets dropped before the inner
	// knock is authenticated — unregistered relay peer, bad relay-reported
	// SourceAddr, malformed/oversize inner packet, non-knock inner type, or a
	// missing inner agent pubkey. These are pre-auth drops with no ack sent
	// (there is no authenticated agent to encrypt one for); auth REJECTS after
	// the inner decrypt are delivered as acks and counted by MetricAuthFailure.
	MetricRelayForwardReject = "RelayForwardReject"
	// MetricOTPRejectRateLimited counts native-UDP OTP requests (including
	// Connector registration) and generic requests on non-direct ingress dropped
	// by the pre-plugin OTP rate limiter (agent_otp_ratelimit.go) before the
	// downstream cost. Configured Connector registration on non-direct ingress is
	// rejected before the limiter and counted by
	// MetricConnectorRegistrationIngressRejected. A non-zero rate means a
	// per-key or aggregate OTP flood is being shed at the server.
	// This is deliberately not relay-prefixed because it is a native/direct-UDP
	// metric; browser relay lifecycle requests are rejected at admission.
	MetricOTPRejectRateLimited      = "OTPRejectRateLimited"
	MetricCloudMapDeregisterFailure = "CloudMapDeregisterFailure"
	// MetricShutdownTransactionDrainTimeout increments when graceful shutdown's
	// in-flight transaction drain exhausts its budget with non-zero local
	// transactions still outstanding — those transactions will return
	// ErrTransactionFailedByClosedConnection to their callers after
	// close(s.signals.stop). Non-zero in normal operation means the
	// shutdownTransactionDrainTimeout budget is too tight or the AC is
	// hung; expect zero in healthy deploys.
	MetricShutdownTransactionDrainTimeout = "ShutdownTransactionDrainTimeout"
	// MetricCloudMapRegisterFailure fires once per process when boot-time
	// Cloud Map registration exhausts its retry budget. Page-worthy if
	// non-zero in burn-in: the server is running but invisible to the
	// auto-assignment fan-out. See issue #1681 for the prod incident this
	// counter fences.
	MetricCloudMapRegisterFailure = "CloudMapRegisterFailure"
	// MetricCloudMapRegisterRefresh fires once per successful periodic
	// re-assertion. Steady-state non-zero is healthy (refresh loop is
	// running); a sudden drop to zero with a live process is the signal
	// that the refresh goroutine has wedged.
	MetricCloudMapRegisterRefresh = "CloudMapRegisterRefresh"
	// MetricCloudMapRegisterRefreshFailure fires once per failed periodic
	// re-assertion. Sustained non-zero in steady state means Cloud Map is
	// rejecting our updates (auth, quota, or service down) — the server
	// will be increasingly stale in DiscoverInstances and may drop out of
	// new assignments.
	MetricCloudMapRegisterRefreshFailure = "CloudMapRegisterRefreshFailure"
	MetricKnockNoAC                      = "KnockNoAC"
	// MetricARTReplayDetected counts replay-dedupe drops of already-seen
	// NHP_ART packets at the server's post-validation chokepoint (#1457)
	// — the symmetric counterpart of the AC's AOPReplayDetected. A drop is
	// a (sender_pubkey, txid, sendTime) triple seen again within the cache
	// TTL: either a replay attempt (the security signal) or a benign
	// in-flight ART arriving twice across an AC failover / NAT rebind.
	// Like the AC counter it fires at human-paced cadence, so a sustained
	// non-zero rate is the actionable signal while a single isolated event
	// can follow restart/failover retries.
	MetricARTReplayDetected = "ARTReplayDetected"
	// MetricARTReplayGateDrop counts matched ARTs dropped by the
	// per-connection replay GATE (core.ErrReplayPacketReceived, a
	// LastRemoteSendTime timestamp regression) — the new behavior #1457's
	// exemption removal introduces, observed where the dropped response
	// surfaces in processACOperation. Kept DISTINCT from
	// MetricARTReplayDetected (the cross-connection cache drop): a gate drop
	// is most often a benign burst reorder (ART send-times are stamped by
	// concurrent msgToPacketRoutine workers, so non-monotonic arrival needs
	// no network reorder), whereas a cache drop is a clean cross-connection
	// replay signal. Conflating them would poison the replay security alarm
	// (#2512). A sustained non-zero rate here means the strict-less-than
	// gate is false-rejecting legitimately reordered ARTs.
	//
	// Scope — this counts only gate-drops on the MATCHED-transaction path
	// (processACOperation). A gate-drop of an UNMATCHED ART (its
	// transaction already completed → the packet is silently destroyed and
	// never reaches here) did NOT fail a live knock, so it is intentionally
	// uncounted. So this is an under-count of TOTAL gate-drops by design —
	// read a near-zero rate as "no live knocks failing to burst reorder"
	// (the availability question), not "zero gate-drops total."
	MetricARTReplayGateDrop = "ARTReplayGateDrop"
	// MetricACTokenStored fires once per AC-issued token persisted to
	// the server tokenStore via UdpServer.storeACToken. Operators use
	// this rate to fence PR-2b's /nhp/internal/token/validate: a
	// non-zero validate-miss rate paired with a zero ACTokenStored
	// rate means the issuer side is silent, not that validate is
	// broken. Sustained zero with live knock traffic should page —
	// the store-on-issue chokepoint has gone dark.
	MetricACTokenStored = "ACTokenStored"
	// MetricTokenStoreSize is a gauge of the current ACTokenEntry
	// population in the server tokenStore. Pair with MetricACTokenStored
	// (the add-rate counter): under sustained knock load the steady
	// state is roughly knock_rate × (OpenTime + late-packet buffer)
	// entries, with no cap. The counter alone can't answer "did the
	// store grow unbounded?" — this gauge does. When PR-2b's validate
	// endpoint starts returning nil unexpectedly, operators check
	// here for runaway growth or, conversely, an unexpectedly empty
	// store (CleanExpired stalled, or the periodic refresh routine
	// died silently). Sampled by the Publisher each flush via
	// RegisterGaugeFunc on tokenStore.Size; the value reflects the
	// post-sweep population because CleanExpired runs every
	// TokenStoreRefreshInterval seconds on the same goroutine.
	MetricTokenStoreSize = "TokenStoreSize"
	// MetricACKTokenSharedStoreInitFailure fires when a configured
	// fleet-visible ACK token store cannot initialize during server
	// startup. This is a deployment/configuration signal, distinct
	// from runtime DynamoDB read/write failures. Hard misconfigurations
	// that abort Start before the metrics publisher exists surface as
	// startup errors/logs rather than this counter.
	MetricACKTokenSharedStoreInitFailure = "ACKTokenSharedStoreInitFailure"
	// MetricACKTokenSharedStoreWriteFailure fires when nhp-server
	// cannot persist ACK token metadata after AC operations complete.
	// In configured multi-server mode this fails the knock so the
	// agent is never given a token only this process can validate.
	MetricACKTokenSharedStoreWriteFailure = "ACKTokenSharedStoreWriteFailure"
	// MetricKnockPinholeOrphaned fires once per ACK publication failure
	// after AC operations have succeeded. It pairs with
	// MetricACKTokenSharedStoreWriteFailure, but is knock-scoped rather
	// than write-attempt-scoped so operators can size the temporary
	// AC-open/no-token window during shared-store outages.
	MetricKnockPinholeOrphaned = "KnockPinholeOrphaned"
	// MetricACKTokenSharedStoreReadFailure fires when
	// /nhp/internal/token/validate cannot load from the shared store
	// after a local tokenStore miss. The handler returns 503 so
	// tunnel-server retries infrastructure failures instead of
	// treating the token as invalid.
	MetricACKTokenSharedStoreReadFailure = "ACKTokenSharedStoreReadFailure"
	// MetricACKTokenSharedStoreHit fires when /nhp/internal/token/validate
	// recovers a live, unexpired token from the shared store after a
	// local tokenStore miss. It records successful metadata retrieval,
	// not successful authorization: a later RunID mismatch also increments
	// MetricInternalTokenValidateFailure. A non-zero hit rate is expected in
	// multi-server deployments where knocks and validator calls land on
	// different instances.
	MetricACKTokenSharedStoreHit = "ACKTokenSharedStoreHit"
	// MetricInternalAuthFailPermit / MetricInternalAuthFailStrict count
	// signed /nhp/internal requests whose HMAC verification failed.
	// /knock and /token/validate follow the rollout flag: permit-mode
	// failures warn + allow, strict-mode failures get 401. The
	// destructive AC revocation sweep endpoint is permanently strict and
	// always emits FailStrict on HMAC verification failure. Operators
	// alarm on Permit > 0 to know when it's safe to flip require=true
	// (signals all rollout-gated callers signing).
	MetricInternalAuthFailPermit = "InternalAuthFailPermit"
	MetricInternalAuthFailStrict = "InternalAuthFailStrict"
	// MetricInternalAuthSignerUnavailable fires when a permanently-strict
	// internal endpoint rejects before HMAC verification because the
	// server has no signer configured. Keep this distinct from FailStrict:
	// this is an operator/configuration problem, not evidence of a caller
	// presenting a bad signature.
	MetricInternalAuthSignerUnavailable = "InternalAuthSignerUnavailable"
	// MetricInternalAuthSuccess pairs with the Fail counters above.
	// FailPermit → 0 alone can mean "everyone signed" OR "no traffic".
	// Watching Success rise while FailPermit drops is the positive
	// signal operators need before flipping NHP_INTERNAL_AUTH_REQUIRE=true.
	MetricInternalAuthSuccess = "InternalAuthSuccess"

	// Cross-server hop attestation counters (issue #1127). Mirror the
	// internal-auth rollout signals: alarm on ForwardHopAttestPermit > 0
	// during rollout; when it holds at zero (and Success is rising) it's
	// safe to flip NHP_INTERNAL_FORWARD_ATTEST_REQUIRE=true.
	MetricForwardHopAttestSuccess = "ForwardHopAttestSuccess"
	MetricForwardHopAttestPermit  = "ForwardHopAttestPermit"
	// MetricForwardHopAttestReject is the strict-mode auth reject — its
	// dominant cause during rollout is an un-upgraded (non-signing) sender,
	// not an attack. Kept distinct from the ceiling counter below so an
	// operator alarming on a real loop signal isn't drowned by rollout noise.
	MetricForwardHopAttestReject = "ForwardHopAttestReject"
	// MetricForwardHopCeilingReject is the always-on hop-ceiling 403 (hop
	// out of [1, maxForwardHops]), independent of this gate's rollout mode.
	// Legitimate traffic never trips it, so a nonzero value is a real
	// over-hop / loop signal worth investigating on its own — BUT only once
	// the upstream shared-secret gate (NHP_INTERNAL_AUTH_REQUIRE) is itself
	// strict. The hop-range check runs before the trust/MAC checks, so while
	// that gate is in permit any private-network actor reaching
	// /nhp/internal/knock can drive this counter with a garbage hop. Alarm on
	// it only after #1122's gate is strict; until then treat spikes as
	// unauthenticated noise, not confirmed loops.
	MetricForwardHopCeilingReject = "ForwardHopCeilingReject"
	// MetricInternalKnockASPNotFound fires when an authenticated
	// /nhp/internal/knock request reaches catalog resolution but the
	// requested aspId is absent. Kept separate from MetricAuthFailure
	// so internal service-to-service catalog misses do not page the
	// UDP knock auth-policy alarm.
	MetricInternalKnockASPNotFound = "InternalKnockASPNotFound"
	// MetricInternalKnockRequest counts parsed /nhp/internal/knock
	// requests after the HMAC request-auth gate, but before resource
	// resolution and forwarded-hop attestation. This is request
	// visibility, not a "passed every downstream authorization check"
	// counter. It is dual-published as a base fleet stream for
	// dashboards/future alarms and as a Source/CallerIP breakdown stream
	// for investigation of VPC-internal callers that should not be
	// driving the internal surface.
	MetricInternalKnockRequest = "InternalKnockRequest"
	// MetricInternalTokenValidateBadNonce fires when an authenticated
	// /nhp/internal/token/validate caller opts in to response auth with
	// a malformed X-Nhp-Nonce. It is deliberately separate from the
	// request-auth success/fail trio so rollout dashboards can catch
	// verifier nonce-shape bugs without redefining request-auth success.
	MetricInternalTokenValidateBadNonce = "InternalTokenValidateBadNonce"
	// MetricInternalTokenValidateFailure counts authoritative negative
	// /nhp/internal/token/validate results (not_found, expired, or
	// run_id_mismatch). It is published as a base counter for the aggregate
	// alarm, a bounded Reason stream for reason-specific alarms, and a
	// CallerIP/Reason breakdown stream for attribution.
	MetricInternalTokenValidateFailure = "InternalTokenValidateFailure"
	MetricACPeerCount                  = "ACPeerCount"
	// MetricACGraceAbsorbed increments once per /health/knock-ready probe
	// where ACPeerChecker returned pass from the grace-window branch
	// (live count was zero but the last-non-zero timestamp was inside
	// ACPeerGracePeriodSeconds). A rising rate means the debounce is
	// doing real work (single-keepalive flickers) rather than hiding
	// sustained AC-side degradation. Pair with KnockNoAC to distinguish:
	//   - GraceAbsorbed up AND KnockNoAC flat → debounce is absorbing
	//     transients as designed; rollout is healthy.
	//   - GraceAbsorbed up AND KnockNoAC up   → AC cluster is actually
	//     broken and the grace window is masking it; page oncall.
	MetricACGraceAbsorbed       = "ACGraceAbsorbed"
	MetricACRegistrationSuccess = "ACRegistrationSuccess"
	MetricACRegistrationFailure = "ACRegistrationFailure"
	MetricACRegistrationLatency = "ACRegistrationLatency"
	// MetricACConnAuthorityNotReadyFiltered counts cloud AC connections kept
	// for durable control recovery but excluded from AOP routing while their
	// target is PREPARING or catch-up failed.
	MetricACConnAuthorityNotReadyFiltered = "ACConnAuthorityNotReadyFiltered"
	MetricBroadcastPartialFail            = "BroadcastPartialFail"
	MetricBroadcastDurationMs             = "BroadcastDurationMs"
	// qURL v2 revocation fanout telemetry (P4e). The server receives a
	// revocation event from qurl-service on /nhp/internal/revocation and pushes
	// NHP_REV to the matching connected ACs fire-and-forget.
	//
	// MetricRevocationReceived counts events that pass the request-auth gate and
	// validation (one per accepted POST, before fanout). MetricRevocationFanoutSent
	// is the per-event count of ACs an NHP_REV was enqueued for (0 on a
	// no-matching-AC no-op). It is emitted as the original base {Environment,Cell}
	// stream and as a bounded FanoutMode breakdown; the #2790 targeted-zero-match
	// alarm reads the FanoutMode=targeted stream so cell-wide traffic cannot mask
	// targeted fanout collapse. Console dashboards should pin either that specific
	// stream or the base {Environment,Cell} stream; aggregating all dimensions for
	// this metric name double-counts base + breakdown series.
	// MetricRevocationFanoutBackpressure fires when the shared send queue is full
	// mid-fanout and the handler fails closed with 503 so qurl-service's
	// at-least-once Publisher retries; a nonzero value means the send pipeline is
	// saturated and revocations are being deferred (page if sustained — a revoke
	// is security-relevant and the retry budget is finite).
	MetricRevocationReceived           = "RevocationReceived"
	MetricRevocationFanoutSent         = "RevocationFanoutSent"
	MetricRevocationFanoutBackpressure = "RevocationFanoutBackpressure"
	// MetricRevocationTargetedZeroMatch counts targeted revocation events that
	// named a non-empty target_ac_ids set but matched ZERO connected ACs on this
	// server (#2790). It turns a formerly-silent no-op into a countable signal so
	// a cross-repo identifier-space drift is observable: target_ac_ids is matched
	// by string equality against ACConn.ACId, and if qurl-service ever changes
	// what it stores in a session's admitted_ac_ids (a pubkey hash, a DB row id, a
	// blue/green-suffixed id, a re-normalized form) targeted fanout silently
	// matches nothing and FAILS OPEN — the lost NHP_REV leaves the AC entry to
	// natural expiry with no error surfaced.
	//
	// READ THIS AS A FLEET-WIDE CANARY, NOT A PER-SERVER ERROR. An AC holds one
	// server connection per blue/green slot, so a targeted revoke naming ACs that
	// live on sibling servers legitimately zero-matches here — a nonzero count on
	// any single server is expected. The drift signal is the fleet-wide shape: if
	// the identifier contract holds, every targeted revoke matches on at least one
	// server so fleet RevocationFanoutSent stays > 0; on drift EVERY server
	// zero-matches, fleet targeted RevocationFanoutSent collapses to 0, and this
	// counter rises to ~100% of targeted events. Until qurl-service enables
	// targeted fanout (cell-wide only today) this path is inert, so any nonzero
	// value before that cross-repo enable is itself a signal.
	//
	// Coverage boundary: this fires only when ALL named ids miss (len(conns)==0),
	// the realistic all-or-nothing shape of a shared-convention drift. A PARTIAL
	// intra-event drift — some target_ac_ids still match a live ACConn.ACId while
	// others don't — leaves the match set non-empty, so this stays 0 and the
	// drifted id's NHP_REV still fails open silently. That is a blind spot by
	// construction, accepted because the id encoding is one shared convention (a
	// subset drifting independently is not a realistic failure mode).
	//
	// Counted per DELIVERY attempt, not per unique event: qurl-service is
	// at-least-once, so a retried event re-increments this on each zero-match
	// server (RevocationFanoutSent re-fires on retry the same way). But the
	// per-increment MAGNITUDES differ: this is +1 per zero-match EVENT, while
	// RevocationFanoutSent is +N per event (N = ACs matched, via AddCounterWithDims).
	// So read the drift as the two series' SHAPE — targeted RevocationFanoutSent
	// collapsing to ~0 while this rises — NOT a literal zeroMatch/(zeroMatch+fanoutSent)
	// division, which would mix events with AC-deliveries.
	MetricRevocationTargetedZeroMatch = "RevocationTargetedZeroMatch"
	// MetricForwardAdmissionResourceHashMismatch counts native forwarded qURL
	// v2 admissions whose origin sidecar resource hash differs from the
	// receiver catalog hash. The receiver keeps its catalog hash authoritative,
	// so this counter is rollout triage for stale catalog rows that can miss a
	// resource-scoped targeted revoke until the receiver catalog catches up.
	MetricForwardAdmissionResourceHashMismatch = "ForwardAdmissionResourceHashMismatch"
	// MetricForwardResolvedResourceFallback counts NHP_FWD receivers that could
	// not resolve the inner knock ResourceId from their local catalog and used
	// the origin server's validated routing snapshot instead. This is expected
	// for qURL v2 browser knocks: the wire ResourceId is the protected-resource
	// public key while the origin's admission response carries the q_ resource
	// row needed to open the peer AZ's AC pinhole.
	MetricForwardResolvedResourceFallback = "ForwardResolvedResourceFallback"
	// MetricRevocationAckReceived counts NHP_RVA acks the server received from
	// ACs (proof-of-delivery, P4e Slice 3 #2793), one per validated ack whose
	// AC identity resolved from the authenticated connection pubkey. Pairs with
	// the AC's MetricRevocationAckSent across the fleet.
	MetricRevocationAckReceived = "RevocationAckReceived"
	// MetricRevocationAckUnresolved counts NHP_RVA acks the server could not
	// attribute to a known AC connection (the authenticated pubkey matched no
	// live ACConn). A spike means acks are arriving from connections the server
	// no longer tracks (a drop/reconnect race) — the ack is ignored (the pending
	// tracker, once added, is keyed by the resolved acId), and the revoke either
	// already cleared or will age out.
	MetricRevocationAckUnresolved = "RevocationAckUnresolved"
	// MetricRevocationAgedOut counts pending per-AC revokes the server gave up
	// retrying because they were never acked before the age-out deadline — a
	// revoke that could NOT be proven delivered. THIS IS THE DE-RISK #5
	// DEGRADED SIGNAL: any nonzero value is an immediate-revocation that the
	// control plane could not confirm reached the AC. It is emitted (never a
	// silent drop) so it can be alarmed. Wired by the retry/age-out engine
	// (deferred — see #2793 design).
	MetricRevocationAgedOut = "RevocationAgedOut"
	// MetricRevocationUntrackable counts invariant breaks where a server already
	// enqueued NHP_REV fanout to an AC connection but could not key that
	// connection to an ACId or authenticated AC pubkey for proof tracking. This
	// is distinct from MetricRevocationAgedOut: no retry deadline elapsed; the
	// server simply cannot prove or redrive that enqueued target. Any nonzero
	// value means the live-connection registry violated the identity invariants
	// the proof engine depends on.
	MetricRevocationUntrackable = "RevocationUntrackable"
	// MetricRevocationDeliveryLatency is the revocation-latency SLO histogram
	// (#2792): one observation, in milliseconds, per revoke that an AC acked —
	// the wall-clock from the server enqueuing the NHP_REV (firstSentAt) to that
	// AC's NHP_RVA being attributed (clearAck), recorded via metrics.RecordLatency.
	// The SLO target, the "why 15s", the EMF-backs-p99 note, the complementary-
	// signal relationship with MetricRevocationAgedOut, and the engine-armed
	// emission coupling all live on RevocationDeliveryLatencyP99SLO
	// (revocation_retry.go) — the one canonical home; the p99 alarm is
	// revocation_delivery_latency_high in terraform/modules/monitoring/main.tf.
	//
	// Coverage boundary (load-bearing for any consumer): samples ACKED revokes
	// ONLY. A never-delivered revoke is counted by MetricRevocationAgedOut, never
	// added here, so the distribution is bounded below the age-out by construction.
	MetricRevocationDeliveryLatency = "RevocationDeliveryLatency"
	// QURL plugin resolve telemetry. The qurl plugin orchestrates the
	// browser-side qurl.link → qurl.site redirect — token validate via
	// qurl-service, NHP knock to AC, JWT cookie set, 302 redirect — and
	// is the synchronous user-facing path. The breakdown is
	// intentionally per-phase so operators can localize tail-latency
	// spikes (e.g., a 10 s p99) to a specific hop without reading logs.
	//
	//   *DurationMs        — total wall clock per AuthWithHttp call.
	//                        Unconditional: fires on every return,
	//                        including FailValidate paths that
	//                        short-circuit before any network I/O.
	//                        Token-fuzzing volume can pull p50/p99
	//                        toward "in-process work" rather than
	//                        user-facing redirect cost; PR 2 panels
	//                        should either filter or surface a
	//                        success-only proxy (e.g. KnockMs +
	//                        TokenValidateMs) for SLO panels.
	//   *TokenValidateMs   — RTT to qurl-service /internal/v1/resolve.
	//   *CatalogResolveMs  — catalog routing resolution after token validate
	//                        (NHP-owned (aspId, q_resId) lookup, #2540).
	//                        Cache-hit p50 is sub-ms; a fresh-mint miss adds
	//                        one DynamoDB GetItem.
	//   *KnockMs           — sum of knock attempts including retries.
	//   *KnockAttemptMs    — single attempt; diff vs KnockMs = retry cost.
	//   *Success           — successful resolve + knock + redirect.
	//   *FailValidate      — token rejected (invalid, expired, revoked).
	//   *FailResolveCatalog — token validated, but AC routing could not be
	//                        resolved from the NHP catalog (miss or lookup
	//                        error) before the knock (#2540). Pre-knock, so
	//                        like FailValidate it never exercises the retry
	//                        loop and is NOT in the KnockRetry denominator. A
	//                        sustained non-zero rate during the #2540 rollout
	//                        means qurl-service is not publishing q_ catalog
	//                        rows (upsertNHPCatalogForToken) the plugin now
	//                        requires — the load-bearing rollout-ordering
	//                        signal, graphed on the "Resolve Outcomes" panel of
	//                        qurl-operations.json (a CloudWatch alarm is tracked
	//                        in #2577). Fails closed: never falls back to the
	//                        qurl-service response body's routing.
	//   *FailKnock         — knock exhausted MaxAttempts retries (and
	//                        only that). Calls counted here exercised
	//                        the retry policy — that's what makes them
	//                        the legitimate FailKnock denominator for
	//                        the retry-rate signal below.
	//   *FailPostKnock     — knock opened the firewall but the user could
	//                        not be redirected: AC returned no resource
	//                        hosts despite ackMsg=success, JWT secret
	//                        missing or unsignable, or cookie/redirect
	//                        URL refused. Distinguished from FailKnock
	//                        because the firewall hole IS open and the
	//                        retry loop never touched these calls —
	//                        operationally different blast radius and
	//                        accounting position.
	//   *FailCanceled      — request context was canceled (client
	//                        disconnected, write deadline elapsed) during
	//                        knock or its retry sleep. Distinguished from
	//                        FailKnock because the failure is downstream
	//                        of the user, not the server — including
	//                        these in the FailKnock denominator would
	//                        inflate the apparent server-failure rate
	//                        every time someone closes a tab mid-retry.
	//   *FailUnknown       — sentinel for return paths that don't set a
	//                        terminal outcome explicitly. Steady-state
	//                        zero. A non-zero value is a regression
	//                        signal — a new return path was added
	//                        without an outcome assignment — and surfaces
	//                        loud rather than being silently absorbed
	//                        into one of the real outcome counters.
	//   *KnockRetry        — fires once each time the loop decides to
	//                        retry (i.e., once per failure that is NOT
	//                        the last attempt).
	//                        Retry rate per call =
	//                          KnockRetry / (Success + FailKnock)
	//                        Why FailValidate / FailPostKnock / FailCanceled
	//                        are NOT in the denominator: the knock loop
	//                        never attempted (validate rejected pre-knock,
	//                        client disconnected pre/mid-retry) or had
	//                        already succeeded (post-knock failure). Only
	//                        Success + FailKnock count call attempts that
	//                        exercised the retry policy.
	// Keep the terminal outcome set below in sync with
	// terraform/modules/monitoring/main.tf
	// (aws_cloudwatch_metric_alarm.qurl_browser_rejected_ratio). That alarm's
	// denominator intentionally includes Success plus every Fail* outcome;
	// adding another terminal outcome without updating Terraform inflates the
	// rejected-field ratio. The alarm currently uses 8 of CloudWatch
	// PutMetricAlarm's 10 MetricStat slots plus 2 of its 10 Expression slots,
	// so any new terminal outcome also has to re-check metric-math headroom.
	MetricQurlResolveDurationMs         = "QurlResolveDurationMs"
	MetricQurlResolveTokenValidateMs    = "QurlResolveTokenValidateMs"
	MetricQurlResolveCatalogResolveMs   = "QurlResolveCatalogResolveMs"
	MetricQurlResolveKnockMs            = "QurlResolveKnockMs"
	MetricQurlResolveKnockAttemptMs     = "QurlResolveKnockAttemptMs"
	MetricQurlResolveSuccess            = "QurlResolveSuccess"
	MetricQurlResolveFailValidate       = "QurlResolveFailValidate"
	MetricQurlResolveFailResolveCatalog = "QurlResolveFailResolveCatalog"
	MetricQurlResolveFailKnock          = "QurlResolveFailKnock"
	MetricQurlResolveFailPostKnock      = "QurlResolveFailPostKnock"
	MetricQurlResolveFailCanceled       = "QurlResolveFailCanceled"
	MetricQurlResolveFailUnknown        = "QurlResolveFailUnknown"
	MetricQurlResolveKnockRetry         = "QurlResolveKnockRetry"
	// QURL browser-side navigation timings — RUM-class data posted by
	// the qurl.link interstitial as additional form fields on the same
	// resolve POST. Values originate in the user's browser via
	// PerformanceNavigationTiming; they are advisory, not authoritative.
	// Use them for hop attribution during investigations; page on the
	// server-observed QurlResolve*Ms set above and on CloudFront
	// OriginLatency for the qurl.link / resolve.qurl.link distributions.
	//
	// Trust gate: timings are parsed after ValidateAccessToken's
	// permissive character-class + length check (8–512 bytes;
	// unicode.IsLetter || IsDigit || '-' || '_' || '.') but BEFORE
	// resolver.Resolve. Any sender that can produce a string passing
	// that gate (scanners, replay attempts, revoked tokens) lands in
	// the parse path — there is no real-qURL gate. The parse is
	// intentionally placed early so CDN/edge issues that ultimately
	// fail the resolve are still attributable. The cap-then-drop +
	// rejected-counter design is the only adversary defense here:
	//   - Range cap [0, 60000 ms] + explicit NaN guard. Without the
	//     guard NaN slips both range checks because every NaN
	//     comparison is false in IEEE 754, and ParseFloat("NaN", 64)
	//     returns (NaN, nil). Out-of-range or unparseable values
	//     increment QurlResolveBrowserRejected* and are dropped, so
	//     adversarial floods become a counter signal rather than
	//     histogram contamination.
	//   - Two counters rather than one with a dimension because the
	//     helper.IncrCounter callback only accepts a name.
	//     CloudWatch alarms live in terraform/modules/monitoring/main.tf
	//     as aws_cloudwatch_metric_alarm.qurl_browser_rejected_ratio:
	//     `${name_prefix}-${cell_id}-qurl-browser-rejected-malformed-ratio`
	//     and `${name_prefix}-${cell_id}-qurl-browser-rejected-out-of-range-ratio`.
	//     They alarm on rejected-count / QurlResolve{Success,Fail*} ratio, not
	//     raw rejected count, because one request can carry up to six forged
	//     timing fields.
	//   - No cross-field coherence check. The natural candidate
	//     (submitReadyMs >= domInteractive) is inverted under W3C HTML
	//     parsing semantics: the parser executes <script> synchronously
	//     while readyState is still "loading", then resumes parsing,
	//     then sets readyState to "interactive" — so an inline script
	//     captures performance.now() before nav.domInteractive is set.
	//     Field-level forgery is the only thing the parse path defends
	//     against; coherence belongs at the frontend if it belongs
	//     anywhere.
	// Histogram p* readings are dominated by honest traffic when redeem
	// rate >> scanner rate. During low-traffic windows honest sample
	// volume can drop low enough that even a small adversarial cohort
	// distorts the p*; cross-reference the server-observed metrics
	// before acting on browser histograms in those windows.
	//
	// p99 is structurally bounded above by the 60s cap. The slowest
	// honest cohort (2G, captive portals, suspended tabs) lands on
	// QurlResolveBrowserRejectedOutOfRange rather than the histogram
	// tail. The rejected counter still surfaces them; the histogram
	// just doesn't reach beyond 60s.
	//
	// Duplicate-key handling: gin.Context.PostForm returns only the
	// first value when a key appears multiple times in the form body.
	// A client sending t_dns_ms=10&t_dns_ms=NaN records 10 and ignores
	// the NaN. Acceptable for an advisory metric — the attacker gains
	// nothing vs. sending NaN alone (which the NaN guard catches).
	//
	// Phase split follows the W3C Resource Timing partition. TCP =
	// secureConnectionStart - connectStart when secure, TLS = connectEnd
	// - secureConnectionStart. The naive connectEnd - connectStart
	// actually measures TCP+TLS combined.
	//
	// Frontend contract: each phase is OMITTED from the form when
	// PerformanceNavigationTiming reports it as zero (cache hit, reused
	// connection). The server treats 0 as a structurally allowed value
	// — frontends MUST NOT send 0 to mean "phase didn't happen," or the
	// histograms accumulate zeros with no rejected-counter signal.
	MetricQurlResolveBrowserDNSMs            = "QurlResolveBrowserDNSMs"
	MetricQurlResolveBrowserTCPMs            = "QurlResolveBrowserTCPMs"
	MetricQurlResolveBrowserTLSMs            = "QurlResolveBrowserTLSMs"
	MetricQurlResolveBrowserTTFBMs           = "QurlResolveBrowserTTFBMs"
	MetricQurlResolveBrowserDOMInteractiveMs = "QurlResolveBrowserDOMInteractiveMs"
	// Name implies "time until form submission" but actually measures
	// script-readiness latency (navigation start → token validated +
	// RESOLVE_URL constructed). The frontend captures it BEFORE the
	// 500ms UX-spinner setTimeout, so the metric is NOT pinned to that
	// floor. Dashboard consumers reading the name in isolation will
	// under-count actual time-to-submit by ~500ms; the captured value
	// is the more useful "what could a faster build achieve" signal.
	// See terraform/modules/qurl-link/frontend/index.html's submitReadyMs
	// capture site for the canonical explanation.
	MetricQurlResolveBrowserTimeToSubmitMs     = "QurlResolveBrowserTimeToSubmitMs"
	MetricQurlResolveBrowserRejectedMalformed  = "QurlResolveBrowserRejectedMalformed"
	MetricQurlResolveBrowserRejectedOutOfRange = "QurlResolveBrowserRejectedOutOfRange"
	// MetricQurlV2RevocationHashError fires when the qURL v2 admission path
	// (buildV2ResourceData) fails to hash a VERIFIED claim key into its
	// revocation-index digest. The keys already decoded during VerifyClaims, so
	// this should be unreachable; if it ever fires, the admission still completes
	// (we do not fail an already-committed, one-time-use admission over
	// revocation-INDEX metadata — see buildV2ResourceData), but the resulting
	// flow lands with an empty hash and is therefore invisible to P4b's targeted
	// revocation, downgrading it to scheduled timer-wheel expiry only. A single
	// log line is easy to miss in aggregate, so this counter makes the
	// decode/hash regression alertable: a non-zero rate means admitted v2 flows
	// are silently becoming un-revocable-by-key. Emitted on the knock-path helper
	// (NewNhpServerHelper binds IncrCounter), so it is live on the real v2 path.
	MetricQurlV2RevocationHashError = "QurlV2RevocationHashError"
	// MetricQurlV2CommitHashDrift fires on the first-knock commit path when the
	// qurl_user_public_key_hash qurl-service echoed in the prepare response
	// diverges from the hash NHP recomputes locally for the AC revocation index.
	// Both are hex(sha256(base64url key)) by contract, so a non-zero rate means the
	// cross-repo hash preimage has drifted: commit still succeeds (the echoed value
	// locates the state row) but targeted user-key revocation would silently miss.
	// A metric (not just the log) makes that latent, security-relevant drift
	// alertable rather than reliant on someone reading logs.
	MetricQurlV2CommitHashDrift = "QurlV2CommitHashDrift"
	// MetricLicenseValidationRateLimited fires from BOTH call sites:
	// the hoisted preflight check (closes the F5 amplification
	// surface) AND the deeper in-validateACLicense check. It's the
	// aggregate signal — operators tracking total rate-limited AOL
	// volume read this counter. Both emissions go through
	// CheckRateLimit so a single rate-limited packet fires the
	// counter exactly once.
	//
	// MetricLicenseValidationRateLimitedAtPreflight is the
	// preflight-only split, so an operator can tell whether a
	// LicenseValidationRateLimited spike during the F5 burn-in is
	// the new hoist behavior catching shared-NAT noise (preflight
	// counter rises) or a real attack pattern hitting the deeper
	// check too (gap between the two counters narrows). Both fire
	// for the same packet at the preflight site (so preflight
	// counter <= aggregate counter); the difference is the spike
	// signature.
	MetricLicenseValidationRateLimited            = "LicenseValidationRateLimited"
	MetricLicenseValidationRateLimitedAtPreflight = "LicenseValidationRateLimitedAtPreflight"
	// MetricASGFilterFailOpen fires when filterServersByASG would
	// fail open (every Cloud Map server is cross-color). Emitted from
	// two sites: autoAssignAC (accepts the fail-open list because no
	// assignment is worse than cross-color) and maybeGrowAssignedServers
	// (refuses to grow because durable cross-color contamination is
	// worse than no growth). Operators triaging dashboard spikes should
	// pair this with new-AC volume vs. AC re-registration volume to
	// distinguish initial-assign noise from grow-time deploy windows.
	MetricASGFilterFailOpen = "ASGFilterFailOpen"

	// MetricTransactionClosed counts every SendMessage / SendPacket
	// call that returns common.ErrTransactionClosed because the
	// RemoteTransaction exited between FindRemoteTransaction and the
	// channel send. Post PR #1096 this is the observable rate of the
	// race that used to panic the server; a sudden spike is a
	// regression signal worth alarming on.
	MetricTransactionClosed = "TransactionClosed"

	// MetricServerStartupEvent fires once per server process start,
	// emitted via CloudWatch Embedded Metric Format (EMF). The Go
	// server writes a JSON line to stdout at startup; docker's
	// awslogs driver ships it to the nhp-server stderr log group,
	// and CloudWatch auto-extracts the metric into LayerV/NHP.
	//
	// Emitted in two dim-set variants (see recordServerStartup):
	// a per-instance series (Environment/Cell/InstanceId, used by
	// dashboards and ad-hoc investigation) and a fleet-wide series
	// (Environment/Cell, drives the server_instance_restart alarm
	// via a classic Sum-over-5min threshold).
	MetricServerStartupEvent = "ServerStartupEvent"

	// MetricAgentLookupDDBError fires once per knock that rejects
	// because the qurl-agent-keys DDB Query returned a transient
	// error (throttle, 5xx, network, malformed-row). Kept distinct
	// from MetricAuthFailure so the auth-failures alarm
	// (terraform/modules/monitoring/main.tf::auth_failures) doesn't
	// page on-call for what is actually an infrastructure event —
	// ops can distinguish "auth policy rejected the agent" from
	// "DDB is unhealthy". An ErrAgentUnknownPubkey reject (agent
	// genuinely not registered) still goes through MetricAuthFailure
	// because that IS an auth-policy outcome.
	//
	// Counter semantics under singleflight piggyback: this counter
	// is NOT gated like MetricAgentFirstResolve. When N concurrent
	// callers piggyback on the same singleflight slot and the
	// underlying DDB Query returns an error, all N receive the same
	// wrapped error and each increments this counter. So a sustained
	// throttle event on a hot-spot pubkey produces ~N× the counter
	// value vs. the underlying DDB-call count, where N is the
	// concurrent-piggybacker count. This is intentional — every
	// caller did experience the reject — but alarm thresholds that
	// expect "1 increment per failed DDB call" need to budget for
	// the piggyback multiplier under bursty load. ErrAgentUnknownPubkey
	// (MetricAuthFailure) has the same fanout characteristic.
	MetricAgentLookupDDBError = "AgentLookupDDBError"

	// MetricAgentFirstResolve fires once per successful first-knock
	// agent resolve through the qurl-agent-keys DDB lookup. The
	// rate is the canonical signal that the writer side
	// (qurl-service) is actually populating qurl-agent-keys in
	// steady state: a sustained zero with non-zero KnockRequest
	// volume means cloud-mode agents are being rejected because
	// the registry is silent, not because the lookup is broken.
	// Doesn't fire on the cache-warm short-circuit path — once a
	// peer is in agentPeerMap, the subsequent knock-success is
	// counted by MetricAuthSuccess downstream.
	//
	// Single-counting under singleflight piggyback: N concurrent
	// first-knocks for the same fresh pubkey deduplicate through
	// AgentPeerLookup.sfGroup and all reach AddAgentPeer; only the
	// caller that actually wins the agentPeerMap insertion
	// increments this counter (resolveAgentPeerForKnock gates on
	// AddAgentPeer's returned `added bool`). Without this gate the
	// counter inflates ~N× under concurrent first-knock bursts —
	// the writer-side liveness signal this metric provides would
	// then be distorted by request shape rather than reflecting
	// real resolve volume.
	//
	// Dashboard caveat: in steady state most agent knocks are
	// cache-warm and do NOT increment this counter, so a naive
	// MetricAgentFirstResolve / MetricKnockRequest ratio reads
	// extremely low. The intended use is the absolute rate
	// (resolves per unit time as a writer-side liveness signal)
	// and the unknown / DDB-error ratios against the same time
	// window. If a future panel wants a "resolve as fraction of
	// knock" view, it needs to add MetricAuthSuccess into the
	// numerator to capture the warm-knock case.
	MetricAgentFirstResolve = "AgentFirstResolve"

	// MetricAgentLookupPubkeyCollision fires once per agent-peer
	// lookup that finds more than one owner on the pubkey-index GSI
	// for the same public_key. qurl-service #488/PR #1037 enforces
	// one-owner-per-pubkey at write time, so a non-zero value means
	// legacy duplicate data, manual table mutation, or writer
	// invariant regression.
	// The resolver rejects fail-closed with
	// event="agent_lookup_pubkey_collision" rather than admitting an
	// arbitrary row.
	MetricAgentLookupPubkeyCollision = "AgentLookupPubkeyCollision"

	// MetricAgentLookupPubkeyCandidateOverflow fires once per
	// agent-peer lookup whose pubkey-index candidate set exceeds the
	// resolver's bounded inspection cap. This is separate from
	// MetricAgentLookupPubkeyCollision so alarms can distinguish a
	// true cross-owner key collision from a same-owner duplicate or
	// orphan-row set that grew too large to prove safe in one bounded
	// read. The resolver rejects fail-closed with
	// event="agent_lookup_pubkey_candidate_overflow".
	MetricAgentLookupPubkeyCandidateOverflow = "AgentLookupPubkeyCandidateOverflow"

	// MetricAgentLookupSchemaMismatch fires when the qurl-agent-keys
	// row declares a schema_version this nhp-server build does not
	// understand. This is the structural
	// writer/reader contract guard for the cross-repo DynamoDB boundary:
	// additive columns require no bump; renames/removals or semantic
	// changes require a version bump and a reader deploy that explicitly
	// accepts it. Legacy rows with no schema_version are version 0 and
	// remain accepted during rollout; explicit unknown versions reject
	// fail-closed and page this metric.
	//
	// Counter semantics under singleflight piggyback: the counter is
	// incremented inside AgentPeerLookup by the singleflight winner, so
	// N concurrent first-knocks for the same mismatched pubkey reject
	// N callers but produce one schema-mismatch increment for that
	// resolve window.
	MetricAgentLookupSchemaMismatch = "AgentLookupSchemaMismatch"

	// MetricAgentLookupInitFailure fires once at server startup
	// when NewAgentPeerLookupFromStorage returns an error.
	// Reachable today on:
	//   - ErrAgentLookupStorageWrapperCycle: the storage decorator
	//     chain hit unwrapMaxHops without finding *DynamoDBStorage
	//     (cycle or chain-too-deep). The factory propagates the
	//     error rather than silently returning (nil, nil) so this
	//     metric covers a real failure mode that would otherwise
	//     disable the agent path with no signal.
	//   - Future failure modes added to NewAgentPeerLookup itself
	//     (e.g. validating the DDB client at construction). The
	//     LRU constructor today only fails on size <= 0 and the
	//     size constant is positive, so that branch is
	//     unreachable — kept as a fence so a future change that
	//     adds a real failure mode surfaces loudly.
	//
	// Why a metric and not just a log: a Warning-only boot in
	// cloud mode looks identical to a healthy boot until the
	// first agent knock fails at the responder layer with no
	// MetricAgentLookupDDBError to alarm on (the lookup never
	// ran). This metric closes the gap so an operator can alarm
	// on "MetricAgentLookupInitFailure >= 1" and catch the
	// silent-fallback failure mode the responder rejects would
	// otherwise hide.
	MetricAgentLookupInitFailure = "AgentLookupInitFailure"

	// MetricAgentLookupNotConfigured fires once at server startup
	// when cloud mode is on (storage_backend=dynamodb) AND the
	// agent peer lookup never wired AND no init error fired —
	// i.e., the (nil, nil) "disabled by config" branch from
	// NewAgentPeerLookupFromStorage (AgentKeysTable unset in
	// storage.toml, storage backend missing, etc).
	//
	// MUTUALLY EXCLUSIVE with MetricAgentLookupInitFailure: that
	// metric catches the (nil, error) branch (wrapper cycle, future
	// init failure modes). The udpserver.go emit site gates this
	// metric on `!agentLookupInitFailed` so a single boot fires
	// exactly one of the two — alarm posture for each assumes
	// single-cause attribution. A double-emit would inflate the
	// page count and conflate failure modes.
	//
	// Both failure modes look identical on the wire (every agent
	// knock rejects at the responder layer because agentPeerMap
	// pre-validation has nothing to match) and neither emits
	// MetricAgentLookupDDBError (the lookup never ran). Without
	// this counter, the cloud-mode-with-empty-AgentKeysTable case
	// boots with just an Info line and looks identical to a
	// healthy boot in dashboards — until the first agent knock
	// fails.
	//
	// Alarm posture: "MetricAgentLookupNotConfigured >= 1 in cloud
	// envs" — fires on the first deploy where the tfvar plumbing
	// regressed. Stays at 0 for legitimate etcd / file-config
	// deployments because cloud mode is off.
	MetricAgentLookupNotConfigured = "AgentLookupNotConfigured"

	// MetricResourceLookupCacheHit fires once per knock where
	// ResourceLookup.LookupAuthServiceProvider served the aspData
	// from the LRU (within TTL) without a DDB Query. Dashboards
	// alongside MetricResourceLookupCacheMiss show the live
	// hit-ratio so an unexpected cache-miss storm (TTL too short,
	// LRU thrashing under multi-aspId load) is visible.
	MetricResourceLookupCacheHit = "ResourceLookupCacheHit"

	// MetricResourceLookupCacheMiss fires once per successful
	// ResourceLookup DDB Query that populated the cache. Steady-state
	// rate is bounded by the cache TTL × distinct aspIds knocked;
	// a sustained increase decoupled from new-aspId deployments
	// indicates LRU eviction pressure (today the cache is sized
	// well above the active aspId count, so this should stay near
	// zero outside the cache-warm window after a process restart).
	MetricResourceLookupCacheMiss = "ResourceLookupCacheMiss"

	// MetricResourceLookupDDBError fires once per knock that rejects
	// because the nhp_resources DDB Query returned a transient
	// error. Mirrors MetricAgentLookupDDBError's role/posture for
	// the agent-peer lookup: kept distinct from MetricAuthFailure
	// so the auth-failures alarm doesn't page on-call for what is
	// actually an infrastructure event. ErrResourceUnknownASP
	// (genuinely no rows for the requested aspId) routes through
	// MetricAuthFailure because that IS an auth-policy outcome.
	//
	// Counter semantics under singleflight piggyback: same fanout
	// shape as MetricAgentLookupDDBError — all N piggybackers receive
	// the same wrapped error and each increments.
	MetricResourceLookupDDBError = "ResourceLookupDDBError"

	// MetricInternalKnockResourceNotFound fires when an authenticated
	// /nhp/internal/knock request reaches an ASP catalog but the
	// requested resourceId is absent. The HTTP response stays opaque
	// ("not found") to avoid an enumeration oracle; this counter gives
	// operators the missing-resource signal without widening the wire body.
	MetricInternalKnockResourceNotFound = "InternalKnockResourceNotFound"

	// MetricResourceLookupMalformedRow fires once per row that the
	// resolver had to skip during a cache-miss iteration. The counter
	// is overloaded across four semantically distinct trigger
	// conditions — operators triaging a non-zero rate should grep the
	// structured-log Warning for the cause:
	//
	//   - UnmarshalMap failed: writer wrote a row with a field type
	//     drift (string-where-int, missing required field). Remediation:
	//     reconcile terraform's `aws_dynamodb_table_item.frps_nhp_resource`
	//     (terraform/resources.tf) with the Go Resource struct
	//     (endpoints/server/storage.go::Resource).
	//   - Empty resource_id: writer wrote a row missing the SK. The
	//     SK is required at table level so this shouldn't reach the
	//     reader, but defensive in case of a future schema change or
	//     a hand-edited row. Remediation: identify the writer that
	//     emitted the empty-SK row and fence it server-side.
	//   - Empty resource_fqdn: writer omitted the public dial host the
	//     agent receives in the ACK. Remediation: reconcile the DDB
	//     seed writer's `resource_fqdn` with ResourceInfo.Hostname.
	//   - port_suffix=true with out-of-range dest_port: writer asked
	//     the ACK to include a public port suffix but emitted no usable
	//     1..65535 port. Remediation: fix the DDB seed row before
	//     agents dial a bare hostname and hide the broken suffix contract.
	//
	// All four are structurally writer-side regressions of similar
	// alarm urgency. A sustained non-zero value is evidence the
	// terraform writer and the Go reader have drifted apart.
	//
	// Alarm-sizing caveat: this metric fires INSIDE the per-row loop
	// in queryAndCache, and every cache-miss re-Queries the full
	// partition, so the steady-state rate is roughly
	// (malformed_row_count × cache_miss_rate × active_aspIds), not
	// (malformed_row_count). With the 60s cache TTL, a single
	// persistent malformed row produces ~1 emit/60s per distinct
	// aspId in active use. The agent-peer analog
	// (MetricAgentLookupDDBError on ErrAgentLookupMalformedRow)
	// aborts on first malformed row and fires at most once per
	// failed Query — a very different alarm-sizing posture. Operators
	// copying agent-peer thresholds will under-alarm for this counter
	// by a factor proportional to row count.
	MetricResourceLookupMalformedRow = "ResourceLookupMalformedRow"

	// MetricResourceLookupCrossPartition fires when DDB returns a
	// row whose customer_id doesn't match the partition the resolver
	// asked for. Today the KeyConditionExpression constrains the
	// query so this is unreachable; the counter exists for the
	// defense-in-depth fence at queryAndCache (a future regression
	// in the query expression — typo, missing :cid substitution,
	// AWS SDK quirk — could let cross-partition rows leak).
	//
	// Split out from MetricResourceLookupMalformedRow so the alarm
	// threshold can be `> 0`. A cross-partition row in a
	// per-tenant schema (the eventual #1976 evolution) would be a
	// potential cross-tenant correctness bug — different alarm
	// urgency than "writer emitted a row with a field type drift."
	MetricResourceLookupCrossPartition = "ResourceLookupCrossPartition"

	// MetricResourceLookupPagination fires when DDB returns a Query
	// response with LastEvaluatedKey != nil (i.e., results past
	// page 1 are silently dropped). Today the system partition holds
	// a handful of rows and won't approach the 1MB page boundary; a
	// future per-tenant schema with a large partition would surface
	// here.
	//
	// Split out from MetricResourceLookupDDBError so the infra-trouble
	// alarm stays clean of "operationally-successful but truncated"
	// events. A non-zero rate means the resolver's catalog view is
	// incomplete — operators should either expand the partition to
	// real pagination (#2120) or split the partition.
	MetricResourceLookupPagination = "ResourceLookupPagination"

	// MetricResourceLookupInitFailure fires once at server startup
	// when NewResourceLookupFromStorage returns an error. Mirrors
	// MetricAgentLookupInitFailure's role/posture: catches the
	// loud-failure path (storage decorator wrapper cycle today;
	// future init failure modes added to NewResourceLookup) so a
	// silent boot in cloud mode doesn't look healthy until the
	// first knock fails with no DDB-error counter to alarm on.
	MetricResourceLookupInitFailure = "ResourceLookupInitFailure"

	// MetricResourceLookupNotConfigured fires once at server startup
	// when cloud mode is on AND the resource lookup never wired AND
	// no init error fired — the (nil, nil) "disabled by config"
	// branch from NewResourceLookupFromStorage (ResourcesTable
	// unset in storage.toml, storage backend missing, etc.).
	//
	// MUTUALLY EXCLUSIVE with MetricResourceLookupInitFailure — same
	// single-cause-attribution posture as the agent-peer pair.
	MetricResourceLookupNotConfigured = "ResourceLookupNotConfigured"

	// MetricResourceLookupAspMismatch fires when DDB returns a row
	// whose `auth_service_id` doesn't match the aspId the resolver
	// asked for. Today the server-side FilterExpression
	// (`auth_service_id = :asp`) constrains the query so this
	// branch is unreachable; the counter exists for the
	// defense-in-depth fence at queryAndCache (a future regression
	// in the filter expression — typo, missing :asp substitution,
	// AWS SDK quirk, or a writer that bypasses the filter — could
	// let mismatched rows leak).
	//
	// Split out from MetricResourceLookupMalformedRow so the alarm
	// is INTENDED for a `> 0` threshold once wired: a mismatched
	// aspId means a knock for aspId X gets resources from aspId Y
	// in its ack — potential cross-aspId routing bug — different
	// urgency than "writer emitted a row with a field type drift."
	// No TF alarm references this metric today (consistent with
	// every other MetricResourceLookup* sibling — none have TF-side
	// wiring; alarms are presumably auto-discovered via the metric
	// stream or wired manually). Adding alarms for the four
	// MetricResourceLookup* defense-in-depth counters (AspMismatch,
	// CrossPartition, MalformedRow, Pagination) is operational
	// follow-up work, not code work.
	MetricResourceLookupAspMismatch = "ResourceLookupAspMismatch"

	// MetricResourceLookupDirectAspMismatch fires when exact resource_id
	// lookup finds a row but its auth_service_id does not match the requested
	// aspId. Unlike MetricResourceLookupAspMismatch, this is not a Query
	// FilterExpression regression; it points at a producer writing a direct
	// row under the wrong auth service.
	//
	// Single-counting under direct-resource singleflight: this and the other
	// direct producer-regression counters below fire inside the winning DDB
	// lookup. N concurrent knocks for the same bad qURL token produce N
	// MetricInternalKnockResourceNotFound increments, but only one producer
	// regression increment; repeated knocks inside the 1s direct negative-cache
	// window also reuse the reject without re-counting. Alarm posture should
	// stay `> 0` rather than interpreting the direct counters as per-knock
	// rates.
	MetricResourceLookupDirectAspMismatch = "ResourceLookupDirectAspMismatch"

	// MetricResourceLookupMissingDirectTTL fires when exact resource_id lookup
	// finds a direct row without the app-level ttl required for qURL dynamic
	// resources. This is a producer-contract regression, distinct from generic
	// malformed static catalog rows.
	MetricResourceLookupMissingDirectTTL = "ResourceLookupMissingDirectTTL"

	// MetricResourceLookupExpiredDirectRow fires when exact resource_id lookup
	// finds a row whose app-level ttl has elapsed. DynamoDB TTL deletion is
	// asynchronous, so the reader rejects expired direct rows before converting
	// them into knockable ResourceData.
	MetricResourceLookupExpiredDirectRow = "ResourceLookupExpiredDirectRow"
)

// Multi-AC broadcast observability metric names (issue #376).
const (
	MetricBroadcastTotal          = "BroadcastTotal"          // total broadcast invocations
	MetricBroadcastSuccess        = "BroadcastSuccess"        // at least one AC succeeded
	MetricBroadcastAllFail        = "BroadcastAllFail"        // every AC in the broadcast failed
	MetricBroadcastACLatencyMs    = "BroadcastACLatencyMs"    // per-AC operation duration within a broadcast
	MetricACConnsPerID            = "ACConnsPerID"            // gauge: max AC connections across all AC IDs
	MetricTotalACConns            = "TotalACConns"            // gauge: total AC connections across all AC IDs
	MetricACConnEviction          = "ACConnEviction"          // MaxACConnsPerID eviction events
	MetricAgentConnPerIPEvictions = "AgentConnPerIPEvictions" // MaxAgentConnsPerIP eviction events

	// MetricServerForwardTargetDrop counts outbound NHP_FWD connection
	// attempts dropped because the requested peer/tuple is not a configured
	// server-peer target or the tuple is already owned by a non-promotable
	// AC/DB/WebRTC connection. Steady state should be zero; a non-zero value
	// points at assignment/peer-map drift or a tuple-owner collision.
	MetricServerForwardTargetDrop = "ServerForwardTargetDrop"

	// MetricGlobalCapRejections counts new inbound packet admits and
	// outbound server-peer forward connection attempts rejected because
	// remoteConnectionMap is at the global MaxConcurrentConnection cap.
	// Emitted by globalCapAdmits and connDataForOutboundAddr on reject
	// paths after dropping the map mutex (see globalCapAdmits for the lock
	// discipline behind where the increment lands).
	//
	// Operator guidance: steady-state value is zero. MaxConcurrentConnection
	// (20480) sits far above any legitimate load, so a non-zero value is a
	// strong signal that something attack-shaped or misbehaved is hammering
	// the server. The counter auto-surfaces in CloudWatch via the publisher
	// flush loop (no registration needed); a `>= 1` single-event alarm is
	// deferred to #2563.
	MetricGlobalCapRejections = "GlobalCapRejections"

	// MetricHandlerBudgetExhausted counts agent-facing handler dispatches
	// shed because the MaxConcurrentHandlers goroutine budget was full
	// (see dispatchHandler). Steady-state value is zero: 4096 in-flight
	// handshake-class handlers is far above any legitimate concurrency,
	// so a non-zero value means the server is shedding knock-class work —
	// either a spoofed/distributed flood that bypasses the per-IP rate
	// limiter, or a stalled downstream (e.g. an unresponsive AC) keeping
	// handlers parked in-flight. The shed itself is graceful: the packet
	// is dropped and the agent retries, so this is a load/health signal,
	// not a correctness failure. Auto-surfaces in CloudWatch via the
	// publisher flush loop (no registration needed); a `>= 1` single-event
	// alarm is deferred to #3097 (sibling of MetricGlobalCapRejections'
	// #2563 — both are steady-state-zero DoS-shed detectors).
	MetricHandlerBudgetExhausted = "HandlerBudgetExhausted"

	// MetricHandlerProtectedReserveExhausted is the subset of handler sheds
	// where a cookie-proven RKN or authenticated relay envelope found both the
	// general partition and its protected reserve full.
	MetricHandlerProtectedReserveExhausted = "HandlerProtectedReserveExhausted"
	MetricHandlerInFlight                  = "HandlerInFlight"
	MetricHandlerProtectedInFlight         = "HandlerProtectedInFlight"
	MetricHandlerPressureOverload          = "HandlerPressureOverload"
	MetricUDPRateLimitDrop                 = "UDPRateLimitDrop"
	MetricPacketDecryptQueueDrop           = "PacketDecryptQueueDrop"
	MetricDecryptedMessageQueueDrop        = "DecryptedMessageQueueDrop"
	MetricPacketDecryptQueueDepth          = "PacketDecryptQueueDepth"
	MetricDecryptedMessageQueueDepth       = "DecryptedMessageQueueDepth"
	MetricRuntimeGoroutine                 = "RuntimeGoroutine"
	MetricRuntimeHeapAllocBytes            = "RuntimeHeapAllocBytes"

	// MetricACConnStaleFiltered counts AC connections skipped by the
	// broadcast-time staleness filter (DefaultStaleACConnThreshold or its
	// per-server override). A non-zero rate is expected during AC
	// reconnects (blue/green switch, EC2 refresh, NAT rebind); a sustained
	// rate against a healthy AC means the server is not clearing stale
	// entries on disconnect. Emitted once per call site per knock with the
	// dropped count (not once per dropped connection), so a single
	// broadcast filtering three stale entries adds 3.
	//
	// Operator guidance:
	//   - Burst spikes during deploys/refresh: expected, no action.
	//   - Sustained > N/min against a single AC ID for > 5 minutes outside
	//     a deploy window: investigate. The AC has likely rotated keys or
	//     IPs without a clean disconnect; check AC logs for recent
	//     re-registration events and CloudMap deregister history.
	//   - Threshold for an alarm depends on knock volume; suggest starting
	//     with "rate > 60/min sustained for 10 min" once a baseline exists.
	MetricACConnStaleFiltered = "ACConnStaleFiltered"
)

// udpCorrelationCtx creates a context with a correlation ID derived from UDP handler
// metadata (e.g. AC ID and NHP transaction ID). This enables storage log lines to be
// correlated with specific NHP transactions instead of showing req_id=-.
func udpCorrelationCtx(timeout time.Duration, id string, transactionId uint64) (context.Context, context.CancelFunc) {
	correlationID := fmt.Sprintf("udp-%s-%d", id, transactionId)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	return ContextWithRequestID(ctx, correlationID), cancel
}

// recordTransactionClosed increments MetricTransactionClosed iff err is
// the transaction-closed race (not ErrTransactionIdNotFound and not a
// random transport error). Single helper so every forward site that
// calls a Send*() helper emits the same counter under the same
// condition — callers never have to remember the errors.Is check.
func (s *UdpServer) recordTransactionClosed(err error) {
	if err != nil && s.metrics != nil && errors.Is(err, common.ErrTransactionClosed) {
		s.metrics.IncrCounter(MetricTransactionClosed)
	}
}

// recordServerStartup emits MetricServerStartupEvent as two EMF counter
// events: one with the InstanceId dim set (per-instance series, used
// by dashboards and ad-hoc incident investigation) and one without
// (fleet-wide series, drives the server_instance_restart alarm in
// terraform/modules/monitoring).
//
// Both fire from the publisher's EMF output (docker-captured stdout);
// CloudWatch auto-extracts them into LayerV/NHP. Called once per
// process start from Start() before plugin loading / listener setup
// so init crashes still register.
//
// The fleet-wide series is what the alarm consumes because AWS
// CloudWatch metric alarms reject the SEARCH expression ("SEARCH is
// not supported on Metric Alarms"), so a per-InstanceId metric_math
// alarm is not possible. ASG churn also rules out enumerating
// InstanceIds in TF. Fleet-wide sum + threshold tuned to fleet size
// is the only tractable form; per-instance resolution is available
// from the other series for investigation only.
//
// No-ops when InstanceID is empty (IMDS unreachable at boot) or
// when the publisher is unavailable (non-cloud local testing). The
// log-filter panic alarm still covers Go runtime panics that bypass
// this path -- those can't EMF-emit because the process is already
// dying.
func (s *UdpServer) recordServerStartup() {
	instanceID := s.InstanceID()
	if instanceID == "" || s.metrics == nil {
		return
	}
	s.metrics.EmitEMFCounterNow(MetricServerStartupEvent, []types.Dimension{
		{Name: dimNameInstanceId, Value: aws.String(instanceID)},
	})
	s.metrics.EmitEMFCounterNow(MetricServerStartupEvent, nil)
}

// forwardToTransaction finds the remote transaction and forwards the message to it.
// Returns common.ErrTransactionIdNotFound if the transaction is not available,
// or common.ErrTransactionClosed if the transaction exited between lookup and
// delivery.
//
// Log format follows the codebase convention: component(id#txn@addr)[handler] message
func (s *UdpServer) forwardToTransaction(connData *core.ConnectionData, transactionId uint64, md *core.MsgData, component, handler, id, addrStr string) error {
	transaction := connData.FindRemoteTransaction(transactionId)
	if transaction == nil {
		log.Error("%s(%s#%d@%s)[%s] transaction is not available", component, id, transactionId, addrStr, handler)
		return common.ErrTransactionIdNotFound
	}
	if err := transaction.SendMessage(md); err != nil {
		log.Error("%s(%s#%d@%s)[%s] transaction closed before message could be forwarded: %v", component, id, transactionId, addrStr, handler, err)
		s.recordTransactionClosed(err)
		return err
	}
	return nil
}

// makeMsgData creates a MsgData for sending a response back through the
// same connection that delivered the request.
func makeMsgData(ppd *core.PacketParserData, headerType int, msg []byte) *core.MsgData {
	return &core.MsgData{
		HeaderType:     headerType,
		TransactionId:  ppd.SenderTrxId,
		Compress:       true,
		PrevParserData: ppd,
		Message:        msg,
	}
}

// HandleOTPRequest
// Server will not respond to agent's otp request
//
// Fire-and-forget per the CSA NHP spec: the server never replies to an OTP.
// Native UDP and WebRTC connection dispatch enter here; relay dispatch calls
// dispatchOTP directly with its synthetic inner ppd. When the Connector
// composition is configured, exact registration is accepted only from native
// UDP and silently rejected on every non-direct ingress before generic dispatch.
func (s *UdpServer) HandleOTPRequest(ppd *core.PacketParserData) (err error) {
	s.wg.Add(1)
	defer s.wg.Done()
	return s.dispatchOTP(ppd)
}

// dispatchOTP first applies the Connector lifecycle ingress gate for every
// caller. With the composition configured, exact Connector registration takes
// the strict handler on native UDP; relay, WebRTC, unknown, and future ingress
// are silently rejected. Requests not claimed as Connector registration
// continue through the generic core: parse AgentOTPMsg, apply the pre-plugin
// limiter, resolve the plugin, and call RequestOTP. The function never sends a
// reply and returns only an error for the caller to log and swallow.
//
// ppd must carry a decrypted OTP body plus the Noise-authenticated RemotePubKey
// (the direct path has both from the responder; the relay path's synthetic
// decrypt populates both — see decryptRelayInnerKnock).
func (s *UdpServer) dispatchOTP(ppd *core.PacketParserData) error {
	if handled, strictErr := s.handleConnectorRegistrationOTP(ppd); handled {
		return strictErr
	}
	transactionId := ppd.SenderTrxId
	addrStr := ppd.ConnData.RemoteAddr.String()

	otpMsg := &common.AgentOTPMsg{}
	if err := json.Unmarshal(ppd.BodyMessage, otpMsg); err != nil {
		log.Error("server-agent(#%d@%s)[HandleOTPRequest] failed to parse %s message: %v", transactionId, addrStr, core.HeaderTypeToString(ppd.HeaderType), err)
		return err
	}

	// Same population as the register path below: the Noise-authenticated
	// initiator static key, std-base64 like every other pubKey field. Also the
	// rate-limiter key (defense-in-depth against per-key OTP/email floods).
	agentPubkey := base64.StdEncoding.EncodeToString(ppd.RemotePubKey)

	if !s.allowOTPRequest(ppd, agentPubkey) {
		return nil
	}

	// Ensure the plugin for this aspId is loaded before resolving it. Unlike the
	// knock path (which loads via updateResources / the DDB resolve bridge on
	// knock), the OTP/REG dispatch calls FindPluginHandler DIRECTLY — a plain map
	// read that does NOT trigger a lazy load — so without this an agent's very
	// first OTP (before any knock warmed the plugin) would find no handler.
	// Idempotent per-aspId sync.Once; a no-op once loaded.
	s.loadPluginOnce(otpMsg.AuthServiceId, "")

	handler := s.FindPluginHandler(otpMsg.AuthServiceId)
	if handler == nil {
		return common.ErrAuthHandlerNotFound
	}

	otpReq := &common.NhpOTPRequest{
		Msg:       otpMsg,
		PublicKey: agentPubkey,
		RawBody:   bytes.Clone(ppd.BodyMessage),
		SrcAddr: &common.NetAddress{
			Ip:   ppd.ConnData.RemoteAddr.IP.String(),
			Port: ppd.ConnData.RemoteAddr.Port,
		},
	}

	// aspData=nil for OTP/Register/List paths: the plugins backing
	// these flows (passcode, OIDC) carry their own SDK-backed
	// resourceHandler and don't read helper.AspData. The host server's
	// aspMap is plumbed through only for the knock path today.
	if err := handler.RequestOTP(otpReq, s.NewNhpServerHelper(ppd, nil)); err != nil {
		// Redact the identity in the error log: usrId is now a key id (an agent
		// self-registers before it is a known user), so log the truncated
		// pubkey rather than the client-chosen UserId. See pubkeyLogPrefix.
		log.Error("server-agent(key=%s#%d@%s)[HandleOTPRequest] error: %v", pubkeyLogPrefix(agentPubkey), transactionId, addrStr, err)
		return err
	}

	log.Info("server-agent(key=%s#%d@%s)[HandleOTPRequest] succeeded", pubkeyLogPrefix(agentPubkey), transactionId, addrStr)
	return nil
}

// allowOTPRequest keeps the peer-key admission gate shared by the strict qURL
// Connector OTP path and generic plugin OTP path. It deliberately depends only
// on the Noise-authenticated peer, never a body credential or client identity.
// agentPubkey is the std-base64 inner device key the caller already derived
// (the limiter key), passed in so the hot path does not re-encode it per OTP.
func (s *UdpServer) allowOTPRequest(ppd *core.PacketParserData, agentPubkey string) bool {
	if s.otpRateLimiter == nil {
		return true
	}
	if s.otpRateLimiter.Allow(agentPubkey) {
		return true
	}
	// DUAL-PUBLISH the shed metric (cf. relay recordShed): the launch-blocking
	// alarm selects on {Environment} only, while the ordinary publisher carries
	// [Environment, Cell]. Keep both fixed-dimension streams.
	s.metrics.IncrCounterExplicitDims(MetricOTPRejectRateLimited, buildServerEnvDimension())
	s.metrics.IncrCounter(MetricOTPRejectRateLimited)
	addrStr := ""
	if ppd.ConnData != nil && ppd.ConnData.RemoteAddr != nil {
		addrStr = ppd.ConnData.RemoteAddr.String()
	}
	log.Warning("server-agent(key=%s#%d@%s)[HandleOTPRequest] OTP rate limited; dropping",
		pubkeyLogPrefix(agentPubkey), ppd.SenderTrxId, addrStr)
	return false
}

// HandleRegisterRequest
// Server will respond with success or error with NHP_RAK message
//
// Native UDP and WebRTC connection dispatch enter here. With the Connector
// composition configured, exact registration takes the strict handler only on
// native UDP and is silently rejected on WebRTC. Remaining generic requests
// build a RAK through buildRegisterAck and deliver it through the connection's
// real transaction. Generic relay REG that survives the same ingress gate also
// shares buildRegisterAck, then diverts its reply through an authenticated
// RelayReturnMsg. Configured Connector registration over relay never reaches it.
func (s *UdpServer) HandleRegisterRequest(ppd *core.PacketParserData) (err error) {
	s.wg.Add(1)
	defer s.wg.Done()
	if handled, strictErr := s.handleDirectConnectorRegistration(ppd, connectorRegistrationActivation); handled {
		return strictErr
	}

	transactionId := ppd.SenderTrxId
	addrStr := ppd.ConnData.RemoteAddr.String()

	rakBytes, buildErr := s.buildRegisterAck(ppd)
	if buildErr != nil {
		// Marshal failure only — a plugin/auth reject is carried IN the ack
		// bytes (fail-closed errCode), not returned as buildErr. Nothing to
		// deliver, so drop.
		log.Error("server-agent(key=%s#%d@%s)[HandleRegisterRequest] failed to build RAK: %v",
			pubkeyLogPrefix(base64.StdEncoding.EncodeToString(ppd.RemotePubKey)), transactionId, addrStr, buildErr)
		return buildErr
	}

	rakMd := makeMsgData(ppd, core.NHP_RAK, rakBytes)
	if fwdErr := s.forwardToTransaction(ppd.ConnData, transactionId, rakMd, "server-agent", "HandleRegisterRequest",
		pubkeyLogPrefix(base64.StdEncoding.EncodeToString(ppd.RemotePubKey)), addrStr); fwdErr != nil {
		return fwdErr
	}
	return nil
}

// buildRegisterAck runs the register plugin-dispatch core — parse
// AgentRegisterMsg → load + resolve the agent plugin → RegisterAgent → marshal
// the ServerRegisterAckMsg — and returns the NHP_RAK body bytes. Shared by the
// direct generic path and generic relayed REG that passed the Connector
// lifecycle ingress gate. Configured strict Connector registration is handled
// before this helper and never reaches it over relay.
//
// FAIL-CLOSED ACK CONTRACT: the returned error is ONLY a marshal failure (drop,
// nothing to send). Every logical failure — parse error, no handler, or a plugin
// error — is instead encoded IN the returned ack bytes with a populated ErrCode,
// so the agent always receives a decryptable RAK carrying a verdict rather than a
// silent timeout. In particular, with the agent plugin still stubbed (N3
// pending) RegisterAgent returns ErrPluginNotRegistered and this yields a RAK
// whose ErrCode is the mapped fail-closed code (registerErrToCode) — the
// inertness N2 relies on.
//
// PublicKey is populated with base64.StdEncoding.EncodeToString(ppd.RemotePubKey)
// exactly as before, so a registration plugin can bind the credential to the
// Noise-authenticated agent key rather than to spoofable message fields.
func (s *UdpServer) buildRegisterAck(ppd *core.PacketParserData) ([]byte, error) {
	transactionId := ppd.SenderTrxId
	addrStr := ppd.ConnData.RemoteAddr.String()
	agentPubkey := base64.StdEncoding.EncodeToString(ppd.RemotePubKey)

	regMsg := &common.AgentRegisterMsg{}
	rakMsg := &common.ServerRegisterAckMsg{}

	func() {
		if err := json.Unmarshal(ppd.BodyMessage, regMsg); err != nil {
			log.Error("server-agent(#%d@%s)[HandleRegisterRequest] failed to parse %s message: %v", transactionId, addrStr, core.HeaderTypeToString(ppd.HeaderType), err)
			rakMsg.ErrCode = common.ErrJsonParseFailed.ErrorCode()
			rakMsg.ErrMsg = err.Error()
			return
		}

		// Load the plugin before resolving it: the OTP/REG dispatch calls
		// FindPluginHandler directly (a plain map read, no lazy load), unlike the
		// knock path — see dispatchOTP for the full rationale. Idempotent.
		s.loadPluginOnce(regMsg.AuthServiceId, "")

		handler := s.FindPluginHandler(regMsg.AuthServiceId)
		if handler == nil {
			rakMsg.ErrCode = common.ErrAuthHandlerNotFound.ErrorCode()
			rakMsg.ErrMsg = common.ErrAuthHandlerNotFound.Error()
			return
		}

		regReq := &common.NhpRegisterRequest{
			Msg:       regMsg,
			Ack:       rakMsg,
			PublicKey: agentPubkey,
			RawBody:   bytes.Clone(ppd.BodyMessage),
			SrcAddr: &common.NetAddress{
				Ip:   ppd.ConnData.RemoteAddr.IP.String(),
				Port: ppd.ConnData.RemoteAddr.Port,
			},
		}

		ack, regErr := handler.RegisterAgent(regReq, s.NewNhpServerHelper(ppd, nil))
		if regErr != nil {
			// Fail closed: keep a non-nil ack carrying a mapped errCode so the
			// agent gets a verdict, never a nil/`null` RAK. The plugin may (N3)
			// return a populated ack alongside the error; prefer it, else fall
			// back to the pre-populated rakMsg and stamp the mapped code.
			if ack != nil {
				rakMsg = ack
			}
			if common.IsSuccessErrCode(rakMsg.ErrCode) {
				rakMsg.ErrCode = registerErrToCode(regErr).ErrorCode()
				rakMsg.ErrMsg = regErr.Error()
			}
			log.Error("server-agent(key=%s#%d@%s)[HandleRegisterRequest] error: %v", pubkeyLogPrefix(agentPubkey), transactionId, addrStr, regErr)
			return
		}
		if ack != nil {
			rakMsg = ack
		}

		log.Info("server-agent(key=%s#%d@%s)[HandleRegisterRequest] succeeded", pubkeyLogPrefix(agentPubkey), transactionId, addrStr)
	}()

	rakBytes, marshalErr := json.Marshal(rakMsg)
	if marshalErr != nil {
		log.Error("server-agent(key=%s#%d@%s)[HandleRegisterRequest] failed to marshal RAK message: %v", pubkeyLogPrefix(agentPubkey), transactionId, addrStr, marshalErr)
		return nil, marshalErr
	}
	return rakBytes, nil
}

// registerErrToCode maps a plugin RegisterAgent error to a fail-closed
// registration errCode for the RAK. A *common.Error already carries its own code
// (used verbatim). Everything else — notably plugins.ErrPluginNotRegistered (a
// bare errors.New that the N3-pending agent stub returns) — maps to
// ErrRegistrationDisabled: "self-registration is administratively switched off
// for this server/service", which is the honest state until N3 lands. The point
// is that the agent always receives a concrete registration errCode rather than a
// silent drop or a success sentinel.
func registerErrToCode(err error) *common.Error {
	var ce *common.Error
	if errors.As(err, &ce) {
		return ce
	}
	return common.ErrRegistrationDisabled
}

// HandleListRequest responds with a success or fail-closed NHP_LRT message.
// Logical generic-list failures are protocol verdicts carried by that LRT, so
// successful delivery returns nil on both direct and relayed paths. Exact qURL
// Connector registration-completion intents are intercepted before generic list
// dispatch and silently rejected on non-direct ingress. Only failures that
// prevent building or delivering the LRT are returned to dispatchHandler, whose
// sole use of the error is logging; it drives no metric or control decision.
// dispatchReceivedMessage is the only production caller and uses that wrapper;
// future callers must treat a delivered LRT as the result and reserve the Go
// error for verdict-construction or transport failure.
func (s *UdpServer) HandleListRequest(ppd *core.PacketParserData) (err error) {
	s.wg.Add(1)
	defer s.wg.Done()

	// qURL Connector post-RAK completion is owned by the strict assigned-cell
	// handler before either recovery routing or permissive ListService dispatch.
	if handled, strictErr := s.handleDirectConnectorRegistration(ppd, connectorRegistrationCompletion); handled {
		return strictErr
	}

	// Post-registration Connector resource discovery is an exact, strict
	// registered-agent LST/LRT operation. Keep it ahead of recovery and generic
	// ListService so malformed claimed requests cannot escape to permissive plugin
	// decoding and ordinary recovery remains on its disjoint query.
	if handled, strictErr := s.handleDirectConnectorResource(ppd); handled {
		return strictErr
	}

	// Assigned-cell credential recovery is a direct-UDP-only capability. This
	// branch must stay before buildListResult: that shared plugin seam is also
	// reachable from HandleRelayForward, clones secret-bearing RawBody, and
	// round-trips results through generic JSON structs.
	if lrtBytes, handled, deadline, classification, recoveryErr := s.buildDirectCredentialRecoveryResult(ppd); handled {
		if recoveryErr != nil {
			s.recordCredentialRecoveryOutcome(classification)
			return recoveryErr
		}
		// Keep the same receipt-anchored absolute deadline through the final
		// transaction handoff. The response is intentionally not cleared here:
		// successful SendMessageContext transfers it to asynchronous NHP response
		// ownership.
		if forwardErr := s.forwardCredentialRecoveryToTransaction(ppd, lrtBytes, deadline); forwardErr != nil {
			if errors.Is(forwardErr, errCredentialRecoveryDeadline) {
				classification = connectorcell.ClassificationDeadlineRejected
			} else {
				classification = connectorcell.ClassificationInternalFailure
			}
			s.recordCredentialRecoveryOutcome(classification)
			return forwardErr
		}
		s.recordCredentialRecoveryOutcome(classification)
		return nil
	}

	lrtBytes, userID, resultErr := s.buildListResult(ppd)
	if lrtBytes == nil {
		return resultErr
	}
	ackMd := makeMsgData(ppd, core.NHP_LRT, lrtBytes)
	if fwdErr := s.forwardToTransaction(ppd.ConnData, ppd.SenderTrxId, ackMd, "server-agent", "HandleListRequest", userID, ppd.ConnData.RemoteAddr.String()); fwdErr != nil {
		return fwdErr
	}
	// A logical list failure is carried in the fail-closed LRT bytes. Once the
	// verdict is delivered, returning resultErr would make dispatchHandler log a
	// second handler failure even though the request completed successfully.
	// dispatchHandler does not derive a metric or control decision from the
	// returned error; buildListResult already logs the exact logical failure.
	return nil
}

// buildListResult runs the generic LST plugin dispatch and marshals its LRT
// verdict. Direct traffic forwards the bytes through its transaction;
// HandleRelayForward encrypts the same bytes for the agent and wraps them in an
// authenticated RelayReturnMsg. Configured Connector registration completion
// is intercepted before this helper. Logical failures still produce an LRT; a
// nil byte slice means the LRT itself could not be marshaled.
func (s *UdpServer) buildListResult(ppd *core.PacketParserData) ([]byte, string, error) {
	transactionId := ppd.SenderTrxId
	addrStr := ppd.ConnData.RemoteAddr.String()
	lstMsg := &common.AgentListMsg{}
	lrtMsg := &common.ServerListResultMsg{}
	var resultErr error

	func() {
		resultErr = json.Unmarshal(ppd.BodyMessage, lstMsg)
		if resultErr != nil {
			log.Error("server-agent(#%d@%s)[HandleListRequest] failed to parse %s message: %v", transactionId, addrStr, core.HeaderTypeToString(ppd.HeaderType), resultErr)
			lrtMsg.ErrCode = common.ErrJsonParseFailed.ErrorCode()
			lrtMsg.ErrMsg = resultErr.Error()
			return
		}

		handler := s.FindPluginHandler(lstMsg.AuthServiceId)
		if handler == nil {
			resultErr = common.ErrAuthHandlerNotFound
			lrtMsg.ErrCode = common.ErrAuthHandlerNotFound.ErrorCode()
			lrtMsg.ErrMsg = resultErr.Error()
			return
		}

		agentPubkey := base64.StdEncoding.EncodeToString(ppd.RemotePubKey)
		listReq := &common.NhpListRequest{
			Msg:       lstMsg,
			Ack:       lrtMsg,
			PublicKey: agentPubkey,
			RawBody:   bytes.Clone(ppd.BodyMessage),
			SrcAddr: &common.NetAddress{
				Ip:   ppd.ConnData.RemoteAddr.IP.String(),
				Port: ppd.ConnData.RemoteAddr.Port,
			},
		}

		pluginLRT, pluginErr := handler.ListService(
			listReq, s.NewNhpServerHelper(ppd, nil),
		)
		if pluginLRT != nil {
			lrtMsg = pluginLRT
		}
		if pluginErr != nil {
			resultErr = pluginErr
			// Empty is a protocol success code. When a plugin returns (nil, err),
			// the zero-valued lrtMsg therefore enters this branch and receives the
			// mandatory fail-closed code instead of being marshaled as success.
			if common.IsSuccessErrCode(lrtMsg.ErrCode) {
				lrtMsg.ErrCode = listErrToCode(pluginErr).ErrorCode()
				lrtMsg.ErrMsg = pluginErr.Error()
			}
			log.Error("server-agent(%s#%d@%s)[HandleListRequest] error: %v", lstMsg.UserId, transactionId, addrStr, pluginErr)
			return
		}
		if pluginLRT == nil {
			resultErr = errors.New("list plugin returned nil result")
			lrtMsg.ErrCode = listErrToCode(resultErr).ErrorCode()
			lrtMsg.ErrMsg = resultErr.Error()
			log.Error("server-agent(%s#%d@%s)[HandleListRequest] error: %v", lstMsg.UserId, transactionId, addrStr, resultErr)
			return
		}

		log.Info("server-agent(%s#%d@%s)[HandleListRequest] succeeded", lstMsg.UserId, transactionId, addrStr)
	}()

	lrtBytes, marshalErr := json.Marshal(lrtMsg)
	if marshalErr != nil {
		log.Error("server-agent(%s#%d@%s)[HandleListRequest] failed to marshal LRT message: %v", lstMsg.UserId, transactionId, addrStr, marshalErr)
		return nil, lstMsg.UserId, marshalErr
	}
	return lrtBytes, lstMsg.UserId, resultErr
}

// listErrToCode maps plugin errors that do not carry an NHP error code to the
// existing fail-closed "auth handler unavailable" verdict. A plugin-provided
// *common.Error remains authoritative and is preserved verbatim.
func listErrToCode(err error) *common.Error {
	var ce *common.Error
	if errors.As(err, &ce) {
		return ce
	}
	return common.ErrAuthHandlerNotFound
}

func (s *UdpServer) HandleACOnline(ppd *core.PacketParserData) (err error) {
	s.wg.Add(1)
	defer s.wg.Done()

	regStart := time.Now()
	transactionId := ppd.SenderTrxId
	addrStr := ppd.ConnData.RemoteAddr.String()
	aolMsg := &common.ACOnlineMsg{}

	err = common.DecodeACOnlineMsg(ppd.BodyMessage, aolMsg)
	if err != nil {
		log.Error("server-ac(#%d@%s)[HandleACOnline] failed to parse %s message: %v", transactionId, addrStr, core.HeaderTypeToString(ppd.HeaderType), err)
		s.metrics.IncrCounter(MetricACRegistrationFailure)
		return err
	}

	acId := aolMsg.ACId
	if strings.TrimSpace(acId) == "" {
		log.Warning("server-ac(#%d@%s)[HandleACOnline] rejecting AC online with empty ACId", transactionId, addrStr)
		s.sendACOnlineRejectAAK(ppd, transactionId, common.ErrServerACOpsFailed, acId, addrStr, "missing-ac-id")
		return common.ErrServerACOpsFailed
	}
	// Preserve non-empty ACId verbatim. Storage, acConnectionMap, and target
	// lookups all key on the configured string; trimming here would be a live
	// ungated identity change rather than a malformed-empty reject.

	cloudMode := s.storageConfig != nil && s.storageConfig.Backend == StorageBackendDynamoDB
	if cloudMode && (!common.ValidNHPACBootID(aolMsg.BootID) ||
		aolMsg.SessionFlushGeneration == 0 || !aolMsg.SessionFlushComplete) {
		log.Warning("server-ac(%s#%d@%s)[HandleACOnline] rejecting cloud AC before boot flush readiness", acId, transactionId, addrStr)
		s.sendACOnlineRejectAAK(ppd, transactionId, common.ErrACSessionControlNotReady, acId, addrStr, "session-control-not-ready")
		return common.ErrACSessionControlNotReady
	}

	// Check if AC should be redirected to its assigned servers (per-AC server assignment).
	// This only applies when storage is configured and AC provides a license key.
	// See docs/design/PLUGGABLE_STORAGE_BACKEND.md section 6.2 for details.
	//
	// TODO(#1541): handleACServerAssignment runs BEFORE the rate-limit
	// hoist below and calls GetACAssignment unconditionally when
	// LicenseKey != "". CachedStorage doesn't cache NotFound, so an
	// attacker spamming AOL with a non-empty LicenseKey + unknown
	// acId can drive one DDB read per packet through this path —
	// the F5 hoist closes the empty-LicenseKey amplification but not
	// this one. Tracked as a hardening follow-up.
	var assignedPeers []common.RedirectTarget
	if s.storage != nil && aolMsg.LicenseKey != "" {
		redirected, peers, ardErr := s.handleACServerAssignment(ppd, aolMsg, transactionId, addrStr)
		if ardErr != nil {
			log.Error("server-ac(%s#%d@%s)[HandleACOnline] server assignment lookup error: %v", acId, transactionId, addrStr, ardErr)
			if IsACAssignmentAuthorityError(ardErr) {
				s.sendACOnlineRejectAAK(ppd, transactionId, common.ErrServerACOpsFailed, acId, addrStr, "candidate-assignment-authority")
				return ardErr
			}
			// Fall through to direct registration on error
		} else if redirected {
			// AC was redirected via NHP_ARD to its assigned servers
			return nil
		} else {
			assignedPeers = peers
		}
		// This server is assigned to handle this AC, continue with registration
	}

	// Register AC connection and send NHP_AAK
	acPubkeyBase64 := base64.StdEncoding.EncodeToString(ppd.RemotePubKey)
	s.acPeerMapMutex.Lock()
	acPeer := s.acPeerMap[acPubkeyBase64] // recvAddr updated by responder.go (unless cloud mode, see below)
	s.acPeerMapMutex.Unlock()

	// In cloud mode (storage_backend=dynamodb), AC peers are not pre-registered.
	// We need to validate the AC via license check and create the peer dynamically.
	// See docs/design/PLUGGABLE_STORAGE_BACKEND.md Section 6.2 for details.
	// #1157 F3 pre-check. Authoritative F3 gate runs inside the
	// acConnectionMapMutex.Lock() further below; pre-fix that path was
	// only reached AFTER validateACLicense (bcrypt) and AddACPeer in
	// cloud mode, so a strict reject leaked the attacker's pubkey into
	// acPeerMap permanently AND paid bcrypt cost per attack packet.
	// The pre-check fixes both. Gated on cloudMode + strict-mode so we
	// don't pay an RLock+alloc on every NHP_AOL during permit-mode
	// rollout or non-cloud deployments. See ac_pubkey_cap_gate.go.
	//
	// Permit-mode trade-off: with acPubkeyCapVerifyRequire=false the
	// pre-check is skipped, so the burn-in window preserves every
	// pre-fix attack surface — FIFO eviction still works, attacker
	// pubkeys still leak into acPeerMap permanently, bcrypt is still
	// paid per attack packet. Permit mode buys observability (metric
	// + log via the in-lock check), nothing else. Operators must
	// flip acPubkeyCapVerifyRequire=true to land actual protection;
	// staying in permit indefinitely is a security regression
	// disguised as a careful rollout. See PR description rollout
	// section + #1514 acceptance criteria.
	//
	// Trade-off: a snapshot taken outside the lock can see "cap
	// exceeded" when a concurrent removeACConnectionRecord is about to
	// bring the count back below cap. The result is a rare, transient
	// strict-mode reject that the AC's transaction-retry loop absorbs.
	if cloudMode && s.acPubkeyCapVerifyRequire {
		s.acConnectionMapMutex.RLock()
		preCheckPubkeys := extractPubkeysFromConns(s.acConnectionMap[acId])
		s.acConnectionMapMutex.RUnlock()
		preVerdict, preDistinct := verifyACPubkeyCap(acPubkeyBase64, preCheckPubkeys, MaxACConnsPerID)
		if preVerdict == verdictACPubkeyCapExceeded {
			_, capRejectErr := s.applyACPubkeyCapVerdict(preVerdict, acId, acPubkeyBase64, preDistinct, transactionId, addrStr)
			// Mirror validateACLicense rejects in feeding the license
			// rate limiter — see TestHandleACOnline_F3StrictReject_FeedsLicenseRateLimiter.
			s.recordLicenseFailure(addrStr, acId)
			s.sendACOnlineRejectAAK(ppd, transactionId, capRejectErr, acId, addrStr, "cap-reject")
			return capRejectErr
		}
	}

	// #1507 F5 pubkey-revocation pre-check. Runs before
	// validateACLicense so a revoked pubkey doesn't pay bcrypt cost
	// (same no-bcrypt-on-attack invariant as F3). The lookup runs
	// in permit mode too — operators rely on the metric as the
	// rollout signal, so gating it on strict (as F3 does) would
	// silence the very signal the rollout window depends on. See
	// ac_pubkey_revoke_gate.go for threat model and storage-error
	// policy.
	//
	// Rate-limit hoist: CachedStorage does not cache NotFound, so
	// an attacker spamming AOL with random unknown acIds and empty
	// LicenseKey would otherwise drive one DDB read per packet via
	// F5 before validateACLicense's rate-limiter threw them out.
	// Hoisting CheckRateLimit BEFORE F5's lookup caps per-source
	// DDB cost at MaxFailuresPerIP. The hoist runs on every
	// cloudMode AOL — including the acPeer != nil re-registration
	// path that previously skipped rate-limiting entirely. That's
	// deliberate: a source IP the rate limiter is throttling is the
	// right population to throttle on re-register too, AND
	// re-registration is the precise moment a revocation must take
	// effect. validateACLicense keeps its own check as a redundant
	// safety net — DO NOT remove this hoist on the assumption that
	// the deeper check covers it: removing the hoist re-opens the
	// per-packet DDB amplification surface for unknown acIds.
	// Fenced by TestHandleACOnline_F5RateLimitHoist_SkipsLookupOnRateLimited.
	//
	// handleACServerAssignment above also calls GetACAssignment
	// (gated on LicenseKey != ""); that path is pre-existing and
	// not covered by this hoist — tracked as #1541.
	if cloudMode {
		if s.licenseRateLimiter != nil {
			if rlErr := s.licenseRateLimiter.CheckRateLimit(addrStr, acId); rlErr != nil {
				// Tag as [ac-online/preflight] — this is a
				// rate-limiter reject, not an F5 reject.
				log.Warning("server-ac(%s#%d@%s)[ac-online/preflight] %s",
					acId, transactionId, addrStr, rlErr.Message)
				s.metrics.IncrCounter(MetricLicenseValidationRateLimited)
				s.metrics.IncrCounter(MetricLicenseValidationRateLimitedAtPreflight)
				s.sendACOnlineRejectAAK(ppd, transactionId, common.ErrServerACOpsFailed, acId, addrStr, "rate-limited")
				return common.ErrServerACOpsFailed
			}
		}
		f5Ctx, f5Cancel := udpCorrelationCtx(DefaultStorageTimeout, acId, transactionId)
		f5Verdict := s.evaluateACPubkeyRevokeVerdict(f5Ctx, acId, acPubkeyBase64, transactionId, addrStr)
		// Inline cancel after the lookup — the ctx is not used past
		// this point. udpCorrelationCtx uses context.WithTimeout
		// which arms a time.AfterFunc; defer-until-function-return
		// would leave that timer pending through validateACLicense
		// (bcrypt), the in-lock F3 check, AddACPeer, and the rest of
		// registration. Inline cancel disarms the timer at the
		// natural boundary.
		f5Cancel()
		f5Proceed, f5RejectErr := s.applyACPubkeyRevokeVerdict(f5Verdict, acId, acPubkeyBase64, transactionId, addrStr)
		if !f5Proceed {
			// Feed the license rate limiter on a real revocation
			// reject so an attacker burning a stolen pubkey against a
			// revoked entry is throttled by the same per-source /
			// per-acId throttle as F3 / validateACLicense rejects. Do
			// NOT feed it on the fail-closed default branch
			// (ErrACPubkeyRevokedInternal): that error fires only
			// when a future verdict constant is added but not
			// registered in applyACPubkeyRevokeVerdict's switch — a
			// server-side dispatch-table bug. Coupling that signal to
			// the rate limiter would dilute the
			// LicenseValidationRateLimited alarm with bug-driven
			// throttling and mislead an operator into reading "spike
			// during a 52020 storm" as attacker activity.
			if errors.Is(f5RejectErr, common.ErrACPubkeyRevoked) {
				s.recordLicenseFailure(addrStr, acId)
			}
			s.sendACOnlineRejectAAK(ppd, transactionId, f5RejectErr, acId, addrStr, "revoke-reject")
			return f5RejectErr
		}
	}

	if acPeer == nil && cloudMode {
		// Validate AC license before accepting connection.
		//
		// #1155 invariant: the last arg MUST be the base64 form of
		// ppd.RemotePubKey — the same value already computed above
		// into acPubkeyBase64. The pubkey-binding gate inside
		// validateACLicense uses this value to look up
		// License.BoundPubKeys; passing the wrong string (e.g.,
		// acId, or a hostname) would silently bypass the gate for
		// all registrations — the attack break would be gone and
		// no test in license_pubkey_gate_test.go would catch it
		// because those tests call validateACLicense directly with
		// a matching literal. A future refactor that moves this
		// call site or changes the signature MUST preserve the
		// "last arg = base64(ppd.RemotePubKey)" contract. See
		// follow-up #1266 for the smoke Tier 2 test that would
		// fence this at the integration layer.
		validationErr := s.validateACLicense(ppd, aolMsg, transactionId, addrStr, acPubkeyBase64)
		if validationErr != nil {
			s.sendACOnlineRejectAAK(ppd, transactionId, validationErr, acId, addrStr, "license-validation")
			return validationErr
		}

		// License valid - create peer from packet data and add to peer pool
		acPeer = &core.UdpPeer{
			Hostname:     acId,
			Ip:           ppd.ConnData.RemoteAddr.IP.String(),
			Port:         ppd.ConnData.RemoteAddr.Port,
			PubKeyBase64: acPubkeyBase64,
			ExpireTime:   0, // No expiration - managed via keepalives
			Type:         core.NHP_AC,
		}
		// Initialize recvAddr from the current packet. Normally this is done by
		// responder.go during packet validation, but in cloud mode peer validation
		// is disabled (DisableACPeerValidation=true) so we must do it here.
		// Without this, processACOperation fails with nil peer address.
		acPeer.UpdateRecv(ppd.LocalInitTime, ppd.ConnData.RemoteAddr)
		log.Info("server-ac(%s#%d@%s)[HandleACOnline] Cloud mode: created AC peer after license validation; publishing after ACConn append", acId, transactionId, addrStr)
	} else if acPeer != nil && cloudMode {
		// Stage a replacement peer instead of mutating the already-published
		// pointer. Durable target registration and every remaining admission gate
		// below may still fail. Updating the shared peer here would let a rejected
		// or stale AOL redirect live AOP traffic to an address that never became an
		// authoritative ACConn. The staged peer is published only after the
		// acConnectionMap replacement commits; non-cloud responder.go continues to
		// own its existing peer-address update path.
		oldRecvAddr := acPeer.RecvAddr()
		acPeer = &core.UdpPeer{
			Hostname:     acId,
			Ip:           ppd.ConnData.RemoteAddr.IP.String(),
			Port:         ppd.ConnData.RemoteAddr.Port,
			PubKeyBase64: acPubkeyBase64,
			ExpireTime:   0,
			Type:         core.NHP_AC,
		}
		acPeer.UpdateRecv(ppd.LocalInitTime, ppd.ConnData.RemoteAddr)
		if oldRecvAddr != nil && oldRecvAddr.String() != ppd.ConnData.RemoteAddr.String() {
			log.Info("server-ac(%s#%d@%s)[HandleACOnline] Staged peer recvAddr replacement from %s",
				acId, transactionId, addrStr, oldRecvAddr.String())
		}
	}

	acConn := &ACConn{
		ConnData:        ppd.ConnData,
		ACPeer:          acPeer,
		ACCipherScheme:  ppd.CipherScheme,
		ACId:            acId,
		ServiceId:       aolMsg.AuthServiceId,
		Apps:            aolMsg.ResourceIds,
		BootID:          aolMsg.BootID,
		FlushGeneration: aolMsg.SessionFlushGeneration,
	}

	var aakMd *core.MsgData
	if cloudMode {
		// Marshal the complete success AAK before the first durable activation.
		// After ActivateTarget commits, this admission must never be canceled:
		// enqueue failure is recovered by the AC's idempotent AOL retry while the
		// target remains ACTIVE.
		var marshalErr error
		aakMd, marshalErr = s.successfulACOnlineAckMsgData(ppd, aolMsg, assignedPeers)
		if marshalErr != nil {
			log.Error("server-ac(%s#%d@%s)[HandleACOnline] failed to marshal AAK message: %v", acId, transactionId, addrStr, marshalErr)
			s.metrics.IncrCounter(MetricACRegistrationFailure)
			return marshalErr
		}
	}

	var releaseAdmission func()
	var targetCtx context.Context
	var activation *acSessionControlTargetActivationResult
	var attachment *sessionControlTargetAttachment
	if cloudMode {
		var targetCancel context.CancelFunc
		targetBudget := DefaultStorageTimeout
		if s.sessionControlAOLBudget > 0 {
			targetBudget = s.sessionControlAOLBudget
		}
		targetCtx, targetCancel = udpCorrelationCtx(targetBudget, acId, transactionId)
		defer targetCancel()
		var admissionLockErr error
		releaseAdmission, admissionLockErr = s.acquireACSessionControlAdmission(targetCtx, acId)
		if admissionLockErr != nil {
			s.sendACOnlineRejectAAK(ppd, transactionId, common.ErrACSessionControlNotReady, acId, addrStr, "session-control-serialization")
			return common.ErrACSessionControlNotReady
		}
		defer releaseAdmission()

		// The per-target write gate excludes an AOP's final ready-check/enqueue
		// section across the complete authority transition. It nests after the
		// per-AC admission serializer, and neither bookkeeping mutex is held while
		// waiting or while store/network work runs.
		releaseAuthority, authorityGateErr := s.acquireACSessionControlAuthorityWrite(targetCtx, acConn)
		if authorityGateErr != nil {
			s.sendACOnlineRejectAAK(ppd, transactionId, common.ErrACSessionControlNotReady, acId, addrStr, "session-control-authority-busy")
			return common.ErrACSessionControlNotReady
		}
		defer releaseAuthority()

		// Lock order is per-AC admission -> per-owner write -> cell read. The
		// cell gate remains held through catch-up, durable readiness authorization,
		// AAK enqueue, and local publication so a same-process close preparation
		// cannot advance CONTROL across this publication boundary.
		releaseCell, cellGateErr := s.acquireSessionControlCellRead(targetCtx)
		if cellGateErr != nil {
			s.sendACOnlineRejectAAK(ppd, transactionId, common.ErrACSessionControlNotReady, acId, addrStr, "session-control-cell-busy")
			return common.ErrACSessionControlNotReady
		}
		defer releaseCell()

		candidate := sessionControlTargetCandidate{
			ACID: acId, PublicKey: acPubkeyBase64, BootID: acConn.BootID,
			FlushGeneration: acConn.FlushGeneration, ControlCellID: s.sessionControlCellID,
		}
		// A READY exact physical AC process is global authority shared by all
		// assigned servers. Another server attaches to that candidate without
		// Prepare/version churn: drain any pending exact work, catch up CONTROL,
		// enqueue AAK, then atomically condition-check TARGET+OWNER+DIRECTORY below.
		// New boot/generation and non-ready recovery retain the ordinary
		// Prepare->Activate->Finalize state machine.
		existingTargetDrained := false
		currentTarget, currentTargetErr := s.sessionControlStore.GetTarget(targetCtx,
			sessionControlTargetKey{ACID: acId, PublicKey: acPubkeyBase64})
		if currentTargetErr == nil && currentTarget != nil && currentTarget.exactCandidate(candidate) &&
			currentTarget.State == sessionControlTargetActive && currentTarget.CountedActiveSlot &&
			currentTarget.ActivatedControlVersion > 0 && currentTarget.RetiredAtMillis == 0 {
			if drainErr := s.drainACSessionControlTasksForTarget(targetCtx, acConn, *currentTarget, false); drainErr != nil {
				log.Error("server-ac(%s#%d@%s)[HandleACOnline] existing-target attachment task drain failed: %v",
					acId, transactionId, addrStr, drainErr)
				s.sendACOnlineRejectAAK(ppd, transactionId, common.ErrACSessionControlNotReady, acId, addrStr,
					"session-control-task-drain")
				return common.ErrACSessionControlNotReady
			}
			existingTargetDrained = true
			acConn.sessionControlTarget.Store(nil)
			if currentTarget.ready() {
				var attachErr error
				attachment, attachErr = s.catchUpReadyACSessionControlTarget(targetCtx, acConn, *currentTarget)
				if attachErr != nil {
					log.Error("server-ac(%s#%d@%s)[HandleACOnline] ready-target attachment catch-up failed: %v",
						acId, transactionId, addrStr, attachErr)
					s.sendACOnlineRejectAAK(ppd, transactionId, common.ErrACSessionControlNotReady, acId, addrStr,
						"session-control-attach")
					return common.ErrACSessionControlNotReady
				}
			} else {
				snapshot, _, catchUpErr := s.snapshotExistingACSessionControlTarget(targetCtx, acConn, *currentTarget)
				if catchUpErr != nil {
					log.Error("server-ac(%s#%d@%s)[HandleACOnline] active-unready target catch-up failed: %v",
						acId, transactionId, addrStr, catchUpErr)
					s.sendACOnlineRejectAAK(ppd, transactionId, common.ErrACSessionControlNotReady, acId, addrStr,
						"session-control-active-recovery")
					return common.ErrACSessionControlNotReady
				}
				if snapshot.DirectoryVersion == currentTarget.ActivatedControlVersion {
					for _, activeFence := range snapshot.Fences {
						if sendErr := s.sendACSessionControlFence(targetCtx, acConn, activeFence); sendErr != nil {
							log.Error("server-ac(%s#%d@%s)[HandleACOnline] active-unready exact-cursor catch-up failed: %v",
								acId, transactionId, addrStr, sendErr)
							s.sendACOnlineRejectAAK(ppd, transactionId, common.ErrACSessionControlNotReady, acId, addrStr,
								"session-control-active-recovery")
							return common.ErrACSessionControlNotReady
						}
					}
					// The existing ACTIVE_UNREADY transition already linearized against
					// this exact CONTROL cursor. A same-candidate server can authorize
					// publication through Finalize without Prepare/version churn; that
					// durable proof still precedes the success AAK enqueue below.
					activation = &acSessionControlTargetActivationResult{Target: *currentTarget, Snapshot: *snapshot}
				} else {
					// CONTROL advanced while the target was ACTIVE_UNREADY. The old
					// activated cursor cannot be finalized as current. Leave activation
					// unset so the ordinary Prepare->Activate path below owns the single
					// fence send and deliberately advances the durable cursor before AAK
					// publication.
					log.Info("server-ac(%s#%d@%s)[HandleACOnline] active-unready CONTROL cursor advanced from %d to %d; re-preparing exact candidate",
						acId, transactionId, addrStr, currentTarget.ActivatedControlVersion, snapshot.DirectoryVersion)
					reprepared, reprepareErr := s.sessionControlStore.ReprepareTargetForControlAdvance(targetCtx,
						sessionControlTargetControlAdvance{Target: *currentTarget, ObservedControlVersion: snapshot.DirectoryVersion})
					if reprepareErr != nil || reprepared == nil || !reprepared.RequiresActivation {
						log.Error("server-ac(%s#%d@%s)[HandleACOnline] active-unready CONTROL reprepare failed: %v",
							acId, transactionId, addrStr, reprepareErr)
						s.sendACOnlineRejectAAK(ppd, transactionId, common.ErrACSessionControlNotReady, acId, addrStr,
							"session-control-active-reprepare")
						return common.ErrACSessionControlNotReady
					}
					// Reprepare opens a new PREPARING interval. A task can be
					// materialized after the earlier ACTIVE drain and before Activate;
					// force the post-activation drain to snapshot/rebind that work.
					existingTargetDrained = false
					// The target is durably PREPARING now. Do not run the generic
					// pre-Prepare drain below against the stale ACTIVE row we first
					// observed; Activate carries any new OWNER counters forward and
					// the required post-activation drain owns that interval.
					currentTarget = nil
				}
			}
		} else if currentTargetErr != nil && !errors.Is(currentTargetErr, errSessionControlTargetNotFound) {
			log.Error("server-ac(%s#%d@%s)[HandleACOnline] current target read before task drain failed: %v",
				acId, transactionId, addrStr, currentTargetErr)
			s.sendACOnlineRejectAAK(ppd, transactionId, common.ErrACSessionControlNotReady, acId, addrStr,
				"session-control-task-authority")
			return common.ErrACSessionControlNotReady
		}

		if attachment == nil && activation == nil {
			// An ACTIVE_UNREADY exact retry may have pending work, and Prepare refuses
			// to version it until the authenticated process drains that inventory.
			if !existingTargetDrained && currentTargetErr == nil && currentTarget != nil && currentTarget.State == sessionControlTargetActive &&
				currentTarget.exactCandidate(candidate) {
				if drainErr := s.drainACSessionControlTasksForTarget(targetCtx, acConn, *currentTarget, false); drainErr != nil {
					log.Error("server-ac(%s#%d@%s)[HandleACOnline] pre-Prepare close-task drain failed: %v",
						acId, transactionId, addrStr, drainErr)
					s.sendACOnlineRejectAAK(ppd, transactionId, common.ErrACSessionControlNotReady, acId, addrStr,
						"session-control-task-drain")
					return common.ErrACSessionControlNotReady
				}
				acConn.sessionControlTarget.Store(nil)
			}
			var targetErr error
			activation, targetErr = s.activateACSessionControlTargetWithSnapshotAfterPrepare(targetCtx, acConn, func(sessionControlTargetPreparation) {
				// Only a successfully persisted PREPARING row revokes the current
				// connection's serving authority. In particular, a delayed lower-generation
				// AOL rejected by PrepareTarget cannot fence a newer ACTIVE connection.
				s.markACSessionControlConnectionNotReady(acId, acPubkeyBase64)
			})
			if targetErr != nil {
				log.Error("server-ac(%s#%d@%s)[HandleACOnline] session-control catch-up/activation failed: %v", acId, transactionId, addrStr, targetErr)
				s.sendACOnlineRejectAAK(ppd, transactionId, common.ErrACSessionControlNotReady, acId, addrStr, "session-control-authority")
				return common.ErrACSessionControlNotReady
			}
			if activation.AlreadyReady {
				attachment = &sessionControlTargetAttachment{
					Candidate: candidate, Target: activation.Target, Snapshot: activation.Snapshot,
				}
			}
			// A strictly newer AC process inherits the old process's pending close
			// tasks. Catch-up and Activate establish its durable target first; rebind,
			// strict REV/RVA, and ACK must then drain owner pending_count before the
			// success AAK can be published or FinalizeTargetReady can succeed.
			if !existingTargetDrained {
				if drainErr := s.drainACSessionControlTasksForTarget(targetCtx, acConn, activation.Target,
					!activation.ExistingActive); drainErr != nil {
					log.Error("server-ac(%s#%d@%s)[HandleACOnline] activated close-task drain failed: %v",
						acId, transactionId, addrStr, drainErr)
					s.sendACOnlineRejectAAK(ppd, transactionId, common.ErrACSessionControlNotReady, acId, addrStr,
						"session-control-task-rebind")
					return common.ErrACSessionControlNotReady
				}
			}
			if attachment != nil {
				activation = nil
			}
		}
		// Activation is durable, but this connection remains ineligible until the
		// exact durable publication proof below succeeds and the success AAK enters
		// the authenticated remote transaction.
		acConn.sessionControlAuthorityReady.Store(false)

		// Prove durable readiness before publishing a success AAK. No fallible
		// authority operation may follow the AAK: otherwise the AC can accept the
		// success, renew its global session-control lease, and advertise ready even
		// though this server subsequently removes the local connection. The live
		// DynamoDB attribute names retain aak_enqueued_* for schema compatibility;
		// in this ordering they audit authorization to publish this exact AAK.
		if attachment != nil {
			verifyCtx, verifyCancel := context.WithTimeout(context.WithoutCancel(targetCtx), DynamoDBOperationTimeout)
			verified, verifyErr := s.sessionControlStore.VerifyReadyTargetAttachment(verifyCtx, *attachment)
			verifyCancel()
			if verifyErr != nil || verified == nil || *verified != attachment.Target {
				log.Error("server-ac(%s#%d@%s)[HandleACOnline] ready-target attachment authorization failed before AAK: %v",
					acId, transactionId, addrStr, verifyErr)
				s.sendACOnlineRejectAAK(ppd, transactionId, common.ErrACSessionControlNotReady,
					acId, addrStr, "session-control-attach-authority")
				return common.ErrACSessionControlNotReady
			}
			verifiedCopy := *verified
			acConn.sessionControlTarget.Store(&verifiedCopy)
		} else {
			publicationAuthorizedAtMillis := time.Now().UnixMilli()
			if publicationAuthorizedAtMillis < activation.Target.PreparedAtMillis {
				publicationAuthorizedAtMillis = activation.Target.PreparedAtMillis
			}
			readiness := activation.Target.fence().readiness(activation.Snapshot,
				publicationAuthorizedAtMillis, transactionId)
			finalizeCtx, finalizeCancel := context.WithTimeout(context.WithoutCancel(targetCtx), DynamoDBOperationTimeout)
			finalized, finalizeErr := s.sessionControlStore.FinalizeTargetReady(finalizeCtx, readiness)
			finalizeCancel()
			recoveredConcurrentReady := false
			if errors.Is(finalizeErr, errSessionControlOwnerConflict) ||
				errors.Is(finalizeErr, errSessionControlTargetConflict) {
				// Another assigned server may have finalized the same physical AC
				// first. Authorize this attachment only through the same exact
				// TARGET+OWNER+DIRECTORY condition transaction.
				recoverCtx, recoverCancel := context.WithTimeout(context.WithoutCancel(targetCtx), DynamoDBOperationTimeout)
				finalized, finalizeErr = s.verifyConcurrentReadyACSessionControlTarget(recoverCtx, acConn, activation.Snapshot)
				recoverCancel()
				recoveredConcurrentReady = finalizeErr == nil
			}
			if finalizeErr != nil {
				log.Error("server-ac(%s#%d@%s)[HandleACOnline] durable publication authorization failed before AAK: %v",
					acId, transactionId, addrStr, finalizeErr)
				s.sendACOnlineRejectAAK(ppd, transactionId, common.ErrACSessionControlNotReady,
					acId, addrStr, "session-control-ready-authority")
				return common.ErrACSessionControlNotReady
			}
			finalizedExact := finalized != nil && sessionControlTargetFinalizedExact(*finalized, readiness)
			if recoveredConcurrentReady {
				finalizedExact = finalized != nil && finalized.ready() &&
					finalized.exactCandidate(sessionControlTargetCandidate{
						ACID: acId, PublicKey: acPubkeyBase64, BootID: acConn.BootID,
						FlushGeneration: acConn.FlushGeneration, ControlCellID: s.sessionControlCellID,
					})
			}
			if !finalizedExact {
				log.Error("server-ac(%s#%d@%s)[HandleACOnline] durable publication authorization returned malformed authority",
					acId, transactionId, addrStr)
				s.sendACOnlineRejectAAK(ppd, transactionId, common.ErrACSessionControlNotReady,
					acId, addrStr, "session-control-ready-result")
				return common.ErrACSessionControlNotReady
			}
			finalizedCopy := *finalized
			acConn.sessionControlTarget.Store(&finalizedCopy)
		}
	}

	// Register the AC connection. Admission policy (pubkey-keyed
	// replace-or-append with FIFO backstop) lives in
	// replaceOrAppendACConn; identity-invariant rationale (why pubkey
	// and not IP) lives on the acConnectionMap field declaration in
	// udpserver.go.
	s.acConnectionMapMutex.Lock()
	existingConns := s.acConnectionMap[acId]

	// #1157 F3 distinct-pubkey cap. In cloud mode the durable target
	// authority already performed the cross-process cap transition before this
	// publication point. The legacy map-local verdict remains only for non-cloud
	// deployments; applying it after durable activation could strand an ACTIVE
	// target without publishing its connection.
	// Snapshot the existing pubkeys
	// under the existing mutex so the gate's kernel stays
	// lock-free. The kernel handles the in-place re-registration
	// case (same pubkey → no new slot consumed). See
	// ac_pubkey_cap_gate.go for the threat model. Permit-mode
	// behavior preserves the legacy FIFO eviction below; strict
	// mode rejects before any state mutation.
	existingPubkeys := extractPubkeysFromConns(existingConns)
	capVerdict, distinctCount := verifyACPubkeyCap(acPubkeyBase64, existingPubkeys, MaxACConnsPerID)
	capProceed := true
	var capRejectErr *common.Error
	if !cloudMode {
		capProceed, capRejectErr = s.applyACPubkeyCapVerdict(capVerdict, acId, acPubkeyBase64, distinctCount, transactionId, addrStr)
	}
	if !capProceed {
		// TOCTOU re-check rejection: the pre-check above let us
		// through but a concurrent registration to this acId pushed
		// the distinct count past the cap before we acquired the
		// write lock. acConnectionMap[acId] is unchanged at this
		// point (we haven't written yet), and cloud-mode peer publish
		// is intentionally delayed until after the successful append,
		// so there is no peer-map cleanup for this call.
		s.acConnectionMapMutex.Unlock()
		s.recordLicenseFailure(addrStr, acId)
		s.sendACOnlineRejectAAK(ppd, transactionId, capRejectErr, acId, addrStr, "cap-reject")
		return capRejectErr
	}

	// Pubkey-keyed admit; F3 cap-gate above fences impostor pubkeys,
	// this admit logic fences the live-connection table. See
	// replaceOrAppendACConn.
	existingConns, replaced, staleConn := replaceOrAppendACConn(existingConns, acConn)
	// No `default:` arm — the under-cap append case `(!replaced &&
	// stale == nil)` falls through silently and is then handled by
	// the `if !replaced` block below (which also handles the FIFO
	// case's registration log). See the comment on that block for
	// why it's outside the switch.
	switch {
	case replaced && staleConn != nil:
		// New addr is in the `@%s` prefix above; only the old addr
		// needs naming explicitly to disambiguate. Pubkey prefix
		// matches the FIFO Warning's shape so dashboards that
		// correlate replace + evict events on a single AC pubkey
		// can pivot on the same field.
		log.Info("server-ac(%s#%d@%s)[HandleACOnline] Replacing same-pubkey connection: pubkey=%s... old=%s",
			acId, transactionId, addrStr, pubkeyLogPrefix(staleConn.ACPeer.PubKeyBase64), staleConn.ConnData.RemoteAddr.String())
	case replaced:
		// (true, nil) — same-pubkey AOL on the live socket (keepalive
		// racing first AOL). Silent by design.
	case staleConn != nil:
		// FIFO eviction on distinct-pubkey overflow. Include the
		// evicted slot's pubkey prefix + addr so #1969's alarm
		// pages an operator with the forensic context that
		// pubkeyLogPrefix-style logs already provide for the F3
		// reject paths. The alarm fires only on legitimate
		// overflow (rare in production), so the operator won't
		// have context cached when paged.
		s.metrics.IncrCounter(MetricACConnEviction)
		log.Warning("server-ac(%s)[HandleACOnline] Max connections per AC ID reached (%d), evicting oldest: pubkey=%s... addr=%s",
			acId, MaxACConnsPerID, pubkeyLogPrefix(staleConn.ACPeer.PubKeyBase64), staleConn.ConnData.RemoteAddr.String())
	}
	// The `if !replaced` is outside the switch on purpose. The
	// FIFO path is `(!replaced, stale != nil)`, not the switch's
	// `default:`, so consolidating this into a `default:` arm
	// would silently drop the registration log on FIFO-then-
	// append. The wrapper test asserts FIFO's metric + slice
	// shape; this Info-log dual-emit isn't directly asserted
	// (no log capture wired) — the structural invariant lives in
	// this comment and a future refactor that consolidates the
	// branches must preserve it by inspection. Adding log
	// capture to the wrapper test is tracked separately if a
	// regression ever surfaces.
	if !replaced {
		log.Info("server-ac(%s#%d@%s)[HandleACOnline] New AC instance registered (total: %d)",
			acId, transactionId, addrStr, len(existingConns))
	}

	// All-partial fallthrough alarm. The helper falls through to a
	// plain append (no FIFO) when every existing entry is partial —
	// safe today (production never inserts partials) but indicates
	// an upstream invariant break if it ever fires. The (!replaced,
	// stale == nil) switch arm above is silent on this path, so log
	// here at WARN so an operator triaging a slow registration sees
	// the cap-overshoot without having to grep for it.
	//
	// TODO: the WARN fires AFTER the slice has already grown past
	// cap, and if the upstream invariant break is persistent (every
	// entry partial), each subsequent registration trips this and
	// grows the slice further. The match loop will skip partials on
	// the next call, but the cap stays structurally breached until
	// the next legitimate registration succeeds and compacts the
	// slice via FIFO. An in-place compaction here (drop nil/partial
	// entries before the append) would converge the slice back to a
	// bounded length on every all-partial trip. Out of scope for
	// #1968 since production never hits this path; tracked as a
	// hardening follow-up.
	if !replaced && staleConn == nil && len(existingConns) > MaxACConnsPerID {
		log.Warning("server-ac(%s#%d@%s)[HandleACOnline] acConnectionMap slice grew past cap (len=%d, cap=%d) — all existing entries partial, FIFO skipped; upstream invariant break suspected",
			acId, transactionId, addrStr, len(existingConns), MaxACConnsPerID)
	}

	s.acConnectionMap[acId] = existingConns
	s.acConnectionMapMutex.Unlock()

	if cloudMode {
		// Publish/re-publish the peer only after its ACConn is visible.
		// The revoked-pubkey live-drop cleanup removes a peer only when
		// no live ACConn with that pubkey is visible; delaying AddACPeer
		// until after this append, and holding the read lock while
		// re-adding, closes the race where cleanup could remove a peer
		// that a concurrent registration had added before its ACConn
		// append.
		s.ensureACPeerForLiveConn(acId, acConn)
	}

	// Clean up stale connection outside the lock (if any). With
	// pubkey-keyed admission, staleConn can now be a same-pubkey
	// reconnect from a DIFFERENT IP (NAT rebind / EIP swap), not
	// just same-IP-different-port. The lookup is by the OLD
	// address regardless — remoteConnectionMap is keyed by remote
	// UDP address — and a missing entry (already cleaned up by
	// the conn routine's defer) is a no-op.
	//
	// The connectionRoutine defer's `perIPElem != nil` branch
	// handles connectionsByIP cleanup for any conn that was
	// bucketed at admit — AC, DB, or agent. In the cloud-mode
	// dynamic-AC corner (#1533), an AC's first NHP_AOL packet
	// from an unknown IP misclassifies as agent and lands in the
	// bucket; that conn's perIPElem is non-nil and the routine's
	// defer will pop it correctly. The direct delete here only
	// touches remoteConnectionMap.
	if staleConn != nil {
		oldAddrStr := staleConn.ConnData.RemoteAddr.String()
		s.remoteConnectionMapMutex.Lock()
		if oldUdpConn, found := s.remoteConnectionMap[oldAddrStr]; found {
			delete(s.remoteConnectionMap, oldAddrStr)
			log.Debug("server-ac(%s)[HandleACOnline] Removed stale UdpConn from remoteConnectionMap: %s",
				acId, oldAddrStr)
			go oldUdpConn.Close()
		}
		s.remoteConnectionMapMutex.Unlock()
	}
	if aakMd == nil {
		var marshalErr error
		aakMd, marshalErr = s.successfulACOnlineAckMsgData(ppd, aolMsg, assignedPeers)
		if marshalErr != nil {
			log.Error("server-ac(%s#%d@%s)[HandleACOnline] failed to marshal AAK message: %v", acId, transactionId, addrStr, marshalErr)
			s.metrics.IncrCounter(MetricACRegistrationFailure)
			return marshalErr
		}
	}

	if err := s.forwardToTransaction(ppd.ConnData, transactionId, aakMd, "server-ac", "HandleACOnline", acId, addrStr); err != nil {
		if cloudMode {
			// Durable READY is recoverable by a subsequent AOL, but a success AAK
			// that was never enqueued must leave no locally eligible/publicized
			// connection or peer.
			s.removePublishedACSessionControlConnection(acId, acConn)
		}
		return err
	}
	if cloudMode {
		// The durable proof completed before enqueue. This in-memory projection is
		// the only remaining step and cannot fail; fresh AOPs still perform their
		// own durable intent CAS against TARGET/OWNER/CONTROL descendants.
		acConn.sessionControlAuthorityReady.Store(true)
	}

	// Emit success only after the AAK has entered the authenticated remote
	// transaction. An enqueue failure is not a completed registration even though
	// its already-ACTIVE durable target intentionally remains retryable.
	s.metrics.IncrCounter(MetricACRegistrationSuccess)
	s.metrics.RecordLatency(MetricACRegistrationLatency, float64(time.Since(regStart).Milliseconds()))
	return nil
}

// sendACOnlineRejectAAK marshals and forwards an AAK reject to the
// AC, increments MetricACRegistrationFailure, and tolerates a
// post-rejection forward failure (the AC's transaction will time out
// and retry). callerLabel appears in log lines so a forensic search
// can distinguish the rejection source (e.g., "license-validation",
// "cap-reject"). Unifies the AAK reject contract across HandleACOnline
// rejection sites — license-validation, F3 cap-exceeded pre-check,
// and F3 cap-exceeded in-lock TOCTOU re-check all share this path so
// the AC observes one consistent wire shape.
func (s *UdpServer) sendACOnlineRejectAAK(
	ppd *core.PacketParserData,
	transactionId uint64,
	rejectErr *common.Error,
	acId string,
	addrStr string,
	callerLabel string,
) {
	s.metrics.IncrCounter(MetricACRegistrationFailure)
	aakMsg := &common.ServerACAckMsg{
		ErrCode: rejectErr.ErrorCode(),
		ErrMsg:  rejectErr.Error(),
	}
	aakBytes, marshalErr := json.Marshal(aakMsg)
	if marshalErr != nil {
		log.Error("server-ac(%s#%d@%s)[HandleACOnline] failed to marshal %s AAK: %v", acId, transactionId, addrStr, callerLabel, marshalErr)
		return
	}
	aakMd := makeMsgData(ppd, core.NHP_AAK, aakBytes)
	if transaction := ppd.ConnData.FindRemoteTransaction(transactionId); transaction != nil {
		if sendErr := transaction.SendMessage(aakMd); sendErr != nil {
			log.Error("server-ac(%s#%d@%s)[HandleACOnline] failed to forward %s AAK: %v", acId, transactionId, addrStr, callerLabel, sendErr)
			s.recordTransactionClosed(sendErr)
		}
	}
}

// handleACServerAssignment checks if the AC should be redirected to its assigned servers.
// Returns (true, nil, nil) if AC was redirected via NHP_ARD.
// Returns (false, peers, nil) if this server should handle the AC. peers contains
// all assigned servers so the caller can include them in the NHP_AAK response.
// Returns (false, nil, error) on storage error.
//
// When an AC has no assignment in storage, this function auto-assigns the AC to
// healthy servers discovered via Cloud Map, writes the assignment to storage,
// and sends NHP_ARD so the AC connects to all assigned servers.
func (s *UdpServer) handleACServerAssignment(
	ppd *core.PacketParserData,
	aolMsg *common.ACOnlineMsg,
	transactionId uint64,
	addrStr string,
) (redirected bool, peers []common.RedirectTarget, err error) {
	acId := aolMsg.ACId
	ctx, cancel := udpCorrelationCtx(DefaultStorageTimeout, acId, transactionId)
	defer cancel()

	// Look up AC assignment from storage
	assignment, err := s.storage.GetACAssignment(ctx, acId)
	if err != nil {
		if IsNotFoundError(err) {
			// AC not found in storage — perform auto-assignment
			log.Info("server-ac(%s#%d@%s)[HandleACOnline] AC not in storage, auto-assigning", acId, transactionId, addrStr)
			_, autoErr := s.autoAssignAC(ppd, aolMsg, transactionId, addrStr, 0, nil)
			return false, nil, autoErr
		}
		log.Error("server-ac(%s#%d@%s)[HandleACOnline] storage error looking up AC assignment: %v", acId, transactionId, addrStr, err)
		return false, nil, err
	}

	// Check TTL expiry (DynamoDB TTL deletion is async — expired items may still exist)
	if assignment.TTL != nil && *assignment.TTL < time.Now().Unix() {
		log.Info("server-ac(%s#%d@%s)[HandleACOnline] assignment expired (TTL=%d), re-assigning", acId, transactionId, addrStr, *assignment.TTL)
		_, autoErr := s.autoAssignAC(ppd, aolMsg, transactionId, addrStr, assignment.Version, nil)
		return false, nil, autoErr
	}

	// Filter assignment to only healthy servers (via Cloud Map health discovery).
	cloudMapCtx, cloudMapCancel := udpCorrelationCtx(DefaultStorageTimeout, acId, transactionId)
	defer cloudMapCancel()
	healthyServers := FilterHealthyServers(cloudMapCtx, s.cloudMap, assignment.AssignedServers)
	if len(healthyServers) == 0 {
		// All assigned servers are unhealthy — re-assign with fresh servers
		log.Warning("server-ac(%s#%d@%s)[HandleACOnline] all %d assigned servers unhealthy, re-assigning",
			acId, transactionId, addrStr, len(assignment.AssignedServers))
		_, autoErr := s.autoAssignAC(ppd, aolMsg, transactionId, addrStr, assignment.Version, nil)
		return false, nil, autoErr
	}

	// Determine this server's identity
	serverID := s.getServerID()
	isAssigned := false
	for _, srv := range healthyServers {
		if srv.ID == serverID {
			isAssigned = true
			break
		}
	}

	if isAssigned {
		// This server is assigned — refresh TTL and accept directly.
		// Return the full list of assigned servers (including this one) so the
		// caller can include them in the NHP_AAK response. The AC will connect
		// to all of its assigned servers (typically 3, one per AZ). Without this,
		// only the first AC (which triggers auto-assignment and receives NHP_ARD)
		// connects to all its assigned servers; subsequent ACs only connect
		// to the one server the NLB routed them to, breaking knock fan-out.
		// Note: the responding server is included in the list. HandleRedispatch
		// will attempt to connect to it at its direct IP (not the NLB VIP), which
		// is harmless — the old NLB peer is removed after the new connections succeed.
		s.refreshAssignmentTTL(acId)
		log.Info("server-ac(%s#%d@%s)[HandleACOnline] this server (%s) is assigned to AC, returning %d peers",
			acId, transactionId, addrStr, serverID, len(healthyServers))
		return false, serverInfosToRedirectTargets(healthyServers, s.device.PublicKeyBase64()), nil
	}

	// This server is NOT in the assignment but the AC connected here.
	//
	// Blue/green migration fast-path: if the AC's still-healthy assigned
	// servers are a different color (ASG) than this server, the AC is pinned
	// to the old color and grafting (updateAssignmentWithSelf) would migrate
	// only one new server per re-registration — the slow coupon-collector that
	// trips the post-switch knock-ready gate. Reassign wholesale to the current
	// color instead. See assignmentIsCrossColor's docstring for the full
	// rationale and the >MaxServersPerAssignment residual; the notes below are
	// the call-site-specific caveats (symmetric with the all-assigned-unhealthy
	// reassign branch above, which is the post-scale-down case).
	//
	// Load-bearing precondition: this fires only when an AC's periodic NLB
	// re-registration actually reaches a NEW-color server. Switch-Traffic
	// repoints the NLB knock target group to the new color before validation,
	// so post-switch re-registrations land on the new color and trigger
	// migration; the "deterministic" claim rests on that repoint, not on
	// anything this function does.
	//
	// Degrades-below-graft under save contention: unlike the same-color
	// updateAssignmentWithSelf path (which still sends an ARD even when its
	// save is a version-conflict no-op), autoAssignAC sends NO ARD if its
	// save-conflict retry cap is exhausted — the AC is then accepted on self
	// alone, briefly thinner fan-out than the old graft's self+old. Bounded,
	// ticks no metric, and self-heals on the next ≤90s re-registration (same as
	// the expired/unhealthy autoAssignAC fallbacks).
	//
	// Coverage preservation: with only a SUBSET of the new color propagated, a
	// wholesale reassign can shrink a healthy 3-server assignment to a singleton.
	// That is worse than staying pinned to the old healthy set: qURL admissions
	// may only reach the one server/AC pair that received the AOP while the
	// viewer's NLB flow lands on a different active AC. Suppress the migration
	// until the current-color target set can preserve the existing dialable
	// coverage.
	if crossColor, discovered := s.assignmentIsCrossColor(cloudMapCtx, healthyServers); crossColor {
		if suppress, current, target := s.crossColorMigrationShrinksCoverage(discovered, healthyServers); suppress {
			log.Warning("server-ac(%s#%d@%s)[HandleACOnline] suppressing cross-color assignment migration: current_dialable=%d current_azs=%d target_dialable=%d target_azs=%d existing=%d",
				acId, transactionId, addrStr, current.dialable, current.azs, target.dialable, target.azs, len(healthyServers))
			s.metrics.IncrCounter(MetricACAssignmentColorMigrationSuppressed)
			s.refreshAssignmentTTLOnly(acId)
			if ardErr := s.sendARD(ppd, acId, transactionId, addrStr, healthyServers); ardErr != nil {
				log.Warning("server-ac(%s#%d@%s)[HandleACOnline] failed to send ARD after suppressing cross-color migration: %v", acId, transactionId, addrStr, ardErr)
			}
			// Do not accept/register locally when migration is suppressed. A
			// failed ARD relies on the existing AC re-registration cadence (same
			// <=90s self-heal window used by assignment save-conflict fallbacks)
			// to retry the redirect, while accepting locally would immediately
			// persist the very coverage split this guard prevents.
			return true, nil, nil
		}
		log.Info("server-ac(%s#%d@%s)[HandleACOnline] assignment is cross-color (this server %s differs from assigned color), reassigning to current color", acId, transactionId, addrStr, serverID)
		persisted, autoErr := s.autoAssignAC(ppd, aolMsg, transactionId, addrStr, assignment.Version, discovered)
		// Count only durable migrations: autoAssignAC can fall through to
		// "accept directly" (e.g. save conflict-cap exhausted) without
		// persisting, and the post-rollout ledger check keys on this counter.
		// IncrCounter is nil-safe, so no s.metrics guard (matches the
		// MetricAutoAssignment call inside autoAssignAC).
		if persisted {
			s.metrics.IncrCounter(MetricACAssignmentColorMigration)
		}
		return false, nil, autoErr
	}

	// Otherwise (same-color reconnect): add self, keep existing healthy ones
	// (up to 3 total). This rebuilds redundancy when assigned servers die and
	// the AC reconnects to a new server.
	log.Info("server-ac(%s#%d@%s)[HandleACOnline] this server (%s) not assigned, updating assignment", acId, transactionId, addrStr, serverID)
	updated := s.updateAssignmentWithSelf(assignment, healthyServers)
	if updated != nil {
		if ardErr := s.sendARD(ppd, acId, transactionId, addrStr, updated); ardErr != nil {
			log.Warning("server-ac(%s#%d@%s)[HandleACOnline] failed to send ARD after assignment update: %v", acId, transactionId, addrStr, ardErr)
		}
	} else {
		// Fallback: just redirect to existing healthy servers
		if ardErr := s.sendARD(ppd, acId, transactionId, addrStr, healthyServers); ardErr != nil {
			log.Warning("server-ac(%s#%d@%s)[HandleACOnline] failed to send ARD: %v", acId, transactionId, addrStr, ardErr)
		}
	}

	// Accept the AC locally since we added ourselves to the assignment
	return false, nil, nil
}

// autoAssignAC discovers healthy servers, picks up to 3 across AZs, writes the
// assignment to storage, and sends NHP_ARD so the AC connects to all assigned servers.
// existingVersion is the version of any existing assignment in storage (0 for new).
// When replacing an expired or stale assignment, pass its version so the conditional
// write uses the correct expected version instead of attribute_not_exists.
//
// preDiscovered, when non-nil, is a Cloud Map snapshot the caller already
// fetched; nil means discover here. The blue/green migration path passes the
// same snapshot assignmentIsCrossColor used for its decision, so the decision
// and this reassignment can't straddle a cache refresh and act on disagreeing
// views (and it saves a redundant DiscoverServerInstances call).
//
// This server always also handles the AC locally (it never redirects the AC
// away), so the only result worth reporting is `persisted`: whether a new
// assignment was actually written to storage. It is false on every "accept
// directly" fallback (no Cloud Map, discovery error/empty, save conflict-cap
// exhausted), so callers can gate success-only side effects (e.g. the
// color-migration counter) on it.
func (s *UdpServer) autoAssignAC(
	ppd *core.PacketParserData,
	aolMsg *common.ACOnlineMsg,
	transactionId uint64,
	addrStr string,
	existingVersion int,
	preDiscovered []ServerInfo,
) (persisted bool, err error) {
	acId := aolMsg.ACId

	// Cloud Map required for auto-assignment
	if s.cloudMap == nil {
		log.Info("server-ac(%s#%d@%s)[autoAssignAC] no Cloud Map client, accepting directly", acId, transactionId, addrStr)
		return false, nil
	}

	allServers := preDiscovered
	if allServers == nil {
		cloudMapCtx, cloudMapCancel := udpCorrelationCtx(DefaultStorageTimeout, acId, transactionId)
		defer cloudMapCancel()
		discovered, derr := s.cloudMap.DiscoverServerInstances(cloudMapCtx)
		if derr != nil {
			log.Warning("server-ac(%s#%d@%s)[autoAssignAC] Cloud Map discovery failed: %v, accepting directly", acId, transactionId, addrStr, derr)
			return false, nil
		}
		allServers = discovered
	}

	if len(allServers) == 0 {
		log.Warning("server-ac(%s#%d@%s)[autoAssignAC] no servers in Cloud Map, accepting directly", acId, transactionId, addrStr)
		return false, nil
	}

	// Filter to same-ASG servers to prevent blue/green cross-color assignment.
	// Must happen before selectServersForAssignment but after DiscoverServerInstances
	// so an AC is never assigned across a blue/green color boundary.
	var asgFailOpen bool
	allServers, asgFailOpen = filterServersByASG(allServers, s.ASGName())
	if asgFailOpen && s.metrics != nil {
		s.metrics.IncrCounter(MetricASGFilterFailOpen)
	}

	// Select up to 3 servers with AZ distribution, ensuring this server is included
	selected := s.selectServersForAssignment(allServers, MaxServersPerAssignment)

	// Strip ASGName from selected servers before persisting — it's a server-side
	// filtering concern, not needed by ACs or in DynamoDB.
	for i := range selected {
		selected[i].ASGName = ""
	}

	// Build assignment. When replacing an existing (expired/stale) assignment,
	// use its version + 1 so the conditional write succeeds against the existing item.
	// For brand-new assignments (existingVersion == 0), Version 1 with attribute_not_exists works.
	version := existingVersion + 1
	now := time.Now().Unix()
	ttl := now + AssignmentTTLSeconds
	assignment := &ACAssignment{
		ACID:            acId,
		CustomerID:      "", // populated from license if available
		AssignedServers: selected,
		Version:         version,
		CreatedAt:       now,
		LastSeen:        now,
		TTL:             &ttl,
	}

	// Phase 0C (qurl-service#976): flag a BAD assignment set at the write point.
	// ACs connect over the VPC InternalIP, so an empty or non-private InternalIP
	// is an unreachable target — this is the 3.17.248.131 stale-EIP signature
	// that stranded an AC on a single unreachable server for a fixed ~30s.
	// (AssignmentRewroteHealthySet is deliberately NOT computed here: it needs
	// the old set + a Cloud Map health judgment that is unreliable in the very
	// fail-open window it measures — it belongs to Candidate A. See the plan.)
	// The AC dials each assigned server's InternalIP (serverInfosToRedirectTargets):
	// a NON-PRIVATE InternalIP is dialed-but-unreachable (the 3.17.248.131
	// signature); an EMPTY InternalIP is silently skipped there (#832), shrinking
	// the reachable set. Count them separately and base "below quorum" on the
	// servers the AC can actually reach.
	publicIPTargets, emptyIPTargets := 0, 0
	for _, srv := range selected {
		switch {
		case srv.InternalIP == "":
			emptyIPTargets++
		case !isPrivateIP(srv.InternalIP):
			publicIPTargets++
		}
	}
	dialable := len(selected) - publicIPTargets - emptyIPTargets
	// Critically low = the AC is left one termination away from all-unconnected
	// (<=1 dialable server). A healthy cell with >=2 reachable servers reads 0
	// here, unlike a plain below-target(<MaxServers) count that fires on every
	// small-cell write and can't be alarmed on.
	criticallyLow := dialable <= 1
	if s.metrics != nil {
		if publicIPTargets > 0 {
			s.metrics.IncrCounter(MetricACAssignmentSelectedPublicIP)
		}
		if criticallyLow {
			s.metrics.IncrCounter(MetricACAssignmentSelectedCriticallyLow)
		}
	}
	// Log only the real anomaly — a dialed-but-unreachable public-IP target.
	// criticallyLow alone can still be a legitimately tiny (1-server) cell rather
	// than a churn-induced collapse, so the metric carries it; a Warning per write
	// would bury the public-IP signal.
	if publicIPTargets > 0 {
		log.Warning("server-ac(%s#%d@%s)[autoAssignAC] phase0c bad-set: selected=%d dialable=%d public_ip_targets=%d empty_ip_targets=%d critically_low=%t version=%d asg_fail_open=%t",
			acId, transactionId, addrStr, len(selected), dialable, publicIPTargets, emptyIPTargets, criticallyLow, version, asgFailOpen)
	}

	// Populate customer ID from license if available.
	//
	// #1157 F4 trust contract: console-side License.Validate rejects
	// empty CustomerID at write-time, so a license read here with
	// non-empty CustomerID is the production invariant. If a future
	// caller bypasses console validation and writes a license with
	// empty CustomerID, the assignment persisted here would have an
	// empty CustomerID — and verifyACIDCustomer's `existingCustomerID
	// == "" → Unbound` branch would treat that as a never-bound
	// assignment forever (TOFU never re-fires for the same acId).
	// Detection lives upstream (console validation); this kernel
	// trusts that invariant rather than re-validating per packet.
	// If console validation is ever loosened, the F4 kernel must
	// tighten in the same PR.
	if aolMsg.LicenseKey != "" {
		licCtx, licCancel := udpCorrelationCtx(DefaultStorageTimeout, acId, transactionId)
		license, licErr := s.storage.GetLicense(licCtx, aolMsg.LicenseKey)
		licCancel()
		if licErr == nil {
			assignment.CustomerID = license.CustomerID
		}
	}

	// Write assignment to storage with bounded retry on optimistic-
	// lock conflict (#1157 F7). Pre-#1157 a VersionConflictError fell
	// through to "accept directly" without retry — under contention
	// (multiple servers racing to claim the same acId slot), the
	// loser's view of "no assignment in storage" persisted and
	// subsequent registrations could trip on stale state. The retry
	// re-reads the current assignment, recomputes Version+1, and
	// tries again, capped at saveAssignmentMaxAttempts.
	//
	// Retry policy: only on VersionConflictError. Any other storage
	// error (DDB unavailable, marshal failure, throttling) preserves
	// the legacy fallthrough — degrading to "accept directly" is the
	// availability fallback, and rejecting on a transient outage
	// would weaponize a storage flap into an outage. Cap-exhausted
	// also falls through to accept; the metric is the operator
	// signal that contention is sustained.
	// MUTATES assignment.Version: each retry sets Version to the
	// freshly-observed-version+1, so the local `assignment` struct
	// is no longer authoritative for the original Version after this
	// call returns (success or failure). Don't reuse the same
	// `assignment` value as a retry input elsewhere — see
	// saveAssignmentWithRetry's docstring.
	if saveErr := s.saveAssignmentWithRetry(acId, transactionId, addrStr, assignment); saveErr != nil {
		if IsACAssignmentAuthorityError(saveErr) {
			log.Error("server-ac(%s#%d@%s)[autoAssignAC] candidate assignment authority failed closed: %v", acId, transactionId, addrStr, saveErr)
			return false, saveErr
		}
		log.Warning("server-ac(%s#%d@%s)[autoAssignAC] failed to save assignment: %v, accepting directly", acId, transactionId, addrStr, saveErr)
		return false, nil
	}

	log.Info("server-ac(%s#%d@%s)[autoAssignAC] assigned to %d servers (AZs: %v)",
		acId, transactionId, addrStr, len(selected), serverAZs(selected))
	s.metrics.IncrCounter(MetricAutoAssignment)

	// Send NHP_ARD with all assigned servers (including this one)
	// so the AC connects directly to each server's private IP
	if ardErr := s.sendARD(ppd, acId, transactionId, addrStr, selected); ardErr != nil {
		log.Warning("server-ac(%s#%d@%s)[autoAssignAC] failed to send ARD: %v", acId, transactionId, addrStr, ardErr)
	}

	// A fresh assignment was persisted; report it so the caller can count a
	// durable migration. This server still also handles the AC locally (the
	// ARD above does not redirect the AC away).
	return true, nil
}

// saveAssignmentMaxAttempts caps the autoAssignAC retry loop on
// optimistic-lock conflicts (#1157 F7). Three attempts is enough to
// converge under expected contention (a small fleet racing to claim
// the same acId slot at startup) while bounding worst-case storage
// load under a thundering-herd scenario. Each retry is a re-read +
// re-write so worst-case is 3 GET + 3 PUT to DDB per registration.
//
// Each retry uses a small random sleep (saveAssignmentRetryBaseDelay
// + jitter) so all racing attempts don't synchronize and re-collide.
const (
	saveAssignmentMaxAttempts    = 3
	saveAssignmentRetryBaseDelay = 25 * time.Millisecond
	saveAssignmentRetryJitter    = 75 * time.Millisecond
)

// MetricACAssignmentVersionConflictRetry fires once per retry
// attempt triggered by a VersionConflictError on SaveACAssignment
// inside saveAssignmentWithRetry. A non-zero rate is the rollout
// signal that two servers are racing to claim the same acId slot;
// sustained at high volume, it's a contention-load alarm. NOTE:
// scoped to the retry-loop path. The refresh path (which swallows
// a single conflict without retrying) emits
// MetricACAssignmentRefreshVersionConflict instead so operators can
// distinguish per-retry contention from refresh-edge overlap.
//
// MetricACAssignmentVersionConflictExhausted fires when the retry
// loop is exhausted without converging — falls through to "accept
// directly" per the legacy availability contract. Page-worthy if
// non-zero in burn-in.
//
// MetricACAssignmentRefreshVersionConflict fires once per refresh
// path that observed a VersionConflictError on SaveACAssignment.
// The refresh path swallows the conflict (another server got there
// first; safe — the assignment was extended either way) and does NOT
// retry, so the count is naturally one-per-conflict. Distinct from
// the retry-scoped counter so dashboards can show refresh-edge
// overlap as a steady low-rate signal without inflating the
// contention-load alarm.
//
// MetricACAssignmentSaveError fires once per non-conflict storage
// error from SaveACAssignment (DDB throttling, marshal failure,
// timeout, etc.). Distinct from the conflict counters so operators
// can tell "DDB is sick" from "contention is high" without grepping
// logs. Sustained non-zero is the storage-flap signal.
const (
	MetricACAssignmentVersionConflictRetry     = "ACAssignmentVersionConflictRetry"
	MetricACAssignmentVersionConflictExhausted = "ACAssignmentVersionConflictExhausted"
	MetricACAssignmentRefreshVersionConflict   = "ACAssignmentRefreshVersionConflict"
	MetricACAssignmentSaveError                = "ACAssignmentSaveError"

	// MetricACAssignmentGrew fires once per refreshAssignmentTTL call that
	// successfully grew an under-filled assignment to include a newly
	// discovered healthy server (issue #1681). Sustained non-zero is the
	// signal that the convergence path is doing real work; the rate should
	// fall to ~0 in steady state once all assignments reach
	// MaxServersPerAssignment.
	MetricACAssignmentGrew = "ACAssignmentGrew"

	// Phase 0C (qurl-service#976) assignment write-quality attribution.
	// MetricACAssignmentSelectedPublicIP fires when autoAssignAC persists an
	// assignment containing a server with a NON-PRIVATE InternalIP — a
	// dialed-but-unreachable target (the 3.17.248.131 stale-EIP signature).
	// Steady state is 0; a spike during a deploy is a prime suspect for the "AC
	// absent" class. MetricACAssignmentSelectedCriticallyLow fires when the AC is
	// left with <=1 DIALABLE server (private InternalIP, after empty-InternalIP
	// #832 skips and public-IP targets are excluded) — one termination away from
	// all-unconnected. Deliberately NOT a plain "below target (<MaxServers)" count:
	// that fires on every write in any cell smaller than MaxServersPerAssignment
	// (a steady non-zero baseline that can't be alarmed on and hides the real
	// event). The <=1 floor instead has a clean steady state of 0 in any healthy
	// cell with >=2 reachable servers, so it separates near-isolation from a
	// merely-small cell and catches the 06:47 collapse-to-one-target signature
	// (dialable==0).
	MetricACAssignmentSelectedPublicIP      = "ACAssignmentSelectedPublicIP"
	MetricACAssignmentSelectedCriticallyLow = "ACAssignmentSelectedCriticallyLow"
)

// saveAssignmentWithRetry performs a bounded retry loop around
// SaveACAssignment to converge under optimistic-lock contention
// (#1157 F7). The first attempt uses the assignment's current
// Version; each retry GETs the current version from storage,
// increments by 1, and tries again.
//
// Returns nil on success. Returns the last error on exhaustion or
// on any non-VersionConflict storage error. The ordinary caller preserves its
// established availability fallthrough; the split candidate authority caller
// recognizes ACAssignmentAuthorityError and rejects instead.
//
// saveAssignmentWithRetry mutates assignment.Version on each retry
// to the freshly observed-version+1, so the function is NOT
// idempotent against the same struct after a non-nil return —
// callers should not retry it externally.
//
// Worst-case latency budget: under sustained DDB throttling each
// Save+GET pair can take up to DefaultStorageTimeout (5s today) per
// attempt, so 3 conflicts in a row → ~30s of wall-clock retry
// (jitter is the small term). The AC's NHP_AOL transaction will have
// timed out long before then, but the assignment-write completing
// in the background is still useful state — the AC retries the
// whole NHP_AOL on its next attempt and observes the converged row.
// #1516 tracks plumbing parent ctx through here to short-circuit
// the retry on caller-side deadline.
func (s *UdpServer) saveAssignmentWithRetry(
	acId string,
	transactionId uint64,
	addrStr string,
	assignment *ACAssignment,
) error {
	var lastErr error
	for attempt := 1; attempt <= saveAssignmentMaxAttempts; attempt++ {
		saveCtx, saveCancel := udpCorrelationCtx(DefaultStorageTimeout, acId, transactionId)
		err := s.storage.SaveACAssignment(saveCtx, assignment)
		saveCancel()
		if err == nil {
			return nil
		}
		lastErr = err
		if !IsVersionConflictError(err) {
			// Non-conflict error: don't retry. Caller falls through
			// to "accept directly" per the legacy availability
			// contract. Emit MetricACAssignmentSaveError so a sick
			// DDB (throttling, timeout) shows up on the dashboard
			// without operators having to grep logs to distinguish
			// it from the conflict counters.
			s.metrics.IncrCounter(MetricACAssignmentSaveError)
			return err
		}
		// Optimistic-lock conflict. Re-read current version + retry.
		// The retry counter increments only when a retry is about
		// to be attempted (i.e., NOT on the last failed attempt) so
		// the counter's semantics is "retries scheduled" rather
		// than "failed attempts." Exhaustion is recorded separately
		// via MetricACAssignmentVersionConflictExhausted, so the
		// two counters add up to "total failed attempts" without
		// double-counting the terminal one.
		log.Info("server-ac(%s#%d@%s)[autoAssignAC] version conflict on attempt %d/%d, retrying",
			acId, transactionId, addrStr, attempt, saveAssignmentMaxAttempts)
		if attempt == saveAssignmentMaxAttempts {
			// Last attempt failed — don't increment retry counter
			// (no retry will follow) and don't sleep before
			// returning.
			break
		}
		s.metrics.IncrCounter(MetricACAssignmentVersionConflictRetry)
		// Backoff with jitter so racing attempts decorrelate. Use
		// math/rand here (NOT crypto/rand): jitter is purely a
		// scheduling decorrelation primitive — it picks a value
		// uniformly from [0, saveAssignmentRetryJitter) so two
		// processes that hit the conflict at the same instant
		// don't immediately re-collide on the retry. Cryptographic
		// unpredictability is irrelevant here; an attacker who
		// could predict the jitter still cannot force a conflict
		// they don't already control. Using crypto/rand would just
		// burn entropy for nothing.
		// #nosec G404 -- decorrelation only; not security-sensitive.
		jitter := time.Duration(rand.Int63n(int64(saveAssignmentRetryJitter)))
		time.Sleep(saveAssignmentRetryBaseDelay + jitter)
		// Re-read the assignment to get the latest version.
		readCtx, readCancel := udpCorrelationCtx(DefaultStorageTimeout, acId, transactionId)
		current, readErr := s.storage.GetACAssignment(readCtx, acId)
		readCancel()
		if readErr != nil && !IsNotFoundError(readErr) {
			// Re-read failed transiently. Try again with the
			// previously-incremented version; if it still
			// conflicts, the next iteration will re-read again.
			continue
		}
		if current == nil || IsNotFoundError(readErr) {
			// Item disappeared (concurrent delete / TTL). Treat as
			// "no assignment" and try Version=1.
			assignment.Version = 1
		} else {
			assignment.Version = current.Version + 1
		}
	}
	s.metrics.IncrCounter(MetricACAssignmentVersionConflictExhausted)
	log.Warning("server-ac(%s#%d@%s)[autoAssignAC] version conflict retries exhausted (%d attempts), returning last conflict",
		acId, transactionId, addrStr, saveAssignmentMaxAttempts)
	return lastErr
}

// selectServersForAssignment picks up to maxCount servers with AZ distribution.
// Ensures this server is included in the selection.
func (s *UdpServer) selectServersForAssignment(allServers []ServerInfo, maxCount int) []ServerInfo {
	selfID := s.getServerID()

	// Group servers by AZ
	byAZ := make(map[string][]ServerInfo)
	var selfServer *ServerInfo
	for i := range allServers {
		srv := &allServers[i]
		if srv.ID == selfID {
			selfServer = srv
		}
		byAZ[srv.AZ] = append(byAZ[srv.AZ], *srv)
	}

	// Collect AZ keys for deterministic round-robin
	azKeys := make([]string, 0, len(byAZ))
	for az := range byAZ {
		azKeys = append(azKeys, az)
	}
	sort.Strings(azKeys)

	selected := make([]ServerInfo, 0, maxCount)
	selectedIDs := make(map[string]bool)

	// Always include this server first
	if selfServer != nil {
		selected = append(selected, *selfServer)
		selectedIDs[selfServer.ID] = true
	}

	// Round-robin across AZs to distribute
	azIdx := make(map[string]int)
	for len(selected) < maxCount {
		added := false
		for _, az := range azKeys {
			if len(selected) >= maxCount {
				break
			}
			servers := byAZ[az]
			idx := azIdx[az]
			for idx < len(servers) {
				srv := servers[idx]
				idx++
				azIdx[az] = idx
				if !selectedIDs[srv.ID] {
					selected = append(selected, srv)
					selectedIDs[srv.ID] = true
					added = true
					break
				}
			}
		}
		if !added {
			break // No more servers available
		}
	}

	return selected
}

// getServerID returns this server's identifier for assignment matching.
// In cloud mode, uses the EC2 instance ID (populated from IMDS).
// Falls back to hostname if instance ID is not available.
func (s *UdpServer) getServerID() string {
	if id := s.InstanceID(); id != "" {
		return id
	}
	return s.config.Hostname
}

// refreshAssignmentTTL extends the TTL of an AC assignment in the background
// and opportunistically grows the assignment to MaxServersPerAssignment when
// new healthy servers have appeared in Cloud Map (issue #1681). Throttled to
// at most once per TTLRefreshMinInterval per AC to prevent excessive writes.
// Tracked by s.wg to prevent data races on storage during shutdown.
//
// Version semantics: SaveACAssignment uses optimistic locking conditional on
// `version = expected-1`, so every successful refresh must bump Version. Two
// servers racing to refresh the same AC's assignment will see one succeed and
// one return VersionConflictError (silently ignored — the winner's write is
// the converged state).
//
// Stickiness vs. recycle: pre-fix, refresh was a silent no-op (the
// `existing.Clone()` preserved Version, so SaveACAssignment's
// `version = expected-1` always conflicted and was swallowed). Assignments
// effectively only lived as long as DDB-side TTL eviction allowed (~30 min),
// then autoAssignAC recreated them. That implicit recycle was the only path
// that re-fetched license CustomerID for the F4 (TOFU) flow per #1157.
// With this fix, assignments are long-lived; the F4 CustomerID stays sticky
// across the assignment's life — consistent with the F4 model (once bound,
// never silently rebound). Future readers chasing F4 stickiness questions:
// the recycle-driven refresh is gone, growth happens here, F4 binding does
// not.
func (s *UdpServer) refreshAssignmentTTL(acID string) {
	s.refreshAssignmentTTLWithGrowth(acID, true)
}

// refreshAssignmentTTLOnly extends TTL without opportunistic growth. It is used
// when a cross-color migration is deliberately suppressed: keeping the old
// healthy assignment alive is correct, but growing it from this new-color
// server's Cloud Map view could persist cross-color contamination.
func (s *UdpServer) refreshAssignmentTTLOnly(acID string) {
	s.refreshAssignmentTTLWithGrowth(acID, false)
}

func (s *UdpServer) refreshAssignmentTTLWithGrowth(acID string, allowGrowth bool) {
	// Throttle: skip if we refreshed recently for this AC
	now := time.Now()
	if v, loaded := s.ttlRefreshTimes.LoadOrStore(acID, now); loaded {
		if now.Sub(v.(time.Time)) < TTLRefreshMinInterval {
			return
		}
		// Optimistically update to prevent concurrent goroutines from also passing the check.
		// On save failure, we delete the entry so the next call retries.
		s.ttlRefreshTimes.Store(acID, now)
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()

		correlationID := fmt.Sprintf("udp-ttl-refresh-%s", acID)
		getCtx, getCancel := context.WithTimeout(context.Background(), DefaultStorageTimeout)
		getCtx = ContextWithRequestID(getCtx, correlationID)
		existing, err := s.storage.GetACAssignment(getCtx, acID)
		getCancel()
		if err != nil {
			s.ttlRefreshTimes.Delete(acID) // allow retry on next call
			return
		}

		// existing is already an owned copy (GetACAssignment clones,
		// #1540); the clone just keeps it pristine while refreshed is
		// mutated — defensive, not load-bearing for cache safety.
		ttl := time.Now().Unix() + AssignmentTTLSeconds
		refreshed := existing.Clone()
		refreshed.LastSeen = time.Now().Unix()
		refreshed.TTL = &ttl
		// SaveACAssignment is conditional on `version = expected-1`. Without
		// the bump, every refresh returns VersionConflictError and the
		// assignment stays frozen at its initial AssignedServers for the
		// whole TTL window (issue #1681).
		refreshed.Version = existing.Version + 1

		var didGrow bool
		var grown []ServerInfo
		if allowGrowth {
			// Issue #1681: opportunistically grow under-filled assignments when
			// new healthy servers have appeared in Cloud Map since the assignment
			// was created. Without this, an assignment created when only N<3
			// servers were healthy stays at N forever — re-registrations to the
			// assigned servers see "this server is in the set, return the set"
			// and never converge to MaxServersPerAssignment.
			// Pass the cloned slice rather than existing.AssignedServers so the
			// no-aliasing-of-cache property is syntactically obvious, not just
			// contractually documented on maybeGrowAssignedServers.
			grown, didGrow = s.maybeGrowAssignedServers(refreshed.AssignedServers)
			if didGrow {
				refreshed.AssignedServers = grown
			}
		}

		saveCtx, saveCancel := context.WithTimeout(context.Background(), DefaultStorageTimeout)
		saveCtx = ContextWithRequestID(saveCtx, correlationID)
		defer saveCancel()
		if err := s.storage.SaveACAssignment(saveCtx, refreshed); err != nil {
			if IsVersionConflictError(err) {
				// Another server refreshed TTL concurrently — safe to ignore.
				// Emit a refresh-scoped metric (not the retry-loop one) so
				// dashboards can distinguish refresh-edge overlap (low,
				// expected) from saveAssignmentWithRetry contention (which
				// can spike under load).
				log.Debug("TTL refresh version conflict for AC %s (concurrent update)", acID)
				if s.metrics != nil {
					s.metrics.IncrCounter(MetricACAssignmentRefreshVersionConflict)
				}
			} else {
				log.Debug("Failed to refresh TTL for AC %s: %v", acID, err)
				if s.metrics != nil {
					s.metrics.IncrCounter(MetricACAssignmentSaveError)
				}
				s.refreshCooldownAfterError(acID)
			}
			return
		}
		if didGrow {
			if s.metrics != nil {
				s.metrics.IncrCounter(MetricACAssignmentGrew)
			}
			log.Info("refreshAssignmentTTL: AC %s grew from %d to %d servers (AZs: %v)",
				acID, len(existing.AssignedServers), len(grown), serverAZs(grown))
		}
	}()
}

// refreshCooldownAfterError installs a 30-second cooldown via the
// ttlRefreshTimes throttle map after a non-version-conflict failure
// (issue #1681). Pre-fix, the error path called Delete() which let
// the next AC re-registration retry immediately; with refresh now
// doing real work (Cloud Map + DDB), unrestricted retry would
// amplify a storage flap into a refresh storm.
//
// The throttle gate (in refreshAssignmentTTL above) is
// `now.Sub(stored) < TTLRefreshMinInterval` — i.e. release when at least
// TTLRefreshMinInterval has elapsed since `stored`. To make the gate
// release in errorCooldown rather than TTLRefreshMinInterval we store
// a timestamp back-dated by `(errorCooldown - TTLRefreshMinInterval)`:
//
//	release_time = stored + TTLRefreshMinInterval
//	             = (now + errorCooldown - TTLRefreshMinInterval) + TTLRefreshMinInterval
//	             = now + errorCooldown   ✓
//
// Robust regardless of which constant is larger:
//   - errorCooldown < TTLRefreshMinInterval (the current case, 30s vs 5m):
//     `(errorCooldown - TTLRefreshMinInterval)` is negative, stored time
//     is in the past, gate releases at now + errorCooldown.
//   - errorCooldown > TTLRefreshMinInterval (hypothetical): the offset
//     is positive, `stored` is in the future, `now.Sub(future)` is
//     negative which is < TTLRefreshMinInterval, gate stays held until
//     now reaches stored + TTLRefreshMinInterval = now + errorCooldown.
//
// The fragile-looking arithmetic is correct in both directions; the
// formulation just leans on the existing gate's `Sub < TTL` shape so
// we don't need a parallel "cooldown end time" path through the map.
func (s *UdpServer) refreshCooldownAfterError(acID string) {
	const errorCooldown = 30 * time.Second
	s.ttlRefreshTimes.Store(acID, time.Now().Add(errorCooldown-TTLRefreshMinInterval))
}

// maybeGrowAssignedServers returns a list extended with up to
// (MaxServersPerAssignment - len(current)) new healthy Cloud Map servers,
// preferring new AZs for distribution. Returns (current, false) when no
// growth is possible (already at max, Cloud Map unavailable, or no new
// candidates). Issue #1681.
//
// Contract: callers may pass a slice that aliases a cache pointer. This
// function reads `current` without mutating it; growth produces a fresh
// slice via the explicit `append(grown, current...)` copy below. A future
// change that mutates `current` in-place would corrupt the cache and must
// be caught at review.
func (s *UdpServer) maybeGrowAssignedServers(current []ServerInfo) ([]ServerInfo, bool) {
	if len(current) >= MaxServersPerAssignment || s.cloudMap == nil {
		return current, false
	}

	ctx, cancel := context.WithTimeout(context.Background(), DefaultStorageTimeout)
	defer cancel()
	discovered, err := s.cloudMap.DiscoverServerInstances(ctx)
	if err != nil || len(discovered) == 0 {
		return current, false
	}
	// Refuse to grow when ASG filtering fails open — autoAssignAC accepts
	// fail-open because *no assignment* is worse than a cross-color one,
	// but growth is opportunistic. Persisting a green server into a blue
	// assignment (or vice versa) makes that cross-color contamination
	// durable across the TTL window. Skip; the next refresh will retry.
	discovered, failOpen := filterServersByASG(discovered, s.ASGName())
	if failOpen {
		if s.metrics != nil {
			s.metrics.IncrCounter(MetricASGFilterFailOpen)
		}
		return current, false
	}

	haveID := make(map[string]bool, len(current))
	haveAZ := make(map[string]bool, len(current))
	for _, srv := range current {
		haveID[srv.ID] = true
		if srv.AZ != "" {
			haveAZ[srv.AZ] = true
		}
	}

	// Prefer candidates in AZs not already represented; break ties by ID
	// for deterministic convergence under concurrent racing servers.
	// Sorting `discovered` in place is safe: DiscoverServerInstances
	// returns a fresh copy of its cache (cloudmap.go: `out := make(...);
	// copy(out, instances)`), so this slice does not alias the cache.
	sort.SliceStable(discovered, func(i, j int) bool {
		iNew := !haveAZ[discovered[i].AZ]
		jNew := !haveAZ[discovered[j].AZ]
		if iNew != jNew {
			return iNew
		}
		return discovered[i].ID < discovered[j].ID
	})

	// Defer the seed copy until at least one candidate is confirmed addable —
	// the steady-state case (assignment already converged) returns without
	// allocating a copy of `current` just to discard it.
	var additions []ServerInfo
	room := MaxServersPerAssignment - len(current)
	for _, cand := range discovered {
		if len(additions) >= room {
			break
		}
		if haveID[cand.ID] {
			continue
		}
		// PubKey from Cloud Map (CloudMapAttrKey) is what serverInfosToRedirectTargets
		// hands to the AC — skip candidates whose registration hasn't yet populated
		// it, otherwise the AC would drop the RedirectTarget on validation.
		if cand.PubKey == "" {
			continue
		}
		// Strip ASGName before persisting (server-side filter concern, not AC-facing).
		cand.ASGName = ""
		additions = append(additions, cand)
		haveID[cand.ID] = true
		haveAZ[cand.AZ] = true
	}
	if len(additions) == 0 {
		return current, false
	}
	grown := make([]ServerInfo, 0, len(current)+len(additions))
	grown = append(grown, current...)
	grown = append(grown, additions...)
	return grown, true
}

// sendARD sends NHP_ARD to redirect the AC to the given servers.
func (s *UdpServer) sendARD(
	ppd *core.PacketParserData,
	acId string,
	transactionId uint64,
	addrStr string,
	servers []ServerInfo,
) error {
	ardMsg := &common.ACRedispatchMsg{
		Targets: serverInfosToRedirectTargets(servers, s.device.PublicKeyBase64()),
		ErrCode: common.ErrSuccess.ErrorCode(),
	}
	ardBytes, marshalErr := json.Marshal(ardMsg)
	if marshalErr != nil {
		log.Error("server-ac(%s#%d@%s)[sendARD] failed to marshal ARD message: %v", acId, transactionId, addrStr, marshalErr)
		return marshalErr
	}
	ardMd := makeMsgData(ppd, core.NHP_ARD, ardBytes)

	return s.forwardToTransaction(ppd.ConnData, transactionId, ardMd, "server-ac", "HandleACOnline/ARD", acId, addrStr)
}

// assignmentIsCrossColor reports whether any of an AC's currently-healthy
// assigned servers belongs to a DIFFERENT color (ASG) than this server.
//
// This is the blue/green-switch signal. Post-switch but pre-scale-down the
// old-color servers stay Cloud Map-healthy (they deregister only at
// scale-down, which runs AFTER deploy validation), so an AC's persisted
// assignment still lists them and FilterHealthyServers keeps them. When the
// AC's periodic NLB re-registration lands on a freshly-switched new-color
// server, updateAssignmentWithSelf would graft just this one server on while
// keeping two old-color servers (cap = MaxServersPerAssignment), so each AC
// adopts only ONE new server per re-registration and the new fleet converges
// as a slow coupon-collector over NLB flow-hashing — long enough to trip the
// post-switch knock-ready gate (.github/scripts/verify-knock-ready.sh). When
// this returns true the caller reassigns the AC wholesale to the current color
// instead, so one re-registration adopts a full new-color set (self + AZ-spread,
// up to MaxServersPerAssignment) and drops every old-color server.
//
// Coverage: for the steady-state one-instance-per-AZ fleet
// (MaxServersPerAssignment = 3 = AZ count) that single re-registration covers
// every new-color server, so convergence is deterministic. A new-active fleet
// LARGER than MaxServersPerAssignment (autoscaling past the AZ count, or a
// deploy stacked on a not-yet-scaled-down color) still converges far faster
// than before — each re-registration now adopts MaxServersPerAssignment new
// servers and discards all old ones, versus one new server per re-registration
// pre-fix — but full coverage of the extra servers stays a (faster)
// coupon-collector over which servers ACs' NLB packets land on. That residual
// is the pre-existing MaxServersPerAssignment < fleet-size limit, not something
// this path closes.
//
// Returns false (preserving the legacy updateAssignmentWithSelf path) on every
// path where color can't be established with confidence: no Cloud Map client,
// empty input, discovery error/empty result, this server's own ASG unknown, or
// the ASG filter failing open. Membership is by IP/InternalIP because the
// persisted assignment has ASGName stripped (autoAssignAC strips it before
// write), so color must be re-derived from a live Cloud Map view. An old-color
// server whose Cloud Map ASGName is empty (IMDS failed to populate ASG_NAME) is
// treated as same-color by filterServersByASG, so migration won't fire for it —
// the conservative bias: never churn an assignment on ambiguous color.
//
// On a true result it also returns the Cloud Map snapshot it discovered so the
// caller can hand the SAME snapshot to autoAssignAC — the decision and the
// reassignment then act on one consistent view instead of two independent
// reads. (The healthyAssigned set still comes from a separate, earlier
// FilterHealthyServers read; a cache refresh straddling the two could flag a
// briefly-absent same-color server as cross-color, but the only consequence is
// a one-off reassign of an already-same-color AC to its current color — safe,
// just a stray counter tick.) Returns nil on every false result.
//
// Cost: this adds one DiscoverServerInstances to every not-assigned
// re-registration (including the common same-color reconnect that ends up
// falling through to updateAssignmentWithSelf). It is unavoidable — color
// can't be read off the stored assignment — but it is a 30s-cached read
// (instancesExpiry), so in steady state it is a cache hit, not an API call.
// Only a cold/expired cache under heavy reconnect churn turns it into an
// extra discovery round-trip.
func (s *UdpServer) assignmentIsCrossColor(ctx context.Context, healthyAssigned []ServerInfo) (bool, []ServerInfo) {
	if s.cloudMap == nil || len(healthyAssigned) == 0 {
		return false, nil
	}
	selfASG := s.ASGName()
	if selfASG == "" {
		return false, nil // own color unknown — don't churn assignments
	}
	allServers, err := s.cloudMap.DiscoverServerInstances(ctx)
	if err != nil || len(allServers) == 0 {
		return false, nil
	}
	sameColor, failOpen := filterServersByASG(allServers, selfASG)
	if failOpen {
		return false, nil // every candidate is cross-color → ASG view unreliable
	}
	sameColorIPs := make(map[string]bool, len(sameColor))
	for _, srv := range sameColor {
		if srv.IP != "" {
			sameColorIPs[srv.IP] = true
		}
		if srv.InternalIP != "" {
			sameColorIPs[srv.InternalIP] = true
		}
	}
	for _, srv := range healthyAssigned {
		if srv.IP == "" && srv.InternalIP == "" {
			continue // no IP to compare — conservative: don't treat as cross-color
		}
		if !sameColorIPs[srv.IP] && !sameColorIPs[srv.InternalIP] {
			return true, allServers // at least one assigned server is a different color
		}
	}
	return false, nil
}

type assignmentCoverage struct {
	dialable int
	azs      int
}

func (s *UdpServer) crossColorMigrationShrinksCoverage(discovered []ServerInfo, healthyAssigned []ServerInfo) (bool, assignmentCoverage, assignmentCoverage) {
	current := dialableAssignmentCoverage(healthyAssigned)
	if current.dialable == 0 {
		return false, current, assignmentCoverage{}
	}

	sameColor, failOpen := filterServersByASG(discovered, s.ASGName())
	if failOpen {
		return true, current, assignmentCoverage{}
	}
	selected := s.selectServersForAssignment(sameColor, MaxServersPerAssignment)
	target := dialableAssignmentCoverage(selected)
	if target.dialable < current.dialable {
		return true, current, target
	}
	if current.azs > 0 && target.azs < current.azs {
		return true, current, target
	}
	return false, current, target
}

func dialableAssignmentCoverage(servers []ServerInfo) assignmentCoverage {
	var coverage assignmentCoverage
	azs := make(map[string]bool, len(servers))
	for _, srv := range servers {
		if srv.InternalIP != "" && isPrivateIP(srv.InternalIP) {
			coverage.dialable++
			if srv.AZ != "" {
				azs[srv.AZ] = true
			}
		}
	}
	coverage.azs = len(azs)
	return coverage
}

// updateAssignmentWithSelf adds this server to an existing AC assignment,
// keeping existing healthy servers up to a total of MaxServersPerAssignment.
// Returns the updated server list on success, or nil on failure.
func (s *UdpServer) updateAssignmentWithSelf(assignment *ACAssignment, healthyServers []ServerInfo) []ServerInfo {
	selfID := s.getServerID()

	// Construct this server's ServerInfo from local state (no Cloud Map call needed —
	// the server knows its own identity)
	selfInfo := ServerInfo{
		ID:         selfID,
		IP:         s.localIp,
		InternalIP: s.localIp,
		AZ:         s.InstanceAZ(),
		Port:       s.config.ListenPort,
		PubKey:     s.device.PublicKeyBase64(),
	}

	// Build updated list: self + existing healthy (up to max total)
	updated := []ServerInfo{selfInfo}
	for _, srv := range healthyServers {
		if len(updated) >= MaxServersPerAssignment {
			break
		}
		if srv.ID != selfID {
			updated = append(updated, srv)
		}
	}

	// assignment is already an owned copy (GetACAssignment clones,
	// #1540); the clone just keeps it pristine while newAssignment is
	// mutated — defensive, not load-bearing for cache safety. On Save
	// failure the cache is untouched regardless (SaveACAssignment only
	// updates it on success).
	ttl := time.Now().Unix() + AssignmentTTLSeconds
	newAssignment := assignment.Clone()
	newAssignment.AssignedServers = updated
	newAssignment.Version = assignment.Version + 1
	newAssignment.LastSeen = time.Now().Unix()
	newAssignment.TTL = &ttl

	correlationID := fmt.Sprintf("udp-assign-update-%s", assignment.ACID)
	saveCtx, saveCancel := context.WithTimeout(context.Background(), DefaultStorageTimeout)
	saveCtx = ContextWithRequestID(saveCtx, correlationID)
	defer saveCancel()
	if err := s.storage.SaveACAssignment(saveCtx, newAssignment); err != nil {
		if IsVersionConflictError(err) {
			log.Info("updateAssignmentWithSelf: version conflict for %s (concurrent update), skipping", assignment.ACID)
		} else {
			log.Warning("updateAssignmentWithSelf: failed to save updated assignment for %s: %v", assignment.ACID, err)
		}
		return nil
	}

	log.Info("updateAssignmentWithSelf: AC %s updated to %d servers (AZs: %v)", assignment.ACID, len(updated), serverAZs(updated))
	return updated
}

// serverAZs returns a list of AZs from a list of servers (for logging).
func serverAZs(servers []ServerInfo) []string {
	azs := make([]string, len(servers))
	for i, s := range servers {
		azs[i] = s.AZ
	}
	return azs
}

// dummyBcryptHash is used for constant-time license validation to prevent timing attacks.
// When a license is not found, we still perform a bcrypt comparison against this dummy
// hash to ensure the response time is similar regardless of whether the license exists.
// This prevents attackers from enumerating valid license keys based on response timing.
// Format: $2a$10$ (7 chars) + 22 char salt + 31 char hash = 60 chars total
var dummyBcryptHash = []byte("$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy")

// licenseKeyPrefix returns the first 8 hex chars of the SHA256 hash of a license key.
// This provides enough context for log correlation without exposing the full key.
func licenseKeyPrefix(licenseKey string) string {
	hash := sha256.Sum256([]byte(licenseKey))
	return hex.EncodeToString(hash[:4]) // First 4 bytes = 8 hex chars
}

// validateACLicense validates AC credentials against DynamoDB in cloud mode.
// Returns nil if validation succeeds, or an error if validation fails.
// See docs/design/PLUGGABLE_STORAGE_BACKEND.md Section 6.2 for the validation flow.
//
// Security: This function uses constant-time comparison to prevent timing attacks.
// The bcrypt comparison is ALWAYS performed (with real or dummy hash) BEFORE any
// fast checks (active, expired) to ensure uniform response time for all cases.
// This prevents attackers from distinguishing between different failure modes.
func (s *UdpServer) validateACLicense(
	ppd *core.PacketParserData,
	aolMsg *common.ACOnlineMsg,
	transactionId uint64,
	addrStr string,
	presentedPubkey string,
) *common.Error {
	acId := aolMsg.ACId

	// Check if license key is provided - required in cloud mode
	// This fast check is OK since missing key is an obvious client error, not useful for enumeration
	if aolMsg.LicenseKey == "" {
		log.Warning("server-ac(%s#%d@%s)[validateACLicense] missing license key",
			acId, transactionId, addrStr)
		return common.ErrServerACOpsFailed
	}

	// RATE LIMITING: Check if this source IP or AC ID has exceeded the failure threshold.
	// This runs BEFORE the expensive bcrypt operation to save resources under attack.
	// Rate-limited requests still return the generic error to avoid leaking information.
	//
	// Post-#1507: this check is functionally redundant with the
	// cloud-mode F5 hoist at HandleACOnline (msghandler.go ~570),
	// which runs the same check before validateACLicense is even
	// reached. validateACLicense itself is invoked only from the
	// `acPeer == nil && cloudMode` branch, so any cloud-mode
	// AOL that gets here has already passed the hoist's
	// CheckRateLimit. The check is kept anyway as a redundant
	// safety net in case the F5 hoist is ever removed in a future
	// refactor — defense-in-depth at the cost of one extra
	// CheckRateLimit on the cold-registration path (cheap, in-
	// memory). Removing it would force a future refactor to revert
	// the hoist atomically; keeping it lets the two checks be
	// audited and modified independently.
	if s.licenseRateLimiter != nil {
		if rlErr := s.licenseRateLimiter.CheckRateLimit(addrStr, acId); rlErr != nil {
			log.Warning("server-ac(%s#%d@%s)[validateACLicense] %s",
				acId, transactionId, addrStr, rlErr.Message)
			if s.metrics != nil {
				s.metrics.IncrCounter(MetricLicenseValidationRateLimited)
			}
			return common.ErrServerACOpsFailed
		}
	}

	// Compute key prefix for log correlation (first 8 hex chars of SHA256)
	// This helps operators debug without exposing full license keys
	keyPrefix := licenseKeyPrefix(aolMsg.LicenseKey)

	// Look up license from storage using license key SHA256 as the partition key
	ctx, cancel := udpCorrelationCtx(DefaultStorageTimeout, acId, transactionId)
	defer cancel()

	license, err := s.storage.GetLicense(ctx, aolMsg.LicenseKey)

	// TIMING ATTACK PROTECTION: Always perform bcrypt comparison before any fast checks.
	// This ensures uniform response time regardless of license existence or validity.
	// The bcrypt operation (~100ms) dominates response time, hiding fast checks.
	var bcryptErr error
	if err != nil || license == nil || license.LicenseKeyHash == "" {
		// Use dummy hash when license not found or has no hash
		bcryptErr = bcrypt.CompareHashAndPassword(dummyBcryptHash, []byte(aolMsg.LicenseKey))
	} else {
		// Use real hash when license exists
		bcryptErr = bcrypt.CompareHashAndPassword([]byte(license.LicenseKeyHash), []byte(aolMsg.LicenseKey))
	}

	// Now perform fast checks AFTER the timing-sensitive bcrypt operation
	// Storage error or not found
	if err != nil {
		if IsNotFoundError(err) {
			log.Warning("server-ac(%s#%d@%s)[validateACLicense] license not found (key=%s...)",
				acId, transactionId, addrStr, keyPrefix)
		} else {
			log.Error("server-ac(%s#%d@%s)[validateACLicense] storage error (key=%s...): %v",
				acId, transactionId, addrStr, keyPrefix, err)
		}
		s.recordLicenseFailure(addrStr, acId)
		return common.ErrServerACOpsFailed
	}

	// License record exists but has no hash (misconfiguration)
	if license.LicenseKeyHash == "" {
		log.Error("server-ac(%s#%d@%s)[validateACLicense] license record has no key hash (key=%s..., misconfiguration)",
			acId, transactionId, addrStr, keyPrefix)
		s.recordLicenseFailure(addrStr, acId)
		return common.ErrServerACOpsFailed
	}

	// Check if license is active
	if !license.Active {
		log.Warning("server-ac(%s#%d@%s)[validateACLicense] license inactive (key=%s...)",
			acId, transactionId, addrStr, keyPrefix)
		s.recordLicenseFailure(addrStr, acId)
		return common.ErrServerACOpsFailed
	}

	// Check if license is expired
	if license.ExpiresAt > 0 && time.Now().Unix() > license.ExpiresAt {
		log.Warning("server-ac(%s#%d@%s)[validateACLicense] license expired (key=%s..., at %d)",
			acId, transactionId, addrStr, keyPrefix, license.ExpiresAt)
		s.recordLicenseFailure(addrStr, acId)
		return common.ErrServerACOpsFailed
	}

	// bcrypt validation result (computed earlier for constant-time)
	if bcryptErr != nil {
		log.Warning("server-ac(%s#%d@%s)[validateACLicense] license key mismatch (key=%s...)",
			acId, transactionId, addrStr, keyPrefix)
		s.recordLicenseFailure(addrStr, acId)
		return common.ErrServerACOpsFailed
	}

	// #1155 pubkey binding gate. Runs AFTER all license-record
	// checks (active, expired, bcrypt) — at this point we know the
	// license key is genuine, so the only remaining question is
	// "is the AC presenting it allowed to register under it?" The
	// gate compares the AEAD-authenticated peer pubkey against the
	// License.BoundPubKeys allowlist. See license_pubkey_gate.go
	// for the permit→strict policy and threat model.
	//
	// presentedPubkey is the base64 form of ppd.RemotePubKey, already
	// computed by HandleACOnline before this call — threading it
	// through avoids a second base64-encode on the registration
	// path. ppd.RemotePubKey itself is populated by the noise
	// responder during packet validation before any handler runs,
	// so the value is AEAD-authenticated; no further authentication
	// is needed here.
	verdict := verifyLicensePubkey(presentedPubkey, license.BoundPubKeys)
	proceed, rejectErr := s.applyLicensePubkeyVerdict(verdict, acId, presentedPubkey, transactionId, addrStr, keyPrefix)
	if !proceed {
		// Reuse the license-failure rate-limit counter: an
		// attacker spamming stolen keys under non-listed pubkeys
		// should trip the same defense as other license failures.
		s.recordLicenseFailure(addrStr, acId)
		return rejectErr
	}

	// #1157 F4 license-customer cross-check. Runs AFTER the
	// pubkey-binding gate so a forged-pubkey registration is
	// rejected first (avoids a storage round-trip on attacker
	// traffic). Looks up ACAssignment.CustomerID for the claimed
	// acId; if a populated CustomerID exists and disagrees with
	// license.CustomerID, this is cross-customer impersonation
	// (#1157 F4 attack signature). See license_customer_gate.go.
	//
	// Storage-error policy: a transient storage outage MUST NOT
	// reject legitimate registrations. We treat lookup-err as
	// "skip the cross-check" and emit MetricLicenseCustomerLookupErr
	// for observability — same availability fallback as
	// autoAssignAC's "fall through to accept directly" branch.
	//
	// Fresh context (rather than reusing the validateACLicense ctx
	// from L1349): the upstream GetLicense + bcrypt could have
	// drained most of the 5s DefaultStorageTimeout under DDB
	// throttling or slow-path bcrypt. If the F4 GetACAssignment
	// then hits a near-expired ctx, it returns a transient error
	// and the storage-error policy degrades to Unbound — a SILENT
	// strict-mode bypass with only MetricLicenseCustomerLookupErr
	// as the operator signal. Decoupling the F4 deadline from
	// upstream latency removes that bypass surface; the alarm on
	// LicenseCustomerLookupErr (#1514) still catches a real DDB
	// outage. Mirrors autoAssignAC's per-call ctx pattern at L892.
	f4Ctx, f4Cancel := udpCorrelationCtx(DefaultStorageTimeout, acId, transactionId)
	customerVerdict, existingCustomerID := s.evaluateACIDCustomerVerdict(f4Ctx, acId, license.CustomerID, transactionId, addrStr)
	f4Cancel()
	customerProceed, customerRejectErr := s.applyACIDCustomerVerdict(customerVerdict, acId, license.CustomerID, existingCustomerID, transactionId, addrStr, keyPrefix)
	if !customerProceed {
		s.recordLicenseFailure(addrStr, acId)
		return customerRejectErr
	}

	log.Info("server-ac(%s#%d@%s)[validateACLicense] license validated (key=%s...), tier=%s, customer=%s",
		acId, transactionId, addrStr, keyPrefix, license.Tier, license.CustomerID)
	return nil
}

// evaluateACIDCustomerVerdict performs the storage lookup half of
// the #1157 F4 gate and returns (verdict, existingCustomerID).
// Pulled out of validateACLicense so the cross-check can be tested
// independently of bcrypt + pubkey-binding setup. Returns the
// observed CustomerID alongside the verdict so the caller can
// pass it into applyACIDCustomerVerdict for log context without a
// second storage round-trip.
//
// Storage-error policy: a transient lookup error fires
// MetricLicenseCustomerLookupErr and returns
// verdictACIDCustomerUnbound (skip-the-cross-check). Same
// availability contract as autoAssignAC's fallthrough branch — a
// flaky DDB cannot weaponize legitimate registrations into
// strict-mode rejects.
func (s *UdpServer) evaluateACIDCustomerVerdict(
	ctx context.Context,
	acId string,
	licenseCustomerID string,
	transactionId uint64,
	addrStr string,
) (licenseACIDCustomerVerdict, string) {
	if s.storage == nil {
		return verdictACIDCustomerUnbound, ""
	}
	assignment, err := s.storage.GetACAssignment(ctx, acId)
	if err != nil {
		if IsNotFoundError(err) {
			return verdictACIDCustomerUnbound, ""
		}
		// Transient storage error. Don't escalate to a strict-mode
		// reject — degrade gracefully and emit the lookup-err
		// counter so operators can spot a sustained flap. No
		// nil-guard: UdpServer.metrics is initialized by NewUdpServer
		// (mirrors applyACPubkeyCapVerdict / applyACIDCustomerVerdict).
		s.metrics.IncrCounter(MetricLicenseCustomerLookupErr)
		log.Warning("server-ac(%s#%d@%s)[LicenseCustomer] ACAssignment lookup failed: %v (skipping cross-check; see %s)",
			acId, transactionId, addrStr, err, MetricLicenseCustomerLookupErr)
		return verdictACIDCustomerUnbound, ""
	}
	if assignment == nil {
		return verdictACIDCustomerUnbound, ""
	}
	return verifyACIDCustomer(assignment.CustomerID, licenseCustomerID), assignment.CustomerID
}

// recordLicenseFailure feeds the per-source/per-acId rate limiter on
// any validateACLicense-class registration reject. The name is
// historical (#1155 introduced it for License.BoundPubKeys mismatches);
// since #1157 F3 it is the shared throttle for ALL registration-time
// reject classes that an attacker could burn to DoS the registration
// path: license-pubkey gate rejects, license-customer gate rejects,
// and AC-pubkey-cap gate rejects (both pre-check and in-lock). A
// future reject class added on the registration path should call this
// too — the rate limiter doesn't distinguish reject classes, and
// leaving any path unwired re-opens the burn-without-throttle attack.
func (s *UdpServer) recordLicenseFailure(addrStr, acId string) {
	if s.licenseRateLimiter != nil {
		s.licenseRateLimiter.RecordFailure(addrStr, acId)
	}
}

func (s *UdpServer) HandleDBOnline(ppd *core.PacketParserData) (err error) {
	s.wg.Add(1)
	defer s.wg.Done()

	transactionId := ppd.SenderTrxId
	addrStr := ppd.ConnData.RemoteAddr.String()
	dolMsg := &common.DBOnlineMsg{}

	err = json.Unmarshal(ppd.BodyMessage, dolMsg)
	if err != nil {
		log.Error("server-db(#%d@%s)[HandleDBOnline] failed to parse %s message: %v", transactionId, addrStr, core.HeaderTypeToString(ppd.HeaderType), err)
		return err
	}

	dbId := dolMsg.DBId
	dbPubkeyBase64 := base64.StdEncoding.EncodeToString(ppd.RemotePubKey)
	s.dbPeerMapMutex.Lock()
	dbPeer := s.dbPeerMap[dbPubkeyBase64] // ac peer's recvAddr has already been updated by nhp packet parser
	s.dbPeerMapMutex.Unlock()

	dbConn := &DBConn{
		ConnData:       ppd.ConnData,
		DBPeer:         dbPeer,
		DBCipherScheme: ppd.CipherScheme,
		DBId:           dbId,
	}

	s.dbConnectionMapMutex.Lock()
	s.dbConnectionMap[dbId] = dbConn
	s.dbConnectionMapMutex.Unlock()

	aakMsg := &common.ServerDBAckMsg{
		ErrCode: common.ErrSuccess.ErrorCode(),
		DBAddr:  ppd.ConnData.RemoteAddr.String(),
	}
	aakBytes, marshalErr := json.Marshal(aakMsg)
	if marshalErr != nil {
		log.Error("server-db(%s#%d@%s)[HandleDBOnline] failed to marshal DBA message: %v", dbId, transactionId, addrStr, marshalErr)
		return marshalErr
	}
	aakMd := makeMsgData(ppd, core.NHP_DBA, aakBytes)

	return s.forwardToTransaction(ppd.ConnData, transactionId, aakMd, "server-db", "HandleDBOnline", dbId, addrStr)
}

func (s *UdpServer) HandleDHPDARMessage(ppd *core.PacketParserData) (err error) {
	s.wg.Add(1)
	defer s.wg.Done()

	transactionId := ppd.SenderTrxId
	addrStr := ppd.ConnData.RemoteAddr.String()
	darMsg := &common.DARMsg{}

	err = json.Unmarshal(ppd.BodyMessage, darMsg)
	if err != nil {
		log.Error("server-agent(#%d@%s)[HandleDHPDARMessage] failed to parse %s message: %v", transactionId, addrStr, core.HeaderTypeToString(ppd.HeaderType), err)
		return err
	}

	doId := darMsg.DoId
	config, err := ReadZdtoConfig(doId)
	dsaMsg := &common.DSAMsg{DoId: doId}
	if err != nil {
		// err is either common.ErrInvalidDoID or errReadConfigFailed —
		// both fixed sentinels with no attacker-controlled bytes, so
		// echoing err.Error() on the wire is safe. The raw cause was
		// already logged at WARN / ERROR inside ReadZdtoConfig.
		log.Error("server-agent(#%d@%s)[HandleDHPDARMessage] read ztdo config for DoId=%q: %v", transactionId, addrStr, doId, err)
		dsaMsg.ErrCode = 1
		dsaMsg.ErrMsg = err.Error()
	} else {
		dsaMsg.SpoId = config.Spo.PolicyId
		dsaMsg.Spo = &config.Spo
		dsaMsg.TTL = int((30 * time.Minute).Milliseconds())
		s.UpdateTeePublicKeyAndConsumerEphemeralPublicKey(darMsg.TeePublicKey, darMsg.ConsumerEphemeralPublicKey, ppd.RemotePubKey)
	}

	aakBytes, marshalErr := json.Marshal(dsaMsg)
	if marshalErr != nil {
		log.Error("server-agent(DoId=%q,trx=#%d@%s)[HandleDHPDARMessage] failed to marshal DSA message: %v", doId, transactionId, addrStr, marshalErr)
		return marshalErr
	}
	log.Debug("dagMsg:%s", (string)(aakBytes))
	aakMd := makeMsgData(ppd, core.NHP_DSA, aakBytes)
	return s.forwardToTransaction(ppd.ConnData, transactionId, aakMd, "server-agent", "HandleDHPDARMessage", doId, addrStr)
}

func (s *UdpServer) HandleDHPDAVMessage(ppd *core.PacketParserData) (err error) {
	s.wg.Add(1)
	defer s.wg.Done()

	transactionId := ppd.SenderTrxId
	addrStr := ppd.ConnData.RemoteAddr.String()
	davMsg := &common.DAVMsg{}

	err = json.Unmarshal(ppd.BodyMessage, davMsg)
	if err != nil {
		log.Error("server-agent(#%d@%s)[HandleDHPDAVMessage] failed to parse %s message: %v", transactionId, addrStr, core.HeaderTypeToString(ppd.HeaderType), err)
		return err
	}

	doId := davMsg.DoId
	config, configErr := ReadZdtoConfig(doId)

	// dagMsg is populated below and always sent via forwardToTransaction —
	// mirror the DAR handler's pattern so a legitimate agent asking for a
	// missing / malformed DoId gets an explicit DAG error response, not a
	// hung request. Pre-PR this path had a shadowed err that silently ran
	// onAttestationVerify against a zero-value Spo; that's closed here by
	// skipping the attestation branch when configErr != nil.
	dagMsg := &common.DAGMsg{DoId: doId}
	if configErr != nil {
		// configErr is either common.ErrInvalidDoID or errReadConfigFailed —
		// both fixed sentinels, so echoing on the wire is safe. Raw cause
		// logged inside ReadZdtoConfig.
		log.Error("server-agent(#%d@%s)[HandleDHPDAVMessage] read ztdo config for DoId=%q: %v", transactionId, addrStr, doId, configErr)
		dagMsg.ErrCode = 1
		dagMsg.ErrMsg = configErr.Error()
	} else {
		if attestErr := s.onAttestationVerify(&config.Spo, davMsg.Evidence); attestErr != nil {
			log.Error("server-agent(#%d@%s)[HandleDHPDAVMessage] failed to verify attestation: %s with error: %s", transactionId, addrStr, davMsg.Evidence, attestErr.Error())
			return attestErr
		}

		teePublicKey, consumerEphemeralPublicKey := s.GetTeePublicKeyBase64AndConsumerEphemeralPublicKeyBase64(ppd.RemotePubKey)

		dwrMsg := &common.DWRMsg{
			DoId:                       doId,
			TeePublicKey:               teePublicKey,
			ConsumerEphemeralPublicKey: consumerEphemeralPublicKey,
		}

		dbConn, found := s.dbConnectionMap[config.DbId]
		if !found {
			log.Critical("dbConn not found for dbId:%q", config.DbId)
			dagMsg.ErrCode = 1
			dagMsg.ErrMsg = common.ErrDBOffline.Error()
		} else {
			dwaMsg, dwaErr := s.ProcessDataPrivateKeyWrapping(dwrMsg, dbConn)
			// ProcessDataPrivateKeyWrapping can return (nil, err) on a
			// marshal failure in its upstream chain. Derefing dwaMsg
			// below would panic the handler; handle that path first.
			// The nil branch catches any dwaMsg==nil shape — including
			// the (nil, nil) case today's implementation shouldn't produce
			// but a future refactor could, and the narrower condition
			// would otherwise fall through to the default Kao deref.
			switch {
			case dwaMsg == nil:
				// Scrub dwaErr on the wire — upstream marshal failures
				// can wrap filesystem paths or other internal detail.
				// Operator signal stays in the log.
				log.Error("server-agent(#%d@%s)[HandleDHPDAVMessage] dwaMsg nil for DoId=%q: %v", transactionId, addrStr, doId, dwaErr)
				dagMsg.ErrCode = 1
				dagMsg.ErrMsg = "data private key wrapping failed"
			case dwaErr != nil || dwaMsg.ErrCode != 0:
				// Error branch — do NOT populate success fields (Kao,
				// Spo, DataSourceType, ...). Pre-fix this block fell
				// through to the success population below, shipping
				// partial config alongside an error code.
				// Belt-and-suspenders on ErrCode: every error path in
				// ProcessDataPrivateKeyWrapping that returns non-nil
				// dwaMsg also sets ErrCode != 0; the dwaErr!=nil slot
				// is a guard against a future error path forgetting.
				// TODO(#1161): retire the else-branch once the
				// (dwaErr != nil) => (dwaMsg.ErrCode != 0) invariant
				// is codified upstream (e.g. via dwaMsg.Validate()).
				if dwaMsg.ErrCode != 0 {
					dagMsg.ErrCode = dwaMsg.ErrCode
					dagMsg.ErrMsg = dwaMsg.ErrMsg
				} else {
					log.Error("server-agent(#%d@%s)[HandleDHPDAVMessage] dwaErr with zero ErrCode for DoId=%q: %v", transactionId, addrStr, doId, dwaErr)
					dagMsg.ErrCode = 1
					dagMsg.ErrMsg = "data private key wrapping failed"
				}
			default:
				dagMsg.Kao = dwaMsg.Kao
				dagMsg.Spo = &config.Spo
				dagMsg.DataSourceType = config.DataSourceType
				dagMsg.AccessUrl = config.AccessUrl
				dagMsg.AccessByNHP = config.AccessByNHP
				dagMsg.DoType = config.DoType
			}
		}
	}

	aakBytes, marshalErr := json.Marshal(dagMsg)
	if marshalErr != nil {
		log.Error("server-agent(DoId=%q,trx=#%d@%s)[HandleDHPDAVMessage] failed to marshal DAG message: %v", doId, transactionId, addrStr, marshalErr)
		return marshalErr
	}
	log.Debug("dagMsg:%s", (string)(aakBytes))
	aakMd := makeMsgData(ppd, core.NHP_DAG, aakBytes)
	return s.forwardToTransaction(ppd.ConnData, transactionId, aakMd, "server-agent", "HandleDHPDAVMessage", doId, addrStr)
}

// HandleDHPDRGMessage
func (s *UdpServer) HandleDHPDRGMessage(ppd *core.PacketParserData) (err error) {
	s.wg.Add(1)
	defer s.wg.Done()

	transactionId := ppd.SenderTrxId
	addrStr := ppd.ConnData.RemoteAddr.String()
	aolMsg := &common.DRGMsg{}

	err = json.Unmarshal(ppd.BodyMessage, aolMsg)
	if err != nil {
		log.Error("server-Device(#%d@%s)[HandleDHPDRGMessage] failed to parse %s message: %v", transactionId, addrStr, core.HeaderTypeToString(ppd.HeaderType), err)
		return err
	}

	doId := aolMsg.DoId

	err = SaveZdtoConfig(aolMsg)

	errCode := 0 //success
	errMsg := ""

	if err != nil {
		// err is either common.ErrInvalidDoID or errSaveConfigFailed —
		// both fixed sentinels, echoing on the wire is safe. Raw cause
		// already logged inside SaveZdtoConfig.
		log.Error("server-db(#%d@%s)[HandleDHPDRGMessage] save ztdo config for DoId=%q: %v", transactionId, addrStr, doId, err)
		errCode = 1
		errMsg = err.Error()
	}

	aakMsg := &common.DAKMsg{
		DoId:    doId,
		ErrCode: errCode,
		ErrMsg:  errMsg,
	}
	aakBytes, marshalErr := json.Marshal(aakMsg)
	if marshalErr != nil {
		log.Error("server-db(DoId=%q,trx=#%d@%s)[HandleDHPDRGMessage] failed to marshal DAK message: %v", doId, transactionId, addrStr, marshalErr)
		return marshalErr
	}
	aakMd := makeMsgData(ppd, core.NHP_DAK, aakBytes)

	return s.forwardToTransaction(ppd.ConnData, transactionId, aakMd, "server-db", "HandleDHPDRGMessage", doId, addrStr)
}

func (s *UdpServer) onAttestationVerify(spo *common.SmartPolicy, attestation string) error {
	if spo.Policy == "" {
		return nil
	}

	wasmBytes, err := base64.StdEncoding.DecodeString(spo.Policy)
	if err != nil {
		wasmPath, err := utils.DownloadFileToTemp(spo.Policy, "wasm-")
		if err != nil {
			return err
		}
		defer func() { _ = os.Remove(filepath.Dir(wasmPath)) }() // LIFO: runs second, removes empty dir
		defer func() { _ = os.Remove(wasmPath) }()               // LIFO: runs first, removes file
		wasmBytes, err = os.ReadFile(wasmPath)
		if err != nil {
			return err
		}
	}

	engine := wasmEngine.NewEngine()
	defer engine.Close()
	if err = engine.LoadWasm(wasmBytes); err != nil {
		return err
	}

	if engine.OnAttestationVerify(attestation) {
		return nil
	}
	return errors.New("attestation verification failed")
}

// errReadConfigFailed / errSaveConfigFailed are fixed sentinels returned
// from ReadZdtoConfig / SaveZdtoConfig when a non-validation error fires
// (os.Open / os.MkdirAll / utils.SaveStructAsJsonFile all wrap
// *PathError with the full filesystem path, which would leak ExeDirPath
// if echoed on the wire). The raw underlying error goes to the server
// log; callers echo these sentinels to the wire without further scrub.
// Kept unexported — only in-package callers (HandleDHPDRGMessage /
// HandleDHPDAVMessage) distinguish invalid-input vs. read vs. save, and
// they do so by the call site, not errors.Is. Promote to nhp/common
// alongside ErrInvalidDoID if a cross-package caller ever needs the
// classification.
var (
	errReadConfigFailed = errors.New("ztdo config read failed")
	errSaveConfigFailed = errors.New("ztdo config save failed")
)

func SaveZdtoConfig(drgMsg *common.DRGMsg) error {
	objectId := drgMsg.DoId
	if err := common.ValidateDoID(objectId); err != nil {
		// Intrusion-detection signal: post-auth malformed DoId is either
		// an agent bug or an attack attempt. Log %q of the raw value for
		// operator triage; the sentinel returned to the caller carries
		// none of the attacker bytes.
		log.Warning("server[SaveZdtoConfig] rejected DoId=%q: %v", objectId, err)
		return err
	}
	configFileName := "data-" + objectId + ".json"

	etcDir := filepath.Join(ExeDirPath, "etc", "ztdo")
	configPath := filepath.Join(etcDir, configFileName)

	if existingDrgMsg, err := ReadZdtoConfig(objectId); err == nil {
		// alway keep original date source type
		drgMsg.DataSourceType = existingDrgMsg.DataSourceType

		if drgMsg.AccessUrl == "" { // provider update access url
			drgMsg.AccessUrl = existingDrgMsg.AccessUrl
		}

		_ = os.Remove(configPath)
	}

	// All non-validation errors below wrap *PathError with the full
	// filesystem path. Log raw with DoId context for triage, return the
	// scrubbed sentinel on the wire.
	if err := os.MkdirAll(etcDir, 0755); err != nil {
		log.Error("server[SaveZdtoConfig] DoId=%q mkdir: %v", objectId, err)
		return errSaveConfigFailed
	}

	if _, err := os.Stat(configPath); err == nil {
		log.Error("server[SaveZdtoConfig] DoId=%q already exists at %s", objectId, configPath)
		return errSaveConfigFailed
	}

	if err := utils.SaveStructAsJsonFile(configPath, drgMsg); err != nil {
		log.Error("server[SaveZdtoConfig] DoId=%q write: %v", objectId, err)
		return errSaveConfigFailed
	}
	return nil
}

// ReadZdtoConfig reads data-<doId>.json into a DRGMsg. Validates doId
// before touching the filesystem and scrubs filesystem-path errors
// before returning — callers may echo the returned error on the wire
// without leaking ExeDirPath.
func ReadZdtoConfig(doId string) (common.DRGMsg, error) {
	if err := common.ValidateDoID(doId); err != nil {
		log.Warning("server[ReadZdtoConfig] rejected DoId=%q: %v", doId, err)
		return common.DRGMsg{}, err
	}
	etcDir := filepath.Join(ExeDirPath, "etc", "ztdo")
	configFilePath := filepath.Join(etcDir, "data-"+doId+".json")
	file, err := os.Open(configFilePath)
	if err != nil {
		// os.ErrNotExist is the normal happy-path result on a first save —
		// SaveZdtoConfig probes via ReadZdtoConfig to decide whether to
		// carry forward the prior DataSourceType. Logging those at ERROR
		// polluted the server error log with "no such file" on every new
		// DoId and made real read failures harder to triage. Demote the
		// not-exist case to DEBUG; keep everything else at ERROR since
		// those are genuine failures (permission denied, partial FS, etc).
		if errors.Is(err, fs.ErrNotExist) {
			log.Debug("server[ReadZdtoConfig] DoId=%q not found: %v", doId, err)
		} else {
			log.Error("server[ReadZdtoConfig] DoId=%q open: %v", doId, err)
		}
		return common.DRGMsg{}, errReadConfigFailed
	}
	defer func() { _ = file.Close() }()

	fileContentByte, err := io.ReadAll(file)
	if err != nil {
		log.Error("server[ReadZdtoConfig] DoId=%q read: %v", doId, err)
		return common.DRGMsg{}, errReadConfigFailed
	}

	var config common.DRGMsg

	if err := json.Unmarshal(fileContentByte, &config); err != nil {
		log.Error("server[ReadZdtoConfig] DoId=%q unmarshal: %v", doId, err)
		return common.DRGMsg{}, errReadConfigFailed
	}
	return config, nil
}
