package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
	"github.com/OpenNHP/opennhp/nhp/log"
	"github.com/layervai/nhp/internalauth"
)

// maxForwardResponseSize bounds the outbound ACK read. Sibling of
// maxInternalKnockRequestSize (request side); both are 64 KiB today
// and kept in sync by the TestMaxForwardResponseSize assertion —
// intentional divergence would update the test at the same time.
// The two literals are declared separately (not aliased) so a
// tuning PR that diverges them produces a diff in both places
// rather than silently propagating through the alias.
const maxForwardResponseSize int64 = 64 << 10 // 64 KiB — ACK messages are typically < 1 KB

// maxInternalKnockRequestSize caps the POST body /nhp/internal/knock
// accepts, used by handleInternalKnock to trip a 413 before the HMAC
// compute. Kept equal to maxForwardResponseSize via the test below;
// separate literal so a future tuning PR that intentionally
// diverges them produces an explicit test update.
const maxInternalKnockRequestSize int64 = 64 << 10 // 64 KiB — knock-forward request envelope

// maxPluginRequestSize caps the request body for /plugins/:aspid. The
// qurl plugin's POST body today is ~200 bytes (token + 6 small numeric
// timing fields per #1824); 16 KiB is generous headroom for any future
// plugin payload while bounding a downstream parse path's exposure to
// adversarial input. Defense-in-depth on top of Go's defaultMaxMemory
// for ParseForm (10 MiB), which is generous enough to be a real DoS
// surface for parser-heavy plugins.
//
// Layered with edge WAF on envs that set
// `deploy_qurl_link && enable_resolve_cloudfront` (sandbox and prod
// today). Production traffic to `resolve.${qurl_link_frontend_domain}`
// (e.g., `resolve.qurl.link.layerv.xyz` in sandbox) fronts the
// qurl_resolve CloudFront distribution
// (terraform/main.tf::aws_wafv2_web_acl.qurl_resolve), whose
// AWSManagedRulesCommonRuleSet rule SizeRestrictions_BODY blocks
// request bodies larger than 8 KiB at the edge. Via that path this
// 16 KiB server cap is structurally unreachable — the 413 code path
// can only be exercised from a non-WAF ingress (NLB-direct, the
// path the smoke suite probes; a greenfield env that opts out of
// `enable_resolve_cloudfront`; or any future internal/non-CF
// endpoint).
//
// The 2× gap (WAF 8 KiB, server 16 KiB) is deliberate: a plugin
// payload growth up to the 16 KiB cap shouldn't force re-tuning the
// AWS-managed WAF rule, and if WAF is ever loosened or excluded the
// server still rejects oversize POSTs. The WAF rule is declared in
// Terraform but has no CI fence asserting it stays present — #1879
// tracks adding one. Until then, a TF change that removed or
// downgraded SizeRestrictions_BODY would silently let POSTs in the
// 8–16 KiB range reach the server (admitted deliberately by the 2×
// headroom above) and would also let arbitrarily large POSTs
// through — the 16 KiB cap is the backstop for the unbounded case.
const maxPluginRequestSize int64 = 16 << 10 // 16 KiB — plugin request envelope

// SourceAPI is the Source value set by API callers (e.g., qurl-service headless resolve).
// When set, the receiving server may forward the knock to another server if the AC
// isn't connected locally, unlike server-to-server forwards which set Forwarded=true.
const SourceAPI = "api"

// HttpKnockForwardRequest is the JSON body sent between servers for internal knock forwarding.
type HttpKnockForwardRequest struct {
	Request  *common.HttpKnockRequest `json:"request"`
	Resource *common.ResourceData     `json:"resource"`
	Source   string                   `json:"source,omitempty"` // See SourceAPI const

	// Attestation cryptographically binds a server-to-server forward hop
	// to the forwarding server's NHP identity (issue #1127). nil on
	// API-origin requests (the start of the chain) and on legacy senders
	// during rollout. See forward_hop_attest.go and
	// docs/design/INTERNAL_FORWARD_HOP_ATTESTATION.md.
	Attestation *ForwardHopAttestation `json:"hop_attestation,omitempty"`
}

// ForwardHopAttestation is the per-hop identity binding carried on
// server-to-server forwards. The MAC is HMAC-SHA256 under a per-pair key
// derived from ECDH(senderPriv, recipientPub), so only the sender and the
// named recipient can compute it. See verifyForwardHopAttestation.
type ForwardHopAttestation struct {
	SenderPubKey string `json:"sender_pubkey"` // base64 NHP static pubkey of the forwarding server
	Hop          int    `json:"hop"`           // server-to-server hop count (origin=0; first forward=1)
	Timestamp    int64  `json:"ts"`            // unix seconds; freshness bound
	MAC          string `json:"mac"`           // lowercase hex HMAC-SHA256 under the per-pair ECDH key
}

// HttpKnockForwardResponse is the JSON response from an internal knock forward.
type HttpKnockForwardResponse struct {
	AckMsg *common.ServerKnockAckMsg `json:"ack_msg"`
	Error  string                    `json:"error,omitempty"`
}

// ForwardOutcome is the bounded, low-cardinality classification of a single
// ForwardHttpKnock call, for failure attribution (qurl-service#976 Phase 0A).
// It splits the pre-existing single KnockForwardFailure counter by *cause* so a
// deploy produces a histogram instead of one opaque number — in particular it
// gives the 06:47 "peer is alive but holds no AC" signature its own bucket
// (ForwardRemoteNoAC). It is a metric dimension value, so it MUST stay a small
// closed set; never fold raw ids/ips/error-strings into it.
type ForwardOutcome string

const (
	ForwardSuccess             ForwardOutcome = "success"
	ForwardForwarderStopped    ForwardOutcome = "forwarder_stopped"
	ForwardNoStorage           ForwardOutcome = "no_storage"
	ForwardNoAssignment        ForwardOutcome = "no_assignment"
	ForwardStorageError        ForwardOutcome = "storage_error"
	ForwardAssignmentExpired   ForwardOutcome = "assignment_expired"
	ForwardAllTargetsFiltered  ForwardOutcome = "all_targets_filtered"
	ForwardContextCanceled     ForwardOutcome = "context_canceled"
	ForwardRequestFailed       ForwardOutcome = "request_failed"
	ForwardRemoteHTTPError     ForwardOutcome = "remote_http_error"
	ForwardRemoteDecodeError   ForwardOutcome = "remote_decode_error"
	ForwardRemoteNoAC          ForwardOutcome = "remote_no_ac"
	ForwardRemoteACOpsFailed   ForwardOutcome = "remote_ac_ops_failed"
	ForwardRemoteNonSuccessAck ForwardOutcome = "remote_non_success_ack"
)

// classifyForwardAttempt maps a single forwardToServer (ack, err) result to a
// ForwardOutcome. On the remote-error path forwardToServer returns the parsed
// peer ack alongside the error (so ack != nil), which lets us read the peer's
// structured ErrCode/ErrMsg rather than string-matching the transport error.
// The 06:47 no-AC signature arrives as the aggregate ErrServerACOpsFailed whose
// detail carries ErrACConnectionNotFound's message, so we check both the code
// and that message before falling back to the generic AC-ops bucket.
func classifyForwardAttempt(ack *common.ServerKnockAckMsg, err error) ForwardOutcome {
	if err == nil {
		return ForwardSuccess
	}
	// Structured peer response (HTTP 200 with a non-success ack).
	if ack != nil {
		switch {
		case ack.ErrCode == common.ErrACConnectionNotFound.ErrorCode() ||
			strings.Contains(ack.ErrMsg, common.ErrACConnectionNotFound.Error()):
			return ForwardRemoteNoAC
		case ack.ErrCode == common.ErrServerACOpsFailed.ErrorCode():
			return ForwardRemoteACOpsFailed
		default:
			return ForwardRemoteNonSuccessAck
		}
	}
	// Transport / protocol errors carry no parsed ack. Keep this coarse and
	// string-based only here (these buckets are rare and not the signal we
	// chase); the important remote_* buckets above are structured.
	msg := err.Error()
	switch {
	case errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded):
		return ForwardContextCanceled
	case strings.Contains(msg, "unmarshal response"):
		return ForwardRemoteDecodeError
	case strings.Contains(msg, "server returned "), strings.Contains(msg, "response too large"):
		return ForwardRemoteHTTPError
	default:
		return ForwardRequestFailed
	}
}

// HttpKnockForwarder forwards HTTP knock requests to assigned servers when
// the receiving server doesn't have a direct AC connection.
var errForwarderStopped = errors.New("forwarder is shutting down")

// httpForwardHealthDecay is how long a server is considered unhealthy after a
// failed forward. Prevents wasting 2s per request on known-dead servers.
// 30s is long enough to avoid retry storms on dead servers but short enough
// that a recovered server (e.g., after AC reconnection) becomes eligible
// quickly. Matches the NLB target group health check interval (2 × 10s).
const httpForwardHealthDecay = 30 * time.Second

// failedServersEvictThreshold is the map size above which markFailed scans
// for expired entries. Below this threshold, expired entries are cleaned up
// lazily when encountered in filterForwardTargets. Set to 20 because typical
// fleet sizes are 3-10 servers; eviction overhead is irrelevant at that scale.
const failedServersEvictThreshold = 20

// MetricCounter is a callback for emitting counter metrics without
// coupling the forwarder to a specific metrics implementation.
type MetricCounter func(name string)

type HttpKnockForwarder struct {
	storage    StorageBackend
	cloudMap   HealthChecker
	localIP    string
	httpPort   int
	httpClient *http.Client
	stopped    atomic.Bool
	wg         sync.WaitGroup // tracks in-flight forwards for graceful shutdown
	emitMetric MetricCounter  // optional; nil-safe

	// internalAuthSigner, when non-nil, signs outgoing /nhp/internal/knock
	// forwards so the receiving nhp-server can verify the request came
	// from a party holding the shared secret. Nil in legacy mode (the
	// pre-HMAC-gate posture). Must be the same signer the verifier
	// uses — both sides construct it from the same
	// NHP_INTERNAL_AUTH_SECRET env var.
	internalAuthSigner *internalauth.Signer

	// selfEcdh / selfPubKey, when set, make the forwarder attest each
	// outgoing server-to-server hop with this server's NHP identity
	// (issue #1127). selfEcdh nil = attestation disabled (local/test mode
	// with no device keypair). Set once via EnableForwardHopAttestation
	// at Start, before any forward fires; read-only thereafter.
	selfEcdh   core.Ecdh
	selfPubKey string

	// failedServers tracks servers that recently failed forward attempts.
	// Key: InternalIP, Value: time of last failure.
	// Servers are considered unhealthy for httpForwardHealthDecay after failure.
	failedMu      sync.RWMutex
	failedServers map[string]time.Time
}

// NewHttpKnockForwarder creates a new HTTP knock forwarder. Pass nil
// for internalAuthSigner in legacy mode (no internal-auth secret configured);
// callers that want the forwarder to sign outgoing requests must
// thread the same signer used by the incoming verifier
// (handleInternalKnock).
func NewHttpKnockForwarder(storage StorageBackend, cloudMap HealthChecker, localIP string, httpPort int, emitMetric MetricCounter, internalAuthSigner *internalauth.Signer) *HttpKnockForwarder {
	return &HttpKnockForwarder{
		storage:  storage,
		cloudMap: cloudMap,
		localIP:  localIP,
		httpPort: httpPort,
		httpClient: &http.Client{
			Timeout: 2 * time.Second, // Per-request timeout; must be < parent context (10s) to allow retries
			// Refuse redirects explicitly. The signature covers the
			// original Method+URL.Path; if a redirect landed at a
			// different URL, the Client would silently re-issue the
			// request without re-signing and the receiver would 401.
			// Returning ErrUseLastResponse surfaces the first
			// response as-is so a misconfigured target produces a
			// loud failure, not a silent stale-signature reject.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		emitMetric:         emitMetric,
		internalAuthSigner: internalAuthSigner,
		failedServers:      make(map[string]time.Time),
	}
}

// EnableForwardHopAttestation makes the forwarder sign each outgoing
// server-to-server hop with this server's NHP identity (issue #1127).
// Pass the server's static ECDH (device.GetEcdhByCipherScheme) and its
// base64 pubkey (device.PublicKeyBase64). A nil selfEcdh leaves
// attestation disabled — the legacy/local posture. Call once at Start
// before serving; the fields are read by forward goroutines without
// further synchronization (the happens-before edge is the Start →
// goroutine launch, identical to internalAuthSigner).
func (f *HttpKnockForwarder) EnableForwardHopAttestation(selfEcdh core.Ecdh, selfPubKey string) {
	f.selfEcdh = selfEcdh
	f.selfPubKey = selfPubKey
}

// Stop stops the forwarder and waits for in-flight forwards to complete.
// Times out after 10 seconds to prevent indefinite shutdown blocking.
func (f *HttpKnockForwarder) Stop() {
	f.stopped.Store(true)
	done := make(chan struct{})
	go func() {
		f.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		log.Warning("HttpKnockForwarder shutdown timed out, some forwards may still be in flight")
	}
}

// ForwardHttpKnock looks up the AC assignment and forwards the knock to an assigned server.
// Returns (ack, outcome, error): on success ack is non-nil and outcome is
// ForwardSuccess; on failure the outcome is a bounded ForwardOutcome (Phase 0A,
// qurl-service#976) so callers can split the opaque KnockForwardFailure counter
// by cause. The (ack, error) semantics are unchanged — outcome is additive.
func (f *HttpKnockForwarder) ForwardHttpKnock(
	ctx context.Context,
	acID string,
	req *common.HttpKnockRequest,
	res *common.ResourceData,
) (ack *common.ServerKnockAckMsg, outcome ForwardOutcome, err error) {
	// Attribution fields for the structured failure log emitted on return.
	var assignmentVersion, assignmentSize, selectedTargets, attemptedTargets int
	var lastTargetID, lastTargetIP, remoteAckErrCode string
	defer func() {
		// Failure attribution is a Debug detail line: the KnockForwardOutcome
		// metric + the handler's terminal "all AC operations failed" Error carry
		// the signal, so this stays off the trough hot path (benign buckets like
		// no_assignment/all_targets_filtered would otherwise spam Warning). Success
		// skips it entirely (no formatting cost).
		if outcome == ForwardSuccess {
			return
		}
		log.Debug("http knock forward attribution outcome=%s ac=%s assignment_version=%d assignment_size=%d selected_targets=%d attempted_targets=%d last_target_id=%s last_target_ip=%s remote_ack_err_code=%s",
			outcome, acID, assignmentVersion, assignmentSize, selectedTargets, attemptedTargets, lastTargetID, lastTargetIP, remoteAckErrCode)
	}()

	if f.stopped.Load() {
		return nil, ForwardForwarderStopped, errForwarderStopped
	}
	f.wg.Add(1)
	defer f.wg.Done()

	if f.storage == nil {
		return nil, ForwardNoStorage, fmt.Errorf("no storage backend configured")
	}

	// Look up AC assignment
	assignment, gerr := f.storage.GetACAssignment(ctx, acID)
	if gerr != nil {
		if IsNotFoundError(gerr) {
			return nil, ForwardNoAssignment, fmt.Errorf("no AC assignment found for %s", acID)
		}
		return nil, ForwardStorageError, fmt.Errorf("storage error for AC %s: %w", acID, gerr)
	}
	assignmentVersion = assignment.Version
	assignmentSize = len(assignment.AssignedServers)

	// Check TTL expiry
	if assignment.TTL != nil && *assignment.TTL < time.Now().Unix() {
		return nil, ForwardAssignmentExpired, fmt.Errorf("AC assignment expired for %s", acID)
	}

	// Filter to healthy servers, excluding self
	servers := f.filterForwardTargets(ctx, assignment.AssignedServers)
	selectedTargets = len(servers)
	if selectedTargets == 0 {
		return nil, ForwardAllTargetsFiltered, fmt.Errorf("no available servers to forward knock for AC %s", acID)
	}

	// Shuffle for load distribution
	rand.Shuffle(len(servers), func(i, j int) {
		servers[i], servers[j] = servers[j], servers[i]
	})

	// Try each server until one succeeds
	var lastErr error
	var lastAck *common.ServerKnockAckMsg
	for _, srv := range servers {
		if ctx.Err() != nil {
			return nil, ForwardContextCanceled, fmt.Errorf("context canceled before trying %s: %w", srv.ID, ctx.Err())
		}
		attemptedTargets++
		lastTargetID, lastTargetIP = srv.ID, srv.InternalIP
		ackMsg, ferr := f.forwardToServer(ctx, srv, req, res)
		if ferr != nil {
			log.Warning("HTTP knock forward to %s (%s) failed: %v", srv.ID, srv.InternalIP, ferr)
			f.markFailed(srv.InternalIP)
			lastErr, lastAck = ferr, ackMsg
			if ackMsg != nil {
				remoteAckErrCode = ackMsg.ErrCode
			}
			continue
		}
		log.Info("HTTP knock forwarded to %s (%s) for AC %s", srv.ID, srv.InternalIP, acID)
		return ackMsg, ForwardSuccess, nil
	}

	// All forwards failed — invalidate CloudMap cache so next attempt gets fresh data
	if f.cloudMap != nil && !f.cloudMap.IsNil() {
		f.cloudMap.InvalidateCache()
	}

	return nil, classifyForwardAttempt(lastAck, lastErr), fmt.Errorf("all %d servers failed for AC %s: %w", len(servers), acID, lastErr)
}

// FanoutHttpKnock forwards the knock to one currently healthy assigned peer
// server per non-local AZ in parallel -- not first-success -- purely so each AZ
// opens its local AC pinhole. This is the HTTP qURL half of the
// qurl-service#948 fix: the origin server already opened its local ACs, and the
// assignment row is the bounded routing table for the AZs that still need the
// forwarded knock.
//
// It does NOT produce the knock ack (the caller owns that from its local
// broadcast / failover); the return is coverage observability only —
// peersAccepted is how many peers reported a successful open. The req MUST carry
// Forwarded=true (use buildForwardedKnock) so a peer does not re-fan-out;
// forwardToServer's /nhp/internal/knock receiver re-enters handleHttpOpenResource
// with that flag, whose fan-out gate is !Forwarded, bounding depth to one hop.
//
// A non-nil error means the assignment itself could not be resolved; the caller
// logs and proceeds on its local coverage. Individual peer failures are logged +
// metered, never surfaced — a single down peer must not fail an otherwise-good
// knock.
func (f *HttpKnockForwarder) FanoutHttpKnock(
	ctx context.Context,
	acID string,
	req *common.HttpKnockRequest,
	res *common.ResourceData,
) (peersAccepted int, err error) {
	if f.stopped.Load() {
		return 0, errForwarderStopped
	}
	f.wg.Add(1)
	defer f.wg.Done()

	if f.storage == nil {
		return 0, fmt.Errorf("no storage backend configured")
	}

	assignment, err := f.storage.GetACAssignment(ctx, acID)
	if err != nil {
		if IsNotFoundError(err) {
			return 0, fmt.Errorf("no AC assignment found for %s", acID)
		}
		return 0, fmt.Errorf("storage error for AC %s: %w", acID, err)
	}
	if assignment.TTL != nil && *assignment.TTL < time.Now().Unix() {
		return 0, fmt.Errorf("AC assignment expired for %s", acID)
	}

	// Current healthy assigned peers, bounded to one target per non-local AZ.
	// Unlike first-success ForwardHttpKnock, coverage fanout intentionally
	// ignores the stale local failure cache: a transient failure must not
	// suppress an entire AZ's pinhole attempt. Zero peers is not an error: a
	// single-server cell has no non-local AZ target to forward to.
	servers := f.filterFanoutTargets(ctx, assignment.AssignedServers)
	if len(servers) == 0 {
		return 0, nil
	}

	f.metric(MetricKnockFanout)

	var wg sync.WaitGroup
	var accepted atomic.Int32
	for _, srv := range servers {
		wg.Add(1)
		go func(srv ServerInfo) {
			defer wg.Done()
			ackMsg, ferr := f.forwardToServer(ctx, srv, req, res)
			if ferr != nil {
				f.markFailed(srv.InternalIP)
				f.metric(MetricKnockFanoutPeerFail)
				log.Warning("knock fan-out to %s (%s) failed for AC %s: %v", srv.ID, srv.InternalIP, acID, ferr)
				return
			}
			// A structured non-success ack (e.g. the peer holds none of the
			// fleet's ACs) is not a fan-out failure — that peer simply opened
			// nothing. Only a real success counts toward coverage.
			if ackMsg != nil && ackMsg.ErrCode == common.ErrSuccess.ErrorCode() {
				accepted.Add(1)
				f.metric(MetricKnockFanoutPeerSuccess)
			}
		}(srv)
	}
	wg.Wait()
	return int(accepted.Load()), nil
}

// filterFanoutTargets returns at most one currently healthy assigned server per
// non-local AZ. Coverage fanout does not consult failedServers because that
// cache is intentionally stale for httpForwardHealthDecay, while fanout is the
// mechanism that creates one effective pinhole per assigned AZ. This path still
// treats CloudMap health as authoritative, unlike native fanout's local
// failure-cache fallback: an AZ whose only peer is CloudMap-unhealthy is skipped
// rather than retried as stale-local-health.
func (f *HttpKnockForwarder) filterFanoutTargets(ctx context.Context, servers []ServerInfo) []ServerInfo {
	healthy := servers
	if f.cloudMap != nil && !f.cloudMap.IsNil() {
		healthy = FilterHealthyServers(ctx, f.cloudMap, servers)
	}
	// Count after CloudMap filtering because HTTP fanout treats unhealthy peers
	// as absent. Native fanout counts the raw assignment instead because its
	// local failure cache is only a stale preference signal.
	if duplicateAZBuckets := countDuplicateFanoutAZBuckets(healthy, f.localIP); duplicateAZBuckets > 0 {
		for i := 0; i < duplicateAZBuckets; i++ {
			f.metric(MetricKnockFanoutDuplicateAZCandidate)
		}
		log.Warning("knock fan-out saw %d non-local AZ bucket(s) with multiple healthy assigned peer candidates; still selecting one peer per AZ", duplicateAZBuckets)
	}

	return selectAssignedFanoutTargetsByAZ(healthy, f.localIP)
}

// filterForwardTargets returns assigned servers that are healthy and not this server.
func (f *HttpKnockForwarder) filterForwardTargets(ctx context.Context, servers []ServerInfo) []ServerInfo {
	// Filter to healthy servers first (CloudMap, if available)
	healthy := servers
	if f.cloudMap != nil && !f.cloudMap.IsNil() {
		healthy = FilterHealthyServers(ctx, f.cloudMap, servers)
	}

	// Exclude self and recently-failed servers
	f.failedMu.RLock()
	now := time.Now()
	var targets []ServerInfo
	for _, srv := range healthy {
		if srv.InternalIP == f.localIP {
			continue
		}
		if failedAt, failed := f.failedServers[srv.InternalIP]; failed && now.Sub(failedAt) < httpForwardHealthDecay {
			log.Debug("Skipping recently-failed server %s (%s), failed %v ago", srv.ID, srv.InternalIP, now.Sub(failedAt))
			f.metric(MetricKnockForwardSkippedDead)
			continue
		}
		targets = append(targets, srv)
	}
	f.failedMu.RUnlock()

	// If all servers were filtered out by failure tracking, fall back to trying
	// all non-self servers. Better to retry a possibly-recovered server than fail.
	if len(targets) == 0 {
		for _, srv := range healthy {
			if srv.InternalIP != f.localIP {
				targets = append(targets, srv)
			}
		}
		if len(targets) > 0 {
			f.metric(MetricKnockForwardFallback)
		}
	}
	return targets
}

// markFailed records a forward failure for a server IP. Evicts expired entries
// when the map exceeds failedServersEvictThreshold to avoid O(n) scans on
// every failure while still bounding memory.
func (f *HttpKnockForwarder) markFailed(ip string) {
	f.failedMu.Lock()
	now := time.Now()
	f.failedServers[ip] = now
	if len(f.failedServers) > failedServersEvictThreshold {
		for k, v := range f.failedServers {
			if now.Sub(v) >= httpForwardHealthDecay {
				delete(f.failedServers, k)
			}
		}
	}
	f.failedMu.Unlock()
}

// metric emits a counter metric if a callback is configured.
func (f *HttpKnockForwarder) metric(name string) {
	if f.emitMetric != nil {
		f.emitMetric(name)
	}
}

// forwardToServer sends the knock request to a specific server's internal endpoint.
func (f *HttpKnockForwarder) forwardToServer(
	ctx context.Context,
	srv ServerInfo,
	req *common.HttpKnockRequest,
	res *common.ResourceData,
) (*common.ServerKnockAckMsg, error) {
	// Validate target is a private IP before constructing the request to prevent SSRF
	if !isPrivateIP(srv.InternalIP) {
		return nil, fmt.Errorf("refusing to forward to non-private IP %s", srv.InternalIP)
	}

	// Source is intentionally NOT propagated to the forwarded request.
	// This ensures loop prevention: API→ServerA (Source="api", can forward)
	// → ServerA→ServerB (Source="", Forwarded=true, cannot forward).
	fwdReq := &HttpKnockForwardRequest{
		Request:  req,
		Resource: res,
	}

	// Attest this server-to-server hop with our NHP identity (issue
	// #1127) so the receiving server can attribute it and refuse a
	// spoofed or over-hop forward. Requires our own keypair AND a target
	// pubkey — the latter is briefly empty in the Cloud Map propagation
	// window just after a new server joins; we fall back to an
	// unattested forward there (the receiver's permit mode tolerates it,
	// strict mode rejects it as designed). The hop is the verified
	// incoming hop (0 for an API origin) + 1.
	//
	// Dual-registry invariant: srv.PubKey here comes from the AC
	// assignment / ServerInfo (storage), while the RECEIVER's trust anchor
	// derives the same peer's key from Cloud Map (fleetTrustAnchor). Both
	// must equal the peer's real device.PublicKeyBase64() or the per-pair
	// ECDH MAC silently fails to verify. Both are populated from each
	// server's own device key at registration, so they agree in steady
	// state; a divergence (stale assignment / mismatched registration)
	// surfaces as ForwardHopAttestPermit that never drains — see the
	// rollout-ledger pre-task and design doc. Do not source one side from a
	// different key than the other.
	if f.selfEcdh != nil && srv.PubKey != "" {
		hop := forwardHopFromContext(ctx) + 1
		// Bind the outgoing envelope Source (always "" here — forwardToServer
		// never propagates Source) so the attestation can't be replayed with
		// Source flipped to "api".
		att, attErr := buildForwardHopAttestation(f.selfEcdh, f.selfPubKey, srv.PubKey, hop, time.Now(), fwdReq.Source, req)
		if attErr != nil {
			// Non-fatal: emit unattested and let the receiver's rollout
			// mode decide. A persistent failure here shows up as the
			// receiver's permit/strict counters climbing.
			log.Warning("forward hop attest: build failed for %s (%s): %v", srv.ID, srv.InternalIP, attErr)
		} else {
			fwdReq.Attestation = att
		}
	}

	body, err := json.Marshal(fwdReq)
	if err != nil {
		return nil, fmt.Errorf("marshal forward request: %w", err)
	}

	url := fmt.Sprintf("http://%s:%d/nhp/internal/knock", srv.InternalIP, f.httpPort)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if f.internalAuthSigner != nil {
		// Sign over (method, path, body) so a VPC-local attacker that
		// intercepts the request can't swap Resource / SrcIp before it
		// reaches the peer server. httpReq.URL.Path is the path the
		// server will see on the other side (no query string is used
		// on this endpoint today — if one is added, the signer must
		// be updated on both sides to include it in the signed input).
		//
		// Use httpReq.Method / httpReq.URL.Path (not http.MethodPost /
		// the url literal) so the signed input is structurally coupled
		// to what the HTTP client will actually transmit. A future
		// refactor that flips the NewRequestWithContext method without
		// updating the Sign literal would otherwise produce a silent 401
		// instead of a compile break.
		httpReq.Header.Set(internalauth.Header, f.internalAuthSigner.Sign(httpReq.Method, httpReq.URL.Path, body))
	}

	resp, err := f.httpClient.Do(httpReq) //nolint:gosec // validated as private IP above
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxForwardResponseSize+1))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if int64(len(respBody)) > maxForwardResponseSize {
		return nil, fmt.Errorf("response too large (%d bytes)", len(respBody))
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned %d: %s", resp.StatusCode, string(respBody))
	}

	var fwdResp HttpKnockForwardResponse
	if err := json.Unmarshal(respBody, &fwdResp); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	if fwdResp.Error != "" {
		// Return the parsed peer ack alongside the error (Phase 0A) so callers
		// can read the peer's structured ErrCode/ErrMsg to classify remote_no_ac
		// vs remote_ac_ops_failed rather than string-matching the transport error.
		// Callers that ignore the ack on error (FanoutHttpKnock) are unaffected.
		return fwdResp.AckMsg, fmt.Errorf("remote error: %s", fwdResp.Error)
	}

	return fwdResp.AckMsg, nil
}

// buildForwardedKnock returns the knock request and caller resource to
// forward when this server has no local AC connection for the resolved
// resource.
//
// The /plugins/:aspid entrypoint (httpserver.go) builds req with only
// AuthServiceId populated — the resId is resolved into res and never copied
// onto req. The internal-knock receiver resolves a resource by (aspId, resId)
// and rejects any forward whose request omits either with 400 "missing aspId
// or resId" (resolveInternalKnockResource → errInvalidInternalKnockRequest).
// So forwarding the bare req silently 400'd every cross-server knock on the
// qURL resolve path: an InService server that lacked a local AC connection
// could not be rescued by a peer that had one, surfacing as
// ErrACConnectionNotFound 500s during AC-connection churn.
//
// resId is taken from res.ResourceId — the resolved resource the receiver
// resolves by, the same value handleHttpOpenResource feeds to
// knkMsg.ResourceId — not from an inner res.Resources key, so it carries the
// correct identity without depending on the catalog's "inner Resources key ==
// resId" shape (resource_lookup.go). This is deliberately the group-level
// resId, not the per-iteration inner resName: a forward triggered by one
// missing AC in a (hypothetical) multi-resource group carries the group id and
// the receiver re-resolves the whole group — matching the pre-existing
// whole-res forward semantics. On the qURL resolve path the group is a single
// resource, so the distinction is moot today.
//
// callerResource carries only the scalars the receiver's
// resolveInternalKnockResource consults — (aspId, resId) for its consistency
// check and OpenTime for the bounded-open override; it never reads Resources,
// so none are attached.
//
// Only scalar fields may be set on the returned request copy: it shallow-
// copies req, so reference fields (Url, Ctx) still alias the caller's req and
// writing one would leak back into the shared request mid-loop.
func buildForwardedKnock(req *common.HttpKnockRequest, res *common.ResourceData) (*common.HttpKnockRequest, *common.ResourceData) {
	fwdReq := *req
	fwdReq.ResourceId = res.ResourceId
	fwdRes := &common.ResourceData{
		ResourceGroup: common.ResourceGroup{
			AuthServiceId: req.AuthServiceId,
			ResourceId:    res.ResourceId,
			OpenTime:      res.OpenTime,
		},
	}
	return &fwdReq, fwdRes
}

// isPrivateIP checks if an IP address is in RFC 1918 private or loopback address space.
func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	return ip.IsPrivate() || ip.IsLoopback()
}
