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
	"sync"
	"sync/atomic"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
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
}

// HttpKnockForwardResponse is the JSON response from an internal knock forward.
type HttpKnockForwardResponse struct {
	AckMsg *common.ServerKnockAckMsg `json:"ack_msg"`
	Error  string                    `json:"error,omitempty"`
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
// Returns nil if no assignment exists or all assigned servers fail.
func (f *HttpKnockForwarder) ForwardHttpKnock(
	ctx context.Context,
	acID string,
	req *common.HttpKnockRequest,
	res *common.ResourceData,
) (*common.ServerKnockAckMsg, error) {
	if f.stopped.Load() {
		return nil, errForwarderStopped
	}
	f.wg.Add(1)
	defer f.wg.Done()

	if f.storage == nil {
		return nil, fmt.Errorf("no storage backend configured")
	}

	// Look up AC assignment
	assignment, err := f.storage.GetACAssignment(ctx, acID)
	if err != nil {
		if IsNotFoundError(err) {
			return nil, fmt.Errorf("no AC assignment found for %s", acID)
		}
		return nil, fmt.Errorf("storage error for AC %s: %w", acID, err)
	}

	// Check TTL expiry
	if assignment.TTL != nil && *assignment.TTL < time.Now().Unix() {
		return nil, fmt.Errorf("AC assignment expired for %s", acID)
	}

	// Filter to healthy servers, excluding self
	servers := f.filterForwardTargets(ctx, assignment.AssignedServers)
	if len(servers) == 0 {
		return nil, fmt.Errorf("no available servers to forward knock for AC %s", acID)
	}

	// Shuffle for load distribution
	rand.Shuffle(len(servers), func(i, j int) {
		servers[i], servers[j] = servers[j], servers[i]
	})

	// Try each server until one succeeds
	var lastErr error
	for _, srv := range servers {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("context canceled before trying %s: %w", srv.ID, ctx.Err())
		}
		ackMsg, err := f.forwardToServer(ctx, srv, req, res)
		if err != nil {
			log.Warning("HTTP knock forward to %s (%s) failed: %v", srv.ID, srv.InternalIP, err)
			f.markFailed(srv.InternalIP)
			lastErr = err
			continue
		}
		log.Info("HTTP knock forwarded to %s (%s) for AC %s", srv.ID, srv.InternalIP, acID)
		return ackMsg, nil
	}

	// All forwards failed — invalidate CloudMap cache so next attempt gets fresh data
	if f.cloudMap != nil && !f.cloudMap.IsNil() {
		f.cloudMap.InvalidateCache()
	}

	return nil, fmt.Errorf("all %d servers failed for AC %s: %w", len(servers), acID, lastErr)
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
		return nil, fmt.Errorf("remote error: %s", fwdResp.Error)
	}

	return fwdResp.AckMsg, nil
}

// isPrivateIP checks if an IP address is in RFC 1918 private or loopback address space.
func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	return ip.IsPrivate() || ip.IsLoopback()
}
