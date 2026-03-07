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
)

const maxForwardResponseSize int64 = 64 << 10 // 64 KiB — ACK messages are typically < 1 KB

// HttpKnockForwardRequest is the JSON body sent between servers for internal knock forwarding.
type HttpKnockForwardRequest struct {
	Request  *common.HttpKnockRequest `json:"request"`
	Resource *common.ResourceData     `json:"resource"`
}

// HttpKnockForwardResponse is the JSON response from an internal knock forward.
type HttpKnockForwardResponse struct {
	AckMsg *common.ServerKnockAckMsg `json:"ack_msg"`
	Error  string                    `json:"error,omitempty"`
}

// HttpKnockForwarder forwards HTTP knock requests to assigned servers when
// the receiving server doesn't have a direct AC connection.
var errForwarderStopped = errors.New("forwarder is shutting down")

type HttpKnockForwarder struct {
	storage    StorageBackend
	cloudMap   HealthChecker
	localIP    string
	httpPort   int
	httpClient *http.Client
	stopped    atomic.Bool
	wg         sync.WaitGroup // tracks in-flight forwards for graceful shutdown
}

// NewHttpKnockForwarder creates a new HTTP knock forwarder.
func NewHttpKnockForwarder(storage StorageBackend, cloudMap HealthChecker, localIP string, httpPort int) *HttpKnockForwarder {
	return &HttpKnockForwarder{
		storage:  storage,
		cloudMap: cloudMap,
		localIP:  localIP,
		httpPort: httpPort,
		httpClient: &http.Client{
			Timeout: 2 * time.Second, // Per-request timeout; must be < parent context (10s) to allow retries
		},
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
			lastErr = err
			continue
		}
		log.Info("HTTP knock forwarded to %s (%s) for AC %s", srv.ID, srv.InternalIP, acID)
		return ackMsg, nil
	}

	return nil, fmt.Errorf("all %d servers failed for AC %s: %w", len(servers), acID, lastErr)
}

// filterForwardTargets returns assigned servers that are healthy and not this server.
func (f *HttpKnockForwarder) filterForwardTargets(ctx context.Context, servers []ServerInfo) []ServerInfo {
	// Filter to healthy servers first
	healthy := servers
	if f.cloudMap != nil && !f.cloudMap.IsNil() {
		healthy = FilterHealthyServers(ctx, f.cloudMap, servers)
	}

	// Exclude self
	var targets []ServerInfo
	for _, srv := range healthy {
		if srv.InternalIP != f.localIP {
			targets = append(targets, srv)
		}
	}
	return targets
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
