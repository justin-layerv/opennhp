//go:build smoke

package smoke

// Tier 1: NHP server's HTTP IdleTimeout MUST exceed CloudFront's
// origin_keepalive_timeout (30s, see
// terraform/main.tf::aws_cloudfront_distribution.qurl_resolve and the
// `terraform_data.http_keepalive_contract` preconditions). When it
// doesn't, CF's origin
// connection pool reuses sockets the server has already FIN'd → next POST
// on that socket gets RST → CF returns 502 to the viewer (CF doesn't retry
// non-idempotent methods). Pre-fix the upstream-OpenNHP default was 6000ms;
// any idle gap >= 7s would FIN the connection before reuse.
//
// Probe: bypass CloudFront, hit resolve-origin.<env>:443 directly, send
// one POST with an invalid token (gets fast 403), hold the connection idle
// for `idleProbeGapSeconds`, send a second POST on the same TCP+TLS
// connection, assert the second send + read succeeded AND returned 403.
// The 403 assertion is load-bearing: it confirms the handler is alive,
// not just the TCP layer (a future bug that crashes the qurl handler but
// keeps the conn open would otherwise pass the fence).
//
// Why not probe through CloudFront: CF maintains a separate origin
// connection pool. CF would happily replay our second request on a fresh
// connection, hiding a regressed server IdleTimeout. The bug class only
// surfaces because the stale socket is in CF's pool, not ours; we need to
// own the socket to fence it.
//
// Regression fence for PR #1795. Specific numbers move over time; the
// canonical source is `endpoints/server/constants.go::DefaultHttpServerIdleTimeoutMs`
// + `terraform/main.tf::local.http_idle_timeout_ms`. The contract this
// test fences is "server idle keep-alive > CloudFront origin_keepalive_timeout
// (30s)", not any specific millisecond value.

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"testing"
	"time"
)

const (
	// idleProbeGapSeconds intentionally lags the contract. The full
	// contract — `IdleTimeoutMs >= origin_keepalive_timeout + 5s` — is
	// owned and enforced by the `terraform_data.http_keepalive_contract`
	// preconditions at plan time. This smoke fence is a runtime
	// corroborator: it asserts only the looser, proxy-visible invariant
	// "server holds idle connections longer than CF's keep-alive (30s)",
	// which is the immediate condition under which the bug class
	// surfaces.
	//
	// 31 = 30 + 1s clock-skew buffer. Setting this to 35s+ would couple
	// the smoke fence to the precondition's safety buffer, which is the
	// precondition's job; intentionally slack here so a smoke-only
	// regression points at the right layer.
	idleProbeGapSeconds = 31

	// idleProbeIOTimeout bounds each socket read/write. The server returns
	// 403 fast for invalid tokens; 10s is well above the observed worst
	// case and short enough that a hung conn fails loud rather than
	// silently slow.
	idleProbeIOTimeout = 10 * time.Second

	// idleProbeRetryBackoff separates the two probe attempts when the
	// first hit a connection-closed error at the second POST. Sized to
	// clear a single mid-stream RST or sub-second AZ network blip —
	// NOT longer events like NLB target deregistration during instance
	// refresh (deregistration_delay defaults to 300s), which is out of
	// scope for this smoke fence: a deploy-window probe hitting that
	// case should fail loud and the operator should re-run smoke after
	// the refresh completes. 2s is short enough to keep total smoke
	// runtime acceptable while still clearing the momentary class.
	//
	// Total worst-case runtime for this single test (including each
	// POST's idleProbeIOTimeout budget, which dominates if the network
	// is slow):
	//   pass-on-attempt-1:    ~31s typical / ~51s worst (idle gap +
	//                         up to 2 IO timeouts on the two POSTs)
	//   pass-on-attempt-2:    ~64s typical / ~104s worst
	//                         (31s + idleProbeRetryBackoff(2s) + 31s
	//                         + up to 4 IO timeouts across both
	//                         attempts)
	//   fail-after-2-attempts ~64s typical / ~104s worst
	// This is currently the dominant single-test cost in the smoke
	// suite. Followup #1804 tracks an env-var override (default
	// unchanged) for fast local iteration; CI must run with the
	// default 31s gap or the regression fence is meaningless.
	idleProbeRetryBackoff = 2 * time.Second

	// idleProbeInvalidToken is the form body sent in both POSTs. 25 chars
	// total — `at_` prefix plus 22 base64url-style chars. Two validators
	// must both accept it for the probe to reach the 403-handler-alive
	// branch:
	//   - The qurl plugin (runtime, the path the probe actually hits)
	//     iterates each rune through isValidTokenChar in
	//     endpoints/server/staticplugins/qurl/config.go::isValidTokenChar
	//     and bounds length via minTokenLength/maxTokenLength.
	//   - The qurl-service spec (regex `^at_[a-z0-9_-]{22}$`) is the
	//     external contract; we keep the probe within it so a future
	//     unification of the two paths doesn't silently invalidate the
	//     fixture.
	// The token contains only [a-z0-9] so it's accepted by both. It won't
	// match any real minted token, so the plugin returns 403 + "Access
	// Link Invalid" without reaching AC dispatch or qurl-service, keeping
	// the probe cheap and side-effect free.
	idleProbeInvalidToken = "at_keepaliveprobeinvalid0"
)

// errSecondPostConnectionClosed is the sentinel returned by
// runIdleTimeoutProbe when the *second* POST hit a closed-connection
// error after the idle gap. The outer test function looks for this
// specifically: a transient blip during the 31s sleep is the only error
// shape we should retry, since (a) first-POST failures aren't the fence
// under test and (b) non-closed errors on the second POST aren't the
// regression class either. A bare error.New is sufficient — we wrap the
// underlying cause with %w so consumers can still inspect it.
var errSecondPostConnectionClosed = errors.New("second POST observed connection closed by peer")

// keepAliveProbe owns one persistent TCP+TLS connection plus the
// bufio.Reader wrapping it, so successive POSTs share the read buffer
// (canonical net/http pattern; avoids buffered-bytes-lost-between-requests
// footguns if a future change adds pipelining or trailers).
type keepAliveProbe struct {
	conn       *tls.Conn
	br         *bufio.Reader
	hostHeader string // canonical Host header value (host or host:port per RFC 7230 §5.4)
}

// TestResolveOrigin_HTTPIdleTimeoutClearsCloudFrontKeepAlive verifies that
// the NHP server's HTTP IdleTimeout exceeds CloudFront's
// origin_keepalive_timeout, fencing the resolve.qurl.link 502 class
// (PR #1795). See file-level comment for rationale.
func TestResolveOrigin_HTTPIdleTimeoutClearsCloudFrontKeepAlive(t *testing.T) {
	if testConfig.NHPServerOriginURL == "" {
		// Sandbox and prod are KNOWN to have a separate
		// resolve-origin.<env> Route53 record (see
		// terraform/main.tf::aws_route53_record.qurl_link_resolve_origin
		// and tests/smoke/dns.go::deriveEndpoints). A missing origin URL
		// in either of those envs means the wiring regressed — fail
		// loudly, don't silently turn off the regression fence. Skip
		// only in unknown/future envs where we explicitly don't expect
		// the record to exist.
		switch testConfig.Environment {
		case "sandbox", "prod":
			t.Fatalf("NHPServerOriginURL is empty for env %q, which is expected to have a separate resolve-origin record (see tests/smoke/dns.go::deriveEndpoints + terraform/main.tf::aws_route53_record.qurl_link_resolve_origin). Either the record is missing or the smoke wiring regressed; this fence cannot be silently skipped in a known env.", testConfig.Environment)
		default:
			t.Skipf("skipped: NHPServerOriginURL not set for env %q (no separate origin record)", testConfig.Environment)
		}
	}

	host, port, path, err := parseOriginURL(testConfig.NHPServerOriginURL)
	if err != nil {
		t.Fatalf("parse NHPServerOriginURL %q: %v", testConfig.NHPServerOriginURL, err)
	}

	// Single re-dial retry: a transient blip during the 31s idle gap
	// (single mid-stream RST, sub-second AZ event) can produce an
	// ECONNRESET on the second POST that's unrelated to IdleTimeout.
	// Tier 1 fences shouldn't soft-retry forever, but one fresh attempt
	// distinguishes a real regression (consistently closed) from
	// flake (closed once, fine on retry). Caps worst-case runtime at
	// ~63s instead of ~31s, which is acceptable for a fence that
	// pages. The errors.Join below preserves both attempts' errors so
	// triage can see whether they looked alike (same root cause) or
	// differed (likely transient on one of the two).
	var attemptErrs []error
	for attempt := 1; attempt <= 2; attempt++ {
		err := runIdleTimeoutProbe(t, host, port, path)
		if err == nil {
			return // pass
		}
		if !errors.Is(err, errSecondPostConnectionClosed) {
			// Anything other than "second POST hit closed conn" is not
			// the regression class — first-POST failures, non-closed
			// errors, status-code mismatches. Fail immediately.
			t.Fatalf("probe attempt %d failed (not the IdleTimeout regression class): %v", attempt, err)
		}
		attemptErrs = append(attemptErrs, fmt.Errorf("attempt %d: %w", attempt, err))
		if attempt == 1 {
			t.Logf("attempt %d hit second-POST connection-closed (%v); retrying once with a fresh dial before declaring regression...", attempt, err)
			time.Sleep(idleProbeRetryBackoff)
		}
	}

	// Both attempts saw second-POST connection-closed — the regression
	// signal isn't a transient blip.
	t.Fatalf("after 2 attempts with %ds idle gap, server consistently closed the connection on the second POST — server IdleTimeout is shorter than CloudFront origin_keepalive_timeout (30s). Re-opens the resolve.qurl.link 502 race fixed in PR #1795. Check (in plan-time-loud-first order):\n  - terraform/main.tf::terraform_data.http_keepalive_contract precondition (should hard-fail at plan time on a contract violation; if this smoke test fails but TF apply was clean, the precondition is broken too).\n  - terraform/modules/compute/user_data.sh.tpl http.toml IdleTimeoutMs.\n  - endpoints/server/constants.go DefaultHttpServerIdleTimeoutMs.\nBoth-attempt errors:\n%v", idleProbeGapSeconds, errors.Join(attemptErrs...))
}

// runIdleTimeoutProbe performs one full attempt: dial, first POST, sleep,
// second POST, validate. Returns nil on success. Wraps the
// errSecondPostConnectionClosed sentinel when the second POST observed
// a closed connection — the only error shape the caller should retry.
func runIdleTimeoutProbe(t *testing.T, host, port, path string) error {
	t.Helper()
	probe, err := dialKeepAliveProbe(host, port)
	if err != nil {
		return fmt.Errorf("dial %s: %w", net.JoinHostPort(host, port), err)
	}
	defer probe.conn.Close()

	// First request — establishes the keep-alive. A failure here is NOT
	// the fence under test (the connection hasn't been idle yet); it
	// indicates a more basic connectivity / TLS / handshake problem.
	resp, err := probe.sendPOST(path, idleProbeInvalidToken)
	if err != nil {
		return fmt.Errorf("first POST (before idle gap) failed — basic connectivity issue, not the IdleTimeout fence: %w", err)
	}

	// Bail before the idle gap if the server (or future middleware) opted
	// out of keep-alive. The conn is then unreusable for a reason
	// unrelated to the IdleTimeout fence; surface that explicitly so
	// triage doesn't chase the wrong root cause. resp.Close captures
	// both `Connection: close` AND HTTP/1.0 responses (where keep-alive
	// is opt-in via `Connection: keep-alive`).
	if resp.Close {
		return fmt.Errorf("first POST returned with keep-alive disabled (resp.Close=true; Status: %d; Connection: %q; Proto: %q) — server is opting out of keep-alive, so this fence cannot exercise IdleTimeout. Possible causes: explicit Connection: close, HTTP/1.0 downgrade, middleware adding the close header, or a status code (e.g. some 4xx variants) that net/http defaults to closing on", resp.StatusCode, resp.Header.Get("Connection"), resp.Proto)
	}

	// Confirm the handler responded correctly, not just the TCP layer.
	// Without this, a future bug that crashes the qurl handler but keeps
	// the conn open (e.g., empty 200, panic recovery returning 500)
	// would still pass the fence.
	if resp.StatusCode != http.StatusForbidden {
		return fmt.Errorf("first POST returned status %d (want %d for invalid token) — handler at %s isn't behaving correctly; not the IdleTimeout fence", resp.StatusCode, http.StatusForbidden, path)
	}

	t.Logf("first POST returned 403 as expected; sleeping %ds (idle gap > CF origin_keepalive_timeout=30s)...", idleProbeGapSeconds)
	time.Sleep(idleProbeGapSeconds * time.Second)

	// Second request on the same connection. If the server's IdleTimeout
	// is shorter than idleProbeGapSeconds, the server has FIN'd the conn
	// and this read returns io.EOF (or a connection-reset error,
	// depending on timing).
	resp2, err := probe.sendPOST(path, idleProbeInvalidToken)
	if err != nil {
		if isConnectionClosedErr(err) {
			// The regression class. Wrap with the sentinel so the caller
			// can retry exactly this case (transient blip → fresh dial).
			return errors.Join(errSecondPostConnectionClosed, err)
		}
		return fmt.Errorf("second POST: %w", err)
	}
	if resp2.StatusCode != http.StatusForbidden {
		return fmt.Errorf("second POST after %ds idle returned status %d (want %d) — connection was reused but handler didn't respond correctly", idleProbeGapSeconds, resp2.StatusCode, http.StatusForbidden)
	}

	t.Logf("second POST returned 403 after %ds idle — IdleTimeout > %ds confirmed", idleProbeGapSeconds, idleProbeGapSeconds)
	return nil
}

// parseOriginURL splits NHPServerOriginURL into host, port, and request
// path. Defaults port to "443" when elided. Honors u.Path so an env-var
// override pointing at a different path works as expected; defaults to
// "/plugins/qurl" for the bare-host case — the only shape today, since
// this fence exclusively probes the qurl plugin. Future smoke tests
// that want to reuse keepAliveProbe against a non-qurl endpoint should
// either (a) populate u.Path on the source URL (the documented escape
// hatch — works today, no signature change needed), or (b) refactor
// parseOriginURL to take a defaultPath parameter when the second
// caller actually arrives. Don't pre-emptively generalize for a
// hypothetical second caller. Rejects inputs without a host (e.g.,
// "https://") loudly rather than passing an empty host through to
// net.JoinHostPort, which would silently dial a wildcard.
func parseOriginURL(rawURL string) (host, port, path string, err error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", "", "", err
	}
	if u.Scheme != "https" {
		return "", "", "", fmt.Errorf("expected https scheme, got %q", u.Scheme)
	}
	host, port = u.Hostname(), u.Port()
	if host == "" {
		return "", "", "", fmt.Errorf("URL has empty host: %q", rawURL)
	}
	if port == "" {
		port = "443"
	}
	path = u.Path
	if path == "" || path == "/" {
		path = "/plugins/qurl"
	}
	return host, port, path, nil
}

// dialKeepAliveProbe opens a TCP+TLS connection and wraps it in the probe
// struct. The tls.Config does NOT InsecureSkipVerify — the resolve-origin
// record has a SAN on the NLB cert, and a verification failure here would
// itself be a bug worth surfacing.
func dialKeepAliveProbe(host, port string) (*keepAliveProbe, error) {
	tcp, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), idleProbeIOTimeout)
	if err != nil {
		return nil, err
	}
	conn := tls.Client(tcp, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
	if err := conn.SetDeadline(time.Now().Add(idleProbeIOTimeout)); err != nil {
		_ = tcp.Close()
		return nil, err
	}
	if err := conn.Handshake(); err != nil {
		_ = tcp.Close()
		return nil, fmt.Errorf("tls handshake: %w", err)
	}
	// RFC 7230 §5.4: omit the port from Host when it's the scheme default
	// (443 for https). Including the canonical "host[:port]" form means the
	// probe stays correct if the env ever points at a non-443 origin.
	hostHeader := host
	if port != "443" {
		hostHeader = net.JoinHostPort(host, port)
	}
	return &keepAliveProbe{
		conn:       conn,
		br:         bufio.NewReader(conn),
		hostHeader: hostHeader,
	}, nil
}

// sendPOST writes one HTTP/1.1 POST with Connection: keep-alive over
// p.conn, reads the response off the persistent bufio.Reader, and drains
// the body so the connection stays reusable for the next request. Returns
// the response on success; an error wrapping io.EOF / a syscall errno when
// the server closed the connection before responding (the canonical signal
// the fence is checking for).
func (p *keepAliveProbe) sendPOST(path, token string) (*http.Response, error) {
	body := "token=" + url.QueryEscape(token)
	req := strings.Join([]string{
		"POST " + path + " HTTP/1.1",
		"Host: " + p.hostHeader,
		"User-Agent: nhp-smoke/keepalive-probe",
		"Accept: */*",
		"Connection: keep-alive",
		"Content-Type: application/x-www-form-urlencoded",
		fmt.Sprintf("Content-Length: %d", len(body)),
		"",
		body,
	}, "\r\n")

	if err := p.conn.SetWriteDeadline(time.Now().Add(idleProbeIOTimeout)); err != nil {
		return nil, err
	}
	if _, err := io.WriteString(p.conn, req); err != nil {
		return nil, fmt.Errorf("write request: %w", err)
	}

	if err := p.conn.SetReadDeadline(time.Now().Add(idleProbeIOTimeout)); err != nil {
		return nil, err
	}
	resp, err := http.ReadResponse(p.br, &http.Request{Method: "POST"})
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("drain body: %w", err)
	}
	if err := resp.Body.Close(); err != nil {
		return nil, fmt.Errorf("close body: %w", err)
	}
	return resp, nil
}

// isConnectionClosedErr reports whether err indicates the peer closed the
// connection (FIN or RST) — the failure mode this smoke fence is built
// around. Uses errors.Is with canonical sentinels (net.ErrClosed, syscall
// errnos, io.EOF / io.ErrUnexpectedEOF) so the check is portable across
// platforms and Go versions.
//
// The "use of closed network connection" substring fallback exists for
// older Go paths where the error didn't satisfy errors.Is(net.ErrClosed).
// `net.ErrClosed` was introduced in Go 1.16 and most stdlib paths now
// wrap properly; the fork's go.mod is on Go 1.26.2, so the fallback is
// likely already dead code. Tracking removal in #1802 — the
// negative-case test in 09_resolve_origin_idle_timeout_helpers_test.go
// guards against the fallback ever broadening if it stays.
func isConnectionClosedErr(err error) bool {
	if err == nil {
		return false
	}
	switch {
	case errors.Is(err, io.EOF),
		errors.Is(err, io.ErrUnexpectedEOF),
		errors.Is(err, net.ErrClosed),
		errors.Is(err, syscall.ECONNRESET),
		errors.Is(err, syscall.EPIPE):
		return true
	}
	// Defensive substring fallback: some older internal/poll errors
	// surface this string without satisfying errors.Is(net.ErrClosed).
	// Narrow scope: only this exact string.
	return strings.Contains(err.Error(), "use of closed network connection")
}
